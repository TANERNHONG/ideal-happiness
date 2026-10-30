// Reports (US-36): an in-house editor for an investigation report built from a set of findings. A report
// is a stack of sections (each with optional subsections), each a stack of blocks, dragged into place:
// blocks from the palette, findings from the list on the right, blocks and whole sections to reorder.
//
// Anomaly and malicious-activity templates share the versioned report editor. It is laid out
// like a printed incident report, in Times New Roman: a masthead, the report's details (reported by, date,
// number, case status, assessment), then I Executive Summary (the case OPEN or CLOSED first), II Target
// Analysis, III Detection, IV Supporting Evidence, V Impact Assessment, VI Analyst Comments, VII MITRE
// ATT&CK, VIII Actions (immediate; planned and preventive), IX Conclusion, X Information Sharing, XI
// Sign-offs (not binding in the POC, Q32), and footnotes.
//
// Every block that shows a rarity score or the models' verdicts carries a short note on how they are
// computed. The local model (on this laptop only) can write a table's query and suggest ATT&CK techniques;
// what it writes is shown for the analyst to check. Saving (Q29), export to Word or PDF (Q30) and non-binding signing are implemented; the executive-summary writer is deferred (Q31).

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, keepScroll, loading } from "../dom";
import type { Child } from "../dom";
import { icon } from "../icons";
import { sqlApi } from "../sql-lock";
import { state } from "../state";
import { verdictBadge } from "../verdicts";
import { dateSpan, groupName, rarity, topValues } from "../words";
import { downloadReport, paperCopy, previewPaper, printSnapshot } from '../report-print';

type BlockType = "status" | "ai" | "text" | "target" | "finding" | "lines" | "table" | "metric" | "attack" | "timeline" | "signature" | "map";
interface Block { id: string; type: BlockType; data: Record<string, any> }
interface Section { id: string; title: string; blocks: Block[]; subs: Section[] }

/** A finding to report on: a Review item (an anomalous group, an activity alert, or firewall activity) or an upload. */
interface Finding {
  key: string; title: string; meta: string; verdict: string | null;
  source: string; view: string; view_label?: string; period?: string; kind: "cluster" | "presence_alert" | "activity_alert" | "upload"; item_id: string;
  cluster_id?: string; row_manifest_ids?: string; lines?: string[]; line_count?: number; upload?: number;
  flagged_rows?: number; lift?: number | null; first_seen?: string; last_seen?: string; top?: Record<string, string>;
}
let known: Finding[] = [];          // the findings list on the right, once loaded

const PALETTE: [BlockType, string, string][] = [
  ["text", "Text", "docs"], ["target", "Target", "target"], ["finding", "Finding", "review"], ["lines", "Log lines", "individual"],
  ["table", "Table", "table"], ["metric", "Metric", "gauge"], ["attack", "ATT&CK", "matrix"], ["timeline", "Timeline", "clock"],
  ["map", "Cluster map", "map"],
  ["ai", "AI draft", "sparkle"], ["signature", "Signature", "sign"],
];
const SIGNERS = ["Prepared by", "Reviewed by", "Approved by"];
const ASSESSMENTS = ["negligible", "minor", "significant", "critical"];
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

let seq = 0;
const id = () => `b${++seq}`;
const block = (type: BlockType, data: Record<string, any> = {}): Block => ({ id: id(), type, data });
const section = (title: string, blocks: Block[] = [], subs: Section[] = []): Section => ({ id: id(), title, blocks, subs });

function template(kind = 'anomaly'): Section[] {
  return [
    section("Executive Summary", [block("status"), block("ai")]),
    section("Target Analysis", [block("target")]),
    section(kind === 'malicious' ? "Confirmed Activity and Detection" : "Detection", [block("metric", { tiles: [{ kind: "rarity" }, { kind: "events" }, { kind: "detectors" }] }),
      ...(kind === 'malicious' ? [block('text', { placeholder: 'Evidence establishing malicious activity; distinguish confirmed facts from hypotheses.' })] : [])]),
    section("Supporting Evidence"),
    section("Impact Assessment", [block("text", { placeholder: "Impact on operations, systems and data" })]),
    section("Analyst Comments", [block("text")]),
    section("MITRE ATT&CK Mapping", [block("attack")]),
    section("Actions", [], [
      section(kind === 'malicious' ? "Containment and Eradication" : "Immediate Action Taken", [block("text")]),
      section(kind === 'malicious' ? "Recovery and Preventive Measures" : "Planned Actions and Preventive Measures", [block("text")]),
    ]),
    section("Conclusion", [block("text")]),
    section("Information Sharing", [block("table", { mode: "manual", columns: ["Department requiring notification", "Point of contact", "Date of notification"],
      rows: [["", "", ""], ["", "", ""], ["", "", ""]] })]),
    section("Sign-offs", SIGNERS.map((role) => block("signature", { role }))),
  ];
}

const today = () => new Date().toISOString().slice(0, 10);
const doc = {
  kind: 'anomaly',
  title: "", status: "open" as "open" | "closed", assessment: "", reportedBy: "", role: "", date: today(), number: "", ticket: "",
  sections: template(), footnotes: [] as { id: string; text: string }[],
};
let savedId: number | null = null, savedVersion = 0, openedVersion = 0, savedJSON = JSON.stringify(doc), savingReport = false;
let versions: any[] = [];
const dirty = () => JSON.stringify(doc) !== savedJSON;
window.addEventListener('beforeunload', e => { if (dirty()) { e.preventDefault(); e.returnValue = ''; } });

// A report started from Review → Reviewed (its Report button): the item as the finding, its notes as the comments.
let pending: { finding: Finding; comments: string } | null = null;

/** Opens Reports on a new anomaly report about ``item`` (a Review item, with its source): its title, Target Analysis,
 * Detection tiles and a finding card in Supporting Evidence from the item, and ``comments`` in VI Analyst Comments. */
export function reportOn(item: any, comments: string): void {
  pending = { finding: findingOf(item), comments };
  location.hash = "#/reports";
}

function startPending(): Finding | null {
  const p = pending;
  pending = null;
  if (!p || (dirty() && !confirm('Discard unsaved report changes and start a report from this finding?'))) return null;
  const sections = template('anomaly');
  const comments = sections.find((s) => s.title === "Analyst Comments")?.blocks.find((b) => b.type === "text");
  if (comments) comments.data.text = p.comments;
  sections.find((s) => s.title === "Supporting Evidence")?.blocks.push(block("finding", { finding: p.finding }));
  savedId = null; savedVersion = openedVersion = 0; versions = [];
  restoreDocument({ kind: 'anomaly', sections, title: p.finding.title, footnotes: [], status: 'open', assessment: '', reportedBy: '', role: '', date: today(), number: '' });
  history.replaceState(null, '', '#/reports');
  return p.finding;
}

function restoreDocument(value: any): void {
  const { print: _print, print_html: _html, print_css: _css, ...content } = value;
  Object.assign(doc, { ticket: "" }, content);                       // reports saved before the ticket field have none
  seq = Math.max(seq, ...[...JSON.stringify(doc).matchAll(/"id":"b(\d+)"/g)].map(m => Number(m[1])));
  painters.clear(); eventsCache.clear();
  savedJSON = JSON.stringify(doc);
}

function* allSections(list: Section[] = doc.sections): Generator<Section> {
  for (const s of list) { yield s; yield* allSections(s.subs); }
}
const allBlocks = () => [...allSections()].flatMap((s) => s.blocks);

const ROMAN: [number, string][] = [[10, "X"], [9, "IX"], [5, "V"], [4, "IV"], [1, "I"]];
function roman(n: number): string {
  let out = "";
  for (const [v, s] of ROMAN) while (n >= v) { out += s; n -= v; }
  return out;
}
const letter = (j: number) => { let s = ""; j++; while (j > 0) { const m = (j - 1) % 26; s = String.fromCharCode(65 + m) + s; j = Math.floor((j - 1) / 26); } return s; };

// --- how the scores are computed: added beside every block that shows them ----------------------------
const NOTES: Record<string, [string, string]> = {
  rarity: ["How rarity is computed.",
    "Each event is scored by three detectors (robust deviation, Isolation Forest and novelty) and by the model-zoo ensemble, all trained only on the training period. " +
    "Each score is placed among the same detector's scores for every event of the validation period, which the models did not learn from, giving a percentile. " +
    "The event's rarity is its highest percentile across the detectors. " +
    "“1 in N” means N = 1 ÷ (1 − percentile): the event is rarer than all but one in N validation events, and “rarest” means it scored at or beyond the most unusual of them. " +
    "Rarity measures how unusual the activity is, not whether it is malicious."],
  models: ["How the models flag activity.",
    "The models learn what normal activity looks like from the training period, without labels, so a flag means unusual, not confirmed malicious. " +
    "Robust deviation flags values far outside their usual range; Isolation Forest flags combinations that are easy to separate from the rest; novelty flags values rarely or never seen in training. " +
    "The model zoo is a set of further unsupervised models, pruned and selected on the validation period, and an event is a consensus alert when at least three of them flag it (all of them, where a view keeps fewer than three). " +
    "Each detector's threshold was set on the validation period to keep alerts within a daily budget; the test period was never used to tune anything. " +
    "Firewall logs use the presence method instead and carry no rarity score."],
  map: ["How the map is drawn.",
    "Each point is one observation of the view from the test or validation period, placed by the saved t-SNE (or UMAP) projection of the models' 32-number summary of it; training points are left out. " +
    "Targets already on the saved map keep their position; the others are placed among their nearest neighbours in that summary and marked as estimated. " +
    "Points close together behaved alike. Distance on the map is not a probability of attack, and a line without a saved score of its own shows no rarity."],
  presence: ["How firewall activity is found.",
    "PF and IPFilter logs are not scored against a baseline: they use the presence method, and the traffic found is reported. " +
    "Lines are grouped into flow episodes (the same flow, close together in time), which Phase 7 ranks. " +
    "These findings therefore carry no rarity score."],
};
const methodNote = (keys: string[]) => keys.length
  ? h("div", { class: "rp-method" }, [...new Set(keys)].map((k) => h("p", {}, h("strong", {}, NOTES[k][0]), " ", NOTES[k][1]))) : null;
const baseline = (source: string | undefined) => state.catalog.sources[source ?? ""]?.method === "baseline";

// --- drag and drop ----------------------------------------------------------------------------------
// What is being dragged: a palette block, a finding, a block already in the report, or a section.
type Drag = { kind: "new"; type: BlockType } | { kind: "finding"; finding: Finding } | { kind: "block"; id: string } | { kind: "section"; id: string };
let dragging: Drag | null = null;

function take(blockId: string): Block | null {
  for (const s of allSections()) {
    const i = s.blocks.findIndex((b) => b.id === blockId);
    if (i >= 0) return s.blocks.splice(i, 1)[0];
  }
  return null;
}

/** Where in a list the pointer is: the index of the first child whose middle is below it. */
function indexAt(list: HTMLElement, y: number, selector: string): number {
  const items = [...list.querySelectorAll<HTMLElement>(`:scope > ${selector}`)];
  const i = items.findIndex((el) => { const r = el.getBoundingClientRect(); return y < r.top + r.height / 2; });
  return i < 0 ? items.length : i;
}

function newBlock(type: BlockType): Block {
  if (type === "signature") return block(type, { role: "Signed by" });
  if (type === "metric") return block(type, { tiles: [{ kind: "rarity" }, { kind: "events" }] });
  return block(type);
}

function dropInto(target: Section, at: number): void {
  if (!dragging || dragging.kind === "section") return;
  let b: Block | null = null;
  if (dragging.kind === "new") b = newBlock(dragging.type);
  else if (dragging.kind === "finding") b = block("finding", { finding: dragging.finding });
  else {
    const before = target.blocks.findIndex((x) => x.id === (dragging as { id: string }).id);
    b = take(dragging.id);
    if (before >= 0 && before < at) at--;                 // moved down within the same section
  }
  if (b) target.blocks.splice(at, 0, b);
}

/** A block that takes a finding: drop a finding card on it (it does not become a block of its own). */
function acceptFinding(el: HTMLElement, on: (f: Finding) => void): void {
  el.addEventListener("dragover", (e) => { if (dragging?.kind !== "finding") return; e.preventDefault(); e.stopPropagation(); el.classList.add("over"); });
  el.addEventListener("dragleave", () => el.classList.remove("over"));
  el.addEventListener("drop", (e) => {
    if (dragging?.kind !== "finding") return;
    e.preventDefault(); e.stopPropagation(); el.classList.remove("over");
    const f = dragging.finding; dragging = null;
    on(f);
  });
}

function findingPicker(current: Finding | undefined, on: (f: Finding) => void): HTMLElement {
  const select = h("select", { "aria-label": "Finding" },
    h("option", { value: "", disabled: true, selected: !current }, "Finding"),
    known.map((f, n) => h("option", { value: String(n), selected: current?.key === f.key }, `${f.title} · ${f.meta}`))) as HTMLSelectElement;
  select.addEventListener("change", () => on(known[Number(select.value)]));
  return h("div", { class: "rp-pick rp-ui" }, icon("review", 14), select);
}

// Blocks that fetch data draw themselves again when an answer arrives (without redrawing the report).
const painters = new Map<string, () => void>();
const repaint = (b: Block) => painters.get(b.id)?.();
function live(b: Block, box: HTMLElement, render: () => Child): void {
  const paint = () => keepScroll(box, () => clear(box, render()));
  painters.set(b.id, paint);
  paint();
}

/** A value written on a ruled line, as on a printed form; it wraps where an input would cut it off. */
function line(value: string, label: string, save: (v: string) => void, placeholder = ""): HTMLElement {
  const el = h("div", { class: "rp-line", contenteditable: "true", role: "textbox", "aria-label": label, "data-placeholder": placeholder });
  el.textContent = value;
  el.addEventListener("input", () => save(el.textContent ?? ""));
  return el;
}

const stamp = () => { const d = new Date(), p = (n: number) => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const meter = (p: number | null | undefined) => {
  const r = rarity(p);
  return h("span", { class: "rarity", title: r.title }, h("span", { class: "meter" }, h("i", { style: { width: `${Math.round(r.fill * 100)}%` } })), h("span", { class: "small" }, r.text));
};

// --- the page -----------------------------------------------------------------------------------------

export async function renderReports(main: HTMLElement): Promise<void> {
  const started = startPending();
  const routeId = Number(location.hash.split('/')[2] || 0);
  if (routeId && savedId !== routeId) {
    if (dirty() && !confirm('Discard unsaved report changes and open this report?')) { history.replaceState(null, '', '#/reports'); return; }
    try {
      const r = await api(`/api/reports/item${qs({ id: String(routeId) })}`);
      restoreDocument(r.document); savedId = r.id; savedVersion = r.current_version; openedVersion = r.version; versions = r.versions;
    } catch (e) { return clear(main, errorBox(e)); }
  }
  const canvas = h("div", { class: "rp-paper" });
  const findings = h("div", { class: "rp-findings" });
  const feedback = h('span', { class: 'rp-feedback', role: 'status', 'aria-live': 'polite' });
  const savedState = h('span', { class: 'rp-state' }, savedId
    ? [h('strong', {}, doc.number), h('span', { class: 'badge muted' }, `v${openedVersion}`),
      openedVersion < savedVersion ? h('span', { class: 'badge info', title: 'Saving creates a new latest version' }, icon('history', 12), 'older version') : null]
    : h('span', { class: 'badge muted' }, 'unsaved'));
  const when = (t: string) => String(t).replace('T', ' ').slice(0, 16);
  const library = h('div', { class: 'rp-library-body' });
  const historyBox = h('select', { class: 'rp-select', 'aria-label': 'Report version', disabled: !versions.length }, h('option', { value: '' }, 'Versions'),
    versions.map(v => h('option', { value: String(v.version) }, `v${v.version} · ${when(v.saved_at)} · ${v.saved_by}`)));
  historyBox.addEventListener('change', async () => {
    if (savingReport || !historyBox.value || !savedId || (dirty() && !confirm('Discard unsaved changes and open this saved version?'))) return;
    try {
      const r = await api(`/api/reports/item${qs({ id: String(savedId), version: historyBox.value })}`);
      restoreDocument(r.document); openedVersion = r.version; savedVersion = r.current_version; versions = r.versions;
      renderReports(main);
    } catch (e) { clear(feedback, errorBox(e)); }
  });
  const draw = () => drawPaper(canvas, draw);
  const save = async () => {
    if (savingReport) return false;
    if (allBlocks().some(b => b.data.busy || b.data.loading || Object.values(b.data.detail ?? {}).some((v: any) => v.busy))) {
      clear(feedback, errorBox(new Error('Wait for evidence retrieval to finish before saving.'))); return false;
    }
    savingReport = true; saveButton.disabled = true;
    try {
      const captured = JSON.stringify(doc);
      const r = await api('/api/reports/save', { body: { id: savedId, base_version: savedVersion, document: { ...JSON.parse(captured), print: printSnapshot(canvas), print_html: paperCopy(canvas).outerHTML } } });
      savedId = r.id; savedVersion = r.version; openedVersion = r.version;
      const capturedDoc = JSON.parse(captured); capturedDoc.number = r.number;
      doc.number = r.number; savedJSON = JSON.stringify(capturedDoc);
      versions.unshift({ version: r.version, saved_by: r.saved_by, saved_at: r.saved_at });
      historyBox.append(h('option', { value: String(r.version) }, `v${r.version} · ${when(r.saved_at)} · ${r.saved_by}`));
      historyBox.disabled = false;
      historyBox.value = String(r.version);
      clear(feedback, icon('check', 12), `v${r.version} saved${dirty() ? ' · unsaved edits remain' : ''}`);
      clear(savedState, h('strong', {}, r.number), h('span', { class: 'badge muted' }, `v${r.version}`));
      (canvas.querySelector('[aria-label="Report no."]') as HTMLInputElement).value = r.number;
      history.replaceState(null, '', `#/reports/${savedId}`);
      return true;
    } catch (e) { clear(feedback, errorBox(e)); return false; }
    finally { savingReport = false; saveButton.disabled = false; }
  };
  const saveButton = h('button', { class: 'btn small primary', onclick: save }, icon('check', 14), 'Save version');
  const FORMATS: [string, string][] = [['pdf', 'PDF'], ['docx', 'Word'], ['html', 'HTML']];
  const format = h('select', { class: 'rp-select', 'aria-label': 'Export format' }, FORMATS.map(([v, label]) => h('option', { value: v }, label)));
  const exportButton = h('button', { class: 'btn small', onclick: async () => {
    exportButton.disabled = true;
    try {
      if (!savedId || dirty()) { if (!await save()) return; }
      clear(feedback, '…');
      downloadReport(await api('/api/reports/export', { body: { id: savedId, version: openedVersion, format: format.value } }));
      clear(feedback, icon('check', 12), `v${openedVersion} · ${FORMATS.find(([v]) => v === format.value)?.[1]}`);
    } catch (e) { clear(feedback, errorBox(e)); }
    finally { exportButton.disabled = false; }
  } }, icon('upload', 14), 'Export');
  const newKind = h('select', { class: 'rp-select', 'aria-label': 'New report template' }, h('option', { value: 'anomaly' }, 'Anomaly'), h('option', { value: 'malicious' }, 'Malicious activity'));
  const newReport = () => {
    if (savingReport) return;
    if (dirty() && !confirm('Discard unsaved changes and create a new report?')) return;
    savedId = null; savedVersion = openedVersion = 0; versions = [];
    restoreDocument({ kind: newKind.value, sections: template(newKind.value), title: '', footnotes: [], status: 'open', assessment: '', reportedBy: '', role: '', date: today(), number: '' });
    history.replaceState(null, '', '#/reports'); renderReports(main);
  };
  const listReports = async () => {
    try {
      const r = await api('/api/reports');
      clear(library, h('div', { class: 'card-head' }, h('span', { class: 'chip-icon' }, icon('folder')), h('h2', {}, `Saved reports · ${r.reports.length}`),
        h('button', { class: 'icon-btn end', title: 'Close', 'aria-label': 'Close saved reports', onclick: () => clear(library) }, icon('close', 14))),
        r.reports.length ? r.reports.map((p: any) => h('a', { class: 'rp-lib-row', href: `#/reports/${p.id}` },
          h('span', { class: 'rp-lib-no' }, p.number, p.ticket ? h('span', { class: 'tiny muted mono' }, ` · ${p.ticket}`) : null),
          h('span', { class: 'up-name' }, h('strong', {}, p.title || 'Untitled report'), h('span', { class: 'tiny muted' }, `${when(p.updated_at)} · ${p.updated_by}`)),
          h('span', { class: 'badge muted' }, p.kind === 'malicious' ? 'malicious activity' : 'anomaly'),
          h('span', { class: `rp-case small ${p.status}` }, p.status.toUpperCase()),
          h('span', { class: 'badge muted' }, `v${p.current_version}`)))
          : h('p', { class: 'muted small' }, 'No saved reports'));
    } catch (e) { clear(library, errorBox(e)); }
  };
  const evidence = () => doc.sections.find((s) => s.title === "Supporting Evidence") ?? doc.sections[Math.max(0, doc.sections.length - 2)];
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Reports"))),
    h("div", { class: "card rp-bar" },
      h("span", { class: "rp-kind-chip" }, icon("reports", 16), doc.kind === 'malicious' ? 'Malicious-activity report' : 'Anomaly report'),
      savedState, feedback,
      h("span", { class: "rp-bar-groups" },
        h('span', { class: 'rp-bar-group' }, newKind, h('button', { class: 'btn small', 'aria-label': 'New report', onclick: newReport }, icon('plus', 14), 'New')),
        h('span', { class: 'rp-bar-group' }, h('button', { class: 'btn small', 'aria-label': 'Saved reports', onclick: listReports }, icon('folder', 14), 'Saved'), historyBox),
        h('span', { class: 'rp-bar-group' }, h("button", { class: "btn small", onclick: () => previewPaper(canvas) }, icon("docs", 14), "Preview"),
          format, exportButton, saveButton))),
    h('div', { class: 'card rp-library' }, library),
    h("div", { class: "rp-grid" },
      h("aside", { class: "card rp-palette" }, h("div", { class: "rp-side-head" }, "Blocks"),
        PALETTE.map(([type, label, glyph]) => {
          const chip = h("div", { class: "rp-chip", draggable: "true", tabindex: "0", title: label }, icon(glyph, 16), label);
          chip.addEventListener("dragstart", (e) => { dragging = { kind: "new", type }; e.dataTransfer?.setData("text/plain", type); canvas.classList.add("dragging"); });
          chip.addEventListener("dragend", () => { dragging = null; canvas.classList.remove("dragging"); });
          chip.addEventListener("keydown", (e) => { if (e.key === "Enter") { evidence().blocks.push(newBlock(type)); draw(); } });
          return chip;
        }),
        h("div", { class: "rp-side-head", style: { marginTop: "14px" } }, "Sections"),
        h("button", { class: "rp-chip", onclick: () => { doc.sections.splice(doc.sections.length - 1, 0, section("New Section", [block("text")])); draw(); } },
          icon("plus", 16), "Section")),
      h("div", { class: "rp-desk" }, canvas),
      h("aside", { class: "card rp-side" }, h("div", { class: "rp-side-head" }, "Findings"), findings)));
  draw();
  if (started) for (const b of allBlocks()) {                // the blocks that take a finding, once they are drawn
    if (b.type === "target") void fillTarget(b, started);
    else if (b.type === "metric") void fillMetric(b, started);
  }
  loadFindings(findings);
}

function drawPaper(paper: HTMLElement, redraw: () => void): void {
  painters.clear();
  const list = h("div", { class: "rp-sections" });
  doc.sections.forEach((s, n) => list.append(sectionEl(s, `${roman(n + 1)}.`, doc.sections, n, 0, redraw)));
  // sections are reordered by dropping them between others
  list.addEventListener("dragover", (e) => { if (dragging?.kind === "section") e.preventDefault(); });
  list.addEventListener("drop", (e) => {
    if (dragging?.kind !== "section") return;
    e.preventDefault();
    const from = doc.sections.findIndex((s) => s.id === (dragging as { id: string }).id);
    if (from < 0) return;
    let to = indexAt(list, e.clientY, ".rp-section");
    if (from < to) to--;
    doc.sections.splice(to, 0, doc.sections.splice(from, 1)[0]);
    dragging = null;
    redraw();
  });
  const title = h("input", { class: "rp-doc-title", value: doc.title, placeholder: "Untitled report", "aria-label": "Report title" }) as HTMLInputElement;
  title.addEventListener("input", () => { doc.title = title.value; });
  clear(paper,
    masthead(),
    h("div", { class: "rp-body" }, title, h("hr", { class: "rp-rule" }), detailsForm(redraw), list, footnotes(redraw)));
}

function masthead(): HTMLElement {
  return h("header", { class: "rp-mast" },
    h("div", {},
      h("div", { class: "rp-mast-title" }, doc.kind === 'malicious' ? 'MALICIOUS ACTIVITY' : 'ANOMALY'),
      h("div", { class: "rp-mast-sub" }, "INVESTIGATION REPORT"),
      h("div", { class: "rp-mast-info" }, ["PROJECT DAD CONSOLE", doc.number ? `REPORT NO. ${doc.number}` : "", doc.date].filter(Boolean).join("  |  "))),
    h("div", { class: "rp-mast-logo" }, h("img", { src: "/brand/smrt-logo.svg", alt: "" })));
}

/** The report's details, as on a printed incident form: who, when, which number, its status and assessment. */
function detailsForm(redraw: () => void): HTMLElement {
  const field = (label: string, key: "reportedBy" | "role" | "date" | "number" | "ticket", attrs: Record<string, unknown> = {}) => {
    const input = h("input", { value: doc[key] ?? "", "aria-label": label, ...attrs }) as HTMLInputElement;
    input.addEventListener("input", () => { doc[key] = input.value; });
    input.addEventListener("change", () => { if (key === "number" || key === "date") redraw(); });
    return h("label", { class: "rp-field" }, h("span", {}, label), input);
  };
  const box = (on: boolean, label: string, act: () => void) =>
    h("button", { class: `rp-box ${on ? "on" : ""}`, role: "checkbox", "aria-label": label, "aria-checked": String(on), onclick: act }, h("i", {}, on ? "✓" : ""), label);
  return h("div", { class: "rp-form" },
    field("Reported by", "reportedBy", { placeholder: state.settings.display_name }), field("Date of report", "date", { type: "date", required: true }),
    field("Title / Role", "role"), field("Report no.", "number", { readonly: true, placeholder: 'Assigned on save' }),
    field("Ticket no.", "ticket", { maxlength: "64" }),
    h("div", { class: "rp-field wide" }, h("span", {}, "Case status"),
      h("div", { class: "rp-boxes" }, (["open", "closed"] as const).map((s) => box(doc.status === s, s.toUpperCase(), () => { doc.status = s; redraw(); })))),
    h("div", { class: "rp-field wide" }, h("span", {}, "Assessment"),
      h("div", { class: "rp-boxes" }, ASSESSMENTS.map((a) => box(doc.assessment === a, a.toUpperCase(), () => { doc.assessment = doc.assessment === a ? "" : a; redraw(); })))));
}

function sectionEl(s: Section, label: string, siblings: Section[], n: number, depth: number, redraw: () => void): HTMLElement {
  const body = h("div", { class: "rp-blocks" });
  s.blocks.forEach((b, i) => body.append(blockEl(s, b, i, redraw)));
  if (!s.blocks.length && !s.subs.length) body.append(h("div", { class: "rp-empty rp-ui" }, icon("plus", 18)));
  // drop blocks and findings into the section, at the pointer
  body.addEventListener("dragover", (e) => { if (!dragging || dragging.kind === "section") return; e.preventDefault(); body.classList.add("over"); });
  body.addEventListener("dragleave", () => body.classList.remove("over"));
  body.addEventListener("drop", (e) => {
    e.preventDefault();
    body.classList.remove("over");
    dropInto(s, indexAt(body, e.clientY, ".rp-block"));
    dragging = null;
    redraw();
  });
  const titleInput = h("input", { class: "rp-sec-title", value: s.title, "aria-label": depth ? "Subsection title" : "Section title" }) as HTMLInputElement;
  titleInput.addEventListener("input", () => { s.title = titleInput.value; });
  const move = (by: number) => { const j = n + by; if (j < 0 || j >= siblings.length) return; siblings.splice(j, 0, siblings.splice(n, 1)[0]); redraw(); };
  const what = depth ? "subsection" : "section";
  let grip: HTMLElement | null = null;
  if (!depth) {
    grip = h("span", { class: "rp-grip rp-ui", draggable: "true", title: "Drag to move the section" }, icon("grip", 16));
    grip.addEventListener("dragstart", (e) => { dragging = { kind: "section", id: s.id }; e.dataTransfer?.setData("text/plain", s.id); });
    grip.addEventListener("dragend", () => { dragging = null; });
  }
  return h("section", { class: `rp-section ${depth ? "rp-sub" : ""}`, "data-id": s.id },
    h("div", { class: "rp-sec-head" }, grip, h("span", { class: "rp-sec-no" }, label), titleInput,
      h("span", { class: "rp-tools rp-ui" },
        depth ? null : h("button", { class: "icon-btn", title: "Subsection", "aria-label": "Add a subsection", onclick: () => { s.subs.push(section("New Subsection", [block("text")])); redraw(); } }, icon("subsection", 14)),
        h("button", { class: "icon-btn", title: "Up", "aria-label": `Move ${what} up`, onclick: () => move(-1) }, "↑"),
        h("button", { class: "icon-btn", title: "Down", "aria-label": `Move ${what} down`, onclick: () => move(1) }, "↓"),
        h("button", { class: "icon-btn", title: "Remove", "aria-label": `Remove ${what}`, onclick: () => { siblings.splice(n, 1); redraw(); } }, icon("close", 14)))),
    body,
    s.subs.length ? h("div", { class: "rp-subs" }, s.subs.map((sub, j) => sectionEl(sub, `${letter(j)}.`, s.subs, j, depth + 1, redraw))) : null);
}

const bars = (widths: number[]) => h("div", { class: "rp-bars" }, widths.map((w) => h("i", { style: { width: `${w}%` } })));

// --- footnotes: a marker in the text (a superscript number) and the note at the foot of the report ------
const SUP = "⁰¹²³⁴⁵⁶⁷⁸⁹";
const sup = (n: number) => String(n).split("").map((c) => SUP[Number(c)]).join("");
const SUPS = new RegExp(`[${SUP}]+`, "g");

function addFootnote(t: HTMLElement, save: () => void, redraw: () => void): void {
  doc.footnotes.push({ id: id(), text: "" });
  const mark = document.createTextNode(sup(doc.footnotes.length));
  const sel = window.getSelection();
  if (sel && sel.rangeCount && t.contains(sel.anchorNode)) { const r = sel.getRangeAt(0); r.collapse(false); r.insertNode(mark); }
  else t.append(mark);
  t.normalize();
  save();
  redraw();
  document.querySelector<HTMLElement>(".rp-foot li:last-child .rp-line")?.focus();
}

function dropFootnote(k: number, redraw: () => void): void {
  doc.footnotes.splice(k - 1, 1);
  for (const b of allBlocks()) {                                            // renumber the markers after it
    if (typeof b.data.text !== "string") continue;
    b.data.text = b.data.text.replace(SUPS, (m: string) => {
      const n = Number([...m].map((c) => SUP.indexOf(c)).join(""));
      return n === k ? "" : n > k ? sup(n - 1) : m;
    });
  }
  redraw();
}

function footnotes(redraw: () => void): HTMLElement {
  return h("footer", { class: "rp-foot" },
    h("div", { class: "rp-foot-head" }, h("span", {}, "Footnotes"),
      h("button", { class: "icon-btn rp-ui", title: "Footnote", "aria-label": "Add a footnote", onclick: () => { doc.footnotes.push({ id: id(), text: "" }); redraw(); } }, icon("plus", 14))),
    doc.footnotes.length ? h("ol", {}, doc.footnotes.map((f, i) => {
      return h("li", {}, h("span", { class: "rp-foot-no" }, sup(i + 1)), line(f.text, `Footnote ${i + 1}`, (v) => { f.text = v; }, "Note"),
        h("button", { class: "icon-btn rp-ui", title: "Remove", "aria-label": `Remove footnote ${i + 1}`, onclick: () => dropFootnote(i + 1, redraw) }, icon("close", 12)));
    })) : null);
}

// --- one block --------------------------------------------------------------------------------------------

function blockEl(container: Section, b: Block, i: number, redraw: () => void): HTMLElement {
  const el = h("div", { class: `rp-block rp-b-${b.type}` });
  // dragged by its grip only, so text inside can be selected and edited
  const grip = h("span", { class: "rp-grip rp-ui", title: "Drag to move" }, icon("grip", 14));
  grip.addEventListener("mousedown", () => { el.draggable = true; });
  el.addEventListener("mouseup", () => { el.draggable = false; });
  el.addEventListener("dragstart", (e) => { if (!el.draggable) return; e.stopPropagation(); dragging = { kind: "block", id: b.id }; e.dataTransfer?.setData("text/plain", b.id); el.classList.add("dragging"); });
  el.addEventListener("dragend", () => { dragging = null; el.draggable = false; el.classList.remove("dragging"); });
  const move = (by: number) => { const j = i + by; if (j < 0 || j >= container.blocks.length) return; container.blocks.splice(j, 0, container.blocks.splice(i, 1)[0]); redraw(); };
  const tools = h("span", { class: "rp-tools rp-ui" },
    h("button", { class: "icon-btn", title: "Up", "aria-label": "Move block up", onclick: () => move(-1) }, "↑"),
    h("button", { class: "icon-btn", title: "Down", "aria-label": "Move block down", onclick: () => move(1) }, "↓"),
    h("button", { class: "icon-btn", title: "Remove", "aria-label": "Remove block", onclick: () => { container.blocks.splice(i, 1); redraw(); } }, icon("close", 14)));
  const editable = (key: string, placeholder: string) => {
    const t = h("div", { class: "rp-text", contenteditable: "true", "data-placeholder": placeholder, role: "textbox", "aria-multiline": "true" });
    t.textContent = b.data[key] ?? "";
    const save = () => { b.data[key] = t.textContent ?? ""; };
    t.addEventListener("input", save);
    return h("div", { class: "rp-edit" }, t,
      h("button", { class: "rp-fn-btn rp-ui", title: "Footnote", "aria-label": "Insert a footnote", onmousedown: (e: Event) => e.preventDefault(), onclick: () => addFootnote(t, save, redraw) }, icon("footnote", 14)));
  };
  let body: Child;
  switch (b.type) {
    case "status":
      body = h("div", { class: "rp-status-line" },
        h("span", {}, "Case status: "), h("span", { class: `rp-case ${doc.status}` }, doc.status.toUpperCase()),
        doc.assessment ? [h("span", { class: "rp-dot" }, "·"), h("span", {}, "Assessment: "), h("strong", { class: `rp-assess ${doc.assessment}` }, cap(doc.assessment))] : null);
      break;
    case "ai":
      body = [h("div", { class: "rp-ai-head rp-ui" }, icon("sparkle", 14),
        h("button", { class: "btn small", disabled: true, title: `Deferred (Q31) · ${state.settings.llm_model}` }, icon("sparkle", 14), "Draft")),
      editable("text", "Executive summary")];
      break;
    case "target": body = targetBlock(b, el); break;
    case "finding": {
      const f = b.data.finding;
      const addLines = () => { container.blocks.splice(i + 1, 0, block("lines", { finding: f })); redraw(); };
      body = f ? h("div", { class: "rp-finding" }, icon("review", 16),
        h("div", {}, h("strong", {}, f.title), h("div", { class: "rp-small" }, f.meta)),
        h("span", { class: "row rp-ui", style: { gap: "6px", flexWrap: "nowrap" } }, f.verdict ? verdictBadge(f.verdict) : badge("needs review", "dark"),
          h("button", { class: "btn small", title: "Log lines", "aria-label": "Add its log lines", onclick: addLines }, icon("plus", 12), icon("individual", 14))))
        : h("div", { class: "rp-finding empty" }, icon("review", 16), bars([60, 35]));
      break;
    }
    case "lines": body = logLines(b, el); break;
    case "table": body = tableBlock(b); break;
    case "metric": body = metricBlock(b, el); break;
    case "attack": body = attackBlock(b, el); break;
    case "timeline": body = timelineBlock(b, el); break;
    case 'map': body = mapBlock(b, el); break;
    case "signature": {
      const input = (key: string, label: string, attrs: Record<string, unknown> = {}) => {
        const x = h("input", { value: b.data[key] ?? "", "aria-label": label, ...attrs }) as HTMLInputElement;
        x.addEventListener("input", () => {
          b.data[key] = x.value; b.data.signed = false;
          el.querySelector('.rp-sign-line')?.replaceChildren();
          const sign = el.querySelector('.rp-sign button'); if (sign) sign.textContent = 'Sign';
          const note = el.querySelector('.rp-sign > p'); if (note) note.textContent = 'Non-binding acknowledgement';
        });
        return x;
      };
      body = h("div", { class: "rp-sign" },
        h("div", { class: "rp-sign-role" }, input("role", "Role")),
        h("label", {}, h("span", {}, "Name"), input("name", "Name", { placeholder: state.settings.display_name })),
        h("label", {}, h("span", {}, "Signature"), h("i", { class: "rp-sign-line" }, b.data.signed ? b.data.name : '')),
        h("label", {}, h("span", {}, "Date"), input("date", "Date", { type: "date", required: true })),
        h("button", { class: "btn small rp-ui", title: "Non-binding acknowledgement", onclick: () => {
          if (b.data.signed) { b.data.signed = false; redraw(); return; }
          b.data.name = String(b.data.name || state.settings.display_name).trim();
          if (!b.data.name || !String(b.data.role || '').trim()) { alert('Enter a name and role before signing.'); return; }
          b.data.date ||= today(); b.data.signed = true; b.data.signedAt = new Date().toISOString(); redraw();
        } }, icon("sign", 14), b.data.signed ? 'Remove acknowledgement' : 'Sign'),
        h('p', { class: 'rp-small' }, b.data.signed ? `Acknowledged ${b.data.signedAt} · Non-binding` : 'Non-binding acknowledgement'));
      break;
    }
    default:
      body = editable("text", b.data.placeholder ?? "Text");
  }
  clear(el, grip, h("div", { class: "rp-block-body" }, body), tools);
  return el;
}

// --- a finding's unusual events (shared by Target, Metric, Log lines and ATT&CK) ---------------------------

interface Ev { id: string; view: string; time: string; server: string; anomaly: number | null; lines?: string[]; own?: boolean[]; flags?: string[] }
const eventsCache = new Map<string, Promise<{ total: number; items: Ev[] }>>();

/** The finding's unusual events, rarest first (fetched once per finding). */
function findingEvents(f: Finding): Promise<{ total: number; items: Ev[] }> {
  let p = eventsCache.get(f.key);
  if (!p) {
    p = fetchEvents(f);
    p.catch(() => eventsCache.delete(f.key));
    eventsCache.set(f.key, p);
  }
  return p;
}

async function fetchEvents(f: Finding): Promise<{ total: number; items: Ev[] }> {
  if (f.kind === "upload") {
    const u = await api(`/api/uploads/item${qs({ id: String(f.upload) })}`);
    const items = u.items.map((i: any): Ev => ({ id: i.item_id, view: i.view, time: i.when, server: i.host, anomaly: i.unusual ?? null, flags: i.flags,
      lines: (i.context ?? []).map((c: any) => c.line), own: (i.context ?? []).map((c: any) => Boolean(c.own)) }));
    return { total: items.length, items };
  }
  if (f.kind === "presence_alert" || f.kind === "activity_alert") {     // firewall activity (one flow), or an activity alert
    const rid = String(f.row_manifest_ids ?? "").split(";")[0].split(":").pop()?.trim() ?? "";
    return { total: 1, items: [{ id: rid, view: f.view, time: f.first_seen ?? "", server: "", anomaly: null, lines: f.lines ?? [] }] };
  }
  const r = await api(`/api/review/flagged${qs({ source: f.source, view: f.view, cluster: f.cluster_id ?? "" })}`);
  if (r.status === "purged") throw new Error("Purged with the data");
  if (r.status !== "ready") throw new Error(`Indexing (${r.status})`);
  return { total: r.total, items: r.items.map((o: any): Ev => ({ id: o.row_id, view: f.view, time: o.time, server: o.server, anomaly: o.anomaly })) };
}

/** Several observations at once, 100 per request. */
async function observations(f: Finding, ids: string[]): Promise<any[]> {
  const out: any[] = [];
  for (let k = 0; k < ids.length; k += 100) {
    const r = await api("/api/review/observations", { body: { source: f.source, view: f.view, ids: ids.slice(k, k + 100) } });
    out.push(...r.observations);
  }
  return out;
}

// --- Target: the anomaly's particulars, as on an incident form ---------------------------------------------

const TARGET_FIELDS: [string, string][] = [
  ["dates", "Date of anomaly"], ["time", "Time"], ["hosts", "No. of servers affected"], ["events", "Unusual events"],
  ["servers", "Servers"], ["accounts", "Accounts"], ["addresses", "Source addresses"], ["log", "Log type"], ["view", "View"], ["period", "Period"],
];

async function fillTarget(b: Block, f: Finding): Promise<void> {
  b.data = { finding: f, fields: { ...(b.data.fields ?? {}) }, loading: true };
  repaint(b);
  const set = (k: string, v: string) => { if (v) b.data.fields[k] = v; };
  const names = (text: string | undefined) => topValues(text, 8).map(([v]) => v).join(", ");
  try {
    const ev = await findingEvents(f);
    const times = ev.items.map((e) => e.time).filter(Boolean).sort();
    const servers = [...new Set(ev.items.map((e) => e.server).filter(Boolean))];
    set("dates", f.first_seen ? dateSpan(f.first_seen, f.last_seen ?? "") : times.length ? dateSpan(times[0], times[times.length - 1]) : "");
    set("time", times.length ? `${times[0].slice(11, 16)} – ${times[times.length - 1].slice(11, 16)}` : "");
    set("hosts", servers.length ? fmt.int(servers.length) : f.top?.host_id || f.top?.hostname ? "1" : "");
    set("servers", servers.length ? servers.slice(0, 10).join(", ") + (servers.length > 10 ? ` (+${servers.length - 10})` : "") : names(f.top?.host_id || f.top?.hostname));
    set("events", fmt.int(ev.total));
    set("accounts", names(f.top?.username));
    set("addresses", names(f.top?.source_ip));
  } catch (e) {
    b.data.error = message(e);
  }
  set("log", state.catalog.sources[f.source]?.label ?? f.source.toUpperCase());
  set("view", f.view_label ?? "");
  set("period", f.kind === "upload" ? "Upload" : f.period === "validation" ? "Validation" : "Test");
  b.data.loading = false;
  repaint(b);
}

function targetBlock(b: Block, el: HTMLElement): HTMLElement {
  const box = h("div", { class: "rp-target" });
  b.data.fields ??= {};
  acceptFinding(el, (f) => fillTarget(b, f));
  live(b, box, () => [
    h("div", { class: "rp-band" }, "Anomaly information"),
    h("div", { class: "rp-target-pick" }, findingPicker(b.data.finding, (f) => fillTarget(b, f)), b.data.loading ? loading() : null,
      b.data.error ? errorBox(new Error(b.data.error)) : null),
    h("div", { class: "rp-form tight" }, TARGET_FIELDS.map(([k, label]) =>
      h("div", { class: `rp-field ${k === "servers" || k === "accounts" || k === "addresses" ? "wide" : ""}` }, h("span", {}, label),
        line(b.data.fields[k] ?? "", label, (v) => { b.data.fields[k] = v; })))),
  ]);
  return box;
}

// --- Metric: dashboard tiles ("Rarity: 1 in 50,000") ------------------------------------------------------

const TILES: Record<string, [string, string]> = {          // label, and what the number is
  rarity: ["Rarity", "rarest event"], events: ["Unusual events", ""], servers: ["Servers", ""], seen: ["Seen", ""],
  detectors: ["Detectors agreeing", "on the rarest event"], lift: ["Flagged vs. usual", "times its view's rate"], custom: ["Label", ""],
};

async function fillMetric(b: Block, f: Finding): Promise<void> {
  b.data.finding = f; b.data.values = {}; b.data.loading = true; b.data.error = "";
  repaint(b);
  const v = b.data.values;
  try {
    const ev = await findingEvents(f);
    const top = ev.items[0];
    v.events = fmt.int(ev.total);
    const servers = new Set(ev.items.map((e) => e.server).filter(Boolean));
    v.servers = servers.size ? fmt.int(servers.size) : "—";
    const times = ev.items.map((e) => e.time).filter(Boolean).sort();
    v.seen = f.first_seen ? dateSpan(f.first_seen, f.last_seen ?? "") : times.length ? dateSpan(times[0], times[times.length - 1]) : "—";
    v.lift = f.lift ? `×${fmt.num(f.lift, 1)}` : "—";
    v.rarity = baseline(f.source) && top && top.anomaly !== null ? rarity(top.anomaly).text : "—";
    if (f.kind === "upload") v.detectors = top?.flags ? fmt.int(top.flags.length) : "—";
    else if (baseline(f.source) && top) {
      const [o] = await observations(f, [top.id]);
      const n = (o?.detectors ?? []).filter((d: any) => d.flagged).length;
      v.detectors = o?.detectors?.length ? `${n} of ${o.detectors.length}` : "—";
    } else v.detectors = "—";
  } catch (e) {
    b.data.error = message(e);
  }
  b.data.loading = false;
  repaint(b);
}

function metricBlock(b: Block, el: HTMLElement): HTMLElement {
  const box = h("div", { class: "rp-metric" });
  b.data.tiles ??= [{ kind: "rarity" }];
  b.data.values ??= {};
  acceptFinding(el, (f) => fillMetric(b, f));
  const tileEl = (t: any, k: number) => {
    const value = h("div", { class: "rp-tile-value", contenteditable: "true", "aria-label": "Value" });
    value.textContent = t.value ?? b.data.values[t.kind] ?? "—";
    value.addEventListener("input", () => { t.value = value.textContent ?? ""; });
    const label = h("div", { class: "rp-tile-label", contenteditable: "true", "aria-label": "Label" });
    label.textContent = t.label ?? TILES[t.kind]?.[0] ?? "";
    label.addEventListener("input", () => { t.label = label.textContent ?? ""; });
    return h("div", { class: "rp-tile" }, label, value,
      TILES[t.kind]?.[1] ? h("div", { class: "rp-tile-sub" }, TILES[t.kind][1]) : null,
      h("button", { class: "rp-tile-x rp-ui", title: "Remove", "aria-label": "Remove tile", onclick: () => { b.data.tiles.splice(k, 1); repaint(b); } }, icon("close", 12)));
  };
  live(b, box, () => {
    const add = h("select", { class: "rp-ui", "aria-label": "Add a tile" },
      h("option", { value: "", selected: true, disabled: true }, "+"),
      Object.entries(TILES).map(([k, [label]]) => h("option", { value: k }, k === "custom" ? "Custom" : label))) as HTMLSelectElement;
    add.addEventListener("change", () => { b.data.tiles.push({ kind: add.value }); repaint(b); });
    const kinds = b.data.tiles.map((t: any) => t.kind);
    const notes = [kinds.includes("rarity") ? "rarity" : "", kinds.includes("detectors") || kinds.includes("lift") ? "models" : "",
      b.data.finding && !baseline(b.data.finding.source) ? "presence" : ""].filter(Boolean);
    return [
      h("div", { class: "rp-target-pick" }, findingPicker(b.data.finding, (f) => fillMetric(b, f)), add, b.data.loading ? loading() : null),
      b.data.error ? errorBox(new Error(b.data.error)) : null,
      h("div", { class: "rp-tiles" }, b.data.tiles.map(tileEl)),
      methodNote(notes),
    ];
  });
  return box;
}

// --- Log lines: a finding's unusual events, rarest first, with their original lines -----------------------
// Retrieved with the same read-only calls as Review (the Around query runs through the SQL guardrails and is
// recorded in the activity log) and kept in the block as retrieved, with the time, so the report holds the
// evidence it was written from. Every event can be chosen at once for logs scored against a baseline.

const SHOWN = 8;                             // events listed before "+ more"
const PICKED = 3;                            // events opened with their lines at first
const LINES = 12;                            // an event's own lines shown
const AROUND_ROWS = 300;                     // lines kept from an Around query
const LOGS = ["auth", "ossec", "pf", "ipf"];
const LOG_LABEL: Record<string, string> = { auth: "AUTH", ossec: "OSSEC", pf: "PF", ipf: "IPFilter" };

async function openEvents(b: Block, evs: Ev[]): Promise<void> {
  const d = b.data, f: Finding = d.finding;
  const todo = evs.filter((e) => !d.detail[e.id]);
  if (!todo.length) return;
  if (f.kind === "upload") {                                             // the upload's own lines, already at hand
    for (const ev of todo) d.detail[ev.id] = { server: ev.server, start: ev.time, end: ev.time, anomaly: ev.anomaly, lines: ev.lines, own: ev.own, line_count: ev.lines?.length ?? 0 };
    return repaint(b);
  }
  for (const ev of todo) d.detail[ev.id] = { busy: true };
  repaint(b);
  try {
    const found = await observations(f, todo.map((e) => e.id));
    for (const ev of todo) {
      const o = found.find((x) => x.row_id === ev.id);
      if (!o || o.error) { d.detail[ev.id] = { error: o?.error ?? "Not found." }; continue; }
      const lines = o.lines?.length ? o.lines : ev.lines ?? [];
      d.detail[ev.id] = { server: o.server, start: o.start, end: o.end, anomaly: o.anomaly, lines,
        line_count: o.lines?.length ? o.line_count : f.line_count ?? lines.length };
    }
  } catch (e) {
    for (const ev of todo) d.detail[ev.id] = { error: message(e) };
  }
  repaint(b);
}

/** Every log's lines from the event's server, `before` minutes before it starts to `after` minutes after it ends. */
async function around(b: Block, ev: Ev, before: number | null, after = 0): Promise<void> {
  const d = b.data, f: Finding = d.finding, x = d.detail[ev.id];
  if (before === null) { delete x.around; return repaint(b); }
  const clamp = (n: number) => Math.max(0, Math.min(1440, Math.round(Number(n) || 0)));
  before = clamp(before); after = clamp(after);
  x.around = { before, after, busy: true };
  repaint(b);
  try {
    const r = await api("/api/review/context", { body: { source: f.source, view: ev.view, id: ev.id, before, after, logs: LOGS } });
    const own: string[] = (r.own ?? []).map(String);
    const first = r.rows.findIndex((row: any[]) => own.includes(String(row[5])));          // keep the event's own lines in view
    const lo = first < 0 ? 0 : Math.max(0, Math.min(first - AROUND_ROWS / 4, r.rows.length - AROUND_ROWS));
    x.around = { before, after, rows: r.rows.slice(lo, lo + AROUND_ROWS), total: r.rows.length, own, start: r.observation.start, end: r.observation.end, at: stamp() };
  } catch (e) {
    x.around = { before, after, error: message(e) };
  }
  repaint(b);
}

async function bindLines(b: Block, f: Finding): Promise<void> {
  b.data = { finding: f, detail: {}, picked: [], loading: true };
  repaint(b);
  try {
    b.data.events = await findingEvents(f);
    b.data.at = stamp();
    b.data.picked = b.data.events.items.slice(0, PICKED).map((e: Ev) => e.id);
    b.data.loading = false;
    repaint(b);
    openEvents(b, b.data.events.items.slice(0, PICKED));
  } catch (e) {
    b.data.error = message(e);
    b.data.loading = false;
    repaint(b);
  }
}

/** "−1:30", "during" or "+0:45": a line's time against the event's start and end. */
function offset(t: string, start: string, end: string): string {
  const at = Date.parse(t.replace(" ", "T")), a = Date.parse(start.replace(" ", "T")), z = Date.parse(end.replace(" ", "T"));
  if ([at, a, z].some(Number.isNaN)) return t.slice(11, 19);
  const s = at < a ? (at - a) / 1000 : at > z ? (at - z) / 1000 : 0;
  if (s === 0) return "during";
  const n = Math.abs(Math.round(s));
  return `${s < 0 ? "−" : "+"}${Math.floor(n / 60)}:${String(n % 60).padStart(2, "0")}`;
}

function logLines(b: Block, el: HTMLElement): HTMLElement {
  const box = h("div", { class: "rp-ll" });
  acceptFinding(el, (f) => bindLines(b, f));

  const toggle = (ev: Ev, on: boolean) => {
    const order = b.data.events.items.map((e: Ev) => e.id);
    b.data.picked = on ? [...new Set([...b.data.picked, ev.id])].sort((x: string, y: string) => order.indexOf(x) - order.indexOf(y))
      : b.data.picked.filter((x: string) => x !== ev.id);
    if (on) openEvents(b, [ev]);
    repaint(b);
  };
  const eventRow = (ev: Ev) => {
    const on = b.data.picked.includes(ev.id);
    const check = h("input", { type: "checkbox", checked: on, "aria-label": `${ev.time} ${ev.server}` }) as HTMLInputElement;
    check.addEventListener("change", () => toggle(ev, check.checked));
    return h("tr", { class: on ? "on" : "" }, h("td", {}, check), h("td", { class: "mono small" }, ev.time || "—"), h("td", {}, ev.server || "—"),
      h("td", {}, baseline(b.data.finding.source) ? meter(ev.anomaly) : "—"));
  };

  const eventEl = (ev: Ev) => {
    const x = b.data.detail[ev.id], f: Finding = b.data.finding;
    if (!x || x.busy) return h("div", { class: "rp-ll-ev" }, loading());
    if (x.error) return h("div", { class: "rp-ll-ev" }, errorBox(new Error(x.error)));
    const span = x.start === x.end ? x.start : `${x.start} → ${x.end}`;
    const a = x.around;
    const minutes = (value: number, label: string) =>
      h("input", { type: "number", min: "0", max: "1440", step: "1", value: String(value), "aria-label": `${label} (minutes)` }) as HTMLInputElement;
    const before = minutes(a?.before ?? 10, "Before"), after = minutes(a?.after ?? 10, "After");
    const controls = f.kind === "upload" ? null : h("div", { class: "rp-ll-around rp-ui" },
      h("button", { class: `btn small ${a ? "" : "on"}`, onclick: () => around(b, ev, null) }, "Event"),
      h("label", {}, "Before", before, "min"),
      h("label", {}, "After", after, "min"),
      h("button", { class: `btn small ${a ? "primary" : ""}`, disabled: Boolean(a?.busy), onclick: () => around(b, ev, Number(before.value), Number(after.value)) }, icon("data", 14), "Show"));
    let lines: Child;
    if (a?.busy) lines = loading();
    else if (a?.error) lines = errorBox(new Error(a.error));
    else if (a) {
      const own = new Set<string>(a.own);
      lines = [
        h("div", { class: "rp-ll-lines list-scroll" }, a.rows.map((r: any[]) => h("div", { class: `rp-ll-line ${own.has(String(r[5])) ? "own" : "ctx"}` },
          h("span", { class: "t" }, offset(String(r[1]), a.start, a.end)), h("span", { class: "g" }, LOG_LABEL[r[0]] ?? r[0]), h("span", { class: "l" }, String(r[4] ?? "")),
          // the line's SHA-256 from Phase 1 (r[6]): the same line in the original file has the same fingerprint
          r[6] ? h("span", { class: "h", title: `SHA-256 ${r[6]}` }, String(r[6]).slice(0, 12)) : null))),
        h("div", { class: "rp-small" }, a.total > a.rows.length ? `${fmt.int(a.rows.length)} of ${fmt.int(a.total)} lines` : `${fmt.int(a.total)} lines`,
          ` · ${a.before} min before, ${a.after} min after · ${a.at}`)];
    } else {
      const shown: string[] = (x.lines ?? []).slice(0, f.kind === "upload" ? 60 : LINES);
      lines = [
        h("div", { class: "rp-ll-lines list-scroll" }, shown.map((l, n) => h("div", { class: `rp-ll-line ${f.kind !== "upload" ? "" : x.own?.[n] ? "own" : "ctx"}` }, h("span", { class: "t" }, String(n + 1)), h("span", { class: "l" }, l)))),
        x.line_count > shown.length ? h("div", { class: "rp-small" }, `${shown.length} of ${fmt.int(x.line_count)} lines`) : null];
    }
    return h("div", { class: "rp-ll-ev" },
      h("div", { class: "rp-ll-ev-head" }, h("span", { class: "who-chip server" }, x.server || "server unknown"), h("span", { class: "mono small" }, span || "—"),
        x.anomaly !== null && x.anomaly !== undefined ? h("span", { class: "end" }, meter(x.anomaly)) : null),
      controls, lines);
  };

  live(b, box, () => {
    const d = b.data;
    if (!d.finding) return findingPicker(undefined, (f) => bindLines(b, f));
    const f: Finding = d.finding;
    const head = h("div", { class: "rp-ll-head" }, icon(f.kind === "upload" ? "uploads" : "review", 16),
      h("div", { class: "rp-ll-title" }, h("strong", {}, f.title), h("div", { class: "rp-small" }, f.meta)),
      d.at ? h("span", { class: "rp-small row", style: { gap: "4px" }, title: "Retrieved" }, icon("clock", 12), d.at) : null,
      h("button", { class: "icon-btn rp-ui", title: "Finding", "aria-label": "Choose another finding", onclick: () => { b.data = {}; repaint(b); } }, icon("refresh", 14)));
    if (d.error) return [head, errorBox(new Error(d.error))];
    if (!d.events) return [head, loading()];
    const items: Ev[] = d.events.items;
    const listed = d.more ? items : items.slice(0, SHOWN);
    let all: Child = "";
    if (baseline(f.source) && items.length > 1) {                          // every event, for logs scored against a baseline
      const c = h("input", { type: "checkbox", checked: d.picked.length === items.length, "aria-label": "Select all", title: "Select all" }) as HTMLInputElement;
      c.indeterminate = d.picked.length > 0 && d.picked.length < items.length;
      c.addEventListener("change", () => {
        d.picked = c.checked ? items.map((e) => e.id) : [];
        if (c.checked) { d.more = true; openEvents(b, items); }
        repaint(b);
      });
      all = c;
    }
    const picker = items.length > 1 ? h("div", { class: "table-wrap rp-ll-list rp-ui" }, h("table", { class: "obs-list" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, all), ["When", "Server", "How rare"].map((c) => h("th", { scope: "col" }, c)))),
      h("tbody", {}, listed.map(eventRow)))) : null;
    const more = items.length > listed.length
      ? h("button", { class: "btn small rp-ui", onclick: () => { d.more = true; repaint(b); } }, icon("plus", 12), fmt.int(items.length - listed.length))
      : d.events.total > items.length ? h("span", { class: "rp-small" }, `${fmt.int(items.length)} rarest of ${fmt.int(d.events.total)}`) : null;
    const open = items.filter((e) => d.picked.includes(e.id));
    return [head, picker, more, d.picked.length > 1 ? h("div", { class: "rp-small" }, `${fmt.int(d.picked.length)} events`) : null,
      open.map(eventEl), methodNote([baseline(f.source) ? "rarity" : "presence"])];
  });
  if (b.data.finding && !b.data.events && !b.data.error && !b.data.loading) bindLines(b, b.data.finding);    // added from a Finding block
  return box;
}

// --- Table: evidence from the database (asked in English, or in SQL), or filled in by hand -----------------
// Query results are kept as run (the query and the time are cited under the table) and are read-only;
// cells, rows and columns can be highlighted and commented on, as in a word processor.

const MODES: [string, string, string, string][] = [
  ["ai", "query-ai", "Ask AI", "Query the database with AI"],
  ["sql", "query-sql", "SQL", "Query the database"],
  ["manual", "table-fill", "Fill in", "Fill in by hand"],
];
const COLORS: [string, string][] = [["yellow", "#fff0a0"], ["green", "#cdeec9"], ["blue", "#d3e4ff"], ["pink", "#ffd3dc"]];
const TABLE_ROWS = 200;

function keyLabel(k: string, cols: string[]): string {
  const [t, a, c] = k.split(":");
  if (t === "r") return `Row ${Number(a) + 1}`;
  if (t === "c") return `Column ${letter(Number(a))}${cols[Number(a)] ? ` · ${cols[Number(a)]}` : ""}`;
  return `Cell ${letter(Number(c))}${Number(a) + 1}`;
}

/** After deleting row or column `at`: drop its highlights and comments and move the later ones up. */
function shiftKeys(d: any, kind: "r" | "c", at: number): void {
  const remap = (k: string): string | null => {
    const [t, a, c] = k.split(":");
    const n = (v: string) => Number(v);
    if (kind === "r") {
      if (t === "r") return n(a) === at ? null : n(a) > at ? `r:${n(a) - 1}` : k;
      if (t === "x") return n(a) === at ? null : n(a) > at ? `x:${n(a) - 1}:${c}` : k;
    } else {
      if (t === "c") return n(a) === at ? null : n(a) > at ? `c:${n(a) - 1}` : k;
      if (t === "x") return n(c) === at ? null : n(c) > at ? `x:${a}:${n(c) - 1}` : k;
    }
    return k;
  };
  const hl: Record<string, string> = {};
  for (const [k, v] of Object.entries(d.hl)) { const m = remap(k); if (m) hl[m] = v as string; }
  d.hl = hl;
  d.comments = d.comments.flatMap((c: any) => { const m = remap(c.key); return m ? [{ ...c, key: m }] : []; });
}

function tableBlock(b: Block): HTMLElement {
  const box = h("div", { class: "rp-tb" });
  const d = b.data;
  d.hl ??= {}; d.comments ??= []; d.columns ??= []; d.rows ??= [];
  let sel: string | null = null;                                     // the selected row, column or cell
  let toolbar: HTMLElement | null = null, table: HTMLElement | null = null;

  const inSel = (i: number | null, j: number | null) => {
    if (!sel) return false;
    const [t, a, c] = sel.split(":");
    return t === "r" ? i === Number(a) : t === "c" ? j === Number(a) : i === Number(a) && j === Number(c);
  };
  const markSelection = () => {
    table?.querySelectorAll<HTMLElement>("[data-i], [data-j]").forEach((el) => {
      const i = el.dataset.i === undefined ? null : Number(el.dataset.i), j = el.dataset.j === undefined ? null : Number(el.dataset.j);
      el.classList.toggle("insel", el.dataset.k === sel || (el.tagName === "TD" && inSel(i, j)));
    });
    box.querySelectorAll<HTMLElement>(".rp-cm").forEach((c) => c.classList.toggle("on", c.dataset.k === sel));
    if (toolbar) clear(toolbar, tools());
  };
  const select = (k: string) => { sel = sel === k ? null : k; markSelection(); };

  const run = async (query: string) => {
    d.busy = true; d.error = ""; repaint(b);
    try {
      const r = await sqlApi("/api/sql", { query });
      d.columns = r.columns.map(String);
      d.rows = r.rows.slice(0, TABLE_ROWS).map((row: unknown[]) => row.map((v) => (v === null || v === undefined ? "" : String(v))));
      d.ran = { sql: query, at: stamp(), total: r.rows.length, truncated: Boolean(r.truncated) || r.rows.length > TABLE_ROWS };
      d.hl = {}; d.comments = []; d.editing = false; sel = null;
    } catch (e) {
      d.error = message(e);
    }
    d.busy = false;
    repaint(b);
  };
  const ask = async (question: string) => {
    d.busy = true; d.error = ""; repaint(b);
    try {
      const r = await api("/api/report/sql", { body: { question } });
      Object.assign(d, { sql: r.sql, note: r.note, rejected: r.rejected });
    } catch (e) {
      d.error = message(e);
    }
    d.busy = false;
    repaint(b);
  };

  function tools(): Child {
    const editable = d.mode === "manual";
    const out: Child[] = [];
    if (editable) out.push(
      h("button", { class: "btn small", onclick: () => { d.rows.push(d.columns.map(() => "")); repaint(b); } }, icon("plus", 12), "Row"),
      h("button", { class: "btn small", onclick: () => { d.columns.push(""); d.rows.forEach((r: string[]) => r.push("")); repaint(b); } }, icon("plus", 12), "Column"));
    if (sel) {
      const k = sel;
      out.push(h("span", { class: "rp-tb-sel" }, keyLabel(k, d.columns)),
        h("span", { class: "rp-swatches", role: "group", "aria-label": "Highlight" },
          COLORS.map(([name, hex]) => h("button", { class: `rp-swatch ${d.hl[k] === hex ? "on" : ""}`, title: cap(name), "aria-label": `Highlight ${name}`, style: { background: hex },
            onclick: () => { d.hl[k] = hex; repaint(b); } })),
          h("button", { class: "rp-swatch none", title: "No highlight", "aria-label": "No highlight", onclick: () => { delete d.hl[k]; repaint(b); } })),
        h("button", { class: "btn small", onclick: () => {
          d.comments.push({ id: id(), key: k, text: "", author: state.settings.display_name, at: stamp() });
          repaint(b);
          box.querySelector<HTMLElement>(".rp-cm:last-child .rp-cm-text")?.focus();
        } }, icon("comment", 14), "Comment"));
      const [t, a] = k.split(":");
      if (editable && (t === "r" || t === "c")) out.push(h("button", { class: "btn small", onclick: () => {
        if (t === "r") d.rows.splice(Number(a), 1);
        else { d.columns.splice(Number(a), 1); d.rows.forEach((r: string[]) => r.splice(Number(a), 1)); }
        shiftKeys(d, t as "r" | "c", Number(a)); sel = null; repaint(b);
      } }, icon("close", 12), t === "r" ? "Row" : "Column"));
    }
    return out;
  }

  const queryArea = (): Child => {
    const glyph = MODES.find(([m]) => m === d.mode)![1];
    if (d.ran && !d.editing) {
      return h("div", { class: "rp-tb-cite" }, icon(glyph, 14),
        h("span", {}, `Source: ${d.mode === "ai" ? "query written by the local model, checked and run" : "query run"} ${d.ran.at} · ${fmt.int(d.ran.total)}${d.ran.truncated ? "+" : ""} rows${d.ran.truncated ? ` (first ${TABLE_ROWS} shown)` : ""}`),
        h("details", {}, h("summary", { class: "rp-ui" }, "SQL"), h("pre", {}, d.ran.sql)),
        h("button", { class: "btn small rp-ui", onclick: () => { d.editing = true; d.sql ??= d.ran.sql; repaint(b); } }, icon("query-sql", 14), "Edit"));
    }
    const sqlBox = h("textarea", { class: "rp-tb-sql", rows: 5, spellcheck: "false", "aria-label": "SQL query", placeholder: "SELECT …" }) as HTMLTextAreaElement;
    sqlBox.value = d.sql ?? "";
    sqlBox.addEventListener("input", () => { d.sql = sqlBox.value; });
    const runBtn = h("button", { class: "btn small primary", disabled: Boolean(d.busy), onclick: () => run(sqlBox.value) }, icon("play", 14), "Run");
    const parts: Child[] = [];
    if (d.mode === "ai") {
      const q = h("textarea", { rows: 2, "aria-label": "Question", placeholder: "Question" }) as HTMLTextAreaElement;
      q.value = d.question ?? "";
      q.addEventListener("input", () => { d.question = q.value; });
      parts.push(h("div", { class: "rp-tb-ask" }, q,
        h("button", { class: "btn small", disabled: Boolean(d.busy), title: state.settings.llm_model, onclick: () => ask(q.value) }, icon("sparkle", 14), "Write query")));
    }
    if (d.mode === "sql" || d.sql) {
      parts.push(sqlBox,
        d.note ? h("div", { class: "rp-small" }, icon("sparkle", 12), " ", d.note) : null,
        d.rejected ? h("div", { class: "rp-warn" }, icon("alert", 14), d.rejected) : null,
        h("div", { class: "row", style: { gap: "6px" } }, runBtn,
          d.ran ? h("button", { class: "btn small", onclick: () => { d.editing = false; repaint(b); } }, "Cancel") : null));
    }
    return h("div", { class: "rp-tb-query rp-ui" }, parts, d.busy ? loading() : null, d.error ? errorBox(new Error(d.error)) : null);
  };

  const grid = (): Child => {
    const editable = d.mode === "manual";
    if (!d.columns.length) return null;
    const commented = new Set(d.comments.map((c: any) => c.key));
    const tint = (i: number | null, j: number) => (i !== null ? d.hl[`x:${i}:${j}`] ?? d.hl[`r:${i}`] : undefined) ?? d.hl[`c:${j}`] ?? "";
    const cell = (tag: "td" | "th", value: string, i: number | null, j: number, save: (v: string) => void) => {
      const k = i === null ? `c:${j}` : `x:${i}:${j}`;
      const c = h(tag, { "data-i": i === null ? undefined : String(i), "data-j": String(j), "data-k": i === null ? undefined : k,
        class: commented.has(k) ? "commented" : "", contenteditable: editable ? "true" : undefined,
        style: i === null ? { boxShadow: tint(i, j) ? `inset 0 -5px 0 ${tint(i, j)}` : "" } : { background: tint(i, j) } });   // a header keeps its band
      c.textContent = value;
      c.addEventListener("input", () => save(c.textContent ?? ""));
      if (i !== null) c.addEventListener("focus", () => { if (sel !== k) select(k); });
      if (i !== null) c.addEventListener("click", () => { if (!editable) select(k); });
      return c;
    };
    table = h("table", {},
      h("thead", {},
        h("tr", { class: "rp-tb-letters rp-ui" }, h("th", {}), d.columns.map((_: string, j: number) =>
          h("th", { "data-k": `c:${j}`, "data-j": String(j), class: commented.has(`c:${j}`) ? "commented" : "", onclick: () => select(`c:${j}`), title: keyLabel(`c:${j}`, d.columns) }, letter(j)))),
        h("tr", {}, h("th", { class: "rp-tb-corner" }), d.columns.map((c: string, j: number) => cell("th", c, null, j, (v) => { d.columns[j] = v; })))),
      h("tbody", {}, d.rows.map((row: string[], i: number) => h("tr", {},
        h("th", { class: `rp-tb-rowno rp-ui ${commented.has(`r:${i}`) ? "commented" : ""}`, "data-k": `r:${i}`, "data-i": String(i), onclick: () => select(`r:${i}`), title: keyLabel(`r:${i}`, d.columns) }, String(i + 1)),
        row.map((v, j) => cell("td", v, i, j, (x) => { row[j] = x; }))))));
    const comments = d.comments.length ? h("aside", { class: "rp-cms" }, d.comments.map((c: any, n: number) => {
      const text = h("div", { class: "rp-cm-text", contenteditable: "true", role: "textbox", "aria-label": "Comment", "data-placeholder": "Comment" });
      text.textContent = c.text;
      text.addEventListener("input", () => { c.text = text.textContent ?? ""; });
      return h("div", { class: `rp-cm ${c.key === sel ? "on" : ""}`, "data-k": c.key, onclick: (e: Event) => { if ((e.target as HTMLElement).tagName !== "BUTTON") { sel = c.key; markSelection(); } } },
        h("div", { class: "rp-cm-head" }, h("strong", {}, c.author || "—"), h("span", {}, c.at),
          h("button", { class: "icon-btn rp-ui", title: "Remove", "aria-label": "Remove comment", onclick: () => { d.comments.splice(n, 1); repaint(b); } }, icon("close", 12))),
        h("div", { class: "rp-cm-on" }, keyLabel(c.key, d.columns)), text);
    })) : null;
    return h("div", { class: `rp-tb-grid ${comments ? "with-comments" : ""}` }, h("div", { class: "rp-tb-wrap" }, table), comments);
  };

  live(b, box, () => {
    box.classList.toggle("query", d.mode === "ai" || d.mode === "sql");
    if (!d.mode) {
      return h("div", { class: "rp-tb-modes rp-ui" }, MODES.map(([m, glyph, label, title]) =>
        h("button", { class: "rp-tb-mode", title, onclick: () => {
          d.mode = m;
          if (m === "manual") { d.ran = undefined; if (!d.columns.length) { d.columns = ["", "", ""]; d.rows = [["", "", ""], ["", "", ""]]; } }
          repaint(b);
        } }, icon(glyph, 30), h("span", {}, label))));
    }
    const glyph = MODES.find(([m]) => m === d.mode)!;
    toolbar = h("div", { class: "rp-tb-tools rp-ui" });
    const out = [
      h("div", { class: "rp-tb-bar rp-ui" }, h("span", { class: "rp-tb-kind", title: glyph[3] }, icon(glyph[1], 16), glyph[2]),
        h("button", { class: "icon-btn", title: "Mode", "aria-label": "Change how the table is filled", onclick: () => { d.mode = undefined; repaint(b); } }, icon("refresh", 14)), toolbar),
      d.mode !== "manual" ? queryArea() : null,
      grid(),
    ];
    queueMicrotask(markSelection);
    return out;
  });
  return box;
}

// --- MITRE ATT&CK: the technique the activity resembles, chosen by the analyst or suggested by the model ----

let attack: any = null;                     // the offline copy, once loaded
let attackLoading: Promise<void> | null = null;
function loadAttack(): Promise<void> {
  return (attackLoading ??= api("/api/attack").then((a) => { attack = a; }, (e) => { attackLoading = null; throw e; }));
}

async function evidenceText(d: any): Promise<string> {
  const parts: string[] = [d.description ?? ""];
  const f: Finding | undefined = d.finding;
  if (f) {
    parts.push(`Finding: ${f.title} (${f.meta})`);
    const ev = await findingEvents(f);
    const top = ev.items.slice(0, 5);
    if (f.kind === "upload") top.forEach((e) => parts.push(...(e.lines ?? []).filter((_, n) => e.own?.[n]).slice(0, 6)));
    else (await observations(f, top.map((e) => e.id))).forEach((o) => parts.push(...(o.lines?.length ? o.lines : f.lines ?? []).slice(0, 6)));
  }
  return parts.filter(Boolean).join("\n").slice(0, 6000);
}

function attackBlock(b: Block, el: HTMLElement): HTMLElement {
  const box = h("div", { class: "rp-att" });
  const d = b.data;
  d.techniques ??= []; d.description ??= "";
  acceptFinding(el, (f) => { d.finding = f; repaint(b); });
  const add = (tid: string, by: "analyst" | "ai", extra: Record<string, unknown> = {}) => {
    if (!d.techniques.some((t: any) => t.id === tid)) d.techniques.push({ id: tid, by, note: "", ...extra });
    repaint(b);
  };
  const match = async () => {
    d.busy = true; d.error = ""; d.similar = null; repaint(b);
    let evidence = "";
    try {
      evidence = await evidenceText(d);
      const r = await api("/api/report/attack", { body: { evidence } });
      r.matches.forEach((m: any) => add(m.id, "ai", { confidence: m.confidence, note: m.reason }));
      if (!r.matches.length) d.error = "The local model found no technique that fits.";
    } catch (e) {
      d.error = message(e);
      if (evidence) d.similar = await api("/api/report/attack/similar", { body: { evidence } }).then((r) => r.candidates).catch(() => null);
    }
    d.busy = false;
    repaint(b);
  };

  live(b, box, () => {
    if (!attack) {
      loadAttack().then(() => repaint(b), (e) => { d.error = message(e); repaint(b); });
      return d.error ? errorBox(new Error(d.error)) : loading();
    }
    const byId: Record<string, any> = Object.fromEntries(attack.techniques.map((t: any) => [t.id, t]));
    const tactic: Record<string, string> = Object.fromEntries(attack.tactics.map((t: any) => [t.short, t.name]));
    const card = (t: any, k: number) => {
      const T = byId[t.id];
      if (!T) return null;
      const note = h("div", { class: "rp-text small", contenteditable: "true", "data-placeholder": "Why it matches", role: "textbox" });
      note.textContent = t.note ?? "";
      note.addEventListener("input", () => { t.note = note.textContent ?? ""; });
      return h("div", { class: `rp-tt ${t.by}` },
        h("div", { class: "rp-tt-tactics" }, T.tactics.map((s: string) => h("span", {}, tactic[s] ?? s))),
        h("div", { class: "rp-tt-head" }, h("strong", {}, `${T.id} · ${T.name}`),
          t.by === "ai" ? h("span", { class: "rp-tt-ai rp-ui" }, icon("sparkle", 12), `AI · ${t.confidence}`,
            h("button", { class: "btn small", title: "Accept", "aria-label": `Accept ${T.id}`, onclick: () => { t.by = "analyst"; repaint(b); } }, icon("check", 12))) : null,
          h("button", { class: "icon-btn rp-ui", title: "Remove", "aria-label": `Remove ${T.id}`, onclick: () => { d.techniques.splice(k, 1); repaint(b); } }, icon("close", 12))),
        h("p", { class: "rp-tt-desc" }, T.description),
        note,
        /^https:\/\/attack\.mitre\.org\//.test(T.url ?? "")                       // anything else stays text, never a link
          ? h("a", { class: "rp-small", href: T.url, target: "_blank", rel: "noreferrer noopener" }, T.url)
          : h("span", { class: "rp-small" }, T.url ?? ""));
    };
    // the search keeps its own list, so typing does not redraw the block
    const results = h("div", { class: "rp-att-results" });
    const search = h("input", { type: "search", placeholder: "Technique, ID or tactic", "aria-label": "Search ATT&CK" }) as HTMLInputElement;
    const pick = h("select", { "aria-label": "Tactic" }, h("option", { value: "" }, "All tactics"), attack.tactics.map((t: any) => h("option", { value: t.short }, t.name))) as HTMLSelectElement;
    const listResults = () => {
      const q = search.value.trim().toLowerCase();
      if (!q && !pick.value) return clear(results);
      const found = attack.techniques.filter((t: any) => (!pick.value || t.tactics.includes(pick.value))
        && (!q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.tactics.some((s: string) => (tactic[s] ?? s).toLowerCase().includes(q)))).slice(0, 10);
      clear(results, found.map((t: any) => h("button", { class: "rp-att-hit", onclick: () => add(t.id, "analyst") }, h("strong", {}, t.id), " ", t.name,
        h("span", { class: "rp-small" }, " · ", t.tactics.map((s: string) => tactic[s] ?? s).join(", ")))));
    };
    search.addEventListener("input", listResults);
    pick.addEventListener("change", listResults);
    const describe = h("textarea", { rows: 2, "aria-label": "What happened", placeholder: "What happened" }) as HTMLTextAreaElement;
    describe.value = d.description;
    describe.addEventListener("input", () => { d.description = describe.value; });
    return [
      d.techniques.length ? h("div", { class: "rp-tts" }, d.techniques.map(card)) : null,
      h("div", { class: "rp-att-tools rp-ui" },
        h("div", { class: "rp-att-find" }, icon("matrix", 16), search, pick), results,
        h("div", { class: "rp-att-ai" }, findingPicker(d.finding, (f) => { d.finding = f; repaint(b); }), describe,
          h("button", { class: "btn small", disabled: Boolean(d.busy), title: state.settings.llm_model, onclick: match }, icon("sparkle", 14), "Match with AI")),
        d.busy ? loading() : null,
        d.error ? h("div", { class: "rp-warn" }, icon("alert", 14), d.error) : null,
        d.similar?.length ? h("div", { class: "rp-att-similar" }, h("span", { class: "rp-small" }, "Closest by wording"),
          d.similar.map((tid: string) => byId[tid] ? h("button", { class: "rp-att-hit", onclick: () => add(tid, "analyst") }, h("strong", {}, tid), " ", byId[tid].name) : null)) : null),
      h("div", { class: "rp-method" }, h("p", {},
        h("strong", {}, "MITRE ATT&CK."), ` Techniques from ATT&CK Enterprise v${attack.version}, kept on this laptop. `,
        "A technique marked AI was suggested by the local model from the finding's lines and the description, choosing only among the techniques closest in wording; an analyst should confirm it. ",
        attack.notice)),
    ];
  });
  return box;
}

// --- report visuals: saved evidence, not live queries on reopen ---------------------------------------

function timelineBlock(b: Block, el: HTMLElement): HTMLElement {
  const box = h('div');
  const fill = async (f: Finding) => {
    b.data.finding = f; b.data.loading = true; b.data.error = ''; repaint(b);
    try {
      const result = await findingEvents(f);
      b.data.entries = result.items.map(e => ({ time: e.time, title: `${e.server} · ${e.view}`, note: '', anomaly: e.anomaly, id: e.id }));
      b.data.total = result.total; b.data.retrieved = stamp();
    } catch (e) { b.data.error = message(e); }
    b.data.loading = false; repaint(b);
  };
  acceptFinding(el, fill);
  live(b, box, () => [
    findingPicker(b.data.finding, fill),
    h('div', { class: 'row rp-ui' }, h('button', { class: 'btn small', title: 'Analyst event', 'aria-label': 'Add analyst event', onclick: () => { (b.data.entries ??= []).push({ time: '', title: '', note: '', manual: true }); repaint(b); } }, icon('plus', 12), icon('clock', 14))),
    b.data.loading ? loading() : null, b.data.error ? errorBox(new Error(b.data.error)) : null,
    h('ol', { class: 'rp-timeline-events' }, [...(b.data.entries ?? [])].sort((a: any, c: any) => a.time.localeCompare(c.time)).map((e: any) =>
      h('li', { class: e.manual ? 'manual' : '', title: e.manual ? 'Analyst event' : `Observation ${e.id}` },
        h('div', { class: 'rp-tl-time' }, line(e.time, 'Timeline time', v => { e.time = v; }, 'YYYY-MM-DD HH:MM')),
        h('div', { class: 'rp-tl-what' }, line(e.title, 'Timeline event', v => { e.title = v; }, 'Event'), line(e.note, 'Timeline note', v => { e.note = v; }, 'Note')),
        h('span', { class: 'rp-tl-rare' }, e.anomaly !== null && e.anomaly !== undefined ? rarity(e.anomaly).text : ''),
        h('button', { class: 'icon-btn rp-ui', title: 'Remove', 'aria-label': 'Remove timeline event', onclick: () => { b.data.entries.splice(b.data.entries.indexOf(e), 1); repaint(b); } }, icon('close', 12))))),
    b.data.retrieved ? h('p', { class: 'rp-small rp-caption' }, `Retrieved ${b.data.retrieved} · ${b.data.entries?.filter((e: any) => !e.manual).length ?? 0} of ${fmt.int(b.data.total ?? 0)} events · local time`) : null,
    (b.data.entries ?? []).some((e: any) => e.anomaly !== null && e.anomaly !== undefined) ? methodNote(['rarity']) : null,
  ]);
  return box;
}

// The report map is drawn on paper (always light), in the console map's colours.
const MAP_COLOURS = { frame: '#e7e2dd', ink: '#141414', test: '#a29a9366', testKey: '#a29a93', validation: '#26222266', validationKey: '#262222',
  flagged: '#e01b1bb0', flaggedKey: '#e01b1b', target: '#f5c400', targetEdge: '#6b5200' };

function mapBlock(b: Block, el: HTMLElement): HTMLElement {
  const box = h('div');
  const pick = async (f: Finding) => {
    b.data = { finding: f, loading: true, layout: b.data.layout ?? 'tsne' }; repaint(b);
    try { b.data.events = await findingEvents(f); b.data.picked = b.data.events.items.map((e: Ev) => e.id); }
    catch (e) { b.data.error = message(e); }
    b.data.loading = false; repaint(b);
  };
  acceptFinding(el, pick);
  const drawMap = async () => {
    const f: Finding = b.data.finding;
    if (!f || !b.data.picked?.length) return;
    b.data.loading = true; b.data.error = ''; repaint(b);
    try {
      const view = b.data.view || f.view || b.data.events.items[0]?.view;
      const ids = b.data.events.items.filter((e: Ev) => e.view === view && b.data.picked.includes(e.id)).map((e: Ev) => e.id);
      const { job } = await api('/api/reports/map', { body: { source: f.source, view, ids, layout: b.data.layout ?? 'tsne', upload: f.upload } });
      for (;;) {
        const r = await api(`/api/analyze/job${qs({ id: job })}`);
        if (r.status === 'failed') throw new Error(r.error);
        if (r.status === 'done') { b.data.map = r.result; b.data.retrieved = stamp(); break; }
        b.data.progress = r.steps.at(-1)?.detail ?? 'Preparing map'; repaint(b);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (e) { b.data.error = message(e); }
    b.data.loading = false; repaint(b);
  };
  function picture(m: any): HTMLElement {
    const canvas = h('canvas', { width: 1200, height: 670, class: 'rp-map-image', 'aria-label': 'Test and validation cluster map with numbered target observations' });
    const c = canvas.getContext('2d')!;
    c.fillStyle = '#ffffff'; c.fillRect(0, 0, 1200, 670);
    const mapped = m.targets.filter((t: any) => Number.isFinite(t.x) && Number.isFinite(t.y));
    const xs: number[] = [...m.baseline.x, ...mapped.map((t: any) => t.x)], ys: number[] = [...m.baseline.y, ...mapped.map((t: any) => t.y)];
    const xmin = xs.reduce((a, x) => Math.min(a, x), Infinity), xmax = xs.reduce((a, x) => Math.max(a, x), -Infinity);
    const ymin = ys.reduce((a, x) => Math.min(a, x), Infinity), ymax = ys.reduce((a, x) => Math.max(a, x), -Infinity);
    const x = (v: number) => 45 + (v-xmin) / (xmax-xmin || 1) * 1100;
    const y = (v: number) => 600 - (v-ymin) / (ymax-ymin || 1) * 550;
    c.strokeStyle = MAP_COLOURS.frame; c.lineWidth = 1.5; c.strokeRect(40, 35, 1110, 570);
    m.baseline.x.forEach((v: number, i: number) => { c.fillStyle = m.baseline.flagged[i] ? MAP_COLOURS.flagged : m.baseline.period[i] === 'validation' ? MAP_COLOURS.validation : MAP_COLOURS.test; c.fillRect(x(v), y(m.baseline.y[i]), 2.4, 2.4); });
    c.font = 'bold 18px "Times New Roman"';
    m.targets.forEach((t: any, i: number) => {
      if (!Number.isFinite(t.x) || !Number.isFinite(t.y)) return;
      c.beginPath(); c.arc(x(t.x), y(t.y), 8, 0, 2*Math.PI); c.fillStyle = MAP_COLOURS.target; c.fill(); c.strokeStyle = MAP_COLOURS.targetEdge; c.lineWidth = 2; c.stroke();
      c.fillStyle = MAP_COLOURS.ink; c.fillText(String(i+1), x(t.x)+10, y(t.y)-8);
    });
    // the legend, in the figure itself so it travels with the exported image
    c.font = '17px "Times New Roman"'; c.textBaseline = 'middle';
    let lx = 40;
    c.fillStyle = MAP_COLOURS.ink; c.font = 'bold 17px "Times New Roman"'; c.fillText(m.layout === 'umap' ? 'UMAP' : 't-SNE', lx, 638); lx += 70;
    c.font = '17px "Times New Roman"';
    for (const [label, fill, edge] of [['test', MAP_COLOURS.testKey, ''], ['validation', MAP_COLOURS.validationKey, ''], ['flagged', MAP_COLOURS.flaggedKey, ''], ['target', MAP_COLOURS.target, MAP_COLOURS.targetEdge]]) {
      c.beginPath(); c.arc(lx + 6, 638, 6, 0, 2 * Math.PI); c.fillStyle = fill; c.fill();
      if (edge) { c.strokeStyle = edge; c.lineWidth = 2; c.stroke(); }
      c.fillStyle = MAP_COLOURS.ink; c.fillText(label, lx + 18, 638); lx += 30 + c.measureText(label).width + 22;
    }
    return canvas;
  }
  live(b, box, () => {
    const f: Finding | undefined = b.data.finding, m = b.data.map;
    const events: Ev[] = b.data.events?.items ?? [];
    const baselineLog = f && baseline(f.source);
    return [findingPicker(f, pick), f && !baselineLog ? methodNote(['presence']) : null,
      baselineLog ? h('div', { class: 'rp-ui' },
        h('select', { class: 'rp-select', 'aria-label': 'Report map layout', onchange: (e: Event) => { b.data.layout = (e.target as HTMLSelectElement).value; } },
          ['tsne', 'umap'].map(v => h('option', { value: v, selected: v === (b.data.layout ?? 'tsne') }, v === 'tsne' ? 't-SNE' : 'UMAP'))),
        f?.kind === 'upload' ? h('select', { class: 'rp-select', 'aria-label': 'Report map view', onchange: (e: Event) => { b.data.view = (e.target as HTMLSelectElement).value; } },
          [...new Set(events.map(e => e.view))].map(v => h('option', { value: v, selected: v === b.data.view }, v))) : null,
        h('button', { class: 'btn small primary', disabled: !!b.data.loading, onclick: drawMap }, icon('play', 14), 'Draw'),
        h('details', {}, h('summary', {}, `Targets · ${b.data.picked?.length ?? 0} of ${b.data.events?.total ?? 0}`),
          h('div', { class: 'list-scroll' }, events.map(e => h('label', { class: 'row small' },
            h('input', { type: 'checkbox', checked: b.data.picked?.includes(e.id), onchange: (v: Event) => {
              if ((v.target as HTMLInputElement).checked) b.data.picked.push(e.id); else b.data.picked = b.data.picked.filter((id: string) => id !== e.id);
            } }), `${e.time} · ${e.server} · ${rarity(e.anomaly).text}`))))) : null,
      b.data.loading ? loading(b.data.progress ?? 'Loading targets') : null,
      b.data.error ? errorBox(new Error(b.data.error)) : null,
      m ? [picture(m), h('p', { class: 'rp-map-caption rp-small rp-caption' }, [state.catalog.sources[m.source]?.label ?? m.source.toUpperCase(),
          state.catalog.sources[m.source]?.views.find((v) => v.id === m.view)?.label ?? m.view,
          `${fmt.int(m.baseline.x.length)} of ${fmt.int(m.baseline_total)} points`, `retrieved ${b.data.retrieved}`,
          m.missing.length ? `${m.missing.length} not placed` : ''].filter(Boolean).join(' · ')),
        h('table', { class: 'rp-map-targets' }, h('thead', {}, h('tr', {}, ['Target', 'When / server', 'How rare', 'Position'].map(v => h('th', {}, v)))),
          h('tbody', {}, m.targets.map((t: any, i: number) => h('tr', {}, h('td', {}, String(i+1)), h('td', {}, `${t.time} · ${t.server}`), h('td', {}, rarity(t.anomaly).text), h('td', {}, t.placement))))),
        h('div', { class: 'rp-map-lines' }, m.targets.map((t: any, i: number) => h('div', { class: 'rp-map-target' },
          h('div', { class: 'rp-map-target-head' }, h('span', { class: 'rp-map-no' }, String(i + 1)), h('strong', {}, `${t.time} · ${t.server}`), h('span', { class: 'end' }, meter(t.anomaly))),
          h('div', { class: 'rp-ll-lines' }, (t.lines ?? []).map((l: string, n: number) => h('div', { class: 'rp-ll-line' },
            h('span', { class: 't' }, t.line_rarity?.[n] !== null && t.line_rarity?.[n] !== undefined ? rarity(t.line_rarity[n]).text : '\u2014'), h('span', { class: 'l' }, l)))),
          t.line_count > (t.lines?.length ?? 0) ? h('div', { class: 'rp-small' }, `${t.lines.length} of ${fmt.int(t.line_count)} lines`) : null))),
        methodNote(['map', 'rarity', 'models'])] : null];
  });
  return box;
}

// --- the findings to build from: reviewed items first, then the rest -----------------------------------

/** A Review item (from /api/review/queue, with its source added) as a finding. */
function findingOf(i: any): Finding {
  return {
    key: `${i.source}/${i.view}/${i.item_id}`, title: i.kind === "cluster" ? (i.renamed ? i.name : groupName(i.name))
      : i.kind === "activity_alert" ? i.name : `Firewall activity #${i.rank}`,
    meta: [i.source.toUpperCase(), i.view_label, i.period === "validation" ? "validation" : "", i.first_seen].filter(Boolean).join(" · "),
    verdict: i.review?.verdict ?? null, source: i.source, view: i.view, view_label: i.view_label, period: i.period, kind: i.kind, item_id: i.item_id,
    cluster_id: i.cluster_id, row_manifest_ids: i.row_manifest_ids, lines: i.lines, line_count: i.line_count,
    flagged_rows: i.flagged_rows, lift: i.lift, first_seen: i.first_seen, last_seen: i.last_seen, top: i.top,
  };
}

async function loadFindings(box: HTMLElement): Promise<void> {
  clear(box, h("div", { class: "tiny muted" }, "…"));
  const search = h("input", { type: "search", placeholder: "Filter", "aria-label": "Filter findings" }) as HTMLInputElement;
  const list = h("div", { class: "rp-find-list" });
  let all: Finding[] = [];
  try {
    const sources = Object.keys(state.catalog.sources);
    const queues = await Promise.all(sources.map((s) => api(`/api/review/queue${qs({ source: s })}`).then((r) => r.items.map((i: any) => ({ ...i, source: s }))).catch(() => [])));
    const uploads = await api("/api/uploads").then((r) => r.uploads).catch(() => []);
    all = [
      ...queues.flat().map(findingOf),
      ...uploads.map((u: any): Finding => ({ key: `upload/${u.id}`, title: `Upload #${u.id} · ${u.name}`, meta: `${u.source.toUpperCase()} · ${fmt.int(u.items)} events`,
        verdict: null, source: u.source, view: "", kind: "upload", item_id: String(u.id), upload: u.id })),
    ].sort((a, b) => Number(!a.verdict) - Number(!b.verdict));
    known = all;
    painters.forEach((paint) => paint());                // blocks waiting for the list
  } catch { /* the list stays empty */ }
  const draw = () => clear(list, all.filter((f) => !search.value || `${f.title} ${f.meta}`.toLowerCase().includes(search.value.toLowerCase())).slice(0, 80)
    .map((f) => {
      const card = h("div", { class: "rp-find", draggable: "true", title: f.title },
        h("div", { class: "row", style: { justifyContent: "space-between", flexWrap: "nowrap", gap: "6px" } },
          h("strong", {}, f.title), f.verdict ? verdictBadge(f.verdict) : null),
        h("div", { class: "tiny muted" }, f.meta));
      card.addEventListener("dragstart", (e) => { dragging = { kind: "finding", finding: f }; e.dataTransfer?.setData("text/plain", f.key); });
      card.addEventListener("dragend", () => { dragging = null; });
      return card;
    }));
  search.addEventListener("input", draw);
  clear(box, search, list);
  draw();
}
