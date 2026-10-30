// Sigma (Advanced, after Analyze): detection rules in the Sigma format (service/sigma.py), run over logs Phase 1 can
// read. Input as on Analyze → Run: every rule that is on, hits below, most serious first. The rules on the left, each
// stamped with who added it and when; the chosen one on the right, written three ways: the form (the default:
// sigma-form.ts), Describe (plain English, drafted by the local model: service/sigma_ai.py) or the YAML. Whichever way,
// a draft goes Draft → Test → Accept: Test runs it alone on the input above (in place of its saved version), and Accept
// stays locked until the draft as it now stands has been tested. Rules change no score and no review; a hit whose
// accounts are all whitelisted says so.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, keepScroll, loading, select, table } from "../dom";
import { icon } from "../icons";
import { sqlLoader } from "../loaders";
import { blankForm, isNew, LEVEL_LABEL, LEVEL_TONE, ruleCard, ruleForm, SOURCE_SHORT, stamp, type RuleForm } from "../sigma-form";
import { sourceLabel, state } from "../state";
import { LOG_FILES, readLogFile } from "../tables";
import { whitelistBadge } from "../verdicts";

type Mode = "paste" | "file" | "path";
type Way = "form" | "describe" | "yaml";
const LEVELS = ["critical", "high", "medium", "low", "informational"];

// New rules start from one of these; each is a complete, working rule for the Solaris authentication log.
const TEMPLATES: [string, string][] = [
  ["Event", `title: New rule
status: experimental
logsource:
  product: solaris
  service: sshd
detection:
  selection:
    event_type: SSH_LOGIN_FAILED
    username:
      - root
      - admin
  condition: selection
level: medium
tags:
  - attack.credential-access
  - attack.t1110.001
`],
  ["Count", `title: Failed login
name: my_failed_login
logsource:
  product: solaris
  service: sshd
detection:
  selection:
    event_type: SSH_LOGIN_FAILED
  condition: selection
level: informational
---
title: Many failed logins from one address
correlation:
  type: event_count
  rules:
    - my_failed_login
  group-by:
    - source_ip
    - host
  timespan: 5m
  condition:
    gte: 10
level: medium
tags:
  - attack.credential-access
  - attack.t1110.001
`],
  ["Distinct", `title: Invalid user
name: my_invalid_user
logsource:
  product: solaris
  service: sshd
detection:
  selection:
    event_type: SSH_INVALID_USER
  condition: selection
level: informational
---
title: Many invalid users from one address
correlation:
  type: value_count
  rules:
    - my_invalid_user
  group-by:
    - source_ip
  timespan: 1h
  condition:
    gte: 5
    field: username
level: medium
tags:
  - attack.credential-access
  - attack.t1110.001
`],
  ["Sequence", `title: Failed root login
name: my_root_failed
logsource:
  product: solaris
  service: sshd
detection:
  selection:
    event_type: SSH_LOGIN_FAILED
    username: root
  condition: selection
level: informational
---
title: Root login
name: my_root_success
logsource:
  product: solaris
  service: sshd
detection:
  selection:
    event_type: SSH_LOGIN_SUCCESS
    username: root
  condition: selection
level: informational
---
title: Root login right after a failure
correlation:
  type: temporal_ordered
  rules:
    - my_root_failed
    - my_root_success
  group-by:
    - source_ip
    - host
  timespan: 10m
level: high
tags:
  - attack.initial-access
  - attack.t1078.003
`],
];

const form = { mode: "paste" as Mode, source: "auto", month: new Date().toISOString().slice(0, 7), host: "", text: "", fileName: "", path: "" };
const st = {
  entries: [] as any[], fields: {} as Record<string, string[]>, eventTypes: {} as Record<string, string[]>,
  leftOpen: false,                           // a folder's run: the files left out, shown (kept while hits redraw)
  selected: null as number | null,           // the entry in the editor; null: a new rule
  way: "form" as Way,                        // how the draft is written
  form: blankForm("auth") as RuleForm,       // the form's fields (way "form", and filled by Describe when it can)
  missing: [] as string[],                   // the form's required fields still empty
  pending: false,                            // the form changed and its YAML is on the way
  describe: { text: "", source: "", busy: false, error: "", model: "", tries: 0 },
  draft: "", saved: "",                      // the YAML to test and accept, and the text the entry was opened with
  dirty: false,                              // typed into since opened
  tested: "", testHits: null as number | null,   // the draft a test last ran to the end on, and its hits
  check: null as any,                        // the draft as the engine reads it (and its form, or null), or { error }
  result: null as any, level: "all", open: new Set<number>(),
  attack: {} as Record<string, string>,      // technique ID → name (offline ATT&CK data)
};
/** Nothing typed that would be lost. */
const pristine = () => !st.dirty || st.draft === st.saved;
const defaultSource = () => (form.source !== "auto" ? form.source : "auth");
let ui: Record<string, HTMLElement> = {};
let checkSeq = 0, checkTimer = 0, previewSeq = 0, previewTimer = 0;
let markMissing: (missing: string[]) => void = () => undefined;

/** What DAD's logs can see of ATT&CK for ICS (service/coverage.py): one column per tactic, a chip per technique,
 * coloured by visibility; the chip's tooltip names the data components and which log gives each. */
function coverageCard(): HTMLElement {
  const box = h("div", {}, loading());
  const LABEL: Record<string, string> = { visible: "Visible", partly: "Partly", planned: "With event logs", blind: "Not visible", none: "None listed" };
  api("/api/attack/ics").then((m: any) => {
    const chip = (t: any) => h("a", {
      class: `cov-chip cov-${t.status}`, href: t.url, target: "_blank", rel: "noopener noreferrer",
      title: `${t.id} ${t.name}\n${t.components.map((c: any) => `${c.name}: ${c.by.join(", ") || (c.planned.length ? `(${c.planned.join(", ")})` : "—")}`).join("\n") || "No detection listed"}`,
    }, t.name);
    clear(box,
      h("div", { class: "row cov-legend" }, (Object.keys(LABEL)).map((s) => h("span", { class: `cov-key cov-${s}` }, h("i"), LABEL[s], h("strong", {}, fmt.int(m.counts[s])))),
        h("span", { class: "tiny muted end" }, `${m.source} v${m.version}`)),
      h("div", { class: "cov-matrix list-scroll" }, m.tactics.map((tactic: any) =>
        h("div", { class: "cov-col" }, h("div", { class: "cov-head" }, tactic.name), tactic.techniques.map(chip)))),
      h("div", { class: "tiny muted", style: { marginTop: "8px" } }, m.notice));
  }).catch((e) => clear(box, errorBox(e)));
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("target")), h("h2", {}, "ATT&CK for ICS")), box);
}

/** The enabled rules over the training period (service/sigma_review.training): a match there was learned as normal. */
function trainingCard(): HTMLElement {
  const box = h("div");
  const go = h("button", { class: "btn small" }, icon("play", 14), "Check") as HTMLButtonElement;
  const draw = async (): Promise<void> => {
    let s: any;
    try { s = await api("/api/sigma/training"); } catch (e) { clear(box, errorBox(e)); return; }
    go.disabled = s.state === "running";
    const sources = Object.entries(s.sources ?? {}) as [string, any][];
    clear(box,
      s.state === "running" ? h("div", { class: "row small muted" }, loading(), s.progress) : null,
      s.state === "failed" ? errorBox(new Error(s.progress)) : null,
      sources.length ? table(["Log", "Events", "Rules matched", ""], sources.map(([source, r]) => [
        source.toUpperCase(), badge(fmt.int(r.events), r.events ? "warn" : "ok"),
        h("span", { class: "small" }, Object.entries(r.rules as Record<string, number>).map(([title, n]) => `${title} (${fmt.int(n)})`).join(" · ") || "—"),
        r.current ? h("span", { class: "tiny muted mono" }, String(r.checked_at).replace("T", " ").slice(0, 16)) : badge("outdated", "muted")]))
        : null);
    if (s.state === "running") setTimeout(() => void draw(), 3000);
  };
  go.addEventListener("click", () => { go.disabled = true; api("/api/sigma/training", { body: {} }).then(() => draw()).catch((e) => clear(box, errorBox(e))); });
  void draw();
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("history")), h("h2", {}, "Training period"), h("span", { class: "end" }, go)),
    box);
}

export function renderSigma(main: HTMLElement): void {
  const run = h("button", { class: "btn primary" }, icon("play", 16), "Run") as HTMLButtonElement;
  run.addEventListener("click", () => void start(run, ""));
  ui = { list: h("div", { class: "sg-list list-scroll" }), editor: h("div", { class: "card sg-editor" }), hits: h("div"), listHead: h("div") };
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Sigma"))),
    inputCard(run),
    h("div", { class: "grid split sg-work" },
      h("div", { class: "card sg-rules" }, rulesHead(), ui.listHead, ui.list),
      ui.editor),
    ui.hits,
    trainingCard(),
    coverageCard());
  drawEditor();
  drawHits();
  void load();
  if (!Object.keys(st.attack).length) {
    api("/api/attack").then((a) => {
      st.attack = Object.fromEntries((a.techniques ?? []).map((t: any) => [t.id, t.name]));
      drawList(); drawHits();
      if (!st.dirty) drawEditor();                       // the form's ATT&CK suggestions
    }).catch(() => undefined);
  }
}

async function load(): Promise<void> {
  try {
    const r = await api("/api/sigma/rules");
    const first = !Object.keys(st.fields).length;
    st.entries = r.entries;
    st.fields = r.fields;
    st.eventTypes = r.event_types ?? {};
    drawList();
    if (first && !st.dirty) drawEditor();                // the form's log types and fields
    else drawFields();
  } catch (e) {
    clear(ui.list, errorBox(e));
  }
}

// --- input: as Analyze -----------------------------------------------------------------------------

function inputCard(run: HTMLButtonElement): HTMLElement {
  const textarea = h("textarea", { rows: 6, spellcheck: "false", placeholder: "Paste log lines…", "aria-label": "Log lines" }) as HTMLTextAreaElement;
  textarea.value = form.text;
  textarea.addEventListener("input", () => { form.text = textarea.value; form.fileName = ""; drawFlow(); });
  const fileInfo = h("span", { class: "small muted" }, form.fileName);
  const fileInput = h("input", { type: "file", accept: LOG_FILES, "aria-label": "Log file" }) as HTMLInputElement;
  const hostInput = h("input", { type: "text", value: form.host, placeholder: "OSSEC only", style: { width: "150px" }, "aria-label": "Server" }) as HTMLInputElement;
  hostInput.addEventListener("input", () => (form.host = hostInput.value.trim()));
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    try {
      form.text = await readLogFile(file);
    } catch (e) {
      clear(fileInfo, errorBox(e));
      return;
    }
    form.fileName = file.name;
    const m = /ossec[_-]?logs?[_-]([^.\\/]+)/i.exec(file.name);
    if (m && !form.host) { form.host = m[1].toLowerCase(); hostInput.value = form.host; }
    clear(fileInfo, `${file.name} · ${(file.size / 1e6).toFixed(1)} MB`);
    drawFlow();
  });
  const pathInput = h("input", { type: "text", value: form.path, placeholder: "C:\\logs\\authlog_host.txt  ·  C:\\logs\\2026\\  ·  .gz  ·  .zip  ·  .csv  ·  .xlsx", style: { width: "100%" }, "aria-label": "File or folder path" }) as HTMLInputElement;
  pathInput.addEventListener("input", () => { form.path = pathInput.value; drawFlow(); });
  const monthInput = h("input", { type: "month", value: form.month, "aria-label": "Month" }) as HTMLInputElement;
  monthInput.addEventListener("change", () => (form.month = monthInput.value));

  const body = h("div");
  const drawBody = () => clear(body,
    form.mode === "paste" ? textarea : null,
    form.mode === "file" ? h("div", { class: "row" }, fileInput, fileInfo) : null,
    form.mode === "path" ? pathInput : null);
  drawBody();
  const modes: [Mode, string][] = [["paste", "Paste"], ["file", "Upload"], ["path", "On this laptop"]];
  const modePills = h("div", { class: "pills small", role: "tablist" });
  const drawModes = () => clear(modePills, modes.map(([m, label]) => h("button", {
    class: form.mode === m ? "on" : "", role: "tab", "aria-selected": String(form.mode === m),
    onclick: () => { form.mode = m; drawModes(); drawBody(); drawFlow(); },
  }, label)));
  drawModes();
  const sources: [string, string][] = [["auto", "Detect"], ...Object.keys(state.catalog.sources).map((k) => [k, `${SOURCE_SHORT[k] ?? k.toUpperCase()} · ${sourceLabel(k)}`] as [string, string])];
  return ui.input = h("div", { class: "card" },
    h("div", { class: "row", style: { justifyContent: "space-between", marginBottom: "14px" } }, modePills,
      h("div", { class: "row", style: { alignItems: "flex-end" } },
        h("label", { class: "field" }, h("span", {}, "Log type"), select(sources, form.source, (v) => { form.source = v; drawFields(); })),
        h("label", { class: "field", title: "Syslog lines carry no year" }, h("span", {}, "Month"), monthInput),
        h("label", { class: "field" }, h("span", {}, "Server"), hostInput),
        run)),
    body);
}

function inputBody(): Record<string, string> {
  const fromPath = form.mode === "path";
  return { text: fromPath ? "" : form.text, path: fromPath ? form.path : "", source: form.source, month: form.month, host: form.host,
    name: fromPath ? "" : form.fileName || "Pasted lines" };
}

async function follow(job: string, onStep: (detail: string) => void): Promise<any> {
  for (;;) {
    const s = await api(`/api/analyze/job${qs({ id: job })}`);
    const last = s.steps[s.steps.length - 1];
    if (last) onStep(last.detail);
    if (s.status === "done") return s.result;
    if (s.status === "failed") throw new Error(s.error);
    await new Promise((r) => setTimeout(r, 400));
  }
}

/** Run every rule that is on (draft ""), or the draft alone in place of its saved version. */
async function start(button: HTMLButtonElement, draft: string): Promise<void> {
  button.disabled = true;
  const loader = sqlLoader(draft ? "Test" : "Sigma");
  clear(ui.hits, h("div", { class: "card" }, loader.el));
  ui.hits.scrollIntoView({ behavior: "smooth", block: "nearest" });
  try {
    const { job } = await api("/api/sigma/run", { body: { ...inputBody(), draft, entry: draft ? st.selected ?? 0 : 0 } });
    const result = await follow(job, (detail) => loader.say(draft ? `Test · ${detail}` : `Sigma · ${detail}`));
    await loader.arrive();
    st.result = result;
    st.level = "all";
    st.open.clear();
    if (draft) {
      st.tested = draft;
      st.testHits = result.hits.length;
    }
    drawHits();
    drawList();
    drawFields();
    drawFlow();
  } catch (e) {
    await loader.fail();
    clear(ui.hits, h("div", { class: "card" }, errorBox(e)));
  } finally {
    button.disabled = false;
  }
}

// --- small pieces ------------------------------------------------------------------------------------

const levelBadge = (level: string) => badge(LEVEL_LABEL[level] ?? level, LEVEL_TONE[level] ?? "muted");

function kindChip(d: any): HTMLElement {
  return h("span", { class: `sg-kind k-${d.kind}` }, d.kind_label, d.window ? h("small", {}, d.window) : null);
}

function techChip(id: string): HTMLElement {
  return h("span", { class: "sg-tech", title: st.attack[id] ?? id }, id);
}

const unique = <T,>(xs: T[]) => [...new Set(xs)];

/** The document an entry reports: the last one that no other document in it uses. */
function mainDoc(entry: any): any {
  const used = new Set(entry.docs.flatMap((d: any) => d.refs));
  const own = entry.docs.filter((d: any) => ![d.name, d.id, d.title].some((k: string) => k && used.has(k)));
  return own[own.length - 1] ?? entry.docs[entry.docs.length - 1] ?? null;
}

/** Hits per saved entry in the last full run (a test's hits belong to the draft). */
function hitsByEntry(): Map<number, number> | null {
  if (!st.result || st.result.draft) return null;
  const counts = new Map<number, number>();
  for (const r of st.result.rules) counts.set(r.entry, (counts.get(r.entry) ?? 0) + r.hits);
  return counts;
}

// --- the rules ---------------------------------------------------------------------------------------

function rulesHead(): HTMLElement {
  const files = h("input", { type: "file", accept: ".yml,.yaml", multiple: true, hidden: true, "aria-label": "Sigma files" }) as HTMLInputElement;
  files.addEventListener("change", async () => {
    const problems: string[] = [];
    for (const file of Array.from(files.files ?? [])) {
      try {
        await api("/api/sigma/rules", { body: { yaml: await file.text() } });
      } catch (e) {
        problems.push(`${file.name}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    files.value = "";
    clear(ui.listHead, problems.length ? errorBox(problems.join("\n")) : null);
    await load();
  });
  const exportAll = async () => {
    const out = await api("/api/sigma/export");
    const link = h("a", { href: URL.createObjectURL(new Blob([out.yaml], { type: "text/yaml" })), download: "sigma-rules.yml" });
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  };
  return h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("sigma")), h("h2", {}, "Rules"),
    h("span", { class: "end" },
      h("button", { class: "btn small", onclick: () => openEntry(null) }, icon("plus", 14), "New"),
      h("button", { class: "btn small", onclick: () => files.click() }, icon("upload", 14), "Import"), files,
      h("button", { class: "icon-btn small", title: "Export", "aria-label": "Export", onclick: () => void exportAll() }, icon("download", 15))));
}

function drawList(): void {
  if (!ui.list) return;
  const counts = hitsByEntry();
  clear(ui.list, st.entries.length ? st.entries.map((e) => ruleRow(e, counts)) : h("div", { class: "pt-empty muted" }, "—"));
}

function ruleRow(e: any, counts: Map<number, number> | null): HTMLElement {
  const d = mainDoc(e);
  const sw = h("input", { type: "checkbox", checked: e.enabled, "aria-label": "On" }) as HTMLInputElement;
  sw.addEventListener("change", async () => {
    try {
      await api("/api/sigma/rules/update", { body: { id: e.id, enabled: sw.checked } });
    } catch (err) {
      clear(ui.listHead, errorBox(err));
    }
    await load();
  });
  const n = counts?.get(e.id);
  return h("div", {
    class: `sg-row ${e.id === st.selected ? "on" : ""} ${e.enabled ? "" : "off"}`, tabindex: "0",
    onclick: () => openEntry(e), onkeydown: (k: KeyboardEvent) => { if (k.key === "Enter") openEntry(e); },
  },
    h("label", { class: "pt-switch", title: e.enabled ? "On" : "Off", onclick: (ev: Event) => ev.stopPropagation() }, sw, h("span")),
    h("div", { class: "sg-row-main" },
      h("div", { class: "sg-row-title" }, d?.title ?? "—", e.docs.length > 1 ? h("span", { class: "sg-docs", title: "Documents" }, String(e.docs.length)) : null),
      h("div", { class: "sg-chips" },
        e.error ? badge("Error", "bad") : d ? [levelBadge(d.level), kindChip(d)] : null,
        unique(e.docs.flatMap((x: any) => x.sources)).map((s: any) => h("span", { class: "sg-src" }, SOURCE_SHORT[s] ?? s)),
        unique(e.docs.flatMap((x: any) => x.techniques)).map((t: any) => techChip(t)),
        e.missing?.length ? badge(`Missing ${e.missing.join(", ")}`, "bad") : null),
      h("div", { class: "sg-stamp-row" }, stamp(e.added_by, e.added_at), isNew(e.added_by, e.added_at) ? badge("New", "info") : null)),
    n === undefined ? null : h("span", { class: `sg-row-hits ${n ? "on" : ""}`, title: "Hits" }, fmt.int(n)));
}

function openEntry(e: any | null): void {
  if (!pristine() && !confirm("Discard the changes?")) return;
  st.selected = e ? e.id : null;
  st.draft = st.saved = e ? e.yaml : "";
  st.way = !e || e.form ? "form" : "yaml";
  st.form = e?.form ? structuredClone(e.form) : blankForm(defaultSource());
  st.describe = { text: "", source: form.source !== "auto" ? form.source : "", busy: false, error: "", model: "", tries: 0 };
  st.missing = [];
  st.check = null;
  st.dirty = false;
  st.tested = "";
  st.testHits = null;
  clear(ui.listHead);
  drawList();
  drawEditor();
}

// --- the editor --------------------------------------------------------------------------------------

function drawEditor(): void {
  const entry = st.entries.find((e) => e.id === st.selected) ?? null;
  for (const key of ["yaml", "fields", "preview", "ai", "ways"]) delete ui[key];
  markMissing = () => undefined;
  ui.check = h("div", { class: "sg-check" });
  ui.flow = h("div", { class: "sg-flow" });
  ui.saveErr = h("div");
  ui.ways = h("div", { class: "pills small sg-ways", role: "tablist" });
  const remove = entry ? h("button", { class: "icon-btn small", title: "Delete", "aria-label": "Delete", onclick: () => void deleteEntry(entry) }, icon("trash", 14)) : null;
  clear(ui.editor,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("sigma")),
      h("h2", {}, entry ? mainDoc(entry)?.title ?? "Rule" : "New rule"),
      entry ? stamp(entry.added_by, entry.added_at) : null, entry?.updated_at ? stamp(entry.updated_by, entry.updated_at, true) : null,
      h("span", { class: "end" }, remove)),
    ui.ways,
    st.way === "form" ? formBody() : st.way === "describe" ? describeBody() : yamlBody(entry),
    ui.flow, ui.saveErr);
  drawWays();
  drawCheck();
  drawFlow();
  if (st.way === "form" && !st.draft) schedulePreview(0);   // a new form: its YAML, and the required fields to fill
  else if (st.draft && !st.check) scheduleCheck(0);
}

/** Form, Describe (new rules only) or YAML; the form only for a draft it can show. */
function drawWays(): void {
  if (!ui.ways) return;
  const canForm = st.way === "form" || !st.draft.trim() || Boolean(st.check?.form);
  const ways: [Way, string, string][] = [["form", "table-fill", "Form"], ...(st.selected === null ? [["describe", "sparkle", "Describe"] as [Way, string, string]] : []),
    ["yaml", "patterns", "YAML"]];
  clear(ui.ways, ways.map(([way, glyph, label]) => h("button", {
    type: "button", class: st.way === way ? "on" : "", role: "tab", "aria-selected": String(st.way === way),
    disabled: way === "form" && !canForm, onclick: () => switchWay(way),
  }, icon(glyph, 13), label)));
}

function switchWay(way: Way): void {
  if (way === st.way) return;
  if (way === "form" && st.way !== "form" && st.draft.trim()) {
    if (!st.check?.form) return;
    st.form = structuredClone(st.check.form);
  }
  st.way = way;
  if (way !== "form") st.missing = [];
  drawEditor();
}

function formBody(): HTMLElement {
  const { el, mark } = ruleForm(st.form, { fields: st.fields, eventTypes: st.eventTypes, attack: st.attack,
    onChange: () => { st.dirty = true; schedulePreview(); } });
  markMissing = mark;
  mark(st.missing);
  ui.preview = h("pre", { class: "sg-preview mono", "aria-label": "YAML" }, st.draft);
  return h("div", { class: "sf-split" }, el, h("div", { class: "sf-side" }, ui.preview, ui.check));
}

function describeBody(): HTMLElement {
  const d = st.describe;
  const text = h("textarea", { rows: 3, placeholder: "Five failed root logins over SSH from one address within 10 minutes", "aria-label": "Description" }) as HTMLTextAreaElement;
  text.value = d.text;
  const write = h("button", { class: "btn primary", title: state.settings.llm_model, disabled: d.busy }, icon("sparkle", 15), "Write") as HTMLButtonElement;
  text.addEventListener("input", () => { d.text = text.value; write.disabled = d.busy || !d.text.trim(); });
  text.addEventListener("keydown", (k) => { if (k.key === "Enter" && (k.ctrlKey || k.metaKey)) write.click(); });
  write.disabled = d.busy || !d.text.trim();
  write.addEventListener("click", () => void describeRule(write));
  const sources: [string, string][] = [["", "Any log type"], ...Object.keys(state.catalog.sources).map((k) => [k, SOURCE_SHORT[k] ?? k.toUpperCase()] as [string, string])];
  ui.ai = h("div", { class: "sg-ai" });
  drawAi();
  return h("div", { class: "sg-describe" }, text,
    h("div", { class: "row" }, h("label", { class: "field" }, h("span", {}, "Log type"), select(sources, d.source, (v) => (d.source = v))), write),
    ui.ai);
}

function yamlBody(entry: any | null): HTMLElement {
  const yaml = h("textarea", { class: "sg-yaml", rows: 22, spellcheck: "false", "aria-label": "YAML" }) as HTMLTextAreaElement;
  yaml.value = st.draft;
  yaml.addEventListener("input", () => { st.draft = yaml.value; st.dirty = true; scheduleCheck(); drawFlow(); });
  yaml.addEventListener("keydown", (k) => {                // Tab indents in YAML, as in an editor
    if (k.key !== "Tab") return;
    k.preventDefault();
    yaml.setRangeText("  ", yaml.selectionStart, yaml.selectionEnd, "end");
    yaml.dispatchEvent(new Event("input"));
  });
  ui.yaml = yaml;
  const templates = entry ? null : h("div", { class: "pills small sg-templates", role: "tablist" }, TEMPLATES.map(([label, text]) => h("button", {
    class: st.draft === text ? "on" : "", role: "tab", "aria-selected": String(st.draft === text),
    onclick: () => {
      if (!pristine() && !confirm("Discard the changes?")) return;
      st.draft = text;
      st.dirty = false;
      st.check = null;
      drawEditor();
    },
  }, label)));
  ui.fields = h("div", { class: "sg-fields" });
  drawFields();
  return h("div", {}, templates, yaml, ui.check, ui.fields);
}

function schedulePreview(delay = 300): void {
  st.pending = true;
  drawFlow();
  clearTimeout(previewTimer);
  previewTimer = window.setTimeout(() => void previewForm(), delay);
}

/** The form as YAML (service/sigma_form.py), the required fields still empty, and how the engine reads it. */
async function previewForm(): Promise<void> {
  const seq = ++previewSeq;
  try {
    const r = await api("/api/sigma/form", { body: { form: st.form } });
    if (seq !== previewSeq) return;
    st.draft = r.yaml;
    st.missing = r.missing;
    st.check = r.missing.length ? null : r.error ? { error: r.error } : { docs: r.docs, form: st.form };
  } catch (e) {
    if (seq !== previewSeq) return;
    st.check = { error: e instanceof Error ? e.message : String(e) };
  }
  st.pending = false;
  if (ui.preview) ui.preview.textContent = st.draft;
  markMissing(st.missing);
  drawCheck();
  drawFlow();
}

async function describeRule(button: HTMLButtonElement): Promise<void> {
  const d = st.describe;
  d.busy = true;
  d.error = "";
  button.disabled = true;
  const loader = sqlLoader("AI");
  loader.say(state.settings.llm_model);
  if (ui.ai) clear(ui.ai, loader.el);
  try {
    const r = await api("/api/sigma/describe", { body: { text: d.text, source: d.source } });
    await loader.arrive();
    Object.assign(d, { model: r.model, tries: r.tries });
    st.draft = r.yaml;
    st.dirty = true;
    st.missing = [];
    st.check = r.error ? { error: r.error } : { docs: r.docs, form: r.form };
    if (r.form) st.form = r.form;
  } catch (e) {
    await loader.fail();
    d.error = e instanceof Error ? e.message : String(e);
  }
  d.busy = false;
  button.disabled = false;
  drawAi();
  drawWays();
  drawCheck();
  drawFlow();
}

/** Describe's preview: the draft as a card (when the form can show it) beside its YAML, and the model that wrote it. */
function drawAi(): void {
  if (!ui.ai || st.describe.busy) return;
  const d = st.describe;
  if (d.error) return clear(ui.ai, errorBox(d.error));
  if (!d.model || !st.draft) return clear(ui.ai);
  const shown = st.check?.form as RuleForm | undefined;
  clear(ui.ai,
    h("div", { class: "sg-ai-head" }, h("span", { class: "sg-ai-model mono" }, icon("sparkle", 13), d.model), d.tries > 1 ? badge(`${d.tries} tries`, "muted") : null,
      h("span", { class: "end" }, h("button", { class: "btn small", onclick: () => switchWay(shown ? "form" : "yaml") }, icon("table-fill", 14), "Edit"))),
    h("div", { class: "sf-split" }, shown ? ruleCard(shown) : null, h("div", { class: "sf-side" }, h("pre", { class: "sg-preview mono", "aria-label": "YAML" }, st.draft), ui.check)));
}

/** What a test runs on: the input above. */
function inputSummary(): [string, string, string] | null {
  if (form.mode === "path") {
    const path = form.path.trim();
    return path ? ["folder", path.split(/[\\/]/).filter(Boolean).pop() ?? path, path] : null;
  }
  const lines = form.text.split("\n").filter((l) => l.trim()).length;
  if (!lines) return null;
  const name = form.fileName || "Pasted lines";
  return [form.mode === "file" ? "upload" : "paste", `${name} · ${fmt.int(lines)}`, name];
}

/** Draft → Test → Accept. Accept opens only once the draft as it now stands has been tested. */
function drawFlow(): void {
  if (!ui.flow) return;
  const reads = Boolean(st.draft.trim()) && !st.pending && Boolean(st.check) && !st.check.error && !st.missing.length;
  const tested = reads && st.tested === st.draft;
  const changed = st.draft !== st.saved;
  const data = inputSummary();
  const test = h("button", { class: `btn small ${reads && !tested && data ? "primary" : ""}`, disabled: !reads || !data }, icon("play", 14), "Test") as HTMLButtonElement;
  test.addEventListener("click", () => void start(test, st.draft));
  const accept = h("button", { class: `btn small ${tested && changed ? "primary" : ""}`, disabled: !(tested && changed) },
    icon(tested ? "check" : "lock", 14), "Accept") as HTMLButtonElement;
  accept.addEventListener("click", () => void acceptDraft(accept));
  const step = (n: number, mode: string, ...body: (HTMLElement | null)[]) =>
    h("div", { class: `sg-step ${mode}` }, h("span", { class: "sg-step-n" }, mode === "done" ? icon("check", 12) : String(n)), ...body);
  const focusInput = () => {
    ui.input?.scrollIntoView({ behavior: "smooth", block: "center" });
    ui.input?.querySelector<HTMLElement>("textarea, input[type=text], input[type=file]")?.focus();
  };
  clear(ui.flow,
    step(1, reads ? "done" : st.check?.error ? "bad" : "now", h("span", { class: "sg-step-label" }, "Draft")),
    h("span", { class: "sg-step-line" }),
    step(2, tested ? "done" : reads ? "now" : "", test,
      data ? h("span", { class: "sg-data", title: data[2] }, icon(data[0], 13), data[1])
        : h("button", { type: "button", class: "sg-data none", onclick: focusInput }, icon("paste", 13), "No data"),
      tested && st.testHits !== null ? h("span", { class: `sg-thr sg-test-hits ${st.testHits ? "on" : ""}` }, h("small", {}, "hits"), fmt.int(st.testHits)) : null),
    h("span", { class: "sg-step-line" }),
    step(3, tested && changed ? "now" : "", accept));
}

function scheduleCheck(delay = 400): void {
  clearTimeout(checkTimer);
  checkTimer = window.setTimeout(() => void checkDraft(), delay);
}

async function checkDraft(): Promise<void> {
  const seq = ++checkSeq;
  try {
    const r = await api("/api/sigma/check", { body: { yaml: st.draft } });
    if (seq !== checkSeq) return;
    st.check = r;
  } catch (e) {
    if (seq !== checkSeq) return;
    st.check = { error: e instanceof Error ? e.message : String(e) };
  }
  drawCheck();
  drawWays();
  drawFlow();
}

/** The draft as the engine reads it: one line per document. */
function drawCheck(): void {
  const c = st.check;
  ui.yaml?.classList.toggle("bad", Boolean(c?.error));
  if (!c) return clear(ui.check);
  if (c.error) return clear(ui.check, errorBox(c.error));
  clear(ui.check, c.docs.map((d: any) => h("div", { class: "sg-doc" },
    kindChip(d), h("strong", {}, d.title), levelBadge(d.level),
    d.sources.length ? d.sources.map((s: string) => h("span", { class: "sg-src" }, SOURCE_SHORT[s] ?? s))
      : d.kind === "event" ? badge("No log type", "bad") : null,
    d.process ? h("span", { class: "sg-src" }, d.process) : null,
    d.refs.length ? h("span", { class: "sg-refs mono" }, d.refs.join(d.kind === "temporal_ordered" ? " → " : " + ")) : null,
    d.group_by.length ? h("span", { class: "sg-by" }, h("small", {}, "by"), d.group_by.join(", ")) : null,
    d.threshold ? h("span", { class: "sg-thr mono" }, d.value_field ? `${d.value_field} ${d.threshold}` : d.threshold) : null,
    d.techniques.map((t: string) => techChip(t)))));
}

/** Phase 1's fields for the log type in use: a click writes one at the cursor. */
function drawFields(): void {
  if (!ui.fields) return;
  const source = st.result?.source ?? (form.source !== "auto" ? form.source : "auth");
  const names = st.fields[source] ?? [];
  clear(ui.fields, names.length ? [h("span", { class: "sg-src" }, SOURCE_SHORT[source] ?? source),
    names.map((f) => h("button", { class: "sg-field mono", onclick: () => {
      const y = ui.yaml as HTMLTextAreaElement;
      y.focus();
      y.setRangeText(f, y.selectionStart, y.selectionEnd, "end");
      y.dispatchEvent(new Event("input"));
    } }, f))] : null);
}

/** Keep the tested draft: a new entry, stamped with who added it and when, or the edited one. */
async function acceptDraft(button: HTMLButtonElement): Promise<void> {
  if (st.tested !== st.draft) return;
  button.disabled = true;
  clear(ui.saveErr);
  try {
    const entry = st.selected === null
      ? await api("/api/sigma/rules", { body: { yaml: st.draft } })
      : await api("/api/sigma/rules/update", { body: { id: st.selected, yaml: st.draft } });
    st.selected = entry.id;
    st.draft = st.saved = st.tested = entry.yaml;
    st.dirty = false;
    st.way = entry.form ? "form" : "yaml";
    if (entry.form) st.form = structuredClone(entry.form);
    st.check = null;
    await load();
    drawEditor();
    ui.list.querySelector(".sg-row.on")?.scrollIntoView({ block: "nearest" });   // the new rule and its stamp
  } catch (e) {
    clear(ui.saveErr, errorBox(e));
    button.disabled = false;
  }
}

async function deleteEntry(entry: any): Promise<void> {
  if (!confirm(`Delete ${mainDoc(entry)?.title ?? "this rule"}?`)) return;
  try {
    await api("/api/sigma/rules/delete", { body: { id: entry.id } });
  } catch (e) {
    clear(ui.saveErr, errorBox(e));
    return;
  }
  st.dirty = false;
  await load();
  openEntry(null);
}

// --- hits --------------------------------------------------------------------------------------------

function when(hit: any): string {
  const a: string = hit.first ?? "", b: string = hit.last ?? "";
  if (!a) return "—";
  if (!b || b === a) return a.slice(5, 19);
  return `${a.slice(5, 19)} → ${b.slice(a.slice(0, 10) === b.slice(0, 10) ? 11 : 5, 19)}`;
}

/** A folder's run: each log type and month checked together, and the files left out with why. */
function folderStrip(folder: any): HTMLElement {
  return h("div", { class: "sg-folder" },
    h("div", { class: "sg-chips" }, folder.groups.map((g: any) => h("span", { class: "sg-kv mono", title: `${fmt.int(g.recognised)} / ${fmt.int(g.lines)} lines` },
      h("small", {}, SOURCE_SHORT[g.source] ?? g.source), `${g.month} · ${fmt.int(g.files)} files · ${fmt.int(g.lines)} lines`))),
    folder.left.length ? h("details", { class: "sg-left", open: st.leftOpen, ontoggle: (e: Event) => { st.leftOpen = (e.currentTarget as HTMLDetailsElement).open; } },
      h("summary", { class: "small muted" }, `Left out · ${fmt.int(folder.left.length)}`),
      h("ul", {}, folder.left.map((x: any) => h("li", {}, h("span", { class: "mono" }, x.path), h("span", { class: "muted" }, x.reason))))) : null);
}

function drawHits(): void {
  if (!ui.hits) return;
  const r = st.result;
  if (!r) return clear(ui.hits);
  const counts = new Map<string, number>();
  r.hits.forEach((x: any) => counts.set(x.level, (counts.get(x.level) ?? 0) + 1));
  const shown = r.hits.map((x: any, i: number) => [x, i]).filter(([x]: any) => st.level === "all" || x.level === st.level);
  const levels = h("div", { class: "pills small", role: "tablist" },
    [["all", "All", r.hits.length] as [string, string, number], ...LEVELS.filter((l) => counts.get(l)).map((l) => [l, LEVEL_LABEL[l], counts.get(l)!] as [string, string, number])]
      .map(([v, label, n]) => h("button", {
        class: st.level === v ? "on" : "", role: "tab", "aria-selected": String(st.level === v),
        onclick: () => { st.level = v; drawHits(); },
      }, label, h("span", { class: "pt-tab-n" }, fmt.int(n)))));
  const rows = shown.flatMap(([x, i]: any) => {
    const open = st.open.has(i);
    const row = h("tr", { class: `sg-hit ${open ? "on" : ""} ${x.whitelisted ? "wl" : ""}`, onclick: () => {
      if (open) st.open.delete(i); else st.open.add(i);
      keepScroll(ui.hits, drawHits);                       // the list stays where it was
    } },
      h("td", {}, levelBadge(x.level)),
      h("td", {}, h("div", { class: "sg-hit-title" }, x.title, x.whitelisted ? whitelistBadge() : null),
        h("div", { class: "sg-chips" }, kindChip(x))),
      h("td", {}, h("div", { class: "sg-chips" }, x.techniques.map((t: string) => techChip(t)))),
      h("td", {}, h("div", { class: "sg-chips" }, Object.entries(x.group).map(([k, v]) =>
        h("span", { class: "sg-kv mono", title: k }, h("small", {}, k), String(v || "—"))))),
      h("td", { class: "mono small sg-when" }, when(x)),
      h("td", { class: "sg-num" }, fmt.int(x.events)));
    const detail = open ? h("tr", { class: "sg-detail" }, h("td", { colspan: "6" },
      h("div", { class: "sg-lines" }, x.lines.map((l: any) => h("div", { class: `sg-line ${l.file ? "f" : ""}` },
        l.file ? h("span", { class: "sg-file", title: l.file }, l.file) : null,
        h("span", { class: "sg-n" }, String(l.n)), h("span", { class: "sg-et" }, l.event_type), h("span", { class: "mono" }, l.line))),
      x.more ? h("div", { class: "small muted" }, `+ ${fmt.int(x.more)}`) : null))) : null;
    return [row, detail];
  });
  clear(ui.hits, h("div", { class: "card sg-hits" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(r.draft ? "play" : "alert")), h("h2", {}, r.draft ? "Test" : "Hits"),
      h("span", { class: "end" },
        (r.folder ? [...new Set<string>(r.folder.groups.map((g: any) => g.source))] : [r.source]).map((s) => badge(SOURCE_SHORT[s] ?? s, "dark")),
        r.folder ? h("span", { class: "small muted", title: r.folder.path }, `${fmt.int(r.folder.files)} files`) : null,
        h("span", { class: "small muted" }, `${fmt.int(r.recognised)} / ${fmt.int(r.lines)} lines`),
        r.span.first ? h("span", { class: "small muted mono" }, `${r.span.first.slice(0, 16)} → ${r.span.last.slice(0, 16)}`) : null)),
    r.broken.length ? errorBox(r.broken.map((b: any) => b.error).join("\n")) : null,
    r.folder ? folderStrip(r.folder) : null,
    r.draft ? h("div", { class: "sg-test-rules" }, r.rules.map((d: any) => h("div", { class: "sg-doc" },
      kindChip(d), h("strong", {}, d.title),
      d.error ? badge(d.error, "bad") : !d.applies ? badge("Other log type", "muted") : null,
      d.matched !== null ? h("span", { class: "sg-thr" }, h("small", {}, "matched"), fmt.int(d.matched)) : null,
      d.helper ? null : h("span", { class: "sg-thr" }, h("small", {}, "hits"), fmt.int(d.hits)),
      d.untimed ? badge(`${fmt.int(d.untimed)} without time`, "warn") : null))) : null,
    r.hits.length ? levels : null,
    shown.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "sg-hit-table" },
        h("thead", {}, h("tr", {}, ["Level", "Rule", "ATT&CK", "Group", "When", "Events"].map((c) => h("th", { scope: "col" }, c)))),
        h("tbody", {}, rows)))
      : h("div", { class: "pt-empty" }, icon("check", 30))));
}
