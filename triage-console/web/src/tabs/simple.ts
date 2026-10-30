// Simple mode (US-35): one flow for the people who run the servers. Upload → Analyze → Map → Review,
// one main button per step. An upload sent for review is kept on this laptop (service/uploads.py)
// with the uploaded lines around each unusual event, so it can be reviewed later, here or by the
// reviewer it was sent to (Waiting for you). Sending opens a mail draft with a summary and no log
// lines (NFR-SEC-01, decision Q28); once SSO is set up the reviewer is their signed-in account.
// Logs Phase 1 knows next to nothing of (under 5% of the first lines) stop at Upload: they need new
// patterns first, made in Advanced → Patterns, where the lines are handed over.

import { api, qs } from "../api";
import { buildGroups, clusterMap, layoutFor, loadMap, mapInfoOrNone, type ClusterMap, type InputPoint } from "../cluster-map";
import { badge, clear, errorBox, fmt, h, keepScroll, loading, note } from "../dom";
import { icon, viewIcon } from "../icons";
import { sqlLoader, type Loader } from "../loaders";
import { lrtLine } from "../lrt-line";
import { sourceLabel, updateSettings } from "../state";
import { LOG_FILES, readLogFile } from "../tables";
import { openInPatterns } from "./patterns";
import { VERDICTS, sigmaBadge, verdictBadge, whitelistBadge } from "../verdicts";
import { eventName, groupName, rarity } from "../words";
import { filterBar, filterQuery, matchesFacts, linkedReports } from '../review-filters';

const STEPS = ["Upload", "Analyze", "Map", "Review"];
const STOPS: [string, string][] = [["phase1", "Classify"], ["phase2", "Group"], ["phase4", "Score"], ["map", "Place"]];
const LOG_TYPES: [string, string][] = [["auth", "AUTH"], ["ossec", "OSSEC"], ["pf", "PF"], ["ipf", "IPFilter"]];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const blank = () => ({ step: 0, text: "", fileName: "", size: 0, pasting: false, source: "", month: "", host: "",
  result: null as any, error: "", running: false, upload: 0, sentTo: "",
  coverage: null as number | null, negligible: false, family: "", sample: 0, layout: null as any, raw: "" });
let sm = blank();
let trainAt = 0;                       // the station the journey's train stood at when last drawn
let analysis: Loader | null = null;    // the running analysis's animation, kept if the page is redrawn meanwhile

// --- the stepper ------------------------------------------------------------------------------------

export function renderSimple(main: HTMLElement): void {
  const reached = sm.upload ? 3 : sm.result ? 2 : sm.text ? 1 : 0;
  const body = h("div", { class: "simple-body" });
  const waiting = h("div");
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Check logs")), waiting),
    journey(reached, (i) => { sm.step = i; renderSimple(main); }),
    body);
  waitingBanner(waiting);
  const go = (step: number) => { sm.step = step; renderSimple(main); };
  if (sm.step === 0) uploadStep(body, () => { sm.result = null; sm.upload = 0; sm.sentTo = ""; go(1); });
  else if (sm.step === 1) analyzeStep(body, main, () => go(2));
  else if (sm.step === 2) mapStep(body, () => go(3), () => { sm = blank(); go(0); });
  else reviewStep(body, () => { sm = blank(); go(0); });
}

/** The four steps as an LRT line (lrt-line.ts); its train rides from the last step drawn to this one. */
function journey(reached: number, open: (step: number) => void): HTMLElement {
  const from = trainAt;
  trainAt = sm.step;
  return h("nav", { class: `card simple-journey ${sm.step === 2 ? "wide" : ""}`, "aria-label": "Steps" },
    lrtLine(STEPS, sm.step, from, reached, sm.running, open));
}

async function waitingBanner(box: HTMLElement): Promise<void> {
  try {
    const { uploads } = await api("/api/uploads");
    const mine = uploads.filter((u: any) => u.waiting);
    if (mine.length) clear(box, h("a", { class: "waiting-chip", href: "#/uploads" }, icon("review", 16), `Waiting for you · ${mine.length}`));
  } catch { /* the banner is a shortcut only */ }
}

// --- (1) upload -------------------------------------------------------------------------------------

function guessMonth(name: string, firstLine: string): string {
  const inName = /(20\d\d)[-_]?(0[1-9]|1[0-2])/.exec(name);
  if (inName) return `${inName[1]}-${inName[2]}`;
  const iso = /^(?:\S+:)?(20\d\d)[/-](\d\d)[/-]\d\d/.exec(firstLine);
  if (iso) return `${iso[1]}-${iso[2]}`;
  const syslog = /^([A-Z][a-z]{2})\s+\d{1,2}\s/.exec(firstLine);
  const now = new Date();
  if (syslog && MONTHS.includes(syslog[1])) {
    const m = MONTHS.indexOf(syslog[1]);
    const year = m > now.getMonth() ? now.getFullYear() - 1 : now.getFullYear();     // syslog has no year: the latest such month
    return `${year}-${String(m + 1).padStart(2, "0")}`;
  }
  return now.toISOString().slice(0, 7);
}

async function takeText(text: string, name: string, size: number, redraw: () => void): Promise<void> {
  Object.assign(sm, { text, fileName: name, size, source: "", error: "", coverage: null, negligible: false, family: "", sample: 0, layout: null, raw: "" });
  const first = text.split(/\r?\n/).find((l) => l.trim()) ?? "";
  sm.month = guessMonth(name, first);
  const host = /ossec[_-]?logs?[_-]([^.\\/]+)/i.exec(name);
  if (host) sm.host = host[1].toLowerCase();
  redraw();
  await detect(redraw);
}

/** The log type, and how much of it Phase 1 knows; a table is read by its raw-line column (``sm.raw``, else found). */
async function detect(redraw: () => void): Promise<void> {
  try {
    const found = await api("/api/analyze/detect", { body: { text: sm.text.split(/\r?\n/, 400).join("\n"), month: sm.month, raw: sm.raw, name: sm.fileName } });
    Object.assign(sm, { source: found.source ?? "", coverage: found.coverage, negligible: found.negligible,
      family: found.family && !LOG_TYPES.some(([v]) => v === found.family) ? found.family : "", sample: found.lines, layout: found.layout });
    if (found.layout) sm.raw = found.layout.raw;
    if (found.host && !sm.host) sm.host = found.host;
    if (found.month && !/(20\d\d)[-_]?(0[1-9]|1[0-2])/.test(sm.fileName)) sm.month = found.month;   // a table's time column, unless the file name says
  } catch (e) {
    sm.error = e instanceof Error ? e.message : String(e);
  }
  redraw();
}

function uploadStep(box: HTMLElement, next: () => void): void {
  const redraw = () => uploadStep(box, next);
  const picker = h("input", { type: "file", accept: LOG_FILES, hidden: true, "aria-label": "Log file" }) as HTMLInputElement;
  const readFile = async (file: File | undefined) => {
    if (!file) return;
    let text: string;
    try {
      text = await readLogFile(file);
    } catch (e) {
      sm.error = e instanceof Error ? e.message : String(e);
      return redraw();
    }
    await takeText(text, file.name, file.size, redraw);
  };
  picker.addEventListener("change", () => readFile(picker.files?.[0]));
  const drop = h("div", { class: `drop ${sm.text ? "filled" : ""}`, tabindex: "0", role: "button", "aria-label": "Choose a log file",
    onclick: () => picker.click(), onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } } },
    icon(sm.text ? "check" : "upload", 26),
    sm.text ? h("strong", {}, sm.fileName || "Pasted lines") : h("strong", {}, "Drop a log file"),
    sm.text ? h("span", { class: "small muted" }, sm.size ? `${(sm.size / 1e6).toFixed(1)} MB · ` : "", sm.layout ? `${fmt.int(sm.text.split(/\r?\n/).filter((l) => l.trim()).length - 1)} rows`
        : `${fmt.int(sm.text.split(/\r?\n/).filter((l) => l.trim()).length)} lines`)
      : h("span", { class: "small muted" }, "or click to choose"), picker);
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); readFile(e.dataTransfer?.files?.[0]); });

  const paste = h("textarea", { rows: 6, spellcheck: "false", placeholder: "Paste log lines…", "aria-label": "Log lines" }) as HTMLTextAreaElement;
  paste.value = sm.fileName ? "" : sm.text;
  paste.addEventListener("change", () => { if (paste.value.trim()) takeText(paste.value, "", 0, redraw); });

  const month = h("input", { type: "month", value: sm.month, "aria-label": "Month" }) as HTMLInputElement;
  month.addEventListener("change", () => (sm.month = month.value));
  const host = h("input", { type: "text", value: sm.host, placeholder: "Server", "aria-label": "Server", style: { width: "150px" } }) as HTMLInputElement;
  host.addEventListener("input", () => { sm.host = host.value.trim(); run.disabled = !ready(); });
  const ready = () => Boolean(sm.text && sm.source && (sm.source !== "ossec" || sm.host));
  const run = h("button", { class: `btn big-btn ${sm.negligible ? "" : "primary"}`, disabled: !ready(), onclick: next }, icon("play", 18), "Analyze") as HTMLButtonElement;
  const unknown = Boolean(sm.text && sm.negligible);
  const find = h("button", { class: "btn primary big-btn", onclick: findPatterns }, icon("patterns", 18), "Find patterns");

  clear(box,
    h("div", { class: "card simple-card" },
      sm.pasting ? paste : drop,
      h("div", { class: "row", style: { justifyContent: "center", marginTop: "10px" } },
        h("button", { class: "btn small", onclick: () => { sm.pasting = !sm.pasting; redraw(); } }, icon(sm.pasting ? "upload" : "paste", 14), sm.pasting ? "Upload a file" : "Paste lines")),
      unknown ? h("div", { class: "simple-unknown" }, icon("unknown", 34), h("strong", {}, "Unknown log format"), coverageMeter(),
        sm.family ? h("span", { class: "who-chip" }, sm.family) : null, tableChip(redraw))
      : sm.text ? h("div", { class: "row simple-facts" }, tableChip(redraw),
        sm.source ? h("label", { class: "type-chip", title: "Log type" },
          h("select", { "aria-label": "Log type", onchange: (e: Event) => { sm.source = (e.target as HTMLSelectElement).value; redraw(); } },
            LOG_TYPES.map(([v, label]) => h("option", { value: v, selected: v === sm.source }, label))))
          : sm.error ? null : loading("Detecting…"),
        sm.source ? coverageMeter() : null,
        month,
        sm.source === "ossec" ? host : null) : null,
      sm.error ? errorBox(sm.error) : null,
      h("div", { class: "row", style: { justifyContent: "center", marginTop: "18px" } }, unknown ? [find, sm.source ? run : null] : run)));
}

/** A table (CSV export): which column holds the raw line; another one is read on a change. */
function tableChip(redraw: () => void): HTMLElement | null {
  if (!sm.layout) return null;
  const pick = h("select", { "aria-label": "Raw line column", title: "Raw line column" },
    sm.layout.columns.map((c: string) => h("option", { value: c, selected: c === sm.raw }, c))) as HTMLSelectElement;
  pick.addEventListener("change", async () => { sm.raw = pick.value; sm.source = ""; redraw(); await detect(redraw); });
  return h("label", { class: "pt-table-chip" }, h("strong", {}, sm.layout.format), icon("table", 14), pick);
}

/** How many of the first lines Phase 1 knows. */
function coverageMeter(): HTMLElement {
  const share = sm.coverage ?? 0;
  return h("span", { class: `cov-meter ${share < 0.05 ? "none" : share < 0.9 ? "low" : ""}`, title: `${Math.round(share * sm.sample)}/${sm.sample} lines known` },
    h("span", { class: "meter" }, h("i", { style: { width: `${Math.round(share * 100)}%` } })), `${Math.round(share * 100)}% known`);
}

/** Unknown logs: to Advanced → Patterns, with these lines. */
function findPatterns(): void {
  openInPatterns({ text: sm.text, name: sm.fileName || "Pasted lines", raw: sm.raw });
  history.replaceState(null, "", "#/patterns");
  void updateSettings({ console_mode: "advanced" });
}

// --- (2) analyze --------------------------------------------------------------------------------------

function analyzeStep(box: HTMLElement, main: HTMLElement, next: () => void): void {
  if (sm.result) return clear(box, verdictCard(sm.result.summary, next));
  const wait = h("div");
  if (sm.running && analysis) return clear(box, h("div", { class: "card simple-card" }, analysis.el, wait));
  const loader = sqlLoader("Analyze");                 // the SQL query's animation (Settings → Animation pack)
  analysis = loader;
  clear(box, h("div", { class: "card simple-card" }, loader.el, wait));
  sm.running = true;
  (async () => {
    try {
      const { job } = await api("/api/simple/analyze", { body: { text: sm.text, source: sm.source, month: sm.month, host: sm.host, name: sm.fileName, raw: sm.raw } });
      for (;;) {
        const status = await api(`/api/analyze/job${qs({ id: job })}`);
        const seen = new Set(status.steps.map((s: any) => (s.step === "phase3" ? "phase4" : s.step)));
        const doing = STOPS.find(([key]) => !seen.has(key));
        if (doing) loader.say(`Analyze · ${doing[1].toLowerCase()}`);
        if (status.status === "done") { sm.result = status.result; break; }
        if (status.status === "failed") throw new Error(status.error);
        await new Promise((r) => setTimeout(r, 600));
      }
      await loader.arrive();
      sm.running = false;
      analysis = null;
      if (location.hash.startsWith("#/simple") || !location.hash) renderSimple(main);
    } catch (e) {
      sm.running = false;
      analysis = null;
      await loader.fail();
      clear(wait, errorBox(e), h("div", { class: "row", style: { justifyContent: "center", marginTop: "12px" } },
        h("button", { class: "btn", onclick: () => analyzeStep(box, main, next) }, icon("refresh", 16), "Try again")));
    }
  })();
}

function verdictCard(s: any, next: () => void): HTMLElement {
  const unusual = s.unusual > 0;
  const covered = s.whitelisted > 0;                   // flagged, but every account named is whitelisted
  const rare = rarity(s.rarest);
  const whitelisted = covered ? h("div", {}, h("div", { class: "big" }, fmt.int(s.whitelisted)),
    h("div", { class: "tiny muted" }, s.whitelisted === 1 ? "whitelisted event" : "whitelisted events")) : null;
  return h("div", { class: `card simple-card verdict-card ${unusual ? "alarm" : "accent"}` },
    h("div", { class: "verdict-mark" }, icon(unusual ? "alert" : covered ? "shield" : "check", 32)),
    h("div", { class: "verdict-title" }, unusual ? "Unusual" : covered ? "Whitelisted" : "Nothing unusual"),
    unusual ? h("div", { class: "verdict-facts" },
      h("div", {}, h("div", { class: "big" }, fmt.int(s.unusual)), h("div", { class: "tiny muted" }, s.unusual === 1 ? "unusual event" : "unusual events")),
      s.method === "baseline" ? h("div", { title: rare.title }, h("div", { class: "big" }, rare.text), h("div", { class: "tiny muted" }, "how rare")) : null,
      h("div", {}, h("div", { class: "row", style: { gap: "6px", justifyContent: "center" } },
        s.hosts.slice(0, 6).map((x: string) => h("span", { class: "who-chip server" }, x)), s.hosts.length > 6 ? `+${s.hosts.length - 6}` : null),
        h("div", { class: "tiny muted" }, s.hosts.length === 1 ? "server" : "servers")), whitelisted)
      : covered ? h("div", { class: "verdict-facts" }, whitelisted,
        h("div", {}, h("div", { class: "row", style: { gap: "6px", justifyContent: "center" } },
          (s.accounts ?? []).slice(0, 6).map((x: string) => h("span", { class: "who-chip user" }, x))),
          h("div", { class: "tiny muted" }, (s.accounts ?? []).length === 1 ? "account" : "accounts"))) : null,
    h("div", { class: "row", style: { justifyContent: "center", marginTop: "18px" } },
      h("button", { class: "btn primary big-btn", onclick: next }, icon("map", 18), "See on the map")));
}

// --- (3) the map ----------------------------------------------------------------------------------------

function mapStep(box: HTMLElement, next: () => void, restart: () => void): void {
  const r = sm.result, s = r.summary;
  const send = h("button", { class: "btn primary big-btn" }, icon("review", 18), "Send for review") as HTMLButtonElement;
  const err = h("div");
  send.addEventListener("click", async () => {
    send.disabled = true;
    try {
      sm.upload = (await api("/api/uploads", { body: { keep: r.keep } })).id;
      next();
    } catch (e) {
      send.disabled = false;
      clear(err, errorBox(e));
    }
  });
  const actions = h("div", { class: "row", style: { justifyContent: "flex-end", marginTop: "14px" } },
    s.unusual ? null : h("button", { class: "btn", onclick: restart }, icon("upload", 16), "New check"), s.unusual ? send : null);
  const mapBox = h("div", {}, loading("Drawing the map…"));
  const near = h("div");
  const block = r.views.find((v: any) => v.view === s.view);
  clear(box,
    h("div", { class: "grid simple-map" },
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, viewIcon(s.view || "individual")), h("h2", {}, s.view_label || "Map")), mapBox),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Nearest groups")), near)),
    err, actions);
  if (!block?.rows?.length) { clear(mapBox, note("No map for these logs.")); clear(near); return; }
  drawMap(r.source, block, mapBox, near).catch((e) => clear(mapBox, errorBox(e)));
}

async function drawMap(source: string, block: any, mapBox: HTMLElement, near: HTMLElement): Promise<void> {
  const groupOf = (o: any): number | null => (o.map?.cluster_id ? Number(o.map.cluster_id.split("#")[1]) : null);
  const [info, list] = await Promise.all([mapInfoOrNone(source, block.view),
    api(`/api/clusters${qs({ source, view: block.view })}`).then((c) => c.clusters)]);
  if (!info) { clear(mapBox, note("No map for these logs.")); return; }
  const { groups } = buildGroups(list, info);
  const inputs: InputPoint[] = block.rows.filter((o: any) => o.map).map((o: any) => ({
    x: o.map.x, y: o.map.y, at: o.map.layouts ?? {}, flagged: o.flags.length > 0 && !o.whitelisted, group: groupOf(o),
    label: `${(o.timestamp ?? o.window_start ?? o.session_start ?? o.episode_start ?? "").slice(0, 19)} · ${eventName(o.event_type ?? o.first_event_type ?? "")}${o.whitelisted ? " · whitelisted" : o.flags.length ? " · unusual" : ""}`,
  }));
  const everywhere = inputs.every((p) => p.at?.umap);
  const layout = everywhere ? layoutFor(info) : "tsne";
  const points = await loadMap(source, block.view, layout);
  let picked: number | null = null;
  const map: ClusterMap = clusterMap(points, groups, {
    visible: new Set(groups.keys()), selected: null, height: 460, inputs, layout,
    info: everywhere ? info : { ...info, layouts: { tsne: "ready", umap: "missing" } },
    loadLayout: (l) => loadMap(source, block.view, l),
    onPick: (n) => pick(n), onClear: () => { if (picked !== null) pick(picked); },
  });
  clear(mapBox, map.el);
  setTimeout(() => map.zoomToInputs(), 80);

  const counts = new Map<number, { n: number; unusual: number }>();
  for (const o of block.rows) {
    const g = groupOf(o);
    if (g === null) continue;
    const c = counts.get(g) ?? { n: 0, unusual: 0 };
    c.n++; c.unusual += o.flags.length && !o.whitelisted ? 1 : 0;
    counts.set(g, c);
  }
  const top = [...counts].sort((a, b) => b[1].unusual - a[1].unusual || b[1].n - a[1].n).slice(0, 3);
  const pick = (n: number) => {
    picked = picked === n ? null : n;
    map.setSelected(picked);
    if (picked !== null) map.zoomToGroup(picked); else map.zoomToInputs();
    drawNear();
  };
  const drawNear = () => clear(near, top.length ? top.map(([n, c]) => {
    const g = groups.get(n);
    const share = g && g.rows ? g.flagged / g.rows : 0;
    return h("button", { class: `near-group ${picked === n ? "on" : ""}`, onclick: () => pick(n) },
      h("strong", {}, g ? (g.kind === "named" ? g.name : groupName(g.name)) : `Group #${n}`),
      h("div", { class: "row", style: { gap: "6px", marginTop: "6px" } },
        badge(`${fmt.int(c.n)} new`, "dark"),
        c.unusual ? badge(`${fmt.int(c.unusual)} unusual`, "bad") : null,
        share >= 0.5 ? badge("usually flagged", "bad") : share > 0 ? badge("sometimes flagged", "warn") : badge("never flagged", "ok")));
  }) : note("Not placed near any group."));
  drawNear();
}

// --- (4) review -----------------------------------------------------------------------------------------

function reviewStep(box: HTMLElement, restart: () => void): void {
  const s = sm.result.summary;
  const sender = sendBox(sm.upload, s, sm.fileName || "Pasted lines", (to) => { sm.sentTo = to; reviewStep(box, restart); });
  clear(box,
    h("div", { class: "card simple-card review-step" },
      h("div", { class: "review-step-head" },
        badge(`#${sm.upload}`, "dark"),
        h("strong", {}, sm.fileName || "Pasted lines"),
        s.unusual > 0 ? badge(`${fmt.int(s.unusual)} unusual`, "bad") : s.whitelisted > 0 ? null : badge("Nothing unusual", "ok"),
        s.whitelisted > 0 ? whitelistBadge(`${fmt.int(s.whitelisted)} whitelisted`) : null,
        s.hosts.slice(0, 3).map((x: string) => h("span", { class: "who-chip server" }, x))),
      h("div", { class: "review-actions" },
        h("a", { class: "btn primary", href: `#/upload/${sm.upload}` }, icon("review", 16), "Review now"),
        h("span", { class: "review-split", "aria-hidden": "true" }),
        sm.sentTo ? h("span", { class: "badge ok" }, icon("check", 14), sm.sentTo) : sender)),
    h("div", { class: "row", style: { justifyContent: "center", marginTop: "14px" } },
      h("button", { class: "btn small", onclick: restart }, icon("upload", 14), "New check")));
}

/** A name or address, and Send: names the reviewer (Waiting for you) and opens a mail draft without log lines. */
function sendBox(id: number, summary: any, name: string, done: (to: string) => void): HTMLElement {
  const input = h("input", { type: "text", list: `reviewers-${id}`, placeholder: "Reviewer's name or e-mail", "aria-label": "Reviewer", style: { minWidth: "220px" } }) as HTMLInputElement;
  const list = h("datalist", { id: `reviewers-${id}` });
  api("/api/uploads").then((r) => clear(list, r.reviewers.map((x: string) => h("option", { value: x })))).catch(() => undefined);
  const err = h("div");
  const send = h("button", { class: "btn primary", onclick: async () => {
    try {
      const to = input.value.trim();
      const r = await api("/api/uploads/assign", { body: { id, reviewer: to } });
      location.href = mailto(r.email ? to : "", id, summary, name);
      done(to);
    } catch (e) {
      clear(err, errorBox(e));
    }
  } }, icon("mail", 16), "Send");
  send.classList.remove("primary");
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") send.click(); });
  return h("div", {}, h("div", { class: "row", style: { gap: "6px", justifyContent: "center" } }, input, list, send), err);
}

/** The mail draft: what to open and where; never a log line or an address from the logs. */
function mailto(to: string, id: number, s: any, name: string): string {
  const rare = rarity(s.rarest).text;
  const subject = `Review #${id}: ${s.unusual} unusual ${s.unusual === 1 ? "event" : "events"}${s.hosts.length ? ` on ${s.hosts.slice(0, 3).join(", ")}` : ""}`;
  const body = [
    `Review #${id} is waiting for you in the Project DAD (Data Anomaly Detection) Console.`, "",
    `File: ${name}`,
    `Unusual events: ${s.unusual}${s.method === "baseline" && s.rarest !== null ? ` (rarest: ${rare})` : ""}`,
    `Servers: ${s.hosts.join(", ") || "—"}`, "",
    `Open the console on the pipeline laptop: Review → #${id}.`,
  ].join("\n");
  return `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

// --- the uploads (Simple mode's Review) -------------------------------------------------------------------

export async function renderUploads(main: HTMLElement): Promise<void> {
  const box = h("div", {}, loading());
  clear(main, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Review"))), box);
  let r: any;
  try {
    r = await api(`/api/uploads${qs({ filters: filterQuery() })}`);
  } catch (e) {
    return clear(box, errorBox(e));
  }
  const mine = r.uploads.filter((u: any) => u.waiting);
  const row = (u: any) => h("a", { class: "upload-row", href: `#/upload/${u.id}` },
    h("span", { class: "up-id" }, `#${u.id}`),
    h("span", { class: "up-name" }, h("strong", {}, u.name), h("span", { class: "tiny muted" },
      `${u.created_at.replace("T", " ").slice(0, 16)} · ${u.created_by}${u.assigned_to ? ` → ${u.assigned_to}` : ""}`)),
    h("span", { class: "row", style: { gap: "4px" } }, badge(u.source.toUpperCase(), "muted"),
      (u.summary.hosts ?? []).slice(0, 2).map((x: string) => h("span", { class: "who-chip server" }, x)),
      u.whitelisted ? whitelistBadge(fmt.int(u.whitelisted)) : null),
    progress(u.reviewed + (u.whitelisted ?? 0), u.items));
  clear(box,
    filterBar('', () => renderUploads(main), (await api('/api/uploads/facts')).facts),
    mine.length ? h("div", { class: "card accent" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("review")), h("h2", {}, `Waiting for you · ${mine.length}`)),
      mine.map(row)) : null,
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Uploads"), h("span", { class: "end" },
      h("a", { class: "btn small", href: "#/simple" }, icon("upload", 14), "Check logs"))),
      r.uploads.length ? r.uploads.map(row) : h("p", { class: "muted" }, "None yet.")));
}

function progress(done: number, total: number): HTMLElement {
  return h("span", { class: "up-progress", title: `${done} of ${total} reviewed` },
    h("span", { class: "meter" }, h("i", { style: { width: `${total ? Math.round((done / total) * 100) : 100}%` } })),
    h("span", { class: "tiny" }, `${done}/${total}`));
}

// --- one upload: its unusual events, rarest first, each with its lines and a label ---------------------------

let chosen = "";

export async function renderUpload(main: HTMLElement): Promise<void> {
  const id = Number(location.hash.split("/")[2] ?? 0);
  const box = h("div", {}, loading());
  const title = h("div", {}, h("h1", {}, `Review #${id}`));
  clear(main, h("div", { class: "page-head" }, title), box);
  let u: any;
  try {
    u = await api(`/api/uploads/item${qs({ id: String(id) })}`);
  } catch (e) {
    return clear(box, errorBox(e));
  }
  const allFacts = u.items.flatMap((i: any) => i.facts ?? []);
  u.items = u.items.filter((i: any) => matchesFacts(i.facts ?? []));
  u.items = [...u.items.filter((i: any) => i.review || !i.whitelisted), ...u.items.filter((i: any) => !i.review && i.whitelisted)];
  const filters = filterBar(u.source, () => renderUpload(main), allFacts);
  const open = u.items.filter((i: any) => !i.review && !i.whitelisted);
  if (!u.items.find((i: any) => i.item_id === chosen)) chosen = (open[0] ?? u.items[0])?.item_id ?? "";
  const list = h("div", { class: "list-scroll" });
  const detail = h("div");
  const send = h("div");
  const drawList = () => keepScroll(list, () => clear(list, u.items.map((item: any) => h("div", {
    class: `list-item ${item.item_id === chosen ? "selected" : ""}`, tabindex: "0",
    onclick: () => { chosen = item.item_id; drawList(); drawItem(detail, u, item, () => renderUpload(main)); },
    onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") (e.currentTarget as HTMLElement).click(); },
  },
    h("div", { class: "row", style: { justifyContent: "space-between", flexWrap: "nowrap" } },
      h("strong", {}, itemTitle(item)),
      h("span", { class: "row", style: { gap: "4px", flexWrap: "nowrap" } },
        item.sigma?.length ? h("span", { class: "badge bad", title: item.sigma.join("\n") }, icon("sigma", 12)) : null,
        item.review ? verdictBadge(item.review.verdict) : item.whitelisted ? whitelistBadge() : null)),
    h("div", { class: "tiny muted" }, [item.host, item.when.slice(5, 16), item.unusual !== null && item.unusual !== undefined ? rarity(item.unusual).text : ""].filter(Boolean).join(" · "))))));
  title.append(h("div", { class: "row", style: { gap: "6px" } },
    badge(sourceLabel(u.source), "muted"), h("span", { class: "small muted" }, `${u.name} · ${u.created_at.replace("T", " ").slice(0, 16)} · ${u.created_by}`)));
  const toolbar = h("div", { class: "row upload-toolbar" }, progress(u.items.length - open.length, u.items.length),
    u.assigned_to ? h("span", { class: "who-chip user", title: "Sent to" }, "→ ", u.assigned_to) : null,
    h("button", { class: "btn small", onclick: () => clear(send, sendBox(id, u.summary, u.name, () => renderUpload(main))) }, icon("mail", 14), "Send to a reviewer"),
    h('button', { class: 'btn small', onclick: async () => {
      const password = prompt('Clear this upload? Existing report snapshots and review history remain. Enter the activity-log password to confirm.');
      if (password === null) return;
      try { await api('/api/uploads/clear', { body: { id, password } }); location.hash = '#/uploads'; }
      catch (e) { clear(send, errorBox(e)); }
    } }, 'Clear upload'), send);
  if (!u.items.length) return clear(box, toolbar, filters, h("div", { class: "card muted" }, "No events match the current filters."));
  clear(box, toolbar, filters, linkedReports(`upload/${id}`), h("div", { class: "grid split" }, h("div", { class: "card" }, list), detail));
  drawList();
  const current = u.items.find((i: any) => i.item_id === chosen);
  if (current) drawItem(detail, u, current, () => renderUpload(main));
}

const itemTitle = (item: any) => (item.event ? eventName(item.event) : item.view_label);

function drawItem(el: HTMLElement, u: any, item: any, refresh: () => void): void {
  const noteBox = h("textarea", { rows: 2, "aria-label": "Note", placeholder: "Note", style: { fontFamily: "var(--font-body)" } }) as HTMLTextAreaElement;
  noteBox.value = item.review?.note ?? "";
  noteBox.addEventListener("input", () => { noteBox.classList.remove("needs"); noteBox.placeholder = "Note"; });
  const err = h("div");
  const decide = async (verdict: string) => {
    const v = VERDICTS.find((x) => x.id === verdict);
    if (v?.note && !noteBox.value.trim()) {
      noteBox.classList.add("needs");
      noteBox.placeholder = v.note.replace(/^./, (c) => c.toUpperCase());
      noteBox.focus();
      return;
    }
    const buttons = [...el.querySelectorAll<HTMLButtonElement>(".verdict-buttons button")];
    if (buttons.some((x) => x.disabled)) return;                 // one label at a time: a second click waits for the first
    buttons.forEach((x) => (x.disabled = true));
    try {
      await api("/api/review", { body: { source: u.source, view: item.view, item_id: item.review_id, kind: "upload", verdict, note: noteBox.value } });
      const next = u.items.find((i: any) => !i.review && i.item_id !== item.item_id);
      if (next) chosen = next.item_id;
      refresh();
    } catch (e) {
      buttons.forEach((x) => (x.disabled = false));
      clear(err, errorBox(e));
    }
  };
  const rare = rarity(item.unusual);
  clear(el,
    h("div", { class: `card ${item.review?.verdict === "security_relevant" ? "alarm" : item.review ? "accent" : ""}` },
      h("div", { class: "obs-head" },
        h("div", {},
          h("h2", { style: { margin: "0 0 6px" } }, itemTitle(item)),
          h("div", { class: "row", style: { gap: "8px" } },
            item.host ? h("span", { class: "who-chip server" }, item.host) : null,
            item.username ? h("span", { class: "who-chip user" }, item.username) : null,
            item.whitelisted ? whitelistBadge() : null,
            h("span", { class: "mono small" }, item.when),
            [item.view_label, ...(item.also ?? [])].map((v: string) => badge(v, "muted")),
            (item.sigma ?? []).map((t: string) => sigmaBadge(t)))),
        item.unusual !== null && item.unusual !== undefined
          ? h("div", { class: "obs-rare", title: rare.title }, h("div", { class: "big" }, rare.text), h("div", { class: "tiny muted" }, "how rare")) : null),
      lines(item),
      h("div", { class: "verdict-buttons", style: { marginTop: "14px" } }, VERDICTS.map((v) =>
        h("button", { class: `btn ${v.id} ${item.review?.verdict === v.id ? "on" : ""}`, title: v.hint, onclick: () => decide(v.id) }, v.label))),
      noteBox, err));
}

/** The uploaded lines around the event, its own lines marked, with the time from the event. */
function lines(item: any): HTMLElement {
  const ctx: any[] = item.context ?? [];
  if (!ctx.length) return h("p", { class: "small muted" }, "No lines.");
  const own = ctx.filter((c) => c.own).map((c) => Date.parse(c.time.replace(" ", "T")));
  const [start, end] = own.length ? [Math.min(...own), Math.max(...own)] : [Date.parse(item.when.replace(" ", "T")), Date.parse(item.when.replace(" ", "T"))];
  const offset = (t: string) => {
    const at = Date.parse(t.replace(" ", "T"));
    const s = at < start ? (at - start) / 1000 : at > end ? (at - end) / 1000 : 0;
    if (!s) return "during";
    const a = Math.abs(Math.round(s));
    return `${s < 0 ? "−" : "+"}${Math.floor(a / 60)}:${String(a % 60).padStart(2, "0")}`;
  };
  const log = h("div", { class: "ctx-log", role: "list", style: { marginTop: "12px" } }, ctx.map((c) => {
    const when = offset(c.time);
    return h("div", { class: `ctx-entry ${c.own ? "own" : when === "during" ? "during" : when.startsWith("−") ? "before" : "after"}`, role: "listitem" },
      h("div", { class: "ctx-when mono" }, h("strong", {}, c.own ? "▶ this" : when), h("span", {}, c.time.slice(11, 19))),
      h("div", { class: "ctx-what" }, h("div", { class: "mono tiny ctx-line" }, c.line)));
  }));
  requestAnimationFrame(() => {
    const first = log.querySelector<HTMLElement>(".ctx-entry.own");
    if (first) log.scrollTop = Math.max(0, first.offsetTop - 80);
  });
  return log;
}
