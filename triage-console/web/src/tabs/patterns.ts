// Patterns (Advanced, before Analyze): the regex rules new logs need before the pipeline can read them
// (service/patterns.py). Scan → how much is known, and the shapes of what is not → slice lines on the
// canvas into prefix | message | suffix → regex candidates from the examples → save → next pass.
// Rules are kept per log type on this laptop and exported for Phase 1. A table (a CSV or Excel export: one
// column the raw line, the others fields) is checked first (its first 100 rows), then the person picks the
// raw-log column and ticks the columns to keep, then scans; the kept fields date the lines, split the
// coverage per value, and filter the canvas.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, loading, pct } from "../dom";
import { icon } from "../icons";
import { sqlLoader } from "../loaders";
import { LOG_FILES, readLogFile } from "../tables";

type Kind = "prefix" | "rule" | "suffix";
type Mode = "paste" | "file" | "path";
type Tab = "lines" | "heads" | "tails";
type Draft = { regex: string; event: string; eventTouched: boolean; custom: boolean; candidates: any[] | null; test: any };

const KINDS: Kind[] = ["prefix", "rule", "suffix"];
const KIND_LABEL: Record<Kind, string> = { prefix: "Prefix", rule: "Message", suffix: "Suffix" };
const TAB_KIND: Record<Tab, Kind> = { lines: "rule", heads: "prefix", tails: "suffix" };
const SEGMENTS: [string, string][] = [["builtin", "Phase 1"], ["custom", "Rules"], ["sliced", "Prefix only"], ["unknown", "Unknown"]];
const BUILTIN: [string, string][] = [["auth", "AUTH"], ["ossec", "OSSEC"], ["pf", "PF"], ["ipf", "IPFilter"]];
const MAX_TRAY = 40;
const PREVIEW_LINES = 2000;                     // enough lines for the first 100 rows of a table

const blankDraft = (): Draft => ({ regex: "", event: "", eventTouched: false, custom: false, candidates: null, test: null });
const form = {
  mode: "paste" as Mode, family: "auto", newName: "", text: "", fileName: "", path: "",
  table: null as any, checking: false, raw: "", fields: new Set<string>(),
};
const st = {
  result: null as any, rules: null as any, lines: null as any,
  view: { show: "unknown", shape: "", search: "", field: "", value: null as string | null }, tab: "lines" as Tab, kind: "rule" as Kind,
  field: "",
  trays: { prefix: [], rule: [], suffix: [] } as Record<Kind, string[]>,
  drafts: { prefix: blankDraft(), rule: blankDraft(), suffix: blankDraft() } as Record<Kind, Draft>,
  saved: new Set<number>(), families: [] as any[],
};
let handOff: { text?: string; path?: string; name?: string; raw?: string } | null = null;
let ui: Record<string, HTMLElement> = {};
let floating: HTMLElement | null = null;
let linesSeq = 0, trySeq = 0, suggestSeq = 0, previewSeq = 0;

/** Simple mode's unknown logs, or Analyze's: open them here (a table first shows its columns; plain logs scan). */
export function openInPatterns(input: { text?: string; path?: string; name?: string; raw?: string }): void {
  handOff = input;
}

const debounce = (f: () => void, ms: number) => {
  let t = 0;
  return () => { clearTimeout(t); t = window.setTimeout(f, ms); };
};
const familyLabel = (name: string) => BUILTIN.find(([k]) => k === name)?.[1] ?? name;

export function renderPatterns(main: HTMLElement): void {
  const results = h("div", { class: "pt-results" });
  const start = handOff;
  if (start) {
    Object.assign(form, start.path ? { mode: "path", path: start.path, text: "", fileName: "" }
      : { mode: "paste", text: start.text ?? "", fileName: start.name ?? "" }, { family: "auto", table: null });
    handOff = null;
  }
  const run = h("button", { class: "btn primary" }, icon("play", 16), "Scan") as HTMLButtonElement;
  run.addEventListener("click", () => void scan(results, run));
  clear(main, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Patterns"))), inputCard(run), results);
  if (start) {
    void check(start.raw).then(() => { if (!form.table?.table) void scan(results, run); });
  } else if (st.result) drawResults(results);
}

// --- input: lines, or a table checked, its raw-log column chosen and its columns ticked ---------------------

let drawTable: () => void = () => undefined;

/** Is the input a table? Its first 100 rows checked, and its columns; the raw-log column ``prefer`` if it has it. */
async function check(prefer = ""): Promise<void> {
  const seq = ++previewSeq;
  const fromPath = form.mode === "path";
  if (fromPath ? !form.path.trim() : !form.text.trim()) { form.table = null; drawTable(); return; }
  form.checking = true;
  drawTable();
  try {
    const found = await api("/api/patterns/preview", { body: fromPath ? { path: form.path }
      : { text: form.text.split(/\r?\n/, PREVIEW_LINES).join("\n"), name: form.fileName } });
    if (seq !== previewSeq) return;
    form.table = found;
    const names: string[] = found.table ? found.columns.map((c: any) => c.name) : [];
    form.raw = names.includes(prefer) ? prefer : found.raw ?? "";
    form.fields = new Set(names.filter((n) => n !== form.raw));
  } catch (e) {
    if (seq !== previewSeq) return;
    form.table = { table: true, problem: e instanceof Error ? e.message : String(e), columns: [] };
  }
  form.checking = false;
  drawTable();
}

function inputCard(run: HTMLButtonElement): HTMLElement {
  const recheck = debounce(() => void check(), 450);
  const textarea = h("textarea", { rows: 6, spellcheck: "false", placeholder: "Paste log lines…", "aria-label": "Log lines" }) as HTMLTextAreaElement;
  textarea.value = form.text;
  textarea.addEventListener("input", () => { form.text = textarea.value; form.fileName = ""; recheck(); });
  const fileInfo = h("span", { class: "small muted" }, form.fileName);
  const fileInput = h("input", { type: "file", accept: LOG_FILES, "aria-label": "Log file" }) as HTMLInputElement;
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    clear(fileInfo, loading(file.name));
    try {
      form.text = await readLogFile(file);
      form.fileName = file.name;
      clear(fileInfo, `${file.name} · ${(file.size / 1e6).toFixed(1)} MB`);
      void check();
    } catch (e) {
      form.text = "";
      clear(fileInfo, errorBox(e));
    }
  });
  const pathInput = h("input", { type: "text", value: form.path, placeholder: "C:\\logs\\new\\  ·  .csv  ·  .xlsx  ·  .zip  ·  .gz", style: { width: "100%" }, "aria-label": "File, folder or archive" }) as HTMLInputElement;
  pathInput.addEventListener("input", () => { form.path = pathInput.value; recheck(); });
  const name = h("input", { type: "text", value: form.newName, placeholder: "Name", "aria-label": "New log type", style: { width: "130px" } }) as HTMLInputElement;
  name.addEventListener("input", () => (form.newName = name.value.trim()));
  const family = h("select", { "aria-label": "Log type" }) as HTMLSelectElement;
  const fillFamilies = () => {
    const custom = st.families.filter((f) => !f.builtin).map((f) => [f.name, f.name] as [string, string]);
    clear(family, [["auto", "Detect"], ...BUILTIN, ...custom, ["new", "New…"]].map(([v, label]) => h("option", { value: v, selected: v === form.family }, label)));
    name.hidden = form.family !== "new";
  };
  family.addEventListener("change", () => { form.family = family.value; name.hidden = form.family !== "new"; if (!name.hidden) name.focus(); });
  fillFamilies();
  api("/api/patterns/rules").then((r) => { st.families = r.families; fillFamilies(); }).catch(() => undefined);

  const body = h("div");
  const drawBody = () => clear(body,
    form.mode === "paste" ? textarea : null,
    form.mode === "file" ? h("div", { class: "row" }, fileInput, fileInfo) : null,
    form.mode === "path" ? pathInput : null);
  drawBody();
  const modes: [Mode, string][] = [["paste", "Paste"], ["file", "Upload"], ["path", "File on this laptop"]];
  const modePills = h("div", { class: "pills small", role: "tablist" });
  const drawModes = () => clear(modePills, modes.map(([m, label]) => h("button", {
    class: form.mode === m ? "on" : "", role: "tab", "aria-selected": String(form.mode === m),
    onclick: () => { form.mode = m; drawModes(); drawBody(); void check(); },
  }, label)));
  drawModes();

  const tableBox = h("div", { class: "pt-table-step" });
  drawTable = () => {
    const t = form.table;
    run.disabled = form.checking || Boolean(t?.table && (t.problem || !form.raw));
    if (form.checking) return clear(tableBox, loading("100 rows"));
    if (!t?.table) return clear(tableBox);
    if (t.problem) return clear(tableBox, h("div", { class: "pt-table-status bad" }, badge(t.format ?? "Table", "bad"), errorBox(t.problem)));
    const names: string[] = t.columns.map((c: any) => c.name);
    const raw = h("select", { "aria-label": "Raw logs", class: `pt-raw-pick ${form.raw ? "" : "empty"}` },
      h("option", { value: "", selected: !form.raw, disabled: true }, "Choose…"),
      names.map((n) => h("option", { value: n, selected: n === form.raw }, n))) as HTMLSelectElement;
    raw.addEventListener("change", () => {
      if (form.raw) form.fields.add(form.raw);           // the column given up goes back among the fields
      form.raw = raw.value;
      form.fields.delete(form.raw);
      drawTable();
    });
    const others = t.columns.filter((c: any) => c.name !== form.raw);
    const all = h("input", { type: "checkbox", checked: others.every((c: any) => form.fields.has(c.name)), "aria-label": "All columns" }) as HTMLInputElement;
    all.indeterminate = !all.checked && others.some((c: any) => form.fields.has(c.name));
    all.addEventListener("change", () => { others.forEach((c: any) => (all.checked ? form.fields.add(c.name) : form.fields.delete(c.name))); drawTable(); });
    clear(tableBox,
      h("div", { class: "pt-table-status" }, badge(t.format, "dark"), h("span", { class: "pt-ok" }, icon("check", 14)), `${t.rows} rows`),
      h("label", { class: "pt-step" }, h("span", { class: "pt-step-no" }, "1"), h("strong", {}, "Raw logs"), raw,
        form.raw ? h("code", { class: "pt-raw-sample" }, t.columns.find((c: any) => c.name === form.raw)?.sample ?? "") : null),
      form.raw ? h("div", { class: "pt-step pt-columns" },
        h("span", { class: "pt-step-no" }, "2"),
        h("div", { class: "pt-column-table" }, h("table", {},
          h("thead", {}, h("tr", {},
            h("th", {}, all),
            h("th", { scope: "col" }, "Column ", h("span", { class: "pt-count" }, `${others.filter((c: any) => form.fields.has(c.name)).length}/${others.length}`)),
            h("th", { scope: "col" }, "Type"),
            h("th", { scope: "col" }, "First values"))),
          h("tbody", {}, others.map((c: any) => {
            const box = h("input", { type: "checkbox", checked: form.fields.has(c.name), "aria-label": c.name }) as HTMLInputElement;
            box.addEventListener("change", () => { if (box.checked) form.fields.add(c.name); else form.fields.delete(c.name); drawTable(); });
            return h("tr", { class: box.checked ? "" : "off", onclick: (e: Event) => { if (e.target !== box) box.click(); } },
              h("td", {}, box),
              h("td", { class: "pt-column-name mono" }, c.name),
              h("td", {}, h("span", { class: "pt-type", "data-type": c.type }, c.type)),
              h("td", {}, h("div", { class: "pt-head" }, (c.head ?? []).map((v: string) =>
                h("span", { class: `mono ${v.trim() ? "" : "blank"}`, title: v }, v.trim() ? v : "—")))));
          }))))) : null);
  };
  drawTable();
  return h("div", { class: "card" },
    h("div", { class: "row", style: { justifyContent: "space-between", marginBottom: "14px" } }, modePills,
      h("div", { class: "row", style: { alignItems: "flex-end" } },
        h("label", { class: "field" }, h("span", {}, "Log type"), h("span", { class: "row", style: { gap: "6px" } }, family, name)),
        run)),
    body, tableBox);
}

async function follow(job: string, onStep: (detail: string) => void): Promise<any> {
  for (;;) {
    const s = await api(`/api/analyze/job${qs({ id: job })}`);
    const last = s.steps[s.steps.length - 1];
    if (last) onStep(last.detail);
    if (s.status === "done") return s.result;
    if (s.status === "failed") throw new Error(s.error);
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function scan(results: HTMLElement, run: HTMLButtonElement): Promise<void> {
  const fromPath = form.mode === "path";
  const table = form.table?.table && !form.table.problem;
  const body = {
    text: fromPath ? "" : form.text, path: fromPath ? form.path : "", name: fromPath ? "" : form.fileName || "Pasted lines",
    family: form.family === "new" ? "auto" : form.family, new_family: form.family === "new" ? form.newName : "",
    raw: table ? form.raw : "", fields: table ? [...form.fields] : undefined,
  };
  run.disabled = true;
  const loader = sqlLoader("Scan");                    // the SQL query's animation (Settings → Animation pack)
  clear(results, h("div", { class: "card" }, loader.el));
  try {
    const { job } = await api("/api/patterns/scan", { body });
    const result = await follow(job, (detail) => loader.say(caption("Scan", detail)));
    await loader.arrive();
    st.result = result;
    st.view = { show: "unknown", shape: "", search: "", field: "", value: null };
    st.field = st.result.fields?.[0]?.name ?? "";
    st.trays = { prefix: [], rule: [], suffix: [] };
    st.drafts = { prefix: blankDraft(), rule: blankDraft(), suffix: blankDraft() };
    st.saved.clear();
    st.lines = null;
    st.kind = st.result.counts.unknown && !st.result.builtin ? "prefix" : "rule";
    st.tab = st.kind === "prefix" ? "heads" : "lines";
    await loadRules();
    drawResults(results);
  } catch (e) {
    await loader.fail();
    clear(results, errorBox(e));
  } finally {
    drawTable();
  }
}

/** A pass's progress as the animation's caption: what it is doing, then the lines read so far. */
function caption(title: string, detail: string): string {
  return detail === "Reading" ? title : detail === "Shapes" ? `${title} · shapes` : `${title} · ${detail}`;
}

async function loadRules(): Promise<void> {
  st.rules = await api(`/api/patterns/rules${qs({ family: st.result.family })}`);
  st.families = st.rules.families;
}

// --- results --------------------------------------------------------------------------------------

function drawResults(results: HTMLElement): void {
  ui = {
    results,
    coverage: h("div", { class: "card pt-coverage" }), time: h("div", { class: "card pt-time-card" }),
    fields: h("div", { class: "card pt-fields-card" }),
    shapes: h("div", { class: "card pt-shapes" }), canvas: h("div", { class: "card pt-canvas" }),
    builder: h("div", { class: "card pt-builder" }), rules: h("div", { class: "card pt-rules" }),
  };
  clear(results,
    h("div", { class: `grid pt-top ${st.result.fields?.length ? "three" : ""}` }, ui.coverage, ui.time, st.result.fields?.length ? ui.fields : null),
    h("div", { class: "grid pt-work" }, ui.shapes, ui.canvas),
    ui.builder, ui.rules);
  drawCoverage(); drawTime(); drawFields(); drawShapes(); drawCanvasFrame(); drawBuilder(); drawRules();
  void loadLines();
}

function drawCoverage(): void {
  const r = st.result, c = r.counts;
  const estimate = st.lines?.estimate;
  const moved = estimate !== null && estimate !== undefined && Math.abs(estimate - r.coverage) > 0.0005;
  const run = h("button", { class: `btn small ${st.saved.size ? "primary" : ""}` }, icon("refresh", 14), "Run pass",
    st.saved.size ? h("span", { class: "pt-plus" }, `+${st.saved.size}`) : null) as HTMLButtonElement;
  run.addEventListener("click", () => rerun(run));
  clear(ui.coverage,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("gauge")), h("h2", {}, "Coverage"),
      h("span", { class: "end" }, badge(`Pass ${r.pass}`, "dark"), run)),
    h("div", { class: "pt-cov-row" },
      h("div", { class: "big" }, pct(r.coverage)),
      moved ? h("div", { class: "pt-est", title: "Estimate" }, icon("arrow", 18), `≈ ${pct(estimate)}`) : null,
      h("div", { class: "pt-cov-facts" }, familyChip(), tableChip(),
        h("span", { class: "small muted" }, `${r.name} · ${fmt.int(r.lines)} lines · ${r.seconds} s`),
        r.truncated ? badge(`first ${fmt.int(r.lines)}`, "warn") : null)),
    stackBar(c),
    passBars(r.history));
}

function familyChip(): HTMLElement {
  const family = st.result.family;
  if (family) return h("span", { class: "pt-family" }, familyLabel(family));
  const input = h("input", { type: "text", placeholder: "Log type name", "aria-label": "Log type name", style: { width: "150px" } }) as HTMLInputElement;
  const err = h("span");
  const create = h("button", { class: "btn small primary", onclick: async () => {
    try {
      const r = await api("/api/patterns/families", { body: { name: input.value, workspace: st.result.workspace } });
      st.result.family = r.family;
      await loadRules();
      drawCoverage(); drawBuilder(); drawRules();
    } catch (e) {
      clear(err, errorBox(e));
    }
  } }, icon("plus", 14), "Create");
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") create.click(); });
  return h("span", { class: "row pt-new-family" }, badge("Unknown type", "bad"), input, create, err);
}

/** A table: its format and the raw-log column it was read by. */
function tableChip(): HTMLElement | null {
  const layout = st.result.layout;
  if (!layout) return null;
  return h("span", { class: "pt-table-chip", title: "Raw logs" }, h("strong", {}, layout.format), icon("table", 14), h("code", {}, layout.raw));
}

function stackBar(c: Record<string, number>): HTMLElement[] {
  const shown = SEGMENTS.filter(([k]) => c[k] || k === "unknown");
  return [
    h("div", { class: "pt-stack", role: "img", "aria-label": shown.map(([k, label]) => `${label} ${c[k]}`).join(", ") },
      shown.filter(([k]) => c[k]).map(([k, label]) => h("span", { class: `pt-seg ${k}`, style: { flexGrow: String(c[k]) }, title: `${label} · ${fmt.int(c[k])}` }))),
    h("div", { class: "legend pt-legend" }, shown.map(([k, label]) =>
      h("span", {}, h("i", { class: `pt-dot ${k}` }), `${label} `, h("strong", {}, fmt.int(c[k]))))),
  ];
}

function passBars(history: any[]): HTMLElement | null {
  if (!history?.length) return null;
  return h("div", { class: "pt-passes" },
    h("span", { class: "tiny muted" }, "Passes"),
    h("div", { class: "pt-pass-bars" }, history.map((p, i) => h("div", {
      class: "pt-pass", title: `${p.at.slice(0, 16).replace("T", " ")} · ${p.rules} rules`,
    },
      h("span", { class: "pt-pass-v" }, pct(p.coverage, 0)),
      h("span", { class: "pt-pass-track" }, h("i", { style: { height: `${Math.max(2, p.coverage * 100)}%` } })),
      h("span", { class: "tiny muted" }, String(i + 1))))));
}

function drawTime(): void {
  const t = st.result.time, b: any[] = t.buckets;
  const most = Math.max(1, ...b.map((x) => x.lines));
  const label = (i: number) => h("span", {}, b[i]?.label ?? "");
  clear(ui.time,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(t.mode === "time" ? "calendar" : "individual")),
      h("h2", {}, t.mode === "time" ? "Over time" : "Through the data"),
      t.mode === "time" && t.field ? h("span", { class: "end" }, h("code", { class: "pt-field-name" }, t.field)) : null),
    h("div", { class: "pt-time" },
      h("div", { class: "pt-axis tiny muted" }, h("span", {}, "100%"), h("span", {}, "0")),
      h("div", { class: "pt-cols" }, b.map((x) => {
        const share = x.lines ? x.known / x.lines : 0;
        return h("div", { class: "pt-col", title: `${x.label} · ${fmt.int(x.lines)} lines · ${pct(share)}` },
          h("span", { class: "pt-col-bar" }, h("i", { style: { height: `${share * 100}%` } })),
          h("span", { class: "pt-col-vol" }, h("i", { style: { height: `${(x.lines / most) * 100}%` } })));
      }))),
    h("div", { class: "pt-time-x tiny muted" }, label(0), b.length > 2 ? label(Math.floor(b.length / 2)) : null, b.length > 1 ? label(b.length - 1) : null),
    h("div", { class: "legend", style: { marginTop: "8px" } },
      h("span", {}, h("i", { class: "pt-dot known" }), "known"), h("span", {}, h("i", { class: "pt-dot unknown" }), "unknown"),
      h("span", {}, h("i", { class: "pt-dot volume" }), "lines")));
}

/** A table's fields: per value, how many lines and how much of them is known; a value shows its lines. */
function drawFields(): void {
  const fields: any[] = st.result.fields ?? [];
  if (!fields.length) return clear(ui.fields);
  const f = fields.find((x) => x.name === st.field) ?? fields[0];
  const top = Math.max(1, ...f.values.map((v: any) => v.lines));
  const shown = fields.slice(0, 5);
  const more = fields.slice(5);
  const pick = (name: string) => { st.field = name; drawFields(); };
  const choose = more.length ? h("select", { "aria-label": "Field", onchange: (e: Event) => pick((e.target as HTMLSelectElement).value) },
    h("option", { value: "", selected: shown.some((x) => x.name === f.name) }, "…"),
    more.map((x) => h("option", { value: x.name, selected: x.name === f.name }, x.name))) : null;
  clear(ui.fields,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("filter")), h("h2", {}, "By field")),
    h("div", { class: "pt-field-pick" },
      h("div", { class: "pills small", role: "tablist" }, shown.map((x) => h("button", {
        class: x.name === f.name ? "on" : "", role: "tab", "aria-selected": String(x.name === f.name), onclick: () => pick(x.name),
      }, x.name))), choose),
    f.many ? h("div", { class: "pt-empty muted" }, h("strong", {}, "200+"))
      : h("div", { class: "pt-field-list list-scroll" }, f.values.map((v: any) => {
        const on = st.view.field === f.name && st.view.value === v.value;
        const share = v.lines ? v.known / v.lines : 0;
        const show = () => {
          st.view.field = on ? "" : f.name;
          st.view.value = on ? null : v.value;
          drawFields(); drawFilter(); void loadLines();
        };
        return h("button", { class: `pt-field-row ${on ? "on" : ""}`, onclick: show, title: `${v.value} · ${fmt.int(v.lines)} lines · ${pct(share)} known` },
          h("span", { class: "pt-field-v mono" }, v.value || "—"),
          h("span", { class: "pt-field-bar", style: { width: `${Math.max(4, (v.lines / top) * 100)}%` } },
            h("i", { style: { width: `${share * 100}%` } })),
          h("span", { class: "pt-field-n" }, fmt.int(v.lines), h("small", {}, pct(share, 0))));
      })));
}

// --- shapes of the unknown lines -------------------------------------------------------------------

// What a masked part of a shape stands for, in words.
const TOKEN_NAMES: Record<string, string> = { n: "number", "*": "any word", ip: "IP", hex: "hex id", path: "path", time: "time", mac: "MAC", empty: "empty" };

/** A shape's text with its masked parts (<time>, <ip>, <n>, <*>) as chips. */
function template(text: string): (string | HTMLElement)[] {
  return text.split(/(<[a-z*]+>)/).filter(Boolean).map((part) => /^<[a-z*]+>$/.test(part)
    ? h("span", { class: `pt-tok ${part === "<*>" ? "any" : ""}` }, TOKEN_NAMES[part.slice(1, -1)] ?? part.slice(1, -1)) : part);
}

function drawShapes(): void {
  const r = st.result;
  const covered = new Set<string>(st.lines?.covered ?? []);
  const list: any[] = r[st.tab === "lines" ? "shapes" : st.tab];
  const top = list[0]?.count || 1;
  // in the order of a line: what a prefix would cut, the message, what a suffix would cut (the slice colours)
  const tabs: [Tab, string][] = [["heads", "Prefix"], ["lines", "Message"], ["tails", "Suffix"]];
  clear(ui.shapes,
    h("div", { class: "card-head" }, h("h2", {}, "Shapes"),
      h("span", { class: "end pills small", role: "tablist" }, tabs.map(([t, label]) => h("button", {
        class: `${st.tab === t ? "on" : ""} pt-kind-${TAB_KIND[t]}`, role: "tab", "aria-selected": String(st.tab === t),
        onclick: () => { st.tab = t; drawShapes(); },
      }, label, h("span", { class: "pt-tab-n" }, String(r[t === "lines" ? "shapes" : t].length)))))),
    list.length
      ? h("div", { class: "pt-shape-list list-scroll" }, list.map((s) => shapeRow(s, top, covered.has(s.id))))
      : h("div", { class: "pt-empty" }, icon("check", 30)),
    st.tab === "lines" && r.small ? h("div", { class: "tiny muted", style: { marginTop: "8px" } }, `+ ${fmt.int(r.small)} lines in smaller shapes`) : null);
}

function shapeRow(s: any, top: number, done: boolean): HTMLElement {
  const kind = TAB_KIND[st.tab];
  const on = st.tab === "lines" && st.view.shape === s.id;
  const pick = () => {
    if (st.tab !== "lines") return void addShape(s, kind);
    st.view.shape = on ? "" : s.id;
    drawShapes(); drawFilter(); void loadLines();
  };
  return h("div", { class: `pt-shape ${on ? "on" : ""} ${done ? "done" : ""}`, tabindex: "0", onclick: pick,
    onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") pick(); } },
    h("span", { class: "pt-shape-n" }, h("span", { class: "pt-shape-bar" }, h("i", { style: { width: `${(s.count / top) * 100}%` } })), fmt.int(s.count)),
    h("span", { class: "pt-shape-t mono" }, template(s.template)),
    h("span", { class: "pt-shape-end" }, s.new ? badge("new", "warn") : null, done ? h("span", { class: "pt-done" }, icon("check", 15)) : null,
      h("button", { class: `pt-add ${kind}`, title: KIND_LABEL[kind], "aria-label": KIND_LABEL[kind],
        onclick: (e: Event) => { e.stopPropagation(); void addShape(s, kind); } }, icon("plus", 14))));
}

async function addShape(s: any, kind: Kind): Promise<void> {
  if (kind !== "rule") return addExamples(kind, s.examples);
  try {                                                  // a shape's lines, cut as the rules cut them now: their messages
    const r = await api("/api/patterns/lines", { body: { workspace: st.result.workspace, show: "unknown", shape: s.id } });
    const messages = r.lines.slice(0, 6).map((l: any) => (l.cut ? l.line.slice(l.cut[0], l.cut[1]) : l.line).trim());
    addExamples("rule", messages.length ? messages : s.examples);
  } catch (e) {
    clear(ui.examples ?? ui.builder, errorBox(e));
  }
}

// --- the canvas: kept lines, sliced into prefix | message | suffix ---------------------------------------

function drawCanvasFrame(): void {
  const search = h("input", { type: "search", placeholder: "Search", value: st.view.search, "aria-label": "Search", class: "pt-search" }) as HTMLInputElement;
  search.addEventListener("input", debounce(() => { st.view.search = search.value; void loadLines(); }, 250));
  const shows: [string, string][] = [["unknown", "Unknown"], ["known", "Known"], ["all", "All"]];
  const showPills = h("div", { class: "pills small", role: "tablist" });
  const drawShow = () => clear(showPills, shows.map(([v, label]) => h("button", {
    class: st.view.show === v ? "on" : "", role: "tab", "aria-selected": String(st.view.show === v),
    onclick: () => { st.view.show = v; drawShow(); void loadLines(); },
  }, label)));
  drawShow();
  ui.filter = h("span", { class: "pt-filter-box" });
  ui.list = h("div", { class: "pt-lines list-scroll" }, loading());
  ui.list.addEventListener("mouseup", () => setTimeout(selectionTools, 0));
  clear(ui.canvas,
    h("div", { class: "card-head" }, h("h2", {}, "Lines"),
      h("span", { class: "end pt-key" }, KINDS.map((k) => h("span", { class: `pt-key-${k}` }, KIND_LABEL[k])))),
    h("div", { class: "row pt-tools" }, showPills, search, ui.filter),
    ui.list);
  drawFilter();
}

function drawFilter(): void {
  const shape = st.view.shape ? st.result.shapes.find((s: any) => s.id === st.view.shape) : null;
  clear(ui.filter, shape ? h("button", { class: "pt-filter mono", title: "Clear", onclick: () => {
    st.view.shape = ""; drawFilter(); drawShapes(); void loadLines();
  } }, template(shape.template.length > 60 ? `${shape.template.slice(0, 60)}…` : shape.template), icon("close", 13)) : null,
  st.view.field && st.view.value !== null ? h("button", { class: "pt-filter mono", title: "Clear", onclick: () => {
    st.view.field = ""; st.view.value = null; drawFilter(); drawFields(); void loadLines();
  } }, h("strong", {}, st.view.field), ` = ${st.view.value || "—"}`, icon("close", 13)) : null);
}

async function loadLines(): Promise<void> {
  const seq = ++linesSeq;
  try {
    const r = await api("/api/patterns/lines", { body: { workspace: st.result.workspace, ...st.view } });
    if (seq !== linesSeq) return;
    st.lines = r;
    drawLineList(); drawCoverage(); drawShapes();
  } catch (e) {
    if (seq === linesSeq) clear(ui.list, errorBox(e));
  }
}

function drawLineList(): void {
  const rows: any[] = st.lines.lines;
  clear(ui.list, rows.length ? rows.map(lineRow) : h("div", { class: "pt-empty" }, icon(st.view.show === "unknown" ? "check" : "filter", 30)));
}

/** A table row's host and time fields as chips; every field on hover. */
function lineFields(fields: Record<string, string> | null): HTMLElement | null {
  if (!fields) return null;
  const layout = st.result.layout ?? {};
  const pick = [layout.time, layout.host].filter((n: string) => n && fields[n]);
  return h("span", { class: "pt-line-fields", title: Object.entries(fields).map(([k, v]) => `${k}: ${v}`).join("\n") },
    pick.map((n: string) => h("span", { class: "pt-line-field" }, n === layout.time ? fields[n].replace("T", " ").slice(0, 19) : fields[n])));
}

function lineRow(l: any): HTMLElement {
  const [a, b] = l.cut ?? [0, l.line.length];
  const message = l.line.slice(a, b);
  return h("div", { class: `pt-line ${l.known ? "known" : ""}` },
    h("span", { class: "pt-mark", title: l.rule === "builtin" ? "Phase 1" : l.event_type || undefined }, l.known ? icon("check", 13) : null),
    h("span", { class: "pt-text mono" }, lineFields(l.fields),
      l.prefix ? h("span", { class: "pt-pre" }, l.line.slice(0, a)) : l.line.slice(0, a),
      h("span", { class: "pt-msg" }, message),
      l.suffix ? h("span", { class: "pt-suf" }, l.line.slice(b)) : l.line.slice(b)),
    l.known ? null : h("button", { class: "pt-add rule", title: "Message", "aria-label": "Message",
      onclick: () => addExamples("rule", [message.trim()]) }, icon("plus", 14)));
}

/** A selection inside one line: a small bar to send it to Prefix, Message or Suffix. */
function selectionTools(): void {
  floating?.remove();
  floating = null;
  const sel = window.getSelection();
  const text = sel?.toString() ?? "";
  if (!sel || sel.isCollapsed || !text.trim() || /\n/.test(text.trimEnd())) return;
  const range = sel.getRangeAt(0);
  if (!ui.list.contains(range.commonAncestorContainer)) return;
  const rect = range.getBoundingClientRect();
  floating = h("div", { class: "pt-float", role: "toolbar", style: { left: `${rect.left + rect.width / 2}px`, top: `${rect.top}px` } },
    KINDS.map((k) => h("button", { class: `pt-float-${k}`, onmousedown: (e: Event) => e.preventDefault(), onclick: () => {
      addExamples(k, [k === "rule" ? text.trim() : text.replace(/\n/g, "")]);
      sel.removeAllRanges();
      floating?.remove();
      floating = null;
    } }, KIND_LABEL[k])));
  document.body.append(floating);
}

document.addEventListener("mousedown", (e) => {
  if (floating && !floating.contains(e.target as Node)) { floating.remove(); floating = null; }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && floating) { floating.remove(); floating = null; }
});
window.addEventListener("scroll", () => { floating?.remove(); floating = null; }, true);

// --- the regex: examples, candidates, a live try, save ------------------------------------------------

function addExamples(kind: Kind, examples: string[]): void {
  const tray = st.trays[kind];
  for (const e of examples) if (e.trim() && !tray.includes(e) && tray.length < MAX_TRAY) tray.push(e);
  st.kind = kind;
  drawBuilder();
  void suggest();
  ui.builder.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function drawBuilder(): void {
  const k = st.kind, d = st.drafts[k];
  const kinds = h("span", { class: "end pills small", role: "tablist" }, KINDS.map((x) => h("button", {
    class: `${st.kind === x ? "on" : ""} pt-kind-${x}`, role: "tab", "aria-selected": String(st.kind === x),
    onclick: () => { st.kind = x; drawBuilder(); },
  }, KIND_LABEL[x], h("span", { class: "pt-tab-n" }, String(st.trays[x].length)))));
  const regex = h("input", { type: "text", class: "mono pt-regex", value: d.regex, spellcheck: "false", placeholder: "Regex", "aria-label": "Regex" }) as HTMLInputElement;
  regex.addEventListener("input", debounce(() => { d.regex = regex.value; d.custom = true; drawCandidates(); void tryRegex(); }, 300));
  const event = h("input", { type: "text", class: "mono pt-event", value: d.event, placeholder: "EVENT_TYPE", spellcheck: "false", "aria-label": "Event type" }) as HTMLInputElement;
  event.addEventListener("input", () => { d.event = event.value.toUpperCase().replace(/[^A-Z0-9_]/g, "_"); d.eventTouched = true; });
  event.addEventListener("change", () => (event.value = d.event));
  ui.regex = regex;
  ui.event = event;
  const save = h("button", { class: "btn primary", title: st.result.family ? undefined : "Name the log type" }, icon("check", 16), "Save") as HTMLButtonElement;
  save.disabled = !st.result.family;
  save.addEventListener("click", () => saveRule(save));
  const paste = h("textarea", { rows: 2, spellcheck: "false", placeholder: "Paste examples", "aria-label": "Examples" }) as HTMLTextAreaElement;
  const add = h("button", { class: "btn small", onclick: () => addExamples(k, paste.value.split(/\r?\n/)) }, icon("plus", 14), "Add");
  ui.cands = h("div", { class: "pt-cands" });
  ui.reach = h("div", { class: "pt-reach" });
  ui.examples = h("div", { class: "pt-examples" });
  ui.saveErr = h("div");
  clear(ui.builder,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("patterns")), h("h2", {}, "Regex"), kinds),
    ui.cands,
    h("div", { class: `pt-editor ${k}` },
      k === "prefix" ? h("span", { class: "pt-anchor" }, "^") : null, regex, k === "suffix" ? h("span", { class: "pt-anchor" }, "$") : null,
      k === "rule" ? event : null, save),
    ui.reach, ui.saveErr, ui.examples,
    h("div", { class: "pt-paste" }, paste, add));
  drawCandidates(); drawTry();
}

async function suggest(): Promise<void> {
  const k = st.kind, d = st.drafts[k], examples = st.trays[k];
  const seq = ++suggestSeq;
  if (!examples.length) { d.candidates = null; drawCandidates(); return; }
  clear(ui.cands, loading());
  try {
    const r = await api("/api/patterns/suggest", { body: { kind: k, examples, family: st.result.family, workspace: st.result.workspace } });
    if (seq !== suggestSeq) return;
    d.candidates = r.candidates;
    if (!d.eventTouched && r.event_type) { d.event = r.event_type; if (st.kind === k && ui.event) (ui.event as HTMLInputElement).value = d.event; }
    const best = r.candidates.find((c: any) => c.covers === c.of) ?? r.candidates[0];
    if (best && !d.custom) choose(best);
    else { drawCandidates(); void tryRegex(); }
  } catch (e) {
    if (seq === suggestSeq) clear(ui.cands, errorBox(e));
  }
}

function choose(c: any): void {
  const d = st.drafts[st.kind];
  d.regex = c.regex;
  d.custom = false;
  if (ui.regex) (ui.regex as HTMLInputElement).value = c.regex;
  drawCandidates();
  void tryRegex();
}

function drawCandidates(): void {
  const d = st.drafts[st.kind];
  if (!d.candidates) return clear(ui.cands);
  clear(ui.cands, d.candidates.length ? d.candidates.map((c: any) => h("button", {
    class: `pt-cand ${d.regex === c.regex ? "on" : ""}`, onclick: () => choose(c), title: c.regex,
  },
    h("span", { class: "pt-cand-head" }, h("strong", {}, c.label),
      badge(`${c.covers}/${c.of}`, c.covers === c.of ? "ok" : "warn"),
      c.lines !== null && c.lines !== undefined ? h("span", { class: "small muted" }, `≈ ${fmt.int(c.lines)}`) : null),
    h("code", { class: "pt-cand-re" }, c.regex))) : h("span", { class: "small muted" }, "—"));
}

async function tryRegex(): Promise<void> {
  const k = st.kind, d = st.drafts[k];
  const seq = ++trySeq;
  if (!d.regex.trim()) { d.test = null; drawTry(); return; }
  try {
    const r = await api("/api/patterns/test", { body: { kind: k, regex: d.regex, examples: st.trays[k], workspace: st.result.workspace } });
    if (seq !== trySeq) return;
    d.test = r;
  } catch (e) {
    if (seq !== trySeq) return;
    d.test = { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  drawTry();
}

function drawTry(): void {
  const k = st.kind, d = st.drafts[k], t = d.test, tray = st.trays[k];
  const open = st.result.counts.sliced + st.result.counts.unknown;
  ui.regex?.classList.toggle("bad", Boolean(t && !t.ok));
  clear(ui.reach, t && !t.ok ? errorBox(t.error) : t && t.lines !== undefined ? h("div", { class: "pt-reach-row" },
    h("span", { class: "pt-reach-bar" }, h("i", { style: { width: `${open ? Math.min(100, (t.lines / open) * 100) : 0}%` } })),
    h("strong", {}, `≈ ${fmt.int(t.lines)}`), h("span", { class: "small muted" }, `/ ${fmt.int(open)}`)) : null);
  const results = t?.ok ? t.examples : [];
  clear(ui.examples, tray.map((text, i) => exampleRow(text, results[i], i)));
}

/** An example with what the regex takes highlighted and each group's name over its value. */
function exampleRow(text: string, t: any, i: number): HTMLElement {
  const shown: string = t?.text ?? text;
  const parts: (string | HTMLElement)[] = [];
  let stacked = false;
  if (t?.match) {
    const [s, e] = t.span;
    parts.push(h("span", { class: "pt-out" }, shown.slice(0, s)));
    const groups = [...t.groups].sort((a: any, b: any) => a.start - b.start);
    const inner: (string | HTMLElement)[] = [];
    let at = s, labelEnd = -1, raised = false;
    for (const g of groups) {
      if (g.start < at || g.end <= g.start) continue;                 // nested or empty groups: the outer one shows
      raised = g.start <= labelEnd && !raised;                        // a name that would run into the last one goes a row up
      if (raised) stacked = true;
      labelEnd = Math.max(labelEnd, g.start + Math.ceil(g.name.length * 0.8));
      inner.push(shown.slice(at, g.start), h("span", { class: `pt-grp${raised ? " up" : ""}`, "data-name": g.name }, shown.slice(g.start, g.end)));
      at = g.end;
    }
    inner.push(shown.slice(at, e));
    parts.push(h("mark", { class: "pt-hit" }, inner), h("span", { class: "pt-out" }, shown.slice(e)));
  } else {
    parts.push(shown);
  }
  return h("div", { class: `pt-ex ${t ? (t.match ? "ok" : "no") : ""} ${t?.groups?.length ? "named" : ""} ${stacked ? "stacked" : ""}` },
    h("span", { class: "pt-ex-mark" }, t ? icon(t.match ? "check" : "close", 14) : null),
    h("span", { class: "pt-ex-text mono" }, parts),
    h("button", { class: "pt-ex-x", title: "Remove", "aria-label": "Remove", onclick: () => {
      st.trays[st.kind].splice(i, 1);
      drawBuilder();
      void suggest();
    } }, icon("close", 13)));
}

async function saveRule(button: HTMLButtonElement): Promise<void> {
  const k = st.kind, d = st.drafts[k];
  button.disabled = true;
  try {
    const r = await api("/api/patterns/rules", { body: { family: st.result.family, kind: k, regex: d.regex, event_type: d.event, examples: st.trays[k] } });
    st.saved.add(r.id);
    st.trays[k] = [];
    st.drafts[k] = blankDraft();
    await loadRules();
    drawBuilder(); drawRules();
    await loadLines();
  } catch (e) {
    clear(ui.saveErr, errorBox(e));
    button.disabled = false;
  }
}

async function rerun(button: HTMLButtonElement): Promise<void> {
  button.disabled = true;
  const title = `Pass ${st.result.pass + 1}`;
  const loader = sqlLoader(title);                     // the SQL query's animation, in place of the results until the pass is done
  const results = ui.results;
  clear(results, h("div", { class: "card" }, loader.el));
  try {
    const { job } = await api("/api/patterns/pass", { body: { workspace: st.result.workspace } });
    const result = await follow(job, (detail) => loader.say(caption(title, detail)));
    await loader.arrive();
    st.result = result;
    st.saved.clear();
    st.view.shape = "";                                  // shapes are numbered afresh each pass
    if (st.view.field && !st.result.fields?.some((f: any) => f.name === st.view.field)) { st.view.field = ""; st.view.value = null; }
    await loadRules();
    drawResults(results);
  } catch (e) {
    await loader.fail();
    drawResults(results);                              // the last pass again, with what went wrong above it
    results.prepend(errorBox(e));
  }
}

// --- the log type's rules -------------------------------------------------------------------------------

function drawRules(): void {
  const r = st.result, info = st.rules;
  ui.rules.hidden = !r.family;                           // nothing to list before the log type has a name
  if (!r.family) return clear(ui.rules);
  const hits = r.hits ?? {};
  const copy = h("button", { class: "btn small" }, icon("copy", 14), "Copy for Phase 1") as HTMLButtonElement;
  copy.addEventListener("click", async () => {
    const out = await api(`/api/patterns/export${qs({ family: r.family })}`);
    await navigator.clipboard.writeText(out.phase1);
    clear(copy, icon("check", 14), "Copy for Phase 1");
    setTimeout(() => clear(copy, icon("copy", 14), "Copy for Phase 1"), 1600);
  });
  const download = h("button", { class: "btn small", onclick: async () => {
    const out = await api(`/api/patterns/export${qs({ family: r.family })}`);
    const link = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(out.pack, null, 2)], { type: "application/json" })),
      download: `patterns-${r.family}.json` });
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  } }, icon("download", 14), "Export");
  const rows: any[] = info.rules;
  const hitCell = (id: string | number) => {
    const x = hits[String(id)];
    if (!x) return st.saved.has(Number(id)) ? h("span", { class: "muted" }, "—") : badge("no hits", "muted");
    return h("span", { class: "pt-hits" },
      h("span", { class: "pt-hit-bar" }, h("i", { style: { width: `${Math.min(100, (x.hits / r.lines) * 100)}%` } })),
      fmt.int(x.hits), x.quiet ? badge("quiet", "warn") : null, r.slow.includes(String(id)) ? badge("slow", "bad") : null);
  };
  const act = async (body: any) => {
    try { await api(body.delete ? "/api/patterns/rules/delete" : "/api/patterns/rules/update", { body }); }
    catch (e) { ui.rules.append(errorBox(e)); return; }
    await loadRules();
    drawRules();
    void loadLines();
  };
  const firstOf = (kind: string) => rows.find((x) => x.kind === kind)?.id;
  clear(ui.rules,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("table")), h("h2", {}, `Rules · ${familyLabel(r.family)}`),
      h("span", { class: "end" }, copy, download)),
    h("div", { class: "table-wrap" }, h("table", { class: "pt-rule-table" },
      h("thead", {}, h("tr", {}, ["", "Kind", "Event type", "Regex", "Hits", ""].map((c) => h("th", { scope: "col" }, c)))),
      h("tbody", {},
        info.builtin_prefix ? h("tr", { class: "pt-builtin" },
          h("td", {}, icon("lock", 14)), h("td", {}, h("span", { class: "pt-kind prefix" }, "Prefix")), h("td", { class: "muted" }, "Phase 1"),
          h("td", {}, h("code", { class: "pt-re", title: info.builtin_prefix }, info.builtin_prefix)), h("td", {}, hitCell("builtin")), h("td")) : null,
        rows.map((x) => h("tr", { class: x.enabled ? "" : "off" },
          h("td", {}, x.id !== firstOf(x.kind) ? h("button", { class: "icon-btn small", title: "Up", "aria-label": "Up",
            onclick: () => act({ id: x.id, move: "up" }) }, icon("up", 14)) : null),
          h("td", {}, h("span", { class: `pt-kind ${x.kind}` }, KIND_LABEL[x.kind as Kind])),
          h("td", {}, x.event_type ? h("code", {}, x.event_type) : null),
          h("td", {}, h("code", { class: "pt-re", title: x.regex }, x.regex)),
          h("td", {}, hitCell(x.id)),
          h("td", { class: "pt-acts" },
            h("label", { class: "pt-switch", title: x.enabled ? "On" : "Off" },
              h("input", { type: "checkbox", checked: Boolean(x.enabled), "aria-label": "On",
                onchange: (e: Event) => act({ id: x.id, enabled: (e.target as HTMLInputElement).checked }) }), h("span")),
            h("button", { class: "icon-btn small", title: "Delete", "aria-label": "Delete", onclick: () => {
              if (confirm(`Delete ${x.event_type || KIND_LABEL[x.kind as Kind]}?`)) void act({ id: x.id, delete: true });
            } }, icon("trash", 14))))),
        !rows.length && !info.builtin_prefix ? h("tr", {}, h("td", { colspan: "6", class: "muted" }, "—")) : null))));
}
