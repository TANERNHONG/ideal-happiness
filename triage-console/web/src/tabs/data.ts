// Data: the training / validation / test timeline, messages by type (Sankey),
// named clusters with messages and comments, and read-only SQL.

import { api } from "../api";
import { badge, clear, errorBox, fmt, h, loading, pills, table } from "../dom";
import { icon, viewIcon } from "../icons";
import { dataScope, logTypePicker, shownSources } from "../log-type";
import { isLocked, lockedCard, sqlApi } from "../sql-lock";
import { csvText } from "../tables";
import { sourceLabel, state, viewLabel } from "../state";
import { sqlLoader } from "../loaders";
import { drawClusters, linesBlock } from "./clusters";
import { drawSankeys } from "./sankey";

type Sub = "sankey" | "clusters" | "sql";
let sub: Sub = "sankey";

const SUBS: Sub[] = ["sankey", "clusters", "sql"];

export function renderData(main: HTMLElement): void {
  // #/data/sql and #/data/clusters open that part directly (bookmarkable); switching updates the address quietly.
  const linked = location.hash.split("/")[2] as Sub | undefined;
  if (linked && SUBS.includes(linked)) sub = linked;
  const body = h("div");
  const draw = () => ({ sankey: drawSankeys, clusters: drawClusters, sql: drawSql })[sub](body);
  const spans = h("div", {}, loading());
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Data")),
      logTypePicker((v) => { dataScope.all = v === "all"; draw(); drawSpans(spans); },
        { extra: [["all", "All log types"]], value: dataScope.all ? "all" : undefined })),
    h("div", { class: "row", style: { marginBottom: "14px" } },
      pills([["sankey", "Message types"], ["clusters", "Clusters"], ["sql", "SQL"]] as [Sub, string][], sub, (v) => {
        sub = v;
        history.replaceState(null, "", `#/data/${v}`);
        draw();
      })),
    spans, body);
  draw();
  drawSpans(spans);
}

// --- split timeline -------------------------------------------------------------------

const T0 = Date.parse("2025-08-01T00:00:00"), T1 = Date.parse("2026-08-01T00:00:00");
const at = (s: string) => Math.max(0, Math.min(100, ((Date.parse(s.replace(" ", "T")) - T0) / (T1 - T0)) * 100));

async function drawSpans(el: HTMLElement): Promise<void> {
  const shown = shownSources();
  const splits = (await api("/api/data/splits")).splits.filter((s: any) => shown.includes(s.source));
  const months = Array.from({ length: 12 }, (_, i) => new Date(2025, 7 + i, 1));
  const ymd = (m: Date) => `${m.getFullYear()}-${String(m.getMonth() + 1).padStart(2, "0")}-01`;
  const gridLines = () => months.map((m) => h("span", { class: "grid-line", style: { left: `${at(ymd(m))}%` } }));
  const bySource = new Map<string, any[]>();
  for (const s of splits) bySource.set(s.source, [...(bySource.get(s.source) ?? []), s]);
  const seg = (cls: string, part: any, label: string) => h("span", {
    class: `seg ${cls}`, style: { left: `${at(part.start)}%`, width: `${Math.max(0.6, at(part.end) - at(part.start))}%` },
    title: `${label}: ${part.start.slice(0, 10)} → ${part.end.slice(0, 10)} · ${fmt.int(part.rows)} rows`,
  });
  clear(el, h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("calendar")), h("h2", {}, "Training, validation, test"),
      h("span", { class: "end legend" },
        h("span", {}, h("i", { style: { background: "var(--split-train)" } }), "training"),
        h("span", {}, h("i", { style: { background: "var(--split-val)" } }), "validation"),
        h("span", {}, h("i", { style: { background: "var(--split-test)" } }), "test"),
        h("span", {}, h("i", { class: "seg baseline", style: { borderRadius: "2px" } }), "quiet-day baseline"))),
    h("div", { class: "timeline" },
      h("div", { class: "axis" }, h("span"), h("div", { class: "ticks" },
        months.map((m) => h("span", { style: { left: `${at(ymd(m)) + 4.1}%` } },
          m.toLocaleString("en", { month: "short" }) + (m.getMonth() === 0 || m.getMonth() === 7 ? ` ${String(m.getFullYear()).slice(2)}` : ""))))),
      [...bySource.entries()].map(([source, rows]) => [
        h("div", { class: "group" }, sourceLabel(source)),
        rows.map((s: any) => h("div", { class: "tl-row" },
          h("div", { class: "tl-label" }, viewIcon(s.view, 16), viewLabel(source, s.view)),
          h("div", { class: "track" }, gridLines(),
            s.method === "time"
              ? [seg("train", s.train, "Training"), seg("validation", s.validation, "Validation"), seg("test", s.test, "Test")]
              : h("span", { class: "seg baseline", style: { left: "0%", width: "100%" },
                  title: `${s.note}\nBaseline ${fmt.int(s.train.rows)} train + ${fmt.int(s.validation.rows)} validation periods; ${fmt.int(s.test.rows)} scored.` })))),
      ]))));
}

export { linesBlock };

// --- SQL ------------------------------------------------------------------------------

let sqlText = "";

async function drawSql(body: HTMLElement): Promise<void> {
  clear(body, h("div", { class: "card" }, sqlLoader("Opening the log stores").el));
  let schema: any;
  try {
    schema = await sqlApi("/api/sql/schema");                 // asks for the SQL password first (sql-lock.ts)
  } catch (e) {
    return clear(body, isLocked(e) ? lockedCard(() => void drawSql(body)) : errorBox(e));
  }
  if (state.pendingSql) { sqlText = state.pendingSql; state.pendingSql = ""; }   // from Review's "Open in SQL"
  if (!sqlText) sqlText = schema.examples[0].sql;
  const { sqlEditor, readOnlyProblem } = await import("../sql-editor");      // CodeMirror loads only when the SQL tab is opened
  const host = h("div", { class: "sql-editor-host" });
  const out = h("div");
  const run = h("button", { class: "btn primary" }, icon("play", 14), "Run") as HTMLButtonElement;
  const warning = h("div", { class: "sql-warning", role: "status" });
  let running = false;
  const refresh = () => {                          // early warning only; the service checks again and decides
    const problem = readOnlyProblem(editor.value);
    clear(warning, problem ? [icon("lock", 14), problem] : null);
    run.disabled = running || Boolean(problem);
  };
  const execute = async () => {
    if (running || readOnlyProblem(editor.value)) return;   // already running, or not a read-only query
    running = true;
    run.disabled = true;
    const loader = sqlLoader("Running query");
    clear(out, loader.el);
    try {
      const r = await sqlApi("/api/sql", { query: editor.value });
      await loader.arrive();                                  // the train pulls in, or the monkey claps its last (Settings → Animations)
      const csv = () => {
        const blob = new Blob([csvText(r.columns, r.rows)], { type: "text/csv" });
        h("a", { href: URL.createObjectURL(blob), download: "query.csv" }).click();
      };
      clear(out, h("div", { class: "row", style: { margin: "10px 0" } },
        h("span", { class: "small muted" }, `${fmt.int(r.rows.length)} rows · ${r.seconds} s${r.truncated ? ` · first ${schema.max_rows}` : ""}`),
        h("button", { class: "btn small", onclick: csv }, "CSV")),
        table(r.columns, r.rows.map((row: unknown[]) => row.map((v) => (v === null ? h("span", { class: "muted" }, "null") : String(v))))));
    } catch (e) {
      await loader.fail();                                    // into the depot, or a cymbal falls
      clear(out, errorBox(e));
    } finally {
      running = false;
      refresh();
    }
  };
  run.addEventListener("click", execute);
  clear(body, h("div", { class: "grid", style: { gridTemplateColumns: "minmax(0, 1fr) 260px", alignItems: "start" } },
    h("div", { class: "stack" },
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("data")), h("h2", {}, "Query"),
          h("span", { class: "end small muted", title: `Read only · one SELECT · ${schema.max_rows} rows max · ${schema.time_limit} s limit · filter auth.events on timestamp_epoch or host_id` }, "read only")),
        h("div", { class: "row", style: { marginBottom: "10px" } },
          schema.examples.map((ex: any) => h("button", { class: "btn small", onclick: () => editor.setValue(ex.sql) }, ex.title))),
        host, warning,
        h("div", { class: "row end", style: { marginTop: "10px" } },
          h("span", { class: "tiny muted" }, "Ctrl+Space suggests table and column names · Ctrl+Enter runs"), run),
        out),
      chatbotConcept()),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Tables")),
      Object.entries(schema.tables).map(([name, cols]) => h("details", {},
        h("summary", {}, h("code", {}, name)),
        h("div", { class: "small mono", style: { padding: "4px 0 8px 12px" } }, (cols as string[]).map((c) => h("div", {}, c))))))));
  const editor = sqlEditor(host, { value: sqlText, tables: schema.tables, onChange: (text) => { sqlText = text; refresh(); }, onRun: execute });
  refresh();
}

// TODO: SQL chatbot. Ask in plain language; the local model (the one picked at the
// top right) writes a read-only query against the tables listed on this tab, shows
// it in the editor for checking, and only runs it when the user presses Run. Needs:
// a service endpoint that prompts the model with the table schema and examples,
// a check that the answer is read-only (sql_guard.py already refuses anything else),
// and a way to explain a query back in plain words.
function chatbotConcept(): HTMLElement {
  return h("div", { class: "card accent" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("analyze")), h("h2", {}, "Ask in plain language"),
      h("span", { class: "end" }, badge("TODO", "warn"))),
    h("div", { class: "concept" },
      h("div", { class: "small" }, `Describe what you want to find. ${state.settings.llm_model} will write the query, put it in the editor for you to check, and you press Run.`),
      h("div", { class: "comment", style: { margin: "10px 0 6px" } }, h("span", { class: "who" }, "You"),
        h("p", {}, "Which addresses failed to log in to mm04kco more than 20 times in July?")),
      h("div", { class: "comment" }, h("span", { class: "who" }, "Model"),
        h("pre", { class: "lines", style: { margin: "6px 0 0" } },
          "SELECT source_ip, COUNT(*) AS failures\nFROM auth.events\nWHERE host_id = 'mm04kco' AND event_type = 'SSH_LOGIN_FAILED'\n" +
          "  AND timestamp_epoch BETWEEN strftime('%s','2026-07-01') AND strftime('%s','2026-08-01')\nGROUP BY source_ip\nHAVING failures > 20")),
      h("div", { class: "row", style: { marginTop: "10px" } },
        h("input", { type: "text", disabled: true, placeholder: "Ask about the logs…", "aria-label": "Question for the chatbot (not available yet)", style: { flex: "1" } }),
        h("button", { class: "btn small", disabled: true }, "Ask"))));
}
