// Audit (service/audit.py): a small random sample of the test period each month, labelled blind. The page shows an
// item's lines and nothing else (no score, flag or stratum), so the label is not anchored; the estimates it feeds
// (precision of the flagged, miss rate of the unflagged, recall) are the only unbiased ones the console has.

import { api } from "../api";
import { badge, clear, errorBox, fmt, h, loading, select, table } from "../dom";
import { icon } from "../icons";
import { sourceLabel } from "../state";
import { VERDICTS, verdictLabel } from "../verdicts";

let month = "";
let picked = "";

const pct = (v: number | null | undefined, digits = 1) => (v === null || v === undefined ? "—" : `${(v * 100).toFixed(digits)}%`);
const range = (s: any, digits = 1) => (s && s.estimate !== null ? `${pct(s.low, digits)}–${pct(s.high, digits)}` : "");

export async function renderAudit(main: HTMLElement): Promise<void> {
  const body = h("div", {}, loading());
  clear(main, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Audit"))), body);
  const draw = async (): Promise<void> => {
    let data: any;
    try { data = await api(`/api/audit-sample${month ? `?month=${month}` : ""}`); } catch (e) { clear(body, errorBox(e)); return; }
    month = data.month;
    const detail = h("div", { class: "card audit-detail" });
    const list = h("div", { class: "card" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("audit")), h("h2", {}, "Sample"),
        h("span", { class: "end row", style: { gap: "8px" } },
          data.months.length ? select(data.months.map((m: string) => [m, m]), month, (v) => { month = v; picked = ""; void draw(); }) : null,
          data.items.length ? null : h("button", { class: "btn small primary", onclick: async () => {
            try { await api("/api/audit-sample/draw", { body: {} }); month = ""; void draw(); } catch (e) { clear(body, errorBox(e)); }
          } }, icon("play", 14), "Draw"))),
      data.items.length
        ? h("div", { class: "audit-list" }, data.items.map((it: any) => h("button", {
            class: `audit-row ${it.item_id === picked ? "on" : ""}`, type: "button",
            onclick: () => { picked = it.item_id; void draw(); },
          }, h("span", { class: "mono" }, `#${it.n}`), h("span", { class: "small muted" }, sourceLabel(it.source)),
            it.verdict ? h("span", { class: `badge v-${it.verdict}` }, verdictLabel(it.verdict)) : h("span", { class: "badge muted" }, "to label"))))
        : h("p", { class: "muted small" }, "—"));
    clear(body, estimatesCard(data.estimates), h("div", { class: "grid split" }, list, detail));
    const item = data.items.find((it: any) => it.item_id === picked) ?? data.items.find((it: any) => !it.verdict);
    if (item) { picked = item.item_id; drawItem(detail, item, draw); } else clear(detail, h("p", { class: "muted" }, "—"));
  };
  void draw();
}

function estimatesCard(e: any): HTMLElement {
  const stat = (label: string, s: any, scale = 1, unit = "") => h("div", { class: "audit-stat" },
    h("div", { class: "tiny muted mono" }, label),
    h("div", { class: "big" }, s?.estimate !== null && s?.estimate !== undefined ? (scale === 1 ? pct(s.estimate) : fmt.num(s.estimate * scale, 1) + unit) : "—"),
    h("div", { class: "small muted mono" }, s && s.estimate !== null ? `95% ${scale === 1 ? range(s) : `${fmt.num(s.low * scale, 1)}–${fmt.num(s.high * scale, 1)}`} · n ${fmt.int(s.n)}` : ""));
  const o = e.overall ?? {};
  const mechanisms = Object.entries(e.mechanisms ?? {}) as [string, any][];
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("gauge")), h("h2", {}, "Estimates"),
      h("span", { class: "end small muted mono" }, `${fmt.int(e.labelled)} / ${fmt.int(e.drawn)} labelled`)),
    h("div", { class: "row audit-stats" }, stat("Precision", o.precision), stat("Miss rate / 10,000", o.miss_rate, 10000), stat("Recall", o.recall)),
    mechanisms.length ? table(["Mechanism", "n", "Precision", "95%"], mechanisms.map(([m, s]) => [m.replace(/_/g, " "), fmt.int(s.n), pct(s.estimate), range(s)])) : null);
}

async function drawItem(el: HTMLElement, item: any, refresh: () => void): Promise<void> {
  clear(el, loading());
  let obs: any;
  try { obs = await api(`/api/audit-sample/item?source=${item.source}&view=${item.view}&row=${encodeURIComponent(item.row_id)}`); }
  catch (e) { clear(el, errorBox(e)); return; }
  const note = h("textarea", { rows: 2, "aria-label": "Note", placeholder: "Note", style: { fontFamily: "var(--font-body)" } }) as HTMLTextAreaElement;
  note.value = item.note ?? "";
  const err = h("div");
  const around = h("div");
  let saving = false;
  const decide = async (verdict: string) => {
    if (saving) return;
    const need = VERDICTS.find((v) => v.id === verdict)?.note;
    if (need && !note.value.trim()) { note.classList.add("needs"); note.placeholder = need.replace(/^./, (c) => c.toUpperCase()); note.focus(); return; }
    saving = true;
    try {
      await api("/api/review", { body: { source: item.source, view: item.view, item_id: item.item_id, kind: "audit", verdict, note: note.value } });
      refresh();
    } catch (e) { saving = false; clear(err, errorBox(e)); }
  };
  const showAround = async () => {
    clear(around, loading());
    try {
      const r = await api("/api/review/context", { body: { source: item.source, view: item.view, id: item.row_id, before: 10, after: 10 } });
      clear(around, h("div", { class: "rp-ll-lines list-scroll" }, r.rows.map((row: any[]) =>
        h("div", { class: "rp-ll-line ctx" }, h("span", { class: "t" }, String(row[1]).slice(11, 19)), h("span", { class: "g" }, String(row[0]).toUpperCase()),
          h("span", { class: "l" }, String(row[4] ?? ""))))));
    } catch (e) { clear(around, errorBox(e)); }
  };
  clear(el,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("review")), h("h2", {}, `#${item.n}`),
      h("span", { class: "end" }, item.verdict ? badge(verdictLabel(item.verdict), "muted") : badge("to label", "dark"))),
    h("div", { class: "row", style: { gap: "8px", marginBottom: "10px" } },
      obs.server ? h("span", { class: "who-chip server" }, obs.server) : null,
      h("span", { class: "mono small" }, obs.start === obs.end ? obs.start : `${obs.start} → ${obs.end}`)),
    obs.lines?.length
      ? h("div", { class: "rp-ll-lines list-scroll" }, obs.lines.map((line: string, n: number) =>
          h("div", { class: "rp-ll-line own" }, h("span", { class: "t" }, String(n + 1)), h("span", { class: "l" }, line))))
      : h("p", { class: "muted small" }, obs.lines_status === "purged" ? "Lines purged" : "—"),
    h("div", { class: "row", style: { marginTop: "8px" } }, h("button", { class: "btn small", onclick: showAround }, icon("data", 14), "Lines around")),
    around,
    h("div", { class: "verdict-buttons", style: { marginTop: "14px" } }, VERDICTS.map((v) =>
      h("button", { class: `btn ${v.id} ${item.verdict === v.id ? "on" : ""}`, title: v.hint, onclick: () => decide(v.id) }, v.label))),
    note, err);
}
