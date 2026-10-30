// Dashboard: what needs a decision, what to open first, and how the work and the data stand. Read top to bottom:
// four figures to act on (waiting, Sigma matches waiting, security relevant, reviewed); the next items to open beside
// review progress; then context (how much the detectors flag, what data there is); then detail (what the models
// learned from, how the console is used). Explanations sit behind each card's info icon; a table icon swaps a chart
// for its table; every mark has a hover / keyboard tooltip. Settings → Dashboard can reorder, resize and hide the cards
// and add SQL tables and tiles of the person's own (dashboard-layout.ts); its preview draws them with the same builders
// (dashboardCards, sqlCard, tileCard).
//
// Colour: review states use status colours, always with labels; training / validation / test use one red
// stepped dark to light (they happen in that order).

import { api } from "../api";
import { TILE_LINKS, cardInfo, isTile, isWidget, normalise, type Layout } from "../dashboard-layout";
import type { DashboardTile, DashboardWidget } from "../api";
import { badge, clear, errorBox, fmt, h, loading, pct, svg, table, type Child } from "../dom";
import { icon } from "../icons";
import { isLocked, sqlApi } from "../sql-lock";
import { state } from "../state";
import { tip, withTip } from "../tooltip";
import { VERDICTS } from "../verdicts";
import { count, dateSpan } from "../words";
import { TYPE_ICONS, openInProfiles, spark, watchTag } from "./profiles";
import { openInReview, title } from "./review";

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const num = (n: number | null | undefined) => (n === null || n === undefined ? "…" : n >= 10_000 ? compact.format(n) : fmt.int(n));
const share = (p: number) => pct(p, p > 0 && p < 0.01 ? 2 : 1);

const STATES: [string, string, string][] = [
  ["open", "Needs review", "var(--st-open)"],
  ["whitelisted", "Whitelisted", "var(--st-wl)"],
  ...VERDICTS.map((v): [string, string, string] => [v.id, v.label, v.color]),
];
const SPLITS: [string, string, string][] = [
  ["train_rows", "Training", "var(--split-train)"],
  ["validation_rows", "Validation", "var(--split-val)"],
  ["test_rows", "Test", "var(--split-test)"],
];
const ACTIONS: [string, string][] = [
  ["analyze", "Analyses"], ["sql", "SQL queries"], ["review", "Reviews"], ["comment", "Comments"],
];
const ACTION_NAMES: Record<string, string> = {
  analyze: "analyses", sql: "queries", review: "reviews", comment: "comments", rename_cluster: "renames",
  settings: "settings changes", clear_activity_log: "log cleared", change_password: "password changes",
  whitelist_add: "accounts whitelisted", whitelist_remove: "accounts removed from the whitelist",
  watch: "entities watched", unwatch: "entities unwatched",
};
const PAGES: Record<string, string> = {
  dashboard: "Dashboard", analyze: "Analyze", models: "Models", data: "Data", review: "Review", explain: "Explain", profiles: "Profiles",
  docs: "Documentation", settings: "Settings",
};
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// What each card's info icon says
const INFO = {
  open: "Groups of unusual events and firewall items with no label yet. A group whose flagged events all belong to whitelisted accounts is counted as Whitelisted instead.",
  sigma: "Waiting items with at least one event matching a Sigma rule: a known attack pattern. Open these first.",
  security: "Items labelled Security relevant: hostile or unauthorised activity shown or strongly suggested. Suspicious: could be hostile, needs a closer look.",
  reviewed: "Share of all items with a label or covered by the whitelist. Columns: review decisions per day over the last 30 days.",
  next: "Waiting items matching a Sigma rule first, then each log type's most unusual groups in turn. Open one to review it.",
  progress: "Every item by its state: waiting, whitelisted, or the label it was given.",
  yield: "For each mechanism, the labelled items it raised (n): precision is the share labelled Security relevant or Suspicious, expected the share labelled Expected behaviour. An item counts for every mechanism that flagged it.",
  audit: "From the blind random sample on the Audit page: precision of flagged observations, missed relevant ones per 10,000 unflagged, and recall, each with its 95% interval and n labelled.",
  triage: "From keeping an upload to the first label on any of its items: the median, the P10–P90 range and n, the uploads labelled.",
  flagged: "Share of the test period's AUTH sessions and OSSEC episodes flagged by at least one detector. Detectors: which of the four flagged them, and how many were flagged by several.",
  data: "Lines read from each log over the year, the months they span, the kinds of event, and the distinct messages found.",
  models: "Rows each model learned from (training), was tuned on (validation) and is judged on (test), per view. Each log type has its own scale. PF and IPFilter learn from quiet periods, so they count periods, not lines.",
  activity: "What the console was used for over the last 30 days, with totals since counting began.",
  watched: "Entities watched in Profiles, on their log type's last day: x (lines that day) against the median of the same weekday's training days, and 8 weeks of daily totals. PF and IPFilter: x only (normal is no activity).",
};

export async function renderDashboard(main: HTMLElement): Promise<void> {
  const period = h("span", { class: "dash-period" });
  const body = h("div", {}, loading());
  clear(main, h("div", { class: "page-head" }, h("h1", {}, "Dashboard"), period), body);
  let d: any;
  try {
    d = await api("/api/dashboard");
  } catch (e) {
    return clear(body, errorBox(e));
  }
  clear(period, dataPeriod(d));
  const grid = h("div", { class: "dash-grid" });
  clear(body, grid);
  layDashboard(grid, d, normalise(state.settings.dashboard_layout));
}

/** The months the data spans, for the page header. */
export function dataPeriod(d: any): string {
  return months(d.data.map((r: any) => r.first_month).filter(Boolean).sort()[0], d.data.map((r: any) => r.last_month).filter(Boolean).sort().pop());
}

/** A card at ``span`` columns of the grid (narrow ones go two to a row on a small screen). */
export function sized(el: HTMLElement, span: number): HTMLElement {
  el.style.gridColumn = `span ${span}`;
  el.classList.toggle("dash-small", span <= 4);
  return el;
}

/** Each card, by its name in dashboard-layout.ts, drawn from ``d`` (an /api/dashboard answer). */
export function dashboardCards(d: any): Record<string, () => HTMLElement> {
  const total = (key: string) => d.review.reduce((s: number, r: any) => s + (r[key] ?? 0), 0);
  const reviews = lastDays(d.usage.days).map((day) => ({ day, n: d.usage.recent.filter((r: any) => r.day === day && r.event === "review").reduce((s: number, r: any) => s + r.n, 0) }));
  const items = total("total"), waiting = total("open");
  return {
    open: () => kpi("open", fmt.int(waiting), INFO.open, bySource(d.review, "open")),
    sigma: () => kpi("sigma", fmt.int(total("sigma_open")), INFO.sigma, bySource(d.review, "sigma_open"), total("sigma_open") > 0 ? "alarm" : ""),
    security: () => kpi("security", fmt.int(total("security_relevant")), INFO.security, bySource(d.review, "security_relevant"), "",
      h("span", { class: "dash-second" }, h("i", { style: { background: "var(--st-warn)" } }), h("strong", {}, fmt.int(total("suspicious"))), "Suspicious")),
    reviewed: () => kpi("reviewed", items ? share((items - waiting) / items) : "—", INFO.reviewed,
      h("div", { class: "dash-foot" }, meter(items ? (items - waiting) / items : 0, "var(--st-good)"),
        columns(reviews.map((r) => ({ ...r, text: `${dayLabel(r.day)} · ${fmt.int(r.n)} review${r.n === 1 ? "" : "s"}` })), 40))),
    triage: () => kpi("triage", d.triage?.n ? duration(d.triage.median) : "—", INFO.triage,
      d.triage?.n ? h("div", { class: "dash-split" }, h("span", { class: "dash-chip" }, "P10–P90",
        h("strong", {}, `${duration(d.triage.p10)}–${duration(d.triage.p90)}`)), h("span", { class: "dash-chip" }, "n", h("strong", {}, fmt.int(d.triage.n))))
        : null),
    next: () => nextCard(d.next),
    progress: () => progressCard(d.review),
    yield: () => yieldCard(d.yields ?? []),
    audit: () => auditCard(d.audit ?? {}),
    flagged: () => outliersCard(d.outliers),
    data: () => dataCard(d.data, d.variants_ready),
    models: () => modelsCard(d.models),
    activity: () => usageCard(d.usage),
    watched: () => watchedCard(d.watched ?? []),
  };
}

/** The cards of ``layout`` in its order and widths, into ``grid``. */
export function layDashboard(grid: HTMLElement, d: any, layout: Layout): void {
  const build = dashboardCards(d);
  clear(grid, layout.cards.map(({ id, span }) =>
    sized(isWidget(id) ? sqlCard(id, layout.widgets![id], d.widgets?.[id]) : isTile(id) ? tileCard(id, layout.tiles![id]) : build[id](), span)));
  pack(grid, layout.packed === true);
}

const ROW = 8, GAP = 16;                            // a packed grid's row and the gap kept under each card, in pixels
const packing = new WeakMap<HTMLElement, ResizeObserver>();

/** Pack tightly (Settings → Dashboard): the grid's rows are ROW pixels and each card spans as many as its own height
 * needs (it keeps that height rather than stretching to its row's tallest), so later cards fill the gaps (dense flow) and
 * short cards stack beside tall ones. Heights are watched, so a card that grows or shrinks (its data arriving, the window
 * resized) keeps its room. Called again whenever the grid's cards change. */
export function pack(grid: HTMLElement, on: boolean): void {
  packing.get(grid)?.disconnect();
  grid.classList.toggle("packed", on);
  const cards = [...grid.children] as HTMLElement[];
  if (!on) {
    cards.forEach((el) => { el.style.gridRowEnd = ""; });
    return;
  }
  const fit = (el: HTMLElement) => { el.style.gridRowEnd = `span ${Math.max(1, Math.ceil((el.offsetHeight + GAP) / ROW))}`; };
  cards.forEach(fit);                               // now, so nothing overlaps before the first resize report
  const watch = new ResizeObserver((entries) => entries.forEach((e) => fit(e.target as HTMLElement)));
  cards.forEach((el) => watch.observe(el));
  packing.set(grid, watch);
}

/** One of the person's own tiles: an icon, a heading and text, in a colour; one with a console page opens it. Its words
 * go in as text. */
export function tileCard(id: string, t: DashboardTile): HTMLElement {
  const words = t.heading || t.text ? h("div", { class: "dash-tile-words" },
    t.heading ? h("div", { class: `dash-tile-heading ${t.size}` }, t.heading) : null,
    t.text ? h("div", { class: "dash-tile-text" }, t.text) : null) : null;
  const inside = [t.icon ? h("span", { class: "dash-tile-icon" }, icon(t.icon, 22)) : null, words];
  const page = TILE_LINKS.includes(t.link) ? t.link : "";
  const attrs = { class: `card dash-card dash-tile tone-${t.tone || "none"} ${t.align}`, "data-card": id };
  const el = page ? h("a", { ...attrs, href: `#/${page}` }, inside) : h("section", attrs, inside);
  el.style.height = `${t.height}px`;
  return el;
}

// --- the person's own SQL tables ----------------------------------------------------------------------------------

const when = (iso: string) => new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

/** One of the person's own SQL tables: the result kept from its last refresh (service/store.py), shown until the
 * refresh button runs the query again (with the SQL password, as any query: sql-lock.ts). Its description is behind
 * the info icon; the table scrolls inside the card's own height. */
export function sqlCard(id: string, w: DashboardWidget, kept: any): HTMLElement {
  const body = h("div", { class: "dash-sql" });
  const refresh = h("button", { class: "icon-btn small", type: "button", title: "Refresh", "aria-label": "Refresh", disabled: !w.query.trim() },
    icon("refresh", 16)) as HTMLButtonElement;
  const draw = (r: any, problem: unknown = null) => clear(body,
    problem ? errorBox(problem) : null,
    r ? [table(r.columns, r.rows.map((row: unknown[]) => row.map((v) => (v === null ? h("span", { class: "muted" }, "null") : String(v))))),
      h("div", { class: "dash-sql-foot tiny muted" }, `${fmt.int(r.rows.length)} rows${r.truncated ? " (first 1,000)" : ""} · ${when(r.refreshed_at)}`,
        r.query !== w.query ? badge("query changed", "warn") : null)]
      : h("div", { class: "dash-empty" }, icon("table", 20), "Not run yet"));
  refresh.addEventListener("click", async () => {
    refresh.disabled = true;
    const before = kept;
    clear(body, loading("Refreshing"));
    try {
      kept = await sqlApi("/api/dashboard/widget", { id, query: w.query });
      draw(kept);
    } catch (e) {
      draw(before, isLocked(e) ? null : e);              // the password dialog cancelled: as it was
    } finally {
      refresh.disabled = false;
    }
  });
  draw(kept);
  const el = card({ id, name: w.title || "SQL table", glyph: "query-sql", info: w.description, body, controls: refresh, cls: "dash-sql-card" });
  el.style.height = `${w.height}px`;
  return el;
}

// --- building blocks: a card, a figure, an info icon, a table toggle ----------------------------------------------

/** A card (``id`` in dashboard-layout.ts: its icon and title), the info icon, optional controls, and a body that fills
 * it. With ``tableOf``, a table icon swaps the body for its table. */
function card(o: { id: string; info: string; body: HTMLElement; controls?: Child; name?: string; glyph?: string;
  tableOf?: () => HTMLElement; tone?: string; cls?: string }): HTMLElement {
  const { name, glyph } = { ...cardInfo(o.id), ...(o.name ? { name: o.name } : {}), ...(o.glyph ? { glyph: o.glyph } : {}) };
  const box = h("div", { class: "dash-body" }, o.body);
  let toggle: HTMLElement | null = null;
  if (o.tableOf) {
    let on = false;
    const b = h("button", { class: "icon-btn small", type: "button", title: "Table", "aria-label": "Table", "aria-pressed": "false" }, icon("table", 16));
    b.addEventListener("click", () => {
      on = !on;
      b.setAttribute("aria-pressed", String(on));
      clear(box, on ? o.tableOf!() : o.body);
    });
    toggle = b;
  }
  return h("section", { class: `card dash-card ${o.tone ?? ""} ${o.cls ?? ""}`, "data-card": o.id },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(glyph)), h("h2", {}, name),
      h("span", { class: "end" }, o.controls, toggle, o.info.trim() ? infoIcon(o.info) : null)),
    box);
}

function infoIcon(text: string): HTMLElement {
  return withTip(h("button", { class: "icon-btn small dash-info", type: "button" }, icon("info", 16)), text);
}

/** A headline figure: label, value (and a second one beside it), and what it is made of underneath. */
/** The audit sample's estimates (service/audit.py): precision, miss rate and recall with their 95% intervals. */
function auditCard(e: any): HTMLElement {
  const o = e.overall ?? {};
  const cell = (label: string, s: any, scale = 1) => h("div", {},
    h("div", { class: "tiny muted mono" }, label),
    h("div", { class: "big small-big" }, s?.estimate !== null && s?.estimate !== undefined ? (scale === 1 ? fmt.pct(s.estimate) : fmt.num(s.estimate * scale, 1)) : "—"),
    h("div", { class: "tiny muted mono" }, s?.estimate !== null && s?.estimate !== undefined
      ? `${scale === 1 ? fmt.pct(s.low) : fmt.num(s.low * scale, 1)}–${scale === 1 ? fmt.pct(s.high) : fmt.num(s.high * scale, 1)} · n ${fmt.int(s.n)}` : ""));
  return card({ id: "audit", info: INFO.audit, body: h("div", { class: "row", style: { gap: "28px", flexWrap: "wrap" } },
    cell("Precision", o.precision), cell("Missed / 10,000", o.miss_rate, 10000), cell("Recall", o.recall),
    h("a", { class: "btn small end", href: "#/audit" }, `${fmt.int(e.labelled ?? 0)} / ${fmt.int(e.drawn ?? 0)} labelled`)) });
}

/** Label yield per mechanism (service/yields.py): n, precision and the expected share, highest precision first. */
function yieldCard(rows: any[]): HTMLElement {
  const sorted = [...rows].sort((a, b) => b.precision - a.precision || b.n - a.n);
  const body = sorted.length
    ? table(["Mechanism", "n", "Precision", "Expected"], sorted.map((r) => [r.label, fmt.int(r.n),
        h("span", { class: "dash-yield" }, meter(r.precision, "var(--st-bad)"), fmt.pct(r.precision)), fmt.pct(r.expected)]))
    : h("p", { class: "muted small" }, "—");
  return card({ id: "yield", info: INFO.yield, body });
}

/** Minutes as the largest two units: 12 min, 3 h 05 min, 2 d 4 h. */
function duration(minutes: number): string {
  const m = Math.round(minutes);
  if (m < 60) return `${m} min`;
  if (m < 1440) return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, "0")} min`;
  return `${Math.floor(m / 1440)} d ${Math.floor((m % 1440) / 60)} h`;
}

function kpi(id: string, value: string, info: string, foot: Child, tone = "", second: Child = null): HTMLElement {
  return card({ id, info, tone, cls: "dash-kpi",
    body: h("div", { class: "dash-kpi-body" }, h("div", { class: "dash-figure-row" }, h("div", { class: "dash-figure" }, value), second), foot) });
}

/** One count per log type, two by two. */
function bySource(review: any[], key: string): HTMLElement {
  return h("div", { class: "dash-split" }, review.map((r) => h("span", { class: `dash-chip ${r[key] ? "" : "zero"}` }, r.source.toUpperCase(), h("strong", {}, fmt.int(r[key] ?? 0)))));
}

function months(first?: string, last?: string): string {
  if (!first || !last) return "";
  const name = (m: string) => `${MONTHS[Number(m.slice(5, 7)) - 1]} ${m.slice(0, 4)}`;
  if (first === last) return name(first);
  return first.slice(0, 4) === last.slice(0, 4) ? `${MONTHS[Number(first.slice(5, 7)) - 1]} – ${name(last)}` : `${name(first)} – ${name(last)}`;
}

/** A single share against the whole, as a filled track. */
function meter(value: number, colour: string, text?: string): HTMLElement {
  const m = h("div", { class: "dash-meter" }, h("span", { style: { width: `${Math.min(100, Math.max(value > 0 ? 0.8 : 0, value * 100))}%`, background: colour } }));
  return text ? withTip(m, text) : m;
}

// --- what to open first ----------------------------------------------------------------------------------------

function nextCard(next: any[]): HTMLElement {
  const rows = next.length
    ? h("ol", { class: "dash-next" }, next.map((i) => h("li", {},
      h("button", { type: "button", class: "dash-next-row", onclick: () => openInReview(i.source, i.item_id) },
        h("span", { class: "dash-next-name" },
          h("strong", {}, title(i)),
          h("span", { class: "tiny muted" }, [i.source.toUpperCase(), i.view_label, i.server,
            i.kind === "cluster" ? count(i.view, i.flagged_rows ?? 0) : i.kind === "activity_alert" ? i.peak : `${fmt.int(i.line_count ?? 0)} lines`,
            i.first_seen ? dateSpan(i.first_seen, i.last_seen ?? "") : ""].filter(Boolean).join(" · "))),
        h("span", { class: "dash-next-tags" },
          i.sigma.length ? h("span", { class: "badge bad", title: i.sigma.join("\n") }, icon("sigma", 12), i.sigma.length > 1 ? `${i.sigma[0]} +${i.sigma.length - 1}` : i.sigma[0]) : null,
          i.period === "validation" ? badge("validation", "info") : null),
        icon("arrow", 16)))))
    : h("div", { class: "dash-empty" }, icon("check", 20), "Nothing waiting");
  return card({ id: "next", info: INFO.next, body: rows,
    controls: h("a", { class: "btn small", href: "#/review" }, "All") });
}

// --- review progress -------------------------------------------------------------------------------------------

function progressCard(review: any[]): HTMLElement {
  const rows = h("div", { class: "dash-rows" },
    review.map((r) => h("div", { class: "dash-row" },
      h("div", { class: "dash-label" }, h("strong", {}, r.source.toUpperCase()), h("span", { class: "tiny muted" }, fmt.int(r.total))),
      stackedBar(STATES.map(([key, label, colour]) => ({ value: r[key], colour, text: `${r.source.toUpperCase()} · ${label} · ${fmt.int(r[key])} of ${fmt.int(r.total)}` })), r.total, r.total),
      h("div", { class: "dash-value" }, r.total ? pct((r.total - r.open) / r.total, 0) : "—"))),
    legend(STATES.map(([, label, colour]) => [label, colour])));
  return card({ id: "progress", info: INFO.progress, body: rows,
    tableOf: () => table(["Log type", ...STATES.map(([, l]) => l), "Total"], review.map((r) => [r.label, ...STATES.map(([k]) => fmt.int(r[k])), fmt.int(r.total)])) });
}

// --- outliers: the share of rows flagged, and which detectors flagged them -------------------------------------------
// The share of flagged test rows (AUTH sessions and OSSEC episodes, the views every mechanism scores), as a figure and
// a meter per log type; Detectors shows a Venn diagram of the four mechanisms. Four sets need ellipses, not circles,
// for every overlap to exist: the standard layout of four ellipses at 40 and 140 degrees, each count in its own region.

const MECH_COLOURS = ["#4298b4", "#88619a", "#e4ae3a", "#33a474"];          // Isolation Forest, model zoo, novelty, subsequences
// [x, y, width, height, angle] in a unit square with y up; then where each region's count goes, keyed by its mask
const VENN_ELLIPSES = [[0.35, 0.4, 0.72, 0.45, 140], [0.45, 0.5, 0.72, 0.45, 140], [0.544, 0.5, 0.72, 0.45, 40], [0.644, 0.4, 0.72, 0.45, 40]];
const VENN_COUNTS: Record<number, [number, number]> = { 8: [0.85, 0.42], 4: [0.68, 0.72], 12: [0.77, 0.59], 2: [0.32, 0.72], 10: [0.71, 0.3], 6: [0.5, 0.66],
  14: [0.65, 0.5], 1: [0.14, 0.42], 9: [0.5, 0.17], 5: [0.29, 0.3], 13: [0.39, 0.24], 3: [0.23, 0.59], 11: [0.61, 0.24], 7: [0.35, 0.5], 15: [0.5, 0.38] };
const VENN_NAMES: [number, number, string][] = [[0.22, 0.1, "end"], [0.16, 0.86, "start"], [0.84, 0.86, "end"], [0.78, 0.1, "start"]];

let outlierScope = "all";
let outlierView: "share" | "venn" = "share";

function outliersCard(o: any): HTMLElement {
  const view = h("div", { class: "dash-fill" });
  const controls = h("div", { class: "dash-controls" });
  const tableOf = () => {
    const { regions, rows, flagged, names } = tally();
    return table(["Flagged by", "Rows"], [...Object.entries(regions).sort((a, b) => b[1] - a[1]).map(([mask, n]) => [names(Number(mask)), fmt.int(n)]),
      ["Any of them", fmt.int(flagged)], ["None", fmt.int(rows - flagged)]]);
  };
  const tally = () => {
    const sources: any[] = o?.sources ?? [];
    const mechanisms: { key: string; label: string }[] = o?.mechanisms ?? [];
    const scope = sources.filter((s) => outlierScope === "all" || s.source === outlierScope);
    const regions: Record<number, number> = {};
    scope.forEach((s) => Object.entries(s.regions as Record<string, number>).forEach(([mask, n]) => { regions[Number(mask)] = (regions[Number(mask)] ?? 0) + n; }));
    return { sources, mechanisms, scope, regions,
      rows: scope.reduce((n, s) => n + s.rows, 0), flagged: scope.reduce((n, s) => n + s.flagged, 0),
      totals: mechanisms.map((m) => scope.reduce((n, s) => n + (s.totals[m.key] ?? 0), 0)),
      names: (mask: number) => mechanisms.filter((_, i) => mask & (1 << i)).map((m) => m.label).join(" + ") };
  };
  const pills = (options: [string, string][], value: string, set: (v: string) => void) => h("div", { class: "pills small" }, options.map(([key, label]) =>
    h("button", { class: value === key ? "on" : "", "aria-pressed": String(value === key), onclick: () => { set(key); draw(); } }, label)));
  const draw = () => {
    const t = tally();
    clear(controls,
      pills([["share", "Share"], ["venn", "Detectors"]], outlierView, (v) => { outlierView = v as "share" | "venn"; }),
      pills([["all", "All"], ...t.sources.map((s): [string, string] => [s.source, s.source.toUpperCase()])], outlierScope, (v) => { outlierScope = v; }));
    if (o?.status !== "ready" || !t.rows) return clear(view, o?.status === "failed" ? h("div", { class: "dash-empty" }, "Unavailable") : loading());
    clear(view, outlierView === "share"
      ? h("div", { class: "dash-share" },
        h("div", { class: "dash-figure" }, share(t.flagged / t.rows)),
        h("div", { class: "tiny muted" }, `${fmt.int(t.flagged)} of ${fmt.int(t.rows)} rows`),
        h("div", { class: "dash-rows" }, t.scope.map((s) => h("div", { class: "dash-row" },
          h("div", { class: "dash-label" }, h("strong", {}, s.source.toUpperCase())),
          meter(s.flagged / s.rows, "var(--red)", `${s.source.toUpperCase()} · ${fmt.int(s.flagged)} of ${fmt.int(s.rows)} rows flagged`),
          h("div", { class: "dash-value" }, share(s.flagged / s.rows))))))
      : outlierVenn(t.regions, t.mechanisms, t.totals, t.names));
  };
  draw();
  if (o?.status === "counting" || o?.status === "idle") {               // counted in the background: look again shortly
    const poll = window.setInterval(async () => {
      if (!view.isConnected) return window.clearInterval(poll);
      try {
        const next = (await api("/api/dashboard")).outliers;
        if (next?.status !== "counting" && next?.status !== "idle") { window.clearInterval(poll); o = next; draw(); }
      } catch { window.clearInterval(poll); }
    }, 3000);
  }
  return card({ id: "flagged", info: INFO.flagged, body: h("div", { class: "dash-flagged" }, controls, view), tableOf });
}

/** The four mechanisms as a Venn diagram of ellipses, each overlap with its count. */
function outlierVenn(regions: Record<number, number>, mechanisms: { key: string; label: string }[], totals: number[], names: (mask: number) => string): HTMLElement {
  const S = 440, X = (x: number) => 70 + x * S, Y = (y: number) => 14 + (1 - y) * S;
  const shapes = VENN_ELLIPSES.map(([x, y, w, hgt, a], i) => svg("ellipse", { cx: X(x), cy: Y(y), rx: (w * S) / 2, ry: (hgt * S) / 2,
    transform: `rotate(${-a} ${X(x)} ${Y(y)})`, fill: MECH_COLOURS[i], "fill-opacity": 0.16, stroke: MECH_COLOURS[i], "stroke-width": 2.2 }));
  const counts = Object.entries(VENN_COUNTS).map(([mask, [x, y]]) => {
    const n = regions[Number(mask)] ?? 0;
    return svg("text", { x: X(x), y: Y(y) + 6, "text-anchor": "middle", class: `venn-n ${n ? "" : "zero"}` },
      svg("title", {}, `${names(Number(mask))}: ${fmt.int(n)}`), n ? fmt.int(n) : "0");
  });
  const labels = mechanisms.map((m, i) => {
    const [x, y, anchor] = VENN_NAMES[i];
    return svg("text", { x: X(x), y: Y(y), "text-anchor": anchor, class: "venn-name", fill: MECH_COLOURS[i] }, m.label);
  });
  return h("div", { class: "outlier-venn" },
    svg("svg", { viewBox: `0 0 ${S + 160} ${S + 30}`, role: "img", "aria-label": mechanisms.map((m, i) => `${m.label} ${totals[i]}`).join(", ") }, ...shapes, ...counts, ...labels),
    h("div", { class: "venn-totals" }, mechanisms.map((m, i) => h("div", { class: "venn-total" },
      h("i", { style: { background: MECH_COLOURS[i] } }), h("span", {}, m.label), h("strong", {}, fmt.int(totals[i]))))));
}

// --- what data there is ----------------------------------------------------------------------------------------

function dataCard(data: any[], variantsReady: boolean): HTMLElement {
  const body = table(["Log type", "Lines", "Months", "Event types", "Messages"], data.map((r) => [
    h("strong", {}, r.source.toUpperCase()), num(r.lines), months(r.first_month, r.last_month) || "—", fmt.int(r.event_types),
    variantsReady && r.variants !== null ? num(r.variants) : "…"]), { class: "dash-table" });
  return card({ id: "data", info: INFO.data, body, cls: "dash-data" });
}

// --- what the models were built on -------------------------------------------------------

function modelsCard(models: any[]): HTMLElement {
  const sources = [...new Set(models.map((m) => m.source))];
  const body = h("div", { class: "dash-multiples" }, sources.map((source) => {
    const rows = models.filter((m) => m.source === source);
    const max = Math.max(...rows.map(total), 1);
    return h("div", {},
      h("h3", { class: "dash-sub" }, source.toUpperCase()),
      rows.map((m) => h("div", { class: `dash-row ${m.used ? "" : "unused"}` },
        h("div", { class: "dash-label" }, h("span", {}, m.view_label, m.used ? null : [" ", badge("not used", "muted")])),
        stackedBar(SPLITS.map(([key, label, colour]) => ({ value: m[key] ?? 0, colour, text: `${m.view_label} · ${label} · ${fmt.int(m[key])}` })), total(m), max),
        h("div", { class: "dash-value" }, num(total(m))))));
  }));
  return card({ id: "models", info: INFO.models, body,
    controls: legend(SPLITS.map(([, label, colour]) => [label, colour])),
    tableOf: () => table(["Log type", "View", "Training", "Validation", "Test", "Used for alerts"],
      models.map((m) => [m.source, m.view_label, fmt.int(m.train_rows), fmt.int(m.validation_rows), fmt.int(m.test_rows), m.used ? "yes" : "no"])) });
}

function total(m: any): number {
  return (m.train_rows ?? 0) + (m.validation_rows ?? 0) + (m.test_rows ?? 0);
}

// --- how the console is used -------------------------------------------------------------

/** The watched entities (Profiles), each on its log type's last day: x against its median and 8 weeks of daily totals. */
function watchedCard(rows: any[]): HTMLElement {
  const who = (w: any) => (w.entity_type === "all" ? "Whole log" : w.entity);
  const body = rows.length ? h("div", { class: "pr-watched" }, rows.map((w) => h("button", { class: "pr-watched-row", type: "button", title: w.name,
    onclick: () => openInProfiles(w.source, w.entity_type, w.entity, w.day ?? "") },
    h("span", { class: "dash-chip" }, w.source.toUpperCase()), icon(TYPE_ICONS[w.entity_type] ?? "chart", 16), h("span", { class: "ex-name" }, who(w)),
    w.ready ? spark(w.spark, 84, 18) : h("span", { class: "tiny muted" }, "no profile"),
    w.ready ? watchTag(w, w.method === "presence") : h("span"))))
    : h("div", { class: "pr-watched-empty" }, icon("eye", 22), h("a", { class: "btn small", href: "#/profiles" }, icon("profiles", 14), "Profiles"));
  const tableOf = () => table(["Log type", "Entity", "Day", "x", "Median", "P10–P90", "n"], rows.map((w) => [w.source.toUpperCase(), who(w), w.day ?? "—",
    w.ready ? fmt.int(w.x) : "—", w.usual ? fmt.int(w.usual.median) : "—", w.usual ? `${fmt.int(w.usual.low)}–${fmt.int(w.usual.high)}` : "—",
    w.usual ? `${w.usual.days} ${w.usual.basis}` : "—"]));
  return card({ id: "watched", info: INFO.watched, body, tableOf: rows.length ? tableOf : undefined });
}

function usageCard(usage: any): HTMLElement {
  const days = lastDays(usage.days);
  const actions = usage.recent.filter((r: any) => !r.event.startsWith("view:"));
  const views = usage.recent.filter((r: any) => r.event.startsWith("view:"));
  const recentTotal = (event: string) => actions.filter((r: any) => r.event === event).reduce((s: number, r: any) => s + r.n, 0);
  const perDay = days.map((day) => {
    const rows = actions.filter((r: any) => r.day === day);
    const n = rows.reduce((s: number, r: any) => s + r.n, 0);
    const detail = rows.map((r: any) => `${r.n} ${ACTION_NAMES[r.event] ?? r.event}`).join(", ");
    return { day, n, rows, text: `${dayLabel(day)} · ${fmt.int(n)} action${n === 1 ? "" : "s"}${detail ? ` (${detail})` : ""}` };
  });
  const pageCounts = Object.entries(views.reduce((acc: Record<string, number>, r: any) => {
    const page = r.event.slice(5);
    acc[page] = (acc[page] ?? 0) + r.n;
    return acc;
  }, {})).sort((a, b) => (b[1] as number) - (a[1] as number)) as [string, number][];
  const since = usage.since ? new Date(`${usage.since}T00:00:00`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : "";
  const body = h("div", { class: "dash-usage" },
    h("div", { class: "dash-usage-tiles" }, ACTIONS.map(([event, label]) =>
      h("div", { class: "stat" }, h("div", { class: "k" }, label), h("div", { class: "v" }, fmt.int(recentTotal(event))),
        h("div", { class: "d" }, `${fmt.int(usage.all_time[event] ?? 0)} total`)))),
    h("div", { class: "dash-cols-wrap" },
      h("div", { class: "dash-cols-axis tiny muted" }, h("span", {}, fmt.int(Math.max(...perDay.map((d) => d.n), 1))), h("span", {}, "0")),
      h("div", {}, columns(perDay, 140),
        h("div", { class: "dash-cols-x tiny muted" },
          h("span", {}, dayLabel(perDay[0].day)), h("span", {}, dayLabel(perDay[Math.floor(perDay.length / 2)].day)), h("span", {}, "Today")))));
  return card({ id: "activity", info: since ? `${INFO.activity} Counting began on ${since}.` : INFO.activity, body,
    controls: h("span", { class: "dash-period" }, `${usage.days} days`),
    tableOf: () => h("div", { class: "dash-tables" },
      table(["Day", "Actions", "Of which"], perDay.filter((d) => d.n).reverse().map((d) => [
        d.day, fmt.int(d.n), d.rows.map((r: any) => `${r.n} ${ACTION_NAMES[r.event] ?? r.event}`).join(", ")])),
      table(["Page", "Opened"], pageCounts.map(([page, n]) => [PAGES[page] ?? page, fmt.int(n)]))) });
}

function lastDays(count: number): string[] {
  const out: string[] = [];
  const today = new Date();
  for (let i = count - 1; i >= 0; i--) {
    const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i);
    out.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`);
  }
  return out;
}

const dayLabel = (day: string) => new Date(`${day}T00:00:00`).toLocaleDateString("en-GB", { day: "numeric", month: "short" });

/** One column per day, ``height`` px tall; each column's tooltip is its ``text``. */
function columns(perDay: { day: string; n: number; text: string }[], height: number): HTMLElement {
  const max = Math.max(...perDay.map((d) => d.n), 1);
  return h("div", { class: "dash-cols", style: { height: `${height}px` }, role: "img", "aria-label": perDay.map((d) => d.text).filter((_, i) => perDay[i].n).join("; ") || "None" },
    perDay.map((d) => withTip(h("div", { class: "dash-col" }, d.n ? h("span", { style: { height: `${Math.max(4, (d.n / max) * 100)}%` } }) : null), d.text)));
}

/** Horizontal bar of segments; its length is `sum / max` of the track. Each segment has a tooltip. */
function stackedBar(parts: { value: number; colour: string; text: string }[], sum: number, max: number): HTMLElement {
  const bar = h("div", { class: "sbar", style: { width: `${max ? Math.max(sum ? 1.5 : 0, (sum / max) * 100) : 0}%` } },
    parts.filter((p) => p.value > 0).map((p) => withTip(h("span", { style: { flexGrow: String(p.value), background: p.colour } }), p.text)));
  bar.addEventListener("pointerleave", () => tip(null));
  return h("div", { class: "sbar-track" }, bar);
}

function legend(items: [string, string][]): HTMLElement {
  return h("div", { class: "legend" }, items.map(([label, colour]) => h("span", {}, h("i", { style: { background: colour, borderRadius: "2px" } }), label)));
}
