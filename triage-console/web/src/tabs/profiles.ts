// Profiles (FR-PRO): every server, source IP, username and destination IP against its own normal, on any day, alerted
// or not (Phase 4h; service/profiles.py). The list shows one entity type on one day, furthest from its normal first,
// each with eight weeks of daily totals; an entity's page draws Explain's charts for that day (explain.ts), its whole
// timeline (a click on a day moves to it), the entities it shared lines with, and its activity alerts. Watched
// entities appear on the Dashboard's Watched card. PF and IPFilter use the presence method: normal is no activity, so
// nothing is compared with a median there.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, keepScroll, loading, select, svg, type Child } from "../dom";
import { icon } from "../icons";
import { choose, chosenSource, logTypePicker } from "../log-type";
import { tip } from "../tooltip";
import { chart, chartCard, dailyChart, dailyTable, dayChart, dayTable, distributionPlot, historyCaveat, legend,
  longDate, openInExplain, shortDate, stat, tableOf, versusTag, versusUsual, weekCharts, weekTable, whole } from "./explain";
import { openInReview } from "./review";

const pr = { source: "", type: "", day: "", q: "", selected: "" };       // selected: the entity shown on the right
export const TYPE_ICONS: Record<string, string> = { all: "chart", server: "server", source_ip: "globe", username: "user", destination_ip: "target" };
const keyOf = (type: string, entity: string) => `${type}/${entity}`;
const addDays = (iso: string, n: number) => { const d = new Date(`${iso}T00:00:00Z`); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };

/** Opens Profiles on one entity and day (Explain's and the Dashboard's Profile links). */
export function openInProfiles(source: string, type: string, entity: string, day: string): void {
  choose(source);
  Object.assign(pr, { source, type, day, q: "", selected: keyOf(type, entity) });
  location.hash = "#/profiles";
}

/** x against the median as the list shows it: N× / %, ≈ within P10–P90, n < 4 without a baseline; x alone (presence). */
export function watchTag(row: any, presence: boolean): HTMLElement {
  if (presence) return h("span", { class: `ex-times ${row.x ? "up" : "mix"}` }, whole(row.x));
  if (!row.usual) return h("span", { class: "ex-times mix" }, "n < 4");
  return row.direction === "within" ? h("span", { class: "ex-times mix" }, "≈") : versusTag(row.x, row.usual.median);
}

/** Daily totals as small columns, the last (the day shown) in the accent colour; gaps where there is no data. */
export function spark(values: (number | null)[], width = 112, height = 22): SVGSVGElement {
  const top = Math.max(1, ...values.map((v) => v ?? 0));
  const slot = width / values.length;
  const kids = values.map((v, i) => v === null ? null : svg("rect", {
    x: i * slot + 0.3, width: Math.max(slot - 0.6, 0.6), y: height - (v ? Math.max((v / top) * height, 1.5) : 0.6),
    height: v ? Math.max((v / top) * height, 1.5) : 0.6, class: `pr-spark-col ${i === values.length - 1 ? "now" : ""}` })).filter(Boolean) as Element[];
  return svg("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "pr-spark", role: "img",
    "aria-label": `Daily totals, last ${values.length} days, at most ${whole(top)}` }, ...kids);
}

function statText(row: any, presence: boolean): string {
  if (presence) return `x = ${whole(row.x)}`;
  return row.usual ? `x = ${whole(row.x)} · median ${whole(row.usual.median)} · n = ${row.usual.days} ${row.usual.basis}` : `x = ${whole(row.x)} · n < 4`;
}

export async function renderProfiles(main: HTMLElement): Promise<void> {
  if (pr.source !== chosenSource()) Object.assign(pr, { source: chosenSource(), type: "", day: "", q: "", selected: "" });
  const listBox = h("div", { class: "card" }, loading());
  const detail = h("div", { class: "ex-detail" });
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Profiles")),
      h("div", { class: "row", style: { gap: "10px" } }, logTypePicker(() => renderProfiles(main)))),
    h("div", { class: "grid split" }, listBox, detail));
  let o: any;
  const asked = pr.type || "source_ip";
  try {
    o = await api(`/api/profiles/list${qs({ source: pr.source, type: asked, day: pr.day, q: pr.q })}`);
  } catch (e) {
    return clear(listBox, errorBox(e));
  }
  if (!o.ready) {
    clear(listBox, h("div", { class: "ex-empty" }, icon("profiles", 28), h("strong", {}, "No profiles yet"),
      h("code", { class: "small" }, `python run_pipeline.py --source ${pr.source} --only-phase 4h`)));
    return clear(detail);
  }
  const types = (o.types as any[]).filter((t) => t.count > 0);
  if (!types.some((t) => t.id === asked)) {
    pr.type = types.some((t) => t.id === "source_ip") ? "source_ip" : types.find((t) => t.id !== "all")?.id ?? "all";
    if (pr.type !== asked) return renderProfiles(main);
  }
  pr.type = asked;
  pr.day = o.day;
  const presence = o.method === "presence";
  const reload = () => renderProfiles(main);
  let timer = 0;
  const search = h("input", { type: "search", value: pr.q, placeholder: "Search", "aria-label": "Search", class: "pr-search" }) as HTMLInputElement;
  search.addEventListener("input", () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => { pr.q = search.value; void refreshList(); }, 250);
  });
  const rowsBox = h("div", { class: "list-scroll" });
  const count = h("span", { class: "tiny muted" });
  const draw = (rows: any[], total: number) => {
    clear(count, total > rows.length ? `${fmt.int(rows.length)} of ${fmt.int(total)}` : fmt.int(total));
    keepScroll(rowsBox, () => clear(rowsBox, rows.length ? rows.map((row) => h("div", {
      class: `list-item pr-item ${keyOf(pr.type, row.entity) === pr.selected ? "selected" : ""}`, tabindex: "0",
      onclick: () => { pr.selected = keyOf(pr.type, row.entity); draw(rows, total); void drawEntity(detail, pr.type, row.entity, actions); },
      onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") (e.currentTarget as HTMLElement).click(); },
    },
      h("div", { class: "row", style: { justifyContent: "space-between", flexWrap: "nowrap" } },
        h("div", { class: "row", style: { flexWrap: "nowrap", minWidth: "0", gap: "6px" } }, icon(TYPE_ICONS[pr.type] ?? "chart", 16),
          h("strong", { class: "ex-name" }, pr.type === "all" ? "Whole log" : row.entity),
          row.in_training === false ? h("span", { class: "ex-new", title: "No training data" }, "new") : null,
          row.watched ? h("span", { class: "pr-mark", title: "Watched" }, icon("eye", 14)) : null,
          row.alerts ? h("span", { class: "pr-mark", title: `${row.alerts} activity alert${row.alerts === 1 ? "" : "s"}` }, icon("review", 13), String(row.alerts)) : null),
        watchTag(row, presence)),
      h("div", { class: "pr-item-foot" }, spark(row.spark), h("span", { class: "tiny muted" }, statText(row, presence)))))
      : h("p", { class: "muted", style: { padding: "12px" } }, "None.")));
  };
  const refreshList = async () => {
    try {
      const fresh = await api(`/api/profiles/list${qs({ source: pr.source, type: pr.type, day: pr.day, q: pr.q })}`);
      draw(fresh.rows, fresh.total);
    } catch (e) {
      clear(rowsBox, errorBox(e));
    }
  };
  clear(listBox,
    h("div", { class: "pr-tools" },
      select(types.map((t) => [t.id, t.id === "all" ? t.label : `${t.label}s (${fmt.int(t.count)})`] as [string, string]), pr.type,
        (v) => { Object.assign(pr, { type: v, selected: "" }); void reload(); }, { "aria-label": "Who" }),
      dayControl(o, (day) => { pr.day = day; void reload(); }),
      h("div", { class: "row", style: { gap: "8px", flexWrap: "nowrap" } }, search, count)),
    rowsBox);
  const actions = { pick: (day: string) => { pr.day = day; void reload(); }, refresh: () => void refreshList() };
  if (!pr.selected && o.rows.length) pr.selected = keyOf(pr.type, o.rows[0].entity);
  draw(o.rows, o.total);
  if (pr.selected) {
    const [type, ...rest] = pr.selected.split("/");
    void drawEntity(detail, type, rest.join("/"), actions);
  } else clear(detail);
}

/** The day shown: a date field between the first and last day with data, and a step back and forward. */
function dayControl(o: any, change: (day: string) => void): HTMLElement {
  const input = h("input", { type: "date", value: o.day, min: o.first_day, max: o.last_day, "aria-label": "Day" }) as HTMLInputElement;
  input.addEventListener("change", () => { if (input.value) change(input.value); });
  const step = (n: number) => {
    const day = addDays(o.day, n);
    if (day >= o.first_day && day <= o.last_day) change(day);
  };
  const button = (glyph: string, label: string, n: number, off: boolean) => h("button", { class: "icon-btn small", type: "button", title: label,
    "aria-label": label, disabled: off, onclick: () => step(n) }, icon(glyph, 16));
  return h("div", { class: "pr-day" }, button("caret-left", "Previous day", -1, o.day <= o.first_day), input,
    button("caret-right", "Next day", 1, o.day >= o.last_day),
    h("span", { class: "small muted" }, [o.weekday.slice(0, 3), o.holiday].filter(Boolean).join(" · ")));
}

// --- one entity on one day ---------------------------------------------------------------------------------------

async function drawEntity(el: HTMLElement, type: string, entity: string, actions: { pick: (day: string) => void; refresh: () => void }): Promise<void> {
  clear(el, h("div", { class: "card" }, loading()));
  let r: any;
  try {
    r = await api(`/api/profiles/entity${qs({ source: pr.source, type, entity, day: pr.day })}`);
  } catch (e) {
    return clear(el, h("div", { class: "card" }, errorBox(e)));
  }
  const presence = r.method === "presence";
  const u = r.big.usual;
  const watch = h("button", { class: `btn small pr-watch ${r.watched ? "on" : ""}`, type: "button", "aria-pressed": String(r.watched) },
    icon("eye", 14), r.watched ? "Watching" : "Watch") as HTMLButtonElement;
  watch.addEventListener("click", async () => {
    watch.disabled = true;
    try {
      await api("/api/profiles/watch", { body: { source: pr.source, type, entity, on: !r.watched } });
      r.watched = !r.watched;
      watch.classList.toggle("on", r.watched);
      watch.setAttribute("aria-pressed", String(r.watched));
      clear(watch, icon("eye", 14), r.watched ? "Watching" : "Watch");
      actions.refresh();
    } catch (e) {
      watch.after(errorBox(e));
    } finally {
      watch.disabled = false;
    }
  });
  const versus = versusUsual(r.big.observed, u?.median);
  const x = r.big.observed;
  const tone = presence ? (x > 0 ? "alarm" : "") : !u ? "" : x > u.high ? "alarm" : x < u.low ? "quiet" : "";
  clear(el,
    h("div", { class: "card ex-summary" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(TYPE_ICONS[type] ?? "chart")), h("h2", {}, r.name),
        h("span", { class: "end" }, badge(r.source_label, "muted"),
          r.when.holiday ? badge(r.when.holiday, "info") : null,
          presence ? badge("presence: normal = 0", "muted") : !u ? badge("n < 4", "warn") : null,
          r.alerts.length ? badge(`${r.alerts.length} activity alert${r.alerts.length === 1 ? "" : "s"}`, "warn") : null, watch)),
      historyCaveat(r),
      h("div", { class: "ex-big" },
        stat(whole(x), "x, lines that day", tone),
        presence ? null : stat(u ? whole(u.median) : "—", u ? `median, n = ${u.days} ${r.big.basis}` : `n < 4 ${r.big.basis}`),
        presence || !u ? null : stat(versus.text, versus.label),
        stat(longDate(r.when.date, r.when.weekday), r.when.holiday ?? r.when.day_words, "", true)),
      h("div", { class: "tiny muted" }, [`first seen ${shortDate(r.stats.first_seen)} ${r.stats.first_seen.slice(0, 4)}`,
        `last seen ${shortDate(r.stats.last_seen)} ${r.stats.last_seen.slice(0, 4)}`, `${fmt.int(r.stats.active_days)} active days`,
        `${fmt.int(r.stats.lines)} lines`, presence ? "" : `${fmt.int(r.stats.training_days)} training days`].filter(Boolean).join(" · "))),
    chartCard("Daily totals, whole period", "chart", (w) => timelineChart(r, w, actions.pick), timelineTable(r)),
    chartCard("Hourly counts, this day", "clock", (w) => dayChart(r, w), dayTable(r)),
    chartCard("Hourly counts, this week", "calendar", (w) => weekCharts(r, w), weekTable(r)),
    chartCard("Daily totals, 8 weeks", "chart", (w) => dailyChart(r, w), dailyTable(r)),
    r.big.distribution?.length ? chartCard("Distribution, daily totals", "chart", (w) => totalsDistribution(r, w), totalsTable(r)) : null,
    touchedCard(r),
    r.alerts.length ? alertsCard(r) : null);
}

/** The whole period's daily totals: one column a day, the day shown in the accent colour, alerts marked above. */
function timelineChart(r: any, W: number, pick: (day: string) => void): Element {
  const totals: (number | null)[] = r.timeline.totals, start: string = r.timeline.start, n = totals.length;
  const H = 156, L = 52, B = 122, T = 22, slot = (W - L - 8) / Math.max(n, 1);
  const top = Math.max(1, ...totals.map((t) => t ?? 0)) * 1.1;
  const y = (v: number) => B - (v / top) * (B - T);
  const index = (iso: string) => Math.round((Date.parse(`${iso}T00:00:00Z`) - Date.parse(`${start}T00:00:00Z`)) / 86_400_000);
  const shown = index(r.when.date);
  const kids: Element[] = [svg("line", { x1: L, x2: W - 8, y1: B, y2: B, class: "ex-axis" }),
    svg("text", { x: L - 6, y: T + 4, class: "ex-tick", "text-anchor": "end" }, whole(top / 1.1)),
    svg("text", { x: L - 6, y: B, class: "ex-tick", "text-anchor": "end" }, "0")];
  if (r.train_end) {
    const at = index(r.train_end);
    if (at > 0 && at < n) kids.push(svg("line", { x1: L + at * slot, x2: L + at * slot, y1: T - 10, y2: B, class: "ex-split" }),
      svg("text", { x: L + at * slot + 4, y: T - 2, class: "ex-tick" }, "after training"));
  }
  const gap = Math.min(1, slot * 0.15);
  totals.forEach((t, i) => {
    const date = addDays(start, i);
    if (t !== null) kids.push(svg("rect", { x: L + i * slot + gap, y: y(t), width: Math.max(slot - 2 * gap, 0.8), height: Math.max(B - y(t), t ? 1.5 : 0),
      class: `ex-col ${i === shown ? "alert" : ""}` }));
    if (date.endsWith("-01")) kids.push(svg("text", { x: L + i * slot, y: B + 18, class: "ex-tick" },
      `${shortDate(date).split(" ")[1]}${date.slice(5, 7) === "01" || i < 31 ? ` ${date.slice(0, 4)}` : ""}`));
    const hit = svg("rect", { x: L + i * slot, y: T - 10, width: Math.max(slot, 1), height: B - T + 10, class: "ex-hit" });
    hit.addEventListener("pointermove", (e) => tip(`${shortDate(date)} ${date.slice(0, 4)} · ${t === null ? "no data from the log" : `x = ${whole(t)}`}`, e as PointerEvent));
    hit.addEventListener("pointerleave", () => tip(null));
    hit.addEventListener("click", () => { tip(null); pick(date); });
    kids.push(hit);
  });
  for (const a of r.alerts) {
    const i = index(String(a.start).slice(0, 10));
    if (i < 0 || i >= n) continue;
    const mark = svg("path", { d: `M${L + (i + 0.5) * slot - 4} ${T - 9} l8 0 l-4 6 z`, class: "pr-alert-mark" });
    mark.addEventListener("pointermove", (e) => tip(`activity alert · ${String(a.start).slice(0, 16)} · ${a.peak}`, e as PointerEvent));
    mark.addEventListener("pointerleave", () => tip(null));
    kids.push(mark);
  }
  return h("div", {}, chart(W, H, "Lines per day over the whole period", kids),
    legend([["ex-k-col", "x per day"], ["ex-k-alert", shortDate(r.when.date)], ...(r.alerts.length ? [["pr-k-alert", "activity alert"]] as [string, string][] : [])]));
}

function timelineTable(r: any): HTMLElement {
  const totals: (number | null)[] = r.timeline.totals;
  return tableOf(["Day", "Count"], totals.map((t, i) => [addDays(r.timeline.start, i), whole(t)]).reverse());
}

/** The day's total among its weekday's training days: histogram and density, P10–P90, the median, x. */
function totalsDistribution(r: any, W: number): Element {
  const u = r.big.usual, values: number[] = r.big.distribution;
  return h("div", {}, distributionPlot([{ values, cls: "" }], r.big.observed,
    { width: W, height: 230, full: true, band: [u.low, u.high], median: u.median, unit: "count per day (log scale)" }),
    legend([["ex-k-dist-bar", `histogram, n = ${values.length} ${r.big.basis}`], ["ex-k-dist-band", `P10–P90 ${whole(u.low)}–${whole(u.high)}`],
      ["ex-k-dist-median", `median ${whole(u.median)}`], ["ex-k-alert", `x = ${whole(r.big.observed)}`]]));
}

function totalsTable(r: any): HTMLElement {
  const counts = new Map<number, number>();
  for (const v of r.big.distribution as number[]) counts.set(v, (counts.get(v) ?? 0) + 1);
  return tableOf(["Count", "Days"], [...counts.entries()].sort((a, b) => a[0] - b[0]).map(([v, n]) => [whole(v), String(n)]));
}

/** Who it shared lines with up to the day shown: lines that day and to date, first seen; new that day, or since training. */
function touchedCard(r: any): HTMLElement {
  const rows: any[] = r.touched;
  const body = rows.length ? tableOf(["Entity", "Day", "To date", "First seen"], rows.map((t) => [
    h("button", { class: "pr-entity", type: "button", title: t.name, onclick: () => openInProfiles(pr.source, t.entity_type, t.entity, r.when.date) },
      icon(TYPE_ICONS[t.entity_type] ?? "chart", 14), h("span", { class: "ex-name" }, t.entity),
      t.new_today ? h("span", { class: "ex-new" }, "new") : t.after_training ? h("span", { class: "pr-since" }, "after training") : null),
    t.on_day ? whole(t.on_day) : "—", whole(t.lines), shortDate(t.first_seen) + " " + t.first_seen.slice(0, 4)]), [0, 3])
    : h("p", { class: "small muted" }, "None.");
  return h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("users")), h("h2", {}, "Shared lines"),
    h("span", { class: "end small muted" }, r.touched_total > rows.length ? `${fmt.int(rows.length)} of ${fmt.int(r.touched_total)}` : fmt.int(r.touched_total))),
    body);
}

function alertsCard(r: any): HTMLElement {
  return h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("review")), h("h2", {}, "Activity alerts"),
    h("span", { class: "end small muted" }, fmt.int(r.alerts.length))),
    tableOf(["Start", "End", "Peak", ""], r.alerts.map((a: any) => [String(a.start).slice(0, 16), String(a.end).slice(0, 16), a.peak,
      h("span", { class: "row", style: { gap: "6px", justifyContent: "flex-end" } },
        h("button", { class: "btn small", type: "button", onclick: () => openInExplain(pr.source, a.view, a.item_id) }, icon("explain", 14), "Explain"),
        h("button", { class: "btn small", type: "button", onclick: () => openInReview(pr.source, a.item_id) }, icon("review", 14), "Review"))] as Child[]),
      [0, 1, 2]));
}
