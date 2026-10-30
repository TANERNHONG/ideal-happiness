// Explain (FR-EXP): why each activity alert (Phase 4g, AUTH and OSSEC) was raised, in pictures first. The
// pipeline computes every number and sentence (activity_explain.py); this page draws them: what was seen against
// the usual range, the reasons as range plots, the alert's day against its usual band, its week as a heatmap
// beside a usual week, and the last eight weeks of daily totals. Each chart can be shown as a table. Reword asks
// the local model for plainer words and keeps them only if every number matches (service/explain.py).
// Charts are drawn at the width of their card, in pixels, so text and marks keep their size on any screen; they
// are drawn again when the card's width changes. Profiles (profiles.ts) draws any entity's day with the same charts:
// a record without an alert window (no when.clock) shades nothing, and one with daily.per_day draws each day's own
// weekday band.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, keepScroll, loading, pills, select, svg, type Child } from "../dom";
import { icon, viewIcon } from "../icons";
import { choose, chosenSource, logTypePicker } from "../log-type";
import { state } from "../state";
import { tip } from "../tooltip";
import { linesBlock } from "./clusters";
import { openInProfiles } from "./profiles";
import { incidentCard, incidentSize, openInReview } from "./review";

const ex = { source: "", selected: "", type: "", day: "", window: "" };
const TYPES: [string, string][] = [["", "Everyone"], ["all", "Whole log"], ["server", "Servers"], ["source_ip", "Source IPs"],
  ["username", "Usernames"], ["destination_ip", "Destination IPs"]];
const DAYS: [string, string][] = [["", "Any day"], ["working", "Working days"], ["non_working", "Weekends and holidays"]];
const REASON_ICONS: Record<string, string> = { volume: "chart", day_type: "calendar", breadth: "server", sudden: "history", combination: "matrix",
  failures: "x-circle", relations: "users", outcome: "key" };
const CHANNEL_NOUN: Record<string, string> = { failures: "failures", "new partners": "new partners" };
const DAY_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const keyOf = (i: any) => `${i.view}/${i.item_id ?? i.row_manifest_id}`;
export const shortDate = (iso: string) => { const [, m, d] = iso.split("-").map(Number); return `${d} ${MONTHS[m - 1]}`; };
export const longDate = (iso: string, weekday: string) => `${weekday.slice(0, 3)} ${shortDate(iso)} ${iso.slice(0, 4)}`;
export const whole = (n: number | null | undefined) => (n === null || n === undefined ? "—" : Math.round(n).toLocaleString());
const range = (u: any) => (!u ? "—" : Math.round(u.low) === Math.round(u.high) ? whole(u.median) : `${whole(u.low)}–${whole(u.high)}`);
const factor = (f: number) => (f >= 10 ? Math.round(f).toLocaleString() : fmt.num(f, 1));
/** This count against the usual, which is the MEDIAN of the comparable days: 37× above it, a percentage of it below
 * (12%, 0.012%), "from 0" when the usual is 0 (no multiple or share of nothing). `up` is null for 0 against 0. */
export function versusUsual(observed: number, median: number | null | undefined): { text: string; label: string; up: boolean | null } {
  if (!median) return observed > 0 ? { text: "from 0", label: "median = 0", up: true } : { text: "0", label: "median = 0", up: null };
  const ratio = observed / median;
  if (ratio >= 1) return { text: `${factor(ratio)}×`, label: "x / median", up: true };
  const pct = ratio * 100;
  const text = pct >= 10 ? Math.round(pct).toString() : pct >= 1 ? fmt.num(pct, 1) : pct > 0 ? Number(pct.toPrecision(2)).toString() : "0";
  return { text: `${text}%`, label: "x / median", up: false };
}
export const hour = (n: number) => `${String(n).padStart(2, "0")}:00`;

/** The alert's window in minutes from the start of its day; the start is below 0 when it began the day before.
 * None for a day without an alert (Profiles). */
function windowOf(r: any): [number, number] | null {
  if (!r.when.clock) return null;
  const [hh, mm] = String(r.when.clock).split("–")[1].split(":").map(Number);
  const end = hh * 60 + mm || 1440;
  return [end - r.big.window_minutes, end];
}

export function versusTag(observed: number, median: number): HTMLElement {
  const v = versusUsual(observed, median);
  return h("span", { class: `ex-times ${v.up === null ? "mix" : v.up ? "up" : "down"}`, title: `${whole(observed)} against a usual (median) of ${whole(median)}` }, v.text);
}

/** Opens Explain on one activity alert (Review's Explain button). */
export function openInExplain(source: string, view: string, id: string): void {
  choose(source);
  Object.assign(ex, { source, selected: `${view}/${id}`, type: "", day: "", window: "" });
  location.hash = "#/explain";
}

export async function renderExplain(main: HTMLElement): Promise<void> {
  if (ex.source !== chosenSource()) Object.assign(ex, { source: chosenSource(), selected: "" });
  const listBox = h("div", { class: "card" }, loading());
  const detail = h("div", { class: "ex-detail" });
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Explain")),
      h("div", { class: "row", style: { gap: "10px" } }, logTypePicker(() => renderExplain(main)))),
    h("div", { class: "grid split" }, listBox, detail));
  let items: any[];
  try {
    items = (await api(`/api/explain/list${qs({ source: ex.source })}`)).items;
  } catch (e) {
    return clear(listBox, errorBox(e));
  }
  if (!items.length) {
    clear(listBox, h("div", { class: "ex-empty" }, icon("lightbulb", 28), h("strong", {}, "Nothing to explain yet"),
      state.catalog.sources[ex.source]?.method === "baseline"
        ? h("code", { class: "small" }, `python run_pipeline.py --source ${ex.source} --only-phase 4g`)
        : h("span", { class: "small muted" }, "AUTH and OSSEC only")));
    return clear(detail);
  }
  const matches = (i: any, skipWindow = false) => (!ex.type || i.entity_type === ex.type) && (!ex.day || i.when.day_type === ex.day)
    && (skipWindow || !ex.window || String(i.window_minutes) === ex.window);
  const shown = () => items.filter((i) => matches(i));
  /** The alert's window (the one its robust deviation peaked on), with how many alerts each has under the other filters;
   * the windows the alerts have (5, 30, 120 and 720 minutes since 2026-10-28; older runs had seven). */
  const windows = [...new Set(items.map((i) => Number(i.window_minutes)))].sort((a, b) => a - b);
  const windowOptions = (): [string, string][] => {
    const others = items.filter((i) => matches(i, true));
    return [["", `Any window (${others.length})`], ...windows.map((m) =>
      [String(m), `${minutes(m)} (${others.filter((i) => i.window_minutes === m).length})`] as [string, string])];
  };
  const draw = () => keepScroll(listBox, () => clear(listBox,
    h("div", { class: "row", style: { gap: "8px", marginBottom: "8px" } },
      select(TYPES, ex.type, (v) => { ex.type = v; draw(); }, { "aria-label": "Who" }),
      select(DAYS, ex.day, (v) => { ex.day = v; draw(); }, { "aria-label": "Day" }),
      select(windowOptions(), ex.window, (v) => { ex.window = v; draw(); }, { "aria-label": "Window" })),
    h("div", { class: "list-scroll" }, shown().length ? shown().map((item) => h("div", {
      class: `list-item ${keyOf(item) === ex.selected ? "selected" : ""}`, tabindex: "0",
      onclick: () => { ex.selected = keyOf(item); draw(); void drawItem(detail, item); },
      onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") (e.currentTarget as HTMLElement).click(); },
    },
      h("div", { class: "row", style: { justifyContent: "space-between", flexWrap: "nowrap" } },
        h("div", { class: "row", style: { flexWrap: "nowrap", minWidth: "0" } }, viewIcon(item.view, 16),
          h("strong", { class: "ex-name" }, item.name), item.in_training === false ? h("span", { class: "ex-new", title: "No training data" }, "new") : null),
        item.mix ? h("span", { class: "ex-times mix" }, "mix") : item.direction === "within" ? h("span", { class: "ex-times mix" }, "≈")
          : versusTag(item.observed, item.median)),
      h("div", { class: "tiny muted" }, [incidentSize(item), longDate(item.when.date, item.when.weekday), item.when.clock, minutes(item.window_minutes),
        item.when.holiday ?? (item.when.day_type === "non_working" ? "weekend" : "")].filter(Boolean).join(" · "))))
      : h("p", { class: "muted", style: { padding: "12px" } }, "None."))));
  draw();
  const holder = items.find((i) => keyOf(i) !== ex.selected && (i.incident?.members ?? []).some((m: any) => `${m.view}/${m.item_id}` === ex.selected));
  const member = holder?.incident.members.find((m: any) => `${m.view}/${m.item_id}` === ex.selected);
  const current = shown().find((i) => keyOf(i) === ex.selected) ?? holder ?? shown()[0];
  if (current) { ex.selected = keyOf(current); draw(); void drawItem(detail, current, member); }
}

// --- one alert ---------------------------------------------------------------------------------------------

/** One alert's explanation; for an incident, its lead's or the member chosen in its Incident card. */
async function drawItem(el: HTMLElement, incident: any, member?: any): Promise<void> {
  clear(el, h("div", { class: "card" }, loading()));
  const item = member ? { ...incident, ...member, view_label: member.view_label ?? incident.view_label } : incident;
  let r: any;
  try {
    r = await api(`/api/explain/item${qs({ source: ex.source, view: item.view, id: item.item_id })}`);
  } catch (e) {
    return clear(el, h("div", { class: "card" }, errorBox(e)));
  }
  const reworded = h("div");
  const showReworded = (saved: any) => clear(reworded, saved ? h("div", { class: "ex-reworded" },
    h("div", { class: "tiny muted row", style: { gap: "6px" } }, icon("sparkle", 12), `Reworded · ${saved.model}`), h("p", {}, saved.text)) : null);
  showReworded(r.reworded);
  const err = h("div");
  const rewordButton = h("button", { class: "btn small", disabled: !state.llm.online, title: state.llm.online ? "" : "The local model is offline" },
    icon("sparkle", 14), "Reword") as HTMLButtonElement;
  rewordButton.addEventListener("click", async () => {
    rewordButton.disabled = true;
    clear(err);
    try {
      showReworded(await api("/api/explain/reword", { body: { source: ex.source, view: item.view, id: item.item_id } }));
    } catch (e) {
      clear(err, errorBox(e));
    } finally {
      rewordButton.disabled = !state.llm.online;
    }
  });
  const ctx = r.context;
  const n = r.big.usual?.days;
  const usualLabel = !r.big.little_history ? `median, n = ${n}` : ctx.baseline === "pooled" ? "pooled median, when active"
    : ctx.baseline === "role" ? `${ctx.peer || "peer"} median, when active` : "median, when active";
  const noun = CHANNEL_NOUN[r.big.channel] ?? "";
  const asset = ctx.asset ?? {};
  clear(el,
    h("div", { class: "card ex-summary" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, viewIcon(item.view)), h("h2", {}, item.name),
        h("span", { class: "end" }, badge(item.view_label, "muted"),
          ctx.holiday ? badge(ctx.holiday, "info") : null,
          ctx.change_windows.length ? badge("change window", "ok") : null,
          ctx.little_history ? badge("n < 4", "warn") : null,
          ctx.baseline === "pooled" ? badge("pooled baseline", "warn") : ctx.baseline === "role" ? badge(`peers: ${ctx.peer}`, "warn") : null,
          asset.zone ? badge(asset.zone, "muted") : null, asset.role ? badge(asset.role, "muted") : null,
          asset.criticality ? badge(`criticality ${asset.criticality}`, asset.criticality === "high" ? "bad" : "warn") : null)),
      historyCaveat(r),
      h("p", { class: "ex-headline" }, r.headline),
      r.evidence ? windowStrip(r) : null,
      h("div", { class: "ex-big" },
        stat(whole(r.big.observed), r.big.channel === "new partners" ? "x, new partners in 2 h"
          : `x${noun ? ` ${noun}` : ""}, ${minutes(r.big.window_minutes)} window`, r.big.direction === "lower" ? "quiet" : "alarm"),
        stat(whole(r.big.usual?.median), usualLabel),
        ((v) => stat(v.text, v.label))(versusUsual(r.big.observed, r.big.usual?.median)),
        stat(longDate(r.when.date, r.when.weekday), `${r.when.clock} · ${r.when.holiday ?? r.when.day_words}`, "", true)),
      r.evidence ? null : h("div", { class: "ex-reasons" }, r.reasons.map((reason: any) => reasonRow(reason, r))),
      reworded, err,
      h("div", { class: "row", style: { gap: "8px", marginTop: "12px" } }, rewordButton,
        h("button", { class: "btn small", onclick: () => openInReview(ex.source, incident.item_id) }, icon("review", 14), "Review"),
        h("button", { class: "btn small", onclick: () => openInProfiles(ex.source, item.entity_type, item.entity, r.when.date) },
          icon("profiles", 14), "Profile"))),
    incident.incident?.size > 1
      ? incidentCard(incident, (m: any) => void drawItem(el, incident, m.item_id === incident.item_id ? undefined : m), ex.source, item.item_id) : null,
    r.evidence ? evidenceCard(r) : null,
    r.big.distribution?.length ? chartCard("Distribution, same window", "chart", (w) => usualDays(r, w), usualDaysTable(r)) : null,
    chartCard("Hourly counts, this day", "clock", (w) => dayChart(r, w), dayTable(r)),
    chartCard("Hourly counts, this week", "calendar", (w) => weekCharts(r, w), weekTable(r)),
    chartCard("Daily totals, 8 weeks", "chart", (w) => dailyChart(r, w), dailyTable(r)),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("individual")), h("h2", {}, "Lines"),
      h("span", { class: "end small muted" }, `${fmt.int(r.lines.length)} of ${fmt.int(r.line_count)} in the peak 5-min step`)),
      r.lines.length ? linesBlock(r.lines, 40) : h("p", { class: "small muted" }, "No lines in the peak 5-min step.")),
    r.evidence ? null : details(r));
}

export const minutes = (m: number) => (m < 60 ? `${m} min` : m % 60 === 0 ? `${m / 60} h` : `${fmt.num(m / 60, 1)} h`);

/** The windows at a glance: black where the count was unusual the alert's way, grey where it was within the
 * usual (or went the other way); the alert's own window outlined. Shows when a clump of minutes is usual by the hour. */
function windowStrip(r: any): HTMLElement {
  const group = r.big.channel === "failures" ? "failures" : "lines";
  const windows = (r.evidence as any[]).filter((e) => e.group === group && !/ vs /.test(e.title));   // older records: one row a window
  return h("div", { class: "ex-strip", role: "list", "aria-label": "Each window against its usual" },
    windows.map((e) => {
      const text = `${statLine(e, r)} · ${verdict(e)}`;
      const pill = h("span", { class: `ex-pill ${e.stance} ${e.peak ? "peak" : ""}`, role: "listitem", "aria-label": text }, e.title);
      pill.addEventListener("pointermove", (ev) => tip(text, ev as PointerEvent));
      pill.addEventListener("pointerleave", () => tip(null));
      return pill;
    }));
}

/** When the series was first seen and how much own history the comparisons had. Recorded by Phase 4g; for older
 * records, read from the 56 daily totals (null before the series appears), so only a first sighting within them shows. */
function history(r: any): { first: string | null; trainEnd: string; inTraining: boolean; trainingDays: number | null;
  thisWeek: boolean; thisDay: boolean } {
  const h0 = r.context.history;
  if (h0) return { first: h0.first_seen, trainEnd: h0.train_end, inTraining: h0.in_training, trainingDays: h0.training_days,
    thisWeek: h0.first_this_week, thisDay: h0.first_this_day };
  const dates: string[] = r.daily.dates, totals: (number | null)[] = r.daily.totals;
  const k = totals.findIndex((t) => t !== null);
  const first = k > 0 ? dates[k] : null;                                  // k = 0: seen before the 8 weeks began
  return { first, trainEnd: r.daily.train_end, inTraining: !first || first < r.daily.train_end, trainingDays: null,
    thisWeek: !!first && first >= r.week.monday, thisDay: !!first && first >= r.when.date };
}

/** A warning when the comparisons rest on no own history: not in training, or nothing before this week or day. */
export function historyCaveat(r: any): HTMLElement | null {
  if (r.method === "presence") return null;
  const s = history(r);
  if (s.inTraining && !s.thisWeek) return null;
  const when = s.first ? longDate(s.first, new Date(`${s.first}T00:00:00Z`).toLocaleDateString("en-GB", { weekday: "long", timeZone: "UTC" })) : "";
  const parts = [
    !s.inTraining ? `No training data: first seen ${when}; training ended ${shortDate(s.trainEnd)} ${s.trainEnd.slice(0, 4)}` : `First seen ${when}`,
    s.thisDay ? "no data before this day" : s.thisWeek ? "no data before this week" : "",
    !s.inTraining ? `n = 0 own training days${!r.context.baseline ? "" : ` · baseline: ${r.context.baseline === "pooled" ? `pooled ${r.label}s` : "its own level when active"}`}` : "",
  ].filter(Boolean);
  return h("div", { class: "ex-caveat", role: "note" }, icon("alert", 16), h("span", {}, parts.join(" · ")));
}

export function stat(value: string, label: string, tone = "", small = false): HTMLElement {
  return h("div", { class: `ex-stat ${tone}` }, h("div", { class: small ? "big small-big" : "big" }, value), h("div", { class: "tiny muted" }, label));
}

function reasonRow(reason: any, r: any): HTMLElement {
  const picture = reason.kind === "combination" ? h("div", { class: "row", style: { gap: "6px", flexWrap: "wrap" } },
    (reason.aspects ?? []).map((a: string) => h("span", { class: "ex-aspect" }, a)))
    : reason.kind === "volume" && reason.distribution?.length ? miniDistribution(reason)
    : reason.kind === "day_type" && reason.distributions ? dayTypeCurves(reason, r)
    : reason.kind === "day_type" && reason.compare ? dayTypePlot(reason, r) : rangePlot(reason);
  return h("div", { class: "ex-reason" },
    h("span", { class: "ex-reason-icon" }, icon(REASON_ICONS[reason.kind] ?? "chart", 18)),
    h("div", { class: "ex-reason-body" }, h("div", { class: "row", style: { gap: "10px", alignItems: "center" } },
      h("strong", {}, reason.title), picture), h("div", { class: "small" }, reason.text)));
}

// --- evidence: every check, the ones that do not support the alert greyed -------------------------------------

const GROUPS: [string, string][] = [["lines", "Window counts vs comparable days"], ["failures", "Failure counts vs comparable days"],
  ["time", "Hour of day, gap, regularity"], ["day", "Daily total"], ["who", "Distinct entities, outcome, new partners"],
  ["context", "Asset context"], ["models", "Detectors"]];

const SUMMARY_KEY = "huh.explain.summarize";
const GROUP_SHORT: Record<string, string> = { lines: "Lines", failures: "Failures", time: "Time", day: "Day", who: "Who",
  context: "Context", models: "Detectors" };

/** Every check, the ones that do not support the alert greyed; or, with Summarize evidence, the alert's summary as
 * bullets (activity_explain.summary) and only the supporting checks, as blocks. The choice is kept in this browser. */
function evidenceCard(r: any): HTMLElement {
  const items: any[] = r.evidence;
  const supporting = items.filter((e) => e.stance === "supports");
  let summarize = false;
  try { summarize = localStorage.getItem(SUMMARY_KEY) === "1"; } catch { /* per-browser convenience only */ }
  const body = h("div");
  const toggle = h("button", { class: "btn small ex-summarize", type: "button", "aria-pressed": String(summarize) },
    icon("note", 14), "Summarize evidence") as HTMLButtonElement;
  const draw = () => clear(body, summarize
    ? h("div", { class: "ex-sum" },
      (r.summary ?? []).length ? h("ul", { class: "ex-sum-list" }, (r.summary as string[]).map((line) => h("li", {}, line))) : null,
      h("div", { class: "ex-blocks" }, supporting.map((e) => evidenceBlock(e, r))))
    : GROUPS.map(([group, title]) => {
      const rows = items.filter((e) => e.group === group);
      return rows.length ? h("div", { class: "ex-ev-group" }, h("div", { class: "ex-ev-head" }, title), rows.map((e) => evidenceRow(e, r))) : null;
    }));
  toggle.addEventListener("click", () => {
    summarize = !summarize;
    toggle.setAttribute("aria-pressed", String(summarize));
    try { localStorage.setItem(SUMMARY_KEY, summarize ? "1" : "0"); } catch { /* per-browser convenience only */ }
    draw();
  });
  draw();
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("analyze")), h("h2", {}, "Evidence"),
      h("span", { class: "end" }, h("span", { class: "small muted" }, `${supporting.length}/${items.length} in the alert's direction`), toggle)),
    body);
}

/** Explain's terms, each defined in its own section of the user guide's Words used. */
const GUIDE = "#/docs/app/01_getting_started";
const TERMS: Record<string, string> = {
  "Robust deviation": "robust-deviation", "Isolation Forest": "isolation-forest", "Unusual mix": "isolation-forest",
  "Silence before": "silence-before", "Regularity, 1 h": "coefficient-of-variation", "Gap regularity, 12 h": "coefficient-of-variation",
  "New partners, 2 h": "new-partners", "Success after failures": "success-after-failures", "Peer baseline": "peer-baseline",
};
const PARTNER_TYPE: Record<string, string> = { server: "Server", source_ip: "Source IP", username: "Username", destination_ip: "Destination IP" };

/** A check's title, linked to its definition when it has one. */
function termTitle(title: string, cls: string): HTMLElement {
  const at = TERMS[title];
  return at ? h("a", { class: `${cls} ex-term`, href: `${GUIDE}?at=${at}`, title: `What is ${title.toLowerCase()}?` }, title)
    : h("strong", { class: cls }, title);
}

/** Minutes as a duration: 35 min, 17.1 h, 2.7 days. */
const duration = (m: number) => (m < 60 ? `${Math.round(m)} min` : m < 48 * 60 ? `${fmt.num(m / 60, m < 600 ? 1 : 0)} h` : `${fmt.num(m / 1440, 1)} days`);

/** A check's value and its unit, for a block. */
function blockValue(e: any): [string, string] {
  if (e.score !== undefined) return [fmt.num(e.score, 2), e.title === "Robust deviation" ? "max |z|" : "anomaly score"];
  if (e.partners) return [String(e.partners.length || e.observed || 0), "new partners"];
  if (e.asset) return [e.asset.role || e.asset.zone || "—", ""];
  if (e.observed === undefined || e.observed === null) return ["—", ""];
  if (e.title === "Silence before") return [duration(e.observed), "without a line"];
  if (e.decimals) return [fmt.num(e.observed, e.decimals), "CV"];
  const unit = e.group === "lines" ? "lines" : e.group === "failures" ? "failures" : e.active_days !== undefined ? "lines that hour"
    : e.group === "day" ? "lines that day" : e.title === "Success after failures" ? "failures before" : e.title === "Zone crossings" ? "lines across zones"
    : e.group === "who" ? `${e.title.charAt(0).toLowerCase()}${e.title.slice(1)}` : "";
  return [whole(e.observed), unit];
}

/** A check's facts, label and value: the median, P10–P90, n and the threshold it is judged by. */
function blockFacts(e: any, r: any): [string, string][] {
  const u = e.usual, days = e.basis ?? r.big.basis ?? KIND_DAYS[r.when.day_type];
  const num = (v: number) => (e.decimals ? fmt.num(v, e.decimals) : e.title === "Silence before" ? duration(v) : whole(v));
  if (e.score !== undefined) return e.title === "Robust deviation"
    ? [["Alerts from", fmt.num(e.threshold, 2)], ["Window", minutes(r.details.peak_window_minutes)], ["Against", "calendar and level, the smaller"]]
    : [["Agrees from", fmt.num(e.threshold, 3)], ...(e.alone !== undefined ? [["Alone from", fmt.num(e.alone, 3)]] as [string, string][] : [])];
  if (e.partners) return e.partners.map((p: any) => [PARTNER_TYPE[p.type] ?? p.type, p.partner] as [string, string]);
  if (e.asset) return [["Zone", e.asset.zone || "—"], ["Role", e.asset.role || "—"], ["Criticality", e.asset.criticality || "—"]];
  if (e.active_days !== undefined) return [["Active on", `${e.active_days} of ${e.days} ${days}`], ["Share", pctOf(e.active_days, e.days)]];
  if (e.compare) return [["Working days", `median ${whole(e.compare.working.median)}`], ["Non-working", `median ${whole(e.compare.non_working.median)}`]];
  if (!u) return [];
  if (!u.days) return [[e.group === "who" ? "Median, when active" : "Usual", num(u.median)],
    ...(e.threshold !== undefined ? [["Alerts from", `≥ ${num(e.threshold)}`]] as [string, string][] : [])];
  return [["Median", num(u.median)], ["P10–P90", `${num(u.low)}–${num(u.high)}`], ["n", `${u.days} ${days}`]];
}

/** One supporting check as a block: what it is (linked to its definition), its value and unit, its facts and its
 * verdict with the value it is judged by. Key blocks (the alert's own window, a detector that flagged, a success after
 * failures, first-time partners) are tinted. */
function evidenceBlock(e: any, r: any): HTMLElement {
  const [value, unit] = blockValue(e);
  const key = e.peak || (e.group === "models" && e.flagged)
    || (["Success after failures", "New partners, 2 h"].includes(e.title) && e.stance === "supports");
  const facts = blockFacts(e, r);
  return h("div", { class: `ex-block ${key ? "key" : ""}` },
    h("span", { class: "ex-block-group" }, GROUP_SHORT[e.group] ?? e.group),
    termTitle(e.title, "ex-block-title"),
    h("div", { class: "ex-block-value" }, value, unit ? h("span", { class: "ex-block-unit" }, unit) : null),
    h("span", { class: "ex-ev-tag ex-block-verdict" }, verdict(e)),
    facts.length ? h("dl", { class: "ex-block-facts" }, facts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))
      : h("p", { class: "ex-block-text" }, e.text));
}

function evidenceRow(e: any, r: any): HTMLElement {
  const chips = (names: string[]) => h("div", { class: "row", style: { gap: "6px", flexWrap: "wrap" } }, names.map((a) => h("span", { class: "ex-aspect" }, a)));
  const picture = e.partners?.length ? chips(e.partners.map((p: any) => p.partner))
    : e.asset ? chips([e.asset.zone, e.asset.role, e.asset.criticality].filter(Boolean))
    : e.active_days !== undefined ? hourStrip(e)
    : e.distributions ? dayTypeCurves(e, r)
    : e.distribution?.length ? miniDistribution(e)
    : e.score !== undefined ? scorePlot(e)
    : e.aspects ? h("div", { class: "row", style: { gap: "6px", flexWrap: "wrap" } }, e.aspects.map((a: string) => h("span", { class: "ex-aspect" }, a)))
    : e.usual ? rangePlot({ ...e, direction: e.status })
    : h("span");
  const tag = verdict(e) + (e.stance === "against" ? " (opposite direction)" : "");
  return h("div", { class: `ex-ev ${e.stance} ${e.peak ? "peak" : ""}` },
    termTitle(e.title, "ex-ev-title"), h("div", { class: "ex-ev-picture" }, picture),
    h("div", { class: "ex-ev-text small" }, statLine(e, r), h("span", { class: "ex-ev-tag" }, tag)));
}

/** The comparable days at this hour: a square per day, dark when it had lines (a bar when there are many days). */
function hourStrip(e: any): Element {
  const n = e.days, k = e.active_days;
  const kids: Element[] = [];
  if (n <= 40) {
    const size = Math.min(14, Math.floor(232 / n) - 2);
    for (let i = 0; i < n; i++) kids.push(svg("rect", { x: 4 + i * (size + 2), y: 13 - size / 2, width: size, height: size, rx: 2, class: `ex-day ${i < k ? "on" : ""}` }));
  } else {
    kids.push(svg("rect", { x: 4, y: 7, width: 232, height: 12, rx: 4, class: "ex-day" }),
      svg("rect", { x: 4, y: 7, width: Math.max(232 * (k / n), k ? 2 : 0), height: 12, rx: 4, class: "ex-day on" }));
  }
  const plot = svg("svg", { viewBox: "0 0 240 26", width: 240, height: 26, class: "ex-range", role: "img", "aria-label": `Active in this hour on ${k} of ${n} days` }, ...kids);
  plot.addEventListener("pointermove", (ev) => tip(`active in ${e.title} on ${k}/${n} comparable days (${pctOf(k, n)}) · x = ${whole(e.observed)}`, ev as PointerEvent));
  plot.addEventListener("pointerleave", () => tip(null));
  return plot;
}

/** A detector's score against its threshold: the tick is where it starts to alert. */
function scorePlot(e: any): Element {
  const top = Math.max(e.score, e.threshold, 1e-9) * 1.25;
  const x = (v: number) => 8 + (v / top) * 224;
  const plot = svg("svg", { viewBox: "0 0 240 26", width: 240, height: 26, class: "ex-range", role: "img", "aria-label": `${e.title}: ${e.score} against ${e.threshold}` },
    svg("line", { x1: 8, x2: 232, y1: 13, y2: 13, class: "ex-track" }),
    svg("rect", { x: x(e.threshold), y: 5, width: Math.max(232 - x(e.threshold), 2), height: 16, rx: 4, class: "ex-alert-zone" }),
    svg("line", { x1: x(e.threshold), x2: x(e.threshold), y1: 3, y2: 23, class: "ex-median" }),
    svg("circle", { cx: x(e.score), cy: 13, r: 6, class: `ex-dot ${e.flagged ? "" : "off"}` }));
  plot.addEventListener("pointermove", (ev) => tip(`${e.title}: ${fmt.num(e.score, 3)} · threshold ${fmt.num(e.threshold, 3)}`, ev as PointerEvent));
  plot.addEventListener("pointerleave", () => tip(null));
  return plot;
}

// --- the statistics of a check, in one line: x = observed, the median and P10-P90 of the n comparable days -----

export const KIND_DAYS: Record<string, string> = { working: "working days", non_working: "non-working days" };
const pctOf = (k: number, n: number) => `${Math.round((100 * k) / Math.max(n, 1))}%`;

/** The check's numbers, e.g. "x = 224 · median 6 · P10–P90 3–7 · n = 8 non-working days". */
function statLine(e: any, r: any): string {
  const u = e.usual;
  const days = e.basis ?? r.big.basis ?? KIND_DAYS[r.when.day_type];         // the alert's comparable days
  if (e.score !== undefined)
    return e.title === "Robust deviation"
      ? `max |z| = ${fmt.num(e.score, 2)} (${minutes(r.details.peak_window_minutes)} window; min of calendar z and level z) · threshold ${fmt.num(e.threshold, 2)}`
      : `max anomaly score = ${fmt.num(e.score, 3)} · agrees ≥ ${fmt.num(e.threshold, 3)}${e.alone !== undefined ? ` · alone ≥ ${fmt.num(e.alone, 3)}` : ""}`;
  if (e.aspects) return `largest standardised deviations (vs training IQR): ${e.aspects.join(", ")}`;
  if (e.active_days !== undefined)
    return `x = ${whole(e.observed)} in ${e.title}–${hour((Number(e.title.slice(0, 2)) + 1) % 24)} · active in this hour on ${e.active_days}/${e.days} ${days} (${pctOf(e.active_days, e.days)})`;
  if (e.compare) {
    const w = e.compare.working, n = e.compare.non_working;
    return `median daily total: working ${whole(w.median)} (n = ${w.days}) · non-working ${whole(n.median)} (n = ${n.days}) · x = ${whole(e.observed)}`;
  }
  if (e.partners || ((e.group === "who" || e.group === "context") && !u)) return e.text;     // new partners, outcome, asset
  if (e.group === "who") return `x = ${whole(e.observed)} distinct ${e.title.charAt(0).toLowerCase()}${e.title.slice(1)} (peak 5-min step) · median ${whole(u.median)} over active steps`;
  if (e.title === "Silence before" && e.rule === "resume")
    return u ? `gap = ${duration(e.observed)} before the first step · past resumptions: median ${duration(u.median)} · P10–P90 `
      + `${duration(u.low)}–${duration(u.high)} · n = ${u.days}` : e.text;
  if (e.title === "Silence before") return `gap = ${minutes(e.observed)} before the first step · median gap ${minutes(u.median)} over active steps`;
  if (e.status === "unknown") return `x = ${whole(e.observed)} · n < 4 comparable ${days}, no distribution`;
  const num = (v: number) => (e.decimals ? fmt.num(v, e.decimals) : whole(v));
  if (u && e.decimals) return `x = ${num(e.observed)} · median ${num(u.median)} · P10–P90 ${num(u.low)}–${num(u.high)} · n = ${u.days} ${days}`;
  if (u && u.days) return `x = ${whole(e.observed)} · median ${whole(u.median)} · P10–P90 ${whole(u.low)}–${whole(u.high)} · n = ${u.days} ${days}`;
  return e.text;
}

/** The check's verdict as a test result, with the value it is judged by: > P90 6, ≥ threshold 5.67, ≥ 3 (about 2×
 * median 1), rarely active: ≤ 20% (6 of 34 days), > P90 2.7 days of past resumptions. */
function verdict(e: any): string {
  const u = e.usual;
  const num = (v: number) => (e.decimals ? fmt.num(v, e.decimals) : whole(v));
  if (e.score !== undefined) return `${e.flagged ? "≥" : "<"} threshold ${fmt.num(e.threshold, e.title === "Robust deviation" ? 2 : 3)}`;
  if (e.aspects) return "top deviations";
  if (e.title === "Success after failures") return `${e.observed >= (e.threshold ?? 5) ? "≥" : "<"} ${e.threshold ?? 5} failures before a success`;
  if (e.partners) return e.observed ? `${e.observed} met for the first time` : "none new";
  if (e.title === "Silence before") {
    if (e.rule !== "resume") return e.status === "above" ? "≥ 4× median gap, ≥ 60 min" : "< 4× median gap";     // older records
    if (!u) return e.observed === undefined ? "first line" : "n < 4 resumptions";
    return `${e.status === "above" ? ">" : "≤"} P90 ${duration(u.high)} of past resumptions`;
  }
  if (e.status === "unknown") return "n < 4";
  if (e.active_days !== undefined) {
    const n = e.days;
    return e.status === "above" ? `rarely active: ≤ 20% of ${n} days` : e.status === "below" ? `usually active: ≥ 80% of ${n} days`
      : `active on ${e.active_days} of ${n} days`;
  }
  if (e.compare) return e.status === "above" ? `quiet day type: x > P90 ${whole(u.high)}` : "day types alike";
  if (e.group === "who" && u) {
    const t = e.threshold ?? Math.max(e.title.endsWith(" failed") ? 3 : 2, 2 * (u.median + 1) - 1);
    return e.status === "above" ? `≥ ${t} (about 2× median ${whole(u.median)})`
      : e.status === "below" ? `≤ ${Math.floor(u.median / 2)} (½ median ${whole(u.median)})` : `< ${t} (about 2× median ${whole(u.median)})`;
  }
  if (u && u.days) return e.status === "above" ? `> P90 ${num(u.high)}${e.decimals ? ": more uneven" : ""}`
    : e.status === "below" ? `< P10 ${num(u.low)}${e.decimals ? ": steadier" : ""}` : `within P10–P90 ${num(u.low)}–${num(u.high)}`;
  return e.tag ?? "";
}

/** A count against its usual range, on a log scale: the band is P10–P90, the tick the median, the dot x. */
function rangePlot(reason: any): Element {
  const u = reason.usual;
  if (!u || reason.observed === null || reason.observed === undefined) return h("span");
  const top = Math.max(reason.observed, u.high, u.max ?? 0, 1) * 1.15;
  const x = (v: number) => 8 + (Math.log1p(Math.max(v, 0)) / Math.log1p(top)) * 224;
  const plot = svg("svg", { viewBox: "0 0 240 26", width: 240, height: 26, class: "ex-range", role: "img", "aria-label": `x = ${whole(reason.observed)}, P10–P90 ${range(u)}` },
    svg("line", { x1: 8, x2: 232, y1: 13, y2: 13, class: "ex-track" }),
    svg("rect", { x: x(u.low), y: 6, width: Math.max(x(u.high) - x(u.low), 3), height: 14, rx: 4, class: "ex-usual" }),
    svg("line", { x1: x(u.median), x2: x(u.median), y1: 4, y2: 22, class: "ex-median" }),
    svg("circle", { cx: x(reason.observed), cy: 13, r: 6, class: `ex-dot ${reason.direction}` }));
  plot.addEventListener("pointermove", (e) => tip(`x = ${whole(reason.observed)} · median ${whole(u.median)} · P10–P90 ${range(u)}`, e as PointerEvent));
  plot.addEventListener("pointerleave", () => tip(null));
  return plot;
}

function miniDistribution(reason: any): Element {
  const plot = distributionPlot([{ values: reason.distribution, cls: "" }], reason.observed,
    { width: 240, height: 44, full: false, band: [reason.usual.low, reason.usual.high] });
  plot.addEventListener("pointermove", (e) => tip(`x = ${whole(reason.observed)} · median ${whole(reason.usual.median)} · P10–P90 ${range(reason.usual)} · n = ${reason.usual.days}`, e as PointerEvent));
  plot.addEventListener("pointerleave", () => tip(null));
  return plot;
}

/** Working days and weekends as two curves of daily lines; this day's total as the red mark. */
function dayTypeCurves(reason: any, r: any): Element {
  const d = reason.distributions;
  const plot = distributionPlot([{ values: d[r.when.day_type], cls: "" }, { values: d[r.when.day_type === "working" ? "non_working" : "working"], cls: "other" }],
    reason.observed, { width: 240, height: 44, full: false });
  const w = reason.compare.working?.median ?? 0, n = reason.compare.non_working?.median ?? 0;
  plot.addEventListener("pointermove", (e) => tip(`median daily total: working ${whole(w)} · non-working ${whole(n)} · x = ${whole(reason.observed)} (solid: this day type; dashed: the other)`, e as PointerEvent));
  plot.addEventListener("pointerleave", () => tip(null));
  return plot;
}

/** Working against non-working days: two bars of usual daily lines, and this day's total as a dot. */
function dayTypePlot(reason: any, r: any): Element {
  const w = reason.compare.working?.median ?? 0, n = reason.compare.non_working?.median ?? 0;
  const top = Math.max(w, n, reason.observed, 1) * 1.1;
  const x = (v: number) => 54 + (v / top) * 178;
  const thisKind = r.when.day_type;
  const plot = svg("svg", { viewBox: "0 0 240 30", width: 240, height: 30, class: "ex-range", role: "img",
    "aria-label": `About ${whole(w)} lines on working days, ${whole(n)} on weekends and holidays; ${whole(reason.observed)} this day` },
    svg("text", { x: 50, y: 11, class: "ex-bar-label", "text-anchor": "end" }, "working"),
    svg("text", { x: 50, y: 25, class: "ex-bar-label", "text-anchor": "end" }, "weekend"),
    svg("rect", { x: 54, y: 3, width: Math.max(x(w) - 54, 2), height: 10, rx: 3, class: `ex-bar ${thisKind === "working" ? "" : "faint"}` }),
    svg("rect", { x: 54, y: 17, width: Math.max(x(n) - 54, 2), height: 10, rx: 3, class: `ex-bar ${thisKind === "non_working" ? "" : "faint"}` }),
    svg("circle", { cx: x(reason.observed), cy: thisKind === "working" ? 8 : 22, r: 5, class: "ex-dot higher" }));
  plot.addEventListener("pointermove", (e) => tip(`median daily total: working ${whole(w)} · non-working ${whole(n)} · x = ${whole(reason.observed)}`, e as PointerEvent));
  plot.addEventListener("pointerleave", () => tip(null));
  return plot;
}

// --- distributions: how many comparable days had each count, as a histogram with a smooth curve -------------
// The x-axis is lines on a log(1 + lines) scale (so 0-6 and 224 both have room), labelled in lines; the y-axis is
// days. The curve is a Gaussian kernel density of the same days, reflected at zero, scaled to days per bar.

type Group = { values: number[]; cls: string };
const gauss = (z: number) => Math.exp(-0.5 * z * z) / Math.sqrt(2 * Math.PI);

/** n x the density per unit of log(1 + lines) at each x (log space). */
function density(values: number[], xs: number[]): number[] {
  const logs = values.map((v) => Math.log1p(Math.max(v, 0)));
  const n = logs.length, mean = logs.reduce((a, b) => a + b, 0) / n;
  const sd = Math.sqrt(logs.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(n - 1, 1));
  const sorted = [...logs].sort((a, b) => a - b);
  const iqr = sorted[Math.floor(0.75 * (n - 1))] - sorted[Math.floor(0.25 * (n - 1))];
  const spread = (iqr > 0 ? Math.min(sd, iqr / 1.34) : sd) || 0.5;
  const bw = Math.max(0.08, 0.9 * spread * Math.pow(n, -0.2));
  return xs.map((x) => logs.reduce((sum, v) => sum + gauss((x - v) / bw) + (v < 3 * bw ? gauss((x + v) / bw) : 0), 0) / bw);
}

/** Tick values in lines: 0, 1, 2, 5, 10, 20, 50 ... over a wide range; round steps over a narrow one. */
function lineTicks(lo: number, hi: number): number[] {
  if (hi / (lo + 1) > 20) {
    const out = lo <= 0 ? [0] : [];
    for (let p = 1; p <= hi; p *= 10) for (const m of [1, 2, 5]) if (p * m >= lo && p * m <= hi) out.push(p * m);
    return out;
  }
  const raw = Math.max((hi - lo) / 4, 1), magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * magnitude).find((v) => v >= raw)!;
  const out: number[] = [];
  for (let t = Math.ceil(lo / step) * step; t <= hi; t += step) out.push(t);
  return out;
}

export function distributionPlot(groups: Group[], observed: number, o: { width: number; height: number; full: boolean;
  band?: [number, number] | null; median?: number | null; unit?: string }): SVGSVGElement {
  const W = o.width, H = o.height;
  const L = o.full ? 44 : 4, R = o.full ? 18 : 4, T = o.full ? 26 : 4, B = o.full ? H - 36 : H - 4;
  const all = [...groups.flatMap((g) => g.values), observed];
  const raw0 = Math.log1p(Math.max(0, Math.min(...all))), raw1 = Math.log1p(Math.max(...all));
  const pad = Math.max((raw1 - raw0) * 0.06, 0.15);
  const x0 = Math.max(0, raw0 - pad), x1 = raw1 + pad;
  const XL = (lv: number) => L + ((lv - x0) / (x1 - x0)) * (W - L - R);
  const X = (v: number) => XL(Math.log1p(Math.max(v, 0)));
  const steps = o.full ? 180 : 90;
  const xs = Array.from({ length: steps + 1 }, (_, i) => x0 + (i / steps) * (x1 - x0));
  const bins = 28, binW = (x1 - x0) / bins;
  const curves = groups.map((g) => density(g.values, xs).map((d) => d * binW));
  const hist: number[] = Array(bins).fill(0);
  if (o.full) for (const v of groups[0].values) hist[Math.min(bins - 1, Math.max(0, Math.floor((Math.log1p(Math.max(v, 0)) - x0) / binW)))]++;
  const top = Math.max(1e-9, ...curves.flat(), ...hist) * 1.12;
  const Y = (d: number) => B - (d / top) * (B - T);
  const line = (c: number[]) => c.map((d, i) => `${i ? "L" : "M"}${XL(xs[i]).toFixed(1)} ${Y(d).toFixed(1)}`).join("");
  const area = (c: number[], from = 0, to = steps) =>
    `M${XL(xs[from]).toFixed(1)} ${B}` + c.slice(from, to + 1).map((d, k) => `L${XL(xs[from + k]).toFixed(1)} ${Y(d).toFixed(1)}`).join("") + `L${XL(xs[to]).toFixed(1)} ${B}Z`;
  const kids: Element[] = [];
  if (o.full) hist.forEach((n, k) => {
    if (!n) return;
    const a = x0 + k * binW, b = a + binW;
    const bar = svg("rect", { x: XL(a) + 1, y: Y(n), width: Math.max(XL(b) - XL(a) - 2, 1), height: B - Y(n), rx: 2, class: "ex-dist-bar" });
    bar.addEventListener("pointermove", (e) => tip(`${whole(Math.expm1(a))}–${whole(Math.expm1(b))} lines · ${n} day${n === 1 ? "" : "s"}`, e as PointerEvent));
    bar.addEventListener("pointerleave", () => tip(null));
    kids.push(bar);
  });
  curves.forEach((c, g) => {
    kids.push(svg("path", { d: area(c), class: `ex-dist-area ${groups[g].cls}` }));
    if (g === 0 && o.band) {
      const from = xs.findIndex((x) => x >= Math.log1p(Math.max(o.band![0], 0)));
      const to = xs.length - 1 - [...xs].reverse().findIndex((x) => x <= Math.log1p(Math.max(o.band![1], 0)));
      if (from >= 0 && to > from) kids.push(svg("path", { d: area(c, from, to), class: "ex-dist-band" }));
    }
    kids.push(svg("path", { d: line(c), class: `ex-dist-line ${groups[g].cls}` }));
  });
  kids.push(svg("line", { x1: L, x2: W - R, y1: B, y2: B, class: "ex-axis" }));
  if (o.full && o.median !== null && o.median !== undefined) kids.push(svg("line", { x1: X(o.median), x2: X(o.median), y1: T, y2: B, class: "ex-dist-median" }));
  const xm = X(observed);
  kids.push(svg("line", { x1: xm, x2: xm, y1: o.full ? T - 6 : T, y2: B, class: "ex-dist-mark" }),
    svg("circle", { cx: xm, cy: o.full ? T - 6 : T + 3, r: o.full ? 5 : 3.5, class: "ex-dist-dot" }));
  if (o.full) {
    const right = xm > W - 120;
    kids.push(svg("text", { x: right ? xm - 9 : xm + 9, y: T - 2, class: "ex-dist-label", "text-anchor": right ? "end" : "start" }, `x = ${whole(observed)}`));
    let last = -1e9;
    for (const t of lineTicks(Math.expm1(x0), Math.expm1(x1))) {
      const x = X(t);
      if (x < L - 1 || x > W - R + 1 || x - last < 38) continue;
      last = x;
      kids.push(svg("line", { x1: x, x2: x, y1: B, y2: B + 4, class: "ex-axis" }),
        svg("text", { x, y: B + 17, class: "ex-tick", "text-anchor": "middle" }, whole(t)));
    }
    kids.push(svg("text", { x: L - 6, y: T + 4, class: "ex-tick", "text-anchor": "end" }, whole(top / 1.12)),
      svg("text", { x: L - 6, y: B, class: "ex-tick", "text-anchor": "end" }, "0"),
      svg("text", { x: L - 6, y: T - 12, class: "ex-tick", "text-anchor": "end" }, "days"),
      svg("text", { x: W - R, y: H - 4, class: "ex-tick", "text-anchor": "end" }, o.unit ?? "lines"));
  }
  const plot = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, class: o.full ? "ex-chart" : "ex-range", role: "img",
    "aria-label": `x = ${whole(observed)} against n = ${groups[0].values.length} comparable days` }, ...kids);
  return plot;
}

/** The big picture: how many comparable days had each count, and this time's count. */
function usualDays(r: any, W: number): Element {
  const u = r.big.usual;
  const values: number[] = r.big.distribution;
  return h("div", {}, distributionPlot([{ values, cls: "" }], r.big.observed,
    { width: W, height: 230, full: true, band: [u.low, u.high], median: u.median, unit: `count per ${minutes(r.big.window_minutes)} (log scale)` }),
    legend([["ex-k-dist-bar", `histogram, n = ${values.length} ${r.big.basis ?? KIND_DAYS[r.when.day_type]}, ${r.when.clock}`],
      ["ex-k-dist-band", `P10–P90 ${range(u)}`], ["ex-k-dist-median", `median ${whole(u.median)}`], ["ex-k-alert", `x = ${whole(r.big.observed)}`]]));
}

function usualDaysTable(r: any): HTMLElement {
  const counts = new Map<number, number>();
  for (const v of r.big.distribution as number[]) counts.set(v, (counts.get(v) ?? 0) + 1);
  return tableOf(["Count", "Days"], [...counts.entries()].sort((a, b) => a[0] - b[0]).map(([v, n]) => [whole(v), String(n)]));
}

/** A chart drawn at its card's width (again when that changes), with a table view behind one switch. */
export function chartCard(title: string, iconName: string, draw: (width: number) => Element, table: HTMLElement): HTMLElement {
  let tabular = false, painted = 0;
  const body = h("div", { class: "ex-chart-body" });
  const paint = () => {
    const width = Math.floor(body.clientWidth);
    if (tabular || !width || Math.abs(width - painted) < 8) return;
    painted = width;
    clear(body, draw(width));
  };
  new ResizeObserver(paint).observe(body);
  const toggle = h("button", { class: "icon-btn", title: "Table", "aria-label": `${title} as a table`, "aria-pressed": "false" }, icon("table", 16));
  toggle.addEventListener("click", () => {
    tabular = !tabular;
    toggle.setAttribute("aria-pressed", String(tabular));
    toggle.classList.toggle("on", tabular);
    if (tabular) clear(body, table);
    else { painted = 0; paint(); }
  });
  return h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(iconName)), h("h2", {}, title),
    h("span", { class: "end" }, toggle)), body);
}

export function legend(items: [string, string][]): HTMLElement {
  return h("div", { class: "ex-legend" }, items.map(([cls, label]) => h("span", {}, h("i", { class: cls }), label)));
}

export function chart(width: number, height: number, label: string, kids: Element[]): SVGSVGElement {
  return svg("svg", { viewBox: `0 0 ${width} ${height}`, width, height, class: "ex-chart", role: "img", "aria-label": label }, ...kids);
}

// --- the day: a line for this day against a usual day and the range on most days, the alert's window shaded ---

export function dayChart(r: any, W: number): Element {
  const hours: number[] = r.day.hours, band = r.day.band;
  const win = windowOf(r);
  const [start, end] = win ?? [0, 0];
  const up = r.big.direction !== "lower";
  const top = Math.max(...hours, ...(band ? band.high : [0]), 1) * 1.12;
  const H = 228, L = 44, B = 194, T = 22, slot = (W - L - 12) / 24;
  const y = (v: number) => B - (v / top) * (B - T);
  const cx = (i: number) => L + (i + 0.5) * slot;                       // each hour's point sits mid-hour
  const xm = (minute: number) => L + (Math.max(0, Math.min(1440, minute)) / 60) * slot;
  const path = (values: number[]) => values.map((v, i) => `${i ? "L" : "M"}${cx(i).toFixed(1)} ${y(v).toFixed(1)}`).join("");
  const kids: Element[] = [
    ...(win ? [svg("rect", { x: xm(start), y: T, width: Math.max(xm(end) - xm(start), 3), height: B - T, class: "ex-window" })] : []),
    svg("line", { x1: L, x2: W - 12, y1: B, y2: B, class: "ex-axis" }),
    svg("text", { x: L - 6, y: T + 4, class: "ex-tick", "text-anchor": "end" }, whole(top / 1.12)),
    svg("text", { x: L - 6, y: B, class: "ex-tick", "text-anchor": "end" }, "0"),
    svg("text", { x: L, y: 10, class: "ex-tick" }, "count / hour")];
  if (band) {
    const upper = band.high.map((v: number, i: number) => `${i ? "L" : "M"}${cx(i).toFixed(1)} ${y(v).toFixed(1)}`).join("");
    const lower = [...band.low].reverse().map((v: number, k: number) => `L${cx(23 - k).toFixed(1)} ${y(v).toFixed(1)}`).join("");
    kids.push(svg("path", { d: `${upper}${lower}Z`, class: "ex-area-usual" }), svg("path", { d: path(band.median), class: "ex-line-usual" }));
  }
  kids.push(svg("path", { d: path(hours), class: "ex-line-day" }));
  hours.forEach((n, i) => {
    const inside = win !== null && i * 60 < end && (i + 1) * 60 > start;
    kids.push(svg("circle", { cx: cx(i), cy: y(n), r: inside ? 5 : 3, class: `ex-point ${inside ? "alert" : ""}` }));
    const hit = svg("rect", { x: L + i * slot, y: T, width: slot, height: B - T, class: "ex-hit" });
    hit.addEventListener("pointermove", (e) => tip(`${hour(i)}–${hour((i + 1) % 24)} · x = ${whole(n)}${band ? ` · median ${whole(band.median[i])} · P10–P90 ${whole(band.low[i])}–${whole(band.high[i])}` : ""}`, e as PointerEvent));
    hit.addEventListener("pointerleave", () => tip(null));
    kids.push(hit);
  });
  [0, 6, 12, 18, 24].forEach((t) => kids.push(svg("text", { x: L + t * slot, y: B + 18, class: "ex-tick", "text-anchor": t === 24 ? "end" : t ? "middle" : "start" }, hour(t % 24))));
  const kinds = KIND_DAYS[r.when.day_type];
  return h("div", {}, chart(W, H, `Lines per hour on ${r.day.date}`, kids),
    legend([["ex-k-line", `${shortDate(r.day.date)} (x per hour)`],
      ...(band ? [["ex-k-line usual", "median"], ["ex-k-area", `P10–P90, n = ${band.days} ${band.basis ?? kinds}`]] as [string, string][] : []),
      ...(win ? [["ex-k-window", `${r.when.clock}${up ? "" : ", quiet"}`]] as [string, string][] : [])]));
}

export function dayTable(r: any): HTMLElement {
  const band = r.day.band;
  return tableOf(["Hour", "Count", "Median", "P10–P90"], r.day.hours.map((n: number, i: number) => [`${hour(i)}–${hour((i + 1) % 24)}`, whole(n),
    band ? whole(band.median[i]) : "—",
    band ? `${whole(band.low[i])}–${whole(band.high[i])}` : "—"]));
}

// --- the week: one heatmap, the alert's window outlined ---------------------------------------------------------
// Count: white (fewest lines) to black (most; reversed in the dark theme), staying light grey for most of the range
// and turning black only near the top (a power curve, HEAT_POWER), from the quietest to the busiest hours of the week
// (the 2% at either end clamped, so one burst cannot flatten the rest; hours with no line stay white).
// x / median: each hour against the median of that hour on the same weekday's training days (the table and the
// tooltips give the medians), cool (blue) below, white at the median, warm (red) above, on a scale fitted to the
// week's own spread (at least half to double, so hours near their median stay pale; at most an eighth to 8 times),
// its ends written on the legend. Hours without a median (n < 4)
// are dashed. The presence method has no median: count only.

let weekMode: "lines" | "usual" = "lines";

/** Light greys for most of the range, black only near the top: the ramp follows a power curve. */
const HEAT_POWER = 2.4;
const heat = (t: number) => 0.03 + 0.97 * t ** HEAT_POWER;
const heatRamp = () => `linear-gradient(90deg in oklab, ${[0, 0.2, 0.4, 0.6, 0.75, 0.9, 1].map((t) =>
  `color-mix(in oklab, var(--heat-high) ${Math.round(heat(t) * 100)}%, var(--heat-low)) ${t * 100}%`).join(", ")})`;

/** The colour share (0 to 1) of a line count, on a log scale between the given ends; null for no value. */
function lineScale(values: number[]): { share: (v: number | null) => number | null; low: number; high: number; clamped: boolean } {
  const logs = values.map((v) => Math.log1p(v)).sort((a, b) => a - b);
  const at = (p: number) => logs[Math.min(logs.length - 1, Math.max(0, Math.round(p * (logs.length - 1))))] ?? 0;
  const lo = at(0.02), hi = Math.max(at(0.98), lo + 1e-9);
  const flat = at(0.98) - lo < 1e-6;
  return {
    share: (v) => v === null ? null : v <= 0 ? 0 : flat ? 0.5 : heat(Math.min(1, Math.max(0, (Math.log1p(v) - lo) / (hi - lo)))),
    low: Math.expm1(lo), high: Math.expm1(hi), clamped: logs[logs.length - 1] > hi + 1e-9,
  };
}

export function weekCharts(r: any, W: number): Element {
  const box = h("div");
  const paint = () => clear(box, weekView(r, W, () => paint()));
  paint();
  return box;
}

function weekView(r: any, W: number, repaint: () => void): Child[] {
  const counts: number[][] = r.week.counts;
  const usual: (number[] | null)[] = r.week.usual;
  const presence = r.method === "presence";
  const versus = weekMode === "usual" && !presence;
  const scale = lineScale(counts.flat());
  const monday = r.week.monday as string;
  const dayOf = (d: number) => { const t = new Date(`${monday}T00:00:00Z`); t.setUTCDate(t.getUTCDate() + d); return t.toISOString().slice(0, 10); };
  const L = 70, T = 18, cell = Math.max(12, Math.min(30, Math.floor((W - L - 4) / 24)));
  const [start, end] = windowOf(r) ?? [0, 1440];                 // without an alert, the whole day is outlined
  const day = r.week.alert[0];
  const segments: [number, number, number][] = [[day, Math.max(start, 0), end]];
  if (start < 0 && day > 0) segments.unshift([day - 1, 1440 + start, 1440]);
  const change = (d: number, hr: number) => (usual[d] ? Math.log2((counts[d][hr] + 1) / (usual[d]![hr] + 1)) : null);
  const changes = counts.flatMap((row, d) => row.map((_, hr) => change(d, hr))).filter((c): c is number => c !== null)
    .map(Math.abs).sort((a, b) => a - b);
  const spread = Math.min(3, Math.max(1, changes[Math.round(0.98 * (changes.length - 1))] ?? 1));   // at least ½× to 2×
  const kids: Element[] = [];
  for (let d = 0; d < 7; d++) {
    const holiday = r.week.holidays[d];
    const name = svg("text", { x: L - 8, y: T + d * cell + cell * 0.68, class: `ex-tick ${r.week.kinds[d] === "non_working" ? "rest" : ""} ${holiday ? "holiday" : ""}`, "text-anchor": "end" },
      `${DAY_SHORT[d]} ${shortDate(dayOf(d)).split(" ")[0]}`);
    if (holiday) name.appendChild(svg("title", {}, holiday));
    kids.push(name);
    for (let hr = 0; hr < 24; hr++) {
      const v = counts[d][hr];
      const u = usual[d] ? usual[d]![hr] : null;
      let cls = "ex-cell", share: number | null = scale.share(v);
      const c = versus ? change(d, hr) : null;                      // doubling = 1
      if (c !== null) {
        share = Math.min(1, Math.abs(c) / spread);
        cls += Math.abs(c) < spread * 0.08 ? " near" : c > 0 ? " above" : " below";
      } else if (versus) cls += " none";
      const rect = svg("rect", { x: L + hr * cell, y: T + d * cell, width: cell - 2, height: cell - 2, rx: 3, class: cls,
        style: share === null ? "" : `--share:${Math.round(share * 100)}%` });
      const basis = r.week.usual_basis ? ` (n = ${r.week.usual_days[d]} ${r.week.usual_basis[d]})` : "";
      const usualText = u === null ? (presence ? "" : ` · n < 4, no median${basis}`) : ` · median ${whole(u)}${basis} · x / median ${versusUsual(v, u).text}`;
      rect.addEventListener("pointermove", (e) => tip(`${DAY_SHORT[d]} ${shortDate(dayOf(d))} ${hour(hr)} · x = ${whole(v)}${usualText}`, e as PointerEvent));
      rect.addEventListener("pointerleave", () => tip(null));
      kids.push(rect);
    }
  }
  segments.forEach(([d, s, e]) => {
    const first = Math.floor(s / 60), last = Math.ceil(e / 60);
    const box = { x: L + first * cell - 2, y: T + d * cell - 2, width: (last - first) * cell + 2, height: cell + 2, rx: 5 };
    kids.push(svg("rect", { ...box, class: "ex-cell-alert halo" }), svg("rect", { ...box, class: "ex-cell-alert" }));
  });
  [0, 6, 12, 18].forEach((t) => kids.push(svg("text", { x: L + t * cell + cell / 2, y: 12, class: "ex-tick", "text-anchor": "middle" }, hour(t).slice(0, 2))));
  const label = versus ? `Week of ${shortDate(monday)} · x / median of the same weekday (training)` : `Week of ${shortDate(monday)}`;
  const modes = presence ? null
    : pills([["lines", "Count"], ["usual", "x / median"]] as ["lines" | "usual", Child][], weekMode, (v) => { weekMode = v; repaint(); }, true);
  const key = versus
    ? [h("span", {}, `≤ ${Math.round(100 / 2 ** spread)}%`), h("i", { class: "ex-ramp diverging" }), h("span", {}, `≥ ${factor(2 ** spread)}×`),
      h("span", {}, h("i", { class: "ex-k-mid" }), "= median"), h("span", {}, h("i", { class: "ex-k-none" }), "n < 4")]
    : [h("span", {}, `${whole(scale.low)} / h (P2)`), h("i", { class: "ex-ramp", style: { background: heatRamp() } }),
      h("span", {}, `${whole(scale.high)}${scale.clamped ? "+" : ""} / h (P98), power ${HEAT_POWER}`)];
  return [modes ? h("div", { class: "row", style: { marginBottom: "8px" } }, modes) : null,
    h("div", { class: "ex-week" }, h("div", { class: "tiny muted" }, label),
      chart(L + 24 * cell, T + 7 * cell, `${label}: count per hour, Monday to Sunday`, kids)),
    h("div", { class: "ex-legend" }, ...key, h("span", {}, h("i", { class: "ex-k-alert-cell" }), r.when.clock ?? shortDate(r.when.date)))];
}

export function weekTable(r: any): HTMLElement {
  const rows: Child[][] = [];
  for (let d = 0; d < 7; d++) {
    const u = r.week.usual[d];
    const day = r.week.usual_totals ? r.week.usual_totals[d] : r.daily.usual?.[r.week.kinds[d]];   // the weekday's own totals
    rows.push([`${DAY_SHORT[d]}${r.week.holidays[d] ? ` (${r.week.holidays[d]})` : ""}`, whole(r.week.counts[d].reduce((a: number, b: number) => a + b, 0)),
      u && day ? whole(day.median) : "—", u && day ? `${whole(day.low)}–${whole(day.high)}` : "—",
      r.week.usual_days ? `${r.week.usual_days[d]} ${r.week.usual_basis[d]}` : "—",
      `${hour(r.week.counts[d].indexOf(Math.max(...r.week.counts[d])))}`]);
  }
  return tableOf(["Day", "Count", "Median", "P10–P90", "n", "Peak hour"], rows);
}

// --- the last eight weeks: daily totals, working and non-working days apart ----------------------------------

/** Each day's band: its weekday's (Profiles' daily.per_day, with its basis) or its day type's (Explain). */
function dayBands(r: any): any[] {
  return r.daily.per_day ?? r.daily.kinds.map((k: string) => (r.daily.usual[k] ? { ...r.daily.usual[k], basis: KIND_DAYS[k] } : null));
}

export function dailyChart(r: any, W: number): Element {
  const totals: (number | null)[] = r.daily.totals, kinds: string[] = r.daily.kinds, dates: string[] = r.daily.dates;
  const bands = dayBands(r);
  const top = Math.max(1, ...totals.map((t) => t ?? 0), ...bands.map((u) => u?.high ?? 0)) * 1.1;
  const H = 190, L = 52, B = 160, T = 12, slot = (W - L - 8) / totals.length;
  const y = (v: number) => B - (v / top) * (B - T);
  const kids: Element[] = [svg("line", { x1: L, x2: W - 8, y1: B, y2: B, class: "ex-axis" }),
    svg("text", { x: L - 6, y: T + 4, class: "ex-tick", "text-anchor": "end" }, whole(top / 1.1)),
    svg("text", { x: L - 6, y: B, class: "ex-tick", "text-anchor": "end" }, "0")];
  const trainEnd = dates.indexOf(r.daily.train_end);
  if (trainEnd > 0) kids.push(svg("line", { x1: L + trainEnd * slot, x2: L + trainEnd * slot, y1: T, y2: B, class: "ex-split" }),
    svg("text", { x: L + trainEnd * slot + 4, y: T + 10, class: "ex-tick" }, "after training"));
  const gap = Math.min(1.5, slot * 0.15);
  const marks: Element[] = [];                                   // the usual range, drawn over the bars
  totals.forEach((t, i) => {
    const u = bands[i];
    const mid = L + i * slot + slot / 2;
    if (u && t !== null) for (const cls of ["ex-whisker halo", "ex-whisker"])         // a light halo keeps it visible on dark bars
      marks.push(svg("line", { x1: mid, x2: mid, y1: y(u.high), y2: y(u.low), class: cls }),
        svg("line", { x1: mid - slot * 0.3, x2: mid + slot * 0.3, y1: y(u.median), y2: y(u.median), class: cls }));
    const last = i === totals.length - 1;
    if (t !== null) kids.push(svg("rect", { x: L + i * slot + gap, y: y(t), width: Math.max(slot - 2 * gap, 1), height: Math.max(B - y(t), t ? 2 : 0), rx: 2,
      class: `ex-col ${last ? "alert" : kinds[i] === "non_working" ? "rest" : ""}` }));
    else kids.push(svg("text", { x: mid, y: B - 3, class: "ex-tick", "text-anchor": "middle" }, "·"));
    const hit = svg("rect", { x: L + i * slot, y: T, width: slot, height: B - T, class: "ex-hit" });
    hit.addEventListener("pointermove", (e) => tip(`${shortDate(dates[i])} · ${t === null ? "no data from the log" : `x = ${whole(t)}`}${u ? ` · ${u.basis}: median ${whole(u.median)}, P10–P90 ${whole(u.low)}–${whole(u.high)}, n = ${u.days}` : ""}`, e as PointerEvent));
    hit.addEventListener("pointerleave", () => tip(null));
    kids.push(hit);
    if (i % 7 === 0) kids.push(svg("text", { x: mid, y: B + 18, class: "ex-tick", "text-anchor": "middle" }, shortDate(dates[i])));
  });
  kids.push(...marks);
  return h("div", {}, chart(W, H, "Lines per day over the last eight weeks", kids),
    legend([["ex-k-col", "working day"], ["ex-k-rest", "non-working day"],
      ["ex-k-whisker", `median, P10–P90 (${r.daily.per_day ? "same weekday" : "by day type"})`], ["ex-k-alert", shortDate(dates[dates.length - 1])]]));
}

export function dailyTable(r: any): HTMLElement {
  const bands = dayBands(r);
  return tableOf(["Day", "Compared with", "Count", "Median", "P10–P90", "n"], r.daily.dates.map((d: string, i: number) => {
    const u = bands[i];
    return [shortDate(d), u?.basis ?? KIND_DAYS[r.daily.kinds[i]], whole(r.daily.totals[i]),
      u ? whole(u.median) : "—", u ? `${whole(u.low)}–${whole(u.high)}` : "—", u ? String(u.days) : "—"];
  }).reverse(), [0, 1]);
}

/** A plain table; columns other than `text` (by index) hold numbers and are right-aligned, headers included. */
export function tableOf(columns: string[], rows: Child[][], text: number[] = [0]): HTMLElement {
  const kind = (i: number) => (text.includes(i) ? "" : "num");
  return h("div", { class: "table-wrap", style: { maxHeight: "320px" } }, h("table", {},
    h("thead", {}, h("tr", {}, columns.map((c, i) => h("th", { scope: "col", class: kind(i) }, c)))),
    h("tbody", {}, rows.map((row) => h("tr", {}, row.map((cell, i) => h("td", { class: kind(i) }, cell)))))));
}

// --- for analysts ----------------------------------------------------------------------------------------------

function details(r: any): HTMLElement {
  const d = r.details;
  const rows: [string, string][] = [
    ["Flagged by", String(d.flagged_by).split("+").map((x) => (x === "activity_robust" ? "robust deviation" : "Isolation Forest")).join(" + ")],
    ["Robust deviation", `${fmt.num(d.robust_deviation, 2)} (alerts from ${fmt.num(d.robust_threshold, 2)})`],
    ["Isolation Forest", `${fmt.num(d.forest_score, 3)} (alerts from ${fmt.num(d.forest_threshold, 3)})`],
    ["Window", `${d.peak_window_minutes} min, ${d.steps} alerting 5-minute steps`],
    ["Baseline", d.baseline === "own" ? "its own history" : "its type's pooled history"],
    ["Compared days", `${r.context.compared_days} ${r.context.basis ?? (r.when.day_type === "working" ? "working days" : "weekends and holidays")} in training`],
  ];
  return h("details", { class: "card model-details" }, h("summary", { class: "small muted" }, "Details"),
    h("dl", { class: "kv" }, rows.map(([k, v]) => [h("dt", {}, k), h("dd", { class: "small" }, v)])));
}
