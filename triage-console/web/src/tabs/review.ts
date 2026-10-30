// Review, for the people who run the servers (US-34): each item is a group of unusual events, shown
// by what an operations engineer knows (servers, accounts, addresses, dates) rather than by model.
// Its unusual events are listed rarest first ("1 in 1,000" against the reference period); opening
// one shows its lines and the logs around it, from every log on the same server (one read-only SQL
// query, which can be opened in Data → SQL). Then a label (verdicts.ts) and a note. The models'
// own scores stay under "Model details". Items still to review are kept apart from reviewed ones.
// Items come from the test period (Phase 7b clusters) and the validation period (flagged observations
// grouped by server and source address); a filter shows one period or both. AUTH and OSSEC also list
// Phase 4g activity alerts: an unusual amount of activity of the whole log, or of one server, source IP,
// username or destination IP, judged on counts and timing only. A group whose flagged events
// all belong to whitelisted accounts (Settings → Whitelisted users) is listed under Whitelisted, not
// Needs review; it can still be opened and labelled.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, keepScroll, loading, pills, select, type Child } from "../dom";
import { icon, viewIcon } from "../icons";
import { choose, chosenSource, logTypePicker } from "../log-type";
import { reviewLoader } from "../loaders";
import { playbookFor } from "../playbooks";
import { sourceLabel, state } from "../state";
import { VERDICTS, sigmaBadge, verdictBadge, verdictLabel, whitelistBadge } from "../verdicts";
import { count, dateSpan, eventName, groupName, rarity, topValues } from "../words";
import { linesBlock } from "./clusters";
import { openInExplain } from "./explain";
import { reportOn } from "./reports";
import { filterBar, filterQuery, filtersActive, linkedReports } from '../review-filters';

type Queue = "open" | "done" | "whitelisted";
const rv = { source: "", view: "", queue: "open" as Queue, verdict: "", selected: "", period: "" };
const PERIODS: [string, string][] = [["", "Test and validation"], ["test", "Test period"], ["validation", "Validation period"]];
const periodOf = (item: any) => item.period ?? "test";
// Kept while the app is open, so the window chosen for one event carries to the next.
const ctx = { before: 10, after: 10, logs: new Set(["auth", "ossec", "pf", "ipf"]) };
const LOG_NAMES: [string, string][] = [["auth", "AUTH"], ["ossec", "OSSEC"], ["pf", "PF"], ["ipf", "IPFilter"]];
const PRESETS: [string, number][] = [["±2 min", 2], ["±10 min", 10], ["±30 min", 30], ["±1 h", 60], ["±6 h", 360]];
const logName = (key: string) => LOG_NAMES.find(([k]) => k === key)?.[1] ?? key;

/** Opens Review on one waiting item (the Dashboard's Next to review). */
export function openInReview(source: string, itemId: string): void {
  choose(source);
  Object.assign(rv, { source, view: "", queue: "open" as Queue, verdict: "", selected: itemId, period: "" });
  location.hash = "#/review";
}

export async function renderReview(main: HTMLElement): Promise<void> {
  if (rv.source !== chosenSource()) Object.assign(rv, { source: chosenSource(), view: "", selected: "" });   // log type changed on another page
  const src = state.catalog.sources[rv.source];
  const listBox = h("div", { class: "card" }, loading());
  const detail = h("div");
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Review")),
      h("div", { class: "row", style: { gap: "10px" } }, h("a", { class: "btn small", href: "#/uploads" }, icon("upload", 14), "Uploads"), logTypePicker(() => renderReview(main)))),
    filterBar(rv.source, () => { rv.selected = ''; renderReview(main); }),
    h("div", { class: "grid split" }, listBox, detail));

  let items: any[];
  try {
    items = (await api(`/api/review/queue${qs({ source: rv.source, view: rv.view, filters: filterQuery() })}`)).items;
  } catch (e) {
    return clear(listBox, errorBox(e));
  }
  items = items.filter((i) => !rv.period || periodOf(i) === rv.period);
  const open = items.filter((i) => !i.review && !i.overridden);
  const covered = items.filter((i) => !i.review && i.overridden);
  const done = items.filter((i) => i.review);
  if (rv.queue === "whitelisted" && !covered.length) rv.queue = "open";
  const byVerdict = Object.fromEntries(VERDICTS.map((v) => [v.id, done.filter((i) => i.review.verdict === v.id).length]));
  const shown = rv.queue === "open" ? open : rv.queue === "whitelisted" ? covered : done.filter((i) => !rv.verdict || i.review.verdict === rv.verdict);

  const queueSwitch = pills([["open", `Needs review · ${open.length}`], ["done", `Reviewed · ${done.length}`],
    ...(covered.length ? [["whitelisted", h("span", { title: "Whitelisted", "aria-label": `Whitelisted · ${covered.length}` },
      icon("shield", 14), fmt.int(covered.length))]] : [])] as [Queue, Child][], rv.queue,
    (v) => { rv.queue = v; rv.verdict = ""; rv.selected = ""; renderReview(main); }, covered.length > 0);
  const verdictFilter = rv.queue === "done" ? h("div", { class: "row", style: { margin: "10px 0 0", gap: "6px" } },
    [["", `All · ${done.length}`], ...VERDICTS.map((v) => [v.id, `${v.label} · ${byVerdict[v.id]}`])].map(([v, label]) =>
      h("button", { class: `btn small ${rv.verdict === v ? "olive" : ""}`, onclick: () => { rv.verdict = v; rv.selected = ""; renderReview(main); } }, label))) : null;

  const draw = () => keepScroll(listBox, () => clear(listBox,
    queueSwitch, verdictFilter,
    h("div", { class: "row", style: { margin: "12px 0 8px" } },
      select([["", "All"], ...[...src.views, ...(src.review_views ?? [])].map((v) => [v.id, v.label] as [string, string])], rv.view,
        (v) => { rv.view = v; rv.selected = ""; renderReview(main); }, { "aria-label": "Grouping" }),
      src.method === "baseline" ? select(PERIODS, rv.period, (v) => { rv.period = v; rv.selected = ""; renderReview(main); }, { "aria-label": "Period" }) : null),
    h("div", { class: "list-scroll" }, shown.length ? shown.map((item) => h("div", {
      class: `list-item ${item.item_id === rv.selected ? "selected" : ""}`, tabindex: "0",
      onclick: () => { rv.selected = item.item_id; draw(); drawItem(detail, item, () => renderReview(main)); },
      onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") (e.currentTarget as HTMLElement).click(); },
    },
      h("div", { class: "row", style: { justifyContent: "space-between", flexWrap: "nowrap" } },
        h("div", { class: "row", style: { flexWrap: "nowrap", minWidth: "0" } }, viewIcon(item.view, 16),
          h("strong", { style: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" } }, title(item))),
        h("span", { class: "row", style: { gap: "4px", flexWrap: "nowrap" } },
          item.sigma?.length ? h("span", { class: "badge bad", title: item.sigma.map((s: any) => s.title).join("\n") }, icon("sigma", 12)) : null,
          periodOf(item) === "validation" ? badge("validation", "info") : null,
          item.review ? verdictBadge(item.review.verdict)
            : item.overridden ? whitelistBadge() : item.whitelisted ? whitelistBadge(fmt.int(item.whitelisted)) : null)),
      h("div", { class: "tiny muted" }, item.kind === "cluster"
        ? [topValues(item.top?.host_id ?? item.top?.hostname, 2).map(([v]) => v).join(", "), count(item.view, item.flagged_rows ?? 0), dateSpan(item.first_seen, item.last_seen)]
          .filter(Boolean).join(" · ")
        : item.kind === "activity_alert" ? [incidentSize(item), item.peak, dateSpan(item.first_seen, item.last_seen)].filter(Boolean).join(" · ")
        : `${count("individual", item.line_count)}`)))
      : h("p", { class: "muted", style: { padding: "12px" } }, rv.queue === "open" ? "Nothing left to review." : rv.queue === "whitelisted" ? "None." : "No reviews yet."))));
  draw();
  listBox.querySelector(".list-item.selected")?.scrollIntoView({ block: "nearest" });     // opened from the Dashboard
  const current = shown.find((i) => i.item_id === rv.selected) ?? shown[0];
  if (current) { rv.selected = current.item_id; draw(); drawItem(detail, current, () => renderReview(main)); }
  else clear(detail, h("div", { class: "card muted" }, "Nothing selected."));
}

/** A Review item's name: a group's (renamed, or read from its event types), an activity alert's entity, or a
 * firewall item's rank. */
export const title = (item: any) => (item.kind === "cluster" ? (item.renamed ? item.name : groupName(item.name))
  : item.kind === "activity_alert" ? item.name : `Firewall activity #${item.rank}`);

/** Servers, accounts and addresses as chips: what an operations engineer recognises. */
function who(top: Record<string, string> | undefined): HTMLElement | null {
  if (!top) return null;
  const rows: [string, string, [string, string][]][] = [
    ["server", "Servers", topValues(top.host_id ?? top.hostname)], ["user", "Accounts", topValues(top.username)],
    ["ip", "From", topValues(top.source_ip)], ["ip", "To", topValues(top.destination_ip)], ["process", "Programs", topValues(top.process_name)]];
  const shown = rows.filter(([, , values]) => values.length);
  if (!shown.length) return null;
  return h("dl", { class: "who" }, shown.map(([kind, label, values]) => [h("dt", {}, label),
    h("dd", {}, values.map(([v, share]) => h("span", { class: `who-chip ${kind}`, title: share ? `${share} of these events` : "" }, v, share ? h("small", {}, share) : null)))]));
}

// --- one item: summary, decision, its unusual events, history ---------------------------------------

async function drawItem(el: HTMLElement, item: any, refresh: () => void): Promise<void> {
  const note = h("textarea", { rows: 2, "aria-label": "Note", placeholder: "Note", style: { fontFamily: "var(--font-body)" } }) as HTMLTextAreaElement;
  note.value = item.review?.note ?? "";
  note.addEventListener("input", () => { note.classList.remove("needs"); note.placeholder = "Note"; });
  const err = h("div");
  const history = h("div");
  const events = h("div");
  let saving = false;
  const decide = async (verdict: string) => {
    if (saving) return;
    if (VERDICTS.find((v) => v.id === verdict)?.note && !note.value.trim()) {    // this label needs a note: ask for it in place
      note.classList.add("needs");
      note.placeholder = VERDICTS.find((v) => v.id === verdict)!.note!.replace(/^./, (c) => c.toUpperCase());
      note.focus();
      return;
    }
    saving = true;
    const buttons = [...el.querySelectorAll<HTMLButtonElement>('.verdict-buttons button')];
    buttons.forEach(b => b.disabled = true);
    try {
      await api("/api/review", { body: { source: rv.source, view: item.view, item_id: item.item_id, kind: item.kind, verdict, note: note.value } });
      refresh();
    } catch (e) {
      saving = false;
      buttons.forEach(b => b.disabled = false);
      clear(err, errorBox(e));
    }
  };
  const tone = item.review?.verdict === "security_relevant" ? "alarm" : item.review ? "accent" : "";
  clear(el,
    h("div", { class: `card ${tone}` },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, viewIcon(item.view)),
        h("h2", {}, title(item)),
        h("span", { class: "end" }, item.review ? verdictBadge(item.review.verdict) : item.overridden ? whitelistBadge() : badge("needs review", "dark"))),
      h("div", { class: "row", style: { gap: "6px", marginBottom: "12px" } }, badge(sourceLabel(rv.source), "muted"), badge(item.view_label, "muted"),
        periodOf(item) === "validation" ? badge("validation period", "info") : null,
        item.whitelisted && !item.overridden ? whitelistBadge(`${fmt.int(item.whitelisted)} of ${fmt.int(item.flagged_rows ?? 0)} whitelisted`) : null,
        filtersActive() ? h("span", { class: "badge info rf-on", title: "Filters narrow the events shown; a label applies to the whole group" }, icon("filter", 12), "filtered") : null,
        (item.sigma ?? []).map((s: any) => sigmaBadge(s.title, s.observations))),
      item.kind === "cluster"
        ? [h("div", { class: "row", style: { gap: "28px", alignItems: "flex-end", marginBottom: "10px" } },
          h("div", {}, h("div", { class: "big" }, fmt.int(item.flagged_rows)), h("div", { class: "tiny muted" }, count(item.view, item.flagged_rows ?? 0).replace(/^[\d,]+ /, "unusual "))),
          h("div", {}, h("div", { class: "big small-big" }, dateSpan(item.first_seen, item.last_seen)), h("div", { class: "tiny muted" }, "seen"))),
          who(item.top)]
        : item.kind === "activity_alert"
        ? [h("div", { class: "row", style: { gap: "28px", alignItems: "flex-end", marginBottom: "10px" } },
          h("div", {}, h("div", { class: "big" }, fmt.int(item.peak_lines)), h("div", { class: "tiny muted" }, `lines in ${item.peak_minutes} min`)),
          h("div", {}, h("div", { class: "big" }, item.usual_text || fmt.num(item.usual, item.usual < 10 ? 1 : 0)),
            h("div", { class: "tiny muted" }, item.usual_text ? "P10–P90" : "median when active")),
          h("div", {}, h("div", { class: "big small-big" }, dateSpan(item.first_seen, item.last_seen)), h("div", { class: "tiny muted" }, "seen"))),
          who(item.top)]
        : h("div", { class: "row", style: { gap: "28px", alignItems: "flex-end" } },
          h("div", {}, h("div", { class: "big" }, `#${item.rank}`), h("div", { class: "tiny muted" }, "rank")),
          h("div", {}, h("div", { class: "big" }, fmt.int(item.line_count)), h("div", { class: "tiny muted" }, "lines"))),
      h("div", { class: "verdict-buttons", style: { marginTop: "14px" } }, VERDICTS.map((v) =>
        h("button", { class: `btn ${v.id} ${item.review?.verdict === v.id ? "on" : ""}`, title: v.hint, onclick: () => decide(v.id) }, v.label))),
      note, err,
      h("div", { class: "row", style: { gap: "8px", marginTop: "8px" } },
        item.kind === "activity_alert" ? h("button", { class: "btn small", onclick: () => openInExplain(rv.source, item.view, item.item_id) },
          icon("explain", 14), "Explain") : null,
        h("a", { class: "btn small", href: playbookFor(item, rv.source) }, icon("docs", 14), "Playbook"),
        item.review ? reportButton(item, err) : null, linkedReports(`${rv.source}/${item.view}/${item.item_id}`))),
    item.incident?.size > 1 ? incidentCard(item, (m: any) => drawEvents(events, { ...item, view: m.view, row_manifest_ids: `${m.view}:${m.item_id}` })) : null,
    h("div", { class: "card" }, events),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("review")), h("h2", {}, "History")), history));

  drawEvents(events, item);
  const { history: rows } = await api(`/api/review/history${qs({ source: rv.source, view: item.view, item: item.item_id })}`);
  clear(history, rows.length ? rows.map((r: any) => h("div", { class: "comment" },
    verdictBadge(r.verdict), h("span", { class: "when" }, `${r.reviewer} · ${r.created_at.replace("T", " ").slice(0, 16)}`),
    r.note ? h("p", {}, r.note) : null)) : h("p", { class: "small muted" }, "Not reviewed yet."));
}

/** An incident's size in the list: its days for a routine, its alerts for an event on several entities. */
export function incidentSize(item: any): string {
  const inc = item.incident;
  return !inc || inc.size < 2 ? "" : inc.kind === "recurring" ? `${inc.days} days` : `${inc.size} alerts`;
}

/** Every alert of an incident (Phase 4g: one event on several entities, or one routine on several days): when, who and
 * its peak. A click shows that alert's lines under This activity; Explain opens its explanation. The label above is
 * the incident's. */
export function incidentCard(item: any, show: (member: any) => void, source = rv.source, selected = item.item_id): HTMLElement {
  const inc = item.incident;
  let chosen = selected;
  const body = h("tbody");
  const draw = () => clear(body, inc.members.map((m: any) => h("tr", {
    class: `clickable ${m.item_id === chosen ? "selected" : ""}`, tabindex: "0",
    onclick: () => { chosen = m.item_id; draw(); show(m); },
    onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") (e.currentTarget as HTMLElement).click(); },
  },
    h("td", { class: "mono small" }, String(m.start).slice(0, 16)), h("td", {}, m.name), h("td", { class: "small" }, m.peak),
    h("td", { class: "num" }, h("button", { class: "btn small", type: "button", onclick: (e: Event) => { e.stopPropagation(); openInExplain(source, m.view, m.item_id); } },
      icon("explain", 14), "Explain")))));
  draw();
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(inc.kind === "recurring" ? "history" : "users")),
      h("h2", {}, inc.kind === "recurring" ? `Recurring: ${inc.days} days` : `Incident: ${inc.size} alerts`),
      h("span", { class: "end small muted" }, inc.kind === "recurring" ? `about ${inc.clock}` : inc.kind === "linked" ? "linked" : "with the whole log")),
    h("div", { class: "table-wrap", style: { maxHeight: "280px" } }, h("table", {},
      h("thead", {}, h("tr", {}, ["When", "Who", "Peak", ""].map((c) => h("th", { scope: "col" }, c)))), body)));
}

/** Starts a report on a reviewed item (Reports → reportOn), its saved notes as the analyst comments: oldest first, each
 * under who wrote it, when, and the label it was saved with, exactly as typed. */
function reportButton(item: any, err: HTMLElement): HTMLElement {
  const button = h("button", { class: "btn small" }, icon("reports", 14), "Report") as HTMLButtonElement;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const { history: rows } = await api(`/api/review/history${qs({ source: rv.source, view: item.view, item: item.item_id })}`);
      const comments = rows.filter((r: any) => r.note?.trim()).reverse()
        .map((r: any) => `${r.created_at.replace("T", " ").slice(0, 16)} · ${r.reviewer} · ${verdictLabel(r.verdict)}\n${r.note.trim()}`).join("\n\n");
      reportOn({ ...item, source: rv.source }, comments);
    } catch (e) {
      button.disabled = false;
      clear(err, errorBox(e));
    }
  });
  return button;
}

// --- the group's unusual events, rarest first ---------------------------------------------------------

const meter = (p: number | null | undefined) => {
  const r = rarity(p);
  return h("span", { class: "rarity", title: r.title }, h("span", { class: "meter" }, h("i", { style: { width: `${Math.round(r.fill * 100)}%` } })), h("span", { class: "small" }, r.text));
};

async function drawEvents(box: HTMLElement, item: any): Promise<void> {
  const list = h("div"), one = h("div", { class: "obs" });
  const head = (n?: string) => h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("analyze")), h("h2", {}, item.kind === "cluster" ? "Unusual events" : "This activity"),
    n ? h("span", { class: "end small muted" }, n) : null);
  if (item.kind !== "cluster") {                                   // firewall activity (one flow) or an activity alert
    const id = String(item.row_manifest_ids ?? "").split(";")[0].split(":").pop()?.trim() ?? "";
    clear(box, head(), one);
    return drawEvent(one, item.view, id);
  }
  clear(box, head(), list, one);
  clear(list, loading());
  let answer: any;
  try {
    answer = await api(`/api/review/flagged${qs({ source: rv.source, view: item.view, cluster: item.cluster_id, filters: filterQuery() })}`);
  } catch (e) {
    return clear(list, errorBox(e));
  }
  if (answer.status === "purged") return clear(list, h("p", { class: "small muted" }, "Purged with the data"));
  if (answer.status !== "ready") return clear(list, loading(`Indexing (${answer.status})`));
  box.replaceChild(head(answer.total > answer.items.length ? `${answer.items.length} rarest of ${fmt.int(answer.total)}` : fmt.int(answer.total)), box.firstChild!);
  let chosen = answer.items[0]?.row_id ?? "";
  const drawList = () => keepScroll(list, () => clear(list,
    h("div", { class: "table-wrap", style: { maxHeight: "240px" } }, h("table", { class: "obs-list" },
      h("thead", {}, h("tr", {}, ["When", "Server", "How rare"].map((c) => h("th", { scope: "col" }, c)))),
      h("tbody", {}, answer.items.map((o: any) => h("tr", {
        class: `clickable ${o.row_id === chosen ? "selected" : ""}`, tabindex: "0",
        onclick: () => { chosen = o.row_id; drawList(); drawEvent(one, item.view, o.row_id); },
        onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") (e.currentTarget as HTMLElement).click(); },
      },
        h("td", { class: "mono small" }, o.time), h("td", {}, o.server, o.whitelisted ? [" ", whitelistBadge()] : null),
        h("td", {}, h("div", { class: "row", style: { gap: "6px", flexWrap: "nowrap" } },
          o.sigma?.length ? h("span", { class: "badge bad", title: o.sigma.join("\n") }, icon("sigma", 12)) : null, meter(o.anomaly))))))))));
  drawList();
  if (chosen) drawEvent(one, item.view, chosen);
}

const duration = (seconds: number) => !Number.isFinite(seconds) ? "—" : seconds < 1 ? "under a second"
  : seconds < 120 ? `${Math.round(seconds)} s` : seconds < 7200 ? `${Math.round(seconds / 60)} min` : `${fmt.num(seconds / 3600, 1)} h`;

async function drawEvent(box: HTMLElement, view: string, id: string): Promise<void> {
  clear(box, loading());
  let o: any;
  try {
    o = await api(`/api/review/observation${qs({ source: rv.source, view, id })}`);
  } catch (e) {
    return clear(box, errorBox(e));
  }
  const results = h("div");
  const minutes = (value: number, label: string) =>
    h("input", { type: "number", min: "0", max: "1440", step: "1", value: String(value), "aria-label": `${label} (minutes)`, style: { width: "84px" } }) as HTMLInputElement;
  const before = minutes(ctx.before, "Before"), after = minutes(ctx.after, "After");
  const fetchButton = h("button", { class: "btn primary small" }, icon("data", 14), "Show") as HTMLButtonElement;
  const run = async () => {
    ctx.before = Math.max(0, Math.min(1440, Number(before.value) || 0));
    ctx.after = Math.max(0, Math.min(1440, Number(after.value) || 0));
    fetchButton.disabled = true;
    const loader = reviewLoader(`${ctx.before} min before · ${ctx.after} min after`, { before: ctx.before, after: ctx.after });
    clear(results, loader.el);
    try {
      const r = await api("/api/review/context", { body: { source: rv.source, view, id, before: ctx.before, after: ctx.after, logs: [...ctx.logs] } });
      await loader.arrive({ found: r.rows.length });
      drawAround(results, r);
    } catch (e) {
      await loader.fail();                                    // a red light at a T-junction, or the cabinet topples
      clear(results, errorBox(e), developerNote(e, { source: rv.source, view, id, before: ctx.before, after: ctx.after, logs: [...ctx.logs] }));
    } finally {
      fetchButton.disabled = false;
    }
  };
  fetchButton.addEventListener("click", run);
  const logBoxes = LOG_NAMES.map(([key, label]) => {
    const check = h("input", { type: "checkbox", checked: ctx.logs.has(key) }) as HTMLInputElement;
    check.addEventListener("change", () => { check.checked ? ctx.logs.add(key) : ctx.logs.delete(key); });
    return h("label", { class: "row small", style: { gap: "4px" } }, check, label);
  });
  const span = o.start === o.end ? o.start : `${o.start} → ${o.end}`;
  const rare = rarity(o.anomaly);
  const purged = o.lines_status === "purged";             // data/ purged: the scores and times remain, the lines do not

  clear(box,
    h("div", { class: "obs-head" },
      h("div", { class: "row", style: { gap: "8px", alignItems: "center" } },
        o.who ? h("span", { class: `who-chip ${o.who.kind}`, title: o.who.label }, o.who.value)
          : h("span", { class: "who-chip server" }, o.server || "server unknown"), h("span", { class: "mono small" }, span || "—")),
      o.method === "baseline" ? h("div", { class: "obs-rare", title: rare.title }, h("div", { class: "big" }, rare.text), meter(o.anomaly).firstChild as HTMLElement) : null),
    o.facts ? h("dl", { class: "kv", style: { margin: "8px 0" } },
      Object.entries(o.facts).map(([k, v]) => k === "duration_hours"
        ? [h("dt", {}, "duration"), h("dd", { class: "small" }, duration(Number(v) * 3600))]
        : [h("dt", {}, k.replace(/_/g, " ")), h("dd", { class: "small" }, String(v))])) : null,
    purged ? h("p", { class: "small muted" }, "Lines purged with the data") : null,
    o.lines?.length ? [linesBlock(o.lines, 12),
      o.line_count > o.lines.length ? h("div", { class: "tiny muted" }, `${o.lines.length} of ${fmt.int(o.line_count)} lines`) : null] : null,
    o.method === "baseline" && o.detectors.length ? modelDetails(o) : null,
    purged ? null : h("div", { class: "ctx-form" },
      h("strong", {}, "Around this event"),
      h("div", { class: "row", style: { gap: "14px", alignItems: "flex-end" } },
        h("label", { class: "field" }, h("span", {}, "Before (min)"), before),
        h("label", { class: "field" }, h("span", {}, "After (min)"), after),
        h("div", { class: "row", style: { gap: "4px" } }, PRESETS.map(([label, m]) =>
          h("button", { class: "btn small", onclick: () => { before.value = after.value = String(m); } }, label))),
        o.scope && o.scope !== "server" ? null : h("div", { class: "row", style: { gap: "10px" } }, logBoxes),     // an entity: its own log
        fetchButton)),
    results);
}

// The console writes and checks this query itself, so a failure is a fault to report, not the user's mistake.
// The details hold no log lines: the error, what was asked for, and when.
function developerNote(error: unknown, asked: Record<string, unknown>): HTMLElement {
  const details = JSON.stringify({ error: error instanceof Error ? error.message : String(error), ...asked,
    page: "Review · Around this event", at: new Date().toISOString() }, null, 2);
  const copy = h("button", { class: "btn small" }, icon("copy", 14), "Copy details") as HTMLButtonElement;
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(details); clear(copy, icon("check", 14), "Copied"); }
    catch { clear(copy, icon("alert", 14), "Copy failed"); }
  });
  return h("div", { class: "dev-note" }, h("span", {}, "A fault in the console, not in your search: please send the details to the developer."), copy);
}

// The models' own view of the event, for whoever looks after them: closed unless opened.
function modelDetails(o: any): HTMLElement {
  return h("details", { class: "model-details" }, h("summary", { class: "small muted" }, "Model details"),
    h("div", { class: "table-wrap" }, h("table", { class: "det-table" },
      h("thead", {}, h("tr", {}, ["Detector", "How rare", "Score", "", "Why"].map((c) => h("th", { scope: "col" }, c)))),
      h("tbody", {}, o.detectors.map((d: any) => h("tr", {},
        h("td", {}, d.label), h("td", {}, meter(d.percentile)),
        h("td", { class: "num small" }, d.score === null || d.score === undefined ? "—" : fmt.num(d.score, 3)),
        h("td", {}, d.flagged ? badge("flagged", "bad") : h("span", { class: "tiny muted" }, "—")),
        h("td", { class: "tiny", title: d.explanation }, d.explanation ? d.explanation.slice(0, 160) + (d.explanation.length > 160 ? "…" : "") : h("span", { class: "muted" }, "—"))))))));
}

function drawAround(box: HTMLElement, r: any): void {
  const own = new Set<string>(r.own ?? []);
  const start = Date.parse(r.observation.start.replace(" ", "T")), end = Date.parse(r.observation.end.replace(" ", "T"));
  const offset = (t: string) => {
    const at = Date.parse(t.replace(" ", "T"));
    if (Number.isNaN(at)) return "";
    const s = at < start ? (at - start) / 1000 : at > end ? (at - end) / 1000 : 0;
    if (s === 0) return "during";
    const a = Math.abs(Math.round(s));
    return `${s < 0 ? "−" : "+"}${Math.floor(a / 60)}:${String(a % 60).padStart(2, "0")}`;
  };
  const counts = new Map<string, number>();
  for (const row of r.rows) counts.set(row[0], (counts.get(row[0]) ?? 0) + 1);
  const openInSql = () => { state.pendingSql = r.query; location.hash = "#/data/sql"; };
  clear(box,
    h("div", { class: "row", style: { margin: "10px 0 6px", justifyContent: "space-between" } },
      h("span", { class: "row", style: { gap: "6px" } }, h("strong", { class: "small" }, `${fmt.int(r.rows.length)} lines`),
        [...counts].map(([log, n]) => badge(`${logName(log)} ${fmt.int(n)}`, "muted")),
        r.truncated ? badge("first 1,000", "warn") : null),
      h("button", { class: "btn small", onclick: openInSql }, icon("data", 14), "Open in SQL")),
    r.rows.length ? h("div", { class: "ctx-log", role: "list" }, r.rows.map((row: any[]) => {
      const mine = row[0] === r.own_log && own.has(String(row[5]));
      const when = offset(String(row[1]));
      const day = String(row[1]).slice(0, 10), time = String(row[1]).slice(11, 19);
      return h("div", { class: `ctx-entry ${mine ? "own" : when === "during" ? "during" : when.startsWith("−") ? "before" : "after"}`, role: "listitem" },
        h("div", { class: "ctx-when mono", title: day }, h("strong", {}, mine ? "▶ this" : when), h("span", {}, time)),
        h("div", { class: "ctx-what" },
          h("div", { class: "row", style: { gap: "6px" } },
            badge(logName(row[0]), row[0] === r.own_log ? "dark" : "muted"),
            h("span", { class: "tiny ctx-event" }, row[3] ? eventName(String(row[3])) : "")),
          h("div", { class: "mono tiny ctx-line" }, row[4] ?? "")));
    }))
      : h("p", { class: "small muted" }, "No lines."));
  const log = box.querySelector<HTMLElement>(".ctx-log"), first = log?.querySelector<HTMLElement>(".ctx-entry.own");
  if (log && first) log.scrollTop = Math.max(0, first.offsetTop - 80);       // open at the event, with a little of what came before
}
