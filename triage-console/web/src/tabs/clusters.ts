// Clusters: a map of similar activity (click a group to open it), the list,
// and the opened group below: what it contains, typical lines, every member.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, loading, note, select } from "../dom";
import { icon, viewIcon } from "../icons";
import { buildGroups, clusterMap, layoutFor, loadMap, mapInfoOrNone, mapOnDemand, pointDetails, type ClusterMap, type MapGroup, type MapInfo } from "../cluster-map";
import { chosenSource, dataScope } from "../log-type";
import { sourceLabel, state } from "../state";
import { verdictBadge } from "../verdicts";

const cl = { source: "", view: "individual", selected: "" };
const TYPE_COLORS = ["#333333", "#999933", "#ff3333", "#b3a07a", "#6b6b6b", "#cccc66", "#ff9999", "#55551f"];

// Which groups are shown on the map, per log type and view (kept while the app is open).
const visibility = new Map<string, Set<number>>();
let drawing = 0;           // only the latest draw may fill the page (the log type can change while a map loads)
const KINDS: [MapGroup["kind"], string][] = [
  ["named", "Named by people"], ["auto", "Automatic names"], ["unnamed", "Unnamed (map only)"], ["isolated", "Isolated points"],
];

export async function drawClusters(body: HTMLElement): Promise<void> {
  // Clusters are per log type, and only the learned-baseline types (AUTH, OSSEC) have them.
  const baseline = Object.keys(state.catalog.sources).filter((k) => state.catalog.sources[k].method === "baseline");
  if (dataScope.all || !baseline.includes(chosenSource())) {
    return clear(body, h("div", { class: "card" }, note(dataScope.all
      ? "Clusters are drawn for one log type at a time. Choose AUTH or OSSEC in Log type above."
      : `${sourceLabel(chosenSource())} has no clusters: firewall logs are checked with the presence rule (any traffic is flagged), not a learned baseline. Choose AUTH or OSSEC in Log type above.`)));
  }
  if (cl.source !== chosenSource()) Object.assign(cl, { source: chosenSource(), selected: "" });
  const src = state.catalog.sources[cl.source];
  if (!src.views.some((v) => v.id === cl.view)) cl.view = src.views[0].id;
  const draw = ++drawing;
  const key = `${cl.source}/${cl.view}`;
  const mapCard = h("div", { class: "card" }, loading());
  const listCard = h("div", { class: "card" }, loading());
  const detail = h("div", { style: { marginTop: "16px" } });
  clear(body,
    h("div", { class: "row", style: { marginBottom: "14px" } },
      h("label", { class: "field" }, h("span", {}, "View"),
        select(src.views.map((v) => [v.id, v.label] as [string, string]), cl.view, (v) => { cl.view = v; cl.selected = ""; drawClusters(body); }, { "aria-label": "View" }))),
    h("div", { class: "grid", style: { gridTemplateColumns: "minmax(0, 1.6fr) minmax(340px, 1fr)", alignItems: "stretch" } }, mapCard, listCard),
    detail);

  // The list and details come first; the map only says how big it is until someone asks to draw it.
  let clusters: any[], info: MapInfo | null;
  try {
    [clusters, info] = await Promise.all([
      api(`/api/clusters${qs({ source: cl.source, view: cl.view })}`).then((r) => r.clusters),
      mapInfoOrNone(cl.source, cl.view),
    ]);
  } catch (e) {
    return clear(listCard, errorBox(e));
  }
  if (draw !== drawing) return;

  const { groups, pointCounts } = buildGroups(clusters, info);
  if (!visibility.has(key)) visibility.set(key, new Set(groups.keys()));
  const visible = visibility.get(key)!;
  const byNumber = new Map<number, any>(clusters.map((c) => [c.number, c]));
  const selectedNumber = () => (cl.selected ? Number(cl.selected.split("#")[1]) : null);

  let map: ClusterMap | null = null;
  const clearButton = h("span");
  const pointBox = h("div");
  const unpick = () => { cl.selected = ""; map?.setSelected(null); clear(clearButton); drawRows(); clear(detail); };
  // Picking a group (list row, or "Highlight its group" on a point) greys out the rest of the map and
  // shows the group in yellow, where it is; the map does not move.
  const pick = (n: number) => {
    cl.selected = `${cl.view}#${n}`;
    map?.setSelected(n);
    clear(clearButton, h("button", { class: "btn small", onclick: unpick }, "Clear"));
    drawRows();
    const c = byNumber.get(n);
    const zoomTo = () => map?.zoomToGroup(n);
    if (c) drawDetail(detail, c, () => drawClusters(body), zoomTo);
    else drawMapOnly(detail, groups.get(n)!, pointCounts.get(n) ?? 0, zoomTo);
  };
  const applyVisibility = () => { map?.setVisible(new Set(visible)); drawRows(); };

  // Map, drawn on request
  if (info) {
    if (selectedNumber() !== null) clear(clearButton, h("button", { class: "btn small", onclick: unpick }, "Clear"));
    const nameOf = (n: number) => groups.get(n)?.name ?? `Group #${n}`;
    clear(mapCard,
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("map")), h("h2", {}, "Map of similar activity"),
        h("span", { class: "end legend" },
          h("span", {}, h("i", { style: { background: "var(--muted)" } }), "observation"),
          h("span", {}, h("i", { style: { background: "var(--red)" } }), "flagged"),
          h("span", {}, h("i", { style: { background: "var(--map-pick)", boxShadow: "inset 0 0 0 1px var(--map-pick-edge)" } }), "selected group"),
          clearButton)),
      mapOnDemand(key, info, async () => {
        const layout = layoutFor(info);
        const points = await loadMap(cl.source, cl.view, layout);
        const closePoint = () => { clear(pointBox); map?.clearPoint(); };
        map = clusterMap(points, groups, {
          visible: new Set(visible), selected: selectedNumber(), aside: pointBox, onClear: unpick,
          layout, info, loadLayout: (l) => loadMap(cl.source, cl.view, l),
          title: `Map of similar activity · ${state.catalog.sources[cl.source].label} · ${src.views.find((v) => v.id === cl.view)?.label ?? cl.view}`,
          onPoint: (i) => {
            clear(pointBox, loading("Opening the point…"));
            pointDetails(cl.source, cl.view, points.id![i], nameOf, pick, closePoint)
              .then((el) => clear(pointBox, el)).catch((e) => clear(pointBox, errorBox(e)));
          },
        });
        return h("div", {}, map.el, h("p", { class: "tiny muted", style: { margin: "8px 0 0" } },
          "Click a point to open it. Click a group in the list to highlight it in yellow. Fullscreen: the corner button or F."));
      }));
  } else {
    clear(mapCard, note("No map for this view."));
  }

  // List with the group filter
  const search = h("input", { type: "text", placeholder: "Find a group…", "aria-label": "Find a group", style: { width: "100%" } }) as HTMLInputElement;
  const kindBar = h("div", { class: "row", style: { gap: "6px", margin: "10px 0" } });
  const rowsBox = h("div");
  const counter = h("span", { class: "end small muted" });
  const all = [...groups.values()].sort((a, b) => (b.rows - a.rows) || (a.number - b.number));
  const setKind = (kind: MapGroup["kind"], on: boolean) => {
    for (const g of all) if (g.kind === kind) (on ? visible.add(g.number) : visible.delete(g.number));
    applyVisibility();
  };
  const drawKinds = () => clear(kindBar,
    KINDS.filter(([kind]) => all.some((g) => g.kind === kind)).map(([kind, label]) => {
      const members = all.filter((g) => g.kind === kind);
      const on = members.filter((g) => visible.has(g.number)).length;
      const state_ = on === members.length ? "on" : on === 0 ? "off" : "some";
      return h("button", { class: `chip-toggle ${state_}`, "aria-pressed": String(state_ === "on"),
        title: `${on} of ${members.length} shown. Click to ${state_ === "on" ? "hide" : "show"} them all.`,
        onclick: () => setKind(kind, state_ !== "on") }, state_ === "on" ? icon("check", 12) : null, `${label} · ${members.length}`);
    }),
    h("button", { class: "btn small", onclick: () => { all.forEach((g) => visible.add(g.number)); applyVisibility(); } }, "Show all"),
    h("button", { class: "btn small", onclick: () => { visible.clear(); applyVisibility(); } }, "Hide all"));
  const drawRows = () => {
    drawKinds();
    clear(counter, `${all.filter((g) => visible.has(g.number)).length} of ${all.length} shown`);
    const q = search.value.toLowerCase();
    const shown = all.filter((g) => !q || `${g.name} ${Object.values(byNumber.get(g.number)?.top ?? {}).join(" ")} #${g.number}`.toLowerCase().includes(q));
    clear(rowsBox, h("div", { class: "table-wrap", style: { maxHeight: "430px" } }, h("table", {},
      h("thead", {}, h("tr", {}, [h("th", { title: "Show on the map" }, "Map"), ...["Group", "Size", "Flagged", ""].map((c) => h("th", {}, c))])),
      h("tbody", {}, shown.map((g) => {
        const c = byNumber.get(g.number);
        const box = h("input", { type: "checkbox", checked: visible.has(g.number), "aria-label": `Show ${g.name} on the map` }) as HTMLInputElement;
        box.addEventListener("click", (e) => e.stopPropagation());
        box.addEventListener("change", () => { box.checked ? visible.add(g.number) : visible.delete(g.number); applyVisibility(); });
        return h("tr", {
          class: `clickable ${selectedNumber() === g.number ? "selected" : ""} ${visible.has(g.number) ? "" : "hidden-group"}`, tabindex: "0",
          onclick: () => pick(g.number),
          onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter") pick(g.number); },
        },
          h("td", {}, box),
          h("td", {}, h("strong", { style: { overflowWrap: "anywhere" } }, g.name),
            h("div", { class: "tiny muted" }, g.kind === "unnamed" ? `map only · ${fmt.int(pointCounts.get(g.number) ?? 0)} points`
              : g.kind === "isolated" ? "points on no island" : c?.pure === false ? `${c.type_count} kinds of line` : c?.pure ? "one kind of line" : `#${g.number}`)),
          h("td", { class: "num" }, g.rows ? fmt.int(g.rows) : "—"),
          h("td", { class: "num" }, g.flagged ? h("span", { style: { color: "var(--red-strong)", fontWeight: "600" } }, fmt.int(g.flagged)) : "0"),
          h("td", {}, c?.verdict ? verdictBadge(c.verdict) : c?.comments ? badge(`${c.comments} 💬`, "muted") : ""));
      })))));
  };
  search.addEventListener("input", drawRows);
  clear(listCard, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, viewIcon(cl.view)), h("h2", {}, `${all.length} groups`), counter),
    search, kindBar, rowsBox);
  drawRows();
  if (selectedNumber() !== null) pick(selectedNumber()!);
}

function drawMapOnly(el: HTMLElement, g: MapGroup, points: number, onZoom: () => void): void {
  clear(el, h("div", { class: "card accent" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("map")), h("h2", {}, g.name),
      h("span", { class: "end" }, h("button", { class: "btn small", onclick: onZoom, title: "Once the map is drawn" }, icon("analyze", 14), "Zoom the map to it"))),
    h("p", { style: { margin: 0 } }, `${fmt.int(points)} points on the map. This island formed from the training and validation periods only: `
      + "it has no observations in the test period, so there are no messages, alerts or reviews for it.")));
}

async function drawDetail(el: HTMLElement, c: any, refresh: () => void, onZoom?: () => void): Promise<void> {
  const name = h("input", { type: "text", value: c.name, "aria-label": "Group name", style: { flex: "1", fontWeight: "600", fontSize: "1.1rem" } }) as HTMLInputElement;
  const save = h("button", { class: "btn small" }, "Rename") as HTMLButtonElement;
  save.addEventListener("click", async () => {
    await api("/api/clusters/name", { method: "PUT", body: { source: cl.source, view: cl.view, cluster_id: c.cluster_id, name: name.value } });
    refresh();
  });
  const examples = h("div", {}, loading());
  const members = h("div");
  const comments = h("div", {}, loading());
  const mix = c.event_types ?? [];
  clear(el,
    h("div", { class: `card ${c.flagged_rows ? "alarm" : "accent"}` },
      h("div", { class: "row" }, h("span", { class: "chip-icon" }, viewIcon(cl.view)), name, save,
        onZoom ? h("button", { class: "btn small", onclick: onZoom, title: "Once the map is drawn" }, icon("analyze", 14), "Zoom the map to it") : null),
      h("div", { class: "row", style: { gap: "28px", margin: "14px 0 6px", alignItems: "flex-end" } },
        h("div", {}, h("div", { class: "big" }, fmt.int(c.rows)), h("div", { class: "tiny muted" }, "observations")),
        h("div", {}, h("div", { class: "big" }, fmt.int(c.flagged_rows)), h("div", { class: "tiny muted" }, "flagged")),
        h("div", { class: "small" }, `${c.first_seen} → ${c.last_seen}`),
        c.pure === true ? badge("one kind of line", "ok") : c.pure === false ? badge(`${c.type_count} kinds of line`, "warn") : null),
      mix.length ? [
        h("div", { class: "composition", role: "img", "aria-label": "Kinds of line in this group" },
          mix.map((m: any, i: number) => h("span", { style: { width: `${m.share * 100}%`, background: TYPE_COLORS[i % TYPE_COLORS.length] }, title: `${m.event_type} · ${(m.share * 100).toFixed(1)}%` }))),
        h("div", { class: "legend" }, mix.map((m: any, i: number) => h("span", {}, h("i", { style: { background: TYPE_COLORS[i % TYPE_COLORS.length] } }),
          `${m.event_type} ${(m.share * 100).toFixed(m.share < 0.01 ? 2 : 0)}%`)))] : null,
      h("dl", { class: "kv", style: { marginTop: "12px" } }, Object.entries(c.top).map(([k, v]) => [h("dt", {}, k.replace(/_/g, " ")), h("dd", { class: "small" }, String(v))]))),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("individual")), h("h2", {}, "Typical lines")), examples),
    h("div", { class: "card" }, members),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("session")), h("h2", {}, "Comments")), comments),
      h("div", { class: "card accent" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("docs")), h("h2", {}, "AI summary"), h("span", { class: "end" }, badge("TODO", "warn"))),
        h("div", { class: "concept" },
          h("div", { class: "small" }, `${state.settings.llm_model} will sum up the comments: what people agree on, where they differ, what is still open.`),
          h("div", { class: "ghost", style: { width: "92%" } }), h("div", { class: "ghost", style: { width: "74%" } }), h("div", { class: "ghost", style: { width: "58%" } }),
          h("button", { class: "btn small", disabled: true }, "Summarise")))));

  api(`/api/clusters/messages${qs({ source: cl.source, view: cl.view, cluster: c.cluster_id })}`).then((m) => clear(examples,
    m.examples.length ? m.examples.map((ex: string[]) => linesBlock(ex, 30)) : h("p", { class: "muted small" }, "No examples recorded.")))
    .catch((e) => clear(examples, errorBox(e)));
  drawMembers(members, c);
  drawComments(comments, c);
}

async function drawMembers(el: HTMLElement, c: any): Promise<void> {
  const state_ = { offset: 0, flagged: false, items: [] as any[] };
  const list = h("div");
  const more = h("button", { class: "btn small" }, "Show more") as HTMLButtonElement;
  const summary = h("summary", {}, h("strong", {}, "Member observations"), h("span", { class: "muted small" }, `  ${fmt.int(c.rows)}`));
  const box = h("details", {}, summary);
  const load = async (reset: boolean) => {
    if (reset) { state_.offset = 0; state_.items = []; clear(list, loading()); }
    try {
      const r = await api(`/api/clusters/members${qs({ source: cl.source, view: cl.view, cluster: c.cluster_id, offset: String(state_.offset), limit: "25", flagged: state_.flagged ? "1" : "" })}`);
      if (r.status !== "ready") {
        clear(list, note(`Preparing the member list (${r.status}). It is built once in the background.`),
          h("button", { class: "btn small", onclick: () => load(true) }, icon("refresh", 14), "Try again"));
        more.hidden = true;
        return;
      }
      state_.items.push(...r.items);
      state_.offset += r.items.length;
      clear(summary, h("strong", {}, "Member observations"), h("span", { class: "muted small" }, `  ${fmt.int(r.total)}${r.flagged ? ` · ${fmt.int(r.flagged)} flagged` : ""}`));
      clear(list, state_.items.map((o) => h("div", { class: "member" },
        h("div", { class: "row small" }, o.flagged ? badge("flagged", "bad") : null, h("span", { class: "mono" }, o.time.slice(0, 19)),
          h("span", { class: "muted" }, `${fmt.int(o.line_count)} line${o.line_count === 1 ? "" : "s"}`)),
        linesBlock(o.lines, 12), o.line_count > o.lines.length ? h("div", { class: "tiny muted" }, `+${fmt.int(o.line_count - o.lines.length)} more lines`) : null)));
      more.hidden = state_.offset >= r.total;
    } catch (e) {
      clear(list, errorBox(e));
    }
  };
  more.addEventListener("click", () => load(false));
  const flaggedOnly = h("input", { type: "checkbox" }) as HTMLInputElement;
  flaggedOnly.addEventListener("change", () => { state_.flagged = flaggedOnly.checked; load(true); });
  box.addEventListener("toggle", () => { if (box.open && !state_.items.length) load(true); });
  box.append(h("div", { class: "row small", style: { margin: "10px 0" } }, h("label", { class: "row" }, flaggedOnly, "Flagged only")), list, h("div", { class: "row end" }, more));
  clear(el, box);
}

export function linesBlock(lines: string[], max = 60): HTMLElement {
  return h("div", { class: "lines" }, lines.slice(0, max).map((l, i) => h("div", {}, h("span", { class: "n" }, String(i + 1)), l)),
    lines.length > max ? h("div", { class: "muted" }, `… ${lines.length - max} more`) : null);
}

async function drawComments(el: HTMLElement, c: any): Promise<void> {
  const { comments } = await api(`/api/clusters/comments${qs({ source: cl.source, view: cl.view, cluster: c.cluster_id })}`);
  const author = h("input", { type: "text", value: state.settings.display_name, "aria-label": "Your name", style: { width: "140px" } }) as HTMLInputElement;
  const text = h("textarea", { rows: 2, placeholder: "What do you know about this activity?", "aria-label": "Comment", style: { fontFamily: "var(--font-body)" } }) as HTMLTextAreaElement;
  const post = h("button", { class: "btn primary small" }, "Post") as HTMLButtonElement;
  const err = h("div");
  post.addEventListener("click", async () => {
    try {
      await api("/api/clusters/comments", { body: { source: cl.source, view: cl.view, cluster_id: c.cluster_id, author: author.value, body: text.value } });
      drawComments(el, c);
    } catch (e) {
      clear(err, errorBox(e));
    }
  });
  clear(el,
    comments.length ? comments.map((m: any) => h("div", { class: "comment" },
      h("span", { class: "who" }, m.author), h("span", { class: "when" }, m.created_at.replace("T", " ").slice(0, 16)), h("p", {}, m.body)))
      : h("p", { class: "small muted" }, "No comments yet."),
    text, err, h("div", { class: "row end", style: { marginTop: "6px" } }, h("span", { class: "small muted" }, "as"), author, post));
}
