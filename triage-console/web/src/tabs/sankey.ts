// Two Sankey charts on the Data tab:
//   Messages by type:    log type -> category -> event type   (lines and variants per type)
//   Traffic by address:  origin -> log type -> destination, addresses grouped by 1 to 4 parts
//                        (a.x.x.x, a.b.x.x, a.b.c.x, a.b.c.d)
// Click a box or band to follow it (the rest dims); click empty space to reset. The traffic chart
// follows whole routes (from → log → to, sent as `paths`): a chosen address lights up only its own share
// of each band after the log, and the boxes on the right count only its lines. On the traffic chart
// the lines behind the chosen box or band can be opened in Data → SQL or downloaded as CSV: the query is
// written by the service (ip_flows.selection_query) and runs through the SQL console's guardrails.

import { sankey as d3sankey, sankeyLinkHorizontal } from "d3-sankey";
import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, loading, pills, select, svg, table } from "../dom";
import { icon } from "../icons";
import { sqlApi } from "../sql-lock";
import { csvText } from "../tables";
import { sqlLoader } from "../loaders";
import { shownSources } from "../log-type";
import { state } from "../state";
import { tip } from "../tooltip";

export const COLORS: Record<string, string> = { auth: "#333333", ossec: "#999933", pf: "#ff3333", ipf: "#b3a07a" };
const LABEL_MIN_PX = 9;
const filters = { from: "", to: "" };            // log types come from the page's Log type dropdown
const typesView = { share: true, height: 2 };
const flowView = { share: false, height: 1.5, top: 25, level: 3 };
const LEVELS: [string, string][] = [["1", "a.x.x.x"], ["2", "a.b.x.x"], ["3", "a.b.c.x"], ["4", "a.b.c.d"]];
interface Selection { a?: string; source?: string; b?: string }


export async function drawSankeys(body: HTMLElement): Promise<void> {
  const types = h("div");
  const flows = h("div");
  clear(body, filterBar(() => drawSankeys(body)), types, flows);
  await Promise.all([drawTypes(types), drawFlows(flows)]);
}

function filterBar(redraw: () => void): HTMLElement {
  const months: [string, string][] = Array.from({ length: 12 }, (_, i) => {
    const d = new Date(2025, 7 + i, 1);
    const m = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
    return [m, m];
  });
  return h("div", { class: "row", style: { margin: "0 4px 14px" } },
    h("span", { class: "small muted" }, "Months"),
    select([["", "From start"], ...months], filters.from, (v) => { filters.from = v; redraw(); }, { "aria-label": "From month" }),
    select([["", "To end"], ...months], filters.to, (v) => { filters.to = v; redraw(); }, { "aria-label": "To month" }));
}

function controls(view: { share: boolean; height: number }, rerender: () => void): HTMLElement[] {
  const share = h("input", { type: "checkbox", checked: view.share }) as HTMLInputElement;
  share.addEventListener("change", () => { view.share = share.checked; rerender(); });
  const height = h("input", { type: "range", min: "1", max: "8", step: "0.5", value: String(view.height), "aria-label": "Chart height", style: { width: "110px" } }) as HTMLInputElement;
  height.addEventListener("change", () => { view.height = Number(height.value); rerender(); });
  return [h("label", { class: "row small", title: "authlog is ~200× larger; equal widths keep the small logs visible" }, share, "Equal width"),
    h("label", { class: "row small" }, "Height", height)];
}

// --- messages by type ------------------------------------------------------------------

async function drawTypes(el: HTMLElement): Promise<void> {
  clear(el, h("div", { class: "card" }, loading()));
  let data: any;
  try {
    data = await api(`/api/data/sankey${qs({ sources: shownSources().join(","), from: filters.from, to: filters.to })}`);
  } catch (e) {
    return clear(el, errorBox(e));
  }
  const chart = h("div", { class: "sankey" });
  const count = (n: any) => n.count ?? 0;
  const render = () => drawChart(chart, data, typesView, (n) => n.level < 2 ? [n.label]
    : [n.label, fmt.int(count(n)), n.variants === undefined || n.variants === null ? "…" : fmt.int(n.variants)],
    (n) => `${n.label} · ${fmt.int(count(n))} lines${n.level === 2 ? ` · ${n.variants ?? "…"} distinct messages` : ""}`);
  const types = data.nodes.filter((n: any) => n.level === 2);
  for (const n of data.nodes) n.count = 0;
  for (const l of data.links) { data.nodes[l.target].count += l.value; if (data.nodes[l.source].level === 0) data.nodes[l.source].count += l.value; }
  const pending = data.variants_status !== "ready";
  clear(el, h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("flow")), h("h2", {}, "Messages by type"),
      h("span", { class: "end row" }, ...controls(typesView, render))),
    h("div", { class: "legend", style: { marginBottom: "8px" } },
      h("span", {}, "After each type: ", h("strong", {}, "lines"), " · ", h("strong", {}, "distinct messages"),
        " (once addresses, numbers and IDs are blanked)"),
      pending ? h("span", {}, `Counting distinct messages… ${data.variants_progress ?? ""}`) : null),
    chart,
    h("details", { style: { marginTop: "12px" } },
      h("summary", {}, h("strong", {}, "All types as a table"), h("span", { class: "muted small" }, `  ${types.length}`)),
      table(["Log type", "Type", "Lines", "Distinct messages"],
        types.sort((a: any, b: any) => count(b) - count(a)).map((n: any) => [n.source, h("code", {}, n.label), fmt.int(count(n)),
          n.variants === undefined || n.variants === null ? "…" : fmt.int(n.variants)])))));
  render();
  if (pending) setTimeout(() => { if (el.isConnected) drawTypes(el); }, 20000);
}

// --- traffic by address ---------------------------------------------------------------

async function drawFlows(el: HTMLElement): Promise<void> {
  clear(el, h("div", { class: "card" }, loading()));
  let data: any;
  try {
    data = await api(`/api/data/ipflow${qs(flowParams())}`);
  } catch (e) {
    return clear(el, errorBox(e));
  }
  const chart = h("div", { class: "sankey" });
  for (const n of data.nodes) n.count = 0;
  for (const l of data.links) { if (data.nodes[l.source].level === 0) data.nodes[l.source].count += l.value; if (data.nodes[l.target].level === 2) data.nodes[l.target].count += l.value; }
  for (const l of data.links) if (data.nodes[l.source].level === 0) data.nodes[l.target].count += l.value;
  const picked = h("div", { class: "sk-pick" });
  const render = () => {
    clear(picked);
    drawChart(chart, data, flowView, (n) => [n.label, fmt.int(n.count)], (n) => `${n.label} · ${fmt.int(n.count)} lines`, true,
      (sel) => selectionBar(picked, sel));
  };
  const top = select([["10", "Top 10"], ["25", "Top 25"], ["50", "Top 50"]], String(flowView.top),
    (v) => { flowView.top = Number(v); drawFlows(el); }, { "aria-label": "How many addresses" });
  const level = pills(LEVELS, String(flowView.level), (v) => { flowView.level = Number(v); drawFlows(el); }, true);
  level.setAttribute("aria-label", "Group addresses");
  const ready = data.status === "ready";
  clear(el, h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("session")), h("h2", {}, "Traffic by address"),
      h("span", { class: "end row" }, level, top, ...controls(flowView, render))),
    h("div", { class: "legend", style: { marginBottom: "8px" } },
      h("span", {}, "From → log → to"),
      ready ? null : h("span", {}, `Counting… ${data.progress ?? ""}`)),
    data.links.length ? [chart, picked] : h("p", { class: "muted small" }, ready ? "No addressed lines for this selection." : "Counting addresses (first start only)…")));
  if (data.links.length) render();
  if (!ready) setTimeout(() => { if (el.isConnected) drawFlows(el); }, 20000);
}

const flowParams = (extra: Record<string, string> = {}) => ({ sources: shownSources().join(","), from: filters.from, to: filters.to,
  top: String(flowView.top), level: String(flowView.level), ...extra });

/** Under the traffic chart: what is chosen, and its lines in Data → SQL or as a CSV file. */
function selectionBar(box: HTMLElement, sel: Selection | null): void {
  if (!sel) return clear(box);
  const query = async () => (await api(`/api/data/ipflow/query${qs(flowParams({ a: sel.a ?? "", source: sel.source ?? "", b: sel.b ?? "" }))}`)).query as string;
  const result = h("div");
  const parts = [sel.a, sel.source, sel.b].filter((x): x is string => Boolean(x));
  const name = parts.join(" → ");
  const openSql = async () => {
    try { state.pendingSql = await query(); location.hash = "#/data/sql"; } catch (e) { clear(result, errorBox(e)); }
  };
  const dl = h("button", { class: "btn small primary" }, icon("upload", 14), "Download CSV") as HTMLButtonElement;
  dl.addEventListener("click", async () => {
    dl.disabled = true;
    const loader = sqlLoader(name);
    clear(result, loader.el);
    try {
      const r = await sqlApi("/api/sql/export", { query: await query() });
      await loader.arrive();
      const csv = csvText(r.columns, r.rows);
      const months = filters.from || filters.to ? `_${filters.from || "start"}_${filters.to || "end"}` : "";
      const file = `traffic_${parts.join("_").replace(/[^\w.-]+/g, "-")}${months}.csv`;
      h("a", { href: URL.createObjectURL(new Blob([csv], { type: "text/csv" })), download: file }).click();
      clear(result, h("div", { class: "row small", style: { gap: "8px", marginTop: "8px" } }, icon("check", 14), file,
        badge(`${fmt.int(r.rows.length)} lines`, "muted"), r.truncated ? badge(`first ${fmt.int(r.rows.length)}`, "warn") : null));
    } catch (e) {
      await loader.fail();
      clear(result, errorBox(e));
    } finally {
      dl.disabled = false;
    }
  });
  clear(box, h("div", { class: "row sk-pick-bar" },
    h("span", { class: "row", style: { gap: "6px" } }, parts.map((x, i) => [h("span", { class: "who-chip" }, x), i < parts.length - 1 ? "→" : null])),
    h("span", { class: "row", style: { gap: "6px" } }, h("button", { class: "btn small", onclick: openSql }, icon("data", 14), "Open in SQL"), dl)),
    result);
}

// --- shared drawing -------------------------------------------------------------------

function drawChart(el: HTMLElement, data: any, view: { share: boolean; height: number },
                   labelParts: (n: any) => string[], tipText: (n: any) => string, mixedEnds = false,
                   onSelect?: (sel: Selection | null) => void): void {
  if (!data.links.length) return clear(el, h("p", { class: "muted" }, "Nothing for this selection."));
  const kindOf = (l: any) => l.kind ?? data.nodes[l.source].source;
  const links = data.links.map((l: any) => ({ source: l.source, target: l.target, count: l.value, kind: kindOf(l),
    value: view.share ? l.value / (data.totals[kindOf(l)] || 1) : l.value }));
  const rightmost = data.nodes.filter((n: any) => n.level === 2).length;
  const width = Math.max(900, el.clientWidth || 900);
  const height = Math.round(Math.max(380, rightmost * 13) * view.height);
  const graph = d3sankey<any, any>().nodeWidth(14).nodePadding(4 * view.height).extent([[150, 6], [width - 330, height - 6]])
    ({ nodes: data.nodes.map((n: any) => ({ ...n })), links });
  const nodeColor = (n: any) => (mixedEnds && n.level !== 1 ? "#8a8a80" : COLORS[n.source] ?? "#888");

  const linkEls = graph.links.map((l: any) => svg("path", {
    class: "link", d: sankeyLinkHorizontal()(l) ?? "", stroke: COLORS[l.kind] ?? "#888", "stroke-width": Math.max(1, l.width ?? 1),
  }));
  const textFor = (n: any, force: boolean) => {
    const tall = (n.y1 ?? 0) - (n.y0 ?? 0) >= LABEL_MIN_PX;
    if (!tall && !force && n.level !== 1) return [];
    const [first, ...rest] = labelParts(n);
    return [svg("tspan", {}, first), ...rest.map((part) => svg("tspan", { class: "n", dx: 7 }, part))];
  };
  const labels: SVGTextElement[] = [];
  const nodeEls = graph.nodes.map((n: any) => {
    const left = n.level === 0 && (n.x0 ?? 0) > 100;
    const label = svg("text", { class: "node-label", x: left ? (n.x0 ?? 0) - 6 : (n.x1 ?? 0) + 6, y: ((n.y0 ?? 0) + (n.y1 ?? 0)) / 2,
      dy: "0.35em", "text-anchor": left ? "end" : "start" }, textFor(n, false));
    labels.push(label);
    return svg("g", { class: "node" },
      svg("rect", { x: n.x0, y: n.y0, rx: 3, width: (n.x1 ?? 0) - (n.x0 ?? 0), height: Math.max(1, (n.y1 ?? 0) - (n.y0 ?? 0)), fill: nodeColor(n) }),
      label);
  });
  // Routes through the choice (traffic chart): each band lit only for its share, each box counting only its lines.
  const shares = svg("g", { class: "shares" });
  const trace = (match: (p: number[]) => boolean) => {
    const byNode = new Map<number, number>(), byLink = new Map<string, number>();
    for (const p of data.paths as number[][]) {
      if (!match(p)) continue;
      const n = p[3];
      for (const i of p.slice(0, 3)) byNode.set(i, (byNode.get(i) ?? 0) + n);
      for (const key of [`${p[0]}>${p[1]}`, `${p[1]}>${p[2]}`]) byLink.set(key, (byLink.get(key) ?? 0) + n);
    }
    graph.nodes.forEach((n: any, i: number) => {
      const v = byNode.get(n.index);
      nodeEls[i].classList.toggle("dim", v === undefined);
      clear(labels[i], v === undefined ? textFor(n, false) : textFor({ ...n, count: v }, true));
    });
    clear(shares);
    graph.links.forEach((l: any, i: number) => {
      const v = byLink.get(`${l.source.index}>${l.target.index}`) ?? 0;
      const whole = v >= l.count;
      linkEls[i].classList.toggle("dim", !whole);
      if (!v || whole) return;
      const w = Math.max(1, (l.width ?? 1) * (v / l.count)), lift = ((l.width ?? 1) - w) / 2;     // its share, along the band's top edge
      shares.append(svg("path", { class: "link share", d: sankeyLinkHorizontal()({ ...l, y0: l.y0 - lift, y1: l.y1 - lift }) ?? "",
        stroke: COLORS[l.kind] ?? "#888", "stroke-width": w }));
    });
  };
  const pick = (nodes: Set<any>, chosen: Set<any>) => {
    clear(shares);
    const any = nodes.size > 0;
    graph.nodes.forEach((n: any, i: number) => {
      nodeEls[i].classList.toggle("dim", any && !nodes.has(n));
      clear(labels[i], textFor(n, any && nodes.has(n)));
    });
    graph.links.forEach((l: any, i: number) => linkEls[i].classList.toggle("dim", any && !chosen.has(l)));
  };
  const follow = (start: any) => {
    if (data.paths) return trace((p) => p[start.level] === start.index);
    const nodes = new Set<any>([start]), chosen = new Set<any>();
    const walk = (n: any, dir: "sourceLinks" | "targetLinks") => {
      for (const l of n[dir] ?? []) {
        chosen.add(l);
        const next = dir === "sourceLinks" ? l.target : l.source;
        if (!nodes.has(next)) { nodes.add(next); walk(next, dir); }
      }
    };
    walk(start, "sourceLinks");
    walk(start, "targetLinks");
    pick(nodes, chosen);
  };
  const end = (n: any): Selection => (n.level === 0 ? { a: n.label } : n.level === 1 ? { source: n.label } : { b: n.label });
  graph.nodes.forEach((n: any, i: number) => {
    nodeEls[i].addEventListener("click", (e) => { e.stopPropagation(); follow(n); onSelect?.(end(n)); });
    nodeEls[i].addEventListener("mousemove", (e) => tip(tipText(n), e));
    nodeEls[i].addEventListener("mouseleave", () => tip(null));
  });
  graph.links.forEach((l: any, i: number) => {
    linkEls[i].addEventListener("click", (e) => {
      e.stopPropagation();
      const at = l.source.level;
      if (data.paths) trace((p) => p[at] === l.source.index && p[at + 1] === l.target.index);
      else pick(new Set([l.source, l.target]), new Set([l]));
      onSelect?.({ ...end(l.source), ...end(l.target) });
    });
    linkEls[i].addEventListener("mousemove", (e) => tip(`${l.source.label} → ${l.target.label} · ${fmt.int(l.count)} lines`, e));
    linkEls[i].addEventListener("mouseleave", () => tip(null));
  });
  const root = svg("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Sankey chart; click to follow a path" },
    svg("rect", { x: 0, y: 0, width, height, fill: "transparent" }), svg("g", {}, linkEls), shares, svg("g", {}, nodeEls));
  root.addEventListener("click", () => { pick(new Set(), new Set()); onSelect?.(null); });
  root.addEventListener("mouseleave", () => tip(null));
  clear(el, root);
}
