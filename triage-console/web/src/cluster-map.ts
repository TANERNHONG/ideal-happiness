// Interactive map of activity groups (the Phase 4c t-SNE map).
//
// Layouts: the same points can be laid out by t-SNE (the map Phase 7b found the groups on) or by
// UMAP (Phase 4c's map_layouts.py). Only the positions change: groups, flags and points stay, so the
// two pictures can be compared point for point. The choice is remembered in this browser.
//
// The map is drawn only when asked (mapOnDemand): the page loads first, and a
// card says how many points the map holds before anyone waits for it.
//
// Wheel / trackpad to zoom, pinch on touch screens, drag to pan, double-click to
// zoom in; buttons and the keyboard (+ / - / arrows / 0) do the same. Axes show
// t-SNE units and rescale with the zoom.
// Points: grey, flagged in red. Picking a group (from a list) turns it yellow and
// everything else grey; hovering a group with nothing picked shows it in ink.
// Clicking a point opens that point (onPoint), not its group.
// Points placed from new logs (the Analyze page) are laid on top as rings.
// Fullscreen (button or the F key) fills the screen with the map, a header with
// its legend, and the point's details as a panel; the view keeps its centre.

import { axisBottom, axisLeft } from "d3-axis";
import { quadtree, type Quadtree } from "d3-quadtree";
import { scaleLinear } from "d3-scale";
import { select } from "d3-selection";
import { zoom as d3zoom, zoomIdentity, type ZoomTransform } from "d3-zoom";
import { api, qs } from "./api";
import { clear, fmt, h, loading, svg } from "./dom";
import { icon } from "./icons";
import { tip } from "./tooltip";

export interface MapPoints { id?: string[]; x: number[]; y: number[]; cluster: number[]; flagged: number[] }
export interface MapInfo { points: number; shown: number; flagged: number; groups: Record<string, number>;
  layouts?: Record<string, string>; layout_command?: string }
export type Layout = "tsne" | "umap";
export interface MapGroup { number: number; name: string; kind: "named" | "auto" | "unnamed" | "isolated"; rows: number; flagged: number }
// A point placed from new logs: drawn as a ring (filled red when flagged), on top of everything.
export interface InputPoint { x: number; y: number; flagged: boolean; group: number | null; label: string;
  at?: Partial<Record<Layout, { x: number; y: number }>> }   // its position on the other layouts
export interface ClusterMap {
  el: HTMLElement;
  setVisible(visible: Set<number>): void;
  setSelected(group: number | null): void;
  zoomToGroup(group: number): void;
  zoomToInputs(): void;                   // frame the new logs (no-op without them)
  clearPoint(): void;
}

const MARGIN = { top: 12, right: 14, bottom: 34, left: 46 };
const KIND_TEXT: Record<MapGroup["kind"], string> = { named: "named by a person", auto: "automatic name", unnamed: "map only, no test observations", isolated: "points on no island" };
const VECTOR_LIMIT = 8_000;          // up to this many points in view, each is drawn as a true circle

const LAYOUT_NAMES: Record<Layout, string> = { tsne: "t-SNE", umap: "UMAP" };
const LAYOUT_NOTES: Record<Layout, string> = {
  tsne: "Axes are in t-SNE units: nearby points behave alike, but distances between far-apart groups and the axis values themselves carry no meaning.",
  umap: "UMAP layout of the same points: it keeps more of the overall shape than t-SNE, but distances are still only a rough guide. The groups were found on the t-SNE map, so a group can look split or merged here.",
};
let preferred: Layout = (() => {
  try { return localStorage.getItem("map-layout") === "umap" ? "umap" : "tsne"; } catch { return "tsne"; }
})();
// The layout to open a map in: the last one chosen, if this view has it.
export function layoutFor(info: MapInfo | null): Layout {
  return info?.layouts?.[preferred] === "ready" ? preferred : "tsne";
}

// Every point of a view's map (up to 60,000), fetched once per view and layout while the app is open.
const mapCache = new Map<string, Promise<MapPoints>>();
export function loadMap(source: string, view: string, layout: Layout = "tsne"): Promise<MapPoints> {
  const key = `${source}/${view}/${layout}`;
  if (!mapCache.has(key)) {
    const request = api<MapPoints>(`/api/map${qs({ source, view, limit: "60000", layout })}`);
    request.catch(() => mapCache.delete(key));
    mapCache.set(key, request);
  }
  return mapCache.get(key)!;
}

// How big a view's map is (cheap: no points are sent).
export function loadMapInfo(source: string, view: string): Promise<MapInfo> {
  return api<MapInfo>(`/api/map/info${qs({ source, view })}`);
}

/** The map's size, or null when the service says this view has no map. A request that did not reach the service
 * (fetch throws a TypeError, e.g. while it restarts) is an error to retry, not "no map". */
export function mapInfoOrNone(source: string, view: string): Promise<MapInfo | null> {
  return loadMapInfo(source, view).catch((e) => { if (e instanceof TypeError) throw e; return null; });
}

/** An error with a button to try again (a failed fetch is not remembered, so trying again asks the service afresh). */
export function retryBox(error: unknown, retry: () => void): HTMLElement {
  return h("div", { class: "error row", role: "alert", style: { justifyContent: "space-between", gap: "10px" } },
    h("span", {}, error instanceof Error ? error.message : String(error)),
    h("button", { class: "btn small", onclick: retry }, icon("refresh", 14), "Try again"));
}

// Every group on the map: listed clusters (with their names) and islands that exist only on the map
// (no test-period observations, so no summary). Group 0 holds the points on no island.
export function buildGroups(clusters: any[], info: MapInfo | null): { groups: Map<number, MapGroup>; pointCounts: Map<number, number> } {
  const groups = new Map<number, MapGroup>();
  for (const c of clusters) {
    const isolated = c.number === 0;
    groups.set(c.number, { number: c.number, name: isolated && !c.renamed ? "Isolated points" : c.name,
      kind: isolated ? "isolated" : c.renamed ? "named" : "auto", rows: c.rows ?? 0, flagged: c.flagged_rows ?? 0 });
  }
  const pointCounts = new Map<number, number>(Object.entries(info?.groups ?? {}).map(([n, count]) => [Number(n), count]));
  for (const n of pointCounts.keys()) {
    if (!groups.has(n)) groups.set(n, { number: n, name: `Unnamed group #${n}`, kind: n === 0 ? "isolated" : "unnamed", rows: 0, flagged: 0 });
  }
  return { groups, pointCounts };
}

// The card shown in place of a map until someone asks for it. Views drawn once are drawn
// straight away for the rest of the session.
const drawnViews = new Set<string>();
export function mapOnDemand(key: string, info: MapInfo, draw: () => Promise<HTMLElement>): HTMLElement {
  const box = h("div", { class: "cmap-demand" });
  const go = async () => {
    drawnViews.add(key);
    clear(box, loading(`Drawing ${fmt.int(info.shown)} points…`));
    try {
      clear(box, await draw());
    } catch (e) {
      drawnViews.delete(key);
      clear(box, retryBox(e, () => void go()));
    }
  };
  if (drawnViews.has(key)) { void go(); return box; }
  clear(box, h("div", { class: "cmap-demand-card" },
    icon("map", 28),
    h("div", {},
      h("strong", {}, `This map has ${fmt.int(info.points)} data points`),
      h("p", { class: "small muted" },
        `${fmt.int(info.flagged)} of them flagged. Drawing ${info.points > info.shown ? `${fmt.int(info.shown)} of them (every flagged point, the rest sampled)` : "them"} can take some time on this laptop, so the map is drawn only when you ask.`)),
    h("button", { class: "btn primary", onclick: go }, icon("play", 14), "Draw the map")));
  return box;
}

export function clusterMap(points: MapPoints, groups: Map<number, MapGroup>, options: {
  visible: Set<number>; selected: number | null; height?: number; inputs?: InputPoint[];
  title?: string;                         // shown above the map in fullscreen
  aside?: HTMLElement;                    // the clicked point's details: below the map, or a panel in fullscreen
  onPoint?(index: number): void;          // a map point was clicked
  onPick?(group: number): void;           // a new-log ring was clicked: its nearest group
  onClear?(): void;                       // "Clear" on the highlighted-group badge
  layout?: Layout;                        // the layout `points` are in (t-SNE when not given)
  info?: MapInfo | null;                  // which layouts this view has
  loadLayout?(layout: Layout): Promise<MapPoints>;   // the same points in another layout
}): ClusterMap {
  const BASE_HEIGHT = options.height ?? 480;
  let HEIGHT = BASE_HEIGHT;               // the full screen's height while in fullscreen
  let layout: Layout = options.layout ?? "tsne";
  points = { ...points };                 // positions are swapped by layout; the cached copy stays as it was
  const inputs = (options.inputs ?? []).map((p) => ({ ...p, ...(layout !== "tsne" && p.at?.[layout] ? p.at[layout] : {}),
    at: { ...p.at, tsne: p.at?.tsne ?? { x: p.x, y: p.y } } }));
  let visible = options.visible;
  let selected = options.selected;
  let hovered: number | null = null;
  let picked: number | null = null;      // the point last clicked
  let transform: ZoomTransform = zoomIdentity;
  let flaggedOnly = false;
  let width = 800;

  const canvas = h("canvas", { class: "cmap-canvas", tabindex: "0",
    "aria-label": "Map of activity groups. Scroll or pinch to zoom, drag to move, click a point to open it. Keys: plus, minus, arrows, 0 to reset." }) as HTMLCanvasElement;
  const axes = svg("svg", { class: "cmap-axes", "aria-hidden": "true" });
  const gx = svg("g", {}), gy = svg("g", {});
  axes.append(gx, gy,
    svg("text", { class: "cmap-axis-title", "text-anchor": "end" }, `${LAYOUT_NAMES[layout]} 1`),
    svg("text", { class: "cmap-axis-title", "text-anchor": "start" }, `${LAYOUT_NAMES[layout]} 2`));
  const status = h("div", { class: "cmap-status tiny" });
  const flaggedBox = h("input", { type: "checkbox" }) as HTMLInputElement;
  flaggedBox.addEventListener("change", () => { flaggedOnly = flaggedBox.checked; rebuildIndex(); draw(); });
  const button = (label: string, iconName: string | null, text: string | null, onClick: () => void) =>
    h("button", { class: "icon-btn cmap-btn", title: label, "aria-label": label, onclick: onClick }, iconName ? icon(iconName, 15) : null, text);
  const fullButton = button("Fullscreen (F)", "fullscreen", null, () => toggleFullscreen());
  const controls = h("div", { class: "cmap-controls" },
    fullButton,
    button("Zoom in", null, "+", () => zoomBy(1.6)),
    button("Zoom out", null, "−", () => zoomBy(1 / 1.6)),
    button("Fit the whole map", "refresh", null, () => reset()),
    inputs.length ? button("Zoom to the new logs", "target", null, () => zoomToInputs()) : null);
  const swatch = (style: Record<string, string>, text: string) => h("span", {}, h("i", { style }), text);
  const head = h("div", { class: "cmap-fs-head" },
    h("strong", {}, options.title ?? "Map"),
    h("span", { class: "legend" },
      swatch({ background: "var(--muted)" }, "observation"),
      swatch({ background: "var(--red)" }, "flagged"),
      swatch({ background: "var(--map-pick)", boxShadow: "inset 0 0 0 1px var(--map-pick-edge)" }, "selected group"),
      inputs.length ? [swatch({ background: "var(--surface)", boxShadow: "inset 0 0 0 2px var(--ink)" }, "new logs"),
        swatch({ background: "var(--red)", boxShadow: "inset 0 0 0 2px var(--ink)" }, "new logs, flagged")] : null),
    h("span", { class: "tiny muted" }, "Esc or F to leave"),
    h("button", { class: "btn small", onclick: () => toggleFullscreen() }, icon("fullscreen-exit", 14), "Exit fullscreen"));
  const badge = h("div", { class: "cmap-badge", hidden: true });
  const aside = h("div", { class: "cmap-aside" }, options.aside ?? null);
  // Layout picker: t-SNE or UMAP of the same points. A layout this view does not have is shown, disabled, with the command that builds it.
  const layoutNote = h("span", { class: "tiny muted cmap-layout-note" }, LAYOUT_NOTES[layout]);
  const layoutBox = h("div", { class: "cmap-layouts", role: "group", "aria-label": "Map layout" });
  const drawLayoutPicker = (busy: Layout | null = null) => clear(layoutBox,
    h("span", { class: "small muted" }, "Layout"),
    (Object.keys(LAYOUT_NAMES) as Layout[]).map((id) => {
      const status = id === "tsne" ? "ready" : options.info?.layouts?.[id] ?? "missing";
      const usable = status === "ready" && Boolean(options.loadLayout);
      return h("button", {
        class: `btn small ${id === layout ? "olive" : ""}`, "aria-pressed": String(id === layout), disabled: !usable || busy !== null,
        title: usable ? `Lay out the same points with ${LAYOUT_NAMES[id]}`
          : `Not ${status === "stale" ? "up to date" : "built"} for this view. ${options.info?.layout_command ? `Run: ${options.info.layout_command}` : ""}`,
        onclick: () => void switchTo(id),
      }, busy === id ? "Laying out…" : LAYOUT_NAMES[id]);
    }));
  const el = h("div", { class: "cmap" },
    head,
    h("div", { class: "cmap-stage" }, canvas, axes, controls, status, badge),
    h("div", { class: "cmap-foot" },
      layoutBox,
      h("label", { class: "row small" }, flaggedBox, "Flagged points only"),
      layoutNote),
    aside);
  const stage = el.querySelector(".cmap-stage") as HTMLElement;
  const drawBadge = () => {
    badge.hidden = selected === null;
    if (selected === null) return;
    clear(badge, h("span", { class: "cmap-badge-dot", "aria-hidden": "true" }),
      h("span", { class: "cmap-badge-text", title: groups.get(selected)?.name ?? "" }, `Highlighted: ${groups.get(selected)?.name ?? `group #${selected}`}`),
      options.onClear ? h("button", { class: "btn small", onclick: () => options.onClear!() }, "Clear") : null);
  };
  drawBadge();

  // Base scales map data to pixels with equal units on both axes; the zoom transform rescales them.
  const xs = scaleLinear(), ys = scaleLinear();
  let ratio = 1;
  const isFull = () => document.fullscreenElement === el;
  const fit = () => {
    width = (isFull() ? stage.clientWidth : el.clientWidth) || 800;
    HEIGHT = isFull() ? Math.max(240, stage.clientHeight) : BASE_HEIGHT;
    const w = width - MARGIN.left - MARGIN.right, hgt = HEIGHT - MARGIN.top - MARGIN.bottom;
    const [x0, x1] = extent(points.x.concat(inputs.map((p) => p.x))), [y0, y1] = extent(points.y.concat(inputs.map((p) => p.y)));
    const unit = Math.max((x1 - x0) / w, (y1 - y0) / hgt) * 1.06;          // data units per pixel, same both ways
    const cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;
    xs.domain([cx - (unit * w) / 2, cx + (unit * w) / 2]).range([MARGIN.left, width - MARGIN.right]);
    ys.domain([cy - (unit * hgt) / 2, cy + (unit * hgt) / 2]).range([HEIGHT - MARGIN.bottom, MARGIN.top]);
    // the canvas holds one pixel per screen pixel, so nothing is ever stretched
    ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * ratio); canvas.height = Math.round(HEIGHT * ratio);
    canvas.style.width = `${width}px`; canvas.style.height = `${HEIGHT}px`;
    axes.setAttribute("width", String(width)); axes.setAttribute("height", String(HEIGHT));
  };

  // Hover / click lookup: a quadtree over the visible points, in data units.
  let index: Quadtree<number> = quadtree<number>();
  const shown = (i: number) => visible.has(points.cluster[i]) && (!flaggedOnly || points.flagged[i] === 1);
  const rebuildIndex = () => {
    index = quadtree<number>().x((i) => points.x[i]).y((i) => points.y[i]);
    for (let i = 0; i < points.x.length; i++) if (shown(i)) index.add(i);
  };
  const nearestAt = (mx: number, my: number): number | null => {
    const zx = transform.rescaleX(xs);
    const radius = Math.abs(zx.invert(mx + 10) - zx.invert(mx));        // 10 px, in data units
    const found = index.find(zx.invert(mx), transform.rescaleY(ys).invert(my), radius);
    return found === undefined ? null : found;
  };
  // New-log points are few, so a plain scan; they win over map points under the pointer.
  const inputAt = (mx: number, my: number): InputPoint | null => {
    const zx = transform.rescaleX(xs), zy = transform.rescaleY(ys);
    let best: InputPoint | null = null, bestDistance = 10;
    for (const p of inputs) {
      const d = Math.hypot(zx(p.x) - mx, zy(p.y) - my);
      if (d < bestDistance) { best = p; bestDistance = d; }
    }
    return best;
  };

  let frame = 0;
  const draw = () => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(render);
  };
  const render = () => {
    const ctx = canvas.getContext("2d")!;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, HEIGHT);
    const zx = transform.rescaleX(xs), zy = transform.rescaleY(ys);
    const css = getComputedStyle(document.documentElement);
    const color = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
    const ink = color("--ink", "#333"), muted = color("--muted", "#888"), red = color("--red", "#ff3333");
    const surface = color("--surface", "#fff"), pick = color("--map-pick", "#f5c400"), pickEdge = color("--map-pick-edge", "#6b5200");
    const radius = Math.min(7, Math.max(1.3, 1.3 * Math.sqrt(transform.k)));
    const left = MARGIN.left - radius, right = width - MARGIN.right + radius, top = MARGIN.top - radius, bottom = HEIGHT - MARGIN.bottom + radius;

    // Sort the points in view into layers, so the group in focus and the flagged points sit on top.
    //  0 grey · 1 flagged · 2 the focus group. With a group picked, everything else is grey.
    const focus = selected ?? hovered;
    const layers: number[][] = [[], [], []];
    for (let i = 0; i < points.x.length; i++) {
      if (!shown(i)) continue;
      const px = zx(points.x[i]), py = zy(points.y[i]);
      if (px < left || px > right || py < top || py > bottom) continue;
      const inFocus = focus !== null && points.cluster[i] === focus;
      layers[inFocus ? 2 : selected === null && points.flagged[i] === 1 ? 1 : 0].push(i);
    }
    const drawn = layers[0].length + layers[1].length + layers[2].length;
    const vector = drawn <= VECTOR_LIMIT;
    const sprites = new Map<string, HTMLCanvasElement>();
    const spriteFor = (fill: string) => sprites.get(fill) ?? sprites.set(fill, dot(fill, radius, ratio, surface)).get(fill)!;
    const styleOf = (layer: number, i: number): { fill: string; alpha: number; edge: string | null } => {
      if (layer === 2) return selected !== null ? { fill: pick, alpha: 1, edge: pickEdge } : { fill: points.flagged[i] ? red : ink, alpha: 0.95, edge: null };
      if (layer === 1) return { fill: red, alpha: focus !== null ? 0.5 : 0.85, edge: null };
      return { fill: muted, alpha: selected !== null ? 0.22 : focus !== null ? 0.2 : 0.45, edge: null };
    };

    ctx.save();
    ctx.beginPath();
    ctx.rect(MARGIN.left, MARGIN.top, width - MARGIN.left - MARGIN.right, HEIGHT - MARGIN.top - MARGIN.bottom);
    ctx.clip();
    for (const layer of [0, 1, 2]) {
      for (const i of layers[layer]) {
        const style = styleOf(layer, i);
        const px = zx(points.x[i]), py = zy(points.y[i]);
        ctx.globalAlpha = style.alpha;
        if (vector || style.edge) {
          // a true circle, exact at any zoom; overlapping points still add up
          ctx.beginPath();
          ctx.arc(px, py, style.edge ? radius + 0.6 : radius, 0, Math.PI * 2);
          ctx.fillStyle = style.fill;
          ctx.fill();
          if (style.edge) { ctx.lineWidth = 1; ctx.strokeStyle = style.edge; ctx.stroke(); }
          else if (radius >= 3) { ctx.lineWidth = 0.75; ctx.strokeStyle = surface; ctx.stroke(); }
        } else {
          // many points: stamp a circle drawn once at screen resolution
          const box = 2 * radius + 2;
          ctx.drawImage(spriteFor(style.fill), px - box / 2, py - box / 2, box, box);
        }
      }
    }
    // the point last clicked: a ring around it
    if (picked !== null && shown(picked)) {
      ctx.globalAlpha = 1;
      ctx.beginPath();
      ctx.arc(zx(points.x[picked]), zy(points.y[picked]), radius + 5, 0, Math.PI * 2);
      ctx.lineWidth = 2.5; ctx.strokeStyle = ink; ctx.stroke();
    }
    // new logs on top: a ring each, filled red when flagged (fill as well as colour, so it reads without colour)
    ctx.globalAlpha = 1;
    ctx.lineWidth = 2;
    for (const p of inputs) {
      ctx.beginPath();
      ctx.arc(zx(p.x), zy(p.y), 6, 0, Math.PI * 2);
      ctx.fillStyle = p.flagged ? red : surface;
      ctx.fill();
      ctx.strokeStyle = ink;
      ctx.stroke();
    }
    ctx.restore();
    ctx.globalAlpha = 1;
    // axes
    select(gx).attr("transform", `translate(0,${HEIGHT - MARGIN.bottom})`).call(axisBottom(zx).ticks(Math.max(3, Math.floor(width / 110))).tickSizeOuter(0));
    select(gy).attr("transform", `translate(${MARGIN.left},0)`).call(axisLeft(zy).ticks(6).tickSizeOuter(0));
    const titles = axes.querySelectorAll(".cmap-axis-title");
    titles[0].setAttribute("x", String(width - MARGIN.right)); titles[0].setAttribute("y", String(HEIGHT - 4));
    titles[1].setAttribute("x", String(MARGIN.left + 6)); titles[1].setAttribute("y", String(MARGIN.top + 10));
    const total = points.x.reduce((n, _, i) => n + (shown(i) ? 1 : 0), 0);
    clear(status, `×${transform.k.toFixed(transform.k < 10 ? 1 : 0)} · ${fmt.int(drawn)} in view of ${fmt.int(total)} shown · ${fmt.int(points.x.length)} on the map`);
  };

  const zoom = d3zoom<HTMLCanvasElement, unknown>()
    .scaleExtent([0.5, 120])
    .on("zoom", (event) => { transform = event.transform; tip(null); draw(); });
  const selection = select(canvas);
  selection.call(zoom);
  const zoomBy = (factor: number) => zoom.scaleBy(selection, factor);
  const reset = () => zoom.transform(selection, zoomIdentity);
  const zoomToBox = (px: [number, number], py: [number, number]) => {
    const w = width - MARGIN.left - MARGIN.right, hgt = HEIGHT - MARGIN.top - MARGIN.bottom;
    const k = Math.min(120, Math.max(1, 0.8 * Math.min(w / Math.max(px[1] - px[0], 1), hgt / Math.max(py[1] - py[0], 1))));
    const cx = (px[0] + px[1]) / 2, cy = (py[0] + py[1]) / 2;
    zoom.transform(selection, zoomIdentity.translate(MARGIN.left + w / 2, MARGIN.top + hgt / 2).scale(k).translate(-cx, -cy));
  };
  // a few new points close together would zoom in absurdly far, so keep at least 40 px around them
  const zoomToInputs = () => {
    const [px0, px1] = extent(inputs.map((p) => xs(p.x))), [py0, py1] = extent(inputs.map((p) => ys(p.y)));
    zoomToBox([px0 - 40, px1 + 40], [py0 - 40, py1 + 40]);
  };

  const describe = (i: number) => {
    const g = groups.get(points.cluster[i]);
    return `${g?.name ?? `Group #${points.cluster[i]}`} · ${g ? KIND_TEXT[g.kind] : ""}${points.flagged[i] ? " · this point flagged" : ""} · click to open this point`;
  };
  canvas.addEventListener("pointermove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const input = inputAt(e.clientX - rect.left, e.clientY - rect.top);
    if (input) {
      if (selected === null && input.group !== hovered) { hovered = input.group; draw(); }
      canvas.style.cursor = "pointer";
      const g = input.group === null ? null : groups.get(input.group);
      tip(`${input.label}${g ? ` · nearest group: ${g.name}` : ""}`, e);
      return;
    }
    const i = nearestAt(e.clientX - rect.left, e.clientY - rect.top);
    const group = i === null ? null : points.cluster[i];
    if (selected === null && group !== hovered) { hovered = group; draw(); }
    if (i === null) { tip(null); canvas.style.cursor = "grab"; return; }
    canvas.style.cursor = "pointer";
    tip(describe(i), e);
  });
  canvas.addEventListener("pointerleave", () => { hovered = null; tip(null); draw(); });
  canvas.addEventListener("click", (e) => {
    const rect = canvas.getBoundingClientRect();
    const input = inputAt(e.clientX - rect.left, e.clientY - rect.top);
    if (input) { if (input.group !== null) options.onPick?.(input.group); return; }
    const i = nearestAt(e.clientX - rect.left, e.clientY - rect.top);
    if (i === null) return;
    picked = i;
    draw();
    options.onPoint?.(i);
  });
  canvas.addEventListener("keydown", (e) => {
    const step = 60;
    const moves: Record<string, () => void> = {
      "+": () => zoomBy(1.4), "=": () => zoomBy(1.4), "-": () => zoomBy(1 / 1.4), "0": reset,
      f: () => toggleFullscreen(), F: () => toggleFullscreen(),
      ArrowLeft: () => zoom.translateBy(selection, step / transform.k, 0), ArrowRight: () => zoom.translateBy(selection, -step / transform.k, 0),
      ArrowUp: () => zoom.translateBy(selection, 0, step / transform.k), ArrowDown: () => zoom.translateBy(selection, 0, -step / transform.k),
    };
    if (moves[e.key]) { e.preventDefault(); moves[e.key](); }
  });

  // Resizing the canvas clears it, so redraw straight away rather than on the next frame. A change of
  // screen density (browser zoom, another monitor) resizes the canvas too.
  const refit = () => { cancelAnimationFrame(frame); fit(); render(); };
  new ResizeObserver(refit).observe(el);

  // Fullscreen: the map takes the whole screen; the same spot stays in the middle at the same zoom.
  const toggleFullscreen = () => {
    if (isFull()) void document.exitFullscreen();
    else void el.requestFullscreen?.().catch(() => undefined);
  };
  let wasFull = false;
  document.addEventListener("fullscreenchange", () => {
    if (isFull() === wasFull) return;               // another element's fullscreen
    wasFull = isFull();
    const zx = transform.rescaleX(xs), zy = transform.rescaleY(ys);
    const centre = [zx.invert(MARGIN.left + (width - MARGIN.left - MARGIN.right) / 2), zy.invert(MARGIN.top + (HEIGHT - MARGIN.top - MARGIN.bottom) / 2)];
    clear(fullButton, icon(wasFull ? "fullscreen-exit" : "fullscreen", 15));
    fullButton.title = fullButton.ariaLabel = wasFull ? "Exit fullscreen (F)" : "Fullscreen (F)";
    tip(null);
    requestAnimationFrame(() => {                    // after the browser has resized the element
      fit();
      const k = transform.k, midX = MARGIN.left + (width - MARGIN.left - MARGIN.right) / 2, midY = MARGIN.top + (HEIGHT - MARGIN.top - MARGIN.bottom) / 2;
      zoom.transform(selection, zoomIdentity.translate(midX - k * xs(centre[0]), midY - k * ys(centre[1])).scale(k));
      render();
      canvas.focus();
    });
  });
  const watchDensity = () => {
    const query = matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`);
    query.addEventListener("change", () => { refit(); watchDensity(); }, { once: true });
  };
  watchDensity();
  rebuildIndex();

  // Switch layout: same points, same order, new positions. The zoom starts again from the whole map.
  const switchTo = async (next: Layout) => {
    if (next === layout || !options.loadLayout) return;
    drawLayoutPicker(next);
    try {
      const moved = await options.loadLayout(next);
      if (moved.x.length !== points.x.length || (moved.id && points.id && moved.id[0] !== points.id[0])) throw new Error("The layouts do not hold the same points.");
      points = { ...points, x: moved.x, y: moved.y };
      for (const p of inputs) Object.assign(p, p.at?.[next] ?? {});
      layout = next;
      preferred = next;
      try { localStorage.setItem("map-layout", next); } catch { /* remembered for this page only */ }
      axes.querySelectorAll(".cmap-axis-title").forEach((t, i) => { t.textContent = `${LAYOUT_NAMES[next]} ${i + 1}`; });
      clear(layoutNote, LAYOUT_NOTES[next]);
      rebuildIndex();
      fit();
      reset();
      render();
    } catch (e) {
      clear(layoutNote, h("span", { class: "error-text" }, e instanceof Error ? e.message : String(e)));
    }
    drawLayoutPicker();
  };
  drawLayoutPicker();

  return {
    el,
    setVisible(next) { visible = next; rebuildIndex(); draw(); },
    setSelected(group) { selected = group; hovered = null; drawBadge(); draw(); },
    clearPoint() { picked = null; draw(); },
    zoomToInputs() { if (inputs.length) zoomToInputs(); },
    zoomToGroup(group) {
      const members = points.x.map((_, i) => i).filter((i) => points.cluster[i] === group);
      if (!members.length) return;
      zoomToBox(extent(members.map((i) => xs(points.x[i]))), extent(members.map((i) => ys(points.y[i]))));
    },
  };
}

// One round point, drawn at the screen's pixel density. Once zoomed in far enough for points to
// overlap visibly, a thin edge in the background colour keeps neighbours apart.
const dotCache = new Map<string, HTMLCanvasElement>();
function dot(color: string, radius: number, ratio: number, edge: string): HTMLCanvasElement {
  const key = `${color}|${radius.toFixed(2)}|${ratio}|${edge}`;
  let sprite = dotCache.get(key);
  if (sprite) return sprite;
  if (dotCache.size > 60) dotCache.clear();
  const box = 2 * radius + 2;
  sprite = document.createElement("canvas");
  sprite.width = sprite.height = Math.ceil(box * ratio);
  const ctx = sprite.getContext("2d")!;
  ctx.scale(sprite.width / box, sprite.height / box);
  ctx.beginPath();
  ctx.arc(box / 2, box / 2, radius, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.fill();
  if (radius >= 3) { ctx.lineWidth = 0.75; ctx.strokeStyle = edge; ctx.stroke(); }
  dotCache.set(key, sprite);
  return sprite;
}

function extent(values: number[]): [number, number] {
  let lo = Infinity, hi = -Infinity;
  for (const v of values) { if (v < lo) lo = v; if (v > hi) hi = v; }
  return lo === Infinity ? [0, 1] : lo === hi ? [lo - 1, hi + 1] : [lo, hi];
}

// The details of one clicked point: its period, time, group and original lines.
export async function pointDetails(source: string, view: string, id: string, groupName: (n: number) => string,
  onHighlight: (group: number) => void, onClose?: () => void): Promise<HTMLElement> {
  const p = await api(`/api/map/point${qs({ source, view, id })}`);
  const period = ({ train: "training", validation: "validation", test: "test" } as Record<string, string>)[p.split] ?? p.split;
  return h("div", { class: "cmap-point" },
    h("div", { class: "row", style: { justifyContent: "space-between" } },
      h("strong", {}, "Selected point"),
      h("span", { class: "row", style: { gap: "6px" } },
        h("button", { class: "btn small", onclick: () => onHighlight(p.cluster) }, "Highlight its group"),
        onClose ? h("button", { class: "icon-btn", title: "Close", "aria-label": "Close", onclick: onClose }, icon("close", 14)) : null)),
    h("dl", { class: "kv" },
      h("dt", {}, "Time"), h("dd", { class: "mono small" }, p.time || "—"),
      h("dt", {}, "Period"), h("dd", {}, period),
      h("dt", {}, "Group"), h("dd", {}, groupName(p.cluster)),
      h("dt", {}, "Flagged"), h("dd", {}, p.flagged ? "yes" : p.split === "train" ? "no (training points are never scored)" : "no"),
      p.votes !== null && p.split !== "train" ? [h("dt", {}, "Model-zoo votes"), h("dd", {}, String(p.votes))] : null,
      p.category ? [h("dt", {}, "Event type"), h("dd", { class: "mono small" }, p.category)] : null),
    p.status === "purged"
      ? h("p", { class: "small muted" }, "Lines purged with the data")
      : p.status !== "ready"
      ? h("p", { class: "small muted" }, `The original lines are still being indexed (${p.status}). Try again in a few minutes.`)
      : p.lines.length
        ? [h("pre", { class: "lines" }, p.lines.join("\n")),
          p.line_count > p.lines.length ? h("p", { class: "tiny muted" }, `First ${p.lines.length} of ${fmt.int(p.line_count)} lines`) : null]
        : h("p", { class: "small muted" }, "No original lines found for this point."));
}
