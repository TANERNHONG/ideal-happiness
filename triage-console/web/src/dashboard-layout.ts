// The Dashboard's cards (their names, icons and default widths in columns of 12) and the layout Settings → Dashboard
// saves: the cards shown, in order, with their widths, the hidden ones, the person's own SQL tables ("widgets": a
// title, a description, a query and a height each) and tiles (an icon and text, from 1 × 1 up), and whether it is packed
// tightly. service/config.py checks its form.

import type { DashboardLayout, DashboardTile, DashboardWidget } from "./api";

export type Layout = DashboardLayout;

export const COLUMNS = 12;
export const MIN_SPAN = 3;
export const WIDGET_SPAN = 6;
export const HEIGHT = { min: 160, max: 1200, start: 360 };           // an SQL table's height, in pixels
export const TILE_HEIGHT = { min: 60, max: 1200, start: 100 };       // a tile's; one column by this is "1 × 1"

export const CARDS: { id: string; name: string; glyph: string; span: number }[] = [
  { id: "open", name: "Needs review", glyph: "hourglass", span: 3 },
  { id: "sigma", name: "Sigma matches", glyph: "sigma", span: 3 },
  { id: "security", name: "Security relevant", glyph: "alert", span: 3 },
  { id: "reviewed", name: "Reviewed", glyph: "check", span: 3 },
  { id: "triage", name: "Time to label", glyph: "clock", span: 3 },
  { id: "next", name: "Next to review", glyph: "review", span: 7 },
  { id: "progress", name: "Review progress", glyph: "gauge", span: 5 },
  { id: "yield", name: "Label yield", glyph: "target", span: 6 },
  { id: "audit", name: "Audit", glyph: "audit", span: 6 },
  { id: "flagged", name: "Flagged", glyph: "analyze", span: 6 },
  { id: "data", name: "Data", glyph: "data", span: 6 },
  { id: "watched", name: "Watched", glyph: "eye", span: 12 },
  { id: "models", name: "Model data", glyph: "models", span: 12 },
  { id: "activity", name: "Activity", glyph: "history", span: 12 },
];
// The console pages a tile can open (main.ts), and a tile's choices
export const TILE_LINKS = ["dashboard", "datasets", "patterns", "models", "analyze", "sigma", "review", "explain", "profiles", "data", "reports", "docs", "settings"];
export const TILE_TONES: DashboardTile["tone"][] = ["", "red", "amber", "green", "blue", "grey"];
export const TILE_SIZES: DashboardTile["size"][] = ["s", "m", "l"];

export const isWidget = (id: string) => /^sql_[a-z0-9]{1,24}$/.test(id);
export const isTile = (id: string) => /^tile_[a-z0-9]{1,24}$/.test(id);
const stamp = () => `${Date.now().toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
export const newWidgetId = () => `sql_${stamp()}`;
export const newTileId = () => `tile_${stamp()}`;
export const newWidget = (): DashboardWidget => ({ title: "", description: "", query: "", height: HEIGHT.start });
export const newTile = (): DashboardTile =>
  ({ icon: "star", link: "", heading: "", text: "", size: "m", tone: "", align: "left", height: TILE_HEIGHT.start });

/** A card's name, icon and default width: a built-in card's, or an SQL table's or tile's (its own words, when it has some). */
export function cardInfo(id: string, layout?: Layout): { id: string; name: string; glyph: string; span: number } {
  if (isWidget(id)) return { id, name: layout?.widgets?.[id]?.title || "SQL table", glyph: "query-sql", span: WIDGET_SPAN };
  if (isTile(id)) {
    const tile = layout?.tiles?.[id];
    return { id, name: tile?.heading || tile?.text.split("\n")[0] || "Tile", glyph: tile?.icon || "note", span: 1 };
  }
  return CARDS.find((c) => c.id === id) ?? CARDS[0];
}
/** A width in columns: a tile from 1, any other card from MIN_SPAN. */
export const clampSpan = (span: number, id = "") => Math.min(COLUMNS, Math.max(isTile(id) ? 1 : MIN_SPAN, Math.round(span)));
/** A height in pixels, to the nearest ten: a tile's within TILE_HEIGHT, an SQL table's within HEIGHT. */
export const clampHeight = (px: number, id = "") => {
  const { min, max } = isTile(id) ? TILE_HEIGHT : HEIGHT;
  return Math.min(max, Math.max(min, Math.round(px / 10) * 10));
};

/** The standard cards, not packed; the person's own SQL tables and tiles, when given, are kept, hidden. */
export const defaultLayout = (widgets: Record<string, DashboardWidget> = {}, tiles: Record<string, DashboardTile> = {}): Layout =>
  ({ cards: CARDS.map(({ id, span }) => ({ id, span })), hidden: [...Object.keys(widgets), ...Object.keys(tiles)],
    widgets: { ...widgets }, tiles: { ...tiles }, packed: false });

/** A tile's saved fields, each kept to what it can be. */
function cleanTile(t: Partial<DashboardTile>, id: string): DashboardTile {
  const pick = <T,>(value: unknown, options: T[]) => (options.includes(value as T) ? value as T : options[0]);
  return { icon: typeof t.icon === "string" ? t.icon : "", link: TILE_LINKS.includes(t.link ?? "") ? t.link! : "",
    heading: String(t.heading ?? ""), text: String(t.text ?? ""), size: pick(t.size, TILE_SIZES), tone: pick(t.tone, TILE_TONES),
    align: t.align === "center" ? "center" : "left", height: clampHeight(Number(t.height) || TILE_HEIGHT.start, id) };
}

/** A saved layout made safe to draw: unknown and repeated cards dropped, widths and heights kept within bounds, and any
 * card it does not mention (one added to the console since, or an SQL table or tile placed nowhere) shown at the end. */
export function normalise(saved: Layout | null | undefined): Layout {
  if (!saved) return defaultLayout();
  const widgets: Record<string, DashboardWidget> = {}, tiles: Record<string, DashboardTile> = {};
  for (const [id, w] of Object.entries(saved.widgets ?? {})) {
    if (isWidget(id) && w) widgets[id] = { title: String(w.title ?? ""), description: String(w.description ?? ""),
      query: String(w.query ?? ""), height: clampHeight(Number(w.height) || HEIGHT.start, id) };
  }
  for (const [id, t] of Object.entries(saved.tiles ?? {})) if (isTile(id) && t) tiles[id] = cleanTile(t, id);
  const known = new Set([...CARDS.map((c) => c.id), ...Object.keys(widgets), ...Object.keys(tiles)]), seen = new Set<string>();
  const fresh = (id: string) => known.has(id) && !seen.has(id) && Boolean(seen.add(id));
  const cards = (saved.cards ?? []).filter((c) => fresh(c.id)).map((c) => ({ id: c.id, span: clampSpan(Number(c.span) || cardInfo(c.id).span, c.id) }));
  const hidden = (saved.hidden ?? []).filter(fresh);
  for (const c of CARDS) if (!seen.has(c.id)) cards.push({ id: c.id, span: c.span });
  for (const id of Object.keys(widgets)) if (!seen.has(id)) cards.push({ id, span: WIDGET_SPAN });
  for (const id of Object.keys(tiles)) if (!seen.has(id)) cards.push({ id, span: 1 });
  return { cards, hidden, widgets, tiles, packed: saved.packed === true };
}
