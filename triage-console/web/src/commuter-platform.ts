// The Commuter pack's SQL scene: an underground East West Line platform (Raffles Place, EW14), seen standing, in the
// first person, phone in hand (commuter-kit.ts). It looks the same by day and night: it is underground.
//
// One-point perspective: the screen-door wall faces you, 4 m away (33 px a metre on the wall), your eyes 1.6 m up.
// Floor and ceiling lines along the platform stay level; lines running towards you meet at eye level in the middle.
// - Ceiling: tiles and long strip lights, CCTV domes, a hanging clock showing the time.
// - The screen-door wall repeats in modules: a holding door, two sliding leaves, a holding door (one module each) and
//   a long fixed panel (two). Beside the doors either side of you, an advertisement (a café and a bank, made up) takes
//   the holding door's place. All of it tinted glass; beyond it, the tunnel wall, or the train.
// - Above, in a row: over every door a banner one door wide (East West Line; To Changi Airport; on red, "Please do not
//   board when the light is flashing" in English, Malay, Tamil and Chinese either side of a yellow triangle pointing
//   down at the door light), and over every other stretch between doors an EW14 Raffles Place sign two doors wide. On
//   the door headers, door lights, green Emergency Exit signs and fire-alarm bells.
// - Floor: granite with a darker border at the doors, and tactile paving for the visually impaired: a road of square
//   blocks of raised bars along the platform and, a little way out from each door, a square of studs twice their size.
// When the query is done the train brakes in, its doors and the screen doors open, and you put the phone down; if it
// fails, you are still playing when the doors open: they close, the train leaves, and only then do you look up.

import { h, svg } from "./dom";
import { C, CX, G, P, R, T, W, commuterPhone, easeIn, lerp, moving, seeded, sleep, tween } from "./commuter-kit";
import { arrivalWanted, loaderShell, type TrainLoader } from "./train-loader";

// The scene is 200 px tall and the wall meets the floor at 130; you stand 2.6 m from the wall.
const HEIGHT = 200, BASE = 130, DIST = 2.6, EYE = 1.6, PXM = 33, FOCAL = PXM * DIST, CEILING_H = 3.5;
const HORIZON = BASE - EYE * PXM;
const floorY = (v: number) => HORIZON + (EYE * FOCAL) / (DIST - v);              // a floor line v metres out from the wall
const ceilY = (v: number) => HORIZON - ((CEILING_H - EYE) * FOCAL) / (DIST - v);
/** A floor point v metres out from the wall, in front of wall position u. Across such a wide view, true perspective
 * would fan the floor out too far, so positions spread out less than sizes grow (as in a panorama). */
const SPREAD = 0.1;
const at = (u: number, v: number): [number, number] => [CX + (u - CX) * (1 + SPREAD * (DIST / (DIST - v) - 1)), floorY(v)];
// The wall, doors, tunnel and train are drawn with their floor line at 134, and moved up by SHIFT to meet the floor.
const FLOOR = 134, SHIFT = BASE - FLOOR, WALL_TOP = ceilY(0) - SHIFT, HEADER = 46, PSD_TOP = 58, KICK = 126;
// The screen doors repeat every PITCH, in modules of U: a holding door, two sliding leaves, a holding door (one module
// each) and a long fixed panel (two), with a steel post between each.
const U = 34, PITCH = 6 * U, POST = 4, LEAF = U - POST / 2, PANE = U - POST;
const doors = Array.from({ length: 15 }, (_, i) => CX + PITCH * (i - 7));
const GREEN = "#009645", STEEL = "#c4c8cc", STEEL_DARK = "#9da3a9", STEEL_LIGHT = "#e2e5e8", GLASS = "rgb(146 174 184 / 46%)";
const BOLD = { "font-weight": 700 }, MID = { "text-anchor": "middle" };

// --- the tunnel and the train behind the glass ------------------------------------------------------------

function tunnel(): SVGElement[] {
  const out: SVGElement[] = [R(0, HEADER, W, FLOOR - HEADER, "#2a2c2f"), R(0, HEADER, W, 14, "#1f2124"), R(0, 96, W, 38, "#323438")];
  for (let x = 0; x < W; x += 60) out.push(R(x, 96, 1, 38, "#28292c"));
  out.push(R(0, 64, W, 3.4, "#4a4e54"), R(0, 63.4, W, 0.8, "#15171a"), R(0, 67.8, W, 0.8, "#15171a"), R(0, 69.4, W, 0.6, "#15171a"));
  for (let x = 40; x < W; x += 230) out.push(R(x - 6, 54.5, 26, 7, "rgb(255 244 210 / 12%)", { rx: 3 }), R(x, 56.5, 14, 3, "#f5efd6", { rx: 1 }));
  return out;
}

const CAR = 4 * PITCH, CARS = 4, TRAIN_LEN = CAR * CARS;
/** Where the train's nose stops: a train door behind every screen door. */
const TRAIN_STOP = CX - PITCH / 2 - PITCH * 7;

function train(): { g: SVGElement; doors: [SVGElement, SVGElement][] } {
  const parts: SVGElement[] = [], pairs: [SVGElement, SVGElement][] = [];
  for (let c = 0; c < CARS; c++) {
    const x0 = c * CAR, centres = [0, 1, 2, 3].map((j) => x0 + PITCH / 2 + PITCH * j);
    parts.push(R(x0 + 3, 50, CAR - 6, 100, "#e8eaed"), R(x0 + 3, 50, CAR - 6, 10, "#d3d6da"));
    const edges = [x0 + 6, ...centres.flatMap((d) => [d - 25, d + 25]), x0 + CAR - 6];
    for (let k = 0; k < edges.length; k += 2) {                          // windows between the doors, seats inside
      const a = edges[k] + 9, b = edges[k + 1] - 9;
      if (b - a < 12) continue;
      parts.push(R(a, 69, b - a, 27, "#3d4954", { rx: 2.2 }), R(a + 2, 70, b - a - 4, 2.4, "rgb(240 236 220 / 55%)"),
        R(a + 3, 85, b - a - 6, 9, "#4f6a8c", { rx: 1 }), R(a + 2, 72.5, b - a - 4, 0.8, "rgb(255 255 255 / 22%)"));
    }
    parts.push(R(x0 + 3, 102, CAR - 6, 5, "#d32f2f"), R(x0 + 3, 107, CAR - 6, 1.6, "#4a4f55"));
    for (const d of centres) {
      parts.push(R(d - 25, 62, 50, 72, "#efe8d6"), R(d - 25, 126, 50, 8, "#b9b3a8"), R(d - 1, 62, 2, 64, "#c4c8cc"),
        R(d - 25, 103, 9, 7, "#3f6bb0", { rx: 1 }), R(d + 16, 103, 9, 7, "#3f6bb0", { rx: 1 }), R(d - 25, 63, 50, 2.4, "#fffbe8"));
      const leaf = (x: number) => G({}, R(x, 60, 25, 76, "#dee1e5", { stroke: "#b2b7bd", "stroke-width": 0.6 }),
        R(x + 4, 68, 17, 30, "#3d4954", { rx: 1.6 }), R(x + 5, 69, 15, 1.4, "rgb(255 255 255 / 25%)"), R(x, 102, 25, 5, "#d32f2f"));
      const pair: [SVGElement, SVGElement] = [leaf(d - 25), leaf(d)];
      parts.push(...pair);
      pairs.push(pair);
    }
    if (c < CARS - 1) parts.push(R(x0 + CAR - 4, 54, 8, 96, "#2b2e33"));
  }
  // the cab at the front (the train runs to the left)
  parts.push(P("M 40 50 L 14 50 Q -10 56 -17 86 L -17 150 L 40 150 Z", "#e8eaed"), P("M 12 58 Q -3 63 -10 86 L 12 86 Z", "#2c3740"),
    P("M -17 102 L 40 102 L 40 107 L -17 107 Z", "#d32f2f"), C(-10, 118, 3, "#fffbe0"), C(-10, 118, 7, "rgb(255 250 220 / 25%)"));
  const g = G({ transform: `translate(${W + 600} 0)` }, ...parts);
  return { g, doors: pairs };
}

// --- the screen doors ----------------------------------------------------------------------------------------

/** Two advertisements, generic and made up, in the style of the backlit posters on the screen doors: a café and a bank.
 * Each fills a lightbox (x, y, w, hh); the brand's colours carry on in blocks below it. */
const SERIF = "Georgia, 'Times New Roman', serif";
function cafeAd(x: number, y: number, w: number, hh: number): SVGElement[] {
  const cx = x + w / 2, rim = y + 19.6, BROWN = "#5a3825";
  return [
    R(x, y, w, hh, "#f6efe4"), R(x, y + hh - 13, w, 13, "#efe3d3"),
    // the brand, on a coffee-brown band
    R(x, y, w, 8.6, BROWN), T(cx, y + 4.7, "BREW & CO.", 2.6, "#f6efe4", { ...MID, ...BOLD, "letter-spacing": 0.25 }),
    T(cx, y + 7.1, "COFFEE HOUSE", 1.2, "#e0c3a5", { ...MID, "letter-spacing": 0.5 }),
    // a latte on its saucer, steam rising
    P(`M ${cx - 2} ${rim - 3} q -1 -1.6 0 -3.2 q 1 -1.6 0 -3.2 M ${cx + 1.8} ${rim - 3} q -1 -1.6 0 -3.2 q 1 -1.6 0 -3.2`, "none",
      { stroke: "#c9b39c", "stroke-width": 0.5, "stroke-linecap": "round", opacity: 0.85 }),
    svg("ellipse", { cx, cy: rim + 7.6, rx: 10, ry: 2.2, fill: "#e2cfb9" }), svg("ellipse", { cx, cy: rim + 7.2, rx: 8.2, ry: 1.6, fill: "#ffffff" }),
    P(`M ${cx + 7} ${rim + 1} c 3 0 3 3.8 -0.6 4.1`, "none", { stroke: "#ffffff", "stroke-width": 1.1 }),
    P(`M ${cx - 7.2} ${rim} h 14.4 c 0 4 -2.5 6.8 -7.2 6.8 c -4.7 0 -7.2 -2.8 -7.2 -6.8 z`, "#ffffff", { stroke: "#e2d3c2", "stroke-width": 0.35 }),
    svg("ellipse", { cx, cy: rim, rx: 7.2, ry: 1.8, fill: "#b77a4b" }), svg("ellipse", { cx, cy: rim, rx: 6.3, ry: 1.4, fill: "#c98b57" }),
    P(`M ${cx} ${rim + 1} c -1.8 -0.8 -1.8 -2.1 -0.7 -2.1 c 0.35 0 0.6 0.2 0.7 0.55 c 0.1 -0.35 0.35 -0.55 0.7 -0.55 c 1.1 0 1.1 1.3 -0.7 2.1 z`, "#f4e6d4"),
    // the line
    T(cx, y + 34.6, "Slow", 4.2, BROWN, { ...MID, "font-family": SERIF, "font-style": "italic" }),
    T(cx, y + 39.2, "mornings.", 4.2, BROWN, { ...MID, "font-family": SERIF, "font-style": "italic" }),
    R(cx - 5, y + hh - 7.6, 10, 0.25, "#c98b57"),
    T(cx, y + hh - 3.6, "KOPI · TOAST · BUNS", 1.3, "#8a6247", { ...MID, "letter-spacing": 0.15 }),
  ];
}
function bankAd(x: number, y: number, w: number, hh: number): SVGElement[] {
  const NAVY = "#14326b", TEAL = "#12a39a", cx = x + w / 2, code = y + hh - 7.6;
  const scan: SVGElement[] = [];                                              // a scan code: corner squares and a scatter of cells
  for (const [a, b] of [[0, 0], [3, 0], [0, 3]]) scan.push(R(x + 2.4 + a, code + 0.2 + b, 1.6, 1.6, "none", { stroke: NAVY, "stroke-width": 0.35 }), R(x + 2.9 + a, code + 0.7 + b, 0.6, 0.6, NAVY));
  for (const [a, b] of [[2.2, 2.2], [3.4, 3.2], [4, 4.2], [2.6, 4.4], [2, 1], [4.2, 2]]) scan.push(R(x + 2.4 + a, code + 0.2 + b, 0.6, 0.6, NAVY));
  return [
    R(x, y, w, hh, "#ffffff"),
    // the mark: two ribbons folding over each other, and the name
    P(`M ${x + 2.2} ${y + 7} q 2 -4.4 6.2 -3.8 q -3 1.1 -3.9 3.8 z`, TEAL), P(`M ${x + 8.8} ${y + 3.6} q -2 4.4 -6.2 3.8 q 3 -1.1 3.9 -3.8 z`, NAVY),
    T(x + 10, y + 5.9, "HAVEN", 2.8, NAVY, { ...BOLD, "letter-spacing": 0.3 }), T(x + 10, y + 7.9, "BANK", 1.3, TEAL, { ...BOLD, "letter-spacing": 1 }),
    // the offer
    T(x + 2.2, y + 15.6, "Savings", 3.4, NAVY, BOLD), T(x + 2.2, y + 19.6, "that grow", 3.4, NAVY, BOLD), T(x + 2.2, y + 23.6, "with you.", 3.4, NAVY, BOLD),
    C(cx, y + 31.6, 5.8, TEAL), T(cx, y + 31.8, "3.10%", 2.7, "#ffffff", { ...MID, ...BOLD }), T(cx, y + 34.4, "p.a.", 1.4, "#e6fbf9", MID),
    T(cx, y + 39.8, "Open an account", 1.5, "#4a5a78", MID), T(cx, y + 41.8, "in five minutes.", 1.5, "#4a5a78", MID),
    // a scan code and the small print
    R(x + 2, code - 0.2, 5.6, 5.6, "#ffffff"), ...scan, T(x + 8.6, code + 3.2, "Scan to apply", 1.4, NAVY, BOLD),
    R(x, y + hh - 1.6, w * 0.62, 1.6, NAVY), R(x + w * 0.62, y + hh - 1.6, w * 0.38, 1.6, TEAL),
  ];
}
const AD_COLOURS: Record<string, string[]> = { cafe: ["#5a3825", "#c98b57", "#e8d6c1"], bank: ["#14326b", "#12a39a", "#9fd9d3"] };

function screenDoors(): { leaves: SVGElement[]; front: SVGElement[]; pairs: [SVGElement, SVGElement][] } {
  const leaves: SVGElement[] = [], front: SVGElement[] = [], pairs: [SVGElement, SVGElement][] = [];
  const post = (x: number) => R(x, PSD_TOP, POST, FLOOR - PSD_TOP, STEEL_DARK);
  const glass = (x: number, w: number) => [R(x, PSD_TOP, w, KICK - PSD_TOP, GLASS), R(x, PSD_TOP, w, 7, "rgb(255 255 255 / 14%)"),
    P(`M ${x + w * 0.2} ${KICK} L ${x + w * 0.62} ${PSD_TOP}`, "none", { stroke: "rgb(255 255 255 / 26%)", "stroke-width": 7 }),
    P(`M ${x + w * 0.62} ${KICK} L ${x + w * 0.86} ${PSD_TOP + 20}`, "none", { stroke: "rgb(255 255 255 / 16%)", "stroke-width": 3 }), R(x, KICK, w, FLOOR - KICK, STEEL)];
  // a holding door: a hinged glass door in a steel frame, opened outwards in an emergency; its handle on the side
  // away from the sliding door (side: +1 if that is to the right)
  const holding = (x: number, side: number) => [R(x + 1, PSD_TOP + 1, PANE - 2, KICK - PSD_TOP - 2, GLASS), R(x + 1, PSD_TOP + 1, PANE - 2, 6, "rgb(255 255 255 / 14%)"),
    P(`M ${x + PANE * 0.3} ${KICK - 2} L ${x + PANE * 0.75} ${PSD_TOP + 2}`, "none", { stroke: "rgb(255 255 255 / 22%)", "stroke-width": 4 }),
    R(x, PSD_TOP, PANE, FLOOR - PSD_TOP, "none", { stroke: STEEL, "stroke-width": 2.6 }), R(x, KICK, PANE, FLOOR - KICK, STEEL),
    R(x + PANE / 2 + side * (PANE / 2 - 4) - 0.7, 86, 1.4, 11, STEEL_DARK, { rx: 0.7 })];
  // an advertisement in a holding door's place: a backlit poster, the brand's colours in blocks below
  const BOX = 113;
  const adPanel = (x: number, kind: "cafe" | "bank") => {
    const c = AD_COLOURS[kind], inner = PANE - 4;
    return [R(x, PSD_TOP, PANE, FLOOR - PSD_TOP, STEEL), R(x + 2, PSD_TOP + 2.4, inner, BOX - PSD_TOP - 2.4, "#f4f6f8"),
      ...(kind === "cafe" ? cafeAd : bankAd)(x + 2.8, PSD_TOP + 3.2, PANE - 5.6, BOX - PSD_TOP - 4),
      R(x + 2, BOX + 0.6, inner * 0.22, KICK - BOX - 1.2, c[1]), R(x + 2 + inner * 0.22, BOX + 0.6, inner * 0.5, KICK - BOX - 1.2, c[0]),
      R(x + 2 + inner * 0.72, BOX + 0.6, inner * 0.28, KICK - BOX - 1.2, c[2]), R(x, KICK, PANE, FLOOR - KICK, STEEL)];
  };
  for (const d of doors) {
    // two glass leaves that slide apart behind the holding doors beside them
    const leaf = (x: number) => G({},
      R(x + 1, PSD_TOP + 1, LEAF - 2, KICK - PSD_TOP - 2, GLASS), R(x + 1, PSD_TOP + 1, LEAF - 2, 6, "rgb(255 255 255 / 14%)"),
      R(x, PSD_TOP, LEAF, FLOOR - PSD_TOP, "none", { stroke: STEEL, "stroke-width": 2.2 }),
      R(x, KICK, LEAF, FLOOR - KICK, STEEL), R(x + 2.5, 97, LEAF - 5, 2.2, "#f2c200"),
      C(x + LEAF / 2, 84, 2.6, "#ffffff", { stroke: "#d32f2f", "stroke-width": 0.8 }), P(`M ${x + LEAF / 2 - 1.8} ${85.8} l 3.6 -3.6`, "none", { stroke: "#d32f2f", "stroke-width": 0.7 }),
      P(`M ${x + LEAF * 0.25} ${KICK - 2} L ${x + LEAF * 0.7} ${PSD_TOP + 2}`, "none", { stroke: "rgb(255 255 255 / 26%)", "stroke-width": 4.4 }));
    const pair: [SVGElement, SVGElement] = [leaf(d - LEAF), leaf(d)];
    leaves.push(...pair);
    pairs.push(pair);
    front.push(post(d - LEAF - POST), post(d + LEAF));
    // to the next door: a holding door, the long panel, a holding door; beside the doors either side of you, an
    // advertisement instead
    const h1 = d + LEAF + POST, long = h1 + PANE + POST, h2 = long + 2 * U - POST + POST;
    front.push(...(d === CX - PITCH ? adPanel(h1, "cafe") : holding(h1, 1)), post(h1 + PANE), ...glass(long, 2 * U - POST), post(h2 - POST),
      ...(d === CX ? adPanel(h2, "bank") : holding(h2, -1)));
  }
  return { leaves, front, pairs };
}

// --- the wall above the doors: headers, signs ------------------------------------------------------------------

/** Over every screen door, a banner one door wide: the line, where the train goes (to the left: it comes in from the
 * right), and on red, "Please do not board when the light is flashing" in English and Malay, and Tamil and Chinese,
 * either side of a yellow triangle pointing down at the door light. Its top and bottom line up with the name signs. */
const SIGN_TOP = 22, SIGN_H = 22;
function doorBanner(c: number): SVGElement {
  const w = 2 * U - 2, x0 = c - w / 2, y0 = SIGN_TOP, INK = "#1d3a63";
  const small = (x: number, y: number, text: string, fit?: number) =>
    T(x, y, text, 1.2, "#fff", { ...MID, ...(fit ? { textLength: fit, lengthAdjust: "spacingAndGlyphs" } : {}) });
  return G({}, R(x0, y0, w, SIGN_H, "#f7f7f5", { stroke: "#aeb3b8", "stroke-width": 0.5 }),
    R(x0, y0, w, 4.4, GREEN), T(c, y0 + 3.3, "East West Line", 2.9, "#fff", { ...MID, ...BOLD, "letter-spacing": 0.1 }),
    P(`M ${c - 22.6} ${y0 + 9.1} h 5 M ${c - 22.6} ${y0 + 9.1} l 1.8 -1.6 M ${c - 22.6} ${y0 + 9.1} l 1.8 1.6`, "none",
      { stroke: INK, "stroke-width": 0.75, "stroke-linecap": "round" }),
    T(c - 15.6, y0 + 10.6, "To Changi Airport", 4.2, INK, { textLength: 37, lengthAdjust: "spacingAndGlyphs" }),
    R(x0, y0 + 13.6, w, SIGN_H - 13.6, "#d8322a"),
    P(`M ${c - 3} ${y0 + 15.2} h 6 l -3 5.2 z`, "#ffd21f", { stroke: "#a87e00", "stroke-width": 0.3, "stroke-linejoin": "round" }),
    small(c - 17.9, y0 + 17.4, "Please do not board when the light is flashing", 27), small(c - 17.9, y0 + 20.3, "Harap jangan naik bila lampu berkelip", 23),
    small(c + 17.9, y0 + 17.4, "விளக்கு மின்னும்போது ஏறாதீர்", 22), small(c + 17.9, y0 + 20.3, "灯光闪烁时请勿上车"));
}

/** The station's name sign, two doors wide, over a holding door, the long panel and the next holding door. */
function nameSign(c: number): SVGElement {
  const w = 4 * U - 2;
  return G({}, R(c - w / 2, SIGN_TOP, w, SIGN_H, "#eef0f1", { stroke: "#aeb3b8", "stroke-width": 0.5 }),
    R(c - 44, SIGN_TOP + 3.2, 21, 11.4, GREEN, { rx: 1.4 }), T(c - 33.5, SIGN_TOP + 11, "EW14", 6, "#fff", { ...MID, ...BOLD }),
    T(c - 18.5, SIGN_TOP + 10.4, "Raffles Place", 7.6, "#1d1d1d", BOLD), T(c - 18.5, SIGN_TOP + 18.6, "莱佛士坊", 5.2, "#333"));
}

function exitSign(c: number): SVGElement {
  const man = (x: number) => P(`M ${x} 49.6 a 0.9 0.9 0 1 1 0.01 0 M ${x - 0.4} 50.8 l -1.6 1.4 l 0.6 0.5 l 1 -0.8 l -0.4 2 l -1.6 1.7 l 0.6 0.5 l 1.8 -1.6 l 0.8 1 l 0.4 1.6 l 0.8 -0.2 l -0.5 -2 l -0.7 -1 l 0.3 -1.4 l 0.7 0.8 l 1.4 0.3 l 0.1 -0.7 l -1.2 -0.3 z`, "#fff");
  return G({}, R(c - 28, 47.2, 56, 9.6, "#0f8a43", { rx: 0.8, stroke: "#ffffff", "stroke-width": 0.5 }),
    P(`M ${c - 25.4} 52 l 2.6 -2.2 v 1.4 h 2 v 1.6 h -2 v 1.4 z`, "#fff"), P(`M ${c + 25.4} 52 l -2.6 -2.2 v 1.4 h -2 v 1.6 h 2 v 1.4 z`, "#fff"),
    man(c - 16.4), T(c + 3, 51.4, "EMERGENCY EXIT", 2.9, "#fff", { ...MID, ...BOLD }), T(c + 3, 55.2, "紧急出口 · PINTU KECEMASAN", 2.1, "#fff", MID),
    C(c + 33, 51.8, 2.6, "#d32f2f", { stroke: "#8e1d1d", "stroke-width": 0.6 }), C(c + 33, 51.8, 1.1, "#f26363"));
}

function wallAndHeader(): { parts: SVGElement[]; lamps: SVGElement[] } {
  const out: SVGElement[] = [R(0, WALL_TOP, W, HEADER - WALL_TOP, "#d8dbde"), R(0, WALL_TOP, W, 1.6, "rgb(0 0 0 / 12%)")];
  for (let x = 0; x < W; x += 95) out.push(R(x, WALL_TOP, 0.8, HEADER - WALL_TOP, "#c2c6ca"));
  out.push(R(0, HEADER - 1.6, W, 1.6, "#b2b7bc"), R(0, HEADER, W, PSD_TOP - HEADER, STEEL), R(0, HEADER, W, 1, STEEL_LIGHT), R(0, PSD_TOP - 1, W, 1, STEEL_DARK));
  const lamps: SVGElement[] = [];
  doors.forEach((d, i) => {
    // a banner over every door, and over every other stretch to the next door the station's name (the clock hangs
    // in front of a bare one)
    out.push(doorBanner(d));
    if ((i - 7) % 2 === 0) out.push(nameSign(d + PITCH / 2));
    out.push(R(d - 6, 48, 12, 6.6, "#555a60", { rx: 1 }));
    const lamp = C(d, 51.3, 1.9, "#3a3d42", { class: "cmu-lamp" });
    lamps.push(lamp);
    out.push(lamp);
    if (i % 3 === 1) out.push(exitSign(d + PITCH / 2));
  });
  return { parts: out, lamps };
}

// --- ceiling and floor -------------------------------------------------------------------------------------------

function ceiling(): SVGElement[] {
  const top = ceilY(0), far = DIST - ((CEILING_H - EYE) * FOCAL) / HORIZON;         // where the ceiling leaves the top of the view
  const out: SVGElement[] = [R(0, 0, W, top + 0.4, "#e8e7e3")];
  for (const v of [0.1, 0.25, 0.4]) out.push(R(0, ceilY(v) - 0.3, W, 0.6, "#d3d1cc"));
  for (let u = CX - 1500; u <= CX + 1500; u += 48) {
    const [x0] = at(u, 0), x1 = CX + ((u - CX) * DIST) / (DIST - far);
    out.push(P(`M ${x0.toFixed(1)} ${top.toFixed(1)} L ${x1.toFixed(1)} 0`, "none", { stroke: "#d6d4cf", "stroke-width": 0.6 }));
  }
  // long fluorescent strips along the platform, in lengths, glowing
  for (const [y, hh] of [[ceilY(0.12), 1.4], [ceilY(0.37), 2.4]] as const) {
    out.push(R(0, y - hh * 1.6, W, hh * 4.2, "rgb(255 252 235 / 35%)"));
    for (let x = 6; x < W; x += 170) out.push(R(x, y - hh / 2, 150, hh, "#fffdf3", { rx: hh / 2 }));
  }
  for (const x of [CX - 760, CX - 95, CX + 570]) {                    // CCTV domes
    const y = ceilY(0.24);
    out.push(R(x - 4.5, y - 0.6, 9, 1.2, "#f4f4f2"), P(`M ${x - 3.4} ${y + 0.6} a 3.4 2.8 0 0 0 6.8 0 z`, "#2b2e33"), C(x - 0.8, y + 1.6, 0.6, "#6e7d8c"));
  }
  return out;
}

function floor(rand: () => number): SVGElement[] {
  const out: SVGElement[] = [R(0, BASE, W, HEIGHT - BASE, "#d3cec5")];
  const speck = ["#b8b2a8", "#a19a8f", "#e9e5dd", "#8f8178", "#c6bfb4"];
  const nearest = DIST - (EYE * FOCAL) / (HEIGHT + 2 - HORIZON);                     // the floor at the bottom of the view
  for (let i = 0; i < 2200; i++) {
    const v = 0.15 + rand() * (nearest - 0.15);
    out.push(C(rand() * W, floorY(v), (0.3 * DIST) / (DIST - v), speck[i % speck.length]));
  }
  out.push(R(0, BASE - 0.6, W, 1.4, "#a8adb2"), R(0, BASE + 0.8, W, floorY(0.15) - BASE - 0.8, "#8e6457"));
  for (const v of [0.6, 1.2]) out.push(R(0, floorY(v) - 0.3, W, 0.6, "rgb(0 0 0 / 9%)"));
  for (let u = CX - 1300; u <= CX + 1300; u += 36) {
    const [x0, y0] = at(u, 0.15), [x1, y1] = at(u, nearest);
    out.push(P(`M ${x0.toFixed(1)} ${y0.toFixed(1)} L ${x1.toFixed(1)} ${y1.toFixed(1)}`, "none", { stroke: "rgb(0 0 0 / 7%)", "stroke-width": 0.6 }));
  }
  // tactile paving, as on the platforms: a road of square blocks of raised bars along the platform and, a little way out
  // from each door, a square of studs twice their size, the road along its near half. It is drawn shallower than true
  // depth, so the squares read as squares lying on the floor.
  const BLOCK = PITCH / 10, FAR = 0.53, HALF = 0.73, NEAR = 0.89;
  const quad = (u0: number, u1: number, v0: number, v1: number, fill: string) => {
    const [a, ya] = at(u0, v0), [b] = at(u1, v0), [c, yc] = at(u1, v1), [e] = at(u0, v1);
    return P(`M ${a.toFixed(1)} ${ya.toFixed(1)} L ${b.toFixed(1)} ${ya.toFixed(1)} L ${c.toFixed(1)} ${yc.toFixed(1)} L ${e.toFixed(1)} ${yc.toFixed(1)} Z`, fill);
  };
  for (let j = -80; j < 80; j++) {
    if ([0, 9].includes(((j % 10) + 10) % 10)) continue;                      // a door's square
    const u = CX + j * BLOCK;
    out.push(quad(u + 0.5, u + BLOCK - 0.5, HALF, NEAR, "#bdb7ad"));
    for (const f of [0.2, 0.5, 0.8]) {
      const v = HALF + (NEAR - HALF) * f, y = floorY(v), [x0] = at(u + 2.6, v), [x1] = at(u + BLOCK - 2.6, v);
      out.push(R(x0, y - 0.5, x1 - x0, 1, "#979ca2", { rx: 0.5 }), R(x0 + 0.5, y - 0.5, x1 - x0 - 1, 0.35, "#eef0f2"));
    }
  }
  for (const d of doors) {
    out.push(quad(d - BLOCK, d + BLOCK, FAR, NEAR, "#bdb7ad"));
    for (let r = 0; r < 5; r++) {
      const v = FAR + ((NEAR - FAR) * (r + 0.5)) / 5, y = floorY(v), k = 1 + SPREAD * (DIST / (DIST - v) - 1);
      for (let c = 0; c < 10; c++) {
        const [x] = at(d - BLOCK + ((c + 0.5) * BLOCK) / 5, v);
        out.push(svg("ellipse", { cx: x, cy: y, rx: 1.05 * k, ry: 0.6 * k, fill: "#979ca2" }),
          svg("ellipse", { cx: x - 0.25, cy: y - 0.2, rx: 0.45 * k, ry: 0.24 * k, fill: "#eef0f2" }));
      }
    }
  }
  return out;
}

/** A clock hanging from the ceiling, showing the time the wait began. */
function clock(x: number): SVGElement {
  const now = new Date(), mins = now.getMinutes(), hrs = (now.getHours() % 12) + mins / 60;
  const hand = (deg: number, len: number, wdt: number) => svg("line", { x1: x, y1: 31, x2: x + len * Math.sin((deg * Math.PI) / 180), y2: 31 - len * Math.cos((deg * Math.PI) / 180),
    stroke: "#1d1d1d", "stroke-width": wdt, "stroke-linecap": "round" });
  const ticks: SVGElement[] = [];
  for (let i = 0; i < 12; i++) {
    const a = (i * 30 * Math.PI) / 180;
    ticks.push(svg("line", { x1: x + 7.2 * Math.sin(a), y1: 31 - 7.2 * Math.cos(a), x2: x + 8.2 * Math.sin(a), y2: 31 - 8.2 * Math.cos(a), stroke: "#333", "stroke-width": i % 3 ? 0.4 : 0.8 }));
  }
  return G({}, R(x - 0.7, 0, 1.4, 21.5, "#8d9298"), R(x - 3, 19.5, 6, 2.4, "#8d9298", { rx: 0.8 }), C(x, 31, 10.2, "#2b2e33"), C(x, 31, 9, "#fbfbf8"),
    ...ticks, hand(hrs * 30, 4.6, 1.1), hand(mins * 6, 7, 0.7), C(x, 31, 0.8, "#1d1d1d"));
}

function platformScene(): { bg: SVGSVGElement; train: SVGElement; trainDoors: [SVGElement, SVGElement][]; screenDoors: [SVGElement, SVGElement][]; lamps: SVGElement[] } {
  const rand = seeded(14);
  const { g: trainG, doors: trainDoors } = train();
  const psd = screenDoors();
  const wall = wallAndHeader();
  const bg = svg("svg", { class: "cm-bg", width: W, height: HEIGHT, viewBox: `0 0 ${W} ${HEIGHT}`, "aria-hidden": "true" },
    G({ transform: `translate(0 ${SHIFT})` }, ...tunnel(), trainG, ...psd.leaves, ...psd.front, ...wall.parts),
    ...ceiling(), ...floor(rand), G({ transform: `translate(0 ${SHIFT})` }, clock(CX + PITCH * 1.5)));
  return { bg, train: trainG, trainDoors, screenDoors: psd.pairs, lamps: wall.lamps };
}

// --- the loader -----------------------------------------------------------------------------------------------------

const OPEN = LEAF - 2, TRAIN_OPEN = 26;            // how far each door leaf slides

/** While a SQL query runs (Data → SQL). */
export function platformLoader(label: string): TrainLoader {
  const parts = platformScene();
  const scene = h("div", { class: "tl-scene cm-scene cmu-station", "aria-hidden": "true" }, parts.bg);
  const me = commuterPhone();
  scene.append(me.el);
  const place = (x: number) => parts.train.setAttribute("transform", `translate(${x.toFixed(1)} 0)`);
  const open = (t: number) => ([[parts.trainDoors, TRAIN_OPEN], [parts.screenDoors, OPEN]] as const).forEach(([list, by]) => list.forEach(([l, r]) => {
    l.setAttribute("transform", `translate(${(-by * t).toFixed(2)} 0)`); r.setAttribute("transform", `translate(${(by * t).toFixed(2)} 0)`);
  }));
  const lamps = (on: boolean) => parts.lamps.forEach((l) => l.classList.toggle("closing", on));
  if (moving()) {
    let last = performance.now();
    const frame = (now: number) => {
      if (!scene.isConnected) return;
      me.tick(Math.min(0.05, (now - last) / 1000));
      last = now;
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  } else me.still();

  const ending = async (missed: boolean): Promise<void> => {
    if (!moving() || !arrivalWanted(scene)) return;
    const half = scene.clientWidth / 2, from = CX + half + 40;
    place(from);
    await tween(scene, 4200, (t) => place(lerp(from, TRAIN_STOP, Math.sin((Math.PI / 2) * t))));     // braking to a stop
    await sleep(300);
    lamps(true);
    await tween(scene, 700, open);
    lamps(false);
    if (!missed) {
      await tween(scene, 700, (t) => me.lower(t));
      await sleep(450);
      return;
    }
    await sleep(1500);                                 // the doors are open; you are still playing
    lamps(true);
    await sleep(900);
    await tween(scene, 700, (t) => open(1 - t));
    lamps(false);
    await sleep(300);
    const gone = CX - half - TRAIN_LEN - 80;
    await tween(scene, 3400, (t) => place(lerp(TRAIN_STOP, gone, easeIn(t))));
    await tween(scene, 650, (t) => me.lower(t));       // and now you look up
    await sleep(450);
  };
  return loaderShell(label, scene, () => ending(false), () => ending(true));
}
