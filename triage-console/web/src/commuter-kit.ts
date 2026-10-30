// Shared parts of the Commuter animation pack: drawing helpers, timing, and you with your phone, in the first person.
//
// You are standing and looking ahead, phone held up in front of you, so only the phone, your hands and your shirt
// sleeves come up into view (not your legs or shoes). The phone tells a small story while the search runs: you scroll
// a social feed with your right thumb, swipe up to the home screen, tap Space Invaders, and the app opens; you turn
// the phone sideways and your left hand comes up to hold it too; the game loads, shows LEVEL 1 · GET READY, and you
// play from the first wave (clearing a wave goes on to the next level).
//
// Sizes follow the phone (54 x 108 px, about 7 x 14.5 cm): a thumb is about 2 cm wide, a wrist about 5.5 cm, and the
// forearms widen as they come towards you. Colours are fixed (an underground station and a phone screen look the same
// by day and night), so they are written inline rather than as theme tokens.

import { svg } from "./dom";

export const W = 2400, CX = 1200;                // backgrounds are wider than any window, centred on you
export const SANS = "Arial, Helvetica, sans-serif";
const MONO = "Consolas, 'Courier New', monospace";

type A = Record<string, unknown>;
export const R = (x: number, y: number, w: number, hh: number, fill: string, extra: A = {}) => svg("rect", { x, y, width: w, height: hh, fill, ...extra });
export const C = (cx: number, cy: number, r: number, fill: string, extra: A = {}) => svg("circle", { cx, cy, r, fill, ...extra });
export const P = (d: string, fill: string, extra: A = {}) => svg("path", { d, fill, ...extra });
export const T = (x: number, y: number, text: string, size: number, fill: string, extra: A = {}) =>
  svg("text", { x, y, fill, "font-size": size, "font-family": SANS, ...extra }, text);
export const G = (attrs: A, ...kids: (SVGElement | null | false | (SVGElement | null)[])[]) => svg("g", attrs, ...kids);

export const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
export const clamp01 = (t: number) => Math.max(0, Math.min(1, t));
export const easeOut = (t: number) => 1 - (1 - t) ** 2;
export const easeIn = (t: number) => t * t;
export const easeInOut = (t: number) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);
/** Progress from a to b seconds, eased in and out. */
const span = (t: number, a: number, b: number) => easeInOut(clamp01((t - a) / (b - a)));
export const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));
let uid = 0;
export const nextId = (prefix: string) => `${prefix}${++uid}`;

export function seeded(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Anything moving at all: not under Animations → None or the system's reduced motion. */
export function moving(): boolean {
  return document.documentElement.getAttribute("data-motion") !== "none" && !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

/** fn(t) for t from 0 to 1 over ms, on animation frames (a hidden tab gets no frames, so a timer finishes it). */
export function tween(scene: HTMLElement, ms: number, fn: (t: number) => void): Promise<void> {
  return new Promise((done) => {
    const began = performance.now();
    const safety = window.setTimeout(() => { fn(1); done(); }, ms + 400);
    const frame = (now: number) => {
      const t = Math.min(1, (now - began) / ms);
      fn(t);
      if (t < 1 && scene.isConnected) requestAnimationFrame(frame);
      else { window.clearTimeout(safety); done(); }
    };
    requestAnimationFrame(frame);
  });
}

/** Pixel art as one path: rows of "0"/"1", each pixel s wide. */
export function pix(rows: string[], s: number): string {
  let d = "";
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] !== "1") continue;
      let end = x;
      while (row[end + 1] === "1") end++;
      d += `M${(x * s).toFixed(2)} ${(y * s).toFixed(2)}h${((end - x + 1) * s).toFixed(2)}v${s.toFixed(2)}h${(-(end - x + 1) * s).toFixed(2)}z`;
      x = end;
    }
  });
  return d;
}

// --- the game's sprites (the classic shapes) ------------------------------------------------------------
const SQUID = [["00011000", "00111100", "01111110", "11011011", "11111111", "00100100", "01011010", "10100101"],
  ["00011000", "00111100", "01111110", "11011011", "11111111", "01011010", "10000001", "01000010"]];
const CRAB = [["00100000100", "00010001000", "00111111100", "01101110110", "11111111111", "10111111101", "10100000101", "00011011000"],
  ["00100000100", "10010001001", "10111111101", "11101110111", "11111111111", "01111111110", "00100000100", "01000000010"]];
const OCTOPUS = [["000011110000", "011111111110", "111111111111", "111001100111", "111111111111", "000110011000", "001101101100", "110000000011"],
  ["000011110000", "011111111110", "111111111111", "111001100111", "111111111111", "001110011100", "011001100110", "001100001100"]];
const BOOM = ["01000100", "00100100", "10011001", "00100100", "01000010", "10010001"];
const CANNON = ["0000001000000", "0000011100000", "0000011100000", "0111111111110", "1111111111111", "1111111111111", "1111111111111", "1111111111111"];
const UFO = ["0000011111100000", "0001111111111000", "0011111111111100", "0110110110110110", "1111111111111111", "0011100110011100", "0001000000001000"];

// --- the phone's screens ------------------------------------------------------------------------------------
// Portrait screens are 50 x 104; the game is landscape, 104 x 50.

const STATUS = (fill: string) => G({},
  T(4, 4.6, "9:41", 3.6, fill, { "font-weight": 700 }),
  R(36, 2.2, 0.8, 1.6, fill), R(37.2, 1.7, 0.8, 2.1, fill), R(38.4, 1.2, 0.8, 2.6, fill),
  P("M 41.2 2.2 q 1.4 -1.2 2.8 0 l -0.5 0.5 q -0.9 -0.8 -1.8 0 z M 41.9 3 q 0.7 -0.6 1.4 0 l -0.7 0.8 z", fill),
  R(45, 1.4, 3.6, 2.2, "none", { stroke: fill, "stroke-width": 0.35, rx: 0.6 }), R(45.5, 1.9, 2.4, 1.2, fill));

/** Small illustrations for the feed's posts (46 x 34). */
const ART: ((y: number) => SVGElement[])[] = [
  (y) => [R(0, y, 50, 22, "#7cc7f0"), R(0, y + 18, 50, 6, "#2f9fd0"), R(0, y + 24, 50, 12, "#f1d9a6"), C(40, y + 7, 4, "#fff4c2"),     // a beach and an orange van
    R(14, y + 17, 22, 12, "#f17d23", { rx: 3 }), R(16, y + 18.5, 7, 4, "#cbe8f6", { rx: 1 }), R(25, y + 18.5, 8, 4, "#cbe8f6", { rx: 1 }),
    R(13, y + 26, 24, 2, "#d9661a"), C(19, y + 30, 2.4, "#2b2b2b"), C(31, y + 30, 2.4, "#2b2b2b"), R(15, y + 13, 20, 3.4, "#57b06a", { rx: 1 })],
  (y) => [R(0, y, 50, 36, "#f6a15b"), R(0, y, 50, 14, "#f27d72"), C(25, y + 20, 7, "#ffd56b"),                                     // the bay at sunset
    R(0, y + 24, 50, 12, "#3a2f4f"), R(11, y + 12, 4, 14, "#2c2340"), R(18, y + 12, 4, 14, "#2c2340"), R(25, y + 12, 4, 14, "#2c2340"),
    P(`M 9 ${y + 12} h 22 l -2 -2.4 h -18 z`, "#2c2340"), R(36, y + 15, 3, 11, "#2c2340"), R(41, y + 18, 5, 8, "#2c2340")],
  (y) => [R(0, y, 50, 36, "#8a5a3c"), C(25, y + 18, 13, "#fafafa"), C(25, y + 18, 10.5, "#e8892f"),                                // a bowl of laksa
    C(21, y + 15, 2.4, "#fff3c4"), C(29, y + 20, 2.2, "#f26b4f"), C(24, y + 22, 2, "#f26b4f"), C(28, y + 13, 1.6, "#4f9a4a"),
    R(36, y + 4, 1.2, 26, "#d8b98f", { transform: `rotate(18 36 ${y + 17})` }), R(39, y + 4, 1.2, 26, "#d8b98f", { transform: `rotate(18 39 ${y + 17})` })],
  (y) => [R(0, y, 50, 36, "#c9d6df"), P(`M 15 ${y + 14} l 3 -8 l 4 6 z M 35 ${y + 14} l -3 -8 l -4 6 z`, "#7d7f86"),               // a cat
    C(25, y + 20, 11, "#8d8f96"), C(21, y + 18, 2, "#c7e86a"), C(29, y + 18, 2, "#c7e86a"), R(20.6, y + 16.6, 0.8, 2.8, "#222"), R(28.6, y + 16.6, 0.8, 2.8, "#222"),
    P(`M 24 ${y + 22} h 2 l -1 1.2 z`, "#f2a0a8"), R(0, y + 30, 50, 6, "#a7b6c0")],
  (y) => [R(0, y, 50, 36, "#9fd3f2"), P(`M 0 ${y + 26} L 13 ${y + 8} L 24 ${y + 22} L 33 ${y + 11} L 50 ${y + 26} Z`, "#7c69a8"),     // mountains and a lake
    P(`M 13 ${y + 8} l -3 4 h 6 z M 33 ${y + 11} l -2.6 3.4 h 5 z`, "#ffffff"), R(0, y + 26, 50, 10, "#4a8fc0"), R(4, y + 29, 14, 0.8, "#cbe6f7")],
  (y) => [R(0, y, 50, 36, "#6f4a33"), C(25, y + 18, 12, "#f4efe8"), C(25, y + 18, 9.5, "#a8683b"),                                // a latte
    P(`M 25 ${y + 24} c -6 -4 -6 -10 -2.4 -10 c 1.2 0 2 0.8 2.4 1.8 c 0.4 -1 1.2 -1.8 2.4 -1.8 c 3.6 0 3.6 6 -2.4 10 z`, "#f4e3cc")],
];

function feedApp(clipId: string): { el: SVGElement; scrollTo(y: number): void } {
  const posts: SVGElement[] = [];
  const POST = 62, N = ART.length;
  for (let copy = 0; copy < 2; copy++) for (let i = 0; i < N; i++) {
    const y = (copy * N + i) * POST;
    posts.push(G({},
      C(4, y + 3.4, 2.6, ["#f5a3b8", "#9cc9f2", "#b7e29a", "#f7cf7a", "#c6a8ef", "#f29c7a"][i]), R(9, y + 2.2, 14 + (i * 5) % 9, 1.8, "#262626"),
      R(46, y + 3, 0.6, 0.6, "#262626"), R(44.6, y + 3, 0.6, 0.6, "#262626"), R(47.4, y + 3, 0.6, 0.6, "#262626"),
      ...ART[i](y + 7),
      P(`M 4 ${y + 48} c -1.6 -1.8 -3.4 0.2 -1.8 1.8 l 1.8 1.8 l 1.8 -1.8 c 1.6 -1.6 -0.2 -3.6 -1.8 -1.8 z`, i % 2 ? "#ed4956" : "none",
        { stroke: i % 2 ? "#ed4956" : "#262626", "stroke-width": 0.5 }),
      P(`M 10.6 ${y + 46.6} a 2 2 0 1 1 -0.8 2.9 l -0.8 0.9 l 0.3 -1.3 a 2 2 0 0 1 1.3 -2.5 z`, "none", { stroke: "#262626", "stroke-width": 0.5 }),
      P(`M 15.4 ${y + 46.6} l 4 1.6 -4 1.6 1 -1.6 z`, "none", { stroke: "#262626", "stroke-width": 0.5 }),
      P(`M 44 ${y + 46.4} h 3 v 4.2 l -1.5 -1.2 l -1.5 1.2 z`, "none", { stroke: "#262626", "stroke-width": 0.5 }),
      R(2, y + 53, 16, 1.6, "#262626"), R(2, y + 56.4, 30 + (i * 7) % 14, 1.3, "#9a9a9a")));
  }
  const list = G({}, ...posts);
  const ring = (x: number, i: number) => G({},
    C(x, 21.5, 4.4, "none", { stroke: i === 0 ? "#c7c7c7" : "#e1306c", "stroke-width": 0.8 }),
    C(x, 21.5, 3.4, ["#d9d9d9", "#f5a3b8", "#9cc9f2", "#b7e29a", "#f7cf7a"][i]));
  const navIcon = [
    P("M 6 98 l 3.4 -3 3.4 3 v 3.4 h -6.8 z", "#262626"), C(17, 98.4, 2.1, "none", { stroke: "#262626", "stroke-width": 0.6 }),
    R(23, 96.2, 4.4, 4.4, "none", { stroke: "#262626", "stroke-width": 0.6, rx: 1.2 }), P("M 35 97 c -1.6 -1.8 -3.4 0.2 -1.8 1.8 l 1.8 1.8 l 1.8 -1.8 c 1.6 -1.6 -0.2 -3.6 -1.8 -1.8 z", "none", { stroke: "#262626", "stroke-width": 0.6 }),
    C(44, 98.4, 2.2, "#f2a0a8")];
  const el = G({ "clip-path": `url(#${clipId})` },
    R(0, 0, 50, 104, "#ffffff"), list,
    R(0, 0, 50, 29, "#ffffff"), STATUS("#111"),
    P("M 4 11.6 q 1.6 -3.6 3.2 0 t 3.2 0 t 3.2 0 t 3.2 0", "none", { stroke: "#262626", "stroke-width": 0.9, "stroke-linecap": "round" }),
    P("M 40.5 8.8 c -1.4 -1.6 -3 0.2 -1.6 1.6 l 1.6 1.6 l 1.6 -1.6 c 1.4 -1.4 -0.2 -3.2 -1.6 -1.6 z", "none", { stroke: "#262626", "stroke-width": 0.55 }),
    P("M 44.4 8.6 l 3.6 1.4 -3.6 1.4 0.9 -1.4 z", "none", { stroke: "#262626", "stroke-width": 0.55 }),
    ...[5, 15, 25, 35, 45].map(ring), R(0, 28.6, 50, 0.3, "#e6e6e6"),
    R(0, 93, 50, 11, "#ffffff"), R(0, 93, 50, 0.3, "#e6e6e6"), ...navIcon, R(17, 101.6, 16, 1.1, "#111", { rx: 0.55 }));
  return { el, scrollTo(y) { list.setAttribute("transform", `translate(0 ${(30 - (y % (N * POST))).toFixed(2)})`); } };
}

// The home screen: wallpaper, widgets, a grid of apps and the dock. The feed app is in the dock; Space Invaders is in
// the third row.
export const INVADERS_ICON = { x: 27.6, y: 56, s: 9 };
const FEED_ICON = { x: 28.4, y: 89, s: 9 };

function appIcon(x: number, y: number, bg: string, glyph: SVGElement[]): SVGElement {
  return G({}, R(x, y, 9, 9, bg, { rx: 2.2 }), ...glyph, R(x + 1, y + 10.4, 7, 0.9, "rgb(255 255 255 / 80%)", { rx: 0.45 }));
}

function homeScreen(clipId: string, gradId: string): { el: SVGElement; icons: SVGElement; invaders: SVGElement } {
  const icons: SVGElement[] = [];
  const cols = [4.6, 16.1, 27.6, 39.1], rows = [30, 43, 56, 69];
  const glyphs: [string, (x: number, y: number) => SVGElement[]][] = [
    ["#34c759", (x, y) => [P(`M ${x + 2.6} ${y + 2.4} c 0.4 2.8 2.4 4.6 4 4.2 l 0.4 -1.2 -1.4 -0.8 -0.7 0.8 c -0.8 -0.4 -1.6 -1.2 -2 -2 l 0.8 -0.7 -0.8 -1.4 z`, "#fff")]],
    ["#ffffff", (x, y) => [R(x, y, 9, 2.6, "#ff3b30", { rx: 1 }), T(x + 4.5, y + 7.6, "8", 4.6, "#111", { "text-anchor": "middle", "font-weight": 700 })]],
    ["#8e8e93", (x, y) => [C(x + 4.5, y + 4.5, 2.6, "none", { stroke: "#fff", "stroke-width": 0.9 }), C(x + 4.5, y + 4.5, 0.8, "#fff")]],
    ["#ff9500", (x, y) => [R(x + 2, y + 2, 5, 5, "#fff", { rx: 0.6 }), R(x + 2.8, y + 3.2, 3.4, 0.5, "#ff9500"), R(x + 2.8, y + 4.5, 3.4, 0.5, "#ff9500")]],
    ["#007aff", (x, y) => [R(x + 1.8, y + 2.6, 5.4, 3.8, "#fff", { rx: 0.5 }), P(`M ${x + 1.8} ${y + 2.8} l 2.7 2 2.7 -2`, "none", { stroke: "#007aff", "stroke-width": 0.5 })]],
    ["#5ac8fa", (x, y) => [C(x + 3.6, y + 3.6, 1.8, "#ffd60a"), P(`M ${x + 3} ${y + 7} h 4.6 a 1.4 1.4 0 0 0 -0.4 -2.8 a 2 2 0 0 0 -3.8 0.6 a 1.1 1.1 0 0 0 -0.4 2.2 z`, "#fff")]],
    ["#111111", (x, y) => [C(x + 4.5, y + 4.5, 3, "#fff"), R(x + 4.3, y + 2.2, 0.4, 2.5, "#111"), R(x + 4.3, y + 4.3, 1.8, 0.4, "#111")]],
    ["#636366", (x, y) => [C(x + 4.5, y + 4.5, 2.4, "none", { stroke: "#d1d1d6", "stroke-width": 1.4, "stroke-dasharray": "0.9 0.6" }), C(x + 4.5, y + 4.5, 1, "#d1d1d6")]],
    ["#30b0c7", (x, y) => [P(`M ${x + 2} ${y + 7} l 2.4 -5 l 2.6 5 z`, "#fff"), C(x + 6.6, y + 3, 0.9, "#fff")]],
    ["#ff2d55", (x, y) => [P(`M ${x + 3.6} ${y + 6.6} v -4.4 l 3 -0.8 v 4`, "none", { stroke: "#fff", "stroke-width": 0.7 }), C(x + 3, y + 6.6, 1, "#fff"), C(x + 6, y + 5.8, 1, "#fff")]],
    ["#111111", (x, y) => [P(pix(CRAB[0], 0.62), "#5dff7a", { transform: `translate(${x + 1.1} ${y + 2})` })]],                     // Space Invaders
    ["#ffcc00", (x, y) => [R(x + 2, y + 2, 5, 5.4, "#fff", { rx: 0.5 }), R(x + 2.6, y + 3, 3.8, 0.4, "#c7a100"), R(x + 2.6, y + 4.2, 3.8, 0.4, "#c7a100")]],
    ["#5856d6", (x, y) => [P(`M ${x + 4.5} ${y + 1.8} l 2.6 4.4 h -5.2 z`, "#fff"), R(x + 3.6, y + 6.4, 1.8, 1, "#fff")]],
    ["#34c759", (x, y) => [P(`M ${x + 2} ${y + 3} h 5 v 3 h -3 l -1.4 1.2 v -1.2 h -0.6 z`, "#fff")]],
    ["#af52de", (x, y) => [R(x + 2.2, y + 2.4, 4.6, 4.2, "none", { stroke: "#fff", "stroke-width": 0.7, rx: 0.8 }), C(x + 4.5, y + 4.5, 1.1, "#fff")]],
    ["#ff9f0a", (x, y) => [R(x + 2, y + 5, 1.2, 2, "#fff"), R(x + 3.9, y + 3.5, 1.2, 3.5, "#fff"), R(x + 5.8, y + 2, 1.2, 5, "#fff")]],
  ];
  glyphs.forEach(([bg, glyph], i) => { const x = cols[i % 4], y = rows[Math.floor(i / 4)]; icons.push(appIcon(x, y, bg, glyph(x, y))); });
  const dock = G({}, R(2.2, 86.6, 45.6, 13.2, "rgb(255 255 255 / 28%)", { rx: 4.4 }),
    appIcon(5.4, 89, "#34c759", glyphs[0][1](5.4, 89)), appIcon(16.9, 89, "#007aff", glyphs[4][1](16.9, 89)),
    G({}, R(FEED_ICON.x, FEED_ICON.y, 9, 9, "#e1306c", { rx: 2.2 }), R(FEED_ICON.x, FEED_ICON.y + 4.5, 9, 4.5, "#f77737", { rx: 2.2 }),
      R(FEED_ICON.x + 2, FEED_ICON.y + 2, 5, 5, "none", { stroke: "#fff", "stroke-width": 0.8, rx: 1.6 }), C(FEED_ICON.x + 4.5, FEED_ICON.y + 4.5, 1.2, "none", { stroke: "#fff", "stroke-width": 0.7 })),
    appIcon(39.9, 89, "#8e8e93", glyphs[2][1](39.9, 89)));
  const grid = G({}, ...icons, dock);
  const el = G({ "clip-path": `url(#${clipId})` },
    svg("defs", {}, svg("linearGradient", { id: gradId, x1: 0, y1: 0, x2: 0.3, y2: 1 },
      svg("stop", { offset: "0", "stop-color": "#203a6b" }), svg("stop", { offset: "0.55", "stop-color": "#6b3fa0" }), svg("stop", { offset: "1", "stop-color": "#f08a5d" }))),
    R(0, 0, 50, 104, `url(#${gradId})`), STATUS("#fff"),
    R(4.6, 9, 40.8, 15.4, "rgb(255 255 255 / 22%)", { rx: 3.4 }),
    T(8, 15.4, "THURSDAY", 2.8, "#ffd2c4", { "font-weight": 700 }), T(8, 22.4, "8 October", 4.4, "#fff", { "font-weight": 700 }),
    C(38.6, 16.6, 3, "#ffd60a"), T(32.6, 22.6, "31°", 3.2, "#fff"),
    grid, C(23, 83.6, 0.7, "#fff"), C(25.4, 83.6, 0.7, "rgb(255 255 255 / 45%)"), C(27.8, 83.6, 0.7, "rgb(255 255 255 / 45%)"),
    R(17, 101.6, 16, 1.1, "#fff", { rx: 0.55 }));
  return { el, icons: grid, invaders: icons[10] };
}

/** Space Invaders (landscape, 104 x 50): its splash, a level banner, and the game, played from wave 1. */
function invadersApp(): { el: SVGElement; splash(p: number): void; banner(level: number, t: number): void; play(dt: number): void;
  readonly cannon: number; readonly firing: number; readonly playing: boolean } {
  const black = R(0, 0, 104, 50, "#05060b");
  // the splash
  const bar = R(27, 35, 0, 2.6, "#5dff7a");
  const splash = G({},
    P(pix(CRAB[0], 1.15), "#5dff7a", { transform: "translate(45.7 3)" }),
    T(52, 21.6, "SPACE", 7.6, "#ffffff", { "text-anchor": "middle", "font-family": MONO, "font-weight": 700 }),
    T(52, 30, "INVADERS", 7.6, "#5dff7a", { "text-anchor": "middle", "font-family": MONO, "font-weight": 700 }),
    R(27, 35, 50, 2.6, "none", { stroke: "#ffffff", "stroke-width": 0.4 }), bar,
    T(52, 43.4, "LOADING", 3, "#9aa3b5", { "text-anchor": "middle", "font-family": MONO, "letter-spacing": 0.6 }));
  // the level banner
  const levelText = T(52, 24, "LEVEL 1", 9, "#ffffff", { "text-anchor": "middle", "font-family": MONO, "font-weight": 700 });
  const ready = T(52, 32.6, "GET READY", 3.6, "#5dff7a", { "text-anchor": "middle", "font-family": MONO, "letter-spacing": 0.5 });
  const banner = G({ visibility: "hidden" }, levelText, ready);
  // the game
  const score = T(2, 4.4, "SCORE 0000", 3.2, "#ffffff", { "font-family": MONO });
  const lvl = T(52, 4.4, "LV 1", 3.2, "#5dff7a", { "font-family": MONO, "text-anchor": "middle" });
  const lifeIcons = [0, 1, 2].map((i) => P(pix(CANNON, 0.32), "#5dff7a", { transform: `translate(${88 + i * 5} 1.6)` }));
  const kinds = [SQUID, CRAB, CRAB, OCTOPUS], widths = [8, 11, 11, 12], points = [30, 20, 20, 10];
  const PX = 0.72, COLS = 8, CELL = 10.5, ROWH = 6, TOP = 9.6, LOWEST = 3;
  const shapes = kinds.map((k) => [pix(k[0], PX), pix(k[1], PX)]), boomD = pix(BOOM, PX), gunD = pix(CANNON, 0.56), gunBoomD = pix(BOOM, 0.56);
  const aliens: { el: SVGElement; row: number; col: number; alive: boolean; boom: number }[] = [];
  const formation = G({});
  for (let row = 0; row < 4; row++) for (let col = 0; col < COLS; col++) {
    const el = P(pix(kinds[row][0], PX), ["#ff6ad5", "#5ee1ff", "#5ee1ff", "#b9ff66"][row]);
    formation.append(el);
    aliens.push({ el, row, col, alive: true, boom: 0 });
  }
  const cannon = P(pix(CANNON, 0.56), "#5dff7a");
  const shot = R(0, 0, 0.6, 2.4, "#ffffff");
  const bombs = [0, 1].map(() => P("M 0 0 l 0.6 0.6 -0.6 0.6 0.6 0.6 -0.6 0.6", "none", { stroke: "#ffe066", "stroke-width": 0.5 }));
  const ufo = P(pix(UFO, 0.42), "#ff4d4d");
  const bunkers = [17, 40, 63, 86].map((x) => P(`M ${x - 4.5} 41.6 v -2.6 q 0 -2 2 -2 h 5 q 2 0 2 2 v 2.6 h -2.2 v -1.3 h -4.6 v 1.3 z`, "#3bd35a"));
  const game = G({ visibility: "hidden" }, score, lvl, ...lifeIcons, ...bunkers, formation, shot, ...bombs, ufo, cannon, R(0, 47.6, 104, 0.4, "#3bd35a"));
  const el = G({}, black, splash, banner, game);

  const st = { level: 1, fx: 10, fy: 0, dir: 1, step: 0, frame: 0, gun: 52, target: 52, shotY: -5, shotX: 0, points: 0, lives: 3,
    bombX: [0, 0], bombY: [-5, -5], bombWait: 1.2, ufoX: -20, ufoDir: 1, ufoWait: 6, firing: 0, pause: 0, playing: false, hurt: 0 };
  const alive = () => aliens.filter((a) => a.alive);
  const ax = (a: { col: number; row: number }) => st.fx + a.col * CELL + (CELL - widths[a.row] * PX) / 2;
  const ay = (a: { row: number }) => TOP + st.fy + a.row * ROWH;
  const newWave = () => {
    aliens.forEach((a) => { a.alive = true; a.boom = 0; a.el.setAttribute("visibility", "visible"); });
    st.fx = 10; st.fy = Math.min(LOWEST, st.level - 1); st.dir = 1; st.step = 0;
    lvl.textContent = `LV ${st.level}`;
  };
  const drawAliens = () => aliens.forEach((a) => {
    a.el.setAttribute("d", a.boom > 0 ? boomD : shapes[a.row][st.frame]);
    a.el.setAttribute("transform", `translate(${ax(a).toFixed(2)} ${ay(a).toFixed(2)})`);
  });
  const draw = () => {
    drawAliens();
    cannon.setAttribute("transform", `translate(${(st.gun - 3.64).toFixed(2)} 42.6)`);
    cannon.setAttribute("d", st.hurt > 0 ? gunBoomD : gunD);
    shot.setAttribute("transform", `translate(${st.shotX.toFixed(2)} ${st.shotY.toFixed(2)})`);
    shot.setAttribute("visibility", st.shotY > 0 ? "visible" : "hidden");
    bombs.forEach((b, i) => { b.setAttribute("transform", `translate(${st.bombX[i].toFixed(2)} ${st.bombY[i].toFixed(2)})`); b.setAttribute("visibility", st.bombY[i] > 0 ? "visible" : "hidden"); });
    ufo.setAttribute("transform", `translate(${st.ufoX.toFixed(2)} 5.4)`);
    ufo.setAttribute("visibility", st.ufoX > -8 && st.ufoX < 104 ? "visible" : "hidden");
    lifeIcons.forEach((l, i) => l.setAttribute("visibility", i < st.lives ? "visible" : "hidden"));
  };
  draw();

  const showLevel = (level: number, t: number) => {
    splash.setAttribute("visibility", "hidden"); game.setAttribute("visibility", "hidden"); banner.setAttribute("visibility", "visible");
    levelText.textContent = `LEVEL ${level}`;
    ready.setAttribute("visibility", Math.floor(t * 4) % 2 ? "hidden" : "visible");
  };
  return {
    el,
    splash(p) {
      splash.setAttribute("visibility", "visible"); banner.setAttribute("visibility", "hidden"); game.setAttribute("visibility", "hidden");
      bar.setAttribute("width", (50 * clamp01(p)).toFixed(2));
    },
    banner(level, t) { showLevel(level, t); },
    play(dt) {
      if (!st.playing) { st.playing = true; newWave(); }
      st.firing = Math.max(0, st.firing - dt);
      if (st.pause > 0) {                                           // the next level's banner, between waves
        st.pause -= dt;
        showLevel(st.level, 1.2 - st.pause);
        if (st.pause <= 0) newWave();
        return;
      }
      banner.setAttribute("visibility", "hidden"); splash.setAttribute("visibility", "hidden"); game.setAttribute("visibility", "visible");
      const left = alive();
      aliens.forEach((a) => { if (a.boom > 0) { a.boom -= dt; if (a.boom <= 0) a.el.setAttribute("visibility", "hidden"); } });
      // the formation steps sideways, faster as it thins out and at higher levels, and down at each edge
      st.step += dt;
      const interval = Math.max(0.07, (0.5 - 0.012 * (32 - left.length)) * (1 - 0.1 * (st.level - 1)));
      if (st.step > interval && left.length) {
        st.step = 0; st.frame ^= 1;
        const xs = left.map(ax), minX = Math.min(...xs), maxX = Math.max(...left.map((a) => ax(a) + widths[a.row] * PX));
        if ((st.dir > 0 && maxX + 1.2 > 102) || (st.dir < 0 && minX - 1.2 < 2)) { st.dir *= -1; st.fy = Math.min(LOWEST, st.fy + 1); }   // stops short of the bunkers
        else st.fx += 1.2 * st.dir;
      }
      // your cannon: chases a column, steps aside from a bomb, fires when lined up
      if (st.hurt > 0) st.hurt -= dt;
      else {
        const danger = st.bombY.some((y, i) => y > 24 && Math.abs(st.bombX[i] - st.gun) < 4);
        if (danger) st.target = st.gun + (st.gun < 52 ? 9 : -9);
        st.gun += Math.sign(st.target - st.gun) * Math.min(Math.abs(st.target - st.gun), dt * 30);
        if (Math.abs(st.target - st.gun) < 0.4) {
          if (st.shotY <= 0) { st.shotX = st.gun - 0.3; st.shotY = 41; st.firing = 0.14; }
          const pick = left[Math.floor(Math.random() * left.length)];
          st.target = pick ? ax(pick) + (widths[pick.row] * PX) / 2 : 52;
        }
      }
      if (st.shotY > 0) {
        st.shotY -= dt * 75;
        for (const a of left) {
          const x = ax(a), y = ay(a);
          if (st.shotX > x - 0.4 && st.shotX < x + widths[a.row] * PX + 0.4 && st.shotY < y + 6 && st.shotY > y - 1) {
            a.alive = false; a.boom = 0.22; st.shotY = -5; st.points += points[a.row];
            break;
          }
        }
        if (st.shotY > 0 && st.shotY < 8.6 && st.ufoX > -8 && Math.abs(st.shotX - (st.ufoX + 3.4)) < 3.6) { st.points += 100; st.ufoX = 200; st.shotY = -5; }
        score.textContent = `SCORE ${String(st.points).padStart(4, "0")}`;
      }
      // bombs from the bottom of a column
      st.bombWait -= dt;
      const free = st.bombY.findIndex((y) => y <= 0);
      if (st.bombWait <= 0 && free >= 0 && left.length) {
        const shooter = left[Math.floor(Math.random() * left.length)];
        const bottom = left.filter((a) => a.col === shooter.col).sort((a, b) => b.row - a.row)[0];
        st.bombX[free] = ax(bottom) + (widths[bottom.row] * PX) / 2; st.bombY[free] = ay(bottom) + 6;
        st.bombWait = 0.9 + Math.random() * 0.8;
      }
      st.bombY.forEach((y, i) => {
        if (y <= 0) return;
        st.bombY[i] = y + dt * 24;
        const by = st.bombY[i], bx = st.bombX[i];
        if (by > 37 && by < 41.6 && [17, 40, 63, 86].some((x) => Math.abs(bx - x) < 4.5)) st.bombY[i] = -5;        // hits a bunker
        else if (by > 42.6 && Math.abs(bx - st.gun) < 3.4 && st.hurt <= 0) { st.bombY[i] = -5; st.hurt = 0.6; st.lives = st.lives > 1 ? st.lives - 1 : 3; }
        else if (by > 47.4) st.bombY[i] = -5;
      });
      // now and then the saucer crosses the top
      st.ufoWait -= dt;
      if (st.ufoWait <= 0 && (st.ufoX < -8 || st.ufoX > 104)) { st.ufoDir = Math.random() < 0.5 ? 1 : -1; st.ufoX = st.ufoDir > 0 ? -7 : 104; st.ufoWait = 7 + Math.random() * 5; }
      if (st.ufoX > -8 && st.ufoX < 104) st.ufoX += st.ufoDir * dt * 18;
      if (!left.length && aliens.every((a) => a.boom <= 0)) { st.level++; st.pause = 1.2; }
      draw();
    },
    get cannon() { return st.gun; },
    get firing() { return st.firing; },
    get playing() { return st.playing; },
  };
}

// --- you: your hands and sleeves, and the phone ---------------------------------------------------------------

export const PHONE_Y = 116;                   // the phone's centre, drawn in a 400 x 186 box (x 0 is the middle of the view)
const BOX_H = 200, LIFT = BOX_H - 186;        // ... and set at the bottom of the scene's 200 px
const SKIN = "#e8b18c", SKIN_SHADE = "#cf946f", SKIN_EDGE = "#b27654", NAIL = "#f4d6c6", NAIL_EDGE = "#ddb3a0";
const SHIRT = "#b4cbe6", SHIRT_SHADE = "#97b2d6", SHIRT_FOLD = "#8ba7cd", CUFF = "#a6bfe0";
const TIMES = { swipeMove: 2.2, swipe: 2.42, home: 2.8, reach: 3.0, press: 3.32, launch: 3.5, launched: 3.85, rotate: 3.95, rotated: 4.65, ready: 6.0, play: 6.9 };
const FLICKS = [0.55, 1.45];

/** A thumb, from its root (bx, by) to the middle of its pad (tx, ty), with its nail. */
function thumb(): { el: SVGElement; set(bx: number, by: number, tx: number, ty: number): void } {
  const body = R(-4, -6.4, 0, 12.8, SKIN, { rx: 6.4, stroke: SKIN_EDGE, "stroke-width": 0.6 });
  const joint = P("", "none", { stroke: SKIN_SHADE, "stroke-width": 0.7, "stroke-linecap": "round" });
  const nail = R(0, -3.7, 7.2, 7.4, NAIL, { rx: 3.2, stroke: NAIL_EDGE, "stroke-width": 0.4 });
  const el = G({}, body, joint, nail);
  return {
    el,
    set(bx, by, tx, ty) {
      const L = Math.hypot(tx - bx, ty - by), a = (Math.atan2(ty - by, tx - bx) * 180) / Math.PI;
      body.setAttribute("width", (L + 8).toFixed(2));
      joint.setAttribute("d", `M ${(L * 0.52).toFixed(2)} -5.4 q 1.4 5.4 0 10.8`);
      nail.setAttribute("x", (L - 3.6).toFixed(2));
      el.setAttribute("transform", `translate(${bx.toFixed(2)} ${by.toFixed(2)}) rotate(${a.toFixed(2)})`);
    },
  };
}

const pad = (x: number, y: number, w: number, hh: number) => R(x, y, w, hh, SKIN, { rx: Math.min(w, hh) / 2, stroke: SKIN_EDGE, "stroke-width": 0.6 });

/** A sleeve from the wrist (two points) out to the bottom corner, with its cuff and a fold or two. */
function sleeve(w1: [number, number], w2: [number, number], e1: [number, number], e2: [number, number]): SVGElement {
  const dir = [(e1[0] - w1[0]) / Math.hypot(e1[0] - w1[0], e1[1] - w1[1]), (e1[1] - w1[1]) / Math.hypot(e1[0] - w1[0], e1[1] - w1[1])];
  const c1 = [w1[0] + dir[0] * 7, w1[1] + dir[1] * 7], c2 = [w2[0] + dir[0] * 7, w2[1] + dir[1] * 7];
  const mid = (a: number[], b: number[], t: number) => `${lerp(a[0], b[0], t).toFixed(1)} ${lerp(a[1], b[1], t).toFixed(1)}`;
  return G({},
    P(`M ${w1.join(" ")} L ${w2.join(" ")} L ${e2.join(" ")} L ${e1.join(" ")} Z`, SHIRT, { stroke: SHIRT_FOLD, "stroke-width": 0.6 }),
    P(`M ${w1.join(" ")} L ${w2.join(" ")} L ${c2.join(" ")} L ${c1.join(" ")} Z`, CUFF, { stroke: SHIRT_FOLD, "stroke-width": 0.6 }),
    C(lerp(w1[0], c1[0], 0.5) + (w2[0] - w1[0]) * 0.2, lerp(w1[1], c1[1], 0.5) + (w2[1] - w1[1]) * 0.2, 0.9, "#f4f7fb"),
    P(`M ${mid(c1, e1, 0.25)} Q ${mid(c1, e2, 0.4)} ${mid(c2, e2, 0.3)}`, "none", { stroke: SHIRT_SHADE, "stroke-width": 1.1, "stroke-linecap": "round" }),
    P(`M ${mid(c1, e1, 0.6)} Q ${mid(c1, e2, 0.65)} ${mid(c2, e2, 0.7)}`, "none", { stroke: SHIRT_SHADE, "stroke-width": 1.1, "stroke-linecap": "round" }));
}

export interface Phone { el: SVGSVGElement; tick(dt: number): void; lower(t: number): void; still(): void }

export function commuterPhone(): Phone {
  const clipPortrait = nextId("cm-clip-p"), clipLand = nextId("cm-clip-l"), clipPhone = nextId("cm-clip"), grad = nextId("cm-wall");
  const feed = feedApp(clipPortrait);
  const home = homeScreen(clipPortrait, grad);
  const game = invadersApp();
  // the app opening: a black window growing out of the icon, with the alien in its middle
  const launchRect = R(0, 0, 0, 0, "#05060b", { rx: 2 });
  const launchLogo = P(pix(CRAB[0], 1.2), "#5dff7a");
  const launch = G({ visibility: "hidden" }, launchRect, launchLogo);
  const portrait = svg("svg", { x: -25, y: -52, width: 50, height: 104, viewBox: "0 0 50 104", overflow: "hidden" },
    svg("defs", {}, svg("clipPath", { id: clipPortrait }, R(0, 0, 50, 104, "#000", { rx: 6 }))), home.el, feed.el, launch);
  const landscape = G({ transform: "rotate(90)", visibility: "hidden" },
    svg("svg", { x: -52, y: -25, width: 104, height: 50, viewBox: "0 0 104 50", overflow: "hidden" },
      svg("defs", {}, svg("clipPath", { id: clipLand }, R(0, 0, 104, 50, "#000", { rx: 6 }))), G({ "clip-path": `url(#${clipLand})` }, game.el)));
  const phone = G({},
    svg("defs", {}, svg("clipPath", { id: clipPhone }, R(-25, -52, 50, 104, "#000", { rx: 6 }))),
    R(-28.4, -30, 1.6, 7, "#2a2c31", { rx: 0.6 }), R(-28.4, -20, 1.6, 7, "#2a2c31", { rx: 0.6 }), R(26.8, -26, 1.6, 11, "#2a2c31", { rx: 0.6 }),
    R(-27, -54, 54, 108, "#141518", { rx: 8.5, stroke: "#45484f", "stroke-width": 0.9 }),
    G({ "clip-path": `url(#${clipPhone})` }, R(-25, -52, 50, 104, "#000"), portrait, landscape),
    R(-6.6, -49.6, 13.2, 3.6, "#000", { rx: 1.8 }));

  // Right hand, portrait grip: the phone lies in the palm, the fingertips curl round its left edge, the thumb is on
  // the screen. Only the thumb's mound and the heel of the hand show beside and below the phone.
  const rpBack = G({},
    P("M 25 118 C 30.5 122 34 133 34 146 C 34 159 33 172 31 186 L -16 186 C -20 182 -23 178 -24.5 172 L -25 150 L 25 150 Z", SKIN, { stroke: SKIN_EDGE, "stroke-width": 0.6 }),
    P("M 29.6 152 C 31.4 162 31.4 174 29.8 184", "none", { stroke: SKIN_SHADE, "stroke-width": 0.9 }));
  const rpThumb = thumb();
  const rpFront = G({},
    pad(-32.4, 96, 9, 12.4), pad(-33, 109.4, 9.4, 12.8), pad(-32.6, 123, 9, 12.2), pad(-31.6, 136, 8, 10),
    P("M -27 96 v 50", "none", { stroke: "rgb(0 0 0 / 25%)", "stroke-width": 0.8 }), rpThumb.el);
  // Landscape grip: each hand holds an end, thumb on the screen, index finger along the top edge.
  // One outline per hand, drawn for the left and mirrored for the right: from the index finger's side round the end of
  // the phone, down the heel of the hand into the wrist, which meets the shirt cuff; the thumb's mound below the phone.
  const landHand = (s: 1 | -1) => {
    const t = thumb();
    const X = (x: number) => (s * x).toFixed(1);
    const back = G({},
      sleeve([s * -69, 160], [s * -37, 171], [s * -152, 200], [s * -102, 226]),
      P(`M ${X(-54)} 96 C ${X(-59)} 96 ${X(-63)} 102 ${X(-63.8)} 112 L ${X(-65)} 140 C ${X(-66)} 148 ${X(-67.4)} 154 ${X(-68.6)} 160.6 L ${X(-36.4)} 171.4 `
        + `C ${X(-35.4)} 162 ${X(-34.4)} 154 ${X(-34)} 147 L ${X(-34)} 143 L ${X(-54)} 143 Z`, SKIN, { stroke: SKIN_EDGE, "stroke-width": 0.6 }),
      P(`M ${X(-57.6)} 140 C ${X(-57.6)} 150 ${X(-55)} 158 ${X(-50.4)} 165`, "none", { stroke: SKIN_SHADE, "stroke-width": 0.9, "stroke-linecap": "round" }),
      // the fingers curled round the back of the phone: creases between them along the outer edge
      ...[[-57.6, 105, -63.4, 107.4], [-58.6, 116.4, -64.4, 118.8], [-59.2, 128, -65, 130.4]].map(([x1, y1, x2, y2]) =>
        P(`M ${X(x1)} ${y1} Q ${X((x1 + x2) / 2 - 1)} ${(y1 + y2) / 2 - 2} ${X(x2)} ${y2}`, "none", { stroke: SKIN_SHADE, "stroke-width": 0.8, "stroke-linecap": "round" })));
    const front = G({},
      P(`M ${X(-63.6)} 101 C ${X(-62.4)} 91 ${X(-56)} 85.6 ${X(-45)} 86 C ${X(-41.6)} 86.2 ${X(-41.4)} 90.8 ${X(-44.6)} 90.9 C ${X(-52)} 91.2 ${X(-56.2)} 94.4 ${X(-58.4)} 101.6 Z`,
        SKIN, { stroke: SKIN_EDGE, "stroke-width": 0.6 }),                                   // the index finger, hooked over the corner
      P(`M ${X(-50.5)} 87.4 c ${1.6 * s} -0.6 ${3.4 * s} -0.6 ${4.4 * s} 0.2`, "none", { stroke: SKIN_SHADE, "stroke-width": 0.6 }),
      t.el);
    return { back, front, thumb: t };
  };
  const ll = landHand(1), rl = landHand(-1);
  const llBack = G({}, ll.back), llFront = G({}, ll.front), rlBack = G({}, rl.back), rlFront = G({}, rl.front);
  const rpBackG = G({}, rpBack), rpFrontG = G({}, rpFront);
  const phoneAt = G({}, phone);
  const me = G({}, llBack, rlBack, rpBackG, phoneAt, rpFrontG, llFront, rlFront);
  const el = svg("svg", { class: "cmp-me", width: 400, height: BOX_H, viewBox: `-200 0 400 ${BOX_H}`, "aria-hidden": "true" }, me);

  let time = 0, low = 0;
  const show = (g: SVGElement, on: boolean) => g.setAttribute("visibility", on ? "visible" : "hidden");
  const apply = () => {
    const t = time, TM = TIMES;
    // --- the portrait screens -----------------------------------------------------------------------------
    let scroll = 0;
    for (const f of FLICKS) scroll += 38 * easeInOut(clamp01((t - f - 0.1) / 0.42));
    feed.scrollTo(scroll);
    const shrink = span(t, TM.swipe, TM.home);                            // swiping home: the feed shrinks into its icon
    feed.el.setAttribute("transform", `translate(${(FEED_ICON.x * shrink).toFixed(2)} ${(FEED_ICON.y * shrink).toFixed(2)}) scale(${lerp(1, FEED_ICON.s / 50, shrink).toFixed(3)} ${lerp(1, FEED_ICON.s / 104, shrink).toFixed(3)})`);
    feed.el.setAttribute("opacity", (1 - clamp01((shrink - 0.7) / 0.3)).toFixed(2));
    show(feed.el, t < TM.home);
    show(home.el, t >= TM.swipe);
    const zoom = lerp(1.08, 1, shrink);
    home.icons.setAttribute("transform", `translate(25 52) scale(${zoom.toFixed(3)}) translate(-25 -52)`);
    const pressed = t >= TM.press && t < TM.launch;
    home.invaders.setAttribute("opacity", pressed ? "0.55" : "1");
    const open = span(t, TM.launch, TM.launched);                       // the app opens out of its icon
    show(launch, t >= TM.launch);
    const I = INVADERS_ICON;
    launchRect.setAttribute("x", lerp(I.x, 0, open).toFixed(2)); launchRect.setAttribute("y", lerp(I.y, 0, open).toFixed(2));
    launchRect.setAttribute("width", lerp(I.s, 50, open).toFixed(2)); launchRect.setAttribute("height", lerp(I.s, 104, open).toFixed(2));
    launchRect.setAttribute("rx", lerp(2.2, 6, open).toFixed(2));
    launchLogo.setAttribute("transform", `translate(${lerp(I.x + 1.1, 18.7, open).toFixed(2)} ${lerp(I.y + 2, 47.6, open).toFixed(2)}) scale(${lerp(0.52, 1, open).toFixed(3)})`);
    // --- turning the phone ----------------------------------------------------------------------------------
    const r = span(t, TM.rotate, TM.rotated);
    phoneAt.setAttribute("transform", `translate(0 ${PHONE_Y}) rotate(${(-90 * r).toFixed(2)})`);
    show(portrait, r < 0.5); show(landscape, r >= 0.5);
    const swap = clamp01((r - 0.3) / 0.3);
    rpBackG.setAttribute("transform", `rotate(${(-28 * r).toFixed(2)} 30 178)`); rpFrontG.setAttribute("transform", `rotate(${(-28 * r).toFixed(2)} 30 178)`);
    rpBackG.setAttribute("opacity", (1 - swap).toFixed(2)); rpFrontG.setAttribute("opacity", (1 - swap).toFixed(2));
    show(rpBackG, swap < 1); show(rpFrontG, swap < 1);
    rlBack.setAttribute("opacity", swap.toFixed(2)); rlFront.setAttribute("opacity", swap.toFixed(2));
    const rise = easeOut(clamp01((r - 0.1) / 0.9));                     // the left hand comes up from below
    const rightIn = `translate(${(8 * (1 - swap)).toFixed(2)} ${(16 * (1 - swap)).toFixed(2)})`, leftIn = `translate(${(-10 * (1 - rise)).toFixed(2)} ${(90 * (1 - rise)).toFixed(2)})`;
    rlBack.setAttribute("transform", rightIn); rlFront.setAttribute("transform", rightIn);
    llBack.setAttribute("transform", leftIn); llFront.setAttribute("transform", leftIn);
    show(llBack, r > 0.05); show(llFront, r > 0.05); show(rlBack, swap > 0); show(rlFront, swap > 0);
    // --- the right thumb in portrait: flicks, the home swipe, the tap on the icon ------------------------------
    const rest: [number, number] = [8, 140];
    let tip: [number, number] = rest;
    for (const f of FLICKS) {
      const k = clamp01((t - f) / 0.55);
      if (k > 0 && k < 1) {
        const up = k < 0.35 ? easeInOut(k / 0.35) : 1 - easeInOut((k - 0.35) / 0.65);
        tip = [lerp(8, 4, up), lerp(146, 124, k < 0.15 ? 0 : up)];
      }
    }
    const iconTip: [number, number] = [-25 + I.x + I.s / 2, PHONE_Y - 52 + I.y + I.s / 2];
    if (t >= TM.swipeMove) {
      const toBottom = span(t, TM.swipeMove, TM.swipe), swipeUp = span(t, TM.swipe, TM.home);
      tip = [lerp(rest[0], 0, toBottom), lerp(rest[1], 164, toBottom) - 30 * swipeUp];
      if (t >= TM.reach) {
        const reach = span(t, TM.reach, TM.press);
        tip = [lerp(0, iconTip[0], reach), lerp(134, iconTip[1] + (pressed ? 0.8 : 0), reach)];
      }
      if (t >= TM.launch) { const back = span(t, TM.launch, TM.rotate); tip = [lerp(iconTip[0], rest[0], back), lerp(iconTip[1], rest[1], back)]; }
    }
    rpThumb.set(31, 154, tip[0], tip[1]);
    // --- landscape: splash, LEVEL 1, then the game; the thumbs follow the cannon and the fire button --------
    if (t >= TM.rotated && t < TM.ready) game.splash((t - TM.rotated) / (TM.ready - TM.rotated - 0.15));
    else if (t >= TM.ready && t < TM.play) game.banner(1, t - TM.ready);
    else if (t < TM.rotated) game.splash(0);
    const steer = game.playing ? clamp01((game.cannon - 6) / 92) * 2 - 1 : 0;
    ll.thumb.set(-44, 154, -35 + steer * 2.4, 127);
    rl.thumb.set(44, 154, 35, 127 + (game.firing > 0 ? 1.6 : 0));
    me.setAttribute("transform", `translate(0 ${(LIFT + 150 * easeIn(low)).toFixed(1)})`);
  };
  apply();
  return {
    el,
    tick(dt) {
      time += dt;
      if (time >= TIMES.play) game.play(dt);
      apply();
    },
    lower(t) { low = t; apply(); },
    still() { apply(); },
  };
}
