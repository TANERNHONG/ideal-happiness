// The Commuter pack's Review scene: a Singapore bus stop, seen standing under the shelter, in the first person, phone
// in hand (commuter-kit.ts, as at the MRT platform). A clear day in the light theme; in the dark one, a tropical
// downpour: a dark sky, haze over the estate, lights on, wet roads with puddles, rain falling beyond the roof (fine and
// far, coarse and near, slanting in the wind), water pouring off its edge onto the bollard line, splashes, umbrellas, and
// now and then lightning.
//
// One-point perspective, as at the platform: the side of a bus at the stop is 2.6 m away (33 px a metre there), your
// eyes 1.6 m up. Lines along the road stay level; lines running towards you meet at eye level in the middle.
// - Overhead: the shelter's roof, reaching out over the bollards (grey, its edge with an orange stripe, a long light
//   underneath), so you stay dry until the kerb. You stand near its end; past it, out in the open and taller than the shelter, the bus-stop pole as at every stop: the blue
//   square with the bus; two wings (the stop's code over its name; the public-transport symbol); two green wings, each
//   with six services in two rows of three.
// - Your side: stone paving along the kerb with a yellow line at the edge, the black-and-white kerb, and stone bollards
//   at an even spacing, each with a yellow sleeve and one black arrow.
// - The road: the bus bay, two lanes, the central divider (black-and-white kerbs, grass, shrubs and small trees, a
//   green railing), two lanes the other way and their bus bay; then the far kerb with its bollards, the footpath along
//   it (people walking, two waiting) with the bus stop for the other direction, the verge with rain trees and street
//   lamps, and the estate: HDB
//   blocks on their grounds, with void decks and block numbers painted top to bottom near the roof. Past the near lanes, distances are drawn compressed so the far side reads.
// - The bus: a double-decker in green, coming from the right (Singapore drives on the left), its front door stopping in
//   front of you; its exit door is in the middle.
// When the logs are in, the bus pulls in, its doors open and you put the phone down; if they cannot be fetched, you
// are still playing when the doors open: they close, the bus leaves, and only then do you look up.

import { h, svg } from "./dom";
import { C, CX, G, P, R, T, W, commuterPhone, easeIn, lerp, moving, nextId, seeded, sleep, tween } from "./commuter-kit";
import { arrivalWanted, loaderShell, type TrainLoader } from "./train-loader";

// The scene is 200 px tall; the road under the bus's side meets it at 150.
const HEIGHT = 200, DIST = 2.6, EYE = 1.6, PXM = 33, FOCAL = PXM * DIST, BASE = 150;
const HORIZON = BASE - EYE * PXM;
/** Screen y of a point at height m (metres) at distance d from you. */
const atHeight = (d: number, m: number) => HORIZON - ((m - EYE) * FOCAL) / d;
const ground = (d: number) => atHeight(d, 0);
const scaleAt = (d: number) => FOCAL / d;                                   // px a metre at distance d
const SPREAD = 0.1;
/** x of a point u px to the side (at the bus's distance) and d metres away: across such a wide view, positions spread
 * out less than sizes grow (as in a panorama), as at the platform. */
const at = (u: number, d: number) => CX + u * (1 + SPREAD * (DIST / d - 1));
const KERB_NEAR = 2.1, KERB_FAR = 2.3, KERB_H = 0.15;
const pavement = (d: number) => atHeight(d, KERB_H);
const MONO = "Consolas, 'Courier New', monospace";

function isRain(): boolean {
  const theme = document.documentElement.getAttribute("data-theme");
  return theme ? theme === "dark" : !!window.matchMedia?.("(prefers-color-scheme: dark)").matches;
}

const DAY = {
  skyTop: "#8fc6ea", skyLow: "#e1f0f8", cloud: "rgb(255 255 255 / 85%)",
  walls: ["#f2ece1", "#ebe6da", "#f0e7d6", "#e7eae5"], accents: ["#c9605a", "#5f8fb5", "#79a66a", "#d39f45"],
  window: "#8fa3b2", lit: "#8fa3b2", corridor: "", voidDeck: "#b9b2a5", pillar: "#d8d1c4", number: "#ffffff",
  tree: "#4e8b3a", treeDark: "#3a6e2b", trunk: "#6b5240", lampPost: "#8d939a", lampHead: "#c9ced3", grass: "#9cc070",
  farPave: "#c9c3b8", road: "#62656a", roadEdge: "#55585d", lane: "#f1f1ef", yellow: "#f2c300", medianKerb: "#d2cfc6", shrub: "#4f7f3a",
  railing: "#3a8f45", kerbB: "#222222", kerbW: "#f4f4f4", pave: "#cfcac0", paveJoint: "rgb(0 0 0 / 9%)",
  canopy: "#a3a9ae", canopyUnder: "#d9dcdf", canopyLight: "#ffffff", accent: "#e8672a",
  stone: "#b3b0a8", stoneTop: "#cfccc4", sleeve: "#f2c300", chevron: "#1f1f1f",
  stoneFloor: "#a7a6a1", stoneSpeck: "rgb(255 255 255 / 22%)", stoneJoint: "rgb(0 0 0 / 14%)", footpath: "#d8d2c6",
  signTeal: "#1f6c74", signBlue: "#2f86d6", signSquare: "#3d93dc", signLight: "#cfe2dc", signMint: "#86d3a9",
  panel: "#e46a2e", bench: "#e8742f",
  bus: "#3a9d48", busTop: "#2f8a3d", busLime: "#a8d36a", glass: "#2c3a44", glassLit: "#2c3a44", inside: "#d3d6d9",
  skirt: "#3b3f45", tyre: "#1f2226", hub: "#a9afb5", headlight: "#f4f1e3", shadow: "rgb(0 0 0 / 22%)",
};
const RAIN: typeof DAY = {
  skyTop: "#3c454e", skyLow: "#7a8590", cloud: "#4f5861",
  walls: ["#c9c6bf", "#c3c1ba", "#c8c3b8", "#bfc3bf"], accents: ["#9a5a55", "#55728d", "#5f7d55", "#a07d45"],
  window: "#6f7c86", lit: "#f2d58a", corridor: "", voidDeck: "#8f8a80", pillar: "#aaa59b", number: "#ffffff",
  tree: "#355f2c", treeDark: "#284a21", trunk: "#4b3a2e", lampPost: "#6c7178", lampHead: "#fff3c4", grass: "#5f7d48",
  farPave: "#8e8a83", road: "#3b3e43", roadEdge: "#33363a", lane: "#c9cbcc", yellow: "#c9a52a", medianKerb: "#8d8b85", shrub: "#2f5228",
  railing: "#2e6e36", kerbB: "#1d1d1d", kerbW: "#bfc0bf", pave: "#8e8b84", paveJoint: "rgb(0 0 0 / 16%)",
  canopy: "#7d8388", canopyUnder: "#9da2a6", canopyLight: "#fffbe8", accent: "#c25a26",
  stone: "#8c8a84", stoneTop: "#a3a19b", sleeve: "#d2aa16", chevron: "#151515",
  stoneFloor: "#74736c", stoneSpeck: "rgb(255 255 255 / 14%)", stoneJoint: "rgb(0 0 0 / 22%)", footpath: "#a19d94",
  signTeal: "#1b5f66", signBlue: "#2a78c0", signSquare: "#3586c9", signLight: "#bccfc9", signMint: "#76bf98",
  panel: "#b75629", bench: "#bf5f2a",
  bus: "#2f8a3f", busTop: "#287836", busLime: "#8fb85c", glass: "#2c3a44", glassLit: "#f0dca6", inside: "#e9dcb6",
  skirt: "#2f3237", tyre: "#17191c", hub: "#8b9096", headlight: "#fff6c9", shadow: "rgb(0 0 0 / 30%)",
};
type Palette = typeof DAY;

// --- across the road: HDB blocks, rain trees, street lamps ---------------------------------------------------------

// Block digits on a 3 x 5 grid, as painted on HDB blocks (one row of cells per string)
const DIGITS = ["111101101101111", "010110010010111", "111001111100111", "111001111001111", "101101111001001",
  "111100111001111", "111100111101111", "111001001001001", "111101111101111", "111101111001111"];

/** A block number painted near the top of a block: its digits stacked top to bottom, each a grid of solid cells. */
function blockNumber(x: number, y: number, cell: number, value: string, colour: string): SVGElement[] {
  const out: SVGElement[] = [];
  [...value].forEach((digit, i) => {
    const rows = DIGITS[Number(digit)], top = y + i * cell * 6.4;
    for (let r = 0; r < 5; r++) {
      for (let k = 0; k < 3;) {
        if (rows[r * 3 + k] !== "1") { k++; continue; }
        let run = 1;
        while (k + run < 3 && rows[r * 3 + k + run] === "1") run++;
        out.push(R(x + k * cell, top + r * cell, run * cell + 0.05, cell + 0.05, colour));
        k += run;
      }
    }
  });
  return out;
}

/** An HDB slab block at distance d: void deck, storeys of windows (a few lit in the storm), a coloured stair core,
 * the painted block number near the top and a water tank on the roof. */
function hdb(x: number, width: number, storeys: number, d: number, c: Palette, rain: boolean, rand: () => number, defs: SVGElement[]): SVGElement[] {
  const s = scaleAt(d), floor = ground(d), storey = 3 * s, bay = 3.3 * s;
  const top = floor - storey * storeys;
  const wall = c.walls[Math.floor(rand() * c.walls.length)], accent = c.accents[Math.floor(rand() * c.accents.length)];
  const id = nextId("cmb-win");
  defs.push(svg("pattern", { id, x, y: top + storey * 0.6, width: bay, height: storey, patternUnits: "userSpaceOnUse" },
    R(bay * 0.18, storey * 0.28, bay * 0.56, storey * 0.42, c.window)));
  const out: SVGElement[] = [R(x, top, width, floor - top, wall),
    R(x, top + storey * 0.6, width, floor - storey - top - storey * 0.6, `url(#${id})`)];
  const corridorSide = rand() < 0.5;
  if (rain) {
    for (let k = 1; k < storeys; k++) {
      if (corridorSide) out.push(R(x, top + storey * (k - 0.35), width, Math.max(0.6, storey * 0.16), "#eef2d6", { opacity: 0.3 }));   // corridor lights on in the gloom
      for (let bx = x + bay * 0.18; bx < x + width - bay * 0.5; bx += bay) {
        if (rand() < 0.06) out.push(R(bx, top + storey * (k - 1) + storey * 0.88, bay * 0.56, storey * 0.42, c.lit));
      }
    }
  }
  const core = x + width * (0.25 + rand() * 0.5);
  out.push(R(core, top - storey * 0.4, bay * 1.1, floor - storey - top + storey * 0.4, accent),
    R(x, top, width, storey * 0.6, accent),
    R(x + width * 0.62, top - storey * 0.9, width * 0.14, storey * 0.9, wall), R(x + width * 0.62, top - storey * 0.9, width * 0.14, storey * 0.18, accent));
  // the block number, on a panel of the accent colour near the roof
  const cell = storey * 0.28, value = String(100 + Math.floor(rand() * 800));
  const panelX = x + width * 0.06, panelTop = top + storey * 0.9;
  out.push(R(panelX, panelTop, cell * 4.6, cell * (6.4 * value.length + 0.6), accent),
    ...blockNumber(panelX + cell * 0.8, panelTop + cell * 0.9, cell, value, rain ? c.number : "#ffffff"));
  // the void deck: open at the ground, on pillars
  out.push(R(x, floor - storey, width, storey, c.voidDeck));
  for (let px = x + 2; px < x + width; px += bay * 1.6) out.push(R(px, floor - storey, Math.max(1, bay * 0.22), storey, c.pillar));
  return out;
}

/** A rain tree as in the Transit pack: a trunk under a broad, flat crown, its dark underside and two lighter clumps. */
function rainTree(x: number, base: number, scale: number, c: Palette, rand: () => number): SVGElement {
  const w = (26 + rand() * 18) * scale, cy = base - (14 + rand() * 6) * scale;
  return G({}, R(x - 1.5 * scale, cy, 3 * scale, base - cy, c.trunk),
    svg("ellipse", { cx: x, cy: cy + 2 * scale, rx: w / 2, ry: 7 * scale, fill: c.treeDark }),
    svg("ellipse", { cx: x - w * 0.12, cy: cy - 1.5 * scale, rx: w * 0.32, ry: 6 * scale, fill: c.tree }),
    svg("ellipse", { cx: x + w * 0.14, cy: cy - 2.5 * scale, rx: w * 0.3, ry: 6.5 * scale, fill: c.tree }));
}

function streetLamp(x: number, d: number, c: Palette, rain: boolean, halo: string): SVGElement {
  const s = scaleAt(d), base = ground(d), top = atHeight(d, 9);
  return G({},
    ...(rain ? [svg("ellipse", { cx: x + 1.45 * s, cy: top + 0.4 * s, rx: 3.4 * s, ry: 2.4 * s, fill: `url(#${halo})` })] : []),
    R(x - 0.1 * s, top, 0.2 * s, base - top, c.lampPost),
    P(`M ${x} ${top + 0.4} q ${0.2 * s} ${-0.5 * s} ${1.4 * s} ${-0.4 * s}`, "none", { stroke: c.lampPost, "stroke-width": 0.18 * s }),
    R(x + 1.0 * s, top - 0.2 * s, 0.9 * s, 0.3 * s, c.lampHead, { rx: 0.15 * s }));
}

// Past the near lanes, distances are drawn compressed (as a painter would), so the divider and the far side stay readable
// from 1.6 m up; up to 6 m everything is true.
const warp = (d: number) => (d <= 6 ? d : 6 + (d - 6) * 0.5);
const groundW = (d: number) => ground(warp(d));
const heightW = (d: number, m: number) => atHeight(warp(d), m);
const scaleW = (d: number) => scaleAt(warp(d));
/** The road from your kerb, in metres from you: the bus bay's line, the lane line, the divider (and its railing), the far
 * lane line and bus bay, the far kerb; then the footpath with the other direction's bus stop on it, and the verge. */
const ROAD = { bay: 5.4, lane: 8.6, divider: [11.0, 12.6], railing: 11.5, farLane: 15.6, farBay: 18.2, farKerb: 20.6,
  path: [20.6, 23.4], shelter: [21.3, 23.1], verge: [23.4, 26.5], trees: 25.2, lamps: 23.9 };
const FAR_STOP = [-200, -112];                         // the other direction's stop: across the road, a little to the left

function backdrop(c: Palette, rain: boolean, defs: SVGElement[], walkers: Walker[]): SVGElement[] {
  const rand = seeded(31);
  const sky = nextId("cmb-sky");
  defs.push(svg("linearGradient", { id: sky, x1: 0, y1: 0, x2: 0, y2: 1 },
    svg("stop", { offset: 0, "stop-color": c.skyTop }), svg("stop", { offset: 1, "stop-color": c.skyLow })));
  const out: SVGElement[] = [R(0, 0, W, HORIZON + 6, `url(#${sky})`)];
  if (rain) {
    for (let x = -40; x < W; x += 90 + rand() * 80) {                               // a low ceiling of heavy cloud
      const y = 6 + rand() * 30;
      out.push(G({ opacity: 0.85 }, svg("ellipse", { cx: x, cy: y, rx: 70 + rand() * 40, ry: 14 + rand() * 8, fill: c.cloud }),
        svg("ellipse", { cx: x + 40, cy: y + 10, rx: 50, ry: 10, fill: "#5d6670" })));
    }
  } else {
    for (let x = 60; x < W; x += 260 + rand() * 220) {                             // a few fair-weather clouds
      const y = 14 + rand() * 26;
      out.push(G({ opacity: 0.9 }, svg("ellipse", { cx: x, cy: y, rx: 26, ry: 6, fill: c.cloud }),
        svg("ellipse", { cx: x - 14, cy: y + 2, rx: 16, ry: 5, fill: c.cloud }), svg("ellipse", { cx: x + 12, cy: y - 3, rx: 14, ry: 6, fill: c.cloud })));
    }
  }
  // two rows of blocks on the estate's grounds, which run forward to the verge
  for (let x = -40; x < W; x += 100 + rand() * 120) out.push(...hdb(x, 110 + rand() * 70, 13 + Math.floor(rand() * 4), 58, c, rain, rand, defs));
  const haze = (bottom: number, alpha: number) => rain && out.push(R(0, 0, W, bottom, `rgb(126 136 146 / ${alpha}%)`));
  haze(ground(58) + 0.5, 42);                                                       // the rain hides the far blocks most
  const vergeBack = heightW(ROAD.verge[1], KERB_H), pathBack = heightW(ROAD.path[1], KERB_H), pathFront = heightW(ROAD.path[0], KERB_H);
  out.push(R(0, ground(58), W, pathBack - ground(58), c.grass));
  for (let x = -20; x < W; x += 230 + rand() * 160) out.push(...hdb(x, 130 + rand() * 80, 10 + Math.floor(rand() * 4), 34, c, rain, rand, defs));
  for (let x = 6; x < W; x += 7 + rand() * 9) {                                     // a hedge at the back of the verge
    out.push(svg("ellipse", { cx: x, cy: vergeBack - 0.4, rx: 4 + rand() * 3, ry: 1.6 + rand() * 0.8, fill: c.shrub }));
  }
  for (let x = 60; x < W; x += 150 + rand() * 110) out.push(rainTree(x, heightW(ROAD.trees, KERB_H), 1.8 + rand() * 0.4, c, rand));
  const halo = nextId("cmb-halo");
  defs.push(svg("radialGradient", { id: halo }, svg("stop", { offset: 0, "stop-color": "#ffd88a", "stop-opacity": 0.55 }),
    svg("stop", { offset: 0.35, "stop-color": "#ffd88a", "stop-opacity": 0.18 }), svg("stop", { offset: 1, "stop-color": "#ffd88a", "stop-opacity": 0 })));
  for (let x = 90; x < W; x += 160) out.push(streetLamp(x, warp(ROAD.lamps), c, rain, halo));
  haze(heightW(ROAD.path[1], KERB_H), 24);
  // the footpath along the road, the other direction's bus stop on it, and the far kerb
  out.push(R(0, pathBack, W, pathFront - pathBack, c.footpath));
  out.push(...farStop(c, rain), ...walkers.map((w) => w.el));
  const roadTop = groundW(ROAD.farKerb);
  out.push(R(0, roadTop, W, BASE + 12 - roadTop, c.road));
  if (rain) {                                                                       // the wet road catches the sky
    const sheen = nextId("cmb-sheen");
    defs.push(svg("linearGradient", { id: sheen, x1: 0, y1: 0, x2: 0, y2: 1 },
      svg("stop", { offset: 0, "stop-color": "#c3ccd5", "stop-opacity": 0.3 }), svg("stop", { offset: 1, "stop-color": "#c3ccd5", "stop-opacity": 0.04 })));
    out.push(R(0, roadTop, W, BASE + 12 - roadTop, `url(#${sheen})`));
  }
  out.push(...kerbFace(ROAD.farKerb, 0.15, c, (x) => x >= CX + FAR_STOP[0] - 40 && x <= CX + FAR_STOP[1] + 30));
  const dashes = (d: number, colour: string, dash: number, gap: number, width: number) => {
    const sc = scaleW(d), y = groundW(d);
    for (let x = -((CX * 0.4) % ((dash + gap) * sc)); x < W; x += (dash + gap) * sc) out.push(R(x, y - width * sc * 0.5, dash * sc, Math.max(0.5, width * sc * 0.4), colour));
  };
  // the far bus bay's line, tapering into the far kerb at each end
  const farBay = groundW(ROAD.farBay);
  out.push(R(CX + FAR_STOP[0] - 40, farBay - 0.4, FAR_STOP[1] - FAR_STOP[0] + 70, 0.9, c.yellow),
    P(`M ${CX + FAR_STOP[0] - 40} ${farBay} L ${CX + FAR_STOP[0] - 70} ${roadTop + 0.4}`, "none", { stroke: c.yellow, "stroke-width": 0.9 }),
    P(`M ${CX + FAR_STOP[1] + 30} ${farBay} L ${CX + FAR_STOP[1] + 60} ${roadTop + 0.4}`, "none", { stroke: c.yellow, "stroke-width": 0.9 }));
  dashes(ROAD.farLane, c.lane, 3, 9, 0.15);                                          // the far lanes
  out.push(...divider(c, rand, defs));
  if (rain) haze(groundW(ROAD.divider[0]) + 0.5, 10);
  dashes(ROAD.lane, c.lane, 3, 9, 0.15);                                             // between the near lanes
  // the near bus bay: a yellow line along its edge, tapering into the kerb at each end
  const bay = ground(ROAD.bay), kerb = ground(KERB_FAR);
  out.push(R(at(-560, ROAD.bay), bay - 0.6, at(560, ROAD.bay) - at(-560, ROAD.bay), 1.3, c.yellow),
    P(`M ${at(-560, ROAD.bay)} ${bay} L ${at(-700, KERB_FAR + 0.2)} ${kerb - 1}`, "none", { stroke: c.yellow, "stroke-width": 1.3 }),
    P(`M ${at(560, ROAD.bay)} ${bay} L ${at(700, KERB_FAR + 0.2)} ${kerb - 1}`, "none", { stroke: c.yellow, "stroke-width": 1.3 }));
  if (rain) {                                                                       // puddles in the bus bay, holding the sky
    for (let u = -900; u < 900; u += 70 + rand() * 90) {
      const d = 2.8 + rand() * 2.2, y = ground(d), w = (0.8 + rand() * 1.6) * scaleAt(d);
      out.push(svg("ellipse", { cx: at(u, d), cy: y, rx: w, ry: w * 0.12, fill: "rgb(176 190 204 / 26%)", stroke: "rgb(255 255 255 / 12%)", "stroke-width": 0.4 }));
    }
  }
  return out;
}

// --- people across the road: walking along the footpath, waiting at the other stop -----------------------------------

interface Walker { el: SVGElement; tick(dt: number): void }

/** A small figure on the far footpath, seen from the side (no face at this distance): legs that swing as it walks. */
function pedestrian(x: number, d: number, shirt: string, trousers: string, skin: string, hair: string, speed: number, umbrella = ""): Walker {
  const s = scaleW(d), foot = heightW(d, KERB_H);
  const legs = [0, 1].map(() => P("", "none", { stroke: trousers, "stroke-width": 0.17 * s, "stroke-linecap": "round" }));
  const el = G({ transform: `translate(${x} ${foot})` }, ...legs,
    R(-0.21 * s, -1.48 * s, 0.42 * s, 0.68 * s, shirt, { rx: 0.12 * s }), C(0, -1.63 * s, 0.13 * s, skin),
    P(`M ${-0.13 * s} ${-1.64 * s} a ${0.13 * s} ${0.13 * s} 0 0 1 ${0.26 * s} 0 z`, hair),
    ...(umbrella ? [R(0.1 * s, -2.0 * s, 0.04 * s + 0.2, 0.75 * s, "#2b2b2b"),
      P(`M ${-0.55 * s} ${-1.98 * s} Q ${0.1 * s} ${-2.55 * s} ${0.75 * s} ${-1.98 * s} Z`, umbrella)] : []));
  let pos = x, phase = Math.random() * 6;
  const pose = () => legs.forEach((leg, i) => {
    const swing = speed ? Math.sin(phase + i * Math.PI) * 0.22 * s : (i ? 0.07 : -0.07) * s;
    leg.setAttribute("d", `M 0 ${(-0.84 * s).toFixed(2)} L ${swing.toFixed(2)} 0`);
  });
  pose();
  return {
    el,
    tick(dt) {
      if (!speed) return;
      pos += speed * dt;
      if (pos > CX + 800) pos = CX - 800;
      if (pos < CX - 800) pos = CX + 800;
      phase += dt * 6.5;
      el.setAttribute("transform", `translate(${pos.toFixed(1)} ${foot})`);
      pose();
    },
  };
}

function people(rain: boolean): Walker[] {
  const shirts = rain ? ["#a84040", "#3a6596", "#cfcfcf", "#5a8040", "#b88634"] : ["#d64545", "#3f7cc4", "#f2f2f2", "#6a9a4a", "#e0a03a"];
  const trousers = "#2d3446", skins = ["#d8a47f", "#b9825e"], hair = "#2a2420";
  const umbrellas = rain ? ["#c62f3a", "#1f3f73", "#e2b21f"] : ["", "", ""];         // out in the rain, under umbrellas
  const walk = 1.3 * scaleW(22);                                           // px a second at a walking pace
  return [
    pedestrian(CX - 420, 22.0, shirts[0], trousers, skins[0], hair, walk, umbrellas[0]),
    pedestrian(CX + 160, 22.4, shirts[1], trousers, skins[1], hair, -walk * 0.9, umbrellas[1]),
    pedestrian(CX - 40, 21.8, shirts[4], "#5b4a3a", skins[0], hair, walk * 0.8, umbrellas[2]),
    pedestrian(CX + FAR_STOP[0] + 50, 22.3, shirts[2], trousers, skins[1], hair, 0),                  // waiting at the other stop
    pedestrian(CX + FAR_STOP[0] + 62, 22.2, shirts[3], trousers, skins[0], hair, 0),
  ];
}

/** The face of a kerb across the road (it faces you): black and white a metre at a time where ``striped``, else grey. */
function kerbFace(d: number, height: number, c: Palette, striped: (x: number) => boolean): SVGElement[] {
  const sc = scaleW(d), bottom = groundW(d), top = heightW(d, height), out: SVGElement[] = [R(0, top, W, bottom - top, c.medianKerb)];
  for (let x = 0, k = 0; x < W; x += sc, k++) if (striped(x)) out.push(R(x, top, sc + 0.05, bottom - top, k % 2 ? c.kerbB : c.kerbW));
  return out;
}

/** The central divider, as on most Singapore roads: raised between black-and-white kerbs, grass, shrubs and small trees,
 * and a green metal railing (posts, a top and a bottom rail, close-set bars) to keep people from crossing. */
function divider(c: Palette, rand: () => number, defs: SVGElement[]): SVGElement[] {
  const [near, far] = ROAD.divider, KH = 0.18;
  const topNear = heightW(near, KH), topFar = heightW(far, KH);
  const out: SVGElement[] = [R(0, topFar, W, topNear - topFar, c.grass)];
  const mid = heightW((near + far) / 2 + 0.3, KH);
  // low shrubs (so the far kerb and footpath show over them), and small trees clear of the far bus stop
  for (let x = 3; x < W; x += 6 + rand() * 6) out.push(svg("ellipse", { cx: x, cy: mid - 0.6, rx: 3.5 + rand() * 3, ry: 1.4 + rand() * 0.6, fill: c.shrub }));
  for (let x = 20; x < W; x += 100 + rand() * 80) {
    if (x > CX + FAR_STOP[0] - 40 && x < CX + FAR_STOP[1] + 45) continue;
    out.push(rainTree(x, mid, 0.95 + rand() * 0.3, c, rand));
  }
  // the railing
  const base = heightW(ROAD.railing, KH), top = heightW(ROAD.railing, KH + 1.05), low = heightW(ROAD.railing, KH + 0.18), sc = scaleW(ROAD.railing);
  const bars = nextId("cmb-bars");
  defs.push(svg("pattern", { id: bars, width: 0.13 * sc, height: 10, patternUnits: "userSpaceOnUse" }, R(0, 0, Math.max(0.45, 0.025 * sc), 10, c.railing)));
  out.push(R(0, top + 0.6, W, low - top - 0.6, `url(#${bars})`), R(0, top, W, 1.1, c.railing), R(0, low, W, 0.8, c.railing));
  for (let x = 0; x < W; x += 2.5 * sc) out.push(R(x, top - 0.4, 1.4, base - top + 0.4, c.railing));
  out.push(...kerbFace(near, KH, c, () => true));
  return out;
}

/** The bus stop for the other direction, across the road on the footpath: bollards along its kerb, a shelter (an orange
 * back panel and a lit advert, benches, posts, its roof's edge) and its pole. */
function farStop(c: Palette, rain: boolean): SVGElement[] {
  const [front, back] = ROAD.shelter, [a, b] = FAR_STOP.map((u) => CX + u);
  const sBack = scaleW(back), ground0 = heightW(back, KERB_H), out: SVGElement[] = [];
  const at2 = (d: number, m: number) => heightW(d, KERB_H + m);
  // the back panel (grey, with an orange section), an advert at its end, and the benches in front of it
  out.push(R(a, at2(back, 2.3), b - a, ground0 - at2(back, 2.3), "#9aa0a6"), R(a + (b - a) * 0.08, at2(back, 2.3), (b - a) * 0.3, ground0 - at2(back, 2.3), c.panel),
    R(b - 0.9 * sBack - 2, at2(back, 2.0), 0.9 * sBack, at2(back, 0.4) - at2(back, 2.0), rain ? "#fff3d6" : "#f4f4f2"),
    R(b - 0.9 * sBack - 1.4, at2(back, 1.85), 0.9 * sBack - 1.2, (at2(back, 0.6) - at2(back, 1.85)) * 0.5, rain ? "#c98b57" : "#3d93dc"));
  const bench = (back + front) / 2 + 0.3, sBench = scaleW(bench);
  for (let x = a + 6; x < b - 0.9 * sBack - 6; x += 2.2 * sBench) {
    out.push(R(x, at2(bench, 0.45), 1.6 * sBench, 0.08 * sBench + 0.5, c.bench), R(x + 0.2 * sBench, at2(bench, 0.45), 0.6, at2(bench, 0) - at2(bench, 0.45), c.bench),
      R(x + 1.35 * sBench, at2(bench, 0.45), 0.6, at2(bench, 0) - at2(bench, 0.45), c.bench));
  }
  for (const x of [a, (a + b) / 2, b]) out.push(R(x - 0.6, at2(back, 2.6), 1.2, ground0 - at2(back, 2.6), "#8c9196"));        // posts
  // its roof's edge: grey, with the orange stripe
  const roofTop = at2(front, 2.9), roofBottom = at2(front, 2.4);
  out.push(R(a - 3, roofTop, b - a + 6, roofBottom - roofTop, c.canopy), R(a - 3, roofTop + (roofBottom - roofTop) * 0.35, b - a + 6, Math.max(0.5, (roofBottom - roofTop) * 0.25), c.accent));
  if (rain) out.push(R(a, roofBottom, b - a, 1.2, "rgb(255 250 225 / 45%)"));
  // bollards along its kerb, evenly spaced, and its pole at the far end (the end its buses stop at)
  const dB = ROAD.farKerb + 0.25, sB = scaleW(dB);
  for (let x = a - 30; x <= b + 20; x += 2 * sB) {
    const top = heightW(dB, KERB_H + 0.9), base = heightW(dB, KERB_H);
    out.push(R(x - 0.11 * sB, top, 0.22 * sB, base - top, c.stone), R(x - 0.11 * sB, top + (base - top) * 0.12, 0.22 * sB, (base - top) * 0.28, c.sleeve));
  }
  const px = b + 16, pTop = heightW(dB, KERB_H + 3.85), pBase = heightW(dB, KERB_H), sq = 0.36 * sB, wing = 0.74 * sB;
  out.push(R(px - 0.065 * sB, pTop, 0.13 * sB, pBase - pTop, "#a9aeb3"), R(px - sq / 2, pTop, sq, sq, c.signSquare),
    R(px - 0.07 * sB - wing, heightW(dB, KERB_H + 3.38) - 0.3, wing, 0.46 * sB, c.signTeal), R(px + 0.07 * sB, heightW(dB, KERB_H + 3.38) - 0.3, wing, 0.46 * sB, c.signTeal),
    R(px - 0.07 * sB - wing, heightW(dB, KERB_H + 2.86), wing, 0.34 * sB, c.signMint), R(px + 0.07 * sB, heightW(dB, KERB_H + 2.86), wing, 0.34 * sB, c.signMint));
  return out;
}

// --- the bus --------------------------------------------------------------------------------------------------------

const BUS_L = 396, FRONT_DOOR = 48, EXIT_DOOR = 198, DOOR_W = 40;
const AXLES = [89, 287, 327];
const BUS_STOP_X = CX - FRONT_DOOR;                                                  // its front door in front of you

interface Door { leaves: [SVGElement, SVGElement]; hinges: [number, number] }
interface Bus { g: SVGElement; doors: Door[]; wheels: SVGElement[] }

function bus(c: Palette, rain: boolean, defs: SVGElement[]): Bus {
  const tint = nextId("cmb-glass");
  defs.push(svg("linearGradient", { id: tint, x1: 0, y1: 0, x2: 0, y2: 1 },
    svg("stop", { offset: 0, "stop-color": rain ? "#b9ab86" : "#4d6474" }), svg("stop", { offset: 1, "stop-color": rain ? "#5d5640" : "#24313a" })));
  const glass = `url(#${tint})`;
  /** A window: glass, the backs of the seats along its bottom, and (by day) a streak of reflected sky. */
  const pane = (x: number, y: number, w: number, hh: number, rx = 2): SVGElement[] => {
    const parts: SVGElement[] = [R(x, y, w, hh, glass, { rx })];
    for (let sx = x + 4; sx < x + w - 6; sx += 15) parts.push(R(sx, y + hh * 0.55, 9, hh * 0.45, rain ? "#3e3424" : "#1b252c", { rx: 2.5, opacity: rain ? 0.8 : 0.55 }));
    if (!rain) parts.push(P(`M ${x + w * 0.18} ${y + hh} L ${x + w * 0.42} ${y} L ${x + w * 0.5} ${y} L ${x + w * 0.26} ${y + hh} Z`, "rgb(255 255 255 / 10%)"));
    return parts;
  };
  const out: SVGElement[] = [svg("ellipse", { cx: BUS_L / 2, cy: BASE, rx: BUS_L / 2 + 8, ry: 2.4, fill: c.shadow }),
    R(0, 8, BUS_L, 133, c.bus, { rx: 7 }), R(3, 8, BUS_L - 6, 4, c.busTop, { rx: 3 }),
    // upper deck: one band of glass with thin pillars; the front window wraps round the corner
    ...pane(2, 20, BUS_L - 8, 36, 4), R(0, 22, 10, 32, glass, { rx: 5 })];
  for (let x = 52; x < BUS_L - 20; x += 47) out.push(R(x, 20, 3, 36, c.bus));
  if (rain) for (let x = 20; x < BUS_L - 20; x += 47) out.push(R(x, 21, 14, 1.2, "#ffffff", { opacity: 0.8 }));   // ceiling lights
  out.push(R(0, 61, BUS_L, 3.4, c.busLime), R(0, 126, BUS_L, 15, c.skirt, { rx: 3 }));
  // lower deck: the driver's window, then windows between the doors and behind the exit door
  out.push(R(3, 74, 23, 40, glass, { rx: 3 }));
  for (const [a, b] of [[72, 122], [125, 175], [222, 266], [269, 313], [316, 360], [363, 391]]) out.push(...pane(a, 78, b - a, 32));
  // the side destination display, over the first window behind the front door
  out.push(R(74, 79.5, 47, 7.5, "#14171a", { rx: 1 }), T(76, 85.3, "66 Jurong East Int", 4.6, "#ffb02e", { "font-family": MONO, "font-weight": 700 }));
  // the doors: the opening (the inside, a grab pole and the step), then two glass leaves that fold back inwards
  const doors: Door[] = [];
  for (const centre of [FRONT_DOOR, EXIT_DOOR]) {
    const left = centre - DOOR_W / 2;
    out.push(R(left, 74, DOOR_W, 63, c.inside), R(left, 128, DOOR_W, 9, rain ? "#c9b98f" : "#9aa0a6"), R(centre + 11, 76, 2, 52, "#e2b400", { rx: 1 }),
      R(left - 1.2, 72.5, DOOR_W + 2.4, 2.4, "#2b2f33"));
    const leaf = (x: number) => G({}, R(x, 74, DOOR_W / 2, 64, "#2b2f33", { rx: 1 }), R(x + 2.2, 77, DOOR_W / 2 - 4.4, 56, glass, { rx: 1.2, opacity: rain ? 0.85 : 0.9 }),
      R(x + 2.2, 103, DOOR_W / 2 - 4.4, 1.4, "#2b2f33"));
    const pair: [SVGElement, SVGElement] = [leaf(left), leaf(centre)];
    out.push(...pair);
    doors.push({ leaves: pair, hinges: [left, left + DOOR_W] });
  }
  // wheels under dark arches, their hubs turning as the bus moves
  const wheels: SVGElement[] = [];
  for (const x of AXLES) {
    const spokes = G({ transform: `translate(${x} ${BASE - 16.5})` }, ...[0, 72, 144, 216, 288].map((a) =>
      C(5.6 * Math.cos((a * Math.PI) / 180), 5.6 * Math.sin((a * Math.PI) / 180), 1.2, c.skirt)));
    out.push(P(`M ${x - 21} 141 a 21 21 0 0 1 42 0 z`, "#1b1d21"), C(x, BASE - 16.5, 16.5, c.tyre), C(x, BASE - 16.5, 9.5, c.hub), spokes, C(x, BASE - 16.5, 2.6, c.skirt));
    wheels.push(spokes);
  }
  // front and rear: bumper, headlight, the mirror on its arm, tail lights
  out.push(R(-1.5, 127, 9, 14, "#2a2d31", { rx: 2 }), R(-0.5, 117, 5, 6, c.headlight, { rx: 1.5 }),
    P("M 1 30 h -8 v 15 h 2.4 v -12.6 h 5.6 z", "#2a2d31"), R(-11.5, 40, 6, 13, "#2a2d31", { rx: 2 }),
    R(BUS_L - 3.5, 108, 4, 16, "#c62828", { rx: 1.5 }), R(BUS_L - 3.5, 30, 3.5, 8, "#c62828", { rx: 1.2 }));
  if (rain) out.push(svg("ellipse", { cx: -10, cy: 120, rx: 18, ry: 7, fill: "rgb(255 246 201 / 30%)" }));
  const g = G({ transform: `translate(${W + 600} 0)` }, ...out);
  return { g, doors, wheels };
}

// --- your side: kerb, stone paving, pavement, bollards, the bus-stop pole -----------------------------------------------

const STONE = 1.72;                                    // the stone strip runs back from the kerb to here

function kerbAndPavement(c: Palette, defs: SVGElement[]): SVGElement[] {
  const far = pavement(KERB_FAR), near = pavement(KERB_NEAR);
  const out: SVGElement[] = [R(0, far, W, HEIGHT - far, c.pave)];
  // black-and-white kerb stones, a metre each, their joints running towards you
  for (let u = -CX - 33; u < CX + 33; u += 33) {
    const k = Math.round(u / 33);
    out.push(P(`M ${at(u, KERB_FAR)} ${far} L ${at(u + 33, KERB_FAR)} ${far} L ${at(u + 33, KERB_NEAR)} ${near} L ${at(u, KERB_NEAR)} ${near} Z`, k % 2 ? c.kerbB : c.kerbW));
  }
  // stone paving from the kerb back past the bollards: large flat slabs of speckled grey stone
  const front = pavement(KERB_NEAR), rear = pavement(STONE), speck = nextId("cmb-speck");
  defs.push(svg("pattern", { id: speck, width: 7, height: 5, patternUnits: "userSpaceOnUse" },
    C(1.2, 1, 0.35, c.stoneSpeck), C(4.6, 3.4, 0.3, c.stoneSpeck), C(5.8, 0.8, 0.25, c.stoneJoint), C(2.6, 3.9, 0.25, c.stoneJoint)));
  out.push(R(0, front, W, rear - front, c.stoneFloor), R(0, front, W, rear - front, `url(#${speck})`),
    R(0, pavement(1.9) - 0.3, W, 0.6, c.stoneJoint));
  for (let u = -CX; u <= CX; u += 26) out.push(P(`M ${at(u, KERB_NEAR)} ${front} L ${at(u, STONE)} ${rear}`, "none", { stroke: c.stoneJoint, "stroke-width": 0.6 }));
  // a yellow line painted along the edge
  out.push(P(`M 0 ${near} L ${W} ${near} L ${W} ${pavement(2.075)} L 0 ${pavement(2.075)} Z`, c.yellow));
  // the shelter's paving behind: joints running towards you, and across
  const back = pavement(STONE);
  out.push(R(0, back - 0.4, W, 0.8, c.paveJoint));
  for (let u = -CX; u <= CX; u += 40) out.push(P(`M ${at(u, STONE)} ${back} L ${at(u, 1.25)} ${pavement(1.25)}`, "none", { stroke: c.paveJoint, "stroke-width": 0.7 }));
  for (const d of [1.55, 1.36]) out.push(R(0, pavement(d) - 0.35, W, 0.7, c.paveJoint));
  return out;
}

/** A stone bollard, as along every bus stop's kerb: a grey pillar with a rounded top and a yellow sleeve with one black
 * arrow (pointing the way the traffic goes). */
function bollard(u: number, c: Palette): SVGElement {
  const d = 2.0, s = scaleAt(d), x = at(u, d), base = pavement(d), top = atHeight(d, KERB_H + 0.9), w = 0.22 * s;
  const y0 = top + (base - top) * 0.13, y1 = top + (base - top) * 0.42, hh = y1 - y0;
  const xr = x + w * 0.36, xl = x - w * 0.3, t = hh * 0.3, ay = y0 + hh * 0.12, ah = hh * 0.76;
  return G({}, R(x - w / 2, top + w * 0.2, w, base - top - w * 0.2, c.stone),
    svg("ellipse", { cx: x, cy: top + w * 0.22, rx: w / 2, ry: w * 0.26, fill: c.stoneTop }),
    R(x - w / 2, y0, w, hh, c.sleeve),
    P(`M ${xr} ${ay} L ${xl} ${ay + ah / 2} L ${xr} ${ay + ah} L ${xr} ${ay + ah - t} L ${xl + t * 1.2} ${ay + ah / 2} L ${xr} ${ay + t} Z`, c.chevron),
    R(x + w * 0.2, top + w * 0.3, w * 0.3, base - top - w * 0.3, "rgb(0 0 0 / 12%)"), R(x - w * 0.42, top + w * 0.3, w * 0.12, base - top - w * 0.3, "rgb(255 255 255 / 14%)"));
}

/** The bus-stop pole, out in the open past the end of the shelter and taller than it, laid out as at every stop. From the
 * top: the blue square with a bus; two wings of one width, the stop's code over its name on the left and the
 * public-transport symbol on the right; below them two green wings of the same width, each with six services in two rows
 * of three. */
function stopPole(u: number, c: Palette): SVGElement {
  const d = 2.0, s = scaleAt(d), x = at(u, d), base = pavement(d), y = (m: number) => atHeight(d, m);
  const half = 0.065 * s, wing = 0.74 * s, sq = 0.36 * s, sqTop = y(3.82);
  const bold = { "font-weight": 700, "text-anchor": "middle" };
  const parts: SVGElement[] = [R(x - half, sqTop + 2, 2 * half, base - sqTop - 2, "#a9aeb3"), R(x - half * 0.3, sqTop + sq, half * 0.6, base - sqTop - sq, c.signBlue, { opacity: 0.8 }),
    R(x - half * 0.9, sqTop + 2, half * 0.35, base - sqTop - 2, "rgb(255 255 255 / 25%)"),
    // the blue square, with a bus seen from the front: body, windscreen, lamps, wheels
    R(x - sq / 2, sqTop, sq, sq, c.signSquare, { rx: sq * 0.12 }),
    R(x - sq * 0.26, sqTop + sq * 0.14, sq * 0.52, sq * 0.62, "#ffffff", { rx: sq * 0.09 }),
    R(x - sq * 0.19, sqTop + sq * 0.2, sq * 0.38, sq * 0.22, c.signSquare, { rx: sq * 0.03 }), R(x - sq * 0.11, sqTop + sq * 0.16, sq * 0.22, sq * 0.025, c.signSquare),
    C(x - sq * 0.15, sqTop + sq * 0.6, sq * 0.04, c.signSquare), C(x + sq * 0.15, sqTop + sq * 0.6, sq * 0.04, c.signSquare),
    R(x - sq * 0.2, sqTop + sq * 0.74, sq * 0.1, sq * 0.09, "#ffffff", { rx: sq * 0.02 }), R(x + sq * 0.1, sqTop + sq * 0.74, sq * 0.1, sq * 0.09, "#ffffff", { rx: sq * 0.02 })];
  // the top wings: code over name; the public-transport symbol
  const wt = y(3.38), wb = y(2.92), hh = wb - wt, lx = x - half - wing, rx = x + half;
  parts.push(R(lx, wt, wing, hh, c.signTeal, { rx: 0.6 }), R(lx + 0.8, wt + 0.8, wing - 1.6, hh * 0.36, c.signBlue),
    T(lx + wing / 2, wt + 0.8 + hh * 0.29, "43009", hh * 0.27, "#ffffff", { ...bold, "letter-spacing": 0.3 }),
    R(lx + 0.8, wt + 0.8 + hh * 0.36, wing - 1.6, hh * 0.26, c.signLight),
    T(lx + wing / 2, wt + 0.8 + hh * 0.555, "Blk 607", hh * 0.17, c.signTeal, bold),
    R(rx, wt, wing, hh, c.signTeal, { rx: 0.6 }), symbol(rx + wing / 2, wt + hh / 2, hh * 0.78));
  // the green wings: six services each, two rows of three
  const gt = y(2.86), gb = y(2.52), services = [["66", "78", "97", "143", "183", "185"], ["197", "333", "335", "", "", ""]];
  [lx, rx].forEach((left, i) => {
    parts.push(R(left, gt, wing, gb - gt, c.signTeal, { rx: 0.6 }));
    const cw = (wing - 1.6) / 3, ch = (gb - gt - 1.6) / 2;
    services[i].forEach((service, k) => {
      const cx = left + 0.8 + (k % 3) * cw, cy = gt + 0.8 + Math.floor(k / 3) * ch;
      parts.push(R(cx + 0.25, cy + 0.25, cw - 0.5, ch - 0.5, c.signMint));
      if (service) parts.push(T(cx + cw / 2, cy + ch * 0.72, service, ch * 0.6, "#111111", bold));
    });
  });
  return G({}, ...parts);
}

/** The public-transport symbol on the sign: two yellow bands that wave from lower left to upper right. */
function symbol(cx: number, cy: number, size: number): SVGElement {
  const X = (f: number) => (cx + (f - 0.5) * size).toFixed(2), Y = (f: number) => (cy + (f - 0.45) * size).toFixed(2);
  const band = (dy: number) => P(`M ${X(0.06)} ${Y(0.46 + dy)} C ${X(0.3)} ${Y(0.06 + dy)} ${X(0.5)} ${Y(0.62 + dy)} ${X(0.94)} ${Y(0.2 + dy)}`, "none",
    { stroke: "#f6b818", "stroke-width": size * 0.16, "stroke-linecap": "butt" });
  return G({}, band(0), band(0.27));
}

// --- overhead: the canopy's edge ---------------------------------------------------------------------------------------

// The shelter's roof reaches out over the bollards, as at most stops: its front edge is 2 m in front of you, 2.75 m up.
const SHELTER_D = 2.0;
const EDGE = atHeight(SHELTER_D, 2.75), FASCIA = atHeight(SHELTER_D, 2.55) - EDGE;
const ROOF = [-430, 80];                               // the shelter runs to your left and ends a little to your right
const DRIP_LINE = pavement(SHELTER_D);                 // where the water off its edge lands
/** Screen x, on the paving, of a line running towards you from where the roof's end (x at its edge) meets it. */
const roofEnd = (x: number, y: number) => CX + ((x - CX) * (y - HORIZON)) / (DRIP_LINE - HORIZON);

function canopy(c: Palette, rain: boolean): SVGElement[] {
  const [a, b] = ROOF, spread = HORIZON / (HORIZON - EDGE);                         // the underside's ends recede to eye level
  const out: SVGElement[] = [P(`M ${CX + a * spread} 0 L ${CX + b * spread} 0 L ${CX + b} ${EDGE} L ${CX + a} ${EDGE} Z`, c.canopyUnder)];
  for (let u = a + 50; u < b; u += 50) {                                           // the ribs, running back over your head
    out.push(P(`M ${CX + u} ${EDGE} L ${CX + u * spread} 0`, "none", { stroke: "rgb(0 0 0 / 10%)", "stroke-width": 1.2 }));
  }
  const light = atHeight(1.45, 2.72);                                                // a long light under the roof, overhead
  if (rain) out.push(R(CX + a + 30, light - 5, b - a - 50, 12, "rgb(255 250 225 / 30%)", { rx: 5 }));
  out.push(R(CX + a + 30, light, b - a - 50, 2.6, c.canopyLight, { rx: 1.3 }), R(CX + a + 30, light + 2.6, b - a - 50, 0.9, "rgb(0 0 0 / 12%)"),
    P(`M ${CX + b} ${EDGE} L ${CX + b * spread} 0 L ${CX + b * spread + 5} 0 L ${CX + b + 6} ${EDGE} Z`, c.canopy),   // its end
    R(CX + a - 6, EDGE, b - a + 12, FASCIA, c.canopy), R(CX + a - 6, EDGE + FASCIA * 0.32, b - a + 12, FASCIA * 0.22, c.accent),
    R(CX + a - 6, EDGE + FASCIA - 0.9, b - a + 12, 0.9, "rgb(0 0 0 / 25%)"));
  return out;
}

// --- the storm ---------------------------------------------------------------------------------------------------------

interface Storm { road: SVGElement; ground: SVGElement; rain: SVGElement; drips: SVGElement; flash: SVGElement; tick(dt: number): void }

/** Heavy rain. Three layers of streaks (fine and slow far away, long and fast near), slanting in the wind, each a
 * repeating pattern moved down a tile at a time; water pouring off the canopy's edge in front of you; splashes on the
 * road and the pavement; and every ten seconds or so a faint double flicker of lightning. */
function storm(defs: SVGElement[]): Storm {
  const rand = seeded(57);
  const layers = [
    { w: 24, h: 46, n: 7, len: [5, 7], width: 0.45, alpha: 0.34, speed: 420 },
    { w: 37, h: 71, n: 6, len: [10, 14], width: 0.7, alpha: 0.36, speed: 560 },
    { w: 59, h: 113, n: 4, len: [18, 26], width: 1.0, alpha: 0.28, speed: 760 },
  ];
  const streams = layers.map((layer) => {
    const id = nextId("cmb-rain"), streaks: SVGElement[] = [];
    for (let i = 0; i < layer.n; i++) {
      const x = rand() * layer.w, y = rand() * layer.h, len = layer.len[0] + rand() * (layer.len[1] - layer.len[0]);
      for (const shift of [0, -layer.h]) {                                          // a streak crossing the tile's foot wraps to its head
        streaks.push(R(x, y + shift, layer.width, len, "#e4eaef", { opacity: layer.alpha, rx: layer.width / 2 }));
      }
    }
    defs.push(svg("pattern", { id, width: layer.w, height: layer.h, patternUnits: "userSpaceOnUse" }, ...streaks));
    const g = G({}, R(-300, -layer.h, W + 600, HEIGHT + 2 * layer.h, `url(#${id})`));
    return { g, layer, y: rand() * layer.h };
  });
  // no rain under the roof: it falls beyond the edge, and on the paving only past the shelter's ends
  const [left, right] = ROOF.map((u) => CX + u), wet = nextId("cmb-wet");
  defs.push(svg("clipPath", { id: wet }, R(0, 0, W, DRIP_LINE, "#000"),
    P(`M 0 ${DRIP_LINE} L ${left} ${DRIP_LINE} L ${roofEnd(left, HEIGHT)} ${HEIGHT} L 0 ${HEIGHT} Z`, "#000"),
    P(`M ${right} ${DRIP_LINE} L ${W} ${DRIP_LINE} L ${W} ${HEIGHT} L ${roofEnd(right, HEIGHT)} ${HEIGHT} Z`, "#000")));
  const rain = G({ "clip-path": `url(#${wet})` }, G({ transform: "skewX(-9)" }, ...streams.map((stream) => stream.g)));
  // the canopy's edge: a curtain of drips across its length, falling to the bollard line
  const clip = nextId("cmb-clip"), drip = nextId("cmb-drip");
  defs.push(svg("clipPath", { id: clip }, R(left, EDGE + FASCIA, right - left, DRIP_LINE - EDGE - FASCIA, "#000")),
    svg("pattern", { id: drip, width: 23, height: 64, patternUnits: "userSpaceOnUse" },
      R(7, 6, 1.3, 15, "#eef3f7", { opacity: 0.5, rx: 0.6 }), R(16, 38, 1.1, 12, "#eef3f7", { opacity: 0.42, rx: 0.5 })));
  const dripTile = 64, dripSheet = G({}, R(left, EDGE - dripTile, right - left, HEIGHT + dripTile, `url(#${drip})`));
  let dripY = 0;
  const drips = G({ "clip-path": `url(#${clip})` }, dripSheet);
  // splashes: rings that spring up and fade, on the road (small, far), along the bollard line where the roof drips, and
  // on the paving past the shelter's ends (larger, near)
  const splashes = (place: () => [number, number], count: number) => {
    const items = Array.from({ length: count }, () => ({ el: svg("ellipse", { fill: "none", stroke: "#e6edf2", "stroke-width": 0.5 }), x: 0, y: 0, t: 0, k: 1 }));
    const spawn = (item: (typeof items)[number]) => {
      [item.x, item.y] = place(); item.k = (item.y - HORIZON) / (BASE - HORIZON); item.t = 0;
    };
    items.forEach((item) => { spawn(item); item.t = rand(); });
    return {
      g: G({}, ...items.map((item) => item.el)),
      tick(dt: number) {
        for (const item of items) {
          item.t += dt / 0.32;
          if (item.t >= 1) spawn(item);
          const r = (0.4 + 2.4 * item.t) * item.k;
          item.el.setAttribute("cx", item.x.toFixed(1)); item.el.setAttribute("cy", item.y.toFixed(1));
          item.el.setAttribute("rx", r.toFixed(2)); item.el.setAttribute("ry", (r * 0.3).toFixed(2));
          item.el.setAttribute("opacity", ((1 - item.t) * 0.7).toFixed(2));
        }
      },
    };
  };
  const roadTop = groundW(ROAD.farKerb), paveTop = pavement(KERB_NEAR) + 1;
  const onRoad = splashes(() => [CX + (rand() - 0.5) * 1100, roadTop + rand() * (BASE - roadTop)], 70);
  const underEdge = splashes(() => [left + rand() * (right - left), DRIP_LINE + (rand() - 0.5) * 2], 28);
  const pastEnds = splashes(() => {
    const y = paveTop + rand() * (HEIGHT - 2 - paveTop);
    return [rand() < 0.5 ? roofEnd(right, y) + 4 + rand() * 420 : roofEnd(left, y) - 4 - rand() * 300, y];
  }, 22);
  const onGround = { g: G({}, underEdge.g, pastEnds.g), tick(dt: number) { underEdge.tick(dt); pastEnds.tick(dt); } };
  // lightning: a faint double flicker over everything, every ten seconds or so
  const flash = R(0, 0, W, HEIGHT, "#eef3ff", { opacity: 0, "pointer-events": "none" });
  let since = 0, next = 6 + rand() * 5;
  return {
    road: onRoad.g, ground: onGround.g, rain, drips, flash,
    tick(dt) {
      for (const stream of streams) {
        stream.y = (stream.y + stream.layer.speed * dt) % stream.layer.h;
        stream.g.setAttribute("transform", `translate(0 ${stream.y.toFixed(1)})`);
      }
      dripY = (dripY + 620 * dt) % dripTile;
      dripSheet.setAttribute("transform", `translate(0 ${dripY.toFixed(1)})`);
      onRoad.tick(dt); onGround.tick(dt);
      since += dt;
      const k = since - next;
      flash.setAttribute("opacity", k < 0 ? "0" : k < 0.07 ? "0.16" : k < 0.16 ? "0" : k < 0.22 ? "0.1" : "0");
      if (k > 0.3) { since = 0; next = 9 + rand() * 8; }
    },
  };
}

const POLE = 205;
// a stone bollard every 2 m along the kerb, evenly, with the pole midway between two of them
const BOLLARDS = Array.from({ length: 40 }, (_, k) => POLE - 33 + 66 * (k - 20));

function busStopScene(): { bg: SVGSVGElement; bus: Bus; walkers: Walker[]; storm: Storm | null } {
  const rain = isRain(), c = rain ? RAIN : DAY;
  const defs: SVGElement[] = [];
  const walkers = people(rain);
  const far = backdrop(c, rain, defs, walkers);
  const theBus = bus(c, rain, defs);
  const near = kerbAndPavement(c, defs);
  const weather = rain ? storm(defs) : null;
  const bg = svg("svg", { class: "cm-bg", width: W, height: HEIGHT, viewBox: `0 0 ${W} ${HEIGHT}`, "aria-hidden": "true" },
    svg("defs", {}, ...defs), ...far, weather?.road ?? null, theBus.g, ...near, weather?.ground ?? null,
    ...BOLLARDS.map((u) => bollard(u, c)), stopPole(POLE, c), weather?.rain ?? null, ...canopy(c, rain), weather?.drips ?? null, weather?.flash ?? null);
  return { bg, bus: theBus, walkers, storm: weather };
}

// --- the loader -------------------------------------------------------------------------------------------------------

const FOLDED = 0.16;                                 // an open leaf, folded back against its hinge, seen nearly edge-on

/** While Review fetches the logs around an observation (the Commuter pack). */
export function busStopLoader(label: string): TrainLoader {
  const parts = busStopScene();
  const scene = h("div", { class: "tl-scene cm-scene cmu-busstop", "aria-hidden": "true" }, parts.bg);
  const me = commuterPhone();
  scene.append(me.el);
  let x = W + 600;
  const place = (to: number) => {
    const turn = ((to - x) / 16.5) * (180 / Math.PI);                                    // rolling: the hubs turn with the distance
    x = to;
    parts.bus.g.setAttribute("transform", `translate(${x.toFixed(1)} 0)`);
    parts.bus.wheels.forEach((w, i) => {
      const angle = (Number(w.dataset.angle ?? 0) + turn) % 360;
      w.dataset.angle = String(angle);
      w.setAttribute("transform", `translate(${AXLES[i]} ${BASE - 16.5}) rotate(${angle.toFixed(1)})`);
    });
  };
  const open = (t: number) => parts.bus.doors.forEach(({ leaves, hinges }) => leaves.forEach((leaf, i) => {
    const k = (1 - (1 - FOLDED) * t).toFixed(3);
    leaf.setAttribute("transform", `translate(${hinges[i]} 0) scale(${k} 1) translate(${-hinges[i]} 0)`);
  }));
  if (moving()) {
    let last = performance.now();
    const frame = (now: number) => {
      if (!scene.isConnected) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      me.tick(dt);
      parts.walkers.forEach((w) => w.tick(dt));
      parts.storm?.tick(dt);
      last = now;
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  } else me.still();

  const ending = async (missed: boolean): Promise<void> => {
    if (!moving() || !arrivalWanted(scene)) return;
    const half = scene.clientWidth / 2, from = CX + half + 30;
    place(from);
    await tween(scene, 3600, (t) => place(lerp(from, BUS_STOP_X, Math.sin((Math.PI / 2) * t))));      // braking to a stop
    await sleep(250);
    await tween(scene, 600, open);
    if (!missed) {
      await tween(scene, 700, (t) => me.lower(t));
      await sleep(450);
      return;
    }
    await sleep(1600);                                 // the doors are open; you are still playing
    await tween(scene, 600, (t) => open(1 - t));
    await sleep(350);
    const gone = CX - half - BUS_L - 60;
    await tween(scene, 2800, (t) => place(lerp(BUS_STOP_X, gone, easeIn(t))));
    await tween(scene, 650, (t) => me.lower(t));       // and now you look up
    await sleep(450);
  };
  return loaderShell(label, scene, () => ending(false), () => ending(true));
}
