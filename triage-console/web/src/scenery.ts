// Scenery for the SQL waiting indicator: the train stays put and a Singapore
// heartland town scrolls past it in layers that move at different speeds: hazy
// blocks far away, HDB flats, a school, a car park, a hawker centre and a condo
// in the middle, and the viaduct close by, which now and then runs through a
// tunnel under a hill. No city centre: there the line is underground.
//
// Day in the light theme, night in the dark one. Every colour is a --sc-* token in
// styles.css, and parts marked sc-day / sc-night are shown by the theme, so the
// same drawing serves both. Built once (seeded, so it always looks the same),
// then cloned for each loader.

import { h, svg } from "./dom";

export const SCENE_H = 150;
const GROUND = 146;            // ground line, behind the viaduct
export const DECK = 122;       // rail head on the viaduct: where the wheels run

interface Layer { name: string; width: number; speed: number; seed: number; draw(rand: () => number, w: number): SVGElement[] }

export const rect = (x: number, y: number, w: number, hgt: number, cls: string) =>
  svg("rect", { x: x.toFixed(1), y: y.toFixed(1), width: w.toFixed(1), height: hgt.toFixed(1), class: cls });
export const ellipse = (cx: number, cy: number, rx: number, ry: number, cls: string) =>
  svg("ellipse", { cx: cx.toFixed(1), cy: cy.toFixed(1), rx: rx.toFixed(1), ry: ry.toFixed(1), class: cls });
export const poly = (points: [number, number][], cls: string) =>
  svg("polygon", { points: points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" "), class: cls });

export function seeded(seed: number): () => number {            // mulberry32
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export const between = (rand: () => number, lo: number, hi: number) => lo + rand() * (hi - lo);
const pick = <T,>(rand: () => number, items: T[]) => items[Math.floor(rand() * items.length)];

// --- the buildings (mid layer: 5.4 px a floor) --------------------------------------------------

const FLOOR = 5.4;

function windowGrid(out: SVGElement[], rand: () => number, x: number, top: number, w: number, floors: number, litShare: number) {
  for (let f = 0; f < floors; f++) {
    const y = top + 2.4 + f * FLOOR;
    for (let cx = x + 3; cx + 3.4 <= x + w - 3; cx += 7) out.push(rect(cx, y, 3.4, 2.5, rand() < litShare ? "win lit" : "win"));
  }
}

// A slab block like the photo: cream facade, pastel stair-and-lift cores with coloured roof caps,
// a grid of windows and an open void deck on the ground floor.
function hdbSlab(out: SVGElement[], rand: () => number, x: number): number {
  const floors = 14 + Math.floor(rand() * 7), w = 84 + Math.floor(rand() * 5) * 14;
  const height = floors * FLOOR + 8, top = GROUND - height;
  out.push(rect(x, top, w, height, "hdb"), rect(x + w - 5, top, 5, height, "hdb-shade"));
  windowGrid(out, rand, x, top + 2, w - 5, floors, 0.3);
  const accent = pick(rand, ["acc1", "acc2", "acc3"]), cap = pick(rand, ["cap1", "cap2"]);
  const cores = w > 110 ? [0.24, 0.66] : [0.4];
  for (const share of cores) {
    const bx = x + w * share, bw = 10;
    out.push(rect(bx, top - 3, bw, height - 5, accent));
    for (let f = 1; f < floors; f += 2) out.push(rect(bx + 3.5, top + f * FLOOR, 3, 3.2, "win"));
    out.push(poly([[bx - 3, top - 3], [bx + bw + 3, top - 3], [bx + bw, top - 9], [bx, top - 9]], cap));
  }
  out.push(rect(x, top, w, 1.6, "hdb-shade"), rect(x, GROUND - 8, w, 8, "void"));
  for (let px = x + 2; px < x + w - 2; px += 13) out.push(rect(px, GROUND - 8, 3, 8, "hdb"));
  return w;
}

function hdbPoint(out: SVGElement[], rand: () => number, x: number): number {
  const floors = 20 + Math.floor(rand() * 6), w = 40 + Math.floor(rand() * 2) * 7;
  const height = floors * FLOOR + 8, top = GROUND - height;
  out.push(rect(x, top, w, height, "hdb"), rect(x + w - 4, top, 4, height, "hdb-shade"));
  windowGrid(out, rand, x, top + 2, w - 4, floors, 0.3);
  const cap = pick(rand, ["cap1", "cap2"]);
  out.push(rect(x + w / 2 - 5, top - 3, 10, height - 5, pick(rand, ["acc1", "acc2", "acc3"])),
    poly([[x + w / 2 - 8, top - 3], [x + w / 2 + 8, top - 3], [x + w / 2 + 5, top - 10], [x + w / 2 - 5, top - 10]], cap),
    rect(x, GROUND - 8, w, 8, "void"));
  for (let px = x + 2; px < x + w - 2; px += 12) out.push(rect(px, GROUND - 8, 3, 8, "hdb"));
  return w;
}

// Four storeys of classrooms with coloured corridor parapets, a hall and the field.
function school(out: SVGElement[], rand: () => number, x: number): number {
  const w = 170, top = GROUND - 38;
  out.push(rect(x, top, w, 38, "school"));
  for (let f = 0; f < 4; f++) {
    const y = top + 4 + f * 8.5;
    for (let cx = x + 4; cx < x + w - 6; cx += 9) out.push(rect(cx, y + 2.4, 4.2, 3.6, rand() < 0.12 ? "win lit" : "win"));
    out.push(rect(x, y + 6.2, w, 2, f % 2 ? "band1" : "band2"));
  }
  out.push(poly([[x - 3, top], [x + w + 3, top], [x + w - 8, top - 6], [x + 8, top - 6]], "roof"));
  const hall = x + w + 8;                                                     // the school hall
  out.push(rect(hall, GROUND - 22, 58, 22, "school"), poly([[hall - 3, GROUND - 22], [hall + 61, GROUND - 22], [hall + 29, GROUND - 32]], "roof"));
  for (let cx = hall + 5; cx < hall + 54; cx += 8) out.push(rect(cx, GROUND - 16, 4, 9, "win"));
  const field = hall + 70;                                                    // the field, with its goals and running track
  out.push(rect(field, GROUND - 3, 120, 3, "field"), rect(field, GROUND - 1.2, 120, 1.2, "track"));
  for (const gx of [field + 12, field + 104]) out.push(rect(gx, GROUND - 8, 0.9, 6, "goal"), rect(gx + 4, GROUND - 8, 0.9, 6, "goal"), rect(gx, GROUND - 8, 4.9, 0.9, "goal"));
  return field + 120 - x;
}

function carPark(out: SVGElement[], rand: () => number, x: number): number {
  const w = 96, levels = 6, top = GROUND - levels * 7 - 3;
  for (let l = 0; l < levels; l++) {
    const y = top + l * 7;
    out.push(rect(x, y, w, 2.4, "mscp"), rect(x, y + 2.4, w, 4.6, "gap"));
    for (let cx = x + 3; cx < x + w - 8; cx += 9) if (rand() < 0.6) out.push(rect(cx, y + 4.2, 6.5, 2.8, pick(rand, ["car1", "car2", "car3"])));
  }
  out.push(rect(x, GROUND - 3, w, 3, "mscp"));
  for (let cx = x; cx <= x + w - 2.4; cx += 23.4) out.push(rect(cx, top, 2.4, GROUND - top, "mscp"));
  return w;
}

function hawkerCentre(out: SVGElement[], _rand: () => number, x: number): number {
  const w = 120;
  out.push(rect(x + 4, GROUND - 16, w - 8, 16, "hawker"),
    poly([[x - 4, GROUND - 16], [x + w + 4, GROUND - 16], [x + w - 16, GROUND - 30], [x + 16, GROUND - 30]], "roof"));
  for (let cx = x + 6; cx < x + w - 6; cx += 14) out.push(rect(cx, GROUND - 16, 2, 16, "hawker-col"));
  for (let cx = x + 12; cx < x + w - 10; cx += 14) out.push(rect(cx, GROUND - 12, 6, 4, "win lit"));
  return w;
}

function condo(out: SVGElement[], rand: () => number, x: number): number {
  const floors = 24 + Math.floor(rand() * 5), w = 46, height = floors * FLOOR + 6, top = GROUND - height;
  out.push(rect(x, top, w, height, "glass"));
  for (let f = 0; f < floors; f++) {
    const y = top + 2 + f * FLOOR;
    if (rand() < 0.28) out.push(rect(x + 3 + rand() * 18, y + 0.6, 12 + rand() * 10, 3, "glass-lit"));
    out.push(rect(x - 1.5, y + 3.8, w + 3, 1.2, "balcony"));
  }
  out.push(poly([[x - 2, top], [x + w + 2, top], [x + w - 6, top - 8], [x + 6, top - 8]], "balcony"));
  return w;
}

export function rainTree(out: SVGElement[], rand: () => number, x: number, scale = 1, base = GROUND): number {
  const w = (26 + rand() * 18) * scale, cy = base - (14 + rand() * 6) * scale;
  out.push(rect(x + w / 2 - 1.5, cy, 3 * scale, base - cy, "trunk"),
    ellipse(x + w / 2, cy + 2 * scale, w / 2, 7 * scale, "tree-dark"),
    ellipse(x + w * 0.38, cy - 1.5 * scale, w * 0.32, 6 * scale, "tree"),
    ellipse(x + w * 0.64, cy - 2.5 * scale, w * 0.3, 6.5 * scale, "tree"));
  return w;
}

function lamp(out: SVGElement[], x: number) {
  out.push(rect(x, GROUND - 16, 1.1, 16, "lamp"), ellipse(x + 0.5, GROUND - 16, 6, 6, "lamp-glow sc-night"));
}

type Draw = (out: SVGElement[], rand: () => number, x: number) => number;
const AMENITIES: Draw[] = [school, carPark, hawkerCentre, condo];

// --- the layers ------------------------------------------------------------------------------------

const LAYERS: Layer[] = [
  { name: "clouds sc-day", width: 1400, speed: 5, seed: 11, draw(rand, w) {
    const out: SVGElement[] = [];
    for (let x = 30; x < w - 160; x += between(rand, 180, 340)) {
      const y = between(rand, 14, 52), s = between(rand, 0.7, 1.3);
      out.push(ellipse(x, y, 26 * s, 7 * s, "cloud"), ellipse(x + 20 * s, y - 5 * s, 18 * s, 8 * s, "cloud"), ellipse(x + 40 * s, y, 22 * s, 6 * s, "cloud"));
    }
    return out;
  } },
  { name: "far", width: 1600, speed: 12, seed: 23, draw(rand, w) {
    const out: SVGElement[] = [];
    for (let x = 0; x < w - 80; x += between(rand, 6, 34)) {
      const bw = between(rand, 26, 70), bh = between(rand, 44, 82), top = GROUND - 10 - bh;
      out.push(rect(x, top, bw, bh + 10, "far"));
      if (rand() < 0.35) out.push(rect(x + bw * 0.4, top - 5, 8, 5, "far"));
      for (let i = 0; i < bw * bh / 260; i++) out.push(rect(x + 2 + rand() * (bw - 5), top + 3 + rand() * (bh - 8), 1.6, 1.4, "far-lit sc-night"));
      x += bw;
    }
    return out;
  } },
  { name: "mid", width: 2600, speed: 34, seed: 37, draw(rand, w) {
    const out: SVGElement[] = [rect(0, GROUND - 2, w, SCENE_H - GROUND + 2, "ground")];
    // nothing may cross the right edge, or the repeat would show a seam
    const place = (draw: Draw, x: number): number | null => {
      const parts: SVGElement[] = [];
      const bw = draw(parts, rand, x);
      if (x + bw > w - 60) return null;
      out.push(...parts);
      return bw;
    };
    let x = 10, amenity = 0;
    estates: for (;;) {
      for (let b = 3 + Math.floor(rand() * 3); b > 0; b--) {           // an estate: HDB blocks close together
        const bw = place(rand() < 0.7 ? hdbSlab : hdbPoint, x);
        if (bw === null) break estates;
        x += bw + between(rand, 5, 16);
      }
      x += rainTree(out, rand, x) + between(rand, 4, 12);
      const bw = place(AMENITIES[amenity++ % AMENITIES.length], x);     // then a school, car park, hawker centre or condo
      if (bw === null) break;
      x += bw + between(rand, 12, 26);
      if (rand() < 0.6) x += rainTree(out, rand, x) + 6;
    }
    for (let tx = 4; tx < w - 50; tx += between(rand, 14, 40)) rainTree(out, rand, tx, between(rand, 0.45, 0.7));   // the green line in front
    for (let lx = 40; lx < w - 10; lx += 150) lamp(out, lx);
    return out;
  } },
];

// The near layer runs on the viaduct and, once a lap, through a tunnel under a hill (cutaway view).
const NEAR = { width: 3360, speed: 140, seed: 53, tunnelAt: 2050, tunnelLength: 980 };

function nearBack(rand: () => number): SVGElement[] {
  const { width: w, tunnelAt: t0, tunnelLength: len } = NEAR;
  const inTunnel = (x: number) => x > t0 - 20 && x < t0 + len + 20;
  const out: SVGElement[] = [rect(0, DECK, w, 9, "deck"), rect(0, DECK, w, 1.6, "deck-edge"), rect(0, DECK + 9, w, 2, "deck-shade"),
    rect(0, DECK - 1.4, w, 1.4, "rail")];
  for (let x = 6; x < w; x += 24) out.push(rect(x, DECK + 4, 8, 1.2, "deck-mark"));
  for (let x = 40; x < w - 20; x += 112) if (!inTunnel(x)) out.push(rect(x, DECK + 9, 11, SCENE_H - DECK - 9, "pillar"), rect(x - 3, DECK + 9, 17, 3, "pillar"));
  // the hill, the tube through it, and lights along the tube wall
  const top = 22;
  const surface: [number, number][] = [[t0, DECK + 2], [t0 + 50, DECK - 14], [t0 + 150, top + 26], [t0 + 270, top],
    [t0 + len - 270, top], [t0 + len - 150, top + 26], [t0 + len - 50, DECK - 14], [t0 + len, DECK + 2]];
  const surfaceAt = (x: number) => {
    for (let i = 1; i < surface.length; i++) {
      const [x0, y0] = surface[i - 1], [x1, y1] = surface[i];
      if (x <= x1) return y0 + ((x - x0) / (x1 - x0)) * (y1 - y0);
    }
    return DECK + 2;
  };
  const below = (depth: number, from: number, to: number): [number, number][] => {
    const pts: [number, number][] = [];
    for (let x = from; x <= to; x += 20) pts.push([x, surfaceAt(x) + depth]);
    return pts;
  };
  out.push(poly([[t0, SCENE_H], ...surface, [t0 + len, SCENE_H]], "hill"),
    svg("polyline", { points: surface.map(([x, y]) => `${x},${y + 1}`).join(" "), class: "hill-edge" }));
  // cut away: the soil under the grass, in layers, so it reads as underground
  const cut = { from: t0 + 70, to: t0 + len - 70 };
  out.push(poly([[cut.from, SCENE_H], ...below(7, cut.from, cut.to), [cut.to, SCENE_H]], "soil"));
  for (const depth of [20, 34, 98]) {
    out.push(svg("polyline", { points: below(depth, cut.from + 10, cut.to - 10).map(([x, y]) => `${x},${Math.min(y, SCENE_H - 2)}`).join(" "), class: "strata" }));
  }
  for (let x = t0 + 275; x < t0 + len - 300; x += between(rand, 30, 60)) rainTree(out, rand, x, 0.55, top + 1);
  out.push(...tunnelInside({ x: t0 + 90, y: DECK - 50, w: len - 180, h: 58 }));
  return out;
}

// Inside the bored tunnel, as on a Singapore MRT line: the concrete lining in rings, wall lamps,
// cable trays on brackets with an orange cable, green EXIT signs, the fire main with red valves,
// the emergency walkway and its handrail, and the concrete track bed with its sleepers.
function tunnelInside(tube: { x: number; y: number; w: number; h: number }): SVGElement[] {
  const { x: x0, y: y0, w, h: hgt } = tube, x1 = x0 + w;
  const along = (step: number, from: number, draw: (x: number) => SVGElement[]) => {
    const parts: SVGElement[] = [];
    for (let x = x0 + from; x < x1 - 4; x += step) parts.push(...draw(x));
    return parts;
  };
  return [
    rect(x0, y0, w, hgt, "tube"), rect(x0, y0 + 2, w, 9, "tube-top"),
    ...along(16, 8, (x) => [rect(x, y0 + 2, 0.8, hgt - 10, "ring")]),                                  // lining rings
    ...along(46, 14, (x) => [ellipse(x + 3.5, y0 + 9, 10, 5.5, "tube-glow"), rect(x, y0 + 4, 7, 1.8, "tube-light")]),
    rect(x0, y0 + 12, w, 1.3, "tray"), rect(x0, y0 + 16.5, w, 1.3, "tray"), rect(x0, y0 + 18.3, w, 0.9, "cable"),
    ...along(10, 4, (x) => [rect(x, y0 + 11, 0.8, 7.5, "tray")]),                                        // tray brackets
    ...along(230, 60, (x) => [rect(x, y0 + 23, 10, 4.6, "exit"), rect(x + 2, y0 + 24.7, 6, 1.3, "exit-mark")]),
    rect(x0, y0 + 30, w, 1.8, "pipe"),
    ...along(120, 40, (x) => [rect(x, y0 + 28.4, 3.2, 5, "valve")]),                                     // fire main valves
    rect(x0, DECK - 21, w, 0.9, "walk-rail"), rect(x0, DECK - 13, w, 3, "walkway"),
    ...along(14, 6, (x) => [rect(x, DECK - 21, 0.8, 8, "walk-rail")]),                                   // walkway handrail posts
    rect(x0, DECK, w, 6, "plinth"),
    ...along(8, 2, (x) => [rect(x, DECK + 0.8, 4, 1.6, "sleeper")]),
    rect(x0, DECK - 1.4, w, 1.4, "rail"),
    rect(x0, y0, w, 2, "tube-edge"), rect(x0, y0 + hgt - 2, w, 2, "tube-edge"),
  ];
}

// Stretches with metal sound barriers, where the line runs past housing estates. The first and last
// join across the end of the lap, so they read as one stretch when the picture repeats.
const BARRIERS: [number, number][] = [[0, 620], [1150, 1820], [3090, NEAR.width]];

function nearFront(): SVGElement[] {
  const { width: w, tunnelAt: t0, tunnelLength: len } = NEAR;
  const tube = { x: t0 + 90, y: DECK - 50, w: len - 180, h: 58 };
  // shade over the train while it is inside, and the portal walls it passes behind
  const out: SVGElement[] = [rect(tube.x, tube.y, tube.w, tube.h, "tube-shade"),
    rect(tube.x - 8, tube.y - 6, 12, tube.h + 6, "portal"), rect(tube.x + tube.w - 4, tube.y - 6, 12, tube.h + 6, "portal")];
  // the near edge of the viaduct, in front of the train: a low upstand and a railing all along
  // (not inside the tunnel), and sound barriers through the estates
  const open = [[0, t0 + 40], [t0 + len - 40, w]];
  for (const [a, b] of open) {
    out.push(rect(a, DECK - 2.2, b - a, 2.6, "upstand"), rect(a, DECK - 10, b - a, 1, "railing"), rect(a, DECK - 6, b - a, 0.7, "railing"));
    for (let x = a + 3; x < b - 1; x += 12) out.push(rect(x, DECK - 10, 0.9, 8, "railing"));
  }
  for (const [a, b] of BARRIERS) {
    out.push(rect(a, DECK - 16, b - a, 14, "barrier noise"), rect(a, DECK - 16.6, b - a, 1.4, "barrier-post noise"));
    for (let x = a + 6; x < b - 1; x += 26) out.push(rect(x, DECK - 17.5, 2, 16, "barrier-post noise"));
  }
  return out;
}

// Each layer holds its picture twice, side by side, and slides left by one width, then repeats.
export function layer(name: string, width: number, speed: number, parts: SVGElement[]): HTMLElement {
  const copy = (dx: number) => svg("g", { transform: `translate(${dx} 0)` }, parts.map((p) => (dx ? p.cloneNode(true) as SVGElement : p)));
  const el = h("div", { class: `sc-layer sc-${name}` },
    svg("svg", { width: width * 2, height: SCENE_H, viewBox: `0 0 ${width * 2} ${SCENE_H}`, "aria-hidden": "true" }, copy(0), copy(width)));
  el.style.setProperty("--w", `${width}px`);
  el.style.animationDuration = `${(width / speed).toFixed(2)}s`;
  return el;
}

// --- the station the train pulls into when a query has finished -----------------------------------
// Seen from the track: the platform screen doors behind the train (dark glass, the green band on
// top, door markers), the long curved roof with its ribs, yellow beam and light strip, green signs
// hanging from the beam, the platform edge with its yellow line, and the concourse below.

export const STATION_W = 600;
export const NEAR_SPEED = NEAR.speed;

function stationParts(): SVGElement[] {
  const w = STATION_W, out: SVGElement[] = [rect(0, DECK + 9, w, SCENE_H - DECK - 9, "st-base")];
  for (let y = DECK + 13; y < SCENE_H; y += 4) out.push(rect(0, y, w, 1, "st-base-line"));
  out.push(rect(6, 38, w - 12, DECK - 38, "st-wall"));
  for (let x = 30; x < w - 20; x += 140) out.push(rect(x, 38, 8, DECK - 38, "st-column"));
  const top = DECK - 50;
  out.push(rect(12, top, w - 24, 50, "st-psd-frame"), rect(12, top, w - 24, 4, "st-psd-band"));
  for (let x = 12, i = 0; x + 36 <= w - 12; x += 36, i++) {        // 16 panels fill the frame exactly
    out.push(rect(x + 2, top + 6, 32, 42, "st-psd-glass"));
    if (i % 3 === 1) out.push(rect(x + 17.5, top + 6, 1, 42, "st-psd-frame"),
      poly([[x + 18, top + 20], [x + 21, top + 23], [x + 18, top + 26], [x + 15, top + 23]], "st-door-mark"));
  }
  out.push(rect(0, DECK, w, 9, "st-platform"), rect(0, DECK, w, 1.4, "st-edge"), rect(0, DECK + 2.4, w, 1.2, "st-yellow"),
    rect(0, DECK - 1.4, w, 1.4, "rail"));
  out.push(svg("path", { d: `M 0 38 Q 0 16 34 13 H ${w - 34} Q ${w} 16 ${w} 38 Z`, class: "st-roof" }));
  for (let x = 40; x < w - 30; x += 36) out.push(rect(x, 14, 1.4, 20, "st-rib"));
  out.push(rect(0, 32, w, 6, "st-roof-under"), rect(6, 38, w - 12, 4, "st-beam"), rect(12, 42, w - 24, 1.6, "st-light"));
  for (const x of [70, w - 120]) {
    out.push(rect(x, 46, 50, 11, "st-sign"),
      poly([[x + 6, 51.5], [x + 12, 48], [x + 12, 50.3], [x + 19, 50.3], [x + 19, 52.7], [x + 12, 52.7], [x + 12, 55]], "st-sign-mark"),
      rect(x + 24, 49, 20, 5, "st-sign-mark"));
  }
  return out;
}

let stationTemplate: HTMLElement | null = null;

/** The station, ready to slide in under the train (see train-loader.ts). */
export function station(): HTMLElement {
  stationTemplate ??= h("div", { class: "sc-station" },
    svg("svg", { width: STATION_W, height: SCENE_H, viewBox: `0 0 ${STATION_W} ${SCENE_H}`, "aria-hidden": "true" }, stationParts()));
  return stationTemplate.cloneNode(true) as HTMLElement;
}

let template: { back: HTMLElement; front: HTMLElement } | null = null;

/** The sky and the town (sun or moon and stars, clouds, far blocks, the estates): the same behind the
 * MRT viaduct and behind the road (bus-scenery.ts). Fresh elements on every call. */
export function town(): (HTMLElement | SVGElement)[] {
  return [h("div", { class: "sc-sun sc-day" }), h("div", { class: "sc-moon sc-night" }), stars(),
    ...LAYERS.map((l) => layer(l.name, l.width, l.speed, l.draw(seeded(l.seed), l.width)))];
}

function build(): { back: HTMLElement; front: HTMLElement } {
  const back = h("div", { class: "sc-back" }, town(),
    layer("near", NEAR.width, NEAR.speed, nearBack(seeded(NEAR.seed))));
  const front = h("div", { class: "sc-front" }, layer("near", NEAR.width, NEAR.speed, nearFront()));
  return { back, front };
}

function stars(): SVGElement {
  const rand = seeded(71);
  return svg("svg", { class: "sc-stars sc-night", width: 1800, height: 90, "aria-hidden": "true" },
    Array.from({ length: 90 }, () => rect(rand() * 1800, rand() * 88, 1.3, 1.3, rand() < 0.2 ? "star bright" : "star")));
}

/** The scenery behind the train and the parts in front of it, cloned from one drawing. */
export function scenery(): { back: HTMLElement; front: HTMLElement } {
  template ??= build();
  return { back: template.back.cloneNode(true) as HTMLElement, front: template.front.cloneNode(true) as HTMLElement };
}

// --- the depot the train stops in when a query fails --------------------------------------------------
// Drawn after the East Coast Integrated Depot, seen from the side. The train pulls into the yard and stops
// at a red signal: behind it the long depot building with its facade of staggered orange, yellow and
// red-brown fins, grey stair towers with vents and solar panels on the roof, and in front of that the
// overhead pedestrian walkway on thin columns with its steel staircase; ahead of it the taller grey block
// with red pipes, a strip of windows and the large door trains go in by, a pickup and a minibus, cones,
// red-and-white barriers, floodlight masts, and tracks fanning out through switches.
//
// The depot is wider than any view, so it cannot slide in whole within the arrival. Its left boundary,
// a grey gateway tower, is placed when the train starts to pull in (train-loader.ts): as far left as can
// still start beyond the right edge. Left of it the viaduct carries on; nothing appears out of nowhere.

export const DEPOT_W = 1700;
const NOSE = 1000;                               // where the train's nose stops
export const TRAIN_HALF = 200;                   // three cars of 133 px
const SIGNAL = NOSE + 16;
/** Where the train's centre ends up, from the depot's left edge. */
export const DEPOT_ANCHOR = NOSE - TRAIN_HALF;

function bufferStop(x: number, rail: number, s: number): SVGElement[] {
  const beam = rail - 15 * s;
  return [poly([[x - 16 * s, rail], [x - 3 * s, beam + 2 * s], [x, beam + 2 * s], [x, rail]], "dp-buffer"),
    rect(x - 2 * s, beam - 1 * s, 8 * s, 11 * s, "dp-buffer"),
    rect(x - 2 * s, beam + 2 * s, 8 * s, 2 * s, "dp-stripe"), rect(x - 2 * s, beam + 6 * s, 8 * s, 2 * s, "dp-stripe"),
    rect(x + 0.5 * s, beam - 5 * s, 3 * s, 4 * s, "dp-head"), svg("circle", { cx: x + 2 * s, cy: beam - 3 * s, r: 1.5 * s, class: "dp-red" })];
}

function track(out: SVGElement[], from: number, to: number, rail: number, s: number): void {
  for (let x = from; x < to; x += 9 * s) out.push(rect(x, rail + 0.4, 5 * s, 2.2 * s, "sleeper"));
  out.push(rect(from, rail - 1.4 * s, to - from, 1.4 * s, "rail"));
}

const path = (d: string, cls: string) => svg("path", { d, class: cls });

/** A switch: the diverging rail, from one track to the next, as a smooth curve. */
function turnout(out: SVGElement[], x0: number, y0: number, x1: number, y1: number): void {
  const mid = (x0 + x1) / 2;
  out.push(path(`M ${x0} ${y0} C ${mid} ${y0} ${mid} ${y1} ${x1} ${y1}`, "dp-rail-line"));
}

const FINS = ["dp-fin-a", "dp-fin-b", "dp-fin-c"];

function fin(out: SVGElement[], x: number, y: number, cls: string): void {
  out.push(poly([[x, y + 10], [x + 11, y + 10], [x + 15, y], [x + 4, y]], cls), poly([[x + 11, y + 10], [x + 15, y], [x + 15, y + 3], [x + 12.5, y + 10]], "dp-fin-edge"));
}

function tower(out: SVGElement[], x0: number, x1: number, top: number, bottom: number): void {
  out.push(rect(x0, top, x1 - x0, bottom - top, "dp-tower"), rect(x1 - 6, top, 6, bottom - top, "dp-tower-shade"));
  for (let y = top + 10; y < bottom - 14; y += 16) out.push(rect(x0 + (x1 - x0) / 2 - 4, y, 8, 8, "dp-vent"));
}

function depotParts(): SVGElement[] {
  const w = DEPOT_W, apron = DECK - 16, out: SVGElement[] = [];
  const rand = seeded(23);
  // the long building behind the train: solar panels, the fin facade, stair towers
  const b0 = 60, b1 = NOSE + 60, top = 36;
  out.push(rect(b0, top, b1 - b0, apron - top, "dp-wall"));
  for (let x = b0 + 6; x < b1 - 50; x += 58) out.push(poly([[x, top], [x + 50, top], [x + 45, top - 6], [x + 5, top - 6]], "dp-solar"));
  for (let r = 0; r < 5; r++) {
    for (let x = b0 + 6 + (r % 2) * 8; x < b1 - 18; x += 16) fin(out, x, top + 4 + r * 13, FINS[Math.floor(rand() * 3)]);
  }
  for (let x = b0 + 10; x < b1 - 20; x += 46) out.push(rect(x, top + 6, 10, 3, "dp-win-lit sc-night"));
  tower(out, 380, 432, 24, apron);
  tower(out, 760, 812, 20, apron);
  // the taller block ahead: fins up its corner, red pipes, windows, the train door, a lattice mast
  const r0 = b1;
  out.push(rect(r0, 28, w - r0, apron - 28 + 14, "dp-wall-light"), rect(r0, 24, w - r0, 5, "dp-tower-shade"));
  for (let k = 0; k < 7; k++) fin(out, r0 + 2 + (k % 2) * 6, 30 + k * 11, FINS[(k + 1) % 3]);
  out.push(path(`M ${r0 + 30} 50 H ${w}`, "dp-pipe"), path(`M ${r0 + 300} 58 H ${w - 60} V ${apron + 12}`, "dp-pipe"),
    path(`M ${r0 + 40} 50 V 44 H ${r0 + 120}`, "dp-pipe"));
  for (let x = r0 + 30; x < r0 + 200; x += 9) out.push(rect(x, 64, 7, 5, "dp-window"), rect(x, 64, 7, 5, "dp-win-lit sc-night"));
  const d0 = r0 + 70, d1 = r0 + 200;
  out.push(rect(d0 - 4, 74, d1 - d0 + 8, apron - 74 + 14, "dp-tower-shade"), rect(d0, 78, d1 - d0, apron - 78 + 14, "dp-door"),
    rect(d0 + 10, 84, d1 - d0 - 20, 2, "dp-door-light"));
  const mx = r0 + 260;
  out.push(rect(mx, 4, 2, 24, "dp-mast"), rect(mx + 8, 4, 2, 24, "dp-mast"));
  for (let y = 6; y < 26; y += 5) out.push(path(`M ${mx + 1} ${y} L ${mx + 9} ${y + 5} M ${mx + 9} ${y} L ${mx + 1} ${y + 5}`, "dp-lattice"));
  // the concrete apron: barriers and cones along it, a pickup and a minibus by the door
  out.push(rect(0, apron, w, 14, "dp-apron"));
  for (let x = 120; x < 560; x += 13) out.push(rect(x, DECK - 10, 12, 7, Math.round(x / 13) % 2 ? "dp-barrier-white" : "dp-barrier-red"));
  for (let x = 580; x < w - 20; x += 24 + rand() * 14) {
    if (x > d0 + 210 && x < d0 + 330) continue;                                  // the vehicles stand here
    out.push(poly([[x, DECK - 3], [x + 6, DECK - 3], [x + 3.6, DECK - 12], [x + 2.4, DECK - 12]], "dp-cone"), rect(x + 1.6, DECK - 8.5, 2.8, 1.6, "dp-cone-band"));
  }
  const vx = d0 + 214;
  out.push(poly([[vx, DECK - 3], [vx, DECK - 11], [vx + 12, DECK - 11], [vx + 15, DECK - 17], [vx + 26, DECK - 17], [vx + 28, DECK - 11], [vx + 34, DECK - 11], [vx + 34, DECK - 3]], "dp-pickup"),
    rect(vx + 16, DECK - 15.5, 9, 4, "dp-glass"), svg("circle", { cx: vx + 7, cy: DECK - 3, r: 3, class: "dp-tyre" }), svg("circle", { cx: vx + 27, cy: DECK - 3, r: 3, class: "dp-tyre" }));
  const bx = vx + 44;
  out.push(svg("rect", { x: bx, y: DECK - 22, width: 44, height: 19, rx: 4, class: "dp-minibus" }));
  for (let x = bx + 4; x < bx + 40; x += 8) out.push(rect(x, DECK - 19, 6, 6, "dp-glass"));
  out.push(svg("circle", { cx: bx + 9, cy: DECK - 3, r: 3.4, class: "dp-tyre" }), svg("circle", { cx: bx + 36, cy: DECK - 3, r: 3.4, class: "dp-tyre" }));
  // the overhead walkway in front of the building, on its columns, with a staircase down to the apron
  const k0 = 20, k1 = NOSE + 120, deck = 74;
  for (let x = k0 + 20; x < k1; x += 72) out.push(rect(x, deck + 5, 3, DECK - deck - 7, "dp-column"));
  out.push(rect(k0, deck, k1 - k0, 5, "dp-walk"), rect(k0, deck - 7, k1 - k0, 1.2, "dp-rail-top"), rect(k0, deck - 3.5, k1 - k0, 0.8, "dp-rail-top"));
  for (let x = k0; x <= k1; x += 12) out.push(rect(x, deck - 7, 1, 7, "dp-rail-top"));
  for (const s0 of [150, NOSE + 70]) {
    const s1 = s0 + 42;
    out.push(poly([[s0, deck + 5], [s0 + 6, deck + 5], [s1 + 6, DECK - 3], [s1, DECK - 3]], "dp-stair"));
    for (let t = 0.1; t < 1; t += 0.1) out.push(rect(s0 + (s1 - s0) * t, deck + 5 + (DECK - 8 - deck) * t, 7, 1, "dp-rail-top"));
    out.push(path(`M ${s0} ${deck - 2} L ${s1} ${DECK - 10}`, "dp-handrail"));
  }
  // the mesh fence along the yard
  out.push(rect(0, DECK - 26, NOSE + 40, 23, "dp-fence"));
  for (let x = 0; x <= NOSE + 40; x += 28) out.push(rect(x, DECK - 27, 1.4, 25, "dp-fence-post"));
  // floodlight masts, with their light at night
  for (const fx of [560, NOSE + 330, NOSE + 620]) {
    out.push(poly([[fx - 30, DECK], [fx + 30, DECK], [fx + 6, 10], [fx - 6, 10]], "dp-beam sc-night"),
      rect(fx - 1.5, 8, 3, DECK - 8, "dp-mast"), rect(fx - 9, 4, 18, 6, "dp-mast"),
      rect(fx - 7.5, 5, 4, 4, "lamp-head"), rect(fx - 2, 5, 4, 4, "lamp-head"), rect(fx + 3.5, 5, 4, 4, "lamp-head"));
  }
  // the yard: ballast, the train's track and the tracks fanning out ahead of it
  out.push(rect(0, DECK - 2, w, SCENE_H - DECK + 2, "dp-ballast"));
  for (let i = 0; i < 600; i++) out.push(rect(rand() * w, DECK + rand() * (SCENE_H - DECK), 1.6, 1.2, "dp-stone"));
  track(out, 0, w, DECK, 1);
  track(out, 0, w, DECK + 11, 1.2);
  track(out, NOSE + 140, w, DECK + 23, 1.4);
  turnout(out, NOSE + 40, DECK - 0.7, NOSE + 140, DECK + 10.3);
  turnout(out, NOSE + 60, DECK + 10, NOSE + 160, DECK + 22);
  turnout(out, 300, DECK + 10, 420, DECK - 0.7);
  out.push(...bufferStop(w - 50, DECK + 23, 1.4));
  // the signal ahead of the train, at red: its head above the train's roof
  const sx = SIGNAL;
  out.push(rect(sx - 1.2, DECK - 58, 2.4, 58, "dp-mast"), svg("rect", { x: sx - 5, y: DECK - 70, width: 10, height: 18, rx: 2.5, class: "dp-head" }),
    svg("circle", { cx: sx, cy: DECK - 65, r: 6, class: "dp-glow" }), svg("circle", { cx: sx, cy: DECK - 65, r: 2.6, class: "dp-red" }),
    svg("circle", { cx: sx, cy: DECK - 57.5, r: 2.6, class: "dp-off" }));
  // the gateway tower at the depot's left boundary (moved into place by train-loader.ts)
  const gate = svg("g", { class: "dp-gate" });
  const g: SVGElement[] = [];
  tower(g, 0, 40, 16, SCENE_H);
  g.push(rect(0, 12, 40, 5, "dp-tower-shade"), rect(8, 22, 24, 6, "dp-sign"), rect(12, 24, 16, 2, "dp-sign-text"));
  gate.append(...g);
  out.push(gate);
  return out;
}

let depotTemplate: HTMLElement | null = null;

/** The depot, ready to slide in behind the train when a query fails (see train-loader.ts). */
export function depot(): HTMLElement {
  depotTemplate ??= h("div", { class: "sc-station" },
    svg("svg", { width: DEPOT_W, height: SCENE_H, viewBox: `0 0 ${DEPOT_W} ${SCENE_H}`, "aria-hidden": "true" }, depotParts()));
  return depotTemplate.cloneNode(true) as HTMLElement;
}
