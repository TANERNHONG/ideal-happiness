// Scenery for the bus loader (Review's "Logs before and after"): the same heartland town as the MRT
// loader (scenery.ts), with a road in front instead of the viaduct, and an SG Bus double-decker that
// stays put while the road scrolls past. When the logs are in, the bus pulls into a bus stop.
//
// The road, seen from the side: the far pavement with its paving, rain trees and street lamps, a
// covered linkway, the kerb, asphalt with double yellow lines along both kerbs and white lane dashes,
// and once a lap an overhead pedestrian bridge: a deck with planters under a white tube roof, a lift
// tower at one end and a covered staircase at the other, its deck above the bus's roof.
// Day in the light theme, night in the dark one: colours are --sc-* / --bus-* tokens in styles.css.

import { h, svg } from "./dom";
import { SCENE_H, between, ellipse, layer, poly, rainTree, rect, seeded, town } from "./scenery";

const PAVE = 108;              // far pavement, where the trees, lamps and the bus stop stand
const KERB = 114;              // the kerb face
const ROAD_TOP = 116, ROAD_BOTTOM = 146;
export const TYRE = 127;       // where the bus's tyres meet the road (the lane by the far kerb)

// The bridge comes round a few seconds into a wait. It starts off the right edge, so a quick query's
// arrival never meets it (train-loader.ts holds back a bridge that is not yet in view).
const ROAD = { width: 2400, speed: 120, seed: 61, linkway: [1350, 1670] as [number, number], bridge: 870 };
export const ROAD_SPEED = ROAD.speed;

function roadBack(rand: () => number): SVGElement[] {
  const { width: w, linkway: [l0, l1], bridge: bx } = ROAD;
  const out: SVGElement[] = [rect(0, PAVE - 8, w, 8, "verge")];
  for (let x = 6; x < w - 30; x += between(rand, 18, 34)) out.push(ellipse(x, PAVE - 7, between(rand, 7, 12), 4, "shrub"));
  out.push(rect(0, PAVE - 1, w, KERB - PAVE + 1, "pave"));
  for (let x = 4; x < w; x += 9) out.push(rect(x, PAVE, 0.6, KERB - PAVE, "pave-joint"));
  out.push(rect(0, KERB, w, ROAD_TOP - KERB, "kerb"), rect(0, ROAD_TOP, w, ROAD_BOTTOM - ROAD_TOP, "asphalt"),
    rect(0, ROAD_TOP + 1.4, w, 0.9, "line-yellow"), rect(0, ROAD_TOP + 3.1, w, 0.9, "line-yellow"),       // no parking along the kerb
    rect(0, ROAD_BOTTOM - 4.2, w, 0.9, "line-yellow"), rect(0, ROAD_BOTTOM - 2.5, w, 0.9, "line-yellow"),
    rect(0, ROAD_BOTTOM, w, SCENE_H - ROAD_BOTTOM, "kerb"));
  for (let x = 8; x < w; x += 30) out.push(rect(x, 131, 15, 1.3, "line-white"));                         // lane divider
  // the covered linkway along the pavement
  out.push(rect(l0, PAVE - 31, l1 - l0, 3, "linkway-roof"), rect(l0, PAVE - 28, l1 - l0, 1, "linkway-edge"));
  for (let x = l0 + 2; x < l1; x += 26) out.push(rect(x, PAVE - 28, 1.6, 28, "linkway-post"));
  out.push(...overheadBridge(rand, bx));
  // rain trees and street lamps along the verge, clear of the linkway and the bridge
  // trees may stand under the bridge's span (as they do), but not in its lift tower or stairs; lamps not under it
  const [b0, b1] = BRIDGE_EXTENT, out_ = (x: number, span: number, a0: number, a1: number) => x + span < a0 || x > a1;
  const clear = (x: number, span: number) => out_(x, span, l0 - 6, l1 + 6) && out_(x, span, bx + b0 - 4, bx + 4) && out_(x, span, bx + SPAN - 4, bx + b1 + 4) && x + span < w - 20;
  for (let x = 20; x < w - 60; x += between(rand, 70, 130)) {
    const span = 44;
    if (clear(x, span)) rainTree(out, rand, x, 1.05, PAVE - 2);
  }
  for (let x = 90; x < w - 30; x += 180) {
    if (!clear(x, 14) || !out_(x, 14, bx + b0, bx + b1)) continue;
    out.push(rect(x, PAVE - 60, 1.6, 60, "lamp"), rect(x, PAVE - 60, 11, 1.4, "lamp"), rect(x + 8, PAVE - 61, 6, 2.2, "lamp-head"),
      ellipse(x + 11, PAVE - 57, 7, 5, "lamp-glow sc-night"), ellipse(x + 11, 121, 34, 2.2, "lamp-pool sc-night"));
  }
  return out;
}

// The overhead bridge, side on, as Singapore's are built: a concrete deck on square piers with a planter
// of shrubs along its parapet and the round height-limit sign, a white tube roof on slim posts, a lift
// tower at the near end and a covered staircase down to the pavement at the far end, its white roof
// sweeping down with the stairs. Its deck is above the bus's roof, so the bus passes under it. All of
// it is one bridge-part group, held back whole when the bus starts to pull in (train-loader.ts).
const SPAN = 220, STAIR_RUN = 80;
const BRIDGE_EXTENT: [number, number] = [-28, SPAN + STAIR_RUN + 4];    // from the lift tower to the foot of the stairs
const DECK_TOP = 38, DECK_BOTTOM = 49, ROOF_Y = 17;

function overheadBridge(rand: () => number, bx: number): SVGElement[] {
  const part = (el: SVGElement) => { el.classList.add("bridge-part"); return el; };
  const out: SVGElement[] = [];
  const s0 = bx + SPAN, s1 = s0 + STAIR_RUN;                                   // the stairs run from s0 down to s1
  const slope = (x: number) => DECK_TOP + 2 + ((x - s0) / (s1 - s0)) * (PAVE - 6 - DECK_TOP - 2);
  // piers and the lift tower
  for (const px of [bx + 34, bx + SPAN - 46]) out.push(rect(px, DECK_BOTTOM, 9, PAVE - DECK_BOTTOM, "ob-pier"), rect(px - 4, DECK_BOTTOM, 17, 3, "ob-pier"));
  out.push(rect(bx - 26, DECK_TOP - 10, 24, PAVE - DECK_TOP + 10, "ob-lift"), rect(bx - 22, DECK_TOP - 5, 16, PAVE - DECK_TOP + 1, "ob-lift-glass"),
    rect(bx - 28, DECK_TOP - 13, 28, 3, "ob-deck"));
  // the staircase: its side panel, the steps' nosings, the handrail and its posts, a landing at the foot
  out.push(poly([[s0, DECK_TOP + 2], [s1, PAVE - 6], [s1, PAVE], [s0, DECK_BOTTOM]], "ob-stair"));
  for (let x = s0 + 5; x < s1 - 2; x += 6) out.push(rect(x, slope(x) - 1.2, 4, 1.2, "ob-step"));
  out.push(svg("line", { x1: s0, y1: DECK_TOP - 7, x2: s1, y2: PAVE - 14, class: "ob-handrail" }));
  for (let x = s0 + 4; x < s1; x += 10) out.push(rect(x, slope(x) - 9, 0.9, 9, "ob-rail"));
  out.push(rect(s1 - 2, PAVE - 6, 10, 6, "ob-stair"));
  // the deck: planter and shrubs on the parapet, the rail behind, the concrete girder, the sign
  out.push(rect(bx, DECK_TOP - 9, SPAN, 0.8, "ob-rail"), rect(bx, DECK_TOP - 3, SPAN, 3, "ob-planter"));
  for (let x = bx + 3; x < bx + SPAN - 2; x += between(rand, 4, 7)) out.push(ellipse(x, DECK_TOP - 3.5, between(rand, 3, 5.5), between(rand, 2, 3.4), rand() < 0.4 ? "ob-shrub-dark" : "ob-shrub"));
  out.push(rect(bx - 2, DECK_TOP, SPAN + 4, DECK_BOTTOM - DECK_TOP, "ob-deck"), rect(bx - 2, DECK_BOTTOM - 2, SPAN + 4, 2, "ob-deck-shade"));
  for (let x = bx + 44; x < bx + SPAN; x += 44) out.push(rect(x, DECK_TOP + 1, 0.8, DECK_BOTTOM - DECK_TOP - 3, "ob-deck-shade"));
  out.push(svg("circle", { cx: bx + SPAN / 2, cy: (DECK_TOP + DECK_BOTTOM) / 2 - 0.5, r: 3.3, class: "ob-sign" }));
  // the roof: slim posts, then the white tube, with a darker line under it for its roundness
  for (let x = bx + 4; x < s0; x += 20) out.push(rect(x, ROOF_Y + 2, 1.1, DECK_TOP - ROOF_Y - 4, "ob-post"));
  for (let x = s0 + 14; x < s1 - 4; x += 18) {
    const roof = ROOF_Y + 2 + ((x - s0) / (s1 - s0)) * (PAVE - 30 - ROOF_Y);
    out.push(rect(x, roof, 1.1, slope(x) - 9 - roof, "ob-post"));
  }
  const tube = `M ${bx - 22} ${ROOF_Y} L ${s0 - 6} ${ROOF_Y} Q ${s0 + 4} ${ROOF_Y} ${s0 + 10} ${ROOF_Y + 6} L ${s1 + 2} ${PAVE - 28}`;
  out.push(svg("path", { d: tube, class: "ob-tube-shade", transform: "translate(0 1.6)" }), svg("path", { d: tube, class: "ob-tube" }));
  for (let x = bx + 8; x < s0 - 4; x += 20) out.push(ellipse(x + 1, ROOF_Y + 5, 6, 3, "ob-glow sc-night"), rect(x, ROOF_Y + 2.4, 2.4, 1.2, "ob-light sc-night"));
  return out.map(part);
}

// --- the bus ------------------------------------------------------------------------------------
// An SG Bus double-decker (MAN A95, three axles) in Lush Green, side on, facing right: black front,
// upper-deck window band, SG♥BUS between the decks, a silver line along the lower deck, and the
// mirror on its arm. We see its offside (Singapore drives on the left): the doors are on the far side,
// facing the kerb and the bus stop, so this side is windows all along.

export const BUS_W = 200, BUS_H = 70, BUS_WHEEL_BOTTOM = 68;
const BUS_FRONT = 191;                          // the front of the bus, which stops just short of the bus-stop pole

function wheel(cx: number): SVGElement {
  const cy = 60.5, spokes: SVGElement[] = [];
  for (let i = 0; i < 5; i++) {
    const a = (i * 2 * Math.PI) / 5;
    spokes.push(svg("line", { x1: cx, y1: cy, x2: (cx + 3.6 * Math.cos(a)).toFixed(2), y2: (cy + 3.6 * Math.sin(a)).toFixed(2), class: "bus-spoke" }));
  }
  return svg("g", { class: "bus-wheel" },
    svg("circle", { cx, cy, r: 7.4, class: "bus-tyre" }), svg("circle", { cx, cy, r: 4.4, class: "bus-hub" }), ...spokes,
    svg("circle", { cx, cy, r: 1.2, class: "bus-tyre" }));
}

const seats = (from: number, to: number, y: number) => {
  const out: SVGElement[] = [];
  for (let x = from; x + 5 <= to; x += 8) out.push(svg("rect", { x, y, width: 5, height: 6, rx: 1.4, class: "bus-seat" }));
  return out;
};

function busParts(): SVGElement[] {
  const arch = (cx: number) => svg("path", { d: `M ${cx - 10} 62 A 10 10 0 0 1 ${cx + 10} 62 Z`, class: "bus-arch" });
  const body = svg("g", { class: "bus-body" },
    svg("rect", { x: 3, y: 3, width: 188, height: 59, rx: 7, class: "bus-paint" }),
    svg("path", { d: "M 175 3 H 184 Q 191 3 191 10 V 58 H 175 Z", class: "bus-black" }),                       // the black front
    rect(14, 7, 152, 22, "bus-glass"), rect(177, 6, 12, 22, "bus-glass"),                                     // upper deck
    ...seats(17, 163, 22),                                                                                   // seat backs in the windows
    ...[14, 39, 64, 89, 114, 139, 164].map((x) => rect(x, 7, 2.2, 22, "bus-frame")),
    rect(166, 3, 7, 30, "bus-silver"),                                                                       // the silver pillar
    rect(177, 29.5, 12, 5, "bus-led-bg"), rect(178.5, 31, 9, 2, "bus-led"),                                  // destination display
    rect(16, 41, 157, 15, "bus-glass"), ...seats(19, 150, 50),                                             // lower deck, the driver at the front
    ...[50, 86, 120, 152].map((x) => rect(x, 41, 1.6, 15, "bus-frame")),
    rect(177, 36, 12, 20, "bus-glass"),                                                                      // lower windscreen
    rect(3, 57, 172, 1.4, "bus-silver"), rect(5, 41, 6, 12, "bus-grille"),
    svg("text", { x: 70, y: 37.6, class: "bus-logo" }, "SG", svg("tspan", { class: "bus-heart" }, "♥"), "BUS"),
    rect(118, 58.8, 9, 2, "bus-smrt"),
    rect(186, 54, 4, 2.6, "bus-headlight"), rect(3, 48, 2, 6, "bus-taillight"),
    rect(190, 14, 6, 1.6, "bus-black"), rect(194, 14, 2.4, 9, "bus-black"),                                   // the mirror on its arm
    arch(47), arch(146));
  return [ellipse(98, 68.6, 92, 2.2, "bus-shadow"), body, wheel(38), wheel(56), wheel(146)];
}

/** The bus, ready to place in the scene (bus-loader in train-loader.ts). */
export function bus(): HTMLElement {
  return h("div", { class: "bl-bus" },
    svg("svg", { width: BUS_W, height: BUS_H, viewBox: `0 0 ${BUS_W} ${BUS_H}`, "aria-hidden": "true" }, busParts()),
    h("span", { class: "bl-beam sc-night" }));
}

// --- the bus stop ---------------------------------------------------------------------------------
// As at a Singapore stop: a shelter of ordinary height (a double-decker stands about a quarter taller) with a grey canopy
// and an orange fascia stripe, a back panel with a little bookshelf and a lit advert, orange benches,
// the blue bus-stop sign on its pole with the service panel, bollards in yellow-and-black sleeves
// along the kerb, and a black-and-white kerb. The doors are on the bus's kerb side, facing the stop,
// so they cannot be seen from the road.

export const STOP_W = 360;
const POLE = STOP_W - 52;                      // just past the end of the shelter
/** Where in the stop the bus's centre ends up: its front just short of the pole (the sign stays in view),
 * so the bus stands along the shelter. */
export const STOP_ANCHOR = POLE - 12 - (BUS_FRONT - BUS_W / 2);

function stopParts(): SVGElement[] {
  const w = STOP_W, out: SVGElement[] = [];
  for (let x = 0; x < w; x += 12) out.push(rect(x, KERB, 6, ROAD_TOP - KERB, "kerb-black"));
  out.push(rect(6, ROAD_TOP + 5.5, w - 12, 1.2, "line-yellow"));                // the bus bay
  // the shelter
  const x0 = 24, x1 = w - 60, roof = 74;
  out.push(rect(x0 + 6, roof + 12, x1 - x0 - 12, PAVE - roof - 16, "stop-panel"));
  out.push(rect(x0 + 14, roof + 14, 30, 16, "stop-shelf"));                                               // the book corner
  const spines = ["book1", "book2", "book3", "book4"];
  for (let r = 0; r < 2; r++) for (let x = x0 + 16, i = r; x < x0 + 42; x += 3, i++) out.push(rect(x, roof + 15.2 + r * 7.4, 2.2, 6, spines[i % 4]));
  out.push(rect(x1 - 74, roof + 13, 56, 17, "stop-ad"), rect(x1 - 70, roof + 15.5, 48, 12, "stop-ad-art"));
  for (const bx of [x0 + 56, x0 + 130]) out.push(rect(bx, PAVE - 9, 54, 3, "bench"), rect(bx + 4, PAVE - 6, 2, 6, "bench-leg"), rect(bx + 48, PAVE - 6, 2, 6, "bench-leg"));
  for (const cx of [x0 + 2, (x0 + x1) / 2, x1 - 6]) out.push(rect(cx, roof + 7, 4, PAVE - roof - 7, "stop-post"));
  out.push(poly([[x0 - 12, roof], [x1 + 12, roof], [x1 + 5, roof + 7], [x0 - 5, roof + 7]], "stop-roof"),
    rect(x0 - 5, roof + 7, x1 - x0 + 10, 2, "stop-roof-under"), rect(x0 - 9, roof + 2.2, x1 - x0 + 18, 1.3, "stop-accent"));
  // the bus-stop sign: blue, with a white bus, a name plate and the service panel, a little above the roof
  const sign = roof - 6;
  out.push(rect(POLE, sign, 2.2, PAVE - sign, "stop-pole"), rect(POLE - 9, sign - 4, 20, 14, "stop-sign"),
    rect(POLE - 5.5, sign - 1, 13, 7, "stop-sign-mark"), rect(POLE - 4, sign + 0.2, 3.6, 2.4, "stop-sign"), rect(POLE + 1, sign + 0.2, 3.6, 2.4, "stop-sign"),
    svg("circle", { cx: POLE - 2.6, cy: sign + 6.2, r: 1.2, class: "stop-sign-mark" }), svg("circle", { cx: POLE + 4.6, cy: sign + 6.2, r: 1.2, class: "stop-sign-mark" }),
    rect(POLE - 9, sign + 11, 20, 4.4, "stop-name"), rect(POLE - 6, sign + 12.5, 14, 1.3, "stop-sign-mark"),
    rect(POLE - 8, sign + 17, 18, 13, "stop-services"));
  for (let r = 0; r < 3; r++) out.push(rect(POLE - 6, sign + 19 + r * 3.8, 6, 1.8, "stop-service-no"), rect(POLE + 2, sign + 19 + r * 3.8, 6, 1.8, "stop-service-no"));
  for (let x = 12; x < w - 8; x += 26) {                                                     // bollards along the kerb
    out.push(rect(x, PAVE - 7, 4.4, KERB - PAVE + 7, "bollard"), rect(x, PAVE - 4.5, 4.4, 4, "bollard-band"),
      poly([[x, PAVE - 0.5], [x + 4.4, PAVE - 3.6], [x + 4.4, PAVE - 2.2], [x, PAVE + 0.9]], "bollard-chevron"), rect(x - 0.4, PAVE - 8, 5.2, 1.4, "bollard"));
  }
  return out;
}

let stopTemplate: HTMLElement | null = null;
const stopLayer = (parts: SVGElement[]) => h("div", { class: "sc-station" },
  svg("svg", { width: STOP_W, height: SCENE_H, viewBox: `0 0 ${STOP_W} ${SCENE_H}`, "aria-hidden": "true" }, parts));

/** The bus stop, ready to slide in behind the bus. */
export function busStop(): HTMLElement {
  stopTemplate ??= stopLayer(stopParts());
  return stopTemplate.cloneNode(true) as HTMLElement;
}

let template: { back: HTMLElement; front: HTMLElement } | null = null;

/** The town and the road behind the bus (its bridge included), cloned from one drawing. */
export function roadScenery(): { back: HTMLElement; front: HTMLElement } {
  template ??= {
    back: h("div", { class: "sc-back" }, town(), layer("road", ROAD.width, ROAD.speed, roadBack(seeded(ROAD.seed)))),
    front: h("div", { class: "sc-front" }),
  };
  return { back: template.back.cloneNode(true) as HTMLElement, front: template.front.cloneNode(true) as HTMLElement };
}

// --- the crossroads the bus stops at when the logs cannot be fetched ----------------------------------
// A signalised cross junction: the white stop line, a pedestrian crossing (two lines of studs), the
// yellow box across the junction, the side road crossing ours (running away through a gap in the far
// pavement, its centre dashes, a car waiting on it), the crossing on the far side, and our road going
// on beyond. Traffic lights on both corners show red (three aspects, red lit). The bus stops just
// short of the stop line.

export const JUNCTION_W = 420;
const STOP_LINE = 200;
const CROSS = [STOP_LINE + 24, STOP_LINE + 150] as const;     // the side road's two edges
/** Where in the junction the bus's centre ends up: its front just short of the stop line. */
export const JUNCTION_ANCHOR = STOP_LINE - 8 - (BUS_FRONT - BUS_W / 2);

function trafficLight(out: SVGElement[], px: number, top: number): void {
  out.push(rect(px - 1.6, top + 22, 3.2, PAVE - top - 22, "stop-pole"), rect(px + 1.6, top + 50, 5, 7, "dp-head"),
    svg("rect", { x: px - 6, y: top - 2, width: 12, height: 30, rx: 2.5, class: "dp-plate" }),
    svg("rect", { x: px - 4.5, y: top, width: 9, height: 26, rx: 2, class: "dp-head" }),
    svg("circle", { cx: px, cy: top + 4.6, r: 7, class: "dp-glow" }), svg("circle", { cx: px, cy: top + 4.6, r: 3, class: "dp-red" }),
    svg("circle", { cx: px, cy: top + 13, r: 3, class: "dp-off" }), svg("circle", { cx: px, cy: top + 21.4, r: 3, class: "dp-off" }));
}

/** Two lines of white studs across our road: a signalised pedestrian crossing. */
function studs(out: SVGElement[], x: number): void {
  for (const dx of [0, 9]) for (let y = ROAD_TOP + 1.5; y < ROAD_BOTTOM - 1; y += 3.4) out.push(rect(x + dx + (y - ROAD_TOP) * 0.12, y, 2.2, 1.6, "line-white"));
}

function junctionParts(): SVGElement[] {
  const [c0, c1] = CROSS, far = PAVE - 14, out: SVGElement[] = [];
  // the side road: away from us through the far pavement, and across our road
  out.push(poly([[c0 + 22, far], [c1 - 22, far], [c1, ROAD_TOP], [c0, ROAD_TOP]], "asphalt"),
    rect(c0, ROAD_TOP - 0.5, c1 - c0, SCENE_H - ROAD_TOP + 0.5, "asphalt"));
  out.push(poly([[c0 - 3, KERB], [c0, KERB], [c0 + 22, far], [c0 + 19, far]], "kerb"), poly([[c1, KERB], [c1 + 3, KERB], [c1 - 19, far], [c1 - 22, far]], "kerb"));
  for (let y = far + 2; y < SCENE_H - 3; y += 8) {
    const t = (y - far) / (SCENE_H - far);
    out.push(rect((c0 + c1) / 2 - 0.7 - 0.8 * t, y, 1.4 + 1.6 * t, 3 + 2.5 * t, "line-white"));
  }
  // a car waiting on the side road, seen from behind
  const cx = (c0 + c1) / 2 + 6, cy = far + 4;
  out.push(svg("rect", { x: cx, y: cy, width: 16, height: 9, rx: 2, class: "jn-car" }), rect(cx + 2.5, cy + 1.2, 11, 3, "dp-glass"),
    rect(cx + 1, cy + 5.5, 3, 1.6, "dp-red"), rect(cx + 12, cy + 5.5, 3, 1.6, "dp-red"), rect(cx + 1, cy + 9, 3, 2, "dp-tyre"), rect(cx + 12, cy + 9, 3, 2, "dp-tyre"));
  // the yellow box across the junction, the stop line, the crossings either side
  out.push(path(`M ${c0 + 2} ${ROAD_TOP + 1} H ${c1 - 2} V ${ROAD_BOTTOM - 1} H ${c0 + 2} Z M ${c0 + 2} ${ROAD_TOP + 1} L ${c1 - 2} ${ROAD_BOTTOM - 1} M ${c1 - 2} ${ROAD_TOP + 1} L ${c0 + 2} ${ROAD_BOTTOM - 1}`, "jn-box"));
  out.push(poly([[STOP_LINE - 1, ROAD_TOP + 1], [STOP_LINE + 3, ROAD_TOP + 1], [STOP_LINE + 6, ROAD_BOTTOM - 1], [STOP_LINE + 2, ROAD_BOTTOM - 1]], "line-white"));
  studs(out, STOP_LINE + 7);
  studs(out, c1 + 4);
  // traffic lights on both corners, red
  trafficLight(out, STOP_LINE + 6, 46);
  trafficLight(out, c1 + 22, 46);
  return out;
}

const path = (d: string, cls: string) => svg("path", { d, class: cls });

let junctionTemplate: HTMLElement | null = null;

/** The crossroads, ready to slide in behind the bus when Review's logs cannot be fetched. */
export function junction(): HTMLElement {
  junctionTemplate ??= h("div", { class: "sc-station" },
    svg("svg", { width: JUNCTION_W, height: SCENE_H, viewBox: `0 0 ${JUNCTION_W} ${SCENE_H}`, "aria-hidden": "true" }, junctionParts()));
  return junctionTemplate.cloneNode(true) as HTMLElement;
}
