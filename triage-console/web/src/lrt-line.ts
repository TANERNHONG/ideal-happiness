// Simple mode's steps drawn as an LRT line (US-35): an elevated concrete guideway on piers, an LRT station for
// each step (see station()), and a two-car driverless LRT train (white body, wraparound black
// windscreens, teal and navy dot livery, as on Singapore's LRT) that rides from the last step to the current one.
// The stations' names are real buttons laid over the drawing; everything else is decoration (aria-hidden).

import { h } from "./dom";

const W = 800;            // scene width, in the drawing's own units
const H = 132;            // scene height: badges 2-18, roofs 28-38, train 49-80, deck 80-96, piers to 132
const DECK = 80;          // top of the guideway, where the train's skirt sits
const CAR = 80;           // one car's length; two cars and a coupler make the train
const TRAIN_W = 2 * CAR + 4;
const K = 0.84;           // the cars' height against the 37-unit drawing below: long and low, like the real ones
const TRAIN_H = 31;
const PIERS = [40, 200, 400, 600, 760];

const x = (i: number, n: number) => (i + 0.5) * (W / n);
const pct = (v: number, of: number) => `${(v / of) * 100}%`;

/** The line for ``steps``; the train starts at station ``from`` and rides to ``current``. Stations up to
 * ``reached`` are open (lit) and can be clicked unless ``locked``. */
export function lrtLine(steps: string[], current: number, from: number, reached: number, locked: boolean,
  open: (step: number) => void): HTMLElement {
  const n = steps.length;
  const first = x(0, n), last = x(n - 1, n);
  const share = (i: number) => (x(i, n) - first) / (last - first);

  const scene = svg(`0 0 ${W} ${H}`, "lrt-scene", sceneMarkup(steps, current, reached));
  const ridden = scene.querySelector(".lrt-ridden") as SVGRectElement;
  ridden.style.transform = `scaleX(${share(from)})`;
  const train = h("div", { class: "lrt-train", style: { left: pct(x(from, n), W), top: pct(DECK - TRAIN_H, H), width: pct(TRAIN_W, W) }, "aria-hidden": "true" },
    svg(`0 0 ${TRAIN_W} ${TRAIN_H}`, "", trainMarkup()));
  if (from !== current) {
    requestAnimationFrame(() => requestAnimationFrame(() => {
      train.style.left = pct(x(current, n), W);
      ridden.style.transform = `scaleX(${share(current)})`;
    }));
  }
  return h("div", { class: "lrt" },
    scene, train,
    h("ol", { class: "lrt-stations" }, steps.map((label, i) => h("li", {},
      h("button", {
        class: `lrt-stn ${i <= reached ? "lit" : ""} ${i === current ? "here" : ""}`,
        disabled: i > reached || locked, "aria-current": i === current ? "step" : undefined, onclick: () => open(i),
      }, h("span", { class: "lrt-name" }, label))))));
}

function svg(viewBox: string, cls: string, markup: string): SVGSVGElement {
  const el = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  el.setAttribute("viewBox", viewBox);
  el.setAttribute("aria-hidden", "true");
  if (cls) el.setAttribute("class", cls);
  el.innerHTML = markup;
  return el;
}

/** The guideway, piers and stations. */
function sceneMarkup(steps: string[], current: number, reached: number): string {
  const n = steps.length;
  const first = x(0, n), last = x(n - 1, n);
  const piers = PIERS.map((p) => `
    <rect x="${p - 13}" y="${DECK + 15}" width="26" height="6" rx="1.5" class="lrt-cap"/>
    <path d="M${p - 7} ${DECK + 21} L${p + 7} ${DECK + 21} L${p + 6} ${H} L${p - 6} ${H} Z" fill="url(#lrt-pier)"/>
    <rect x="${p - 5}" y="${DECK + 21}" width="2.4" height="${H - DECK - 25}" class="lrt-pier-light"/>`).join("");
  const stations = steps.map((_, i) => station(x(i, n), i, i <= reached, i === current)).join("");
  return `
    <defs>
      <linearGradient id="lrt-deck" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" style="stop-color: var(--lrt-concrete-hi)"/><stop offset="1" style="stop-color: var(--lrt-concrete-lo)"/>
      </linearGradient>
      <linearGradient id="lrt-pier" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" style="stop-color: var(--lrt-concrete-lo)"/>
        <stop offset="0.6" style="stop-color: var(--lrt-concrete-hi); stop-opacity: 0.9"/>
        <stop offset="1" style="stop-color: var(--lrt-concrete-hi); stop-opacity: 0"/>
      </linearGradient>
    </defs>
    ${piers}
    ${stations}
    <rect x="16" y="${DECK}" width="${W - 32}" height="16" rx="2" fill="url(#lrt-deck)"/>
    <rect x="16" y="${DECK}" width="${W - 32}" height="3.5" class="lrt-running"/>
    <rect x="${first}" y="${DECK}" width="${last - first}" height="3.5" class="lrt-ridden"/>
    <rect x="16" y="${DECK + 15}" width="${W - 32}" height="1" class="lrt-deck-shadow"/>`;
}

/** One elevated LRT station, centred on ``c``, as its platform looks from the track: a blue roof over a white
 * vaulted ceiling with recessed lights, blue columns at either end, a back wall of blue-framed windows, a
 * platform sign with a clock, blue half-height platform gates, and a terracotta floor with a grey tactile strip
 * and a yellow line at the edge. Stations not yet open are drawn in greys. */
function station(c: number, i: number, lit: boolean, here: boolean): string {
  const arc = (dx: number) => { const t = (dx + 92) / 184; return 38 - 40 * t + 40 * t * t; };   // the roof's curve
  const mullions = [1, 2, 3, 4, 5].map((k) => `<line x1="${(c - 80 + k * 26.7).toFixed(1)}" y1="43" x2="${(c - 80 + k * 26.7).toFixed(1)}" y2="58" class="lrt-transom"/>`).join("");
  const windows = `<rect x="${c - 80}" y="43" width="160" height="15" class="lrt-window"/>
      <line x1="${c - 80}" y1="47.5" x2="${c + 80}" y2="47.5" class="lrt-transom"/>${mullions}`;
  const lights = [-60, -30, 0, 30, 60].map((d) => `<circle cx="${c + d}" cy="${(arc(d) + 4.4).toFixed(1)}" r="1.1" class="lrt-light"/>`).join("");
  const gates = [-56, -19, 19, 56].map((g) => `<rect x="${c + g - 3.6}" y="53" width="7.2" height="18" rx="1" class="lrt-gate"/>
      <rect x="${c + g - 1.4}" y="56" width="2.8" height="12" rx="0.6" class="lrt-gate-glass"/>`).join("");
  const leds = [0, 1, 2, 3, 4, 5, 6].map((k) => `<rect x="${c + 31 + k * 2.3}" y="46" width="1.5" height="2" class="lrt-led"/>`).join("");
  const column = (cx: number) => `<rect x="${cx - 3.5}" y="38" width="7" height="34" rx="2.2" class="lrt-column"/>
      <rect x="${cx - 2.2}" y="40" width="1.4" height="30" rx="0.7" class="lrt-column-light"/>`;
  return `<g class="lrt-station ${lit ? "lit" : ""} ${here ? "here" : ""}">
      <rect x="${c - 84}" y="40" width="168" height="27" class="lrt-wall"/>
      ${windows}
      <path d="M${c - 92} 38 Q${c} 18 ${c + 92} 38 L${c + 92} 42 L${c - 92} 42 Z" class="lrt-ceiling"/>
      <path d="M${c - 70} ${(arc(-70) + 2.6).toFixed(1)} Q${c} 24.6 ${c + 70} ${(arc(70) + 2.6).toFixed(1)}" class="lrt-rib"/>
      ${lights}
      <line x1="${c + 31}" y1="42" x2="${c + 31}" y2="44" class="lrt-hanger"/><line x1="${c + 45}" y1="42" x2="${c + 45}" y2="44" class="lrt-hanger"/>
      <rect x="${c + 24}" y="44" width="24" height="6" rx="0.8" class="lrt-sign"/>
      <circle cx="${c + 27.2}" cy="47" r="2" class="lrt-clock"/>
      ${leds}
      <rect x="${c - 88}" y="66" width="176" height="8" class="lrt-floor"/>
      <rect x="${c - 88}" y="70" width="176" height="1.6" class="lrt-tactile"/>
      <rect x="${c - 88}" y="72" width="176" height="1.8" class="lrt-edge"/>
      <rect x="${c - 88}" y="74" width="176" height="6" class="lrt-platform-face"/>
      ${gates}
      ${column(c - 85)}${column(c + 85)}
      <path d="M${c - 92} 38 Q${c} 18 ${c + 92} 38" class="lrt-roof"/>
      <rect x="${c - 11}" y="5" width="22" height="16" rx="4" class="lrt-code"/>
      <text x="${c}" y="16.6" class="lrt-code-text">${i + 1}</text>
    </g>`;
}

/** Two coupled cars seen from the side; each car has a cab at both ends, as on a driverless LRT. */
function trainMarkup(): string {
  return `
    <defs>
      <linearGradient id="lrt-body" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" style="stop-color: var(--lrt-body-hi)"/><stop offset="0.75" style="stop-color: var(--lrt-body-hi)"/>
        <stop offset="1" style="stop-color: var(--lrt-body-lo)"/>
      </linearGradient>
    </defs>
    <rect x="${CAR - 1}" y="${25.5 * K}" width="6" height="${3 * K}" class="lrt-dark"/>
    ${car(0)}${car(CAR + 4)}`;
}

/** One car, ``CAR`` long and 37 high, after the driverless LRT cars: a white body with rounded noses, a black
 * glazed band from windscreen to windscreen broken by thin white pillars, a pair of doors in the middle, the dot
 * livery along the lower side, and a black skirt over the rubber tyres. */
function car(dx: number): string {
  const L = CAR;
  const pair = /(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/g;
  const sy = (d: string) => d.replace(pair, (_, px, py) => `${px},${(Number(py) * K).toFixed(2)}`);
  const v = (n: number) => (n * K).toFixed(2);
  const dots: string[] = [];
  const palette = ["lrt-dot-a", "lrt-dot-b", "lrt-dot-c", "lrt-dot-d", "lrt-dot-e"];
  [23.9, 26.7, 29.4].forEach((y, row) => {
    for (let cx = 6, col = 0; cx <= L - 6; cx += 3, col++) {
      if (cx > 33.2 && cx < 46.8 && row === 0) continue;                  // the doors' sills stay plain
      const bell = Math.exp(-(((cx - L / 2) / (L * 0.32)) ** 2));         // densest around the doors
      const jitter = ((col * 37 + row * 71 + dx) % 13) / 13;              // fixed, so every draw is the same
      const r = (0.35 + 1.2 * bell) * (0.62 + 0.38 * jitter) * (row === 0 ? 0.8 : 1);
      if (r < 0.5) continue;
      dots.push(`<circle cx="${cx.toFixed(1)}" cy="${v(y)}" r="${(r * 0.92).toFixed(2)}" class="${palette[(col * 3 + row * 2 + (dx ? 1 : 0)) % palette.length]}"/>`);
    }
  });
  const mirror = (d: string) => d.replace(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/g, (_, px, py) => `${(L - Number(px)).toFixed(2)},${py}`);
  const screen = "M66,2.4 L71,2.4 C75.3,2.4 77.6,4.6 78.2,8.4 L78.9,20.6 C75,21.8 70,21.8 66,21.2 Z";
  const lamp = "M76.2,24.6 L79.3,24.6 L79.1,26.4 L76.2,26.4 Z";
  const pillars = [13.5, 24, 56, 66.5].map((px) => `<rect x="${px - 0.7}" y="${v(4.4)}" width="1.4" height="${v(15.6)}" class="lrt-pillar"/>`).join("");
  return `<g transform="translate(${dx} 0)">
    <path d="${sy("M4.5,30.5 L75.5,30.5 L74.2,36.6 L5.8,36.6 Z")}" class="lrt-dark"/>
    <path d="${sy("M9,1 L71,1 C76,1 78.6,3.5 79.2,8 L79.9,23.5 C80,28.5 78.5,31.5 76,31.5 L4,31.5 C1.5,31.5 0,28.5 0.1,23.5 L0.8,8 C1.4,3.5 4,1 9,1 Z")}" class="lrt-car"/>
    <path d="${sy("M9.5,1.7 L70.5,1.7")}" class="lrt-roofline"/>
    <rect x="9" y="${v(4.4)}" width="62" height="${v(15.6)}" rx="1" class="lrt-glass"/>
    <path d="${sy(screen)}" class="lrt-glass"/><path d="${sy(mirror(screen))}" class="lrt-glass"/>
    ${pillars}
    <rect x="33.4" y="${v(3.4)}" width="13.2" height="${v(27.6)}" rx="0.9" class="lrt-door"/>
    <path d="${sy("M33.4,4.2 L33.4,30.8 M46.6,4.2 L46.6,30.8")}" class="lrt-door-edge"/>
    <path d="${sy("M40,3.4 L40,31")}" class="lrt-door-line"/>
    <path d="${sy("M71.8,4.4 L75.8,19 M8.2,4.4 L4.2,19 M15.5,5.5 L18.5,18.5 M58,5.5 L61,18.5")}" class="lrt-glare"/>
    ${dots.join("")}
    <path d="${sy(lamp)}" class="lrt-lamp"/><path d="${sy(mirror(lamp))}" class="lrt-lamp"/>
    <rect x="69" y="${v(23.4)}" width="3.6" height="${v(1.2)}" class="lrt-tag"/><rect x="${L - 72.6}" y="${v(23.4)}" width="3.6" height="${v(1.2)}" class="lrt-tag"/>
  </g>`;
}
