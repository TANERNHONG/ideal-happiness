// The Desk animation pack (Settings → Animation pack): loaders that act out what each search does.
// - monkeyLoader (Data → SQL): a wind-up cymbal monkey, the "SQL monkey", claps on an office desk
//   while the query runs; when it is done, one big clash and the toy winds down. If the query fails,
//   one cymbal slips on the last clap, drops to the desk, bounces and rolls away.
// - filesLoader (Review, logs before and after): a row of filing cabinets labelled as a timeline,
//   from the Before minutes to the After minutes around a red-tagged drawer (the observation). A
//   magnifying glass works outwards, before then after, opening drawers and lifting out the files
//   worth keeping onto a tray; when the logs are in, the tray gets a tick and the number of lines. If
//   they cannot be fetched, the glass stops and the red-tagged cabinet topples over, spilling files.
// Drawn inline, day in the light theme and night in the dark one (--dk-* / --fc-* tokens in
// styles.css, and .sc-day / .sc-night parts). Motion runs on animation frames, so it checks the
// same settings as the transit pack: Animations → None, or the system's reduced motion, shows a
// still picture; "Skip the ending" goes straight to the results.

import { h, svg } from "./dom";
import { arrivalWanted, loaderShell, type Finish, type TrainLoader } from "./train-loader";
import { ellipse, rect, seeded } from "./scenery";

const DWELL_MS = 450;
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const ease = (t: number) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);
const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));
const circle = (cx: number, cy: number, r: number, cls: string) => svg("circle", { cx, cy, r, class: cls });

/** Anything moving at all: not under Animations → None or the system's reduced motion. */
function moving(): boolean {
  return document.documentElement.getAttribute("data-motion") !== "none" && !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

/** fn(t) for t from 0 to 1 over ms, on animation frames; finishes at once when cut() says so. */
function tween(scene: HTMLElement, ms: number, fn: (t: number) => void, cut: () => boolean = () => false): Promise<void> {
  return new Promise((done) => {
    const began = performance.now();
    const safety = window.setTimeout(() => { fn(1); done(); }, ms + 400);       // a hidden tab gets no frames
    const frame = (now: number) => {
      const t = cut() ? 1 : Math.min(1, (now - began) / ms);
      fn(t);
      if (t < 1 && scene.isConnected) requestAnimationFrame(frame);
      else { window.clearTimeout(safety); done(); }
    };
    requestAnimationFrame(frame);
  });
}

// --- the cymbal monkey (Data → SQL) ----------------------------------------------------------------
// Like the wind-up toy: brown fur, a pale face with big googly eyes rimmed in red, orange ears, a
// yellow vest with red buttons, red-and-white striped trousers, and a brass cymbal in each hand.
// The arms swing in from the sides until the cymbals meet, edge on, in front of its belly; at each
// clash the eyes pop, the mouth opens on its teeth and the cymbals ring. The key turns at its side.

const MK = { cx: 60, shoulderY: 62, shoulderDx: 17, arm: 26, rest: 165, clash: 57.4, w: 120, h: 118 };

interface Monkey { el: SVGSVGElement; pose(s: number, turn: number, ring: number, big: number): void; notes: SVGElement;
  drop(): { cymbal: SVGElement; x: number; y: number } }          // the right-hand cymbal lets go, from where it is

function monkey(): Monkey {
  const { cx, shoulderY: sy, shoulderDx: dx, arm } = MK;
  const out: SVGElement[] = [];
  // the key, at its side behind the trousers
  const bow = svg("g", {}, ellipse(99, 86.6, 3.6, 5, "mk-key"), ellipse(99, 96.6, 3.6, 5, "mk-key"), rect(97.5, 88.5, 3, 6.4, "mk-key"));
  out.push(rect(84, 90, 12, 3.2, "mk-key"), bow);
  // striped trousers (stripes kept inside the rounded corners), then the body, vest and buttons
  out.push(svg("rect", { x: 33, y: 86, width: 54, height: 26, rx: 9, class: "mk-pants" }));
  for (let x = 36; x <= 82; x += 4) {
    const d = x + 1 < 42 ? 42 - (x + 1) : x + 1 > 78 ? x + 1 - 78 : 0;
    const inset = d ? 9 - Math.sqrt(Math.max(0, 81 - d * d)) : 0;
    out.push(rect(x, 86 + inset + 0.6, 2, 26 - 2 * inset - 1.2, "mk-stripe"));
  }
  out.push(ellipse(cx, 74, 21, 19, "mk-fur"),
    svg("path", { d: "M 39 62 Q 60 56 81 62 L 83 89 Q 60 95 37 89 Z", class: "mk-vest" }),
    svg("path", { d: "M 51 59.5 L 60 76 L 69 59.5 Q 60 57 51 59.5 Z", class: "mk-fur" }),
    circle(66, 75, 2.3, "mk-button"), circle(66, 84, 2.3, "mk-button"));
  // the head: ears, a fuzzy outline, the face and muzzle, googly eyes, nose, a mouth that opens
  const eye = (x: number) => svg("g", {}, circle(x, 31, 5.6, "mk-eye"), circle(x, 31.4, 2.8, "mk-pupil"), circle(x - 0.9, 30.3, 0.9, "mk-glint"));
  const eyes = [eye(53.5), eye(66.5)];
  const shut = svg("path", { d: "M 54 47.5 Q 60 51 66 47.5", class: "mk-mouth" });
  const open = svg("g", { visibility: "hidden" }, ellipse(cx, 48.4, 6, 3.4, "mk-dark"), rect(55.4, 46.2, 9.2, 1.7, "mk-teeth"));
  const fuzz: SVGElement[] = [];
  for (let a = -170; a <= -10; a += 20) fuzz.push(circle(cx + 21.5 * Math.cos((a * Math.PI) / 180), 34 + 21.5 * Math.sin((a * Math.PI) / 180), 4.4, "mk-fur"));
  const head = svg("g", {},
    ellipse(36, 37, 7.5, 9.5, "mk-ear"), ellipse(36.6, 37.6, 4.2, 6, "mk-ear-in"), ellipse(84, 37, 7.5, 9.5, "mk-ear"), ellipse(83.4, 37.6, 4.2, 6, "mk-ear-in"),
    ...fuzz, circle(cx, 34, 22.5, "mk-fur"),
    ellipse(cx, 31, 15.5, 11.5, "mk-face"), ellipse(cx, 45, 12.5, 8.6, "mk-face"),
    ...eyes, ellipse(58.3, 41, 0.9, 0.7, "mk-dark"), ellipse(61.7, 41, 0.9, 0.7, "mk-dark"), shut, open);
  out.push(head);
  // arms (drawn along +x from the shoulder, turned each frame), then the cymbals on top
  const limb = () => svg("g", {}, svg("rect", { x: -3, y: -5, width: arm + 2, height: 10, rx: 5, class: "mk-fur" }), ellipse(arm, 0.5, 5.6, 4.6, "mk-hand"));
  const cymbal = () => svg("g", {}, circle(0, 0, 11.5, "mk-cymbal"), circle(0, 0, 8, "mk-cymbal-ring"), circle(0, 0, 3.4, "mk-cymbal-boss"),
    svg("path", { d: "M -7 -6 A 9 9 0 0 1 3 -9", class: "mk-cymbal-shine" }));
  const arms = [limb(), limb()], cymbals = [cymbal(), cymbal()];
  const hands = [{ x: 0, y: 0 }, { x: 0, y: 0 }];
  let loose = false;
  out.push(...arms, ...cymbals);
  // the ring of a clash, and the notes of the last one
  const ring = svg("g", { opacity: 0 });
  for (let i = 0; i < 10; i++) {
    const a = (i / 10) * 2 * Math.PI;
    ring.append(svg("line", { x1: (cx + 15 * Math.cos(a)).toFixed(1), y1: (84 + 15 * Math.sin(a)).toFixed(1), x2: (cx + 22 * Math.cos(a)).toFixed(1), y2: (84 + 22 * Math.sin(a)).toFixed(1), class: "mk-clang" }));
  }
  const notes = svg("g", { opacity: 0 }, svg("text", { x: 86, y: 22, class: "mk-note" }, "♪"), svg("text", { x: 22, y: 18, class: "mk-note" }, "♫"));
  out.push(ring, notes);
  const el = svg("svg", { class: "dk-monkey", width: MK.w, height: MK.h, viewBox: `0 0 ${MK.w} ${MK.h}`, "aria-hidden": "true" }, out);

  const pose = (s: number, turn: number, ringing: number, big: number) => {
    const deg = lerp(MK.rest, MK.clash, s), rad = (deg * Math.PI) / 180, flat = lerp(1, 0.26, s);
    const shake = ringing > 0.5 ? (Math.random() - 0.5) * 1.2 : 0;
    [[-1, deg, rad], [1, 180 - deg, Math.PI - rad]].forEach(([side, angle, r], i) => {
      const x = cx + side * dx, hx = x + arm * Math.cos(r), hy = sy + arm * Math.sin(r);
      arms[i].setAttribute("transform", `translate(${(x + shake).toFixed(2)} ${sy}) rotate(${angle.toFixed(2)})`);
      hands[i] = { x: hx + shake, y: hy };
      if (!(loose && i === 1)) cymbals[i].setAttribute("transform", `translate(${(hx + shake).toFixed(2)} ${hy.toFixed(2)}) scale(${flat.toFixed(3)} 1)`);
    });
    head.setAttribute("transform", `translate(${shake.toFixed(2)} ${(-1.4 * s).toFixed(2)})`);
    const pop = 1 + 0.18 * ringing;
    eyes.forEach((e, i) => { const ex = i ? 66.5 : 53.5; e.setAttribute("transform", `translate(${ex} 31) scale(${pop.toFixed(3)}) translate(${-ex} -31)`); });
    shut.setAttribute("visibility", s > 0.75 ? "hidden" : "visible");
    open.setAttribute("visibility", s > 0.75 ? "visible" : "hidden");
    const grow = 1 + 0.25 * ringing + 0.6 * big;
    ring.setAttribute("opacity", Math.min(1, ringing + big).toFixed(2));
    ring.setAttribute("transform", `translate(${cx} 84) scale(${grow.toFixed(3)}) translate(${-cx} -84)`);
    bow.setAttribute("transform", `translate(99 91.6) scale(1 ${Math.cos(turn).toFixed(3)}) translate(-99 -91.6)`);
  };
  pose(0, 0, 0, 0);
  const drop = () => { loose = true; return { cymbal: cymbals[1], ...hands[1] }; };
  return { el, pose, notes, drop };
}

/** The dropped cymbal: falls to the desk turning flat, bounces once, then rolls away to the right. */
function fallingCymbal(scene: HTMLElement, c: { cymbal: SVGElement; x: number; y: number }): Promise<void> {
  const floor = 110;
  return tween(scene, 1700, (t) => {
    let x = c.x, y = c.y, sx = 1, sy = 0.3, turn = 0;
    if (t < 0.38) {                                        // falling, and turning from edge-on to flat
      const a = t / 0.38;
      x += 12 * a; y = lerp(c.y, floor, a * a); sx = lerp(0.26, 1, a); sy = lerp(1, 0.3, a); turn = 40 * a;
    } else if (t < 0.58) {                                 // one bounce
      const b = (t - 0.38) / 0.2;
      x += 12 + 10 * b; y = floor - 9 * Math.sin(Math.PI * b); turn = 40 + 30 * b;
    } else {                                               // rolling away, wobbling less and less
      const r = (t - 0.58) / 0.42, e = 1 - (1 - r) ** 2;
      x += 22 + 80 * e; y = floor; sy = 0.3 + 0.12 * Math.sin(r * 14 * Math.PI) * (1 - r); turn = 70 + 300 * e;
    }
    c.cymbal.setAttribute("transform", `translate(${x.toFixed(1)} ${y.toFixed(1)}) rotate(${(turn % 360).toFixed(1)}) scale(${sx.toFixed(3)} ${sy.toFixed(3)})`);
    c.cymbal.setAttribute("opacity", t > 0.9 ? ((1 - t) / 0.1).toFixed(2) : "1");
  });
}

// The office: a wall, a window (sky and estate by day, moon and lit flats by night), the desk, a
// monitor with a query on it, and a mug. All of it is HTML/CSS around inline drawings.
function windowView(): SVGElement {
  const out: SVGElement[] = [rect(0, 0, 118, 80, "dk-frame"), rect(4, 4, 110, 72, "dk-sky sc-day"), rect(4, 4, 110, 72, "dk-sky-night sc-night")];
  out.push(ellipse(30, 26, 12, 4, "dk-cloud sc-day"), ellipse(40, 23, 9, 5, "dk-cloud sc-day"), ellipse(86, 18, 11, 3.5, "dk-cloud sc-day"),
    circle(92, 18, 5, "dk-moon sc-night"));
  const rand = seeded(5);
  for (let i = 0; i < 18; i++) out.push(rect(6 + rand() * 106, 6 + rand() * 30, 1, 1, "dk-star sc-night"));
  for (const [x, w, hgt] of [[8, 22, 34], [34, 18, 44], [56, 26, 30], [86, 24, 40]]) {          // flats across the road
    out.push(rect(x, 76 - hgt, w, hgt, "dk-bldg"));
    for (let y = 76 - hgt + 4; y < 74; y += 5) for (let wx = x + 3; wx < x + w - 3; wx += 5) out.push(rect(wx, y, 2.4, 2, rand() < 0.45 ? "dk-bldg-win lit" : "dk-bldg-win"));
  }
  out.push(rect(57, 4, 4, 72, "dk-frame"), rect(4, 38, 110, 3, "dk-frame"), rect(4, 4, 110, 9, "dk-blind"));
  for (let y = 6; y < 13; y += 2.4) out.push(rect(4, y, 110, 0.6, "dk-frame"));
  out.push(rect(-4, 78, 126, 4, "dk-frame"));
  return svg("svg", { width: 118, height: 82, viewBox: "-4 0 126 82", "aria-hidden": "true" }, out);
}

function monitorView(): SVGElement {
  const rand = seeded(9), lines: SVGElement[] = [];
  const tokens = ["kw", "id", "id", "str", "num", "id"];
  for (let copy = 0; copy < 2; copy++) {                        // the query twice, so it can scroll round
    for (let l = 0; l < 12; l++) {
      let x = 4 + (l % 4 === 0 ? 0 : 6);
      const y = copy * 84 + 4 + l * 7;
      for (let t = 0; t < 2 + Math.floor(rand() * 3) && x < 92; t++) {
        const w = 6 + rand() * 16;
        lines.push(rect(x, y, w, 3, `dk-code-${t === 0 && l % 4 === 0 ? "kw" : tokens[Math.floor(rand() * tokens.length)]}`));
        x += w + 3;
      }
    }
  }
  return svg("svg", { width: 112, height: 86, viewBox: "0 0 112 86", "aria-hidden": "true" },
    rect(48, 70, 16, 10, "dk-stand"), svg("rect", { x: 36, y: 79, width: 40, height: 5, rx: 2, class: "dk-stand" }),
    svg("rect", { x: 0, y: 0, width: 112, height: 72, rx: 4, class: "dk-bezel" }),
    svg("svg", { x: 5, y: 5, width: 102, height: 61, viewBox: "0 0 102 61" }, rect(0, 0, 102, 61, "dk-screen"), svg("g", { class: "dk-code" }, lines),
      rect(4, 52, 3, 4, "dk-cursor")),
    circle(104, 68.5, 1.2, "dk-led"));
}

function mugView(): SVGElement {
  return svg("svg", { width: 30, height: 34, viewBox: "0 0 30 34", "aria-hidden": "true" },
    svg("path", { d: "M 9 8 q 3 -4 0 -7 M 15 8 q 3 -4 0 -7", class: "dk-steam" }),
    svg("path", { d: "M 21 16 q 7 0 7 6 q 0 6 -7 6", class: "dk-mug-handle" }),
    svg("rect", { x: 3, y: 11, width: 19, height: 21, rx: 3, class: "dk-mug" }), ellipse(12.5, 12, 8.5, 2, "dk-coffee"),
    svg("text", { x: 12.5, y: 25, class: "dk-mug-text" }, "SQL"));
}

export function monkeyLoader(label: string): TrainLoader {
  const toy = monkey();
  const scene = h("div", { class: "tl-scene dk-scene", "aria-hidden": "true" },
    h("div", { class: "dk-window" }, windowView()),
    h("div", { class: "dk-desk" }),
    h("div", { class: "dk-monitor" }, monitorView()),
    h("div", { class: "dk-mug-at" }, mugView()),
    h("div", { class: "dk-monkey-at" }, toy.el));
  // the toy's state: where it is in its clap, how fast it claps, and its ending
  const st = { u: 0, turn: 0, rate: 2, big: 0, phase: "clapping" as "clapping" | "last" | "winding" | "still", clashAt: 0, done: null as null | (() => void),
    failing: false, falling: Promise.resolve() };
  if (moving()) {
    let last = performance.now();
    const frame = (now: number) => {
      if (!scene.isConnected) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (st.phase === "last") {
        st.rate = Math.min(3, st.rate + dt * 4);                                   // a quick last clap
        if (st.u >= st.clashAt && st.failing) { st.phase = "winding"; st.falling = fallingCymbal(scene, toy.drop()); }   // it slips
        else if (st.u >= st.clashAt) { st.phase = "winding"; st.big = 1; animateNotes(scene, toy.notes); }
      } else if (st.phase === "winding") {
        st.rate = Math.max(0.35, st.rate - dt * 1.9);                              // the spring runs down
        st.big = Math.max(0, st.big - dt * 2.5);
        if (st.rate < 0.7 && st.u % 1 < 0.04 && st.u > st.clashAt + 0.3) { st.phase = "still"; st.u = Math.round(st.u); }
      }
      if (st.phase !== "still") { st.u += dt * st.rate; st.turn += dt * 5.5 * (st.rate / 2); }
      const s = 0.5 - 0.5 * Math.cos(2 * Math.PI * st.u);
      toy.pose(s, st.turn, s > 0.78 ? (s - 0.78) / 0.22 : 0, st.big);
      if (st.phase === "still") { toy.pose(0, st.turn, 0, 0); st.done?.(); st.done = null; return; }
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
  }
  const ending = async (failing: boolean): Promise<void> => {
    if (!moving() || !arrivalWanted(scene)) return;
    st.failing = failing;
    await new Promise<void>((resolve) => {
      st.done = resolve;
      st.clashAt = Math.floor(st.u - 0.5) + 1.5;                                  // the next time the cymbals meet
      st.phase = "last";
      window.setTimeout(resolve, 3500);                                            // a hidden tab: show the results anyway
    });
    await st.falling;
    await sleep(DWELL_MS);
  };
  return loaderShell(label, scene, () => ending(false), () => ending(true));
}

function animateNotes(scene: HTMLElement, notes: SVGElement): void {
  void tween(scene, 900, (t) => {
    notes.setAttribute("opacity", (t < 0.2 ? t / 0.2 : 1 - (t - 0.2) / 0.8).toFixed(2));
    notes.setAttribute("transform", `translate(0 ${(-10 * t).toFixed(1)})`);
  });
}

// --- the filing cabinets (Review: logs before and after) ----------------------------------------------
// Steel cabinets of four drawers stand in a row, each labelled with how far before or after the
// observation its files are. The middle one, the observation, has a red card and a red tag on a
// drawer. A magnifying glass visits drawers from the middle outwards, before then after: the drawer
// slides out, the glass runs along the folder tabs, and a file worth keeping is lifted out and laid
// on the tray on top of the middle cabinet. Cabinets outside the chosen window are greyed.

const FC = { w: 1400, mid: 700, pitch: 70, cab: 64, top: 40, bottom: 138, drawer: 23.5, drawers: 4, side: 9 };
const cabX = (i: number) => FC.mid - FC.cab / 2 + i * FC.pitch;
const drawerY = (k: number) => FC.top + 4 + k * FC.drawer;
const minutes = (m: number) => (m >= 60 ? `${+(m / 60).toFixed(1)} h` : `${+m.toFixed(1)} min`);

interface Window_ { before: number; after: number }

function cabinets(win: Window_): { parts: SVGElement[]; tray: { x: number; y: number }; middle: SVGElement } {
  const out: SVGElement[] = [rect(0, FC.bottom, FC.w, 150 - FC.bottom, "fc-floor"), rect(0, FC.bottom, FC.w, 1.4, "fc-skirting")];
  const stepB = win.before / 4, stepA = win.after / 4;
  let middle = out[0];
  for (let i = -FC.side; i <= FC.side; i++) {
    const x = cabX(i), mid = i === 0;
    const inside = mid || (i < 0 ? -i <= 4 && stepB > 0 : i <= 4 && stepA > 0);
    const g = svg("g", { class: inside ? "" : "fc-dim" },
      rect(x, FC.top, FC.cab, FC.bottom - FC.top, "fc-cab"), rect(x - 1, FC.top - 2, FC.cab + 2, 4, "fc-cab-top"),
      rect(x + FC.cab - 4, FC.top, 4, FC.bottom - FC.top, "fc-cab-shade"), rect(x + 2, FC.bottom - 4, FC.cab - 4, 4, "fc-cab-shade"));
    for (let k = 0; k < FC.drawers; k++) {
      const y = drawerY(k);
      g.append(svg("rect", { x: x + 4, y, width: FC.cab - 8, height: FC.drawer - 2.5, rx: 1.5, class: "fc-drawer" }),
        svg("rect", { x: x + 24, y: y + 11.5, width: 16, height: 3.2, rx: 1.6, class: "fc-handle" }),
        rect(x + 25, y + 4, 14, 6.5, "fc-label"), rect(x + 27, y + 6.4, 10, 0.9, "fc-label-text"), rect(x + 27, y + 8, 7, 0.9, "fc-label-text"));
    }
    // the card on top: how far from the observation this cabinet's files are
    const text = mid ? "event" : !inside ? "" : `${i < 0 ? "−" : "+"}${minutes(Math.abs(i) * (i < 0 ? stepB : stepA))}`;
    const cardW = mid ? 30 : 40, cardX = mid ? x + 3 : x + (FC.cab - cardW) / 2;
    g.append(rect(cardX, FC.top - 13, cardW, 11, mid ? "fc-card-red" : "fc-card"));
    if (text) g.append(svg("text", { x: cardX + cardW / 2, y: FC.top - 5.2, class: mid ? "fc-card-text red" : "fc-card-text" }, text));
    if (mid) g.append(rect(x + 46, drawerY(1) - 3, 8, 5, "fc-redtag"));                // the observation's own file
    out.push(g);
    if (mid) middle = g;
  }
  // the tray on top of the middle cabinet, where kept files go
  const tray = { x: cabX(0) + 36, y: FC.top - 3 };
  middle.append(rect(tray.x - 1, tray.y - 7, 26, 1, "fc-tray"), rect(tray.x - 1, tray.y - 7, 1, 7, "fc-tray"), rect(tray.x + 24, tray.y - 7, 1, 7, "fc-tray"));
  return { parts: out, tray, middle };
}

function lens(): SVGElement {
  return svg("g", { class: "fc-lens" },
    svg("line", { x1: 9, y1: 9, x2: 20, y2: 20, class: "fc-lens-handle" }),
    circle(0, 0, 12, "fc-lens-glass"), circle(0, 0, 12, "fc-lens-rim"),
    svg("path", { d: "M -7 -4 A 8 8 0 0 1 -2 -8", class: "fc-lens-shine" }));
}

const TABS = ["fc-tab1", "fc-tab2", "fc-tab3", "fc-tab4"];

/** The open drawer: pulled out a little, its folders' tabs showing above its front. */
function openDrawer(i: number, k: number, rand: () => number): SVGElement {
  const x = cabX(i), y = drawerY(k);
  const g = svg("g", { class: "fc-open" }, rect(x + 3, y - 6, FC.cab - 6, 7, "fc-inside"));
  for (let fx = x + 6; fx < x + FC.cab - 10; fx += 6.5) g.append(rect(fx + rand() * 2, y - 8 - rand() * 2, 5, 6, TABS[Math.floor(rand() * TABS.length)]));
  g.append(svg("rect", { x: x + 2.5, y: y + 1, width: FC.cab - 5, height: FC.drawer - 1.5, rx: 1.5, class: "fc-drawer-out" }),
    svg("rect", { x: x + 23, y: y + 12.5, width: 18, height: 3.4, rx: 1.7, class: "fc-handle" }));
  return g;
}

function folder(): SVGElement {
  return svg("g", {}, rect(-9, -6, 18, 12, "fc-folder"), rect(-9, -8, 7, 2.5, "fc-folder"), rect(-6, -3, 12, 0.8, "fc-folder-line"),
    rect(-6, -0.8, 9, 0.8, "fc-folder-line"), rect(-6, 1.4, 11, 0.8, "fc-folder-line"));
}

export function filesLoader(label: string, win: Window_): TrainLoader {
  const { parts, tray, middle } = cabinets(win);
  const glass = lens(), stack = svg("g", {}), overlay = svg("g", {}), badge = svg("g", { opacity: 0 });
  const art = svg("svg", { class: "fc-art", width: FC.w, height: 150, viewBox: `0 0 ${FC.w} 150`, "aria-hidden": "true" },
    parts, stack, overlay, badge, glass);
  const scene = h("div", { class: "tl-scene fc-scene", "aria-hidden": "true" }, h("div", { class: "fc-lamp sc-night" }), art);
  const at = (x: number, y: number) => glass.setAttribute("transform", `translate(${x.toFixed(1)} ${y.toFixed(1)})`);
  let lx = FC.mid, ly = drawerY(1) + 8, kept = 0;
  at(lx, ly);
  const st = { ending: false, idle: Promise.resolve() };
  const cut = () => st.ending;
  const moveTo = (x: number, y: number, ms: number) => {
    const [x0, y0] = [lx, ly];
    return tween(scene, ms, (t) => { const e = ease(t); lx = lerp(x0, x, e); ly = lerp(y0, y, e); at(lx, ly); }, cut);
  };
  const addSheet = () => {
    if (kept >= 7) return;
    stack.append(svg("rect", { x: tray.x + 1, y: tray.y - 2.2 - kept * 1.9, width: 22, height: 1.9, class: "fc-sheet" }));
    kept++;
  };

  // which drawers to search: from the middle outwards, before then after, inside the window
  const visits = (): [number, number][] => {
    const reach = Math.max(1, Math.min(4, Math.floor((scene.clientWidth / 2 - FC.cab / 2) / FC.pitch)));
    const out: [number, number][] = [];
    for (let d = 1; d <= reach; d++) {
      if (win.before > 0) out.push([-d, (d * 3) % 4]);
      if (win.after > 0) out.push([d, (d * 3 + 2) % 4]);
    }
    return out.length ? out : [[0, 2]];
  };
  const search = async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));             // on the page first, so its width is known
    const rand = seeded(17);
    const plan = visits();
    for (let n = 0; !st.ending && scene.isConnected; n++) {
      const [i, k] = plan[n % plan.length];
      const x = cabX(i), y = drawerY(k);
      await moveTo(x + 12, y - 4, 480);
      if (st.ending) break;
      const drawer = openDrawer(i, k, rand);
      overlay.append(drawer);
      await tween(scene, 200, (t) => drawer.setAttribute("opacity", t.toFixed(2)), cut);
      await moveTo(x + FC.cab - 12, y - 4, 520);                                    // along the folder tabs
      if (!st.ending && rand() < 0.62) {                                            // one worth keeping
        const file = folder();
        overlay.append(file);
        const fx = x + FC.cab / 2, fy = y - 6;
        await tween(scene, 260, (t) => file.setAttribute("transform", `translate(${fx} ${fy - 12 * ease(t)})`), cut);
        const tx = tray.x + 12, ty = tray.y - 6 - kept * 1.9;
        await tween(scene, 520, (t) => {
          const e = ease(t), px = lerp(fx, tx, e), py = lerp(fy - 12, ty, e) - 26 * Math.sin(Math.PI * e);
          file.setAttribute("transform", `translate(${px.toFixed(1)} ${py.toFixed(1)}) scale(${lerp(1, 0.7, e).toFixed(2)})`);
        }, cut);
        file.remove();
        addSheet();
      } else {
        await sleep(st.ending ? 0 : 160);
      }
      await tween(scene, 160, (t) => drawer.setAttribute("opacity", (1 - t).toFixed(2)), cut);
      drawer.remove();
    }
    overlay.replaceChildren();
  };
  if (moving()) st.idle = search();

  const finish = async (info?: Finish): Promise<void> => {
    if (!moving() || !arrivalWanted(scene)) return;
    st.ending = true;
    await st.idle;                                                               // the current step snaps to its end
    if (!kept) addSheet();
    st.ending = false;
    await moveTo(tray.x + 12, tray.y - 10, 420);
    const found = info?.found;
    const text = found === undefined ? "found" : `${found.toLocaleString()} line${found === 1 ? "" : "s"}`;
    badge.replaceChildren(svg("rect", { x: tray.x - 14, y: tray.y - 31, width: 52, height: 12, rx: 6, class: "fc-badge" }),
      svg("text", { x: tray.x + 12, y: tray.y - 22.6, class: "fc-badge-text" }, `✓ ${text}`));
    await tween(scene, 260, (t) => {
      badge.setAttribute("opacity", t.toFixed(2));
      badge.setAttribute("transform", `translate(${tray.x + 12} ${tray.y - 25}) scale(${lerp(0.6, 1, ease(t)).toFixed(3)}) translate(${-tray.x - 12} ${-tray.y + 25})`);
    });
    await sleep(DWELL_MS + 250);
  };
  // the glass stops; the red-tagged cabinet tips over to the right (about its foot), lands, bounces,
  // its drawers slide open and a few files spill onto the floor
  const failed = async (): Promise<void> => {
    if (!moving() || !arrivalWanted(scene)) return;
    st.ending = true;
    await st.idle;
    overlay.replaceChildren();
    middle.append(stack);
    art.append(middle, glass);                                                   // in front of its neighbours now
    const px = cabX(0) + FC.cab, py = FC.bottom;
    const tilt = (deg: number) => middle.setAttribute("transform", `rotate(${deg.toFixed(2)} ${px} ${py})`);
    await tween(scene, 650, (t) => tilt(90 * t * t));
    await tween(scene, 260, (t) => tilt(90 - 7 * Math.sin(Math.PI * t)));
    const rand = seeded(29);
    const drawers = [openDrawer(0, 0, rand), openDrawer(0, 2, rand)];
    middle.append(...drawers);
    const files = [[-34, 0.7], [126, 1], [176, 0.85]].map(([dx, s]) => ({ el: folder(), dx, s }));
    art.append(...files.map((f) => f.el), glass);
    const fx = px + 50, fy = py - 46;
    await tween(scene, 700, (t) => {
      drawers.forEach((d) => d.setAttribute("opacity", Math.min(1, t * 3).toFixed(2)));
      files.forEach((f, i) => {
        const e = Math.min(1, Math.max(0, t * 1.3 - i * 0.12));
        const x = fx + (f.dx - 50) * e, y = lerp(fy, py - 5, e * e) - 30 * Math.sin(Math.PI * e) * f.s;
        f.el.setAttribute("transform", `translate(${x.toFixed(1)} ${y.toFixed(1)}) rotate(${(e * (i - 1) * 40).toFixed(1)}) scale(${(0.8 * f.s).toFixed(2)})`);
      });
    });
    glass.setAttribute("transform", `translate(${lx.toFixed(1)} ${(ly + 6).toFixed(1)}) rotate(-24)`);       // let fall a little, at rest
    await sleep(DWELL_MS + 250);
  };
  return loaderShell(label, scene, finish, failed);
}

