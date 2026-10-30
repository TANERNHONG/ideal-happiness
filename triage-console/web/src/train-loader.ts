// Waiting indicators. While a SQL query runs, a vehicle holds still while the town scrolls past
// (day in the light theme, night in the dark one), with the time waited so far; when the query is
// done, arrive() brings it to a stop before the results show.
// - trainLoader: an MRT train on its viaduct (scenery.ts) pulls into a station. Data → SQL.
// - busLoader: an SG Bus double-decker on the road (bus-scenery.ts) pulls into a bus stop. Review.
// Both centre on their own box, wherever the page puts it (Review's is in the right-hand column).
// When the request fails, fail() ends the wait instead: the train turns into a depot and stops short
// of a buffer stop under a red signal; the bus stops at a red light where the road ends at a T-junction.
// Train cars are in web/public/brand/ (web/scripts/brand_assets.py); the bus is drawn inline.

import { BUS_W, BUS_WHEEL_BOTTOM, JUNCTION_ANCHOR, ROAD_SPEED, STOP_ANCHOR, TYRE, bus, busStop, junction, roadScenery } from "./bus-scenery";
import { h } from "./dom";
import { DEPOT_ANCHOR, NEAR_SPEED, STATION_W, TRAIN_HALF, depot, scenery, station } from "./scenery";

const CARS = ["train-side-tail", "train-side-car", "train-side-lead"];      // left to right; the lead car's nose faces right
const BRAKE_S = 2.2;             // braking, from cruising speed to a stop
const LONGEST_S = 6;             // the whole arrival at most; in very wide windows the stop starts nearer
const DWELL_MS = 450;            // standing at the platform or the stop before the results show

/** What the page knows once the query is done, for loaders that show it in their ending (the Desk pack's files). */
export interface Finish { found?: number }
export interface TrainLoader { el: HTMLElement; arrive(info?: Finish): Promise<void>; fail(): Promise<void>; say(text: string): void }
export type Loader = TrainLoader;

// What arrive() needs to know about a vehicle and where it stops.
interface Ride {
  speed: number;                 // px/s of the layer the vehicle runs on
  anchor: number;                // the point of the stop (px from its left edge) that ends under the vehicle's centre
  stop(): HTMLElement;           // the station or bus stop, slid in behind the vehicle
  vehicle: string;               // selector of the vehicle (the stop goes in just before it)
  idle: string[];                // animations that stop with the vehicle (rocking, bobbing)
  endFront?: boolean;            // the scenery in front (the viaduct's noise barriers, tunnel) ends where the stop begins
  gate?: boolean;                // wider than the view: its left boundary (.dp-gate) is placed so it enters from the right
}

function loader(label: string, scene: HTMLElement, ride: Ride, failed: Partial<Ride>): TrainLoader {
  return loaderShell(label, scene, () => arrive(scene, ride), () => arrive(scene, { ...ride, ...failed }));
}

/** A scene with its caption and the time waited so far; finish() is its ending and failed() its ending when the
 * request fails (see loaders.ts for the packs); say() changes the caption while it waits (a long job's progress). */
export function loaderShell(label: string, scene: HTMLElement, finish: (info?: Finish) => Promise<void>,
  failed: () => Promise<void> = async () => undefined): TrainLoader {
  const timer = h("span", { class: "tl-time" }, "0 s");
  const caption = h("span", {}, label);
  const el = h("div", { class: "train-loader", role: "status", "aria-live": "polite" }, scene, h("div", { class: "tl-caption" }, caption, " · ", timer));
  const started = Date.now();
  const tick = window.setInterval(() => {
    if (!el.isConnected) { window.clearInterval(tick); return; }      // replaced by the result
    timer.textContent = `${Math.round((Date.now() - started) / 1000)} s`;
  }, 1000);
  const fail = async () => { el.classList.add("failed"); await failed(); };
  return { el, arrive: finish, fail, say: (text) => { if (caption.textContent !== text) caption.textContent = text; } };
}

export function trainLoader(label: string): TrainLoader {
  const { back, front } = scenery();
  const scene = h("div", { class: "tl-scene", "aria-hidden": "true" },
    back,
    // fixed size, centred by a fixed margin (as the bus): not by a share of its width, which is nothing until the cars
    // have loaded, and a transform animation on the graphics card can keep that first width, leaving it off centre
    h("div", { class: "tl-train", style: { width: `${2 * TRAIN_HALF}px`, marginLeft: `${-TRAIN_HALF}px` } },
      CARS.map((name) => h("img", { src: `/brand/${name}.svg`, alt: "", draggable: "false", style: { width: `${(2 * TRAIN_HALF) / CARS.length}px` } })),
      h("span", { class: "tl-beam sc-night" })),
    front);
  return loader(label, scene, { speed: NEAR_SPEED, anchor: STATION_W / 2, stop: station, vehicle: ".tl-train", idle: ["tl-rock"], endFront: true },
    { anchor: DEPOT_ANCHOR, stop: depot, gate: true });
}

export function busLoader(label: string): TrainLoader {
  const { back, front } = roadScenery();
  const vehicle = bus();
  vehicle.style.top = `${TYRE - BUS_WHEEL_BOTTOM}px`;
  vehicle.style.marginLeft = `${-BUS_W / 2}px`;            // fixed size, drawn inline: centred from the first frame
  const scene = h("div", { class: "tl-scene bl-scene", "aria-hidden": "true" }, back, vehicle, front);
  return loader(label, scene, { speed: ROAD_SPEED, anchor: STOP_ANCHOR, stop: busStop, vehicle: ".bl-bus", idle: ["bus-bob"] },
    { anchor: JUNCTION_ANCHOR, stop: junction });
}

// The road's overhead bridge (bus-scenery.ts) is drawn in two layers: its stairs behind the bus, its
// deck and near pier in front, once in each copy of the repeating picture. A bridge already in view when
// the bus starts to pull in stays whole and scrolls away; one still to come is hidden, whole, so it
// cannot slide in during the arrival and stand in front of the stop.
function holdBackBridges(scene: HTMLElement): void {
  const right = scene.getBoundingClientRect().right;
  const copies = (layer: string) => [...scene.querySelectorAll(`${layer} .sc-road svg > g`)];
  const back = copies(".sc-back"), front = copies(".sc-front");
  back.forEach((copy, i) => {
    const parts = [...copy.querySelectorAll(".bridge-part")];
    const start = Math.min(...parts.map((p) => p.getBoundingClientRect().left));       // the foot of the stairs
    if (parts.length && start >= right) [...parts, ...(front[i]?.querySelectorAll(".bridge-part") ?? [])].forEach((p) => p.classList.add("held"));
  });
}

/** Skipped when Settings → Animations says so (shared with desk-loaders.ts), when the system asks for reduced motion, or when nobody can see it. */
export function arrivalWanted(scene: HTMLElement): boolean {
  const motion = document.documentElement.getAttribute("data-motion");
  return scene.isConnected && !document.hidden && motion !== "none" && motion !== "no-arrival"
    && !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

// Pulling in: every scrolling layer moves on together (all by the same time step, so they keep their
// depth) while the stop comes in behind the vehicle. The vehicle never speeds up: it carries on at its
// cruising speed until the stop is near, then brakes smoothly to a stop at its place.
// Braking eases in and out (speed falls along a smoothstep), which covers half the distance that
// cruising for the same time would. The bus's wheels turn at the speed it is going.
async function arrive(scene: HTMLElement, ride: Ride): Promise<void> {
  if (!arrivalWanted(scene)) return;
  const width = scene.clientWidth;
  const running = scene.getAnimations({ subtree: true }) as CSSAnimation[];
  const scrolling = running.filter((a) => a.animationName === "sc-scroll");
  const wheels = running.filter((a) => a.animationName === "bus-spin");
  const v = ride.speed, braking = (v * BRAKE_S) / 2;                     // px/s, and px covered while braking
  const place = (w: number) => w / 2 - ride.anchor;                      // the stop's left edge once it is in place
  const stop = place(width);
  const farthest = v * (LONGEST_S - BRAKE_S) + braking;                  // what fits in the longest arrival
  const distance = Math.min(width + 20 - stop, farthest);                // from just off the right edge, if it fits
  const start = stop + distance, cruising = (distance - braking) / v;    // seconds at full speed
  const total = cruising + BRAKE_S;
  const progress = (t: number) => (t <= cruising ? 0 : Math.min(1, (t - cruising) / BRAKE_S));
  const moved = (t: number) => {
    if (t <= cruising) return v * t;
    const s = progress(t);
    return v * cruising + v * BRAKE_S * (s - s ** 3 + s ** 4 / 2);       // speed v·(1 − smoothstep(s))
  };
  const platform = ride.stop();
  platform.style.transform = `translateX(${start}px)`;
  // A stop wider than the view (the depot) begins at its gateway, set as far left as can still start just
  // beyond the right edge; the rest of it, left of the gateway, is cut away and the viaduct shows there.
  const cut = ride.gate ? Math.max(0, width + 12 - start) : 0;
  if (ride.gate) {
    platform.style.clipPath = `inset(0 0 0 ${cut}px)`;
    platform.querySelector(".dp-gate")?.setAttribute("transform", `translate(${cut} 0)`);
  }
  if (start + cut < width) platform.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 600, easing: "ease-out" });   // a very wide window: it starts in view
  scene.insertBefore(platform, scene.querySelector(ride.vehicle));
  scene.classList.add("arriving");
  // The viaduct's noise barriers (and a tunnel) stand in front of the train. Rather than vanish, they end
  // where the station or depot begins: the front layer is cut off at its left edge, which moves in with it.
  const front = ride.endFront ? scene.querySelector<HTMLElement>(".sc-front") : null;
  const endAt = (left: number) => { if (front) front.style.clipPath = `inset(0 ${Math.max(0, scene.clientWidth - left).toFixed(1)}px 0 0)`; };
  holdBackBridges(scene);
  const from = scrolling.map((a) => Number(a.currentTime ?? 0));
  scrolling.forEach((a) => a.pause());
  const began = performance.now();
  await new Promise<void>((done) => {
    const safety = window.setTimeout(done, total * 1000 + 300);   // if the tab is hidden, frames stop: show the results anyway
    const frame = (now: number) => {
      const t = Math.min(total, (now - began) / 1000), gone = moved(t), s = progress(t);
      // measured again each frame, so the stop still ends in place if the width changes on the way
      // in (a scrollbar appearing, the window resized)
      const left = place(scene.clientWidth) + distance - gone;
      platform.style.transform = `translateX(${left.toFixed(1)}px)`;
      endAt(left + cut);
      scrolling.forEach((a, i) => { a.currentTime = from[i] + (gone / v) * 1000; });
      wheels.forEach((a) => { a.playbackRate = Math.max(0.001, 1 - s * s * (3 - 2 * s)); });
      if (t < total && scene.isConnected) requestAnimationFrame(frame);
      else { window.clearTimeout(safety); done(); }
    };
    requestAnimationFrame(frame);
  });
  running.filter((a) => a.animationName === "bus-spin" || ride.idle.includes(a.animationName)).forEach((a) => a.pause());
  scene.classList.add("arrived");
  await new Promise((resolve) => window.setTimeout(resolve, DWELL_MS));
}
