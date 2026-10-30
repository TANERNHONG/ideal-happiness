// Progress shown like the route map above a train's doors: one light per
// station on a line.
//
//   stops ahead     steady green
//   current stop    steady red - one red light that moves along the line from
//                   station to station as the work moves on (it never flashes)
//   stops passed    unlit
//
// Built once and updated in place, so the red light glides rather than jumps.

import { h } from "./dom";

export interface RouteBoard {
  el: HTMLElement;
  update(seen: string[], status: "running" | "done" | "failed"): void;
}

export function routeBoard(stops: [string, string][]): RouteBoard {
  const at = (i: number) => (stops.length > 1 ? (i / (stops.length - 1)) * 100 : 50);
  const stations = stops.map(([, label], i) =>
    h("div", { class: "route-station ahead", style: { left: `${at(i)}%` } },
      h("span", { class: "route-stop" }, h("span", { class: "led" })),
      h("span", { class: "route-label" }, label)));
  const marker = h("span", { class: "route-marker", style: { left: `${at(0)}%` } });
  const caption = h("div", { class: "route-caption" });
  const track = h("div", { class: "route-track" }, h("span", { class: "route-rail" }), stations, marker);
  const el = h("div", { class: "route-board", role: "progressbar", "aria-valuemin": "1", "aria-valuemax": String(stops.length) }, track, caption);

  const update = (seen: string[], status: "running" | "done" | "failed") => {
    const reached = stops.reduce((last, [id], i) => (seen.includes(id) ? i : last), -1);
    const current = status === "done" ? stops.length - 1 : Math.max(reached, 0);
    stations.forEach((station, i) => {
      station.className = `route-station ${i < current ? "passed" : i > current ? "ahead" : "current"}`;
    });
    marker.style.left = `${at(current)}%`;
    const label = stops[current][1];
    caption.textContent = status === "done" ? "Arrived. Results below."
      : status === "failed" ? `Service stopped at ${label}.`
      : `Next stop: ${label}`;
    el.setAttribute("aria-valuenow", String(current + 1));
    el.setAttribute("aria-valuetext", caption.textContent);
  };
  update([], "running");
  return { el, update };
}
