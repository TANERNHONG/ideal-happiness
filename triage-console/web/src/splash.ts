// Start-up screen: the logo dead centre inside a circle of track; a four-car
// train, seen from above, runs laps around it (train-loop.ts).
//
// The logo was rebuilt from the supplied image; replace smrt-logo.svg with
// the official file for exact fidelity. If the logo cannot load, a text
// wordmark is shown.

import { h } from "./dom";
import { trainLoop } from "./train-loop";

const LOGO_FILES = ["/brand/smrt-logo.svg", "/brand/smrt-logo.png"];

function logo(): HTMLElement {
  const box = h("div", { class: "splash-logo" });
  const word = h("span", { class: "splash-wordmark" }, "SMRT");
  const tryFile = (i: number) => {
    if (i >= LOGO_FILES.length) { box.replaceChildren(word); return; }
    const img = h("img", { src: LOGO_FILES[i], alt: "SMRT" }) as HTMLImageElement;
    img.addEventListener("error", () => tryFile(i + 1), { once: true });
    img.addEventListener("load", () => box.replaceChildren(img), { once: true });
  };
  tryFile(0);
  return box;
}

function stage(): HTMLElement {
  return h("div", { class: "splash-stage" }, trainLoop("splash-loop"), logo());
}

export function splash(status: string, ...extra: (Node | null)[]): HTMLElement {
  return h("div", { class: "splash", role: "status", "aria-live": "polite" },
    h("div"),                                   // top third, empty: keeps the logo dead centre
    stage(),
    h("div", { class: "splash-bottom" },
      h("div", { class: "splash-title" }, "Project DAD Console"),
      h("div", { class: "splash-status" }, status),
      ...extra));
}
