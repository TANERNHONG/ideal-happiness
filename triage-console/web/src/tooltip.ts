// One floating tooltip for the whole page, moved with a transform once per
// frame (keeps hover smooth over large charts). Text only: never HTML.

import { h } from "./dom";

let tipEl: HTMLDivElement | null = null;
let frame = 0;

export function tip(text: string | null, e?: MouseEvent | { clientX: number; clientY: number }): void {
  if (!tipEl) tipEl = h("div", { class: "float-tip", hidden: true }) as HTMLDivElement;
  const host = document.fullscreenElement ?? document.body;     // in fullscreen only that element is drawn
  if (tipEl.parentElement !== host) host.append(tipEl);
  if (text === null || !e) { cancelAnimationFrame(frame); tipEl.hidden = true; return; }
  const x = Math.min(e.clientX + 14, window.innerWidth - 380), y = e.clientY + 12;
  cancelAnimationFrame(frame);
  frame = requestAnimationFrame(() => {
    if (!tipEl) return;
    if (tipEl.textContent !== text) tipEl.textContent = text;
    tipEl.style.transform = `translate(${x}px, ${y}px)`;
    tipEl.hidden = false;
  });
}

/** Hover and keyboard focus on `el` show `text` (focus places it at the element). */
export function withTip(el: HTMLElement, text: string): HTMLElement {
  el.tabIndex = 0;
  el.setAttribute("aria-label", text);
  el.addEventListener("pointermove", (e) => tip(text, e));
  el.addEventListener("pointerleave", () => tip(null));
  el.addEventListener("focus", () => { const r = el.getBoundingClientRect(); tip(text, { clientX: r.left, clientY: r.bottom }); });
  el.addEventListener("blur", () => tip(null));
  return el;
}
