// Tiny DOM helpers. Text always goes in as text nodes, never as HTML, so log
// lines and comments cannot inject markup.

import { waitingPanel } from "./train-loop";

export type Child = Node | string | number | null | undefined | false | Child[];
type Attrs = Record<string, unknown>;

function append(parent: Node, child: Child): void {
  if (child === null || child === undefined || child === false) return;
  if (Array.isArray(child)) child.forEach((c) => append(parent, c));
  else parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
}

function apply(el: Element, attrs: Attrs): void {
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === "class") {
      el.setAttribute("class", String(value));
    } else if (key === "style" && typeof value === "object") {
      Object.assign((el as HTMLElement).style, value);
    } else if (key === "value" && "value" in el) {
      (el as HTMLInputElement).value = String(value);
    } else if (key === "checked" || key === "disabled" || key === "selected") {
      (el as unknown as Record<string, boolean>)[key] = Boolean(value);
    } else {
      el.setAttribute(key, value === true ? "" : String(value));
    }
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  apply(el, attrs);
  children.forEach((c) => append(el, c));
  return el;
}

export function svg<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): SVGElementTagNameMap[K] {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  apply(el, attrs);
  children.forEach((c) => append(el, c));
  return el;
}

export function clear(el: Element, ...children: Child[]): void {
  el.replaceChildren();
  children.forEach((c) => append(el, c));
}

/** Rebuild a part of the page (a list redrawn to show a new selection) without its scrolling boxes jumping back to
 * the top: the box itself and the scrollers inside it keep their positions, matched in order. */
export function keepScroll(el: Element, rebuild: () => void): void {
  const scrollers = () => [el, ...el.querySelectorAll(".list-scroll, .table-wrap")];
  const before = scrollers().map((s) => s.scrollTop);
  rebuild();
  scrollers().forEach((s, i) => { if (before[i]) s.scrollTop = before[i]; });
}

export const fmt = {
  int: (n: number | null | undefined) => (n === null || n === undefined ? "—" : Math.round(n).toLocaleString()),
  pct: (n: number | null | undefined, digits = 1) => (n === null || n === undefined ? "—" : `${(n * 100).toFixed(digits)}%`),
  num: (n: number | null | undefined, digits = 2) => (n === null || n === undefined ? "—" : n.toFixed(digits)),
};

export function badge(text: string, tone: "ok" | "warn" | "bad" | "info" | "muted" | "dark" = "muted"): HTMLElement {
  return h("span", { class: `badge ${tone}` }, text);
}

export function todo(text: string): HTMLElement {
  return h("div", { class: "todo" }, h("strong", {}, "TODO "), text);
}

export function note(...children: Child[]): HTMLElement {
  return h("div", { class: "note" }, ...children);
}

// Capsule meter as in the dashboard: `count` capsules, the first `filled` dark.
export function capsules(share: number, count = 8): HTMLElement {
  const filled = Math.round(Math.max(0, Math.min(1, share)) * count);
  return h("div", { class: "capsules", role: "img", "aria-label": `${Math.round(share * 100)}%` },
    Array.from({ length: count }, (_, i) => h("span", { class: i < filled ? "on" : "" })));
}

export function pills<T extends string>(options: [T, Child][], value: T, onChange: (v: T) => void, small = false): HTMLElement {
  const box = h("div", { class: `pills ${small ? "small" : ""}`, role: "tablist" });
  const draw = (current: T) => clear(box, options.map(([v, label]) => h("button", {
    class: v === current ? "on" : "", role: "tab", "aria-selected": String(v === current),
    onclick: () => { draw(v); onChange(v); },
  }, label)));
  draw(value);
  return box;
}

export function pct(p: number | null | undefined, digits = 1): string {
  return p === null || p === undefined || Number.isNaN(p) ? "—" : `${(p * 100).toFixed(digits)}%`;
}

export function loading(text = "Loading…"): HTMLElement {
  return waitingPanel(text);
}

export function errorBox(error: unknown): HTMLElement {
  return h("div", { class: "error", role: "alert" }, error instanceof Error ? error.message : String(error));
}

export function select(options: [string, string][], value: string, onChange: (v: string) => void, attrs: Attrs = {}): HTMLSelectElement {
  const el = h("select", attrs, options.map(([v, label]) => h("option", { value: v, selected: v === value }, label)));
  el.addEventListener("change", () => onChange(el.value));
  return el;
}

export function table(columns: string[], rows: Child[][], attrs: Attrs = {}): HTMLElement {
  return h("div", { class: "table-wrap" },
    h("table", attrs,
      h("thead", {}, h("tr", {}, columns.map((c) => h("th", { scope: "col" }, c)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
}
