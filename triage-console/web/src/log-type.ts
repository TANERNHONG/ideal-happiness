// The log-type dropdown at the top of every page that shows one log type at a
// time (Models, Data, Review). There is one choice for the whole app, so moving
// between pages keeps the same log type. AUTH comes first (catalog order).

import { h, select } from "./dom";
import { sourceLabel, state } from "./state";

const KEY = "huh.logType";

export function chosenSource(): string {
  if (!state.catalog.sources[state.source]) {
    let stored = "";
    try { stored = localStorage.getItem(KEY) ?? ""; } catch { /* per-browser convenience only */ }
    state.source = state.catalog.sources[stored] ? stored : Object.keys(state.catalog.sources)[0];
  }
  return state.source;
}

export function choose(source: string): void {
  state.source = source;
  try { localStorage.setItem(KEY, source); } catch { /* per-browser convenience only */ }
}

// `extra` adds page-specific choices after the log types (the Data page adds "All log types").
export function logTypePicker(onChange: (value: string) => void, options: { extra?: [string, string][]; value?: string } = {}): HTMLElement {
  const types = Object.keys(state.catalog.sources).map((k) => [k, `${k.toUpperCase()} · ${sourceLabel(k)}`] as [string, string]);
  return h("label", { class: "field log-type" }, h("span", {}, "Log type"),
    select([...types, ...(options.extra ?? [])], options.value ?? chosenSource(), (v) => {
      if (state.catalog.sources[v]) choose(v);
      onChange(v);
    }, { "aria-label": "Log type" }));
}

// The Data page can also show every log type at once (the timeline and the Sankeys).
export const dataScope = { all: false };

export function shownSources(): string[] {
  return dataScope.all ? Object.keys(state.catalog.sources) : [chosenSource()];
}
