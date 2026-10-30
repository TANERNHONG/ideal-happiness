// Shared state: settings (one copy, so the top-bar model picker and the
// Settings tab always agree), the catalog of sources and views, and the
// local language-model status.

import { api, type Catalog, type Settings } from "./api";

type Listener = () => void;
const listeners = new Set<Listener>();

export const state = {
  settings: null as unknown as Settings,
  catalog: null as unknown as Catalog,
  source: "",          // the log type chosen in the page headers (see log-type.ts)
  pendingSql: "",      // a query handed to Data → SQL (Review's "Open in SQL"); used once
  llm: { online: false, models: [] as string[], installed: [] as string[], error: "", endpoint: "" },
};

export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function notify(): void {
  listeners.forEach((l) => l());
}

const FONTS: Record<Settings["font_family"], string> = {
  inter: `"Inter Variable", Inter, Helvetica, Arial, sans-serif`,
  roboto: `"Roboto Variable", Roboto, "Segoe UI", Arial, sans-serif`,
  helvetica: `Helvetica, "Helvetica Neue", Arial, sans-serif`,
  system: `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`,
  serif: `Georgia, Cambria, "Times New Roman", serif`,
  mono: `"JetBrains Mono Variable", ui-monospace, "Cascadia Code", Consolas, monospace`,
  readable: `Verdana, "Segoe UI", Tahoma, sans-serif`,
  installed: `"Inter Variable", Inter, Helvetica, Arial, sans-serif`,    // behind the installed font, if it is missing
};

export function applyAppearance(): void {
  const s = state.settings;
  const root = document.documentElement;
  if (s.theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", s.theme);
  // An installed font (e.g. a licensed corporate typeface) is used by name only; nothing is downloaded or bundled.
  const installed = s.font_family === "installed" && /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(s.font_installed ?? "") ? `"${s.font_installed}", ` : "";
  root.style.setProperty("--font-body", installed + (FONTS[s.font_family] ?? FONTS.inter));
  root.style.fontSize = `${Math.round(16 * s.font_scale)}px`;
  root.lang = s.language;
  if (s.animations && s.animations !== "all") root.setAttribute("data-motion", s.animations);   // styles.css and train-loader.ts read it
  else root.removeAttribute("data-motion");
}

export async function loadAll(): Promise<void> {
  [state.settings, state.catalog] = await Promise.all([api<Settings>("/api/settings"), api<Catalog>("/api/catalog")]);
  applyAppearance();
  await refreshLlm(false);
}

export async function refreshLlm(announce = true): Promise<void> {
  try {
    const r = await api("/api/llm/models");
    state.llm = { online: r.online, models: r.models, installed: r.installed, error: r.error, endpoint: r.endpoint };
  } catch (e) {
    state.llm = { ...state.llm, online: false, error: String(e) };
  }
  if (announce) notify();
}

export async function updateSettings(changes: Partial<Settings>): Promise<void> {
  state.settings = await api<Settings>("/api/settings", { method: "PUT", body: changes });
  applyAppearance();
  if ("llm_endpoint" in changes) await refreshLlm(false);
  notify();
}

export function sourceLabel(id: string): string {
  return state.catalog?.sources[id]?.label ?? id;
}

export function viewLabel(source: string, view: string): string {
  return state.catalog?.sources[source]?.views.find((v) => v.id === view)?.label ?? view;
}
