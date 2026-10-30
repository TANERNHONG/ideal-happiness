import "@fontsource-variable/inter";      // bundled locally (OFL-1.1); no font requests leave the laptop
import "@fontsource-variable/roboto";     // the same, for the Roboto option (close to the trains' passenger displays)
import "@fontsource-variable/space-grotesk";    // the same: titles and figures
import "@fontsource-variable/jetbrains-mono";   // the same: labels, log lines and codes
import "./styles.css";
import { api } from "./api";
import { clear, errorBox, h } from "./dom";
import { t } from "./i18n";
import { icon } from "./icons";
import { setMode } from "./mode";
import { splash } from "./splash";
import { loadAll, refreshLlm, state, subscribe, updateSettings } from "./state";
import { renderAnalyze } from "./tabs/analyze";
import { renderDashboard } from "./tabs/dashboard";
import { renderDatasets } from "./tabs/datasets";
import { renderData } from "./tabs/data";
import { renderDocs } from "./tabs/docs";
import { renderAudit } from "./tabs/audit";
import { renderExplain } from "./tabs/explain";
import { renderModels } from "./tabs/models";
import { renderPatterns } from "./tabs/patterns";
import { renderProfiles } from "./tabs/profiles";
import { renderReview } from "./tabs/review";
import { renderSettings } from "./tabs/settings";
import { renderSigma } from "./tabs/sigma";
import { renderReports } from "./tabs/reports";
import { renderSimple, renderUpload, renderUploads } from "./tabs/simple";

type Tab = { id: string; render: (main: HTMLElement) => void | Promise<void> };
// Simple mode (US-35) shows four pages; Advanced shows every page but the two Simple-only ones.
const SIMPLE: Tab[] = [
  { id: "simple", render: renderSimple },
  { id: "uploads", render: renderUploads },
  { id: "reports", render: renderReports },
  { id: "settings", render: renderSettings },
];
const UPLOAD: Tab = { id: "upload", render: renderUpload };      // one upload: from either mode's Review
const TABS: Tab[] = [
  { id: "dashboard", render: renderDashboard },
  { id: "datasets", render: renderDatasets },
  { id: "patterns", render: renderPatterns },
  { id: "models", render: renderModels },
  { id: "analyze", render: renderAnalyze },
  { id: "sigma", render: renderSigma },
  { id: "review", render: renderReview },
  { id: "audit", render: renderAudit },
  { id: "explain", render: renderExplain },
  { id: "profiles", render: renderProfiles },
  { id: "data", render: renderData },
  { id: "reports", render: renderReports },
  { id: "docs", render: renderDocs },
  { id: "settings", render: renderSettings },
];
// Advanced mode's menu, in the order of an investigation: where things stand; making the logs readable and the models
// ready (what the console can see); detecting; investigating; reporting; then the console itself.
const GROUPS: { id: string; tabs: string[] }[] = [
  { id: "overview", tabs: ["dashboard"] },
  { id: "prepare", tabs: ["datasets", "patterns", "models"] },
  { id: "detect", tabs: ["analyze", "sigma"] },
  { id: "investigate", tabs: ["review", "audit", "explain", "profiles", "data"] },
  { id: "report", tabs: ["reports"] },
  { id: "console", tabs: ["docs", "settings"] },
];
const COLLAPSE_KEY = "huh.sidebar.collapsed";
const app = document.getElementById("app")!;

const simple = () => state.settings.console_mode !== "advanced";
const shown = () => (simple() ? SIMPLE : TABS);
const hashId = () => location.hash.replace(/^#\/?/, "").split("/")[0];

function currentTab(): Tab {
  const id = hashId();
  if (id === UPLOAD.id) return UPLOAD;
  return [...TABS, ...SIMPLE].find((tab) => tab.id === id) ?? shown()[0];
}

// The page an upload belongs under in the menu.
const menuId = (tab: Tab) => (tab.id !== UPLOAD.id ? tab.id : simple() ? "uploads" : "review");

/** An Advanced page opened in Simple mode: offer to switch rather than fail. */
function advancedOnly(tab: Tab): HTMLElement {
  return h("div", { class: "card simple-card advanced-only" }, icon(tab.id, 34), h("h1", {}, t(`nav.${tab.id}` as never)),
    h("div", { class: "row", style: { justifyContent: "center", gap: "8px" } },
      h("a", { class: "btn", href: "#/simple" }, t("nav.simple")),
      h("button", { class: "btn primary", onclick: () => updateSettings({ console_mode: "advanced" }) }, t("mode.switch"))));
}

function modeSwitch(): HTMLElement {
  const mode = simple() ? "simple" : "advanced";
  return h("div", { class: "mode-switch", role: "group", "aria-label": "Console mode" },
    (["simple", "advanced"] as const).map((m) => h("button", {
      class: m === mode ? "on" : "", "aria-pressed": String(m === mode), title: t(`mode.${m}`), "aria-label": t(`mode.${m}`),
      onclick: () => { if (m !== mode) void setMode(m); },
    }, icon(`mode-${m}`, 16), h("span", { class: "full" }, t(`mode.${m}`)))));
}

function collapsed(): boolean {
  try { return localStorage.getItem(COLLAPSE_KEY) === "1"; } catch { return false; }
}

// Top-right model picker. Same setting as the Settings tab.
function llmPicker(): HTMLElement {
  const { llm, settings } = state;
  const choose = h("select", { "aria-label": t("llm.label") },
    llm.models.map((m) => h("option", { value: m, selected: m === settings.llm_model },
      llm.installed.includes(m) || !llm.online ? m : `${m} (not installed)`)));
  choose.addEventListener("change", () => updateSettings({ llm_model: choose.value }));
  return h("div", { class: "llm-picker", title: `${llm.online ? t("llm.online") : t("llm.offline")} · ${llm.endpoint}` },
    h("span", { class: `dot ${llm.online ? "on" : ""}`, "aria-hidden": "true" }),
    choose,
    h("button", { class: "icon-btn", title: t("llm.refresh"), "aria-label": t("llm.refresh"), onclick: () => refreshLlm() }, icon("refresh", 16)));
}

let main: HTMLElement;

function renderShell(): void {
  const active = currentTab();
  const shell = h("div", { class: `shell ${collapsed() ? "collapsed" : ""}` });
  const toggle = h("button", { class: "toggle", "aria-label": "Collapse or expand the menu", title: "Collapse / expand" },
    h("span", { class: "chip" }, icon(collapsed() ? "expand" : "collapse", 18)));
  toggle.addEventListener("click", () => {
    const next = !shell.classList.contains("collapsed");
    shell.classList.toggle("collapsed", next);
    shell.querySelectorAll<HTMLElement>(".nav-flyout").forEach((panel) => { panel.hidden = true; });
    try { localStorage.setItem(COLLAPSE_KEY, next ? "1" : "0"); } catch { /* per-browser convenience only */ }
    clear(toggle, h("span", { class: "chip" }, icon(next ? "expand" : "collapse", 18)));
  });
  main = h("main", { id: "main", tabindex: "-1" });
  const link = (tab: Tab) => {
    const on = tab.id === menuId(active);
    const label = t(`nav.${tab.id === "uploads" ? "review" : tab.id}` as never);
    return h("a", { href: `#/${tab.id}`, class: on ? "active" : "", title: label, "aria-current": on ? "page" : undefined },
      h("span", { class: "chip" }, icon(tab.id, 18)), h("span", { class: "label" }, label));
  };
  const menu = simple() ? SIMPLE.map(link) : GROUPS.map((g) => {
    const name = t(`group.${g.id}` as never);
    const tabs = g.tabs.map((id) => TABS.find((tab) => tab.id === id)!);
    return h("div", { class: "nav-group", role: "group", "aria-label": name },
      h("div", { class: "nav-group-head", "aria-hidden": "true" }, icon(`group-${g.id}`, 14), h("span", { class: "label" }, name)),
      tabs.map(link),
      groupIcon(g.id, name, tabs, tabs.some((tab) => tab.id === menuId(active)), link));     // shown when collapsed
  });
  clear(shell,
    h("nav", { class: "sidebar", "aria-label": "Main" },
      h("div", { class: "brand", title: t("appName") },
        h("span", { class: "brand-mark", "aria-hidden": "true" }, h("img", { src: "/brand/smrt-logo.svg", alt: "" })),
        h("span", { class: "label" }, t("appName"))),
      modeSwitch(),
      menu,
      h("div", { class: "spacer" }),
      toggle),
    h("div", { class: "workspace" }, main));
  clear(app, shell);
  dockPicker(main);
  renderTab();
  api("/api/usage", { body: { event: `view:${active.id}` } }).catch(() => undefined);   // count the page view (count only)
}

/** The menu collapsed: one icon per group, lit when it holds the open page. A group of one page goes straight to it;
 * a larger one opens a panel of its pages beside the menu (on hover, or a click or Enter); it closes when the pointer
 * or the focus leaves it, or on Escape. */
function groupIcon(id: string, name: string, tabs: Tab[], on: boolean, link: (tab: Tab) => HTMLElement): HTMLElement {
  const chip = h("span", { class: "chip" }, icon(`group-${id}`, 18));
  if (tabs.length === 1) {
    const label = t(`nav.${tabs[0].id}` as never);
    return h("div", { class: "nav-group-icon" },
      h("a", { class: `nav-group-btn ${on ? "active" : ""}`, href: `#/${tabs[0].id}`, title: label, "aria-label": label }, chip));
  }
  const panel = h("div", { class: "nav-flyout", hidden: true }, h("div", { class: "nav-flyout-head", "aria-hidden": "true" }, name), tabs.map(link));
  const button = h("button", { class: `nav-group-btn ${on ? "active" : ""}`, type: "button", title: name, "aria-label": name, "aria-expanded": "false" }, chip);
  const box = h("div", { class: "nav-group-icon" }, button, panel);
  let closing = 0;
  const show = () => {
    window.clearTimeout(closing);
    if (!panel.hidden) return;
    document.querySelectorAll<HTMLElement>(".nav-flyout").forEach((other) => { other.hidden = true; });
    panel.hidden = false;
    const at = button.getBoundingClientRect(), menu = button.closest(".sidebar")!.getBoundingClientRect();
    panel.style.left = `${menu.right + 8}px`;
    panel.style.top = `${Math.max(8, Math.min(at.top - 8, window.innerHeight - panel.offsetHeight - 8))}px`;
    button.setAttribute("aria-expanded", "true");
  };
  const hide = () => { panel.hidden = true; button.setAttribute("aria-expanded", "false"); };
  const hideSoon = () => { window.clearTimeout(closing); closing = window.setTimeout(hide, 180); };   // time to cross the gap
  button.addEventListener("click", show);
  for (const el of [button, panel]) {
    el.addEventListener("pointerenter", show);
    el.addEventListener("pointerleave", hideSoon);
  }
  box.addEventListener("focusout", (e) => { if (!box.contains(e.relatedTarget as Node | null)) hide(); });
  box.addEventListener("keydown", (e) => { if (e.key === "Escape" && !panel.hidden) { hide(); button.focus(); } });
  return box;
}

// The page's stage of an investigation, numbered as in the menu ("03 — Detect"), drawn above its title in Advanced mode.
function stageOf(tab: Tab): string {
  const at = GROUPS.findIndex((g) => g.tabs.includes(menuId(tab)));
  return simple() || at < 0 ? "" : `${String(at + 1).padStart(2, "0")} — ${t(`group.${GROUPS[at].id}` as never)}`;
}

// The model picker sits at the right end of each page's title row. Tabs rebuild
// their header when filters or settings change, so re-dock it whenever a new
// header appears.
function dockPicker(container: HTMLElement): void {
  const place = () => {
    const head = container.querySelector<HTMLElement>(".page-head");
    if (!head) return;
    const stage = stageOf(currentTab());
    if (head.dataset.stage !== stage) stage ? (head.dataset.stage = stage) : delete head.dataset.stage;
    if (!head.querySelector(".llm-picker")) head.append(llmPicker());
  };
  new MutationObserver(place).observe(container, { childList: true, subtree: true });
}

async function renderTab(): Promise<void> {
  const tab = currentTab();
  if (simple() && tab !== UPLOAD && !SIMPLE.some((s) => s.id === tab.id)) return clear(main, advancedOnly(tab));
  try {
    await tab.render(main);
  } catch (e) {
    clear(main, errorBox(e));
  }
}

const SPLASH_MIN_MS = 1200;      // long enough to see the train, short enough not to wait for it

async function start(): Promise<void> {
  clear(app, splash("Connecting…"));
  const shown = Date.now();
  try {
    await loadAll();
  } catch (e) {
    clear(app, splash("Could not reach the local service.", errorBox(e),
      h("p", { class: "small" }, "Start it from the triage-console folder: ", h("code", {}, "..\\.venv\\Scripts\\python.exe -m service"))));
    return;
  }
  await new Promise((r) => setTimeout(r, Math.max(0, SPLASH_MIN_MS - (Date.now() - shown))));
  renderShell();
  window.addEventListener("hashchange", renderShell);
  let last = `${state.settings.language}/${state.settings.console_mode}`;
  subscribe(() => {
    app.querySelector(".llm-picker")?.replaceWith(llmPicker());
    const now = `${state.settings.language}/${state.settings.console_mode}`;
    if (now !== last) {
      last = now;
      renderShell();
    }
  });
}

start();
