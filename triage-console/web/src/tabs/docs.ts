// Documentation: the pipeline as an MRT line map (click a station), then the guides,
// disclaimers, requirements and the pipeline's own notes as bus stops.

import DOMPurify from "dompurify";
import { marked } from "marked";
import { api, qs } from "../api";
import { clear, errorBox, h, loading } from "../dom";
import { readable } from "../doc-reader";
import { enhanceDoc } from "../doc-visuals";
import { icon } from "../icons";

interface Phase { id: string; name: string; icon: string; what: string; gives: string; sources: string; doc?: string }
// Plain-language descriptions; no machine-learning background assumed.
const PHASES: Phase[][] = [
  [{ id: "0", name: "Raw logs", icon: "folder", sources: "all", what: "The monthly archives copied from the servers, unchanged.", gives: "Zip files per month" }],
  [{ id: "1", name: "Classify", icon: "individual", sources: "all", what: "Every line is matched against written rules and given a type, such as “failed SSH login”. Lines no rule fits are kept as unknown.", gives: "One row per line, with its type and fields" }],
  [{ id: "2", name: "Observations", icon: "episode", sources: "all", what: "Lines are grouped the ways an analyst would look at them: single lines, a login session, five minutes on one server, a whole day.", gives: "One table per way of grouping (a “view”)" },
   { id: "2c", name: "Coverage", icon: "calendar", sources: "auth, OSSEC", what: "Checks which servers sent logs on which days, so gaps are not mistaken for quiet days.", gives: "Days with and without logs per server" }],
  [{ id: "3", name: "Describe", icon: "models", sources: "all", what: "Each observation is turned into a list of numbers (counts, times, which words appear) so that observations can be compared.", gives: "Numbers for every observation" }],
  [{ id: "4a", name: "Detectors", icon: "alert", sources: "all", what: "Three checks learn what normal looked like over most of the year, then flag what departs from it: values far from usual, observations that are easy to single out, and rare combinations never seen before.", gives: "A score and a flag per observation" },
   { id: "4b", name: "More methods", icon: "episode", sources: "auth, OSSEC", what: "Twelve further methods score the same observations; the ones that work best together are kept, and agreement between them is a stronger signal.", gives: "Combined score and votes" },
   { id: "4c", name: "Map", icon: "map", sources: "auth, OSSEC", what: "Places observations on a flat map so that similar ones sit close together; you can see groups and stragglers. Drawn with t-SNE, and with UMAP as a second view of the same points.", gives: "A position for each observation" },
   { id: "4d", name: "Silence", icon: "clock", sources: "auth, OSSEC", what: "Finds servers that went quiet when they normally talk, which can mean logging was switched off.", gives: "Silent stretches per server" },
   { id: "4e", name: "First seen", icon: "review", sources: "auth, OSSEC, PF", what: "Lists accounts and addresses that appear on a server for the first time.", gives: "New pairs per server" },
   { id: "4f", name: "Routines", icon: "flow", sources: "auth, OSSEC", what: "Reads each session as a sentence of events, learns the usual sentences on each server, and flags the ones told in an order rarely or never seen, saying which step was odd.", gives: "Routine catalogue and sequence alerts", doc: "pipeline/phase4f_sequences/guide" }],
  [{ id: "5", name: "Evidence", icon: "docs", sources: "all", what: "Every flag is traced back to the original log lines behind it.", gives: "Original lines for every flag" }],
  [{ id: "6", name: "Report", icon: "docs", sources: "all", what: "A self-contained web page per log type with the findings, maps and explanations.", gives: "HTML report" }],
  [{ id: "7", name: "Alerts", icon: "alert", sources: "all", what: "Everything flagged is collected into one ranked list per log type.", gives: "Alert lists" },
   { id: "7b", name: "Groups", icon: "map", sources: "auth, OSSEC", what: "Similar observations are grouped, named, and marked with how often each group was flagged.", gives: "Named groups (clusters)", doc: "pipeline/phase7b_clusters" },
   { id: "7c", name: "Context", icon: "session", sources: "auth, OSSEC", what: "What the other logs say about the same addresses and servers.", gives: "Context per address" }],
  [{ id: "8", name: "Learn from reviews", icon: "models", sources: "planned", what: "Learns from the decisions made on the Review tab, to tell harmful from harmless activity.", gives: "A classifier (needs reviewed examples)", doc: "pipeline/phase8_malice_classifier" }],
  [{ id: "9", name: "AI triage", icon: "analyze", sources: "all", what: "A small language model on this laptop reads flagged lines and suggests a category with its reasons. A person decides.", gives: "Suggested category and reasons", doc: "pipeline/phase9_llm_triage" }],
];
const GROUPS: Record<string, string> = { app: "Using the console", requirements: "Requirements and design", pipeline: "The pipeline" };

// The pipeline is drawn as an MRT line: the phases are stations on the main line (North-South red),
// and the sub-phases branch off in the colours of other Singapore lines (East-West green, Circle
// orange, Downtown blue). Phase 8 is built into the line but not open yet, like Bukit Brown (CC18).
// The documents are bus stops, each with a "next bus" board: service number, destination, and the
// reading time as the arrival time.
const BRANCH_LINE: Record<string, string> = { "2": "ew", "4a": "cc", "7": "dt" };
const STOP_CODES: Record<string, string> = { app: "01011", requirements: "02021", pipeline: "07071" };
const lineOf = (id: string) => {
  const group = PHASES.find((g) => g.some((p) => p.id === id))!;
  return group[0].id === id ? "ns" : BRANCH_LINE[group[0].id] ?? "ns";
};
const code = (p: Phase) => `PH${p.id}`;

/** The stations either side: along the main line, or along a branch (its first stop's neighbour is the interchange). */
function neighbours(id: string): [Phase | null, Phase | null] {
  const gi = PHASES.findIndex((g) => g.some((p) => p.id === id));
  const group = PHASES[gi], i = group.findIndex((p) => p.id === id);
  if (i === 0) return [PHASES[gi - 1]?.[0] ?? null, PHASES[gi + 1]?.[0] ?? null];
  return [group[i - 1], group[i + 1] ?? null];
}

// Bus services: the document's number (01 → 1), the phase for pipeline notes (7b → 7B), PH for the overview.
// OT for the console's own README.
const service = (id: string) => {
  const phase = /phase(\d+[a-z]?)/.exec(id), num = /\/(\d+)_/.exec(id);
  return phase ? phase[1].toUpperCase() : num ? String(Number(num[1])) : id.startsWith("app/") ? "OT" : "PH";
};
const DESTINATIONS: Record<string, string> = { "app/README": "Running it: setup, caches and tests", "app/QUICKSTART": "Quick start" };
const destination = (id: string, title: string) => {
  const t = DESTINATIONS[id] ?? title.replace(/^(SMRT OT Console|Project Huh|Phase \w+):\s*/i, "");
  return t.charAt(0).toUpperCase() + t.slice(1);
};
const minutes = (words: number) => Math.max(1, Math.round((words || 0) / 200));

let current = "";          // "" = overview
let anchor = "";           // a section to show once the document is drawn
let picked = "1";

export async function renderDocs(main: HTMLElement): Promise<void> {
  // #/docs/<document id>?at=<section>, from a link on another page (Models → the model zoo's information icon):
  // open that document, then keep the plain #/docs address, as the page's own links do.
  const link = /^#\/docs\/([^?]+)(?:\?at=([\w-]+))?$/.exec(location.hash);
  if (link) {
    current = decodeURIComponent(link[1]);
    anchor = link[2] ?? "";
    history.replaceState(null, "", "#/docs");
  }
  const { docs } = await api("/api/docs");
  const body = h("div");
  clear(main, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Documentation"))), body);
  const open = (id: string, section = "") => { current = id; anchor = section; draw(); main.parentElement?.scrollTo({ top: 0 }); };
  const draw = () => {
    if (current) {
      const page = h("article", { class: "card markdown" }, loading());
      const toc = h("aside", { class: "doc-toc", "aria-label": "On this page", hidden: true });
      clear(body, h("div", { class: "row", style: { marginBottom: "12px" } },
        h("button", { class: "btn small", onclick: () => open("") }, icon("collapse", 14), "Overview")),
        h("div", { class: "doc-reader" }, page, toc));
      drawPage(page, toc, docs, open);
      return;
    }
    const detail = h("div");
    const map = h("div", { class: "mrt-wrap" });
    const pick = (id: string) => { picked = id; drawMap(); drawDetail(); };
    const station = (p: Phase, sub: boolean, interchange = false) => {
      const planned = p.sources === "planned";
      return h("button", {
        class: `mrt-stn ${sub ? "sub" : "main"} line-${lineOf(p.id)} ${interchange ? "ix" : ""} ${planned ? "planned" : ""} ${p.id === picked ? "on" : ""}`,
        "aria-pressed": String(p.id === picked), "aria-label": `${code(p)} ${p.name}${planned ? ", not open yet" : ""}`,
        title: `Phase ${p.id} · ${p.name}${planned ? " (planned)" : ""}`, onclick: () => pick(p.id),
      },
        h("span", { class: "mrt-code" }, code(p)), h("span", { class: "mrt-name" }, p.name), h("span", { class: "mrt-dot", "aria-hidden": "true" }),
        planned ? h("span", { class: "mrt-note" }, "not open yet") : null);
    };
    const drawMap = () => {
      const n = PHASES.length;
      clear(map, h("div", { class: "mrt", style: { gridTemplateColumns: `repeat(${n}, minmax(92px, 1fr))` } },
        h("span", { class: "mrt-track", "aria-hidden": "true", style: { left: `${50 / n}%`, right: `${50 / n}%` } }),
        PHASES.map((group) => h("div", { class: "mrt-col" },
          station(group[0], false, group.length > 1),
          group.length > 1 ? h("div", { class: `mrt-branch line-${BRANCH_LINE[group[0].id] ?? "ns"}` }, group.slice(1).map((p) => station(p, true))) : null))));
    };
    const drawDetail = () => {
      const p = PHASES.flat().find((x) => x.id === picked)!;
      const docId = p.doc && docs.some((d: any) => d.id === p.doc) ? p.doc : "pipeline/README";
      const [prev, next] = neighbours(p.id);
      const go = (q: Phase | null, label: string, cls: string) => q
        ? h("button", { class: `btn small stn-go ${cls}`, onclick: () => pick(q.id) },
          h("span", { class: "tiny muted" }, label), h("span", {}, h("span", { class: `mrt-code line-${lineOf(q.id)}` }, code(q)), " ", q.name))
        : h("span");
      clear(detail, h("div", { class: `card stn-card line-${lineOf(p.id)}` },
        h("div", { class: "stn-sign" },
          h("span", { class: "mrt-code big" }, code(p)),
          h("div", { style: { minWidth: "0" } }, h("div", { class: "stn-name" }, p.name),
            h("div", { class: "stn-sub" }, `Phase ${p.id} · ${p.sources === "planned" ? "planned: not open yet" : `serves ${p.sources === "all" ? "every log type" : p.sources}`}`)),
          h("span", { class: "stn-icon" }, icon(p.icon, 22))),
        h("p", { style: { margin: "0 0 10px", maxWidth: "72ch" } }, p.what),
        h("div", { class: "row small" }, h("strong", {}, "Produces:"), p.gives),
        h("div", { class: "stn-nav" }, go(prev, "Previous station", "back"),
          h("button", { class: "btn small", onclick: () => open(docId) }, "Read more", icon("external", 14)),
          go(next, "Next station", "ahead"))));
    };
    drawMap();
    drawDetail();
    const stop = (g: string, label: string) => h("div", { class: "card bus-stop" },
      h("div", { class: "bus-pole" }, h("span", { class: "bus-sign", "aria-hidden": "true" }, icon("bus", 22)),
        h("div", {}, h("h2", { class: "bus-name" }, label), h("div", { class: "bus-code" }, `Bus stop ${STOP_CODES[g] ?? "00000"}`))),
      h("div", { class: "bus-board" },
        h("div", { class: "bus-row head", "aria-hidden": "true" }, h("span", {}, "Svc"), h("span", {}, "Destination"), h("span", {}, "Next")),
        h("ul", {}, docs.filter((d: any) => d.group === g).map((d: any) => {
          const m = minutes(d.words);
          return h("li", {}, h("a", {
            class: "bus-row", href: "#/docs", title: `${d.title} · about ${m} minute${m === 1 ? "" : "s"} to read`,
            onclick: (e: Event) => { e.preventDefault(); open(d.id); },
          }, h("span", { class: "bus-svc" }, service(d.id)), h("span", { class: "bus-dest" }, destination(d.id, d.title)),
            h("span", { class: "bus-eta" }, m <= 1 ? "Arr" : `${m} min`)));
        }))));
    clear(body,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("train")), h("h2", {}, "The pipeline line"),
        h("span", { class: "end small muted" }, "Each phase is a station: click one")), map,
        h("div", { class: "mrt-legend tiny muted" },
          h("span", {}, h("i", { class: "lg-dot" }), "Station"),
          h("span", {}, h("i", { class: "lg-ix" }), "Interchange: sub-phases branch off"),
          h("span", {}, h("i", { class: "lg-planned" }), "Not open yet (planned)"),
          h("span", {}, "Branches run for some log types only: each station says which"))),
      detail,
      h("div", { class: "grid three", style: { marginTop: "16px" } }, Object.entries(GROUPS).map(([g, label]) => stop(g, label))),
      h("p", { class: "tiny muted", style: { margin: "6px 2px 0" } }, "Next: reading time at about 200 words a minute. Arr: under a minute and a half."));
  };
  draw();
}

// Links inside a document are written for the files on disk. Here they are made to work in the
// console: a section link scrolls to its heading (headings get the same ids as on GitHub), a link to
// another document opens it in this page, and a link to anything else in the project (code, data,
// folders) becomes plain text naming its path, since the console does not show those files.
const slug = (text: string) => text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");

function resolve(from: string, link: string): string {
  const parts = from.split("/").slice(0, -1);
  for (const part of link.split("/")) {
    if (part === "..") parts.pop();
    else if (part && part !== ".") parts.push(part);
  }
  return parts.join("/");
}

function scrollToSection(page: HTMLElement, section: string): void {
  if (section) page.querySelector(`#${CSS.escape(decodeURIComponent(section))}`)?.scrollIntoView({ block: "start" });
}

async function drawPage(page: HTMLElement, toc: HTMLElement, docs: any[], open: (id: string, section?: string) => void): Promise<void> {
  try {
    const { markdown, path } = await api(`/api/docs/page${qs({ id: current })}`);
    page.innerHTML = DOMPurify.sanitize(await marked.parse(markdown));
    const seen = new Map<string, number>();
    page.querySelectorAll("h1, h2, h3, h4, h5, h6").forEach((heading) => {
      const base = slug(heading.textContent ?? ""), n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      heading.id = n ? `${base}-${n}` : base;
    });
    const byPath = new Map<string, string>(docs.map((d: any) => [d.path, d.id]));
    page.querySelectorAll<HTMLAnchorElement>("a[href]").forEach((a) => {
      const href = a.getAttribute("href") ?? "";
      if (/^(https?:|mailto:)/i.test(href)) {
        a.rel = "noreferrer";
        a.target = "_blank";
        return;
      }
      const [file, section = ""] = href.split("#");
      const target = file ? resolve(path, decodeURIComponent(file)) : path;
      const id = byPath.get(target);
      if (id) {
        a.href = "#/docs";
        a.addEventListener("click", (e) => {
          e.preventDefault();
          if (id === current) scrollToSection(page, section);
          else open(id, section);
        });
      } else {
        a.replaceWith(h("span", { class: "doc-file", title: `Not shown in the console: ${target} in the project folder` }, a.textContent ?? target));
      }
    });
    enhanceDoc(current, page);                                         // personas, epics (doc-visuals.ts)
    const doc = docs.find((d: any) => d.id === current);
    if (doc) readable(page, toc, doc, docs, GROUPS[doc.group] ?? "", (id) => open(id));   // header, tables, code, contents (doc-reader.ts)
    scrollToSection(page, anchor);
    anchor = "";
  } catch (e) {
    clear(page, errorBox(e));
  }
}
