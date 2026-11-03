// Visuals for the guides that had none, and a lighter look for every other document. As in doc-visuals.ts, the Markdown
// stays the one source: each list or table is redrawn from what it says.
// - Quick start: steps as a timeline, commands as terminals, features as cards, Symptom | What to check as rows.
// - Reports and Review, and Sigma: a title card per section; Rule | Looks for as rule cards; bold-led lists as cards.
// - Measuring the detectors: Page | Compares… as two cards side by side; Measure | … as figures with their sums.
// - Playbooks: each kind of alert as a card: what it looks like, what to check, when it is usually harmless (green),
//   when to escalate (red), and the labels to give, in the review labels' colours.
// - Any other document: the chapters at the top and a small title card per section.

import { h } from "./dom";
import { CHAPTER_COLOURS, actionRows, cells, chapters, content, glossary, headers, sectionOf, stepTiles, timeline, titleCard } from "./doc-visuals";
import { icon } from "./icons";
import { VERDICTS } from "./verdicts";

type Icons = [RegExp, string][];
const glyphOf = (icons: Icons, title: string, fallback = "docs") => icons.find(([rx]) => rx.test(title))?.[1] ?? fallback;
const titleOf = (heading: Element) => heading.firstChild?.textContent ?? "";
const items = (list: Element) => [...list.querySelectorAll(":scope > li")];
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The element starts with a bold term ("**Form**, the default…"), inside its paragraph in a loose list. */
function leadsWithBold(el: Element): boolean {
  const first = [...el.childNodes].find((n) => n.nodeType !== Node.TEXT_NODE || (n.textContent ?? "").trim());
  return first instanceof HTMLElement && (first.tagName === "STRONG" || first.tagName === "P" && leadsWithBold(first));
}
const boldLed = (list: Element) => items(list).length > 0 && items(list).every(leadsWithBold);

/** A list → cards, each with an icon in the section's colour. */
function iconCards(list: Element, glyph: string, colour: string): HTMLElement {
  const grid = h("div", { class: "dc-grid" }, items(list).map((li) => h("div", { class: "dc-card" }, h("span", { class: "dc-icon" }, icon(glyph, 15)), h("div", {}, ...content(li)))));
  grid.style.setProperty("--dc", colour);
  return grid;
}

/** The common pass: chapters, then for each section its lists and tables redrawn by `redraw` and its title card. */
function sections(page: HTMLElement, icons: Icons, redraw: (el: Element, title: string, colour: string) => string, small = false): void {
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = titleOf(heading), colour = CHAPTER_COLOURS[i % CHAPTER_COLOURS.length];
    const counts = sectionOf(heading).map((el) => redraw(el, title, colour)).filter(Boolean);
    titleCard(heading, counts.join(" · "), glyphOf(icons, title), colour, i + 1, small);
  });
}

// --- Quick start -----------------------------------------------------------------------------------------------------

const QUICK_ICONS: Icons = [[/^open/i, "play"], [/set up|rebuild/i, "settings"], [/first investigation/i, "review"], [/optional/i, "sparkle"],
  [/problems/i, "alert"], [/keep/i, "archive"], [/purge/i, "trash"]];

export function quickStart(page: HTMLElement): void {
  sections(page, QUICK_ICONS, (el) => {
    if (el.tagName === "PRE") el.classList.add("terminal");
    else if (el.tagName === "OL") { const n = items(el).length; el.replaceWith(timeline(el)); return plural(n, "step"); }
    else if (el.tagName === "UL" && boldLed(el)) { const n = items(el).length; el.replaceWith(glossary(el)); return plural(n, "feature"); }
    else if (el.tagName === "TABLE" && headers(el)[0] === "symptom") {
      const n = cells(el).length; el.replaceWith(actionRows(el, "Symptom", "What to check")); return plural(n, "problem");
    }
    return "";
  });
}

// --- Reports and Review ----------------------------------------------------------------------------------------------

const REPORT_ICONS: Icons = [[/find/i, "filter"], [/start and save/i, "reports"], [/maps|timelines/i, "map"], [/acknowledge|export/i, "sign"],
  [/ai and records/i, "sparkle"], [/what else/i, "note"]];

export function reportsAndReview(page: HTMLElement): void {
  sections(page, REPORT_ICONS, (el) => {
    if (el.tagName === "UL" && boldLed(el)) { const n = items(el).length; el.replaceWith(glossary(el)); return plural(n, "detail"); }
    return "";
  });
}

// --- Sigma -----------------------------------------------------------------------------------------------------------

const SIGMA_ICONS: Icons = [[/^run/i, "play"], [/^the rules/i, "sigma"], [/write|change/i, "sign"], [/hits/i, "review"], [/limits/i, "alert"],
  [/training|att&ck/i, "target"]];

/** Rule | Looks for → a card per rule. */
function ruleCards(table: Element): HTMLElement {
  return h("div", { class: "gs-grid" }, cells(table).map(([name, what]) => h("div", { class: "gs-card sg-rule" },
    h("div", { class: "gs-term" }, icon("sigma", 15), h("span", {}, ...content(name))), h("div", { class: "gs-def" }, ...content(what)))));
}

export function sigmaGuide(page: HTMLElement): void {
  sections(page, SIGMA_ICONS, (el, title, colour) => {
    if (el.tagName === "OL") { const n = items(el).length; el.replaceWith(timeline(el)); return plural(n, "step"); }
    if (el.tagName === "TABLE" && headers(el)[0] === "rule") { const n = cells(el).length; el.replaceWith(ruleCards(el)); return plural(n, "starter rule"); }
    if (el.tagName === "UL") {
      const n = items(el).length;
      if (boldLed(el)) { el.replaceWith(glossary(el)); return /write|change/i.test(title) ? plural(n, "way") : ""; }
      el.replaceWith(iconCards(el, "alert", colour));
      return plural(n, "limit");
    }
    return "";
  });
}

// --- Measuring the detectors -----------------------------------------------------------------------------------------

const MEASURE_ICONS: Icons = [[/^models/i, "models"], [/^audit/i, "audit"], [/one line/i, "check-circle"]];
const MEASURE_COLOURS = ["#4298b4", "#33a474", "#88619a"];

/** Page | Compares the alerts with | Gives | Costs → a card per page, side by side. */
function compareCards(table: Element): HTMLElement {
  const labels = [...table.querySelectorAll("thead th")].map((th) => (th.textContent ?? "").trim());
  return h("div", { class: "ms-compare" }, cells(table).map(([page, ...rest], i) => {
    const name = (page.textContent ?? "").trim();
    const card = h("div", { class: "ms-card" },
      h("div", { class: "ms-card-head" }, h("span", { class: "ms-card-icon" }, icon(/audit/i.test(name) ? "audit" : "models", 18)), name),
      rest.map((cell, j) => h("div", { class: "ms-row" }, h("small", {}, labels[j + 1]), h("div", {}, ...content(cell)))));
    card.style.setProperty("--mc", MEASURE_COLOURS[i % MEASURE_COLOURS.length]);
    return card;
  }));
}

/** Measure | The question | How it is worked out | In the example → a figure per measure, with its sum. */
function metricCards(table: Element): HTMLElement {
  return h("div", { class: "ms-metrics" }, cells(table).map(([name, question, how, example], i) => {
    const value = example?.querySelector("strong")?.textContent?.trim() ?? "";
    const sum = (example?.textContent ?? "").replace(value, "").replace(/\s*=\s*$/, "").trim();
    const card = h("div", { class: "ms-metric" },
      h("div", { class: "ms-value" }, value),
      h("div", { class: "ms-name" }, (name.textContent ?? "").trim()),
      h("div", { class: "ms-question" }, ...content(question)),
      h("div", { class: "ms-formula" }, ...content(how), sum ? ` · ${sum}` : ""));
    card.style.setProperty("--mc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
    return card;
  }));
}

export function measuresGuide(page: HTMLElement): void {
  const compare = [...page.querySelectorAll("table")].find((t) => headers(t)[0] === "page");
  if (compare) compare.replaceWith(compareCards(compare));
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = titleOf(heading), colour = MEASURE_COLOURS[i % MEASURE_COLOURS.length];
    let sub = "";
    const counts: string[] = [];
    for (const el of sectionOf(heading)) {
      if (el.tagName === "H3") { sub = el.textContent ?? ""; continue; }
      if (el.tagName === "TABLE" && headers(el)[0] === "measure") { counts.push(plural(cells(el).length, "number")); el.replaceWith(metricCards(el)); }
      else if (el.tagName === "OL") { counts.push(plural(items(el).length, "step")); el.replaceWith(timeline(el)); }
      else if (el.tagName === "UL" && /reading/i.test(sub)) el.replaceWith(iconCards(el, "lightbulb", colour));
      else if (el.tagName === "UL" && boldLed(el)) {
        if (/estimates/i.test(sub)) counts.push(plural(items(el).length, "estimate"));
        el.replaceWith(glossary(el));
      } else if (el.tagName === "P" && /one line/i.test(title)) el.replaceWith(h("div", { class: "ms-oneliner" }, ...content(el)));
    }
    titleCard(heading, counts.join(" · "), glyphOf(MEASURE_ICONS, title), colour, i + 1);
  });
}

// --- Playbooks -------------------------------------------------------------------------------------------------------

const PLAYBOOK_ICONS: Icons = [[/before you start/i, "check-circle"], [/guessing/i, "key"], [/spraying/i, "users"], [/enumeration/i, "user"],
  [/after failures/i, "lock"], [/root/i, "shield-warning"], [/new source/i, "globe"], [/amount|timing/i, "chart"], [/order/i, "flow"],
  [/quiet/i, "bell"], [/firewall/i, "shield"], [/sigma/i, "sigma"], [/escalation/i, "megaphone"]];

/** "**Looks like:** …" → its part ("looks like") and the rest of the paragraph, without the bold lead. */
function part(el: Element): [string, Node[]] | null {
  const lead = el.firstElementChild;
  if (el.tagName !== "P" || lead?.tagName !== "STRONG" || el.firstChild !== lead) return null;
  const name = (lead.textContent ?? "").replace(/:\s*$/, "").trim().toLowerCase();
  const rest = content(el).slice(1);
  if (rest[0]?.nodeType === Node.TEXT_NODE) rest[0].textContent = (rest[0].textContent ?? "").replace(/^\s*:?\s*/, "");
  return [name, rest];
}

/** A label named in italics (*Suspicious*) → a chip in that label's colour. */
function labelChips(nodes: Node[]): Node[] {
  return nodes.map((node) => {
    const verdict = node instanceof HTMLElement && node.tagName === "EM"
      ? VERDICTS.find((v) => v.label.toLowerCase() === (node.textContent ?? "").trim().toLowerCase()) : undefined;
    if (!verdict) return node;
    const chip = h("span", { class: "pb-chip" }, verdict.label);
    chip.style.setProperty("--lc", verdict.color);
    return chip;
  });
}

const when = (kind: "harmless" | "escalate", nodes: Node[]) => {
  const box = h("div", { class: "pb-when" }, h("div", { class: "pb-kicker" }, icon(kind === "harmless" ? "check-circle" : "alert", 13),
    kind === "harmless" ? "Usually harmless when" : "Escalate when"), h("div", {}, ...nodes));
  box.style.setProperty("--wc", kind === "harmless" ? "var(--st-good)" : "var(--st-bad)");
  return box;
};

/** One kind of alert's paragraphs and check list → a playbook card; anything else in the section stays, in order. */
function playbookCard(parts: Element[]): [HTMLElement, number] {
  const card = h("div", { class: "pb-card" });
  let pair: HTMLElement | null = null, checks = 0;
  for (let i = 0; i < parts.length; i++) {
    const el = parts[i], found = part(el);
    if (!found) { card.append(el.cloneNode(true)); continue; }
    const [name, rest] = found;
    if (name === "looks like") {
      card.append(h("div", { class: "pb-looks" }, icon("eye", 18), h("div", {}, h("div", { class: "pb-kicker" }, "Looks like"), ...rest)));
    } else if (name === "check" && parts[i + 1]?.tagName === "OL") {
      checks = items(parts[i + 1]).length;
      card.append(h("div", { class: "pb-check" }, h("div", { class: "pb-kicker" }, "Check"), parts[++i].cloneNode(true)));
    } else if (name.startsWith("usually harmless") || name.startsWith("escalate")) {
      if (!pair) { pair = h("div", { class: "pb-pair" }); card.append(pair); }
      pair.append(when(name.startsWith("usually") ? "harmless" : "escalate", rest));
    } else if (name === "label") {
      card.append(h("div", { class: "pb-label" }, h("span", { class: "pb-kicker" }, "Label"), h("span", {}, ...labelChips(rest))));
    } else {
      card.append(el.cloneNode(true));
    }
  }
  return [card, checks];
}

export function playbooksGuide(page: HTMLElement): void {
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = titleOf(heading), colour = CHAPTER_COLOURS[i % CHAPTER_COLOURS.length];
    const parts = sectionOf(heading);
    let count = "";
    if (parts.some((el) => part(el)?.[0] === "looks like")) {
      const [card, checks] = playbookCard(parts);
      parts[0].before(card);
      parts.forEach((el) => el.remove());
      count = checks ? plural(checks, "check") : "";
    } else {
      for (const el of parts) {
        if (el.tagName !== "OL") continue;
        count = plural(items(el).length, "step");
        el.replaceWith(/before you start/i.test(title) ? stepTiles(el) : timeline(el));
      }
    }
    titleCard(heading, count, glyphOf(PLAYBOOK_ICONS, title), colour, i + 1, true);
  });
}

// --- every other document --------------------------------------------------------------------------------------------

const PLAIN_ICONS: Icons = [[/run it|running|how to run|start/i, "play"], [/status/i, "gauge"], [/output|files?\b|folder/i, "folder"],
  [/test/i, "check"], [/securit|privacy/i, "lock"], [/input|data|log sources?/i, "data"], [/device/i, "server"],
  [/model|detector|classifier|train/i, "models"], [/review|label/i, "review"], [/report/i, "reports"], [/limit|gap|caveat|cannot|not do/i, "alert"],
  [/question|decision|still open/i, "lightbulb"], [/architecture|shape|module|interface|storage/i, "matrix"],
  [/unreleased|release|version|history|\d+\.\d+\.\d+/i, "history"], [/plan|next|later/i, "clock"], [/word|glossary/i, "docs"],
  [/rule|pattern/i, "sigma"], [/cluster|group|map/i, "map"], [/sequence|routine|order/i, "flow"], [/performance|speed/i, "gauge"],
  [/usab|accessib|interface/i, "dashboard"], [/triage|prompt|language model|llm/i, "analyze"], [/approved|automation/i, "shield"],
  [/window|calendar/i, "calendar"], [/fits|how it works|overview/i, "flow"], [/simulated|baseline/i, "target"]];

/** The chapters (when there are a handful to a couple of dozen) and a small title card per section; a heading's own
 * number is kept, none is added. */
export function plainLook(page: HTMLElement): void {
  const headings = [...page.querySelectorAll<HTMLElement>("h2")];
  if (headings.length <= 24) chapters(page);
  headings.forEach((heading, i) => titleCard(heading, "", glyphOf(PLAIN_ICONS, titleOf(heading)), CHAPTER_COLOURS[i % CHAPTER_COLOURS.length], undefined, true));
}
