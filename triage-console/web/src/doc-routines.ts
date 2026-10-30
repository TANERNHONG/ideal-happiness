// Phase 4f's guide (pipeline/phase4f_sequences/GUIDE.md) as pictures. As for the other documents (doc-visuals.ts),
// the Markdown stays the one source; each table or list is redrawn from what it says:
// - the four steps at the top: a strip of step cards;
// - a sentence of events (`A` → `B` written in code): word pills joined by arrows, coloured by what they mean;
// - Stage | AUTH | OSSEC: two funnels;      Problem | Fix | Found: fix cards;
// - Routine | Share: a donut and its legend; Sentence | Sessions and Pattern | Found in: sentences and bars;
// - After | Comes | How often: rule cards with a ring;  From | To | Chance: one path with the chances on its arrows;
// - Chance | Surprise: a ruler of bits;      Line | AUTH | OSSEC: a gauge per log;
// - When | Server: incident cards;           Kind | Alerts: a stacked bar and its legend;
// - Also flagged by | Alerts: bars of the total; Finding | Share: big figures;
// - bold-led lists: cards, and the Words: glossary cards.

import { h, svg } from "./dom";
import { CHAPTER_COLOURS, cells, chapters, content, dropLeadingColon, glossary, sectionOf, stepTiles, titleCard } from "./doc-visuals";
import { icon } from "./icons";

const SECTION_ICONS: [RegExp, string][] = [[/sentences$/i, "session"], [/cleaning/i, "filter"], [/tiny/i, "gauge"], [/prefixspan/i, "matrix"],
  [/rules/i, "flow"], [/step model/i, "history"], [/surprise/i, "sparkle"], [/line/i, "target"], [/found/i, "alert"], [/pile up/i, "map"],
  [/cannot/i, "lock"], [/words/i, "docs"]];

// --- words: event types as pills ------------------------------------------------------------------------------------

/** An event type as a word: lower case, its log's prefix dropped ("SSH_LOGIN_SUCCESS" → "login success"). */
const word = (token: string) => token.length <= 2 ? token
  : token.replace(/^(SSH|OSSEC|SU|GDM|PAM|CRON|SYSLOG|DBUS)_/, "").replace(/_/g, " ").toLowerCase();

/** What a word means, for its colour: refused, done, leaving, the start or end of a sentence, or anything else. */
function tone(token: string): string {
  if (/FAIL|INVALID|DENIED|LOCKED|ERROR|EMPTY|REFUSED/.test(token)) return "bad";
  if (/DISCONNECT|CLOSED|EXIT|TERMINAT/.test(token)) return "leave";               // before "connected", which "disconnected" contains
  if (/SUCCESS|ENDED|CONNECTED|USING/.test(token)) return "good";
  if (/^(start|end)$/i.test(token)) return "edge";
  return "plain";
}

/** The words of a cell or paragraph written as `A` → `B`, or null if it holds anything else. */
function tokensOf(el: Element): string[] | null {
  const codes = [...el.querySelectorAll("code")].map((c) => c.textContent ?? "");
  let rest = el.textContent ?? "";
  for (const c of codes) rest = rest.replace(c, "");
  return codes.length && /^[\s→]*$/.test(rest) ? codes : null;
}

/** A cell's single word: the code in it, or its plain text ("start", "end"). */
const tokenOf = (el: Element) => el.querySelector("code")?.textContent ?? (el.textContent ?? "").trim();

/** Words joined by arrows; an arrow can carry a label (a chance). */
function chain(tokens: string[], arrows: string[] = [], big = false): HTMLElement {
  const out = h("div", { class: `rt-chain ${big ? "big" : ""}` });
  tokens.forEach((t, i) => {
    if (i) out.append(h("span", { class: "rt-arrow" }, arrows[i - 1] ? h("span", { class: "rt-chance" }, arrows[i - 1]) : null, h("span", { class: "rt-tip" }, "→")));
    out.append(h("span", { class: `rt-word ${tone(t)}`, title: t }, word(t)));
  });
  return out;
}

const number = (text: string) => Number((text.match(/[\d.,]+/)?.[0] ?? "0").replace(/,/g, ""));
const text = (el: Element | undefined) => (el?.textContent ?? "").trim();
const thead = (table: Element) => [...table.querySelectorAll("thead th")].map((th) => text(th));

// --- the pictures ----------------------------------------------------------------------------------------------------

const FLOW_ICONS = ["filter", "models", "gauge", "alert"];

/** "1. **Clean**: …" → a strip of step cards, arrows between. */
function flow(list: Element): HTMLElement {
  return h("div", { class: "rt-flow" }, [...list.querySelectorAll(":scope > li")].map((li, i) => {
    const title = text(li.querySelector("strong") ?? undefined);
    const rest = li.cloneNode(true) as HTMLElement;
    rest.querySelector("strong")?.remove();
    dropLeadingColon(rest);
    const card = h("div", { class: "rt-flow-step" },
      h("div", { class: "rt-flow-head" }, h("span", { class: "rt-flow-icon" }, icon(FLOW_ICONS[i] ?? "check", 18)), h("span", { class: "rt-flow-no" }, String(i + 1))),
      h("div", { class: "rt-flow-title" }, title), h("div", { class: "rt-flow-text" }, ...content(rest)));
    card.style.setProperty("--pc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
    return card;
  }));
}

/** Stage | AUTH | OSSEC → a funnel per log. */
function stages(table: Element): HTMLElement {
  const names = thead(table).slice(1), rows = cells(table);
  return h("div", { class: "rt-stages" }, names.map((name, c) => h("div", { class: "rt-stage-col" },
    h("div", { class: "rt-stage-name" }, name),
    rows.map((row, r) => {
      const step = h("div", { class: "rt-stage" }, h("span", { class: "rt-stage-n" }, text(row[c + 1])), h("span", { class: "rt-stage-label" }, text(row[0]).toLowerCase()));
      step.style.setProperty("--w", `${100 - r * 24}%`);
      step.style.setProperty("--pc", CHAPTER_COLOURS[r % CHAPTER_COLOURS.length]);
      return step;
    }))));
}

const FIX_ICONS = ["clock", "copy", "attempt", "filter", "calendar"];

/** Problem | Fix | Found → a card per fix: the problem, what is done, and how often. */
function fixes(table: Element): HTMLElement {
  return h("div", { class: "rt-fixes" }, cells(table).map(([problem, fix, found], i) => {
    const card = h("div", { class: "rt-fix" },
      h("div", { class: "rt-fix-head" }, h("span", { class: "rt-fix-icon" }, icon(FIX_ICONS[i] ?? "check", 16)), h("span", {}, ...content(problem))),
      h("div", { class: "rt-fix-do" }, h("span", { class: "rt-fix-arrow" }, "→"), h("span", {}, ...content(fix))),
      found ? h("span", { class: "rt-found" }, text(found)) : null);
    card.style.setProperty("--pc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
    return card;
  }));
}

const DONUT = ["#33a474", "#4298b4", "#e4ae3a", "#a3a39a"];

/** Routine | Share → a donut of the shares, and a legend of sentences. */
function shares(table: Element): HTMLElement {
  const rows = cells(table), r = 52, around = 2 * Math.PI * r;
  let offset = 0;
  const rings = rows.map(([, share], i) => {
    const length = (around * number(text(share))) / 100;
    const ring = svg("circle", { cx: 75, cy: 75, r, fill: "none", stroke: DONUT[i % DONUT.length], "stroke-width": 24,
      "stroke-dasharray": `${length.toFixed(2)} ${(around - length).toFixed(2)}`, "stroke-dashoffset": (-offset).toFixed(2), transform: "rotate(-90 75 75)" });
    offset += length;
    return ring;
  });
  const top = text(rows[0]?.[1]);
  return h("div", { class: "rt-share" },
    svg("svg", { class: "rt-donut", viewBox: "0 0 150 150", width: 170, height: 170, role: "img", "aria-label": `${top} of sessions follow the commonest routine` },
      ...rings, svg("text", { x: 75, y: 76, "text-anchor": "middle", class: "rt-donut-n" }, top), svg("text", { x: 75, y: 94, "text-anchor": "middle", class: "rt-donut-l" }, "one routine")),
    h("div", { class: "rt-legend" }, rows.map(([what, share], i) => {
      const tokens = tokensOf(what);
      const row = h("div", { class: "rt-legend-row" }, h("span", { class: "rt-swatch" }), h("span", { class: "rt-legend-n" }, text(share)),
        tokens ? chain(tokens) : h("span", { class: "muted" }, text(what)));
      row.style.setProperty("--sc", DONUT[i % DONUT.length]);
      return row;
    })));
}

/** Sentence | Sessions → each sentence, with a count. */
function sentences(table: Element): HTMLElement {
  return h("div", { class: "rt-sentences" }, cells(table).map(([what, n]) => h("div", { class: "rt-sentence" },
    chain(tokensOf(what) ?? [text(what)]), h("span", { class: "rt-count" }, `× ${text(n)}`))));
}

/** Pattern | Found in → each pattern, with a bar as long as its count. */
function patterns(table: Element): HTMLElement {
  const rows = cells(table), most = Math.max(...rows.map(([, n]) => number(text(n))), 1);
  return h("div", { class: "rt-bars" }, rows.map(([what, n]) => {
    const value = number(text(n));
    return h("div", { class: "rt-bar-row" }, chain(tokensOf(what) ?? [text(what)]),
      h("div", { class: "rt-bar" }, h("span", { class: "rt-bar-fill", style: { width: `${(100 * value) / most}%` } })), h("span", { class: "rt-bar-n" }, text(n)));
  }));
}

/** A small ring for a percentage. */
function ring(percent: number, colour: string): SVGSVGElement {
  const r = 20, around = 2 * Math.PI * r, length = (around * Math.min(100, percent)) / 100;
  return svg("svg", { class: "rt-ring", viewBox: "0 0 50 50", width: 54, height: 54, "aria-hidden": "true" },
    svg("circle", { cx: 25, cy: 25, r, fill: "none", stroke: "var(--surface-2)", "stroke-width": 6 }),
    svg("circle", { cx: 25, cy: 25, r, fill: "none", stroke: colour, "stroke-width": 6, "stroke-linecap": "round",
      "stroke-dasharray": `${length.toFixed(2)} ${(around - length).toFixed(2)}`, transform: "rotate(-90 25 25)" }));
}

/** After | Comes | How often | Seen in → a card per rule. */
function rules(table: Element): HTMLElement {
  return h("div", { class: "rt-rules" }, cells(table).map(([after, comes, often, seen]) => {
    const p = number(text(often));
    return h("div", { class: "rt-rule" },
      h("div", { class: "rt-rule-ring" }, ring(p, "#33a474"), h("span", { class: "rt-rule-p" }, text(often))),
      h("div", { class: "rt-rule-body" }, chain([tokenOf(after), tokenOf(comes)]), seen ? h("div", { class: "rt-rule-seen" }, text(seen)) : null));
  }));
}

/** From | To | Chance → one path, its chances on the arrows. */
function path(table: Element): HTMLElement {
  const rows = cells(table);
  const tokens = [tokenOf(rows[0][0]), ...rows.map(([, to]) => tokenOf(to))];
  return h("div", { class: "rt-path" }, chain(tokens, rows.map(([, , chance]) => text(chance)), true));
}

/** Chance | Surprise | Example → a ruler of bits, each mark labelled with its chance; the lines in colour. */
function ruler(table: Element): HTMLElement {
  const rows = cells(table), W = 680, x0 = 30, x1 = W - 30, max = 32;
  const X = (bits: number) => x0 + ((x1 - x0) * Math.min(bits, max)) / max;
  const parts: SVGElement[] = [svg("rect", { x: x0, y: 58, width: x1 - x0, height: 8, rx: 4, fill: "url(#rt-heat)" })];
  for (let b = 0; b <= max; b += 4) parts.push(svg("text", { x: X(b), y: 84, "text-anchor": "middle", class: "rt-tick" }, `${b}`));
  parts.push(svg("text", { x: x1, y: 104, "text-anchor": "end", class: "rt-tick" }, "bits of surprise →"));
  // ordinary marks are labelled above the ruler; the two lines below it, pointing away from each other
  rows.forEach(([chance, surprise, example]) => {
    const bits = number(text(surprise)), x = X(bits), note = text(example);
    const line = /line/i.test(note), colour = /AUTH/.test(note) ? "#d0312d" : /OSSEC/.test(note) ? "#e08a1e" : "var(--text)";
    const anchor = line ? (/OSSEC/.test(note) ? "end" : "start") : x < 80 ? "start" : x > W - 80 ? "end" : "middle";
    parts.push(svg("line", { x1: x, x2: x, y1: line ? 62 : 30, y2: line ? 94 : 62, stroke: colour, "stroke-width": line ? 2.5 : 1.2 }),
      svg("circle", { cx: x, cy: 62, r: line ? 5.5 : 3.5, fill: line ? colour : "var(--surface)", stroke: colour, "stroke-width": 1.5 }),
      svg("text", { x: line ? x + (anchor === "end" ? -6 : 6) : x, y: line ? 104 : 24, "text-anchor": anchor, class: `rt-mark ${line ? "line" : ""}`, fill: colour },
        line ? `${note.replace(/'s line/i, "")}: ${text(chance)}` : text(chance)));
  });
  return h("div", { class: "rt-ruler" }, svg("svg", { viewBox: `0 0 ${W} 120`, role: "img", "aria-label": "Chances and their surprise in bits" },
    svg("defs", {}, svg("linearGradient", { id: "rt-heat", x1: 0, x2: 1, y1: 0, y2: 0 },
      svg("stop", { offset: 0, "stop-color": "#33a474" }), svg("stop", { offset: 0.35, "stop-color": "#e4ae3a" }), svg("stop", { offset: 1, "stop-color": "#d0312d" }))),
    ...parts));
}

/** Line | AUTH | OSSEC → a gauge per log: where the budget and the floor fall, the line used, and the alerts. */
function lines(table: Element): HTMLElement {
  const names = thead(table).slice(1), rows = cells(table), scale = 14;
  const find = (rx: RegExp) => rows.find(([label]) => rx.test(text(label)));
  const budget = find(/^budget/i), floor = find(/^floor/i), used = find(/^used/i), alerts = find(/^test alerts/i);
  return h("div", { class: "rt-lines" }, names.map((name, c) => {
    const at = (row: HTMLTableCellElement[] | undefined) => number(text(row?.[c + 1]));
    const mark = (row: HTMLTableCellElement[] | undefined, label: string, cls: string) => row
      ? h("span", { class: `rt-gauge-mark ${cls}`, style: { left: `${(100 * Math.min(at(row), scale)) / scale}%` } }, h("span", {}, `${label} ${text(row[c + 1])}`))
      : null;
    const usedValue = at(used), fromBudget = Math.abs(usedValue - at(budget)) < 0.05;
    return h("div", { class: "rt-line-card" },
      h("div", { class: "rt-line-head" }, h("strong", {}, name), h("span", { class: "rt-line-by" }, fromBudget ? "set by the budget" : "set by the floor")),
      h("div", { class: "rt-gauge" }, h("span", { class: "rt-gauge-fill", style: { width: `${(100 * Math.min(usedValue, scale)) / scale}%` } }),
        mark(budget, "budget", fromBudget ? "on" : ""), mark(floor, "floor", fromBudget ? "" : "on")),
      h("div", { class: "rt-line-foot" }, h("span", { class: "rt-big" }, text(alerts?.[c + 1])), h("span", { class: "muted" }, "test alerts, at"),
        h("strong", {}, text(used?.[c + 1]))));
  }));
}

/** When | Server | What happened → incident cards. */
function incidents(table: Element): HTMLElement {
  return h("div", { class: "rt-incidents" }, cells(table).map(([when, server, what]) => {
    const m = /^(\d+)\s+(\w+),?\s*(.*)$/.exec(text(when));
    return h("div", { class: "rt-incident" },
      h("div", { class: "rt-date" }, h("span", { class: "rt-day" }, m?.[1] ?? ""), h("span", { class: "rt-month" }, m?.[2] ?? text(when))),
      h("div", {}, h("div", { class: "rt-incident-head" }, h("span", { class: "rt-server" }, text(server)), h("span", { class: "muted" }, icon("clock", 13), m?.[3] ?? "")),
        h("div", { class: "rt-incident-what" }, ...content(what))));
  }));
}

const KINDS: [RegExp, string][] = [[/worth/i, "#d0312d"], [/new habit/i, "#e08a1e"], [/maintenance/i, "#4298b4"], [/without/i, "#88619a"],
  [/two connections/i, "#3f9c8f"], [/busy/i, "#9a9a90"], [/other/i, "#c9c9c0"]];

/** Kind | Alerts | What it is → a stacked bar of the kinds, and a card per kind. */
function kinds(table: Element): HTMLElement {
  const rows = cells(table), total = rows.reduce((sum, [, n]) => sum + number(text(n)), 0) || 1;
  const colour = (kind: string) => KINDS.find(([rx]) => rx.test(kind))?.[1] ?? "#9a9a90";
  return h("div", { class: "rt-kinds" },
    h("div", { class: "rt-stack", role: "img", "aria-label": rows.map(([k, n]) => `${text(k)} ${text(n)}`).join(", ") },
      rows.map(([kind, n]) => h("span", { class: "rt-stack-part", title: `${text(kind)}: ${text(n)}`,
        style: { width: `${(100 * number(text(n))) / total}%`, background: colour(text(kind)) } }, number(text(n)) / total > 0.07 ? text(n) : ""))),
    h("div", { class: "rt-kind-grid" }, rows.map(([kind, n, what]) => {
      const card = h("div", { class: "rt-kind" }, h("div", { class: "rt-kind-head" }, h("span", { class: "rt-kind-n" }, text(n)), h("strong", {}, text(kind))),
        text(what) ? h("div", { class: "rt-kind-what" }, ...content(what)) : null);
      card.style.setProperty("--kc", colour(text(kind)));
      return card;
    })));
}

/** Also flagged by | Alerts → bars against the first row, the total. */
function overlap(table: Element): HTMLElement {
  const [first, ...rows] = cells(table), total = number(text(first?.[1])) || 1;
  return h("div", { class: "rt-bars overlap" }, h("div", { class: "rt-total" }, h("span", { class: "rt-big" }, text(first?.[1])), h("span", { class: "muted" }, text(first?.[0]).toLowerCase())),
    rows.map(([who, n]) => {
      const value = number(text(n)), only = /only/i.test(text(who));
      return h("div", { class: `rt-bar-row ${only ? "only" : ""}` }, h("span", { class: "rt-bar-who" }, text(who)),
        h("div", { class: "rt-bar" }, h("span", { class: "rt-bar-fill", style: { width: `${(100 * value) / total}%` } })), h("span", { class: "rt-bar-n" }, text(n)));
    }));
}

/** Finding | Share → big figures. */
function findings(table: Element): HTMLElement {
  return h("div", { class: "rt-findings" }, cells(table).map(([what, share]) => {
    const p = number(text(share));
    return h("div", { class: "rt-finding" }, h("span", { class: "rt-big" }, text(share)),
      h("div", { class: "rt-bar thin" }, h("span", { class: "rt-bar-fill", style: { width: `${p}%` } })), h("div", { class: "rt-finding-what" }, ...content(what)));
  }));
}

const NOTE_ICONS: [RegExp, string][] = [[/weighted|counted/i, "copy"], [/closed/i, "check"], [/common/i, "gauge"], [/server/i, "individual"],
  [/labels/i, "review"], [/memory/i, "history"], [/event types/i, "filter"], [/busy/i, "attempt"], [/phase 2/i, "session"]];

/** A list of **Term**: text items → cards. */
function notes(list: Element, colour: string): HTMLElement {
  const grid = h("div", { class: "dc-grid" }, [...list.querySelectorAll(":scope > li")].map((li) => {
    const term = text(li.querySelector("strong") ?? undefined);
    return h("div", { class: "dc-card" }, h("span", { class: "dc-icon" }, icon(NOTE_ICONS.find(([rx]) => rx.test(term))?.[1] ?? "check", 15)), h("div", {}, ...content(li)));
  }));
  grid.style.setProperty("--dc", colour);
  return grid;
}

// --- the guide --------------------------------------------------------------------------------------------------------

/** Redraw the guide's tables and lists as pictures, and give each chapter its title card. */
export function routinesGuide(page: HTMLElement): void {
  const title = page.querySelector("h1");
  const intro = [...(function* () { for (let el = title?.nextElementSibling; el && el.tagName !== "H2"; el = el.nextElementSibling) yield el; })()];
  const steps = intro.find((el) => el.tagName === "OL");
  if (steps) steps.replaceWith(flow(steps));
  page.querySelectorAll("p").forEach((p) => {
    const tokens = tokensOf(p);
    if (tokens && tokens.length > 1) p.replaceWith(chain(tokens, [], true));
  });
  chapters(page);
  const nav = page.querySelector(".ch-nav"), strip = page.querySelector(".rt-flow");
  if (nav && strip) strip.after(nav);                                               // the chapters after the four steps
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const name = heading.firstChild?.textContent ?? "";
    const colour = CHAPTER_COLOURS[i % CHAPTER_COLOURS.length];
    let count = "";
    for (const el of sectionOf(heading)) {
      if (el.tagName === "TABLE") {
        const first = (thead(el)[0] ?? "").toLowerCase(), n = cells(el).length;
        const swap = (to: HTMLElement, label = "") => { el.replaceWith(to); if (label && !count) count = label; };
        if (first === "stage") swap(stages(el), "from events to sentences");
        else if (first === "problem") swap(fixes(el), `${n} fixes`);
        else if (first === "routine") swap(shares(el), "98% in three sentences");
        else if (first === "sentence") swap(sentences(el));
        else if (first === "pattern") swap(patterns(el), "an example");
        else if (first === "after") swap(rules(el), `${n} rules`);
        else if (first === "from") swap(path(el), "the commonest path");
        else if (first === "chance") swap(ruler(el), "from a coin toss to never seen");
        else if (first === "line") swap(lines(el), "budget or floor, whichever is higher");
        else if (first === "when") swap(incidents(el), "19 + 608 alerts");
        else if (first === "kind") swap(kinds(el));
        else if (first === "also flagged by") swap(overlap(el));
        else if (first === "finding") swap(findings(el), `${n} findings`);
      } else if (el.tagName === "OL") {
        el.replaceWith(stepTiles(el));
        count ||= `${el.querySelectorAll(":scope > li").length} steps`;
      } else if (el.tagName === "UL") {
        const items = el.querySelectorAll(":scope > li").length;
        if (/words/i.test(name)) { el.replaceWith(glossary(el)); count = `${items} words`; }
        else { el.replaceWith(notes(el, colour)); count ||= `${items} limits`; }
      } else if (el.tagName === "H3") {
        el.classList.add("rt-sub");
      }
    }
    titleCard(heading, count, SECTION_ICONS.find(([rx]) => rx.test(name))?.[1] ?? "docs", colour, i + 1, true);
  });
}
