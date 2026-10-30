// Visuals for the documents, drawn from the Markdown after it is rendered, so the files stay the one
// source: what the doc says, the picture shows.
// - Personas (01 Product requirements §3): the table becomes persona cards with illustrated avatars,
//   in the spirit of 16personalities.com's type cards: a flat, faceted figure on its own colour, a
//   name, a short code and a tagline; picking a card shows who they are and what they need.
// - Epics (§6): an epic board, each epic a coloured tile with its stories (priority, status, and
//   the faces of the personas they serve), read as the book's contents; each epic in the text is
//   then a book page, and each story on it gets those faces too.
// - Goals (§2) and Scope (§4): a title card opens each section; goals become numbered cards, the
//   built pages tiles with their sidebar icons, the planned and out-of-scope items cards.
// - Purpose (§1): a title card, the funnel from millions of log lines to a person's decision (its
//   figures read from the paragraph), and what the console lets a person do, as page tiles.
// - Chapters: at the top, a numbered link to every section; each section heading links back.

import { clear, h, svg } from "./dom";
import { icon } from "./icons";
import { routinesGuide } from "./doc-routines";
import { VERDICTS } from "./verdicts";

type Key = "ops" | "sec" | "ml" | "adm" | "rev";
interface Look { name: string; code: string; colour: string; skin: string; skinLight: string; top: string; topShade: string; legs: string; legsShade: string; hair: string }

const LOOKS: Record<Key, Look> = {
  ops: { name: "Operations engineer", code: "OPS", colour: "#4298b4", skin: "#c98f62", skinLight: "#dba57a", top: "#2f4b63", topShade: "#263d51", legs: "#33404c", legsShade: "#2a353f", hair: "#1e1a17" },
  sec: { name: "Security analyst", code: "SEC", colour: "#88619a", skin: "#e9bf9b", skinLight: "#f5d2b3", top: "#4b3a63", topShade: "#3d2f52", legs: "#2f3a52", legsShade: "#273044", hair: "#3a2418" },
  ml: { name: "Pipeline owner", code: "ML", colour: "#33a474", skin: "#b9805a", skinLight: "#cc966e", top: "#2f7d5a", topShade: "#27684b", legs: "#3b3f46", legsShade: "#31353b", hair: "#15110f" },
  adm: { name: "Administrator", code: "ADM", colour: "#e4ae3a", skin: "#8a5a3c", skinLight: "#9f6b4a", top: "#3d4148", topShade: "#32363c", legs: "#2c2f35", legsShade: "#24272c", hair: "#121010" },
  rev: { name: "Reviewer", code: "REV", colour: "#d9705a", skin: "#e6b592", skinLight: "#f2c8a8", top: "#24365e", topShade: "#1d2c4d", legs: "#2e3442", legsShade: "#262b37", hair: "#b9b6b1" },
};
const ORDER: Key[] = ["ops", "sec", "ml", "adm", "rev"];

const poly = (points: number[][], fill: string, extra: Record<string, unknown> = {}) =>
  svg("polygon", { points: points.map(([x, y]) => `${x},${y}`).join(" "), fill, ...extra });
const circ = (cx: number, cy: number, r: number, fill: string, extra: Record<string, unknown> = {}) => svg("circle", { cx, cy, r, fill, ...extra });
const box = (x: number, y: number, w: number, hgt: number, fill: string, extra: Record<string, unknown> = {}) =>
  svg("rect", { x, y, width: w, height: hgt, fill, ...extra });
const path = (d: string, fill: string, extra: Record<string, unknown> = {}) => svg("path", { d, fill, ...extra });

/** A standing figure, faceted like a low-poly illustration: each part a base colour and a shaded facet. */
function figure(key: Key): SVGElement[] {
  const L = LOOKS[key];
  const out: SVGElement[] = [svg("ellipse", { cx: 80, cy: 193, rx: 44, ry: 5, fill: "#000", opacity: 0.12 })];
  // legs and shoes
  out.push(poly([[56, 132], [79, 132], [77, 184], [60, 184]], L.legs), poly([[81, 132], [104, 132], [100, 184], [83, 184]], L.legsShade),
    poly([[59, 183], [78, 183], [78, 192], [52, 192]], "#1d1f22"), poly([[82, 183], [101, 183], [107, 192], [82, 192]], "#2a2c30"));
  // torso, with its shaded facet, and the neck
  out.push(poly([[74, 64], [86, 64], [86, 78], [74, 78]], L.skin),
    poly([[50, 76], [110, 76], [114, 134], [46, 134]], L.top), poly([[50, 76], [80, 76], [80, 134], [46, 134]], L.topShade));
  // the arm on the left of the picture hangs down, unless both hands hold something (EXTRAS draws both arms then)
  if (!BOTH_HANDS.has(key)) out.push(poly([[50, 78], [41, 82], [35, 124], [45, 126], [50, 96]], L.topShade), circ(40, 128, 6, L.skin));
  // head: two facets, ears, eyes, brows, a small smile
  out.push(poly([[59, 44], [55, 50], [60, 54]], L.skin), poly([[101, 44], [105, 50], [100, 54]], L.skinLight),
    poly([[66, 26], [80, 24], [80, 70], [63, 61], [59, 43]], L.skin), poly([[80, 24], [94, 26], [101, 43], [97, 61], [80, 70]], L.skinLight),
    svg("ellipse", { cx: 72.5, cy: 47, rx: 2.3, ry: 2.9, fill: "#1b1716" }), svg("ellipse", { cx: 87.5, cy: 47, rx: 2.3, ry: 2.9, fill: "#1b1716" }),
    box(69, 40.5, 7, 1.6, L.hair === "#b9b6b1" ? "#8f8b85" : L.hair, { rx: 0.8 }), box(84, 40.5, 7, 1.6, L.hair === "#b9b6b1" ? "#8f8b85" : L.hair, { rx: 0.8 }),
    path("M 75 58 Q 80 61.5 85 58", "none", { stroke: "#7a3f2f", "stroke-width": 1.6, "stroke-linecap": "round" }));
  out.push(...EXTRAS[key](L));
  return out;
}

// Personas holding their thing in both hands: their EXTRAS draw both arms.
const BOTH_HANDS = new Set<Key>(["ml"]);

// What makes each persona theirs: hair, clothes and the thing they hold.
const EXTRAS: Record<Key, (L: Look) => SVGElement[]> = {
  // hard hat and hi-vis vest over a work shirt, a tablet in hand
  ops: (L) => [
    poly([[50, 78], [72, 78], [78, 134], [47, 134]], "#f28c28"), poly([[88, 78], [110, 78], [113, 134], [82, 134]], "#f6a14a"),
    box(47, 106, 31, 4, "#e9eef2"), box(82, 106, 31, 4, "#f4f7f9"), box(47, 120, 31, 4, "#e9eef2"), box(82, 120, 31, 4, "#f4f7f9"),
    poly([[61, 46], [64, 52], [61, 56]], L.hair), poly([[99, 46], [96, 52], [99, 56]], L.hair),
    path("M 58 38 Q 80 4 102 38 Z", "#f6f6f2"), path("M 80 13 Q 96 17 102 38 L 80 38 Z", "#e4e4de"), box(54, 35, 52, 5, "#dcdcd5", { rx: 2.5 }), box(78, 12, 4, 26, "#d2d2ca"),
    poly([[110, 78], [119, 84], [114, 110], [98, 113], [101, 101]], L.topShade),
    svg("g", { transform: "rotate(-8 99 113)" }, box(84, 94, 28, 36, "#1f2328", { rx: 3 }), box(87, 98, 22, 26, "#4298b4", { rx: 1.5 }),
      box(90, 102, 14, 2, "#d9f1fa"), box(90, 107, 10, 2, "#d9f1fa"), box(90, 112, 16, 2, "#d9f1fa"), box(90, 117, 8, 2, "#d9f1fa")),
    circ(100, 116, 6, L.skin)],
  // bob of hair, glasses, a hood behind the neck, a shield badge, a raised magnifying glass
  sec: (L) => [
    path("M 57 46 Q 55 18 80 17 Q 105 18 103 46 L 105 66 L 97 62 L 97 34 Q 80 26 63 34 L 63 62 L 55 66 Z", L.hair),
    path("M 58 72 Q 80 88 102 72 L 106 82 Q 80 96 54 82 Z", L.topShade),
    box(67, 42.5, 12, 9, "none", { stroke: "#1b1716", "stroke-width": 1.6, rx: 2 }), box(81, 42.5, 12, 9, "none", { stroke: "#1b1716", "stroke-width": 1.6, rx: 2 }),
    box(79, 46, 2, 1.4, "#1b1716"),
    poly([[60, 92], [70, 92], [70, 100], [65, 105], [60, 100]], "#e4ae3a"), poly([[65, 92], [70, 92], [70, 100], [65, 105]], "#c99528"),
    poly([[110, 78], [121, 72], [129, 48], [121, 45], [114, 66]], L.topShade), circ(126, 43, 6, L.skin),
    svg("line", { x1: 126, y1: 40, x2: 129, y2: 33, stroke: "#6b4f3a", "stroke-width": 4, "stroke-linecap": "round" }),
    circ(134, 23, 11, "#cfeaff", { opacity: 0.55 }), circ(134, 23, 11, "none", { stroke: "#2b2f35", "stroke-width": 3.2 }),
    path("M 127 19 A 8 8 0 0 1 132 14", "none", { stroke: "#fff", "stroke-width": 1.6, "stroke-linecap": "round" })],
  // curly hair, headphones round the neck, an open laptop with a chart
  ml: (L) => [
    ...[[64, 30, 8], [72, 22, 8], [82, 19, 9], [92, 23, 8], [98, 31, 7], [60, 39, 6], [101, 40, 6]].map(([x, y, r]) => circ(x, y, r, L.hair)),
    path("M 63 72 Q 80 88 97 72", "none", { stroke: "#1d1f22", "stroke-width": 4 }), circ(62, 73, 5.5, "#2b2e33"), circ(98, 73, 5.5, "#2b2e33"),
    poly([[110, 78], [118, 86], [112, 110], [104, 112], [104, 98]], L.topShade), poly([[50, 78], [42, 86], [48, 110], [56, 112], [56, 98]], L.topShade),
    poly([[61, 80], [101, 80], [104, 110], [58, 110]], "#2a2f36"), poly([[64, 84], [98, 84], [100, 106], [62, 106]], "#16323f"),
    box(68, 96, 5, 8, "#33a474"), box(76, 91, 5, 13, "#e4ae3a"), box(84, 94, 5, 10, "#88619a"), box(92, 88, 5, 16, "#4298b4"),
    poly([[56, 110], [106, 110], [112, 118], [50, 118]], "#bfc5cc"), poly([[81, 110], [106, 110], [112, 118], [81, 118]], "#d3d8dd"),
    circ(54, 116, 6, L.skin), circ(108, 116, 6, L.skin)],
  // short hair, a blazer over a white shirt, a lanyard badge, a key
  adm: (L) => [
    poly([[60, 41], [63, 25], [80, 19], [97, 25], [100, 41], [94, 31], [66, 31]], L.hair),
    poly([[72, 76], [88, 76], [84, 112], [76, 112]], "#f2f2ee"), poly([[72, 76], [80, 76], [76, 112], [66, 86]], "#e6e6e0"),
    svg("polyline", { points: "73,77 78,100 82,100 87,77", fill: "none", stroke: "#e4ae3a", "stroke-width": 2 }),
    box(74, 99, 12, 16, "#ffffff", { rx: 1.5 }), box(76, 101, 8, 6, "#9aa5ae"), box(76, 109, 8, 1.4, "#c9cdd2"), box(76, 112, 6, 1.4, "#c9cdd2"),
    poly([[110, 78], [119, 82], [125, 120], [115, 123], [110, 96]], L.topShade), circ(120, 126, 6, L.skin),
    circ(128, 134, 6, "none", { stroke: "#e4ae3a", "stroke-width": 3 }), box(127, 139, 3, 18, "#e4ae3a"), box(130, 150, 5, 2.6, "#e4ae3a"), box(130, 145, 4, 2.6, "#e4ae3a")],
  // grey hair in a bun, a blazer with a coral scarf, a clipboard with ticks
  rev: (L) => [
    circ(80, 14, 8, L.hair), path("M 58 44 Q 57 21 80 20 Q 103 21 102 44 L 98 34 Q 80 28 62 34 Z", L.hair),
    poly([[70, 76], [90, 76], [86, 92], [74, 92]], "#d9705a"), poly([[80, 76], [90, 76], [86, 92], [80, 92]], "#c45f4a"),
    poly([[110, 78], [118, 84], [112, 108], [100, 112], [102, 98]], L.topShade),
    svg("g", { transform: "rotate(6 101 110)" }, box(86, 90, 30, 40, "#a8794d", { rx: 3 }), box(89, 95, 24, 32, "#fdfbf6"), box(96, 87, 10, 6, "#6f7378", { rx: 1.5 }),
      ...[100, 108, 116].flatMap((y) => [path(`M 92 ${y} l 2.5 2.5 l 4.5 -5`, "none", { stroke: "#33a474", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round" }),
        box(101, y - 1, 9, 1.6, "#b7bcc1")])),
    circ(101, 114, 6, L.skin)],
};

function avatar(key: Key, cls = "pv-avatar"): SVGElement {
  return svg("svg", { class: cls, viewBox: "0 0 160 200", "aria-hidden": "true" }, figure(key));
}
/** The persona's face in a coloured disc, for story rows and story headings. */
function face(key: Key): HTMLElement {
  return h("span", { class: "pv-face", style: { background: LOOKS[key].colour }, title: LOOKS[key].name },
    svg("svg", { viewBox: "50 6 60 60", "aria-hidden": "true" }, figure(key)));
}
function keysIn(text: string): Key[] {
  if (/everyone/i.test(text)) return [...ORDER];
  return ORDER.filter((k) => text.toLowerCase().includes(LOOKS[k].name.toLowerCase()));
}

// --- personas -------------------------------------------------------------------------------------------

function personas(page: HTMLElement): void {
  const heading = [...page.querySelectorAll("h2")].find((el) => /^3\.\s*Users/.test(el.textContent ?? ""));
  let table = heading?.nextElementSibling;
  while (table && table.tagName !== "TABLE" && table.tagName !== "H2") table = table.nextElementSibling;
  if (!table || table.tagName !== "TABLE") return;
  const rows = [...table.querySelectorAll("tbody tr")].map((tr) => {
    const cells = [...tr.querySelectorAll("td")];
    const key = keysIn(cells[0]?.textContent ?? "")[0];
    return key ? { key, who: cells[1], needs: cells[2] } : null;
  }).filter((r): r is { key: Key; who: HTMLTableCellElement; needs: HTMLTableCellElement } => r !== null);
  if (!rows.length) return;
  const detail = h("div", { class: "pv-detail" });
  const cards = h("div", { class: "pv-grid", role: "tablist" });
  const pick = (i: number) => {
    const r = rows[i], L = LOOKS[r.key];
    cards.querySelectorAll(".pv-card").forEach((c, j) => { c.classList.toggle("on", i === j); c.setAttribute("aria-selected", String(i === j)); });
    clear(detail, h("div", { class: "pv-detail-head", style: { "--pc": L.colour } as any },
      avatar(r.key, "pv-avatar small"),
      h("div", {}, h("div", { class: "pv-name" }, L.name), h("span", { class: "pv-code" }, L.code))),
      h("div", { class: "pv-detail-body" },
        h("div", {}, h("h4", {}, "Who"), h("p", {}, ...[...r.who.childNodes].map((n) => n.cloneNode(true)))),
        h("div", {}, h("h4", {}, "What they need"), h("p", {}, ...[...r.needs.childNodes].map((n) => n.cloneNode(true))))));
    detail.style.setProperty("--pc", L.colour);
  };
  rows.forEach((r, i) => {
    const L = LOOKS[r.key];
    const whoText = (r.who.textContent ?? "").trim();
    const most = /most users/i.test(whoText);
    const tagline = whoText.replace(/^(most users|some users)\.\s*/i, "").split(/(?<=\.)\s/)[0].replace(/[:;].*$/, "").replace(/\.$/, "");
    const card = h("button", { class: "pv-card", role: "tab", style: { "--pc": L.colour } as any, onclick: () => pick(i) },
      h("div", { class: "pv-stage" }, avatar(r.key)),
      h("div", { class: "pv-name" }, L.name),
      h("div", { class: "pv-tags" }, h("span", { class: "pv-code" }, L.code), most ? h("span", { class: "pv-most" }, "Most users") : null),
      h("div", { class: "pv-tagline" }, tagline));
    // custom properties set through style objects need setProperty
    card.style.setProperty("--pc", L.colour);
    cards.append(card);
  });
  table.replaceWith(h("div", { class: "pv" }, cards, detail));
  pick(0);
}

// --- epics -------------------------------------------------------------------------------------------------

const EPIC_COLOURS = ["#4298b4", "#33a474", "#88619a", "#e4ae3a", "#d9705a", "#5b72c4", "#3f9c8f", "#b5568a"];
const PRIORITY: Record<string, [string, string]> = { M: ["Must", "#d0312d"], S: ["Should", "#e0a020"], C: ["Could", "#7a9a3a"], W: ["Won't", "#8a8f94"] };

interface Story { id: string; title: string; priority: string; actors: Key[]; status: "built" | "partly" | "planned"; anchor: HTMLElement }

function epics(page: HTMLElement): void {
  const heading = [...page.querySelectorAll("h2")].find((el) => /^6\.\s*User stories/.test(el.textContent ?? ""));
  if (!heading) return;
  const groups: { letter: string; title: string; stories: Story[]; anchor: HTMLElement }[] = [];
  let first: Element | null = null;
  for (let el = heading.nextElementSibling; el && el.tagName !== "H2"; el = el.nextElementSibling) {
    if (el.tagName === "H3") {
      const m = /Epic\s+(\w+)\s*·\s*(.+)/.exec(el.textContent ?? "");
      if (m) { groups.push({ letter: m[1], title: m[2].trim(), stories: [], anchor: el as HTMLElement }); first ??= el; }
      continue;
    }
    const strong = el.tagName === "P" ? el.querySelector("strong") : null;
    const m = strong ? /^(US-\d+)\s*·\s*(.+)$/.exec(strong.textContent ?? "") : null;
    if (!m || !groups.length) continue;
    const rest = el.textContent ?? "";
    const priority = /\((M|S|C|W)\)/.exec(rest)?.[1] ?? "";
    const actors = keysIn(el.querySelector("em")?.textContent ?? rest);
    const list = el.nextElementSibling?.tagName === "UL" ? el.nextElementSibling.textContent ?? "" : "";
    if (el.nextElementSibling?.tagName === "UL") el.nextElementSibling.replaceWith(criteria(el.nextElementSibling as HTMLUListElement));
    const status = /Status:\s*Partly/i.test(list) ? "partly" : /Status:\s*Planned/i.test(list) ? "planned" : "built";
    groups.at(-1)!.stories.push({ id: m[1], title: m[2].trim(), priority, actors, status, anchor: el as HTMLElement });
    if (actors.length) el.append(h("span", { class: "pv-faces inline" }, actors.map(face)));      // faces beside each story
  }
  if (!groups.length || !first) return;
  const board = h("div", { class: "ep-grid" }, groups.map((g, gi) => {
    const colour = EPIC_COLOURS[gi % EPIC_COLOURS.length];
    const card = h("div", { class: "ep-card" },
      h("button", { class: "ep-head", onclick: () => g.anchor.scrollIntoView({ block: "start", behavior: "smooth" }) },
        h("span", { class: "ep-letter" }, g.letter), h("span", { class: "ep-title" }, g.title), h("span", { class: "ep-count" }, String(g.stories.length))),
      h("ul", { class: "ep-stories" }, g.stories.map((s) => h("li", {},
        h("button", { class: "ep-story", onclick: () => s.anchor.scrollIntoView({ block: "start", behavior: "smooth" }) },
          s.priority ? h("span", { class: "ep-pri", style: { background: PRIORITY[s.priority]?.[1] ?? "#888" }, title: PRIORITY[s.priority]?.[0] ?? "" }, s.priority) : null,
          h("span", { class: "ep-id" }, s.id), h("span", { class: "ep-name" }, s.title),
          h("span", { class: `ep-status ${s.status}`, title: s.status === "built" ? "Built" : s.status === "partly" ? "Partly built" : "Planned" }),
          h("span", { class: "pv-faces" }, s.actors.map(face)))))));
    card.style.setProperty("--ec", colour);
    return card;
  }));
  const legend = h("div", { class: "ep-legend" },
    ...Object.entries(PRIORITY).slice(0, 3).map(([k, [label, c]]) => h("span", {}, h("span", { class: "ep-pri", style: { background: c } }, k), label)),
    h("span", {}, h("span", { class: "ep-status built" }), "Built"), h("span", {}, h("span", { class: "ep-status partly" }), "Partly"));
  first.parentElement!.insertBefore(h("div", { class: "ep" }, legend, board), first);
  // each epic in the text becomes a page of a book: its heading as the chapter, its stories as the page
  groups.forEach((g, gi) => {
    const parts: Element[] = [g.anchor];
    for (let el = g.anchor.nextElementSibling; el && !["H2", "H3"].includes(el.tagName); el = el.nextElementSibling) parts.push(el);
    const ids = g.stories.map((st) => st.id);
    const chapter = h("div", { class: "bk-chapter" }, h("span", { class: "bk-initial" }, g.letter),
      h("div", {}, h("div", { class: "bk-kicker" }, `Epic ${g.letter}`), h("div", { class: "bk-title" }, g.title)));
    const page = h("section", { class: `bk-page ${gi % 2 ? "verso" : "recto"}` }, h("span", { class: "bk-ribbon", "aria-hidden": "true" }), chapter);
    page.style.setProperty("--ec", EPIC_COLOURS[gi % EPIC_COLOURS.length]);
    g.anchor.before(page);
    g.anchor.classList.add("bk-anchor");                                  // kept for links and the contents, drawn by the chapter
    page.append(...parts, h("footer", { class: "bk-foot" }, h("span", {}, ids.length ? `${ids[0]}${ids.length > 1 ? ` – ${ids.at(-1)}` : ""}` : ""),
      h("span", { class: "bk-folio" }, String(gi + 1))));
  });
}

// --- acceptance criteria: "When …, then …" as rows, the situation on the left and the result on the right ---

/** The contents of `root` between two character offsets of its text, formatting kept. */
export function slice(root: HTMLElement, from: number, to: number): DocumentFragment {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const range = document.createRange();
  let seen = 0, started = false;
  for (let node = walker.nextNode() as Text | null; node; node = walker.nextNode() as Text | null) {
    const len = node.data.length;
    if (!started && from <= seen + len) { range.setStart(node, from - seen); started = true; }
    if (started && to <= seen + len) { range.setEnd(node, to - seen); return range.cloneContents(); }
    seen += len;
  }
  if (started) range.setEndAfter(root.lastChild!);
  return started ? range.cloneContents() : document.createDocumentFragment();
}

/** Given / when / and as small keywords inside a situation. */
function keywords(fragment: DocumentFragment): DocumentFragment {
  const walker = document.createTreeWalker(fragment, NodeFilter.SHOW_TEXT);
  const texts: Text[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) texts.push(n as Text);
  for (const text of texts) {
    const parts = text.data.split(/\b(Given|given|when|When)\b/);
    if (parts.length === 1) continue;
    text.replaceWith(...parts.map((part, i) => (i % 2 ? h("span", { class: "ac-kw" }, part.toLowerCase()) : document.createTextNode(part))));
  }
  return fragment;
}

function criteria(list: HTMLUListElement): HTMLElement {
  const rows = [...list.querySelectorAll(":scope > li")].map((li) => {
    const item = li as HTMLElement, text = item.textContent ?? "";
    const then = /,\s*then\s+/i.exec(text);
    const condition = /^\s*(given|when)\b/i.test(text);
    if (condition && then) {                                                  // When …, then …
      const lead = /^\s*when\s+/i.exec(text)?.[0].length ?? 0;            // the column says "When"
      return h("div", { class: "ac-row" },
        h("div", { class: "ac-if" }, keywords(slice(item, lead, then.index))), h("span", { class: "ac-arrow", "aria-hidden": "true" }, "→"),
        h("div", { class: "ac-then" }, slice(item, then.index + then[0].length, text.length)));
    }
    const alone = /^\s*then\s+/i.exec(text);
    if (alone) {                                                              // Then … (still under the row above)
      return h("div", { class: "ac-row cont" }, h("div", { class: "ac-if" }), h("span", { class: "ac-arrow", "aria-hidden": "true" }, "→"),
        h("div", { class: "ac-then" }, slice(item, alone[0].length, text.length)));
    }
    const status = /^\s*status:\s*/i.exec(text);
    return h("div", { class: `ac-row full ${status ? "status" : ""}` },
      status ? h("span", { class: "ac-status" }, "Status") : null, h("div", { class: "ac-note" }, slice(item, status ? status[0].length : 0, text.length)));
  });
  return h("div", { class: "ac" }, h("div", { class: "ac-row head", "aria-hidden": "true" }, h("div", {}, "When"), h("span", {}), h("div", {}, "Then")), rows);
}

// --- title cards: Goals (§2) and Scope (§4) -----------------------------------------------------------------

/** The section's heading inside a title card: a large numeral, the title, and a count. */
export function titleCard(heading: HTMLElement, count: string, glyph: string, colour: string, number?: number, small = false): void {
  const own = heading.firstChild?.nodeType === Node.TEXT_NODE ? heading.firstChild as Text : null;   // its text, not the ↑ link
  const m = /^(\d+)\.\s*(.+)$/.exec((own?.data ?? heading.textContent ?? "").trim());
  const card = h("div", { class: `tc-card ${small ? "small" : ""}` },
    h("span", { class: "tc-num" }, m?.[1] ?? (number ? String(number) : "")),
    h("div", { class: "tc-text" }, h("div", { class: "tc-count" }, count)),
    h("span", { class: "tc-glyph", "aria-hidden": "true" }, icon(glyph, 64)));
  card.style.setProperty("--tc", colour);
  heading.before(card);
  card.querySelector(".tc-text")!.prepend(heading);                     // the h2 keeps its id, so links still land here
  if (m && own) own.data = m[2];
}

const GOAL_ICONS: [RegExp, string][] = [[/machine-learning/i, "models"], [/reviewable/i, "review"], [/new logs/i, "analyze"],
  [/evidence/i, "docs"], [/on site/i, "datasets"], [/accident/i, "lock"], [/who did what/i, "dashboard"]];
const GOAL_COLOURS = ["#4298b4", "#33a474", "#88619a", "#e4ae3a", "#d9705a", "#5b72c4", "#3f9c8f"];

function goals(page: HTMLElement): void {
  const heading = [...page.querySelectorAll("h2")].find((el) => /^2\.\s*Goals/.test(el.textContent ?? ""));
  const table = heading?.nextElementSibling;
  if (!heading || table?.tagName !== "TABLE") return;
  const rows = [...table.querySelectorAll("tbody tr")].map((tr) => [...tr.querySelectorAll("td")]);
  const grid = h("div", { class: "gl-grid" }, rows.map(([goal, measure], i) => {
    const glyph = GOAL_ICONS.find(([rx]) => rx.test(goal.textContent ?? ""))?.[1] ?? "check";
    const card = h("div", { class: "gl-card" },
      h("div", { class: "gl-top" }, h("span", { class: "gl-icon" }, icon(glyph, 20)), h("span", { class: "gl-no" }, String(i + 1).padStart(2, "0"))),
      h("div", { class: "gl-goal" }, ...[...goal.childNodes].map((n) => n.cloneNode(true))),
      h("div", { class: "gl-measure" }, ...[...measure.childNodes].map((n) => n.cloneNode(true))));
    card.style.setProperty("--gc", GOAL_COLOURS[i % GOAL_COLOURS.length]);
    return card;
  }));
  table.replaceWith(grid);
  titleCard(heading as HTMLElement, `${rows.length} goals`, "target", "#4298b4");
}

const PAGE_ICONS: Record<string, string> = { Dashboard: "dashboard", Analyze: "analyze", Models: "models", Data: "data", Review: "review",
  Datasets: "datasets", Documentation: "docs", Settings: "settings", "Check logs": "upload", "Check logs (Simple)": "upload", "Simple mode": "upload",
  Patterns: "patterns", Sigma: "sigma", Reports: "reports" };

function scope(page: HTMLElement): void {
  const heading = [...page.querySelectorAll("h2")].find((el) => /^4\.\s*Scope/.test(el.textContent ?? ""));
  if (!heading) return;
  let built = 0, planned = 0, out = 0;
  for (let el = heading.nextElementSibling; el && el.tagName !== "H2"; el = el.nextElementSibling) {
    if (el.tagName !== "H3") continue;
    const kind = /built/i.test(el.textContent ?? "") ? "built" : /planned/i.test(el.textContent ?? "") ? "planned" : "out";
    el.classList.add("sc-head", kind);
    const next = el.nextElementSibling;
    if (kind === "built" && next?.tagName === "TABLE") {
      const rows = [...next.querySelectorAll("tbody tr")].map((tr) => [...tr.querySelectorAll("td")]);
      built = rows.length;
      next.replaceWith(h("div", { class: "sc-pages" }, rows.map(([name, what]) => h("div", { class: "sc-page" },
        h("div", { class: "sc-page-head" }, h("span", { class: "sc-page-icon" }, icon(PAGE_ICONS[(name.textContent ?? "").trim()] ?? "docs", 18)),
          h("strong", {}, (name.textContent ?? "").trim())),
        h("div", { class: "sc-page-what" }, ...[...what.childNodes].map((n) => n.cloneNode(true)))))));
    } else if (next?.tagName === "UL") {
      const items = [...next.querySelectorAll(":scope > li")];
      if (kind === "planned") planned = items.length; else out = items.length;
      next.replaceWith(h("div", { class: `sc-items ${kind}` }, items.map((li) => h("div", { class: `sc-item ${kind}` },
        h("span", { class: "sc-item-icon" }, icon(kind === "planned" ? "clock" : "close", 16)),
        h("div", {}, ...[...li.childNodes].map((n) => n.cloneNode(true)))))));
    }
  }
  titleCard(heading as HTMLElement, `${built} pages built · ${planned} planned · ${out} not in scope`, "map", "#33a474");
}

// --- chapters: a numbered link to every section, at the top -------------------------------------------------

export const CHAPTER_COLOURS = ["#4298b4", "#33a474", "#88619a", "#e4ae3a", "#d9705a", "#5b72c4", "#3f9c8f", "#b5568a"];

export function chapters(page: HTMLElement): void {
  const headings = [...page.querySelectorAll<HTMLElement>("h2")];
  if (headings.length < 3) return;
  const nav = h("nav", { class: "ch-nav", "aria-label": "Chapters" }, headings.map((heading, i) => {
    const m = /^(\d+)\.\s*(.+)$/.exec(heading.textContent ?? "");
    const chip = h("button", { class: "ch-chip", onclick: () => heading.scrollIntoView({ block: "start", behavior: "smooth" }) },
      h("span", { class: "ch-no" }, m?.[1] ?? String(i + 1)), h("span", { class: "ch-name" }, m?.[2] ?? heading.textContent ?? ""));
    chip.style.setProperty("--cc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
    return chip;
  }));
  // under the document's header (its title and the table of version and status)
  const title = page.querySelector("h1");
  const after = title?.nextElementSibling?.tagName === "TABLE" ? title.nextElementSibling : title;
  if (after) after.after(nav); else page.prepend(nav);
  for (const heading of headings) {
    heading.append(h("button", { class: "ch-up", title: "Chapters", "aria-label": "Back to the chapters",
      onclick: () => nav.scrollIntoView({ block: "start", behavior: "smooth" }) }, "↑"));
  }
}

// --- purpose (§1): from millions of lines to one decision, and what the console is for ----------------------

const STEP_ICONS = ["datasets", "alert", "map", "review"];

function purpose(page: HTMLElement): void {
  const heading = [...page.querySelectorAll<HTMLElement>("h2")].find((el) => /^1\.\s*Purpose/.test(el.textContent ?? ""));
  if (!heading) return;
  const lead = heading.nextElementSibling;
  const list = [...(function* () { for (let el = heading.nextElementSibling; el && el.tagName !== "H2"; el = el.nextElementSibling) yield el; })()]
    .find((el) => el.tagName === "OL");
  // the funnel, from the paragraph's own figures
  const text = lead?.textContent ?? "";
  const lines = /([\d.,]+\s*(?:million|thousand)?)\s+server\s+log\s+lines/i.exec(text)?.[1];
  const servers = /from\s+(\d+)\s+servers/i.exec(text)?.[1];
  const alerts = /about\s+([\d,]+)\s+alert\s+rows/i.exec(text)?.[1];
  const groups = /(a\s+few\s+hundred|[\d,]+)\s+behavioural\s+groups/i.exec(text)?.[1];
  if (lead && lead.tagName === "P" && lines && alerts) {
    lead.classList.add("pp-lead");
    const steps: [string, string][] = [[lines, servers ? `log lines from ${servers} servers` : "log lines"], [alerts, "alert rows"],
      [groups?.replace(/\s+/g, " ") ?? "", groups ? "behavioural groups" : ""], ["1", "person decides"]];
    const funnel = h("div", { class: "pp-funnel" }, steps.filter(([n]) => n).map(([n, label], i, all) => {
      const step = h("div", { class: "pp-step" },
        h("span", { class: "pp-step-icon" }, icon(STEP_ICONS[i] ?? "check", 18)),
        h("span", { class: "pp-step-n" }, n), h("span", { class: "pp-step-label" }, label));
      step.style.setProperty("--w", `${100 - (i * 52) / Math.max(1, all.length - 1)}%`);
      step.style.setProperty("--pc", CHAPTER_COLOURS[i]);
      return step;
    }));
    lead.after(funnel);
  }
  // what it lets a person do: one tile per item, with its page
  let count = 0;
  if (list) {
    const items = [...list.querySelectorAll<HTMLElement>(":scope > li")];
    count = items.length;
    list.replaceWith(h("div", { class: "pp-grid" }, items.map((li, i) => {
      const itemText = li.textContent ?? "";
      const m = /\(([A-Za-z ]+)\)[;.]?\s*$/.exec(itemText);
      const pageName = m?.[1].trim() ?? "";
      const body = m ? slice(li, 0, m.index) : slice(li, 0, itemText.length);
      const tile = h("div", { class: "pp-tile" },
        h("div", { class: "pp-tile-head" }, h("span", { class: "pp-no" }, String(i + 1)),
          pageName ? h("span", { class: "pp-page" }, icon(PAGE_ICONS[pageName] ?? "docs", 14), pageName) : null),
        h("div", { class: "pp-tile-text" }, body));
      tile.style.setProperty("--pc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
      return tile;
    })));
  }
  titleCard(heading, count ? `${count} things it lets a person do` : "", "flow", "#88619a");
}

// --- the user guides: Getting started and Disclaimers ------------------------------------------------------

const SECTION_ICONS: [RegExp, string][] = [[/^settings/i, "settings"], [/whitelist/i, "shield"], [/pages/i, "dashboard"], [/cluster map/i, "map"], [/review/i, "review"], [/starting/i, "play"],
  [/words/i, "docs"], [/flag means/i, "alert"], [/model figures/i, "models"], [/language model/i, "analyze"], [/decisions/i, "check"],
  [/new logs|analyze/i, "analyze"], [/adding data|datasets/i, "datasets"], [/^sql/i, "data"], [/^data/i, "lock"]];
const sectionIcon = (title: string) => SECTION_ICONS.find(([rx]) => rx.test(title))?.[1] ?? "docs";

/** The elements of a section, after its heading and before the next. */
export function sectionOf(heading: Element): Element[] {
  const out: Element[] = [];
  for (let el = heading.nextElementSibling; el && el.tagName !== "H2"; el = el.nextElementSibling) out.push(el);
  return out;
}
const headers = (table: Element) => [...table.querySelectorAll("thead th")].map((th) => (th.textContent ?? "").trim().toLowerCase());
export const cells = (table: Element) => [...table.querySelectorAll("tbody tr")].map((tr) => [...tr.querySelectorAll("td")]);
export const content = (el: Element) => [...el.childNodes].map((n) => n.cloneNode(true));

/** "Page | What it is for" → page tiles with their sidebar icons. */
function pageTiles(table: Element): HTMLElement {
  return h("div", { class: "sc-pages" }, cells(table).map(([name, what]) => h("div", { class: "sc-page" },
    h("div", { class: "sc-page-head" }, h("span", { class: "sc-page-icon" }, icon(PAGE_ICONS[(name.textContent ?? "").trim()] ?? "docs", 18)),
      h("strong", {}, (name.textContent ?? "").trim())),
    h("div", { class: "sc-page-what" }, ...content(what)))));
}

/** "To | Do" → rows like the acceptance criteria: what you want, an arrow, how. */
function actionRows(table: Element, left = "To", right = "Do"): HTMLElement {
  return h("div", { class: "ac" }, h("div", { class: "ac-row head", "aria-hidden": "true" }, h("div", {}, left), h("span", {}), h("div", {}, right)),
    cells(table).map(([a, b]) => h("div", { class: "ac-row" }, h("div", { class: "ac-if strong-left" }, ...content(a)),
      h("span", { class: "ac-arrow", "aria-hidden": "true" }, "→"), h("div", { class: "ac-then" }, ...content(b)))));
}

/** "Label | Use it when | Note" → a card per review label, in its colour. */
function labelCards(table: Element): HTMLElement {
  return h("div", { class: "lb-grid" }, cells(table).map(([name, use, note]) => {
    const label = (name.textContent ?? "").trim();
    const verdict = VERDICTS.find((v) => v.label.toLowerCase() === label.toLowerCase());
    const needed = !/optional/i.test(note?.textContent ?? "");
    const card = h("div", { class: "lb-card" },
      h("div", { class: "lb-name" }, h("span", { class: "lb-dot" }), label),
      h("div", { class: "lb-use" }, ...content(use)),
      h("div", { class: `lb-note ${needed ? "needed" : ""}` }, icon(needed ? "docs" : "check", 13), needed ? (note.textContent ?? "").trim() : "No note needed"));
    card.style.setProperty("--lc", verdict?.color ?? "var(--muted)");
    return card;
  }));
}

/** An ordered list → numbered step tiles. */
export function stepTiles(list: Element): HTMLElement {
  return h("div", { class: "pp-grid steps" }, [...list.querySelectorAll(":scope > li")].map((li, i) => {
    const tile = h("div", { class: "pp-tile" }, h("div", { class: "pp-tile-head" }, h("span", { class: "pp-no" }, String(i + 1))),
      h("div", { class: "pp-tile-text" }, ...content(li)));
    tile.style.setProperty("--pc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
    return tile;
  }));
}

/** Drops the ": " after a list item's bold term from its first text, editing the text itself (never re-reading the
 * item as HTML). */
export function dropLeadingColon(el: Element): void {
  for (const node of [...el.childNodes]) {
    if (node.nodeType !== Node.TEXT_NODE) return;
    const text = node.textContent ?? "";
    if (!text.trim()) continue;
    node.textContent = text.replace(/^\s*:\s*/, "");
    return;
  }
}

/** "**Term**: meaning" items → glossary cards. */
export function glossary(list: Element): HTMLElement {
  return h("div", { class: "gs-grid" }, [...list.querySelectorAll(":scope > li")].map((li) => {
    const term = li.querySelector("strong");
    const rest = li.cloneNode(true) as HTMLElement;
    rest.querySelector("strong")?.remove();
    dropLeadingColon(rest);
    return h("div", { class: "gs-card" }, h("div", { class: "gs-term" }, term?.textContent ?? ""), h("div", { class: "gs-def" }, ...content(rest)));
  }));
}

function gettingStarted(page: HTMLElement): void {
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = heading.firstChild?.textContent ?? "";
    const parts = sectionOf(heading);
    let count = "";
    for (const el of parts) {
      if (el.tagName === "TABLE") {
        const cols = headers(el);
        if (cols[0] === "page") { count = `${cells(el).length} pages`; el.replaceWith(pageTiles(el)); }
        else if (cols[0] === "to") { count = `${cells(el).length} things to do`; el.replaceWith(actionRows(el)); }
        else if (cols[0] === "label") el.replaceWith(labelCards(el));
      } else if (el.tagName === "OL") {
        count = `${el.querySelectorAll(":scope > li").length} steps`; el.replaceWith(stepTiles(el));
      } else if (el.tagName === "UL" && /words/i.test(title)) {
        count = `${el.querySelectorAll(":scope > li").length} words`; el.replaceWith(glossary(el));
      } else if (el.tagName === "PRE") {
        el.classList.add("terminal");
      }
    }
    titleCard(heading, count, sectionIcon(title), CHAPTER_COLOURS[i % CHAPTER_COLOURS.length], i + 1);
  });
}

function disclaimers(page: HTMLElement): void {
  const intro = page.querySelector("h1")?.nextElementSibling;
  if (intro?.tagName === "P") intro.replaceWith(h("div", { class: "dc-banner" }, h("span", { class: "dc-banner-icon" }, icon("alert", 22)), h("div", {}, ...content(intro))));
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = heading.firstChild?.textContent ?? "";
    const colour = CHAPTER_COLOURS[i % CHAPTER_COLOURS.length], glyph = sectionIcon(title);
    let count = "";
    for (const el of sectionOf(heading)) {
      if (el.tagName !== "UL") continue;
      const items = [...el.querySelectorAll(":scope > li")];
      count = `${items.length} point${items.length === 1 ? "" : "s"}`;
      const grid = h("div", { class: "dc-grid" }, items.map((li) => h("div", { class: "dc-card" }, h("span", { class: "dc-icon" }, icon(glyph, 15)),
        h("div", {}, ...content(li)))));
      grid.style.setProperty("--dc", colour);
      el.replaceWith(grid);
    }
    titleCard(heading, count, glyph, colour, i + 1, true);
  });
}

/** An ordered list of steps with long content → a numbered vertical timeline. */
function timeline(list: Element): HTMLElement {
  return h("ol", { class: "tl-steps" }, [...list.querySelectorAll(":scope > li")].map((li, i) => {
    const step = h("li", { class: "tl-step" }, h("span", { class: "tl-no" }, String(i + 1)), h("div", { class: "tl-body" }, ...content(li)));
    step.style.setProperty("--pc", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length]);
    return step;
  }));
}

function ssoAndDatasets(page: HTMLElement): void {
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = heading.firstChild?.textContent ?? "";
    let count = "";
    for (const el of sectionOf(heading)) {
      if (el.tagName === "OL") { count = `${el.querySelectorAll(":scope > li").length} steps`; el.replaceWith(timeline(el)); }
      else if (el.tagName === "UL") {
        const grid = h("div", { class: "dc-grid" }, [...el.querySelectorAll(":scope > li")].map((li) => h("div", { class: "dc-card" },
          h("span", { class: "dc-icon" }, icon("lock", 15)), h("div", {}, ...content(li)))));
        grid.style.setProperty("--dc", "#33a474");
        el.replaceWith(grid);
      } else if (el.tagName === "TABLE") {
        const cols = headers(el);
        if (cols[0] === "the console says") el.replaceWith(actionRows(el, "The console says", "What to do"));
        else if (cols[0] === "step") { count = `${cells(el).length} steps`; el.replaceWith(actionRows(el, "Step", "What happens")); }
      }
    }
    titleCard(heading, count, /sso/i.test(title) ? "lock" : "datasets", CHAPTER_COLOURS[i % CHAPTER_COLOURS.length], i + 1);
  });
}

const README_ICONS: [RegExp, string][] = [[/running/i, "play"], [/tests/i, "check"], [/planned/i, "clock"], [/documents/i, "docs"], [/folder/i, "folder"]];

function consoleReadme(page: HTMLElement): void {
  const pages = [...page.querySelectorAll("table")].find((t) => headers(t)[0] === "page");
  if (pages) pages.replaceWith(pageTiles(pages));
  chapters(page);
  [...page.querySelectorAll<HTMLElement>("h2")].forEach((heading, i) => {
    const title = heading.firstChild?.textContent ?? "";
    const glyph = README_ICONS.find(([rx]) => rx.test(title))?.[1] ?? "docs";
    const colour = CHAPTER_COLOURS[i % CHAPTER_COLOURS.length];
    let count = "";
    for (const el of sectionOf(heading)) {
      if (el.tagName === "PRE") el.classList.add("terminal");
      else if (el.tagName === "UL") {
        const items = [...el.querySelectorAll(":scope > li")];
        count = `${items.length} ${/tests/i.test(title) ? "suites" : "caches"}`;
        const grid = h("div", { class: "dc-grid" }, items.map((li) => h("div", { class: "dc-card" }, h("span", { class: "dc-icon" }, icon(glyph, 15)), h("div", {}, ...content(li)))));
        grid.style.setProperty("--dc", colour);
        el.replaceWith(grid);
      } else if (el.tagName === "TABLE") {
        const cols = headers(el);
        count = `${cells(el).length} ${cols[0] === "document" ? "documents" : "planned"}`;
        el.replaceWith(actionRows(el, cols[0] === "where" ? "Where" : "Document", cols[0] === "where" ? "What" : "What it covers"));
      }
    }
    titleCard(heading, count, glyph, colour, i + 1, true);
  });
}

/** Add the visuals a document has. */
export function enhanceDoc(id: string, page: HTMLElement): void {
  if (id === "requirements/01_product_requirements") {
    chapters(page);
    purpose(page);
    goals(page);
    personas(page);
    scope(page);
    epics(page);
  } else if (id === "app/01_getting_started") {
    gettingStarted(page);
  } else if (id === "app/02_disclaimers") {
    disclaimers(page);
  } else if (id === "app/03_sso_and_datasets") {
    ssoAndDatasets(page);
  } else if (id === "app/README") {
    consoleReadme(page);
  } else if (id === "pipeline/phase4f_sequences/guide") {
    routinesGuide(page);
  }
}
