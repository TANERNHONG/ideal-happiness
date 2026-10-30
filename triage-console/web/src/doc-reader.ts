// The reading view every document gets, after its own visuals (doc-visuals.ts): a header with its group, reading time
// and size; a requirements document's version history folded away under its latest version; tables that scroll
// sideways, with requirement IDs and statuses marked; code with a Copy button; an "On this page" list that follows the
// reader; and the previous and next documents of its group.

import { h } from "./dom";
import { icon } from "./icons";

export interface DocEntry { id: string; group: string; title: string; words: number }

const GROUP_ICONS: Record<string, string> = { app: "docs", requirements: "reports", pipeline: "train" };
const minutes = (words: number) => Math.max(1, Math.round((words || 0) / 200));

/** A title without its series ("Phase 4f: sequential pattern mining" → "Phase 4f", "Sequential pattern mining"). */
export function splitTitle(title: string): [string, string] {
  const m = /^([^:]{2,60}):\s+(.+)$/.exec(title.trim());
  return m ? [m[1], m[2].charAt(0).toUpperCase() + m[2].slice(1)] : ["", title.trim()];
}

/** The heading's own words, without the buttons other visuals add to it (the chapters' ↑). */
const headingText = (heading: Element) => {
  const copy = heading.cloneNode(true) as Element;
  copy.querySelectorAll("button").forEach((b) => b.remove());
  const text = (copy.textContent ?? "").trim();
  const number = heading.closest(".tc-card")?.querySelector(".tc-num")?.textContent?.trim();   // a title card holds it apart
  return number && !/^\d/.test(text) ? `${number}. ${text}` : text;
};

// --- the header --------------------------------------------------------------------------------------------------------

/** Version cells read "0.18 (2026-10-26): what changed. 0.17 (2026-10-26): …": one entry per version. */
function versions(text: string): string[] {
  return text.split(/\s(?=\d+\.\d+(?:\s*\(\d{4}-\d{2}-\d{2}\))?:)/).map((s) => s.trim()).filter(Boolean);
}

function header(page: HTMLElement, doc: DocEntry, groupLabel: string): void {
  const title = page.querySelector<HTMLElement>("h1");
  if (!title) return;
  const sections = page.querySelectorAll("h2").length;
  const [series, name] = splitTitle(title.textContent ?? "");
  const head = h("header", { class: "doc-head" },
    h("div", { class: "doc-kicker" }, icon(GROUP_ICONS[doc.group] ?? "docs", 14), h("span", {}, groupLabel),
      h("span", { class: "doc-dot", "aria-hidden": "true" }), h("span", {}, `${minutes(doc.words)} min read`),
      sections ? [h("span", { class: "doc-dot", "aria-hidden": "true" }), h("span", {}, `${sections} section${sections === 1 ? "" : "s"}`)] : null),
    series ? h("div", { class: "doc-series" }, series) : null);
  title.before(head);
  head.append(title);
  if (series) title.textContent = name;

  // a requirements document's own table (Document, Status, Version, Related): a lede, its version and links
  const table = head.nextElementSibling;
  if (table?.tagName !== "TABLE") return;
  const rows = new Map([...table.querySelectorAll("tr")].map((tr) => {
    const cells = tr.querySelectorAll("td");
    return [(cells[0]?.textContent ?? "").trim().toLowerCase(), cells[1]] as const;
  }));
  if (!rows.has("version")) return;
  const status = rows.get("status"), version = rows.get("version"), related = rows.get("related");
  if (status) head.append(h("p", { class: "doc-lede" }, status.textContent ?? ""));
  const entries = versions(version?.textContent ?? "");
  const latest = /^(\d+\.\d+)(?:\s*\((\d{4}-\d{2}-\d{2})\))?/.exec(entries[0] ?? "");
  const meta = h("div", { class: "doc-meta" },
    latest ? h("span", { class: "doc-version" }, `Version ${latest[1]}`, latest[2] ? h("span", { class: "muted" }, ` · ${latest[2]}`) : null) : null,
    related ? h("span", { class: "doc-related" }, ...related.childNodes) : null);     // moved, so their links keep working
  head.append(meta);
  if (entries.length) {
    head.append(h("details", { class: "doc-history" }, h("summary", {}, `Version history · ${entries.length}`),
      h("ol", {}, entries.map((entry) => {
        const m = /^(\d+\.\d+(?:\s*\(\d{4}-\d{2}-\d{2}\))?):\s*(.*)$/s.exec(entry);
        return h("li", {}, m ? [h("strong", {}, m[1]), " ", m[2]] : entry);
      }))));
  }
  table.remove();
}

// --- tables ------------------------------------------------------------------------------------------------------------

const STATUS: [RegExp, string][] = [
  [/^(built, not measured|partly|wireframe|built \(proof)/i, "warn"],
  [/^(built|met)\b/i, "ok"],
  [/^(planned|open|deferred)\b/i, "plan"],
  [/^(withdrawn|replaced)\b/i, "off"],
];
const statusTone = (text: string) => STATUS.find(([rx]) => rx.test(text.trim()))?.[1] ?? "";
const ID = /^(FR|NFR|US|Q)(-[A-Z]+)*-?\d+[a-z]?$/;
const NUMBER = /^[−\-+]?[\d,.]+\s*(%|×|x|ms|s|MB|GB)?$/;

function tables(page: HTMLElement): void {
  for (const table of [...page.querySelectorAll<HTMLTableElement>("table")]) {
    if (table.closest(".md-table, .doc-head")) continue;
    const heads = [...table.querySelectorAll("thead th")].map((th) => (th.textContent ?? "").trim().toLowerCase());
    const statusAt = heads.indexOf("status");
    for (const row of table.querySelectorAll("tbody tr")) {
      const cells = [...row.querySelectorAll("td")];
      if (cells[0] && ID.test((cells[0].textContent ?? "").trim())) cells[0].classList.add("md-id");
      cells.forEach((td, i) => { if (i > 0 && NUMBER.test((td.textContent ?? "").trim())) td.classList.add("num"); });
      const cell = cells[statusAt];
      if (statusAt < 0 || !cell) continue;
      const text = (cell.textContent ?? "").trim(), tone = statusTone(text);
      if (!tone) continue;
      const lead = cell.firstElementChild;
      if (text.length <= 40) {                                             // a short status: the cell is the badge
        cell.replaceChildren(h("span", { class: `md-status ${tone}` }, text.replace(/\.$/, "")));
      } else if (lead?.tagName === "STRONG" && cell.firstChild === lead && statusTone(lead.textContent ?? "")) {
        lead.replaceWith(h("span", { class: `md-status ${tone}` }, (lead.textContent ?? "").replace(/[.:]\s*$/, "")));
      }
    }
    const wrap = h("div", { class: "md-table" });
    table.before(wrap);
    wrap.append(table);
  }
}

// --- code --------------------------------------------------------------------------------------------------------------

function code(page: HTMLElement): void {
  // a short name (a file, a command, a value) stays on one line; only a long path may break
  page.querySelectorAll(":not(pre) > code").forEach((c) => { if ((c.textContent ?? "").length <= 28) c.classList.add("nw"); });
  for (const pre of [...page.querySelectorAll<HTMLPreElement>("pre")]) {
    if (pre.closest(".md-code")) continue;
    const lang = /language-(\w+)/.exec(pre.querySelector("code")?.className ?? "")?.[1];
    const copy = h("button", { class: "icon-btn small md-copy", type: "button", title: "Copy", "aria-label": "Copy" }, icon("copy", 15)) as HTMLButtonElement;
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.textContent ?? "");
        copy.replaceChildren(icon("check", 15));
        copy.classList.add("done");
        setTimeout(() => { copy.replaceChildren(icon("copy", 15)); copy.classList.remove("done"); }, 1500);
      } catch { /* the clipboard is refused outside a secure, focused page: nothing to undo */ }
    });
    if (/[─│┌┐└┘├┤┬┴┼]/.test(pre.textContent ?? "")) pre.classList.add("diagram");   // box lines must touch
    const wrap = h("div", { class: `md-code ${pre.classList.contains("terminal") ? "dark" : ""}` },
      lang ? h("span", { class: "md-lang" }, lang) : null, copy);
    pre.before(wrap);
    wrap.prepend(pre);
  }
}

// --- On this page ------------------------------------------------------------------------------------------------------

function contents(page: HTMLElement, toc: HTMLElement): void {
  const headings = [...page.querySelectorAll<HTMLElement>("h2, h3")].filter((el) => el.id && !el.closest(".doc-head, .bk-page"));
  const top = headings.filter((el) => el.tagName === "H2");
  if (top.length < 3) { toc.hidden = true; return; }
  toc.hidden = false;
  const links = new Map<HTMLElement, HTMLAnchorElement>();
  const item = (heading: HTMLElement) => {
    const a = h("a", { href: "#/docs", class: heading.tagName === "H3" ? "sub" : "" }, headingText(heading)) as HTMLAnchorElement;
    a.addEventListener("click", (e) => { e.preventDefault(); heading.scrollIntoView({ block: "start", behavior: "smooth" }); });
    links.set(heading, a);
    return a;
  };
  const groups: { head: HTMLElement; subs: HTMLElement[] }[] = [];
  for (const el of headings) {
    if (el.tagName === "H2") groups.push({ head: el, subs: [] });
    else groups[groups.length - 1]?.subs.push(el);
  }
  const lists = new Map<HTMLElement, HTMLElement>();
  const title = page.querySelector<HTMLElement>(".doc-head h1");
  const toTop = h("a", { href: "#/docs", class: "toc-title" }, title?.textContent ?? "") as HTMLAnchorElement;
  toTop.addEventListener("click", (e) => { e.preventDefault(); page.scrollIntoView({ block: "start", behavior: "smooth" }); });
  toc.replaceChildren(h("h2", {}, "On this page"), toTop,
    h("ol", {}, groups.map(({ head, subs }) => {
      const sub = subs.length && subs.length <= 12 ? h("ol", {}, subs.map((s) => h("li", {}, item(s)))) : null;
      const li = h("li", { class: "closed" }, item(head), sub);
      lists.set(head, li);
      subs.forEach((s) => lists.set(s, li));
      return li;
    })));

  // follow the reader: the last heading above the upper third of the screen is the current one
  const mark = () => {
    if (!toc.isConnected) return observer.disconnect();
    const current = headings.filter((el) => el.getBoundingClientRect().top < window.innerHeight * 0.3).pop() ?? headings[0];
    links.forEach((a, el) => a.classList.toggle("on", el === current));
    lists.forEach((li) => li.classList.add("closed"));
    lists.get(current)?.classList.remove("closed");
    const on = links.get(current);                                     // keep it in view in a long list, without moving the page
    if (on && (on.offsetTop < toc.scrollTop || on.offsetTop > toc.scrollTop + toc.clientHeight - 40)) toc.scrollTop = on.offsetTop - 80;
  };
  const observer = new IntersectionObserver(mark, { rootMargin: "0px 0px -60% 0px" });
  headings.forEach((el) => observer.observe(el));
  mark();
}

// --- previous and next -------------------------------------------------------------------------------------------------

function neighbours(page: HTMLElement, doc: DocEntry, docs: DocEntry[], open: (id: string) => void): void {
  const group = docs.filter((d) => d.group === doc.group);
  const i = group.findIndex((d) => d.id === doc.id);
  const link = (d: DocEntry | undefined, label: string, cls: string) => {
    if (!d) return h("span");
    const a = h("a", { href: "#/docs", class: cls }, h("small", {}, label), h("span", {}, splitTitle(d.title)[1])) as HTMLAnchorElement;
    a.addEventListener("click", (e) => { e.preventDefault(); open(d.id); });
    return a;
  };
  if (i < 0 || group.length < 2) return;
  page.append(h("nav", { class: "doc-foot", "aria-label": "More in this group" },
    link(group[i - 1], "← Previous", "prev"), link(group[i + 1], "Next →", "next")));
}

/** Make a drawn document easy to read. */
export function readable(page: HTMLElement, toc: HTMLElement, doc: DocEntry, docs: DocEntry[], groupLabel: string,
  open: (id: string) => void): void {
  header(page, doc, groupLabel);
  tables(page);
  code(page);
  neighbours(page, doc, docs, open);
  contents(page, toc);
}
