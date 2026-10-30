// Sigma's rule form (service/sigma_form.py turns it into YAML and back): the required fields first (title, log type,
// the tests an event must pass), then Except, an optional count, the level, and the rest under More. Required fields
// still empty are marked by mark(); the service says which. Also the readable card of a rule (Describe's preview) and
// the stamp of who added a rule and when.

import { badge, clear, h, select, type Child } from "./dom";
import { icon } from "./icons";

export interface Row { field: string; op: string; values: string[] }
export interface Count { min: number; within: string; by: string[]; distinct: string }
export interface RuleForm {
  id: string; title: string; source: string; service: string; match: Row[]; exclude: Row[]; count: Count | null;
  level: string; status: string; description: string; tags: string[]; falsepositives: string[]; author: string; date: string;
  keep: Record<string, unknown>;
}
export interface FormContext {
  fields: Record<string, string[]>; eventTypes: Record<string, string[]>; attack: Record<string, string>; onChange: () => void;
}

export const SOURCE_SHORT: Record<string, string> = { auth: "AUTH", ossec: "OSSEC", pf: "PF", ipf: "IPFilter" };
export const LEVEL_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Info" };
export const LEVEL_TONE: Record<string, "bad" | "warn" | "info" | "muted" | "dark"> = { critical: "dark", high: "bad", medium: "warn", low: "info", informational: "muted" };
const SERVICES = ["sshd", "su", "sudo", "cron", "login"];
const OPS: [string, string][] = [["is", "is"], ["contains", "contains"], ["startswith", "starts with"], ["endswith", "ends with"],
  ["re", "regex"], ["cidr", "in subnet"], ["gt", ">"], ["gte", "≥"], ["lt", "<"], ["lte", "≤"]];
const OP_SIGN: Record<string, string> = { is: "=", contains: "∋", startswith: "^", endswith: "$", re: "~", cidr: "∈", gt: ">", gte: "≥", lt: "<", lte: "≤" };
const UNITS: [string, string][] = [["s", "sec"], ["m", "min"], ["h", "h"], ["d", "d"]];
const STATUSES = ["experimental", "test", "stable"];

export function blankForm(source: string): RuleForm {
  return { id: crypto.randomUUID(), title: "", source, service: "", match: [{ field: "event_type", op: "is", values: [] }], exclude: [],
    count: null, level: "medium", status: "experimental", description: "", tags: [], falsepositives: [], author: "", date: "", keep: {} };
}

/** Chips with a text box: Enter, a comma or leaving the box adds what is typed; Backspace in an empty box takes the last
 * one back. ``show`` draws a chip, ``take`` turns typed text into a value (or "" to drop it). */
function chips(values: string[], changed: () => void, opts: { list?: string; label: string; placeholder?: string;
  show?: (v: string) => Child; take?: (t: string) => string; title?: (v: string) => string } ): HTMLElement {
  const box = h("div", { class: "sf-chips" });
  const input = h("input", { type: "text", list: opts.list ?? "", placeholder: opts.placeholder ?? "", "aria-label": opts.label }) as HTMLInputElement;
  const draw = () => {
    clear(box, values.map((v, i) => h("span", { class: "sf-chip", title: opts.title?.(v) ?? v }, opts.show ? opts.show(v) : v,
      h("button", { type: "button", class: "sf-x", "aria-label": `Remove ${v}`, onclick: () => { values.splice(i, 1); draw(); changed(); } }, "×"))), input);
  };
  const add = () => {
    const parts = input.value.split(",").map((p) => (opts.take ? opts.take(p.trim()) : p.trim())).filter(Boolean);
    input.value = "";
    if (!parts.length) return;
    values.push(...parts.filter((p) => !values.includes(p)));
    draw();
    input.focus();
    changed();
  };
  input.addEventListener("keydown", (k) => {
    if (k.key === "Enter" || k.key === ",") { k.preventDefault(); add(); }
    else if (k.key === "Backspace" && !input.value && values.length) { values.pop(); draw(); input.focus(); changed(); }
  });
  input.addEventListener("change", add);                       // a suggestion picked from the list
  box.addEventListener("click", (e) => { if (e.target === box) input.focus(); });
  draw();
  return box;
}

function datalist(id: string, options: [string, string][]): HTMLElement {
  return h("datalist", { id }, options.map(([value, label]) => h("option", { value, label })));
}

const techniqueTag = (text: string) => {
  const t = text.trim().toLowerCase().replace(/\s+/g, "-");
  return !t ? "" : t.startsWith("attack.") ? t : `attack.${t}`;
};
const tagLabel = (tag: string) => (/^attack\.t\d{4}/.test(tag) ? tag.slice(7).toUpperCase() : tag.replace(/^attack\./, ""));

/** The form, and mark(): the required fields the service says are still empty. */
export function ruleForm(f: RuleForm, ctx: FormContext): { el: HTMLElement; mark: (missing: string[]) => void } {
  const el = h("div", { class: "sf" });
  const changed = () => ctx.onChange();
  const fieldsFor = (row?: Row) => {
    const names = ctx.fields[f.source] ?? [];
    return row?.field && !names.includes(row.field) ? [...names, row.field] : names;
  };

  const block = (key: string, label: string, required: boolean, ...body: Child[]) =>
    h("div", { class: `sf-block ${required ? "req" : ""}`, "data-key": key }, h("span", { class: "sf-label" }, label), h("div", { class: "sf-body" }, ...body));

  const title = h("input", { type: "text", class: "sf-title", value: f.title, placeholder: "Title", "aria-label": "Title" }) as HTMLInputElement;
  title.addEventListener("input", () => { f.title = title.value; changed(); });

  const sourceBox = h("div", { class: "row sf-source" });
  const drawSource = () => clear(sourceBox,
    h("div", { class: "pills small", role: "tablist" }, Object.keys(SOURCE_SHORT).filter((s) => ctx.fields[s]).map((s) => h("button", {
      type: "button", class: f.source === s ? "on" : "", role: "tab", "aria-selected": String(f.source === s),
      onclick: () => {
        if (f.source === s) return;
        f.source = s;
        if (s !== "auth") f.service = "";
        drawAll();
        changed();
      },
    }, SOURCE_SHORT[s]))),
    f.source === "auth" ? select([["", "Any program"], ...SERVICES.map((v) => [v, v] as [string, string])], f.service,
      (v) => { f.service = v; changed(); }, { "aria-label": "Program", class: "sf-service" }) : null);

  const rowsBox = (rows: Row[], kind: "match" | "exclude") => {
    const box = h("div", { class: "sf-rows" });
    const draw = () => clear(box,
      rows.map((row, i) => {
        const listId = `sf-${kind}-${i}-values`;
        const types = row.field === "event_type" ? (ctx.eventTypes[f.source] ?? []) : [];
        return h("div", { class: "sf-row" },
          select(fieldsFor(row).map((n) => [n, n] as [string, string]), row.field, (v) => { row.field = v; draw(); changed(); },
            { "aria-label": "Field", class: "sf-field mono" }),
          select(OPS, row.op, (v) => { row.op = v; changed(); }, { "aria-label": "Test", class: "sf-op" }),
          chips(row.values, changed, { label: "Values", list: types.length ? listId : undefined, placeholder: row.values.length ? "" : "value" }),
          types.length ? datalist(listId, types.map((t) => [t, t])) : null,
          kind === "exclude" || rows.length > 1
            ? h("button", { type: "button", class: "icon-btn small", title: "Remove", "aria-label": "Remove", onclick: () => { rows.splice(i, 1); draw(); changed(); } }, icon("close", 13))
            : h("span"));
      }),
      h("button", { type: "button", class: "btn small sf-add", "aria-label": kind === "match" ? "Add match" : "Add except",
        onclick: () => { rows.push({ field: "username", op: "is", values: [] }); draw(); changed(); } }, icon("plus", 13)));
    draw();
    return box;
  };

  const countBox = h("div", { class: "sf-count" });
  const drawCount = () => {
    const c = f.count;
    const sw = h("input", { type: "checkbox", checked: Boolean(c), "aria-label": "Count" }) as HTMLInputElement;
    sw.addEventListener("change", () => {
      f.count = sw.checked ? { min: 5, within: "10m", by: (ctx.fields[f.source] ?? []).includes("source_ip") ? ["source_ip"] : ["host"], distinct: "" } : null;
      drawCount();
      changed();
    });
    const toggle = h("label", { class: "pt-switch", title: c ? "On" : "Off" }, sw, h("span"));
    if (!c) return clear(countBox, toggle);
    const [, n = "10", unit = "m"] = /^(\d+)\s*([smhd])$/.exec(c.within) ?? [];
    const min = h("input", { type: "number", min: "1", value: String(c.min), class: "sf-num", "aria-label": "At least" }) as HTMLInputElement;
    min.addEventListener("input", () => { c.min = Number(min.value) || 0; changed(); });
    const span = h("input", { type: "number", min: "1", value: n, class: "sf-num", "aria-label": "Within" }) as HTMLInputElement;
    const units = select(UNITS, unit, () => setWithin(), { "aria-label": "Unit" });
    const setWithin = () => { c.within = `${span.value || "1"}${units.value}`; changed(); };
    span.addEventListener("input", setWithin);
    const fields = ctx.fields[f.source] ?? [];
    const addBy = select([["", "+"], ...fields.filter((x) => !c.by.includes(x)).map((x) => [x, x] as [string, string])], "", (v) => {
      if (v) c.by.push(v);
      drawCount();
      changed();
    }, { "aria-label": "Group by", class: "sf-addby" });
    clear(countBox, toggle,
      h("span", { class: "sf-word" }, "≥"), min,
      select([["", "events"], ...fields.map((x) => [x, `distinct ${x}`] as [string, string])], c.distinct, (v) => { c.distinct = v; changed(); }, { "aria-label": "Counted", class: "sf-counted" }),
      h("span", { class: "sf-word" }, "within"), span, units,
      h("span", { class: "sf-word" }, "by"),
      c.by.map((x, i) => h("span", { class: "sf-chip mono" }, x,
        h("button", { type: "button", class: "sf-x", "aria-label": `Remove ${x}`, onclick: () => { c.by.splice(i, 1); drawCount(); changed(); } }, "×"))),
      addBy);
  };

  const levelBox = h("div", { class: "pills small sf-level", role: "tablist" });
  const drawLevel = () => clear(levelBox, ["informational", "low", "medium", "high", "critical"].map((l) => h("button", {
    type: "button", class: `${f.level === l ? "on" : ""} lv-${l}`, role: "tab", "aria-selected": String(f.level === l),
    onclick: () => { f.level = l; drawLevel(); changed(); },
  }, LEVEL_LABEL[l])));

  const statusBox = h("div", { class: "pills small", role: "tablist" });
  const drawStatus = () => clear(statusBox, [...new Set([...STATUSES, f.status || "experimental"])].map((s) => h("button", {
    type: "button", class: (f.status || "experimental") === s ? "on" : "", role: "tab", "aria-selected": String((f.status || "experimental") === s),
    onclick: () => { f.status = s; drawStatus(); changed(); },
  }, s)));
  const description = h("textarea", { rows: 2, "aria-label": "Description" }) as HTMLTextAreaElement;
  description.value = f.description;
  description.addEventListener("input", () => { f.description = description.value; changed(); });
  const more = h("details", { class: "sf-more", open: Boolean(f.description || f.tags.length || f.falsepositives.length) },
    h("summary", {}, "More"),
    block("status", "Status", false, statusBox),
    block("description", "Description", false, description),
    block("tags", "ATT&CK", false, chips(f.tags, changed, { label: "ATT&CK", list: "sf-attack", placeholder: f.tags.length ? "" : "T1110.001",
      take: techniqueTag, show: tagLabel, title: (v) => ctx.attack[tagLabel(v)] ?? v })),
    block("falsepositives", "False positives", false, chips(f.falsepositives, changed, { label: "False positives" })),
    datalist("sf-attack", Object.entries(ctx.attack).map(([id, name]) => [id, name])));

  const drawAll = () => {
    drawSource(); drawCount(); drawLevel(); drawStatus();
    clear(el,
      block("title", "Title", true, title),
      block("source", "Log type", true, sourceBox),
      block("match", "Match", true, rowsBox(f.match, "match")),
      block("exclude", "Except", false, rowsBox(f.exclude, "exclude")),
      block("count", "Count", false, countBox),
      block("level", "Level", false, levelBox),
      more);
  };
  drawAll();
  const mark = (missing: string[]) => el.querySelectorAll<HTMLElement>(".sf-block.req").forEach((b) =>
    b.classList.toggle("missing", missing.includes(b.dataset.key ?? "")));
  return { el, mark };
}

/** A rule as a card: where it reads, what an event must hold and must not, the count, the level and ATT&CK. */
export function ruleCard(f: RuleForm): HTMLElement {
  const test = (row: Row, not = false) => h("span", { class: `sf-test mono ${not ? "not" : ""}` },
    h("small", {}, row.field), `${not ? "≠ " : ""}${not ? "" : (OP_SIGN[row.op] ?? row.op) + " "}${row.values.join(" | ")}`);
  const c = f.count;
  return h("div", { class: "sf-card" },
    h("div", { class: "sf-card-head" },
      h("span", { class: "sg-src" }, SOURCE_SHORT[f.source] ?? f.source), f.service ? h("span", { class: "sg-src" }, f.service) : null,
      h("strong", {}, f.title || "—"), badge(LEVEL_LABEL[f.level] ?? f.level, LEVEL_TONE[f.level] ?? "muted")),
    h("div", { class: "sg-chips" }, f.match.filter((r) => r.values.length).map((r) => test(r)), f.exclude.filter((r) => r.values.length).map((r) => test(r, true))),
    c ? h("div", { class: "sg-chips" }, h("span", { class: "sg-kind k-event_count" }, `≥ ${c.min} ${c.distinct ? `distinct ${c.distinct}` : "events"}`, h("small", {}, c.within)),
      c.by.length ? h("span", { class: "sg-by" }, h("small", {}, "by"), c.by.join(", ")) : null) : null,
    f.tags.length ? h("div", { class: "sg-chips" }, f.tags.map((t) => h("span", { class: "sg-tech" }, tagLabel(t)))) : null);
}

const DATE = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" });

/** Who added (or edited) a rule and on what day; the full time on hover. */
export function stamp(by: string, at: string, edited = false): HTMLElement | null {
  if (!at) return null;
  const when = new Date(at);
  const name = by || "local-user";
  return h("span", { class: `sg-stamp ${edited ? "edited" : ""}`, title: `${edited ? "Edited" : "Added"} · ${name} · ${when.toLocaleString("en-GB")}` },
    h("span", { class: "sg-avatar", "aria-hidden": "true" }, edited ? icon("table-fill", 11) : name.slice(0, 1).toUpperCase()),
    h("span", { class: "sg-stamp-name" }, name), h("span", { class: "sg-stamp-date" }, Number.isNaN(when.getTime()) ? at : DATE.format(when)));
}

/** Added in the last week, by a person (not the starter rules). */
export const isNew = (by: string, at: string) => by !== "starter rules" && Date.now() - new Date(at).getTime() < 7 * 86400_000;
