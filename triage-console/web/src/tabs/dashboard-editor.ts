// Settings → Dashboard: the Dashboard itself, scaled to fit, as the editor. A card is dragged to a new place, made wider
// or narrower by the handle on its right edge (in columns of 12), or hidden with × into the Hidden tray, from which it
// is dragged or clicked back (the tray and the buttons stay in view as the page scrolls). From the keyboard, the move
// and width handles take the arrow keys. *SQL table* adds a table of the person's own: a title, a description and a
// query, edited in a dialog (the pencil), whose result is kept until it is refreshed; its height is dragged from its
// bottom edge. *Tile* adds a tile, 1 × 1 to start (one column, 100 pixels), as wide and high as it is dragged: an icon,
// a heading and text, a colour, an alignment and a console page to open, chosen in a dialog with the tile as it will
// look. *Pack tightly* lets short cards fill the gaps beside tall ones (dashboard.ts pack). Changes show at once and stay
// a draft until saved (the setting dashboard_layout); Discard goes back to the saved layout, Reset to the default (the
// person's SQL tables and tiles kept, hidden).

import { api, type DashboardTile } from "../api";
import { clear, errorBox, fmt, h, loading, table, type Child } from "../dom";
import { COLUMNS, TILE_LINKS, TILE_SIZES, TILE_TONES, WIDGET_SPAN, cardInfo, clampHeight, clampSpan, defaultLayout, isTile, isWidget,
  newTile, newTileId, newWidget, newWidgetId, normalise, type Layout } from "../dashboard-layout";
import { t } from "../i18n";
import { TILE_ICONS, icon } from "../icons";
import { isLocked, sqlApi } from "../sql-lock";
import { state, updateSettings } from "../state";
import { dashboardCards, pack, sized, sqlCard, tileCard } from "./dashboard";

const STAGE_WIDTH = 1400;        // the width the preview is laid out at, before it is scaled to fit
const GAP = 16;                  // .dash-grid's gap, in the preview's own pixels
const PREVIEW_ROWS = 50;         // rows of a query's result shown in its dialog
const COLUMN_PX = 100;           // about one column of the Dashboard, for the tile dialog's preview

export function dashboardEditor(box: HTMLElement): void {
  const saved = () => normalise(state.settings.dashboard_layout);
  const same = (a: Layout, b: Layout) => JSON.stringify(a) === JSON.stringify(b);
  let draft = saved();
  let data: any = null;                                          // the /api/dashboard answer the preview is drawn from
  let build: Record<string, () => HTMLElement> | null = null;
  const cards = new Map<string, HTMLElement>();                  // each card drawn once, with its handles
  let dragging: { id: string; from: "grid" | "tray" } | null = null;
  let target: number | null = null;                              // the place a dragged card would take

  const err = h("div");
  const grid = h("div", { class: "dash-grid" }, loading());
  const stage = h("div", { class: "dl-stage" }, grid);
  const frame = h("div", { class: "dl-preview" }, stage);
  const tray = h("div", { class: "dl-tray" });
  const button = (glyph: string, label: string, cls = "") => h("button", { class: `btn small ${cls}`, type: "button" }, icon(glyph, 14), label) as HTMLButtonElement;
  const add = button("query-sql", "SQL table"), addTile = button("note", "Tile");
  const packed = h("button", { class: "btn small dl-pack", type: "button", "aria-pressed": "false" }, icon("dashboard", 14), "Pack tightly") as HTMLButtonElement;
  const discard = button("history", "Discard"), reset = button("refresh", "Reset"), save = button("check", "Save", "primary");

  // --- the preview, scaled to the width it has --------------------------------------------------------------------
  const fit = () => {
    const scale = frame.clientWidth / STAGE_WIDTH;
    if (!scale) return;
    stage.style.transform = `scale(${scale})`;
    stage.style.setProperty("--dl-u", String(1 / scale));       // handles keep their size on screen
    frame.style.height = `${Math.ceil(stage.offsetHeight * scale)}px`;
  };
  new ResizeObserver(fit).observe(stage);
  new ResizeObserver(fit).observe(frame);
  const scale = () => frame.clientWidth / STAGE_WIDTH;

  const status = () => {
    packed.setAttribute("aria-pressed", String(draft.packed === true));
    save.disabled = discard.disabled = same(draft, saved());
    reset.disabled = same(draft, defaultLayout(draft.widgets, draft.tiles));
  };
  const place = () => {
    if (!build) return;
    clear(grid, draft.cards.map(({ id, span }) => sized(cards.get(id) ?? editable(id), span)));
    pack(grid, draft.packed === true);
    clear(tray, h("span", { class: "dl-tray-head" }, "Hidden"), draft.hidden.map(chip));
    status();
  };
  const moveTo = (id: string, at: number) => {
    const from = draft.cards.findIndex((c) => c.id === id);
    const card = from >= 0 ? draft.cards.splice(from, 1)[0] : { id, span: cardInfo(id).span };
    if (from >= 0 && from < at) at--;
    draft.hidden = draft.hidden.filter((x) => x !== id);
    draft.cards.splice(Math.max(0, Math.min(at, draft.cards.length)), 0, card);
    place();
  };
  const hide = (id: string) => {
    draft.cards = draft.cards.filter((c) => c.id !== id);
    draft.hidden = [...draft.hidden, id];
    place();
  };
  const redraw = (id: string) => { cards.delete(id); place(); };          // after its title, query or result changed

  // --- dragging: onto a card (before or after it, by which half), below the last card (the end), or onto the tray --
  const mark = (el: HTMLElement | null, cls = "") => {
    cards.forEach((c) => c.classList.remove("dl-before", "dl-after"));
    grid.classList.remove("dl-end");
    if (el && cls) el.classList.add(cls);
  };
  const endDrag = () => { dragging = null; target = null; mark(null); tray.classList.remove("over"); };
  const drop = () => {
    if (dragging && target !== null) moveTo(dragging.id, target);
    endDrag();
  };
  grid.addEventListener("dragover", (e) => {
    if (!dragging) return;
    e.preventDefault();
    const last = cards.get(draft.cards[draft.cards.length - 1]?.id ?? "");
    if (!last || e.clientY > last.getBoundingClientRect().bottom) { mark(null); grid.classList.add("dl-end"); target = draft.cards.length; }
  });
  grid.addEventListener("drop", (e) => { e.preventDefault(); drop(); });
  tray.addEventListener("dragover", (e) => { if (dragging?.from !== "grid") return; e.preventDefault(); mark(null); tray.classList.add("over"); });
  tray.addEventListener("dragleave", () => tray.classList.remove("over"));
  tray.addEventListener("drop", (e) => {
    if (dragging?.from !== "grid") return;
    e.preventDefault();
    const id = dragging.id;
    endDrag();
    hide(id);
  });

  /** A handle dragged along one axis (or moved with two arrow keys), reporting where the pointer is. */
  const handle = (el: HTMLElement, cls: string, label: string, keys: [string, string], step: (by: -1 | 1) => void,
    drag: (ev: PointerEvent) => void): HTMLElement => {
    const knob = h("button", { class: cls, type: "button", title: label, "aria-label": label });
    knob.addEventListener("keydown", (e) => {
      const by = e.key === keys[0] ? -1 : e.key === keys[1] ? 1 : 0;
      if (!by) return;
      e.preventDefault();
      step(by);
    });
    knob.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      el.draggable = false;                                    // a resize, not a move
      knob.setPointerCapture(e.pointerId);
      knob.classList.add("active");
      const up = () => { knob.removeEventListener("pointermove", drag); knob.classList.remove("active"); el.draggable = true; };
      knob.addEventListener("pointermove", drag);
      knob.addEventListener("pointerup", up, { once: true });
      knob.addEventListener("pointercancel", up, { once: true });
    });
    return knob;
  };

  /** A card of the preview with its handles: move (drag it, or the arrow keys), hide, width; an SQL table's and a
   * tile's also edit and height. */
  const editable = (id: string): HTMLElement => {
    const widget = isWidget(id), tile = isTile(id);
    const el = widget ? sqlCard(id, draft.widgets![id], data?.widgets?.[id]) : tile ? tileCard(id, draft.tiles![id]) : build![id]();
    for (const child of el.children) (child as HTMLElement).inert = true;          // a picture of the card: its own controls stay still
    el.addEventListener("click", (e) => e.preventDefault());                         // a tile that opens a page does not, here
    const { name } = cardInfo(id, draft);
    const grip = h("button", { class: "dl-grip", type: "button", title: "Move", "aria-label": `Move ${name}` }, icon("grip", 16));
    const close = h("button", { class: "dl-hide", type: "button", title: "Hide", "aria-label": `Hide ${name}` }, icon("close", 16));
    const index = () => draft.cards.findIndex((c) => c.id === id);
    const resize = (span: number) => {
      const c = draft.cards[index()];
      if (!c || clampSpan(span, id) === c.span) return;
      c.span = clampSpan(span, id);
      sized(el, c.span);
      status();
    };
    grip.addEventListener("keydown", (e) => {
      const step = e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : 0;
      const i = index(), j = i + step;
      if (!step || j < 0 || j >= draft.cards.length) return;
      e.preventDefault();
      [draft.cards[i], draft.cards[j]] = [draft.cards[j], draft.cards[i]];
      place();
      grip.focus();
    });
    close.addEventListener("click", () => hide(id));
    const width = handle(el, "dl-size", `Width of ${name}`, ["ArrowLeft", "ArrowRight"], (by) => resize(draft.cards[index()].span + by), (ev) => {
      const gap = GAP * scale();
      const col = (grid.getBoundingClientRect().width - gap * (COLUMNS - 1)) / COLUMNS;
      resize(Math.round((ev.clientX - el.getBoundingClientRect().left + gap) / (col + gap)));
    });
    const tools: HTMLElement[] = [grip];
    const extra: HTMLElement[] = [];
    if (widget || tile) {
      const owner = () => (widget ? draft.widgets![id] : draft.tiles![id]);        // where its height is kept
      const setHeight = (px: number) => {
        const w = owner();
        if (clampHeight(px, id) === w.height) return;
        w.height = clampHeight(px, id);
        el.style.height = `${w.height}px`;
        status();
      };
      const edit = h("button", { class: "dl-edit", type: "button", title: "Edit", "aria-label": `Edit ${name}` }, icon("table-fill", 16));
      edit.addEventListener("click", () => (widget ? editWidget(id) : editTile(id)));
      tools.push(edit);
      extra.push(handle(el, "dl-height", `Height of ${name}`, ["ArrowUp", "ArrowDown"], (by) => setHeight(owner().height + by * 20),
        (ev) => setHeight((ev.clientY - el.getBoundingClientRect().top) / scale())));
    }
    tools.push(close);
    el.append(h("div", { class: "dl-overlay" }, h("div", { class: "dl-tools" }, tools), width, extra));
    el.classList.add("dl-card");
    el.draggable = true;
    el.addEventListener("dragstart", (e) => {
      dragging = { id, from: "grid" };
      e.dataTransfer?.setData("text/plain", id);
      if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
      requestAnimationFrame(() => el.classList.add("dragging"));
    });
    el.addEventListener("dragend", () => { el.classList.remove("dragging"); endDrag(); });
    el.addEventListener("dragover", (e) => {
      if (!dragging) return;
      e.preventDefault();
      e.stopPropagation();
      const r = el.getBoundingClientRect(), after = e.clientX > r.left + r.width / 2;
      mark(el, after ? "dl-after" : "dl-before");
      target = index() + (after ? 1 : 0);
    });
    el.addEventListener("drop", (e) => { e.preventDefault(); e.stopPropagation(); drop(); });
    cards.set(id, el);
    return el;
  };

  /** A hidden card in the tray: click to show it at the end, or drag it into place. */
  const chip = (id: string): HTMLElement => {
    const { name, glyph } = cardInfo(id, draft);
    const el = h("button", { class: "dl-chip", type: "button", draggable: "true", title: "Show", "aria-label": `Show ${name}` }, icon(glyph, 16), name, icon("plus", 14));
    el.addEventListener("click", () => moveTo(id, draft.cards.length));
    el.addEventListener("dragstart", (e) => { dragging = { id, from: "tray" }; e.dataTransfer?.setData("text/plain", id); });
    el.addEventListener("dragend", endDrag);
    return el;
  };

  /** An SQL table's title, description and query, in a dialog. Run refreshes its kept result (with the SQL password);
   * Done keeps the edits in the draft; Delete takes the table away. */
  const editWidget = async (id: string) => {
    const w = draft.widgets![id];
    let query = w.query;
    const title = h("input", { type: "text", value: w.title, placeholder: "Title", maxlength: "80", "aria-label": "Title" }) as HTMLInputElement;
    const description = h("textarea", { rows: 2, placeholder: "Description", maxlength: "2000", "aria-label": "Description" }) as HTMLTextAreaElement;
    description.value = w.description;
    const host = h("div", { class: "sql-editor-host" });
    const warning = h("div", { class: "sql-warning", role: "status" });
    const out = h("div", { class: "dl-widget-out" });
    const run = button("play", "Run", "primary"), done = button("check", "Done", "primary"), remove = button("trash", "Delete");
    const cancel = h("button", { class: "btn small", type: "button" }, "Cancel");
    const dialog = h("dialog", { class: "dl-widget", "aria-label": "SQL table" },
      h("div", { class: "dl-widget-body" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("query-sql")), h("h2", {}, "SQL table")),
        title, description, host, warning, h("div", { class: "row" }, run), out,
        h("div", { class: "row dl-widget-actions" }, remove, h("span", { class: "spacer" }), cancel, done))) as HTMLDialogElement;
    dialog.addEventListener("close", () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
    title.focus();
    const { sqlEditor, readOnlyProblem } = await import("../sql-editor");    // CodeMirror, loaded when first needed
    const check = () => {
      const problem = query.trim() ? readOnlyProblem(query) : "Write a query";
      clear(warning, problem ? [icon("lock", 14), problem] : null);
      run.disabled = Boolean(problem);
    };
    const execute = async () => {
      if (run.disabled) return;
      run.disabled = true;
      clear(out, loading("Running"));
      try {
        const r = await sqlApi("/api/dashboard/widget", { id, query });
        data.widgets = { ...(data.widgets ?? {}), [id]: r };
        clear(out, h("div", { class: "tiny muted" }, `${fmt.int(r.rows.length)} rows${r.rows.length > PREVIEW_ROWS ? ` · first ${PREVIEW_ROWS} shown` : ""}`),
          table(r.columns, r.rows.slice(0, PREVIEW_ROWS).map((row: unknown[]) => row.map((v) => (v === null ? "null" : String(v))))));
      } catch (e) {
        clear(out, isLocked(e) ? null : errorBox(e));
      } finally {
        check();
      }
    };
    sqlEditor(host, { value: query, tables: {}, onChange: (text) => { query = text; check(); }, onRun: () => void execute() });
    check();
    run.addEventListener("click", execute);
    cancel.addEventListener("click", () => dialog.close());
    done.addEventListener("click", () => {
      draft.widgets![id] = { title: title.value.trim().slice(0, 80), description: description.value.trim().slice(0, 2000), query, height: w.height };
      dialog.close();
      redraw(id);
    });
    remove.addEventListener("click", () => {
      draft.cards = draft.cards.filter((c) => c.id !== id);
      draft.hidden = draft.hidden.filter((x) => x !== id);
      delete draft.widgets![id];
      dialog.close();
      redraw(id);
    });
  };

  /** A tile's icon, heading (and its size), text, colour, alignment and page, in a dialog showing the tile as it will
   * look at its size. Done keeps the edits in the draft; Delete takes the tile away. */
  const editTile = (id: string) => {
    const tile: DashboardTile = { ...draft.tiles![id] };
    const span = draft.cards.find((c) => c.id === id)?.span ?? 1;
    const preview = h("div", { class: "dl-tile-preview" });
    preview.inert = true;
    const paint = () => {
      const card = tileCard(id, tile);
      card.style.width = `${Math.min(520, span * COLUMN_PX + (span - 1) * GAP)}px`;
      card.style.height = `${Math.min(300, tile.height)}px`;
      clear(preview, card);
    };
    const option = (on: boolean, label: string, content: Child, act: () => void) =>
      h("button", { type: "button", class: `dl-option ${on ? "on" : ""}`, "aria-pressed": String(on), title: label, "aria-label": label, onclick: act }, content);
    const icons = h("div", { class: "dl-icons" }), sizes = h("div", { class: "pills small" }), tones = h("div", { class: "dl-tones" });
    const aligns = h("div", { class: "pills small" });
    const choices = () => {
      clear(icons, option(!tile.icon, "No icon", icon("close", 16), () => set({ icon: "" })),
        TILE_ICONS.map((name) => option(tile.icon === name, name, icon(name, 18), () => set({ icon: name }))));
      clear(sizes, TILE_SIZES.map((size) => h("button", { type: "button", class: tile.size === size ? "on" : "", "aria-pressed": String(tile.size === size),
        onclick: () => set({ size }) }, size.toUpperCase())));
      clear(tones, TILE_TONES.map((tone) => option(tile.tone === tone, tone || "None", h("i", { class: `dl-swatch tone-${tone || "none"}` }), () => set({ tone }))));
      clear(aligns, (["left", "center"] as const).map((align) => h("button", { type: "button", class: tile.align === align ? "on" : "",
        "aria-pressed": String(tile.align === align), title: align === "left" ? "Left" : "Centre", "aria-label": align === "left" ? "Left" : "Centre",
        onclick: () => set({ align }) }, icon(`align-${align}`, 16))));
    };
    const set = (change: Partial<DashboardTile>) => { Object.assign(tile, change); paint(); choices(); };
    const heading = h("input", { type: "text", value: tile.heading, placeholder: "Heading", maxlength: "80", "aria-label": "Heading" }) as HTMLInputElement;
    heading.addEventListener("input", () => { tile.heading = heading.value; paint(); });
    const text = h("textarea", { rows: 3, placeholder: "Text", maxlength: "1000", "aria-label": "Text" }) as HTMLTextAreaElement;
    text.value = tile.text;
    text.addEventListener("input", () => { tile.text = text.value; paint(); });
    const link = h("select", { "aria-label": "Link" }, h("option", { value: "", selected: !tile.link }, "None"),
      TILE_LINKS.map((page) => h("option", { value: page, selected: tile.link === page }, t(`nav.${page}` as never)))) as HTMLSelectElement;
    link.addEventListener("change", () => { tile.link = link.value; paint(); });
    const field = (label: string, ...control: Child[]) => h("div", { class: "dl-field" }, h("span", { class: "small muted" }, label), ...control);
    const done = button("check", "Done", "primary"), remove = button("trash", "Delete");
    const cancel = h("button", { class: "btn small", type: "button" }, "Cancel");
    const dialog = h("dialog", { class: "dl-widget dl-tile-dialog", "aria-label": "Tile" },
      h("div", { class: "dl-widget-body" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("note")), h("h2", {}, "Tile")),
        preview,
        h("div", { class: "dl-tile-form" },
          field("Icon", icons),
          h("div", { class: "dl-tile-row" }, field("Heading", heading), field("Size", sizes)),
          field("Text", text),
          h("div", { class: "dl-tile-row" }, field("Colour", tones), field("Align", aligns), field("Link", link))),
        h("div", { class: "row dl-widget-actions" }, remove, h("span", { class: "spacer" }), cancel, done))) as HTMLDialogElement;
    dialog.addEventListener("close", () => dialog.remove());
    cancel.addEventListener("click", () => dialog.close());
    done.addEventListener("click", () => {
      draft.tiles![id] = { ...tile, heading: tile.heading.trim().slice(0, 80), text: tile.text.replace(/\s+$/, "").slice(0, 1000) };
      dialog.close();
      redraw(id);
    });
    remove.addEventListener("click", () => {
      draft.cards = draft.cards.filter((c) => c.id !== id);
      draft.hidden = draft.hidden.filter((x) => x !== id);
      delete draft.tiles![id];
      dialog.close();
      redraw(id);
    });
    paint();
    choices();
    document.body.append(dialog);
    dialog.showModal();
    heading.focus();
  };

  addTile.addEventListener("click", () => {
    const id = newTileId();
    draft.tiles = { ...(draft.tiles ?? {}), [id]: newTile() };
    draft.cards.push({ id, span: 1 });
    place();
    editTile(id);
  });
  add.addEventListener("click", () => {
    const id = newWidgetId();
    draft.widgets = { ...(draft.widgets ?? {}), [id]: newWidget() };
    draft.cards.push({ id, span: WIDGET_SPAN });
    place();
    void editWidget(id);
  });
  packed.addEventListener("click", () => { draft.packed = !draft.packed; place(); });
  discard.addEventListener("click", () => { draft = saved(); cards.clear(); place(); });
  reset.addEventListener("click", () => { draft = defaultLayout(draft.widgets, draft.tiles); place(); });
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      await updateSettings({ dashboard_layout: same(draft, defaultLayout()) ? null : draft });
      clear(err);
    } catch (e) {
      clear(err, errorBox(e));
    }
    status();
  });

  clear(box,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("dashboard")), h("h2", {}, "Dashboard")),
    h("div", { class: "dl-bar" }, tray, addTile, add, packed, discard, reset, save),          // stays in view while the preview scrolls
    err, frame);
  status();
  api("/api/dashboard").then((d) => { data = d; build = dashboardCards(d); place(); }, (e) => clear(grid, errorBox(e)));
}
