// Adjacent development workspace. Portable flow documents are planned here and executed by registered Python
// operators; the existing console's review data and trained DAD models are independent from experiment artifacts.
import "../pipeline-studio.css";
import { clear, h, svg, table, type Child } from "../dom";
import { icon } from "../icons";
import { api, qs } from "../api";
import { sqlApi } from "../sql-lock";
import { state } from "../state";
import {
  BLOCKS, BLOCK_FIELDS, blockOf, compatible, createNode, emptyDraft, parseDraft, starterDraft, validateDraft,
  type BlockKind, type PipelineDraft, type PipelineNode, type PipelinePreview, type PreviewResult,
} from "../pipeline-flow";

const STORAGE_KEY = "dad.pipeline-studio.draft.v1";
const NODE_WIDTH = 210;
const PORT_Y = 54;
const clone = (value: PipelineDraft): PipelineDraft => structuredClone(value);
const snap = (n: number) => Math.round(n / 16) * 16;
type BottomTab = "preview" | "validation" | "log";
type StudioResult = Omit<PipelinePreview, "results"> & { id?: string; storage?: string; mode?: string; seconds?: number; bytes_saved?: number;
  results: (PreviewResult & { meta?: Record<string, unknown>; retained?: boolean; executor?: string; seconds?: number })[] };

function readDraft(): { draft: PipelineDraft; error: string } {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return { draft: saved ? parseDraft(JSON.parse(saved)) : starterDraft(), error: "" };
  } catch {
    return { draft: starterDraft(), error: "The saved draft could not be opened. A sample flow is shown; import a JSON copy to recover another draft." };
  }
}

function dadTemplate(): PipelineDraft {
  const draft = emptyDraft();
  draft.name = "Project DAD · from logs to evidence";
  const kinds: BlockKind[] = ["raw", "classify", "observations", "features", "detect", "evidence", "report"];
  draft.nodes = kinds.map((kind, i) => createNode(kind, 64 + (i % 4) * 280, 96 + Math.floor(i / 4) * 224));
  draft.edges = draft.nodes.slice(1).map((node, i) => ({ id: `dad-edge-${i}`, from: draft.nodes[i].id, to: node.id }));
  return draft;
}

function supervisedTemplate(): PipelineDraft {
  const draft = emptyDraft();
  draft.name = "Six labels · train and evaluate";
  const kinds: BlockKind[] = ["csv", "labels", "supervised", "evaluate"];
  draft.nodes = kinds.map((kind, i) => createNode(kind, 64 + Math.min(i, 2) * 280, i === 3 ? 288 : 80));
  draft.nodes[0].config.csv = "signal_a,signal_b,target\n" + Array.from({ length: 120 }, (_, i) => `${i % 6 * 10 + i % 3},${i % 6 * 2 + i % 2},${i % 6}`).join("\n");
  draft.nodes[1].config = { column: "target", mapping: "{}" };
  draft.nodes[2].config = { algorithm: "random_forest", label_column: "target", features: "signal_a,signal_b", test_fraction: "0.2" };
  draft.nodes[3].config = { method: "classification", label_column: "target", prediction_column: "prediction", score_column: "score" };
  draft.edges = draft.nodes.slice(1).map((node, i) => ({ id: `supervised-edge-${i}`, from: draft.nodes[i].id, to: node.id }));
  return draft;
}

export function renderPipelines(main: HTMLElement): void {
  const loaded = readDraft();
  let draft = loaded.draft;
  let selected = draft.nodes[0]?.id ?? "";
  let selectedEdge = "";
  let connecting = "";
  let search = "";
  let category = "All";
  let bottomTab: BottomTab = "preview";
  let validation: ReturnType<typeof validateDraft> | null = null;
  let preview: StudioResult | null = null;
  let running = false;
  let runningNode = "";
  let portDragging = false;
  let resultNode = "";
  let storageFailed = false;
  const history: PipelineDraft[] = [];
  const future: PipelineDraft[] = [];
  const view = { x: 40, y: 30, zoom: 0.75 };
  const nodes = new Map<string, HTMLElement>();
  const markerId = `ps-arrow-${Math.random().toString(36).slice(2)}`;

  const notice = h("div", { class: "ps-notice", role: "status", "aria-live": "polite", hidden: !loaded.error }, loaded.error);
  const library = h("div", { class: "ps-library-list" });
  const inspector = h("aside", { class: "ps-inspector", "aria-label": "Block settings" });
  const connections = svg("svg", { class: "ps-edges", width: 2400, height: 1600, "aria-label": "Pipeline connections" });
  const nodeLayer = h("div", { class: "ps-node-layer" });
  const world = h("div", { class: "ps-world" }, connections, nodeLayer);
  const canvas = h("div", { class: "ps-canvas", tabindex: "0", role: "region", "aria-label": "Pipeline canvas. Drag blocks to move; drag the background to pan. Use the zoom controls to change scale." }, world);
  const emptyCanvas = h("div", { class: "ps-canvas-empty" });
  const canvasHint = h("div", { class: "ps-canvas-hint", "aria-live": "polite" });
  const mini = svg("svg", { class: "ps-minimap", width: 112, height: 68, "aria-label": "Flow overview", role: "img" });
  const zoomLabel = h("span", {}, "75%");
  const bottom = h("section", { class: "ps-bottom", "aria-label": "Pipeline preview and validation" });
  const footer = h("div", { class: "ps-footer" });
  const draftState = h("span", { class: "ps-draft-state" }, "Browser draft");
  const graphState = h("span", { class: "ps-summary-chip" }, "Not checked");
  const undoButton = action("Undo", "history", undo, true);
  const redoButton = action("Redo", "refresh", redo, true);
  const name = h("input", { class: "ps-flow-name", value: draft.name, "aria-label": "Pipeline name", maxlength: 120 });
  name.addEventListener("change", () => commit(() => { draft.name = name.value.trim() || "Untitled pipeline"; }, false));

  function action(label: string, glyph: string, run: () => void, small = false): HTMLButtonElement {
    return h("button", { type: "button", class: small ? "icon-btn" : "btn", title: label, "aria-label": label, onclick: run }, icon(glyph, 16), small ? null : label);
  }

  function announce(message: string, bad = false): void {
    notice.hidden = false;
    notice.classList.toggle("error", bad);
    notice.textContent = message;
  }

  function persist(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(draft));
      storageFailed = false;
    } catch {
      storageFailed = true;
      announce("Browser storage is unavailable or full. Export JSON to keep this draft.", true);
    }
    draftState.textContent = storageFailed ? "Not saved · export JSON" : "Saved in this browser";
  }

  function resetResults(): void {
    validation = null;
    preview = null;
    resultNode = "";
  }

  function remember(before = clone(draft)): void {
    history.push(before);
    if (history.length > 50) history.shift();
    future.length = 0;
  }

  function commit(change: () => void, redrawInspector = true): void {
    if (running) return announce("Wait for the active run to finish before editing the flow.");
    remember();
    change();
    resetResults();
    persist();
    draw(redrawInspector);
  }

  function undo(): void {
    if (running) return;
    const previous = history.pop();
    if (!previous) return;
    future.push(clone(draft));
    draft = previous;
    resetResults();
    if (!draft.nodes.some((node) => node.id === selected)) selected = "";
    persist();
    draw();
  }

  function redo(): void {
    if (running) return;
    const next = future.pop();
    if (!next) return;
    history.push(clone(draft));
    draft = next;
    resetResults();
    persist();
    draw();
  }

  function replaceDraft(next: PipelineDraft): void {
    if (running) return announce("Wait for the current run to finish before replacing its flow.");
    remember();
    draft = next;
    selected = draft.nodes[0]?.id ?? "";
    selectedEdge = connecting = "";
    resetResults();
    persist();
    draw();
    requestAnimationFrame(fit);
  }

  const templates = h("select", { class: "ps-template", "aria-label": "Load a pipeline template" },
    h("option", { value: "" }, "Templates"),
    h("option", { value: "sanity" }, "Sample sanity check"),
    h("option", { value: "supervised" }, "Supervised learning · 6 labels"),
    h("option", { value: "dad" }, "Project DAD phases"),
    h("option", { value: "blank" }, "Blank canvas"));
  templates.addEventListener("change", () => {
    if (!templates.value) return;
    replaceDraft(templates.value === "dad" ? dadTemplate() : templates.value === "supervised" ? supervisedTemplate() : templates.value === "blank" ? emptyDraft() : starterDraft());
    templates.value = "";
    announce("Template loaded. Undo restores your previous flow.");
  });
  const importer = h("input", { type: "file", accept: ".json,application/json", hidden: true, "aria-label": "Import pipeline JSON file" });
  importer.addEventListener("change", () => void importDraft());

  async function importDraft(): Promise<void> {
    const file = importer.files?.[0];
    if (!file) return;
    try {
      if (file.size > 1_000_000) throw new Error("Choose a pipeline JSON file smaller than 1 MB.");
      replaceDraft(parseDraft(JSON.parse(await file.text())));
      announce(`Opened ${file.name}. The draft is saved in this browser.`);
    } catch (error) {
      announce(error instanceof Error ? error.message : "This pipeline file could not be opened.", true);
    }
    importer.value = "";
  }

  function exportDraft(): void {
    const executable = { ...draft, execution: { engine: "studio.python.v1", operators: Object.fromEntries(draft.nodes.map((node) => [node.id, blockOf(node.kind).executor])) } };
    const url = URL.createObjectURL(new Blob([JSON.stringify(executable, null, 2) + "\n"], { type: "application/json" }));
    const filename = draft.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 70) || "pipeline";
    const link = h("a", { href: url, download: `${filename}.pipeline.json` });
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    announce("Pipeline exported as JSON. It contains your blocks and settings, with no execution results.");
  }

  function checkFlow(): void {
    validation = validateDraft(draft);
    bottomTab = "validation";
    draw();
    announce(validation.valid ? "Flow structure checked. Preview a sample to check its data." : "The flow needs attention. Select an issue below to find its block.", !validation.valid);
  }

  async function waitJob<T>(job: string): Promise<T> {
    for (;;) {
      const item = await api<{ status: string; error: string; result: T; steps: { step: string; detail: string }[] }>(`/api/analyze/job${qs({ id: job })}`);
      if (!canvas.isConnected) throw new Error("The run continues in the background. Open Run history to inspect its result.");
      const current = item.steps.at(-1);
      if (current && current.step !== runningNode) { runningNode = current.step; drawNodes(); drawEdges(); }
      if (item.status === "done") return item.result;
      if (item.status === "failed") throw new Error(item.error);
      await new Promise((resolve) => window.setTimeout(resolve, 450));
    }
  }

  async function studioRequest<T>(path: string, body: Record<string, unknown>): Promise<T> {
    return draft.nodes.some((node) => node.kind === "database") ? sqlApi<T>(path, body) : api<T>(path, { body });
  }

  async function execute(mode: "sample" | "full"): Promise<void> {
    if (running) return;
    flushInspector();
    validation = validateDraft(draft);
    if (!validation.valid) { bottomTab = "validation"; draw(); announce("Resolve the flow checks before execution.", true); return; }
    running = true;
    runningNode = "";
    drawFooter();
    announce(mode === "sample" ? "Running the flow on a bounded sample…" : "Running the full supplied input…");
    try {
      const started = await studioRequest<{ job?: string; validation?: ReturnType<typeof validateDraft> }>("/api/studio/run", { draft, mode });
      if (started.validation) { validation = started.validation; bottomTab = "validation"; draw(); return; }
      preview = await waitJob<StudioResult>(started.job!);
      bottomTab = preview.valid ? "preview" : "validation";
      resultNode = preview.results.filter((result) => result.status === "passed").at(-1)?.nodeId ?? "";
      draw();
      announce(!preview.valid ? "Sample preview found an issue. Review the checks below."
        : `${mode === "sample" ? "Sample" : "Full"} run complete · ${preview.seconds ?? 0}s · ${preview.storage === "memory" ? "intermediates in memory" : "outputs retained"}. Select a block to inspect its output.`, !preview.valid);
    } catch (error) {
      announce(error instanceof Error ? error.message : "The flow could not run.", true);
    } finally {
      running = false;
      runningNode = "";
      if (canvas.isConnected) { drawNodes(); drawFooter(); }
    }
  }

  function runPreview(): void { void execute("sample"); }

  function flushInspector(): void {
    const active = document.activeElement;
    if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement || active instanceof HTMLSelectElement) active.blur();
  }

  function modal(title: string, body: Child, actions: Child = null): HTMLDialogElement {
    const dialog = h("dialog", { class: "ps-dialog", "aria-label": title }, h("div", { class: "ps-dialog-head" }, h("h2", {}, title),
      action("Close dialog", "close", () => dialog.close(), true)), h("div", { class: "ps-dialog-body" }, body), h("div", { class: "ps-dialog-actions" }, actions));
    dialog.addEventListener("close", () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
    return dialog;
  }

  function editJson(): void {
    flushInspector();
    const editor = h("textarea", { class: "ps-json", value: JSON.stringify(draft, null, 2), spellcheck: "false", "aria-label": "Pipeline JSON", maxlength: 1_000_000 });
    const errors = h("div", { role: "alert" });
    const dialog = modal("Pipeline JSON", h("div", {}, h("p", { class: "small muted" }, "Edit blocks, configuration and connections directly. Applying JSON runs the same document checks as importing a file."), editor, errors),
      action("Apply JSON", "check", () => { try { replaceDraft(parseDraft(JSON.parse(editor.value))); dialog.close(); announce("Pipeline JSON applied."); } catch (error) { errors.textContent = String(error); } }));
  }

  async function labelDialog(node: PipelineNode): Promise<void> {
    flushInspector();
    if (!node.config.column) return announce("Choose the label column before scanning.", true);
    const content = h("div", {}, h("p", {}, "Scanning the upstream data for distinct labels…"));
    const dialog = modal("Discover & name labels", content);
    try {
      const started = await studioRequest<{ job: string }>("/api/studio/labels", { draft, node_id: node.id, column: node.config.column });
      const result = await waitJob<{ values: string[]; rows: number; truncated: boolean }>(started.job);
      const mapping = JSON.parse(node.config.mapping || "{}") as Record<string, string>;
      const inputs = result.values.map((value) => ({ value, input: h("input", { value: mapping[value] ?? "", placeholder: "What does this label mean?", "aria-label": `Meaning of label ${value}`, maxlength: 200 }) }));
      const save = action("Save label meanings", "check", () => {
        commit(() => { node.config.mapping = JSON.stringify(Object.fromEntries(inputs.map(({ value, input }) => [value, input.value]))); });
        dialog.close();
        announce(`Named ${result.values.length} labels from ${node.config.column}.`);
      });
      clear(content, h("p", {}, `Found ${result.values.length} distinct labels across ${result.rows.toLocaleString()} rows in “${node.config.column}”: `,
        h("strong", {}, result.values.join(", "))), result.truncated ? h("p", { class: "error" }, "The upstream source was truncated. These values may not cover the complete dataset.") : null,
        inputs.map(({ value, input }) => h("label", { class: "ps-label-row" }, h("code", {}, value), input)), save);
    } catch (error) { clear(content, h("div", { class: "error" }, error instanceof Error ? error.message : String(error))); }
    finally { runningNode = ""; drawNodes(); }
  }

  async function runHistory(): Promise<void> {
    const content = h("div", {}, "Loading runs…");
    const dialog = modal("Run history", content);
    try {
      const result = await api<{ runs: { id: string; name: string; valid: boolean; mode: string; storage: string; seconds: number; created_at: string }[] }>("/api/studio/runs");
      clear(content, result.runs.length ? result.runs.map((run) => h("button", { class: "ps-history-row", type: "button", onclick: async () => {
        try {
          const saved = await api<StudioResult & { draft: PipelineDraft }>(`/api/studio/run${qs({ id: run.id })}`);
          replaceDraft(parseDraft(saved.draft));
          preview = saved;
          bottomTab = "preview";
          resultNode = saved.results.at(-1)?.nodeId ?? "";
          draw();
          dialog.close();
        } catch (error) { announce(String(error), true); }
      } }, icon(run.valid ? "check-circle" : "alert", 16), h("strong", {}, run.name), h("span", {}, `${run.mode} · ${run.storage} · ${run.seconds}s`),
        h("time", {}, new Date(run.created_at).toLocaleString()))) : h("p", {}, "Run a flow to start its history."));
    } catch (error) { clear(content, h("p", { class: "error" }, String(error))); }
  }

  function addBlock(kind: BlockKind, x?: number, y?: number): void {
    if (draft.nodes.length >= 100) return announce("This draft can hold up to 100 blocks.", true);
    const rect = canvas.getBoundingClientRect();
    const node = createNode(kind,
      snap(x ?? (rect.width / 2 - view.x) / view.zoom - NODE_WIDTH / 2 + (draft.nodes.length % 3) * 24),
      snap(y ?? (rect.height / 2 - view.y) / view.zoom - 54 + (draft.nodes.length % 3) * 24));
    commit(() => { draft.nodes.push(node); selected = node.id; selectedEdge = connecting = ""; });
    announce(`${blockOf(kind).label} added. Connect its ports to another block.`);
  }

  function removeNode(id = selected): void {
    if (!id) return;
    const label = draft.nodes.find((node) => node.id === id)?.label ?? "Block";
    commit(() => {
      draft.nodes = draft.nodes.filter((node) => node.id !== id);
      draft.edges = draft.edges.filter((edge) => edge.from !== id && edge.to !== id);
      selected = selectedEdge = connecting = "";
    });
    announce(`${label} removed. Undo is available.`);
  }

  function connect(from: string, to: string): void {
    const source = draft.nodes.find((node) => node.id === from);
    const target = draft.nodes.find((node) => node.id === to);
    if (!source || !target || source.id === target.id) return announce("Choose a different block for this connection.", true);
    if (!blockOf(source.kind).output || !blockOf(target.kind).input) return announce("This port cannot receive that connection.", true);
    if (!compatible(source.kind, target.kind)) {
      return announce(`${source.label} outputs ${blockOf(source.kind).output}; ${target.label} needs ${blockOf(target.kind).input}. Choose matching ports.`, true);
    }
    if (draft.edges.some((edge) => edge.from === from && edge.to === to)) return announce("These blocks are already connected.");
    if (draft.edges.some((edge) => edge.to === to)) return announce("This block already has an input. Remove its existing connection first.", true);
    const edge = { id: crypto.randomUUID(), from, to };
    const proposed = { ...draft, edges: [...draft.edges, edge] };
    const cycle = validateDraft(proposed).issues.find((issue) => issue.severity === "error" && /cycle|circular/i.test(issue.message));
    if (cycle) return announce("That connection would create a cycle. Connect blocks in one direction.", true);
    commit(() => { draft.edges.push(edge); connecting = ""; selected = to; selectedEdge = ""; });
    announce(`${source.label} connected to ${target.label}.`);
  }

  function choose(id: string): void {
    flushInspector();
    selected = id;
    selectedEdge = "";
    if (preview?.results.some((result) => result.nodeId === id)) resultNode = id;
    drawSelection();
    drawInspector();
    drawBottom();
    drawMap();
  }

  function drawLibrary(): void {
    const matches = BLOCKS.filter((block) => (category === "All" || block.category === category)
      && `${block.label} ${block.description} ${block.phase ?? ""}`.toLowerCase().includes(search.toLowerCase()));
    const sections = [...new Set(matches.map((block) => block.category))];
    clear(library, matches.length ? sections.map((section) => h("div", { class: "ps-category" }, h("h3", {}, section),
      matches.filter((block) => block.category === section).map((block) => {
        const button = h("button", { type: "button", class: "ps-library-block", draggable: "true", "data-kind": block.kind,
          "data-category": block.category, title: `${block.description} Click to add, or drag onto the canvas.`, onclick: () => addBlock(block.kind) },
        h("span", { class: "ps-block-icon" }, icon(block.icon, 18)),
        h("span", { class: "ps-library-copy" }, h("strong", {}, block.label), h("small", {}, block.phase ?? block.description)),
        h("span", { class: "ps-add", "aria-hidden": "true" }, icon("plus", 12)));
        button.addEventListener("dragstart", (event) => {
          event.dataTransfer?.setData("application/x-dad-block", block.kind);
          if (event.dataTransfer) event.dataTransfer.effectAllowed = "copy";
        });
        return button;
      }))) : h("p", { class: "small muted", style: { padding: "16px" } }, "No matching blocks. Try another search."));
  }

  function nodeDetail(node: PipelineNode): string {
    if (node.kind === "sql") return node.config.query?.replace(/\s+/g, " ") || "Choose columns from a table";
    if (node.kind === "filter") return `${node.config.field || "field"} ${{ equals: "=", not_equals: "≠", contains: "contains", greater_than: ">", less_than: "<" }[node.config.operator] || node.config.operator || "="} ${node.config.value || "…"}`;
    if (node.kind === "check") return `At least ${node.config.min_rows || "1"} row · required columns`;
    if (node.kind === "output") return node.config.name || "Inspect the resulting table";
    return blockOf(node.kind).description;
  }

  function drawNodes(): void {
    nodes.clear();
    clear(nodeLayer, draft.nodes.map((node, index) => {
      const block = blockOf(node.kind);
      const result = preview?.results.find((item) => item.nodeId === node.id);
      const issue = validation?.issues.find((item) => item.nodeId === node.id && item.severity === "error");
      const status = runningNode === node.id ? "Executing…" : result ? result.status === "passed" ? `${result.rows} rows · ${result.retained ? "saved" : "in memory"}` : result.status === "skipped" ? "Upstream failed" : "Check failed"
        : issue ? "Needs attention" : block.phase ? `${block.phase} · ${block.executor}` : `${block.input ?? "source"} → ${block.output ?? "output"}`;
      const el = h("div", { class: `ps-node${selected === node.id ? " selected" : ""}`, "data-id": node.id, "data-category": block.category,
        "data-status": runningNode === node.id ? "running" : result?.status ?? (issue ? "failed" : "idle"), tabindex: "0", role: "group", "aria-label": `${node.label}. ${block.label} block.`,
        style: { left: `${node.x}px`, top: `${node.y}px` } },
      h("div", { class: "ps-node-category" }, block.category, h("span", { class: "ps-node-index" }, String(index + 1).padStart(2, "0"))),
      h("div", { class: "ps-node-top" }, h("span", { class: "ps-block-icon" }, icon(block.icon, 20)), h("strong", { class: "ps-node-title" }, node.label)),
      h("div", { class: "ps-node-detail", title: nodeDetail(node) }, nodeDetail(node)),
      h("div", { class: "ps-node-status" }, result?.status === "passed" ? icon("check-circle", 12) : issue ? icon("alert", 12) : icon("table", 12), status));
      if (block.input) el.append(h("button", { type: "button", class: "ps-port in", title: `Input: ${block.input}`, "aria-label": `Connect input of ${node.label}`,
        onclick: (event: Event) => { event.stopPropagation(); if (connecting) connect(connecting, node.id); else { choose(node.id); announce("Choose an output port first, or use Connect from in Block settings."); } } }));
      if (block.output) el.append(h("button", { type: "button", class: `ps-port out${connecting === node.id ? " armed" : ""}`, title: `Output: ${block.output}`, "aria-label": `Connect output of ${node.label}`,
        onpointerdown: (event: PointerEvent) => beginPortDrag(event, node.id),
        onclick: (event: Event) => { event.stopPropagation(); if (portDragging) return; connecting = connecting === node.id ? "" : node.id; choose(node.id); drawSelection(); drawHints(); } }));
      el.addEventListener("pointerdown", (event) => beginNodeDrag(event, node, el));
      el.addEventListener("keydown", (event) => {
        if (event.target !== el) return;
        const direction: Record<string, [number, number]> = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
        if (direction[event.key]) {
          event.preventDefault();
          const [dx, dy] = direction[event.key];
          commit(() => { node.x += dx * (event.shiftKey ? 64 : 16); node.y += dy * (event.shiftKey ? 64 : 16); }, false);
          nodes.get(node.id)?.focus();
        } else if (event.key === "Enter") { choose(node.id); inspector.querySelector<HTMLInputElement>("input")?.focus(); }
      });
      nodes.set(node.id, el);
      return el;
    }));
    emptyCanvas.hidden = draft.nodes.length > 0;
    if (!draft.nodes.length) clear(emptyCanvas, icon("pipelines", 32), h("strong", {}, "Start with a source"), h("p", {}, "Drag a block here, or choose one from the library."),
      action("Add SQL query", "query-sql", () => addBlock("sql")));
  }

  function beginNodeDrag(event: PointerEvent, node: PipelineNode, el: HTMLElement): void {
    if (running || event.button !== 0 || (event.target as Element).closest("button")) return;
    event.preventDefault();
    event.stopPropagation();
    choose(node.id);
    el = nodes.get(node.id) ?? el;
    const before = clone(draft), startX = event.clientX, startY = event.clientY, x = node.x, y = node.y;
    let moved = false;
    el.setPointerCapture(event.pointerId);
    el.classList.add("dragging");
    const move = (next: PointerEvent) => {
      if (Math.hypot(next.clientX - startX, next.clientY - startY) < 3 && !moved) return;
      moved = true;
      node.x = snap(x + (next.clientX - startX) / view.zoom);
      node.y = snap(y + (next.clientY - startY) / view.zoom);
      el.style.left = `${node.x}px`;
      el.style.top = `${node.y}px`;
      drawEdges();
      drawMap();
    };
    const end = () => {
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", end);
      el.removeEventListener("pointercancel", end);
      el.classList.remove("dragging");
      if (moved) { remember(before); persist(); drawFooter(); }
      el.focus();
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", end);
    el.addEventListener("pointercancel", end);
  }

  function beginPortDrag(event: PointerEvent, from: string): void {
    if (running || event.button !== 0) return;
    event.stopPropagation();
    const start = { x: event.clientX, y: event.clientY };
    canvas.setPointerCapture(event.pointerId);
    const move = (next: PointerEvent) => {
      if (!portDragging && Math.hypot(next.clientX - start.x, next.clientY - start.y) < 4) return;
      portDragging = true;
      connecting = from;
      drawSelection();
      drawHints();
      const node = draft.nodes.find((item) => item.id === from)!;
      const rect = canvas.getBoundingClientRect();
      const x = (next.clientX - rect.left - view.x) / view.zoom, y = (next.clientY - rect.top - view.y) / view.zoom;
      connections.append(svg("path", { class: "ps-edge connect-draft", d: `M ${node.x + NODE_WIDTH} ${node.y + PORT_Y} C ${node.x + NODE_WIDTH + 80} ${node.y + PORT_Y}, ${x - 80} ${y}, ${x} ${y}`, fill: "none" }));
    };
    const end = (next: PointerEvent) => {
      canvas.removeEventListener("pointermove", move);
      canvas.removeEventListener("pointerup", end);
      canvas.removeEventListener("pointercancel", end);
      if (portDragging) {
        const target = document.elementFromPoint(next.clientX, next.clientY)?.closest<HTMLElement>(".ps-port.in")?.closest<HTMLElement>(".ps-node");
        if (target?.dataset.id) connect(from, target.dataset.id);
        else announce("Drop onto a compatible input port, or click the input to finish connecting.");
        drawEdges();
      }
      window.setTimeout(() => { portDragging = false; }, 0);
    };
    canvas.addEventListener("pointermove", move);
    canvas.addEventListener("pointerup", end);
    canvas.addEventListener("pointercancel", end);
  }

  function drawSelection(): void {
    nodes.forEach((el, id) => {
      el.classList.toggle("selected", id === selected);
      el.querySelector(".ps-port.out")?.classList.toggle("armed", id === connecting);
    });
    drawEdges();
  }

  function drawEdges(): void {
    const byId = new Map(draft.nodes.map((node) => [node.id, node]));
    clear(connections, svg("defs", {}, svg("marker", { id: markerId, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse" },
      svg("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "currentColor" }))));
    draft.edges.forEach((edge) => {
      const from = byId.get(edge.from), to = byId.get(edge.to);
      if (!from || !to) return;
      const x1 = from.x + NODE_WIDTH, y1 = from.y + PORT_Y, x2 = to.x, y2 = to.y + PORT_Y;
      const bend = Math.max(64, Math.abs(x2 - x1) * 0.45);
      const d = `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`;
      const hit = svg("path", { class: "ps-edge-hit", d, fill: "none", stroke: "transparent", "stroke-width": 18, "pointer-events": "stroke", tabindex: "0", role: "button",
        "aria-label": `Connection from ${from.label} to ${to.label}` });
      const select = () => { selectedEdge = edge.id; selected = connecting = ""; drawSelection(); drawInspector(); drawHints(); };
      hit.addEventListener("click", (event) => { event.stopPropagation(); select(); });
      hit.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); } });
      connections.append(hit, svg("path", { class: `ps-edge${selectedEdge === edge.id ? " selected" : ""}${edge.from === selected || edge.to === selected || edge.from === runningNode ? " active" : ""}`, d, fill: "none", "marker-end": `url(#${markerId})`, "pointer-events": "none" }));
    });
  }

  function drawInspector(): void {
    const node = draft.nodes.find((item) => item.id === selected);
    const edge = draft.edges.find((item) => item.id === selectedEdge);
    const head = h("div", { class: "ps-panel-head" }, h("span", { class: "ps-eyebrow" }, "Configuration"), icon("settings", 16));
    if (!node) {
      clear(inspector, head, edge ? h("div", { class: "ps-inspector-section" }, h("h3", {}, "Connection"),
        h("p", { class: "small" }, `${draft.nodes.find((n) => n.id === edge.from)?.label} → ${draft.nodes.find((n) => n.id === edge.to)?.label}`),
        action("Remove connection", "trash", () => commit(() => { draft.edges = draft.edges.filter((e) => e.id !== edge.id); selectedEdge = ""; })))
        : h("div", { class: "ps-empty-inspector" }, icon("settings", 28), h("strong", {}, "Make it your flow"), h("p", {}, "Select a block to change its settings, inspect its ports, or connect it to another step."),
          h("a", { href: "#/docs/app/08_pipeline_studio" }, "Open the Studio guide ", icon("arrow", 13))));
      return;
    }
    const block = blockOf(node.kind);
    const title = h("input", { value: node.label, maxlength: 100, "aria-label": "Block name" });
    title.addEventListener("change", () => commit(() => { node.label = title.value.trim() || block.label; }, false));
    const fields = BLOCK_FIELDS[node.kind].filter((field) => {
      if (node.kind === "parse") {
        const method = node.config.method;
        if (field.key === "regex") return method === "regex";
        if (field.key === "classifications") return method === "manual";
        if (["provider", "endpoint", "model", "token_env", "prompt"].includes(field.key)) return method === "llm" || method === "llm_regex";
      }
      return true;
    }).map((field) => {
      let control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
      if (field.type === "select") control = h("select", { "aria-label": field.label }, (field.options ?? []).map((option) => h("option", { value: option.value, selected: node.config[field.key] === option.value }, option.label)));
      else if (field.type === "textarea") control = h("textarea", { rows: field.key === "query" ? 7 : 4, value: node.config[field.key] ?? "", spellcheck: "false", "aria-label": field.label, maxlength: field.maxLength ?? 20000 });
      else control = h("input", { type: field.type === "number" ? "number" : "text", value: node.config[field.key] ?? "", "aria-label": field.label, maxlength: field.maxLength ?? 20000 });
      control.addEventListener("change", () => commit(() => { node.config[field.key] = control.value; }, field.key === "method"));
      return h("label", { class: "ps-field" }, h("span", {}, field.label), control, field.help ? h("small", {}, field.help) : null);
    });
    const incoming = draft.edges.filter((item) => item.to === node.id);
    const outgoing = draft.edges.filter((item) => item.from === node.id);
    const candidates = draft.nodes.filter((other) => other.id !== node.id && compatible(other.kind, node.kind));
    const from = h("select", { "aria-label": "Connect from block" }, h("option", { value: "" }, "Choose an upstream block"), candidates.map((other) => h("option", { value: other.id }, other.label)));
    const connectButton = action("Connect", "link", () => { if (from.value) connect(from.value, node.id); else announce("Choose an upstream block first."); });
    clear(inspector, head,
      h("div", { class: "ps-selection-head", "data-category": block.category }, h("span", { class: "ps-block-icon" }, icon(block.icon, 22)),
        h("div", {}, h("strong", {}, block.label), h("div", { class: "ps-selection-subtitle" }, block.phase ? `Project DAD · ${block.phase}` : `${block.category} block`))),
      h("div", { class: "ps-inspector-section" }, h("label", { class: "ps-field" }, h("span", {}, "Block name"), title), fields),
      node.kind === "csv" || node.kind === "raw" ? h("div", { class: "ps-inspector-section" }, action("Import file", "upload", () => {
        const file = h("input", { type: "file", accept: node.kind === "csv" ? ".csv,text/csv" : ".log,.txt,text/plain" });
        file.addEventListener("change", async () => {
          const chosen = file.files?.[0]; if (!chosen) return;
          if (chosen.size > 1_000_000) return announce("Choose an input file smaller than 1 MB for this local release.", true);
          const text = await chosen.text(); commit(() => { node.config[node.kind === "csv" ? "csv" : "text"] = text; });
        });
        file.click();
      })) : null,
      node.kind === "labels" ? h("div", { class: "ps-inspector-section" }, action("Discover & name labels", "sign", () => void labelDialog(node))) : null,
      node.kind === "evaluate" ? h("div", { class: "ps-inspector-section ps-metric-guide" }, h("h3", {}, "What is measured"),
        h("p", {}, node.config.method === "classification" ? "Accuracy · balanced accuracy · precision · recall · F1 · confusion matrix · ROC AUC and average precision for binary scores."
          : node.config.method === "regression" ? "MAE · MSE · RMSE · R²"
            : node.config.method === "clustering" ? "Silhouette · Davies–Bouldin · Calinski–Harabasz"
              : "Flagged share · score percentiles. These describe workload, not attack detection accuracy.")) : null,
      h("div", { class: "ps-inspector-section" }, h("h3", {}, "Data contract"), h("div", { class: "ps-contract" }, h("span", {}, block.input ?? "Source"), icon("arrow", 12), h("span", {}, block.output ?? "Result")),
        h("code", { class: "ps-executor" }, block.executor),
        h("p", { class: "small muted" }, "Registered Python execution · sample and full runs use the same operator.")),
      h("div", { class: "ps-inspector-section" }, h("h3", {}, "Connections"),
        [...incoming, ...outgoing].map((connection) => h("div", { class: "ps-connection-row" }, h("span", {}, incoming.includes(connection) ? `From ${draft.nodes.find((other) => other.id === connection.from)?.label}` : `To ${draft.nodes.find((other) => other.id === connection.to)?.label}`),
          action("Remove connection", "close", () => commit(() => { draft.edges = draft.edges.filter((item) => item.id !== connection.id); }), true))),
        !incoming.length && block.input ? h("div", { class: "ps-connect-form" }, from, connectButton) : null,
        !incoming.length && !outgoing.length ? h("p", { class: "small muted" }, "Click an output port, then the next block’s input port.") : null),
      h("div", { class: "ps-inspector-section" }, h("button", { type: "button", class: "btn ps-delete", onclick: () => removeNode(node.id) }, icon("trash", 15), "Delete block")));
  }

  function drawBottom(): void {
    const allIssues = preview?.issues ?? validation?.issues ?? [];
    const errors = allIssues.filter((issue) => issue.severity === "error").length;
    const tabs: [BottomTab, string, string][] = [["preview", "Data preview", "table"], ["validation", "Checks", "check-circle"], ["log", "Run log", "list-checks"]];
    const bar = h("div", { class: "ps-bottom-tabs", role: "tablist", "aria-label": "Preview views" }, tabs.map(([id, label, glyph]) => h("button", {
      type: "button", class: bottomTab === id ? "active" : "", role: "tab", "aria-selected": String(bottomTab === id),
      onclick: () => { bottomTab = id; drawBottom(); } }, icon(glyph === "list-checks" ? "audit" : glyph, 14), label,
    id === "validation" && allIssues.length ? h("span", { class: "ps-summary-chip" }, allIssues.length) : null)),
    h("span", { class: "ps-preview-scope" }, preview ? `${preview.mode ?? "Sample"} · ${preview.storage === "memory" ? "In memory" : "Outputs retained"}` : "No run yet"));
    let content: Child;
    if (bottomTab === "validation") {
      content = !validation && !preview ? h("div", { class: "ps-bottom-empty" }, icon("check-circle", 26), h("strong", {}, "Check before you run"),
        h("p", {}, "Find missing settings, incompatible data and circular connections."), action("Check flow", "check-circle", checkFlow))
        : h("div", { class: "ps-issues" }, h("div", { class: `ps-issue ${errors ? "error" : "pass"}` }, icon(errors ? "alert" : "check-circle", 16),
          h("strong", {}, errors ? `${errors} issue${errors === 1 ? "" : "s"} to resolve` : preview ? "Execution checks passed" : "Flow structure is valid")),
        allIssues.map((issue) => h("button", { type: "button", class: `ps-issue ${issue.severity}`, onclick: () => { if (issue.nodeId) { choose(issue.nodeId); centerNode(issue.nodeId); } } },
          icon(issue.severity === "error" ? "alert" : "info", 14), h("span", {}, issue.message), issue.nodeId ? icon("arrow", 13) : null)),
        !allIssues.length ? h("p", { class: "small muted" }, "All configured blocks have compatible inputs and outputs. Sample execution checks row contents separately.") : null);
    } else if (bottomTab === "log") {
      content = !preview ? h("div", { class: "ps-bottom-empty" }, icon("history", 25), h("strong", {}, "A run you can follow"), h("p", {}, "Run a sample to see the result of each step."))
        : h("div", { class: "ps-run-log" }, preview.results.map((result, i) => h("div", { class: "ps-log-row" }, h("span", { class: "mono muted" }, String(i + 1).padStart(2, "0")),
          icon(result.status === "passed" ? "check-circle" : result.status === "failed" ? "alert" : "clock", 16),
          h("strong", {}, draft.nodes.find((node) => node.id === result.nodeId)?.label ?? result.nodeId), h("span", {}, result.message), h("span", { class: "mono" }, `${result.rows} rows`))));
    } else if (!preview?.results.length) {
      content = h("div", { class: "ps-bottom-empty" }, icon("table", 28), h("strong", {}, "A small run. A clearer picture."),
        h("p", {}, "Execute a bounded sample and inspect each block before a full run."), action("Preview sample", "play", runPreview));
    } else {
      const result = preview.results.find((item) => item.nodeId === resultNode) ?? preview.results.at(-1)!;
      const pickers = h("div", { class: "ps-result-list", "aria-label": "Choose a block’s sample output" }, preview.results.map((item) => h("button", {
        type: "button", class: item.nodeId === result.nodeId ? "active" : "", onclick: () => { resultNode = item.nodeId; drawBottom(); } },
      draft.nodes.find((node) => node.id === item.nodeId)?.label ?? "Block", h("span", {}, item.rows))));
      content = h("div", {}, pickers, h("div", { class: "ps-preview-summary" }, h("strong", {}, `${result.rows} rows`), h("span", {}, `${result.columns.length} columns`),
        h("span", {}, result.status === "passed" ? result.retained ? "Output saved" : "Preview in memory" : result.message),
        result.meta?.feature_count ? h("span", {}, `${result.meta.feature_count} feature columns`) : null,
        preview.id && result.retained ? action("View saved output", "data", () => void api<{ rows: typeof result.sample; columns: string[] }>(`/api/studio/output${qs({ run: preview!.id!, node: result.nodeId })}`)
          .then((data) => { result.sample = data.rows; result.columns = data.columns; drawBottom(); }).catch((error) => announce(String(error), true))) : null),
      result.columns.length ? table(result.columns, result.sample.map((row) => result.columns.map((column) => String(row[column] ?? "—"))), { class: "ps-table" })
        : h("p", { class: "small muted", style: { padding: "16px" } }, result.message));
    }
    clear(bottom, bar, h("div", { class: "ps-preview-body", role: "tabpanel" }, content));
  }

  function drawHints(): void {
    const source = draft.nodes.find((node) => node.id === connecting);
    canvasHint.textContent = source ? `Connect ${source.label} → click a matching input port · Esc to cancel` : "Drag to arrange · click ports to connect · drag the canvas to pan";
  }

  function drawFooter(): void {
    undoButton.disabled = running || history.length === 0;
    redoButton.disabled = running || future.length === 0;
    previewButton.disabled = running;
    fullRun.disabled = running || !preview?.valid;
    fullRun.title = !preview?.valid ? "Complete a successful sample run before the full run." : "Run the same operators over the full supplied input.";
    templates.disabled = running;
    name.value = draft.name;
    const issues = preview?.issues ?? validation?.issues;
    graphState.textContent = issues ? issues.some((issue) => issue.severity === "error") ? "Needs attention"
      : preview?.results.some((result) => result.status === "skipped") ? "Partial preview" : "Checks passed" : "Not checked";
    graphState.classList.toggle("pass", !!issues && !issues.some((issue) => issue.severity === "error"));
    clear(footer, h("span", {}, `${draft.nodes.length} blocks`, h("span", { class: "ps-footer-dot" }, "·"), `${draft.edges.length} connections`),
      h("span", {}, state.settings.pipeline_storage === "memory" ? "In memory · first inputs & final outputs saved" : "Each block output retained", h("span", { class: "ps-footer-dot" }, "·"),
        h("a", { href: "#/settings" }, "Storage settings")));
  }

  function drawMap(): void {
    const x0 = Math.min(0, ...draft.nodes.map((node) => node.x)) - 32;
    const y0 = Math.min(0, ...draft.nodes.map((node) => node.y)) - 32;
    const width = Math.max(800, ...draft.nodes.map((node) => node.x + NODE_WIDTH + 64)) - x0;
    const height = Math.max(420, ...draft.nodes.map((node) => node.y + 160)) - y0;
    mini.setAttribute("viewBox", `${x0} ${y0} ${width} ${height}`);
    const byId = new Map(draft.nodes.map((node) => [node.id, node]));
    clear(mini, draft.edges.map((edge) => {
      const a = byId.get(edge.from), b = byId.get(edge.to);
      return a && b ? svg("line", { x1: a.x + NODE_WIDTH, y1: a.y + PORT_Y, x2: b.x, y2: b.y + PORT_Y, stroke: "var(--muted)", "stroke-width": 7 }) : null;
    }), draft.nodes.map((node) => svg("rect", { x: node.x, y: node.y, width: NODE_WIDTH, height: 112, fill: node.id === selected ? "var(--brand)" : "var(--muted)", opacity: node.id === selected ? 1 : 0.45 })),
    svg("rect", { x: -view.x / view.zoom, y: -view.y / view.zoom, width: canvas.clientWidth / view.zoom, height: canvas.clientHeight / view.zoom,
      fill: "none", stroke: "var(--text)", "stroke-width": 5, opacity: 0.4 }));
  }

  function transform(): void {
    world.style.transform = `translate(${view.x}px, ${view.y}px) scale(${view.zoom})`;
    zoomLabel.textContent = `${Math.round(view.zoom * 100)}%`;
    canvas.style.backgroundSize = `${24 * view.zoom}px ${24 * view.zoom}px`;
    canvas.style.backgroundPosition = `${view.x}px ${view.y}px`;
    drawMap();
  }

  function zoomTo(next: number): void {
    const zoom = Math.max(0.3, Math.min(1.5, next));
    const x = canvas.clientWidth / 2, y = canvas.clientHeight / 2;
    view.x = x - (x - view.x) * zoom / view.zoom;
    view.y = y - (y - view.y) * zoom / view.zoom;
    view.zoom = zoom;
    transform();
  }

  function fit(): void {
    if (!canvas.isConnected) return;
    const x0 = Math.min(...draft.nodes.map((node) => node.x), 0);
    const y0 = Math.min(...draft.nodes.map((node) => node.y), 0);
    const width = Math.max(400, ...draft.nodes.map((node) => node.x + NODE_WIDTH)) - x0;
    const height = Math.max(260, ...draft.nodes.map((node) => node.y + 136)) - y0;
    view.zoom = Math.max(0.3, Math.min(1, (canvas.clientWidth - 70) / width, (canvas.clientHeight - 100) / height));
    view.x = (canvas.clientWidth - width * view.zoom) / 2 - x0 * view.zoom;
    view.y = (canvas.clientHeight - height * view.zoom) / 2 - y0 * view.zoom;
    transform();
  }

  function centerNode(id: string): void {
    const node = draft.nodes.find((item) => item.id === id);
    if (!node) return;
    view.x = canvas.clientWidth / 2 - (node.x + NODE_WIDTH / 2) * view.zoom;
    view.y = canvas.clientHeight / 2 - (node.y + 60) * view.zoom;
    transform();
  }

  function draw(redrawInspector = true): void {
    drawNodes();
    drawEdges();
    if (redrawInspector) drawInspector();
    drawBottom();
    drawHints();
    drawFooter();
    transform();
  }

  canvas.addEventListener("dragover", (event) => {
    if (!event.dataTransfer?.types.includes("application/x-dad-block")) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
    canvas.classList.add("dropping");
  });
  canvas.addEventListener("dragleave", () => canvas.classList.remove("dropping"));
  canvas.addEventListener("drop", (event) => {
    event.preventDefault();
    canvas.classList.remove("dropping");
    const kind = event.dataTransfer?.getData("application/x-dad-block");
    if (!BLOCKS.some((block) => block.kind === kind)) return;
    const rect = canvas.getBoundingClientRect();
    addBlock(kind as BlockKind, (event.clientX - rect.left - view.x) / view.zoom, (event.clientY - rect.top - view.y) / view.zoom);
  });
  canvas.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || (event.target as Element).closest(".ps-node, button, .ps-edge-hit, .ps-minimap")) return;
    const x = view.x, y = view.y, startX = event.clientX, startY = event.clientY;
    let moved = false;
    canvas.setPointerCapture(event.pointerId);
    const move = (next: PointerEvent) => {
      if (Math.hypot(next.clientX - startX, next.clientY - startY) > 3) moved = true;
      if (moved) { view.x = x + next.clientX - startX; view.y = y + next.clientY - startY; transform(); }
    };
    const end = () => {
      canvas.removeEventListener("pointermove", move);
      canvas.removeEventListener("pointerup", end);
      canvas.removeEventListener("pointercancel", end);
      if (!moved) { selected = selectedEdge = connecting = ""; drawSelection(); drawInspector(); drawHints(); }
    };
    canvas.addEventListener("pointermove", move);
    canvas.addEventListener("pointerup", end);
    canvas.addEventListener("pointercancel", end);
  });
  canvas.addEventListener("wheel", (event) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    zoomTo(view.zoom * (event.deltaY < 0 ? 1.1 : 0.9));
  }, { passive: false });

  const searchBox = h("input", { type: "search", placeholder: "Find a block…", "aria-label": "Search blocks" });
  searchBox.addEventListener("input", () => { search = searchBox.value; drawLibrary(); });
  const categories = h("select", { "aria-label": "Block category" }, ["All", ...new Set(BLOCKS.map((block) => block.category))].map((value) => h("option", { value }, value === "All" ? "All blocks" : value)));
  categories.addEventListener("change", () => { category = categories.value; drawLibrary(); });
  const previewButton = action("Preview sample", "play", runPreview);
  previewButton.classList.add("primary");
  const fullRun = h("button", { type: "button", class: "btn", disabled: true, title: "Complete a sample run before the full run.", onclick: () => void execute("full") }, icon("play", 14), "Full run");
  const studio = h("div", { class: "ps-studio" },
    h("div", { class: "ps-toolbar" }, h("div", { class: "ps-name-area" }, h("span", { class: "ps-eyebrow" }, "WORKSPACE / LOCAL DRAFT"), name, draftState),
      h("div", { class: "ps-toolbar-actions" }, templates, action("Import JSON", "upload", () => importer.click()), action("Export JSON", "download", exportDraft),
        action("Edit JSON", "patterns", editJson), action("Run history", "history", () => void runHistory()),
        action("Save draft", "check", () => { persist(); if (!storageFailed) announce("Draft saved in this browser. Export JSON to share or back it up."); }))),
    h("div", { class: "ps-body" }, h("aside", { class: "ps-library", "aria-label": "Block library" },
      h("div", { class: "ps-panel-head" }, h("span", { class: "ps-eyebrow" }, "Block library"), icon("plus", 16)),
      h("div", { class: "ps-search" }, searchBox, categories), library,
      h("div", { class: "ps-library-foot" }, icon("grip", 13), "Drag a block onto the canvas")),
    h("section", { class: "ps-canvas-wrap", "aria-label": "Visual flow editor" },
      h("div", { class: "ps-canvas-head" }, h("span", {}, icon("pipelines", 15), "Flow canvas"), h("div", { class: "ps-canvas-actions" }, graphState, undoButton, redoButton,
        action("Fit flow", "fullscreen-exit", fit, true))), canvas), inspector), bottom, footer);
  canvas.append(emptyCanvas, canvasHint, mini,
    h("div", { class: "ps-zoom" }, action("Zoom out", "minus", () => zoomTo(view.zoom - 0.1), true), zoomLabel, action("Zoom in", "plus", () => zoomTo(view.zoom + 0.1), true)));
  studio.addEventListener("keydown", (event) => {
    const editing = (event.target as Element).closest("input, textarea, select, [contenteditable=true]");
    if (event.key === "Escape") { connecting = ""; drawSelection(); drawHints(); }
    if (editing) return;
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "z") { event.preventDefault(); event.shiftKey ? redo() : undo(); }
    if ((event.key === "Delete" || event.key === "Backspace") && selected) { event.preventDefault(); removeNode(); }
  });
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Pipeline Studio")), h("span", { class: "ps-prototype" }, "DEVELOPMENT")),
    h("div", { class: "ps-page-intro" }, h("p", {}, "Build a flow. Check a sample. Follow the data."),
      h("div", { class: "ps-header-actions" }, action("Check flow", "check-circle", checkFlow), previewButton, fullRun)),
    h("div", { class: "ps-mode-note" }, icon("info", 14), "Compose sources, parsing, features and models. Check a sample first, then run the supplied input. Click a block to inspect its settings and output."),
    notice, studio, importer);
  drawLibrary();
  draw();
  requestAnimationFrame(fit);
}
