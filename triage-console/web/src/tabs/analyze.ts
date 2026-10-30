// Analyze: run new lines through the pipeline (Phases 1-4 and the map) and
// say whether they would be flagged. Input on top, results build up below.

import { api, qs } from "../api";
import { buildGroups, clusterMap, layoutFor, loadMap, mapInfoOrNone, mapOnDemand, pointDetails, retryBox, type ClusterMap, type InputPoint } from "../cluster-map";
import { badge, capsules, clear, errorBox, fmt, h, loading, note, pct, select, table } from "../dom";
import { icon, viewIcon } from "../icons";
import { routeBoard } from "../route-board";
import { sourceLabel, state } from "../state";
import { LOG_FILES, readLogFile } from "../tables";
import { openInPatterns } from "./patterns";
import { sigmaBadge, whitelistBadge } from "../verdicts";

// Example lines with documentation addresses (192.0.2.0/24) and made-up server names.
const SAMPLES: Record<string, { month: string; host?: string; text: string }> = {
  auth: {
    month: "2026-07",
    text: [
      "Jul 14 16:20:37 host-a sshd[27857]: [ID 800047 auth.info] Failed password for invalid user maint1 from 192.0.2.17 port 50123 ssh2",
      "Jul 14 16:20:41 host-a sshd[27857]: [ID 800047 auth.info] Failed password for invalid user maint1 from 192.0.2.17 port 50123 ssh2",
      "Jul 14 16:20:44 host-a sshd[27857]: [ID 800047 auth.info] Connection closed by 192.0.2.17 port 50123 [preauth]",
      "Jul 14 16:33:08 host-a su: [ID 366847 auth.notice] 'su root' succeeded for root on /dev/pts/2",
    ].join("\n"),
  },
  ossec: {
    month: "2026-07", host: "host-b",
    text: [
      "2026/07/01 10:00:00 ossec-agentd: INFO: Trying to connect to server (ossec/192.0.2.5:1514).",
      "2026/07/01 10:00:00 ossec-agentd: INFO: Using IPv4 for: 192.0.2.5 .",
      "2026/07/01 10:00:21 ossec-agentd(4102): ERROR: Waiting for server reply (not started). Tried: 'ossec/192.0.2.5'.",
    ].join("\n"),
  },
  ipf: {
    month: "2025-11",
    text: "Nov 27 10:15:44 host-c ipmon[172]: [ID 702911 local0.warning] 10:15:43.941525 e1000g0 @0:2 b 192.0.2.111,49758 -> 192.0.2.255,161 PR udp len 20 69 IN",
  },
};
const STEPS: [string, string][] = [["parse", "Parse"], ["phase1", "Classify"], ["phase2", "Observations"], ["phase3", "Features"],
  ["phase4", "Models"], ["map", "Map"], ["done", "Done"]];

type Mode = "paste" | "file" | "path";
const form = { mode: "paste" as Mode, source: "auto", month: new Date().toISOString().slice(0, 7), host: "", text: "", fileName: "", path: "" };
let lastResult: any = null;
let selectedView = "";

export function renderAnalyze(main: HTMLElement): void {
  const results = h("div");
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Analyze"))),
    inputCard(results), results);
  if (lastResult) clear(results, ...renderResult(lastResult));
}

function inputCard(results: HTMLElement): HTMLElement {
  const textarea = h("textarea", { rows: 7, spellcheck: "false", placeholder: "Paste log lines…", "aria-label": "Log lines" }) as HTMLTextAreaElement;
  textarea.value = form.text;
  textarea.addEventListener("input", () => (form.text = textarea.value));
  const fileInfo = h("span", { class: "small muted" }, form.fileName || "");
  const fileInput = h("input", { type: "file", accept: LOG_FILES, "aria-label": "Log file" }) as HTMLInputElement;
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    try {
      form.text = await readLogFile(file);
    } catch (e) {
      clear(fileInfo, errorBox(e));
      return;
    }
    form.fileName = file.name;
    const m = /ossec[_-]?logs?[_-]([^.\\/]+)/i.exec(file.name);
    if (m && !form.host) { form.host = m[1].toLowerCase(); hostInput.value = form.host; }
    clear(fileInfo, `${file.name} · ${(file.size / 1e6).toFixed(1)} MB`);
  });
  const pathInput = h("input", { type: "text", value: form.path, placeholder: "C:\\logs\\authlog_host.txt  ·  .csv  ·  .xlsx", style: { width: "100%" }, "aria-label": "File path" }) as HTMLInputElement;
  pathInput.addEventListener("input", () => (form.path = pathInput.value));
  const hostInput = h("input", { type: "text", value: form.host, placeholder: "OSSEC only", style: { width: "150px" } }) as HTMLInputElement;
  hostInput.addEventListener("input", () => (form.host = hostInput.value.trim()));
  const monthInput = h("input", { type: "month", value: form.month }) as HTMLInputElement;
  monthInput.addEventListener("change", () => (form.month = monthInput.value));

  const body = h("div");
  const drawBody = () => clear(body,
    form.mode === "paste" ? [textarea, h("div", { class: "row small muted", style: { marginTop: "8px" } }, "Examples:",
      Object.entries(SAMPLES).map(([k, s]) => h("button", { class: "btn small", onclick: () => {
        form.text = textarea.value = s.text; form.month = monthInput.value = s.month;
        form.host = hostInput.value = s.host ?? ""; form.source = "auto";
      } }, k)))] : null,
    form.mode === "file" ? h("div", { class: "row" }, fileInput, fileInfo) : null,
    form.mode === "path" ? [pathInput, h("div", { class: "small muted", style: { marginTop: "6px" } }, "Up to 3 million lines, read on this laptop.")] : null);
  drawBody();

  const run = h("button", { class: "btn primary" }, icon("play", 16), "Analyze") as HTMLButtonElement;
  run.addEventListener("click", () => start(run, results));

  const sources: [string, string][] = [["auto", "Detect"], ...Object.keys(state.catalog.sources).map((k) => [k, `${k.toUpperCase()} · ${sourceLabel(k)}`] as [string, string])];
  const modes: [Mode, string][] = [["paste", "Paste"], ["file", "Upload"], ["path", "File on this laptop"]];
  return h("div", { class: "card" },
    h("div", { class: "row", style: { justifyContent: "space-between", marginBottom: "14px" } },
      h("div", { class: "pills small", role: "tablist" }, modes.map(([m, label]) => h("button", {
        class: form.mode === m ? "on" : "", onclick: (e: Event) => {
          form.mode = m; drawBody();
          (e.currentTarget as HTMLElement).parentElement!.querySelectorAll("button").forEach((b, i) => b.classList.toggle("on", modes[i][0] === m));
        },
      }, label))),
      h("div", { class: "row", style: { alignItems: "flex-end" } },
        h("label", { class: "field" }, h("span", {}, "Log type"), select(sources, form.source, (v) => (form.source = v))),
        h("label", { class: "field", title: "Syslog lines carry no year" }, h("span", {}, "Month"), monthInput),
        h("label", { class: "field" }, h("span", {}, "Server"), hostInput),
        run)),
    body);
}

async function start(run: HTMLButtonElement, results: HTMLElement): Promise<void> {
  run.disabled = true;
  const board = routeBoard(STEPS);
  const progress = board.el;
  clear(results, progress);
  let lastSeen: string[] = [];
  const drawProgress = (seen: string[], status: string) => {
    lastSeen = seen;
    board.update(seen, status === "done" || status === "failed" ? status : "running");
  };
  try {
    const { job } = await api("/api/analyze", { body: { text: form.mode === "path" ? "" : form.text, path: form.mode === "path" ? form.path : "",
      source: form.source, month: form.month, host: form.host, name: form.mode === "file" ? form.fileName : "" } });
    for (;;) {
      const state = await api(`/api/analyze/job${qs({ id: job })}`);
      drawProgress(state.steps.map((s: any) => s.step), state.status);
      if (state.status === "done") {
        lastResult = state.result;
        selectedView = "";
        clear(results, progress, ...renderResult(state.result));
        break;
      }
      if (state.status === "failed") throw new Error(state.error);
      await new Promise((r) => setTimeout(r, 600));
    }
  } catch (e) {
    board.update(lastSeen, "failed");
    const unknown = /recognises these lines/.test(e instanceof Error ? e.message : String(e));
    clear(results, progress, errorBox(e), unknown ? h("div", { class: "row", style: { marginTop: "10px" } },
      h("button", { class: "btn primary", onclick: () => {
        openInPatterns(form.mode === "path" ? { path: form.path } : { text: form.text, name: form.fileName || "Pasted lines" });
        location.hash = "#/patterns";
      } }, icon("patterns", 16), "Find patterns")) : null);
  } finally {
    run.disabled = false;
  }
}

function renderResult(r: any): HTMLElement[] {
  const v = r.verdict;
  const presence = v.method === "presence";
  const usedViews = r.views.filter((x: any) => x.observations);
  if (!selectedView) selectedView = (usedViews.find((x: any) => x.flagged) ?? usedViews[0])?.view ?? "";
  const detail = h("div");
  const viewCards = h("div", { class: "grid three" });
  const drawViews = () => clear(viewCards, r.views.map((x: any) => viewCard(x, presence, () => { selectedView = x.view; drawViews(); drawDetail(); })));
  const drawDetail = () => clear(detail, ...(presence ? [] : viewDetail(r, r.views.find((x: any) => x.view === selectedView))));
  drawViews();
  drawDetail();

  return [
    h("div", { class: "grid two", style: { marginBottom: "16px" } },
      h("div", { class: `card ${v.flagged ? "alarm" : "accent"}` },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon(v.flagged ? "alert" : v.whitelisted ? "shield" : "check")), h("h2", {}, "Verdict")),
        h("div", { class: "verdict-title" }, v.flagged ? "Would be flagged" : v.whitelisted ? "Whitelisted" : "Would not be flagged"),
        h("div", { class: "row", style: { alignItems: "flex-end", margin: "14px 0 8px" } },
          h("div", { class: "big" }, presence ? "100%" : pct(v.confidence)),
          h("div", { class: "small muted", style: { maxWidth: "26ch" } }, presence ? "presence rule: any traffic is flagged" : "more unusual than this share of validation observations")),
        capsules(presence ? 1 : v.confidence ?? 0, 10),
        !presence ? h("div", { class: "small", style: { marginTop: "10px" } },
          `${fmt.int(v.flagged_observations)} of ${fmt.int(v.observations)} observations flagged in the views used for alerts`,
          v.whitelisted ? [" ", whitelistBadge(`${fmt.int(v.whitelisted)} whitelisted`)] : null) : null),
      h("div", { class: "card" },
        h("div", { class: "stat-grid" },
          stat("Log type", r.source, `${r.detected.source === r.source ? "detected" : "chosen"}${r.layout ? ` · ${r.layout.format} · ${r.layout.raw}` : ""}`),
          stat("Lines recognised", `${fmt.int(r.recognised)} / ${fmt.int(r.lines)}`, pct(r.lines ? r.recognised / r.lines : 0)),
          stat("Time span", `${r.span.hours} h`, r.span.first ? `${r.span.first.slice(0, 16)} → ${r.span.last.slice(0, 16)}` : "—"),
          stat("Servers", String(r.hosts.length), r.hosts.slice(0, 3).join(", ") || "—")))),
    h("div", { class: "card-head", style: { margin: "4px 4px 10px" } }, h("h2", {}, "Views")),
    viewCards,
    h("div", { style: { marginTop: "16px" } }, detail),
    h("div", { class: "card", style: { marginTop: "16px" } },
      h("details", {}, h("summary", {}, h("strong", {}, "Event types"), h("span", { class: "muted small" }, `  ${r.event_types.length}`)),
        table(["Event type", "Input", "In the year", "Share", "Months"], r.event_types.map((e: any) => [h("code", {}, e.event_type),
          fmt.int(e.input_count), e.year_count === 0 ? badge("never seen", "bad") : fmt.int(e.year_count), pct(e.share, 4), `${e.months_seen}/${e.months}`]))),
      h("details", { style: { marginTop: "10px" } }, h("summary", {}, h("strong", {}, "Parsed lines"), h("span", { class: "muted small" }, `  first ${Math.min(100, r.lines)}`)),
        table(["#", "Event type", "Line"], r.sample.map((s: any, i: number) => [String(i + 1),
          s.known ? h("code", {}, s.event_type) : badge(s.event_type, "bad"),
          h("div", { class: "small mono", style: { maxWidth: "760px", overflowWrap: "anywhere" } }, s.line)])))),
  ];
}

function stat(k: string, v: string, d: string): HTMLElement {
  return h("div", { class: "stat" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "d", title: d }, d));
}

function viewCard(x: any, presence: boolean, onPick: () => void): HTMLElement {
  const has = x.observations !== null && x.observations !== undefined;
  const flaggedShare = has && x.observations ? x.flagged / x.observations : 0;
  return h("div", { class: `card view-card ${x.view === selectedView && !presence ? "on" : ""} ${x.used ? "" : "dim"}`, tabindex: "0",
    onclick: presence ? undefined : onPick, onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter" && !presence) onPick(); } },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, viewIcon(x.view)), h("h2", {}, x.label),
      h("span", { class: "end row", style: { gap: "4px" } }, x.whitelisted ? whitelistBadge(fmt.int(x.whitelisted)) : null,
        badge(x.used ? "alerts" : "info only", x.used ? "ok" : "muted"))),
    presence
      ? h("div", { class: "small muted" }, x.used ? "Presence rule: flagged if active." : "Reported, not alerted.")
      : has
        ? [h("div", { class: "big" }, fmt.int(x.flagged), h("small", {}, `/ ${fmt.int(x.observations)} flagged`)),
          h("div", { class: "hbar", style: { marginTop: "10px" } }, h("span", { class: "muted" }, "most unusual"),
            h("span", { class: "track" }, h("span", { class: `fill ${x.flagged ? "red" : "olive"}`, style: { width: pct(x.max_unusual ?? 0) } })),
            h("span", { class: "n" }, pct(x.max_unusual, 0))),
          h("div", { class: "tiny muted", title: x.why }, flaggedShare ? `${pct(flaggedShare, 0)} of observations flagged` : x.why),
          driftRow(x.drift)]
        : h("div", { class: "small muted" }, "No observation formed."));
}

/** Drift against the training baseline (service/drift.py): KS D of the Isolation Forest percentiles against
 * Uniform(0, 1), the 99th percentile of D for validation blocks of the same size, and n, and the share of observations naming a server, account or address new since training. */
function driftRow(d: any): HTMLElement | null {
  if (!d || (!d.scores && !d.new)) return null;
  const s = d.scores;
  const NEW: Record<string, string> = { server: "srv", username: "acct", source_ip: "addr" };
  const fresh = Object.entries(d.new ?? {}) as [string, { new: number; named: number }][];
  return h("div", { class: "row drift-row" },
    s ? h("span", { class: `badge ${s.drift ? "warn" : "muted"}`, title: "Kolmogorov-Smirnov D: Isolation Forest percentiles against Uniform(0, 1); null: the 99th percentile of D for blocks of validation this size" },
      `KS D ${s.d.toFixed(2)}${s.null !== null && s.null !== undefined ? ` · null ${s.null.toFixed(2)}` : ""} · n ${fmt.int(s.n)}`) : null,
    fresh.map(([kind, c]) => h("span", { class: `badge ${c.new ? "warn" : "muted"}`, title: "Not seen on a training day" },
      `new ${NEW[kind] ?? kind} ${pct(c.new / c.named, 0)}`)));
}

// --- map and observations for one view ---------------------------------------------------

const clusterCache = new Map<string, Promise<any[]>>();
const when = (o: any): string => (o.timestamp ?? o.window_start ?? o.session_start ?? o.episode_start ?? "").slice(0, 19);
const groupOf = (o: any): number | null => (o.map?.cluster_id ? Number(o.map.cluster_id.split("#")[1]) : null);

function viewDetail(r: any, x: any): HTMLElement[] {
  if (!x || !x.rows?.length) return [];
  const mapBox = h("div", {}, loading("Loading…"));
  const clusters = h("div", {}, loading("Loading clusters…"));
  const key = `${r.source}/${x.view}`;
  const load = () => {
  if (!clusterCache.has(key)) {
    const request = api(`/api/clusters${qs({ source: r.source, view: x.view })}`).then((c) => c.clusters);
    request.catch(() => clusterCache.delete(key));          // a failed fetch is not kept: the next try asks again
    clusterCache.set(key, request);
  }
  clear(mapBox, loading("Loading…"));
  Promise.all([mapInfoOrNone(r.source, x.view), clusterCache.get(key)!]).then(([info, list]) => {
    const { groups } = buildGroups(list, info);
    const nameOf = (n: number | null) => (n === null ? "No group" : groups.get(n)?.name ?? `Group #${n}`);
    // the new observations, placed among their nearest neighbours on the year's map
    const inputs: InputPoint[] = x.rows.filter((o: any) => o.map).map((o: any) => ({
      x: o.map.x, y: o.map.y, at: o.map.layouts ?? {}, flagged: o.flags.length > 0 && !o.whitelisted, group: groupOf(o),
      label: `${when(o) || "new observation"} · ${o.event_type ?? o.first_event_type ?? x.label}${o.flags.length ? ` · flagged by ${o.flags.join(", ").replace(/_/g, " ")}${o.whitelisted ? " · whitelisted" : ""}` : " · not flagged"}`,
    }));
    let map: ClusterMap | null = null;
    let picked: number | null = null;
    // Picking a group greys out the rest of the map and shows the group in yellow; clicking it again clears it.
    const pick = (n: number) => {
      picked = picked === n ? null : n;
      map?.setSelected(picked);
      drawTable();
    };
    const pointBox = h("div");
    if (info) {
      clear(mapBox, mapOnDemand(`analyze/${key}`, info, async () => {
        // new lines analysed before UMAP layouts existed have no UMAP position, so they stay on t-SNE
        const placedEverywhere = inputs.every((p) => p.at?.umap);
        const layout = placedEverywhere ? layoutFor(info) : "tsne";
        const points = await loadMap(r.source, x.view, layout);
        const closePoint = () => { clear(pointBox); map?.clearPoint(); };
        map = clusterMap(points, groups, {
          visible: new Set(groups.keys()), selected: picked, height: 440, inputs, aside: pointBox,
          layout, info: placedEverywhere ? info : { ...info, layouts: { tsne: "ready", umap: "missing" } },
          loadLayout: (l) => loadMap(r.source, x.view, l),
          title: `On the map · ${x.label} · new logs and the year's observations`,
          onPick: (n) => pick(n),
          onClear: () => { if (picked !== null) pick(picked); },
          onPoint: (i) => {
            clear(pointBox, loading("Opening the point…"));
            pointDetails(r.source, x.view, points.id![i], nameOf, (n) => { if (picked !== n) pick(n); }, closePoint)
              .then((el) => clear(pointBox, el)).catch((e) => clear(pointBox, errorBox(e)));
          },
        });
        return map.el;
      }));
    } else {
      clear(mapBox, note("No map for this view."));
    }
    const counts = new Map<number | null, { n: number; flagged: number; agreement: number }>();
    for (const row of x.rows) {
      const id = row.map ? groupOf(row) : null;
      const c = counts.get(id) ?? { n: 0, flagged: 0, agreement: 0 };
      c.n++; c.flagged += row.flags.length ? 1 : 0; c.agreement += row.map?.agreement ?? 0;
      counts.set(id, c);
    }
    const drawTable = () => clear(clusters, h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Nearest group", "New obs.", "Flagged", "Agreement"].map((c) => h("th", { scope: "col" }, c)))),
      h("tbody", {}, [...counts.entries()].sort((a, b) => b[1].n - a[1].n).map(([id, c]) => h("tr", {
        class: `${id !== null ? "clickable" : ""} ${id !== null && id === picked ? "selected" : ""}`, tabindex: id !== null ? "0" : undefined,
        title: id !== null ? "Highlight this group on the map (click again to clear)" : undefined,
        onclick: () => { if (id !== null) pick(id); },
        onkeydown: (e: KeyboardEvent) => { if (e.key === "Enter" && id !== null) pick(id); },
      },
        h("td", {}, h("strong", {}, nameOf(id)), h("div", { class: "tiny muted" }, id === null ? "not placed" : `#${id}`)),
        h("td", {}, fmt.int(c.n)), h("td", {}, c.flagged ? badge(String(c.flagged), "bad") : "0"), h("td", {}, pct(c.agreement / c.n, 0))))))));
    drawTable();
  }).catch((e) => { clear(clusters, errorBox(e)); clear(mapBox, retryBox(e, load)); });
  };
  load();

  return [
    h("div", { class: "grid", style: { gridTemplateColumns: "minmax(0, 1.6fr) minmax(300px, 1fr)", alignItems: "start", marginBottom: "16px" } },
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("map")), h("h2", {}, `On the map · ${x.label}`)),
        h("div", { class: "legend", style: { marginBottom: "10px" } },
          h("span", {}, h("i", { style: { background: "var(--muted)", opacity: "0.6" } }), "the year's observations"),
          h("span", {}, h("i", { style: { background: "var(--red)", opacity: "0.8" } }), "flagged then"),
          h("span", {}, h("i", { style: { background: "var(--surface)", boxShadow: "inset 0 0 0 2px var(--ink)" } }), "new logs"),
          h("span", {}, h("i", { style: { background: "var(--red)", boxShadow: "inset 0 0 0 2px var(--ink)" } }), "new logs, flagged"),
          h("span", {}, h("i", { style: { background: "var(--map-pick)", boxShadow: "inset 0 0 0 1px var(--map-pick-edge)" } }), "selected group"),
          h("span", { class: "tiny" }, "Click a point to open it; click a cluster row to highlight its group.")),
        mapBox),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Clusters")), clusters,
        x.zoo_members?.length ? note(`Zoo ensemble: ${x.zoo_members.join(", ")} · consensus needs ${x.votes_needed} votes`) : null)),
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, viewIcon(x.view)), h("h2", {}, "Observations"),
        h("span", { class: "end small muted" }, `${fmt.int(x.observations)} · most flagged first`)),
      table(["Time", "Server", "Event", "Flagged by", "Unusual", "Cluster"], x.rows.slice(0, 200).map((o: any) => [
        h("span", { class: "small mono" }, when(o)),
        o.host_id ?? o.hostname ?? "—",
        h("code", {}, o.event_type ?? o.first_event_type ?? "—"),
        o.flags.length ? h("div", { class: "row", style: { gap: "4px" } }, o.flags.filter((f: string) => f !== "sigma").map((f: string) => badge(f.replace(/_/g, " "), o.whitelisted ? "muted" : "bad")),
          (o.sigma ?? []).map((t: string) => sigmaBadge(t)),
          o.whitelisted ? whitelistBadge() : null) : h("span", { class: "muted" }, "—"),
        h("span", { title: Object.entries(o.percentiles).map(([k, p]) => `${k}: ${pct(p as number)}`).join("\n") }, pct(o.unusual)),
        h("span", { class: "small" }, o.map?.cluster_id || "—"),
      ]))),
  ];
}
