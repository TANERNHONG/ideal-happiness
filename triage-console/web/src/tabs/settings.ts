// Settings: language, appearance, the local model (same setting as the
// top-right picker), your name, the Dashboard's layout (dashboard-editor.ts), whitelisted users (an override on the anomalies, service/whitelist.py)
// and the activity log. Changing the whitelist or clearing the log needs the admin password.

import { api, qs } from "../api";
import { badge, clear, errorBox, fmt, h, loading, select, table } from "../dom";
import { dashboardEditor } from "./dashboard-editor";
import { icon } from "../icons";
import { LANGUAGES, t } from "../i18n";
import { reviewLoader, sqlLoader } from "../loaders";
import { setMode } from "../mode";
import { refreshLlm, state, subscribe, updateSettings } from "../state";

let unsubscribe: (() => void) | null = null;

/** Whether a font is on this laptop: text set in it measures differently from the fallbacks (document.fonts.check
 * cannot tell, since it reports any font it would not need to download as available). */
function fontInstalled(name: string): boolean {
  const c = document.createElement("canvas").getContext("2d");
  if (!c) return false;
  const sample = "mmmmmmmmmmlliWW@#0123456789";
  return ["monospace", "serif", "sans-serif"].some((fallback) => {
    c.font = `72px ${fallback}`;
    const base = c.measureText(sample).width;
    c.font = `72px "${name}", ${fallback}`;
    return c.measureText(sample).width !== base;
  });
}

export function renderSettings(main: HTMLElement): void {
  unsubscribe?.();
  const activity = h("div", { class: "card" }, loading());
  const kept = h("div", {}, loading());                    // Retention: what is past the limit (drawRetention)
  const whitelisted = h("div", { class: "card", style: { marginBottom: "16px" } }, loading());
  const layout = h("div", { class: "card", style: { marginBottom: "16px" } });          // keeps its draft when the page redraws
  dashboardEditor(layout);
  const draw = () => {
    const s = state.settings;
    const err = h("div");
    const previewBox = h("div", { style: { flexBasis: "100%" } });
    const save = (changes: object) => updateSettings(changes).catch((e) => clear(err, errorBox(e)));
    const choice = (options: [string, string][], current: string, key: string) =>
      h("div", { class: "pills small" }, options.map(([v, label]) =>
        h("button", { class: v === current ? "on" : "", onclick: () => save({ [key]: v }) }, label)));
    const endpoint = h("input", { type: "text", value: s.llm_endpoint, style: { width: "230px" }, "aria-label": "Ollama address" }) as HTMLInputElement;
    const name = h("input", { type: "text", value: s.display_name, style: { width: "180px" }, "aria-label": "Your name" }) as HTMLInputElement;
    const installed = h("input", { type: "text", value: s.font_installed ?? "", placeholder: "Font name", style: { width: "200px" }, "aria-label": "Installed font name" }) as HTMLInputElement;
    const useInstalled = () => save({ font_family: "installed", font_installed: installed.value.trim() });
    installed.addEventListener("keydown", (e) => { if (e.key === "Enter") useInstalled(); });
    const found = s.font_installed && fontInstalled(s.font_installed);
    const size = h("input", { type: "range", min: "0.8", max: "1.4", step: "0.05", value: String(s.font_scale), "aria-label": t("settings.fontSize") }) as HTMLInputElement;
    size.addEventListener("change", () => save({ font_scale: Number(size.value) }));
    const filterSeconds = h("input", { type: "number", min: "10", max: "3600", step: "10", value: String(s.review_filter_seconds ?? 120),
      style: { width: "90px" }, "aria-label": "Filter time limit in seconds" }) as HTMLInputElement;
    const saveFilterSeconds = () => save({ review_filter_seconds: Number(filterSeconds.value) });
    filterSeconds.addEventListener("keydown", (e) => { if (e.key === "Enter") saveFilterSeconds(); });
    clear(main,
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("nav.settings")))),
      err,
      h("div", { class: "grid two", style: { marginBottom: "16px" } },
        h("div", { class: "card" },
          h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("settings")), h("h2", {}, "Appearance")),
          h("label", { class: "field" }, h("span", {}, t("settings.language")), select(LANGUAGES, s.language, (v) => save({ language: v }))),
          h("div", { class: "set-row" }, h("span", { class: "small muted" }, t("settings.mode")),
            h("div", { class: "pills small" }, (["simple", "advanced"] as const).map((m) => h("button", {
              class: (s.console_mode ?? "simple") === m ? "on" : "", onclick: () => setMode(m).catch((e) => clear(err, errorBox(e))),
            }, icon(`mode-${m}`, 14), t(`mode.${m}`))))),
          h("div", { class: "set-row" }, h("span", { class: "small muted" }, t("settings.theme")),
            choice([["light", t("settings.theme.light")], ["dark", t("settings.theme.dark")], ["system", t("settings.theme.system")]], s.theme, "theme")),
          h("label", { class: "field", style: { marginTop: "14px" } }, h("span", {}, t("settings.font")),
            select([["inter", "Inter"], ["roboto", "Roboto"], ["helvetica", "Helvetica"], ["system", "System"], ["readable", "Readable"], ["serif", "Serif"], ["mono", "Monospace"],
              ["installed", s.font_installed || t("settings.font.installed")]], s.font_family, (v) => save({ font_family: v }))),
          s.font_family === "installed" ? h("div", { class: "row set-sub", style: { marginTop: "8px" } }, installed,
            h("button", { class: "btn small", onclick: useInstalled }, t("common.save")),
            s.font_installed ? h("span", { class: `badge ${found ? "ok" : "warn"}`, title: found ? "" : "Not installed on this laptop" }, icon(found ? "check" : "alert", 12), found ? "installed" : "missing") : null) : null,
          h("label", { class: "field", style: { marginTop: "14px" } }, h("span", {}, `${t("settings.fontSize")} · ${Math.round(s.font_scale * 100)}%`), size),
          h("div", { class: "set-row" }, h("span", { class: "small muted" }, t("settings.animations")),
            choice([["all", t("settings.animations.all")], ["no-arrival", t("settings.animations.noArrival")], ["none", t("settings.animations.none")]],
              s.animations ?? "all", "animations")),
          h("div", { class: "set-row" }, h("span", { class: "small muted" }, t("settings.pack")),
            choice([["transit", t("settings.pack.transit")], ["desk", t("settings.pack.desk")], ["commuter", t("settings.pack.commuter")]], s.animation_pack ?? "transit", "animation_pack"),
            h("div", { class: "row set-sub" },
              h("span", { class: "tiny muted" }, "Preview"),
              h("button", { class: "btn small", onclick: () => void preview(previewBox, "sql") }, "SQL query"),
              h("button", { class: "btn small", onclick: () => void preview(previewBox, "review") }, "Review"),
              h("button", { class: "btn small", onclick: () => void preview(previewBox, "sql", true) }, "SQL query fails"),
              h("button", { class: "btn small", onclick: () => void preview(previewBox, "review", true) }, "Review fails")),
            previewBox)),
        h("div", { class: "settings-column" },
          h("div", { class: "card" },
            h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("models")), h("h2", {}, "Language model"),
              h("span", { class: "end row small" }, h("span", { class: `dot ${state.llm.online ? "on" : ""}` }), state.llm.online ? "running" : "not running",
                h("button", { class: "icon-btn", title: t("llm.refresh"), onclick: () => refreshLlm() }, icon("refresh", 14)))),
            h("label", { class: "field" }, h("span", {}, "Model (also at the top right)"),
              select(state.llm.models.map((m) => [m, m]), s.llm_model, (v) => save({ llm_model: v }))),
            h("label", { class: "field", style: { marginTop: "12px" } }, h("span", {}, "Ollama on this laptop"),
              h("div", { class: "row" }, endpoint, h("button", { class: "btn small", onclick: () => save({ llm_endpoint: endpoint.value }) }, t("common.save")))),
            h("label", { class: "field", style: { marginTop: "12px" } }, h("span", {}, "Your name (comments and reviews)"),
              h("div", { class: "row" }, name, h("button", { class: "btn small", onclick: () => save({ display_name: name.value }) }, t("common.save"))))),
          h("div", { class: "card" },
            h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("review")), h("h2", {}, "Review")),
            h("label", { class: "field" }, h("span", {}, "Filter time limit"),
              h("div", { class: "row" }, filterSeconds, h("span", { class: "small muted" }, "s"),
                h("button", { class: "btn small", onclick: saveFilterSeconds }, t("common.save"))))),
          h("div", { class: "card" },
            h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("history")), h("h2", {}, "Retention")),
            h("div", { class: "set-row" }, h("span", { class: "small muted" }, "Log lines kept"),
              h("div", { class: "pills small" }, [3, 6, 12, 24, 36].map((m) => h("button", {
                class: (s.retention_months ?? 12) === m ? "on" : "",
                onclick: () => updateSettings({ retention_months: m }).then(() => api("/api/retention/apply", { body: {} }))
                  .then(() => drawRetention(kept)).catch((e) => clear(err, errorBox(e))),
              }, `${m} mo`)))),
            kept))),
      layout,
      whitelisted,
      activity);
  };
  draw();
  drawRetention(kept);
  drawWhitelist(whitelisted);
  drawActivity(activity);
  unsubscribe = subscribe(() => { if (location.hash.startsWith("#/settings")) { draw(); drawWhitelist(whitelisted); drawActivity(activity); } });
}

// --- retention: the console's copies of log lines past Settings → Retention (service/retention.py) ------------

async function drawRetention(box: HTMLElement): Promise<void> {
  try {
    const r = await api("/api/retention");
    const row = (label: string, n: number) => h("div", { class: "set-row" }, h("span", { class: "small muted" }, label),
      badge(fmt.int(n), n ? "warn" : "muted"));
    clear(box,
      h("div", { class: "set-row" }, h("span", { class: "small muted" }, "Before"), h("span", { class: "mono small" }, r.cutoff)),
      row("Upload lines", r.upload_items_due), row("Dashboard tables", r.dashboard_results_due),
      row("Reports with log lines", r.reports_with_lines_past));
  } catch (e) {
    clear(box, errorBox(e));
  }
}

// --- whitelisted users: accounts whose flagged events need no review -------------------------------

async function drawWhitelist(card: HTMLElement): Promise<void> {
  let entries: any[];
  try {
    ({ entries } = await api("/api/whitelist"));
  } catch (e) {
    return clear(card, errorBox(e));
  }
  const err = h("div");
  const panel = h("div");
  const input = (attrs: Record<string, string>) => h("input", { type: "text", autocomplete: "off", ...attrs }) as HTMLInputElement;
  const account = input({ list: "wl-accounts", "aria-label": "Account", style: "width:160px" });
  const server = input({ list: "wl-servers", placeholder: "All servers", "aria-label": "Server", style: "width:150px" });
  const reason = input({ "aria-label": "Reason" });
  const until = h("input", { type: "date", "aria-label": "Until", min: new Date().toISOString().slice(0, 10) }) as HTMLInputElement;
  const password = h("input", { type: "password", autocomplete: "off", "aria-label": "Password", style: { width: "130px" } }) as HTMLInputElement;
  const privileged = h("input", { type: "checkbox", "aria-label": "Includes su" }) as HTMLInputElement;
  const accounts = h("datalist", { id: "wl-accounts" }), servers = h("datalist", { id: "wl-servers" });
  for (const [field, list] of [["username", accounts], ["host", servers]] as const) {
    api(`/api/review/options${qs({ source: "auth", field })}`)
      .then((r) => clear(list, r.values.map((v: string) => h("option", { value: v })))).catch(() => undefined);
  }
  const add = h("button", { class: "btn primary small" }, icon("plus", 14), "Add") as HTMLButtonElement;
  add.addEventListener("click", async () => {
    add.disabled = true;
    try {
      await api("/api/whitelist", { body: { username: account.value, host: server.value, reason: reason.value, until: until.value,
        password: password.value, privileged: privileged.checked } });
      drawWhitelist(card);
    } catch (e) {
      clear(err, errorBox(e));
      add.disabled = false;
    }
  });
  const confirmRemove = (entry: any) => {
    const pw = h("input", { type: "password", autocomplete: "off", "aria-label": "Password", style: { width: "160px" } }) as HTMLInputElement;
    const failed = h("div");
    const go = h("button", { class: "btn danger small" }, icon("trash", 14), "Remove") as HTMLButtonElement;
    go.addEventListener("click", async () => {
      go.disabled = true;
      try {
        await api("/api/whitelist/remove", { body: { id: entry.id, password: pw.value } });
        drawWhitelist(card);
      } catch (e) {
        clear(failed, errorBox(e));
        go.disabled = false;
      }
    });
    clear(panel, h("div", { class: "card alarm", style: { margin: "0 0 12px" } },
      h("div", { class: "row" }, icon("lock", 18), h("strong", {}, `Remove ${entry.username}${entry.host ? ` on ${entry.host}` : ""}?`)),
      h("div", { class: "row", style: { marginTop: "10px" } }, h("label", { class: "field" }, h("span", {}, "Password"), pw), go,
        h("button", { class: "btn small", onclick: () => clear(panel) }, "Cancel")), failed));
    pw.focus();
  };
  const field = (label: string, control: HTMLElement, cls = "") => h("label", { class: `field ${cls}` }, h("span", {}, label), control);
  clear(card,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("shield")), h("h2", {}, "Whitelisted users"),
      entries.length ? h("span", { class: "end small muted" }, fmt.int(entries.filter((e) => !e.expired).length)) : null),
    h("div", { class: "wl-form" }, field("Account", account), field("Server", server), field("Reason", reason, "wl-reason"),
      field("Until", until), h("label", { class: "field wl-check" }, h("span", {}, "su"), privileged), field("Password", password), add,
      accounts, servers),
    err, panel,
    entries.length
      ? table(["Account", "Server", "Reason", "Until", "Flagged", "Added", ""], entries.map((e: any) => [
          h("span", {}, h("strong", {}, e.username), e.privileged ? h("span", { class: "badge warn", style: { marginLeft: "6px" } }, "su") : null),
          e.host ? h("span", { class: "who-chip server" }, e.host) : h("span", { class: "muted" }, "All servers"),
          h("span", { class: "small" }, e.reason),
          e.expired ? badge(`ended ${e.until}`, "warn") : h("span", { class: "small mono" }, e.until || "—"),
          e.flagged === null || e.flagged === undefined ? h("span", { class: "muted" }, "—") : fmt.int(e.flagged),
          h("span", { class: "tiny muted" }, `${e.added_by} · ${e.added_at.replace("T", " ").slice(0, 16)}`),
          h("button", { class: "icon-btn", title: "Remove", "aria-label": `Remove ${e.username}`, onclick: () => confirmRemove(e) }, icon("trash", 14)),
        ]), { class: "wl-table" })
      : h("p", { class: "muted" }, "None."));
  card.querySelectorAll<HTMLTableRowElement>(".wl-table tbody tr").forEach((row, i) => { if (entries[i].expired) row.classList.add("wl-expired"); });
}

/** The activity log's hash chain: intact (entries checked, archives) or where it breaks, and its latest hash,
 * which copies on click (store.verify_audit, store.audit_head). */
function chainRow(chain: { ok: boolean; checked: number; head: string; where?: string; entry?: number | null }, archives: number): HTMLElement {
  const head = h("button", { class: "hash-chip", type: "button", title: "Copy", "aria-label": "Copy the latest hash" },
    icon("copy", 12), chain.head ? chain.head.slice(0, 16) : "—") as HTMLButtonElement;
  head.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(chain.head); head.classList.add("done"); } catch { /* refused outside a focused page */ }
  });
  return h("div", { class: "row", style: { margin: "0 0 12px", gap: "8px" } },
    chain.ok ? badge(`Chain ✓ ${fmt.int(chain.checked)}`, "ok")
      : badge(`Chain broken · ${chain.where === "live" ? `#${chain.entry}` : chain.where}`, "bad"),
    archives ? badge(`${fmt.int(archives)} archived`, "muted") : null, head);
}

async function drawActivity(card: HTMLElement): Promise<void> {
  const [{ entries, default_password, chain, archives }, sqlPassword] = await Promise.all([api("/api/audit"), api("/api/sql/password")]);
  const panel = h("div");
  const password = () => h("input", { type: "password", autocomplete: "off", style: { width: "160px" } }) as HTMLInputElement;
  const showClear = () => {
    const pw = password();
    const err = h("div");
    const go = h("button", { class: "btn danger small" }, icon("archive", 14), "Archive") as HTMLButtonElement;
    go.addEventListener("click", async () => {
      go.disabled = true;
      try {
        await api("/api/audit/clear", { body: { password: pw.value } });
        drawActivity(card);
      } catch (e) {
        if ((e as { code?: string }).code === "default_password") return showChange("/api/admin/password");
        clear(err, errorBox(e));
        go.disabled = false;
      }
    });
    clear(panel, h("div", { class: "card alarm", style: { margin: "0 0 12px" } },
      h("div", { class: "row" }, icon("lock", 18), h("strong", {}, "Archive the activity log?"),
        h("span", { class: "small muted" }, `${entries.length} entries`)),
      h("div", { class: "row", style: { marginTop: "10px" } }, h("label", { class: "field" }, h("span", {}, "Password"), pw), go,
        h("button", { class: "btn small", onclick: () => clear(panel) }, "Cancel")), err));
    pw.focus();
  };
  // the admin password (/api/admin/password) or the SQL password (/api/sql/password, service/sql_lock.py)
  const showChange = (endpoint: string) => {
    const old = password(), next = password();
    const err = h("div");
    const go = h("button", { class: "btn primary small" }, "Change") as HTMLButtonElement;
    go.addEventListener("click", async () => {
      try {
        await api(endpoint, { body: { old: old.value, new: next.value } });
        drawActivity(card);
      } catch (e) {
        clear(err, errorBox(e));
      }
    });
    clear(panel, h("div", { class: "card accent", style: { margin: "0 0 12px" } },
      h("div", { class: "row" }, h("label", { class: "field" }, h("span", {}, "Current password"), old),
        h("label", { class: "field" }, h("span", {}, "New password (6+ characters)"), next), go,
        h("button", { class: "btn small", onclick: () => clear(panel) }, "Cancel")), err));
  };
  clear(card,
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("docs")), h("h2", {}, "Activity log"),
      h("span", { class: "end" },
        h("button", { class: "btn small", onclick: () => showChange("/api/admin/password") }, icon("lock", 14), "Admin password",
          default_password ? h("span", { class: "badge warn" }, "Default") : null),
        h("button", { class: "btn small", onclick: () => showChange("/api/sql/password") }, icon("data", 14), "SQL password",
          sqlPassword.default ? h("span", { class: "badge warn" }, "Default") : null),
        h("button", { class: "btn small", onclick: showClear }, icon("archive", 14), "Archive"))),
    chainRow(chain, archives),
    panel,
    entries.length
      ? table(["When", "Who", "What", "Object", "Detail"], entries.map((e: any) => [
          h("span", { class: "small mono" }, e.at.replace("T", " ").slice(0, 19)), e.actor, e.action.replace(/_/g, " "), e.object,
          h("span", { class: "tiny mono" }, e.detail)]))
      : h("p", { class: "muted" }, "Nothing recorded yet."));
}

// A few seconds of the chosen pack's animation, then its ending, without running anything.
let previewing = 0;
async function preview(box: HTMLElement, kind: "sql" | "review", fails = false): Promise<void> {
  const run = ++previewing;
  const loader = kind === "sql" ? sqlLoader("Preview: a SQL query") : reviewLoader("Preview: 10 min before and 10 min after", { before: 10, after: 10 });
  clear(box, h("div", { style: { marginTop: "10px" } }, loader.el));
  // the Commuter pack tells a longer story on the phone before the train or the bus arrives
  await new Promise((resolve) => window.setTimeout(resolve, state.settings.animation_pack === "commuter" ? 9000 : 4000));
  if (run !== previewing || !loader.el.isConnected) return;
  await (fails ? loader.fail() : loader.arrive({ found: 42 }));
  if (run === previewing) clear(box);
}
