// Datasets: the data the pipeline holds, adding a new dataset, importing its
// archives and training models. Viewing is open; every change needs a signed-in
// admin (single sign-on), because it changes the data the whole console uses.
// The exception: log types made in Patterns are not the pipeline's (unapproved),
// and anyone here may delete one (decision Q34), with a second click to confirm.

import { api } from "../api";
import { badge, clear, errorBox, fmt, h, loading, pct, select, table } from "../dom";
import { icon } from "../icons";

let poll = 0;

export async function renderDatasets(main: HTMLElement): Promise<void> {
  window.clearTimeout(poll);
  const body = h("div", {}, loading());
  clear(main, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Datasets"))), body);
  await draw(body);
}

async function draw(body: HTMLElement): Promise<void> {
  let d: any;
  try {
    d = await api("/api/datasets");
  } catch (e) {
    return clear(body, errorBox(e));
  }
  const admin = d.auth.admin;
  const reason = d.auth.mode === "off" ? "Needs single sign-on (SSO), which is not set up yet"
    : !d.auth.signed_in ? "Sign in with SSO first" : !admin ? "Needs the admin role" : "";
  const err = h("div");
  const act = async (path: string, payload: object) => {
    try {
      await api(path, { body: payload });
      await draw(body);
    } catch (e) {
      clear(err, errorBox(e));
    }
  };
  const running = d.runs.some((r: any) => r.status === "running" || r.status === "stopping");

  clear(body,
    signInCard(d.auth),
    err,
    h("div", { class: "card" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("data")), h("h2", {}, "Datasets")),
      table(["Dataset", "Log type", "Source", "Last trained", "Actions"], d.datasets.map((ds: any) => {
        const phase = select(d.phases.map((p: string) => [p, `from Phase ${p}`] as [string, string]), "1", () => undefined,
          { "aria-label": "Start training from phase", disabled: !admin || !ds.trainable || running });
        return [
          h("div", {}, h("strong", {}, ds.name), h("div", { class: "tiny muted" }, ds.id)),
          ds.log_type === "other" ? badge("needs a classifier", "warn") : ds.log_type.toUpperCase(),
          ds.builtin ? "built in" : h("span", { class: "small" }, `${ds.archives} archives · added by ${ds.added_by}`),
          ds.trained_at ?? (ds.builtin ? "—" : "not yet"),
          h("div", { class: "row", style: { gap: "6px" } },
            ds.builtin ? null : h("button", { class: "btn small", disabled: !admin || !ds.trainable, title: reason || "Copy its archives into the pipeline's raw folder",
              onclick: () => act("/api/datasets/import", { id: ds.id }) }, icon("upload", 14), "Import"),
            phase,
            h("button", { class: "btn small primary", disabled: !admin || !ds.trainable || running,
              title: reason || (running ? "A training run is already going" : !ds.trainable ? "No classifier for this log type yet" : "Run the pipeline and retrain the models"),
              onclick: () => act("/api/datasets/train", { id: ds.id, from_phase: (phase as HTMLSelectElement).value }) }, icon("play", 14), "Train")),
        ];
      }))),
    unapprovedCard(d.unapproved ?? [], () => draw(body), err),
    addCard(d, admin, reason, act),
    runsCard(d.runs, admin, act));
  if (running) poll = window.setTimeout(() => { if (body.isConnected) draw(body); }, 5000);
}

function signInCard(a: any): HTMLElement {
  if (a.mode === "off") {
    return h("div", { class: "card accent" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("lock")), h("h2", {}, "Single sign-on is not set up"),
        h("span", { class: "end" }, badge("read only", "warn"))),
      h("p", { style: { margin: 0, maxWidth: "80ch" } },
        "Adding datasets and training models change the data everyone relies on, so they need an administrator signed in with your organisation's single sign-on. "
        + "An administrator sets it up once in var/auth.json on this laptop and checks it with python -m service.sso_check (Documentation → SSO and datasets). "
        + "Until then you can look, but not add data or train."));
  }
  if (!a.signed_in) {
    return h("div", { class: "card accent" },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("lock")), h("h2", {}, "Sign in to make changes")),
      h("a", { class: "btn primary", href: a.login_url }, "Sign in with SSO"));
  }
  return h("div", { class: "card" },
    h("div", { class: "row" }, icon("check", 16), h("span", {}, "Signed in as ", h("strong", {}, a.user.name), ` (${a.user.email})`),
      a.admin ? badge("admin", "ok") : badge("not an admin: view only", "warn"),
      h("a", { class: "btn small", href: "/auth/logout", style: { marginLeft: "auto" } }, "Sign out")));
}

/** Log types made in Patterns, not part of the pipeline: each with its rules, last scan and table, and Delete. */
function unapprovedCard(list: any[], redraw: () => Promise<void>, err: HTMLElement): HTMLElement | null {
  if (!list.length) return null;
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("patterns")), h("h2", {}, "Unapproved log types"),
      h("span", { class: "end" }, badge(String(list.length), "warn"))),
    table(["Log type", "Rules", "Last scan", "Table", ""], list.map((u) => [
      h("div", {}, h("strong", {}, u.name), h("div", { class: "tiny muted" }, `${u.created_by} · ${u.created_at.slice(0, 16).replace("T", " ")}`)),
      String(Object.values(u.rules as Record<string, number>).reduce((a, b) => a + b, 0)),
      u.last ? h("div", {}, h("span", { class: "small" }, u.last.dataset),
        h("div", { class: "tiny muted" }, `${fmt.int(u.last.lines)} lines · ${pct(u.last.coverage)} known · ${u.passes} scans`)) : "—",
      u.table ? h("span", { class: "pt-table-chip" }, h("strong", {}, u.table.format), h("code", {}, u.table.raw)) : "—",
      deleteButton(u.name, redraw, err),
    ])));
}

/** Delete, then once more to confirm (for a few seconds); no sign-in needed. */
function deleteButton(name: string, redraw: () => Promise<void>, err: HTMLElement): HTMLElement {
  const button = h("button", { class: "btn small" }, icon("trash", 14), "Delete") as HTMLButtonElement;
  let armed = 0;
  const disarm = () => { armed = 0; button.classList.remove("danger"); clear(button, icon("trash", 14), "Delete"); };
  button.addEventListener("click", async () => {
    if (!armed) {
      armed = window.setTimeout(disarm, 4000);
      button.classList.add("danger");
      clear(button, icon("trash", 14), `Delete ${name}?`);
      return;
    }
    window.clearTimeout(armed);
    button.disabled = true;
    try {
      await api("/api/patterns/families/delete", { body: { name } });
      await redraw();
    } catch (e) {
      disarm();
      button.disabled = false;
      clear(err, errorBox(e));
    }
  });
  return button;
}

function addCard(d: any, admin: boolean, reason: string, act: (path: string, payload: object) => Promise<void>): HTMLElement {
  const field = (label: string, input: HTMLElement) => h("label", { class: "field" }, h("span", {}, label), input);
  const id = h("input", { type: "text", placeholder: "auth-2026-08", disabled: !admin }) as HTMLInputElement;
  const name = h("input", { type: "text", placeholder: "Authentication logs, August 2026", disabled: !admin }) as HTMLInputElement;
  const folder = h("input", { type: "text", placeholder: "D:\\deliveries\\2026-08", disabled: !admin, style: { width: "100%" } }) as HTMLInputElement;
  const notes = h("input", { type: "text", placeholder: "Optional", disabled: !admin, style: { width: "100%" } }) as HTMLInputElement;
  const type = select([...d.log_types, ["other", "Another log type (needs a classifier first)"]], "auth", () => undefined, { disabled: !admin });
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("upload")), h("h2", {}, "Add a dataset"),
      admin ? null : h("span", { class: "end small muted" }, reason)),
    h("p", { class: "small muted", style: { margin: "-4px 0 12px" } },
      "A folder of monthly archives named like the existing ones (for example “2026-08 NSEWL SCS.zip”). Registering does not change anything yet; Import copies the archives into the pipeline, and Train runs it."),
    h("div", { class: "grid", style: { gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" } },
      field("Short name", id), field("Name", name), field("Log type", type)),
    h("div", { class: "grid", style: { gridTemplateColumns: "2fr 1fr", gap: "12px", marginTop: "12px" } },
      field("Folder on this laptop", folder), field("Notes", notes)),
    h("div", { class: "row end", style: { marginTop: "12px" } },
      h("button", { class: "btn primary", disabled: !admin, title: reason,
        onclick: () => act("/api/datasets", { id: id.value, name: name.value, log_type: (type as HTMLSelectElement).value, folder: folder.value, notes: notes.value }) },
        "Add dataset")));
}

function runsCard(runs: any[], admin: boolean, act: (path: string, payload: object) => Promise<void>): HTMLElement {
  const tone = (s: string) => (s === "finished" ? "ok" : s === "failed" ? "bad" : s === "running" ? "info" : "warn");
  return h("div", { class: "card" },
    h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("models")), h("h2", {}, "Training runs")),
    runs.length ? runs.map((r) => h("div", { class: "comment" },
      h("div", { class: "row" }, badge(r.status, tone(r.status) as any), h("strong", {}, `${r.dataset} · from Phase ${r.from_phase}`),
        h("span", { class: "small muted" }, `${r.started_by} · ${r.started_at.replace("T", " ").slice(0, 16)}`),
        r.status === "running" && admin ? h("button", { class: "btn small", style: { marginLeft: "auto" }, onclick: () => act("/api/datasets/stop", {}) }, "Stop") : null),
      r.tail.length ? h("details", { open: r.status === "running" }, h("summary", { class: "small" }, "Output"),
        h("div", { class: "lines" }, r.tail.map((line: string) => h("div", {}, line)))) : null))
      : h("p", { class: "small muted" }, "No training runs yet."));
}
