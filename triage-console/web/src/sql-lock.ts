// The SQL password (service/sql_lock.py). The first SQL request of a sitting asks for it in a small dialog; the token it
// gives goes with every SQL request until it lapses (30 minutes without a query), the password changes, or the page
// reloads, and then the dialog asks again. One dialog however many requests wait on it.

import { api } from "./api";
import { clear, errorBox, h } from "./dom";
import { icon } from "./icons";

let token = "";
let asking: Promise<string> | null = null;

const locked = () => Object.assign(new Error("SQL password needed."), { code: "sql_locked" });

/** An SQL request (/api/sql, /api/sql/export, /api/sql/schema) with the token, asking for the password when needed.
 * Cancelling the dialog rejects with code "sql_locked". */
export async function sqlApi<T = any>(path: string, body: Record<string, unknown> = {}): Promise<T> {
  for (;;) {
    if (!token) token = await (asking ??= ask().finally(() => { asking = null; }));
    try {
      return await api<T>(path, { body: { ...body, token } });
    } catch (e) {
      if ((e as { code?: string }).code !== "sql_locked") throw e;
      token = "";                                                // lapsed or changed: ask again
    }
  }
}

export const isLocked = (e: unknown) => (e as { code?: string })?.code === "sql_locked";

/** In place of an SQL panel the password was not given for: one button to ask again. */
export function lockedCard(retry: () => void): HTMLElement {
  return h("div", { class: "card sql-locked" }, h("span", { class: "chip-icon" }, icon("lock")),
    h("button", { class: "btn primary", type: "button", onclick: retry }, icon("lock", 14), "Unlock"));
}

function ask(): Promise<string> {
  return new Promise((resolve, reject) => {
    const input = h("input", { type: "password", autocomplete: "off", placeholder: "Password", "aria-label": "SQL password" }) as HTMLInputElement;
    const err = h("div");
    const go = h("button", { class: "btn primary", type: "submit" }, icon("lock", 14), "Unlock") as HTMLButtonElement;
    const dialog = h("dialog", { class: "sql-lock", "aria-label": "SQL" },
      h("form", {},
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("data")), h("h2", {}, "SQL")),
        input, err,
        h("div", { class: "row sql-lock-actions" }, h("button", { class: "btn", type: "button", onclick: () => dialog.close() }, "Cancel"), go))) as HTMLDialogElement;
    let unlocked = false;
    let replacing = "";                          // the default password, while the dialog asks for a new one
    dialog.querySelector("form")!.addEventListener("submit", async (e) => {
      e.preventDefault();
      go.disabled = true;
      try {
        if (replacing) await api("/api/sql/password", { body: { old: replacing, new: input.value } });
        const r = await api("/api/sql/unlock", { body: { password: input.value } });
        unlocked = true;
        dialog.close();
        resolve(r.token);
      } catch (x) {
        if ((x as { code?: string }).code === "default_password") {    // the default opens nothing: set a new one
          replacing = input.value;
          input.value = "";
          input.placeholder = "New password";
          input.setAttribute("aria-label", "New SQL password");
          go.replaceChildren(icon("lock", 14), "Set");
          clear(err);
        } else {
          clear(err, errorBox(x));
        }
        input.select();
        go.disabled = false;
      }
    });
    dialog.addEventListener("close", () => { dialog.remove(); if (!unlocked) reject(locked()); });
    document.body.append(dialog);
    dialog.showModal();
    input.focus();
  });
}
