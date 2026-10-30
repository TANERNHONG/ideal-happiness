// The review labels, most serious first (service/store.py VERDICTS). Four match the triage
// categories of Phases 8 and 9; Suspicious sits between Security relevant and the rest.

import { h } from "./dom";
import { icon } from "./icons";

export interface Verdict { id: string; label: string; color: string; hint: string; note?: string }

export const VERDICTS: Verdict[] = [
  { id: "security_relevant", label: "Security relevant", color: "var(--st-bad)",
    hint: "Hostile or unauthorised activity is shown or strongly suggested, even if it was blocked or failed.", note: "what you found" },
  { id: "suspicious", label: "Suspicious", color: "var(--st-warn)",
    hint: "Could be hostile and nothing explains it yet: it needs a closer look.", note: "what should be checked next" },
  { id: "operationally_interesting", label: "Operationally interesting", color: "var(--st-ops)",
    hint: "Nothing hostile, but something needs fixing: a failing job, a misconfiguration, an outage." },
  { id: "expected_behavior", label: "Expected behaviour", color: "var(--st-good)",
    hint: "A specific routine explanation fits every line: maintenance, approved automation, a known job." },
  { id: "insufficient_evidence", label: "Insufficient evidence", color: "var(--st-gap)",
    hint: "The logs cannot decide it.", note: "what is missing" },
];

export function verdictLabel(id: string): string {
  return VERDICTS.find((v) => v.id === id)?.label ?? id.replace(/_/g, " ");
}

/** A Sigma rule that matched (Advanced → Sigma): its title. */
export function sigmaBadge(title: string, observations?: number): HTMLElement {
  return h("span", { class: "badge bad", title: observations ? String(observations) : "" }, icon("sigma", 12), title);
}

/** Covered by Settings → Whitelisted users: flagged by the models, but no review needed. */
export function whitelistBadge(text = "Whitelisted"): HTMLElement {
  return h("span", { class: "badge wl" }, icon("shield", 12), text);
}

/** A label as a badge; the colour is backed by the words, never alone. */
export function verdictBadge(id: string): HTMLElement {
  return h("span", { class: `badge verdict v-${id}` }, verdictLabel(id));
}
