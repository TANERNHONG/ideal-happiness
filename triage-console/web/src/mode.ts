// Simple or Advanced (Settings → Console, and the switch at the top of the menu). One setting for both
// modes, like every other: switching keeps you where you are when that page is in both (Settings, an
// upload), or takes you to its counterpart: Check logs ↔ Analyze, the uploads ↔ Review.

import { updateSettings } from "./state";

const COUNTERPART: Record<string, string> = { simple: "analyze", analyze: "simple", uploads: "review", review: "uploads" };

export function setMode(to: "simple" | "advanced"): Promise<void> {
  const id = location.hash.replace(/^#\/?/, "").split("/")[0];
  const next = id === "settings" || id === "upload" ? location.hash : `#/${COUNTERPART[id] ?? (to === "simple" ? "simple" : "dashboard")}`;
  if (next !== location.hash) history.replaceState(null, "", next);
  return updateSettings({ console_mode: to });
}
