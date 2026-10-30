// Models: one card per view (icon, status, alerts by detector) and the model zoo. Retraining is
// on Datasets, for an administrator signed in with SSO (Q26); the Retrain button goes there.

import { api } from "../api";
import { badge, capsules, clear, fmt, h, loading, pct } from "../dom";
import { icon, viewIcon } from "../icons";
import { chosenSource, logTypePicker } from "../log-type";
import { sourceLabel, state } from "../state";

const DETECTOR_LABELS: [string, string, string][] = [["robust", "Robust", ""], ["isolation_forest", "Isolation forest", "olive"], ["novelty", "Novelty", "red"]];
const MEASURES_DOC = "#/docs/app/06_model_zoo_measures";     // docs/user/06_model_zoo_measures.md, opened in Documentation

export async function renderModels(main: HTMLElement): Promise<void> {
  clear(main, loading());
  const data = await api("/api/models");
  const body = h("div");
  const draw = () => clear(body, ...section(data.models.filter((m: any) => m.source === chosenSource())));
  const admin = Boolean(data.auth?.admin);
  const retrain = h("a", { class: "btn small", href: "#/datasets", title: admin ? "Datasets → Train" : "Administrators only (SSO)" },
    icon(admin ? "refresh" : "lock", 14), "Retrain");
  clear(main,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Models")),
      h("div", { class: "row", style: { gap: "10px", alignItems: "flex-end" } }, retrain, logTypePicker(() => draw()))),
    body);
  draw();
}

function section(rows: any[]): (HTMLElement | null)[] {
  if (!rows.length) return [h("div", { class: "card" }, "No models for this log type.")];
  const presence = rows[0].method === "presence";
  const used = rows.filter((r) => r.used).length;
  const alerts = rows.reduce((s, r) => s + (r.used ? r.alerts.any ?? 0 : 0), 0);
  return [
    h("div", { class: "grid three", style: { marginBottom: "16px" } },
      h("div", { class: "card dark" },
        h("div", { class: "small", style: { opacity: "0.7" } }, sourceLabel(chosenSource())),
        h("div", { class: "big", style: { margin: "8px 0" } }, presence ? "Presence" : "Baseline"),
        h("div", { class: "small", style: { opacity: "0.8" } }, presence ? "Normal = no traffic" : "Learned normal activity")),
      h("div", { class: "card accent" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("models")), h("h2", {}, "Views used for alerts")),
        h("div", { class: "big" }, String(used), h("small", {}, `/ ${rows.length}`)),
        h("div", { style: { marginTop: "12px" } }, capsules(used / rows.length, rows.length))),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("alert")), h("h2", {}, "Test-period alerts")),
        h("div", { class: "big" }, fmt.int(alerts)),
        h("div", { class: "small muted", style: { marginTop: "8px" } }, "from views used for alerts"))),
    h("div", { class: "grid three" }, rows.map((r) => viewCard(r, presence))),
    !presence && rows.some((r) => r.zoo) ? h("div", { class: "card", style: { marginTop: "16px" } },
      h("div", { class: "card-head" }, h("span", { class: "chip-icon" }, icon("episode")), h("h2", {}, "Model zoo"),
        h("span", { class: "end row", style: { gap: "6px" } }, badge(`${state.settings.feature_set} features`, "muted"),
          h("a", { class: "icon-btn small info-link", href: MEASURES_DOC, title: "Detection, precision and lift", "aria-label": "Detection, precision and lift" },
            icon("info", 16)))),
      h("div", { class: "grid three" }, rows.filter((r) => r.zoo).map((r) => h("div", { class: `stat ${r.used ? "" : "excluded"}` },
        h("div", { class: "row" }, viewIcon(r.view, 18), h("strong", {}, r.view_label)),
        inclusion(r),
        h("div", { class: "row", style: { margin: "8px 0", gap: "4px" } }, r.zoo.ensemble.map((m: string) => badge(m.replace(/_/g, " "), "dark"))),
        h("div", { class: "small" }, `${fmt.int(r.zoo.ensemble_alerts)} ensemble · ${fmt.int(r.zoo.consensus_alerts)} consensus`),
        h("div", { class: "tiny muted", title: "Against a proxy label (known-risky events), not analyst labels" },
          `detection ${pct(r.zoo.test_detection_rate, 0)} · precision ${pct(r.zoo.test_precision, 0)} · lift ${fmt.num(r.zoo.test_lift, 0)}×`))))) : null,
  ];
}

function inclusion(r: any): HTMLElement {
  return h("div", { class: `inclusion ${r.used ? "in" : "out"}`, title: r.why },
    icon(r.used ? "check" : "alert", 14), r.used ? "Included in alerts" : "Excluded from alerts — too little data to trust");
}

function viewCard(r: any, presence: boolean): HTMLElement {
  const counts = DETECTOR_LABELS.map(([key]) => r.alerts[key] ?? 0);
  const max = Math.max(1, ...counts);
  return h("div", { class: "card" },
    h("div", { class: "card-head", style: { marginBottom: "6px" } }, h("span", { class: "chip-icon" }, viewIcon(r.view)), h("h2", {}, r.view_label)),
    inclusion(r),
    h("div", { class: "big" }, fmt.int(r.alerts.any), h("small", {}, `/ ${fmt.int(r.test_rows)}`)),
    h("div", { style: { margin: "12px 0" } }, DETECTOR_LABELS.map(([key, label, tone], i) => h("div", { class: "hbar" },
      h("span", { class: "muted" }, label),
      h("span", { class: "track" }, h("span", { class: `fill ${tone}`, style: { width: `${(counts[i] / max) * 100}%` } })),
      h("span", { class: "n" }, fmt.int(r.alerts[key]))))),
    presence && r.presence ? h("div", { class: "small" },
      `${fmt.int(r.presence.active_flagged)}/${fmt.int(r.presence.active_rows)} active flagged · ${fmt.int(r.presence.quiet_flagged)} quiet flagged`) : null,
    h("details", { class: "small" },
      h("summary", { class: "muted" }, "Details"),
      h("dl", { class: "kv", style: { marginTop: "8px" } },
        h("dt", {}, "Train / val / test"), h("dd", {}, `${fmt.int(r.train_rows)} / ${fmt.int(r.validation_rows)} / ${fmt.int(r.test_rows)}`),
        r.features ? [h("dt", {}, "Features"), h("dd", {}, fmt.int(r.features))] : null,
        Object.entries(r.thresholds).map(([k, v]) => [h("dt", {}, `${k} threshold`), h("dd", { class: "mono" }, fmt.num(v as number, 3))]),
        r.zoo?.families?.length ? [h("dt", {}, "Families"), h("dd", { class: "row", style: { gap: "4px", flexWrap: "wrap" } },
          r.zoo.families.map((family: string[]) => h("span", { class: "badge muted" }, family.map((m) => m.replace(/_/g, " ")).join(" + "))))] : null,
        r.calibration ? [h("dt", { title: "Test alert rate ÷ the rate the budget allowed on validation's calibrating half" }, "Test ÷ budget"),
          h("dd", { class: "row", style: { gap: "4px", flexWrap: "wrap" } }, Object.entries(r.calibration as Record<string, number | null>)
            .filter(([, ratio]) => ratio !== null && Number.isFinite(ratio))
            .map(([k, ratio]) => h("span", { class: `badge ${ratio! > 2 || ratio! < 0.5 ? "warn" : "muted"}` }, `${k.replace(/_/g, " ")} ×${fmt.num(ratio!, 2)}`)))] : null,
        h("dt", {}, "Status"), h("dd", {}, r.why))));
}
