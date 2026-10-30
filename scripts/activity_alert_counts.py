"""How Phase 4g's activity alerts (the Explain tab) were flagged, for one log type: counts only, no names or addresses.

  python scripts/activity_alert_counts.py auth
  python scripts/activity_alert_counts.py ossec --data path/to/data

Reads data/phase4_detection/<source>/activity/<view>/test_scores.csv, explanations.jsonl and summary.json.
"""
import argparse
import json
from pathlib import Path

import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument("source", nargs="?", default="auth")
parser.add_argument("--data", type=Path, default=Path(__file__).resolve().parents[1] / "data")
args = parser.parse_args()
root = args.data / "phase4_detection" / args.source / "activity"
pd.set_option("display.width", 200)
pd.set_option("display.max_columns", 30)

frames, types = [], []
for view in ("activity", "activity_by_entity"):
    folder = root / view
    if not (folder / "test_scores.csv").is_file():
        continue
    alerts = pd.read_csv(folder / "test_scores.csv")
    records = {}
    if (folder / "explanations.jsonl").is_file():
        with (folder / "explanations.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                r = json.loads(line)
                records[r["row_manifest_id"]] = r
    big = alerts["row_manifest_id"].map(lambda i: (records.get(i) or {}).get("big") or {})
    history = alerts["row_manifest_id"].map(lambda i: ((records.get(i) or {}).get("context") or {}).get("history") or {})
    alerts["explained"] = big.map(lambda b: "mix (forest only)" if b.get("mix") else b.get("direction", "no record"))
    alerts["compared_with"] = (alerts["calendar_basis"].fillna("").replace("", "level when active")
                               if "calendar_basis" in alerts else "level when active (before 2026-10-28)")
    alerts["in_training"] = history.map(lambda h: {True: "yes", False: "no (first seen after training)"}.get(h.get("in_training"), "unknown"))
    frames.append(alerts)
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    types += summary.get("types", [])

if not frames:
    raise SystemExit(f"No Phase 4g output under {root}")
alerts = pd.concat(frames, ignore_index=True)
print(f"\n{args.source}: {len(alerts):,} activity alerts (episodes)\n")
print("1. Which detector flagged them, by entity type")
print(pd.crosstab(alerts["entity_type"], alerts["detector_combination"], margins=True), "\n")
print("2. Baseline of the level (own: >= --min-history active training steps; pooled: its entity type's) and the direction Explain found")
print(pd.crosstab([alerts["detector_combination"], alerts["baseline"]], alerts["explained"], margins=True), "\n")
print("3. What the calendar half compared them with")
print(pd.crosstab(alerts["compared_with"], alerts["entity_type"], margins=True), "\n")
print("4. Seen in training?")
print(pd.crosstab(alerts["entity_type"], alerts["in_training"], margins=True), "\n")
print("5. The alert's peak window (minutes) and how many 5-minute steps it lasted")
print(pd.crosstab(alerts["peak_window_minutes"], alerts["steps"].clip(upper=12).map(lambda s: f"{s}" if s < 12 else "12+"), margins=True), "\n")
print("6. Per entity type: thresholds, validation alerts, and test alert steps by rule")
columns = ["view", "entity_type", "series", "own_baseline_series", "calendar_share", "validation_days",
           "allowed_validation_alerts", "robust_threshold", "robust_threshold_source", "validation_robust_alerts",
           "forest_threshold", "forest_alone_threshold", "validation_forest_alone_alerts", "test_rows", "test_alert_steps",
           "test_robust_steps", "test_forest_alone_steps", "test_drop_steps"]
print(pd.DataFrame(types).reindex(columns=columns).to_string(index=False))
