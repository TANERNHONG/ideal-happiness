"""What the pipeline has produced: sources, views, models, time splits.

Read from the Phase 4 summaries on disk, so the console always describes the
models that actually exist.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import activity, event_counts
from .config import DATA

SOURCES = {
    "auth": {"label": "Authentication (authlog)", "prefix": "authlog", "method": "baseline",
             "views": ["individual", "authentication_sessions", "host_5min", "host_behavior_1d"]},
    "ossec": {"label": "OSSEC agent (ossec)", "prefix": "ossec", "method": "baseline",
              "views": ["individual", "episodes", "host_5min", "host_behavior_1d"]},
    "pf": {"label": "PF firewall (pflog)", "prefix": "pflog", "method": "presence",
           "views": ["individual", "attempts", "flow_episodes", "slots_5min", "slots_1h", "slots_1d"]},
    "ipf": {"label": "IPFilter firewall (ipflog)", "prefix": "ipflog", "method": "presence",
            "views": ["individual", "attempts", "flow_episodes", "slots_5min", "slots_1h", "slots_1d"]},
}

# What one observation of each view is, and what an input must contain to form one.
VIEWS = {
    "individual": {"label": "Individual lines", "unit": "one log line", "needs": "line"},
    "authentication_sessions": {"label": "Sessions", "unit": "one SSH or su session", "needs": "session"},
    "episodes": {"label": "Episodes", "unit": "one burst of related agent events", "needs": "session"},
    "attempts": {"label": "Attempts", "unit": "one connection attempt (packets of one flow, no pause over 5 minutes)", "needs": "session"},
    "flow_episodes": {"label": "Flow episodes", "unit": "one flow's activity, no pause over 30 minutes", "needs": "session"},
    "host_5min": {"label": "5-minute windows", "unit": "one server over 5 minutes", "needs": "5min"},
    "slots_5min": {"label": "5-minute slots", "unit": "one server over 5 minutes, empty slots included", "needs": "5min"},
    "slots_1h": {"label": "1-hour slots", "unit": "one server over an hour", "needs": "1h"},
    "host_behavior_1d": {"label": "Daily behaviour", "unit": "one server over a day", "needs": "1d"},
    "slots_1d": {"label": "1-day slots", "unit": "one server over a day", "needs": "1d"},
}


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def model_status(source: str, view: str) -> dict:
    """Whether the view's models exist and whether Phase 7 uses them for alerts."""
    folder = DATA / "phase4_detection" / source / "detectors" / view
    summary = _json(folder / "summary.json")
    if not summary:
        return {"available": False, "used": False, "why": "No trained models for this view."}
    if "alerting_in_phase7" in summary:              # presence method
        used = bool(summary["alerting_in_phase7"])
        why = "Alerts in Phase 7." if used else "Report only: reported but not used for alerts."
    else:
        status = summary.get("status", "")
        used = status == "acceptable_for_evaluation"
        why = "Alerts in Phase 7." if used else {
            "warning_low_rows_per_feature": "Not used for alerts: too few observations per feature to trust the models.",
        }.get(status, f"Status: {status or 'unknown'}.")
    return {"available": True, "used": used, "why": why, "status": summary.get("status", "")}


def catalog() -> dict:
    """Per source: its views, and the extra views Review lists (Phase 4g activity alerts, auth and OSSEC)."""
    return {"sources": {
        key: {**{k: v for k, v in meta.items() if k != "views"},
              "views": [{"id": view, **VIEWS[view], **model_status(key, view)} for view in meta["views"]],
              "review_views": activity.available_views(key) if meta["method"] == "baseline" else []}
        for key, meta in SOURCES.items()}}


def models(feature_set: str = "selected") -> list[dict]:
    """One row per source and view: detector and model-zoo figures."""
    rows = []
    for source, meta in SOURCES.items():
        for view in meta["views"]:
            det = _json(DATA / "phase4_detection" / source / "detectors" / view / "summary.json")
            if not det:
                continue
            zoo = _json(DATA / "phase4_detection" / source / "model_zoo" / view / feature_set / "dataset_summary.json")
            families = _json(DATA / "phase4_detection" / source / "model_zoo" / view / feature_set / "families.json")
            rows.append({
                "source": source, "view": view, "view_label": VIEWS[view]["label"], **model_status(source, view),
                "method": meta["method"],
                "train_rows": det.get("train_rows", det.get("baseline_train_rows")),
                "validation_rows": det.get("validation_rows", det.get("baseline_validation_rows")),
                "test_rows": det.get("test_rows", det.get("scored_rows")),
                "features": det.get("selected_features"),
                "thresholds": {k.replace("_threshold", ""): det[k] for k in
                               ("robust_threshold", "isolation_threshold", "novelty_threshold") if k in det},
                "threshold_rule": det.get("threshold_rule") or det.get("isolation_threshold_source", ""),
                "alerts": {"robust": det.get("test_robust_alerts"), "isolation_forest": det.get("test_isolation_alerts"),
                           "novelty": det.get("test_novelty_alerts"), "any": det.get("test_either_model_alerts")},
                "calibration": {**{k: v.get("ratio") for k, v in (det.get("calibration") or {}).items()},
                                **({"ensemble": zoo["ensemble_calibration"].get("ratio")} if zoo.get("ensemble_calibration") else {})} or None,
                "calibration_split": zoo.get("calibration_split") if zoo else None,
                "presence": {k: det[k] for k in ("active_rows", "active_flagged", "active_missed", "quiet_flagged",
                                                 "baseline_train_false_alarms") if k in det} or None,
                "zoo": {
                    "models": zoo.get("models_completed", []), "ensemble": zoo.get("ensemble_members", []),
                    "consensus_alerts": zoo.get("test_consensus_alerts"), "ensemble_alerts": zoo.get("test_ensemble_alerts"),
                    "proxy_label": zoo.get("proxy_label_source"), "test_detection_rate": zoo.get("test_ensemble_detection_rate"),
                    "test_precision": zoo.get("test_ensemble_precision"), "test_lift": zoo.get("test_ensemble_lift"),
                    "families": families.get("families"), "family_consensus_alerts": families.get("test_family_consensus_alerts"),
                } if zoo else None,
                "seconds": det.get("total_seconds"),
            })
    return rows


def splits() -> list[dict]:
    """The time spans used for training, validation and testing, per source and view."""
    out = []
    for source, meta in SOURCES.items():
        for view in meta["views"]:
            folder = DATA / "phase4_detection" / source / "detectors" / view
            cover = _json(folder / "temporal_coverage_validation.json")
            det = _json(folder / "summary.json")
            if cover:
                val, test = cover.get("validation", {}), cover.get("test", {})
                out.append({"source": source, "view": view, "method": "time",
                            "train": {"start": event_counts.first_day(source), "end": val.get("first_timestamp", "")[:19],
                                      "rows": det.get("train_rows")},
                            "validation": {"start": val.get("first_timestamp", "")[:19],
                                           "end": val.get("last_timestamp", "")[:19], "rows": val.get("rows")},
                            "test": {"start": test.get("first_timestamp", "")[:19],
                                     "end": test.get("last_timestamp", "")[:19], "rows": test.get("rows")}})
            elif det and meta["method"] == "presence":
                out.append({"source": source, "view": view, "method": "presence",
                            "note": "Baseline = certified quiet periods across the year (85% train, 15% validation); "
                                    "every period is scored. There is no single training span.",
                            "train": {"rows": det.get("baseline_train_rows")},
                            "validation": {"rows": det.get("baseline_validation_rows")},
                            "test": {"rows": det.get("scored_rows")}})
    return out
