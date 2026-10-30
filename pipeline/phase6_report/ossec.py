"""Generate a self-contained HTML threat-analysis report for OSSEC Stages 1-5.

Default inputs
--------------
data/phase1_classify/ossec/
data/phase2_observations/ossec/
data/phase3_features/ossec/
data/phase4_detection/ossec/detectors/
data/phase4_detection/ossec/model_zoo/
data/phase5_evidence/ossec/

Default output
--------------
data/phase6_report/ossec/ossec_threat_analysis_report.html

The report has no external CSS, JavaScript, font, image, or chart dependency.
Charts are rendered as inline SVG, allowing offline analyst use.

Update 2026-09-23
-----------------
* New sections read the Stage 4b model-zoo outputs (``--zoo``): ensemble
  results with proxy detection rates, greedy model-selection curves and
  membership decisions, feature relevance and top-K sweeps, full-vs-selected
  comparison, and the highest-agreement consensus alerts.
* The pipeline section shows events per observation for every Stage 2
  dataset, and the overview checks the episode grouping: builder version,
  events per episode and the share of scan episodes with both start and end.
  A later ``--episodes-only`` rebuild summary is preferred for episodes.
* Stage 1 totals come from ``processed_osseclogs.json`` and the unknown-event
  summaries. The previous fallback searched for ``classified_ossec_events_*``
  files, which Stage 1 does not write, so the total was zero.
* Stage 4 ``test_scores.csv`` files are no longer loaded; they were read in
  full but never used.

Update 2026-09-28
-----------------
* Stage 5 message chains can hold up to 250,000 characters in one field,
  above Python's default CSV field limit of 131,072, so reading them failed.
  The limit is raised at start-up, and the chain and detailed-evidence files
  are read keeping only the columns the report uses (``CHAIN_COLUMNS`` and
  ``DETAIL_COLUMNS``), so the full chain text is never held in memory.
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import html
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from model_behaviour import collect as collect_behaviour, render_section as behaviour_section
import report_layout as layout
from coverage_sections import activity_section, context_section, coverage_section, first_seen_section, silence_section
from cluster_maps import render_clusters_section, render_section as cluster_section

DATASETS = ("episodes", "individual", "host_5min", "host_behavior_1d")
LABELS = {
    "episodes": "Security episodes",
    "individual": "Individual events",
    "host_5min": "Five-minute host windows",
    "host_behavior_1d": "Daily host behavior",
}
FEATURE_SETS = ("full", "selected")
MINIMUM_SCAN_COMPLETION = 0.8
CHAIN_COLUMNS = ("dataset", "isolation_score", "observation_timestamp", "observation_entity",
                 "observation_process", "host_id", "process_name", "source_event_types",
                 "evidence_status", "representative_original_log_lines")
DETAIL_COLUMNS = ("severity", "hostname", "host_id", "process_name", "username", "source_ip")


def raise_csv_field_limit():
    """Allow very long CSV fields (Stage 5 chains can exceed the 131,072 default).

    ``sys.maxsize`` overflows the C long used on Windows, so the limit steps
    down by a factor of ten until it is accepted.
    """
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


raise_csv_field_limit()


def parse_args():
    parser = argparse.ArgumentParser(description="Generate an OSSEC threat-analysis HTML report.")
    parser.add_argument("--ossec-logs", type=Path, default=Path("data/phase1_classify/ossec"))
    parser.add_argument("--datasets", type=Path, default=Path("data/phase2_observations/ossec"))
    parser.add_argument("--features", type=Path, default=Path("data/phase3_features/ossec"))
    parser.add_argument("--experiments", type=Path, default=Path("data/phase4_detection/ossec/detectors"))
    parser.add_argument("--zoo", type=Path, default=Path("data/phase4_detection/ossec/model_zoo"),
                        help="Stage 4b model-zoo output folder.")
    parser.add_argument("--evidence", type=Path, default=Path("data/phase5_evidence/ossec"))
    parser.add_argument("--output", type=Path, default=Path("data/phase6_report/ossec/ossec_threat_analysis_report.html"))
    parser.add_argument("--top-alerts", type=int, default=25)
    parser.add_argument("--top-categories", type=int, default=16)
    parser.add_argument("--top-entities", type=int, default=12)
    parser.add_argument("--top-features", type=int, default=15)
    parser.add_argument("--no-model-behaviour", action="store_true",
                        help="Skip the Model behaviour section (it reads every Phase 4 score file once; later runs use model_behaviour_cache.json beside the report).")
    parser.add_argument("--redact-source-ips", action="store_true")
    parser.add_argument("--redact-usernames", action="store_true")
    runlog.add_arguments(parser)
    return parser.parse_args()


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


def txt(value):
    return "" if value is None else str(value).strip()


def num(value, default=0.0):
    try:
        value = float(value)
        return value if math.isfinite(value) else default
    except (TypeError, ValueError):
        return default


def integer(value):
    return int(num(value))


def esc(value):
    return html.escape(txt(value), quote=True)


def compact(value, limit=220):
    value = re.sub(r"\s+", " ", txt(value)).strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def read_csv(path, limit=None, columns=None):
    """Read a CSV into dictionaries, optionally keeping only some columns.

    :param path: CSV path; a missing file returns an empty list.
    :param limit: Optional maximum number of rows.
    :param columns: Optional column names to keep (missing ones become empty).
    :returns: Row dictionaries.
    :rtype: list
    """
    if not path.is_file():
        return []
    rows = []
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle)):
            rows.append({key: row.get(key, "") for key in columns} if columns else dict(row))
            if limit is not None and index + 1 >= limit:
                break
    return rows


def read_json(path, default=None):
    if not path.is_file():
        return {} if default is None else default
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def count(value):
    return f"{integer(value):,}"


def rate(value):
    return f"{num(value) * 100:.2f}%"


def maybe_rate(value):
    return rate(value) if txt(value) not in ("", "None", "nan") else "–"


def number(value, digits=5):
    return f"{num(value):,.{digits}f}"


def truth(value):
    return txt(value).lower() in {"1", "true", "yes", "y"}


def redact(value, prefix, enabled):
    value = txt(value)
    if not enabled or not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return prefix + "-" + digest


def badge(value, kind="neutral"):
    return f'<span class="badge {kind}">{esc(value)}</span>'


def status_badge(value):
    raw = txt(value) or "unknown"
    lower = raw.lower()
    if any(token in lower for token in ("failed", "invalid", "missing")):
        kind = "danger"
    elif any(token in lower for token in ("skip", "partial", "warning", "fallback")):
        kind = "warning"
    elif any(token in lower for token in ("complete", "acceptable", "calibrated", "success")):
        kind = "success"
    else:
        kind = "neutral"
    return badge(raw.replace("_", " "), kind)


def empty(message):
    return f'<div class="empty">{esc(message)}</div>'


def table(headers, rows, css_class=""):
    if not rows:
        return empty("No data available")
    output = [f'<div class="table-wrap"><table class="{esc(css_class)}"><thead><tr>']
    output.extend(f"<th>{esc(header)}</th>" for header in headers)
    output.append("</tr></thead><tbody>")
    for row in rows:
        output.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    output.append("</tbody></table></div>")
    return "".join(output)


def bar_chart(items, title, color="#2563eb"):
    values = [(txt(label), num(value)) for label, value in items if txt(label)]
    if not values:
        return empty("No chart data available")
    width, left, right, top, step = 900, 225, 90, 46, 30
    height = top + 26 + len(values) * step
    maximum = max(value for _, value in values) or 1
    plot = width - left - right
    output = [f'<svg class="chart" viewBox="0 0 {width} {height}"><text x="0" y="22" class="chart-title">{esc(title)}</text>']
    for index, (label, value) in enumerate(values):
        y = top + index * step
        bar = max((value / maximum) * plot, 1 if value else 0)
        output.extend([
            f'<text x="0" y="{y+16}" class="axis">{esc(compact(label, 32))}</text>',
            f'<rect x="{left}" y="{y+2}" width="{plot}" height="18" rx="5" fill="#e5e7eb"/>',
            f'<rect x="{left}" y="{y+2}" width="{bar:.1f}" height="18" rx="5" fill="{color}"/>',
            f'<text x="{left+bar+7:.1f}" y="{y+16}" class="value">{value:,.0f}</text>',
        ])
    output.append("</svg>")
    return "".join(output)


def grouped_chart(rows):
    if not rows:
        return empty("No detector data available")
    width, height = 900, 370
    left, right, top, bottom = 68, 24, 52, 94
    plot_width, plot_height = width-left-right, height-top-bottom
    maximum = max([value for row in rows for value in row[1:4]] + [.01])
    colors = ("#8b5cf6", "#dc2626", "#f59e0b")
    output = [f'<svg class="chart" viewBox="0 0 {width} {height}"><text x="0" y="24" class="chart-title">Test alert rate by detector</text>']
    for tick in range(6):
        value = maximum * tick / 5
        y = top + plot_height - plot_height * tick / 5
        output.extend([
            f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#e5e7eb"/>',
            f'<text x="{left-7}" y="{y+4}" text-anchor="end" class="axis">{value*100:.1f}%</text>',
        ])
    group_width = plot_width / len(rows)
    bar_width = min(40, group_width / 5)
    for index, row in enumerate(rows):
        center = left + group_width * (index + .5)
        for series, value in enumerate(row[1:4]):
            bar_height = value / maximum * plot_height
            x = center + (series - 1) * (bar_width + 5) - bar_width / 2
            y = top + plot_height - bar_height
            output.append(f'<rect x="{x}" y="{y}" width="{bar_width}" height="{bar_height}" rx="4" fill="{colors[series]}"/>')
        output.append(f'<text transform="translate({center},{height-bottom+18}) rotate(22)" class="axis">{esc(compact(row[0], 25))}</text>')
    for index, (label, color) in enumerate(zip(("Robust", "Isolation Forest", "Novelty"), colors)):
        x = width - 430 + index * 140
        output.extend([
            f'<rect x="{x}" y="12" width="13" height="13" rx="3" fill="{color}"/>',
            f'<text x="{x+18}" y="23" class="axis">{label}</text>',
        ])
    output.append("</svg>")
    return "".join(output)


def curve_chart(rows, title):
    """Detection rate by number of models, with the kept prefix highlighted."""
    points = [(integer(row.get("step")), num(row.get("validation_detection_rate")), txt(row.get("model_added")), truth(row.get("selected"))) for row in rows]
    points = [point for point in points if point[0] > 0]
    if not points:
        return empty("No selection curve available")
    width, height, left, right, top, bottom = 900, 330, 64, 110, 48, 92
    plot_width, plot_height = width-left-right, height-top-bottom
    maximum = max(max(point[1] for point in points), 0.01)
    steps = max(point[0] for point in points)

    def xy(step, value):
        x = left + (step - 1) / max(steps - 1, 1) * plot_width
        return x, top + plot_height - value / maximum * plot_height

    output = [f'<svg class="chart" viewBox="0 0 {width} {height}"><text x="0" y="24" class="chart-title">{esc(title)}</text>']
    for tick in range(6):
        value = maximum * tick / 5
        y = top + plot_height - plot_height * tick / 5
        output.extend([
            f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#e5e7eb"/>',
            f'<text x="{left-7}" y="{y+4}" text-anchor="end" class="axis">{value*100:.0f}%</text>',
        ])
    path = " ".join(("M" if index == 0 else "L") + f"{xy(step, value)[0]:.1f},{xy(step, value)[1]:.1f}" for index, (step, value, _, _) in enumerate(points))
    output.append(f'<path d="{path}" fill="none" stroke="#2563eb" stroke-width="2.5"/>')
    for step, value, model, kept in points:
        x, y = xy(step, value)
        output.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{"#16a34a" if kept else "#94a3b8"}"/>')
        output.append(f'<text transform="translate({x:.1f},{height-bottom+16}) rotate(30)" class="axis">{esc(compact(model, 20))}</text>')
    output.append(f'<text x="{width-right}" y="24" text-anchor="end" class="axis">green = kept in ensemble</text></svg>')
    return "".join(output)


def donut(parts):
    parts = [(label, num(value), color) for label, value, color in parts if num(value) > 0]
    if not parts:
        return empty("No evidence data available")
    total = sum(value for _, value, _ in parts)
    radius = 70
    circumference = 2 * math.pi * radius
    offset = 0
    output = ['<svg class="chart" viewBox="0 0 560 260"><text x="0" y="24" class="chart-title">Evidence completeness</text>']
    for label, value, color in parts:
        length = circumference * value / total
        output.append(f'<circle cx="120" cy="130" r="{radius}" fill="none" stroke="{color}" stroke-width="29" stroke-dasharray="{length} {circumference-length}" stroke-dashoffset="{-offset}" transform="rotate(-90 120 130)"/>')
        offset += length
    output.extend([
        f'<text x="120" y="128" text-anchor="middle" class="donut">{total:,.0f}</text>',
        '<text x="120" y="149" text-anchor="middle" class="axis">alerts</text>',
    ])
    for index, (label, value, color) in enumerate(parts):
        y = 76 + index * 36
        output.extend([
            f'<rect x="245" y="{y-12}" width="14" height="14" rx="3" fill="{color}"/>',
            f'<text x="268" y="{y}" class="axis">{esc(label)}: {value:,.0f}</text>',
        ])
    output.append("</svg>")
    return "".join(output)


def first_existing_csv(folder, names):
    for name in names:
        path = folder / name
        if path.is_file():
            return read_csv(path)
    return []


def load_classification(folder):
    """Build per-month Stage 1 totals without re-reading the monthly CSVs.

    Rows come from ``processed_osseclogs.json`` and unknown counts from the
    monthly unknown-event summaries. Legacy summary CSVs are still accepted.
    """
    legacy = first_existing_csv(folder, (
        "ossec_classification_summary.csv", "classification_summary.csv",
        "ossec_monthly_classification_summary.csv",
    ))
    if legacy:
        return legacy
    manifest = read_json(folder / "processed_osseclogs.json")
    outputs = manifest.get("outputs", {}) if isinstance(manifest, dict) else {}
    rows = []
    for month, information in sorted(outputs.items()):
        unknown = sum(integer(row.get("count")) for row in read_csv(folder / f"unknown_ossec_events_{month}.csv"))
        rows.append({"month": month, "output_file": txt(information.get("path")),
                     "output_rows": integer(information.get("rows")), "unknown_events": unknown})
    return rows


def load_observations(folder):
    """Load Stage 2 summaries; an ``--episodes-only`` rebuild replaces episodes."""
    observations = first_existing_csv(folder, (
        "ossec_observation_dataset_summary.csv", "observation_dataset_summary.csv",
    ))
    combined = read_json(folder / "ossec_observation_dataset_summary.json")
    episodes_only = read_csv(folder / "ossec_security_episodes_summary.csv")
    episode_json = combined
    if episodes_only:
        observations = [row for row in observations if txt(row.get("dataset")) != "episodes"] + episodes_only
        episode_json = read_json(folder / "ossec_security_episodes_summary.json")
    episode_json = episode_json if isinstance(episode_json, dict) else {}
    return observations, {
        "builder_version": txt(episode_json.get("builder_version")),
        "has_lifecycle_rules": bool(episode_json.get("episode_rules")),
        "statistics": episode_json.get("episode_statistics") or {},
    }


def load_zoo(folder, top_alerts, log):
    """Load Stage 4b model-zoo outputs; every part is optional."""
    zoo = {"summaries": [], "metrics": [], "membership": read_csv(folder / "all_ensemble_membership.csv"),
           "curves": read_csv(folder / "all_model_selection_curves.csv"),
           "comparison": read_csv(folder / "feature_set_comparison.csv"),
           "sweeps": read_csv(folder / "all_feature_sweeps.csv"),
           "relevance": {}, "consensus": {}}
    summary = read_json(folder / "model_zoo_summary.json")
    if isinstance(summary, dict):
        zoo["summaries"] = [item for item in summary.get("datasets", []) if isinstance(item, dict)]
        zoo["metrics"] = [item for item in summary.get("model_metrics", []) if isinstance(item, dict)]
    for dataset in DATASETS:
        zoo["relevance"][dataset] = read_csv(folder / dataset / "feature_relevance.csv")
        for feature_set in FEATURE_SETS:
            files = sorted(glob.glob(str(folder / dataset / feature_set / "consensus_alerts_min*.csv")))
            if files:
                zoo["consensus"][(dataset, feature_set)] = read_csv(Path(files[0]), limit=top_alerts)
    if zoo["summaries"]:
        log.say(f"Loaded model-zoo results for {len(zoo['summaries'])} dataset/feature-set runs", "DONE")
    return zoo


def load_data(args, log):
    log.say("Loading OSSEC Stage 1-5 artifacts", "PHASE")
    observations, episode_health = load_observations(args.datasets)
    result = {
        "classification": load_classification(args.ossec_logs),
        "stage1": read_json(args.ossec_logs / "ossec_lineage_summary.json"),
        "observations": observations,
        "episode_health": episode_health,
        "features": read_json(args.features / "feature_engineering_summary.json"),
        "feature_lineage": read_csv(args.features / "lineage_summary.csv"),
        "export": read_csv(args.evidence / "ossec_isolation_forest_outlier_export_summary.csv"),
        "categories": read_csv(args.evidence / "ossec_isolation_forest_outlier_categories.csv"),
        "chains": read_csv(args.evidence / "ossec_isolation_forest_outlier_message_chains.csv", columns=CHAIN_COLUMNS),
        "details": read_csv(args.evidence / "ossec_isolation_forest_outlier_events_detailed.csv", columns=DETAIL_COLUMNS),
        "summaries": {}, "reviews": {},
        "zoo": load_zoo(args.zoo, args.top_alerts, log),
    }
    for dataset in DATASETS:
        folder = args.experiments / dataset
        result["summaries"][dataset] = read_json(folder / "summary.json")
        result["reviews"][dataset] = read_csv(folder / "manual_review_queue.csv")
    result["behaviour"] = None if args.no_model_behaviour else collect_behaviour(
        args.experiments, args.zoo, "selected", args.output.parent / "model_behaviour_cache.json",
        log=lambda message: log.say(message, "PHASE"))
    log.say(f"Loaded {len(result['chains']):,} anomaly chains and {len(result['details']):,} source OSSEC events", "DONE")
    return result


def calculate_metrics(data):
    total = sum(integer(row.get("output_rows", row.get("total_events", row.get("rows")))) for row in data["classification"])
    unknown = sum(integer(row.get("unknown_events", row.get("unknown_event_count"))) for row in data["classification"])
    completed = [summary for summary in data["summaries"].values() if summary and not txt(summary.get("status")).startswith("skipped") and summary.get("status") != "failed"]
    union = sum(integer(summary.get("test_either_model_alerts")) for summary in completed)
    isolation = sum(integer(summary.get("test_isolation_alerts")) for summary in completed)
    complete = sum(integer(row.get("complete_evidence_alerts", row.get("alerts_with_complete_evidence"))) for row in data["export"])
    partial = sum(integer(row.get("partial_evidence_alerts", row.get("alerts_with_partial_evidence"))) for row in data["export"])
    missing = sum(integer(row.get("missing_evidence_alerts", row.get("alerts_without_evidence"))) for row in data["export"])
    return {
        "total": total, "unknown": unknown,
        "unknown_rate": unknown / total if total else 0,
        "completed": len(completed), "union": union, "isolation": isolation,
        "complete": complete, "partial": partial, "missing": missing,
    }


def risk_score(data, metrics):
    rates = [num(summary.get("test_either_model_alert_rate")) for summary in data["summaries"].values() if summary]
    maximum_rate = max(rates, default=0)
    dangerous = sum(
        integer(row.get("source_event_rows"))
        for row in data["categories"]
        if any(token in (txt(row.get("event_category")) + " " + txt(row.get("event_type"))).lower()
               for token in ("authentication", "rootcheck", "syscheck", "integrity", "critical", "error", "failure"))
    )
    value = min(round(
        min(metrics["unknown_rate"] / .05, 1) * 20
        + min(maximum_rate / .10, 1) * 25
        + min(dangerous / 100, 1) * 25
        + min(metrics["union"] / 500, 1) * 20
        + (10 if metrics["partial"] or metrics["missing"] else 0)
    ), 100)
    if value >= 75:
        return value, "Critical review priority", "danger"
    if value >= 50:
        return value, "High review priority", "danger"
    if value >= 25:
        return value, "Moderate review priority", "warning"
    return value, "Low observed risk", "success"


def episode_findings(data):
    """Check whether Stage 2 episodes use the lifecycle grouping and look healthy."""
    record = next((row for row in data["observations"] if txt(row.get("dataset")) == "episodes"), None)
    if record is None:
        return []
    health = data["episode_health"]
    mean = num(record.get("mean_events_per_observation"))
    if not health["has_lifecycle_rules"]:
        return [("Episodes use version 01 grouping", f"{mean:.2f} events per episode. Scans and outages are split across episodes; rerun Stage 2 (builder version 02) and Stage 3.", "danger")]
    statistics = health["statistics"]
    completion = statistics.get("scan_completion_rate")
    reasons = statistics.get("close_reasons") or {}
    detail = f"{mean:.2f} events per episode; close reasons: " + ", ".join(f"{key} {value:,}" for key, value in sorted(reasons.items(), key=lambda item: -item[1]))
    if completion is not None and num(completion) < MINIMUM_SCAN_COMPLETION:
        return [("Many scans have no end event", f"Only {num(completion)*100:.1f}% of scan episodes contain both start and end. Check for missing log lines or long interruptions. " + detail, "warning")]
    suffix = f" {num(completion)*100:.1f}% of scans have both start and end." if completion is not None else ""
    return [("Episode grouping is healthy", detail + "." + suffix, "success")]


def overview(data, metrics, risk):
    value, label, kind = risk
    zoo_runs = [summary for summary in data["zoo"]["summaries"] if summary.get("status") == "completed"]
    consensus_total = sum(integer(summary.get("test_consensus_alerts")) for summary in zoo_runs if summary.get("feature_set") in ("selected", None)) or sum(integer(summary.get("test_consensus_alerts")) for summary in zoo_runs)
    cards = (
        ("Threat review score", f"{value}/100", label, kind),
        ("Classified OSSEC events", count(metrics["total"]), count(metrics["unknown"]) + " unknown", "neutral"),
        ("Union anomaly candidates", count(metrics["union"]), "Stage 4 experiments", "warning"),
        ("Isolation Forest alerts", count(metrics["isolation"]), "Exported for source review", "danger"),
        ("Model-zoo consensus alerts", count(consensus_total), f"{len(zoo_runs)} zoo runs", "warning" if consensus_total else "neutral"),
        ("Complete evidence", count(metrics["complete"]), count(metrics["missing"]) + " missing", "success" if not metrics["missing"] else "danger"),
    )
    card_html = "".join(
        f'<article class="metric-card {card_kind}"><div class="metric-title">{esc(title)}</div><div class="metric-value">{esc(card_value)}</div><div class="metric-sub">{esc(subtitle)}</div></article>'
        for title, card_value, subtitle, card_kind in cards
    )
    findings = []
    if metrics["unknown_rate"] > .02:
        findings.append(("Classification coverage needs attention", f"Unknown events are {metrics['unknown_rate']*100:.2f}% of classified OSSEC activity.", "warning"))
    elif metrics["total"]:
        findings.append(("Classification coverage is strong", f"Unknown events are {metrics['unknown_rate']*100:.2f}% of classified OSSEC activity.", "success"))
    findings.extend(episode_findings(data))
    for dataset in DATASETS:
        summary = data["summaries"].get(dataset) or {}
        state = txt(summary.get("status"))
        if state.startswith("skipped"):
            findings.append((LABELS[dataset] + " was skipped", "Population, temporal coverage, or dimensionality safeguards were not satisfied.", "warning"))
        elif state == "failed":
            findings.append((LABELS[dataset] + " failed", compact(summary.get("error"), 300), "danger"))
        elif integer(summary.get("test_either_model_alerts")):
            findings.append((LABELS[dataset] + " generated " + count(summary.get("test_either_model_alerts")) + " candidates", "Union alert rate: " + rate(summary.get("test_either_model_alert_rate")) + ". This is review workload, not confirmed compromise.", "warning"))
    for summary in zoo_runs:
        if txt(summary.get("test_ensemble_detection_rate")):
            findings.append((f"Model zoo – {LABELS.get(summary.get('dataset'), summary.get('dataset'))} ({summary.get('feature_set')})",
                             f"{len(summary.get('ensemble_members') or [])} ensemble models; proxy detection rate {maybe_rate(summary.get('test_ensemble_detection_rate'))} on test at {maybe_rate(summary.get('test_proxy_base_rate'))} base rate.", "neutral"))
    if metrics["missing"] or metrics["partial"]:
        findings.append(("Evidence gaps require remediation", f"Partial: {metrics['partial']:,}; missing: {metrics['missing']:,}.", "danger"))
    elif metrics["complete"]:
        findings.append(("Evidence lineage is complete", f"{metrics['complete']:,} Isolation Forest alerts resolve to original OSSEC records.", "success"))
    finding_html = "".join(f'<div class="finding {finding_kind}"><b>{esc(title)}</b><p>{esc(description)}</p></div>' for title, description, finding_kind in findings)
    return (
        '<section id="overview"><h2>Executive overview</h2>'
        '<p class="lead">Consolidated OSSEC behavior, anomaly candidates, and source evidence. Anomalies identify unusual activity, not proven attacks.</p>'
        f'<div class="metric-grid">{card_html}</div><div class="two"><div class="panel"><h3>Priority findings</h3>{finding_html}</div>'
        '<div class="panel"><h3>Analyst guidance</h3><ul><li>Start with model-zoo consensus alerts, three-detector consensus and the highest Isolation Forest scores.</li>'
        '<li>Review episode chains before individual records where both exist; interrupted scans and agent stops deserve early attention.</li><li>Validate original event lines before escalation.</li>'
        '<li>Separate malicious activity, operational faults, expected behavior, and data-quality issues.</li></ul></div></div></section>'
    )


def pipeline(data):
    feature_sets = data["features"].get("datasets", []) if isinstance(data["features"], dict) else []
    rows = [
        ["Stage 1", "OSSEC classification and event lookup", count(sum(integer(row.get("output_rows", row.get("total_events", row.get("rows")))) for row in data["classification"])), status_badge("complete" if data["classification"] else "missing")],
        ["Stage 2", "Observation and episode construction", count(sum(integer(row.get("dataset_rows")) for row in data["observations"])), status_badge("complete" if data["observations"] else "missing")],
        ["Stage 3", "Feature engineering and chronological splits", count(sum(integer(row.get("rows")) for row in feature_sets)), status_badge("complete" if feature_sets else "missing")],
        ["Stage 4", "Anomaly experiments", count(sum(bool(value) for value in data["summaries"].values())), status_badge("complete" if any(data["summaries"].values()) else "missing")],
        ["Stage 4b", "Model-zoo benchmark", count(len(data["zoo"]["summaries"])), status_badge("complete" if data["zoo"]["summaries"] else "missing")],
        ["Stage 5", "Isolation Forest evidence export", count(len(data["chains"])), status_badge("complete" if data["chains"] else "missing")],
    ]
    observation_rows = [[esc(LABELS.get(txt(row.get("dataset")), row.get("dataset"))), count(row.get("dataset_rows")), count(row.get("lineage_rows")), number(row.get("mean_events_per_observation"), 2), count(row.get("maximum_events_per_observation"))] for row in data["observations"]]
    health = data["episode_health"]
    statistics = health["statistics"]
    key_rows = [[esc(key.replace("_", " ")), count(value)] for key, value in sorted((statistics.get("key_types") or {}).items(), key=lambda item: -item[1])]
    reason_rows = [[esc(key.replace("_", " ")), count(value)] for key, value in sorted((statistics.get("close_reasons") or {}).items(), key=lambda item: -item[1])]
    episode_panel = ""
    if key_rows or reason_rows:
        episode_panel = ('<h3 style="margin-top:18px">Episode grouping</h3><p class="lead">Builder '
                         + esc(health["builder_version"] or "unknown") + '. Scan completion: '
                         + maybe_rate(statistics.get("scan_completion_rate")) + ' of scan episodes contain both start and end.</p>'
                         + '<div class="two"><div class="panel"><h3>Key types</h3>' + table(["Key type", "Episodes"], key_rows)
                         + '</div><div class="panel"><h3>Close reasons</h3>' + table(["Reason", "Episodes"], reason_rows) + '</div></div>')
    return ('<section id="pipeline"><h2>Pipeline health</h2><p class="lead">Coverage across the OSSEC explainable-lineage workflow.</p>'
            + table(["Stage", "Purpose", "Rows or artifacts", "Status"], rows)
            + '<h3 style="margin-top:18px">Stage 2 observations</h3><p class="lead">Events per observation are exactly 1 for individual events. Episodes can average close to 1 when periodic single-line messages dominate; scan completion is the better check.</p>'
            + table(["Representation", "Observations", "Lineage links", "Mean events/observation", "Max events/observation"], observation_rows)
            + episode_panel + '</section>')


def experiments(data):
    rows, chart = [], []
    for dataset in DATASETS:
        summary = data["summaries"].get(dataset) or {}
        robust = num(summary.get("test_robust_alert_rate"))
        isolation = num(summary.get("test_isolation_alert_rate"))
        novelty = num(summary.get("test_novelty_alert_rate"))
        chart.append((LABELS[dataset], robust, isolation, novelty))
        rows.append([
            esc(LABELS[dataset]), status_badge(summary.get("status", "missing")),
            count(summary.get("train_rows")), count(summary.get("test_rows")),
            count(summary.get("selected_features")), rate(robust), rate(isolation),
            rate(novelty), rate(summary.get("test_either_model_alert_rate")),
            count(summary.get("test_either_model_alerts")),
        ])
    return '<section id="experiments"><h2>Detection results (Stage 4)</h2><p class="lead">Detector behavior by OSSEC representation. High alert rates may indicate threats, instability, maintenance activity, or calibration issues.</p><div class="panel">' + grouped_chart(chart) + '</div>' + table(["Representation", "Status", "Train", "Test", "Features", "Robust", "Isolation", "Novelty", "Union", "Union alerts"], rows) + '</section>'


def zoo_results(data):
    zoo = data["zoo"]
    if not zoo["summaries"]:
        return '<section id="zoo"><h2>Model-zoo benchmark</h2>' + empty("No model-zoo outputs found (--zoo).") + '</section>'
    rows = []
    for summary in zoo["summaries"]:
        label = esc(LABELS.get(summary.get("dataset"), summary.get("dataset")))
        if summary.get("status") != "completed":
            rows.append([label, esc(summary.get("feature_set", "")), status_badge("failed"), "", "", "", "", "", "", "", ""])
            continue
        rows.append([label, esc(summary.get("feature_set")), count(summary.get("features")),
                     esc(", ".join(summary.get("ensemble_members") or [])), esc(txt(summary.get("model_selection")).replace("_", " ")),
                     maybe_rate(summary.get("test_proxy_base_rate")), maybe_rate(summary.get("validation_ensemble_detection_rate")),
                     maybe_rate(summary.get("test_ensemble_detection_rate")), maybe_rate(summary.get("test_ensemble_precision")),
                     count(summary.get("test_consensus_alerts")), maybe_rate(summary.get("test_consensus_precision"))])
    metric_rows = []
    for metric in zoo["metrics"]:
        if metric.get("status") != "completed":
            continue
        metric_rows.append([esc(LABELS.get(metric.get("dataset"), metric.get("dataset"))), esc(metric.get("feature_set")), esc(metric.get("model")), rate(metric.get("validation_alert_rate")), rate(metric.get("test_alert_rate")), maybe_rate(metric.get("validation_detection_rate")), maybe_rate(metric.get("test_detection_rate")), number(metric.get("test_proxy_lift"), 1), number(metric.get("fit_score_seconds"), 0)])
    return ('<section id="zoo"><h2>Model-zoo benchmark (Stage 4b)</h2><p class="lead">Thirteen detector families fitted on the same Stage 3 features, pruned and greedily reduced to the smallest ensemble that keeps its detection rate. '
            '<b>Detection rate</b> is the share of proxy monitoring-risk rows (agent stops, manager-communication failures, integrity-baseline and configuration gaps, ERROR or higher severity) caught within the fixed alert budget; it measures alignment with known-risky events, not confirmed attacks. A high base rate, common for daily rows, makes the proxy weak.</p>'
            + table(["Representation", "Feature set", "Features", "Ensemble members", "Selection", "Proxy base rate", "Val detection", "Test detection", "Test precision", "Consensus alerts", "Consensus precision"], rows)
            + '<h3 style="margin-top:18px">Per-model detection</h3>'
            + table(["Representation", "Feature set", "Model", "Val alert rate", "Test alert rate", "Val detection", "Test detection", "Test lift", "Seconds"], metric_rows) + '</section>')


def model_selection(data):
    zoo = data["zoo"]
    if not zoo["curves"] and not zoo["membership"]:
        return '<section id="selection"><h2>Model selection</h2>' + empty("No selection curves available.") + '</section>'
    grouped = defaultdict(list)
    for row in zoo["curves"]:
        grouped[(txt(row.get("dataset")), txt(row.get("feature_set")))].append(row)
    panels = ['<div class="panel">' + curve_chart(sorted(rows, key=lambda row: integer(row.get("step"))), f"{LABELS.get(dataset, dataset)} – {feature_set}: detection rate as models are added") + '</div>'
              for (dataset, feature_set), rows in sorted(grouped.items())]
    reason_kind = {"kept": "success", "little_detection_gain": "warning", "redundant": "warning", "failed": "danger"}
    membership_rows = [[esc(LABELS.get(row.get("dataset"), row.get("dataset"))), esc(row.get("feature_set")), esc(row.get("model")),
                        badge("member" if truth(row.get("included")) else "dropped", "success" if truth(row.get("included")) else "neutral"),
                        badge(txt(row.get("reason")).replace("_", " "), reason_kind.get(txt(row.get("reason")), "neutral")),
                        esc(row.get("greedy_step", "")), maybe_rate(row.get("greedy_detection_rate")), number(row.get("max_agreement"), 2), esc(row.get("redundant_with", ""))]
                       for row in zoo["membership"]]
    return ('<section id="selection"><h2>Model selection</h2><p class="lead">Models are first pruned (failed, degenerate, unstable, isolated or redundant), then added greedily by validation detection rate. The ensemble keeps the smallest prefix within the gain tolerance of the best prefix; later additions bring little or negative gain.</p>'
            + '<div class="chart-grid">' + "".join(panels) + '</div><h3 style="margin-top:18px">Membership decisions</h3>'
            + table(["Representation", "Feature set", "Model", "Status", "Reason", "Greedy step", "Detection at step", "Best agreement", "Redundant with"], membership_rows) + '</section>')


def feature_relevance(data, args):
    zoo = data["zoo"]
    blocks = []
    for dataset in DATASETS:
        rows = zoo["relevance"].get(dataset) or []
        if not rows:
            continue
        decisions = Counter(txt(row.get("decision")) for row in rows)
        top = [row for row in rows if truth(row.get("selected"))][:args.top_features]
        chart = bar_chart([(row.get("feature_name"), num(row.get("importance")) * 1000) for row in top], f"{LABELS[dataset]}: top features by permutation importance (×1000)", "#0891b2")
        decision_rows = [[esc(key.replace("_", " ")), count(value)] for key, value in decisions.most_common()]
        blocks.append(f'<div class="panel"><h3>{esc(LABELS[dataset])}</h3>{chart}{table(["Decision", "Features"], decision_rows)}</div>')
    sweep_rows = [[esc(LABELS.get(row.get("dataset"), row.get("dataset"))), esc(row.get("top_k")), count(row.get("features")), maybe_rate(row.get("validation_detection_rate")), maybe_rate(row.get("validation_precision")), badge("chosen", "success") if truth(row.get("chosen")) else ""] for row in zoo["sweeps"]]
    comparison_rows = [[esc(LABELS.get(row.get("dataset"), row.get("dataset"))), esc(row.get("item")), count(row.get("full_test_alerts")), count(row.get("selected_test_alerts")), count(row.get("shared_alerts")) if txt(row.get("shared_alerts")) else "–", number(row.get("jaccard"), 2) if txt(row.get("jaccard")) else "–"]
                       for row in zoo["comparison"] if txt(row.get("item")) in ("feature_count", "consensus", "ensemble")]
    if not blocks and not sweep_rows and not comparison_rows:
        return '<section id="features"><h2>Feature relevance</h2>' + empty("No feature relevance outputs available.") + '</section>'
    return ('<section id="features"><h2>Feature relevance</h2><p class="lead">Constant, drifting and redundant features are removed using training and validation data only; the rest are ranked by Isolation Forest permutation importance. Importance shows what drives anomaly scores, not what is security-relevant, so the reduced set is always compared with the full set.</p>'
            + '<div class="chart-grid">' + "".join(blocks) + '</div>'
            + '<h3 style="margin-top:18px">Top-K sweep (Isolation Forest probe, validation)</h3>' + table(["Representation", "Top K", "Features", "Detection rate", "Precision", ""], sweep_rows)
            + '<h3 style="margin-top:18px">Full vs selected features (test)</h3>' + table(["Representation", "Item", "Full", "Selected", "Shared", "Jaccard"], comparison_rows) + '</section>')


def consensus_alerts(data, args):
    rows = []
    for (dataset, feature_set), alerts in sorted(data["zoo"]["consensus"].items()):
        for row in alerts:
            votes = row.get("member_vote_count") or row.get("all_model_vote_count") or ""
            when = next((txt(row.get(column)) for column in ("timestamp", "window_start", "episode_start", "first_timestamp") if txt(row.get(column))), "")
            entity = next((txt(row.get(column)) for column in ("host_id", "hostname", "agent_name") if txt(row.get(column))), "")
            activity = next((txt(row.get(column)) for column in ("event_type", "episode_family", "event_category") if txt(row.get(column))), "")
            proxy = row.get("proxy_security_relevant")
            rows.append([esc(LABELS.get(dataset, dataset)), esc(feature_set), esc(votes), esc(compact(row.get("flagged_by"), 90)), number(row.get("model_zoo_ensemble_score"), 3), esc(when), esc(entity), esc(row.get("process_name", "")), esc(activity), esc(row.get("close_reason", "")), badge("yes", "danger") if truth(proxy) else (badge("no", "neutral") if txt(proxy) else "–"), '<code>' + esc(row.get("row_manifest_id")) + '</code>'])
    return ('<section id="consensus"><h2>Consensus alerts</h2><p class="lead">Highest-agreement test observations from the model zoo (top rows per run). Trace any row to its original log lines with its <code>row_manifest_id</code> through the Stage 3 split lineage and the Stage 1 event lookup.</p>'
            + table(["Representation", "Feature set", "Votes", "Flagged by", "Ensemble score", "Time", "Host", "Process", "Event type or activity", "Close reason", "Proxy risk", "row_manifest_id"], rows, "alerts") + '</section>')


def evidence_section(data, metrics):
    rows = []
    for row in data["export"]:
        rows.append([
            esc(LABELS.get(txt(row.get("dataset")), row.get("dataset"))),
            status_badge(row.get("status")), count(row.get("isolation_alerts")),
            count(row.get("alerts_with_complete_evidence", row.get("complete_evidence_alerts"))),
            count(row.get("alerts_with_partial_evidence", row.get("partial_evidence_alerts"))),
            count(row.get("alerts_without_evidence", row.get("missing_evidence_alerts"))),
            count(row.get("source_event_rows", row.get("raw_evidence_rows"))),
        ])
    graphic = donut((("Complete", metrics["complete"], "#16a34a"), ("Partial", metrics["partial"], "#f59e0b"), ("Missing", metrics["missing"], "#dc2626")))
    flow = '<div class="flow"><span>Anomaly</span><b>→</b><span>row_manifest_id</span><b>→</b><span>event_id</span><b>→</b><span>Original OSSEC line</span><b>→</b><span>Source coordinates</span></div>'
    return '<section id="evidence"><h2>Evidence integrity</h2><p class="lead">Every disposition should resolve to the contributing OSSEC events.</p><div class="two"><div class="panel">' + graphic + '</div><div class="panel"><h3>Lineage contract</h3>' + flow + '<p>Partial or missing evidence should be fixed before analyst disposition.</p></div></div>' + table(["Representation", "Status", "Isolation alerts", "Complete", "Partial", "Missing", "Source events"], rows) + '</section>'


def categories_section(data, args):
    aggregate = defaultdict(lambda: [0, 0, 0.0])
    severity = Counter()
    for row in data["categories"]:
        category = txt(row.get("event_category")) or "unknown"
        aggregate[category][0] += integer(row.get("isolation_alerts"))
        aggregate[category][1] += integer(row.get("source_event_rows"))
        aggregate[category][2] = max(aggregate[category][2], num(row.get("maximum_isolation_score")))
    for row in data["details"]:
        severity[txt(row.get("severity")) or "unknown"] += 1
    top = sorted(aggregate.items(), key=lambda item: (-item[1][0], -item[1][1]))[:args.top_categories]
    rows = [[esc(label), count(values[0]), count(values[1]), number(values[2])] for label, values in top]
    return '<section id="categories"><h2>OSSEC danger patterns</h2><p class="lead">Event categories and severities represented in Isolation Forest evidence.</p><div class="two"><div class="panel">' + bar_chart([(label, values[0]) for label, values in top], "Top anomalous OSSEC categories", "#dc2626") + '</div><div class="panel">' + bar_chart(severity.most_common(10), "Source events by severity", "#f59e0b") + '</div></div>' + table(["Event category", "Alerts", "Source events", "Maximum score"], rows) + '</section>'


def entities_section(data, args):
    counters = {"Hosts": Counter(), "Processes": Counter(), "Users": Counter(), "Source IPs": Counter()}
    for row in data["details"]:
        values = {
            "Hosts": txt(row.get("hostname", row.get("host_id"))),
            "Processes": txt(row.get("process_name")),
            "Users": redact(row.get("username"), "user", args.redact_usernames),
            "Source IPs": redact(row.get("source_ip"), "ip", args.redact_source_ips),
        }
        for key, value in values.items():
            if value:
                counters[key][value] += 1
    colors = {"Hosts": "#2563eb", "Processes": "#0891b2", "Users": "#8b5cf6", "Source IPs": "#dc2626"}
    panels = "".join('<div class="panel">' + bar_chart(counters[key].most_common(args.top_entities), key, colors[key]) + '</div>' for key in counters)
    return '<section id="entities"><h2>Concentrated entities</h2><p class="lead">Frequently represented hosts, processes, users, and sources may indicate targeted assets, noisy services, or repetitive expected behavior.</p><div class="chart-grid">' + panels + '</div></section>'


def top_alerts_section(data, args):
    chains = sorted(data["chains"], key=lambda row: num(row.get("isolation_score")), reverse=True)[:args.top_alerts]
    rows = []
    for index, row in enumerate(chains, 1):
        entity = txt(row.get("observation_entity", row.get("host_id")))
        process = txt(row.get("observation_process", row.get("process_name")))
        preview = '<details><summary>View evidence</summary><pre>' + esc(compact(row.get("representative_original_log_lines"), 1800)) + '</pre></details>'
        evidence_kind = "success" if txt(row.get("evidence_status")) == "complete" else "warning"
        rows.append([
            str(index), esc(LABELS.get(txt(row.get("dataset")), row.get("dataset"))),
            number(row.get("isolation_score")), esc(row.get("observation_timestamp")),
            esc(entity), esc(process), esc(compact(row.get("source_event_types"), 160)),
            badge(row.get("evidence_status"), evidence_kind), preview,
        ])
    return '<section id="alerts"><h2>Highest-scoring Isolation Forest observations</h2><p class="lead">Prioritized OSSEC review candidates with original-event previews.</p>' + table(["#", "Representation", "Score", "Time", "Entity", "Process", "Event types", "Evidence", "Original lines"], rows, "alerts") + '</section>'


def review_section(data):
    queue_rows = []
    labels = Counter()
    for dataset in DATASETS:
        rows = data["reviews"].get(dataset, [])
        queue_rows.append([esc(LABELS[dataset]), count(len(rows))])
        for row in rows:
            label = txt(row.get("review_label"))
            if label:
                labels[label] += 1
    label_names = ("security_relevant", "operationally_interesting", "expected_behavior", "data_quality_issue", "insufficient_context")
    label_rows = [[esc(label.replace("_", " ")), count(labels[label])] for label in label_names]
    return '<section id="review"><h2>Analyst review plan</h2><p class="lead">Detector output remains provisional until representative observations are labelled. Labels also replace the model zoo\'s proxy labels.</p><div class="two"><div class="panel"><h3>Available queues</h3>' + table(["Representation", "Rows"], queue_rows) + '</div><div class="panel"><h3>Current labels</h3>' + table(["Label", "Count"], label_rows) + '</div></div><div class="panel"><h3>Recommended sequence</h3><ol><li>Review model-zoo consensus alerts and three-detector consensus episodes.</li><li>Review robust plus Isolation Forest episodes and host windows.</li><li>Sample detector-only populations.</li><li>Inspect complete original-event chains before assigning danger.</li><li>Calculate precision by detector combination after sufficient labels.</li></ol></div></section>'


CSS = """
:root{--bg:#f3f6fb;--panel:#fff;--ink:#172033;--muted:#5f6b7d;--line:#dce3ed;--shadow:0 9px 28px rgba(31,41,55,.08)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.52}.hero{background:linear-gradient(135deg,#111827,#1d4ed8 62%,#0891b2);color:#fff;padding:42px 24px}.hero-inner,.shell{max-width:1500px;margin:auto}.hero h1{font-size:clamp(2rem,4vw,3.4rem);margin:4px 0 10px}.hero p{color:#dbeafe;max-width:900px}.eyebrow{text-transform:uppercase;letter-spacing:.14em;color:#bfdbfe;font-size:.76rem;font-weight:800}.meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.meta span{padding:6px 10px;border-radius:99px;background:#ffffff20;border:1px solid #ffffff35}.shell{padding:0 24px 55px}.nav{position:sticky;top:0;z-index:5;display:flex;gap:7px;overflow:auto;background:#f3f6fbef;backdrop-filter:blur(10px);padding:10px 0;margin-bottom:25px}.nav a{white-space:nowrap;text-decoration:none;color:#334155;background:#fff;border:1px solid var(--line);border-radius:99px;padding:6px 10px;font-size:.82rem}section{scroll-margin-top:64px;margin-bottom:34px}h2{font-size:1.75rem;margin:0 0 5px}h3{margin:0 0 13px}.lead{color:var(--muted);max-width:1000px;margin:0 0 18px}.metric-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:13px;margin-bottom:18px}.metric-card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}.metric-card{padding:17px;border-top:4px solid #94a3b8}.metric-card.danger{border-top-color:#dc2626}.metric-card.warning{border-top-color:#f59e0b}.metric-card.success{border-top-color:#16a34a}.metric-title{text-transform:uppercase;letter-spacing:.07em;font-weight:800;color:var(--muted);font-size:.74rem}.metric-value{font-size:1.8rem;font-weight:850;margin:5px 0}.metric-sub{color:var(--muted);font-size:.82rem}.panel{padding:19px}.two,.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:17px}.chart{width:100%;height:auto}.chart-title{font-size:17px;font-weight:800;fill:#172033}.axis{font-size:12px;fill:#5f6b7d}.value{font-size:12px;fill:#172033;font-weight:700}.donut{font-size:24px;font-weight:850;fill:#172033}.finding{border-left:4px solid #94a3b8;background:#f8fafc;border-radius:10px;padding:11px 13px;margin:9px 0}.finding p{margin:3px 0;color:var(--muted)}.finding.danger{border-color:#dc2626;background:#fff5f5}.finding.warning{border-color:#f59e0b;background:#fffbeb}.finding.success{border-color:#16a34a;background:#f0fdf4}.table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}table{border-collapse:collapse;width:100%;font-size:.87rem}th{text-align:left;background:#eaf0f9;padding:10px 11px;border-bottom:1px solid var(--line);white-space:nowrap}td{padding:9px 11px;border-bottom:1px solid #edf1f5;vertical-align:top}tbody tr:hover{background:#f8fbff}.badge{display:inline-block;padding:3px 8px;border-radius:99px;font-size:.74rem;font-weight:800;white-space:nowrap}.badge.success{background:#dcfce7;color:#166534}.badge.warning{background:#fef3c7;color:#92400e}.badge.danger{background:#fee2e2;color:#991b1b}.badge.neutral{background:#e2e8f0;color:#334155}.flow{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.flow span{padding:7px 10px;border-radius:8px;background:#eef2ff;color:#3730a3;font-weight:700}.empty{padding:24px;text-align:center;color:var(--muted);border:1px dashed #cbd5e1;border-radius:11px}details summary{cursor:pointer;color:#2563eb;font-weight:700}pre{white-space:pre-wrap;word-break:break-word;background:#111827;color:#e5e7eb;padding:11px;border-radius:8px;max-width:650px;max-height:300px;overflow:auto;font-size:.77rem}code{font-size:.78rem}.alerts td:last-child{min-width:210px}.footer{text-align:center;color:var(--muted);font-size:.8rem;padding:20px}@media(max-width:1100px){.metric-grid{grid-template-columns:repeat(3,1fr)}.two,.chart-grid{grid-template-columns:1fr}}@media(max-width:620px){.metric-grid{grid-template-columns:1fr 1fr}.shell{padding:0 12px 45px}.hero{padding:30px 12px}}@media print{body{background:#fff}.nav{display:none}.metric-card,.panel,.table-wrap{box-shadow:none}.two,.chart-grid{grid-template-columns:1fr 1fr}}
"""


def methodology():
    return '<section id="method"><h2>Methodology and limitations</h2><div class="two"><div class="panel"><h3>Detection channels</h3><ul><li><b>Robust deviation:</b> extreme changes in stable numeric behavior.</li><li><b>Isolation Forest:</b> unusual multivariate combinations.</li><li><b>Novelty:</b> rare categorical, text, and sequence features.</li><li><b>Model zoo:</b> thirteen detector families, pruned to an ensemble whose votes form consensus alerts.</li></ul><h3>Episodes</h3><ul><li>Scan cycles run from start to end; connectivity episodes end on reconnect; restarts are one host-wide lifecycle episode.</li><li>A stop during a scan closes it as <i>interrupted</i>.</li></ul></div><div class="panel"><h3>Limitations</h3><ul><li>Anomalies are not confirmed malicious activity.</li><li>Thresholds control workload but do not establish precision.</li><li>Model-zoo detection rates use proxy labels that partly overlap with the features, so they rank models rather than measure true detection.</li><li>Repeated benign OSSEC activity can dominate anomaly counts.</li><li>Skipped representations should not be interpreted as safe.</li><li>Evidence may contain sensitive hosts, users, addresses, and paths.</li></ul></div></div></section>'


RESULTS_INTRO = ("<p>This section reports what the detectors flagged in the test period, checks that they "
                 "behave like detectors rather than flagging everything (Model behaviour), and compares the "
                 "model zoo. Alert rates describe workload, not how many attacks occurred.</p>")
EVIDENCE_INTRO = ("<p>An alert is only useful if an analyst can see what actually happened. This section checks "
                  "that every alert traces back to its original log lines, and summarises which events, "
                  "servers, users and addresses the alerts involve.</p>")


def render(data, args):
    metrics = calculate_metrics(data)
    risk = risk_score(data, metrics)
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    zoo_runs = [s for s in data["zoo"]["summaries"] if s.get("status") == "completed"]
    consensus = sum(integer(s.get("test_consensus_alerts")) for s in zoo_runs if s.get("feature_set") in ("selected", None))
    scored = sum(sum(run["rows"].values()) for run in (data["behaviour"] or {}).get("detector", []))
    name = layout.SOURCE["ossec"]["name"]
    chapters = [
        ("Introduction", layout.INTRO, [layout.text_section("how-to-read", "How to read this report", layout.HOW_TO_READ.format(name=name)), overview(data, metrics, risk)]),
        ("Data", "<p>" + layout.SOURCE["ossec"]["data"] + "</p>", [pipeline(data), coverage_section("ossec")]),
        ("Methodology", layout.APPROACH, [feature_relevance(data, args), model_selection(data)]),
        ("Results", RESULTS_INTRO, [experiments(data), behaviour_section(data["behaviour"], "OSSEC"), zoo_results(data), cluster_section(args.zoo.parent / "model_zoo_map", args.output, "OSSEC"), render_clusters_section(args.zoo.parents[2] / "phase7b_clusters" / "ossec", args.zoo.parent / "model_zoo_map", "OSSEC"), consensus_alerts(data, args), silence_section("ossec"), first_seen_section("ossec"), activity_section("ossec")]),
        ("Evidence and Analysis", EVIDENCE_INTRO, [evidence_section(data, metrics), categories_section(data, args), entities_section(data, args), top_alerts_section(data, args), context_section("ossec")]),
        ("Discussion", layout.MEANING, [methodology()]),
        ("Recommendations", "", [review_section(data)]),
        ("Conclusion", layout.CONCLUSION, []),
    ]
    abstract = layout.abstract_text("ossec", lines=metrics.get("total"), alerts=metrics.get("union"),
                                    traced=metrics.get("isolation"), consensus=consensus, scored=scored)
    return layout.document(title="Unsupervised Anomaly Detection in OSSEC Agent Logs: Analysis Report", source="ossec",
                           generated=generated, abstract=abstract, base_css=CSS, chapters=chapters,
                           footer="Generated by Phase 6. Analyst validation is required before incident escalation.")


def main():
    args = parse_args()
    log = Log(args.quiet, args.verbose)
    log.say("OSSEC Stage 6 starting", "START")
    data = load_data(args, log)
    log.say("Building dashboards, findings, and analyst review tables", "PHASE")
    report = render(data, args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(report, encoding="utf-8")
    os.replace(temporary, args.output)
    log.say(f"Report written: {args.output} ({args.output.stat().st_size/1024:,.1f} KB)", "DONE")
    log.say("OSSEC Stage 6 completed successfully", "COMPLETE", always=True)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
