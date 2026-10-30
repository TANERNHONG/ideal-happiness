"""Generate a self-contained HTML threat report from authentication Stages 1-5.

The report is offline-capable and uses inline CSS and SVG charts only.
Default output: data/phase6_report/auth/authlog_threat_analysis_report.html

Update 2026-09-23
-----------------
* New sections read the model-zoo benchmark v2 outputs (``--zoo``): ensemble
  results with proxy detection rates, greedy model-selection curves and
  membership decisions, feature relevance and top-K sweeps, full-vs-selected
  comparison, and the highest-agreement consensus alerts.
* The pipeline section shows records per observation for every Stage 2
  dataset, so the session-boundary fix is visible (it should be well above 1).
* Stage 4 ``test_scores.csv`` files are no longer loaded; they were read in
  full (millions of rows) but never used.
* Stage 5 message chains can hold up to 250,000 characters in one field,
  above Python's default CSV field limit of 131,072. The limit is raised at
  start-up, and the chain and detailed-evidence files are read keeping only
  the columns the report uses (``CHAIN_COLUMNS`` and ``DETAIL_COLUMNS``), so
  the full chain text is never held in memory.
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
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from model_behaviour import collect as collect_behaviour, render_section as behaviour_section
import report_layout as layout
from coverage_sections import activity_section, context_section, coverage_section, first_seen_section, silence_section
from cluster_maps import render_clusters_section, render_section as cluster_section

DATASETS = ("authentication_sessions", "individual", "host_5min", "host_behavior_1d")
LABELS = {
    "authentication_sessions": "Authentication sessions",
    "individual": "Individual events",
    "host_5min": "Five-minute host windows",
    "host_behavior_1d": "Daily host behavior",
}
FEATURE_SETS = ("full", "selected")
CHAIN_COLUMNS = ("dataset", "isolation_score", "observation_timestamp", "observation_entity",
                 "observation_username", "observation_source_ip", "source_event_types",
                 "evidence_status", "representative_original_log_lines")
DETAIL_COLUMNS = ("hostname", "username", "source_ip", "process_name")


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


def args_parser():
    parser = argparse.ArgumentParser(description="Generate authentication threat-analysis HTML report.")
    parser.add_argument("--auth-logs", type=Path, default=Path("data/phase1_classify/auth"))
    parser.add_argument("--datasets", type=Path, default=Path("data/phase2_observations/auth"))
    parser.add_argument("--features", type=Path, default=Path("data/phase3_features/auth"))
    parser.add_argument("--experiments", type=Path, default=Path("data/phase4_detection/auth/detectors"))
    parser.add_argument("--evidence", type=Path, default=Path("data/phase5_evidence/auth"))
    parser.add_argument("--zoo", type=Path, default=Path("data/phase4_detection/auth/model_zoo"),
                        help="Model-zoo benchmark v2 output folder.")
    parser.add_argument("--output", type=Path, default=Path("data/phase6_report/auth/authlog_threat_analysis_report.html"))
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
    if value is None:
        return ""
    return str(value).strip()


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


def number(value, digits=3):
    return f"{num(value):,.{digits}f}"


def redact(value, prefix, enabled):
    value = txt(value)
    if not enabled or not value:
        return value
    return prefix + "-" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]


def truth(value):
    return txt(value).lower() in {"1", "true", "yes", "y"}


def badge(value, kind="neutral"):
    return f'<span class="badge {kind}">{esc(value)}</span>'


def status(value):
    raw = txt(value) or "unknown"
    lower = raw.lower()
    kind = "danger" if any(x in lower for x in ("failed", "invalid", "missing")) else "warning" if any(x in lower for x in ("skip", "partial", "warning", "fallback")) else "success" if any(x in lower for x in ("complete", "acceptable", "calibrated", "success")) else "neutral"
    return badge(raw.replace("_", " "), kind)


def empty(message):
    return f'<div class="empty">{esc(message)}</div>'


def table(headers, rows, css_class=""):
    if not rows:
        return empty("No data available")
    out = [f'<div class="table-wrap"><table class="{esc(css_class)}"><thead><tr>']
    out += [f"<th>{esc(item)}</th>" for item in headers]
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def bar_chart(items, title, color="#2563eb", percentages=False):
    values = [(txt(k), num(v)) for k, v in items if txt(k)]
    if not values:
        return empty("No chart data available")
    width, left, right, top, step = 900, 225, 90, 46, 30
    height = top + 26 + len(values) * step
    maximum = max(v for _, v in values) or 1
    plot = width - left - right
    out = [f'<svg class="chart" viewBox="0 0 {width} {height}"><text x="0" y="22" class="chart-title">{esc(title)}</text>']
    for index, (label, value) in enumerate(values):
        y = top + index * step
        bar = max((value / maximum) * plot, 1 if value else 0)
        display = f"{value*100:.2f}%" if percentages else f"{value:,.0f}"
        out += [
            f'<text x="0" y="{y+16}" class="axis">{esc(compact(label, 32))}</text>',
            f'<rect x="{left}" y="{y+2}" width="{plot}" height="18" rx="5" fill="#e5e7eb"/>',
            f'<rect x="{left}" y="{y+2}" width="{bar:.1f}" height="18" rx="5" fill="{color}"/>',
            f'<text x="{left+bar+7:.1f}" y="{y+16}" class="value">{display}</text>',
        ]
    out.append("</svg>")
    return "".join(out)


def grouped_chart(rows):
    if not rows:
        return empty("No detector data available")
    width, height = 900, 370
    left, right, top, bottom = 68, 24, 52, 94
    plot_w, plot_h = width-left-right, height-top-bottom
    maximum = max([v for row in rows for v in row[1:4]] + [.01])
    colors = ("#8b5cf6", "#dc2626", "#f59e0b")
    out = [f'<svg class="chart" viewBox="0 0 {width} {height}"><text x="0" y="24" class="chart-title">Test alert rate by detector</text>']
    for tick in range(6):
        v = maximum*tick/5
        y = top+plot_h-plot_h*tick/5
        out += [f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#e5e7eb"/>', f'<text x="{left-7}" y="{y+4}" text-anchor="end" class="axis">{v*100:.1f}%</text>']
    group_w = plot_w/len(rows)
    bar_w = min(40, group_w/5)
    for i, row in enumerate(rows):
        center = left+group_w*(i+.5)
        for j, value in enumerate(row[1:4]):
            bh = value/maximum*plot_h
            x = center+(j-1)*(bar_w+5)-bar_w/2
            y = top+plot_h-bh
            out.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bh}" rx="4" fill="{colors[j]}"/>')
        out.append(f'<text transform="translate({center},{height-bottom+18}) rotate(22)" class="axis">{esc(compact(row[0], 25))}</text>')
    for i, (label, color) in enumerate(zip(("Robust", "Isolation Forest", "Novelty"), colors)):
        x = width-430+i*140
        out += [f'<rect x="{x}" y="12" width="13" height="13" rx="3" fill="{color}"/>', f'<text x="{x+18}" y="23" class="axis">{label}</text>']
    out.append("</svg>")
    return "".join(out)


def curve_chart(rows, title):
    """Detection rate by number of models, with the kept prefix highlighted."""
    points = [(integer(r.get("step")), num(r.get("validation_detection_rate")), txt(r.get("model_added")), truth(r.get("selected"))) for r in rows]
    points = [p for p in points if p[0] > 0]
    if not points:
        return empty("No selection curve available")
    width, height, left, right, top, bottom = 900, 330, 64, 110, 48, 92
    plot_w, plot_h = width-left-right, height-top-bottom
    maximum = max(max(p[1] for p in points), 0.01)
    steps = max(p[0] for p in points)
    def xy(step, value):
        x = left + (step-1)/max(steps-1, 1)*plot_w
        return x, top+plot_h-value/maximum*plot_h
    out = [f'<svg class="chart" viewBox="0 0 {width} {height}"><text x="0" y="24" class="chart-title">{esc(title)}</text>']
    for tick in range(6):
        v = maximum*tick/5; y = top+plot_h-plot_h*tick/5
        out += [f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#e5e7eb"/>', f'<text x="{left-7}" y="{y+4}" text-anchor="end" class="axis">{v*100:.0f}%</text>']
    path = " ".join(("M" if i == 0 else "L") + f"{xy(s, v)[0]:.1f},{xy(s, v)[1]:.1f}" for i, (s, v, _, _) in enumerate(points))
    out.append(f'<path d="{path}" fill="none" stroke="#2563eb" stroke-width="2.5"/>')
    for s, v, model, kept in points:
        x, y = xy(s, v)
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{"#16a34a" if kept else "#94a3b8"}"/>')
        out.append(f'<text transform="translate({x:.1f},{height-bottom+16}) rotate(30)" class="axis">{esc(compact(model, 20))}</text>')
    out.append(f'<text x="{width-right}" y="24" text-anchor="end" class="axis">green = kept in ensemble</text></svg>')
    return "".join(out)


def donut(parts):
    parts = [(k, num(v), c) for k, v, c in parts if num(v) > 0]
    if not parts:
        return empty("No evidence data available")
    total = sum(v for _, v, _ in parts)
    r, circumference, offset = 70, 2*math.pi*70, 0
    out = ['<svg class="chart" viewBox="0 0 560 260"><text x="0" y="24" class="chart-title">Evidence completeness</text>']
    for label, value, color in parts:
        length = circumference*value/total
        out.append(f'<circle cx="120" cy="130" r="{r}" fill="none" stroke="{color}" stroke-width="29" stroke-dasharray="{length} {circumference-length}" stroke-dashoffset="{-offset}" transform="rotate(-90 120 130)"/>')
        offset += length
    out += [f'<text x="120" y="128" text-anchor="middle" class="donut">{total:,.0f}</text>', '<text x="120" y="149" text-anchor="middle" class="axis">alerts</text>']
    for i, (label, value, color) in enumerate(parts):
        y = 76+i*36
        out += [f'<rect x="245" y="{y-12}" width="14" height="14" rx="3" fill="{color}"/>', f'<text x="268" y="{y}" class="axis">{esc(label)}: {value:,.0f}</text>']
    out.append("</svg>")
    return "".join(out)


def load_zoo(folder, top_alerts, log):
    """Load model-zoo v2 outputs; every part is optional."""
    zoo = {"summaries": [], "metrics": [], "membership": read_csv(folder/"all_ensemble_membership.csv"),
           "curves": read_csv(folder/"all_model_selection_curves.csv"),
           "comparison": read_csv(folder/"feature_set_comparison.csv"),
           "sweeps": read_csv(folder/"all_feature_sweeps.csv"),
           "relevance": {}, "consensus": {}}
    summary = read_json(folder/"model_zoo_summary.json")
    if isinstance(summary, dict):
        zoo["summaries"] = [s for s in summary.get("datasets", []) if isinstance(s, dict)]
        zoo["metrics"] = [m for m in summary.get("model_metrics", []) if isinstance(m, dict)]
    for dataset in DATASETS:
        zoo["relevance"][dataset] = read_csv(folder/dataset/"feature_relevance.csv")
        for feature_set in FEATURE_SETS:
            files = sorted(glob.glob(str(folder/dataset/feature_set/"consensus_alerts_min*.csv")))
            if files:
                zoo["consensus"][(dataset, feature_set)] = read_csv(Path(files[0]), limit=top_alerts)
    if zoo["summaries"]:
        log.say(f"Loaded model-zoo results for {len(zoo['summaries'])} dataset/feature-set runs", "DONE")
    return zoo


def load_data(args, log):
    log.say("Loading Stage 1-5 artifacts", "PHASE")
    observations = read_csv(args.datasets/"authlog_observation_dataset_summary.csv")
    # A later --sessions-only rebuild writes its own summary; prefer it for sessions.
    sessions = read_csv(args.datasets/"authlog_authentication_sessions_summary.csv")
    if sessions:
        observations = [r for r in observations if txt(r.get("dataset")) != "authentication_sessions"] + sessions
    result = {
        "classification": read_csv(args.auth_logs/"authlog_classification_summary.csv"),
        "stage1": read_json(args.auth_logs/"authlog_lineage_summary.json"),
        "observations": observations,
        "features": read_json(args.features/"feature_engineering_summary.json"),
        "feature_lineage": read_csv(args.features/"lineage_summary.csv"),
        "export": read_csv(args.evidence/"authlog_isolation_forest_outlier_export_summary.csv"),
        "categories": read_csv(args.evidence/"authlog_isolation_forest_outlier_categories.csv"),
        "chains": read_csv(args.evidence/"authlog_isolation_forest_outlier_message_chains.csv", columns=CHAIN_COLUMNS),
        "details": read_csv(args.evidence/"authlog_isolation_forest_outlier_events_detailed.csv", columns=DETAIL_COLUMNS),
        "summaries": {}, "reviews": {},
        "zoo": load_zoo(args.zoo, args.top_alerts, log),
    }
    for dataset in DATASETS:
        folder = args.experiments/dataset
        result["summaries"][dataset] = read_json(folder/"summary.json")
        result["reviews"][dataset] = read_csv(folder/"manual_review_queue.csv")
    result["behaviour"] = None if args.no_model_behaviour else collect_behaviour(
        args.experiments, args.zoo, "selected", args.output.parent / "model_behaviour_cache.json",
        log=lambda message: log.say(message, "PHASE"))
    log.say(f"Loaded {len(result['chains']):,} anomaly chains and {len(result['details']):,} source records", "DONE")
    return result


def metrics(data):
    total = sum(integer(r.get("output_rows", r.get("total_events"))) for r in data["classification"])
    unknown = sum(integer(r.get("unknown_events")) for r in data["classification"])
    completed = [s for s in data["summaries"].values() if s and not txt(s.get("status")).startswith("skipped") and s.get("status") != "failed"]
    union = sum(integer(s.get("test_either_model_alerts")) for s in completed)
    isolation = sum(integer(s.get("test_isolation_alerts")) for s in completed)
    complete = sum(integer(r.get("complete_evidence_alerts", r.get("alerts_with_complete_evidence"))) for r in data["export"])
    partial = sum(integer(r.get("partial_evidence_alerts", r.get("alerts_with_partial_evidence"))) for r in data["export"])
    missing = sum(integer(r.get("missing_evidence_alerts", r.get("alerts_without_evidence"))) for r in data["export"])
    return {"total": total, "unknown": unknown, "unknown_rate": unknown/total if total else 0, "completed": len(completed), "union": union, "isolation": isolation, "complete": complete, "partial": partial, "missing": missing}


def risk_score(data, met):
    rates = [num(s.get("test_either_model_alert_rate")) for s in data["summaries"].values() if s]
    max_rate = max(rates, default=0)
    dangerous = sum(integer(r.get("source_record_rows")) for r in data["categories"] if txt(r.get("event_outcome")).lower() in {"failure", "invalid_user", "account_lock", "access_denied"})
    value = min(round(min(met["unknown_rate"]/.05, 1)*20 + min(max_rate/.10, 1)*25 + min(dangerous/100, 1)*25 + min(met["union"]/500, 1)*20 + (10 if met["partial"] or met["missing"] else 0)), 100)
    if value >= 75: return value, "Critical review priority", "danger"
    if value >= 50: return value, "High review priority", "danger"
    if value >= 25: return value, "Moderate review priority", "warning"
    return value, "Low observed risk", "success"


def overview(data, met, risk):
    value, label, kind = risk
    zoo_runs = [s for s in data["zoo"]["summaries"] if s.get("status") == "completed"]
    consensus_total = sum(integer(s.get("test_consensus_alerts")) for s in zoo_runs if s.get("feature_set") in ("selected", None)) or sum(integer(s.get("test_consensus_alerts")) for s in zoo_runs)
    cards = (
        ("Threat review score", f"{value}/100", label, kind),
        ("Classified records", count(met["total"]), count(met["unknown"])+" unknown", "neutral"),
        ("Union anomaly candidates", count(met["union"]), "Stage 4 experiments", "warning"),
        ("Isolation Forest alerts", count(met["isolation"]), "Source evidence exported", "danger"),
        ("Model-zoo consensus alerts", count(consensus_total), f"{len(zoo_runs)} zoo runs", "warning" if consensus_total else "neutral"),
        ("Complete evidence", count(met["complete"]), count(met["missing"])+" missing", "success" if not met["missing"] else "danger"),
    )
    cards_html = "".join(f'<article class="metric-card {k}"><div class="metric-title">{esc(t)}</div><div class="metric-value">{esc(v)}</div><div class="metric-sub">{esc(s)}</div></article>' for t,v,s,k in cards)
    findings = []
    if met["unknown_rate"] > .02:
        findings.append(("Classification coverage needs attention", f"Unknown records are {met['unknown_rate']*100:.2f}% of classified activity.", "warning"))
    elif met["total"]:
        findings.append(("Classification coverage is strong", f"Unknown records are {met['unknown_rate']*100:.2f}% of classified activity.", "success"))
    for record in data["observations"]:
        if txt(record.get("dataset")) == "authentication_sessions":
            mean = num(record.get("mean_records_per_observation"))
            if mean and mean < 1.5:
                findings.append(("Sessions look fragmented", f"Only {mean:.2f} events per session; rebuild sessions with the Stage 2 boundary fix.", "danger"))
            elif mean:
                findings.append(("Session grouping is healthy", f"{mean:.2f} events per session on average.", "success"))
    for dataset in DATASETS:
        summary = data["summaries"].get(dataset) or {}
        state = txt(summary.get("status"))
        if state.startswith("skipped"):
            findings.append((LABELS[dataset]+" was skipped", "Population, temporal coverage, or dimensionality safeguards were not satisfied.", "warning"))
        elif state == "failed":
            findings.append((LABELS[dataset]+" failed", compact(summary.get("error"), 300), "danger"))
        elif integer(summary.get("test_either_model_alerts")):
            findings.append((LABELS[dataset]+" generated "+count(summary.get("test_either_model_alerts"))+" candidates", "Union alert rate: "+rate(summary.get("test_either_model_alert_rate"))+". This is review workload, not confirmed compromise.", "warning"))
    for s in zoo_runs:
        if txt(s.get("test_ensemble_detection_rate")):
            findings.append((f"Model zoo – {LABELS.get(s.get('dataset'), s.get('dataset'))} ({s.get('feature_set')})",
                             f"{len(s.get('ensemble_members') or [])} ensemble models; proxy detection rate {maybe_rate(s.get('test_ensemble_detection_rate'))} on test at {maybe_rate(s.get('test_proxy_base_rate'))} base rate.", "neutral"))
    if met["missing"] or met["partial"]:
        findings.append(("Evidence gaps require remediation", f"Partial: {met['partial']:,}; missing: {met['missing']:,}.", "danger"))
    elif met["complete"]:
        findings.append(("Evidence lineage is complete", f"{met['complete']:,} Isolation Forest alerts resolve to original records.", "success"))
    finding_html = "".join(f'<div class="finding {k}"><b>{esc(t)}</b><p>{esc(d)}</p></div>' for t,d,k in findings)
    return f'<section id="overview"><h2>Executive overview</h2><p class="lead">A consolidated view of authentication behavior, anomaly candidates, and evidence quality. Anomaly scores identify unusual behavior, not proven attacks.</p><div class="metric-grid">{cards_html}</div><div class="two"><div class="panel"><h3>Priority findings</h3>{finding_html}</div><div class="panel"><h3>Analyst guidance</h3><ul><li>Start with model-zoo consensus alerts and the highest Isolation Forest scores.</li><li>Validate the original log chain before escalation.</li><li>Separate malicious activity, operational incidents, expected behavior, and data-quality problems.</li><li>Use alert rates as workload indicators rather than incident prevalence.</li></ul></div></div></section>'


def pipeline(data):
    feature_sets = data["features"].get("datasets", []) if isinstance(data["features"], dict) else []
    rows = [
        ["Stage 1", "Classification and source-line lineage", count(sum(integer(r.get("output_rows")) for r in data["classification"])), status("complete" if data["classification"] else "missing")],
        ["Stage 2", "Observation construction", count(sum(integer(r.get("dataset_rows")) for r in data["observations"])), status("complete" if data["observations"] else "missing")],
        ["Stage 3", "Feature engineering and chronological splits", count(sum(integer(r.get("rows")) for r in feature_sets)), status("complete" if feature_sets else "missing")],
        ["Stage 4", "Anomaly experiments", count(sum(bool(v) for v in data["summaries"].values())), status("complete" if any(data["summaries"].values()) else "missing")],
        ["Stage 4b", "Model-zoo benchmark v2", count(len(data["zoo"]["summaries"])), status("complete" if data["zoo"]["summaries"] else "missing")],
        ["Stage 5", "Isolation Forest evidence export", count(len(data["chains"])), status("complete" if data["chains"] else "missing")],
    ]
    observation_rows = [[esc(LABELS.get(txt(r.get("dataset")), r.get("dataset"))), count(r.get("dataset_rows")), count(r.get("lineage_rows")), number(r.get("mean_records_per_observation"), 2), count(r.get("maximum_records_per_observation"))] for r in data["observations"]]
    return ('<section id="pipeline"><h2>Pipeline health</h2><p class="lead">Coverage across the explainable-lineage workflow.</p>'
            + table(["Stage","Purpose","Rows or artifacts","Status"], rows)
            + '<h3 style="margin-top:18px">Stage 2 observations</h3><p class="lead">Records per observation should be exactly 1 for individual events and well above 1 for sessions and windows.</p>'
            + table(["Representation","Observations","Lineage links","Mean records/observation","Max records/observation"], observation_rows) + '</section>')


def experiments(data):
    rows, chart = [], []
    for dataset in DATASETS:
        s = data["summaries"].get(dataset) or {}
        robust, isolation, novelty = num(s.get("test_robust_alert_rate")), num(s.get("test_isolation_alert_rate")), num(s.get("test_novelty_alert_rate"))
        chart.append((LABELS[dataset], robust, isolation, novelty))
        rows.append([esc(LABELS[dataset]), status(s.get("status", "missing")), count(s.get("train_rows")), count(s.get("test_rows")), count(s.get("selected_features")), rate(robust), rate(isolation), rate(novelty), rate(s.get("test_either_model_alert_rate")), count(s.get("test_either_model_alerts"))])
    return '<section id="experiments"><h2>Detection results (Stage 4)</h2><p class="lead">Detector behavior by representation. High rates may indicate attacks, instability, repetitive activity, or calibration issues.</p><div class="panel">'+grouped_chart(chart)+'</div>'+table(["Representation","Status","Train","Test","Features","Robust","Isolation","Novelty","Union","Union alerts"], rows)+'</section>'


def zoo_results(data):
    zoo = data["zoo"]
    if not zoo["summaries"]:
        return '<section id="zoo"><h2>Model-zoo benchmark</h2>'+empty("No model-zoo v2 outputs found (--zoo).")+'</section>'
    rows = []
    for s in zoo["summaries"]:
        if s.get("status") != "completed":
            rows.append([esc(LABELS.get(s.get("dataset"), s.get("dataset"))), esc(s.get("feature_set", "")), status("failed"), "", "", "", "", "", "", "", ""])
            continue
        rows.append([esc(LABELS.get(s.get("dataset"), s.get("dataset"))), esc(s.get("feature_set")), count(s.get("features")),
                     esc(", ".join(s.get("ensemble_members") or [])), esc(txt(s.get("model_selection")).replace("_", " ")),
                     maybe_rate(s.get("test_proxy_base_rate")), maybe_rate(s.get("validation_ensemble_detection_rate")),
                     maybe_rate(s.get("test_ensemble_detection_rate")), maybe_rate(s.get("test_ensemble_precision")),
                     count(s.get("test_consensus_alerts")), maybe_rate(s.get("test_consensus_precision"))])
    metric_rows = []
    for m in zoo["metrics"]:
        if m.get("status") != "completed":
            continue
        metric_rows.append([esc(LABELS.get(m.get("dataset"), m.get("dataset"))), esc(m.get("feature_set")), esc(m.get("model")), rate(m.get("validation_alert_rate")), rate(m.get("test_alert_rate")), maybe_rate(m.get("validation_detection_rate")), maybe_rate(m.get("test_detection_rate")), number(m.get("test_proxy_lift"), 1), number(m.get("fit_score_seconds"), 0)])
    return ('<section id="zoo"><h2>Model-zoo benchmark</h2><p class="lead">Thirteen detector families fitted on the same Stage 3 features, pruned and greedily reduced to the smallest ensemble that keeps its detection rate. '
            '<b>Detection rate</b> is the share of proxy security-relevant rows (failures, invalid users, PAM/privilege/protocol errors) caught within the fixed alert budget; it measures alignment with known-risky events, not confirmed attacks.</p>'
            + table(["Representation","Feature set","Features","Ensemble members","Selection","Proxy base rate","Val detection","Test detection","Test precision","Consensus alerts","Consensus precision"], rows)
            + '<h3 style="margin-top:18px">Per-model detection</h3>'
            + table(["Representation","Feature set","Model","Val alert rate","Test alert rate","Val detection","Test detection","Test lift","Seconds"], metric_rows) + '</section>')


def model_selection(data):
    zoo = data["zoo"]
    if not zoo["curves"] and not zoo["membership"]:
        return '<section id="selection"><h2>Model selection</h2>'+empty("No selection curves available.")+'</section>'
    panels = []
    grouped = defaultdict(list)
    for r in zoo["curves"]:
        grouped[(txt(r.get("dataset")), txt(r.get("feature_set")))].append(r)
    for (dataset, feature_set), rows in sorted(grouped.items()):
        panels.append('<div class="panel">'+curve_chart(sorted(rows, key=lambda r: integer(r.get("step"))), f"{LABELS.get(dataset, dataset)} – {feature_set}: detection rate as models are added")+'</div>')
    reason_kind = {"kept": "success", "little_detection_gain": "warning", "redundant": "warning", "failed": "danger"}
    membership_rows = [[esc(LABELS.get(r.get("dataset"), r.get("dataset"))), esc(r.get("feature_set")), esc(r.get("model")),
                        badge("member" if truth(r.get("included")) else "dropped", "success" if truth(r.get("included")) else "neutral"),
                        badge(txt(r.get("reason")).replace("_", " "), reason_kind.get(txt(r.get("reason")), "neutral")),
                        esc(r.get("greedy_step", "")), maybe_rate(r.get("greedy_detection_rate")), number(r.get("max_agreement"), 2), esc(r.get("redundant_with", ""))]
                       for r in zoo["membership"]]
    return ('<section id="selection"><h2>Model selection</h2><p class="lead">Models are first pruned (failed, degenerate, unstable, isolated or redundant), then added greedily by validation detection rate. The ensemble keeps the smallest prefix within the gain tolerance of the best prefix; later additions bring little or negative gain.</p>'
            + '<div class="chart-grid">' + "".join(panels) + '</div><h3 style="margin-top:18px">Membership decisions</h3>'
            + table(["Representation","Feature set","Model","Status","Reason","Greedy step","Detection at step","Best agreement","Redundant with"], membership_rows) + '</section>')


def feature_relevance(data, args):
    zoo = data["zoo"]
    blocks = []
    for dataset in DATASETS:
        rows = zoo["relevance"].get(dataset) or []
        if not rows:
            continue
        decisions = Counter(txt(r.get("decision")) for r in rows)
        top = [r for r in rows if truth(r.get("selected"))][:args.top_features]
        chart = bar_chart([(r.get("feature_name"), num(r.get("importance"))*1000) for r in top], f"{LABELS[dataset]}: top features by permutation importance (×1000)", "#0891b2")
        decision_rows = [[esc(k.replace("_", " ")), count(v)] for k, v in decisions.most_common()]
        blocks.append(f'<div class="panel"><h3>{esc(LABELS[dataset])}</h3>{chart}{table(["Decision","Features"], decision_rows)}</div>')
    sweep_rows = [[esc(LABELS.get(r.get("dataset"), r.get("dataset"))), esc(r.get("top_k")), count(r.get("features")), maybe_rate(r.get("validation_detection_rate")), maybe_rate(r.get("validation_precision")), badge("chosen", "success") if truth(r.get("chosen")) else ""] for r in zoo["sweeps"]]
    comparison_rows = [[esc(LABELS.get(r.get("dataset"), r.get("dataset"))), esc(r.get("item")), count(r.get("full_test_alerts")), count(r.get("selected_test_alerts")), count(r.get("shared_alerts")) if txt(r.get("shared_alerts")) else "–", number(r.get("jaccard"), 2) if txt(r.get("jaccard")) else "–"]
                       for r in zoo["comparison"] if txt(r.get("item")) in ("feature_count", "consensus", "ensemble")]
    if not blocks and not sweep_rows and not comparison_rows:
        return '<section id="features"><h2>Feature relevance</h2>'+empty("No feature relevance outputs available.")+'</section>'
    return ('<section id="features"><h2>Feature relevance</h2><p class="lead">Constant, drifting and redundant features are removed using training and validation data only; the rest are ranked by Isolation Forest permutation importance. Importance shows what drives anomaly scores, not what is security-relevant, so the reduced set is always compared with the full set.</p>'
            + '<div class="chart-grid">' + "".join(blocks) + '</div>'
            + '<h3 style="margin-top:18px">Top-K sweep (Isolation Forest probe, validation)</h3>' + table(["Representation","Top K","Features","Detection rate","Precision",""], sweep_rows)
            + '<h3 style="margin-top:18px">Full vs selected features (test)</h3>' + table(["Representation","Item","Full","Selected","Shared","Jaccard"], comparison_rows) + '</section>')


def consensus_alerts(data, args):
    zoo = data["zoo"]
    rows = []
    for (dataset, feature_set), alerts in sorted(zoo["consensus"].items()):
        for r in alerts:
            votes = r.get("member_vote_count") or r.get("all_model_vote_count") or ""
            when = next((txt(r.get(c)) for c in ("timestamp", "window_start", "session_start") if txt(r.get(c))), "")
            entity = next((txt(r.get(c)) for c in ("host_id", "hostname") if txt(r.get(c))), "")
            user = redact(r.get("username"), "user", args.redact_usernames)
            ip = redact(r.get("source_ip"), "ip", args.redact_source_ips)
            proxy = r.get("proxy_security_relevant")
            rows.append([esc(LABELS.get(dataset, dataset)), esc(feature_set), esc(votes), esc(compact(r.get("flagged_by"), 90)), number(r.get("model_zoo_ensemble_score"), 3), esc(when), esc(entity), esc(user), esc(ip), esc(r.get("event_type", "")), badge("yes", "danger") if truth(proxy) else (badge("no", "neutral") if txt(proxy) else "–"), '<code>'+esc(r.get("row_manifest_id"))+'</code>'])
    return ('<section id="consensus"><h2>Consensus alerts</h2><p class="lead">Highest-agreement test observations from the model zoo (top rows per run). Trace any row to its original log lines with its <code>row_manifest_id</code> through the Stage 3 split lineage and the Stage 1 event lookup.</p>'
            + table(["Representation","Feature set","Votes","Flagged by","Ensemble score","Time","Host","Username","Source IP","Event type","Proxy security","row_manifest_id"], rows, "alerts") + '</section>')


def evidence(data, met):
    rows = []
    for r in data["export"]:
        rows.append([esc(LABELS.get(txt(r.get("dataset")), r.get("dataset"))), status(r.get("status")), count(r.get("isolation_alerts")), count(r.get("complete_evidence_alerts", r.get("alerts_with_complete_evidence"))), count(r.get("partial_evidence_alerts", r.get("alerts_with_partial_evidence"))), count(r.get("missing_evidence_alerts", r.get("alerts_without_evidence"))), count(r.get("source_record_rows"))])
    graphic = donut((("Complete",met["complete"],"#16a34a"),("Partial",met["partial"],"#f59e0b"),("Missing",met["missing"],"#dc2626")))
    flow = '<div class="flow"><span>Anomaly</span><b>→</b><span>row_manifest_id</span><b>→</b><span>record_id</span><b>→</b><span>Original log line</span><b>→</b><span>Source coordinates</span></div>'
    return '<section id="evidence"><h2>Evidence integrity</h2><p class="lead">Every disposition should resolve to the original authentication record.</p><div class="two"><div class="panel">'+graphic+'</div><div class="panel"><h3>Lineage contract</h3>'+flow+'<p>Partial or missing evidence should be fixed before analyst disposition.</p></div></div>'+table(["Representation","Status","Isolation alerts","Complete","Partial","Missing","Source records"],rows)+'</section>'


def categories(data, args):
    aggregate = defaultdict(lambda: [0,0,0.0])
    outcomes = Counter()
    for r in data["categories"]:
        label = (txt(r.get("event_category")) or "unknown")+" / "+(txt(r.get("event_outcome")) or "unknown")
        aggregate[label][0] += integer(r.get("isolation_alerts")); aggregate[label][1] += integer(r.get("source_record_rows")); aggregate[label][2] = max(aggregate[label][2], num(r.get("maximum_isolation_score")))
        outcomes[txt(r.get("event_outcome")) or "unknown"] += integer(r.get("source_record_rows"))
    top = sorted(aggregate.items(), key=lambda x:(-x[1][0],-x[1][1]))[:args.top_categories]
    rows = [[esc(k),count(v[0]),count(v[1]),number(v[2],5)] for k,v in top]
    return '<section id="categories"><h2>Authentication danger patterns</h2><p class="lead">Event categories and outcomes represented in Isolation Forest evidence.</p><div class="two"><div class="panel">'+bar_chart([(k,v[0]) for k,v in top],"Top categories and outcomes","#dc2626")+'</div><div class="panel">'+bar_chart(outcomes.most_common(10),"Source records by outcome","#f59e0b")+'</div></div>'+table(["Category / outcome","Alerts","Source records","Maximum score"],rows)+'</section>'


def entities(data, args):
    counters = {"Hosts":Counter(),"Usernames":Counter(),"Source IPs":Counter(),"Processes":Counter()}
    for r in data["details"]:
        values = {
            "Hosts": txt(r.get("hostname")),
            "Usernames": redact(r.get("username"),"user",args.redact_usernames),
            "Source IPs": redact(r.get("source_ip"),"ip",args.redact_source_ips),
            "Processes": txt(r.get("process_name")),
        }
        for key,value in values.items():
            if value: counters[key][value]+=1
    colors = {"Hosts":"#2563eb","Usernames":"#8b5cf6","Source IPs":"#dc2626","Processes":"#0891b2"}
    panels = "".join('<div class="panel">'+bar_chart(counters[k].most_common(args.top_entities),k,colors[k])+'</div>' for k in counters)
    return '<section id="entities"><h2>Concentrated entities</h2><p class="lead">Frequently represented entities may be attacked assets, noisy services, or repetitive expected activity.</p><div class="chart-grid">'+panels+'</div></section>'


def top_alerts(data, args):
    chains = sorted(data["chains"],key=lambda r:num(r.get("isolation_score")),reverse=True)[:args.top_alerts]
    rows=[]
    for i,r in enumerate(chains,1):
        user=redact(r.get("observation_username"),"user",args.redact_usernames); ip=redact(r.get("observation_source_ip"),"ip",args.redact_source_ips)
        preview='<details><summary>View evidence</summary><pre>'+esc(compact(r.get("representative_original_log_lines"),1800))+'</pre></details>'
        kind="success" if txt(r.get("evidence_status"))=="complete" else "warning"
        rows.append([str(i),esc(LABELS.get(txt(r.get("dataset")),r.get("dataset"))),number(r.get("isolation_score"),5),esc(r.get("observation_timestamp")),esc(r.get("observation_entity")),esc(user),esc(ip),esc(compact(r.get("source_event_types"),150)),badge(r.get("evidence_status"),kind),preview])
    return '<section id="alerts"><h2>Highest-scoring Isolation Forest observations</h2><p class="lead">Prioritized review candidates with original-record previews.</p>'+table(["#","Representation","Score","Time","Entity","Username","Source IP","Event types","Evidence","Original lines"],rows,"alerts")+'</section>'


def review(data):
    queue_rows=[]; labels=Counter()
    for dataset in DATASETS:
        rows=data["reviews"].get(dataset,[]); queue_rows.append([esc(LABELS[dataset]),count(len(rows))])
        for r in rows:
            if txt(r.get("review_label")): labels[txt(r.get("review_label"))]+=1
    label_names=("security_relevant","operationally_interesting","expected_behavior","data_quality_issue","insufficient_context")
    label_rows=[[esc(k.replace("_"," ")),count(labels[k])] for k in label_names]
    return '<section id="review"><h2>Analyst review plan</h2><p class="lead">Detector output remains provisional until representative observations are labelled.</p><div class="two"><div class="panel"><h3>Available queues</h3>'+table(["Representation","Rows"],queue_rows)+'</div><div class="panel"><h3>Current labels</h3>'+table(["Label","Count"],label_rows)+'</div></div><div class="panel"><h3>Recommended sequence</h3><ol><li>Review model-zoo consensus alerts, highest vote count first.</li><li>Review three-detector Stage 4 consensus alerts.</li><li>Sample detector-only populations.</li><li>Inspect original record chains before assigning danger.</li><li>Replace proxy labels with analyst labels and recalculate precision by detector.</li></ol></div></section>'


CSS = """
:root{--bg:#f3f6fb;--panel:#fff;--ink:#172033;--muted:#5f6b7d;--line:#dce3ed;--shadow:0 9px 28px rgba(31,41,55,.08)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.52}.hero{background:linear-gradient(135deg,#111827,#1d4ed8 62%,#0891b2);color:#fff;padding:42px 24px}.hero-inner,.shell{max-width:1500px;margin:auto}.hero h1{font-size:clamp(2rem,4vw,3.4rem);margin:4px 0 10px}.hero p{color:#dbeafe;max-width:900px}.eyebrow{text-transform:uppercase;letter-spacing:.14em;color:#bfdbfe;font-size:.76rem;font-weight:800}.meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.meta span{padding:6px 10px;border-radius:99px;background:#ffffff20;border:1px solid #ffffff35}.shell{padding:0 24px 55px}.nav{position:sticky;top:0;z-index:5;display:flex;gap:7px;overflow:auto;background:#f3f6fbef;backdrop-filter:blur(10px);padding:10px 0;margin-bottom:25px}.nav a{white-space:nowrap;text-decoration:none;color:#334155;background:#fff;border:1px solid var(--line);border-radius:99px;padding:6px 10px;font-size:.82rem}section{scroll-margin-top:64px;margin-bottom:34px}h2{font-size:1.75rem;margin:0 0 5px}h3{margin:0 0 13px}.lead{color:var(--muted);max-width:1000px;margin:0 0 18px}.metric-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:13px;margin-bottom:18px}.metric-card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}.metric-card{padding:17px;border-top:4px solid #94a3b8}.metric-card.danger{border-top-color:#dc2626}.metric-card.warning{border-top-color:#f59e0b}.metric-card.success{border-top-color:#16a34a}.metric-title{text-transform:uppercase;letter-spacing:.07em;font-weight:800;color:var(--muted);font-size:.74rem}.metric-value{font-size:1.8rem;font-weight:850;margin:5px 0}.metric-sub{color:var(--muted);font-size:.82rem}.panel{padding:19px}.two,.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:17px}.chart{width:100%;height:auto}.chart-title{font-size:17px;font-weight:800;fill:#172033}.axis{font-size:12px;fill:#5f6b7d}.value{font-size:12px;fill:#172033;font-weight:700}.donut{font-size:24px;font-weight:850;fill:#172033}.finding{border-left:4px solid #94a3b8;background:#f8fafc;border-radius:10px;padding:11px 13px;margin:9px 0}.finding p{margin:3px 0;color:var(--muted)}.finding.danger{border-color:#dc2626;background:#fff5f5}.finding.warning{border-color:#f59e0b;background:#fffbeb}.finding.success{border-color:#16a34a;background:#f0fdf4}.table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}table{border-collapse:collapse;width:100%;font-size:.87rem}th{text-align:left;background:#eaf0f9;padding:10px 11px;border-bottom:1px solid var(--line);white-space:nowrap}td{padding:9px 11px;border-bottom:1px solid #edf1f5;vertical-align:top}tbody tr:hover{background:#f8fbff}.badge{display:inline-block;padding:3px 8px;border-radius:99px;font-size:.74rem;font-weight:800;white-space:nowrap}.badge.success{background:#dcfce7;color:#166534}.badge.warning{background:#fef3c7;color:#92400e}.badge.danger{background:#fee2e2;color:#991b1b}.badge.neutral{background:#e2e8f0;color:#334155}.flow{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.flow span{padding:7px 10px;border-radius:8px;background:#eef2ff;color:#3730a3;font-weight:700}.empty{padding:24px;text-align:center;color:var(--muted);border:1px dashed #cbd5e1;border-radius:11px}details summary{cursor:pointer;color:#2563eb;font-weight:700}pre{white-space:pre-wrap;word-break:break-word;background:#111827;color:#e5e7eb;padding:11px;border-radius:8px;max-width:650px;max-height:300px;overflow:auto;font-size:.77rem}code{font-size:.78rem}.alerts td:last-child{min-width:210px}.footer{text-align:center;color:var(--muted);font-size:.8rem;padding:20px}@media(max-width:1100px){.metric-grid{grid-template-columns:repeat(3,1fr)}.two,.chart-grid{grid-template-columns:1fr}}@media(max-width:620px){.metric-grid{grid-template-columns:1fr 1fr}.shell{padding:0 12px 45px}.hero{padding:30px 12px}}@media print{body{background:#fff}.nav{display:none}.metric-card,.panel,.table-wrap{box-shadow:none}.two,.chart-grid{grid-template-columns:1fr 1fr}}
"""


def methodology():
    return '<section id="method"><h2>Methodology and limitations</h2><div class="two"><div class="panel"><h3>Detection channels</h3><ul><li><b>Robust deviation:</b> extreme changes in stable numeric behavior.</li><li><b>Isolation Forest:</b> unusual multivariate combinations.</li><li><b>Novelty:</b> rare categorical, text, and sequence features.</li><li><b>Model zoo:</b> 13 detector families, pruned and greedily reduced; ensemble of training-referenced percentiles.</li></ul></div><div class="panel"><h3>Limitations</h3><ul><li>Anomalies are not confirmed malicious activity.</li><li>Thresholds control workload but do not establish precision.</li><li>Proxy detection rates reward known-risky event types; they cannot measure detection of novel attacks and are partly circular because the same counts are features.</li><li>Repeated benign activity can dominate anomaly counts.</li><li>Skipped representations should not be interpreted as safe.</li><li>Evidence may contain sensitive identifiers and paths.</li></ul></div></div></section>'


RESULTS_INTRO = ("<p>This section reports what the detectors flagged in the test period, checks that they "
                 "behave like detectors rather than flagging everything (Model behaviour), and compares the "
                 "model zoo. Alert rates describe workload, not how many attacks occurred.</p>")
EVIDENCE_INTRO = ("<p>An alert is only useful if an analyst can see what actually happened. This section checks "
                  "that every alert traces back to its original log lines, and summarises which events, "
                  "servers, users and addresses the alerts involve.</p>")


def render(data, args):
    met = metrics(data); risk = risk_score(data, met)
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    zoo_runs = [s for s in data["zoo"]["summaries"] if s.get("status") == "completed"]
    consensus = sum(integer(s.get("test_consensus_alerts")) for s in zoo_runs if s.get("feature_set") in ("selected", None))
    scored = sum(sum(run["rows"].values()) for run in (data["behaviour"] or {}).get("detector", []))
    name = layout.SOURCE["auth"]["name"]
    chapters = [
        ("Introduction", layout.INTRO, [layout.text_section("how-to-read", "How to read this report", layout.HOW_TO_READ.format(name=name)), overview(data, met, risk)]),
        ("Data", "<p>" + layout.SOURCE["auth"]["data"] + "</p>", [pipeline(data), coverage_section("auth")]),
        ("Methodology", layout.APPROACH, [feature_relevance(data, args), model_selection(data)]),
        ("Results", RESULTS_INTRO, [experiments(data), behaviour_section(data["behaviour"], "Authentication"), zoo_results(data), cluster_section(args.zoo.parent / "model_zoo_map", args.output, "Authentication"), render_clusters_section(args.zoo.parents[2] / "phase7b_clusters" / "auth", args.zoo.parent / "model_zoo_map", "Authentication"), consensus_alerts(data, args), silence_section("auth"), first_seen_section("auth"), activity_section("auth")]),
        ("Evidence and Analysis", EVIDENCE_INTRO, [evidence(data, met), categories(data, args), entities(data, args), top_alerts(data, args), context_section("auth")]),
        ("Discussion", layout.MEANING, [methodology()]),
        ("Recommendations", "", [review(data)]),
        ("Conclusion", layout.CONCLUSION, []),
    ]
    abstract = layout.abstract_text("auth", lines=met["total"], months=len(data["classification"]) or None,
                                    alerts=met["union"], traced=met["isolation"], consensus=consensus, scored=scored)
    return layout.document(title="Unsupervised Anomaly Detection in Authentication Logs: Analysis Report", source="auth",
                           generated=generated, abstract=abstract, base_css=CSS, chapters=chapters,
                           footer="Generated by Phase 6. Analyst validation is required before incident escalation.")


def main():
    args=args_parser(); log=Log(args.quiet,args.verbose)
    log.say("Authentication Stage 6 starting","START")
    data=load_data(args,log)
    log.say("Building dashboards, findings, and review tables","PHASE")
    report=render(data,args)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    temporary=args.output.with_suffix(args.output.suffix+".tmp")
    temporary.write_text(report,encoding="utf-8")
    os.replace(temporary,args.output)
    log.say(f"Report written: {args.output} ({args.output.stat().st_size/1024:,.1f} KB)","DONE")
    log.say("Authentication Stage 6 completed successfully","COMPLETE",always=True)


if __name__=="__main__":
    raise SystemExit(runlog.main(main))
