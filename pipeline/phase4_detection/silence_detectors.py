"""Phase 4d: hosts that go silent while other logs show them running.

  python pipeline/phase4_detection/silence_detectors.py --source auth
  python pipeline/phase4_detection/silence_detectors.py --source ossec --min-surprise 4

Reads the Phase 2c calendar (<prefix>_host_days.csv), which has a row for every
host and day, empty days included.

Silence. A SILENT day is one on which the host logged nothing in this source
while other logs show it was up (status quiet or collection_gap). Consecutive
silent days of one host form one EPISODE, which is the alert (one alert for a
61-day hole, not 61). An episode is scored by how unlikely that many silent
days in a row are for that host: if the host is silent on a share p of its up
days (one added to each count, so p is never 0 or 1), k days in a row have a
chance of about p^k, and the score is -log10(p^k). An episode alerts when the
score is at least --min-surprise (default 3: a run expected once in 1,000) and
the host logs on most of its up days (p <= --max-silent-share). This works the
same for an auth log with hundreds of lines a day and an OSSEC agent that
writes four.

Volume. For context, each day also gets a robust deviation on log(1 + lines):
    z = (log1p(lines) - host median) / max(1.4826 x host MAD, floor)
Unusually busy days (z >= --threshold) are counted but only reported: the
host_behavior_1d detectors already cover bursts.

The shares and medians come from the whole year, not just the training period:
a silence is a data-quality and monitoring question for the whole study period.
Days on which no log shows the host up ('unknown') are left out, because silence
there cannot be told apart from the host being off.

Outputs (data/phase4_detection/<source>/silence/):
    silence_episodes/test_scores.csv     alerting episodes; Phase 7 reads silence_alert / silence_score
    silence_episodes/test_raw_alert_evidence.csv   a written description per episode (there are no log
                                                   lines to show: the alert IS their absence)
    silence_episodes/summary.json
    silent_runs.csv                      every run of silent days, alerting or not
    daily_scores.csv                     every host-day with its deviation
    experiment_summary.csv
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from sources import ROOT, SOURCES  # noqa: E402

FLOOR = 0.25          # on the log1p scale: a host with no spread still needs a ~30% change to count
COLUMNS = ["row_manifest_id", "hostname", "start", "end", "days", "quiet_days", "collection_gap_days",
           "usual_lines_per_day", "witness_lines", "witness_sources", "file_statuses", "host_silent_share",
           "chance_of_run", "deepest_deviation", "silence_score", "silence_alert", "detector_combination"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=["auth", "ossec", "pf"])
    parser.add_argument("--threshold", type=float, default=3.5, help="Robust deviation for a busy day (report only).")
    parser.add_argument("--min-surprise", type=float, default=3.0,
                        help="-log10 chance of the silent run; 3 = a run expected once in 1,000.")
    parser.add_argument("--max-silent-share", type=float, default=0.5,
                        help="Hosts silent on more than this share of their up days cannot raise silence alerts.")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.days = ROOT / "data" / "phase2_observations" / args.source / f"{SOURCES[args.source]['prefix']}_host_days.csv"
    args.output = ROOT / "data" / "phase4_detection" / args.source / "silence"
    return args


log = runlog.log


def score_days(days, args):
    days = days.copy()
    up = days["status"].isin(["active", "quiet", "collection_gap"])
    days["log_lines"] = np.log1p(days["lines"])
    stats = days[up].groupby("hostname")["log_lines"].agg(
        median="median", mad=lambda v: float(np.median(np.abs(v - np.median(v)))))
    stats["median_lines"] = np.expm1(stats["median"])
    days = days.merge(stats, left_on="hostname", right_index=True, how="left")
    scale = np.maximum(1.4826 * days["mad"].fillna(0), FLOOR)
    days["deviation"] = np.where(up, (days["log_lines"] - days["median"].fillna(0)) / scale, np.nan)
    days["silent"] = up & days["lines"].eq(0)
    days["busy"] = up & (days["deviation"] >= args.threshold)
    share = days[up].groupby("hostname").agg(up_days=("silent", "size"), silent_days=("silent", "sum"))
    share["silent_share"] = (share["silent_days"] + 1) / (share["up_days"] + 2)
    stats = stats.join(share)
    days = days.merge(share[["silent_share"]], left_on="hostname", right_index=True, how="left")
    return days, stats


def silent_runs(days, source, args):
    rows = []
    silent = days[days["silent"]].sort_values(["hostname", "day"])
    for host, part in silent.groupby("hostname"):
        for _, run in part.groupby((part["day"].diff().dt.days != 1).cumsum()):
            start, end = run["day"].min(), run["day"].max()
            statuses = run["status"].value_counts().to_dict()
            share = float(run["silent_share"].iloc[0])
            score = -len(run) * np.log10(share)
            rows.append({
                "row_manifest_id": hashlib.sha256(f"silence|{source}|{host}|{start.date()}".encode()).hexdigest()[:24],
                "hostname": host, "start": str(start.date()), "end": str(end.date()), "days": len(run),
                "quiet_days": statuses.get("quiet", 0), "collection_gap_days": statuses.get("collection_gap", 0),
                "usual_lines_per_day": round(float(run["median_lines"].iloc[0]), 1),
                "witness_lines": int(run["witness_lines"].sum()), "witness_sources": run["witness_sources"].iloc[0],
                "file_statuses": ", ".join(f"{k} {v}" for k, v in run["file_status"].value_counts().items()),
                "host_silent_share": round(share, 4), "chance_of_run": float(f"{10 ** -score:.3g}"),
                "deepest_deviation": round(float(run["deviation"].min()), 2), "silence_score": round(score, 3),
                "silence_alert": bool(score >= args.min_surprise and share <= args.max_silent_share),
                "detector_combination": "silence",
            })
    return pd.DataFrame(rows, columns=COLUMNS)


def describe(row, label):
    span = row["start"] if row["start"] == row["end"] else f"{row['start']} to {row['end']}"
    if not row["collection_gap_days"]:
        kind = "Its monthly file was collected but holds nothing for these days"
    elif row["quiet_days"]:
        kind = f"Its monthly file in the archive is empty or missing for {row['collection_gap_days']} of these days"
    else:
        kind = "Its monthly file in the archive is empty or missing"
    return (f"[silence] {row['hostname']}: no {label} lines {span} ({row['days']} day{'s' if row['days'] != 1 else ''}); "
            f"usually about {row['usual_lines_per_day']:,.0f} lines a day, silent on {row['host_silent_share']:.1%} of "
            f"its up days. The host was up: {row['witness_sources']} logged {row['witness_lines']:,} lines from it in "
            f"this period. {kind}.")


def main():
    args = parse_args()
    spec = SOURCES[args.source]
    days = pd.read_csv(args.days, parse_dates=["day"])
    scored, stats = score_days(days, args)
    runs = silent_runs(scored, args.source, args)
    alerts = runs[runs["silence_alert"]]
    folder = args.output / "silence_episodes"
    folder.mkdir(parents=True, exist_ok=True)
    scored.drop(columns=["log_lines"]).to_csv(args.output / "daily_scores.csv", index=False)
    runs.sort_values("silence_score", ascending=False).to_csv(args.output / "silent_runs.csv", index=False)
    alerts.to_csv(folder / "test_scores.csv", index=False)
    pd.DataFrame({"row_manifest_id": alerts["row_manifest_id"], "event_position": 1,
                  spec["message_column"]: [describe(row, spec["label"]) for _, row in alerts.iterrows()]}).to_csv(
        folder / "test_raw_alert_evidence.csv", index=False)
    summary = {
        "dataset": "silence_episodes", "layer": "silence", "probability_rule": "rank_within_alerts",
        "generated_at": datetime.now().isoformat(timespec="seconds"), "min_surprise": args.min_surprise,
        "max_silent_share": args.max_silent_share, "busy_threshold": args.threshold, "floor_log_scale": FLOOR,
        "host_days": len(scored), "host_days_scored": int(scored["deviation"].notna().sum()),
        "hosts": len(stats), "hosts_eligible": int((stats["silent_share"] <= args.max_silent_share).sum()),
        "silent_days": int(scored["silent"].sum()), "silent_runs": len(runs), "episodes": len(alerts),
        "test_silence_alerts": len(alerts), "silent_days_in_alerts": int(alerts["days"].sum()),
        "busy_days": int(scored["busy"].sum()),
    }
    (folder / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    pd.DataFrame([summary]).to_csv(args.output / "experiment_summary.csv", index=False)
    log(f"{spec['label']} silence: {summary['host_days_scored']:,} up host-days on {summary['hosts']} hosts "
        f"({summary['hosts_eligible']} log on most up-days); {summary['silent_days']} silent days in "
        f"{summary['silent_runs']} runs, {summary['episodes']} alerting ({summary['silent_days_in_alerts']} days); "
        f"{summary['busy_days']} unusually busy days (report only)", args.quiet)
    top = alerts.sort_values("silence_score", ascending=False).head(8)
    if len(top):                                         # servers and dates stay in the output: counts only here
        log(f"Strongest silent runs: {', '.join(f'{days} days' for days in top['days'])}; servers and dates in {folder}",
            args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
