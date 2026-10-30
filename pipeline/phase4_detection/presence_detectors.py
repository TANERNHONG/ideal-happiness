"""Phase 4a of the presence method: the same three detectors, adapted to an empty baseline.

  python pipeline/phase4_detection/presence_detectors.py --source ipf
  python pipeline/phase4_detection/presence_detectors.py --source pf

Used for the logs that are empty, or nearly, in normal operation (IPFilter, PF).

PRESENCE layer (slot views). The detectors are those of the other sources:
    Robust deviation  per count feature, (x - baseline median) / scale, where the
                      scale is 1.4826 x MAD with a floor of one count. The
                      baseline median and MAD are both zero here, so without the
                      floor every count would be an infinite deviation (and with
                      the auth rules, which drop zero-MAD features, it would be
                      silent). Score = largest positive deviation.
    Isolation Forest  fitted on every certified slot, baseline and active alike
                      (the usual unsupervised use: anomalies are few and
                      different). A model fitted on the baseline alone cannot work:
                      the baseline slots are identical, so the trees would never
                      split on the count features.
    Novelty           tokens (flow, source, port, rule...) never or rarely seen in
                      the baseline training slots: sum of log((n + 1) / (count + 1)).
Threshold: ZERO TOLERANCE instead of an alert budget. Each detector's threshold is
the highest score among the baseline validation slots, and a slot alerts when it
scores above it. "N alerts a day" makes no sense when the policy says any
activity should be looked at. The checks reported are: baseline training slots
above the threshold (false alarms, should be 0), and active slots missed
(should be 0).

WITHIN-ACTIVITY layer (individual, attempts, flow_episodes). Every row is an
alert by policy, so the detectors are used to RANK the activity against itself:
    Novelty           mean surprisal, -log(share), of the row's tokens, where a
                      token's share is the fraction of ALL active log lines that
                      carry it. Weighting by lines rather than by rows of the view
                      keeps "8 lines out of 52,231" rare even when it forms 2 of
                      only 5 episodes.
    Isolation Forest  fitted on the view's active rows; it catches odd shapes
                      (cadence, sizes, gaps) rather than odd attributes. With
                      fewer than MIN_ROWS_FOR_FOREST rows it is not used for
                      ranking: there is nothing to learn from.
The within-activity score is the larger of the two percentile ranks (a row stands
out if either signal says so), ties broken by their mean. Rank 1 is the row least
like the rest of the activity.

What goes to Phase 7 (files named test_scores.csv; the rest are scores.csv and
feed only the report):
    slots_1d       robust / Isolation Forest / novelty alerts, one per active host-day
    flow_episodes  presence alerts, one per episode, ranked within the activity
The 5-minute and hourly slots and the single events and attempts would turn one
migration into thousands of alerts; they stay in the report.

The model zoo (Phase 4b) is not run for this source: most of its models need a
non-degenerate training distribution, which an all-zero baseline does not have.
"""
from __future__ import annotations

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = {"ipf": {"prefix": "ipflog", "label": "IPFilter"}, "pf": {"prefix": "pflog", "label": "PF"}}
SLOT_VIEWS = ("slots_5min", "slots_1h", "slots_1d")
ACTIVITY_VIEWS = ("individual", "attempts", "flow_episodes")
ALERTING = {"slots_1d", "flow_episodes"}
COUNT_FEATURES = ["packets", "lines", "attempts_started", "syn_packets", "rst_packets", "udp_packets", "icmp_packets",
                  "broadcast_packets", "blocked_packets", "passed_packets", "distinct_flows", "distinct_sources",
                  "distinct_destinations", "distinct_destination_ports", "distinct_rules"]
META_COLUMNS = ["row_manifest_id", "timestamp", "hostname", "split", "regime", "active"]
SEED = 13
MIN_ROWS_FOR_FOREST = 20


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(CONFIG))
    parser.add_argument("--robust-floor", type=float, default=1.0, help="Smallest scale for robust deviation (counts).")
    parser.add_argument("--trees", type=int, default=200)
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.features = ROOT / "data" / "phase3_features" / args.source
    args.lookup = ROOT / "data" / "phase1_classify" / args.source / f"{CONFIG[args.source]['prefix']}_event_lookup.csv"
    args.output = ROOT / "data" / "phase4_detection" / args.source / "detectors"
    return args


log = runlog.log


def load(view, folder):
    table = pd.read_csv(folder / view / "features.csv", dtype={"row_manifest_id": str, "timestamp": str})
    tokens = pd.read_csv(folder / view / "tokens.csv", dtype=str, keep_default_na=False)
    table = table.merge(tokens, on="row_manifest_id", how="left")
    table["tokens"] = table["tokens"].fillna("")
    table["active"] = table["active"].astype(str).eq("True")
    meta = json.loads((folder / view / "metadata.json").read_text(encoding="utf-8"))
    return table, meta


def isolation_scores(matrix, trees):
    model = IsolationForest(n_estimators=trees, max_samples=min(256, len(matrix)), random_state=SEED)
    model.fit(matrix)
    return -model.score_samples(matrix)


def token_lists(series):
    return [set(text.split()) for text in series]


def novelty_against(reference_tokens, tokens):
    """Sum over a row's distinct tokens of log((n + 1) / (count_in_reference + 1))."""
    counts = {}
    for row in reference_tokens:
        for token in row:
            counts[token] = counts.get(token, 0) + 1
    n = len(reference_tokens)
    return np.array([sum(np.log((n + 1) / (counts.get(token, 0) + 1)) for token in row) for row in tokens])


def percentile_rank(values):
    return pd.Series(values).rank(method="average", pct=True).to_numpy()


def presence(view, table, args):
    scored = table[table["split"].isin(["train", "validation", "scored"])].copy()
    counts = scored[COUNT_FEATURES].to_numpy(dtype=float)
    train = scored["split"].eq("train").to_numpy()
    median = np.median(counts[train], axis=0)
    mad = np.median(np.abs(counts[train] - median), axis=0)
    scale = np.maximum(1.4826 * mad, args.robust_floor)
    scored["robust_score"] = ((counts - median) / scale).clip(min=0).max(axis=1)
    model_columns = [c for c in scored.columns if c in COUNT_FEATURES or c.startswith("log1p_")]
    scored["isolation_score"] = isolation_scores(scored[model_columns].to_numpy(dtype=float), args.trees)
    tokens = token_lists(scored["tokens"])
    scored["novelty_score"] = novelty_against([t for t, keep in zip(tokens, train) if keep], tokens)
    validation = scored["split"].eq("validation")
    thresholds, flagged = {}, []
    for name in ("robust", "isolation", "novelty"):
        threshold = float(scored.loc[validation, f"{name}_score"].max())
        thresholds[name] = threshold
        scored[f"{name}_alert"] = scored[f"{name}_score"] > threshold + 1e-9
        flagged.append(scored[f"{name}_alert"])
    scored["presence_alert"] = np.logical_or.reduce(flagged)
    scored["detector_combination"] = [
        "+".join(name for name in ("robust", "isolation", "novelty") if row[f"{name}_alert"]) or "none"
        for _, row in scored.iterrows()] if len(scored) < 20000 else _combinations(scored)
    baseline_train = scored["split"].eq("train")
    summary = {
        "dataset": view, "layer": "presence", "alerting_in_phase7": view in ALERTING,
        "threshold_rule": "zero tolerance: above the highest baseline validation score",
        "rows": len(table), "scored_rows": len(scored), "excluded_rows": int(len(table) - len(scored)),
        "baseline_train_rows": int(baseline_train.sum()), "baseline_validation_rows": int(validation.sum()),
        "active_month_rows": int(scored["split"].eq("scored").sum()), "active_rows": int(scored["active"].sum()),
        "robust_median_max": float(median.max()), "robust_mad_max": float(mad.max()), "robust_floor": args.robust_floor,
        **{f"{name}_threshold": value for name, value in thresholds.items()},
        **{f"test_{name}_alerts": int(scored[f"{name}_alert"].sum()) for name in ("robust", "isolation", "novelty")},
        "test_either_model_alerts": int(scored["presence_alert"].sum()),
        "active_flagged": int((scored["active"] & scored["presence_alert"]).sum()),
        "active_missed": int((scored["active"] & ~scored["presence_alert"]).sum()),
        "quiet_flagged": int((~scored["active"] & scored["presence_alert"]).sum()),
        "baseline_train_false_alarms": int((baseline_train & scored["presence_alert"]).sum()),
        "validation_alerts": int((validation & scored["presence_alert"]).sum()),
    }
    columns = META_COLUMNS + ["packets", "lines", "robust_score", "robust_alert", "isolation_score", "isolation_alert",
                              "novelty_score", "novelty_alert", "presence_alert", "detector_combination"]
    return scored[columns], summary


def _combinations(frame):
    parts = [np.where(frame[f"{name}_alert"], name, "") for name in ("robust", "isolation", "novelty")]
    joined = ["+".join(p for p in triple if p) or "none" for triple in zip(*parts)]
    return joined


def line_token_shares(features_folder):
    """Share of all active log lines carrying each token (from the single-event view)."""
    events = token_lists(pd.read_csv(features_folder / "individual" / "tokens.csv", dtype=str,
                                     keep_default_na=False)["tokens"])
    counts = {}
    for row in events:
        for token in row:
            counts[token] = counts.get(token, 0) + 1
    return {token: count / len(events) for token, count in counts.items()}, len(events)


def within_activity(view, table, args, shares):
    scored = table.copy()
    feature_columns = [c for c in scored.columns if c not in META_COLUMNS + ["tokens"]]
    matrix = scored[feature_columns].to_numpy(dtype=float)
    use_forest = len(scored) >= MIN_ROWS_FOR_FOREST
    scored["isolation_score"] = isolation_scores(matrix, args.trees) if len(scored) > 1 else np.zeros(len(scored))
    tokens = token_lists(scored["tokens"])
    smallest = min(shares.values()) if shares else 1.0
    scored["novelty_score"] = [np.mean([-np.log(shares.get(t, smallest)) for t in row]) if row else 0.0
                               for row in tokens]
    novelty_pct = percentile_rank(scored["novelty_score"])
    forest_pct = percentile_rank(scored["isolation_score"])
    primary = np.maximum(novelty_pct, forest_pct) if use_forest else novelty_pct
    scored["within_activity_score"] = primary
    scored["tie_break"] = (novelty_pct + forest_pct) / 2
    order = scored.sort_values(["within_activity_score", "tie_break"], ascending=False).index
    scored.loc[order, "within_activity_rank"] = np.arange(1, len(order) + 1)
    scored["within_activity_rank"] = scored["within_activity_rank"].astype(int)
    scored["ranked_by"] = "novelty or Isolation Forest" if use_forest else "novelty (too few rows for a forest)"
    columns = META_COLUMNS + ["isolation_score", "novelty_score", "within_activity_score", "tie_break",
                              "within_activity_rank", "ranked_by"]
    if view in ALERTING:
        scored["presence_alert"] = True
        # higher = more unusual within the activity; Phase 7 turns it into a rank among the alerts
        scored["presence_score"] = (len(scored) - scored["within_activity_rank"] + 1) / len(scored)
        scored["detector_combination"] = "presence"
        columns += ["presence_score", "presence_alert", "detector_combination"]
    summary = {
        "dataset": view, "layer": "within_activity", "alerting_in_phase7": view in ALERTING,
        "threshold_rule": "none: every active row is an alert by policy; scores rank the activity",
        "probability_rule": "rank_within_alerts" if view in ALERTING else "",
        "rows": len(scored), "scored_rows": len(scored), "active_rows": len(scored),
        "test_presence_alerts": len(scored) if view in ALERTING else 0,
        "ranked_by": scored["ranked_by"].iloc[0] if len(scored) else "",
        "rarest_tokens": sorted(((t, round(s, 6)) for t, s in shares.items()), key=lambda item: item[1])[:5],
    }
    return scored[columns].sort_values("within_activity_rank"), summary


def write_evidence(folder, scores, meta, lookup):
    """Original lines for each alerted row, in event order (test_raw_alert_evidence.csv, as Phase 7 expects)."""
    alerted = set(scores.loc[scores["presence_alert"].astype(bool), "row_manifest_id"])
    lineage = pd.read_csv(ROOT / meta["lineage_file"], dtype=str)
    lineage = lineage[lineage["row_manifest_id"].isin(alerted)]
    evidence = lineage.merge(lookup, on="event_id", how="left")
    evidence["event_position"] = pd.to_numeric(evidence["event_position"])
    evidence = evidence.sort_values(["row_manifest_id", "event_position"])
    evidence[["row_manifest_id", "event_position", "event_id", "event_timestamp", "raw_message"]].to_csv(
        folder / "test_raw_alert_evidence.csv", index=False)
    resolved = evidence["raw_message"].notna().groupby(evidence["row_manifest_id"]).all()
    return {"alerts_with_complete_evidence": int(resolved.sum()),
            "alerts_without_evidence": int(len(alerted - set(resolved.index)) + (~resolved).sum()),
            "evidence_rows": len(evidence)}


def main():
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    lookup = pd.read_csv(args.lookup, dtype=str, usecols=["event_id", "raw_message"])
    shares, active_lines = line_token_shares(args.features)
    log(f"Within-activity token shares from {active_lines:,} active lines", args.quiet)
    rows = []
    for view in SLOT_VIEWS + ACTIVITY_VIEWS:
        table, meta = load(view, args.features)
        scores, summary = (presence(view, table, args) if view in SLOT_VIEWS
                           else within_activity(view, table, args, shares))
        folder = args.output / view
        folder.mkdir(parents=True, exist_ok=True)
        name = "test_scores.csv" if view in ALERTING else "scores.csv"
        for stale in ("test_scores.csv", "scores.csv"):
            if stale != name and (folder / stale).exists():
                (folder / stale).unlink()
        scores.to_csv(folder / name, index=False)
        if view in ALERTING:
            summary.update(write_evidence(folder, scores, meta, lookup))
        summary["scores_file"] = str((folder / name).relative_to(ROOT))
        (folder / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        rows.append(summary)
        if summary["layer"] == "presence":
            log(f"{view}: {summary['scored_rows']:,} certified slots ({summary['baseline_train_rows']:,} baseline "
                f"train); alerts robust {summary['test_robust_alerts']}, IF {summary['test_isolation_alerts']}, "
                f"novelty {summary['test_novelty_alerts']}; active flagged {summary['active_flagged']}/"
                f"{summary['active_rows']}, quiet flagged {summary['quiet_flagged']}", args.quiet)
        else:
            top = scores.iloc[0]
            log(f"{view}: {summary['rows']:,} active rows ranked; most unusual {top['row_manifest_id']} "
                f"(score {top['within_activity_score']:.3f})", args.quiet)
    flat = pd.DataFrame([{k: v for k, v in row.items() if not isinstance(v, (list, dict))} for row in rows])
    flat.to_csv(args.output / "experiment_summary.csv", index=False)
    (args.output / "experiment_summary.json").write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
    log(f"{CONFIG[args.source]['label']} Phase 4a (presence method) done -> {args.output}", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
