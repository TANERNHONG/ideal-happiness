"""Phase 3 of the presence method: observations -> feature tables and a split by regime.

  python pipeline/phase3_features/presence.py --source ipf
  python pipeline/phase3_features/presence.py --source pf

Used for the logs that are empty, or nearly, in normal operation (IPFilter, PF).

Two layers, because the baseline is empty (see Phase 2):

PRESENCE layer (slots_5min, slots_1h, slots_1d)
    Features are the slot's counts: packets, lines, attempts started, SYN, RST,
    UDP, ICMP, broadcast, blocked and passed packets, distinct flows, sources,
    destinations, ports and rules, each also as log(1 + x). Time of day is left
    out on purpose: the baseline covers every hour equally and is empty at every
    hour, so time carries no information about normal.
    Split by REGIME, not by date. The chronological 70/15/15 split would put the
    only activity (Nov 2025) into training and leave an empty test period.
        train       certified slots on days the host logged nothing (the baseline), earliest 85%
        validation  the remaining 15% of those baseline slots (sets the threshold)
        scored      every other certified slot, including all the active ones
        excluded    uncertified slots (host not shown to be up, or file missing)

WITHIN-ACTIVITY layer (individual, attempts, flow_episodes)
    These views only exist where there is activity, so there is no baseline to
    train on. Every row is already unusual by policy. These features rank the
    activity against itself: what departs from the dominant pattern. They add
    time of day (sine and cosine), the gap since the previous row of the same
    flow, packet sizes, flags, and per-view shape (retries, cadence, duration).
    split = "activity" for every row.

Every view also gets novelty TOKENS (flow=, src=, dst=, dport=, rule=, action=,
flags=, iface=, broadcast) built from its events through the Phase 2 lineage.

Outputs (data/phase3_features/<source>/<view>/): features.csv (row_manifest_id,
timestamp, split, regime, active, features), tokens.csv, feature_names.csv,
metadata.json; and data/phase3_features/<source>/feature_engineering_summary.json.
"""
from __future__ import annotations

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = {"ipf": {"prefix": "ipflog", "label": "IPFilter"}, "pf": {"prefix": "pflog", "label": "PF"}}
VERSION = "2026-10-01-presence-features-02"
SLOT_VIEWS = ("slots_5min", "slots_1h", "slots_1d")
ACTIVITY_VIEWS = ("individual", "attempts", "flow_episodes")
FILES = {}       # set in main() from the source prefix
SLOT_COUNTS = ["packets", "lines", "attempts_started", "syn_packets", "rst_packets", "udp_packets", "icmp_packets",
               "broadcast_packets", "blocked_packets", "passed_packets", "distinct_flows", "distinct_sources",
               "distinct_destinations", "distinct_destination_ports", "distinct_rules"]
WELL_KNOWN = 1024


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(CONFIG))
    parser.add_argument("--validation-share", type=float, default=0.15)
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.observations = ROOT / "data" / "phase2_observations" / args.source
    args.output = ROOT / "data" / "phase3_features" / args.source
    prefix = CONFIG[args.source]["prefix"]
    FILES.update({"individual": f"{prefix}_events_all_months", "attempts": f"{prefix}_attempts",
                  "flow_episodes": f"{prefix}_flow_episodes", **{view: f"{prefix}_{view}" for view in SLOT_VIEWS}})
    return args


log = runlog.log


def cyclical(frame, when):
    hour = when.dt.hour + when.dt.minute / 60
    frame["hour_sin"], frame["hour_cos"] = np.sin(2 * np.pi * hour / 24), np.cos(2 * np.pi * hour / 24)
    frame["weekday_sin"] = np.sin(2 * np.pi * when.dt.weekday / 7)
    frame["weekday_cos"] = np.cos(2 * np.pi * when.dt.weekday / 7)


def add_logs(frame, columns):
    for column in columns:
        frame[f"log1p_{column}"] = np.log1p(frame[column].astype(float).clip(lower=0))


def event_tokens(events):
    """Space-separated novelty tokens per event."""
    port = events["service_port"].replace("", "-")
    parts = [
        "flow=" + events["flow"],
        "src=" + events["client_ip"], "dst=" + events["server_ip"], "dport=" + port + "/" + events["protocol"],
        "rule=" + events["rule_group"] + ":" + events["rule_number"], "action=" + events["action"],
        "flags=" + events["tcp_flags"].replace("", "none"), "iface=" + events["interface"],
    ]
    tokens = parts[0]
    for part in parts[1:]:
        tokens = tokens + " " + part
    return tokens + np.where(events["is_broadcast"].eq("True"), " broadcast", "")


def view_tokens(view, observations, events):
    lineage = pd.read_csv(observations / f"{FILES[view]}_lineage.csv", dtype=str, usecols=["row_manifest_id", "event_id"])
    tokens = events[["event_id"]].assign(tokens=event_tokens(events))
    joined = lineage.merge(tokens, on="event_id")
    return (joined.groupby("row_manifest_id")["tokens"]
            .agg(lambda values: " ".join(sorted(set(" ".join(values).split())))).rename("tokens"))


def slot_features(frame, validation_share):
    when = pd.to_datetime(frame["slot_start"])
    features = frame[SLOT_COUNTS].astype(float).copy()
    add_logs(features, SLOT_COUNTS)
    certified = frame["certified"].astype(str).eq("True")
    baseline = certified & frame["regime"].eq("baseline")
    split = pd.Series("excluded", index=frame.index)
    split[certified] = "scored"
    order = when[baseline].sort_values().index
    cut = int(round(len(order) * (1 - validation_share)))
    split[order[:cut]] = "train"
    split[order[cut:]] = "validation"
    return features, split, when


def activity_features(view, frame):
    if view == "individual":
        when = pd.to_datetime(frame["timestamp"])
        flags = frame["tcp_flags"].fillna("")
        features = pd.DataFrame({
            "packet_length": pd.to_numeric(frame["packet_length"], errors="coerce").fillna(0),
            "header_length": pd.to_numeric(frame["header_length"], errors="coerce").fillna(0),
            "repeat_count": pd.to_numeric(frame["repeat_count"], errors="coerce").fillna(1),
            "is_tcp": frame["protocol"].eq("tcp").astype(float), "is_udp": frame["protocol"].eq("udp").astype(float),
            "is_icmp": frame["protocol"].eq("icmp").astype(float),
            "is_broadcast": frame["is_broadcast"].astype(str).eq("True").astype(float),
            "is_blocked": frame["action"].eq("block").astype(float),
            "flag_syn": flags.str.startswith("S").astype(float), "flag_ecn": flags.isin(["SEC", "SE", "SC"]).astype(float),
            "flag_rst": flags.str.contains("R").astype(float), "flag_ack": flags.str.contains("A").astype(float),
            "flag_fin": flags.str.contains("F").astype(float),
            "service_port_well_known": (pd.to_numeric(frame["service_port"], errors="coerce").fillna(99999) < WELL_KNOWN).astype(float),
        })
        flow = frame["flow"]
    elif view == "attempts":
        when = pd.to_datetime(frame["start"])
        columns = ["duration_seconds", "lines", "packets", "syn_packets", "ecn_syn_packets", "rst_packets", "retries"]
        features = frame[columns].astype(float).copy()
        features["broadcast"] = frame["broadcast"].astype(str).eq("True").astype(float)
        features["is_udp"] = frame["protocol"].eq("udp").astype(float)
        flow = frame["flow"]
    else:
        when = pd.to_datetime(frame["start"])
        columns = ["attempts", "lines", "packets", "distinct_source_ports", "mean_interval_seconds", "interval_cv",
                   "mean_retries", "rst_share", "ecn_share", "duration_hours"]
        features = frame[columns].astype(float).copy()
        features["broadcast"] = frame["broadcast"].astype(str).eq("True").astype(float)
        features["is_udp"] = frame["protocol"].eq("udp").astype(float)
        flow = frame["flow"]
    order = when.sort_values().index
    previous = when[order].groupby(flow[order]).diff().dt.total_seconds()
    features["log1p_gap_same_flow_seconds"] = np.log1p(previous.reindex(frame.index).fillna(-1).clip(lower=0))
    features["first_of_flow"] = previous.reindex(frame.index).isna().astype(float)
    add_logs(features, [c for c in features.columns if c in ("packets", "lines", "duration_seconds", "attempts",
                                                              "mean_interval_seconds", "duration_hours")])
    cyclical(features, when)
    return features, pd.Series("activity", index=frame.index), when


def main():
    args = parse_args()
    events = pd.read_csv(args.observations / f"{FILES['individual']}.csv", dtype=str, keep_default_na=False)
    summary = {"version": VERSION, "generated_at": datetime.now().isoformat(timespec="seconds"), "views": {}}
    for view in SLOT_VIEWS + ACTIVITY_VIEWS:
        frame = pd.read_csv(args.observations / f"{FILES[view]}.csv", dtype=str, keep_default_na=False)
        if view in SLOT_VIEWS:
            features, split, when = slot_features(frame, args.validation_share)
            layer, regime = "presence", frame["regime"]
            active = frame["active"].astype(str).eq("True")
        else:
            features, split, when = activity_features(view, frame)
            layer, regime, active = "within_activity", pd.Series("active", index=frame.index), pd.Series(True, index=frame.index)
        tokens = view_tokens(view, args.observations, events).reindex(frame["row_manifest_id"]).fillna("")
        folder = args.output / view
        folder.mkdir(parents=True, exist_ok=True)
        table = pd.concat([pd.DataFrame({"row_manifest_id": frame["row_manifest_id"],
                                         "timestamp": when.dt.strftime("%Y-%m-%d %H:%M:%S"),
                                         "hostname": frame["hostname"], "split": split, "regime": regime,
                                         "active": active}), features.round(6)], axis=1)
        table.to_csv(folder / "features.csv", index=False)
        pd.DataFrame({"row_manifest_id": frame["row_manifest_id"].to_numpy(), "tokens": tokens.to_numpy()}).to_csv(
            folder / "tokens.csv", index=False)
        pd.DataFrame({"feature_name": features.columns}).to_csv(folder / "feature_names.csv", index=False)
        meta = {"dataset": view, "layer": layer, "rows": len(table), "features": int(features.shape[1]),
                "split_rows": {k: int(v) for k, v in split.value_counts().items()},
                "active_rows": int(active.sum()), "distinct_tokens": int(len(set(" ".join(tokens).split()))),
                "lineage_file": str((args.observations / f"{FILES[view]}_lineage.csv").relative_to(ROOT))}
        (folder / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        summary["views"][view] = meta
        log(f"{view} ({layer}): {len(table):,} rows, {features.shape[1]} features, "
            f"splits {meta['split_rows']}, {meta['active_rows']:,} active, {meta['distinct_tokens']} distinct tokens",
            args.quiet)
    (args.output / "feature_engineering_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"{CONFIG[args.source]['label']} Phase 3 (presence method) done -> {args.output}", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
