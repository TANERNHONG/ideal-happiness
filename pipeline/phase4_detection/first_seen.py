"""Phase 4e: things a host does in the test period that it never did before.

  python pipeline/phase4_detection/first_seen.py --source auth
  python pipeline/phase4_detection/first_seen.py --source ossec --lines 10

The novelty detector scores rare tokens, but its alerts are capped by the daily
alert budget, so a genuinely new behaviour can be pushed off the list on a busy
day. This step applies ZERO TOLERANCE to a few things that should never be new
on a host without a reason. For every host it records, in the baseline period
(everything before the test period), which of these it has shown:

    auth    event_type       an event type (e.g. SSH_INVALID_USER) the host never logged
            login_source     an address that never logged in successfully to this host
            login_account    an account that never logged in successfully to this host
    ossec   event_type       an agent event type the host never logged
    pf      event_type       a packet type the host's firewall never logged
            source_address   an address the host's firewall never saw as a source

Every (host, kind, value) first seen in the test period is one alert, carrying
its first lines. Alerts are ranked by how rare they are within the host's test
traffic (fewer occurrences rank higher), and Phase 7 turns the rank into the
probability (1.0 = rarest). The test period starts where the source's Phase 3
split starts it (validation_boundary_epoch); without that, at the last 15% of
the study period.

Outputs (data/phase4_detection/<source>/first_seen/):
    first_seen_pairs/test_scores.csv, test_raw_alert_evidence.csv, summary.json
    experiment_summary.csv
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from sources import ROOT, SOURCES, host_from_path  # noqa: E402

CHUNK = 500_000


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=["auth", "ossec", "pf"])
    parser.add_argument("--lines", type=int, default=20, help="Original lines kept per alert.")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.output = ROOT / "data" / "phase4_detection" / args.source / "first_seen"
    return args


log = runlog.log


def test_start(source):
    path = ROOT / "data" / "phase3_features" / source / "individual" / "metadata.json"
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
        split = meta.get("split_metadata", meta)
        epoch = split.get("validation_boundary_epoch")
        if epoch:
            return pd.Timestamp(datetime.fromtimestamp(float(epoch))), "Phase 3 split (individual view)"
    except (OSError, ValueError):
        pass
    days = pd.read_csv(ROOT / "data" / "phase2_observations" / source / f"{SOURCES[source]['prefix']}_host_days.csv",
                       usecols=["day"], parse_dates=["day"])["day"]
    start, end = days.min(), days.max()
    return start + (end - start) * 0.85, "last 15% of the study period"


def readers(source):
    """(files, columns, message column, function(chunk) -> frame with hostname, timestamp, kind, value, message)."""
    data = ROOT / "data"
    if source == "auth":
        files = sorted((data / "phase1_classify" / "auth").glob("classified_authlog_events_*.csv"))
        columns = ["timestamp", "hostname", "event_type", "source_ip", "username", "original_log_line"]

        def keys(chunk):
            base = chunk[["hostname", "timestamp", "original_log_line"]].rename(columns={"original_log_line": "message"})
            parts = [base.assign(kind="event_type", value=chunk["event_type"])]
            login = chunk["event_type"].eq("SSH_LOGIN_SUCCESS")
            parts.append(base[login].assign(kind="login_source", value=chunk.loc[login, "source_ip"]))
            parts.append(base[login].assign(kind="login_account", value=chunk.loc[login, "username"]))
            return pd.concat(parts, ignore_index=True)
        return files, columns, keys
    if source == "ossec":
        files = sorted((data / "phase1_classify" / "ossec").glob("ossec_events_*.csv"))
        columns = ["timestamp", "hostname", "event_type", "original_log_line"]

        def keys(chunk):
            return chunk.rename(columns={"original_log_line": "message"}).assign(kind="event_type",
                                                                                 value=chunk["event_type"])
        return files, columns, keys
    files = [data / "phase2_observations" / "pf" / "pflog_events_all_months.csv"]
    columns = ["timestamp", "event_type", "source_ip", "source_file", "raw_message"]

    def keys(chunk):
        chunk = chunk[~chunk["source_file"].fillna("").str.contains("_tmp")]
        base = chunk[["timestamp", "raw_message"]].rename(columns={"raw_message": "message"})
        base["hostname"] = host_from_path(chunk["source_file"])
        return pd.concat([base.assign(kind="event_type", value=chunk["event_type"]),
                          base.assign(kind="source_address", value=chunk["source_ip"])], ignore_index=True)
    return files, columns, keys


def stream(files, columns, keys):
    for path in files:
        header = pd.read_csv(path, nrows=0).columns
        use = [c for c in columns if c in header]
        for chunk in pd.read_csv(path, usecols=use, dtype=str, chunksize=CHUNK, keep_default_na=False):
            frame = keys(chunk)
            frame = frame[frame["value"].fillna("").str.strip().ne("") & frame["hostname"].fillna("").ne("")]
            frame["when"] = pd.to_datetime(frame["timestamp"].str[:19].str.replace("/", "-"), errors="coerce")
            yield frame.dropna(subset=["when"])


def main():
    args = parse_args()
    spec = SOURCES[args.source]
    start, basis = test_start(args.source)
    files, columns, keys = readers(args.source)
    log(f"{spec['label']} first-seen: test period from {start:%Y-%m-%d %H:%M} ({basis}); reading {len(files)} files",
        args.quiet)
    seen = set()
    test = defaultdict(lambda: {"count": 0, "first": None, "last": None, "lines": []})
    test_rows_per_host = defaultdict(int)
    for frame in stream(files, columns, keys):
        before = frame["when"] < start
        seen.update(zip(frame.loc[before, "hostname"], frame.loc[before, "kind"], frame.loc[before, "value"]))
        later = frame[~before]
        if len(later):
            events = later[later["kind"].eq("event_type")]
            for host, count in events["hostname"].value_counts().items():
                test_rows_per_host[host] += int(count)
            for (host, kind, value), part in later.groupby(["hostname", "kind", "value"], sort=False):
                entry = test[(host, kind, value)]
                entry["count"] += len(part)
                first, last = part["when"].min(), part["when"].max()
                entry["first"] = first if entry["first"] is None else min(entry["first"], first)
                entry["last"] = last if entry["last"] is None else max(entry["last"], last)
                if len(entry["lines"]) < args.lines:
                    ordered = part.sort_values("when")
                    entry["lines"] += list(zip(ordered["when"], ordered["message"]))[:args.lines - len(entry["lines"])]
    new = {key: entry for key, entry in test.items() if key not in seen}
    hosts_seen = {host for host, _, _ in seen}
    rows, evidence = [], []
    for (host, kind, value), entry in new.items():
        row_id = hashlib.sha256(f"first_seen|{args.source}|{host}|{kind}|{value}".encode()).hexdigest()[:24]
        share = entry["count"] / max(test_rows_per_host.get(host, entry["count"]), 1)
        rows.append({"row_manifest_id": row_id, "hostname": host, "kind": kind, "value": value,
                     "occurrences": entry["count"], "first_seen": str(entry["first"]), "last_seen": str(entry["last"]),
                     "host_new_in_test": host not in hosts_seen, "share_of_host_test_events": round(share, 6),
                     "first_seen_score": round(float(-np.log10(max(share, 1e-12))), 4),
                     "first_seen_alert": True, "detector_combination": "first_seen"})
        note = (f"[first seen] {host}: {kind.replace('_', ' ')} '{value}' never appeared on this host before "
                f"{start:%Y-%m-%d}; {entry['count']:,} occurrence{'s' if entry['count'] != 1 else ''} from "
                f"{entry['first']:%Y-%m-%d %H:%M} to {entry['last']:%Y-%m-%d %H:%M}"
                + (f"; the first {len(entry['lines'])} follow" if entry["count"] > 1 else "") + ".")
        evidence.append((row_id, 0, note))
        for position, (_, message) in enumerate(sorted(entry["lines"]), start=1):
            evidence.append((row_id, position, message))
    columns_out = ["row_manifest_id", "hostname", "kind", "value", "occurrences", "first_seen", "last_seen",
                   "host_new_in_test", "share_of_host_test_events", "first_seen_score", "first_seen_alert",
                   "detector_combination"]
    scores = pd.DataFrame(rows, columns=columns_out).sort_values("first_seen_score", ascending=False)
    folder = args.output / "first_seen_pairs"
    folder.mkdir(parents=True, exist_ok=True)
    scores.to_csv(folder / "test_scores.csv", index=False)
    pd.DataFrame(evidence, columns=["row_manifest_id", "event_position", spec["message_column"]]).to_csv(
        folder / "test_raw_alert_evidence.csv", index=False)
    summary = {"dataset": "first_seen_pairs", "layer": "first_seen", "probability_rule": "rank_within_alerts",
               "generated_at": datetime.now().isoformat(timespec="seconds"), "test_start": str(start),
               "test_start_basis": basis, "baseline_pairs": len(seen), "test_pairs": len(test),
               "test_first_seen_alerts": len(scores),
               "by_kind": {k: int(v) for k, v in scores["kind"].value_counts().items()},
               "hosts_with_alerts": int(scores["hostname"].nunique())}
    (folder / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    pd.DataFrame([{k: v for k, v in summary.items() if not isinstance(v, dict)}]).to_csv(
        args.output / "experiment_summary.csv", index=False)
    log(f"{spec['label']} first-seen: {len(seen):,} (host, kind, value) pairs in the baseline; {len(test):,} in the "
        f"test period, {len(scores):,} of them new: {summary['by_kind']}", args.quiet)
    if len(scores):                                      # the values themselves stay in the output: counts only here
        log(f"First-seen alerts on {summary['hosts_with_alerts']:,} servers; each value is in {folder}", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
