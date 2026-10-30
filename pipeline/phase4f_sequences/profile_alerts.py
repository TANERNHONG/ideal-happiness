"""Phase 4f: association rules that profile each detector's test alerts (what drives alert volume).

  .venv/Scripts/python.exe pipeline/phase4f_sequences/profile_alerts.py --source auth

For every test-period session (AUTH) or episode (OSSEC), a transaction of coarse items:

    host=mm04kco  family=mm  hour=00-06  day=weekend  has=SSH_LOGIN_FAILED  steps=4-6
    ended=terminal  duplicated_lines  user=named  source=private

(no raw usernames or addresses: classes only). For each detector (robust, Isolation Forest, novelty,
model-zoo consensus, sequence), FP-growth (mlxtend) finds the item combinations common among its
alerts (at least 5% of them, up to 3 items); each is then counted over all test observations, giving

    alert rate with the items (confidence)   and   lift = that rate / the detector's overall rate.

A combination is kept when its lift is at least 2 and clearly above that of any combination it
contains (so "host=mm04kco & has=SSH_LOGIN_SUCCESS" appears only if it says more than host=mm04kco),
and only once among combinations that pick out exactly the same observations (the shortest is kept,
e.g. "scan started" and "scan ended" on a host where scans always finish).
High lift with high coverage answers "where do this detector's alerts pile up?", for example whether
the model zoo's alerts on the mm servers follow the servers or something they do.

Writes data/phase4f_sequences/<source>/alert_profile/alert_profile.csv and alert_profile.md.
Read-only for every input; uses the sequence store (streams.py) for event types and times.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import time
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from mlxtend.frequent_patterns import fpgrowth

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DETECTION_OUTPUT, OUTPUT, SOURCES, load_sequences, open_store, write_json  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

MIN_COVERAGE = 0.05
MAX_ITEMS = 3
MIN_LIFT = 2.0
LIFT_GAIN = 1.1
MIN_ALERTS = 10
SHOWN = 12


log = runlog.log


def family(host):
    match = re.match(r"[a-z]+(?=\d)", str(host))
    return match.group(0) if match else str(host)


def hour_band(hour):
    return f"{hour // 6 * 6:02d}-{hour // 6 * 6 + 6:02d}"


def steps_band(count):
    return "1" if count <= 1 else "2-3" if count <= 3 else "4-6" if count <= 6 else "7+"


def source_class(value):
    text = str(value or "").strip()
    if not text or text.lower() == "nan":
        return "none"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "other"
    return "loopback" if address.is_loopback else "private" if address.is_private else "public"


def detector_alerts(source, dataset, ids):
    """{detector name: boolean array over ``ids``} from the Phase 4 and 4f test outputs."""
    position = pd.Series(np.arange(len(ids)), index=ids)
    found = {}

    def mark(name, alerted):
        flags = np.zeros(len(ids), dtype=bool)
        hit = position.reindex(pd.Index(alerted).astype(str)).dropna().astype(int).to_numpy()
        flags[hit] = True
        if flags.sum() >= MIN_ALERTS:
            found[name] = flags

    root = DETECTION_OUTPUT / source
    path = root / "detectors" / dataset / "test_scores.csv"
    if path.is_file():
        frame = pd.read_csv(path, usecols=lambda c: c in {"row_manifest_id", "robust_alert", "isolation_alert", "novelty_alert"},
                            dtype={"row_manifest_id": str})
        for column, name in (("robust_alert", "Robust deviation"), ("isolation_alert", "Isolation Forest"), ("novelty_alert", "Novelty")):
            if column in frame:
                mark(name, frame.loc[frame[column].astype(str).str.lower().isin({"true", "1"}), "row_manifest_id"])
    zoo = set()
    for path in sorted((root / "model_zoo" / dataset).glob("*/consensus_alerts_min*.csv")):
        zoo |= set(pd.read_csv(path, usecols=["row_manifest_id"], dtype=str)["row_manifest_id"])
    if zoo:
        mark("Model-zoo consensus", sorted(zoo))
    path = root / "sequences" / dataset / "test_scores.csv"
    if path.is_file():
        frame = pd.read_csv(path, usecols=["row_manifest_id", "sequence_alert"], dtype={"row_manifest_id": str})
        mark("Sequence", frame.loc[frame["sequence_alert"].astype(str).str.lower().isin({"true", "1"}), "row_manifest_id"])
    return found


def transactions(source):
    """(ids, item names, boolean item matrix as a dict of columns) for the test observations."""
    spec = SOURCES[source]
    connection = open_store(source)
    sequences = load_sequences(connection)
    units = pd.read_sql_query("SELECT row_manifest_id, host_id, start_epoch, close_reason, merged_copies, sequence_id, token_count "
                              "FROM units WHERE split='test'", connection)
    connection.close()
    extra = pd.read_csv(spec["features"] / "test_rows.csv", usecols=lambda c: c in {"row_manifest_id", "username", "source_ip"},
                        dtype=str)
    units = units.merge(extra, on="row_manifest_id", how="left")
    times = pd.to_datetime(units["start_epoch"], unit="s", utc=True)
    columns = {}

    def add(name, mask):
        mask = np.asarray(mask, dtype=bool)
        if mask.any():
            columns[name] = mask

    for value in sorted(units["host_id"].astype(str).unique()):
        add(f"host={value}", units["host_id"].astype(str).eq(value))
    families = units["host_id"].astype(str).map(family)
    for value in sorted(families.unique()):
        if (units["host_id"].astype(str) != value).any() and families.eq(value).sum() > units["host_id"].astype(str).eq(value).sum():
            add(f"family={value}", families.eq(value))
    hours = times.dt.hour.map(hour_band)
    for value in sorted(hours.unique()):
        add(f"hour={value}", hours.eq(value))
    add("day=weekend", times.dt.dayofweek >= 5)
    add("day=weekday", times.dt.dayofweek < 5)
    bands = units["token_count"].map(steps_band)
    for value in ("1", "2-3", "4-6", "7+"):
        add(f"steps={value}", bands.eq(value))
    for value in sorted(units["close_reason"].astype(str).unique()):
        add(f"ended={value}", units["close_reason"].astype(str).eq(value))
    add("duplicated_lines", units["merged_copies"] > 0)
    if "username" in units:
        named = units["username"].fillna("").str.strip().replace("nan", "").ne("")
        add("user=named", named)
        add("user=none", ~named)
    if "source_ip" in units:
        classes = units["source_ip"].map(source_class)
        for value in sorted(classes.unique()):
            add(f"source={value}", classes.eq(value))
    present = {}
    for sid in units["sequence_id"].unique():
        for token in set(sequences[sid]):
            present.setdefault(token, set()).add(sid)
    for token in sorted(present):
        add(f"has={token}", units["sequence_id"].isin(present[token]))
    return units["row_manifest_id"].astype(str).to_numpy(), columns


def profile(name, flags, columns):
    total, alerts = len(flags), int(flags.sum())
    base = alerts / total
    frame = pd.DataFrame({item: mask[flags] for item, mask in columns.items()})
    frame = frame.loc[:, frame.any(axis=0)]
    itemsets = fpgrowth(frame, min_support=MIN_COVERAGE, use_colnames=True, max_len=MAX_ITEMS)
    lifts, rows, signatures = {}, [], set()
    for items, support in sorted(zip(itemsets["itemsets"], itemsets["support"]), key=lambda pair: len(pair[0])):
        items = frozenset(items)
        mask = np.logical_and.reduce([columns[item] for item in items])
        with_items = int(mask.sum())
        hit = int((mask & flags).sum())
        rate = hit / with_items if with_items else 0.0
        lift = rate / base if base else 0.0
        lifts[items] = lift
        best_part = max((lifts.get(frozenset(part), 0.0) for k in range(1, len(items)) for part in combinations(items, k)), default=0.0)
        signature = hash(np.packbits(mask).tobytes())
        if lift >= MIN_LIFT and lift >= LIFT_GAIN * best_part and signature not in signatures:
            signatures.add(signature)
            rows.append({"detector": name, "items": " & ".join(sorted(items)), "alerts_with_items": hit,
                         "share_of_alerts": round(hit / alerts, 4), "observations_with_items": with_items,
                         "alert_rate_with_items": round(rate, 6), "alert_rate_overall": round(base, 6), "lift": round(lift, 2)})
    return rows, alerts, base


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(SOURCES))
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    started = time.perf_counter()
    dataset = SOURCES[args.source]["dataset"]
    ids, columns = transactions(args.source)
    log(f"{args.source.upper()} {dataset}: {len(ids):,} test observations, {len(columns)} items")
    alerts = detector_alerts(args.source, dataset, ids)
    output = OUTPUT / args.source / "alert_profile"
    output.mkdir(parents=True, exist_ok=True)
    rows, overview = [], []
    for name, flags in alerts.items():
        found, count, base = profile(name, flags, columns)
        found.sort(key=lambda row: (-row["share_of_alerts"] * min(row["lift"], 50), -row["lift"]))
        rows += found
        overview.append({"detector": name, "alerts": count, "rate": base, "combinations": len(found)})
        log(f"{name}: {count:,} alerts ({base:.3%}), {len(found)} combinations with lift >= {MIN_LIFT}")
    table = pd.DataFrame(rows)
    table.to_csv(output / "alert_profile.csv", index=False)
    lines = [f"# Where the {args.source.upper()} {dataset.replace('_', ' ')} alerts pile up", "",
             f"Test period, {len(ids):,} observations. For each detector: item combinations found in at least "
             f"{MIN_COVERAGE:.0%} of its alerts, with lift >= {MIN_LIFT} (alert rate with the items / overall rate). "
             "Sorted by how many alerts they cover, weighted by lift.", ""]
    for item in overview:
        lines += [f"## {item['detector']}: {item['alerts']:,} alerts ({item['rate']:.3%} of observations)", "",
                  "| Items | Share of alerts | Alert rate with items | Lift |", "|---|---:|---:|---:|"]
        part = table[table["detector"].eq(item["detector"])].head(SHOWN) if len(table) else table
        for _, row in part.iterrows():
            lines.append(f"| {row['items']} | {row['share_of_alerts']:.1%} | {row['alert_rate_with_items']:.2%} | {row['lift']:.1f} |")
        if part.empty:
            lines.append("| (no combination reaches the lift) | | | |")
        lines.append("")
    (output / "alert_profile.md").write_text("\n".join(lines), encoding="utf-8")
    write_json(output / "summary.json", {"source": args.source, "dataset": dataset, "test_observations": len(ids),
                                         "items": len(columns), "detectors": overview,
                                         "parameters": {"min_coverage": MIN_COVERAGE, "max_items": MAX_ITEMS, "min_lift": MIN_LIFT,
                                                        "lift_gain": LIFT_GAIN, "min_alerts": MIN_ALERTS},
                                         "seconds": round(time.perf_counter() - started, 1)})
    log(f"Wrote {len(table):,} rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
