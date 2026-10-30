"""Phase 2c: log coverage per host and day, with silence confirmed by the other logs.

  python pipeline/phase2_observations/coverage.py --source auth
  python pipeline/phase2_observations/coverage.py --source ossec
  python pipeline/phase2_observations/coverage.py --source pf

The Phase 2 views only have a row where a host logged something, so a host
that goes quiet leaves no row, and no detector can see it. This step builds the
full calendar: one row per host per day of the study period, with
    file_status    present / empty / missing: the host's file for that month in the archive
    lines          lines the host logged that day in this source
    witness_lines  lines from the OTHER logs that day (auth for OSSEC, OSSEC for
                   auth, both for PF), which show the host was up
    status         active          the host logged that day
                   quiet           no lines, but the file was collected and the host was up
                   collection_gap  no lines, the host was up, and the month's file is empty or missing
                   unknown         no lines and no other log shows the host up: we cannot tell
                   no_log          the host never has a file for this source (mm06moc runs
                                   IPFilter, not PF)
For a firewall (PF), an empty monthly file usually means nothing was blocked,
which is normal, so an empty file on a day the host was up counts as 'quiet'.
For auth and OSSEC, which log every day in normal operation, it counts as a
'collection_gap'. A missing file is a collection gap for every source.
Silence counts as real (certified) only for 'quiet'. 'collection_gap' days are a
data-quality finding: the host was running, but this log has nothing for it.

Outputs (data/phase2_observations/<source>/):
    <prefix>_host_days.csv         the calendar
    <prefix>_coverage_summary.json per host: days by status, months by file status, longest runs
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from sources import ROOT, SOURCES, WITNESSES, archive_inventory, host_day_counts, study_days  # noqa: E402

STATUSES = ("active", "quiet", "collection_gap", "unknown", "no_log")
# Does an EMPTY monthly file mean "nothing happened" (firewalls) or "nothing was collected"?
EMPTY_FILE_IS_QUIET = {"auth": False, "ossec": False, "pf": True}


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=["auth", "ossec", "pf"])
    parser.add_argument("--output", type=Path)
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.output = args.output or ROOT / "data" / "phase2_observations" / args.source
    return args


log = runlog.log


def runs(frame, status):
    """Longest consecutive runs of one status per host: [(host, first, last, days)]."""
    found = []
    for host, part in frame[frame["status"].eq(status)].groupby("hostname"):
        days = part["day"].sort_values()
        for _, run in days.groupby((days.diff().dt.days != 1).cumsum()):
            found.append((host, str(run.min().date()), str(run.max().date()), len(run)))
    return sorted(found, key=lambda item: -item[3])


def build(source, quiet=False):
    spec = SOURCES[source]
    inventory = archive_inventory()
    days = study_days(inventory)
    mine = inventory[inventory["kind"].eq(spec["kind"]) & ~inventory["tmp"]]
    files = mine.groupby(["hostname", "partition_month"])["bytes"].sum()
    hosts = sorted(set(inventory.loc[~inventory["tmp"], "hostname"]))
    grid = pd.MultiIndex.from_product([hosts, days], names=["hostname", "day"]).to_frame(index=False)
    grid["partition_month"] = grid["day"].dt.strftime("%Y-%m")
    keys = pd.MultiIndex.from_frame(grid[["hostname", "partition_month"]])
    grid["file_bytes"] = files.reindex(keys).to_numpy()
    grid["file_status"] = np.where(grid["file_bytes"].isna(), "missing",
                                   np.where(grid["file_bytes"].fillna(0) > 0, "present", "empty"))
    grid["file_bytes"] = grid["file_bytes"].fillna(0).astype(int)
    counts = host_day_counts(source).rename(columns={"lines": "lines"})
    grid = grid.merge(counts, on=["hostname", "day"], how="left")
    grid["lines"] = grid["lines"].fillna(0).astype(int)
    grid["witness_lines"] = 0
    used = []
    for witness in WITNESSES[source]:
        try:
            other = host_day_counts(witness).rename(columns={"lines": f"{witness}_lines"})
        except FileNotFoundError:
            log(f"WARNING: {witness} Phase 2 output missing; it cannot confirm hosts were up", quiet)
            continue
        grid = grid.merge(other, on=["hostname", "day"], how="left")
        grid[f"{witness}_lines"] = grid[f"{witness}_lines"].fillna(0).astype(int)
        grid["witness_lines"] += grid[f"{witness}_lines"]
        used.append(witness)
    grid["witness_sources"] = "+".join(used)
    alive = grid["witness_lines"].gt(0)
    collected = grid["file_status"].eq("present") | (grid["file_status"].eq("empty") & EMPTY_FILE_IS_QUIET[source])
    has_log = grid["hostname"].isin(set(mine["hostname"]))
    grid["status"] = np.select(
        [~has_log, grid["lines"].gt(0), alive & collected, alive],
        ["no_log", "active", "quiet", "collection_gap"], default="unknown")
    grid["host_alive"] = grid["lines"].gt(0) | alive
    grid["certified"] = grid["status"].isin(["active", "quiet"])
    grid["empty_file_is_quiet"] = EMPTY_FILE_IS_QUIET[source]
    return grid, inventory, used


def summarise(grid, used):
    hosts = {}
    for host, part in grid.groupby("hostname"):
        months = part.drop_duplicates("partition_month")["file_status"].value_counts().to_dict()
        hosts[host] = {"days": {status: int(part["status"].eq(status).sum()) for status in STATUSES},
                       "months_by_file_status": {k: int(v) for k, v in months.items()},
                       "median_lines_on_active_days": float(part.loc[part["lines"] > 0, "lines"].median() or 0)}
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "study_period": [str(grid["day"].min().date()), str(grid["day"].max().date())],
        "hosts": len(hosts), "host_days": len(grid), "witnesses": used,
        "days_by_status": {status: int(grid["status"].eq(status).sum()) for status in STATUSES},
        "longest_collection_gaps": runs(grid, "collection_gap")[:10],
        "longest_unknown_runs": runs(grid, "unknown")[:10],
        "per_host": hosts,
    }


def main():
    args = parse_args()
    prefix = SOURCES[args.source]["prefix"]
    grid, _, used = build(args.source, args.quiet)
    args.output.mkdir(parents=True, exist_ok=True)
    grid.to_csv(args.output / f"{prefix}_host_days.csv", index=False)
    summary = summarise(grid, used)
    (args.output / f"{prefix}_coverage_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    log(f"{SOURCES[args.source]['label']} coverage: {summary['hosts']} hosts x {len(grid) // max(summary['hosts'], 1)} days; "
        f"{summary['days_by_status']}; witnesses {used}", args.quiet)
    gaps = summary["longest_collection_gaps"][:5]
    if gaps:                                             # servers and dates stay in the summary file: counts only here
        log(f"Longest collection gaps: {', '.join(str(length) for *_, length in gaps)} days; servers and dates in "
            f"{prefix}_coverage_summary.json", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
