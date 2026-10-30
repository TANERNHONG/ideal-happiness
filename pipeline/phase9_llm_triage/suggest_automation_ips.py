"""Suggest candidate approved-automation addresses from the Phase 1 auth logs.

  python pipeline/phase9_llm_triage/suggest_automation_ips.py
  python pipeline/phase9_llm_triage/suggest_automation_ips.py --months 2026-03 2026-04

Automation tends to log in often, on most days, at steady hours, with keys, as
few accounts, and almost never fails. This profiles every source address and
writes data/phase9_llm_triage/automation_ip_candidates.csv, ranked. It proposes
only: confirm each address with its owner before adding it to
site/approved_automation_ips.csv.
"""
from __future__ import annotations

import argparse
import sys
import glob
import math
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

COLUMNS = ["timestamp", "hostname", "event_type", "username", "source_ip", "authentication_method"]
FAILURE_WORDS = ("FAIL", "INVALID", "DENIED", "EXCEED", "LOCK", "REFUSED")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", default="data/phase1_classify/auth/classified_authlog_events_*.csv")
    parser.add_argument("--months", nargs="*", help="only these YYYY-MM partitions")
    parser.add_argument("--output", type=Path, default=Path("data/phase9_llm_triage/automation_ip_candidates.csv"))
    parser.add_argument("--min-logins", type=int, default=100)
    runlog.add_arguments(parser)
    return parser.parse_args()


def main():
    args = parse_args()
    paths = sorted(glob.glob(args.events))
    if args.months:
        paths = [path for path in paths if any(month in Path(path).name for month in args.months)]
    if not paths:
        raise SystemExit(f"No files match {args.events}")
    stats = defaultdict(lambda: {"success": 0, "failure": 0, "events": 0, "key": 0, "users": Counter(),
                                 "hosts": set(), "days": set(), "hours": Counter()})
    all_days = set()
    for path in paths:
        runlog.log(f"Reading {Path(path).name}")
        for chunk in pd.read_csv(path, usecols=COLUMNS, dtype=str, chunksize=1_000_000, low_memory=False):
            chunk = chunk[chunk["source_ip"].notna() & chunk["source_ip"].str.strip().ne("")]
            day = chunk["timestamp"].str.slice(0, 10)
            hour = chunk["timestamp"].str.slice(11, 13)
            all_days.update(day.dropna().unique())
            event = chunk["event_type"].fillna("")
            success = event.eq("SSH_LOGIN_SUCCESS")
            failure = event.str.contains("|".join(FAILURE_WORDS), regex=True)
            key = success & chunk["authentication_method"].fillna("").str.lower().str.contains("publickey")
            frame = pd.DataFrame({"ip": chunk["source_ip"], "success": success, "failure": failure, "key": key,
                                  "user": chunk["username"], "host": chunk["hostname"], "day": day, "hour": hour})
            for ip, part in frame.groupby("ip"):
                entry = stats[ip]
                entry["events"] += len(part)
                entry["success"] += int(part["success"].sum())
                entry["failure"] += int(part["failure"].sum())
                entry["key"] += int(part["key"].sum())
                entry["users"].update(part.loc[part["success"], "user"].dropna())
                entry["hosts"].update(part["host"].dropna())
                entry["days"].update(part["day"].dropna())
                entry["hours"].update(part.loc[part["success"], "hour"].dropna())
    rows = []
    for ip, entry in stats.items():
        if entry["success"] < args.min_logins:
            continue
        hours = entry["hours"]
        total = sum(hours.values()) or 1
        entropy = -sum(count / total * math.log2(count / total) for count in hours.values())
        failure_rate = entry["failure"] / max(entry["success"] + entry["failure"], 1)
        key_share = entry["key"] / max(entry["success"], 1)
        day_share = len(entry["days"]) / max(len(all_days), 1)
        reasons = []
        if key_share >= 0.95:
            reasons.append("key-based")
        if failure_rate <= 0.01:
            reasons.append("almost no failures")
        if day_share >= 0.5:
            reasons.append("active on most days")
        if len(entry["users"]) <= 3:
            reasons.append("few accounts")
        rows.append({
            "address": ip, "automation_signs": len(reasons), "signs": ", ".join(reasons),
            "successful_logins": entry["success"], "failures": entry["failure"],
            "failure_rate": round(failure_rate, 4), "key_share": round(key_share, 3),
            "days_active": len(entry["days"]), "day_share": round(day_share, 3),
            "accounts": "; ".join(user for user, _ in entry["users"].most_common(5)),
            "account_count": len(entry["users"]), "servers": len(entry["hosts"]),
            "hour_entropy_bits": round(entropy, 2), "busiest_hours": ", ".join(h for h, _ in hours.most_common(3)),
            "confirm_with_owner": "",
        })
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise SystemExit("No address reached --min-logins")
    frame = frame.sort_values(["automation_signs", "successful_logins"], ascending=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output, index=False)
    runlog.log(f"{len(frame):,} addresses profiled; {int((frame['automation_signs'] == 4).sum()):,} show all four "
               f"automation signs -> {args.output}")


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
