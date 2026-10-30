"""Phase 7c: what the other logs know about every address in this source's alerts.

  python pipeline/phase7_alerts/context.py --source auth
  python pipeline/phase7_alerts/context.py --source pf --top 300 --no-report

An alert shows a few lines from one log. Whether an address is an admin
workstation, a monitoring server or something nobody recognises usually shows
in the OTHER logs. This step takes every IPv4 address in the source's Phase 7
alert files and profiles it across the whole study period:

    auth       SSH logins from it: successful and failed, accounts, servers, days active
    PF         lines naming it in the PF firewall logs (study files only), ports it was blocked on
    IPFilter   lines naming it in mm06moc's IPFilter log
    OSSEC      OSSEC lines naming it, and the server name OSSEC gives it (e.g. per1kco/172.16.10.41)
    site       whether it is on the approved-automation list, and whether it is a private address

The auth profile reads 26 million lines, so it is cached in
data/phase7_alerts/_shared/auth_address_profile.csv and rebuilt only when the
auth Phase 1 output is newer.

Output: data/phase7_alerts/<source>/<prefix>_cross_source_context.csv, the
--top addresses by number of alerts naming them. Like Phase 7b, this step then
rebuilds the source's Phase 6 report (skip with --no-report), so the report
always shows the current context.
"""
from __future__ import annotations

import argparse
import csv
import glob
import ipaddress
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from sources import ROOT, SOURCES  # noqa: E402
from profiles import auth_profile, firewall_profile, ossec_profile  # noqa: E402

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
NAMED = re.compile(r"\b([A-Za-z][\w-]{2,})/(\d{1,3}(?:\.\d{1,3}){3})\b")
SHARED = ROOT / "data" / "phase7_alerts" / "_shared"
APPROVED = ROOT / "pipeline" / "phase9_llm_triage" / "site" / "approved_automation_ips.csv"
IGNORED = {"0.0.0.0", "255.255.255.255"}
CHUNK = 1_000_000


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=["auth", "ossec", "pf"])
    parser.add_argument("--top", type=int, default=150)
    parser.add_argument("--no-report", action="store_true")
    runlog.add_arguments(parser)
    return parser.parse_args()


log = runlog.log


def valid(address):
    try:
        ipaddress.ip_address(address)
        return address not in IGNORED
    except ValueError:
        return False


def alert_addresses(source):
    """{address: (alerts naming it, set of alert files)} from the source's Phase 7 CSVs."""
    csv.field_size_limit(2 ** 31 - 1)
    counts, files = Counter(), defaultdict(set)
    prefix = SOURCES[source]["prefix"]
    for path in sorted(glob.glob(str(ROOT / "data" / "phase7_alerts" / source / f"{prefix}_cumulative_*_alerts.csv"))):
        kind = re.search(r"_cumulative_(.+?)_alerts", Path(path).name).group(1)
        with open(path, encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                found = {a for a in IPV4.findall(row.get("raw_messages") or "") if valid(a)}
                counts.update(found)
                for address in found:
                    files[address].add(kind)
    return counts, files


def approved_networks():
    networks = []
    if APPROVED.is_file():
        for row in csv.DictReader(open(APPROVED, encoding="utf-8-sig", newline="")):
            try:
                networks.append(ipaddress.ip_network((row.get("address") or "").strip(), strict=False))
            except ValueError:
                pass
    return networks


def main():
    args = parse_args()
    spec = SOURCES[args.source]
    counts, files = alert_addresses(args.source)
    if not counts:
        log("No addresses in the Phase 7 alerts; nothing to profile", args.quiet)
    chosen = [address for address, _ in counts.most_common(args.top)]
    auth = auth_profile(args.quiet)
    pf = firewall_profile(ROOT / "data" / "phase2_observations" / "pf" / "pflog_events_all_months.csv",
                          source_file_column="source_file")
    ipf = firewall_profile(ROOT / "data" / "phase2_observations" / "ipf" / "ipflog_events_all_months.csv",
                           host_column="hostname")
    names, ossec_mentions = ossec_profile()
    approved = approved_networks()
    rows = []
    for address in chosen:
        ip = ipaddress.ip_address(address)
        row = {"address": address, "alerts_naming_it": counts[address], "alert_files": ", ".join(sorted(files[address])),
               "known_as": names.get(address, ""), "private_address": ip.is_private,
               "approved_automation": any(ip in network for network in approved)}
        if address in auth.index:
            a = auth.loc[address]
            row.update({k: a[k] for k in auth.columns if pd.notna(a[k])})
        for label, table in (("pf", pf), ("ipf", ipf)):
            if len(table) and address in table.index:
                t = table.loc[address]
                row.update({f"{label}_lines": int(t["lines"]), f"{label}_roles": t["roles"], f"{label}_months": t["months"],
                            f"{label}_ports": t["ports"], f"{label}_hosts": t["hosts"]})
        row["ossec_lines_naming_it"] = ossec_mentions.get(address, 0)
        rows.append(row)
    out = pd.DataFrame(rows)
    target = ROOT / "data" / "phase7_alerts" / args.source / f"{spec['prefix']}_cross_source_context.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(target, index=False)
    unknown = int(((out.get("auth_logins_from", pd.Series(dtype=float)).fillna(0) == 0)
                   & (out.get("pf_lines", pd.Series(dtype=float)).fillna(0) == 0)
                   & (out["known_as"] == "")).sum()) if len(out) else 0
    log(f"{spec['label']} context: {len(counts):,} addresses in the alerts; profiled the top {len(out):,}; "
        f"{int((~out['private_address']).sum()) if len(out) else 0} public, {unknown} not seen in auth or PF and "
        f"unnamed by OSSEC -> {target.relative_to(ROOT)}", args.quiet)
    if not args.no_report:
        report = ROOT / "pipeline" / "phase6_report" / f"{args.source}.py"
        log(f"Rebuilding the Phase 6 report so it shows this context ({report.name})", args.quiet)
        subprocess.run([sys.executable, str(report)] + (["--quiet"] if args.quiet else []), cwd=ROOT, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
