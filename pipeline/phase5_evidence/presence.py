"""Phase 5 of the presence method: trace every alert to its lines, and gather context from the other logs.

  python pipeline/phase5_evidence/presence.py --source ipf
  python pipeline/phase5_evidence/presence.py --source pf

Used for the logs that are empty, or nearly, in normal operation (IPFilter, PF).
File names below start with the source prefix (ipflog_, pflog_).

1. Evidence. For every alert going to Phase 7 (active host-days and flow
   episodes), the observation is followed independently through the Phase 2
   lineage to the Phase 1 lookup, and the count of resolved lines is checked
   against the observation's own line count. Outputs, as for the other sources:
       <prefix>_isolation_forest_outlier_export_summary.csv   per view: alerts, complete, partial, missing
       <prefix>_alert_message_chains.csv                      one row per alert: time span, lines, first lines
       <prefix>_review_queue.csv                              the same with an empty review_label column

2. Cross-source context. An empty baseline gives the models nothing to compare
   with, so the analyst needs context from elsewhere. For every address and
   service port in the active lines (<prefix>_cross_source_context.csv):
       firewall  how often it appears in the OTHER firewall log (PF for IPFilter,
                 IPFilter for PF), and when
       auth      SSH logins from the address over the study period (accounts, servers),
                 from the cached profile shared with Phase 7c
       OSSEC     the server name OSSEC gives the address, and OSSEC lines naming it
   plus <prefix>_host_liveness_by_month.csv from the Phase 2 certification table.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from sources import ROOT  # noqa: E402
from profiles import auth_profile, firewall_profile, ossec_profile  # noqa: E402

CONFIG = {"ipf": {"prefix": "ipflog", "label": "IPFilter"}, "pf": {"prefix": "pflog", "label": "PF"}}
OTHER_FIREWALL = {"ipf": "pf", "pf": "ipf"}
PREVIEW_LINES = 6


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(CONFIG))
    parser.add_argument("--no-auth-context", action="store_true", help="Skip the auth profile (built once, then cached).")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.prefix = CONFIG[args.source]["prefix"]
    args.detectors = ROOT / "data" / "phase4_detection" / args.source / "detectors"
    args.observations = ROOT / "data" / "phase2_observations" / args.source
    args.lookup = ROOT / "data" / "phase1_classify" / args.source / f"{args.prefix}_event_lookup.csv"
    args.output = ROOT / "data" / "phase5_evidence" / args.source
    args.views = {"slots_1d": f"{args.prefix}_slots_1d", "flow_episodes": f"{args.prefix}_flow_episodes"}
    return args


log = runlog.log


def evidence(args, lookup):
    summary_rows, chains = [], []
    for view, file_stem in args.views.items():
        scores = pd.read_csv(args.detectors / view / "test_scores.csv", dtype={"row_manifest_id": str})
        alerts = scores[scores["presence_alert"].astype(str).eq("True")].copy()
        observations = pd.read_csv(args.observations / f"{file_stem}.csv", dtype={"row_manifest_id": str})
        expected = observations.set_index("row_manifest_id")["lines"].astype(int)
        lineage = pd.read_csv(args.observations / f"{file_stem}_lineage.csv", dtype=str)
        lineage = lineage[lineage["row_manifest_id"].isin(alerts["row_manifest_id"])]
        resolved = lineage.merge(lookup, on="event_id", how="left")
        resolved["event_position"] = pd.to_numeric(resolved["event_position"])
        resolved = resolved.sort_values(["row_manifest_id", "event_position"])
        by_id = alerts.set_index("row_manifest_id")
        status = {}
        for row_id, part in resolved.groupby("row_manifest_id"):
            found = int(part["raw_message"].notna().sum())
            want = int(expected.get(row_id, -1))
            status[row_id] = "complete" if found == want else ("partial" if found else "missing")
            messages = part["raw_message"].dropna().tolist()
            score_row = by_id.loc[row_id]
            chains.append({
                "dataset": view, "row_manifest_id": row_id, "hostname": score_row.get("hostname", ""),
                "first_timestamp": part["event_timestamp"].min(), "last_timestamp": part["event_timestamp"].max(),
                "lines": found, "expected_lines": want, "evidence_status": status[row_id],
                "flagged_by": score_row["detector_combination"],
                "within_activity_rank": score_row.get("within_activity_rank", ""),
                "distinct_flows": part["source_ip"].str.cat(part["destination_ip"], sep=">").nunique(),
                "first_lines": " | ".join(messages[:PREVIEW_LINES]), "last_line": messages[-1] if messages else "",
            })
        for row_id in set(alerts["row_manifest_id"]) - set(status):
            status[row_id] = "missing"
        values = pd.Series(status, dtype=str)
        summary_rows.append({"run_key": view, "dataset": view, "isolation_alerts": len(alerts),
                             "complete_evidence_alerts": int(values.eq("complete").sum()),
                             "partial_evidence_alerts": int(values.eq("partial").sum()),
                             "missing_evidence_alerts": int(values.eq("missing").sum()),
                             "source_event_rows": int(resolved["raw_message"].notna().sum())})
        log(f"{view}: {len(alerts)} alerts, {int(values.eq('complete').sum())} with complete evidence", args.quiet)
    return pd.DataFrame(summary_rows), pd.DataFrame(chains)


def cross_source(args, events, days):
    addresses = sorted((set(events["client_ip"]) | set(events["server_ip"])) - {""})
    ports = sorted(set(events["service_port"]) - {""})
    other = OTHER_FIREWALL[args.source]
    other_path = ROOT / "data" / "phase2_observations" / other / f"{CONFIG[other]['prefix']}_events_all_months.csv"
    firewall = firewall_profile(other_path, host_column="hostname", source_file_column=None)
    auth = pd.DataFrame() if args.no_auth_context else auth_profile(args.quiet)
    names, ossec_mentions = ossec_profile()
    rows = []
    for address in addresses:
        mine = (events["client_ip"] == address) | (events["server_ip"] == address)
        roles = sorted(({"client"} if (events["client_ip"] == address).any() else set())
                       | ({"server"} if (events["server_ip"] == address).any() else set()))
        row = {"kind": "address", "value": address, "lines_here": int(mine.sum()), "role_here": ", ".join(roles),
               "hosts_here": ", ".join(events.loc[mine, "hostname"].value_counts().head(5).index),
               "known_as": names.get(address, ""), "ossec_lines_naming_it": ossec_mentions.get(address, 0)}
        if len(firewall) and address in firewall.index:
            f = firewall.loc[address]
            row.update({f"{other}_lines": int(f["lines"]), f"{other}_months": f["months"], f"{other}_ports": f["ports"]})
        if len(auth) and address in auth.index:
            a = auth.loc[address]
            row.update({k: a[k] for k in ("auth_logins_from", "auth_failures_from", "auth_accounts", "auth_servers",
                                          "auth_days_active") if k in a and pd.notna(a[k])})
        rows.append(row)
    for port in ports:
        mine = events["service_port"] == port
        row = {"kind": "service_port", "value": port, "lines_here": int(mine.sum()), "role_here": "service port",
               "hosts_here": ", ".join(events.loc[mine, "hostname"].value_counts().head(5).index)}
        if os_path_exists(other_path):
            other_events = pd.read_csv(other_path, dtype=str, usecols=["destination_port", "source_port", "timestamp"],
                                       keep_default_na=False)
            hits = other_events[(other_events["destination_port"] == port) | (other_events["source_port"] == port)]
            row.update({f"{other}_lines": len(hits), f"{other}_months": ", ".join(sorted(set(hits["timestamp"].str[:7])))})
        rows.append(row)
    alive = days.groupby(["hostname", "partition_month"]).agg(
        days=("day", "size"), alive_days=("host_alive", "sum"), certified_days=("certified", "sum"),
        month_status=("month_status", "first")).reset_index()
    return pd.DataFrame(rows), alive


def os_path_exists(path):
    return Path(path).is_file()


def main():
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    lookup = pd.read_csv(args.lookup, dtype=str, keep_default_na=False)
    summary, chains = evidence(args, lookup[["event_id", "raw_message", "source_ip", "destination_ip"]])
    summary.to_csv(args.output / f"{args.prefix}_isolation_forest_outlier_export_summary.csv", index=False)
    chains.to_csv(args.output / f"{args.prefix}_alert_message_chains.csv", index=False)
    chains.assign(review_label="", review_notes="").to_csv(args.output / f"{args.prefix}_review_queue.csv", index=False)
    events = pd.read_csv(args.observations / f"{args.prefix}_events_all_months.csv", dtype=str, keep_default_na=False)
    days = pd.read_csv(args.observations / f"{args.prefix}_host_days.csv")
    context, alive = cross_source(args, events, days)
    context.to_csv(args.output / f"{args.prefix}_cross_source_context.csv", index=False)
    alive.to_csv(args.output / f"{args.prefix}_host_liveness_by_month.csv", index=False)
    (args.output / "evidence_summary.json").write_text(json.dumps({
        "generated_at": datetime.now().isoformat(timespec="seconds"), "alerts": int(summary["isolation_alerts"].sum()),
        "complete": int(summary["complete_evidence_alerts"].sum()), "context_rows": len(context)}, indent=2),
        encoding="utf-8")
    log(f"{CONFIG[args.source]['label']} Phase 5 (presence method) done: "
        f"{int(summary['complete_evidence_alerts'].sum())}/{int(summary['isolation_alerts'].sum())} alerts with "
        f"complete evidence; {len(context)} context rows -> {args.output}", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
