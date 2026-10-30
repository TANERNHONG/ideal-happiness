"""Simulated Phase 9 triage: hand-written analyst judgements in the triage.csv layout.

This is not the SLM. It is a first-cut, human-style reading of the single-event
(individual) alerts that Phase 7b grouped into behavioural clusters. Each rule
below records one analyst judgement, with the evidence behind it, so the real
SLM run can later be compared against it (and the rules double as few-shot
examples for the prompt).

The rules were written after profiling the 2026 test period (Phase 7b run of
2026-09-30). Cluster numbers change when Phase 4c is re-run, so the rules match
on message content, not on cluster IDs.

    python pipeline/phase9_llm_triage/simulate_triage.py --source ossec
    python pipeline/phase9_llm_triage/simulate_triage.py --source pf

Writes data/phase9_llm_triage/<source>/triage_simulated.csv (one row per
distinct alert) and triage_simulated_by_cluster.csv (category counts per cluster).
"""
import argparse
import sys
import hashlib
import re
from datetime import datetime
from pathlib import Path

import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
PREFIX = {"ossec": "ossec", "pf": "pflog"}
OUTPUT_FIELDS = ["alert_id", "source", "probability", "alert_types", "flagged_by", "dataset", "clusters", "line_count",
                 "category", "confidence", "reasoning", "key_lines", "approved_automation_involved",
                 "approved_addresses_in_lines", "missing_context", "attack_technique", "next_step",
                 "knowledge_ids", "status", "error", "model", "prompt_version", "triaged_at", "analyst_category",
                 "analyst_notes", "raw_messages", "verdict", "finding"]
MODEL = "claude-simulated-analyst"
PROMPT_VERSION = "simulated-2026-09-30"

# verdict: benign / suspicious / unknown. "suspicious" is kept for rules that would
# need it; none of the 2026 single-event alerts earned it.
RULES = {
    "ossec": [
        dict(finding="OSSEC-1 monitord checksum misses (mm06moc)",
             match=r"ossec-monitord.*(No previous (md5|sha1|md5/sha1) checksum|checksum skipped)",
             category="operationally_interesting", confidence=0.9, verdict="benign",
             reasoning="ossec-monitord on mm06moc cannot find the previous checksum file for its alert and "
                       "firewall logs (daily alert logs, weekly firewall logs on Mondays) and starts over. It has "
                       "happened about 120 times a month in every month since Aug 2025, and only on the one server that runs monitord. The models flag it because each line names a new "
                       "date-stamped file path, not because the behaviour is new.",
             missing_context="Why the /logs/alerts and /logs/firewall .sum checksum files are missing (rotation or disk layout).",
             attack_technique="none",
             next_step="Raise one maintenance ticket for the mm06moc OSSEC log rotation. Pipeline: mask dates in file paths "
                       "before hashing so this stops reaching the alert list."),
        dict(finding="OSSEC-2 agent restarts in 02:00 maintenance windows",
             match=r"^2026/(04/28 (02:[0-5]\d|03:(0\d|1[0-5]))|06/17 (01:5\d|02:[0-3]\d)|07/13 02:[0-5]\d)",
             category="expected_behavior", confidence=0.7, verdict="benign",
             reasoning="OSSEC agents started, pre-scanned the syscheck database and briefly could not reach the "
                       "manager on several servers around 02:00 on three nights. On 2026-04-28 it rolled "
                       "through the pair: com1kco first (02:05), com2kco after (02:48-03:10), as is usual for "
                       "redundant servers. At the same times sshd on com1kco was stopped and started again (signal 15, then 'Server listening'), and the "
                       "logins in the window are the usual root/spsy publickey sessions from 172.16.10.x. That "
                       "pattern is a coordinated restart or maintenance window. About 13 lines a day appear at "
                       "this hour normally, against 73-110 on these nights.",
             missing_context="Change record or maintenance schedule for 2026-04-28, 2026-06-17 and 2026-07-13 ~02:00. "
                             "On 2026-07-13 at 02:38 there was also one failed login for the non-existent user "
                             "'maint1' from 172.16.10.21 on com1kco (probably a typo during the work).",
             attack_technique="none",
             next_step="Confirm the three dates against the change log. If either was unplanned, re-open as "
                       "security_relevant (unexplained reboots of several servers)."),
        dict(finding="OSSEC-3 agent losing its manager (mm04kco)",
             match=r"Server responded\. Releasing lock|Process locked\. Waiting for permission|Lock free|"
                   r"Lost connection with manager|Trying to connect to server|Waiting for server reply|"
                   r"Trying next server ip|Closing connection to server|Connected to the server",
             category="operationally_interesting", confidence=0.8, verdict="benign",
             reasoning="The OSSEC agent's link to its manager keeps dropping and recovering. It recurs all year "
                       "(52 to 165 lines a month) and shows up only on mm04kco and dewskco, which points to a "
                       "chronic connectivity or manager-load problem. A silenced agent is a blind spot, so it is "
                       "worth a ticket, but there is no sign anyone is causing it.",
             missing_context="Network or manager outages around the lock periods, and whether PF blocks agent traffic "
                             "(UDP 1514) at those times.",
             attack_technique="none seen (a deliberate block would be T1562.001, Impair Defenses)",
             next_step="Ticket the mm04kco agent link. Cross-check PF for blocked 1514/udp at the lock times to rule "
                       "out deliberate blocking."),
        dict(finding="OSSEC-4 rootcheck run at an unusual time (mm05kco)",
             match=r"rootcheck",
             category="expected_behavior", confidence=0.6, verdict="benign",
             reasoning="Start and end lines of a normal OSSEC rootcheck scan. They were flagged because they ran on a "
                       "Sunday evening (17:00-23:00) on mm05kco, while scans normally run on weekdays between "
                       "04:00 and 09:00. The scan itself reported nothing.",
             missing_context="Whether the scan schedule was changed or a manual scan was started.",
             attack_technique="none",
             next_step="Check the ossec.conf rootcheck frequency on mm05kco. No action if the schedule changed."),
    ],
    "pf": [
        dict(finding="PF-1 licence-discovery broadcasts from 192.168.0.5",
             match=r"192\.168\.0\.5\.\d+ > 192\.168\.255\.255\.1947|192\.168\.0\.5\.\d+ > 255\.255\.255\.255\.1947|"
                   r"192\.168\.0\.5\.\d+ > [\d.]+\.1947",
             category="insufficient_context", confidence=0.7, verdict="unknown",
             reasoning="A device at 192.168.0.5 broadcast UDP to port 1947 (Sentinel HASP licence-manager "
                       "discovery) onto net2 and net3 of every server. The traffic itself is harmless and was "
                       "blocked, but it appears only in March 2026 (2,475 lines, mostly 2026-03-10 08:06-08:43 "
                       "and 2026-03-12 15:22-15:29), and 192.168.0.x is not part of the normal server plan. The "
                       "likely story is a vendor or engineering laptop plugged in with licensed software running; "
                       "the risk is an unmanaged device on the control network.",
             missing_context="Which device owns 192.168.0.5 (switch port / MAC), and whether a vendor visit or "
                             "commissioning work took place on 2026-03-10 and 2026-03-12.",
             attack_technique="none in the traffic; unmanaged device access would be T0848 (Rogue Master) "
                              "or T0864 (Transient Cyber Asset) in ATT&CK for ICS",
             next_step="Ask site engineering who was connected on those dates. If nobody can account for it, escalate "
                       "as security_relevant."),
        dict(finding="PF-3 X11 traffic from public-range 173.16.10.17",
             match=r"173\.16\.10\.17\.6000",
             category="insufficient_context", confidence=0.7, verdict="unknown",
             reasoning="Packets from port 6000 (X11, remote graphical display) on 173.16.10.17 to 172.16.10.29 "
                       "(27 lines, Jan-Feb 2026). 173.16.x.x is a public address range, yet it is used inside the "
                       "network: the auth logs show 173.16.10.11 and 173.16.10.14 logging in as root and spsy. "
                       "This is probably a misnumbered internal subnet, but X11 over the control network is itself "
                       "risky, because it can expose screens and keyboards.",
             missing_context="Asset register entry for 173.16.10.0/24, and whether X11 forwarding is meant to be "
                             "used to 172.16.10.29.",
             attack_technique="none seen; X11 misuse would be T1021 (Remote Services)",
             next_step="High priority for the site: confirm who owns 173.16.10.0/24. If it is internal, document it "
                       "and add it to the approved list; if not, escalate."),
        dict(finding="PF-2 late packets on internal sessions (no new connection)",
             match=r"17[23]\.16\.1[01]\.\d+\.\d+ > 17[23]\.16\.1[01]\.\d+\.\d+: Flags \[(?!S\])[^\]]*\]",
             category="expected_behavior", confidence=0.85, verdict="benign",
             reasoning="Blocked packets between internal servers, all mid- or end-of-conversation (P., FP., F., R., "
                       "'.') and never a new connection (no SYN). PF blocks these when a packet arrives after the "
                       "session's state entry has expired or been flushed, for example after a PF reload or a "
                       "restart. Most are SSH (port 22) from the usual admin hosts (.19, .21, .23). Others are "
                       "X11 display traffic from 172.16.10.22/.23 to .29 (Jan 2026), FIN packets to port 9711 on "
                       "2026-07-13 02:10 (the same minutes as the OSSEC maintenance restarts), and one stuck SSH "
                       "session from 173.16.10.17 retrying once a minute on 2026-02-20 03:24-03:29.",
             missing_context="Whether PF was reloaded, or state timeouts were changed, near these times; what "
                             "service listens on 9711.",
             attack_technique="none",
             next_step="No action. Suppress 'block without SYN on established internal pairs' in the next model "
                       "update (knowledge note RH-PF-04)."),
        dict(finding="PF-4 X11 traffic between 200.1.1.2 and 64.1.1.253",
             match=r"200\.1\.1\.2\.6000|64\.1\.1\.253",
             category="insufficient_context", confidence=0.6, verdict="unknown",
             reasoning="X11 (port 6000) packets from 200.1.1.2 to 64.1.1.253 on net1 in Jan 2026 (13 lines). Both "
                       "are public-range addresses that do not appear elsewhere in the logs. They could be a lab "
                       "or test numbering, or equipment configured with default addresses.",
             missing_context="What sits on net1 with these addresses.",
             attack_technique="none seen",
             next_step="Ask the network owner to identify both addresses."),
        dict(finding="PF-5 IEC-104 telecontrol reset from 10.2.101.11",
             match=r"\.2404\b",
             category="insufficient_context", confidence=0.6, verdict="unknown",
             reasoning="One blocked TCP reset from 10.2.101.11 port 2404 (IEC 60870-5-104, the telecontrol protocol "
                       "used between control centres and substations) to 192.169.251.1 on net5, in May 2026. A "
                       "single reset is most likely a stray end-of-connection packet, but IEC-104 traffic reaching "
                       "a server interface is worth the OT team knowing about.",
             missing_context="Whether net5 is expected to carry IEC-104, and who 192.169.251.1 is (another "
                             "public-range address).",
             attack_technique="none seen",
             next_step="Pass to the OT or telecontrol team for a sanity check. Low urgency."),
        dict(finding="PF-6 RIP routing broadcasts in a leftover 2024 capture",
             match=r"\.520 > [\d.]+\.520|RIP",
             category="expected_behavior", confidence=0.8, verdict="benign",
             reasoning="RIP routing-protocol broadcasts (port 520), which routers send routinely. They come from the "
                       "dewskco_tmp capture file dated 2024, which is outside the 2026 test period and was left in "
                       "the log folder.",
             missing_context="None for the traffic. The tmp capture files should not be in the dataset.",
             attack_technique="none",
             next_step="Data quality: exclude *_tmp PF capture files from Phase 1."),
    ],
}

FALLBACK = dict(finding="unmatched", category="insufficient_context", confidence=0.3, verdict="unknown",
                reasoning="No analyst rule covers this line yet.", missing_context="Needs a human look.",
                attack_technique="unknown", next_step="Review by hand and add a rule.")


def load_alerts(path):
    """Single-event alerts, one entry per distinct line, like triage.load_alerts."""
    data = pd.read_csv(path, dtype=str).fillna("")
    data = data[data["dataset"].eq("individual") & data["raw_messages"].str.strip().ne("")]
    data["probability"] = pd.to_numeric(data["rank"] if "rank" in data else data["probability"], errors="coerce").fillna(0)
    join = lambda values: "; ".join(dict.fromkeys(v for value in values for v in value.split("; ") if v))
    grouped = data.groupby("raw_messages", sort=False).agg(
        probability=("probability", "max"), flagged_by=("flagged_by", join), dataset=("dataset", join),
        clusters=("cluster_id", join), copies=("raw_messages", "size")).reset_index()
    grouped["alert_id"] = grouped["raw_messages"].map(lambda raw: hashlib.sha1(raw.strip().encode()).hexdigest()[:16])
    return grouped.sort_values("probability", ascending=False), len(data)


def judge(raw, rules):
    for rule in rules:
        if re.search(rule["match"], raw):
            return rule
    return FALLBACK


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=sorted(PREFIX), required=True)
    runlog.add_arguments(parser)
    args = parser.parse_args()
    prefix = PREFIX[args.source]
    alerts, flagged_rows = load_alerts(ROOT / "data" / "phase7b_clusters" / args.source / f"{prefix}_alerts_by_cluster.csv")
    now = datetime.now().isoformat(timespec="seconds")
    rows = []
    for alert in alerts.itertuples():
        rule = judge(alert.raw_messages, RULES[args.source])
        rows.append({"alert_id": alert.alert_id, "source": args.source, "probability": f"{alert.probability:.6f}",
                     "alert_types": "cluster alerts", "flagged_by": alert.flagged_by, "dataset": alert.dataset,
                     "clusters": alert.clusters, "line_count": 1, "category": rule["category"],
                     "confidence": rule["confidence"], "reasoning": rule["reasoning"], "key_lines": "1",
                     "approved_automation_involved": False, "approved_addresses_in_lines": "",
                     "missing_context": rule["missing_context"], "attack_technique": rule["attack_technique"],
                     "next_step": rule["next_step"], "knowledge_ids": "", "status": "simulated", "error": "",
                     "model": MODEL, "prompt_version": PROMPT_VERSION, "triaged_at": now, "analyst_category": "",
                     "analyst_notes": "", "raw_messages": alert.raw_messages, "verdict": rule["verdict"],
                     "finding": rule["finding"], "_copies": alert.copies})
    out = pd.DataFrame(rows)
    folder = ROOT / "data" / "phase9_llm_triage" / args.source
    folder.mkdir(parents=True, exist_ok=True)
    out[OUTPUT_FIELDS].to_csv(folder / "triage_simulated.csv", index=False)

    exploded = out.assign(cluster=out["clusters"].str.split("; ")).explode("cluster")
    by_cluster = (exploded.groupby(["cluster", "finding", "category", "verdict"])["_copies"].sum()
                  .rename("flagged_rows").reset_index().sort_values(["cluster", "flagged_rows"], ascending=[True, False]))
    by_cluster.to_csv(folder / "triage_simulated_by_cluster.csv", index=False)

    runlog.log(f"{args.source}: {flagged_rows:,} flagged single-event rows -> {len(out):,} distinct alerts")
    summary = out.groupby(["finding", "category", "verdict"]).agg(alerts=("alert_id", "size"), rows=("_copies", "sum"))
    print(summary.sort_values("rows", ascending=False).to_string())
    runlog.log(f"Wrote {folder / 'triage_simulated.csv'} and triage_simulated_by_cluster.csv")


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
