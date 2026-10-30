"""Phase 2 of the presence method (logs that are empty, or nearly, in normal operation).

  python pipeline/phase2_observations/presence.py --source ipf
  python pipeline/phase2_observations/presence.py --source pf --gap-episode 1800

Used for mm06moc's IPFilter log (11 of 12 monthly files empty) and the PF
firewall log (with the 2022-24 leftover captures removed, activity on 41 of 365
days). For auth, OSSEC and PF before, normal activity filled the logs and the
models learned "normal" from the lines. Here the baseline is NO lines, and a
table with one row per line has no normal rows to learn from. So the main views
are time SLOTS covering the whole study period, one row per host per slot, with
the empty slots included. Those empty slots are the baseline.

An empty slot only counts as quiet if we know the host was up and logging could
have happened. Each host-day is therefore CERTIFIED when both hold:
  * the host's file for that month is in the archive (empty or not), and
  * the host left evidence of being up that day: lines in this log, or in the
    other logs (OSSEC for IPFilter; auth and OSSEC for PF).
Certified days with no lines are the BASELINE; certified days with lines are
ACTIVE; the rest are UNCERTIFIED, kept but left out of the later phases.

Views (data/phase2_observations/<source>/, file names start with the source prefix):
    <prefix>_slots_5min.csv, _slots_1h.csv, _slots_1d.csv
        one row per host per slot over the full calendar, empty slots included
    <prefix>_attempts.csv
        one connection attempt: same host, protocol, source and destination
        address and port, with no gap over --gap-attempt seconds (a TCP SYN,
        its retries and the final RST form one attempt)
    <prefix>_flow_episodes.csv
        attempts on the same flow with no gap over --gap-episode seconds. A flow
        is keyed by its SERVICE side: client > server:service_port/protocol, where
        the service port is the lower of the two ports. So a server's late reply
        packets to many client ports form one flow, not one per port.
    <prefix>_events_all_months.csv     single events (packet lines), all Phase 1 columns kept
    <prefix>_host_days.csv             the certification table
    <prefix>_<view>_lineage.csv        observation -> event_id, the same layout as the other sources
    <prefix>_observation_dataset_summary.json / .csv

PF lines are normalised to the IPFilter field names: host from the file name,
TCP flags in ipmon letters (tcpdump's "." for ACK becomes "A", "W" for CWR "C"),
a repeat count of 1, and the sub-rule as the rule group. Non-packet lines (such
as a .bat script kept in the pflog folder) are left out.
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
from sources import ROOT, WITNESSES, archive_inventory, host_day_counts, host_from_path, study_days  # noqa: E402

BUILDER_VERSION = "2026-10-01-presence-observations-02"
CONFIG = {
    "ipf": {"prefix": "ipflog", "kind": "ipflog", "label": "IPFilter", "classified": "ipflog_events_*.csv"},
    "pf": {"prefix": "pflog", "kind": "pflog", "label": "PF", "classified": "classified_pflog_events_*.csv"},
}
SLOTS = {"slots_5min": "5min", "slots_1h": "1h", "slots_1d": "1D"}
LINEAGE_FIELDS = ["dataset", "row_manifest_id", "event_id", "event_position", "event_timestamp", "relationship_role"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(CONFIG))
    parser.add_argument("--gap-attempt", type=float, default=300.0)
    parser.add_argument("--gap-episode", type=float, default=1800.0)
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.classified = ROOT / "data" / "phase1_classify" / args.source
    args.output = ROOT / "data" / "phase2_observations" / args.source
    return args


log = runlog.log


def row_id(*parts):
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:24]


def normalise_pf(events):
    events = events[events["event_type"].str.startswith("PF_")].copy()
    events["hostname"] = host_from_path(events["source_file"])
    events["repeat_count"] = "1"
    events["rule_group"] = events.get("subrule_number", pd.Series("", index=events.index)).fillna("").replace("", "0")
    events["tcp_flags"] = events["tcp_flags"].fillna("").str.replace(".", "A", regex=False).str.replace("W", "C", regex=False)
    destination = events["destination_ip"].fillna("")
    events["is_broadcast"] = (destination.str.endswith(".255") | destination.eq("255.255.255.255")).astype(str)
    events["header_length"] = ""
    for column in ("source_port", "destination_port"):
        events[column] = events[column].fillna("").astype(str).str.replace(r"\.0$", "", regex=True)
    return events


def load_events(source, folder):
    files = sorted(folder.glob(CONFIG[source]["classified"]))
    frames = [pd.read_csv(path, dtype=str, keep_default_na=False) for path in files]
    events = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    if source == "pf":
        events = normalise_pf(events)
    else:
        events = events[events["event_type"].ne("IPF_UNKNOWN_EVENT")].copy()
    events["when"] = pd.to_datetime(events["timestamp"], errors="coerce")
    events = events.dropna(subset=["when"])
    events["packets"] = pd.to_numeric(events["repeat_count"], errors="coerce").fillna(1).astype(int)
    source_port = pd.to_numeric(events["source_port"], errors="coerce")
    destination_port = pd.to_numeric(events["destination_port"], errors="coerce")
    server_is_source = source_port.notna() & destination_port.notna() & (source_port < destination_port)
    events["client_ip"] = np.where(server_is_source, events["destination_ip"], events["source_ip"])
    events["server_ip"] = np.where(server_is_source, events["source_ip"], events["destination_ip"])
    events["service_port"] = np.where(server_is_source, events["source_port"], events["destination_port"])
    events["flow"] = (events["client_ip"] + ">" + events["server_ip"] + ":" + events["service_port"].replace("", "-")
                      + "/" + events["protocol"])
    return events.sort_values(["hostname", "when", "source_line"]).reset_index(drop=True)


def host_days(source, events, quiet):
    """Certification table: one row per host (with a file for this log) and day of the study period."""
    inventory = archive_inventory()
    days = study_days(inventory)
    mine = inventory[inventory["kind"].eq(CONFIG[source]["kind"]) & ~inventory["tmp"]]
    files = mine.groupby(["hostname", "partition_month"])["bytes"].sum()
    grid = pd.MultiIndex.from_product([sorted(mine["hostname"].unique()), days], names=["hostname", "day"]).to_frame(index=False)
    grid["partition_month"] = grid["day"].dt.strftime("%Y-%m")
    keys = pd.MultiIndex.from_frame(grid[["hostname", "partition_month"]])
    grid["file_bytes"] = files.reindex(keys).to_numpy()
    grid["file_present"] = grid["file_bytes"].notna()
    grid["file_bytes"] = grid["file_bytes"].fillna(0).astype(int)
    grid["month_status"] = np.where(~grid["file_present"], "missing", np.where(grid["file_bytes"] > 0, "active", "empty"))
    own = events.assign(day=events["when"].dt.normalize()).groupby(["hostname", "day"]).size().rename("lines")
    grid = grid.merge(own.reset_index(), on=["hostname", "day"], how="left")
    grid["lines"] = grid["lines"].fillna(0).astype(int)
    grid["alive_lines"] = 0
    used = []
    for witness in WITNESSES[source]:
        try:
            other = host_day_counts(witness).rename(columns={"lines": f"{witness}_lines"})
        except FileNotFoundError:
            log(f"WARNING: {witness} Phase 2 output missing; it cannot confirm hosts were up", quiet)
            continue
        grid = grid.merge(other, on=["hostname", "day"], how="left")
        grid[f"{witness}_lines"] = grid[f"{witness}_lines"].fillna(0).astype(int)
        grid["alive_lines"] += grid[f"{witness}_lines"]
        used.append(witness)
    grid["alive_evidence"] = np.where(grid["lines"] > 0, "own lines",
                                      np.where(grid["alive_lines"] > 0, "+".join(used), "none"))
    grid["host_alive"] = grid["alive_evidence"].ne("none")
    grid["certified"] = grid["file_present"] & grid["host_alive"]
    grid["regime"] = np.where(~grid["certified"], "uncertified", np.where(grid["lines"].eq(0), "baseline", "active"))
    grid["status"] = np.where(grid["lines"] > 0, "active", np.where(grid["certified"], "quiet", "unknown"))
    return grid, used


def attempts_view(events, gap):
    """One row per connection attempt; returns (attempts, event -> attempt id)."""
    keys = ["hostname", "protocol", "source_ip", "source_port", "destination_ip", "destination_port"]
    ordered = events.sort_values(keys + ["when"]).copy()
    new = (ordered[keys].ne(ordered[keys].shift()).any(axis=1)
           | ordered["when"].diff().dt.total_seconds().gt(gap))
    ordered["attempt_number"] = new.cumsum()
    first = ordered.groupby("attempt_number").first()
    ordered["row_manifest_id"] = ordered["attempt_number"].map(
        {number: row_id("attempt", r.hostname, r.flow, r.source_port, r.timestamp) for number, r in first.iterrows()})
    flags = ordered["tcp_flags"].fillna("")
    ordered["syn"] = flags.str.startswith("S") * ordered["packets"]
    ordered["ecn_syn"] = flags.isin(["SEC", "SE", "SC"]) * ordered["packets"]
    ordered["rst"] = flags.str.contains("R") * ordered["packets"]
    grouped = ordered.groupby("row_manifest_id", sort=False)
    attempts = grouped.agg(
        hostname=("hostname", "first"), start=("when", "min"), end=("when", "max"), flow=("flow", "first"),
        source_ip=("source_ip", "first"), source_port=("source_port", "first"),
        destination_ip=("destination_ip", "first"), destination_port=("destination_port", "first"),
        protocol=("protocol", "first"), lines=("event_id", "size"), packets=("packets", "sum"),
        syn_packets=("syn", "sum"), ecn_syn_packets=("ecn_syn", "sum"), rst_packets=("rst", "sum"),
        flag_sequence=("tcp_flags", lambda s: " ".join(x or "-" for x in s)),
        rules=("rule_number", lambda s: ";".join(sorted(set(s)))),
        actions=("action", lambda s: ";".join(sorted(set(s)))),
        broadcast=("is_broadcast", lambda s: bool(s.eq("True").any())),
    ).reset_index()
    attempts["duration_seconds"] = (attempts["end"] - attempts["start"]).dt.total_seconds()
    attempts["retries"] = (attempts["syn_packets"] - 1).clip(lower=0)
    return attempts.sort_values("start").reset_index(drop=True), ordered[["event_id", "row_manifest_id"]]


def episodes_view(attempts, gap):
    keys = ["hostname", "flow"]
    ordered = attempts.sort_values(keys + ["start"]).copy()
    previous_end = ordered.groupby(keys)["end"].shift()
    new = ordered[keys].ne(ordered[keys].shift()).any(axis=1) | (ordered["start"] - previous_end).dt.total_seconds().gt(gap)
    ordered["episode_number"] = new.cumsum()
    first = ordered.groupby("episode_number").first()
    ordered["episode_id"] = ordered["episode_number"].map(
        {number: row_id("episode", r.hostname, r.flow, r.start) for number, r in first.iterrows()})
    rows = []
    for episode, part in ordered.groupby("episode_id", sort=False):
        starts = part["start"].sort_values()
        intervals = starts.diff().dt.total_seconds().dropna()
        flow = part["flow"].iloc[0]
        client, rest = flow.split(">", 1)
        server_port, protocol = rest.rsplit("/", 1)
        server, port = server_port.rsplit(":", 1)
        rows.append({
            "row_manifest_id": episode, "hostname": part["hostname"].iloc[0], "flow": flow,
            "source_ip": client, "destination_ip": server, "destination_port": port, "protocol": protocol,
            "start": part["start"].min(), "end": part["end"].max(), "attempts": len(part),
            "lines": int(part["lines"].sum()), "packets": int(part["packets"].sum()),
            "distinct_source_ports": part["source_port"].nunique(),
            "mean_interval_seconds": float(intervals.mean()) if len(intervals) else 0.0,
            "interval_cv": float(intervals.std() / intervals.mean()) if len(intervals) > 1 and intervals.mean() else 0.0,
            "mean_retries": float(part["retries"].mean()), "rst_share": float((part["rst_packets"] > 0).mean()),
            "ecn_share": float((part["ecn_syn_packets"] > 0).mean()), "broadcast": bool(part["broadcast"].any()),
            "rules": ";".join(sorted(set(";".join(part["rules"]).split(";")))),
            "actions": ";".join(sorted(set(";".join(part["actions"]).split(";")))),
            "succeeded": bool(part["actions"].str.contains("pass").any()),
        })
    episodes = pd.DataFrame(rows)
    episodes["duration_hours"] = (episodes["end"] - episodes["start"]).dt.total_seconds() / 3600
    return episodes.sort_values("start").reset_index(drop=True), ordered[["row_manifest_id", "episode_id"]]


def slots_view(name, frequency, events, days, attempts):
    """Full calendar of slots per host, empty ones included."""
    frames = []
    for host, host_frame in days.groupby("hostname"):
        starts = pd.date_range(host_frame["day"].min(), host_frame["day"].max() + pd.Timedelta(days=1),
                               freq=frequency, inclusive="left")
        frame = pd.DataFrame({"hostname": host, "slot_start": starts})
        frame["slot_end"] = frame["slot_start"] + pd.tseries.frequencies.to_offset(frequency)
        frame["day"] = frame["slot_start"].dt.normalize()
        frame = frame.merge(host_frame[["day", "partition_month", "certified", "regime", "month_status"]],
                            on="day", how="left")
        mine = events[events["hostname"].eq(host)].copy()
        mine["slot_start"] = mine["when"].dt.floor(frequency)
        flags = mine["tcp_flags"].fillna("")
        mine["syn"] = flags.str.startswith("S") * mine["packets"]
        mine["rst"] = flags.str.contains("R") * mine["packets"]
        mine["udp"] = mine["protocol"].eq("udp") * mine["packets"]
        mine["icmp"] = mine["protocol"].eq("icmp") * mine["packets"]
        mine["broadcast"] = mine["is_broadcast"].eq("True") * mine["packets"]
        mine["blocked"] = mine["action"].eq("block") * mine["packets"]
        mine["passed"] = mine["action"].eq("pass") * mine["packets"]
        numeric = ["lines", "packets", "syn_packets", "rst_packets", "udp_packets", "icmp_packets", "broadcast_packets",
                   "blocked_packets", "passed_packets", "distinct_flows", "distinct_sources", "distinct_destinations",
                   "distinct_destination_ports", "distinct_rules"]
        if len(mine):
            counts = mine.groupby("slot_start").agg(
                lines=("event_id", "size"), packets=("packets", "sum"), syn_packets=("syn", "sum"),
                rst_packets=("rst", "sum"), udp_packets=("udp", "sum"), icmp_packets=("icmp", "sum"),
                broadcast_packets=("broadcast", "sum"), blocked_packets=("blocked", "sum"),
                passed_packets=("passed", "sum"), distinct_flows=("flow", "nunique"),
                distinct_sources=("source_ip", "nunique"), distinct_destinations=("destination_ip", "nunique"),
                distinct_destination_ports=("service_port", "nunique"), distinct_rules=("rule_number", "nunique"),
                top_flow=("flow", lambda s: s.value_counts().index[0]))
            frame = frame.merge(counts, left_on="slot_start", right_index=True, how="left")
        else:
            for column in numeric + ["top_flow"]:
                frame[column] = np.nan
        started = attempts[attempts["hostname"].eq(host)].assign(
            slot_start=lambda a: a["start"].dt.floor(frequency)).groupby("slot_start").size().rename("attempts_started")
        frame = frame.merge(started, left_on="slot_start", right_index=True, how="left")
        frame[numeric + ["attempts_started"]] = frame[numeric + ["attempts_started"]].fillna(0).astype(int)
        frame["top_flow"] = frame["top_flow"].fillna("")
        frame["row_manifest_id"] = [row_id(name, host, value) for value in frame["slot_start"]]
        frame["active"] = frame["lines"].gt(0)
        mine = mine.merge(frame[["slot_start", "row_manifest_id"]], on="slot_start", how="left")
        frames.append((frame, mine[["event_id", "row_manifest_id", "timestamp"]]))
    slots = pd.concat([frame for frame, _ in frames], ignore_index=True)
    links = pd.concat([link for _, link in frames], ignore_index=True)
    return slots, links


def write_lineage(path, dataset, links, events, role):
    frame = links[["event_id", "row_manifest_id"]].merge(events[["event_id", "timestamp"]], on="event_id", how="left")
    frame = frame.rename(columns={"timestamp": "event_timestamp"}).sort_values(["row_manifest_id", "event_timestamp", "event_id"])
    frame["event_position"] = frame.groupby("row_manifest_id").cumcount() + 1
    frame["dataset"], frame["relationship_role"] = dataset, role
    frame[LINEAGE_FIELDS].to_csv(path, index=False)
    return len(frame)


def main():
    args = parse_args()
    prefix, out = CONFIG[args.source]["prefix"], args.output
    out.mkdir(parents=True, exist_ok=True)
    events = load_events(args.source, args.classified)
    log(f"{CONFIG[args.source]['label']}: {len(events):,} packet lines ({events['packets'].sum():,} packets) "
        f"on {events['hostname'].nunique()} hosts", args.quiet)
    days, witnesses = host_days(args.source, events, args.quiet)
    days.to_csv(out / f"{prefix}_host_days.csv", index=False)
    counts = days["regime"].value_counts().to_dict()
    log(f"Host-days: {len(days):,}; baseline {counts.get('baseline', 0):,}, active {counts.get('active', 0):,}, "
        f"uncertified {counts.get('uncertified', 0):,} (witnesses: {', '.join(witnesses) or 'none'})", args.quiet)
    summary = {"builder_version": BUILDER_VERSION, "source": args.source, "method": "presence",
               "generated_at": datetime.now().isoformat(timespec="seconds"),
               "events": len(events), "packets": int(events["packets"].sum()), "hosts": int(days["hostname"].nunique()),
               "study_period": [str(days["day"].min().date()), str(days["day"].max().date())],
               "host_days": {k: int(v) for k, v in counts.items()}, "witnesses": witnesses,
               "settings": {"gap_attempt_seconds": args.gap_attempt, "gap_episode_seconds": args.gap_episode},
               "datasets": []}

    def record(dataset, frame, lineage_rows, file_name, lineage_name):
        frame.to_csv(out / file_name, index=False)
        entry = {"dataset": dataset, "dataset_file": str((out / file_name).relative_to(ROOT)),
                 "lineage_file": str((out / lineage_name).relative_to(ROOT)), "dataset_rows": len(frame),
                 "lineage_rows": lineage_rows}
        if "active" in frame:
            entry["active_rows"] = int(frame["active"].sum())
            entry["regimes"] = {k: int(v) for k, v in frame["regime"].value_counts().items()}
        summary["datasets"].append(entry)
        log(f"{dataset}: {len(frame):,} rows" + (f" ({entry['active_rows']:,} with activity)" if "active_rows" in entry else ""),
            args.quiet)

    individual = events.drop(columns=["when"]).assign(row_manifest_id=events["event_id"])
    lineage = write_lineage(out / f"{prefix}_events_all_months_lineage.csv", "individual",
                            individual[["event_id", "row_manifest_id"]], events, "individual_event")
    record("individual", individual, lineage, f"{prefix}_events_all_months.csv", f"{prefix}_events_all_months_lineage.csv")
    attempts, attempt_links = attempts_view(events, args.gap_attempt)
    lineage = write_lineage(out / f"{prefix}_attempts_lineage.csv", "attempts", attempt_links, events, "attempt_packet")
    record("attempts", attempts, lineage, f"{prefix}_attempts.csv", f"{prefix}_attempts_lineage.csv")
    episodes, episode_of_attempt = episodes_view(attempts, args.gap_episode)
    episode_links = attempt_links.merge(episode_of_attempt, on="row_manifest_id")[["event_id", "episode_id"]]
    episode_links = episode_links.rename(columns={"episode_id": "row_manifest_id"})
    lineage = write_lineage(out / f"{prefix}_flow_episodes_lineage.csv", "flow_episodes", episode_links, events,
                            "episode_packet")
    record("flow_episodes", episodes, lineage, f"{prefix}_flow_episodes.csv", f"{prefix}_flow_episodes_lineage.csv")
    for name, frequency in SLOTS.items():
        slots, links = slots_view(name, frequency, events, days, attempts)
        lineage = write_lineage(out / f"{prefix}_{name}_lineage.csv", name, links, events, "slot_packet")
        record(name, slots, lineage, f"{prefix}_{name}.csv", f"{prefix}_{name}_lineage.csv")
    (out / f"{prefix}_observation_dataset_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    pd.DataFrame(summary["datasets"]).drop(columns=["regimes"], errors="ignore").to_csv(
        out / f"{prefix}_observation_dataset_summary.csv", index=False)
    log(f"{CONFIG[args.source]['label']} Phase 2 (presence method) done -> {out}", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
