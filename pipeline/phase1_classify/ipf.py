"""Phase 1 for IPFilter (ipmon) logs: raw ipflog lines -> one typed event per line.

  python pipeline/phase1_classify/ipf.py
  python pipeline/phase1_classify/ipf.py --archive-folder data/phase0_raw/archives

mm06moc runs Solaris IPFilter rather than PF, and logs blocked packets through
ipmon to /var/log/ipflog. The monthly archives carry one ipflog member per
month, and in normal operation it is EMPTY: nothing is expected to reach a rule
that logs. So this phase records the empty months as carefully as the lines,
because Phase 2 uses "file present and empty" as evidence of a quiet baseline.

A line looks like (the "/var/log/ipflog.22:" prefix comes from the collection
script and is optional):

    /var/log/ipflog.22:Nov 30 03:13:03 mm06moc ipmon[172]: [ID 702911 local0.warning]
        03:13:03.560605 e1000g0 @0:1 b 172.16.10.29,40781 -> 172.16.10.26,9711 PR tcp len 20 60 -S IN

Fields after the syslog header: packet time, optional repeat count ("2x" means
ipmon folded two identical packets into one line), interface, @group:rule,
action (b block, p pass, L log, S short, n no match), source[,port] ->
destination[,port], protocol, header and packet length, TCP flags (-S SYN,
-SEC SYN with ECN, -R RST, -A ACK, -F FIN, -P PSH) or ICMP type/code, direction.

Outputs (data/phase1_classify/ipf/):
    ipflog_events_<YYYY-MM>.csv      one row per line, including unrecognised ones
    ipflog_event_lookup.csv          event_id -> original line (used by Phases 5 and 7)
    ipflog_file_coverage.csv         one row per archive member: bytes, lines, status (empty/active)
    ipflog_lineage_summary.json      totals and the identity contract

The syslog line has no year. It is taken from the archive month, minus one when
the line's month is later than the archive month (a December line in a January
archive).
"""
from __future__ import annotations

import argparse
import sys
import csv
import hashlib
import json
import os
import re
import zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = ROOT / "data" / "phase0_raw" / "archives"
RAW = ROOT / "data" / "phase0_raw" / "ipf"
OUTPUT = ROOT / "data" / "phase1_classify" / "ipf"
CLASSIFIER_VERSION = "2026-10-01-ipf-01"

MONTHS = {name: number for number, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
ACTIONS = {"b": "block", "p": "pass", "L": "log", "S": "short", "n": "nomatch", "B": "block", "P": "pass"}
LINE = re.compile(
    r"^(?:(?P<log_path>[^:\s]+):)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<clock>\d\d:\d\d:\d\d) "
    r"(?P<host>\S+) ipmon\[(?P<pid>\d+)\]: (?:\[ID (?P<msgid>\d+) (?P<facility>[\w.]+)\] )?"
    r"(?P<packet_time>\d\d:\d\d:\d\d(?:\.\d+)?)\s+(?:(?P<repeat>\d+)x\s+)?(?P<interface>\S+) "
    r"@(?P<group>-?\d+):(?P<rule>-?\d+) (?P<action>[A-Za-z]) (?P<src>\S+) -> (?P<dst>\S+) "
    r"PR (?P<proto>\S+) len (?P<header_length>\d+) (?P<packet_length>\d+)(?P<rest>.*)$")
FIELDS = [
    "event_id", "raw_message_sha256", "timestamp", "timestamp_epoch", "partition_month", "hostname", "event_type",
    "action", "direction", "interface", "rule_group", "rule_number", "protocol", "source_ip", "source_port",
    "destination_ip", "destination_port", "header_length", "packet_length", "tcp_flags", "icmp_type",
    "repeat_count", "is_broadcast", "log_path", "ipmon_pid", "source_archive", "archive_member", "source_file",
    "source_line", "raw_message",
]
LOOKUP_FIELDS = ["event_id", "raw_message_sha256", "timestamp", "event_type", "hostname", "source_ip", "source_port",
                 "destination_ip", "destination_port", "protocol", "partition_month", "source_archive",
                 "archive_member", "source_file", "source_line", "raw_message"]
COVERAGE_FIELDS = ["partition_month", "hostname", "source_archive", "archive_member", "source_file", "bytes",
                   "lines", "parsed_lines", "unknown_lines", "packets", "first_timestamp", "last_timestamp", "status"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive-folder", type=Path, default=ARCHIVES)
    parser.add_argument("--raw-folder", type=Path, default=RAW)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    runlog.add_arguments(parser)
    return parser.parse_args()


log = runlog.log


def is_ipflog_member(name):
    """Archive members such as '2025-11 NSEWL SCS/ipflog/ipflog_mm06moc.txt' (the .txt is optional)."""
    parts = name.replace("\\", "/").split("/")
    return len(parts) >= 2 and parts[-2].lower() == "ipflog" and parts[-1].lower().startswith("ipflog")


def host_from_member(name):
    stem = Path(name.replace("\\", "/")).name
    stem = stem[:-4] if stem.lower().endswith(".txt") else stem
    return re.sub(r"^ipflogs?[_-]?", "", stem, flags=re.IGNORECASE) or "unknown"


def extract_archives(archive_folder, raw_folder, quiet):
    """Copy every ipflog member out of the monthly ZIPs, keeping the archive's folder layout."""
    members = []
    for archive in sorted(archive_folder.glob("*.zip")):
        month = archive.name[:7]
        with zipfile.ZipFile(archive) as handle:
            for info in handle.infolist():
                if info.is_dir() or not is_ipflog_member(info.filename):
                    continue
                target = raw_folder / Path(info.filename)
                data = handle.read(info)
                if not target.is_file() or target.read_bytes() != data:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                members.append({"partition_month": month, "source_archive": str(archive.relative_to(ROOT)),
                                "archive_member": info.filename, "source_file": str(target.relative_to(ROOT)),
                                "hostname": host_from_member(info.filename), "bytes": len(data)})
    log(f"{len(members)} ipflog members in {len(list(archive_folder.glob('*.zip')))} archives; "
        f"{sum(1 for m in members if m['bytes'])} non-empty", quiet)
    return members


def event_id(month, source_file, line_number, raw):
    seed = f"ipf|{month}|{source_file}|{line_number}|{raw}"
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:24]


def split_endpoint(text):
    """'172.16.10.29,40781' -> ('172.16.10.29', '40781'); ICMP has no port."""
    address, _, port = text.partition(",")
    return address, port


def year_for(month_number, partition_month):
    year, archive_month = int(partition_month[:4]), int(partition_month[5:7])
    return year - 1 if month_number > archive_month else year


def parse_line(raw, partition_month):
    match = LINE.match(raw)
    if not match:
        return None
    g = match.groupdict()
    month_number = MONTHS.get(g["mon"])
    if not month_number:
        return None
    year = year_for(month_number, partition_month)
    logged = datetime(year, month_number, int(g["day"]), *map(int, g["clock"].split(":")))
    hours, minutes, seconds = g["packet_time"].split(":")
    packet = logged.replace(hour=int(hours), minute=int(minutes), second=int(float(seconds)),
                            microsecond=int(round((float(seconds) % 1) * 1_000_000)) % 1_000_000)
    if packet - logged > timedelta(hours=12):        # packet just before midnight, logged just after
        packet -= timedelta(days=1)
    rest = g["rest"].split()
    direction = rest[-1] if rest and rest[-1] in ("IN", "OUT") else ""
    rest = rest[:-1] if direction else rest
    flags = next((token[1:] for token in rest if token.startswith("-")), "")
    icmp = " ".join(rest[1:]) if rest and rest[0].lower() == "icmp" else ""
    source_ip, source_port = split_endpoint(g["src"])
    destination_ip, destination_port = split_endpoint(g["dst"])
    action = ACTIONS.get(g["action"], g["action"])
    protocol = g["proto"].lower()
    return {
        "timestamp": packet.strftime("%Y-%m-%d %H:%M:%S.%f"), "timestamp_epoch": f"{packet.timestamp():.6f}",
        "hostname": g["host"], "event_type": f"IPF_{action.upper()}_{protocol.upper()}", "action": action,
        "direction": direction.lower(), "interface": g["interface"], "rule_group": g["group"], "rule_number": g["rule"],
        "protocol": protocol, "source_ip": source_ip, "source_port": source_port, "destination_ip": destination_ip,
        "destination_port": destination_port, "header_length": g["header_length"], "packet_length": g["packet_length"],
        "tcp_flags": flags if protocol == "tcp" else "", "icmp_type": icmp, "repeat_count": g["repeat"] or "1",
        "is_broadcast": str(destination_ip.endswith(".255") or destination_ip == "255.255.255.255"),
        "log_path": g["log_path"] or "", "ipmon_pid": g["pid"],
    }


def classify(members, output, quiet):
    output.mkdir(parents=True, exist_ok=True)
    coverage, totals, types = [], Counter(), Counter()
    by_month = {}
    for member in members:
        by_month.setdefault(member["partition_month"], []).append(member)
    lookup_path = output / "ipflog_event_lookup.csv"
    seen = set()
    with open(lookup_path.with_suffix(".csv.tmp"), "w", encoding="utf-8", newline="") as lookup_handle:
        lookup = csv.DictWriter(lookup_handle, fieldnames=LOOKUP_FIELDS, extrasaction="ignore")
        lookup.writeheader()
        for month, month_members in sorted(by_month.items()):
            path = output / f"ipflog_events_{month}.csv"
            with open(path.with_suffix(".csv.tmp"), "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
                writer.writeheader()
                for member in month_members:
                    stats = Counter()
                    first = last = ""
                    source = ROOT / member["source_file"]
                    with open(source, encoding="utf-8", errors="replace") as lines:
                        for number, raw in enumerate(lines, start=1):
                            raw = raw.rstrip("\r\n")
                            if not raw.strip():
                                continue
                            stats["lines"] += 1
                            row = parse_line(raw, month) or {"event_type": "IPF_UNKNOWN_EVENT",
                                                             "hostname": member["hostname"]}
                            stats["parsed_lines" if row["event_type"] != "IPF_UNKNOWN_EVENT" else "unknown_lines"] += 1
                            stats["packets"] += int(row.get("repeat_count") or 1)
                            row.update(event_id=event_id(month, member["source_file"], number, raw),
                                       raw_message_sha256=hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
                                       partition_month=month, source_archive=member["source_archive"],
                                       archive_member=member["archive_member"], source_file=member["source_file"],
                                       source_line=number, raw_message=raw)
                            if row["event_id"] in seen:
                                raise ValueError("Duplicate event_id: " + row["event_id"])
                            seen.add(row["event_id"])
                            if row.get("timestamp"):
                                first = min(first or row["timestamp"], row["timestamp"])
                                last = max(last, row["timestamp"])
                            types[row["event_type"]] += 1
                            writer.writerow(row)
                            lookup.writerow(row)
                    status = "active" if stats["lines"] else "empty"
                    coverage.append({**member, **{key: stats[key] for key in ("lines", "parsed_lines", "unknown_lines", "packets")},
                                     "first_timestamp": first, "last_timestamp": last, "status": status})
                    totals.update(stats)
                    log(f"{month} {member['archive_member']}: {member['bytes']:,} bytes, {stats['lines']:,} lines "
                        f"({stats['unknown_lines']:,} unrecognised) -> {status}", quiet)
            os.replace(path.with_suffix(".csv.tmp"), path)
    os.replace(lookup_path.with_suffix(".csv.tmp"), lookup_path)
    with open(output / "ipflog_file_coverage.csv", "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COVERAGE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(coverage)
    summary = {
        "classifier_version": CLASSIFIER_VERSION, "generated_at": datetime.now().isoformat(timespec="seconds"),
        "archive_members": len(coverage), "active_members": sum(row["status"] == "active" for row in coverage),
        "empty_members": sum(row["status"] == "empty" for row in coverage), "lines": totals["lines"],
        "packets": totals["packets"], "unknown_lines": totals["unknown_lines"], "event_types": dict(types.most_common()),
        "event_lookup_rows": len(seen), "event_lookup_file": str(lookup_path.relative_to(ROOT)),
        "identity_contract": {"event_id": "physical line occurrence (month, file, line number, text)",
                              "raw_message_sha256": "exact line content fingerprint",
                              "source_coordinates": ["source_archive", "archive_member", "source_file", "source_line"]},
    }
    (output / "ipflog_lineage_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main():
    args = parse_args()
    members = extract_archives(args.archive_folder, args.raw_folder, args.quiet)
    if not members:
        raise SystemExit(f"No ipflog members found in {args.archive_folder}")
    summary = classify(members, args.output, args.quiet)
    log(f"IPF Phase 1 done: {summary['lines']:,} lines ({summary['packets']:,} packets) in "
        f"{summary['active_members']} active and {summary['empty_members']} empty monthly files -> {args.output}",
        args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
