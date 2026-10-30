"""Classify extracted PF firewall logs into normalized monthly CSV files.

The script first extracts PF log files from ZIP archives beneath ``data/phase0_raw/archives`` and
then recursively scans files whose names begin with ``pflog`` beneath
``data/phase0_raw/pf/YYYY-MM*/``. It supports extensionless names such as
``pflog_admikco`` as well as names such as ``pflog_admikco.txt`` and
``pflog.0.txt``.

Recognized packet records are written to one classified CSV per month. Records
that do not match a supported PF log format are retained as
``PFLOG_UNKNOWN_EVENT`` and written to monthly and all-month unknown reports.

Lineage outputs preserve the path from each classified event back to its exact
physical log occurrence. Each event receives an occurrence-level ``event_id``,
a content-level ``raw_message_sha256``, source archive/member metadata when
available, the extracted source file and physical source line, and the exact
raw message excluding only the newline terminator. A consolidated
``pflog_event_lookup.csv`` supports downstream ML evidence joins.

Command-line usage
------------------
Run with timestamped INFO checkpoints and ten-second activity updates::

    python pipeline/phase1_classify/pf.py

Enable detailed per-file and per-batch messages and five-second updates::

    python pipeline/phase1_classify/pf.py --verbose --progress-interval 5

Leftover capture files named ``pflog_<host>_tmp`` hold packets from 2022-2024,
outside the study period, and made up 96% of all PF lines. They are left out by
default; ``--include-tmp`` brings them back::

    python pipeline/phase1_classify/pf.py --include-tmp

Suppress routine progress with ``--quiet``. Both switches are mutually
exclusive. Use ``--help`` to view the logging options.

Runtime reporting
-----------------
Each log record includes elapsed time since module startup in ``HH:MM:SS.s``
format using ``time.monotonic()``. Timed stages report their own duration.
A background heartbeat reports the active stage during long extraction,
classification and lookup-rebuilding work. Loop checkpoints also report item
counts and throughput. CLI runs report total runtime on completion, early
return, errors and interruption.

.. note::

   Heartbeats indicate activity, not a percentage or an estimated finish time.
   They may be delayed by native code holding the interpreter lock. Abrupt
   process termination cannot emit a final summary. Quiet mode suppresses
   routine timing messages; warnings and errors remain visible.
   Imported callers can configure logging and use
   ``with runlog.run(): main()`` for the same runtime reporting.
"""

import time
import argparse
from pathlib import Path
import csv
import glob
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import sys
import threading
import zipfile
from collections import Counter
from contextlib import contextmanager
from functools import wraps

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import progress_items, stage, timed_stage  # noqa: E402

LOGGER = runlog.LOGGER

ZIP_FOLDER = "data/phase0_raw/archives"
EXTRACT_FOLDER = "data/phase0_raw/pf"
EXTRACT_ZIP_FILES = True
OVERWRITE_EXTRACTED_FILES = False
MAX_MEMBER_SIZE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_SIZE_BYTES = 20 * 1024 * 1024 * 1024
OUTPUT_FOLDER = "data/phase1_classify/pf"
WRITE_BATCH_SIZE = 10000
UNKNOWN_EVENT_TYPE = "PFLOG_UNKNOWN_EVENT"
SKIP_COMPLETED_MONTHS = True
FILE_PREFIX = "pflog"
EXTRACTION_MANIFEST_FILE = os.path.join(OUTPUT_FOLDER, "pflog_extraction_manifest.csv")
EVENT_LOOKUP_FILE = os.path.join(OUTPUT_FOLDER, "pflog_event_lookup.csv")

YEAR_MONTH_FOLDER_PATTERN = re.compile(r"^(?P<year_month>\d{4}-\d{2})(?:\s+.*)?$")
TIMESTAMP_PREFIX = r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
RULE_PREFIX = r"rule\s+(?P<rule_number>\d+)/(?P<subrule_number>\d+)\((?P<rule_reason>[^)]+)\):\s+"
ACTION_PREFIX = r"(?P<action>pass|block|match)\s+(?P<direction>in/out|in|out)(?:\s+log)?\s+on\s+(?P<interface>[^:]+):\s*"
COMMON_PREFIX = r"^(?:(?P<log_path>.*?):)?" + TIMESTAMP_PREFIX + r"\s+" + RULE_PREFIX + ACTION_PREFIX

PFLOG_PREFIX_PATTERN = re.compile(COMMON_PREFIX + r"(?P<packet_message>.*)$", re.IGNORECASE)
TCP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+flags\s+\[(?P<tcp_flags>[^]]*)\](?:,\s+seq\s+(?P<sequence_number>\d+)(?::(?P<sequence_end>\d+))?)?(?:,\s+ack\s+(?P<acknowledgement_number>\d+))?(?:,\s+win\s+(?P<window_size>\d+))?(?:,\s+options\s+\[(?P<tcp_options>[^]]*)\])?(?:,\s+length\s+(?P<packet_length>\d+))?\s*$", re.IGNORECASE)
UDP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+(?:(?P<udp_label>udp),\s*)?length\s+(?P<packet_length>\d+)\s*$", re.IGNORECASE)
ICMP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_ip>\S+)\s*>\s*(?P<destination_ip>\S+):\s+(?P<icmp_message>icmp6?\s+.*)$", re.IGNORECASE)
RIP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+ripv1,\s*(?P<protocol_message>.*)$", re.IGNORECASE)
ISAKMP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+isakmp:\s*(?P<protocol_message>.*)$", re.IGNORECASE)
DNS_INVALID_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+domain\s+\[length\s+(?P<actual_length>\d+)\s+<\s+(?P<expected_length>\d+)\]\s+\(invalid\)\s*$", re.IGNORECASE)
DHCP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+bootp/dhcp(?:,\s*|\s+)(?P<protocol_message>.*)$", re.IGNORECASE)
SNMP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s*\[\|snmp\]\s*$", re.IGNORECASE)
TFTP_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+?)(?:\s*:\s*|\s+)(?P<tftp_opcode>\d+)\s+tftp-#(?P<tftp_block>\d+)\s*$", re.IGNORECASE)
GENERIC_PACKET_PATTERN = re.compile(COMMON_PREFIX + r"(?P<source_endpoint>\S+)\s*>\s*(?P<destination_endpoint>\S+):\s+(?P<packet_message>.*)$", re.IGNORECASE)

SCRIPT_CD_PATTERN = re.compile(r"^cd\s+.+$", re.IGNORECASE)
SCRIPT_ECHO_PATTERN = re.compile(r"^echo\s+.+(?:>|>>).*$", re.IGNORECASE)
SCRIPT_FINDSTR_PATTERN = re.compile(r"^findstr\s+.+$", re.IGNORECASE)
HOST_MARKER_PATTERN = re.compile(r"^\d+-\d+-\d+$")
TRUNCATED_LENGTH_PATTERN = re.compile(r",\s+le\s*$", re.IGNORECASE)

OUTPUT_FIELDNAMES = [
    "event_id", "raw_message_sha256", "timestamp", "event_type", "action",
    "direction", "interface", "rule_number", "subrule_number", "rule_reason",
    "protocol", "ip_version", "source_ip", "source_port", "destination_ip",
    "destination_port", "tcp_flags", "sequence_number", "sequence_end",
    "acknowledgement_number", "window_size", "tcp_options", "packet_length",
    "icmp_message", "reason", "raw_message", "classification_message",
    "log_path", "partition_month", "source_archive", "archive_member",
    "source_file", "source_line",
]

UNKNOWN_DETAIL_FIELDS = [
    "event_id", "raw_message_sha256", "timestamp", "event_type", "raw_message",
    "classification_message", "normalized_message", "partition_month",
    "source_archive", "archive_member", "source_file", "source_line",
]

UNKNOWN_SUMMARY_FIELDS = [
    "normalized_message", "count", "first_timestamp", "last_timestamp",
    "months", "source_archives", "source_files", "example_message",
]

EXTRACTION_MANIFEST_FIELDS = [
    "source_archive", "archive_member", "inferred_month", "extracted_path",
    "uncompressed_size", "compressed_size", "archive_crc", "extraction_status",
]

EVENT_LOOKUP_FIELDS = [
    "event_id", "raw_message_sha256", "timestamp", "event_type", "action",
    "direction", "interface", "rule_number", "protocol", "ip_version",
    "source_ip", "source_port", "destination_ip", "destination_port",
    "partition_month", "source_archive", "archive_member", "source_file",
    "source_line", "raw_message",
]


# =============================================================================
# Logging, timing and progress reporting
# =============================================================================


def parse_args():
    """Parse verbosity and heartbeat interval settings.

    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    runlog.add_arguments(parser)
    parser.add_argument("--include-tmp", action="store_true",
                        help="Also classify leftover pflog_*_tmp capture files (2022-2024, outside the study period).")
    args = parser.parse_args()
    return args


# =============================================================================
# Value helpers
# =============================================================================

def clean(value):
    """Normalize a value to stripped text, mapping None to empty text.

    :param value: Value to normalize.
    :returns: Normalized text.
    :rtype: str
    """
    return str(value).strip() if value is not None else ""


def safe_member_path(destination, member_name):
    """Resolve a ZIP member path and reject any path escaping the destination.

    :param destination: Extraction destination directory.
    :param member_name: Member path within the ZIP archive.
    :returns: Absolute resolved member path.
    :rtype: str
    :raises ValueError: If the resolved path escapes the destination directory.
    """
    destination = os.path.abspath(destination)
    candidate = os.path.abspath(os.path.join(destination, member_name))
    if os.path.commonpath([destination, candidate]) != destination:
        raise ValueError("Unsafe ZIP member path: " + member_name)
    return candidate


def archive_year_month(zip_path):
    """Extract a YYYY-MM identifier from an archive filename.

    :param zip_path: ZIP archive path.
    :returns: Matched year-month text, or None if the filename has no match.
    :rtype: str or None
    """
    match = re.search(r"(?<!\d)(\d{4}-\d{2})(?!\d)", os.path.basename(zip_path))
    return match.group(1) if match else None


def member_contains_year_month(member_name):
    """Check whether a ZIP member's first path component is a year-month folder.

    :param member_name: Member path within the ZIP archive.
    :returns: True if the first path segment matches YEAR_MONTH_FOLDER_PATTERN.
    :rtype: bool
    """
    normalized = member_name.replace("\\", "/")
    first_component = normalized.split("/", 1)[0]
    return YEAR_MONTH_FOLDER_PATTERN.match(first_component) is not None


def write_extraction_manifest(rows):
    """Write extraction metadata rows sorted by archive and member.

    :param rows: Extraction manifest row dictionaries.
    :rtype: None
    """
    with open(EXTRACTION_MANIFEST_FILE, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EXTRACTION_MANIFEST_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: (row["source_archive"], row["archive_member"])))


def load_extraction_lookup():
    """Read the existing extraction manifest into a destination-keyed lookup.

    :returns: Archive and member metadata keyed by absolute extracted path.
    :rtype: dict
    """
    lookup = {}
    if not os.path.isfile(EXTRACTION_MANIFEST_FILE):
        return lookup
    with open(EXTRACTION_MANIFEST_FILE, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            extracted_path = clean(row.get("extracted_path"))
            if extracted_path:
                lookup[os.path.abspath(extracted_path)] = {
                    "source_archive": clean(row.get("source_archive")),
                    "archive_member": clean(row.get("archive_member")),
                }
    return lookup


@timed_stage
def extract_pflog_archives():
    """Extract eligible PF log members from every ZIP archive under ZIP_FOLDER.

    :returns: Archive and file counts for the extraction pass.
    :rtype: dict
    :raises ValueError: If a member or archive exceeds its configured size limit.
    """
    if not EXTRACT_ZIP_FILES:
        return {"archives_found": 0, "archives_extracted": 0, "files_extracted": 0, "files_skipped": 0}

    os.makedirs(ZIP_FOLDER, exist_ok=True)
    os.makedirs(EXTRACT_FOLDER, exist_ok=True)
    zip_paths = sorted(glob.glob(os.path.join(ZIP_FOLDER, "**", "*.zip"), recursive=True))
    statistics = {"archives_found": len(zip_paths), "archives_extracted": 0, "files_extracted": 0, "files_skipped": 0}
    manifest_rows = []

    for zip_path in progress_items(zip_paths, "PF log archives inspected"):
        LOGGER.debug("Inspecting PF log archive: %s", zip_path)
        inferred_month = archive_year_month(zip_path)
        archive_extracted = False
        archive_uncompressed_size = 0

        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in progress_items(archive.infolist(), "Archive members examined"):
                if member.is_dir():
                    continue
                archive_uncompressed_size += member.file_size
                if member.file_size > MAX_MEMBER_SIZE_BYTES:
                    raise ValueError("ZIP member exceeds size limit: " + member.filename)
                if archive_uncompressed_size > MAX_ARCHIVE_SIZE_BYTES:
                    raise ValueError("ZIP archive exceeds uncompressed size limit: " + zip_path)

                member_name = member.filename.replace("\\", "/").lstrip("/")
                if not member_name:
                    continue
                if member_contains_year_month(member_name):
                    relative_target = member_name
                elif inferred_month:
                    relative_target = inferred_month + "/" + member_name
                else:
                    statistics["files_skipped"] += 1
                    continue

                target_path = safe_member_path(EXTRACT_FOLDER, relative_target)
                manifest_row = {
                    "source_archive": os.path.normpath(zip_path),
                    "archive_member": member.filename,
                    "inferred_month": inferred_month or "",
                    "extracted_path": os.path.abspath(target_path),
                    "uncompressed_size": str(member.file_size),
                    "compressed_size": str(member.compress_size),
                    "archive_crc": str(member.CRC),
                    "extraction_status": "",
                }
                if not os.path.basename(target_path).lower().startswith(FILE_PREFIX):
                    manifest_row["extraction_status"] = "skipped_non_pflog"
                    manifest_rows.append(manifest_row)
                    statistics["files_skipped"] += 1
                    continue
                if os.path.exists(target_path) and not OVERWRITE_EXTRACTED_FILES:
                    manifest_row["extraction_status"] = "existing"
                    manifest_rows.append(manifest_row)
                    statistics["files_skipped"] += 1
                    continue

                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with archive.open(member, "r") as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                manifest_row["extraction_status"] = "extracted"
                manifest_rows.append(manifest_row)
                statistics["files_extracted"] += 1
                archive_extracted = True
                LOGGER.debug("Extracted %s", target_path)

        if archive_extracted:
            statistics["archives_extracted"] += 1

    write_extraction_manifest(manifest_rows)
    return statistics


def get_year_month_from_path(file_path):
    """Read the YYYY-MM folder segment from an extracted file path.

    :param file_path: Extracted source path beneath EXTRACT_FOLDER.
    :returns: Matched year-month text, or None if the top folder does not match.
    :rtype: str or None
    """
    relative_path = os.path.relpath(file_path, EXTRACT_FOLDER)
    top_level_folder = relative_path.split(os.sep, 1)[0]
    match = YEAR_MONTH_FOLDER_PATTERN.match(top_level_folder)
    return match.group("year_month") if match else None


INCLUDE_TMP = False


@timed_stage
def find_pflog_files_by_month():
    """Recursively find extracted pflog-prefixed files grouped by month.

    :returns: File path lists keyed by year-month.
    :rtype: dict
    """
    files_by_month, skipped_tmp = {}, []
    search_pattern = os.path.join(EXTRACT_FOLDER, "????-??*", "**", "*")
    candidates = glob.iglob(search_pattern, recursive=True)
    for file_path in progress_items(sorted(candidates), "PF log candidate paths scanned"):
        if not os.path.isfile(file_path):
            continue
        if not os.path.basename(file_path).lower().startswith(FILE_PREFIX):
            continue
        if not INCLUDE_TMP and "_tmp" in os.path.basename(file_path).lower():
            skipped_tmp.append(file_path)
            continue
        year_month = get_year_month_from_path(file_path)
        if year_month:
            files_by_month.setdefault(year_month, []).append(file_path)
    if skipped_tmp:
        LOGGER.info("Left out %s leftover *_tmp capture files (use --include-tmp to keep them)", len(skipped_tmp))
    return files_by_month


def parse_ip(value):
    """Parse and normalize a bracket- or punctuation-wrapped IP address.

    :param value: Candidate IP address text.
    :returns: Normalized address text and its version, empty when unparseable.
    :rtype: tuple
    """
    value = clean(value).strip("[](),")
    try:
        address = ipaddress.ip_address(value)
        return str(address), str(address.version)
    except ValueError:
        return value, ""


def split_endpoint(endpoint):
    """Split a source or destination endpoint into address, port and version.

    :param endpoint: Endpoint text such as ``host.port`` or ``[host].port``.
    :returns: IP address text, port text and IP version, each possibly empty.
    :rtype: tuple
    """
    endpoint = clean(endpoint).rstrip(":,")
    if endpoint.startswith("[") and "]" in endpoint:
        closing = endpoint.rfind("]")
        host = endpoint[1:closing]
        remainder = endpoint[closing + 1:]
        port = remainder[1:] if remainder.startswith(".") else ""
        ip_value, version = parse_ip(host)
        return ip_value, port if port.isdigit() else "", version
    try:
        address = ipaddress.ip_address(endpoint)
        return str(address), "", str(address.version)
    except ValueError:
        pass
    if "." in endpoint:
        host, possible_port = endpoint.rsplit(".", 1)
        if possible_port.isdigit():
            ip_value, version = parse_ip(host)
            return ip_value, possible_port, version
    ip_value, version = parse_ip(endpoint)
    return ip_value, "", version


def event_type_for(action, protocol):
    """Build an event-type label from an action and protocol.

    :param action: PF action text such as pass, block or match.
    :param protocol: Protocol name.
    :returns: PF_<ACTION>_<PROTOCOL> event type label.
    :rtype: str
    """
    return "PF_" + (clean(action).upper() or "UNKNOWN") + "_" + (clean(protocol).upper() or "IP")


def reason_for(action, direction, protocol):
    """Build a lowercase human-readable reason from action, direction and protocol.

    :param action: PF action text.
    :param direction: PF direction text.
    :param protocol: Protocol name.
    :returns: Space-joined reason text.
    :rtype: str
    """
    parts = [clean(action).lower(), clean(direction).lower(), clean(protocol).lower(), "packet"]
    return " ".join(part for part in parts if part)


def build_raw_message_hash(physical_line):
    """Fingerprint the decoded physical source line without its terminator.

    :param physical_line: Decoded source line without newline terminators.
    :returns: Full SHA-256 hexadecimal digest.
    :rtype: str
    """
    return hashlib.sha256(
        physical_line.encode("utf-8", errors="replace")
    ).hexdigest()


def build_event_id(year_month, source_file, source_line, physical_line):
    """Identify one physical occurrence, not merely one distinct message.

    :param year_month: Partition month for the source file.
    :param source_file: Source path.
    :param source_line: One-based physical source line number.
    :param physical_line: Decoded source line without newline terminators.
    :returns: First 24 digest characters derived from month, path, line and content.
    :rtype: str
    """
    seed = "|".join([
        year_month,
        os.path.normcase(os.path.abspath(source_file)),
        str(source_line),
        build_raw_message_hash(physical_line),
    ])
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:24]


def populate_endpoint_event(event, protocol, event_type=None, reason=None):
    """Fill source/destination address, port and reason fields on a parsed event.

    :param event: Parsed event fields including source_endpoint and destination_endpoint.
    :param protocol: Protocol name.
    :param event_type: Optional explicit event type; derived from action/protocol otherwise.
    :param reason: Optional explicit reason; derived from action/direction/protocol otherwise.
    :returns: The same event dictionary, updated in place.
    :rtype: dict
    """
    source_ip, source_port, source_version = split_endpoint(event.get("source_endpoint"))
    destination_ip, destination_port, destination_version = split_endpoint(event.get("destination_endpoint"))
    event.update({
        "event_type": event_type or event_type_for(event.get("action"), protocol),
        "protocol": protocol,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "ip_version": source_version or destination_version,
        "reason": reason or reason_for(event.get("action"), event.get("direction"), protocol),
    })
    return event


def protocol_event_type(event, protocol, suffix=""):
    """Build an event-type label with an optional suffix for protocol variants.

    :param event: Parsed event fields.
    :param protocol: Protocol name.
    :param suffix: Optional suffix, such as _MALFORMED.
    :returns: Suffixed event type label.
    :rtype: str
    """
    base = event_type_for(event.get("action"), protocol)
    return base + suffix


def normalize_line_for_classification(line):
    """Repair a known truncated-length pattern before pattern matching.

    :param line: Stripped classification line.
    :returns: Line with a truncated length token rewritten, or the input unchanged.
    :rtype: str
    """
    if TRUNCATED_LENGTH_PATTERN.search(line):
        return TRUNCATED_LENGTH_PATTERN.sub(", length 0", line)
    return line


def classify_line(line):
    """Classify one PF log line into a structured event or an unknown event.

    :param line: Stripped classification line.
    :returns: Parsed event fields including event_type, reason and raw_message.
    :rtype: dict
    """
    raw_line = line
    line = normalize_line_for_classification(line)

    if SCRIPT_CD_PATTERN.match(line):
        return {"event_type": "PFLOG_SCRIPT_COMMAND", "reason": "pflog processing script command", "raw_message": raw_line}
    if SCRIPT_ECHO_PATTERN.match(line):
        return {"event_type": "PFLOG_SCRIPT_COMMAND", "reason": "pflog processing script command", "raw_message": raw_line}
    if SCRIPT_FINDSTR_PATTERN.match(line):
        return {"event_type": "PFLOG_SCRIPT_COMMAND", "reason": "pflog processing script command", "raw_message": raw_line}
    if HOST_MARKER_PATTERN.match(line):
        return {"event_type": "PFLOG_HOST_MARKER", "reason": "pflog inventory marker", "raw_message": raw_line}

    match = TCP_PACKET_PATTERN.match(line)
    if match:
        event = populate_endpoint_event(match.groupdict(), "tcp")
        event["raw_message"] = raw_line
        return event

    match = UDP_PACKET_PATTERN.match(line)
    if match:
        event = populate_endpoint_event(match.groupdict(), "udp")
        event["raw_message"] = raw_line
        return event

    match = ICMP_PACKET_PATTERN.match(line)
    if match:
        event = match.groupdict()
        source_ip, source_version = parse_ip(event.get("source_ip"))
        destination_ip, destination_version = parse_ip(event.get("destination_ip"))
        protocol = "icmp6" if clean(event.get("icmp_message")).lower().startswith("icmp6") else "icmp"
        event.update({"event_type": event_type_for(event.get("action"), protocol), "protocol": protocol, "source_ip": source_ip, "destination_ip": destination_ip, "ip_version": source_version or destination_version, "reason": reason_for(event.get("action"), event.get("direction"), protocol), "raw_message": raw_line})
        return event

    protocol_patterns = [
        (RIP_PACKET_PATTERN, "rip", None, "routing information protocol traffic"),
        (ISAKMP_PACKET_PATTERN, "isakmp", None, "ipsec ike negotiation traffic"),
        (DNS_INVALID_PATTERN, "dns", "_MALFORMED", "malformed dns packet"),
        (DHCP_PACKET_PATTERN, "dhcp", None, "dynamic host configuration traffic"),
        (SNMP_PACKET_PATTERN, "snmp", None, "snmp traffic"),
        (TFTP_PACKET_PATTERN, "tftp", None, "tftp file transfer traffic"),
    ]
    for pattern, protocol, suffix, reason in protocol_patterns:
        match = pattern.match(line)
        if match:
            event = match.groupdict()
            event_type = protocol_event_type(event, protocol, suffix or "")
            event = populate_endpoint_event(event, protocol, event_type, reason)
            event["raw_message"] = raw_line
            return event

    match = GENERIC_PACKET_PATTERN.match(line)
    if match:
        event = populate_endpoint_event(match.groupdict(), "ip")
        event["raw_message"] = raw_line
        return event

    match = PFLOG_PREFIX_PATTERN.match(line)
    if match:
        event = match.groupdict()
        event.update({"event_type": UNKNOWN_EVENT_TYPE, "reason": "unrecognized PF packet format", "raw_message": raw_line})
        return event

    return {"event_type": UNKNOWN_EVENT_TYPE, "reason": "unrecognized PF log prefix", "raw_message": raw_line}


def normalize_unknown_message(message):
    """Replace timestamps, endpoint-like strings and numbers for grouping.

    :param message: Raw unknown-event message.
    :returns: Lowercase normalized message with stable placeholders.
    :rtype: str
    """
    value = clean(message).lower()
    value = re.sub(r"\b\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", "{timestamp}", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:\.\d+)?\b", "{endpoint}", value)
    value = re.sub(r"(?<![a-f0-9:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]+(?:\.\d+)?", "{endpoint}", value, flags=re.IGNORECASE)
    value = re.sub(r"\b\d+\b", "{number}", value)
    return re.sub(r"\s+", " ", value).strip()


def prepare_output_row(
    event,
    year_month,
    source_file,
    source_line,
    physical_line,
    classification_line,
    extraction_lookup,
):
    """Normalize a classified event into one output CSV row with lineage fields.

    :param event: Parsed event fields returned by classify_line.
    :param year_month: Partition month for the source file.
    :param source_file: Source path.
    :param source_line: One-based physical source line number.
    :param physical_line: Decoded source line without newline terminators.
    :param classification_line: Stripped text supplied to the classifier.
    :param extraction_lookup: Archive and member metadata keyed by absolute extracted path.
    :returns: CSV-ready row dictionary with occurrence identity and source coordinates.
    :rtype: dict
    """
    row = {field: clean(event.get(field, "")) for field in OUTPUT_FIELDNAMES}
    extraction = extraction_lookup.get(os.path.abspath(source_file), {})
    row["event_id"] = build_event_id(year_month, source_file, source_line, physical_line)
    row["raw_message_sha256"] = build_raw_message_hash(physical_line)
    row["raw_message"] = physical_line
    row["classification_message"] = classification_line
    row["partition_month"] = year_month
    row["source_archive"] = clean(extraction.get("source_archive"))
    row["archive_member"] = clean(extraction.get("archive_member"))
    row["source_file"] = os.path.normpath(source_file)
    row["source_line"] = str(source_line)
    row["action"] = row["action"].lower()
    row["direction"] = row["direction"].lower()
    row["protocol"] = row["protocol"].lower()
    return row


def count_non_empty_lines(files):
    """Count non-blank lines across a list of source files.

    :param files: Source file paths for one month.
    :returns: Total non-empty physical lines.
    :rtype: int
    """
    total = 0
    for file_path in progress_items(files, "Files scanned for expected row counts"):
        with open(file_path, "r", encoding="utf-8", errors="replace", buffering=1024 * 1024, newline="") as handle:
            total += sum(1 for line in handle if line.strip())
    return total


def inspect_existing_output(output_file):
    """Read a previously classified monthly CSV's row and event-type counts.

    :param output_file: Monthly classified CSV path.
    :returns: Total row count and per-event-type counts.
    :rtype: tuple
    :raises ValueError: If the CSV has no header or lacks required columns.
    """
    row_count = 0
    event_counts = Counter()
    with open(output_file, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("CSV has no header: " + output_file)
        missing = set(OUTPUT_FIELDNAMES).difference(reader.fieldnames)
        if missing:
            raise ValueError("CSV is missing columns in " + output_file + ": " + ", ".join(sorted(missing)))
        for row in progress_items(reader, "Existing classified rows inspected"):
            row_count += 1
            event_counts[clean(row.get("event_type")) or UNKNOWN_EVENT_TYPE] += 1
    return row_count, event_counts


def add_unknown_group(groups, row):
    """Accumulate one unknown-event row into its normalized message group.

    :param groups: Mutable registry of normalized-message group statistics.
    :param row: Unknown-event row fields.
    :rtype: None
    """
    normalized = normalize_unknown_message(row.get("raw_message", ""))
    group = groups.setdefault(normalized, {"normalized_message": normalized, "count": 0, "first_timestamp": "", "last_timestamp": "", "months": set(), "source_archives": set(), "source_files": set(), "example_message": row.get("raw_message", "")})
    group["count"] += 1
    timestamp = row.get("timestamp", "")
    if timestamp and (not group["first_timestamp"] or timestamp < group["first_timestamp"]):
        group["first_timestamp"] = timestamp
    if timestamp and (not group["last_timestamp"] or timestamp > group["last_timestamp"]):
        group["last_timestamp"] = timestamp
    group["months"].add(row.get("partition_month", "unknown"))
    if clean(row.get("source_archive")):
        group["source_archives"].add(clean(row.get("source_archive")))
    group["source_files"].add(row.get("source_file", ""))


def write_unknown_summary(output_file, groups):
    """Write one row per normalized unknown-message group, most frequent first.

    :param output_file: Destination summary CSV path.
    :param groups: Normalized-message group statistics registry.
    :rtype: None
    """
    with open(output_file, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=UNKNOWN_SUMMARY_FIELDS)
        writer.writeheader()
        for item in sorted(groups.values(), key=lambda value: (-value["count"], value["normalized_message"])):
            writer.writerow({"normalized_message": item["normalized_message"], "count": str(item["count"]), "first_timestamp": item["first_timestamp"], "last_timestamp": item["last_timestamp"], "months": "|".join(sorted(item["months"])), "source_archives": "|".join(sorted(item["source_archives"])), "source_files": "|".join(sorted(item["source_files"])), "example_message": item["example_message"]})


@timed_stage
def rebuild_combined_unknown_outputs(files_by_month):
    """Rebuild the all-months unknown-event detail file and its summary.

    :param files_by_month: Source file path lists keyed by year-month.
    :returns: Combined detail and combined summary file paths.
    :rtype: tuple
    """
    combined_detail_file = os.path.join(OUTPUT_FOLDER, "unknown_pflog_events_all_months.csv")
    combined_summary_file = os.path.join(OUTPUT_FOLDER, "unknown_pflog_summary_all_months.csv")
    groups = {}
    with open(combined_detail_file, "w", encoding="utf-8", newline="", buffering=1024 * 1024) as target:
        writer = csv.DictWriter(target, fieldnames=UNKNOWN_DETAIL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for year_month in progress_items(sorted(files_by_month), "Months combined into unknown-event summary"):
            monthly_file = os.path.join(OUTPUT_FOLDER, "unknown_pflog_events_" + year_month + ".csv")
            if not os.path.isfile(monthly_file):
                continue
            with open(monthly_file, "r", encoding="utf-8-sig", errors="replace", newline="") as source:
                for row in csv.DictReader(source):
                    writer.writerow(row)
                    add_unknown_group(groups, {"timestamp": clean(row.get("timestamp")), "raw_message": clean(row.get("raw_message")), "partition_month": clean(row.get("partition_month")), "source_file": clean(row.get("source_file"))})
    write_unknown_summary(combined_summary_file, groups)
    return combined_detail_file, combined_summary_file


@timed_stage
def classify_month(year_month, files, extraction_lookup):
    """Classify every source line for one month into classified and unknown CSVs.

    :param year_month: Partition month being classified.
    :param files: Source file paths for this month.
    :param extraction_lookup: Archive and member metadata keyed by absolute extracted path.
    :returns: Month status, output file, total/unknown event counts and per-type counts.
    :rtype: dict
    :raises ValueError: If a duplicate event_id is generated or the written row count
        does not match the expected non-blank line count.
    """
    output_file = os.path.join(OUTPUT_FOLDER, "classified_pflog_events_" + year_month + ".csv")
    unknown_file = os.path.join(OUTPUT_FOLDER, "unknown_pflog_events_" + year_month + ".csv")
    unknown_summary_file = os.path.join(OUTPUT_FOLDER, "unknown_pflog_summary_" + year_month + ".csv")
    expected_rows = count_non_empty_lines(files)

    if SKIP_COMPLETED_MONTHS and os.path.isfile(output_file) and os.path.isfile(unknown_file) and os.path.isfile(unknown_summary_file):
        existing_rows, existing_counts = inspect_existing_output(output_file)
        if existing_rows == expected_rows:
            LOGGER.info("Skipping complete month %s: %s", year_month, output_file)
            return {"year_month": year_month, "status": "skipped", "output_file": output_file, "total_events": existing_rows, "event_counts": existing_counts, "unknown_events": existing_counts.get(UNKNOWN_EVENT_TYPE, 0)}

    event_counts = Counter()
    unknown_groups = {}
    batch = []
    unknown_batch = []
    total_events = 0
    seen_event_ids = set()

    with open(output_file, "w", encoding="utf-8", newline="", buffering=1024 * 1024) as output_handle, open(unknown_file, "w", encoding="utf-8", newline="", buffering=1024 * 1024) as unknown_handle:
        writer = csv.DictWriter(output_handle, fieldnames=OUTPUT_FIELDNAMES, extrasaction="ignore")
        unknown_writer = csv.DictWriter(unknown_handle, fieldnames=UNKNOWN_DETAIL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        unknown_writer.writeheader()

        for source_file in files:
            LOGGER.debug("Reading pflog: %s", source_file)
            with open(source_file, "r", encoding="utf-8", errors="replace", buffering=1024 * 1024, newline="") as source:
                for source_line, line in enumerate(
                    progress_items(source, year_month + " source lines processed"), start=1
                ):
                    physical_line = line.rstrip("\r\n")
                    if not physical_line.strip():
                        continue
                    classification_line = physical_line.strip()
                    row = prepare_output_row(
                        classify_line(classification_line),
                        year_month,
                        source_file,
                        source_line,
                        physical_line,
                        classification_line,
                        extraction_lookup,
                    )
                    if row["event_id"] in seen_event_ids:
                        raise ValueError("Duplicate event_id generated: " + row["event_id"])
                    seen_event_ids.add(row["event_id"])
                    batch.append(row)
                    event_counts[row["event_type"]] += 1
                    total_events += 1

                    if row["event_type"] == UNKNOWN_EVENT_TYPE:
                        unknown_row = {field: row.get(field, "") for field in UNKNOWN_DETAIL_FIELDS}
                        unknown_row["normalized_message"] = normalize_unknown_message(row["raw_message"])
                        unknown_batch.append(unknown_row)
                        add_unknown_group(unknown_groups, row)

                    if len(batch) >= WRITE_BATCH_SIZE:
                        writer.writerows(batch)
                        batch.clear()
                    if len(unknown_batch) >= WRITE_BATCH_SIZE:
                        unknown_writer.writerows(unknown_batch)
                        unknown_batch.clear()

        if batch:
            writer.writerows(batch)
        if unknown_batch:
            unknown_writer.writerows(unknown_batch)

    write_unknown_summary(unknown_summary_file, unknown_groups)
    if total_events != expected_rows:
        raise ValueError("PF log row-count mismatch for " + year_month + ": expected=" + str(expected_rows) + ", written=" + str(total_events))
    return {"year_month": year_month, "status": "classified", "output_file": output_file, "total_events": total_events, "event_counts": event_counts, "unknown_events": event_counts.get(UNKNOWN_EVENT_TYPE, 0)}


@timed_stage
def rebuild_event_lookup(files_by_month):
    """Create the authoritative event_id-to-raw-message lookup.

    :param files_by_month: Source file path lists keyed by year-month.
    :returns: Total rows written to the event lookup.
    :rtype: int
    :raises ValueError: If a classified file lacks lineage fields, has a blank
        event_id, or an event_id repeats across monthly files.
    """
    seen_event_ids = set()
    total_rows = 0
    with open(EVENT_LOOKUP_FILE, "w", encoding="utf-8", newline="", buffering=1024 * 1024) as target:
        writer = csv.DictWriter(target, fieldnames=EVENT_LOOKUP_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for year_month in progress_items(sorted(files_by_month), "Months merged into event lookup"):
            classified_file = os.path.join(OUTPUT_FOLDER, "classified_pflog_events_" + year_month + ".csv")
            if not os.path.isfile(classified_file):
                continue
            with open(classified_file, "r", encoding="utf-8-sig", errors="replace", newline="") as source:
                reader = csv.DictReader(source)
                missing = set(EVENT_LOOKUP_FIELDS).difference(reader.fieldnames or [])
                if missing:
                    raise ValueError("Classified CSV lacks lineage fields in " + classified_file + ": " + ", ".join(sorted(missing)))
                for row in reader:
                    event_id = clean(row.get("event_id"))
                    if not event_id:
                        raise ValueError("Blank event_id in " + classified_file)
                    if event_id in seen_event_ids:
                        raise ValueError("Duplicate event_id across monthly files: " + event_id)
                    seen_event_ids.add(event_id)
                    writer.writerow(row)
                    total_rows += 1
    return total_rows


def main():
    """Run PF log extraction, monthly classification and lookup rebuilding.

    :rtype: None
    """
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    extraction = extract_pflog_archives()
    LOGGER.info("PF log ZIP archives found: %s", extraction["archives_found"])
    LOGGER.info("PF log ZIP archives extracted: %s", extraction["archives_extracted"])
    LOGGER.info("PF log files extracted: %s", extraction["files_extracted"])
    LOGGER.info("PF log archive members skipped: %s", extraction["files_skipped"])

    files_by_month = find_pflog_files_by_month()
    if not files_by_month:
        LOGGER.error("No PF log files beginning with 'pflog' were found.")
        LOGGER.error("Expected: %s", os.path.join(EXTRACT_FOLDER, "YYYY-MM *", "**", "pflog*"))
        raise SystemExit(1)

    extraction_lookup = load_extraction_lookup()
    results = []
    for index, year_month in enumerate(sorted(files_by_month), 1):
        LOGGER.info("Month %s/%s: %s", index, len(files_by_month), year_month)
        result = classify_month(year_month, files_by_month[year_month], extraction_lookup)
        results.append(result)
        LOGGER.info("Month %s: events=%s, unknown=%s", year_month, result["total_events"], result["unknown_events"])

    combined_detail_file, combined_summary_file = rebuild_combined_unknown_outputs(files_by_month)
    event_lookup_rows = rebuild_event_lookup(files_by_month)
    LOGGER.info("PF log classification complete.")
    LOGGER.info("Months found: %s", len(results))
    LOGGER.info("Total events: %s", sum(item["total_events"] for item in results))
    LOGGER.info("Total unknown events: %s", sum(item["unknown_events"] for item in results))
    LOGGER.info("Extraction manifest: %s", EXTRACTION_MANIFEST_FILE)
    LOGGER.info("Event lookup rows: %s", event_lookup_rows)
    LOGGER.info("Event lookup: %s", EVENT_LOOKUP_FILE)
    LOGGER.info("Combined unknown details: %s", combined_detail_file)
    LOGGER.info("Combined unknown summary: %s", combined_summary_file)


if __name__ == "__main__":
    args = parse_args()
    INCLUDE_TMP = args.include_tmp
    runlog.configure_from(args)
    try:
        with runlog.run():
            main()
    except KeyboardInterrupt:                    # runlog.run() has logged it
        sys.exit(130)
    except Exception:
        LOGGER.exception("PF log classification failed")
        sys.exit(1)