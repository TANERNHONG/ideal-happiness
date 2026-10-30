"""Classify OSSEC text logs with end-to-end event lineage.

Each non-empty physical source line receives a stable occurrence ``event_id``,
a SHA-256 fingerprint, an exact ``original_log_line``, and archive/file/line
coordinates. Monthly normalized CSVs remain the modeling source, while
``data/phase1_classify/ossec/ossec_event_lookup.csv`` is the authoritative downstream evidence
lookup.

Command-line usage
------------------
Run with timestamped INFO checkpoints and ten-second activity updates::

    python pipeline/phase1_classify/ossec.py

Enable detailed file and batch messages and five-second updates::

    python pipeline/phase1_classify/ossec.py --verbose --progress-interval 5

Suppress routine progress with ``--quiet``. Both switches are mutually
exclusive. Use ``--help`` to view the logging options.

Runtime reporting
-----------------
Each log record includes elapsed time since module startup in ``HH:MM:SS.s``
format using ``time.monotonic()``. Timed stages report their own duration.
A background heartbeat reports the active stage during long reads, writes and
processing. Loop checkpoints also report item counts and throughput. CLI runs
report total runtime on completion, early return, errors and interruption.

.. note::

   Heartbeats indicate activity, not a percentage or an estimated finish time.
   They may be delayed by native code holding the interpreter lock. Abrupt
   process termination cannot emit a final summary. Quiet mode suppresses
   routine timing messages; warnings and errors remain visible.
   Imported callers can configure logging and use
   ``with runlog.run(): main()`` for the same runtime reporting.

Configuration
-------------
Folder and processing constants retain their original defaults. Paths are
relative to the working directory unless changed in the configuration section.
Raw unknown-message examples are included only with ``--verbose``.
"""

import time
import argparse
from pathlib import Path
import logging
import sys
import threading
from contextlib import contextmanager
from functools import wraps
import csv
import glob
import hashlib
import json
import os
import re
import shutil
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import progress_items, stage, timed_stage  # noqa: E402

LOGGER = runlog.LOGGER

INPUT_FOLDER = "data/phase0_raw/archives"
EXTRACT_FOLDER = "data/phase0_raw/ossec"
OUTPUT_FOLDER = "data/phase1_classify/ossec"
EXTRACTION_MANIFEST = os.path.join(EXTRACT_FOLDER, "extracted_osseclogs.csv")
PROCESSING_MANIFEST = os.path.join(OUTPUT_FOLDER, "processed_osseclogs.json")
COMBINED_UNKNOWN_SUMMARY = os.path.join(OUTPUT_FOLDER, "unknown_ossec_events_all_months.csv")
UNKNOWN_OCCURRENCES_FILE = os.path.join(OUTPUT_FOLDER, "unknown_ossec_event_occurrences_all_months.csv")
EVENT_LOOKUP_FILE = os.path.join(OUTPUT_FOLDER, "ossec_event_lookup.csv")
LINEAGE_SUMMARY_FILE = os.path.join(OUTPUT_FOLDER, "ossec_lineage_summary.json")
DEFAULT_YEAR = 2026
UNKNOWN_EVENT_TYPE = "OSSEC_UNKNOWN_EVENT"
CLASSIFIER_VERSION = "2026-09-18-lineage-01"
VALID_OSSEC_DIRECTORIES = {"ossec", "osseclog", "ossec_logs", "ossec-log", "ossec-logs"}


ARCHIVE_NAME_PATTERN = re.compile(r"^(?P<archive_year>\d{4})-(?P<archive_month>0[1-9]|1[0-2])\s+(?P<identifier_1>\S+)\s+(?P<identifier_2>.+)$")
MEMBER_HOST_PATTERN = re.compile(r"^ossec[_-]?logs?[_-](?P<host>.+?)(?:\.txt)?$", re.IGNORECASE)
LOG_PREFIX = r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<process_name>[A-Za-z0-9_.@+-]+)(?:\((?P<pid>\d+)\))?:\s+(?:(?P<severity>[A-Za-z0-9_-]+):\s+)?"
UNKNOWN_EVENT_PATTERN = re.compile(LOG_PREFIX + r"(?P<raw_message>.*)$")

PATTERNS = [
    ("OSSEC_ROOTCHECK_SCAN_STARTED", re.compile(LOG_PREFIX + r"Starting rootcheck scan\.?\s*$", re.IGNORECASE)),
    ("OSSEC_ROOTCHECK_SCAN_ENDED", re.compile(LOG_PREFIX + r"Ending rootcheck scan\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SYSCHECK_FORWARDING_SCAN_STARTED", re.compile(LOG_PREFIX + r"Starting syscheck scan\s+\((?P<scan_mode>forwarding database)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SYSCHECK_FORWARDING_SCAN_ENDED", re.compile(LOG_PREFIX + r"Ending syscheck scan\s+\((?P<scan_mode>forwarding database)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SYSCHECK_DATABASE_PRESCAN_STARTED", re.compile(LOG_PREFIX + r"Starting syscheck database\s+\((?P<scan_mode>pre-scan)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SYSCHECK_DATABASE_PRESCAN_COMPLETED", re.compile(LOG_PREFIX + r"Finished creating syscheck database\s+\((?P<scan_mode>pre-scan completed)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SYSCHECK_SCAN_STARTED", re.compile(LOG_PREFIX + r"Starting syscheck scan\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SYSCHECK_SCAN_ENDED", re.compile(LOG_PREFIX + r"Ending syscheck scan\.?\s*$", re.IGNORECASE)),
    ("OSSEC_PROCESS_STARTED", re.compile(LOG_PREFIX + r"Started\s+\(pid:\s*(?P<started_pid>\d+)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SIGNAL_RECEIVED_EXITING", re.compile(LOG_PREFIX + r"(?P<reason>SIGNAL Received)\.\s+(?P<operation>Exit Cleaning)\.{3}\s*$", re.IGNORECASE)),
    ("OSSEC_SHUTDOWN_RESPONSES_DELETED", re.compile(LOG_PREFIX + r"Shutdown received\.\s+(?P<operation>Deleting responses)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_EMAIL_DISABLED_CLEAN_EXIT", re.compile(LOG_PREFIX + r"(?P<reason>E-Mail notification disabled)\.\s+(?P<operation>Clean Exit)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_PROCESS_LOCKED", re.compile(LOG_PREFIX + r"(?P<reason>Process locked)\.\s+(?P<operation>Waiting for permission)\.{3}\s*$", re.IGNORECASE)),
    ("OSSEC_SERVER_UNAVAILABLE_LOCK_SET", re.compile(LOG_PREFIX + r"Server unavailable\.\s+Setting lock\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SERVER_RESPONDED_LOCK_RELEASED", re.compile(LOG_PREFIX + r"Server responded\.\s+Releasing lock\.?\s*$", re.IGNORECASE)),
    ("OSSEC_LOCK_FREE_CONTINUING", re.compile(LOG_PREFIX + r"Lock free\.\s+Continuing\.{3}\s*$", re.IGNORECASE)),
    ("OSSEC_SERVER_CONNECTED", re.compile(LOG_PREFIX + r"Connected to the server\s+\((?P<server_name>[^/()]+)/(?P<server_ip>[^:()]+):(?P<server_port>\d+)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SERVER_IP_CONFIGURED", re.compile(LOG_PREFIX + r"Server IP Address:\s+(?P<server_name>[^/\s]+)/(?P<server_ip>\S+?)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_WAITING_FOR_REPLY", re.compile(LOG_PREFIX + r"Waiting for server reply\s+\((?P<reason>[^)]+)\)\.\s+Tried:\s+'(?P<server_name>[^/']+)/(?P<server_ip>[^']+)'\.?\s*$", re.IGNORECASE)),
    ("OSSEC_NEXT_SERVER", re.compile(LOG_PREFIX + r"Trying next server ip in the line:\s+'(?P<server_name>[^/']+)/(?P<server_ip>[^']+)'\.?\s*$", re.IGNORECASE)),
    ("OSSEC_CONNECTION_CLOSED", re.compile(LOG_PREFIX + r"Closing connection to server\s+\((?P<server_name>[^/)]+)/(?P<server_ip>[^():\s]+):(?P<server_port>\d+)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_CONNECTION_ATTEMPT", re.compile(LOG_PREFIX + r"Trying to connect to server\s+\((?P<server_name>[^/)]+)/(?P<server_ip>[^():\s]+):(?P<server_port>\d+)\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_USING_IPV4", re.compile(LOG_PREFIX + r"Using IPv4 for:\s+(?P<server_ip>\S+?)\s*\.?\s*$", re.IGNORECASE)),
    ("OSSEC_AGENT_COUNTER_ASSIGNED", re.compile(LOG_PREFIX + r"Assigning counter for agent\s+(?P<agent_name>[^:]+):\s*'(?P<counter_value>[^']+)'\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SENDER_COUNTER_ASSIGNED", re.compile(LOG_PREFIX + r"Assigning sender counter:\s*(?P<counter_value>\S+?)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_EVENT_COUNTER_UPDATED", re.compile(LOG_PREFIX + r"Event count after\s+'(?P<event_threshold>\d+)':\s*(?P<previous_event_count>\d+)->(?P<current_event_count>\d+)\s+\((?P<retained_percentage>\d+(?:\.\d+)?)%\)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_DIRECTORY_MONITORING_STARTED", re.compile(LOG_PREFIX + r"Monitoring directory:\s+['\"](?P<monitored_path>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_AUTHENTICATION_KEYS_READING", re.compile(LOG_PREFIX + r"Reading authentication keys file\.?\s*$", re.IGNORECASE)),
    ("OSSEC_LOCAL_DECODER_READING", re.compile(LOG_PREFIX + r"Reading local decoder file\.?\s*$", re.IGNORECASE)),
    ("OSSEC_RULES_FILE_READING", re.compile(LOG_PREFIX + r"Reading rules file:\s+['\"](?P<rules_file>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_LOG_FILE_ANALYSIS_STARTED", re.compile(LOG_PREFIX + r"Analyzing file:\s+['\"](?P<analyzed_file>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_MANAGER_IP_NOT_SET", re.compile(LOG_PREFIX + r"Manager IP not set\.?\s*$", re.IGNORECASE)),
    ("OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE", re.compile(LOG_PREFIX + r"No previous counter available for\s+['\"](?P<agent_name>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_ACTIVE_RESPONSE_IP_ALLOWLIST_COUNT", re.compile(LOG_PREFIX + r"(?P<allowlist_count>\d+)\s+IPs?\s+in the white list for active response\.?\s*$", re.IGNORECASE)),
    ("OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLIST_COUNT", re.compile(LOG_PREFIX + r"(?P<allowlist_count>\d+)\s+Hostname\(s\)\s+in the white list for active response\.?\s*$", re.IGNORECASE)),
    ("OSSEC_ACTIVE_RESPONSE_IP_ALLOWLISTED", re.compile(LOG_PREFIX + r"White listing IP:\s+['\"](?P<allowlisted_ip>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLISTED", re.compile(LOG_PREFIX + r"White listing Hostname:\s+['\"](?P<allowlisted_hostname>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_EXEC_QUEUE_CONNECTED", re.compile(LOG_PREFIX + r"Connected to\s+['\"](?P<queue_path>[^'\"]+)['\"]\s+\((?P<queue_name>exec queue)\)\s*$", re.IGNORECASE)),
    ("OSSEC_RULES_ENABLED_TOTAL", re.compile(LOG_PREFIX + r"Total rules enabled:\s+['\"](?P<rules_enabled_count>\d+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_FILE_IGNORED", re.compile(LOG_PREFIX + r"Ignoring file:\s+['\"](?P<ignored_file>[^'\"]+)['\"]\.?\s*$", re.IGNORECASE)),
    ("OSSEC_ACTIVE_RESPONSE_COMMAND_UNAVAILABLE", re.compile(LOG_PREFIX + r"Active response command not present:\s+['\"](?P<command_path>[^'\"]+)['\"]\.\s+(?P<reason>Not using it on this system)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SERVER_MESSAGE_SEND_FAILED", re.compile(LOG_PREFIX + r"(?P<reason>Unable to send message to server)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_QUEUE_MESSAGE_SEND_FAILED", re.compile(LOG_PREFIX + r"(?P<reason>Error sending message to queue)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND", re.compile(LOG_PREFIX + r"File\s+['\"](?P<checksum_source_file>[^'\"]+)['\"]\s+not found\.\s+(?P<checksum_algorithm>MD5|SHA1)\s+checksum skipped\.?\s*$", re.IGNORECASE)),
    ("OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND", re.compile(LOG_PREFIX + r"No previous\s+(?P<checksum_algorithm>md5|sha1)\s+checksum found:\s+['\"](?P<checksum_file>[^'\"]+)['\"]\.\s+(?P<operation>Starting over)\.?\s*$", re.IGNORECASE)),
    ("OSSEC_SOCKET_ERROR_UNAVAILABLE", re.compile(LOG_PREFIX + r"(?P<operation>socketerr)\s+\((?P<reason>not available)\)\.?\s*$", re.IGNORECASE)),
]

DEFAULT_REASON_MAP = {
    "OSSEC_ROOTCHECK_SCAN_STARTED": "rootcheck scan started",
    "OSSEC_ROOTCHECK_SCAN_ENDED": "rootcheck scan ended",
    "OSSEC_SYSCHECK_FORWARDING_SCAN_STARTED": "syscheck forwarding-database scan started",
    "OSSEC_SYSCHECK_FORWARDING_SCAN_ENDED": "syscheck forwarding-database scan ended",
    "OSSEC_SYSCHECK_DATABASE_PRESCAN_STARTED": "syscheck database pre-scan started",
    "OSSEC_SYSCHECK_DATABASE_PRESCAN_COMPLETED": "syscheck database pre-scan completed",
    "OSSEC_SYSCHECK_SCAN_STARTED": "syscheck scan started",
    "OSSEC_SYSCHECK_SCAN_ENDED": "syscheck scan ended",
    "OSSEC_PROCESS_STARTED": "OSSEC process started",
    "OSSEC_SIGNAL_RECEIVED_EXITING": "termination signal received",
    "OSSEC_SHUTDOWN_RESPONSES_DELETED": "shutdown received and active responses deleted",
    "OSSEC_EMAIL_DISABLED_CLEAN_EXIT": "email notification disabled during clean exit",
    "OSSEC_PROCESS_LOCKED": "process locked while waiting for permission",
    "OSSEC_SERVER_UNAVAILABLE_LOCK_SET": "server unavailable and processing lock set",
    "OSSEC_SERVER_RESPONDED_LOCK_RELEASED": "server responded and processing lock released",
    "OSSEC_LOCK_FREE_CONTINUING": "processing lock is free",
    "OSSEC_SERVER_CONNECTED": "connected to OSSEC server",
    "OSSEC_SERVER_IP_CONFIGURED": "OSSEC server address configured",
    "OSSEC_WAITING_FOR_REPLY": "waiting for OSSEC server reply",
    "OSSEC_NEXT_SERVER": "trying next configured OSSEC server",
    "OSSEC_CONNECTION_CLOSED": "OSSEC server connection closed",
    "OSSEC_CONNECTION_ATTEMPT": "OSSEC server connection attempted",
    "OSSEC_USING_IPV4": "IPv4 selected for OSSEC server",
    "OSSEC_AGENT_COUNTER_ASSIGNED": "counter assigned to OSSEC agent",
    "OSSEC_SENDER_COUNTER_ASSIGNED": "OSSEC sender counter assigned",
    "OSSEC_EVENT_COUNTER_UPDATED": "OSSEC event counter updated",
    "OSSEC_DIRECTORY_MONITORING_STARTED": "directory monitoring started",
    "OSSEC_AUTHENTICATION_KEYS_READING": "authentication keys file reading started",
    "OSSEC_LOCAL_DECODER_READING": "local decoder file reading started",
    "OSSEC_RULES_FILE_READING": "OSSEC rules file reading started",
    "OSSEC_LOG_FILE_ANALYSIS_STARTED": "log file analysis started",
    "OSSEC_MANAGER_IP_NOT_SET": "OSSEC manager IP address is not configured",
    "OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE": "previous agent counter is unavailable",
    "OSSEC_ACTIVE_RESPONSE_IP_ALLOWLIST_COUNT": "active-response IP allowlist loaded",
    "OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLIST_COUNT": "active-response hostname allowlist loaded",
    "OSSEC_ACTIVE_RESPONSE_IP_ALLOWLISTED": "IP address added to the active-response allowlist",
    "OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLISTED": "hostname added to the active-response allowlist",
    "OSSEC_EXEC_QUEUE_CONNECTED": "connected to the active-response execution queue",
    "OSSEC_RULES_ENABLED_TOTAL": "OSSEC rules enabled",
    "OSSEC_FILE_IGNORED": "file excluded from OSSEC monitoring",
    "OSSEC_ACTIVE_RESPONSE_COMMAND_UNAVAILABLE": "active-response command is unavailable on this system",
    "OSSEC_SERVER_MESSAGE_SEND_FAILED": "unable to send message to the OSSEC server",
    "OSSEC_QUEUE_MESSAGE_SEND_FAILED": "unable to send message to the OSSEC queue",
    "OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND": "checksum source file not found and checksum calculation skipped",
    "OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND": "previous checksum unavailable and checksum tracking restarted",
    "OSSEC_SOCKET_ERROR_UNAVAILABLE": "socket error information is unavailable",
}

FIELDNAMES = [
    "event_id", "raw_line_sha256", "session_id", "timestamp", "hostname",
    "process_name", "pid", "severity", "event_type", "username",
    "source_ip", "source_port", "destination_hostname", "destination_ip",
    "destination_port", "authentication_method", "connection_stage",
    "scan_mode", "operation", "started_pid", "agent_name", "counter_value",
    "event_threshold", "previous_event_count", "current_event_count",
    "retained_percentage", "allowlist_count", "allowlisted_ip",
    "allowlisted_hostname", "queue_path", "queue_name", "rules_enabled_count",
    "monitored_path", "analyzed_file", "rules_file", "ignored_file",
    "command_path", "checksum_algorithm", "checksum_source_file",
    "checksum_file", "reason", "raw_message", "original_log_line",
    "classification_line", "partition_month", "source_file", "source_line",
    "archive_name", "archive_member",
]

monthly_output_files = {}
monthly_csv_writers = {}
monthly_event_counts = Counter()
event_type_counts = Counter()


def parse_args():
    """Parse verbosity and heartbeat interval settings.

    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    runlog.add_arguments(parser)
    args = parser.parse_args()
    return args


def clean_value(value):
    """Normalize a value to stripped text, mapping None to empty text.
    
    :param value: Value to normalize or interpret.
    :returns: Normalized text.
    :rtype: str
    """
    return str(value).strip() if value is not None else ""


def close_monthly_output_files():
    """Close every open monthly CSV handle in the processing registry.
    
    :rtype: None
    """
    for information in monthly_output_files.values():
        handle = information.get("handle")
        if handle and not handle.closed:
            handle.close()


def reset_processing_state():
    """Close handles and clear monthly writer and event-count registries.
    
    :rtype: None
    """
    close_monthly_output_files()
    monthly_output_files.clear()
    monthly_csv_writers.clear()
    monthly_event_counts.clear()
    event_type_counts.clear()


def get_archive_metadata(zip_path):
    """Parse archive year, month and host identifiers from its filename.
    
    :param zip_path: ZIP archive path.
    :returns: Archive metadata; unmatched names use DEFAULT_YEAR and empty identifiers.
    :rtype: dict
    """
    archive_name = os.path.basename(zip_path)
    match = ARCHIVE_NAME_PATTERN.fullmatch(os.path.splitext(archive_name)[0])
    if match is None:
        return {"archive_name": archive_name, "archive_year": DEFAULT_YEAR, "archive_month": "", "identifier_1": "", "identifier_2": ""}
    metadata = match.groupdict()
    metadata["archive_name"] = archive_name
    metadata["archive_year"] = int(metadata["archive_year"])
    metadata["archive_month"] = int(metadata["archive_month"])
    return metadata


def is_ossec_text_file(member_name):
    """Recognize log members inside a supported OSSEC directory.

    Archives up to 2026-04 name them ``osseclog_<host>.txt``; from 2026-05 they
    are extensionless (``ossec_log_<host>``), so both forms are accepted.

    :param member_name: Member path within the ZIP archive.
    :returns: True for an eligible archive member.
    :rtype: bool
    """
    member_path = PurePosixPath(member_name.replace("\\", "/"))
    return member_path.suffix.lower() in (".txt", "") and any(part.lower() in VALID_OSSEC_DIRECTORIES for part in member_path.parts)


def hostname_from_member(member_name):
    """Read the server name from an OSSEC member file name.

    OSSEC agent lines do not name their server; the file does:
    ``osseclog_<host>.txt`` (to 2026-04) or ``ossec_log_<host>`` (from 2026-05).
    The archive name ("2026-04 NSEWL SCS") was used before, which gave every
    event the same host.

    :param member_name: Member path within the ZIP archive.
    :returns: Lower-case host name, or "" when the name does not match.
    :rtype: str
    """
    match = MEMBER_HOST_PATTERN.match(PurePosixPath(clean_value(member_name).replace("\\", "/")).name)
    return match.group("host").lower() if match else ""


def create_manifest_key(archive_name, member_name):
    """Combine archive and normalized member names into an extraction key.
    
    :param archive_name: Archive filename.
    :param member_name: Member path within the ZIP archive.
    :returns: Manifest lookup key.
    :rtype: str
    """
    return archive_name + "|" + member_name.replace("\\", "/")


def load_extraction_manifest():
    """Read previously extracted members from the extraction manifest.
    
    :returns: Entries keyed by archive/member; empty if absent or header is incompatible.
    :rtype: dict
    """
    entries = {}
    if not os.path.isfile(EXTRACTION_MANIFEST):
        return entries
    with open(EXTRACTION_MANIFEST, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"archive_name", "archive_member", "destination", "crc", "file_size"}
        if reader.fieldnames is None or required.difference(reader.fieldnames):
            return entries
        for row in progress_items(reader, "CSV rows processed"):
            archive_name = clean_value(row.get("archive_name"))
            archive_member = clean_value(row.get("archive_member")).replace("\\", "/")
            if archive_name and archive_member:
                entries[create_manifest_key(archive_name, archive_member)] = {
                    "archive_name": archive_name,
                    "archive_member": archive_member,
                    "destination": clean_value(row.get("destination")),
                    "crc": clean_value(row.get("crc")),
                    "file_size": clean_value(row.get("file_size")),
                }
    return entries


def rewrite_extraction_manifest(entries):
    """Write extraction metadata to a temporary CSV and replace the manifest.
    
    :param entries: Extraction manifest entries indexed by archive/member key.
    :rtype: None
    """
    temporary_manifest = EXTRACTION_MANIFEST + ".tmp"
    with open(temporary_manifest, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["archive_name", "archive_member", "destination", "crc", "file_size"])
        writer.writeheader()
        for key in sorted(entries):
            writer.writerow(entries[key])
    os.replace(temporary_manifest, EXTRACTION_MANIFEST)


def get_unique_destination(folder, filename):
    """Choose an unused filename, appending a numeric suffix when needed.
    
    :param folder: Destination directory.
    :param filename: Preferred output filename.
    :returns: Available destination path; the path is not reserved.
    :rtype: str
    """
    destination = os.path.join(folder, filename)
    if not os.path.exists(destination):
        return destination
    stem, extension = os.path.splitext(filename)
    counter = 1
    while True:
        candidate = os.path.join(folder, stem + "_" + str(counter) + extension)
        if not os.path.exists(candidate):
            return candidate
        counter += 1


@timed_stage
def extract_osseclogs_from_zip(zip_path, manifest_entries):
    """Extract eligible logs or reuse matching CRC and size manifest entries.
    
    :param zip_path: ZIP archive path.
    :param manifest_entries: Mutable extraction registry updated when new files are extracted.
    :returns: Extracted-file metadata list. Archive errors are logged and partial results retained.
    :rtype: list
    """
    extracted_files = []
    metadata = get_archive_metadata(zip_path)
    folder = os.path.join(EXTRACT_FOLDER, os.path.splitext(metadata["archive_name"])[0])
    os.makedirs(folder, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in progress_items(archive.infolist(), "Archive members examined"):
                if member.is_dir() or not is_ossec_text_file(member.filename):
                    continue
                member_name = member.filename.replace("\\", "/")
                filename = PurePosixPath(member_name).name
                key = create_manifest_key(metadata["archive_name"], member_name)
                record = manifest_entries.get(key, {})
                recorded_path = clean_value(record.get("destination"))
                record_matches = recorded_path and os.path.isfile(recorded_path) and clean_value(record.get("crc")) == str(member.CRC) and clean_value(record.get("file_size")) == str(member.file_size)
                if record_matches:
                    destination = recorded_path
                    status = "ALREADY_EXTRACTED"
                else:
                    destination = get_unique_destination(folder, filename)
                    temporary_destination = destination + ".tmp"
                    with archive.open(member, "r") as source, open(temporary_destination, "wb") as target:
                        shutil.copyfileobj(source, target)
                    os.replace(temporary_destination, destination)
                    manifest_entries[key] = {"archive_name": metadata["archive_name"], "archive_member": member_name, "destination": destination, "crc": str(member.CRC), "file_size": str(member.file_size)}
                    status = "EXTRACTED"
                LOGGER.debug("%s: %s", status, destination)
                extracted_files.append({"file_path": destination, "archive_member": member_name, "archive_name": metadata["archive_name"], "archive_year": metadata["archive_year"], "archive_month": metadata["archive_month"], "identifier_1": metadata["identifier_1"], "identifier_2": metadata["identifier_2"], "extraction_status": status})
    except (zipfile.BadZipFile, PermissionError, OSError) as error:
        LOGGER.error("Could not process " + zip_path + ": " + str(error))
    return extracted_files


def normalize_timestamp(timestamp_text):
    """Convert the OSSEC timestamp format to normalized date/time text.
    
    :param timestamp_text: OSSEC timestamp text.
    :returns: Formatted timestamp, empty text, or unchanged input if parsing fails.
    :rtype: str
    """
    timestamp_text = clean_value(timestamp_text)
    if not timestamp_text:
        return ""
    try:
        return datetime.strptime(timestamp_text, "%Y/%m/%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp_text


def extract_raw_message(line):
    """Remove a recognized OSSEC prefix from a classification line.
    
    :param line: Classification input line.
    :returns: Stripped payload, or the stripped full line when no prefix matches.
    :rtype: str
    """
    match = UNKNOWN_EVENT_PATTERN.match(line)
    return match.group("raw_message").strip() if match else line.strip()


def raw_line_sha256(physical_line):
    """Fingerprint the decoded physical source line without its terminator.
    
    :param physical_line: Decoded source line without newline terminators.
    :returns: Full SHA-256 hexadecimal digest.
    :rtype: str
    """
    return hashlib.sha256(
        physical_line.encode("utf-8", errors="replace")
    ).hexdigest()


def create_event_id(extracted_file, file_path, line_number, physical_line):
    """Create a stable identity for one physical source-line occurrence.
    
    :param extracted_file: Source metadata returned during extraction.
    :param file_path: Source path.
    :param line_number: One-based physical source line number.
    :param physical_line: Decoded source line without newline terminators.
    :returns: First 24 digest characters derived from archive, member, source path, line and content.
    :rtype: str
    """
    archive_name = clean_value(extracted_file.get("archive_name"))
    archive_member = clean_value(extracted_file.get("archive_member")).replace("\\", "/")
    source_reference = os.path.relpath(file_path, EXTRACT_FOLDER).replace(os.sep, "/")
    seed = "|".join([
        archive_name,
        archive_member,
        source_reference,
        str(line_number),
        raw_line_sha256(physical_line),
    ])
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:24]


def create_session_id(event, extracted_file, file_path, line_number):
    """Group events using archive month, host, process, source and PID.
    
    :param event: Parsed event fields.
    :param extracted_file: Source metadata returned during extraction.
    :param file_path: Source path.
    :param line_number: One-based physical source line number.
    :returns: Session identifier; a line-number suffix is used when PID is absent.
    :rtype: str
    """
    timestamp = event.get("timestamp", "")
    hostname = hostname_from_member(extracted_file.get("archive_member")) or "unknown-host"
    process_name = clean_value(event.get("process_name")).lower() or "unknown-process"
    pid = clean_value(event.get("pid"))
    source_reference = os.path.relpath(file_path, EXTRACT_FOLDER).replace(os.sep, "/")
    try:
        year_month = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m")
    except (TypeError, ValueError):
        year = extracted_file.get("archive_year") or DEFAULT_YEAR
        month = extracted_file.get("archive_month")
        year_month = str(year) + "-" + str(month).zfill(2) if str(month).isdigit() and 1 <= int(month) <= 12 else str(year) + "-unknown"
    suffix = "pid-" + pid if pid else "line-" + str(line_number)
    return year_month + ":ossec:" + hostname + ":" + process_name + ":" + source_reference + ":" + suffix


def prepare_output_event(event, extracted_file, file_path, line_number, physical_line, classification_line):
    """Normalize event fields and attach exact-line provenance.
    
    :param event: Parsed event fields.
    :param extracted_file: Source metadata returned during extraction.
    :param file_path: Source path.
    :param line_number: One-based physical source line number.
    :param physical_line: Decoded source line without newline terminators.
    :param classification_line: Stripped text supplied to the classifier.
    :returns: CSV-ready event dictionary with occurrence identity and source coordinates.
    :rtype: dict
    """
    normalized = {key: clean_value(value) for key, value in event.items()}
    normalized["timestamp"] = normalize_timestamp(normalized.get("timestamp"))
    normalized["process_name"] = normalized.get("process_name", "").lower()
    normalized["severity"] = normalized.get("severity", "").upper()
    normalized["server_name"] = normalized.get("server_name", "").strip("'\"")
    normalized["server_ip"] = normalized.get("server_ip", "").strip("'\"").rstrip(".")
    normalized["server_port"] = normalized.get("server_port", "").rstrip(".")
    normalized["source_ip"] = normalized.get("source_ip", "").strip("'\"").rstrip(".")
    normalized["source_port"] = normalized.get("source_port", "").rstrip(".")
    normalized["agent_name"] = normalized.get("agent_name", "").strip("'\"").lower()
    normalized["allowlisted_ip"] = normalized.get("allowlisted_ip", "").strip("'\"").rstrip(".")
    normalized["allowlisted_hostname"] = normalized.get("allowlisted_hostname", "").strip("'\"").lower()
    normalized["queue_path"] = normalized.get("queue_path", "").strip("'\"")
    normalized["ignored_file"] = normalized.get("ignored_file", "").strip("'\"")
    normalized["command_path"] = normalized.get("command_path", "").strip("'\"")
    normalized["checksum_algorithm"] = normalized.get("checksum_algorithm", "").lower()
    normalized["checksum_source_file"] = normalized.get("checksum_source_file", "").strip("'\"")
    normalized["checksum_file"] = normalized.get("checksum_file", "").strip("'\"")
    event_type = normalized.get("event_type", UNKNOWN_EVENT_TYPE)
    reason = normalized.get("reason", "") or ("no configured OSSEC pattern matched" if event_type == UNKNOWN_EVENT_TYPE else DEFAULT_REASON_MAP.get(event_type, ""))
    timestamp_text = normalized.get("timestamp", "")
    partition_month = ""
    try:
        partition_month = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m")
    except (TypeError, ValueError):
        year = extracted_file.get("archive_year") or DEFAULT_YEAR
        month = extracted_file.get("archive_month")
        partition_month = str(year) + "-" + str(month).zfill(2) if str(month).isdigit() and 1 <= int(month) <= 12 else str(year) + "-unknown"
    return {
        "event_id": create_event_id(extracted_file, file_path, line_number, physical_line),
        "raw_line_sha256": raw_line_sha256(physical_line),
        "session_id": create_session_id(normalized, extracted_file, file_path, line_number),
        "timestamp": normalized.get("timestamp", ""),
        "hostname": hostname_from_member(extracted_file.get("archive_member")),
        "process_name": normalized.get("process_name", ""),
        "pid": normalized.get("pid", ""),
        "severity": normalized.get("severity", ""),
        "event_type": event_type,
        "username": normalized.get("username", ""),
        "source_ip": normalized.get("source_ip", ""),
        "source_port": normalized.get("source_port", ""),
        "destination_hostname": normalized.get("server_name", ""),
        "destination_ip": normalized.get("server_ip", ""),
        "destination_port": normalized.get("server_port", ""),
        "authentication_method": normalized.get("authentication_method", ""),
        "connection_stage": normalized.get("connection_stage", ""),
        "scan_mode": normalized.get("scan_mode", ""),
        "operation": normalized.get("operation", ""),
        "started_pid": normalized.get("started_pid", ""),
        "agent_name": normalized.get("agent_name", ""),
        "counter_value": normalized.get("counter_value", ""),
        "event_threshold": normalized.get("event_threshold", ""),
        "previous_event_count": normalized.get("previous_event_count", ""),
        "current_event_count": normalized.get("current_event_count", ""),
        "retained_percentage": normalized.get("retained_percentage", ""),
        "monitored_path": normalized.get("monitored_path", ""),
        "analyzed_file": normalized.get("analyzed_file", ""),
        "rules_file": normalized.get("rules_file", ""),
        "allowlist_count": normalized.get("allowlist_count", ""),
        "allowlisted_ip": normalized.get("allowlisted_ip", ""),
        "allowlisted_hostname": normalized.get("allowlisted_hostname", ""),
        "queue_path": normalized.get("queue_path", ""),
        "queue_name": normalized.get("queue_name", ""),
        "rules_enabled_count": normalized.get("rules_enabled_count", ""),
        "ignored_file": normalized.get("ignored_file", ""),
        "command_path": normalized.get("command_path", ""),
        "checksum_algorithm": normalized.get("checksum_algorithm", ""),
        "checksum_source_file": normalized.get("checksum_source_file", ""),
        "checksum_file": normalized.get("checksum_file", ""),
        "reason": reason,
        "raw_message": normalized.get("raw_message", ""),
        "original_log_line": physical_line,
        "classification_line": classification_line,
        "partition_month": partition_month,
        "source_file": os.path.relpath(file_path, EXTRACT_FOLDER).replace(os.sep, "/"),
        "source_line": str(line_number),
        "archive_name": clean_value(extracted_file.get("archive_name")),
        "archive_member": clean_value(extracted_file.get("archive_member")),
    }


def get_monthly_writer(event_year, event_month):
    """Create or reuse a temporary CSV writer for one event month.
    
    :param event_year: Event year or archive-derived fallback.
    :param event_month: Event month or archive-derived fallback.
    :returns: CSV writer and month key.
    :rtype: tuple
    """
    try:
        year = int(event_year)
    except (TypeError, ValueError):
        year = DEFAULT_YEAR
    try:
        month = int(event_month)
    except (TypeError, ValueError):
        month = 0
    month_key = str(year) + "-" + str(month).zfill(2) if 1 <= month <= 12 else str(year) + "-unknown"
    if month_key not in monthly_csv_writers:
        final_path = os.path.join(OUTPUT_FOLDER, "ossec_events_" + month_key + ".csv")
        temporary_path = final_path + ".tmp"
        output_handle = open(temporary_path, "w", newline="", encoding="utf-8")
        writer = csv.DictWriter(output_handle, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        monthly_output_files[month_key] = {"handle": output_handle, "path": final_path, "temporary_path": temporary_path}
        monthly_csv_writers[month_key] = writer
        LOGGER.info("Creating monthly output: " + final_path)
    return monthly_csv_writers[month_key], month_key


def write_event(event, extracted_file, file_path, line_number, physical_line, classification_line):
    """Write one normalized event and update monthly and event-type counts.
    
    :param event: Parsed event fields.
    :param extracted_file: Source metadata returned during extraction.
    :param file_path: Source path.
    :param line_number: One-based physical source line number.
    :param physical_line: Decoded source line without newline terminators.
    :param classification_line: Stripped text supplied to the classifier.
    :rtype: None
    """
    output_event = prepare_output_event(event, extracted_file, file_path, line_number, physical_line, classification_line)
    try:
        parsed_timestamp = datetime.strptime(output_event["timestamp"], "%Y-%m-%d %H:%M:%S")
        event_year = parsed_timestamp.year
        event_month = parsed_timestamp.month
    except (TypeError, ValueError):
        event_year = extracted_file.get("archive_year", DEFAULT_YEAR)
        event_month = extracted_file.get("archive_month", "")
    writer, month_key = get_monthly_writer(event_year, event_month)
    writer.writerow(output_event)
    monthly_event_counts[month_key] += 1
    event_type_counts[output_event["event_type"]] += 1


@timed_stage
def commit_monthly_output_files():
    """Close temporary monthly files and replace their final destinations.
    
    :rtype: None
    
    .. note::
    
       Each file replacement is atomic; the group is not one transaction.
    """
    close_monthly_output_files()
    for information in monthly_output_files.values():
        os.replace(information["temporary_path"], information["path"])


def discard_temporary_output_files():
    """Close monthly handles and remove remaining temporary outputs.
    
    :rtype: None
    """
    close_monthly_output_files()
    for information in monthly_output_files.values():
        temporary_path = information.get("temporary_path", "")
        if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)


def remove_stale_monthly_outputs():
    """Remove monthly CSVs that are absent from the current output registry.
    
    :rtype: None
    """
    current_paths = {os.path.abspath(information["path"]) for information in monthly_output_files.values()}
    for output_path in glob.glob(os.path.join(OUTPUT_FOLDER, "ossec_events_*.csv")):
        if os.path.abspath(output_path) not in current_paths:
            os.remove(output_path)


@timed_stage
def parse_ossec_file(file_path, extracted_file):
    """Classify each non-blank source line and write lineage-bearing events.
    
    :param file_path: Source path.
    :param extracted_file: Source metadata returned during extraction.
    :returns: Known, unknown and total event counts.
    :rtype: tuple
    :raises ValueError: If parsing or identity validation fails.
    """
    known_count = 0
    unknown_count = 0
    total_count = 0
    seen_event_ids = set()
    with open(file_path, "r", encoding="utf-8", errors="replace", newline="") as ossec_log:
        for line_number, line in enumerate(progress_items(ossec_log, "Source lines processed"), start=1):
            physical_line = line.rstrip("\r\n")
            if not physical_line.strip():
                continue
            classification_line = physical_line.strip()
            for event_type, pattern in PATTERNS:
                match = pattern.match(classification_line)
                if match is None:
                    continue
                event = match.groupdict()
                event["event_type"] = event_type
                event["raw_message"] = extract_raw_message(classification_line)
                event_id = create_event_id(extracted_file, file_path, line_number, physical_line)
                if event_id in seen_event_ids:
                    raise ValueError("Duplicate OSSEC event_id generated in " + file_path + ": " + event_id)
                seen_event_ids.add(event_id)
                write_event(event, extracted_file, file_path, line_number, physical_line, classification_line)
                known_count += 1
                total_count += 1
                break
            else:
                unknown_match = UNKNOWN_EVENT_PATTERN.match(classification_line)
                event = unknown_match.groupdict() if unknown_match else {
                    "timestamp": "", "process_name": "", "pid": "",
                    "severity": "", "raw_message": classification_line,
                }
                event["event_type"] = UNKNOWN_EVENT_TYPE
                event_id = create_event_id(extracted_file, file_path, line_number, physical_line)
                if event_id in seen_event_ids:
                    raise ValueError("Duplicate OSSEC event_id generated in " + file_path + ": " + event_id)
                seen_event_ids.add(event_id)
                write_event(event, extracted_file, file_path, line_number, physical_line, classification_line)
                unknown_count += 1
                total_count += 1
    LOGGER.info("Classified %s: total=%s, known=%s, unknown=%s", file_path, total_count, known_count, unknown_count)
    return known_count, unknown_count, total_count


@timed_stage
def calculate_source_signature(extracted_files):
    """Hash classifier version and sorted source names, sizes and modification times.
    
    :param extracted_files: List of extracted-file metadata dictionaries.
    :returns: Source-state SHA-256 digest; source contents are not read for this signature.
    :rtype: str
    """
    digest = hashlib.sha256()
    digest.update(CLASSIFIER_VERSION.encode("utf-8"))
    for item in sorted(extracted_files, key=lambda value: (value["archive_name"], value["archive_member"])):
        stat = os.stat(item["file_path"])
        digest.update(item["archive_name"].encode("utf-8", errors="replace"))
        digest.update(item["archive_member"].encode("utf-8", errors="replace"))
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
    return digest.hexdigest()


def load_processing_manifest():
    """Load the last processing manifest when readable and valid JSON.
    
    :returns: Manifest dictionary, or an empty dictionary.
    :rtype: dict
    """
    if not os.path.isfile(PROCESSING_MANIFEST):
        return {}
    try:
        with open(PROCESSING_MANIFEST, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


@timed_stage
def outputs_are_complete(manifest, source_signature):
    """Check classifier/source signatures, required headers and stored row counts.
    
    :param manifest: Previously recorded processing metadata.
    :param source_signature: Digest representing current source state and classifier version.
    :returns: True if all manifest-listed outputs pass the existing completion checks.
    :rtype: bool
    """
    if manifest.get("classifier_version") != CLASSIFIER_VERSION or manifest.get("source_signature") != source_signature:
        return False
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict) or not outputs:
        return False
    for information in outputs.values():
        output_path = clean_value(information.get("path"))
        expected_rows = information.get("rows")
        if not output_path or not os.path.isfile(output_path):
            return False
        try:
            with open(output_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None or set(FIELDNAMES).difference(reader.fieldnames):
                    return False
                actual_rows = sum(1 for _ in progress_items(reader, "Existing CSV rows checked"))
            if actual_rows != expected_rows:
                return False
        except (OSError, csv.Error, TypeError, ValueError):
            return False
    return True


def write_processing_manifest(source_signature):
    """Atomically record current source signature and monthly output row counts.
    
    :param source_signature: Digest representing current source state and classifier version.
    :rtype: None
    """
    data = {"classifier_version": CLASSIFIER_VERSION, "source_signature": source_signature, "outputs": {month_key: {"path": monthly_output_files[month_key]["path"], "rows": monthly_event_counts[month_key]} for month_key in sorted(monthly_output_files)}}
    temporary_manifest = PROCESSING_MANIFEST + ".tmp"
    with open(temporary_manifest, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary_manifest, PROCESSING_MANIFEST)


# =============================================================================
# Unknown-message aggregation
# =============================================================================

def get_month_key_from_classified_file(classified_file):
    """Extract a month key from a classified monthly filename.
    
    :param classified_file: Monthly classified CSV filename.
    :returns: Parsed month key or None for an unrecognized filename.
    :rtype: str or None
    """
    filename = os.path.basename(classified_file)
    prefix = "ossec_events_"
    suffix = ".csv"
    if not filename.startswith(prefix) or not filename.endswith(suffix):
        return None
    return filename[len(prefix):-len(suffix)]


@timed_stage
def read_unknown_ossec_events(classified_file):
    """Read unknown-event occurrences with source and archive references.
    
    :param classified_file: Monthly classified CSV filename.
    :returns: Unknown-event dictionaries.
    :rtype: list
    :raises ValueError: If parsing or identity validation fails.
    """
    unknown_events = []
    with open(classified_file, "r", encoding="utf-8-sig", errors="replace", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError("CSV file has no header: " + classified_file)
        required_columns = {"event_type", "raw_message", "timestamp", "hostname", "process_name", "pid", "severity", "source_file", "source_line", "archive_name", "archive_member"}
        missing_columns = required_columns.difference(reader.fieldnames)
        if missing_columns:
            raise ValueError("Missing required columns in " + classified_file + ": " + ", ".join(sorted(missing_columns)))
        for row in progress_items(reader, "CSV rows processed"):
            if clean_value(row.get("event_type")) != UNKNOWN_EVENT_TYPE:
                continue
            raw_message = clean_value(row.get("raw_message")) or "<EMPTY_RAW_MESSAGE>"
            unknown_events.append({
                "timestamp": clean_value(row.get("timestamp")),
                "hostname": clean_value(row.get("hostname")),
                "process_name": clean_value(row.get("process_name")),
                "pid": clean_value(row.get("pid")),
                "severity": clean_value(row.get("severity")),
                "raw_message": raw_message,
                "source_file": clean_value(row.get("source_file")),
                "source_line": clean_value(row.get("source_line")),
                "archive_name": clean_value(row.get("archive_name")),
                "archive_member": clean_value(row.get("archive_member")),
                "monthly_file": classified_file,
            })
    return unknown_events


def write_unknown_ossec_summary(month_key, unknown_events):
    """Write message frequencies for unknown events in one month.
    
    :param month_key: Month identifier used in the output filename.
    :param unknown_events: Unknown-event occurrence dictionaries.
    :returns: Summary path, occurrence count, unique-message count and blank-message count.
    :rtype: dict
    """
    unknown_counts = Counter(event["raw_message"] for event in unknown_events)
    output_file = os.path.join(OUTPUT_FOLDER, "unknown_ossec_events_" + month_key + ".csv")
    temporary_file = output_file + ".tmp"
    with open(temporary_file, "w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target)
        writer.writerow(["raw_message", "count"])
        for raw_message, count in unknown_counts.most_common():
            writer.writerow([raw_message, count])
    os.replace(temporary_file, output_file)
    return {"path": output_file, "unknown_rows": len(unknown_events), "unique_unknown_messages": len(unknown_counts), "blank_messages": unknown_counts.get("<EMPTY_RAW_MESSAGE>", 0)}


def write_combined_unknown_occurrences(unknown_events):
    """Write all unknown-event occurrences in deterministic source order.
    
    :param unknown_events: Unknown-event occurrence dictionaries.
    :returns: Combined occurrence CSV path.
    :rtype: str
    """
    fieldnames = ["timestamp", "hostname", "process_name", "pid", "severity", "raw_message", "source_file", "source_line", "archive_name", "archive_member", "monthly_file"]
    temporary_file = UNKNOWN_OCCURRENCES_FILE + ".tmp"
    with open(temporary_file, "w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for event in sorted(unknown_events, key=lambda item: (item["timestamp"], item["hostname"], item["process_name"], item["source_file"], item["source_line"])):
            writer.writerow(event)
    os.replace(temporary_file, UNKNOWN_OCCURRENCES_FILE)
    return UNKNOWN_OCCURRENCES_FILE


def write_combined_unknown_summary(unknown_events):
    """Aggregate unknown-message counts and observed hosts, processes and times.
    
    :param unknown_events: Unknown-event occurrence dictionaries.
    :returns: Combined summary path and sorted summary rows.
    :rtype: tuple
    """
    message_statistics = {}
    for event in unknown_events:
        raw_message = event["raw_message"]
        statistics = message_statistics.setdefault(raw_message, {"raw_message": raw_message, "count": 0, "timestamps": [], "months": set(), "hostnames": set(), "processes": set(), "severities": set()})
        statistics["count"] += 1
        timestamp = event["timestamp"]
        if timestamp:
            statistics["timestamps"].append(timestamp)
            if len(timestamp) >= 7:
                statistics["months"].add(timestamp[:7])
        else:
            month_key = get_month_key_from_classified_file(event["monthly_file"])
            if month_key:
                statistics["months"].add(month_key)
        if event["hostname"]:
            statistics["hostnames"].add(event["hostname"])
        if event["process_name"]:
            statistics["processes"].add(event["process_name"])
        if event["severity"]:
            statistics["severities"].add(event["severity"])
    output_rows = []
    for statistics in message_statistics.values():
        timestamps = sorted(statistics["timestamps"])
        months = sorted(statistics["months"])
        hostnames = sorted(statistics["hostnames"])
        processes = sorted(statistics["processes"])
        severities = sorted(statistics["severities"])
        output_rows.append({
            "raw_message": statistics["raw_message"],
            "count": statistics["count"],
            "first_seen": timestamps[0] if timestamps else "",
            "last_seen": timestamps[-1] if timestamps else "",
            "months_seen": "|".join(months),
            "month_count": len(months),
            "hostnames_seen": "|".join(hostnames),
            "hostname_count": len(hostnames),
            "processes_seen": "|".join(processes),
            "process_count": len(processes),
            "severities_seen": "|".join(severities),
            "severity_count": len(severities),
        })
    output_rows.sort(key=lambda item: (-item["count"], item["raw_message"].lower()))
    fieldnames = ["raw_message", "count", "first_seen", "last_seen", "months_seen", "month_count", "hostnames_seen", "hostname_count", "processes_seen", "process_count", "severities_seen", "severity_count"]
    temporary_file = COMBINED_UNKNOWN_SUMMARY + ".tmp"
    with open(temporary_file, "w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(output_rows)
    os.replace(temporary_file, COMBINED_UNKNOWN_SUMMARY)
    return COMBINED_UNKNOWN_SUMMARY, output_rows


@timed_stage
def create_unknown_ossec_summaries():
    """Rebuild monthly and combined unknown-message reports and remove stale summaries.
    
    :returns: Summary filenames, aggregate counts and combined message rows.
    :rtype: dict
    """
    summary_files = {}
    all_unknown_events = []
    expected_monthly_summary_paths = set()
    for classified_file in sorted(glob.glob(os.path.join(OUTPUT_FOLDER, "ossec_events_*.csv"))):
        month_key = get_month_key_from_classified_file(classified_file)
        if not month_key:
            continue
        unknown_events = read_unknown_ossec_events(classified_file)
        summary = write_unknown_ossec_summary(month_key, unknown_events)
        summary_files[month_key] = summary
        expected_monthly_summary_paths.add(os.path.abspath(summary["path"]))
        all_unknown_events.extend(unknown_events)
    for output_file in glob.glob(os.path.join(OUTPUT_FOLDER, "unknown_ossec_events_*.csv")):
        absolute_output_file = os.path.abspath(output_file)
        if absolute_output_file == os.path.abspath(COMBINED_UNKNOWN_SUMMARY):
            continue
        if absolute_output_file not in expected_monthly_summary_paths:
            os.remove(output_file)
    combined_summary_file, combined_rows = write_combined_unknown_summary(all_unknown_events)
    occurrences_file = write_combined_unknown_occurrences(all_unknown_events)
    return {
        "monthly_summaries": summary_files,
        "combined_summary_file": combined_summary_file,
        "occurrences_file": occurrences_file,
        "unknown_rows": len(all_unknown_events),
        "unique_unknown_messages": len(combined_rows),
        "blank_messages": sum(1 for event in all_unknown_events if event["raw_message"] == "<EMPTY_RAW_MESSAGE>"),
        "combined_rows": combined_rows,
    }


def print_unknown_summary_results(summary_results):
    """Log summary counts at INFO and example raw messages at DEBUG.
    
    :param summary_results: Summary metadata and message frequencies.
    :rtype: None
    """
    LOGGER.info("Unknown-event summary files:")
    if summary_results["monthly_summaries"]:
        for month_key in sorted(summary_results["monthly_summaries"]):
            summary = summary_results["monthly_summaries"][month_key]
            LOGGER.info("%s: %s unknown events, %s unique messages, %s blank messages", summary["path"],
                        f"{summary['unknown_rows']:,}", f"{summary['unique_unknown_messages']:,}", f"{summary['blank_messages']:,}")
    else:
        LOGGER.info("No monthly unknown-event summaries were created")
    LOGGER.info("Combined unknown-message universe: " + summary_results["combined_summary_file"])
    LOGGER.info("Combined unknown-event occurrences: " + summary_results["occurrences_file"])
    LOGGER.info("Unknown event occurrences across all months: " + str(summary_results["unknown_rows"]))
    LOGGER.info("Unique unknown messages across all months: " + str(summary_results["unique_unknown_messages"]))
    LOGGER.info("Blank unknown messages across all months: " + str(summary_results["blank_messages"]))
    if not summary_results["combined_rows"]:            # the messages themselves stay in the summary file
        LOGGER.info("No unknown OSSEC events were found")


@timed_stage
def rebuild_ossec_event_lookup():
    """Build the authoritative event-ID lookup from monthly CSVs.
    
    :returns: Number of lookup rows written; also writes the lineage summary JSON.
    :rtype: int
    :raises ValueError: If parsing or identity validation fails.
    """
    preferred = [
        "event_id", "raw_line_sha256", "timestamp", "partition_month",
        "hostname", "process_name", "pid", "severity", "event_type",
        "username", "source_ip", "source_port", "destination_hostname",
        "destination_ip", "destination_port", "agent_name", "reason",
        "raw_message", "original_log_line", "classification_line",
        "source_file", "source_line", "archive_name", "archive_member",
    ]
    monthly = sorted(glob.glob(os.path.join(OUTPUT_FOLDER, "ossec_events_*.csv")))
    temporary = EVENT_LOOKUP_FILE + ".tmp"
    seen = set()
    rows = 0
    try:
        with open(temporary, "w", encoding="utf-8", newline="", buffering=1024 * 1024) as target:
            writer = csv.DictWriter(target, fieldnames=preferred, extrasaction="ignore")
            writer.writeheader()
            for path in monthly:
                with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as source:
                    reader = csv.DictReader(source)
                    required = {"event_id", "raw_line_sha256", "original_log_line", "source_file", "source_line"}
                    missing = required.difference(reader.fieldnames or [])
                    if missing:
                        raise ValueError("Monthly OSSEC file lacks lineage columns in " + path + ": " + ", ".join(sorted(missing)))
                    for row in progress_items(reader, "CSV rows processed"):
                        event_id = clean_value(row.get("event_id"))
                        if not event_id:
                            raise ValueError("Blank event_id in " + path)
                        if event_id in seen:
                            raise ValueError("Duplicate event_id across OSSEC monthly files: " + event_id)
                        seen.add(event_id)
                        writer.writerow(row)
                        rows += 1
        os.replace(temporary, EVENT_LOOKUP_FILE)
    except Exception:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise
    with open(LINEAGE_SUMMARY_FILE, "w", encoding="utf-8") as handle:
        json.dump({
            "classifier_version": CLASSIFIER_VERSION,
            "monthly_files": len(monthly),
            "event_lookup_rows": rows,
            "unique_event_ids": len(seen),
            "event_lookup_file": EVENT_LOOKUP_FILE,
            "identity_contract": {
                "event_id": "physical occurrence identity",
                "raw_line_sha256": "exact physical line content fingerprint",
                "source_coordinates": ["archive_name", "archive_member", "source_file", "source_line"],
            },
        }, handle, indent=2)
    return rows


def main():
    """Run the complete OSSEC workflow using configured folder constants.
    
    :rtype: None
    """
    os.makedirs(INPUT_FOLDER, exist_ok=True)
    os.makedirs(EXTRACT_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    reset_processing_state()
    zip_files = sorted(glob.glob(os.path.join(INPUT_FOLDER, "*.zip")))
    if not zip_files:
        LOGGER.error("No ZIP archives found in: " + INPUT_FOLDER)
        raise SystemExit(1)
    manifest_entries = load_extraction_manifest()
    extracted_ossec_files = []
    LOGGER.info("Previously recorded extracted OSSEC logs: " + str(len(manifest_entries)))
    for zip_path in zip_files:
        LOGGER.info("Processing ZIP: " + zip_path)
        extracted_ossec_files.extend(extract_osseclogs_from_zip(zip_path, manifest_entries))
    rewrite_extraction_manifest(manifest_entries)
    if not extracted_ossec_files:
        LOGGER.error("No OSSEC TXT files were found in the ZIP archives.")
        raise SystemExit(1)
    source_signature = calculate_source_signature(extracted_ossec_files)
    if outputs_are_complete(load_processing_manifest(), source_signature):
        LOGGER.info("Existing OSSEC CSV outputs are complete and match the current sources and classifier version.")
        LOGGER.info("Classification skipped.")
        print_unknown_summary_results(create_unknown_ossec_summaries())
        return
    known_event_count = 0
    unknown_event_count = 0
    total_event_count = 0
    file_error_count = 0
    try:
        for extracted_file in extracted_ossec_files:
            file_path = extracted_file["file_path"]
            LOGGER.info("Reading OSSEC log: " + file_path)
            try:
                known_count, unknown_count, total_count = parse_ossec_file(file_path, extracted_file)
                known_event_count += known_count
                unknown_event_count += unknown_count
                total_event_count += total_count
            except (OSError, csv.Error, ValueError) as error:
                file_error_count += 1
                LOGGER.error("Could not process " + file_path + ": " + str(error))
        if file_error_count:
            raise RuntimeError("OSSEC classification was not committed because one or more source files failed.")
        commit_monthly_output_files()
        remove_stale_monthly_outputs()
        write_processing_manifest(source_signature)
        unknown_summary_results = create_unknown_ossec_summaries()
    except Exception:
        discard_temporary_output_files()
        raise
    lookup_rows = rebuild_ossec_event_lookup()
    newly_extracted_count = sum(1 for item in extracted_ossec_files if item["extraction_status"] == "EXTRACTED")
    previously_extracted_count = sum(1 for item in extracted_ossec_files if item["extraction_status"] == "ALREADY_EXTRACTED")
    LOGGER.info("Processing complete.")
    LOGGER.info("ZIP archives processed: " + str(len(zip_files)))
    LOGGER.info("OSSEC log files available: " + str(len(extracted_ossec_files)))
    LOGGER.info("New OSSEC log files extracted: " + str(newly_extracted_count))
    LOGGER.info("Previously extracted files reused: " + str(previously_extracted_count))
    LOGGER.info("Known OSSEC events parsed: " + str(known_event_count))
    LOGGER.info("Unknown OSSEC events retained: " + str(unknown_event_count))
    LOGGER.info("Total OSSEC events: " + str(total_event_count))
    LOGGER.info("OSSEC log files with read errors: " + str(file_error_count))
    LOGGER.info("Extraction manifest: " + EXTRACTION_MANIFEST)
    LOGGER.info("Processing manifest: " + PROCESSING_MANIFEST)
    LOGGER.info("OSSEC event lookup rows: " + str(lookup_rows))
    LOGGER.info("OSSEC event lookup: " + EVENT_LOOKUP_FILE)
    LOGGER.info("Lineage summary: " + LINEAGE_SUMMARY_FILE)
    if event_type_counts:
        for event_type, count in sorted(event_type_counts.items()):
            LOGGER.info("Event type %s: %s events", event_type, f"{count:,}")
    else:
        LOGGER.info("No events found")
    if monthly_output_files:
        for month_key in sorted(monthly_output_files):
            LOGGER.info("%s: %s events", monthly_output_files[month_key]["path"], f"{monthly_event_counts[month_key]:,}")
    else:
        LOGGER.info("No monthly CSV files were created")
    print_unknown_summary_results(unknown_summary_results)


if __name__ == "__main__":
    args = parse_args()
    runlog.configure_from(args)
    try:
        with runlog.run():
            main()
    except KeyboardInterrupt:                    # runlog.run() has logged it
        sys.exit(130)
    except Exception:
        LOGGER.exception("OSSEC workflow failed")
        sys.exit(1)
