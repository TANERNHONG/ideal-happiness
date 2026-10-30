"""Build lineage-preserving authentication-log observation datasets.

Stage 2 of the authentication-log explainable-lineage workflow.

Inputs
------
data/phase1_classify/auth/classified_authlog_events_YYYY-MM.csv
data/phase1_classify/auth/authlog_event_lookup.csv

Outputs
-------
data/phase2_observations/auth/authlog_events_all_months.csv
data/phase2_observations/auth/authlog_events_all_months_lineage.csv
data/phase2_observations/auth/authlog_host_windows_5min.csv
data/phase2_observations/auth/authlog_host_windows_5min_lineage.csv
data/phase2_observations/auth/authlog_authentication_sessions.csv
data/phase2_observations/auth/authlog_authentication_sessions_lineage.csv
data/phase2_observations/auth/authlog_host_behavior_1d.csv
data/phase2_observations/auth/authlog_host_behavior_1d_lineage.csv
data/phase2_observations/auth/authlog_observation_dataset_summary.csv
data/phase2_observations/auth/authlog_observation_dataset_summary.json


Runtime and existing-output checks
----------------------------------
Every checkpoint includes total runtime in ``HH:MM:SS.s`` format. Loop progress
also retains its stage elapsed seconds and throughput. Timing uses
``time.monotonic()``, so wall-clock corrections do not affect elapsed time.
Total runtime is reported on success, skip, failure and keyboard interruption;
an abrupt process kill cannot emit a final message. ``--quiet`` suppresses
routine timing messages along with other INFO checkpoints.

Before processing, exact expected output filenames are checked for non-empty
regular files. A complete set skips processing; ``--force`` regenerates it::

    python pipeline/phase2_observations/auth.py --force --verbose

Rebuild only sessions and their lineage after changing the session logic::

    python pipeline/phase2_observations/auth.py --sessions-only --force

This still reloads source events into SQLite, but preserves the other three
dataset/lineage pairs. It writes separate ``authlog_authentication_sessions_summary``
CSV/JSON reports; the previous combined summary is not updated by this mode.

.. note::

   Filename matches do not prove that files are valid or up to date. Use
   ``--force`` after changing inputs or configuration, or for damaged outputs.
   The builder checks all eight dataset/lineage CSVs and both summaries
   before reading inputs or replacing the SQLite store. If any is missing or
   empty, all outputs are regenerated together for consistency.

Command-line usage
------------------
Run with timestamped INFO checkpoints (the default)::

    python pipeline/phase2_observations/auth.py

Enable batch details and five-second progress updates::

    python pipeline/phase2_observations/auth.py --verbose --progress-interval 5

Select input and output directories::

    python pipeline/phase2_observations/auth.py --input-folder data/phase1_classify/auth --output-folder data/phase2_observations/auth

Use ``--quiet`` to show only warnings and errors. Progress is flushed to stderr
and reports processed counts, elapsed seconds and throughput. SQLite activity
checkpoints report elapsed time without an estimated percentage. Loop updates
can be delayed by blocking I/O. Raw log messages are not included in progress.

.. note::

   The SQLite store is rebuilt whenever processing is required. Invalid timestamps are skipped and
   counted. Existing timestamp semantics interpret naive source times as UTC.
   Although events are stored on disk, active aggregates, novelty history and
   validation dictionaries/sets still consume memory proportional to their size.

Lineage contract
----------------
Every observation has one stable ``row_manifest_id``. Every lineage file maps
that observation to every contributing source ``record_id``:

    row_manifest_id -> record_id -> data/phase1_classify/auth/authlog_event_lookup.csv
    -> original_log_line -> source_file -> source_line

Observation representations
---------------------------
``individual``
    One observation per classified authentication event.

``host_5min``
    One hostname-oriented five-minute tumbling window.

``authentication_sessions``
    One network connection or local privilege/console attempt (see below).

``host_behavior_1d``
    One daily behavior observation per host, with historical novelty fields.

Session construction (builder version 03)
-----------------------------------------
A single SSH login is logged across several lines, and not every line carries
every field. For example, ``Accepted ... for alice from IP port P``,
``Received disconnect from IP port P`` (no username) and
``error: PAM: Authentication failed for alice from IP`` (no port). Earlier
versions grouped by host, process, PID, username, IP and port, and closed a
session on every success or failure event, so almost every line became its own
session.

Events are now grouped as follows:

1. **Connection key** ``(host, source_ip, source_port)`` when both IP and port
   are present. The client port identifies one TCP connection. Username and
   PID are deliberately excluded because they are missing from some lines.
2. **PID bridge.** A line without IP/port but with a PID (for example a PAM
   failure or subsystem request) joins the open connection session that the
   same ``(host, process, PID)`` last belonged to.
3. **Process key** ``(host, process, PID, username)`` otherwise, for example
   ``su`` attempts and console logins.

Success and failure events no longer close a session, so repeated failures
within one connection stay together. A session closes when:

* a terminal event is seen (disconnect, connection closed/reset, "too many
  authentication failures", ``su`` result, console login), followed by a
  ``SESSION_TERMINAL_GRACE_SECONDS`` window that absorbs trailing lines of the
  same connection;
* no event arrives for ``SESSION_INACTIVITY_SECONDS``; or
* the data ends.

The reason is written to ``close_reason`` and the grouping key type to
``session_key_type``. Sessions are flushed from memory by a periodic sweep, so
memory stays proportional to concurrently open connections.

All monthly CSVs are loaded into an on-disk SQLite store so the complete source
dataset does not have to fit in memory.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import sys
import time
from contextlib import contextmanager
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import Progress  # noqa: E402

LOGGER = runlog.LOGGER

INPUT_FOLDER = Path("data/phase1_classify/auth")
OUTPUT_FOLDER = Path("data/phase2_observations/auth")
INPUT_PATTERN = "classified_authlog_events_????-??.csv"
EVENT_LOOKUP_FILE = INPUT_FOLDER / "authlog_event_lookup.csv"
DATABASE_FILE = OUTPUT_FOLDER / "authlog_observation_store.sqlite"

BUILDER_VERSION = "2026-09-23-auth-session-boundaries-03"
COMMIT_BATCH_SIZE = 50_000
CSV_WRITE_BATCH_SIZE = 10_000
HOST_WINDOW_SECONDS = 5 * 60
SESSION_INACTIVITY_SECONDS = 15 * 60
SESSION_TERMINAL_GRACE_SECONDS = 10
SESSION_SWEEP_SECONDS = 60
DELETE_DATABASE_WHEN_COMPLETE = False
MAX_SEQUENCE_LENGTH = 96

REQUIRED_INPUT_FIELDS = {
    "record_id", "raw_line_sha256", "timestamp", "partition_month",
    "hostname", "process_name", "event_type", "raw_message",
    "original_log_line", "source_file", "source_line",
}

SOURCE_FIELDS = [
    "record_id", "raw_line_sha256", "source_event_id", "session_id",
    "timestamp", "partition_month", "hostname", "process_name", "pid",
    "facility", "event_type", "username", "target_username",
    "invalid_user_indicator", "source_ip", "source_port", "source_location",
    "authentication_method", "connection_stage", "terminal_path",
    "failure_count", "failure_code", "disconnect_code",
    "server_protocol_version", "client_protocol_version", "message_type",
    "sequence_number", "module_index", "pam_config_path", "module_path",
    "operation", "reason", "raw_message", "original_log_line",
    "classification_line", "source_file", "source_line",
]

INDIVIDUAL_OUTPUT_FIELDS = [
    "row_manifest_id", "record_id", "timestamp", "timestamp_epoch",
    "partition_month", "hostname", "host_id", "process_name", "pid",
    "facility", "event_type", "event_category", "event_outcome",
    "username", "target_username", "invalid_user_indicator", "source_ip",
    "source_port", "source_location", "authentication_method",
    "connection_stage", "terminal_path", "failure_count", "failure_code",
    "disconnect_code", "server_protocol_version", "client_protocol_version",
    "message_type", "sequence_number", "module_index", "pam_config_path",
    "module_path", "operation", "reason", "source_ip_version",
    "source_ip_zone", "source_ip_subnet", "source_port_category",
    "hour_of_day", "day_of_week", "is_weekend", "normalized_event_token",
    "normalized_message", "raw_message", "original_log_line",
    "raw_line_sha256", "source_event_id", "source_file", "source_line",
]

HOST_WINDOW_OUTPUT_FIELDS = [
    "row_manifest_id", "dataset_id", "window_label", "window_start",
    "window_end", "host_id", "total_events", "events_per_minute",
    "success_count", "failure_count", "postponed_count", "invalid_user_count",
    "account_lock_count", "access_denied_count", "privilege_success_count",
    "privilege_failure_count", "connection_open_count",
    "connection_close_count", "connection_reset_count", "disconnect_count",
    "protocol_error_count", "pam_error_count", "key_error_count",
    "unknown_event_count", "authentication_event_count",
    "connection_event_count", "privilege_event_count", "system_event_count",
    "other_category_count", "unique_event_types", "unique_processes",
    "unique_usernames", "unique_target_usernames", "unique_source_ips",
    "unique_source_ports", "unique_authentication_methods",
    "unique_terminal_paths", "event_type_entropy", "process_entropy",
    "username_entropy", "source_ip_entropy", "dominant_event_type",
    "dominant_event_type_count", "dominant_process", "dominant_process_count",
    "dominant_username", "dominant_username_count", "dominant_source_ip",
    "dominant_source_ip_count", "first_event_type", "last_event_type",
    "first_record_id", "last_record_id", "first_timestamp", "last_timestamp",
    "active_span_seconds", "mean_inter_event_seconds",
    "minimum_inter_event_seconds", "maximum_inter_event_seconds",
    "event_type_sequence", "outcome_sequence",
]

SESSION_OUTPUT_FIELDS = [
    "row_manifest_id", "authentication_session_id", "session_start",
    "session_end", "duration_seconds", "inactivity_threshold_seconds",
    "session_key_type", "close_reason",
    "host_id", "process_name", "pid", "username", "source_ip",
    "source_port", "event_count", "events_per_minute", "success_count",
    "failure_count", "postponed_count", "invalid_user_count",
    "account_lock_count", "access_denied_count", "connection_close_count",
    "connection_reset_count", "disconnect_count", "protocol_error_count",
    "pam_error_count", "key_error_count", "unknown_event_count",
    "unique_event_types", "unique_usernames", "unique_target_usernames",
    "unique_authentication_methods", "unique_terminal_paths",
    "unique_reasons", "authentication_succeeded", "authentication_failed",
    "session_closed", "first_event_type", "last_event_type",
    "first_record_id", "last_record_id", "mean_inter_event_seconds",
    "maximum_inter_event_seconds", "event_type_sequence", "outcome_sequence",
    "username_sequence", "authentication_method_sequence",
]

BEHAVIOR_OUTPUT_FIELDS = [
    "row_manifest_id", "dataset_id", "window_label", "window_start",
    "window_end", "host_id", "total_events", "events_per_hour",
    "active_hours", "active_span_seconds", "mean_inter_event_seconds",
    "maximum_inter_event_seconds", "success_count", "failure_count",
    "postponed_count", "invalid_user_count", "account_lock_count",
    "access_denied_count", "privilege_success_count",
    "privilege_failure_count", "connection_close_count",
    "connection_reset_count", "disconnect_count", "protocol_error_count",
    "pam_error_count", "key_error_count", "unknown_event_count",
    "unique_event_types", "unique_processes", "unique_usernames",
    "unique_target_usernames", "unique_source_ips", "unique_source_ports",
    "unique_authentication_methods", "unique_terminal_paths",
    "new_event_types", "new_processes", "new_usernames",
    "new_target_usernames", "new_source_ips", "new_authentication_methods",
    "event_type_entropy", "process_entropy", "username_entropy",
    "source_ip_entropy", "dominant_event_type", "dominant_event_type_count",
    "dominant_process", "dominant_process_count", "dominant_username",
    "dominant_username_count", "dominant_source_ip",
    "dominant_source_ip_count", "first_event_type", "last_event_type",
    "first_record_id", "last_record_id", "first_timestamp", "last_timestamp",
    "event_type_sequence", "outcome_sequence",
]

LINEAGE_OUTPUT_FIELDS = [
    "dataset", "row_manifest_id", "record_id", "event_position",
    "event_timestamp", "relationship_role",
]

SUCCESS_EVENTS = {
    "SSH_LOGIN_SUCCESS", "SU_SESSION_SUCCESS", "LOGIN_ROOT_CONSOLE",
}
FAILURE_EVENTS = {
    "SSH_LOGIN_FAILED", "SU_SESSION_FAILED", "LOGIN_REPEATED_CONSOLE_FAILURES",
    "GDM_EMPTY_PASSWORD_NOT_ALLOWED", "SSH_PAM_ACCOUNT_ACCESS_DENIED",
    "SSH_PAM_NO_ACCOUNT_PRESENT", "SSH_PAM_MAX_ATTEMPTS_EXCEEDED",
    "SSH_PAM_CONVERSATION_FAILURE", "SSH_KEYBOARD_INTERACTIVE_PAM_FAILED",
    "SSH_PAM_AUTHENTICATION_TOKEN_MANIPULATION_ERROR",
    "PAM_AUTHENTICATION_TOKEN_MANIPULATION_ERROR",
    "PAM_PASSWORD_CHANGE_CONVERSATION_FAILURE",
}
POSTPONED_EVENTS = {"SSH_AUTHENTICATION_POSTPONED"}
INVALID_USER_EVENTS = {
    "SSH_INVALID_USER", "SSH_ILLEGAL_USER", "SSH_ILLEGAL_USER_AUTH_REQUEST",
    "SSH_AUTHENTICATED_INVALID_USER_IGNORED",
    "SSH_INVALID_USER_DISCONNECTED", "SSH_INVALID_USER_CONNECTION_RESET",
    "SSH_INVALID_USER_CONNECTION_CLOSED",
}
ACCOUNT_LOCK_EVENTS = {
    "GDM_ACCOUNT_LOCKED", "AUTH_ACCOUNT_LOCKED",
    "SSH_LOCKED_ACCOUNT_VALIDATION", "CRON_LOCKED_ACCOUNT_VALIDATION",
}
ACCESS_DENIED_EVENTS = {"SSH_USER_NOT_ALLOWED", "SSH_PAM_ACCOUNT_ACCESS_DENIED"}
# Events that end a connection or a local attempt. Success and failure events
# are deliberately absent: a connection continues after a failed password or
# a successful login, and repeated failures must stay in one session.
SESSION_TERMINAL_EVENTS = {
    "SSH_USER_DISCONNECTED", "SSH_DISCONNECT_RECEIVED",
    "SSH_USER_DISCONNECT_RECEIVED", "SSH_CONNECTION_CLOSED",
    "SSH_CONNECTION_CLOSED_PREAUTH", "SSH_CONNECTION_RESET",
    "SSH_AUTHENTICATING_USER_CONNECTION_RESET",
    "SSH_AUTHENTICATING_USER_DISCONNECTED",
    "SSH_INVALID_USER_CONNECTION_CLOSED", "SSH_INVALID_USER_CONNECTION_RESET",
    "SSH_INVALID_USER_DISCONNECTED", "SSH_DISCONNECT_AUTHENTICATION_FAILED",
    "SSH_DISCONNECTING_AUTH_FAILURES",
    "SU_SESSION_SUCCESS", "SU_SESSION_FAILED",
    "LOGIN_ROOT_CONSOLE", "LOGIN_REPEATED_CONSOLE_FAILURES",
}

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
)


def parse_args():
    """Parse paths, verbosity and a positive progress interval.
    
    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-folder", type=Path, default=INPUT_FOLDER,
                        help="Folder containing monthly CSVs and the event lookup.")
    parser.add_argument("--output-folder", type=Path, default=OUTPUT_FOLDER,
                        help="Folder for datasets, lineage files and SQLite store.")
    parser.add_argument("--force", action="store_true",
                        help="Regenerate outputs even if all expected files exist.")
    parser.add_argument("--sessions-only", action="store_true",
                        help="Build and validate only sessions and their lineage; write separate summaries.")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    return args


def outputs_already_produced(paths, force=False):
    """Check expected output names before expensive processing begins.

    :param paths: Exact expected paths in the selected output directory.
    :param force: Bypass reuse and regenerate outputs when True.
    :returns: True if every expected path is a non-empty regular file and
        regeneration was not forced.
    :rtype: bool

    .. note::

       This fast check compares filenames and file sizes. It does not verify
       contents, source freshness or configuration changes. Use ``--force``
       when inputs or processing settings have changed. Temporary files and
       the SQLite working store do not count as completed outputs.
    """
    paths = list(paths)
    LOGGER.info("Preflight: checking %s expected output filenames", len(paths))
    present = []
    for path in paths:
        exists = path.is_file() and path.stat().st_size > 0
        present.append(exists)
        LOGGER.info("%s: %s", "FOUND" if exists else "MISSING OR EMPTY", path)
    if force:
        LOGGER.info("--force enabled: regenerating outputs")
        return False
    if present and all(present):
        LOGGER.info("All expected outputs already exist; skipping processing. "
                    "Use --force to regenerate after input or configuration changes.")
        return True
    LOGGER.info("Output set incomplete (%s/%s present); continuing processing",
                sum(present), len(paths))
    return False


def clean(value):
    """Convert a value to stripped text, mapping None to empty text.
    
    :param value: Input value to transform.
    :returns: Normalized text.
    :rtype: str
    """
    return str(value).strip() if value is not None else ""


def safe_int(value, default=0):
    """Convert numeric text through float to int, using a fallback on type or value errors.
    
    :param value: Input value to transform.
    :param default: Fallback integer when conversion fails.
    :returns: Converted integer or default.
    :rtype: int
    """
    try:
        return int(float(clean(value)))
    except (TypeError, ValueError):
        return default


def parse_timestamp(value):
    """Parse supported naive timestamp strings and interpret them as UTC.
    
    :param value: Input value to transform.
    :returns: Timezone-aware UTC datetime.
    :rtype: datetime
    :raises ValueError: If input parsing or identity validation fails.
    """
    value = clean(value)
    for timestamp_format in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, timestamp_format).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    raise ValueError("Unsupported authentication timestamp: " + value)


def epoch_to_text(value):
    """Format Unix epoch seconds as UTC text with microseconds.
    
    :param value: Input value to transform.
    :returns: Formatted timestamp.
    :rtype: str
    """
    return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )


def bucket_start(value, seconds):
    """Floor Unix epoch seconds to a fixed-duration bucket.
    
    :param value: Input value to transform.
    :param seconds: Positive bucket duration in seconds.
    :returns: Bucket start in epoch seconds.
    :rtype: int
    """
    return int(math.floor(float(value) / seconds) * seconds)


def stable_id(*parts):
    """Hash pipe-delimited normalized parts into a stable identifier.
    
    :param parts: Ordered identifier components.
    :returns: First 24 hexadecimal SHA-256 characters.
    :rtype: str
    """
    seed = "|".join(clean(part) for part in parts)
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:24]


def normalize_token(value):
    """Normalize a value to a lowercase underscore-separated token.
    
    :param value: Input value to transform.
    :returns: Token, or unknown for empty normalized input.
    :rtype: str
    """
    result = re.sub(r"[^a-z0-9]+", "_", clean(value).lower()).strip("_")
    return result or "unknown"


def normalize_message(value):
    """Replace addresses, numbers and fingerprints with message placeholders.
    
    :param value: Input value to transform.
    :returns: Normalized message text.
    :rtype: str
    """
    value = clean(value).lower()
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " {ip} ", value)
    value = re.sub(r"(?<![a-f0-9:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]+", " {ip} ", value, flags=re.I)
    value = re.sub(r"\b0x[a-f0-9]+\b", " {hex} ", value)
    value = re.sub(r"\b\d+\b", " {number} ", value)
    value = re.sub(r"sha256:\S+", " sha256:{fingerprint} ", value, flags=re.I)
    return re.sub(r"\s+", " ", value).strip()


def event_outcome(event_type):
    """Map an event type to the first matching outcome group.
    
    :param event_type: Classified event-type name.
    :returns: Outcome label or neutral.
    :rtype: str
    """
    value = clean(event_type)
    if value in SUCCESS_EVENTS:
        return "success"
    if value in FAILURE_EVENTS:
        return "failure"
    if value in POSTPONED_EVENTS:
        return "postponed"
    if value in INVALID_USER_EVENTS:
        return "invalid_user"
    if value in ACCOUNT_LOCK_EVENTS:
        return "account_lock"
    if value in ACCESS_DENIED_EVENTS:
        return "access_denied"
    return "neutral"


def event_category(event_type):
    """Assign a broad category using ordered event-name checks.
    
    :param event_type: Classified event-type name.
    :returns: Category label or other.
    :rtype: str
    """
    value = clean(event_type).upper()
    if value.startswith("SSH_LOGIN") or "AUTHENTICATION" in value or "PAM_" in value:
        return "authentication"
    if "CONNECTION" in value or "DISCONNECT" in value or "KEX" in value:
        return "connection"
    if value.startswith("SU_") or value.startswith("LOGIN_") or value.startswith("GDM_"):
        return "privilege"
    if "KEY" in value or "PROTOCOL" in value or "PACKET" in value or "DISPATCH" in value:
        return "protocol"
    if value.startswith("SYSLOG_") or value.startswith("DBUS_") or value.startswith("GNOME_") or value.startswith("CRON_"):
        return "system"
    return "other"


def network_properties(value):
    """Derive IP version, address zone and /24 or /64 subnet.
    
    :param value: Input value to transform.
    :returns: Version, zone and subnet; unknown placeholders for invalid input.
    :rtype: tuple
    """
    try:
        address = ipaddress.ip_address(clean(value))
        zone = (
            "loopback" if address.is_loopback else
            "multicast" if address.is_multicast else
            "link_local" if address.is_link_local else
            "private" if address.is_private else
            "reserved" if address.is_reserved else "public"
        )
        prefix = 24 if address.version == 4 else 64
        subnet = str(ipaddress.ip_network(str(address) + "/" + str(prefix), strict=False))
        return str(address.version), zone, subnet
    except ValueError:
        return "", "unknown", "unknown"


def port_category(value):
    """Classify a port as well-known, registered, ephemeral or unknown.
    
    :param value: Input value to transform.
    :returns: Port category label.
    :rtype: str
    """
    port = safe_int(value, -1)
    if port < 0 or port > 65535:
        return "unknown"
    if port <= 1023:
        return "well_known"
    if port <= 49151:
        return "registered"
    return "ephemeral"


def input_files():
    """Discover sorted monthly CSV paths under INPUT_FOLDER.
    
    :returns: Matching source filenames.
    :rtype: list
    :raises FileNotFoundError: If required input files are absent.
    """
    files = sorted(glob.glob(str(INPUT_FOLDER / INPUT_PATTERN)))
    if not files:
        raise FileNotFoundError(
            "No lineage-enabled authentication monthly files found: "
            + str(INPUT_FOLDER / INPUT_PATTERN)
        )
    return files


def validate_header(path, fieldnames):
    """Require all input lineage columns in a CSV header.
    
    :param path: Source CSV path used in error context.
    :param fieldnames: CSV header column names.
    :rtype: None
    :raises ValueError: If input parsing or identity validation fails.
    """
    if not fieldnames:
        raise ValueError("CSV has no header: " + str(path))
    missing = REQUIRED_INPUT_FIELDS.difference(fieldnames)
    if missing:
        raise ValueError(
            "Authentication CSV lacks required lineage fields in " + str(path)
            + ": " + ", ".join(sorted(missing))
        )


def create_database(connection):
    """Drop and recreate the event and lookup tables and their indexes.
    
    :param connection: Open SQLite connection to the observation store.
    :rtype: None
    """
    connection.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-200000;
        DROP TABLE IF EXISTS known_record_ids;
        CREATE TABLE known_record_ids (record_id TEXT PRIMARY KEY);
        DROP TABLE IF EXISTS events;
        CREATE TABLE events (
            record_id TEXT PRIMARY KEY,
            raw_line_sha256 TEXT NOT NULL,
            source_event_id TEXT,
            source_session_id TEXT,
            timestamp_text TEXT NOT NULL,
            timestamp_epoch REAL NOT NULL,
            partition_month TEXT,
            hostname TEXT,
            host_id TEXT,
            process_name TEXT,
            pid TEXT,
            facility TEXT,
            event_type TEXT,
            event_category TEXT,
            event_outcome TEXT,
            username TEXT,
            target_username TEXT,
            invalid_user_indicator TEXT,
            source_ip TEXT,
            source_port TEXT,
            source_location TEXT,
            authentication_method TEXT,
            connection_stage TEXT,
            terminal_path TEXT,
            failure_count INTEGER,
            failure_code TEXT,
            disconnect_code TEXT,
            server_protocol_version TEXT,
            client_protocol_version TEXT,
            message_type TEXT,
            sequence_number TEXT,
            module_index TEXT,
            pam_config_path TEXT,
            module_path TEXT,
            operation TEXT,
            reason TEXT,
            raw_message TEXT,
            original_log_line TEXT,
            classification_line TEXT,
            source_file TEXT,
            source_line TEXT
        );
        CREATE INDEX idx_auth_time ON events(timestamp_epoch);
        CREATE INDEX idx_auth_host_time ON events(host_id, timestamp_epoch);
        CREATE INDEX idx_auth_session ON events(
            host_id, process_name, pid, username, source_ip, source_port,
            timestamp_epoch
        );
    """)
    connection.commit()


def load_lookup_ids(connection):
    """Load unique non-blank lookup IDs into SQLite in committed batches.
    
    :param connection: Open SQLite connection to the observation store.
    :returns: Number of lookup IDs stored.
    :rtype: int
    :raises ValueError: If input parsing or identity validation fails.
    :raises FileNotFoundError: If required input files are absent.
    """
    if not EVENT_LOOKUP_FILE.is_file():
        raise FileNotFoundError("Authentication event lookup is missing: " + str(EVENT_LOOKUP_FILE))
    LOGGER.info("[2/9] Loading authoritative lookup IDs")
    progress = Progress("Lookup IDs read")
    count = 0
    batch = []
    with open(EVENT_LOOKUP_FILE, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "record_id" not in reader.fieldnames:
            raise ValueError("record_id missing from authentication event lookup")
        for row_number, row in enumerate(reader, start=2):
            record_id = clean(row.get("record_id"))
            if not record_id:
                raise ValueError("Blank record_id in event lookup row " + str(row_number))
            batch.append((record_id,))
            count += 1
            progress.report(count)
            if len(batch) >= COMMIT_BATCH_SIZE:
                try:
                    connection.executemany("INSERT INTO known_record_ids VALUES (?)", batch)
                except sqlite3.IntegrityError as error:
                    raise ValueError("Duplicate record_id in authentication event lookup") from error
                connection.commit()
                LOGGER.debug("Committed %s lookup IDs", len(batch))
                batch.clear()
    if batch:
        try:
            connection.executemany("INSERT INTO known_record_ids VALUES (?)", batch)
        except sqlite3.IntegrityError as error:
            raise ValueError("Duplicate record_id in authentication event lookup") from error
        connection.commit()
    progress.report(count, force=True)
    return int(connection.execute("SELECT COUNT(*) FROM known_record_ids").fetchone()[0])


def load_events(connection, files):
    """Load monthly CSVs into SQLite, skipping unsupported timestamps.
    
    :param connection: Open SQLite connection to the observation store.
    :param files: Sorted monthly CSV filenames.
    :returns: Loaded-event count and skipped-timestamp count.
    :rtype: tuple
    :raises ValueError: If input parsing or identity validation fails.
    """
    LOGGER.info("[3/9] Loading monthly authentication events")
    progress = Progress("Monthly CSV rows scanned")
    scanned = 0
    columns = [
        "record_id", "raw_line_sha256", "source_event_id", "source_session_id",
        "timestamp_text", "timestamp_epoch", "partition_month", "hostname",
        "host_id", "process_name", "pid", "facility", "event_type",
        "event_category", "event_outcome", "username", "target_username",
        "invalid_user_indicator", "source_ip", "source_port", "source_location",
        "authentication_method", "connection_stage", "terminal_path",
        "failure_count", "failure_code", "disconnect_code",
        "server_protocol_version", "client_protocol_version", "message_type",
        "sequence_number", "module_index", "pam_config_path", "module_path",
        "operation", "reason", "raw_message", "original_log_line",
        "classification_line", "source_file", "source_line",
    ]
    sql = "INSERT INTO events (" + ",".join(columns) + ") VALUES (" + ",".join("?" for _ in columns) + ")"
    batch = []
    loaded = 0
    invalid_timestamps = 0
    for path in files:
        LOGGER.info("Loading authentication events: " + path)
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            validate_header(path, reader.fieldnames)
            for row_number, row in enumerate(reader, start=2):
                scanned += 1
                progress.report(scanned)
                try:
                    timestamp = parse_timestamp(row.get("timestamp"))
                except ValueError:
                    invalid_timestamps += 1
                    continue
                hostname = clean(row.get("hostname")).lower()
                host_id = hostname or "unknown-host"
                event_type_value = clean(row.get("event_type")) or "AUTHLOG_UNKNOWN_EVENT"
                values = {
                    "record_id": clean(row.get("record_id")),
                    "raw_line_sha256": clean(row.get("raw_line_sha256")),
                    "source_event_id": clean(row.get("source_event_id")),
                    "source_session_id": clean(row.get("session_id")),
                    "timestamp_text": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp_epoch": timestamp.timestamp(),
                    "partition_month": clean(row.get("partition_month")) or timestamp.strftime("%Y-%m"),
                    "hostname": hostname,
                    "host_id": host_id,
                    "process_name": clean(row.get("process_name")).lower(),
                    "pid": clean(row.get("pid")),
                    "facility": clean(row.get("facility")).lower(),
                    "event_type": event_type_value,
                    "event_category": event_category(event_type_value),
                    "event_outcome": event_outcome(event_type_value),
                    "username": clean(row.get("username")).lower(),
                    "target_username": clean(row.get("target_username")).lower(),
                    "invalid_user_indicator": clean(row.get("invalid_user_indicator")).lower(),
                    "source_ip": clean(row.get("source_ip")),
                    "source_port": clean(row.get("source_port")),
                    "source_location": clean(row.get("source_location")).lower(),
                    "authentication_method": clean(row.get("authentication_method")).lower(),
                    "connection_stage": clean(row.get("connection_stage")).lower(),
                    "terminal_path": clean(row.get("terminal_path")),
                    "failure_count": safe_int(row.get("failure_count")),
                    "failure_code": clean(row.get("failure_code")),
                    "disconnect_code": clean(row.get("disconnect_code")),
                    "server_protocol_version": clean(row.get("server_protocol_version")),
                    "client_protocol_version": clean(row.get("client_protocol_version")),
                    "message_type": clean(row.get("message_type")),
                    "sequence_number": clean(row.get("sequence_number")),
                    "module_index": clean(row.get("module_index")),
                    "pam_config_path": clean(row.get("pam_config_path")),
                    "module_path": clean(row.get("module_path")),
                    "operation": clean(row.get("operation")).lower(),
                    "reason": clean(row.get("reason")),
                    "raw_message": clean(row.get("raw_message")),
                    "original_log_line": clean(row.get("original_log_line")),
                    "classification_line": clean(row.get("classification_line")),
                    "source_file": clean(row.get("source_file")),
                    "source_line": clean(row.get("source_line")),
                }
                if not values["record_id"] or not values["raw_line_sha256"]:
                    raise ValueError("Blank lineage identity in " + path + " row " + str(row_number))
                batch.append(tuple(values[column] for column in columns))
                if len(batch) >= COMMIT_BATCH_SIZE:
                    try:
                        connection.executemany(sql, batch)
                    except sqlite3.IntegrityError as error:
                        raise ValueError("Duplicate record_id in monthly authentication CSVs") from error
                    connection.commit()
                    loaded += len(batch)
                    LOGGER.debug("Committed event batch; %s events stored", loaded)
                    batch.clear()
    if batch:
        try:
            connection.executemany(sql, batch)
        except sqlite3.IntegrityError as error:
            raise ValueError("Duplicate record_id in monthly authentication CSVs") from error
        connection.commit()
        loaded += len(batch)
    progress.report(scanned, force=True)
    if invalid_timestamps:
        LOGGER.warning("Skipped %s records with invalid timestamps", invalid_timestamps)
    return loaded, invalid_timestamps


def validate_lookup_coverage(connection):
    """Require every loaded event ID to exist in the authoritative lookup.
    
    :param connection: Open SQLite connection to the observation store.
    :rtype: None
    :raises ValueError: If input parsing or identity validation fails.
    """
    LOGGER.info("[4/9] Checking source-record coverage in the event lookup")
    missing = int(connection.execute(
        "SELECT COUNT(*) FROM events e LEFT JOIN known_record_ids k ON e.record_id=k.record_id WHERE k.record_id IS NULL"
    ).fetchone()[0])
    if missing:
        examples = [row[0] for row in connection.execute(
            "SELECT e.record_id FROM events e LEFT JOIN known_record_ids k ON e.record_id=k.record_id WHERE k.record_id IS NULL LIMIT 10"
        )]
        raise ValueError(
            "Authentication events absent from event lookup: " + str(missing)
            + "; examples=" + ",".join(examples)
        )


def event_rows(connection, where="", parameters=()):
    """Stream event dictionaries ordered by timestamp and record ID.
    
    :param connection: Open SQLite connection to the observation store.
    :param where: Optional trusted SQL WHERE expression; do not pass untrusted SQL.
    :param parameters: Bound SQL values for the optional WHERE expression.
    :yields: Chronologically ordered event mappings.
    :rtype: iterator
    """
    query = "SELECT * FROM events"
    if where:
        query += " WHERE " + where
    query += " ORDER BY timestamp_epoch, record_id"
    LOGGER.debug("Opening chronologically ordered event stream")
    cursor = connection.execute(query, parameters)
    columns = [item[0] for item in cursor.description]
    for values in cursor:
        yield dict(zip(columns, values))


def entropy(counter):
    """Calculate Shannon entropy in bits from positive counts.
    
    :param counter: Mapping of values to occurrence counts.
    :returns: Entropy, or zero for an empty distribution.
    :rtype: float
    """
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counter.values() if count > 0)


def dominant(counter):
    """Select the most frequent value, breaking ties by normalized text.
    
    :param counter: Mapping of values to occurrence counts.
    :returns: Value and count, or an empty string and zero.
    :rtype: tuple
    """
    if not counter:
        return "", 0
    return min(counter.items(), key=lambda item: (-item[1], clean(item[0])))


def new_accumulator():
    """Create counters, sets and sequences for one observation.
    
    :returns: Fresh mutable aggregate state.
    :rtype: dict
    """
    return {
        "total_events": 0,
        "outcomes": Counter(), "categories": Counter(), "event_types": Counter(),
        "processes": Counter(), "usernames": Counter(), "target_usernames": set(),
        "source_ips": Counter(), "source_ports": set(), "methods": set(),
        "terminals": set(), "reasons": set(), "first_epoch": None,
        "last_epoch": None, "previous_epoch": None, "gap_sum": 0.0,
        "gap_count": 0, "minimum_gap": None, "maximum_gap": 0.0,
        "first_event_type": "", "last_event_type": "",
        "first_record_id": "", "last_record_id": "", "event_types_sequence": [],
        "outcome_sequence": [], "username_sequence": [], "method_sequence": [],
        "event_position": 0, "active_hours": set(),
    }


def update_accumulator(acc, row):
    """Update aggregate state in place from one chronological event.
    
    :param acc: Mutable observation accumulator.
    :param row: Event dictionary from the SQLite store.
    :returns: One-based position of this event in the observation.
    :rtype: int
    """
    event_type_value = clean(row["event_type"]) or "AUTHLOG_UNKNOWN_EVENT"
    outcome = clean(row["event_outcome"]) or "neutral"
    category = clean(row["event_category"]) or "other"
    process = clean(row["process_name"]) or "unknown-process"
    username = clean(row["username"])
    source_ip = clean(row["source_ip"])
    epoch = float(row["timestamp_epoch"])
    acc["total_events"] += 1
    acc["outcomes"][outcome] += 1
    acc["categories"][category] += 1
    acc["event_types"][event_type_value] += 1
    acc["processes"][process] += 1
    if username:
        acc["usernames"][username] += 1
    if clean(row["target_username"]):
        acc["target_usernames"].add(clean(row["target_username"]))
    if source_ip:
        acc["source_ips"][source_ip] += 1
    for value, target in (
        (row["source_port"], "source_ports"),
        (row["authentication_method"], "methods"),
        (row["terminal_path"], "terminals"),
        (row["reason"], "reasons"),
    ):
        value = clean(value)
        if value:
            acc[target].add(value)
    if acc["first_epoch"] is None:
        acc["first_epoch"] = epoch
        acc["first_event_type"] = event_type_value
        acc["first_record_id"] = row["record_id"]
    if acc["previous_epoch"] is not None:
        gap = max(0.0, epoch - acc["previous_epoch"])
        acc["gap_sum"] += gap
        acc["gap_count"] += 1
        acc["minimum_gap"] = gap if acc["minimum_gap"] is None else min(acc["minimum_gap"], gap)
        acc["maximum_gap"] = max(acc["maximum_gap"], gap)
    acc["previous_epoch"] = epoch
    acc["last_epoch"] = epoch
    acc["last_event_type"] = event_type_value
    acc["last_record_id"] = row["record_id"]
    acc["active_hours"].add(datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H"))
    if len(acc["event_types_sequence"]) < MAX_SEQUENCE_LENGTH:
        acc["event_types_sequence"].append(normalize_token(event_type_value))
    if len(acc["outcome_sequence"]) < MAX_SEQUENCE_LENGTH:
        acc["outcome_sequence"].append(outcome)
    if username and len(acc["username_sequence"]) < MAX_SEQUENCE_LENGTH:
        acc["username_sequence"].append(normalize_token(username))
    method = clean(row["authentication_method"])
    if method and len(acc["method_sequence"]) < MAX_SEQUENCE_LENGTH:
        acc["method_sequence"].append(normalize_token(method))
    acc["event_position"] += 1
    return acc["event_position"]


def common_aggregate_fields(acc):
    """Compute shared counts, entropy, timing and sequence features.
    
    :param acc: Mutable observation accumulator.
    :returns: Aggregate output fields.
    :rtype: dict
    """
    event_type_value, event_type_count = dominant(acc["event_types"])
    process, process_count = dominant(acc["processes"])
    username, username_count = dominant(acc["usernames"])
    source_ip, source_ip_count = dominant(acc["source_ips"])
    return {
        "success_count": acc["outcomes"].get("success", 0),
        "failure_count": acc["outcomes"].get("failure", 0),
        "postponed_count": acc["outcomes"].get("postponed", 0),
        "invalid_user_count": acc["outcomes"].get("invalid_user", 0),
        "account_lock_count": acc["outcomes"].get("account_lock", 0),
        "access_denied_count": acc["outcomes"].get("access_denied", 0),
        "privilege_success_count": sum(count for key, count in acc["event_types"].items() if key == "SU_SESSION_SUCCESS"),
        "privilege_failure_count": sum(count for key, count in acc["event_types"].items() if key == "SU_SESSION_FAILED"),
        "connection_open_count": sum(count for key, count in acc["event_types"].items() if key in SUCCESS_EVENTS),
        "connection_close_count": sum(count for key, count in acc["event_types"].items() if "CLOSED" in key),
        "connection_reset_count": sum(count for key, count in acc["event_types"].items() if "RESET" in key),
        "disconnect_count": sum(count for key, count in acc["event_types"].items() if "DISCONNECT" in key),
        "protocol_error_count": sum(count for key, count in acc["event_types"].items() if any(token in key for token in ("PROTOCOL", "PACKET", "DISPATCH", "KEX"))),
        "pam_error_count": sum(count for key, count in acc["event_types"].items() if "PAM" in key),
        "key_error_count": sum(count for key, count in acc["event_types"].items() if "KEY" in key),
        "unknown_event_count": acc["event_types"].get("AUTHLOG_UNKNOWN_EVENT", 0),
        "authentication_event_count": acc["categories"].get("authentication", 0),
        "connection_event_count": acc["categories"].get("connection", 0),
        "privilege_event_count": acc["categories"].get("privilege", 0),
        "system_event_count": acc["categories"].get("system", 0),
        "other_category_count": acc["categories"].get("other", 0),
        "unique_event_types": len(acc["event_types"]),
        "unique_processes": len(acc["processes"]),
        "unique_usernames": len(acc["usernames"]),
        "unique_target_usernames": len(acc["target_usernames"]),
        "unique_source_ips": len(acc["source_ips"]),
        "unique_source_ports": len(acc["source_ports"]),
        "unique_authentication_methods": len(acc["methods"]),
        "unique_terminal_paths": len(acc["terminals"]),
        "event_type_entropy": entropy(acc["event_types"]),
        "process_entropy": entropy(acc["processes"]),
        "username_entropy": entropy(acc["usernames"]),
        "source_ip_entropy": entropy(acc["source_ips"]),
        "dominant_event_type": event_type_value,
        "dominant_event_type_count": event_type_count,
        "dominant_process": process,
        "dominant_process_count": process_count,
        "dominant_username": username,
        "dominant_username_count": username_count,
        "dominant_source_ip": source_ip,
        "dominant_source_ip_count": source_ip_count,
        "first_event_type": acc["first_event_type"],
        "last_event_type": acc["last_event_type"],
        "first_record_id": acc["first_record_id"],
        "last_record_id": acc["last_record_id"],
        "first_timestamp": epoch_to_text(acc["first_epoch"]),
        "last_timestamp": epoch_to_text(acc["last_epoch"]),
        "active_span_seconds": max(0.0, acc["last_epoch"] - acc["first_epoch"]),
        "mean_inter_event_seconds": acc["gap_sum"] / max(acc["gap_count"], 1),
        "minimum_inter_event_seconds": acc["minimum_gap"] if acc["minimum_gap"] is not None else 0.0,
        "maximum_inter_event_seconds": acc["maximum_gap"],
        "event_type_sequence": " ".join(acc["event_types_sequence"]),
        "outcome_sequence": " ".join(acc["outcome_sequence"]),
    }


def open_output_pair(dataset_path, lineage_path, fields):
    """Open temporary dataset and lineage CSVs and write their headers.
    
    :param dataset_path: Destination observation CSV path.
    :param lineage_path: Destination lineage CSV path.
    :param fields: Ordered observation column names.
    :returns: Two handles, two CSV writers and two temporary filenames.
    :rtype: tuple
    """
    dataset_tmp = str(dataset_path) + ".tmp"
    lineage_tmp = str(lineage_path) + ".tmp"
    dataset_handle = open(dataset_tmp, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
    lineage_handle = open(lineage_tmp, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
    writer = csv.DictWriter(dataset_handle, fieldnames=fields, extrasaction="ignore")
    lineage_writer = csv.DictWriter(lineage_handle, fieldnames=LINEAGE_OUTPUT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    lineage_writer.writeheader()
    return dataset_handle, lineage_handle, writer, lineage_writer, dataset_tmp, lineage_tmp


def commit_pair(values, dataset_path, lineage_path):
    """Close and replace the two output files sequentially.
    
    :param values: Six-element handle/writer/path tuple from open_output_pair.
    :param dataset_path: Destination observation CSV path.
    :param lineage_path: Destination lineage CSV path.
    :rtype: None
    
    .. note::
    
       Each replacement is atomic, but the pair is not a single transaction.
    """
    dataset_handle, lineage_handle, _, _, dataset_tmp, lineage_tmp = values
    dataset_handle.close()
    lineage_handle.close()
    os.replace(dataset_tmp, dataset_path)
    os.replace(lineage_tmp, lineage_path)
    LOGGER.debug("Committed dataset and lineage files: %s; %s", dataset_path, lineage_path)


def discard_pair(values):
    """Close output handles and delete any remaining temporary files.
    
    :param values: Six-element handle/writer/path tuple from open_output_pair.
    :rtype: None
    """
    dataset_handle, lineage_handle, _, _, dataset_tmp, lineage_tmp = values
    for handle in (dataset_handle, lineage_handle):
        if not handle.closed:
            handle.close()
    for path in (dataset_tmp, lineage_tmp):
        if os.path.exists(path):
            os.remove(path)


def write_individual_dataset(connection):
    """Write one observation and one lineage link per event.
    
    :param connection: Open SQLite connection to the observation store.
    :returns: Dataset path, lineage path, observation count, link count and count-column marker.
    :rtype: tuple
    """
    LOGGER.info("[5/9] Individual events: starting")
    progress = Progress("[5/9] Individual events: source events processed")
    dataset_path = OUTPUT_FOLDER / "authlog_events_all_months.csv"
    lineage_path = OUTPUT_FOLDER / "authlog_events_all_months_lineage.csv"
    pair = open_output_pair(dataset_path, lineage_path, INDIVIDUAL_OUTPUT_FIELDS)
    _, _, writer, lineage_writer, _, _ = pair
    rows = lineage_rows = 0
    batch = []
    lineage_batch = []
    try:
        for row in event_rows(connection):
            progress.report(lineage_rows)
            timestamp = datetime.fromtimestamp(float(row["timestamp_epoch"]), tz=timezone.utc)
            ip_version, ip_zone, ip_subnet = network_properties(row["source_ip"])
            output = dict(row)
            output.update({
                "row_manifest_id": row["record_id"],
                "timestamp": row["timestamp_text"],
                "source_ip_version": ip_version,
                "source_ip_zone": ip_zone,
                "source_ip_subnet": ip_subnet,
                "source_port_category": port_category(row["source_port"]),
                "hour_of_day": timestamp.hour,
                "day_of_week": timestamp.weekday(),
                "is_weekend": int(timestamp.weekday() >= 5),
                "normalized_event_token": normalize_token(row["event_type"]),
                "normalized_message": normalize_message(row["raw_message"] or row["original_log_line"]),
            })
            batch.append(output)
            lineage_batch.append({
                "dataset": "individual", "row_manifest_id": row["record_id"],
                "record_id": row["record_id"], "event_position": 1,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "individual_event",
            })
            rows += 1
            lineage_rows += 1
            if len(batch) >= CSV_WRITE_BATCH_SIZE:
                writer.writerows(batch)
                lineage_writer.writerows(lineage_batch)
                batch.clear(); lineage_batch.clear()
        if batch:
            writer.writerows(batch); lineage_writer.writerows(lineage_batch)
        commit_pair(pair, dataset_path, lineage_path)
        progress.report(lineage_rows, force=True)
        LOGGER.info("Completed %s: %s observations, %s lineage links",
                    dataset_path.name, rows, lineage_rows)
    except Exception:
        discard_pair(pair); raise
    return dataset_path, lineage_path, rows, lineage_rows, "__one__"


def host_window_id(start_epoch, host_id):
    """Build a stable ID for a host and five-minute bucket.
    
    :param start_epoch: Bucket start in Unix epoch seconds.
    :param host_id: Normalized host identifier.
    :returns: Observation manifest identifier.
    :rtype: str
    """
    return stable_id("auth", "host_5min", start_epoch, host_id)


def finalize_host_window(acc, start_epoch, host_id):
    """Convert a host-window accumulator into an output row.
    
    :param acc: Mutable observation accumulator.
    :param start_epoch: Bucket start in Unix epoch seconds.
    :param host_id: Normalized host identifier.
    :returns: Five-minute observation fields.
    :rtype: dict
    """
    row_id = host_window_id(start_epoch, host_id)
    result = {
        "row_manifest_id": row_id, "dataset_id": row_id, "window_label": "5min",
        "window_start": epoch_to_text(start_epoch),
        "window_end": epoch_to_text(start_epoch + HOST_WINDOW_SECONDS),
        "host_id": host_id, "total_events": acc["total_events"],
        "events_per_minute": acc["total_events"] / 5.0,
    }
    result.update(common_aggregate_fields(acc))
    return result


def write_host_windows(connection):
    """Write five-minute host observations and every contributing lineage link.
    
    :param connection: Open SQLite connection to the observation store.
    :returns: Dataset path, lineage path, observation count, link count and count-column name.
    :rtype: tuple
    """
    LOGGER.info("[6/9] Five-minute host windows: starting")
    progress = Progress("[6/9] Five-minute host windows: source events processed")
    dataset_path = OUTPUT_FOLDER / "authlog_host_windows_5min.csv"
    lineage_path = OUTPUT_FOLDER / "authlog_host_windows_5min_lineage.csv"
    pair = open_output_pair(dataset_path, lineage_path, HOST_WINDOW_OUTPUT_FIELDS)
    _, _, writer, lineage_writer, _, _ = pair
    active = {}; rows = lineage_rows = 0; lineage_batch = []
    try:
        for row in event_rows(connection):
            progress.report(lineage_rows)
            start = bucket_start(row["timestamp_epoch"], HOST_WINDOW_SECONDS)
            host_id = row["host_id"]
            current = active.get(host_id)
            if current is None or current[0] != start:
                if current is not None:
                    writer.writerow(finalize_host_window(current[1], current[0], host_id)); rows += 1
                current = (start, new_accumulator()); active[host_id] = current
            position = update_accumulator(current[1], row)
            lineage_batch.append({
                "dataset": "host_5min", "row_manifest_id": host_window_id(start, host_id),
                "record_id": row["record_id"], "event_position": position,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "host_window_member",
            }); lineage_rows += 1
            if len(lineage_batch) >= CSV_WRITE_BATCH_SIZE:
                lineage_writer.writerows(lineage_batch); lineage_batch.clear()
        for host_id, (start, acc) in sorted(active.items()):
            writer.writerow(finalize_host_window(acc, start, host_id)); rows += 1
        if lineage_batch: lineage_writer.writerows(lineage_batch)
        commit_pair(pair, dataset_path, lineage_path)
        progress.report(lineage_rows, force=True)
        LOGGER.info("Completed %s: %s observations, %s lineage links",
                    dataset_path.name, rows, lineage_rows)
    except Exception:
        discard_pair(pair); raise
    return dataset_path, lineage_path, rows, lineage_rows, "total_events"


def connection_key(row):
    """Return the TCP-connection key when the event carries IP and port.

    :param row: Event dictionary from the SQLite store.
    :returns: ``("connection", host, ip, port)`` or None.
    :rtype: tuple or None
    """
    source_ip, source_port = clean(row["source_ip"]), clean(row["source_port"])
    if source_ip and source_port:
        return ("connection", row["host_id"], source_ip, source_port)
    return None


def process_key(row):
    """Return the local-process key for events without connection identity.

    :param row: Event dictionary from the SQLite store.
    :returns: ``("process", host, process, pid, username)``.
    :rtype: tuple
    """
    return ("process", row["host_id"], clean(row["process_name"]) or "unknown-process",
            clean(row["pid"]), clean(row["username"]))


def resolve_session_key(row, active, pid_owner):
    """Choose the session an event belongs to.

    Order: connection key; otherwise the open connection session that the same
    host/process/PID last belonged to; otherwise the process key.

    :param row: Event dictionary from the SQLite store.
    :param active: Open sessions keyed by session key.
    :param pid_owner: Mapping of (host, process, pid) to the last connection key.
    :returns: Session key.
    :rtype: tuple
    """
    pid = clean(row["pid"])
    pid_reference = (row["host_id"], clean(row["process_name"]), pid) if pid else None
    key = connection_key(row)
    if key is not None:
        if pid_reference is not None:
            pid_owner[pid_reference] = key
        return key
    if pid_reference is not None:
        owner = pid_owner.get(pid_reference)
        if owner is not None and owner in active:
            return owner
    return process_key(row)


def new_session(row, key):
    """Initialize a session and its accumulator from the first event.

    The first source record distinguishes consecutive sessions with identical
    keys and second-resolution timestamps. The source SQLite table enforces
    unique record IDs. Dataset rows and lineage links share this ID.
    
    :param row: Event dictionary from the SQLite store.
    :param key: Session key from :func:`resolve_session_key`.
    :returns: Mutable session state.
    :rtype: dict
    """
    acc = new_accumulator()
    acc.update({
        "row_manifest_id": stable_id("auth", "session", *key, row["timestamp_epoch"], row["record_id"]),
        "session_key_type": key[0], "host_id": row["host_id"],
        "process_name": clean(row["process_name"]) or "unknown-process",
        "pid": clean(row["pid"]), "username": clean(row["username"]),
        "source_ip": clean(row["source_ip"]), "source_port": clean(row["source_port"]),
        "authentication_succeeded": 0, "authentication_failed": 0,
        "session_closed": 0, "closing_epoch": None, "close_reason": "",
    })
    return acc


def session_expiry(session, epoch):
    """Return why an open session must close before an event at ``epoch``.

    :param session: Open session state.
    :param epoch: Timestamp of the event being processed, in epoch seconds.
    :returns: ``"terminal"``, ``"inactivity"`` or None if still open.
    :rtype: str or None
    """
    if session["closing_epoch"] is not None and epoch - session["closing_epoch"] > SESSION_TERMINAL_GRACE_SECONDS:
        return "terminal"
    if epoch - session["last_epoch"] > SESSION_INACTIVITY_SECONDS:
        return "inactivity"
    return None


def finalize_session(acc):
    """Convert session state to timing, outcome and sequence features.
    
    :param acc: Mutable observation accumulator.
    :returns: Session output fields.
    :rtype: dict
    """
    common = common_aggregate_fields(acc)
    return {
        "row_manifest_id": acc["row_manifest_id"],
        "authentication_session_id": acc["row_manifest_id"],
        "session_start": epoch_to_text(acc["first_epoch"]),
        "session_end": epoch_to_text(acc["last_epoch"]),
        "duration_seconds": max(0.0, acc["last_epoch"] - acc["first_epoch"]),
        "inactivity_threshold_seconds": SESSION_INACTIVITY_SECONDS,
        "session_key_type": acc["session_key_type"],
        "close_reason": acc["close_reason"],
        "host_id": acc["host_id"], "process_name": acc["process_name"],
        "pid": acc["pid"], "username": acc["username"],
        "source_ip": acc["source_ip"], "source_port": acc["source_port"],
        "event_count": acc["total_events"],
        "events_per_minute": acc["total_events"] / max((acc["last_epoch"] - acc["first_epoch"]) / 60.0, 1.0),
        "success_count": common["success_count"],
        "failure_count": common["failure_count"],
        "postponed_count": common["postponed_count"],
        "invalid_user_count": common["invalid_user_count"],
        "account_lock_count": common["account_lock_count"],
        "access_denied_count": common["access_denied_count"],
        "connection_close_count": common["connection_close_count"],
        "connection_reset_count": common["connection_reset_count"],
        "disconnect_count": common["disconnect_count"],
        "protocol_error_count": common["protocol_error_count"],
        "pam_error_count": common["pam_error_count"],
        "key_error_count": common["key_error_count"],
        "unknown_event_count": common["unknown_event_count"],
        "unique_event_types": common["unique_event_types"],
        "unique_usernames": common["unique_usernames"],
        "unique_target_usernames": common["unique_target_usernames"],
        "unique_authentication_methods": common["unique_authentication_methods"],
        "unique_terminal_paths": common["unique_terminal_paths"],
        "unique_reasons": len(acc["reasons"]),
        "authentication_succeeded": acc["authentication_succeeded"],
        "authentication_failed": acc["authentication_failed"],
        "session_closed": acc["session_closed"],
        "first_event_type": common["first_event_type"],
        "last_event_type": common["last_event_type"],
        "first_record_id": common["first_record_id"],
        "last_record_id": common["last_record_id"],
        "mean_inter_event_seconds": common["mean_inter_event_seconds"],
        "maximum_inter_event_seconds": common["maximum_inter_event_seconds"],
        "event_type_sequence": common["event_type_sequence"],
        "outcome_sequence": common["outcome_sequence"],
        "username_sequence": " ".join(acc["username_sequence"]),
        "authentication_method_sequence": " ".join(acc["method_sequence"]),
    }


def write_sessions(connection):
    """Group events into connection/process sessions (see module docstring).
    
    :param connection: Open SQLite connection to the observation store.
    :returns: Dataset path, lineage path, observation count, link count and count-column name.
    :rtype: tuple
    """
    LOGGER.info("[7/9] Authentication sessions: starting")
    progress = Progress("[7/9] Authentication sessions: source events processed")
    dataset_path = OUTPUT_FOLDER / "authlog_authentication_sessions.csv"
    lineage_path = OUTPUT_FOLDER / "authlog_authentication_sessions_lineage.csv"
    pair = open_output_pair(dataset_path, lineage_path, SESSION_OUTPUT_FIELDS)
    _, _, writer, lineage_writer, _, _ = pair
    active = {}; pid_owner = {}; rows = lineage_rows = 0; lineage_batch = []
    reasons = Counter(); key_types = Counter(); last_sweep = None

    def close(session, reason):
        nonlocal rows
        session["close_reason"] = reason
        writer.writerow(finalize_session(session)); rows += 1
        reasons[reason] += 1
        key_types[session["session_key_type"]] += 1

    def sweep(epoch):
        expired = []
        for key, session in active.items():
            reason = session_expiry(session, epoch)
            if reason:
                expired.append((session["first_epoch"], session["row_manifest_id"], key, reason))
        for _, _, key, reason in sorted(expired):
            close(active.pop(key), reason)
        for reference in [ref for ref, owner in pid_owner.items() if owner not in active]:
            del pid_owner[reference]

    try:
        for row in event_rows(connection):
            progress.report(lineage_rows)
            epoch = float(row["timestamp_epoch"])
            if last_sweep is None:
                last_sweep = epoch
            elif epoch - last_sweep >= SESSION_SWEEP_SECONDS:
                sweep(epoch); last_sweep = epoch
            key = resolve_session_key(row, active, pid_owner)
            session = active.get(key)
            if session is not None:
                reason = session_expiry(session, epoch)
                if reason:
                    close(active.pop(key), reason); session = None
            if session is None:
                session = new_session(row, key); active[key] = session
            position = update_accumulator(session, row)
            if not session["username"] and clean(row["username"]):
                session["username"] = clean(row["username"])
            if row["event_type"] in SUCCESS_EVENTS: session["authentication_succeeded"] = 1
            if row["event_type"] in FAILURE_EVENTS: session["authentication_failed"] = 1
            if row["event_type"] in SESSION_TERMINAL_EVENTS:
                session["session_closed"] = 1
                if session["closing_epoch"] is None:
                    session["closing_epoch"] = epoch
            lineage_batch.append({
                "dataset": "authentication_sessions",
                "row_manifest_id": session["row_manifest_id"],
                "record_id": row["record_id"], "event_position": position,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "authentication_session_member",
            }); lineage_rows += 1
            if len(lineage_batch) >= CSV_WRITE_BATCH_SIZE:
                lineage_writer.writerows(lineage_batch); lineage_batch.clear()
        for key, session in sorted(active.items(), key=lambda item: (item[1]["first_epoch"], item[1]["row_manifest_id"])):
            close(session, "terminal" if session["closing_epoch"] is not None else "end_of_data")
        active.clear()
        if lineage_batch: lineage_writer.writerows(lineage_batch)
        commit_pair(pair, dataset_path, lineage_path)
        progress.report(lineage_rows, force=True)
        LOGGER.info("Completed %s: %s observations, %s lineage links (%.2f events/session)",
                    dataset_path.name, rows, lineage_rows, lineage_rows / max(rows, 1))
        LOGGER.info("Session close reasons: %s", dict(reasons))
        LOGGER.info("Session key types: %s", dict(key_types))
    except Exception:
        discard_pair(pair); raise
    return dataset_path, lineage_path, rows, lineage_rows, "event_count"


def behavior_id(start_epoch, host_id):
    """Build a stable ID for a host and daily bucket.
    
    :param start_epoch: Bucket start in Unix epoch seconds.
    :param host_id: Normalized host identifier.
    :returns: Observation manifest identifier.
    :rtype: str
    """
    return stable_id("auth", "host_behavior_1d", start_epoch, host_id)


def finalize_behavior(acc, start, host_id, history):
    """Compute daily features and update host novelty history in place.
    
    :param acc: Mutable observation accumulator.
    :param start: Daily bucket start in Unix epoch seconds.
    :param host_id: Normalized host identifier.
    :param history: Mutable per-host sets of previously observed values.
    :returns: Daily observation fields.
    :rtype: dict
    """
    prior = history.setdefault(host_id, {
        "event_types": set(), "processes": set(), "usernames": set(),
        "target_usernames": set(), "source_ips": set(), "methods": set(),
    })
    current = {
        "event_types": set(acc["event_types"]),
        "processes": set(acc["processes"]),
        "usernames": set(acc["usernames"]),
        "target_usernames": set(acc["target_usernames"]),
        "source_ips": set(acc["source_ips"]),
        "methods": set(acc["methods"]),
    }
    common = common_aggregate_fields(acc)
    row_id = behavior_id(start, host_id)
    result = {
        "row_manifest_id": row_id, "dataset_id": row_id, "window_label": "1d",
        "window_start": epoch_to_text(start), "window_end": epoch_to_text(start + 86400),
        "host_id": host_id, "total_events": acc["total_events"],
        "events_per_hour": acc["total_events"] / 24.0,
        "active_hours": len(acc["active_hours"]),
        "new_event_types": len(current["event_types"] - prior["event_types"]),
        "new_processes": len(current["processes"] - prior["processes"]),
        "new_usernames": len(current["usernames"] - prior["usernames"]),
        "new_target_usernames": len(current["target_usernames"] - prior["target_usernames"]),
        "new_source_ips": len(current["source_ips"] - prior["source_ips"]),
        "new_authentication_methods": len(current["methods"] - prior["methods"]),
    }
    result.update(common)
    for key in prior:
        prior[key].update(current[key])
    return result


def write_behavior(connection):
    """Write daily host observations with historical novelty and lineage.
    
    :param connection: Open SQLite connection to the observation store.
    :returns: Dataset path, lineage path, observation count, link count and count-column name.
    :rtype: tuple
    """
    LOGGER.info("[8/9] Daily host behavior: starting")
    progress = Progress("[8/9] Daily host behavior: source events processed")
    dataset_path = OUTPUT_FOLDER / "authlog_host_behavior_1d.csv"
    lineage_path = OUTPUT_FOLDER / "authlog_host_behavior_1d_lineage.csv"
    pair = open_output_pair(dataset_path, lineage_path, BEHAVIOR_OUTPUT_FIELDS)
    _, _, writer, lineage_writer, _, _ = pair
    active = {}; history = {}; rows = lineage_rows = 0; lineage_batch = []
    try:
        for row in event_rows(connection):
            progress.report(lineage_rows)
            start = bucket_start(row["timestamp_epoch"], 86400); host_id = row["host_id"]
            current = active.get(host_id)
            if current is None or current[0] != start:
                if current is not None:
                    writer.writerow(finalize_behavior(current[1], current[0], host_id, history)); rows += 1
                current = (start, new_accumulator()); active[host_id] = current
            position = update_accumulator(current[1], row)
            lineage_batch.append({
                "dataset": "host_behavior_1d", "row_manifest_id": behavior_id(start, host_id),
                "record_id": row["record_id"], "event_position": position,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "host_behavior_member",
            }); lineage_rows += 1
            if len(lineage_batch) >= CSV_WRITE_BATCH_SIZE:
                lineage_writer.writerows(lineage_batch); lineage_batch.clear()
        for host_id, (start, acc) in sorted(active.items()):
            writer.writerow(finalize_behavior(acc, start, host_id, history)); rows += 1
        if lineage_batch: lineage_writer.writerows(lineage_batch)
        commit_pair(pair, dataset_path, lineage_path)
        progress.report(lineage_rows, force=True)
        LOGGER.info("Completed %s: %s observations, %s lineage links",
                    dataset_path.name, rows, lineage_rows)
    except Exception:
        discard_pair(pair); raise
    return dataset_path, lineage_path, rows, lineage_rows, "total_events"


def validate_dataset_lineage(dataset_path, lineage_path, count_column):
    """Validate observation IDs, unique links and per-observation link counts.
    
    :param dataset_path: Destination observation CSV path.
    :param lineage_path: Destination lineage CSV path.
    :param count_column: Expected membership-count column, or __one__ for individual events.
    :returns: Dataset and lineage cardinality statistics.
    :rtype: dict
    :raises ValueError: If input parsing or identity validation fails.
    """
    LOGGER.info("Validating lineage: %s", dataset_path.name)
    progress = Progress("Observation rows checked")
    expected = {}
    with open(dataset_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"row_manifest_id"}
        if count_column != "__one__": required.add(count_column)
        missing = required.difference(reader.fieldnames or [])
        if missing: raise ValueError("Dataset lacks validation fields: " + str(dataset_path))
        for row in reader:
            row_id = clean(row.get("row_manifest_id"))
            if not row_id: raise ValueError("Blank row_manifest_id in " + str(dataset_path))
            if row_id in expected: raise ValueError("Duplicate row_manifest_id: " + row_id)
            expected[row_id] = 1 if count_column == "__one__" else safe_int(row.get(count_column))
            progress.report(len(expected))
    progress.report(len(expected), force=True)
    progress = Progress("Lineage links checked")
    actual = Counter(); links = set(); events = set()
    with open(lineage_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_id = clean(row.get("row_manifest_id")); record_id = clean(row.get("record_id"))
            if not row_id or not record_id: raise ValueError("Blank lineage identity in " + str(lineage_path))
            link = (row_id, record_id)
            if link in links: raise ValueError("Duplicate lineage link: " + row_id + " -> " + record_id)
            links.add(link); events.add(record_id); actual[row_id] += 1
            progress.report(len(links))
    progress.report(len(links), force=True)
    missing_rows = set(expected) - set(actual); unknown_rows = set(actual) - set(expected)
    mismatched = [row_id for row_id, count in expected.items() if actual.get(row_id, 0) != count]
    if missing_rows or unknown_rows or mismatched:
        raise ValueError(
            "Lineage validation failed for " + str(dataset_path)
            + ": missing=" + str(len(missing_rows))
            + ", unknown=" + str(len(unknown_rows))
            + ", mismatched=" + str(len(mismatched))
        )
    return {
        "dataset_rows": len(expected), "lineage_rows": sum(actual.values()),
        "unique_source_records": len(events),
        "minimum_records_per_observation": min(actual.values()) if actual else 0,
        "maximum_records_per_observation": max(actual.values()) if actual else 0,
        "mean_records_per_observation": sum(actual.values()) / len(actual) if actual else 0.0,
    }


def write_summary(records, stem="authlog_observation_dataset_summary"):
    """Write validated dataset summaries as CSV and JSON.
    
    :param records: Validated per-dataset summary dictionaries.
    :param stem: Summary filename stem, without its CSV or JSON extension.
    :rtype: None
    """
    csv_path = OUTPUT_FOLDER / (stem + ".csv")
    json_path = OUTPUT_FOLDER / (stem + ".json")
    fields = [
        "dataset", "dataset_file", "lineage_file", "dataset_rows", "lineage_rows",
        "unique_source_records", "minimum_records_per_observation",
        "maximum_records_per_observation", "mean_records_per_observation",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(records)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({
            "builder_version": BUILDER_VERSION,
            "event_lookup_file": str(EVENT_LOOKUP_FILE),
            "lineage_contract": "row_manifest_id_to_record_id",
            "session_rules": {
                "inactivity_seconds": SESSION_INACTIVITY_SECONDS,
                "terminal_grace_seconds": SESSION_TERMINAL_GRACE_SECONDS,
                "terminal_events": sorted(SESSION_TERMINAL_EVENTS),
            },
            "datasets": records,
        }, handle, indent=2)


def main():
    """Build, validate and summarize all representations or only sessions.
    
    :rtype: None
    """
    global INPUT_FOLDER, OUTPUT_FOLDER, EVENT_LOOKUP_FILE, DATABASE_FILE
    args = parse_args()
    runlog.configure_from(args)
    with runlog.run():
        INPUT_FOLDER = args.input_folder
        OUTPUT_FOLDER = args.output_folder
        EVENT_LOOKUP_FILE = INPUT_FOLDER / "authlog_event_lookup.csv"
        DATABASE_FILE = OUTPUT_FOLDER / "authlog_observation_store.sqlite"
        stems = (
            "authlog_events_all_months", "authlog_host_windows_5min",
            "authlog_authentication_sessions", "authlog_host_behavior_1d",
        )
        summary_stem = "authlog_observation_dataset_summary"
        if args.sessions_only:
            stems = ("authlog_authentication_sessions",)
            summary_stem = "authlog_authentication_sessions_summary"
        expected_outputs = [
            OUTPUT_FOLDER / (stem + suffix)
            for stem in stems for suffix in (".csv", "_lineage.csv")
        ] + [
            OUTPUT_FOLDER / (summary_stem + ".csv"),
            OUTPUT_FOLDER / (summary_stem + ".json"),
        ]
        if outputs_already_produced(expected_outputs, args.force):
            return
        LOGGER.info("[1/9] Discovering inputs and initializing SQLite store")
        OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
        files = input_files()
        LOGGER.info("Found %s monthly CSVs", len(files))
        if DATABASE_FILE.exists():
            LOGGER.info("Rebuilding existing SQLite store: %s", DATABASE_FILE)
            DATABASE_FILE.unlink()
        connection = sqlite3.connect(DATABASE_FILE)
        records = []
        sql_progress = Progress("SQLite operation still running")
        def sqlite_checkpoint():
            """Emit a periodic SQLite activity checkpoint without interrupting SQL.
        
            :returns: Zero so SQLite continues execution.
            :rtype: int
            """
            now = time.monotonic()
            if now - sql_progress.last_report >= runlog.interval():
                LOGGER.info("SQLite active | elapsed %s since database work began",
                            runlog.format_duration(now - sql_progress.started))
                sql_progress.last_report = now
            return 0
        connection.set_progress_handler(sqlite_checkpoint, 100_000)
        try:
            create_database(connection)
            lookup_ids = load_lookup_ids(connection)
            loaded, invalid_timestamps = load_events(connection, files)
            if loaded <= 0: raise ValueError("No valid timestamped authentication events loaded")
            validate_lookup_coverage(connection)
            LOGGER.info("Authentication records loaded: " + str(loaded))
            LOGGER.info("Authentication lookup IDs: " + str(lookup_ids))
            LOGGER.info("Invalid timestamp records skipped: " + str(invalid_timestamps))
            if args.sessions_only:
                generated = [("authentication_sessions",) + write_sessions(connection)]
            else:
                generated = [
                    ("individual",) + write_individual_dataset(connection),
                    ("host_5min",) + write_host_windows(connection),
                    ("authentication_sessions",) + write_sessions(connection),
                    ("host_behavior_1d",) + write_behavior(connection),
                ]
            LOGGER.info("[9/9] Validating generated dataset lineages and writing summaries")
            for dataset, dataset_path, lineage_path, rows, lineage_rows, count_column in generated:
                validation = validate_dataset_lineage(dataset_path, lineage_path, count_column)
                if validation["dataset_rows"] != rows or validation["lineage_rows"] != lineage_rows:
                    raise ValueError("Internal count mismatch for " + dataset)
                record = {
                    "dataset": dataset, "dataset_file": str(dataset_path),
                    "lineage_file": str(lineage_path), **validation,
                }
                records.append(record)
                LOGGER.info(dataset + ": rows=" + str(rows) + ", lineage_rows=" + str(lineage_rows))
            write_summary(records, summary_stem)
            LOGGER.info("All %s generated dataset lineages validated; summaries written", len(records))
        finally:
            connection.set_progress_handler(None, 0)
            connection.close()
        if DELETE_DATABASE_WHEN_COMPLETE and DATABASE_FILE.exists():
            DATABASE_FILE.unlink()
        else:
            LOGGER.info("SQLite observation store: " + str(DATABASE_FILE))
        LOGGER.info("Complete: " + str(OUTPUT_FOLDER / (summary_stem + ".csv")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        LOGGER.exception("Observation dataset build failed")
        sys.exit(1)