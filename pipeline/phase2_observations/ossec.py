"""Build lineage-preserving OSSEC observation datasets.

Step 2 of the OSSEC anomaly-detection workflow.

Inputs
------
data/phase1_classify/ossec/ossec_events_YYYY-MM.csv
data/phase1_classify/ossec/ossec_event_lookup.csv

Outputs
-------
data/phase2_observations/ossec/ossec_events_all_months.csv
data/phase2_observations/ossec/ossec_events_all_months_lineage.csv
data/phase2_observations/ossec/ossec_host_windows_5min.csv
data/phase2_observations/ossec/ossec_host_windows_5min_lineage.csv
data/phase2_observations/ossec/ossec_security_episodes.csv
data/phase2_observations/ossec/ossec_security_episodes_lineage.csv
data/phase2_observations/ossec/ossec_host_behavior_1d.csv
data/phase2_observations/ossec/ossec_host_behavior_1d_lineage.csv
data/phase2_observations/ossec/ossec_observation_dataset_summary.csv
data/phase2_observations/ossec/ossec_observation_dataset_summary.json

Lineage contract
----------------
Every observation has one stable ``row_manifest_id``. Every lineage file is
long-form and maps that observation to every contributing classified OSSEC
``event_id``:

    row_manifest_id -> event_id -> data/phase1_classify/ossec/ossec_event_lookup.csv
                       -> original_log_line / source file / source line

The four initial observation representations are:

* individual: one observation per classified OSSEC event;
* host_5min: one host-oriented five-minute tumbling window;
* episodes: one agent activity lifecycle (see below);
* host_behavior_1d: one source-host behavior summary per UTC day.

The implementation uses SQLite as an on-disk event store so all monthly CSVs
do not need to fit in memory at once.

Episode construction (builder version 02)
-----------------------------------------
Version 01 grouped events by ``(host, process, event_category, source_ip)``
with a 15-minute inactivity gap. That split one agent activity across several
episodes, because the event types of one activity fall into different
categories. For example, an outage produces ``Server unavailable`` (server),
``Waiting for server reply`` (other), ``Trying to connect`` (connection) and
``Connected to the server`` (server). A syscheck scan that runs longer than 15
minutes also split into a lone ``Starting`` episode and a lone ``Ending``
episode, since nothing is logged between them.

Events are now grouped by what the agent was doing:

1. **Scan key** ``(host, process, scan_family)`` for rootcheck, syscheck,
   syscheck forwarding-database and syscheck pre-scan cycles. A start opens
   the episode and the matching end closes it. Inactivity does not apply,
   because a scan is silent between start and end; ``SCAN_MAX_SECONDS``
   bounds an episode whose end never arrives.
2. **Connectivity key** ``(host, process)`` for manager-connection events:
   lock set/released, waiting for reply, next server, connection attempts,
   send failures and socket errors. ``Connected``, ``Server responded`` and
   ``Lock free`` are terminal.
3. **Lifecycle key** ``(host)`` for process start/stop and start-up
   configuration (keys, rules, allowlists, monitored directories, counters).
   Keyed by host because a restart stops and starts every OSSEC process
   together. It closes after ``LIFECYCLE_INACTIVITY_SECONDS`` of silence.
4. **Scan bridge.** Any other event from a ``(host, process)`` with an open
   scan joins that scan (for example an unclassified syscheck error).
5. **Process key** ``(host, process, event_category)`` otherwise, with the
   version 01 15-minute inactivity rule.

A stop event (``SIGNAL Received``, ``Shutdown received``, ``Clean Exit``)
closes any open scan or connectivity episode of the same process with reason
``interrupted`` before joining the lifecycle episode. A second scan start while
a scan is open closes the first with reason ``superseded``.

Terminal events are followed by ``EPISODE_TERMINAL_GRACE_SECONDS`` that absorb
trailing lines logged in the same second. The reason an episode closed is
written to ``close_reason`` (``terminal``, ``inactivity``, ``scan_timeout``,
``interrupted``, ``superseded`` or ``end_of_data``), the grouping key to
``episode_key_type`` and the scan family or category to ``episode_family``.
The summary JSON adds ``episode_statistics``: close reasons, key types and the
scan completion rate (share of scan episodes containing both start and end).
Episodes are flushed by a periodic sweep, so memory stays proportional to
concurrently open episodes. Events within one second are processed in source
file and line order, so a start is never read after its own end.

Monitoring-risk counts (builder version 02)
-------------------------------------------
Aggregate datasets gain ``agent_stop_count``, ``agent_start_count``,
``communication_failure_count``, ``integrity_gap_count`` and
``configuration_gap_count`` (see ``RISK_EVENT_GROUPS``). The model-zoo
benchmark uses them as weak proxy labels.

Command-line usage
------------------
Run with timestamped INFO checkpoints and ten-second activity updates::

    python pipeline/phase2_observations/ossec.py

Rebuild only episodes and their lineage after changing the episode logic::

    python pipeline/phase2_observations/ossec.py --episodes-only

This still reloads source events into SQLite, but preserves the other three
dataset/lineage pairs. It writes separate ``ossec_security_episodes_summary``
CSV/JSON reports; the combined summary is not updated by this mode.

.. note::

   ``--episodes-only`` does not add the monitoring-risk counts to the host
   window and daily behavior datasets. Run the full build once after
   upgrading from builder version 01.

Enable detailed file and batch messages and five-second updates::

    python pipeline/phase2_observations/ossec.py --verbose --progress-interval 5

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
"""

from __future__ import annotations
import time
import argparse
import logging
import sys
import threading
from contextlib import contextmanager
from functools import wraps

import csv
import glob
import hashlib
import json
import math
import os
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import progress_items, stage, timed_stage  # noqa: E402

LOGGER = runlog.LOGGER

INPUT_FOLDER = Path("data/phase1_classify/ossec")
OUTPUT_FOLDER = Path("data/phase2_observations/ossec")
INPUT_PATTERN = "ossec_events_????-??.csv"
EVENT_LOOKUP_FILE = INPUT_FOLDER / "ossec_event_lookup.csv"
DATABASE_FILE = OUTPUT_FOLDER / "ossec_observation_store.sqlite"

OVERWRITE_OUTPUTS = True
DELETE_DATABASE_WHEN_COMPLETE = False
COMMIT_BATCH_SIZE = 50_000
CSV_WRITE_BATCH_SIZE = 10_000
HOST_WINDOW_SECONDS = 300
EPISODE_INACTIVITY_SECONDS = 15 * 60
LIFECYCLE_INACTIVITY_SECONDS = 120
EPISODE_TERMINAL_GRACE_SECONDS = 10
SCAN_MAX_SECONDS = 6 * 3600
EPISODE_SWEEP_SECONDS = 60

BUILDER_VERSION = "2026-09-23-ossec-episode-lifecycles-02"

# Filled by write_episode_dataset and written to the summary JSON.
EPISODE_STATISTICS = {}

# Scan cycles: event type -> (scan family, start or end).
SCAN_EVENTS = {
    "OSSEC_ROOTCHECK_SCAN_STARTED": ("rootcheck", "start"),
    "OSSEC_ROOTCHECK_SCAN_ENDED": ("rootcheck", "end"),
    "OSSEC_SYSCHECK_SCAN_STARTED": ("syscheck", "start"),
    "OSSEC_SYSCHECK_SCAN_ENDED": ("syscheck", "end"),
    "OSSEC_SYSCHECK_FORWARDING_SCAN_STARTED": ("syscheck_forwarding", "start"),
    "OSSEC_SYSCHECK_FORWARDING_SCAN_ENDED": ("syscheck_forwarding", "end"),
    "OSSEC_SYSCHECK_DATABASE_PRESCAN_STARTED": ("syscheck_prescan", "start"),
    "OSSEC_SYSCHECK_DATABASE_PRESCAN_COMPLETED": ("syscheck_prescan", "end"),
}

CONNECTIVITY_EVENTS = frozenset({
    "OSSEC_SERVER_UNAVAILABLE_LOCK_SET", "OSSEC_SERVER_RESPONDED_LOCK_RELEASED",
    "OSSEC_LOCK_FREE_CONTINUING", "OSSEC_PROCESS_LOCKED", "OSSEC_SERVER_CONNECTED",
    "OSSEC_WAITING_FOR_REPLY", "OSSEC_NEXT_SERVER", "OSSEC_CONNECTION_CLOSED",
    "OSSEC_CONNECTION_ATTEMPT", "OSSEC_USING_IPV4",
    "OSSEC_SERVER_MESSAGE_SEND_FAILED", "OSSEC_QUEUE_MESSAGE_SEND_FAILED",
    "OSSEC_SOCKET_ERROR_UNAVAILABLE",
})

CONNECTIVITY_TERMINAL_EVENTS = frozenset({
    "OSSEC_SERVER_CONNECTED", "OSSEC_SERVER_RESPONDED_LOCK_RELEASED",
    "OSSEC_LOCK_FREE_CONTINUING",
})

LIFECYCLE_STOP_EVENTS = frozenset({
    "OSSEC_SIGNAL_RECEIVED_EXITING", "OSSEC_SHUTDOWN_RESPONSES_DELETED",
    "OSSEC_EMAIL_DISABLED_CLEAN_EXIT",
})

LIFECYCLE_EVENTS = LIFECYCLE_STOP_EVENTS | frozenset({
    "OSSEC_PROCESS_STARTED", "OSSEC_AUTHENTICATION_KEYS_READING",
    "OSSEC_LOCAL_DECODER_READING", "OSSEC_RULES_FILE_READING",
    "OSSEC_RULES_ENABLED_TOTAL", "OSSEC_DIRECTORY_MONITORING_STARTED",
    "OSSEC_LOG_FILE_ANALYSIS_STARTED", "OSSEC_FILE_IGNORED",
    "OSSEC_AGENT_COUNTER_ASSIGNED", "OSSEC_SENDER_COUNTER_ASSIGNED",
    "OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE", "OSSEC_MANAGER_IP_NOT_SET",
    "OSSEC_SERVER_IP_CONFIGURED", "OSSEC_ACTIVE_RESPONSE_IP_ALLOWLIST_COUNT",
    "OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLIST_COUNT",
    "OSSEC_ACTIVE_RESPONSE_IP_ALLOWLISTED",
    "OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLISTED", "OSSEC_EXEC_QUEUE_CONNECTED",
    "OSSEC_ACTIVE_RESPONSE_COMMAND_UNAVAILABLE",
    "OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND", "OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND",
})

# Monitoring-risk groups counted in every aggregate dataset.
RISK_EVENT_GROUPS = {
    "agent_stop": LIFECYCLE_STOP_EVENTS,
    "agent_start": frozenset({"OSSEC_PROCESS_STARTED"}),
    "communication_failure": frozenset({
        "OSSEC_SERVER_UNAVAILABLE_LOCK_SET", "OSSEC_WAITING_FOR_REPLY",
        "OSSEC_NEXT_SERVER", "OSSEC_CONNECTION_CLOSED", "OSSEC_PROCESS_LOCKED",
        "OSSEC_SERVER_MESSAGE_SEND_FAILED", "OSSEC_QUEUE_MESSAGE_SEND_FAILED",
        "OSSEC_SOCKET_ERROR_UNAVAILABLE",
    }),
    "integrity_gap": frozenset({
        "OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND", "OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND",
        "OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE",
    }),
    "configuration_gap": frozenset({
        "OSSEC_MANAGER_IP_NOT_SET", "OSSEC_ACTIVE_RESPONSE_COMMAND_UNAVAILABLE",
    }),
}
RISK_GROUP_BY_EVENT = {
    event_type: group
    for group, event_types in RISK_EVENT_GROUPS.items()
    for event_type in event_types
}
RISK_COUNT_FIELDS = [group + "_count" for group in RISK_EVENT_GROUPS]

REQUIRED_INPUT_FIELDS = {
    "event_id",
    "raw_line_sha256",
    "timestamp",
    "hostname",
    "process_name",
    "severity",
    "event_type",
    "raw_message",
    "original_log_line",
    "partition_month",
    "source_file",
    "source_line",
    "archive_name",
    "archive_member",
}

OPTIONAL_INPUT_FIELDS = (
    "session_id", "pid", "username", "source_ip", "source_port",
    "destination_hostname", "destination_ip", "destination_port",
    "authentication_method", "connection_stage", "scan_mode", "operation",
    "started_pid", "agent_name", "counter_value", "event_threshold",
    "previous_event_count", "current_event_count", "retained_percentage",
    "allowlist_count", "allowlisted_ip", "allowlisted_hostname", "queue_path",
    "queue_name", "rules_enabled_count", "monitored_path", "analyzed_file",
    "rules_file", "ignored_file", "command_path", "checksum_algorithm",
    "checksum_source_file", "checksum_file", "reason", "classification_line",
)

INDIVIDUAL_OUTPUT_FIELDS = [
    "row_manifest_id", "event_id", "timestamp", "timestamp_epoch",
    "partition_month", "hostname", "host_id", "host_identity_type",
    "process_name", "pid", "severity", "severity_rank", "event_type",
    "event_category", "username", "source_ip", "source_port",
    "destination_hostname", "destination_ip", "destination_port",
    "authentication_method", "connection_stage", "scan_mode", "operation",
    "started_pid", "agent_name", "counter_value", "event_threshold",
    "previous_event_count", "current_event_count", "retained_percentage",
    "allowlist_count", "allowlisted_ip", "allowlisted_hostname", "queue_path",
    "queue_name", "rules_enabled_count", "monitored_path", "analyzed_file",
    "rules_file", "ignored_file", "command_path", "checksum_algorithm",
    "checksum_source_file", "checksum_file", "reason", "hour_of_day",
    "day_of_week", "is_weekend", "normalized_event_token",
    "normalized_message", "raw_message", "original_log_line",
    "raw_line_sha256", "source_file", "source_line", "archive_name",
    "archive_member",
]

HOST_WINDOW_OUTPUT_FIELDS = [
    "row_manifest_id", "dataset_id", "window_label", "window_start",
    "window_end", "host_id", "host_identity_type", "hostname", "agent_name",
    "total_events", "events_per_minute", "active_span_seconds",
    "mean_inter_event_seconds", "minimum_inter_event_seconds",
    "maximum_inter_event_seconds", "severity_rank_sum", "mean_severity_rank",
    "maximum_severity_rank", "debug_count", "info_count", "notice_count",
    "warning_count", "error_count", "critical_count", "alert_count",
    "emergency_count", "unknown_severity_count", "unknown_event_count",
    "authentication_count", "rootcheck_count", "syscheck_count",
    "connection_count", "agent_count", "server_count", "queue_count",
    "rules_count", "file_count", "active_response_count", "other_category_count",
    *RISK_COUNT_FIELDS,
    "unique_event_types", "unique_processes", "unique_users",
    "unique_source_ips", "unique_destination_ips", "unique_agents",
    "unique_monitored_paths", "unique_files", "event_type_entropy",
    "process_entropy", "severity_entropy", "dominant_event_type",
    "dominant_event_type_count", "dominant_process", "dominant_process_count",
    "dominant_severity", "dominant_severity_count", "first_event_type",
    "last_event_type", "first_event_id", "last_event_id", "first_timestamp",
    "last_timestamp", "event_type_sequence",
]

EPISODE_OUTPUT_FIELDS = [
    "row_manifest_id", "episode_id", "episode_start", "episode_end",
    "duration_seconds", "inactivity_threshold_seconds", "episode_key_type",
    "episode_family", "close_reason", "episode_completed", "host_id",
    "host_identity_type", "hostname", "agent_name", "process_name",
    "event_category", "source_ip", "event_count", "events_per_minute",
    "severity_rank_sum", "mean_severity_rank", "maximum_severity_rank",
    "severity_increase", "debug_count", "info_count", "notice_count",
    "warning_count", "error_count", "critical_count", "alert_count",
    "emergency_count", "unknown_severity_count", "unknown_event_count",
    *RISK_COUNT_FIELDS,
    "unique_event_types", "unique_processes", "unique_categories",
    "unique_users", "unique_destination_ips",
    "unique_files", "unique_reasons", "first_event_type", "last_event_type",
    "first_event_id", "last_event_id", "mean_inter_event_seconds",
    "maximum_inter_event_seconds", "event_type_sequence",
    "severity_sequence", "username_sequence",
]

BEHAVIOR_OUTPUT_FIELDS = [
    "row_manifest_id", "dataset_id", "window_label", "window_start",
    "window_end", "host_id", "host_identity_type", "hostname", "agent_name",
    "total_events", "events_per_hour", "active_hours", "active_span_seconds",
    "mean_inter_event_seconds", "maximum_inter_event_seconds",
    "severity_rank_sum", "mean_severity_rank", "maximum_severity_rank",
    "high_severity_count", "unknown_event_count", *RISK_COUNT_FIELDS,
    "unique_event_types",
    "unique_processes", "unique_users", "unique_source_ips",
    "unique_destination_ips", "unique_agents", "unique_files",
    "unique_reasons", "new_event_types", "new_processes", "new_users",
    "new_source_ips", "new_destination_ips", "new_agents", "new_files",
    "event_type_entropy", "process_entropy", "severity_entropy",
    "source_ip_entropy", "dominant_event_type", "dominant_event_type_count",
    "dominant_process", "dominant_process_count", "dominant_severity",
    "dominant_severity_count", "first_event_type", "last_event_type",
    "first_event_id", "last_event_id", "first_timestamp", "last_timestamp",
    "event_type_sequence",
]

LINEAGE_OUTPUT_FIELDS = [
    "dataset", "row_manifest_id", "event_id", "event_position",
    "event_timestamp", "relationship_role",
]

SEVERITY_RANKS = {
    "TRACE": 0,
    "DEBUG": 1,
    "INFO": 2,
    "INFORMATION": 2,
    "NOTICE": 3,
    "WARN": 4,
    "WARNING": 4,
    "ERR": 5,
    "ERROR": 5,
    "CRIT": 6,
    "CRITICAL": 6,
    "ALERT": 7,
    "EMERG": 8,
    "EMERGENCY": 8,
    "FATAL": 8,
}

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_args():
    """Parse verbosity, heartbeat interval and episodes-only settings.

    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    runlog.add_arguments(parser)
    parser.add_argument("--episodes-only", action="store_true",
                        help="Rebuild only episodes and their lineage; keep the other datasets.")
    args = parser.parse_args()
    return args


def clean(value):
    """Convert a value to stripped text, mapping None to empty text.
    
    :param value: Value to normalize or interpret.
    :returns: Normalized text.
    :rtype: str
    """
    return str(value).strip() if value is not None else ""


def safe_float(value, default=0.0):
    """Convert text to float, using a default on type or value errors.
    
    :param value: Value to normalize or interpret.
    :param default: Fallback floating-point value.
    :returns: Parsed number or fallback.
    :rtype: float
    """
    try:
        return float(clean(value))
    except (TypeError, ValueError):
        return default


def parse_timestamp(value):
    """Parse supported date/time strings and interpret them as UTC.
    
    :param value: Value to normalize or interpret.
    :returns: Timezone-aware UTC datetime.
    :rtype: datetime
    :raises ValueError: If parsing or identity validation fails.
    """
    value = clean(value)
    for timestamp_format in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, timestamp_format).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    raise ValueError("Unsupported OSSEC timestamp: " + value)


def epoch_to_text(epoch_value):
    """Format Unix epoch seconds as UTC text with microseconds.
    
    :param epoch_value: Unix timestamp in seconds.
    :returns: Formatted date/time text.
    :rtype: str
    """
    return datetime.fromtimestamp(float(epoch_value), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )


def bucket_start(epoch_value, seconds):
    """Floor an epoch time to a fixed-duration bucket boundary.
    
    :param epoch_value: Unix timestamp in seconds.
    :param seconds: Positive bucket duration in seconds.
    :returns: Bucket start in epoch seconds.
    :rtype: int
    """
    return int(math.floor(float(epoch_value) / seconds) * seconds)


def stable_id(*parts):
    """Hash ordered normalized parts into a deterministic observation identity.
    
    :param parts: Ordered identity components.
    :returns: First 24 hexadecimal SHA-256 characters.
    :rtype: str
    """
    seed = "|".join(clean(part) for part in parts)
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:24]


def normalize_token(value):
    """Create a lowercase underscore-separated token.
    
    :param value: Value to normalize or interpret.
    :returns: Normalized token, or unknown for empty input.
    :rtype: str
    """
    normalized = re.sub(r"[^a-z0-9]+", "_", clean(value).lower()).strip("_")
    return normalized or "unknown"


def normalize_text(value):
    """Replace timestamps, IP addresses, hex values and numbers with placeholders.
    
    :param value: Value to normalize or interpret.
    :returns: Normalized lowercase message text.
    :rtype: str
    """
    value = clean(value).lower()
    value = re.sub(r"\b\d{4}[-/]\d{2}[-/]\d{2}[ t]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", " {timestamp} ", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " {ip} ", value)
    value = re.sub(r"(?<![a-f0-9:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]+", " {ip} ", value, flags=re.IGNORECASE)
    value = re.sub(r"\b0x[a-f0-9]+\b", " {hex} ", value)
    value = re.sub(r"\b\d+\b", " {number} ", value)
    return re.sub(r"\s+", " ", value).strip()


def severity_rank(value):
    """Map named or numeric severity to a bounded rank.
    
    :param value: Value to normalize or interpret.
    :returns: Severity rank from 0 to 15, with unknown values mapped to zero.
    :rtype: int
    """
    severity = clean(value).upper()
    if severity in SEVERITY_RANKS:
        return SEVERITY_RANKS[severity]
    try:
        numeric = int(float(severity))
        return max(0, min(numeric, 15))
    except (TypeError, ValueError):
        return 0


def severity_bucket(value):
    """Map severity rank to a named bucket.
    
    :param value: Value to normalize or interpret.
    :returns: Bucket from unknown through emergency.
    :rtype: str
    """
    rank = severity_rank(value)
    if rank <= 0:
        return "unknown"
    if rank == 1:
        return "debug"
    if rank == 2:
        return "info"
    if rank == 3:
        return "notice"
    if rank == 4:
        return "warning"
    if rank == 5:
        return "error"
    if rank == 6:
        return "critical"
    if rank == 7:
        return "alert"
    return "emergency"


def event_category(event_type):
    """Choose the first matching category from ordered event-name checks.
    
    :param event_type: Classified event-type name.
    :returns: Lowercase category or other.
    :rtype: str
    """
    value = clean(event_type).upper()
    tests = (
        ("AUTHENTICATION", ("AUTH", "LOGIN", "PASSWORD", "USER")),
        ("ROOTCHECK", ("ROOTCHECK",)),
        ("SYSCHECK", ("SYSCHECK", "CHECKSUM", "INTEGRITY")),
        ("ACTIVE_RESPONSE", ("ACTIVE_RESPONSE", "EXEC")),
        ("CONNECTION", ("CONNECTION", "SOCKET", "NETWORK", "SERVER_MESSAGE")),
        ("AGENT", ("AGENT",)),
        ("SERVER", ("SERVER", "MANAGER")),
        ("QUEUE", ("QUEUE",)),
        ("RULES", ("RULE", "DECODER")),
        ("FILE", ("FILE", "PATH", "IGNORED")),
        ("PROCESS", ("PROCESS", "PID", "LOCK")),
    )
    for category, tokens in tests:
        if any(token in value for token in tokens):
            return category.lower()
    return "other"


def host_identity(row):
    """Select the first available host, agent, destination host or source address.
    
    :param row: Stored or classified event dictionary.
    :returns: Normalized host identifier and its identity type.
    :rtype: tuple
    """
    candidates = (
        ("hostname", row.get("hostname")),
        ("agent_name", row.get("agent_name")),
        ("destination_hostname", row.get("destination_hostname")),
        ("source_ip", row.get("source_ip")),
    )
    for identity_type, value in candidates:
        value = clean(value).lower()
        if value:
            return value, identity_type
    return "unknown-host", "unknown"


def input_files():
    """Discover sorted classified monthly CSV filenames.
    
    :returns: Matching source paths.
    :rtype: list
    :raises FileNotFoundError: If required input files are absent.
    """
    pattern = str(INPUT_FOLDER / INPUT_PATTERN)
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError("No classified OSSEC monthly CSV files found at: " + pattern)
    return files


def validate_header(path, fieldnames):
    """Require the configured input lineage columns in a CSV header.
    
    :param path: Input CSV path used for diagnostics.
    :param fieldnames: Column names from the CSV header.
    :rtype: None
    :raises ValueError: If parsing or identity validation fails.
    """
    if not fieldnames:
        raise ValueError("CSV has no header: " + str(path))
    missing = REQUIRED_INPUT_FIELDS.difference(fieldnames)
    if missing:
        raise ValueError(
            "CSV is missing required lineage fields in " + str(path) + ": "
            + ", ".join(sorted(missing))
        )


@timed_stage
def event_lookup_ids(connection):
    """Recreate the known-event table and load unique lookup IDs in batches.
    
    :param connection: Open SQLite observation-store connection.
    :returns: Number of authoritative lookup IDs stored.
    :rtype: int
    :raises ValueError: If parsing or identity validation fails.
    :raises FileNotFoundError: If required input files are absent.
    """
    if not EVENT_LOOKUP_FILE.is_file():
        raise FileNotFoundError("OSSEC event lookup is missing: " + str(EVENT_LOOKUP_FILE))
    connection.execute("DROP TABLE IF EXISTS known_event_ids")
    connection.execute("CREATE TABLE known_event_ids (event_id TEXT PRIMARY KEY)")
    batch = []
    with open(EVENT_LOOKUP_FILE, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "event_id" not in reader.fieldnames:
            raise ValueError("event_id missing from OSSEC event lookup")
        for source_row, row in enumerate(progress_items(reader, "Input CSV rows scanned"), start=2):
            event_id = clean(row.get("event_id"))
            if not event_id:
                raise ValueError("Blank event_id in OSSEC lookup row " + str(source_row))
            batch.append((event_id,))
            if len(batch) >= COMMIT_BATCH_SIZE:
                try:
                    connection.executemany("INSERT INTO known_event_ids(event_id) VALUES (?)", batch)
                except sqlite3.IntegrityError as error:
                    raise ValueError("Duplicate event_id in OSSEC event lookup") from error
                connection.commit()
                batch.clear()
    if batch:
        try:
            connection.executemany("INSERT INTO known_event_ids(event_id) VALUES (?)", batch)
        except sqlite3.IntegrityError as error:
            raise ValueError("Duplicate event_id in OSSEC event lookup") from error
        connection.commit()
    return int(connection.execute("SELECT COUNT(*) FROM known_event_ids").fetchone()[0])


@timed_stage
def create_database(connection):
    """Initialize the SQLite event schema and indexes for the current build.
    
    :param connection: Open SQLite observation-store connection.
    :rtype: None
    """
    connection.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-200000;
        DROP TABLE IF EXISTS events;
        CREATE TABLE events (
            event_id TEXT PRIMARY KEY,
            raw_line_sha256 TEXT NOT NULL,
            timestamp_text TEXT NOT NULL,
            timestamp_epoch REAL NOT NULL,
            partition_month TEXT,
            hostname TEXT,
            process_name TEXT,
            pid TEXT,
            severity TEXT,
            severity_rank INTEGER,
            event_type TEXT,
            event_category TEXT,
            username TEXT,
            source_ip TEXT,
            source_port TEXT,
            destination_hostname TEXT,
            destination_ip TEXT,
            destination_port TEXT,
            authentication_method TEXT,
            connection_stage TEXT,
            scan_mode TEXT,
            operation TEXT,
            started_pid TEXT,
            agent_name TEXT,
            counter_value TEXT,
            event_threshold TEXT,
            previous_event_count TEXT,
            current_event_count TEXT,
            retained_percentage TEXT,
            allowlist_count TEXT,
            allowlisted_ip TEXT,
            allowlisted_hostname TEXT,
            queue_path TEXT,
            queue_name TEXT,
            rules_enabled_count TEXT,
            monitored_path TEXT,
            analyzed_file TEXT,
            rules_file TEXT,
            ignored_file TEXT,
            command_path TEXT,
            checksum_algorithm TEXT,
            checksum_source_file TEXT,
            checksum_file TEXT,
            reason TEXT,
            raw_message TEXT,
            original_log_line TEXT,
            classification_line TEXT,
            source_file TEXT,
            source_line TEXT,
            archive_name TEXT,
            archive_member TEXT,
            host_id TEXT,
            host_identity_type TEXT
        );
        CREATE INDEX idx_ossec_time ON events(timestamp_epoch);
        CREATE INDEX idx_ossec_host_time ON events(host_id, timestamp_epoch);
        CREATE INDEX idx_ossec_episode ON events(host_id, process_name, event_category, source_ip, timestamp_epoch);
    """)
    connection.commit()


@timed_stage
def load_events(connection, files):
    """Load normalized monthly events into SQLite, skipping invalid timestamps.
    
    :param connection: Open SQLite observation-store connection.
    :param files: Monthly source CSV paths.
    :returns: Loaded-event and skipped-timestamp counts.
    :rtype: tuple
    :raises ValueError: If parsing or identity validation fails.
    """
    columns = [
        "event_id", "raw_line_sha256", "timestamp_text", "timestamp_epoch",
        "partition_month", "hostname", "process_name", "pid", "severity",
        "severity_rank", "event_type", "event_category", "username",
        "source_ip", "source_port", "destination_hostname", "destination_ip",
        "destination_port", "authentication_method", "connection_stage",
        "scan_mode", "operation", "started_pid", "agent_name", "counter_value",
        "event_threshold", "previous_event_count", "current_event_count",
        "retained_percentage", "allowlist_count", "allowlisted_ip",
        "allowlisted_hostname", "queue_path", "queue_name",
        "rules_enabled_count", "monitored_path", "analyzed_file", "rules_file",
        "ignored_file", "command_path", "checksum_algorithm",
        "checksum_source_file", "checksum_file", "reason", "raw_message",
        "original_log_line", "classification_line", "source_file",
        "source_line", "archive_name", "archive_member", "host_id",
        "host_identity_type",
    ]
    placeholders = ",".join("?" for _ in columns)
    insert_sql = "INSERT INTO events (" + ",".join(columns) + ") VALUES (" + placeholders + ")"
    batch = []
    loaded = 0
    invalid_timestamp_rows = 0
    for file_path in files:
        LOGGER.info("Loading OSSEC events: " + file_path)
        with open(file_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            validate_header(file_path, reader.fieldnames)
            for source_row, row in enumerate(progress_items(reader, "Input CSV rows scanned"), start=2):
                try:
                    timestamp = parse_timestamp(row.get("timestamp"))
                except ValueError:
                    invalid_timestamp_rows += 1
                    continue
                host_id, host_type = host_identity(row)
                values = {
                    "event_id": clean(row.get("event_id")),
                    "raw_line_sha256": clean(row.get("raw_line_sha256")),
                    "timestamp_text": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "timestamp_epoch": timestamp.timestamp(),
                    "partition_month": clean(row.get("partition_month")) or timestamp.strftime("%Y-%m"),
                    "hostname": clean(row.get("hostname")).lower(),
                    "process_name": clean(row.get("process_name")).lower(),
                    "pid": clean(row.get("pid")),
                    "severity": clean(row.get("severity")).upper(),
                    "severity_rank": severity_rank(row.get("severity")),
                    "event_type": clean(row.get("event_type")) or "OSSEC_UNKNOWN_EVENT",
                    "event_category": event_category(row.get("event_type")),
                    "username": clean(row.get("username")).lower(),
                    "source_ip": clean(row.get("source_ip")),
                    "source_port": clean(row.get("source_port")),
                    "destination_hostname": clean(row.get("destination_hostname")).lower(),
                    "destination_ip": clean(row.get("destination_ip")),
                    "destination_port": clean(row.get("destination_port")),
                    "authentication_method": clean(row.get("authentication_method")).lower(),
                    "connection_stage": clean(row.get("connection_stage")).lower(),
                    "scan_mode": clean(row.get("scan_mode")).lower(),
                    "operation": clean(row.get("operation")).lower(),
                    "started_pid": clean(row.get("started_pid")),
                    "agent_name": clean(row.get("agent_name")).lower(),
                    "counter_value": clean(row.get("counter_value")),
                    "event_threshold": clean(row.get("event_threshold")),
                    "previous_event_count": clean(row.get("previous_event_count")),
                    "current_event_count": clean(row.get("current_event_count")),
                    "retained_percentage": clean(row.get("retained_percentage")),
                    "allowlist_count": clean(row.get("allowlist_count")),
                    "allowlisted_ip": clean(row.get("allowlisted_ip")),
                    "allowlisted_hostname": clean(row.get("allowlisted_hostname")).lower(),
                    "queue_path": clean(row.get("queue_path")),
                    "queue_name": clean(row.get("queue_name")),
                    "rules_enabled_count": clean(row.get("rules_enabled_count")),
                    "monitored_path": clean(row.get("monitored_path")),
                    "analyzed_file": clean(row.get("analyzed_file")),
                    "rules_file": clean(row.get("rules_file")),
                    "ignored_file": clean(row.get("ignored_file")),
                    "command_path": clean(row.get("command_path")),
                    "checksum_algorithm": clean(row.get("checksum_algorithm")).lower(),
                    "checksum_source_file": clean(row.get("checksum_source_file")),
                    "checksum_file": clean(row.get("checksum_file")),
                    "reason": clean(row.get("reason")),
                    "raw_message": clean(row.get("raw_message")),
                    "original_log_line": clean(row.get("original_log_line")),
                    "classification_line": clean(row.get("classification_line")),
                    "source_file": clean(row.get("source_file")),
                    "source_line": clean(row.get("source_line")),
                    "archive_name": clean(row.get("archive_name")),
                    "archive_member": clean(row.get("archive_member")),
                    "host_id": host_id,
                    "host_identity_type": host_type,
                }
                if not values["event_id"] or not values["raw_line_sha256"]:
                    raise ValueError("Blank OSSEC lineage identity in " + file_path + " row " + str(source_row))
                batch.append(tuple(values[column] for column in columns))
                if len(batch) >= COMMIT_BATCH_SIZE:
                    try:
                        connection.executemany(insert_sql, batch)
                    except sqlite3.IntegrityError as error:
                        raise ValueError("Duplicate event_id in classified OSSEC monthly files") from error
                    connection.commit()
                    loaded += len(batch)
                    LOGGER.debug("Committed batch: %s events stored", loaded)
                    batch.clear()
    if batch:
        try:
            connection.executemany(insert_sql, batch)
        except sqlite3.IntegrityError as error:
            raise ValueError("Duplicate event_id in classified OSSEC monthly files") from error
        connection.commit()
        loaded += len(batch)
    LOGGER.info("OSSEC events loaded: " + str(loaded))
    if invalid_timestamp_rows:
        LOGGER.warning("Invalid timestamp rows skipped: %s", invalid_timestamp_rows)
    return loaded, invalid_timestamp_rows


@timed_stage
def validate_lookup_coverage(connection):
    """Require every loaded event ID to occur in the authoritative lookup.
    
    :param connection: Open SQLite observation-store connection.
    :rtype: None
    :raises ValueError: If parsing or identity validation fails.
    """
    missing = int(connection.execute(
        "SELECT COUNT(*) FROM events e LEFT JOIN known_event_ids k ON e.event_id=k.event_id WHERE k.event_id IS NULL"
    ).fetchone()[0])
    if missing:
        examples = [row[0] for row in connection.execute(
            "SELECT e.event_id FROM events e LEFT JOIN known_event_ids k ON e.event_id=k.event_id WHERE k.event_id IS NULL LIMIT 10"
        )]
        raise ValueError("Classified OSSEC events absent from event lookup: " + str(missing) + "; examples=" + ",".join(examples))


def entropy(counter):
    """Compute Shannon entropy in bits from positive category counts.
    
    :param counter: Mapping from categories to occurrence counts.
    :returns: Entropy, or zero for an empty distribution.
    :rtype: float
    """
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counter.values() if count > 0)


def dominant(counter):
    """Select the most frequent value with a deterministic text tie-break.
    
    :param counter: Mapping from categories to occurrence counts.
    :returns: Value and count, or empty text and zero.
    :rtype: tuple
    """
    if not counter:
        return "", 0
    return min(counter.items(), key=lambda item: (-item[1], clean(item[0])))


def open_output_pair(dataset_path, lineage_path, output_fields):
    """Open temporary observation and lineage CSVs and write their headers.
    
    :param dataset_path: Final observation CSV path.
    :param lineage_path: Final lineage CSV path.
    :param output_fields: Ordered observation column names.
    :returns: Two handles, two writers and two temporary filenames.
    :rtype: tuple
    """
    dataset_tmp = str(dataset_path) + ".tmp"
    lineage_tmp = str(lineage_path) + ".tmp"
    dataset_handle = open(dataset_tmp, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
    lineage_handle = open(lineage_tmp, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
    dataset_writer = csv.DictWriter(dataset_handle, fieldnames=output_fields, extrasaction="ignore")
    lineage_writer = csv.DictWriter(lineage_handle, fieldnames=LINEAGE_OUTPUT_FIELDS, extrasaction="ignore")
    dataset_writer.writeheader()
    lineage_writer.writeheader()
    return dataset_handle, lineage_handle, dataset_writer, lineage_writer, dataset_tmp, lineage_tmp


def commit_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp, dataset_path, lineage_path):
    """Close handles and replace dataset and lineage files sequentially.
    
    :param dataset_handle: Open temporary dataset file handle.
    :param lineage_handle: Open temporary lineage file handle.
    :param dataset_tmp: Temporary dataset filename.
    :param lineage_tmp: Temporary lineage filename.
    :param dataset_path: Final observation CSV path.
    :param lineage_path: Final lineage CSV path.
    :rtype: None
    
    .. note::
    
       Each file replacement is atomic; the group is not one transaction.
    """
    dataset_handle.close()
    lineage_handle.close()
    os.replace(dataset_tmp, dataset_path)
    os.replace(lineage_tmp, lineage_path)
    LOGGER.debug("Committed output pair: %s; %s", dataset_path, lineage_path)


def discard_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp):
    """Close output handles and remove remaining temporary files.
    
    :param dataset_handle: Open temporary dataset file handle.
    :param lineage_handle: Open temporary lineage file handle.
    :param dataset_tmp: Temporary dataset filename.
    :param lineage_tmp: Temporary lineage filename.
    :rtype: None
    """
    for handle in (dataset_handle, lineage_handle):
        if handle and not handle.closed:
            handle.close()
    for path in (dataset_tmp, lineage_tmp):
        if os.path.exists(path):
            os.remove(path)


def event_rows(connection, where="", parameters=(), source_order=False):
    """Stream SQLite event dictionaries ordered by timestamp and event ID.
    
    :param connection: Open SQLite observation-store connection.
    :param where: Optional trusted SQL WHERE expression; never insert untrusted SQL.
    :param parameters: Bound SQL parameters for the optional WHERE expression.
    :param source_order: Break same-second ties by source file and line
        instead of event ID, so a scan start is never read after its end.
    :yields: Chronologically ordered event dictionaries.
    :rtype: iterator
    """
    query = "SELECT * FROM events"
    if where:
        query += " WHERE " + where
    if source_order:
        query += (" ORDER BY timestamp_epoch, archive_name, source_file,"
                  " CAST(source_line AS INTEGER), event_id")
    else:
        query += " ORDER BY timestamp_epoch, event_id"
    cursor = connection.execute(query, parameters)
    columns = [item[0] for item in cursor.description]
    for values in cursor:
        yield dict(zip(columns, values))


def individual_row(row):
    """Convert a stored event into an individual observation.
    
    :param row: Stored or classified event dictionary.
    :returns: Individual observation fields including normalized time and severity features.
    :rtype: dict
    """
    timestamp = datetime.fromtimestamp(float(row["timestamp_epoch"]), tz=timezone.utc)
    output = dict(row)
    output.update({
        "row_manifest_id": row["event_id"],
        "timestamp": row["timestamp_text"],
        "hour_of_day": timestamp.hour,
        "day_of_week": timestamp.weekday(),
        "is_weekend": int(timestamp.weekday() >= 5),
        "normalized_event_token": normalize_token(row["event_type"]),
        "normalized_message": normalize_text(row["raw_message"] or row["original_log_line"]),
    })
    return output


@timed_stage
def write_individual_dataset(connection):
    """Write one observation and lineage link per stored event.
    
    :param connection: Open SQLite observation-store connection.
    :returns: Dataset path, lineage path, observation count and lineage count.
    :rtype: tuple
    """
    dataset = "individual"
    dataset_path = OUTPUT_FOLDER / "ossec_events_all_months.csv"
    lineage_path = OUTPUT_FOLDER / "ossec_events_all_months_lineage.csv"
    handles = open_output_pair(dataset_path, lineage_path, INDIVIDUAL_OUTPUT_FIELDS)
    dataset_handle, lineage_handle, writer, lineage_writer, dataset_tmp, lineage_tmp = handles
    rows = 0
    lineage_rows = 0
    try:
        dataset_batch = []
        lineage_batch = []
        for row in progress_items(event_rows(connection), "Events aggregated"):
            output = individual_row(row)
            dataset_batch.append(output)
            lineage_batch.append({
                "dataset": dataset,
                "row_manifest_id": row["event_id"],
                "event_id": row["event_id"],
                "event_position": 1,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "individual_event",
            })
            rows += 1
            lineage_rows += 1
            if len(dataset_batch) >= CSV_WRITE_BATCH_SIZE:
                writer.writerows(dataset_batch)
                lineage_writer.writerows(lineage_batch)
                dataset_batch.clear()
                lineage_batch.clear()
        if dataset_batch:
            writer.writerows(dataset_batch)
            lineage_writer.writerows(lineage_batch)
        commit_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp, dataset_path, lineage_path)
    except Exception:
        discard_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp)
        raise
    LOGGER.info("Wrote %s: %s observations, %s lineage links", dataset_path.name, rows, lineage_rows)
    return dataset_path, lineage_path, rows, lineage_rows


def new_accumulator():
    """Initialize mutable counts, sets, timing and sequence state.
    
    :returns: Fresh accumulator.
    :rtype: dict
    """
    return {
        "total_events": 0,
        "severity_rank_sum": 0,
        "maximum_severity_rank": 0,
        "first_severity_rank": 0,
        "last_severity_rank": 0,
        "severity_counts": Counter(),
        "event_types": Counter(),
        "categories": Counter(),
        "processes": Counter(),
        "risk_counts": Counter(),
        "users": set(),
        "source_ips": set(),
        "destination_ips": set(),
        "agents": set(),
        "files": set(),
        "reasons": set(),
        "first_epoch": None,
        "last_epoch": None,
        "previous_epoch": None,
        "gap_sum": 0.0,
        "gap_count": 0,
        "minimum_gap": None,
        "maximum_gap": 0.0,
        "first_event_type": "",
        "last_event_type": "",
        "first_event_id": "",
        "last_event_id": "",
        "event_type_sequence": [],
        "severity_sequence": [],
        "username_sequence": [],
        "event_position": 0,
        "hostname": "",
        "agent_name": "",
    }


def update_accumulator(acc, row):
    """Update aggregate state in place using one chronological event.
    
    :param acc: Mutable observation accumulator.
    :param row: Stored or classified event dictionary.
    :returns: One-based event position within the aggregate.
    :rtype: int
    """
    rank = int(row["severity_rank"])
    severity = severity_bucket(row["severity"])
    event_type = clean(row["event_type"]) or "OSSEC_UNKNOWN_EVENT"
    category = clean(row["event_category"]) or "other"
    process = clean(row["process_name"]) or "unknown-process"
    epoch_value = float(row["timestamp_epoch"])
    acc["total_events"] += 1
    acc["severity_rank_sum"] += rank
    acc["maximum_severity_rank"] = max(acc["maximum_severity_rank"], rank)
    acc["last_severity_rank"] = rank
    acc["severity_counts"][severity] += 1
    acc["event_types"][event_type] += 1
    acc["categories"][category] += 1
    acc["processes"][process] += 1
    risk_group = RISK_GROUP_BY_EVENT.get(event_type)
    if risk_group:
        acc["risk_counts"][risk_group] += 1
    for value, target in (
        (row["username"], "users"),
        (row["source_ip"], "source_ips"),
        (row["destination_ip"], "destination_ips"),
        (row["agent_name"], "agents"),
        (row["monitored_path"] or row["analyzed_file"] or row["ignored_file"] or row["checksum_file"], "files"),
        (row["reason"], "reasons"),
    ):
        value = clean(value)
        if value:
            acc[target].add(value)
    if acc["first_epoch"] is None:
        acc["first_epoch"] = epoch_value
        acc["first_severity_rank"] = rank
        acc["first_event_type"] = event_type
        acc["first_event_id"] = row["event_id"]
        acc["hostname"] = row["hostname"]
        acc["agent_name"] = row["agent_name"]
    if acc["previous_epoch"] is not None:
        gap = max(0.0, epoch_value - acc["previous_epoch"])
        acc["gap_sum"] += gap
        acc["gap_count"] += 1
        acc["minimum_gap"] = gap if acc["minimum_gap"] is None else min(acc["minimum_gap"], gap)
        acc["maximum_gap"] = max(acc["maximum_gap"], gap)
    acc["previous_epoch"] = epoch_value
    acc["last_epoch"] = epoch_value
    acc["last_event_type"] = event_type
    acc["last_event_id"] = row["event_id"]
    if len(acc["event_type_sequence"]) < 64:
        acc["event_type_sequence"].append(normalize_token(event_type))
    if len(acc["severity_sequence"]) < 64:
        acc["severity_sequence"].append(severity)
    username = clean(row["username"])
    if username and len(acc["username_sequence"]) < 64:
        acc["username_sequence"].append(normalize_token(username))
    acc["event_position"] += 1
    return acc["event_position"]


def risk_count_fields(acc):
    """Return the monitoring-risk counts of an accumulator.

    :param acc: Mutable observation accumulator.
    :returns: One ``<group>_count`` field per ``RISK_EVENT_GROUPS`` entry.
    :rtype: dict
    """
    return {group + "_count": acc["risk_counts"].get(group, 0) for group in RISK_EVENT_GROUPS}


def host_window_id(start_epoch, host_id):
    """Create an observation identity for a host and five-minute bucket.
    
    :param start_epoch: Bucket or episode start in Unix seconds.
    :param host_id: Normalized host identity.
    :returns: Stable manifest ID.
    :rtype: str
    """
    return stable_id("ossec", "host_5min", start_epoch, host_id)


def finalize_host_window(acc, start_epoch, host_id, host_type):
    """Compute severity, category, diversity and timing fields for a host window.
    
    :param acc: Mutable observation accumulator.
    :param start_epoch: Bucket or episode start in Unix seconds.
    :param host_id: Normalized host identity.
    :param host_type: Field supplying the host identity.
    :returns: Five-minute observation row.
    :rtype: dict
    """
    row_id = host_window_id(start_epoch, host_id)
    event_type, event_type_count = dominant(acc["event_types"])
    process, process_count = dominant(acc["processes"])
    severity, severity_count = dominant(acc["severity_counts"])
    row = {
        "row_manifest_id": row_id,
        "dataset_id": row_id,
        "window_label": "5min",
        "window_start": epoch_to_text(start_epoch),
        "window_end": epoch_to_text(start_epoch + HOST_WINDOW_SECONDS),
        "host_id": host_id,
        "host_identity_type": host_type,
        "hostname": acc["hostname"],
        "agent_name": acc["agent_name"],
        "total_events": acc["total_events"],
        "events_per_minute": acc["total_events"] / (HOST_WINDOW_SECONDS / 60.0),
        "active_span_seconds": max(0.0, acc["last_epoch"] - acc["first_epoch"]),
        "mean_inter_event_seconds": acc["gap_sum"] / max(acc["gap_count"], 1),
        "minimum_inter_event_seconds": acc["minimum_gap"] if acc["minimum_gap"] is not None else 0.0,
        "maximum_inter_event_seconds": acc["maximum_gap"],
        "severity_rank_sum": acc["severity_rank_sum"],
        "mean_severity_rank": acc["severity_rank_sum"] / max(acc["total_events"], 1),
        "maximum_severity_rank": acc["maximum_severity_rank"],
        "unknown_event_count": acc["event_types"].get("OSSEC_UNKNOWN_EVENT", 0),
        "unique_event_types": len(acc["event_types"]),
        "unique_processes": len(acc["processes"]),
        "unique_users": len(acc["users"]),
        "unique_source_ips": len(acc["source_ips"]),
        "unique_destination_ips": len(acc["destination_ips"]),
        "unique_agents": len(acc["agents"]),
        "unique_monitored_paths": len(acc["files"]),
        "unique_files": len(acc["files"]),
        "event_type_entropy": entropy(acc["event_types"]),
        "process_entropy": entropy(acc["processes"]),
        "severity_entropy": entropy(acc["severity_counts"]),
        "dominant_event_type": event_type,
        "dominant_event_type_count": event_type_count,
        "dominant_process": process,
        "dominant_process_count": process_count,
        "dominant_severity": severity,
        "dominant_severity_count": severity_count,
        "first_event_type": acc["first_event_type"],
        "last_event_type": acc["last_event_type"],
        "first_event_id": acc["first_event_id"],
        "last_event_id": acc["last_event_id"],
        "first_timestamp": epoch_to_text(acc["first_epoch"]),
        "last_timestamp": epoch_to_text(acc["last_epoch"]),
        "event_type_sequence": " ".join(acc["event_type_sequence"]),
        **risk_count_fields(acc),
    }
    for bucket in ("debug", "info", "notice", "warning", "error", "critical", "alert", "emergency", "unknown"):
        row[bucket + "_severity_count" if bucket == "unknown" else bucket + "_count"] = acc["severity_counts"].get(bucket, 0)
    row["unknown_severity_count"] = acc["severity_counts"].get("unknown", 0)
    for category in ("authentication", "rootcheck", "syscheck", "connection", "agent", "server", "queue", "rules", "file", "active_response", "other"):
        row[category + "_count"] = acc["categories"].get(category, 0)
    return row


@timed_stage
def write_host_window_dataset(connection):
    """Write five-minute host observations and all contributing event links.
    
    :param connection: Open SQLite observation-store connection.
    :returns: Dataset path, lineage path, observation count and lineage count.
    :rtype: tuple
    """
    dataset = "host_5min"
    dataset_path = OUTPUT_FOLDER / "ossec_host_windows_5min.csv"
    lineage_path = OUTPUT_FOLDER / "ossec_host_windows_5min_lineage.csv"
    handles = open_output_pair(dataset_path, lineage_path, HOST_WINDOW_OUTPUT_FIELDS)
    dataset_handle, lineage_handle, writer, lineage_writer, dataset_tmp, lineage_tmp = handles
    active = {}
    rows = 0
    lineage_rows = 0
    lineage_batch = []
    try:
        for row in progress_items(event_rows(connection), "Events aggregated"):
            start_epoch = bucket_start(row["timestamp_epoch"], HOST_WINDOW_SECONDS)
            key = row["host_id"]
            current = active.get(key)
            if current is None or current[0] != start_epoch:
                if current is not None:
                    writer.writerow(finalize_host_window(current[1], current[0], key, current[2]))
                    rows += 1
                current = (start_epoch, new_accumulator(), row["host_identity_type"])
                active[key] = current
            position = update_accumulator(current[1], row)
            lineage_batch.append({
                "dataset": dataset,
                "row_manifest_id": host_window_id(start_epoch, key),
                "event_id": row["event_id"],
                "event_position": position,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "host_window_member",
            })
            lineage_rows += 1
            if len(lineage_batch) >= CSV_WRITE_BATCH_SIZE:
                lineage_writer.writerows(lineage_batch)
                lineage_batch.clear()
        for host_id, (start_epoch, acc, host_type) in sorted(active.items()):
            writer.writerow(finalize_host_window(acc, start_epoch, host_id, host_type))
            rows += 1
        if lineage_batch:
            lineage_writer.writerows(lineage_batch)
        commit_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp, dataset_path, lineage_path)
    except Exception:
        discard_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp)
        raise
    LOGGER.info("Wrote %s: %s observations, %s lineage links", dataset_path.name, rows, lineage_rows)
    return dataset_path, lineage_path, rows, lineage_rows


# =============================================================================
# Episodes (builder version 02: activity lifecycles)
# =============================================================================

def process_reference(row):
    """Return the ``(host, process)`` pair used by scan and connectivity keys.

    :param row: Event dictionary from the SQLite store.
    :returns: Host identity and normalized process name.
    :rtype: tuple
    """
    return row["host_id"], clean(row["process_name"]) or "unknown-process"


def episode_key(row, open_scans):
    """Choose the episode key an event belongs to (see module docstring).

    Order: scan cycle; connectivity; lifecycle; the open scan of the same
    host/process (scan bridge); otherwise the host/process/category key.

    :param row: Event dictionary from the SQLite store.
    :param open_scans: Mapping of (host, process) to its open scan key.
    :returns: Episode key whose first element is the key type.
    :rtype: tuple
    """
    event_type = clean(row["event_type"])
    host, process = process_reference(row)
    if event_type in SCAN_EVENTS:
        return ("scan", host, process, SCAN_EVENTS[event_type][0])
    if event_type in CONNECTIVITY_EVENTS:
        return ("connectivity", host, process)
    if event_type in LIFECYCLE_EVENTS:
        return ("lifecycle", host)
    bridged = open_scans.get((host, process))
    if bridged is not None:
        return bridged
    return ("process", host, process, clean(row["event_category"]) or "other")


def episode_family(key):
    """Describe what an episode key groups, for ``episode_family``.

    :param key: Episode key from :func:`episode_key`.
    :returns: Scan family, ``connectivity``, ``lifecycle`` or the event category.
    :rtype: str
    """
    if key[0] == "scan":
        return key[3]
    if key[0] == "process":
        return key[3]
    return key[0]


def episode_limit(key_type):
    """Return the inactivity (or maximum-duration) limit of a key type.

    :param key_type: Episode key type.
    :returns: Limit in seconds.
    :rtype: int
    """
    if key_type == "scan":
        return SCAN_MAX_SECONDS
    if key_type == "lifecycle":
        return LIFECYCLE_INACTIVITY_SECONDS
    return EPISODE_INACTIVITY_SECONDS


def new_episode(row, key):
    """Initialize an episode and its accumulator from the first event.

    The first event ID distinguishes consecutive episodes with identical keys
    and second-resolution timestamps.

    :param row: Event dictionary from the SQLite store.
    :param key: Episode key from :func:`episode_key`.
    :returns: Episode accumulator.
    :rtype: dict
    """
    acc = new_accumulator()
    acc["row_manifest_id"] = stable_id(
        "ossec", "episode", *key, row["timestamp_epoch"], row["event_id"]
    )
    acc["episode_key_type"] = key[0]
    acc["episode_family"] = episode_family(key)
    acc["host_id"] = row["host_id"]
    acc["host_identity_type"] = row["host_identity_type"]
    acc["source_ip"] = clean(row["source_ip"])
    acc["closing_epoch"] = None
    acc["close_reason"] = ""
    acc["episode_completed"] = 0
    return acc


def episode_expiry(episode, epoch):
    """Return why an open episode must close before an event at ``epoch``.

    :param episode: Open episode accumulator.
    :param epoch: Timestamp of the event being processed, in epoch seconds.
    :returns: ``terminal``, ``scan_timeout``, ``inactivity`` or None.
    :rtype: str or None
    """
    if episode["closing_epoch"] is not None:
        if epoch - episode["closing_epoch"] > EPISODE_TERMINAL_GRACE_SECONDS:
            return "terminal"
        return None
    if episode["episode_key_type"] == "scan":
        if epoch - episode["first_epoch"] > SCAN_MAX_SECONDS:
            return "scan_timeout"
        return None
    if epoch - episode["last_epoch"] > episode_limit(episode["episode_key_type"]):
        return "inactivity"
    return None


def finalize_episode(acc):
    """Convert an episode accumulator to duration, severity and sequence features.
    
    :param acc: Mutable observation accumulator.
    :returns: Episode observation row.
    :rtype: dict
    """
    process, _ = dominant(acc["processes"])
    category, _ = dominant(acc["categories"])
    return {
        "row_manifest_id": acc["row_manifest_id"],
        "episode_id": acc["row_manifest_id"],
        "episode_start": epoch_to_text(acc["first_epoch"]),
        "episode_end": epoch_to_text(acc["last_epoch"]),
        "duration_seconds": max(0.0, acc["last_epoch"] - acc["first_epoch"]),
        "inactivity_threshold_seconds": episode_limit(acc["episode_key_type"]),
        "episode_key_type": acc["episode_key_type"],
        "episode_family": acc["episode_family"],
        "close_reason": acc["close_reason"],
        "episode_completed": acc["episode_completed"],
        "host_id": acc["host_id"],
        "host_identity_type": acc["host_identity_type"],
        "hostname": acc["hostname"],
        "agent_name": acc["agent_name"],
        "process_name": process,
        "event_category": category,
        "source_ip": acc["source_ip"],
        "event_count": acc["total_events"],
        "events_per_minute": acc["total_events"] / max((acc["last_epoch"] - acc["first_epoch"]) / 60.0, 1.0),
        "severity_rank_sum": acc["severity_rank_sum"],
        "mean_severity_rank": acc["severity_rank_sum"] / max(acc["total_events"], 1),
        "maximum_severity_rank": acc["maximum_severity_rank"],
        "severity_increase": acc["last_severity_rank"] - acc["first_severity_rank"],
        "debug_count": acc["severity_counts"].get("debug", 0),
        "info_count": acc["severity_counts"].get("info", 0),
        "notice_count": acc["severity_counts"].get("notice", 0),
        "warning_count": acc["severity_counts"].get("warning", 0),
        "error_count": acc["severity_counts"].get("error", 0),
        "critical_count": acc["severity_counts"].get("critical", 0),
        "alert_count": acc["severity_counts"].get("alert", 0),
        "emergency_count": acc["severity_counts"].get("emergency", 0),
        "unknown_severity_count": acc["severity_counts"].get("unknown", 0),
        "unknown_event_count": acc["event_types"].get("OSSEC_UNKNOWN_EVENT", 0),
        **risk_count_fields(acc),
        "unique_event_types": len(acc["event_types"]),
        "unique_processes": len(acc["processes"]),
        "unique_categories": len(acc["categories"]),
        "unique_users": len(acc["users"]),
        "unique_destination_ips": len(acc["destination_ips"]),
        "unique_files": len(acc["files"]),
        "unique_reasons": len(acc["reasons"]),
        "first_event_type": acc["first_event_type"],
        "last_event_type": acc["last_event_type"],
        "first_event_id": acc["first_event_id"],
        "last_event_id": acc["last_event_id"],
        "mean_inter_event_seconds": acc["gap_sum"] / max(acc["gap_count"], 1),
        "maximum_inter_event_seconds": acc["maximum_gap"],
        "event_type_sequence": " ".join(acc["event_type_sequence"]),
        "severity_sequence": " ".join(acc["severity_sequence"]),
        "username_sequence": " ".join(acc["username_sequence"]),
    }


@timed_stage
def write_episode_dataset(connection):
    """Group events into scan, connectivity, lifecycle and process episodes.
    
    :param connection: Open SQLite observation-store connection.
    :returns: Dataset path, lineage path, observation count and lineage count.
    :rtype: tuple
    """
    dataset = "episodes"
    dataset_path = OUTPUT_FOLDER / "ossec_security_episodes.csv"
    lineage_path = OUTPUT_FOLDER / "ossec_security_episodes_lineage.csv"
    handles = open_output_pair(dataset_path, lineage_path, EPISODE_OUTPUT_FIELDS)
    dataset_handle, lineage_handle, writer, lineage_writer, dataset_tmp, lineage_tmp = handles
    active = {}
    open_scans = {}
    rows = 0
    lineage_rows = 0
    lineage_batch = []
    reasons = Counter()
    key_types = Counter()
    scans_started = scans_completed = 0
    last_sweep = None

    def close(key, reason):
        """Write and forget one open episode."""
        nonlocal rows, scans_started, scans_completed
        episode = active.pop(key)
        if key[0] == "scan" and SCAN_EVENTS.get(episode["first_event_type"], ("", ""))[1] == "start":
            scans_started += 1
            scans_completed += episode["episode_completed"]
        episode["close_reason"] = reason
        writer.writerow(finalize_episode(episode))
        rows += 1
        reasons[reason] += 1
        key_types[episode["episode_key_type"]] += 1
        if key[0] == "scan" and open_scans.get(key[1:3]) == key:
            del open_scans[key[1:3]]

    def sweep(epoch):
        """Close every expired episode, oldest first."""
        expired = sorted(
            (episode["first_epoch"], episode["row_manifest_id"], key, reason)
            for key, episode in active.items()
            for reason in [episode_expiry(episode, epoch)] if reason
        )
        for _, _, key, reason in expired:
            close(key, reason)

    try:
        for row in progress_items(event_rows(connection, source_order=True), "Events aggregated"):
            epoch = float(row["timestamp_epoch"])
            if last_sweep is None:
                last_sweep = epoch
            elif epoch - last_sweep >= EPISODE_SWEEP_SECONDS:
                sweep(epoch)
                last_sweep = epoch
            event_type = clean(row["event_type"])
            reference = process_reference(row)
            if event_type in LIFECYCLE_STOP_EVENTS:
                for key in [k for k in active
                            if k[0] in ("scan", "connectivity") and k[1:3] == reference
                            and active[k]["closing_epoch"] is None]:
                    close(key, "interrupted")
            key = episode_key(row, open_scans)
            episode = active.get(key)
            if episode is not None:
                reason = episode_expiry(episode, epoch)
                if reason is None and SCAN_EVENTS.get(event_type, ("", ""))[1] == "start":
                    reason = "terminal" if episode["closing_epoch"] is not None else "superseded"
                if reason:
                    close(key, reason)
                    episode = None
            if episode is None:
                episode = new_episode(row, key)
                active[key] = episode
                if key[0] == "scan":
                    open_scans[key[1:3]] = key
            position = update_accumulator(episode, row)
            if not episode["source_ip"] and clean(row["source_ip"]):
                episode["source_ip"] = clean(row["source_ip"])
            is_terminal = (
                SCAN_EVENTS.get(event_type, ("", ""))[1] == "end"
                or event_type in CONNECTIVITY_TERMINAL_EVENTS
            )
            if is_terminal:
                if key[0] != "scan" or episode["total_events"] > 1:
                    episode["episode_completed"] = 1
                if episode["closing_epoch"] is None:
                    episode["closing_epoch"] = epoch
                if key[0] == "scan" and open_scans.get(key[1:3]) == key:
                    del open_scans[key[1:3]]
            lineage_batch.append({
                "dataset": dataset,
                "row_manifest_id": episode["row_manifest_id"],
                "event_id": row["event_id"],
                "event_position": position,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "episode_member",
            })
            lineage_rows += 1
            if len(lineage_batch) >= CSV_WRITE_BATCH_SIZE:
                lineage_writer.writerows(lineage_batch)
                lineage_batch.clear()
        for key, episode in sorted(
            list(active.items()),
            key=lambda item: (item[1]["first_epoch"], item[1]["row_manifest_id"]),
        ):
            close(key, "terminal" if episode["closing_epoch"] is not None else "end_of_data")
        if lineage_batch:
            lineage_writer.writerows(lineage_batch)
        commit_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp, dataset_path, lineage_path)
    except Exception:
        discard_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp)
        raise
    LOGGER.info("Wrote %s: %s observations, %s lineage links (%.2f events/episode)",
                dataset_path.name, rows, lineage_rows, lineage_rows / max(rows, 1))
    LOGGER.info("Episode close reasons: %s", dict(reasons))
    LOGGER.info("Episode key types: %s", dict(key_types))
    scan_completion = scans_completed / scans_started if scans_started else None
    if scan_completion is not None:
        LOGGER.info("Scan episodes with both start and end: %s of %s (%.1f%%)",
                    scans_completed, scans_started, 100 * scan_completion)
    EPISODE_STATISTICS.clear()
    EPISODE_STATISTICS.update({
        "close_reasons": dict(reasons),
        "key_types": dict(key_types),
        "scan_episodes_started": scans_started,
        "scan_episodes_completed": scans_completed,
        "scan_completion_rate": scan_completion,
    })
    return dataset_path, lineage_path, rows, lineage_rows


def behavior_row_id(start_epoch, host_id):
    """Create a stable observation identity for a host and daily bucket.
    
    :param start_epoch: Bucket or episode start in Unix seconds.
    :param host_id: Normalized host identity.
    :returns: Daily manifest ID.
    :rtype: str
    """
    return stable_id("ossec", "host_behavior_1d", start_epoch, host_id)


def finalize_behavior(acc, start_epoch, host_id, host_type, history):
    """Compute daily behavior fields and update prior host history in place.
    
    :param acc: Mutable observation accumulator.
    :param start_epoch: Bucket or episode start in Unix seconds.
    :param host_id: Normalized host identity.
    :param host_type: Field supplying the host identity.
    :param history: Mutable host history used to compute novelty.
    :returns: Daily behavior observation row.
    :rtype: dict
    """
    row_id = behavior_row_id(start_epoch, host_id)
    event_types = set(acc["event_types"])
    processes = set(acc["processes"])
    users = set(acc["users"])
    source_ips = set(acc["source_ips"])
    destination_ips = set(acc["destination_ips"])
    agents = set(acc["agents"])
    files = set(acc["files"])
    prior = history.setdefault(host_id, {
        "event_types": set(), "processes": set(), "users": set(),
        "source_ips": set(), "destination_ips": set(), "agents": set(),
        "files": set(),
    })
    event_type, event_type_count = dominant(acc["event_types"])
    process, process_count = dominant(acc["processes"])
    severity, severity_count = dominant(acc["severity_counts"])
    active_hours = set()
    # Reconstruct active-hour count from first/last is not exact; the writer
    # stores exact hours in the accumulator when events are added below.
    active_hours.update(acc.get("active_hours", set()))
    row = {
        "row_manifest_id": row_id,
        "dataset_id": row_id,
        "window_label": "1d",
        "window_start": epoch_to_text(start_epoch),
        "window_end": epoch_to_text(start_epoch + 86400),
        "host_id": host_id,
        "host_identity_type": host_type,
        "hostname": acc["hostname"],
        "agent_name": acc["agent_name"],
        "total_events": acc["total_events"],
        "events_per_hour": acc["total_events"] / 24.0,
        "active_hours": len(active_hours),
        "active_span_seconds": max(0.0, acc["last_epoch"] - acc["first_epoch"]),
        "mean_inter_event_seconds": acc["gap_sum"] / max(acc["gap_count"], 1),
        "maximum_inter_event_seconds": acc["maximum_gap"],
        "severity_rank_sum": acc["severity_rank_sum"],
        "mean_severity_rank": acc["severity_rank_sum"] / max(acc["total_events"], 1),
        "maximum_severity_rank": acc["maximum_severity_rank"],
        "high_severity_count": sum(count for bucket, count in acc["severity_counts"].items() if bucket in {"error", "critical", "alert", "emergency"}),
        "unknown_event_count": acc["event_types"].get("OSSEC_UNKNOWN_EVENT", 0),
        **risk_count_fields(acc),
        "unique_event_types": len(event_types),
        "unique_processes": len(processes),
        "unique_users": len(users),
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "unique_agents": len(agents),
        "unique_files": len(files),
        "unique_reasons": len(acc["reasons"]),
        "new_event_types": len(event_types - prior["event_types"]),
        "new_processes": len(processes - prior["processes"]),
        "new_users": len(users - prior["users"]),
        "new_source_ips": len(source_ips - prior["source_ips"]),
        "new_destination_ips": len(destination_ips - prior["destination_ips"]),
        "new_agents": len(agents - prior["agents"]),
        "new_files": len(files - prior["files"]),
        "event_type_entropy": entropy(acc["event_types"]),
        "process_entropy": entropy(acc["processes"]),
        "severity_entropy": entropy(acc["severity_counts"]),
        "source_ip_entropy": entropy(Counter({value: 1 for value in source_ips})),
        "dominant_event_type": event_type,
        "dominant_event_type_count": event_type_count,
        "dominant_process": process,
        "dominant_process_count": process_count,
        "dominant_severity": severity,
        "dominant_severity_count": severity_count,
        "first_event_type": acc["first_event_type"],
        "last_event_type": acc["last_event_type"],
        "first_event_id": acc["first_event_id"],
        "last_event_id": acc["last_event_id"],
        "first_timestamp": epoch_to_text(acc["first_epoch"]),
        "last_timestamp": epoch_to_text(acc["last_epoch"]),
        "event_type_sequence": " ".join(acc["event_type_sequence"]),
    }
    prior["event_types"].update(event_types)
    prior["processes"].update(processes)
    prior["users"].update(users)
    prior["source_ips"].update(source_ips)
    prior["destination_ips"].update(destination_ips)
    prior["agents"].update(agents)
    prior["files"].update(files)
    return row


@timed_stage
def write_behavior_dataset(connection):
    """Write daily host behavior and contributing event lineage.
    
    :param connection: Open SQLite observation-store connection.
    :returns: Dataset path, lineage path, observation count and lineage count.
    :rtype: tuple
    """
    dataset = "host_behavior_1d"
    dataset_path = OUTPUT_FOLDER / "ossec_host_behavior_1d.csv"
    lineage_path = OUTPUT_FOLDER / "ossec_host_behavior_1d_lineage.csv"
    handles = open_output_pair(dataset_path, lineage_path, BEHAVIOR_OUTPUT_FIELDS)
    dataset_handle, lineage_handle, writer, lineage_writer, dataset_tmp, lineage_tmp = handles
    active = {}
    history = {}
    rows = 0
    lineage_rows = 0
    lineage_batch = []
    try:
        for row in progress_items(event_rows(connection), "Events aggregated"):
            start_epoch = bucket_start(row["timestamp_epoch"], 86400)
            host_id = row["host_id"]
            current = active.get(host_id)
            if current is None or current[0] != start_epoch:
                if current is not None:
                    writer.writerow(finalize_behavior(current[1], current[0], host_id, current[2], history))
                    rows += 1
                acc = new_accumulator()
                acc["active_hours"] = set()
                current = (start_epoch, acc, row["host_identity_type"])
                active[host_id] = current
            event_time = datetime.fromtimestamp(float(row["timestamp_epoch"]), tz=timezone.utc)
            current[1]["active_hours"].add(event_time.strftime("%Y-%m-%d %H"))
            position = update_accumulator(current[1], row)
            lineage_batch.append({
                "dataset": dataset,
                "row_manifest_id": behavior_row_id(start_epoch, host_id),
                "event_id": row["event_id"],
                "event_position": position,
                "event_timestamp": row["timestamp_text"],
                "relationship_role": "host_behavior_member",
            })
            lineage_rows += 1
            if len(lineage_batch) >= CSV_WRITE_BATCH_SIZE:
                lineage_writer.writerows(lineage_batch)
                lineage_batch.clear()
        for host_id, (start_epoch, acc, host_type) in sorted(active.items()):
            writer.writerow(finalize_behavior(acc, start_epoch, host_id, host_type, history))
            rows += 1
        if lineage_batch:
            lineage_writer.writerows(lineage_batch)
        commit_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp, dataset_path, lineage_path)
    except Exception:
        discard_output_pair(dataset_handle, lineage_handle, dataset_tmp, lineage_tmp)
        raise
    LOGGER.info("Wrote %s: %s observations, %s lineage links", dataset_path.name, rows, lineage_rows)
    return dataset_path, lineage_path, rows, lineage_rows


@timed_stage
def validate_dataset_lineage(dataset_path, lineage_path, count_column):
    """Check observation identities, unique links and expected membership counts.
    
    :param dataset_path: Final observation CSV path.
    :param lineage_path: Final lineage CSV path.
    :param count_column: Expected event-count field, or __one__ for individual observations.
    :returns: Validated observation and lineage cardinality statistics.
    :rtype: dict
    :raises ValueError: If parsing or identity validation fails.
    """
    expected = {}
    with open(dataset_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"row_manifest_id"}
        if count_column != "__one__":
            required.add(count_column)
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError("Dataset lacks lineage validation fields: " + str(dataset_path))
        for row in progress_items(reader, "Validation rows checked"):
            row_id = clean(row.get("row_manifest_id"))
            if not row_id:
                raise ValueError("Blank row_manifest_id in " + str(dataset_path))
            if row_id in expected:
                raise ValueError("Duplicate row_manifest_id in " + str(dataset_path) + ": " + row_id)
            expected[row_id] = 1 if count_column == "__one__" else int(float(clean(row.get(count_column)) or 0))
    actual = Counter()
    links = set()
    with open(lineage_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"row_manifest_id", "event_id", "event_position"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError("Lineage lacks required fields: " + str(lineage_path))
        for row in progress_items(reader, "Validation rows checked"):
            row_id = clean(row.get("row_manifest_id"))
            event_id = clean(row.get("event_id"))
            if not row_id or not event_id:
                raise ValueError("Blank lineage identifier in " + str(lineage_path))
            link = (row_id, event_id)
            if link in links:
                raise ValueError("Duplicate lineage link: " + row_id + " -> " + event_id)
            links.add(link)
            actual[row_id] += 1
    missing_rows = set(expected) - set(actual)
    unknown_rows = set(actual) - set(expected)
    mismatched = [row_id for row_id, count in expected.items() if actual.get(row_id, 0) != count]
    if missing_rows or unknown_rows or mismatched:
        raise ValueError(
            "Lineage validation failed for " + str(dataset_path)
            + ": missing_rows=" + str(len(missing_rows))
            + ", unknown_rows=" + str(len(unknown_rows))
            + ", count_mismatches=" + str(len(mismatched))
        )
    return {
        "dataset_rows": len(expected),
        "lineage_rows": sum(actual.values()),
        "unique_events": len({event_id for _, event_id in links}),
        "minimum_events_per_observation": min(actual.values()) if actual else 0,
        "maximum_events_per_observation": max(actual.values()) if actual else 0,
        "mean_events_per_observation": sum(actual.values()) / len(actual) if actual else 0.0,
    }


@timed_stage
def write_summaries(records, stem="ossec_observation_dataset_summary"):
    """Write validated observation dataset summaries as CSV and JSON.
    
    :param records: Validated dataset summary dictionaries.
    :param stem: Summary filename stem, without its CSV or JSON extension.
    :rtype: None
    """
    csv_path = OUTPUT_FOLDER / (stem + ".csv")
    json_path = OUTPUT_FOLDER / (stem + ".json")
    fields = [
        "dataset", "dataset_file", "lineage_file", "dataset_rows",
        "lineage_rows", "unique_events", "minimum_events_per_observation",
        "maximum_events_per_observation", "mean_events_per_observation",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({
            "builder_version": BUILDER_VERSION,
            "event_lookup_file": str(EVENT_LOOKUP_FILE),
            "episode_rules": {
                "process_inactivity_seconds": EPISODE_INACTIVITY_SECONDS,
                "lifecycle_inactivity_seconds": LIFECYCLE_INACTIVITY_SECONDS,
                "terminal_grace_seconds": EPISODE_TERMINAL_GRACE_SECONDS,
                "scan_max_seconds": SCAN_MAX_SECONDS,
                "scan_events": {key: list(value) for key, value in sorted(SCAN_EVENTS.items())},
                "connectivity_terminal_events": sorted(CONNECTIVITY_TERMINAL_EVENTS),
                "lifecycle_stop_events": sorted(LIFECYCLE_STOP_EVENTS),
            },
            "episode_statistics": EPISODE_STATISTICS,
            "risk_event_groups": {key: sorted(value) for key, value in RISK_EVENT_GROUPS.items()},
            "datasets": records,
        }, handle, indent=2)


def main(episodes_only=False):
    """Build, validate and summarize all representations or only episodes.
    
    :param episodes_only: Rebuild only the episodes dataset and its lineage.
    :rtype: None
    """
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    files = input_files()
    LOGGER.info("OSSEC monthly classified files: " + str(len(files)))
    if DATABASE_FILE.exists():
        DATABASE_FILE.unlink()
    connection = sqlite3.connect(DATABASE_FILE)
    records = []
    summary_stem = (
        "ossec_security_episodes_summary" if episodes_only
        else "ossec_observation_dataset_summary"
    )
    try:
        create_database(connection)
        lookup_count = event_lookup_ids(connection)
        loaded, invalid_timestamps = load_events(connection, files)
        if loaded <= 0:
            raise ValueError("No valid timestamped OSSEC events were loaded")
        validate_lookup_coverage(connection)
        LOGGER.info("OSSEC event lookup IDs: " + str(lookup_count))

        generated = []
        if not episodes_only:
            generated.append(("individual", *write_individual_dataset(connection), "__one__"))
            generated.append(("host_5min", *write_host_window_dataset(connection), "total_events"))
        generated.append(("episodes", *write_episode_dataset(connection), "event_count"))
        if not episodes_only:
            generated.append(("host_behavior_1d", *write_behavior_dataset(connection), "total_events"))

        for dataset, dataset_path, lineage_path, rows, lineage_rows, count_column in generated:
            validation = validate_dataset_lineage(dataset_path, lineage_path, count_column)
            if validation["dataset_rows"] != rows or validation["lineage_rows"] != lineage_rows:
                raise ValueError("Internal output count mismatch for " + dataset)
            record = {
                "dataset": dataset,
                "dataset_file": str(dataset_path),
                "lineage_file": str(lineage_path),
                **validation,
            }
            records.append(record)
            LOGGER.info(
                dataset + ": rows=" + str(rows)
                + ", lineage_rows=" + str(lineage_rows)
                + ", unique_events=" + str(validation["unique_events"])
                + ", events/observation=" + format(validation["mean_events_per_observation"], ".2f")
            )
        write_summaries(records, summary_stem)
        LOGGER.info("Invalid timestamp rows skipped upstream: " + str(invalid_timestamps))
    finally:
        connection.close()
    LOGGER.info("Complete: " + str(OUTPUT_FOLDER / (summary_stem + ".csv")))
    if DELETE_DATABASE_WHEN_COMPLETE and DATABASE_FILE.is_file():
        DATABASE_FILE.unlink()
        LOGGER.info("Deleted temporary SQLite observation store")
    else:
        LOGGER.info("SQLite observation store: " + str(DATABASE_FILE))


if __name__ == "__main__":
    args = parse_args()
    runlog.configure_from(args)
    try:
        with runlog.run():
            main(args.episodes_only)
    except KeyboardInterrupt:                    # runlog.run() has logged it
        sys.exit(130)
    except Exception:
        LOGGER.exception("OSSEC workflow failed")
        sys.exit(1)
