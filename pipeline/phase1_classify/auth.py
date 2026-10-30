"""Classify authentication logs with occurrence-level lineage.

Stage 1 of the authentication-log explainable-lineage workflow.

This module is fully standalone. It contains its ordered authentication-event
classification registry, normalization logic, recursive source discovery,
atomic monthly CSV generation, and occurrence-level lineage handling.

Inputs
------
data/phase0_raw/archives/*.zip      (authlog members are extracted first)
data/phase0_raw/auth/YYYY-MM*/**/*.txt, and extensionless authlog_* files

Outputs
-------
data/phase1_classify/auth/classified_authlog_events_YYYY-MM.csv
data/phase1_classify/auth/authlog_event_lookup.csv
data/phase1_classify/auth/authlog_lineage_summary.json
data/phase1_classify/auth/authlog_classification_summary.csv


Command-line usage
------------------
Run with INFO checkpoints (the default)::

    python pipeline/phase1_classify/auth.py

Include file and batch details, updating loop progress every five seconds::

    python pipeline/phase1_classify/auth.py --verbose --progress-interval 5

Suppress routine progress::

    python pipeline/phase1_classify/auth.py --quiet

.. note::

   Checkpoints are flushed to stderr with local timestamps. Progress reports
   include elapsed seconds and item throughput; classification also reports
   percentage completion. Updates happen during loop processing, so blocking
   I/O can delay a checkpoint. No raw authentication lines are logged.
   Counting reads the sources once before the classification pass.

Identity contract
-----------------
``record_id``
    Unique physical occurrence of one source line. This is the downstream
    lineage primary key.

``source_event_id``
    Solaris/syslog event identifier parsed from the source prefix. It is kept
    as metadata and is not assumed to be globally unique.

``raw_line_sha256``
    SHA-256 fingerprint of the exact physical source line, excluding only its
    newline terminator.

``original_log_line``
    Exact physical source line, excluding only the newline terminator.

``classification_line``
    Stripped line passed to the existing regex classifier.

The downstream evidence path is:

    row_manifest_id -> record_id -> authlog_event_lookup.csv
    -> original_log_line -> source_file -> source_line
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import Progress  # noqa: E402

LOGGER = runlog.LOGGER

ARCHIVE_FOLDER = Path("data/phase0_raw/archives")
EXTRACT_FOLDER = Path("data/phase0_raw/auth")
OUTPUT_FOLDER = Path("data/phase1_classify/auth")
# Archives up to 2026-04 name the logs authlog_<host>.txt; from 2026-05 they
# are extensionless (authlog_<host>), so both are read.
INPUT_PATTERN = "????-??*/**/*"
AUTH_ARCHIVE_DIRECTORY = "authlog"
AUTH_FILE_PREFIX = "authlog"
WRITE_BATCH_SIZE = 10_000
SKIP_COMPLETED_MONTHS = True
CLASSIFIER_WRAPPER_VERSION = "2026-09-18-auth-lineage-01"

EVENT_LOOKUP_FILE = OUTPUT_FOLDER / "authlog_event_lookup.csv"
LINEAGE_SUMMARY_FILE = OUTPUT_FOLDER / "authlog_lineage_summary.json"
CLASSIFICATION_SUMMARY_FILE = OUTPUT_FOLDER / "authlog_classification_summary.csv"

LINEAGE_FIELDS = [
    "record_id",
    "raw_line_sha256",
    "source_event_id",
]

SOURCE_FIELDS = [
    "partition_month",
    "source_file",
    "source_line",
    "original_log_line",
    "classification_line",
]

LOOKUP_PREFERRED_FIELDS = [
    "record_id",
    "raw_line_sha256",
    "source_event_id",
    "timestamp",
    "partition_month",
    "hostname",
    "process_name",
    "pid",
    "facility",
    "event_type",
    "username",
    "target_username",
    "invalid_user_indicator",
    "source_ip",
    "source_port",
    "source_location",
    "authentication_method",
    "connection_stage",
    "terminal_path",
    "failure_count",
    "failure_code",
    "disconnect_code",
    "operation",
    "reason",
    "raw_message",
    "original_log_line",
    "classification_line",
    "source_file",
    "source_line",
]


def parse_args():
    """Parse and validate command-line options.
    
    :returns: Validated CLI settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description=(
            "Run the existing authentication classifier with exact source-line "
            "lineage and an authoritative event lookup."
        )
    )
    parser.add_argument(
        "--archive-folder",
        type=Path,
        default=ARCHIVE_FOLDER,
        help="Monthly ZIPs; new authlog files are extracted from them first.",
    )
    parser.add_argument(
        "--extract-folder",
        type=Path,
        default=EXTRACT_FOLDER,
    )
    parser.add_argument(
        "--output-folder",
        type=Path,
        default=OUTPUT_FOLDER,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Reclassify all monthly partitions even when outputs are complete.",
    )
    runlog.add_arguments(parser)
    args = parser.parse_args()
    return args


def clean(value):
    """Convert a value to stripped text; map None to an empty string.
    
    :param value: Value to normalize.
    :returns: Normalized text.
    :rtype: str
    """
    return str(value).strip() if value is not None else ""


class StandaloneAuthClassifier:
    """Standalone ordered authlog classifier with no external dependency."""

    UNKNOWN_EVENT_TYPE = "AUTHLOG_UNKNOWN_EVENT"
    OUTPUT_FIELDNAMES = [
        "session_id", "timestamp", "hostname", "process_name", "pid",
        "facility", "event_type", "username", "target_username",
        "invalid_user_indicator", "source_ip", "source_port",
        "source_location", "authentication_method", "connection_stage",
        "terminal_path", "failure_count", "failure_code", "disconnect_code",
        "server_protocol_version", "client_protocol_version", "message_type",
        "sequence_number", "module_index", "pam_config_path", "module_path",
        "operation", "reason", "raw_message",
    ]

    BASE = re.compile(
        r"^(?:(?P<log_path>.*?):)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<process_name>[A-Za-z0-9_.@+-]+)\]?"
        r"(?:\[(?P<pid>\d+)\])?:\s+\[ID\s+(?P<event_id>\d+)\s+"
        r"(?P<facility>[^\]]+)\]\s+(?P<raw_message>.*)$"
    )
    REPEAT = re.compile(
        r"^(?:(?P<log_path>.*?):)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+(?P<raw_message>last message repeated\s+\d+\s+times?)\s*$",
        re.I,
    )

    DEFAULT_REASONS = {
        "SSH_LOGIN_SUCCESS": "authentication accepted",
        "SSH_LOGIN_FAILED": "authentication failed",
        "SSH_INVALID_USER": "invalid user connection attempt",
        "SSH_AUTHENTICATION_POSTPONED": "authentication postponed",
        "SSH_MAX_AUTHENTICATION_ATTEMPTS_EXCEEDED": "maximum authentication attempts exceeded",
        "SSH_DISCONNECTING_AUTH_FAILURES": "too many authentication failures",
        "SSH_CONNECTION_CLOSED": "connection closed",
        "SSH_CONNECTION_RESET": "connection reset",
        "SSH_SUBSYSTEM_REQUEST": "subsystem requested",
        "SSH_SUBSYSTEM_NOT_FOUND": "requested subsystem not found",
        "SU_SESSION_SUCCESS": "user switch succeeded",
        "SU_SESSION_FAILED": "user switch failed",
        "LOGIN_ROOT_CONSOLE": "root console login",
        "AUTH_ACCOUNT_LOCKED": "account locked after excessive failures",
        "DBUS_SEND_MESSAGE_REJECTED": "D-Bus message rejected by access-control rules",
    }

    # Ordered message-payload patterns. Specific forms precede broad forms.
    RULES = [
        ("SSH_DEPRECATED_OPTION", r"(?P<config_context>rexec|reprocess config)\s+line\s+(?P<config_line>\d+):\s+Deprecated option\s+(?P<option_name>\S+)"),
        ("SSH_HOST_KEY_LOAD_FAILED", r"(?:error:\s+)?(?:Unable to load|Could not load)\s+host key:\s+(?P<key_path>\S+)"),
        ("SSH_AUTHORIZED_KEYS_PERMISSIONS_INVALID", r"Authentication refused:\s+(?P<reason>bad ownership or modes for file)\s+(?P<key_path>\S+)"),
        ("SSH_SERVER_LISTENING", r"Server listening on\s+(?P<listen_ip>\S+)\s+port\s+(?P<listen_port>\d+)\.?"),
        ("SSH_DAEMON_RESTARTING", r"Received\s+(?P<signal_name>SIGHUP);\s+(?P<reason>restarting)\.?"),
        ("SSH_DAEMON_TERMINATING", r"Received signal\s+(?P<signal_number>\d+);\s+terminating\.?"),
        ("SSH_DAEMON_EXITING_SIGNAL", r"Exiting on signal\s+(?P<signal_number>\d+)\.?"),
        ("SSH_KEX_INVALID_BANNER", r"error:\s+kex_exchange_identification:\s+(?P<reason>banner line contains invalid characters)\.?"),
        ("SSH_KEX_INVALID_PROTOCOL_IDENTIFIER", r"error:\s+kex_exchange_identification:\s+(?P<reason>client sent invalid protocol identifier)\s+\"(?P<protocol_identifier>[^\"]*)\""),
        ("SSH_KEX_CONNECTION_RESET", r"error:\s+kex_exchange_identification:\s+(?P<operation>read):\s+(?P<reason>Connection reset by peer)\.?"),
        ("SSH_KEX_CONNECTION_CLOSED", r"error:\s+kex_exchange_identification:\s+(?P<reason>Connection closed by remote host)"),
        ("SSH_KEX_WRITE_BROKEN_PIPE", r"error:\s+kex_exchange_identification:\s+(?P<operation>write):\s+(?P<reason>Broken pipe)"),
        ("SSH_BAD_PACKET_LENGTH", r"Bad packet length\s+(?P<packet_length>\d+)\.?(?:\s+\[(?P<connection_stage>[^\]]+)\])?"),
        ("SSH_PROTOCOL_VERSION_MISMATCH", r"error:\s+(?P<reason>Protocol major versions differ):\s+(?P<server_protocol_version>\d+)\s+vs\.\s+(?P<client_protocol_version>\d+)"),
        ("SSH_DISPATCH_PROTOCOL_ERROR", r"dispatch_protocol_error:\s+type\s+(?P<message_type>\d+)\s+seq\s+(?P<sequence_number>\d+)\s+\[(?P<connection_stage>preauth)\]"),
        ("PAM_MODULE_STAT_FAILED", r"open_module\[(?P<module_index>\d+):(?P<pam_config_path>[^\]]+)\]:\s+stat\((?P<module_path>[^)]+)\)\s+failed:\s+(?P<reason>No such file or directory)"),
        ("PAM_MODULE_LOAD_FAILED", r"load_modules\[(?P<module_index>\d+):(?P<pam_config_path>[^\]]+)\]:\s+can not open module\s+(?P<module_path>\S+)"),
        ("PAM_AUTHENTICATION_TOKEN_MANIPULATION_ERROR", r"fatal:\s+PAM:\s+(?P<operation>pam_chauthtok)\(\):\s+(?P<reason>Authentication token manipulation error)"),
        ("PAM_PASSWORD_CHANGE_CONVERSATION_FAILURE", r"(?P<operation>change password failure):\s+(?P<reason>Conversation failure)"),
        ("SU_SESSION_INITIATED", r"initiated by\s+(?P<username><invalid username>|\S+)\s+on\s+(?P<terminal_path>/dev/\S+)"),
        ("SSH_INVALID_USER", r"\s*(?P<invalid_user_indicator>Invalid user|Illegal user)\s+(?P<username><invalid username>|\S+)\s+from\s+(?P<source_ip>\S+)(?:\s+port\s+(?P<source_port>\d+))?"),
        ("SSH_USER_NOT_ALLOWED", r"User\s+(?P<username>\S+)(?:\s+from\s+(?P<source_ip>\S+))?\s+not allowed because not listed in\s+(?P<access_control>AllowUsers)"),
        ("SSH_PUBLIC_KEY_TYPE_NOT_ACCEPTED", r"userauth_pubkey:\s+key type\s+(?P<key_type>\S+)\s+not in\s+(?P<access_control>PubkeyAcceptedKeyTypes)\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_PAM_ACCOUNT_ACCESS_DENIED", r"fatal:\s+Access denied for user\s+(?P<username>\S+)\s+by\s+(?P<access_control>PAM account configuration)\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_PAM_NO_ACCOUNT_PRESENT", r"error:\s+PAM:\s+(?P<reason>No account present for user)\s+for\s+(?:(?P<invalid_user_indicator>illegal user|invalid user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)"),
        ("SSH_PAM_MAX_ATTEMPTS_EXCEEDED", r"error:\s+PAM:\s+(?P<reason>Maximum number of attempts exceeded)\s+for\s+(?:(?P<invalid_user_indicator>illegal user|invalid user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)"),
        ("SSH_PAM_CONVERSATION_FAILURE", r"error:\s+PAM:\s+(?P<reason>Conversation failure)\s+for\s+(?:(?P<invalid_user_indicator>illegal user|invalid user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)"),
        ("SSH_MAX_AUTHENTICATION_ATTEMPTS_EXCEEDED", r"error:\s+(?P<reason>maximum authentication attempts exceeded)\s+for\s+(?:(?P<invalid_user_indicator>invalid user|illegal user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)\s+ssh2\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_DISCONNECTING_AUTH_FAILURES", r"Disconnecting\s+(?:(?P<invalid_user_indicator>invalid user|illegal user)|authenticating user)\s+(?P<username>\S+)\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+):\s+(?P<reason>Too many authentication failures)\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_AUTHENTICATION_POSTPONED", r"Postponed\s+(?P<authentication_method>keyboard-interactive/pam|keyboard-interactive|publickey|password)\s+for\s+(?:(?P<invalid_user_indicator>invalid user|illegal user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)\s+ssh2\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_LOGIN_SUCCESS", r"Accepted\s+(?P<authentication_method>publickey|keyboard-interactive/pam|keyboard-interactive|password)\s+for\s+(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)\s+ssh2(?:\s*:\s*(?P<key_type>\S+)\s+SHA256:(?P<fingerprint>\S+))?"),
        ("SSH_LOGIN_FAILED", r"Failed\s+(?P<authentication_method>keyboard-interactive/pam|keyboard-interactive|password|none|publickey)\s+for\s+(?:(?P<invalid_user_indicator>invalid user|illegal user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)\s+ssh2(?:\s*:\s*(?P<key_type>\S+)\s+SHA256:(?P<fingerprint>\S+))?"),
        ("SSH_LOGIN_FAILED", r"error:\s+PAM:\s+(?P<reason>Authentication failed)\s+for\s+(?:(?P<invalid_user_indicator>illegal user|invalid user)\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)"),
        ("SSH_SUBSYSTEM_NOT_FOUND", r"subsystem request for\s+(?P<subsystem>\S+)(?:\s+by user\s+(?P<username>\S+))?\s+failed,\s+(?P<reason>subsystem not found)\.?"),
        ("SSH_SUBSYSTEM_REQUEST", r"subsystem request for\s+(?P<subsystem>\S+)(?:\s+by user\s+(?P<username>\S+))?"),
        ("SSH_INVALID_USER_CONNECTION_RESET", r"Connection reset by\s+(?P<invalid_user_indicator>invalid user|illegal user)\s+(?P<username>\S+)\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_INVALID_USER_CONNECTION_CLOSED", r"Connection closed by\s+(?P<invalid_user_indicator>invalid user|illegal user)\s+(?P<username>\S+)\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)\s*\[(?P<connection_stage>preauth)\]"),
        ("SSH_CONNECTION_RESET", r"Connection reset by(?: authenticating user\s+(?P<username>\S+)\s+)?\s*(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)(?:\s*\[(?P<connection_stage>preauth)\])?"),
        ("SSH_USER_DISCONNECT_RECEIVED", r"Received disconnect from\s+(?P<source_ip>\S+?)(?:\s+port\s+|\s*:\s*)(?P<source_port>\d+):\s*(?P<reason>disconnected by user)\.?"),
        ("SSH_DISCONNECT_RECEIVED", r"Received disconnect from\s+(?P<source_ip>\S+?)(?:\s+port\s+|\s*:\s*)(?P<source_port>\d+):\s*(?P<reason>.*?)"),
        ("SSH_USER_DISCONNECTED", r"Disconnected from user\s+(?P<username>\S+)\s+(?P<source_ip>\S+)\s+port\s+(?P<source_port>\d+)"),
        ("SSH_CONNECTION_CLOSED", r"Connection closed by\s+(?P<source_ip>\S+)(?:\s+port\s+(?P<source_port>\d+))?(?:\s*\[(?P<connection_stage>[^\]]+)\])?"),
        ("SU_SESSION_SUCCESS", r"'su\s+(?P<target_username>[^']+)'\s+succeeded for\s+(?P<username>\S+)\s+on\s+(?P<terminal_path>\S+)"),
        ("SU_SESSION_FAILED", r"'su\s+(?P<target_username>[^']+)'\s+failed for\s+(?P<username>\S+)\s+on\s+(?P<terminal_path>\S+)"),
        ("LOGIN_ROOT_CONSOLE", r"(?P<reason>ROOT LOGIN)\s+(?P<terminal_path>/dev/\S+)"),
        ("LOGIN_REPEATED_CONSOLE_FAILURES", r"(?P<reason>REPEATED LOGIN FAILURES)\s+ON\s+(?P<terminal_path>/dev/\S+)(?:,\s*(?P<username>\S+))?"),
        ("GDM_ACCOUNT_LOCKED", r"Excessive\s+\((?P<failure_count>\d+)\)\s+login failures for\s+(?P<username>\S+):\s+locking account\.?"),
        ("GDM_EMPTY_PASSWORD_NOT_ALLOWED", r"(?:pam_authtok_get:\s+gdm-password:\s+)?(?P<reason>empty password(?: not allowed)?)\s+for\s+(?P<username>\S+)(?:\s+from\s+(?P<source_location>localhost)|\s+(?P<access_control>not allowed))?\.?"),
        ("AUTH_ACCOUNT_LOCKED", r"Excessive\s+\((?P<failure_count>\d+)\)\s+login failures for\s+(?P<username>\S+):\s+locking account\.?"),
        ("CRON_LOCKED_ACCOUNT_VALIDATION", r"pam_unix_account:\s+cron attempting to validate locked account\s+(?P<username>\S+)\s+from\s+(?P<source_location>local host)"),
        ("GNOME_KEYRING_STORE_OPEN_FAILED", r"couldn't open store file:\s+(?P<store_path>\S+):\s+(?P<reason>Permission denied|Bad file number)"),
        ("GNOME_KEYRING_NO_PRIVATE_KEYS", r"(?P<reason>no private keys found in file)"),
        ("GNOME_KEYRING_INVALID_PRIVATE_SSH_KEY", r"(?P<reason>invalid or unrecognized private SSH key):\s*(?P<key_reference>.+?)"),
        ("GNOME_KEYRING_SECURE_MEMORY_ALLOCATION_FAILED", r"(?P<reason>couldn't allocate secure memory to keep passwords and or keys from being written to the disk)"),
        ("GNOME_KEYRING_SIGNING_FAILED", r"(?P<operation>signing of the data)\s+failed:\s+(?P<reason>The operation failed)"),
        ("GNOME_KEYRING_INTERNAL_ASSERTION_FAILED", r"file\s+(?P<source_code_file>\S+):\s+line\s+(?P<source_code_line>\d+)\s+\((?P<function_name>[^)]+)\):\s+(?P<reason>should not be reached)"),
        ("DBUS_SEND_MESSAGE_REJECTED", r"\[system\]\s+Rejected send message,\s+(?P<matched_rule_count>\d+)\s+matched rules?;.*"),
        ("SSH_INTERNAL_MESSAGE_SEND_BROKEN_PIPE", r"error:\s+ssh_msg_send:\s+write:\s+(?P<reason>Broken pipe)"),
        ("SSH_PACKET_SEND_DEBUG_BROKEN_PIPE", r"fatal:\s+ssh_packet_send_debug:\s+(?P<reason>Broken pipe)"),
        ("SSH_PROCESS_OUTPUT_BROKEN_PIPE", r"fatal:\s+process_output:\s+ssh_packet_write_poll:\s+(?P<reason>Broken pipe)"),
        ("SSH_SOCKET_OPTION_ERROR", r"error:\s+setsockopt\s+SO_KEEPALIVE:\s+(?P<reason>Invalid argument)"),
    ]
    COMPILED_RULES = [(event_type, re.compile(r"^" + pattern + r"$", re.I)) for event_type, pattern in RULES]

    def classify_line(self, line):
        """Classify a syslog line using the first matching ordered rule.
        
        :param line: Stripped source line.
        :returns: Parsed fields and event type, including the unknown fallback.
        :rtype: dict
        """
        repeat = self.REPEAT.match(line)
        if repeat:
            event = repeat.groupdict()
            event.update({"process_name": "syslog", "event_id": "", "facility": "", "event_type": "SYSLOG_MESSAGE_REPEATED"})
            return event
        match = self.BASE.match(line)
        if match:
            event = match.groupdict()
            message = event.get("raw_message", "")
        else:
            event = {"log_path": "", "timestamp": "", "hostname": "", "process_name": "", "pid": "", "event_id": "", "facility": "", "raw_message": line.strip()}
            message = event["raw_message"]
        for event_type, pattern in self.COMPILED_RULES:
            found = pattern.match(message)
            if found:
                event.update({key: value for key, value in found.groupdict().items() if value is not None})
                event["event_type"] = event_type
                return event
        event["event_type"] = self.UNKNOWN_EVENT_TYPE
        return event

    def normalize_event_fields(self, event):
        """Normalize text fields and supply event-specific defaults.
        
        :param event: Parsed event mapping; not modified in place.
        :returns: Normalized event fields.
        :rtype: dict
        """
        normalized = {key: clean(value) for key, value in event.items()}
        for key in ("hostname", "process_name", "authentication_method", "connection_stage", "invalid_user_indicator"):
            normalized[key] = normalized.get(key, "").lower()
        normalized["source_ip"] = normalized.get("source_ip", "").rstrip(".")
        if normalized.get("event_type") == "LOGIN_ROOT_CONSOLE":
            normalized["username"] = "root"
        if not normalized.get("reason"):
            normalized["reason"] = self.DEFAULT_REASONS.get(normalized.get("event_type", ""), "")
        return normalized

    def normalize_timestamp(self, timestamp, year_month):
        """Add the archive year to a syslog timestamp.
        
        :param timestamp: Syslog timestamp or empty text.
        :param year_month: Archive partition in YYYY-MM format.
        :returns: Formatted timestamp, or the original text if parsing fails.
        
        January archives map December timestamps to the previous year.
        :rtype: str
        """
        timestamp = clean(timestamp)
        if not timestamp:
            return ""
        try:
            archive_year = int(year_month[:4])
            archive_month = int(year_month[5:7])
            parsed = datetime.strptime(str(archive_year) + " " + timestamp, "%Y %b %d %H:%M:%S")
            if archive_month == 1 and parsed.month == 12:
                parsed = parsed.replace(year=archive_year - 1)
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return timestamp

    def create_session_id(self, event, year_month, source_file, source_line):
        """Build the existing session grouping identifier.
        
        :param event: Normalized event fields.
        :param year_month: Archive month.
        :param source_file: Source path; its basename is used.
        :param source_line: One-based physical line number used as a fallback.
        :returns: Session identifier; this is not the occurrence-level primary key.
        :rtype: str
        """
        hostname = clean(event.get("hostname"))
        process_name = clean(event.get("process_name"))
        pid = clean(event.get("pid"))
        source_filename = os.path.basename(source_file)
        if hostname and process_name and pid:
            return ":".join((year_month, hostname, process_name, source_filename, pid))
        if hostname and process_name:
            return ":".join((year_month, hostname, process_name, source_filename, str(source_line)))
        return ":".join((year_month, "unknown", source_filename, str(source_line)))


def load_classifier(_path=None):
    """Instantiate the embedded standalone classifier.
    
    :param _path: Unused compatibility argument.
    :returns: Classifier instance and the resolved module path.
    :rtype: tuple
    """
    return StandaloneAuthClassifier(), Path(__file__).resolve()

def year_month_from_path(file_path, extract_folder):
    """Read a valid month from the first relative path component.
    
    :param file_path: Source file path.
    :param extract_folder: Root containing month directories.
    :returns: YYYY-MM prefix, or None when the prefix is invalid.
    :rtype: str or None
    """
    relative = file_path.resolve().relative_to(extract_folder.resolve())
    first = relative.parts[0]
    if len(first) < 7:
        return None
    value = first[:7]
    try:
        datetime.strptime(value, "%Y-%m")
        return value
    except ValueError:
        return None


def is_auth_log_file(name):
    """Accept any ``.txt`` file (as before) or an extensionless ``authlog_*`` file.

    :param name: File name without folders.
    :rtype: bool
    """
    suffix = PurePosixPath(name).suffix.lower()
    return suffix == ".txt" or (suffix == "" and name.lower().startswith(AUTH_FILE_PREFIX))


def extract_auth_archives(archive_folder, extract_folder):
    """Copy authlog members of every monthly ZIP to ``<extract>/<archive stem>/<file>``.

    Files already there are left alone, so earlier months are not touched and
    reruns only add new archives. Member folders are dropped, matching the
    layout of the months extracted before this step existed.

    :param archive_folder: Folder holding the monthly ZIPs.
    :param extract_folder: Root of the extracted authentication logs.
    :returns: Counts of archives read, files extracted and files already present.
    :rtype: dict
    """
    counts = {"archives": 0, "extracted": 0, "present": 0}
    for zip_path in sorted(Path(archive_folder).glob("*.zip")):
        counts["archives"] += 1
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.infolist():
                member_path = PurePosixPath(member.filename.replace("\\", "/"))
                folders = [part.lower() for part in member_path.parts[:-1]]
                if (member.is_dir() or AUTH_ARCHIVE_DIRECTORY not in folders
                        or not member_path.name.lower().startswith(AUTH_FILE_PREFIX)
                        or not is_auth_log_file(member_path.name)):
                    continue
                target = Path(extract_folder) / zip_path.stem / member_path.name
                if target.exists():
                    counts["present"] += 1
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(target.name + ".part")
                with archive.open(member) as source, open(temporary, "wb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                os.replace(temporary, target)
                counts["extracted"] += 1
                LOGGER.debug("Extracted %s -> %s", member.filename, target)
    LOGGER.info("Archives read: %s; authlog files extracted: %s; already present: %s",
                counts["archives"], counts["extracted"], counts["present"])
    return counts


def discover_files(extract_folder):
    """Recursively discover text files and group them by archive month.
    
    :param extract_folder: Root directory searched with INPUT_PATTERN.
    :returns: Month-to-sorted-file-list mapping.
    :rtype: dict
    :raises FileNotFoundError: If no eligible input files exist.
    """
    pattern = str(extract_folder / INPUT_PATTERN)
    files_by_month = {}
    LOGGER.info("[1/4] Discovering source files: %s", pattern)
    progress = Progress("Source files discovered")
    discovered = []
    for value in glob.iglob(pattern, recursive=True):
        discovered.append(value)
        progress.report(len(discovered))
    progress.report(len(discovered), force=True)
    for value in sorted(discovered):
        path = Path(value)
        if not path.is_file() or not is_auth_log_file(path.name):
            continue
        year_month = year_month_from_path(path, extract_folder)
        if year_month:
            files_by_month.setdefault(year_month, []).append(path)
    if not files_by_month:
        raise FileNotFoundError(
            "No authentication text files found at: " + pattern
        )
    return files_by_month


def relative_source_file(file_path, extract_folder):
    """Create a portable source reference relative to the input root.
    
    :param file_path: Source file path.
    :param extract_folder: Input root directory.
    :returns: POSIX-style relative path.
    :rtype: str
    """
    return file_path.resolve().relative_to(extract_folder.resolve()).as_posix()


def line_hash(physical_line):
    """Hash the decoded physical line without its newline terminator.
    
    :param physical_line: Unstripped line content encoded as UTF-8 with replacement.
    :returns: Full SHA-256 hexadecimal digest.
    :rtype: str
    """
    return hashlib.sha256(
        physical_line.encode("utf-8", errors="replace")
    ).hexdigest()


def build_record_id(year_month, source_file, source_line, physical_line):
    """Build a deterministic occurrence identifier from source coordinates.
    
    :param year_month: Archive month.
    :param source_file: Relative source reference.
    :param source_line: One-based physical line number.
    :param physical_line: Exact decoded line without newline terminators.
    :returns: First 24 hexadecimal characters of the occurrence digest.
    :rtype: str
    """
    seed = "|".join([
        year_month,
        source_file.replace("\\", "/"),
        str(source_line),
        line_hash(physical_line),
    ])
    return hashlib.sha256(
        seed.encode("utf-8", errors="replace")
    ).hexdigest()[:24]


def normalize_event(classifier, event):
    """Normalize fields using classifier support or a text fallback.
    
    :param classifier: Classifier instance.
    :param event: Parsed event mapping.
    :returns: Normalized event mapping.
    :rtype: dict
    """
    if hasattr(classifier, "normalize_event_fields"):
        return classifier.normalize_event_fields(event)
    return {
        key: clean(value)
        for key, value in event.items()
    }


def prepare_lineage_row(
    classifier,
    event,
    year_month,
    file_path,
    source_reference,
    source_line,
    physical_line,
    classification_line,
):
    """Combine classification fields with occurrence-level lineage.
    
    :param classifier: Classifier instance.
    :param event: Parsed event mapping.
    :param year_month: Archive month.
    :param file_path: Source file path.
    :param source_reference: Relative POSIX source path.
    :param source_line: One-based physical line number.
    :param physical_line: Decoded original line without newline terminators.
    :param classification_line: Stripped text passed to the classifier.
    :returns: CSV-ready classification and provenance fields.
    :rtype: dict
    """
    normalized = normalize_event(classifier, event)
    parsed_source_event_id = clean(normalized.get("event_id"))
    timestamp = classifier.normalize_timestamp(
        normalized.get("timestamp", ""),
        year_month,
    )
    session_id = classifier.create_session_id(
        normalized,
        year_month,
        str(file_path),
        source_line,
    )
    row = {
        field: clean(normalized.get(field, ""))
        for field in classifier.OUTPUT_FIELDNAMES
    }
    row.update({
        "record_id": build_record_id(
            year_month,
            source_reference,
            source_line,
            physical_line,
        ),
        "raw_line_sha256": line_hash(physical_line),
        "source_event_id": parsed_source_event_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "partition_month": year_month,
        "source_file": source_reference,
        "source_line": str(source_line),
        "original_log_line": physical_line,
        "classification_line": classification_line,
    })
    if not clean(row.get("event_type")):
        row["event_type"] = getattr(
            classifier,
            "UNKNOWN_EVENT_TYPE",
            "AUTHLOG_UNKNOWN_EVENT",
        )
    return row


def output_fields(classifier):
    """Combine lineage, classifier and source columns in stable order.
    
    :param classifier: Classifier exposing OUTPUT_FIELDNAMES.
    :returns: Deduplicated column names.
    :rtype: list
    """
    fields = []
    for field in LINEAGE_FIELDS + list(classifier.OUTPUT_FIELDNAMES) + SOURCE_FIELDS:
        if field not in fields:
            fields.append(field)
    return fields


def count_non_empty_lines(files):
    """Count non-blank input lines with periodic scanning checkpoints.
    
    :param files: Iterable of source paths.
    :returns: Number of lines eligible for classification.
    :rtype: int
    """
    count = 0
    scanned = 0
    progress = Progress("Source physical lines scanned")
    for path in files:
        LOGGER.debug("Counting source lines: %s", path)
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
            buffering=1024 * 1024,
            newline="",
        ) as handle:
            for line in handle:
                scanned += 1
                if line.rstrip("\r\n").strip():
                    count += 1
                progress.report(scanned)
    progress.report(scanned, force=True)
    LOGGER.info("Counted %s non-empty source lines", f"{count:,}")
    return count


def inspect_existing(path, fields):
    """Validate required columns and unique non-blank record IDs.
    
    :param path: Existing monthly CSV path.
    :param fields: Required column names.
    :returns: Row count and event-type Counter.
    
    This checks structure and IDs, not equality with current source contents.
    :rtype: tuple
    :raises ValueError: If lineage validation fails.
    """
    LOGGER.info("Checking existing output: %s", path)
    progress = Progress("Existing rows validated")
    rows = 0
    event_counts = Counter()
    seen = set()
    with open(
        path,
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("CSV has no header: " + str(path))
        missing = set(fields).difference(reader.fieldnames)
        if missing:
            raise ValueError(
                "CSV lacks lineage columns in " + str(path) + ": "
                + ", ".join(sorted(missing))
            )
        for row in reader:
            record_id = clean(row.get("record_id"))
            if not record_id:
                raise ValueError("Blank record_id in " + str(path))
            if record_id in seen:
                raise ValueError(
                    "Duplicate record_id in " + str(path) + ": " + record_id
                )
            seen.add(record_id)
            rows += 1
            progress.report(rows)
            event_counts[
                clean(row.get("event_type")) or "AUTHLOG_UNKNOWN_EVENT"
            ] += 1
    progress.report(rows, force=True)
    return rows, event_counts


def atomic_text_csv(path, fields):
    """Open a temporary CSV beside its eventual destination.
    
    :param path: Final output path.
    :param fields: Ordered CSV column names.
    :returns: Open handle, temporary path and DictWriter.
    
    The caller must close the handle and replace the destination on success,
    or remove the temporary file on failure.
    :rtype: tuple
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        delete=False,
        dir=path.parent,
        prefix=path.name + ".",
        suffix=".tmp",
    )
    writer = csv.DictWriter(
        handle,
        fieldnames=fields,
        extrasaction="ignore",
    )
    writer.writeheader()
    return handle, Path(handle.name), writer


def classify_month(
    classifier,
    year_month,
    files,
    extract_folder,
    output_folder,
    force,
):
    """Validate or regenerate one monthly classification CSV.
    
    :param classifier: Classifier instance.
    :param year_month: Month to process.
    :param files: Source paths for this month.
    :param extract_folder: Input root directory.
    :param output_folder: Destination directory.
    :param force: Regenerate even when an existing output passes validation.
    :returns: Monthly status, row counts and event-type counts.
    :rtype: dict
    :raises ValueError: If lineage validation fails.
    """
    fields = output_fields(classifier)
    output_path = output_folder / (
        "classified_authlog_events_" + year_month + ".csv"
    )
    LOGGER.info("%s: counting lines in %s source files", year_month, len(files))
    expected_rows = count_non_empty_lines(files)
    if (
        SKIP_COMPLETED_MONTHS
        and not force
        and output_path.is_file()
    ):
        try:
            existing_rows, existing_counts = inspect_existing(
                output_path,
                fields,
            )
            if existing_rows == expected_rows:
                LOGGER.info(
                    "Skipping complete lineage output "
                    + year_month + ": " + str(output_path)
                )
                return {
                    "year_month": year_month,
                    "status": "skipped",
                    "output_file": str(output_path),
                    "source_files": len(files),
                    "expected_rows": expected_rows,
                    "output_rows": existing_rows,
                    "known_events": existing_rows - existing_counts.get(
                        getattr(
                            classifier,
                            "UNKNOWN_EVENT_TYPE",
                            "AUTHLOG_UNKNOWN_EVENT",
                        ),
                        0,
                    ),
                    "unknown_events": existing_counts.get(
                        getattr(
                            classifier,
                            "UNKNOWN_EVENT_TYPE",
                            "AUTHLOG_UNKNOWN_EVENT",
                        ),
                        0,
                    ),
                    "event_counts": dict(existing_counts),
                }
        except (OSError, csv.Error, ValueError) as error:
            LOGGER.warning(
                "Existing monthly output will be regenerated: "
                + str(error)
            )

    handle, temporary_path, writer = atomic_text_csv(
        output_path,
        fields,
    )
    LOGGER.info("%s: classifying %s events", year_month, f"{expected_rows:,}")
    progress = Progress(year_month + " events classified", expected_rows)
    batch = []
    event_counts = Counter()
    seen_record_ids = set()
    total = 0
    try:
        for file_path in files:
            source_reference = relative_source_file(
                file_path,
                extract_folder,
            )
            LOGGER.debug("Reading authlog: " + str(file_path))
            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="replace",
                buffering=1024 * 1024,
                newline="",
            ) as source:
                for source_line, line in enumerate(source, start=1):
                    progress.report(total)
                    physical_line = line.rstrip("\r\n")
                    if not physical_line.strip():
                        continue
                    classification_line = physical_line.strip()
                    event = classifier.classify_line(classification_line)
                    row = prepare_lineage_row(
                        classifier,
                        event,
                        year_month,
                        file_path,
                        source_reference,
                        source_line,
                        physical_line,
                        classification_line,
                    )
                    record_id = row["record_id"]
                    if record_id in seen_record_ids:
                        raise ValueError(
                            "Duplicate record_id generated in "
                            + year_month + ": " + record_id
                        )
                    seen_record_ids.add(record_id)
                    batch.append(row)
                    event_counts[row["event_type"]] += 1
                    total += 1
                    if len(batch) >= WRITE_BATCH_SIZE:
                        writer.writerows(batch)
                        batch.clear()
                        LOGGER.debug("%s: batch written; %s rows processed", year_month, total)
        if batch:
            writer.writerows(batch)
            batch.clear()
        handle.close()
        if total != expected_rows:
            raise ValueError(
                "Authentication row-count mismatch for " + year_month
                + ": expected=" + str(expected_rows)
                + ", written=" + str(total)
            )
        os.replace(temporary_path, output_path)
        progress.report(total, force=True)
        LOGGER.info("Monthly CSV committed: %s", output_path)
    except Exception:
        if not handle.closed:
            handle.close()
        if temporary_path.exists():
            temporary_path.unlink()
        raise

    unknown_type = getattr(
        classifier,
        "UNKNOWN_EVENT_TYPE",
        "AUTHLOG_UNKNOWN_EVENT",
    )
    return {
        "year_month": year_month,
        "status": "classified",
        "output_file": str(output_path),
        "source_files": len(files),
        "expected_rows": expected_rows,
        "output_rows": total,
        "known_events": total - event_counts.get(unknown_type, 0),
        "unknown_events": event_counts.get(unknown_type, 0),
        "event_counts": dict(event_counts),
    }


def rebuild_event_lookup(output_folder, fields):
    """Rebuild the lookup from all monthly CSVs in the output folder.
    
    :param output_folder: Directory containing monthly outputs.
    :param fields: Available classification columns.
    :returns: Lookup path and lineage cardinality statistics.
    :rtype: dict
    :raises ValueError: If lineage validation fails.
    :raises FileNotFoundError: If no eligible input files exist.
    """
    LOGGER.info("[3/4] Rebuilding authoritative event lookup")
    progress = Progress("Lookup rows written")
    monthly_paths = sorted(
        output_folder.glob("classified_authlog_events_????-??.csv")
    )
    if not monthly_paths:
        raise FileNotFoundError(
            "No classified authentication monthly CSV files were produced"
        )
    lookup_fields = [
        field for field in LOOKUP_PREFERRED_FIELDS
        if field in fields
    ]
    for required in (
        "record_id",
        "raw_line_sha256",
        "original_log_line",
        "source_file",
        "source_line",
    ):
        if required not in lookup_fields:
            lookup_fields.append(required)

    event_lookup_path = output_folder / EVENT_LOOKUP_FILE.name
    handle, temporary_path, writer = atomic_text_csv(
        event_lookup_path,
        lookup_fields,
    )
    seen = set()
    rows = 0
    duplicate_source_event_ids = Counter()
    try:
        for path in monthly_paths:
            LOGGER.info("Adding monthly output to lookup: %s", path)
            with open(
                path,
                "r",
                encoding="utf-8-sig",
                errors="replace",
                newline="",
            ) as source:
                reader = csv.DictReader(source)
                missing = {
                    "record_id",
                    "raw_line_sha256",
                    "original_log_line",
                    "source_file",
                    "source_line",
                }.difference(reader.fieldnames or [])
                if missing:
                    raise ValueError(
                        "Monthly authlog CSV lacks lineage columns in "
                        + str(path) + ": " + ", ".join(sorted(missing))
                    )
                for row in reader:
                    record_id = clean(row.get("record_id"))
                    if not record_id:
                        raise ValueError(
                            "Blank record_id in " + str(path)
                        )
                    if record_id in seen:
                        raise ValueError(
                            "Duplicate record_id across monthly outputs: "
                            + record_id
                        )
                    seen.add(record_id)
                    source_event_id = clean(row.get("source_event_id"))
                    if source_event_id:
                        duplicate_source_event_ids[source_event_id] += 1
                    writer.writerow(row)
                    rows += 1
                    progress.report(rows)
        handle.close()
        os.replace(temporary_path, event_lookup_path)
        progress.report(rows, force=True)
        LOGGER.info("Event lookup committed: %s", event_lookup_path)
    except Exception:
        if not handle.closed:
            handle.close()
        if temporary_path.exists():
            temporary_path.unlink()
        raise

    return {
        "event_lookup_file": str(event_lookup_path),
        "event_lookup_rows": rows,
        "unique_record_ids": len(seen),
        "unique_source_event_ids": len(duplicate_source_event_ids),
        "repeated_source_event_ids": int(
            sum(1 for count in duplicate_source_event_ids.values() if count > 1)
        ),
    }


def write_summary(output_folder, classifier_path, monthly_results, lookup):
    """Write classification CSV and lineage JSON summaries.
    
    :param output_folder: Destination directory.
    :param classifier_path: Path recorded as classifier provenance.
    :param monthly_results: Monthly result dictionaries.
    :param lookup: Lookup result statistics.
    :returns: Paths of the CSV summary and JSON summary.
    :rtype: tuple
    """
    LOGGER.info("[4/4] Writing classification and lineage summaries")
    summary_csv = output_folder / CLASSIFICATION_SUMMARY_FILE.name
    columns = [
        "year_month",
        "status",
        "output_file",
        "source_files",
        "expected_rows",
        "output_rows",
        "known_events",
        "unknown_events",
    ]
    with open(summary_csv, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=columns,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(monthly_results)

    lineage_summary_path = output_folder / LINEAGE_SUMMARY_FILE.name
    with open(
        lineage_summary_path,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            {
                "wrapper_version": CLASSIFIER_WRAPPER_VERSION,
                "standalone_classifier": str(classifier_path),
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "monthly_partitions": len(monthly_results),
                "total_events": int(
                    sum(result["output_rows"] for result in monthly_results)
                ),
                "known_events": int(
                    sum(result["known_events"] for result in monthly_results)
                ),
                "unknown_events": int(
                    sum(result["unknown_events"] for result in monthly_results)
                ),
                "identity_contract": {
                    "record_id": "unique physical source-line occurrence",
                    "source_event_id": (
                        "parsed Solaris/syslog event identifier; not globally unique"
                    ),
                    "raw_line_sha256": "exact physical line content fingerprint",
                    "source_coordinates": [
                        "partition_month",
                        "source_file",
                        "source_line",
                    ],
                },
                **lookup,
                "monthly_results": monthly_results,
            },
            handle,
            indent=2,
        )
    return summary_csv, lineage_summary_path


def main():
    """Run discovery, monthly classification, lookup and summary stages.
    
    :rtype: None
    """
    args = parse_args()
    runlog.configure_from(args)
    started = time.monotonic()
    LOGGER.info("Starting authentication classification")
    classifier, classifier_path = load_classifier()
    args.output_folder.mkdir(parents=True, exist_ok=True)

    extract_auth_archives(args.archive_folder, args.extract_folder)
    files_by_month = discover_files(args.extract_folder)
    LOGGER.info("Standalone authentication classifier: " + str(classifier_path))
    LOGGER.info("Monthly partitions: " + str(len(files_by_month)))
    LOGGER.info(
        "Authentication source files: "
        + str(sum(len(files) for files in files_by_month.values()))
    )

    results = []
    LOGGER.info("[2/4] Processing %s monthly partitions", len(files_by_month))
    for year_month in sorted(files_by_month):
        LOGGER.info("Processing authentication month: " + year_month)
        result = classify_month(
            classifier,
            year_month,
            files_by_month[year_month],
            args.extract_folder,
            args.output_folder,
            args.force,
        )
        results.append(result)
        LOGGER.info(
            year_month + ": status=" + result["status"]
            + ", rows=" + str(result["output_rows"])
            + ", unknown=" + str(result["unknown_events"])
        )

    fields = output_fields(classifier)
    lookup = rebuild_event_lookup(
        args.output_folder,
        fields,
    )
    summary_csv, lineage_summary = write_summary(
        args.output_folder,
        classifier_path,
        results,
        lookup,
    )

    LOGGER.info("Authentication classification complete")
    LOGGER.info("Event lookup: " + lookup["event_lookup_file"])
    LOGGER.info("Event lookup rows: " + str(lookup["event_lookup_rows"]))
    LOGGER.info("Classification summary: " + str(summary_csv))
    LOGGER.info("Lineage summary: " + str(lineage_summary))
    LOGGER.info("Finished in %.1f seconds", time.monotonic() - started)


if __name__ == "__main__":
    try:
        raise SystemExit(runlog.main(main))
    except Exception:
        LOGGER.exception("Authentication classification failed")
        sys.exit(1)
