"""Resumable Stage 3 feature engineering for large OSSEC observation datasets.

Step 3 of the OSSEC anomaly-detection workflow. Port of the resumable
authentication Stage 3 (``pipeline/phase3_features/auth.py``) to the four
OSSEC observation datasets written by ``pipeline/phase2_observations/ossec.py``:

* individual
* host_5min
* episodes
* host_behavior_1d

Usage
-----
Initial execution and automatic continuation use the same command::

    python pipeline/phase3_features/ossec.py --dataset individual --verbose --progress-interval 10

Restart one completed section and its dependent sections::

    python pipeline/phase3_features/ossec.py --dataset individual --resume-from stats

``--resume-from`` accepts index, split, stats, shards, merge_train,
merge_validation, merge_test, lineage or metadata. It requires matching completed
prerequisites; omit it for automatic recovery. ``--force`` rebuilds the selected
datasets from indexing. Neither option affects unselected datasets. Console output
follows pipeline/STYLE_GUIDE.md: ``--verbose``, ``--quiet`` and ``--progress-interval``
(``--debug`` and ``--progress-seconds`` are accepted as old names).

Small test runs
---------------
Exercise feature engineering on the first 1,000 individual event rows::

    python pipeline/phase3_features/ossec.py --dataset individual --max-rows 1000

``--max-rows N`` selects the first N CSV data rows in file order, before timestamp
validation and chronological splitting. It applies independently to each selected
dataset. For aggregate datasets, N counts observations (episodes/windows/days),
not their contributing raw events. Invalid timestamps count toward N and are
then skipped. At least three valid rows and nonempty chronological splits are
required; increase N if timestamp ties or purge gaps leave a split empty.

Test artifacts, summaries and checkpoints go under ``OUTPUT/subset_first_N``;
for default paths and N=1000 this is
``data/phase3_features/ossec/subset_first_1000``. Repeating the same command
resumes that test. Omit ``--max-rows`` to return to full-data processing.

Aggregate lineage export reads until the expected memberships of the selected,
unpurged observations are collected, using Stage 2's ``event_count`` (episodes)
or ``total_events`` (windows) columns. If the count column is absent, it scans
the complete lineage file and logs a warning.

Duplicate episode IDs
---------------------
Duplicate ``row_manifest_id`` values stop indexing with example IDs and one-based
CSV data-row numbers. Rebuild episodes and their lineage together, then resume
Stage 3 with the same paths and settings::

    python pipeline/phase2_observations/ossec.py --episodes-only
    python pipeline/phase3_features/ossec.py --dataset episodes

Do not drop or rename duplicate rows independently of their source-event lineage.

Durable checkpoints
-------------------
* index: each CSV chunk and its progress commit together in SQLite;
* split: chronological split assignment and counts;
* stats: training numeric means, scales and feature names;
* shards: all sparse chunks and split row manifests;
* merge_train / merge_validation / merge_test: each final CSR matrix;
* lineage: split lineage exports;
* metadata: final artifact bundle and metadata.

Indexing resumes after the last committed chunk. Other incomplete stages restart
at their beginning; completed stages and individual matrix merges are reused.
SQLite, numeric statistics and shards are retained by default, including after
failures. ``checkpoints.json`` records source paths, byte sizes, nanosecond
modification times, software versions and settings. Changed sources or settings
invalidate the affected dataset's checkpoints. The checks do not hash file
contents and will not detect edits that preserve both size and timestamps.
Only one Stage 3 process may use an output folder at a time (OS file lock).

Feature channels (changes from the in-memory version 01)
--------------------------------------------------------
Feature names are fixed by the input header, never by the data, so every chunk
and every pass produces the same schema:

* ``numeric__<column>`` and ``numeric__<column>__log1p`` for every configured
  numeric Stage 2 column (``NUMERIC_CANDIDATES``). Raw ports, process IDs and
  agent counters are not numeric inputs.
* ``numeric__<count>__ratio``: each ``*_count`` column divided by
  ``total_events`` or ``event_count``.
* ``numeric__severity_is_high`` / ``severity_is_critical`` / ``event_is_unknown``
  (individual) and ``maximum_severity_is_high`` / ``_critical`` (aggregates).
* ``numeric__history_prior_observations`` and ``numeric__<column>__prior_mean``,
  ``__prior_std`` and ``__prior_z`` for aggregates, from running per-entity
  accumulators carried across chunks (``HistoryState``). Only earlier rows of
  the same entity contribute, in file order; Stage 2 writes each entity's
  windows and episodes chronologically. The 7/30/90-day rolling means of
  version 01 need unbounded per-entity windows and are no longer produced.
* ``numeric__time_*``: hour, day of week, weekend and cyclical time of day.
* ``category_hash__NNNN``: hashed ``column=value`` tokens of the categorical
  columns Stage 4 already admitted for the dataset (``CATEGORICAL_CANDIDATES``)
  plus derived IP zone/version/subnet and port-range categories.
* ``text_hash__NNNN`` (individual): hashed character 3-5-grams of the
  normalized raw message.
* ``sequence_hash__NNNN`` (aggregates): hashed word 1-3-grams of the event-type,
  severity and username sequences.

Numeric features are imputed with the training mean and divided by the
training standard deviation without centering, so zero counts stay exactly
zero. This keeps matrices sparse and preserves Stage 4's robust-eligibility
rule, which relies on the share of zero values.

Lineage contract
----------------
The upstream ``row_manifest_id`` is never regenerated. For every chronological
split, the script writes the matching long-format lineage rows:

    feature matrix row
    -> row_manifest_id
    -> event_id
    -> data/phase1_classify/ossec/ossec_event_lookup.csv
    -> original_log_line / source coordinates

The exporter routes links by observation ID and records the lookup path; it
does not re-validate event-ID coverage (Stage 4 validates alert evidence).

Outputs
-------
data/phase3_features/ossec/<dataset>/
    X_train.npz, X_validation.npz, X_test.npz
    train_rows.csv, validation_rows.csv, test_rows.csv
    train_lineage.csv, validation_lineage.csv, test_lineage.csv
    feature_names.csv, feature_policy_inputs.csv
    numeric_statistics.npz, preprocessing_bundle.joblib, metadata.json
    continuity_by_day.csv, checkpoints.json

Global outputs
--------------
data/phase3_features/ossec/feature_engineering_summary.json
data/phase3_features/ossec/lineage_summary.csv
data/phase3_features/ossec/continuity_summary.csv

No anomaly threshold is selected here. Model fitting and human-review queues
belong in Step 4. Requires pandas 2.0+ with ``Series.dt.as_unit``, NumPy,
SciPy, scikit-learn and joblib.
"""
from __future__ import annotations

import argparse
import sys
import csv
import gc
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import sqlite3
import time
import threading
from contextlib import contextmanager
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import scipy
import sklearn
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer

INPUT_FOLDER = Path("data/phase2_observations/ossec")
OUTPUT_FOLDER = Path("data/phase3_features/ossec")
EVENT_LOOKUP_FILE = Path("data/phase1_classify/ossec/ossec_event_lookup.csv")
SCRATCH_FOLDER = OUTPUT_FOLDER / "_scratch"
DATABASE_FILE = SCRATCH_FOLDER / "ossec_stage3_index.sqlite"
FEATURE_ENGINEER_VERSION = "2026-10-28-ossec-resumable-lineage-03"
# 03 (2026-10-28): no identity as a feature: host and agent names are not categories, usernames not sequence words
# (a model that learns names overfits to particular entities; see the auth Stage 3).
FEATURE_ARTIFACT_CONTRACT = "ossec_explainable_lineage"
# Identity tag written into, and checked against, earlier phases' metadata. It is the
# producer's historical file name, not a path: keep it unless all phases are rerun.
EXPECTED_OBSERVATION_BUILDER = "osseclogs_stage2_build_datasets.py"
LINEAGE_KEY = "event_id"

DATASETS = {
    "individual": "ossec_events_all_months.csv",
    "host_5min": "ossec_host_windows_5min.csv",
    "episodes": "ossec_security_episodes.csv",
    "host_behavior_1d": "ossec_host_behavior_1d.csv",
}
PURGE_GAP_SECONDS = {
    "individual": 0,
    "host_5min": 300,
    "episodes": 15 * 60,
    "host_behavior_1d": 86400,
}
CHANNELS = {
    "individual": {"text": True, "sequence": False, "history": False},
    "host_5min": {"text": False, "sequence": True, "history": True},
    "episodes": {"text": False, "sequence": True, "history": True},
    "host_behavior_1d": {"text": False, "sequence": True, "history": True},
}
# Stage 2 membership-count column for each aggregate dataset.
MEMBERSHIP_COUNT_COLUMN = {"episodes": "event_count"}
DEFAULT_MEMBERSHIP_COUNT_COLUMN = "total_events"
TIME_COLUMNS = ("timestamp", "window_start", "episode_start", "first_timestamp")
TRAIN_FRACTION = 0.70
VALIDATION_FRACTION = 0.15
DEFAULT_CHUNK_ROWS = 50_000
DEFAULT_CATEGORY_HASH_FEATURES = 256
DEFAULT_TEXT_HASH_FEATURES = 512
DEFAULT_SEQUENCE_HASH_FEATURES = 256
TEXT_NGRAM_RANGE = (3, 5)
SEQUENCE_NGRAM_RANGE = (1, 3)
PRIOR_Z_CAP = 1e4
PROGRESS_SECONDS = 15.0

NUMERIC_CANDIDATES = (
    # Individual events
    "severity_rank", "event_threshold", "previous_event_count",
    "current_event_count", "retained_percentage", "allowlist_count",
    "rules_enabled_count",
    # Aggregates
    "total_events", "event_count", "events_per_minute", "events_per_hour",
    "active_hours", "active_span_seconds", "duration_seconds",
    "mean_inter_event_seconds", "minimum_inter_event_seconds",
    "maximum_inter_event_seconds", "episode_completed", "severity_rank_sum",
    "mean_severity_rank", "maximum_severity_rank", "severity_increase",
    "high_severity_count", "debug_count", "info_count", "notice_count",
    "warning_count", "error_count", "critical_count", "alert_count",
    "emergency_count", "unknown_severity_count", "unknown_event_count",
    "authentication_count", "rootcheck_count", "syscheck_count",
    "connection_count", "agent_count", "server_count", "queue_count",
    "rules_count", "file_count", "active_response_count",
    "other_category_count", "agent_stop_count", "agent_start_count",
    "communication_failure_count", "integrity_gap_count",
    "configuration_gap_count", "unique_event_types", "unique_processes",
    "unique_categories", "unique_users", "unique_source_ips",
    "unique_destination_ips", "unique_agents", "unique_monitored_paths",
    "unique_files", "unique_reasons", "new_event_types", "new_processes",
    "new_users", "new_source_ips", "new_destination_ips", "new_agents",
    "new_files", "event_type_entropy", "process_entropy", "severity_entropy",
    "source_ip_entropy", "dominant_event_type_count", "dominant_process_count",
    "dominant_severity_count",
)
RATIO_DENOMINATORS = ("total_events", "event_count")
# (feature name, source column, minimum severity rank or None for the unknown-event flag)
FLAG_FEATURES = {
    "individual": (
        ("severity_is_high", "severity_rank", 5),
        ("severity_is_critical", "severity_rank", 7),
        ("event_is_unknown", "event_type", None),
    ),
    "aggregate": (
        ("maximum_severity_is_high", "maximum_severity_rank", 5),
        ("maximum_severity_is_critical", "maximum_severity_rank", 7),
    ),
}
UNKNOWN_EVENT_TYPE = "OSSEC_UNKNOWN_EVENT"
HISTORICAL_COLUMNS = (
    "total_events", "event_count", "events_per_minute", "events_per_hour",
    "active_span_seconds", "duration_seconds", "mean_inter_event_seconds",
    "maximum_inter_event_seconds", "severity_rank", "severity_rank_sum",
    "mean_severity_rank", "maximum_severity_rank", "severity_increase",
    "high_severity_count", "unknown_event_count", "unique_event_types",
    "unique_processes", "unique_users", "unique_source_ips",
    "unique_destination_ips", "unique_agents", "unique_files",
    "unique_reasons", "new_event_types", "new_processes", "new_users",
    "new_source_ips", "new_destination_ips", "new_agents", "new_files",
)
HOST_COLUMNS = ("host_id", "hostname", "agent_name", "source_ip")
# ("first", candidates) groups by the first available column; ("all", candidates) by every available one.
HISTORY_GROUPS = {
    "host_5min": ("first", HOST_COLUMNS),
    "host_behavior_1d": ("first", HOST_COLUMNS),
    "episodes": ("all", ("host_id", "process_name", "event_category", "source_ip")),
}
DERIVED_IP_CATEGORIES = ("zone", "version", "subnet")
DERIVED_PORT_CATEGORIES = ("range",)
CATEGORICAL_CANDIDATES = {
    "individual": (
        "severity", "event_type", "event_category", "process_name",
        "authentication_method", "connection_stage", "scan_mode",
        "operation", "source_ip__zone", "source_ip__version", "source_ip__subnet",
        "destination_ip__zone", "destination_ip__version", "destination_ip__subnet",
        "allowlisted_ip__zone", "allowlisted_ip__version", "allowlisted_ip__subnet",
        "source_port__range", "destination_port__range",
    ),
    "host_5min": (
        "dominant_event_type", "dominant_process", "dominant_severity",
        "host_identity_type",
    ),
    "episodes": (
        "process_name", "event_category", "host_identity_type",
        "source_ip__zone", "source_ip__version", "source_ip__subnet",
    ),
    "host_behavior_1d": (
        "dominant_event_type", "dominant_process", "dominant_severity",
        "host_identity_type",
    ),
}
SEQUENCE_SOURCES = ("event_type_sequence", "severity_sequence")
MANIFEST_CANDIDATES = (
    "row_manifest_id", "event_id", "episode_id", "timestamp", "window_start",
    "episode_start", "first_timestamp", "host_id", "host_identity_type",
    "hostname", "agent_name", "process_name", "event_category", "source_ip",
    "destination_ip", "username", "event_type", "severity", "severity_rank",
    "dominant_event_type", "first_event_type", "episode_family",
    "episode_key_type", "close_reason",
)
LINEAGE_REQUIRED = {
    "dataset", "row_manifest_id", LINEAGE_KEY, "event_position",
    "event_timestamp", "relationship_role",
}
DUPLICATE_GUIDANCE = {
    "episodes": (" Rebuild episodes AND their lineage with "
                 "'python pipeline/phase2_observations/ossec.py --episodes-only', then rerun Stage 3."),
}


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


CHECKPOINT_STAGES = (
    "index", "split", "stats", "shards", "merge_train", "merge_validation",
    "merge_test", "lineage", "metadata",
)
CHECKPOINT_DEPENDENCIES = {
    "index": (), "split": ("index",), "stats": ("split",),
    "shards": ("stats",), "merge_train": ("shards",),
    "merge_validation": ("shards",), "merge_test": ("shards",),
    "lineage": ("shards", "split"),
    "metadata": ("merge_train", "merge_validation", "merge_test", "lineage"),
}


def file_signature(path):
    """Describe a file without rereading its potentially enormous contents.

    :param path: File to describe.
    :returns: Resolved path, byte size and nanosecond modification time, or None.
    :rtype: dict or None
    """
    path = Path(path)
    if not path.is_file():
        return None
    stat = path.stat()
    return {"path": str(path.resolve()), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def read_json(path, default=None):
    """Read JSON or return a default for a missing/unreadable checkpoint.

    :param path: JSON file path.
    :param default: Value returned on file or parsing errors.
    :returns: Decoded value or default.
    :rtype: object
    """
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def run_identity(dataset, path, args):
    """Capture inputs and feature-affecting settings for checkpoint reuse.

    :param dataset: Dataset key.
    :param path: Observation CSV path.
    :param args: CLI settings.
    :returns: JSON-compatible identity dictionary.
    :rtype: dict
    """
    lineage = path.with_name(path.stem + "_lineage.csv")
    identity = {
        "version": FEATURE_ENGINEER_VERSION, "dataset": dataset,
        "input": file_signature(path),
        "lineage": file_signature(lineage) if dataset != "individual" else None,
        "chunk_rows": args.chunk_rows,
        "category_hash_features": args.category_hash_features,
        "text_hash_features": args.text_hash_features,
        "sequence_hash_features": args.sequence_hash_features,
        "disable_individual_text": args.disable_individual_text,
        "train_fraction": TRAIN_FRACTION, "validation_fraction": VALIDATION_FRACTION,
        "purge_seconds": PURGE_GAP_SECONDS[dataset],
        "channels": CHANNELS[dataset],
        "numeric_candidates": list(NUMERIC_CANDIDATES),
        "categorical_candidates": list(CATEGORICAL_CANDIDATES[dataset]),
        "historical_columns": list(HISTORICAL_COLUMNS),
        "pandas": pd.__version__, "numpy": np.__version__,
        "scipy": scipy.__version__, "sklearn": sklearn.__version__,
    }
    if getattr(args, "max_rows", None) is not None:
        identity["subset"] = {"max_rows": args.max_rows, "selection": "first_csv_rows_v1"}
    return identity


def read_index_state(connection, dataset):
    """Read transactional indexing and split progress stored in SQLite.

    :param connection: Open observation store.
    :param dataset: Dataset key.
    :returns: Stored state or an empty dictionary.
    :rtype: dict
    """
    row = connection.execute("SELECT payload FROM dataset_checkpoints WHERE dataset=?", (dataset,)).fetchone()
    return json.loads(row[0]) if row else {}


def write_index_state(connection, dataset, state):
    """Write progress within the caller's current SQLite transaction.

    :param connection: Open observation store.
    :param dataset: Dataset key.
    :param state: JSON-compatible progress state.
    :rtype: None
    """
    connection.execute(
        "INSERT OR REPLACE INTO dataset_checkpoints(dataset,payload) VALUES (?,?)",
        (dataset, json.dumps(state, allow_nan=False)),
    )


class Checkpoints:
    """Persist stage completion only after its output artifacts are committed."""

    def __init__(self, path, identity, connection, dataset, log):
        """Load matching stage state or initialize a new checkpoint manifest.

        :param path: Dataset checkpoint JSON path.
        :param identity: Expected inputs and settings.
        :param connection: Open SQLite store.
        :param dataset: Dataset key.
        :param log: Progress logger.
        """
        self.path, self.identity = path, identity
        self.connection, self.dataset, self.log = connection, dataset, log
        self.signature = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        loaded = read_json(path, {})
        if not isinstance(loaded, dict) or not isinstance(loaded.get("stages"), dict):
            loaded = {}
        self.state = loaded if isinstance(loaded, dict) and loaded.get("identity") == identity else {
            "identity": identity, "stages": {},
        }
        if loaded and loaded.get("identity") != identity:
            log.write(f"{dataset}: inputs/settings changed; prior checkpoints will not be reused", "CHECKPOINT")
        self.save()

    def save(self):
        """Atomically persist the current completion manifest.

        :rtype: None
        """
        write_json(self.path, self.state)

    def valid(self, stage):
        """Check a stage marker and its recorded artifacts or SQLite state.

        :param stage: Checkpoint stage name.
        :returns: True if completed artifacts still match their metadata.
        :rtype: bool
        """
        entry = self.state["stages"].get(stage)
        if (not isinstance(entry, dict) or "result" not in entry
                or not isinstance(entry.get("artifacts"), list)):
            return False
        if stage in ("index", "split"):
            state = read_index_state(self.connection, self.dataset)
            if state.get("signature") != self.signature or not state.get("complete"):
                return False
            if stage == "split" and not state.get("split"):
                return False
        return all(file_signature(item["path"]) == item for item in entry.get("artifacts", []))

    def result(self, stage):
        """Retrieve the saved JSON-compatible stage result.

        :param stage: Completed stage name.
        :returns: Saved result.
        :rtype: object
        """
        return self.state["stages"][stage]["result"]

    def mark(self, stage, result, artifacts=()):
        """Record successful completion after validating output files exist.

        :param stage: Completed stage name.
        :param result: Small JSON-compatible stage result.
        :param artifacts: Paths of all artifacts required to reuse this stage.
        :rtype: None
        """
        for key in ("input", "lineage"):
            previous = self.identity.get(key)
            if previous and file_signature(previous["path"]) != previous:
                raise RuntimeError("Source changed during processing; rerun after input writes finish")
        signatures = [file_signature(path) for path in artifacts]
        if any(item is None for item in signatures):
            raise FileNotFoundError("Cannot checkpoint missing artifacts for " + stage)
        self.state["stages"][stage] = {
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "result": result, "artifacts": signatures,
        }
        self.save()
        self.log.write(f"{self.dataset}: saved checkpoint {stage}", "CHECKPOINT")

    def invalidate(self, stage):
        """Invalidate a stage and all dependent completion markers.

        :param stage: Earliest stage to redo.
        :returns: Names of invalidated stages.
        :rtype: set
        """
        affected = {stage}
        for name in CHECKPOINT_STAGES:
            if any(dep in affected for dep in CHECKPOINT_DEPENDENCIES[name]):
                affected.add(name)
        for name in affected:
            self.state["stages"].pop(name, None)
        self.save()
        return affected


@contextmanager
def output_lock(folder):
    """Hold a non-blocking OS lock against overlapping runs in one output folder.

    :param folder: Output root shared by artifacts and scratch files.
    :yields: Control after acquiring the lock.
    :raises RuntimeError: If another process holds this output lock.
    """
    folder.mkdir(parents=True, exist_ok=True)
    handle = open(folder / ".stage3.lock", "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0"); handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise RuntimeError("Another Stage 3 run is using this output folder") from error
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise RuntimeError("Another Stage 3 run is using this output folder") from error
        yield
    finally:
        handle.close()


def duplicate_id_details(connection, dataset, ids, source_positions):
    """Describe duplicate IDs after the failed insertion has rolled back.

    :param connection: SQLite connection containing only committed chunks.
    :param dataset: Dataset key whose index failed.
    :param ids: Valid observation IDs from the failed chunk.
    :param source_positions: One-based CSV data-row numbers, excluding header.
    :returns: Up to five conflicting IDs, current rows and conflict locations.
    :rtype: str
    """
    counts = Counter(str(value) for value in ids)
    conflicts = {value: "within current chunk" for value, count in counts.items() if count > 1}
    unique_ids = list(counts)
    for start in range(0, len(unique_ids), 900):
        if len(conflicts) >= 5:
            break
        batch = unique_ids[start:start + 900]
        placeholders = ",".join("?" for _ in batch)
        for (value,) in connection.execute(
            f"SELECT row_manifest_id FROM observations WHERE dataset=? AND row_manifest_id IN ({placeholders})",
            [dataset, *batch],
        ):
            conflicts[value] = "also in an earlier committed chunk"
    examples = dict(list(conflicts.items())[:5])
    positions = {value: [] for value in examples}
    for value, position in zip(ids, source_positions):
        value = str(value)
        if value in positions and len(positions[value]) < 5:
            positions[value].append(int(position))
    return "; ".join(f"{value!r}: CSV data rows {positions[value]} ({location})"
                     for value, location in examples.items()) or "no duplicate located; inspect SQLite constraint error"


def index_observations(dataset, path, connection, chunk_rows, log, signature, max_rows=None):
    """Index CSV chunks with progress committed in the same transaction as rows.

    :param dataset: Dataset key.
    :param path: Observation CSV path.
    :param connection: Open SQLite store.
    :param chunk_rows: Configured CSV chunk size.
    :param log: Progress logger.
    :param signature: Matching input/configuration signature.
    :param max_rows: Maximum source CSV data rows; None processes all rows.
    :returns: Durable index progress with completion status.
    :rtype: dict
    :raises ValueError: If identities are blank/duplicated or too few rows are valid.
    """
    state = read_index_state(connection, dataset)
    if state.get("signature") != signature:
        state = {"signature": signature, "chunks": 0, "source_rows": 0,
                 "rows": 0, "invalid_timestamps": 0, "last_epoch": None,
                 "input_timestamp_sorted": True, "complete": False}
        with log.phase(f"{dataset}: initialize index checkpoint", connection):
            with connection:
                connection.execute("DELETE FROM observations WHERE dataset=?", (dataset,))
                write_index_state(connection, dataset, state)
    if state.get("complete"):
        log.write(f"{dataset}: reuse completed SQLite index ({state['rows']:,} observations)", "RESUME")
        return state
    skipped_chunks = state["chunks"]
    if skipped_chunks:
        log.write(f"{dataset}: resume after {skipped_chunks:,} committed chunks "
                  f"({state['source_rows']:,} source rows); scanning past them", "RESUME")
    sql = "INSERT INTO observations(dataset,row_manifest_id,epoch) VALUES (?,?,?)"
    for number, frame in enumerate(pd.read_csv(path, chunksize=chunk_rows, nrows=max_rows, low_memory=False), 1):
        if number <= skipped_chunks:
            log.progress(f"{dataset}: scanning past committed chunk {number:,}/{skipped_chunks:,}")
            continue
        if "row_manifest_id" not in frame:
            raise ValueError(str(path) + " lacks row_manifest_id")
        ids = frame["row_manifest_id"].fillna("").astype(str).str.strip()
        if ids.eq("").any():
            raise ValueError(dataset + " contains blank row_manifest_id")
        _, timestamps = parse_time(frame)
        epochs = epoch_seconds(timestamps)
        valid = np.isfinite(epochs)
        valid_ids, valid_epochs = ids.to_numpy()[valid], epochs[valid]
        next_state = dict(state)
        if valid_epochs.size:
            previous = state["last_epoch"]
            if (previous is not None and valid_epochs[0] < previous) or np.any(np.diff(valid_epochs) < 0):
                next_state["input_timestamp_sorted"] = False
            next_state["last_epoch"] = float(valid_epochs[-1])
        next_state.update(chunks=number, source_rows=state["source_rows"] + len(frame),
                          rows=state["rows"] + len(valid_ids),
                          invalid_timestamps=state["invalid_timestamps"] + int((~valid).sum()))
        try:
            with connection:
                connection.executemany(sql, ((dataset, str(i), float(e)) for i, e in zip(valid_ids, valid_epochs)))
                write_index_state(connection, dataset, next_state)
        except sqlite3.IntegrityError as error:
            details = duplicate_id_details(
                connection, dataset, valid_ids,
                state["source_rows"] + np.flatnonzero(valid) + 1,
            )
            guidance = DUPLICATE_GUIDANCE.get(
                dataset, " Repair the source dataset and its lineage together before rerunning.")
            raise ValueError(
                f"{dataset} contains duplicate row_manifest_id in {path}; "
                f"chunk {number}: {details}. Failed chunk rolled back; "
                f"{state['chunks']} earlier chunks preserved." + guidance
            ) from error
        state = next_state
        log.progress(f"{dataset} pass 1: indexed {state['rows']:,} observations; "
                     f"invalid timestamps={state['invalid_timestamps']:,}; committed chunk={number:,}")
    if state["rows"] < 3:
        raise ValueError(dataset + " has fewer than three valid observations")
    state["complete"] = True
    with connection:
        write_index_state(connection, dataset, state)
    return state


def parse_args():
    """Parse and validate CLI paths, dataset selection and resource settings.

    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description="Memory-safe, resumable OSSEC Stage 3 feature engineering."
    )
    parser.add_argument("--input", type=Path, default=INPUT_FOLDER)
    parser.add_argument("--output", type=Path, default=OUTPUT_FOLDER)
    parser.add_argument("--event-lookup", type=Path, default=EVENT_LOOKUP_FILE,
                        help="Recorded as lineage provenance for Stage 4 and 5.")
    parser.add_argument("--chunk-rows", type=int, default=DEFAULT_CHUNK_ROWS)
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Test the first N CSV rows per dataset; outputs go to OUTPUT/subset_first_N.")
    parser.add_argument("--dataset", action="append", default=[], choices=list(DATASETS))
    parser.add_argument("--category-hash-features", type=int, default=DEFAULT_CATEGORY_HASH_FEATURES)
    parser.add_argument("--text-hash-features", type=int, default=DEFAULT_TEXT_HASH_FEATURES)
    parser.add_argument("--sequence-hash-features", type=int, default=DEFAULT_SEQUENCE_HASH_FEATURES)
    parser.add_argument("--disable-individual-text", action="store_true")
    parser.add_argument("--resume-from", choices=CHECKPOINT_STAGES,
                        help="Re-run this stage and its dependents; requires valid preceding checkpoints.")
    parser.add_argument("--force", action="store_true")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    for option in ("chunk_rows", "category_hash_features", "text_hash_features", "sequence_hash_features"):
        if getattr(args, option) <= 0:
            parser.error("--" + option.replace("_", "-") + " must be positive")
    if args.max_rows is not None:
        if args.max_rows < 3:
            parser.error("--max-rows must be at least 3 for train/validation/test splitting")
        args.output = args.output / f"subset_first_{args.max_rows}"
    if args.force and args.resume_from:
        parser.error("--force and --resume-from cannot be combined")
    return args


def write_json(path, payload):
    """Write JSON through a temporary sibling file and atomic replacement.

    :param path: Input or output filesystem path.
    :param payload: JSON payload to serialize.
    :rtype: None
    """
    def convert(value):
        """Recursively convert paths and NumPy scalars to JSON-compatible values.

        :param value: Value to make JSON-compatible.
        :returns: Converted value; non-finite floats become None.
        :rtype: object
        """
        if isinstance(value, dict):
            return {str(key): convert(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [convert(item) for item in value]
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, (np.floating, float)):
            value = float(value)
            return value if math.isfinite(value) else None
        if isinstance(value, np.bool_):
            return bool(value)
        return value

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(convert(payload), indent=2, allow_nan=False),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def parse_time(frame):
    """Select the first timestamp column with any parseable value in this chunk.

    :param frame: Current chunk of observation rows.
    :returns: Column name and UTC timestamp Series; invalid values remain NaT.
    :rtype: tuple
    :raises ValueError: If no timestamp column exists.
    """
    for column in TIME_COLUMNS:
        if column in frame.columns:
            values = pd.to_datetime(frame[column], errors="coerce", utc=True)
            if values.notna().any():
                return column, values
    raise ValueError("No usable timestamp column in observation chunk")


def epoch_seconds(values):
    """Convert datetime values of any supported resolution to epoch seconds.

    :param values: Pandas datetime Series, including microsecond or nanosecond resolution.
    :returns: Epoch seconds, with NaN for missing timestamps.
    :rtype: numpy.ndarray
    """
    nanoseconds = values.dt.as_unit("ns")
    result = nanoseconds.astype("int64").to_numpy(dtype=np.float64) / 1e9
    result[values.isna().to_numpy()] = np.nan
    return result


# =============================================================================
# Feature plan and row-local features
# =============================================================================

def derived_source(name):
    """Return the Stage 2 column a derived ``column__property`` category comes from.

    :param name: Candidate categorical column.
    :returns: Source column for derived names, otherwise None.
    :rtype: str or None
    """
    if "__" not in name:
        return None
    source, prop = name.split("__", 1)
    return source if prop in DERIVED_IP_CATEGORIES + DERIVED_PORT_CATEGORIES else None


def feature_plan(dataset, header):
    """Fix every numeric and categorical input from the header alone.

    :param dataset: Dataset key.
    :param header: Observation CSV column names.
    :returns: Numeric, ratio, flag, history and categorical column selections.
    :rtype: dict
    """
    available = set(header)
    channels = CHANNELS[dataset]
    numeric = [column for column in NUMERIC_CANDIDATES if column in available]
    denominator = next((column for column in RATIO_DENOMINATORS if column in available), None)
    ratio = [column for column in numeric
             if denominator and column.endswith("_count") and column != denominator]
    kind = "individual" if dataset == "individual" else "aggregate"
    flags = [flag for flag in FLAG_FEATURES[kind] if flag[1] in available]
    group = []
    if channels["history"] and dataset in HISTORY_GROUPS:
        mode, candidates = HISTORY_GROUPS[dataset]
        present = [column for column in candidates if column in available]
        group = present[:1] if mode == "first" else present
    history = [column for column in HISTORICAL_COLUMNS if column in available] if group else []
    categorical = [column for column in CATEGORICAL_CANDIDATES[dataset]
                   if column in available or derived_source(column) in available]
    return {
        "numeric": numeric, "ratio_denominator": denominator, "ratio": ratio,
        "flags": [list(flag) for flag in flags], "history_group": group,
        "history": history, "categorical": categorical,
        "text": channels["text"], "sequence": channels["sequence"],
    }


def numeric_feature_names(plan):
    """List numeric feature names in the exact order numeric_block builds them.

    :param plan: Feature plan from feature_plan.
    :returns: Ordered numeric feature names (without the ``numeric__`` prefix).
    :rtype: list
    """
    names = []
    for column in plan["numeric"]:
        names += [column, column + "__log1p"]
    names += [column + "__ratio" for column in plan["ratio"]]
    names += [flag[0] for flag in plan["flags"]]
    if plan["history_group"]:
        names.append("history_prior_observations")
        for column in plan["history"]:
            names += [column + "__prior_mean", column + "__prior_std", column + "__prior_z"]
    names += ["time_hour", "time_day_of_week", "time_is_weekend", "time_sin_day", "time_cos_day"]
    return names


class HistoryState:
    """Running per-entity count, sum and sum of squares carried across chunks.

    Every row sees only earlier rows of the same entity, so the features equal
    version 01's grouped cumulative statistics when entity rows are in file
    order. Memory grows with the number of entities, not rows.
    """

    def __init__(self, columns):
        """Start empty accumulators.

        :param columns: Numeric columns whose prior statistics are tracked.
        :rtype: None
        """
        self.width = len(columns)
        self.index = {}
        self.count = np.zeros(1024)
        self.sums = np.zeros((1024, self.width))
        self.squares = np.zeros((1024, self.width))

    def _grow(self, size):
        """Enlarge accumulator arrays to hold at least ``size`` entities.

        :param size: Required entity capacity.
        :rtype: None
        """
        if size <= len(self.count):
            return
        capacity = max(size, 2 * len(self.count))
        self.count = np.concatenate([self.count, np.zeros(capacity - len(self.count))])
        extra = np.zeros((capacity - len(self.sums), self.width))
        self.sums = np.vstack([self.sums, extra])
        self.squares = np.vstack([self.squares, extra.copy()])

    def update(self, keys, values):
        """Return prior statistics for each row, then add the chunk to the state.

        :param keys: Entity key per row.
        :param values: Row-by-column float matrix with missing values set to 0.
        :returns: Prior count, prior mean, prior std and prior z-score.
        :rtype: tuple
        """
        codes, uniques = pd.factorize(pd.Series(keys, dtype=object), sort=False)
        global_index = np.fromiter((self.index.setdefault(key, len(self.index)) for key in uniques),
                                   dtype=np.int64, count=len(uniques))
        self._grow(len(self.index))
        rows = global_index[codes]
        within = pd.Series(codes).groupby(codes).cumcount().to_numpy(dtype=float)
        prior_count = self.count[rows] + within
        if self.width:
            frame = pd.DataFrame(values)
            prior_sum = self.sums[rows] + frame.groupby(codes).cumsum().to_numpy() - values
            squared = values * values
            prior_squares = (self.squares[rows] + pd.DataFrame(squared).groupby(codes).cumsum().to_numpy()
                             - squared)
            with np.errstate(divide="ignore", invalid="ignore"):
                denominator = np.where(prior_count > 0, prior_count, np.nan)[:, None]
                mean = prior_sum / denominator
                std = np.sqrt(np.clip(prior_squares / denominator - mean * mean, 0, None))
                z = np.where(std > 0, (values - mean) / std, np.nan)
            z = np.clip(z, -PRIOR_Z_CAP, PRIOR_Z_CAP)
            self.sums[global_index] += frame.groupby(codes).sum().to_numpy()
            self.squares[global_index] += pd.DataFrame(squared).groupby(codes).sum().to_numpy()
        else:
            mean = std = z = np.zeros((len(keys), 0))
        self.count[global_index] += np.bincount(codes, minlength=len(uniques))
        return prior_count, mean, std, z


def entity_keys(frame, columns):
    """Join entity columns into one string key per row.

    :param frame: Current chunk of observation rows.
    :param columns: Grouping columns.
    :returns: Key per row.
    :rtype: numpy.ndarray
    """
    keys = frame[columns[0]].fillna("").astype(str)
    for column in columns[1:]:
        keys = keys + "|" + frame[column].fillna("").astype(str)
    return keys.to_numpy()


def numeric_block(frame, timestamps, plan, history, means=None, scales=None):
    """Build the numeric feature block for one chunk.

    :param frame: Current chunk of observation rows.
    :param timestamps: Parsed UTC timestamps aligned with frame.
    :param plan: Feature plan from feature_plan.
    :param history: HistoryState updated in place, or None when disabled.
    :param means: Optional training means used to impute missing values.
    :param scales: Training scales; required with means.
    :returns: Float32 matrix and ordered feature names.
    :rtype: tuple
    """
    arrays, names = [], []
    base = {}
    for column in plan["numeric"]:
        values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=float)
        base[column] = values
        arrays += [values, np.log1p(np.clip(np.nan_to_num(values, nan=0.0), 0.0, None))]
        names += [column, column + "__log1p"]
    if plan["ratio"]:
        denominator = np.nan_to_num(base[plan["ratio_denominator"]], nan=0.0)
        for column in plan["ratio"]:
            numerator = np.nan_to_num(base[column], nan=0.0)
            with np.errstate(divide="ignore", invalid="ignore"):
                arrays.append(np.where(denominator != 0, numerator / denominator, 0.0))
            names.append(column + "__ratio")
    for name, source, minimum in plan["flags"]:
        if minimum is None:
            flag = frame[source].fillna("").astype(str).str.strip().str.upper().eq(UNKNOWN_EVENT_TYPE)
            arrays.append(flag.to_numpy(dtype=float))
        else:
            rank = np.nan_to_num(pd.to_numeric(frame[source], errors="coerce").to_numpy(dtype=float), nan=0.0)
            arrays.append((rank >= minimum).astype(float))
        names.append(name)
    if plan["history_group"]:
        values = (np.column_stack([
            np.nan_to_num(pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=float), nan=0.0)
            for column in plan["history"]]) if plan["history"] else np.zeros((len(frame), 0)))
        prior_count, mean, std, z = history.update(entity_keys(frame, plan["history_group"]), values)
        arrays.append(prior_count)
        names.append("history_prior_observations")
        for index, column in enumerate(plan["history"]):
            arrays += [mean[:, index], std[:, index], z[:, index]]
            names += [column + "__prior_mean", column + "__prior_std", column + "__prior_z"]
    seconds = timestamps.dt.hour * 3600 + timestamps.dt.minute * 60 + timestamps.dt.second
    arrays += [
        timestamps.dt.hour.to_numpy(dtype=float),
        timestamps.dt.dayofweek.to_numpy(dtype=float),
        (timestamps.dt.dayofweek >= 5).to_numpy(dtype=float),
        np.sin(2 * np.pi * seconds.to_numpy(dtype=float) / 86400),
        np.cos(2 * np.pi * seconds.to_numpy(dtype=float) / 86400),
    ]
    names += ["time_hour", "time_day_of_week", "time_is_weekend", "time_sin_day", "time_cos_day"]
    matrix = np.column_stack(arrays).astype(np.float64)
    if means is not None:
        missing = ~np.isfinite(matrix)
        if missing.any():
            matrix[missing] = np.take(means, np.nonzero(missing)[1])
        matrix = matrix / scales
    return matrix.astype(np.float32), names


def ip_properties(value):
    """Derive address version, zone and /24 or /64 subnet.

    :param value: Candidate IP address text.
    :returns: Version, zone and subnet, with unknown placeholders for invalid input.
    :rtype: tuple
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
        zone = (
            "loopback" if address.is_loopback else
            "multicast" if address.is_multicast else
            "link_local" if address.is_link_local else
            "private" if address.is_private else
            "reserved" if address.is_reserved else
            "public"
        )
        subnet = str(ipaddress.ip_network(
            str(address) + ("/24" if address.version == 4 else "/64"), strict=False))
        return str(address.version), zone, subnet
    except ValueError:
        return "", "unknown", "unknown"


def port_range(value):
    """Classify a port as well-known, registered, ephemeral or unknown.

    :param value: Candidate port value.
    :returns: Port range label.
    :rtype: str
    """
    try:
        port = int(float(str(value)))
    except (TypeError, ValueError):
        return "unknown"
    if not 0 <= port <= 65535:
        return "unknown"
    return "well_known" if port <= 1023 else "registered" if port <= 49151 else "ephemeral"


def add_derived_categories(frame, columns):
    """Add derived IP and port categories requested by the feature plan in place.

    :param frame: Current chunk of observation rows.
    :param columns: Planned categorical columns.
    :rtype: None
    """
    for column in columns:
        source = derived_source(column)
        if source is None or column in frame.columns or source not in frame.columns:
            continue
        prop = column.split("__", 1)[1]
        values = frame[source].fillna("").astype(str)
        unique = values.unique()
        if prop == "range":
            mapping = {value: port_range(value) for value in unique}
        else:
            position = DERIVED_IP_CATEGORIES.index(prop)
            mapping = {value: ip_properties(value)[position] for value in unique}
        frame[column] = values.map(mapping)


def category_documents(frame, columns):
    """Encode categorical columns as normalized column=value tokens.

    :param frame: Current chunk of observation rows.
    :param columns: Ordered categorical columns present in the chunk.
    :returns: One categorical document per row.
    :rtype: pandas.Series
    """
    columns = [column for column in columns if column in frame.columns]
    if not columns:
        return pd.Series([""] * len(frame), index=frame.index)
    documents = []
    values = frame[columns].fillna("").astype(str)
    for row in values.itertuples(index=False, name=None):
        documents.append(" ".join(
            column + "=" + re.sub(r"\s+", "_", value.strip().lower())
            for column, value in zip(columns, row) if value.strip()
        ))
    return pd.Series(documents, index=frame.index)


def normalize_message(value):
    """Replace timestamps, addresses, hex values, numbers and hashes in a message.

    :param value: Raw message text.
    :returns: Lowercase normalized message with stable placeholders.
    :rtype: str
    """
    value = str(value or "").lower()
    value = re.sub(r"\b\d{4}[-/]\d{2}[-/]\d{2}[ t]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", " {timestamp} ", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " {ip} ", value)
    value = re.sub(r"(?<![a-f0-9:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9:]+", " {ip} ", value, flags=re.IGNORECASE)
    value = re.sub(r"\b0x[a-f0-9]+\b", " {hex} ", value)
    value = re.sub(r"\b\d+\b", " {number} ", value)
    value = re.sub(r"[a-f0-9]{32,}", " {hash} ", value)
    return re.sub(r"\s+", " ", value).strip()


def text_documents(frame):
    """Normalize individual raw messages for the character n-gram channel.

    :param frame: Current chunk of individual observation rows.
    :returns: One normalized message per row.
    :rtype: pandas.Series
    """
    source = next((column for column in ("raw_message", "original_log_line") if column in frame.columns), None)
    if source is None:
        return pd.Series([""] * len(frame), index=frame.index)
    return frame[source].fillna("").astype(str).map(normalize_message)


def sequence_documents(frame):
    """Concatenate the event-type, severity and username sequence columns.

    :param frame: Current chunk of aggregate observation rows.
    :returns: One sequence document per row.
    :rtype: pandas.Series
    """
    columns = [column for column in SEQUENCE_SOURCES if column in frame.columns]
    if not columns:
        return pd.Series([""] * len(frame), index=frame.index)
    return frame[columns].fillna("").astype(str).agg(" ".join, axis=1).str.strip()


# =============================================================================
# SQLite index and chronological splits
# =============================================================================

def create_database(path):
    """Open or create the persistent observation index without deleting prior work.

    :param path: Input or output filesystem path.
    :returns: Open SQLite connection with durable indexing checkpoints.
    :rtype: sqlite3.Connection
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=FILE;
        CREATE TABLE IF NOT EXISTS observations (
            dataset TEXT NOT NULL,
            row_manifest_id TEXT NOT NULL,
            epoch REAL NOT NULL,
            data_split TEXT,
            PRIMARY KEY (dataset, row_manifest_id)
        );
        CREATE TABLE IF NOT EXISTS dataset_checkpoints (dataset TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_observations_dataset_epoch
            ON observations(dataset, epoch, row_manifest_id);
    """)
    connection.commit()
    return connection


def assign_splits(dataset, connection, index_state, log):
    """Assign chronological splits after indexing has completed.

    :param dataset: Dataset key.
    :param connection: Open SQLite observation store.
    :param index_state: Durable completed index metadata.
    :param log: Progress logger.
    :returns: Split boundaries, row counts and purge metadata.
    :rtype: dict
    """
    if index_state.get("split"):
        log.write(dataset + ": reusing completed SQLite split assignments", "RESUME")
        return index_state["split"]
    total = index_state["rows"]
    train_offset = min(max(int(total * TRAIN_FRACTION), 1), total - 2)
    validation_offset = min(max(int(total * (TRAIN_FRACTION + VALIDATION_FRACTION)), 2), total - 1)
    log.progress(f"{dataset} pass 1: CSV indexing finished ({total:,} rows); "
                 "starting SQLite split preparation", force=True)
    with log.phase(f"{dataset} pass 1: locating training boundary", connection):
        train_boundary = connection.execute(
            "SELECT epoch FROM observations WHERE dataset=? "
            "ORDER BY epoch,row_manifest_id LIMIT 1 OFFSET ?",
            (dataset, train_offset),
        ).fetchone()[0]
    with log.phase(f"{dataset} pass 1: locating validation boundary", connection):
        validation_boundary = connection.execute(
            "SELECT epoch FROM observations WHERE dataset=? "
            "ORDER BY epoch,row_manifest_id LIMIT 1 OFFSET ?",
            (dataset, validation_offset),
        ).fetchone()[0]
    gap = PURGE_GAP_SECONDS[dataset]
    with log.phase(f"{dataset} pass 1: assigning splits to all observations", connection):
        connection.execute(
            "UPDATE observations SET data_split=CASE "
            "WHEN epoch < ? THEN 'train' "
            "WHEN epoch >= ? AND epoch < ? THEN 'validation' "
            "WHEN epoch >= ? THEN 'test' ELSE 'purged' END WHERE dataset=?",
            (train_boundary - gap, train_boundary + gap, validation_boundary - gap,
             validation_boundary + gap, dataset),
        )
    with log.phase(f"{dataset} pass 1: committing split assignments", connection):
        connection.commit()
    with log.phase(f"{dataset} pass 1: counting split membership", connection):
        counts = dict(connection.execute(
            "SELECT data_split,COUNT(*) FROM observations WHERE dataset=? GROUP BY data_split",
            (dataset,),
        ).fetchall())
    if min(counts.get(name, 0) for name in ("train", "validation", "test")) < 1:
        raise ValueError(dataset + " has an empty chronological split: " + repr(counts)
                         + ". If using --max-rows, increase it to cover a wider time span; "
                         "timestamp ties and purge gaps can empty small splits.")
    log.progress(f"{dataset} pass 1 complete: {total:,} valid rows; splits={counts}", force=True)
    result = {
        "rows": total,
        "invalid_timestamps": index_state["invalid_timestamps"],
        "input_timestamp_sorted": index_state["input_timestamp_sorted"],
        "train_boundary_epoch": train_boundary,
        "validation_boundary_epoch": validation_boundary,
        "purge_gap_seconds": gap,
        "split_rows": counts,
    }
    index_state["split"] = result
    with connection:
        write_index_state(connection, dataset, index_state)
    return result


def lookup_splits(connection, dataset, ids):
    """Look up observation split labels in bounded SQL parameter batches.

    :param connection: Open SQLite observation index.
    :param dataset: Dataset key from DATASETS.
    :param ids: Observation identities to query.
    :returns: Mapping from known observation IDs to split labels.
    :rtype: dict
    """
    unique_ids = list(dict.fromkeys(str(value) for value in ids))
    mapping = {}
    for start in range(0, len(unique_ids), 900):
        batch = unique_ids[start:start + 900]
        placeholders = ",".join("?" for _ in batch)
        query = ("SELECT row_manifest_id,data_split FROM observations "
                 "WHERE dataset=? AND row_manifest_id IN (" + placeholders + ")")
        for row_id, split in connection.execute(query, [dataset, *batch]):
            mapping[row_id] = split
    return mapping


def read_chunks(path, chunk_rows, max_rows):
    """Iterate observation CSV chunks with trimmed row identities.

    :param path: Observation CSV path.
    :param chunk_rows: Maximum CSV rows per chunk.
    :param max_rows: Maximum source CSV data rows; None reads all rows.
    :yields: Chunk and its row identities.
    :rtype: iterator
    """
    for frame in pd.read_csv(path, chunksize=chunk_rows, nrows=max_rows, low_memory=False):
        frame = frame.reset_index(drop=True)
        yield frame, frame["row_manifest_id"].fillna("").astype(str).str.strip()


def fit_numeric_stats(dataset, path, connection, chunk_rows, plan, log, max_rows=None):
    """Accumulate training-only numeric means and population scales across chunks.

    Every chunk is transformed, not only those with training rows, so history
    accumulators see rows in the same order as in the shard pass.

    :param dataset: Dataset key from DATASETS.
    :param path: Observation CSV path.
    :param connection: Open SQLite observation index.
    :param chunk_rows: Maximum CSV rows loaded per chunk.
    :param plan: Feature plan from feature_plan.
    :param log: Configured Log instance.
    :param max_rows: Maximum source CSV data rows; None processes all rows.
    :returns: Means, scales and ordered numeric feature names.
    :rtype: tuple
    """
    names = numeric_feature_names(plan)
    history = HistoryState(plan["history"]) if plan["history_group"] else None
    sum_values = np.zeros(len(names))
    sum_squares = np.zeros(len(names))
    valid_counts = np.zeros(len(names), dtype=np.int64)
    total = scanned = 0
    for frame, ids in read_chunks(path, chunk_rows, max_rows):
        _, timestamps = parse_time(frame)
        matrix, current = numeric_block(frame, timestamps, plan, history)
        if current != names:
            raise ValueError(dataset + " numeric feature order changed between chunks")
        mask = ids.map(lookup_splits(connection, dataset, ids)).eq("train").to_numpy()
        scanned += len(frame)
        if mask.any():
            selected = matrix[mask].astype(np.float64)
            finite = np.isfinite(selected)
            safe = np.where(finite, selected, 0.0)
            sum_values += safe.sum(axis=0)
            sum_squares += (safe * safe).sum(axis=0)
            valid_counts += finite.sum(axis=0)
            total += int(mask.sum())
        log.progress(f"{dataset} pass 2: scanned {scanned:,} rows; fitted numeric statistics from {total:,} training rows")
        del frame, matrix
        gc.collect()
    means = np.divide(sum_values, np.maximum(valid_counts, 1))
    variances = np.divide(sum_squares, np.maximum(valid_counts, 1)) - means ** 2
    scales = np.sqrt(np.maximum(variances, 1e-12))
    scales[scales < 1e-6] = 1.0
    log.progress(f"{dataset} pass 2 complete: {total:,} training rows", force=True)
    return means, scales, names


# =============================================================================
# Sparse shards, manifests and continuity
# =============================================================================

def save_shard(folder, split, number_value, matrix):
    """Write one uncompressed CSR shard for a split.

    :param folder: Destination directory.
    :param split: Train, validation or test label.
    :param number_value: One-based shard number.
    :param matrix: Feature matrix to save.
    :returns: Saved shard path.
    :rtype: pathlib.Path
    """
    target = folder / split / f"part_{number_value:07d}.npz"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".npz.tmp")
    with open(temporary, "wb") as handle:
        sparse.save_npz(handle, matrix.tocsr(), compressed=False)
    os.replace(temporary, target)
    return target


def open_manifest_writers(folder, columns):
    """Open temporary row manifests for train, validation and test.

    :param folder: Destination directory.
    :param columns: Ordered manifest column names.
    :returns: Mapping from split to temporary path, handle and CSV writer.
    :rtype: dict
    """
    resources = {}
    for split in ("train", "validation", "test"):
        path = folder / (split + "_rows.csv.tmp")
        handle = open(path, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        resources[split] = (path, handle, writer)
    return resources


def close_manifest_writers(resources, folder):
    """Close temporary manifests and replace each final destination.

    :param resources: Manifest paths, handles and CSV writers indexed by split.
    :param folder: Destination directory.
    :rtype: None
    """
    for split, (temporary, handle, _) in resources.items():
        handle.close()
        os.replace(temporary, folder / (split + "_rows.csv"))


class Continuity:
    """Accumulate rows, observed hours and hosts per split and calendar day."""

    def __init__(self, dataset, host_column):
        """Start empty daily counters.

        :param dataset: Dataset key.
        :param host_column: Entity column counted per day, or None.
        :rtype: None
        """
        self.dataset, self.host_column = dataset, host_column
        self.rows = Counter()
        self.hours = defaultdict(set)
        self.hosts = defaultdict(set)

    def add(self, frame, timestamps):
        """Add one chunk of rows that carry a ``data_split`` column.

        :param frame: Current chunk with split labels.
        :param timestamps: Parsed UTC timestamps aligned with frame.
        :rtype: None
        """
        mask = frame["data_split"].isin(("train", "validation", "test")).to_numpy() & timestamps.notna().to_numpy()
        if not mask.any():
            return
        work = pd.DataFrame({
            "split": frame.loc[mask, "data_split"].to_numpy(),
            "date": timestamps[mask].dt.strftime("%Y-%m-%d").to_numpy(),
            "hour": timestamps[mask].dt.hour.to_numpy(),
        })
        if self.host_column:
            work["host"] = frame.loc[mask, self.host_column].fillna("").astype(str).to_numpy()
        for (split, date), group in work.groupby(["split", "date"], sort=False):
            self.rows[(split, date)] += len(group)
            self.hours[(split, date)].update(group["hour"].tolist())
            if self.host_column:
                self.hosts[(split, date)].update(group["host"].tolist())

    def frame(self):
        """Return one row per split and calendar date.

        :returns: Daily continuity report.
        :rtype: pandas.DataFrame
        """
        rows = [{
            "dataset": self.dataset, "data_split": split, "date": date, "rows": count,
            "unique_hosts": len(self.hosts[(split, date)]) if self.host_column else np.nan,
            "observed_hours": len(self.hours[(split, date)]),
            "missing_hours": 24 - len(self.hours[(split, date)]),
        } for (split, date), count in sorted(self.rows.items())]
        return pd.DataFrame(rows, columns=["dataset", "data_split", "date", "rows", "unique_hosts",
                                           "observed_hours", "missing_hours"])


def hashing_vectorizers(dataset, args):
    """Create the category, text and sequence hashing vectorizers for a dataset.

    :param dataset: Dataset key.
    :param args: Parsed CLI configuration.
    :returns: Category, text and sequence vectorizers (text/sequence may be None).
    :rtype: tuple
    """
    category = HashingVectorizer(
        n_features=args.category_hash_features, alternate_sign=False, norm="l2",
        analyzer="word", token_pattern=r"[^ ]+", lowercase=False, dtype=np.float32,
    )
    text = sequence = None
    if CHANNELS[dataset]["text"] and not args.disable_individual_text:
        text = HashingVectorizer(
            n_features=args.text_hash_features, alternate_sign=False, norm="l2",
            analyzer="char", ngram_range=TEXT_NGRAM_RANGE, lowercase=True, dtype=np.float32,
        )
    if CHANNELS[dataset]["sequence"]:
        sequence = HashingVectorizer(
            n_features=args.sequence_hash_features, alternate_sign=False, norm="l2",
            analyzer="word", ngram_range=SEQUENCE_NGRAM_RANGE, lowercase=True, dtype=np.float32,
        )
    return category, text, sequence


def build_shards(dataset, path, connection, plan, means, scales, numeric_names, args,
                 scratch, output, log):
    """Transform chunked observations to split shards and preserve row manifests.

    :param dataset: Dataset key from DATASETS.
    :param path: Observation CSV path.
    :param connection: Open SQLite observation index.
    :param plan: Feature plan from feature_plan.
    :param means: Training means used for imputation.
    :param scales: Training scales used for scaling.
    :param numeric_names: Expected numeric feature names from training statistics.
    :param args: Parsed CLI configuration.
    :param scratch: Dataset scratch directory.
    :param output: Dataset artifact output directory.
    :param log: Configured Log instance.
    :returns: Ordered feature names and the daily continuity report.
    :rtype: tuple
    :raises ValueError: If the numeric schema changes between passes.
    """
    category_vectorizer, text_vectorizer, sequence_vectorizer = hashing_vectorizers(dataset, args)
    header = pd.read_csv(path, nrows=0).columns.tolist()
    manifest_columns = [name for name in MANIFEST_CANDIDATES if name in header]
    if "row_manifest_id" not in manifest_columns:
        manifest_columns.insert(0, "row_manifest_id")
    manifest_columns.append("data_split")
    writers = open_manifest_writers(output, manifest_columns)
    history = HistoryState(plan["history"]) if plan["history_group"] else None
    continuity = Continuity(dataset, next((column for column in HOST_COLUMNS if column in header), None))
    shard_numbers = defaultdict(int)
    processed = 0
    try:
        for frame, ids in read_chunks(path, args.chunk_rows, getattr(args, "max_rows", None)):
            frame["data_split"] = ids.map(lookup_splits(connection, dataset, ids)).fillna("purged")
            _, timestamps = parse_time(frame)
            numeric_values, calculated = numeric_block(frame, timestamps, plan, history, means, scales)
            if calculated != numeric_names:
                raise ValueError(dataset + " numeric feature order changed between passes")
            add_derived_categories(frame, plan["categorical"])
            parts = [sparse.csr_matrix(numeric_values),
                     category_vectorizer.transform(category_documents(frame, plan["categorical"]))]
            if text_vectorizer is not None:
                parts.append(text_vectorizer.transform(text_documents(frame)))
            if sequence_vectorizer is not None:
                parts.append(sequence_vectorizer.transform(sequence_documents(frame)))
            all_features = sparse.hstack(parts, format="csr", dtype=np.float32)
            all_features.eliminate_zeros()
            continuity.add(frame, timestamps)
            for split in ("train", "validation", "test"):
                mask = frame["data_split"].eq(split).to_numpy()
                if not mask.any():
                    continue
                shard_numbers[split] += 1
                save_shard(scratch, split, shard_numbers[split], all_features[mask])
                manifest = frame.loc[mask, [column for column in manifest_columns if column in frame.columns]]
                writers[split][2].writerows(manifest.to_dict("records"))
            processed += len(frame)
            log.progress(f"{dataset} pass 3: transformed {processed:,} rows; "
                         f"shards train={shard_numbers['train']}, "
                         f"validation={shard_numbers['validation']}, test={shard_numbers['test']}")
            del frame, numeric_values, parts, all_features
            gc.collect()
    except BaseException:
        for temporary, handle, _ in writers.values():
            handle.close()
            temporary.unlink(missing_ok=True)
        raise
    else:
        close_manifest_writers(writers, output)
    feature_names = (
        ["numeric__" + name for name in numeric_names]
        + [f"category_hash__{index:04d}" for index in range(args.category_hash_features)]
        + ([f"text_hash__{index:04d}" for index in range(args.text_hash_features)]
           if text_vectorizer is not None else [])
        + ([f"sequence_hash__{index:04d}" for index in range(args.sequence_hash_features)]
           if sequence_vectorizer is not None else [])
    )
    log.progress(f"{dataset} pass 3 complete: {processed:,} rows", force=True)
    return feature_names, continuity.frame()


def merge_shards(shard_folder, output_path, feature_count, log, label):
    """Combine sparse shards through disk-backed CSR arrays into a final NPZ.

    :param shard_folder: Directory containing ordered part_*.npz shards.
    :param output_path: Final CSR NPZ output path.
    :param feature_count: Expected number of feature columns.
    :param log: Configured Log instance.
    :param label: Progress label for the current matrix.
    :returns: Rows, columns, nonzero count and density.
    :rtype: dict
    :raises ValueError: If no shard exists or a shard has the wrong width.
    """
    shards = sorted(shard_folder.glob("part_*.npz"))
    if not shards:
        raise ValueError("No sparse shards generated for " + label)
    row_count = 0
    nonzero_count = 0
    metadata = []
    for path in shards:
        matrix = sparse.load_npz(path).tocsr()
        if matrix.shape[1] != feature_count:
            raise ValueError("Shard feature-width mismatch: " + str(path))
        metadata.append((path, matrix.shape[0], matrix.nnz))
        row_count += matrix.shape[0]
        nonzero_count += matrix.nnz
        del matrix
    work = shard_folder.parent / (label + "_merge")
    work.mkdir(parents=True, exist_ok=True)
    data = np.memmap(work / "data.dat", dtype=np.float32, mode="w+", shape=(max(nonzero_count, 1),))
    indices = np.memmap(work / "indices.dat", dtype=np.int32, mode="w+", shape=(max(nonzero_count, 1),))
    indptr = np.memmap(work / "indptr.dat", dtype=np.int64, mode="w+", shape=(row_count + 1,))
    indptr[0] = 0
    row_offset = 0
    nnz_offset = 0
    for index_value, (path, rows, nnz) in enumerate(metadata, start=1):
        matrix = sparse.load_npz(path).tocsr()
        data[nnz_offset:nnz_offset + nnz] = matrix.data.astype(np.float32, copy=False)
        indices[nnz_offset:nnz_offset + nnz] = matrix.indices.astype(np.int32, copy=False)
        indptr[row_offset + 1:row_offset + rows + 1] = matrix.indptr[1:] + nnz_offset
        row_offset += rows
        nnz_offset += nnz
        log.progress(f"{label}: merged shard {index_value:,}/{len(metadata):,}; "
                     f"rows={row_offset:,}, nnz={nnz_offset:,}")
        del matrix
    data.flush(); indices.flush(); indptr.flush()
    matrix = sparse.csr_matrix((data[:nonzero_count], indices[:nonzero_count], indptr),
                               shape=(row_count, feature_count), copy=False)
    temporary = output_path.with_suffix(".npz.tmp")
    with open(temporary, "wb") as handle:
        sparse.save_npz(handle, matrix, compressed=False)
    os.replace(temporary, output_path)
    del matrix, data, indices, indptr
    gc.collect()
    shutil.rmtree(work, ignore_errors=True)
    log.progress(f"{label}: final matrix rows={row_count:,}, features={feature_count:,}, "
                 f"nnz={nonzero_count:,}", force=True)
    return {
        "rows": row_count,
        "features": feature_count,
        "nonzero": nonzero_count,
        "density": nonzero_count / (row_count * feature_count) if row_count and feature_count else 0.0,
    }


# =============================================================================
# Split lineage
# =============================================================================

def subset_lineage_counts(dataset, path, connection, chunk_rows, max_rows, log):
    """Read expected memberships for selected observations retained in splits.

    :param dataset: Aggregate dataset key.
    :param path: Source observation CSV.
    :param connection: SQLite index containing this subset's split assignments.
    :param chunk_rows: Maximum observation rows per chunk.
    :param max_rows: Maximum source CSV data rows selected for this test.
    :param log: Progress logger.
    :returns: Remaining link counts by ID, or None if no count column exists.
    :rtype: dict or None
    :raises ValueError: If a selected observation has an invalid membership count.
    """
    column = MEMBERSHIP_COUNT_COLUMN.get(dataset, DEFAULT_MEMBERSHIP_COUNT_COLUMN)
    if column not in pd.read_csv(path, nrows=0).columns:
        log.write(f"{dataset}: no {column} column; subset lineage requires a full scan", "WARNING")
        return None
    expected = {}
    for frame, ids in read_chunks(path, chunk_rows, max_rows):
        mapping = lookup_splits(connection, dataset, ids)
        for row_id, value in zip(ids, frame[column]):
            if mapping.get(row_id) not in ("train", "validation", "test"):
                continue
            try:
                count = int(value)
                if count <= 0 or float(value) != count:
                    raise ValueError("not a positive integer")
            except (ValueError, TypeError, OverflowError) as error:
                raise ValueError(f"{dataset}: invalid {column} for {row_id!r}: {value!r}") from error
            expected[row_id] = count
    return expected


def stream_lineage(dataset, dataset_path, connection, output, chunk_rows, log, max_rows=None):
    """Write split lineage without loading the full source lineage into memory.

    :param dataset: Dataset key from DATASETS.
    :param dataset_path: Observation CSV path used to locate upstream lineage.
    :param connection: Open SQLite observation index.
    :param output: Dataset artifact output directory.
    :param chunk_rows: Maximum CSV rows loaded per chunk.
    :param log: Configured Log instance.
    :param max_rows: Selected source observation limit; None uses full export.
    :returns: Counts of written links by split. Individual links are rebuilt from
        row manifests using the upstream one-to-one contract.
    :rtype: collections.Counter
    :raises ValueError: If lineage columns or subset link counts are invalid.
    :raises FileNotFoundError: If the source lineage file is absent.
    """
    path = dataset_path.with_name(dataset_path.stem + "_lineage.csv")
    counts = Counter()
    if dataset == "individual":
        # The individual contract is one-to-one and row_manifest_id == event_id.
        fields = ["dataset", "row_manifest_id", LINEAGE_KEY, "event_position",
                  "event_timestamp", "relationship_role"]
        for split in ("train", "validation", "test"):
            target = output / (split + "_lineage.csv.tmp")
            with open(target, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for frame in pd.read_csv(output / (split + "_rows.csv"), chunksize=chunk_rows,
                                         dtype=str, keep_default_na=False, low_memory=False):
                    for row in frame.to_dict("records"):
                        timestamp = next((row.get(column) for column in TIME_COLUMNS if row.get(column)), "")
                        writer.writerow({
                            "dataset": "individual",
                            "row_manifest_id": row["row_manifest_id"],
                            LINEAGE_KEY: row.get(LINEAGE_KEY) or row["row_manifest_id"],
                            "event_position": 1,
                            "event_timestamp": timestamp,
                            "relationship_role": "individual_event",
                        })
                        counts[split] += 1
                    log.progress(f"{dataset}/{split} lineage: wrote {counts[split]:,} links")
            os.replace(target, output / (split + "_lineage.csv"))
        return counts

    if not path.is_file():
        raise FileNotFoundError("Missing observation lineage: " + str(path))
    header = pd.read_csv(path, nrows=0).columns.tolist()
    missing = LINEAGE_REQUIRED.difference(header)
    if missing:
        raise ValueError("Lineage missing columns: " + ", ".join(sorted(missing)))
    remaining = (subset_lineage_counts(dataset, dataset_path, connection, chunk_rows, max_rows, log)
                 if max_rows is not None else None)
    remaining_total = sum(remaining.values()) if remaining is not None else None
    resources = {}
    for split in ("train", "validation", "test"):
        temporary = output / (split + "_lineage.csv.tmp")
        handle = open(temporary, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
        writer = csv.DictWriter(handle, fieldnames=header)
        writer.writeheader()
        resources[split] = (temporary, handle, writer)
    processed = 0
    try:
        for frame in pd.read_csv(path, chunksize=chunk_rows, dtype=str, keep_default_na=False,
                                 low_memory=False):
            ids = frame["row_manifest_id"].str.strip()
            frame["data_split"] = ids.map(lookup_splits(connection, dataset, ids)).fillna("purged")
            for split in ("train", "validation", "test"):
                selected = frame.loc[frame["data_split"].eq(split), header]
                if not len(selected):
                    continue
                if remaining is not None:
                    for row_id, count in ids.loc[selected.index].value_counts().items():
                        remaining[row_id] -= int(count)
                        remaining_total -= int(count)
                        if remaining[row_id] < 0:
                            raise ValueError(f"{dataset}: more lineage links than expected for {row_id!r}")
                resources[split][2].writerows(selected.to_dict("records"))
                counts[split] += len(selected)
            processed += len(frame)
            log.progress(f"{dataset} lineage: streamed {processed:,} links; written={sum(counts.values()):,}")
            if remaining is not None and remaining_total == 0:
                log.write(f"{dataset}: all {sum(counts.values()):,} expected subset lineage links collected; stopping scan")
                break
        if remaining is not None and remaining_total:
            raise ValueError(f"{dataset}: subset lineage is missing {remaining_total:,} expected links")
    except BaseException:
        for temporary, handle, _ in resources.values():
            handle.close()
            temporary.unlink(missing_ok=True)
        raise
    else:
        for split, (temporary, handle, _) in resources.items():
            handle.close()
            os.replace(temporary, output / (split + "_lineage.csv"))
    return counts


# =============================================================================
# Dataset workflow
# =============================================================================

def process_dataset(dataset, filename, connection, args, log):
    """Resume a dataset from committed stages, validating inputs and artifacts.

    :param dataset: Dataset key.
    :param filename: Observation CSV filename.
    :param connection: Open persistent SQLite index.
    :param args: CLI configuration.
    :param log: Progress logger.
    :returns: Dataset completion metadata and its daily continuity report.
    :rtype: tuple
    """
    started = time.perf_counter()
    max_rows = getattr(args, "max_rows", None)
    path = args.input / filename
    if not path.is_file():
        raise FileNotFoundError("Missing OSSEC observation dataset: " + str(path))
    output = args.output / dataset
    scratch = SCRATCH_FOLDER / dataset
    output.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    checkpoints = Checkpoints(output / "checkpoints.json", run_identity(dataset, path, args),
                              connection, dataset, log)
    requested = getattr(args, "resume_from", None)
    if args.force:
        requested = "index"
    if requested:
        required = set()
        def require_predecessors(stage):
            """Collect prerequisites of a requested restart stage.

            :param stage: Stage to inspect recursively.
            :rtype: None
            """
            for dep in CHECKPOINT_DEPENDENCIES[stage]:
                required.add(dep)
                require_predecessors(dep)
        require_predecessors(requested)
        missing = [stage for stage in CHECKPOINT_STAGES if stage in required and not checkpoints.valid(stage)]
        if missing:
            raise ValueError("Cannot resume from " + requested + "; missing/invalid preceding checkpoints: "
                             + ", ".join(missing) + ". Run without --resume-from to recover automatically.")
        checkpoints.invalidate(requested)
        if requested == "index":
            with connection:
                connection.execute("DELETE FROM dataset_checkpoints WHERE dataset=?", (dataset,))
        elif requested == "split":
            state = read_index_state(connection, dataset)
            state.pop("split", None)
            with connection:
                write_index_state(connection, dataset, state)
    elif checkpoints.valid("metadata"):
        log.write(f"{dataset}: all completed artifacts match; skipping dataset", "RESUME")
        continuity_path = output / "continuity_by_day.csv"
        continuity = pd.read_csv(continuity_path) if continuity_path.is_file() else pd.DataFrame()
        return checkpoints.result("metadata"), continuity

    def reuse(stage):
        """Reuse a valid completion marker or invalidate its dependent markers.

        :param stage: Stage about to execute.
        :returns: True when stored outputs remain reusable.
        :rtype: bool
        """
        if checkpoints.valid(stage):
            log.write(f"{dataset}: reusing checkpoint {stage}", "RESUME")
            return True
        checkpoints.invalidate(stage)
        return False

    plan = feature_plan(dataset, pd.read_csv(path, nrows=0).columns.tolist())
    log.debug(f"{dataset}: numeric={len(plan['numeric'])}, ratios={len(plan['ratio'])}, "
              f"history={len(plan['history'])} grouped by {plan['history_group'] or 'none'}, "
              f"categorical={len(plan['categorical'])}")
    if not reuse("index"):
        state = index_observations(dataset, path, connection, args.chunk_rows, log, checkpoints.signature, max_rows)
        checkpoints.mark("index", {key: state[key] for key in
                                   ("rows", "source_rows", "invalid_timestamps", "input_timestamp_sorted")})
    if not reuse("split"):
        split_metadata = assign_splits(dataset, connection, read_index_state(connection, dataset), log)
        checkpoints.mark("split", split_metadata)
    else:
        split_metadata = checkpoints.result("split")
    if not split_metadata.get("input_timestamp_sorted", True):
        log.write(f"{dataset}: input rows are not globally time-sorted; history features use "
                  "per-entity file order (Stage 2 writes each entity chronologically)", "NOTE")
    stats_path = output / "numeric_statistics.npz"
    if not reuse("stats"):
        with log.phase(f"{dataset}: fit training numeric statistics"):
            means, scales, numeric_names = fit_numeric_stats(
                dataset, path, connection, args.chunk_rows, plan, log, max_rows)
        temporary = stats_path.with_suffix(".npz.tmp")
        with open(temporary, "wb") as handle:
            np.savez(handle, means=means, scales=scales, names=np.asarray(numeric_names))
        os.replace(temporary, stats_path)
        checkpoints.mark("stats", {"numeric_names": numeric_names}, [stats_path])
    else:
        with np.load(stats_path, allow_pickle=False) as stats:
            means, scales = stats["means"], stats["scales"]
            numeric_names = stats["names"].tolist()
    shard_root = scratch / "shards"
    continuity_path = output / "continuity_by_day.csv"
    if not reuse("shards"):
        shutil.rmtree(shard_root, ignore_errors=True)
        shard_root.mkdir(parents=True, exist_ok=True)
        with log.phase(f"{dataset}: building sparse shards and row manifests"):
            feature_names, continuity = build_shards(
                dataset, path, connection, plan, means, scales, numeric_names, args,
                shard_root, output, log)
        continuity.to_csv(continuity_path, index=False)
        artifacts = list(shard_root.glob("*/part_*.npz")) + [output / (split + "_rows.csv")
                    for split in ("train", "validation", "test")] + [continuity_path]
        checkpoints.mark("shards", {"feature_names": feature_names}, artifacts)
    else:
        feature_names = checkpoints.result("shards")["feature_names"]
        continuity = pd.read_csv(continuity_path)
    shapes = {}
    for split in ("train", "validation", "test"):
        stage = "merge_" + split
        matrix_path = output / ("X_" + split + ".npz")
        if not reuse(stage):
            with log.phase(f"{dataset}/{split}: merging and saving sparse matrix"):
                shape = merge_shards(shard_root / split, matrix_path, len(feature_names), log, split)
            if shape["rows"] != split_metadata["split_rows"][split]:
                raise ValueError("Matrix row count disagrees with split checkpoint: " + split)
            checkpoints.mark(stage, shape, [matrix_path])
        shapes[split] = checkpoints.result(stage)
    if not reuse("lineage"):
        with log.phase(f"{dataset}: exporting split lineage"):
            lineage_counts = stream_lineage(dataset, path, connection, output, args.chunk_rows, log, max_rows)
        checkpoints.mark("lineage", dict(lineage_counts),
                         [output / (split + "_lineage.csv") for split in ("train", "validation", "test")])
    else:
        lineage_counts = checkpoints.result("lineage")
    if reuse("metadata"):
        return checkpoints.result("metadata"), continuity
    pd.DataFrame({"feature_index": np.arange(len(feature_names)), "feature_name": feature_names}).to_csv(
        output / "feature_names.csv", index=False)
    selection = {"mode": "first_csv_rows" if max_rows is not None else "all",
                 "max_rows": max_rows,
                 "source_rows_read": checkpoints.result("index")["source_rows"]}
    channels = {"text": any(name.startswith("text_hash__") for name in feature_names),
                "sequence": CHANNELS[dataset]["sequence"],
                "history": bool(plan["history_group"])}
    bundle = {
        "data_selection": selection,
        "feature_engineer_version": FEATURE_ENGINEER_VERSION,
        "feature_artifact_contract": FEATURE_ARTIFACT_CONTRACT,
        "dataset": dataset,
        "feature_plan": plan,
        "numeric_feature_names": numeric_names,
        "numeric_means": means,
        "numeric_scales": scales,
        "numeric_scaling": "impute_training_mean_then_divide_by_training_std_without_centering",
        "category_hash_features": args.category_hash_features,
        "text_hash_features": args.text_hash_features if channels["text"] else 0,
        "text_ngram_range": TEXT_NGRAM_RANGE,
        "sequence_hash_features": args.sequence_hash_features if channels["sequence"] else 0,
        "sequence_ngram_range": SEQUENCE_NGRAM_RANGE,
        "channels": channels,
        "split_metadata": split_metadata,
        "lineage_contract": "row_manifest_id_to_event_id",
        "event_lookup_file": str(args.event_lookup),
        "streaming": True,
    }
    joblib.dump(bundle, output / "preprocessing_bundle.joblib", compress=3)
    policy_rows = (
        [{"source_column": name, "feature_type": "numeric", "model_channel": "tabular",
          "lineage_or_evidence": False} for name in numeric_names]
        + [{"source_column": name, "feature_type": "categorical", "model_channel": "hashed_categorical",
            "lineage_or_evidence": False} for name in plan["categorical"]]
        + ([{"source_column": "raw_message", "feature_type": "text", "model_channel": "text",
             "lineage_or_evidence": False}] if channels["text"] else [])
        + ([{"source_column": "|".join(SEQUENCE_SOURCES), "feature_type": "sequence",
             "model_channel": "sequence", "lineage_or_evidence": False}] if channels["sequence"] else [])
    )
    pd.DataFrame(policy_rows).to_csv(output / "feature_policy_inputs.csv", index=False)

    tabular = sum(1 for name in feature_names if name.startswith(("numeric__", "category_hash__")))
    metadata = {
        "data_selection": selection,
        "dataset": dataset,
        "feature_artifact_contract": FEATURE_ARTIFACT_CONTRACT,
        "feature_engineer_version": FEATURE_ENGINEER_VERSION,
        "expected_observation_builder": EXPECTED_OBSERVATION_BUILDER,
        "source_dataset": str(path),
        "rows": split_metadata["rows"],
        "features": len(feature_names),
        "tabular_features": tabular,
        "text_features": sum(1 for name in feature_names if name.startswith("text_hash__")),
        "sequence_features": sum(1 for name in feature_names if name.startswith("sequence_hash__")),
        "numeric_source_columns": len(plan["numeric"]),
        "categorical_source_columns": len(plan["categorical"]),
        "history_group": plan["history_group"],
        "channels": channels,
        "split_metadata": split_metadata,
        "split_shapes": shapes,
        "lineage_status": "complete",
        "lineage_contract": "row_manifest_id_to_event_id",
        "event_lookup_file": str(args.event_lookup),
        "train_lineage_rows": lineage_counts["train"],
        "validation_lineage_rows": lineage_counts["validation"],
        "test_lineage_rows": lineage_counts["test"],
        "memory_safe_streaming": True,
        "engineered_dataset_written": False,
        "duration_seconds": time.perf_counter() - started,
    }
    write_json(output / "metadata.json", metadata)

    final_files = [output / name for name in (
        "feature_names.csv", "feature_policy_inputs.csv", "preprocessing_bundle.joblib",
        "metadata.json", "continuity_by_day.csv")]
    final_files += [output / name for split in ("train", "validation", "test")
                    for name in ("X_" + split + ".npz", split + "_rows.csv", split + "_lineage.csv")]
    checkpoints.mark("metadata", metadata, final_files)
    (output / "last_failure.json").unlink(missing_ok=True)
    log.write(f"{dataset} complete; checkpoints retained for future runs", "DONE")
    return metadata, continuity


def run(args, log):
    """Execute requested datasets while preserving completed checkpoint state.

    :param args: Parsed CLI configuration.
    :param log: Progress logger.
    :returns: Zero for success, one for a failed dataset.
    :rtype: int
    """
    global SCRATCH_FOLDER, DATABASE_FILE
    SCRATCH_FOLDER = args.output / "_scratch"
    DATABASE_FILE = SCRATCH_FOLDER / "ossec_stage3_index.sqlite"
    args.output.mkdir(parents=True, exist_ok=True)
    SCRATCH_FOLDER.mkdir(parents=True, exist_ok=True)
    datasets = list(dict.fromkeys(args.dataset or list(DATASETS)))
    connection = create_database(DATABASE_FILE)
    summaries = []
    continuity_frames = []
    failures = 0
    log.write("Memory-safe OSSEC Stage 3 starting", "START")
    log.write("Datasets: " + ", ".join(datasets))
    log.write("Output folder: " + str(args.output))
    if getattr(args, "max_rows", None) is not None:
        log.write(f"SUBSET TEST: first {args.max_rows:,} CSV rows per dataset; "
                  "chronological splitting and purge gaps remain active", "TEST")
    try:
        for dataset in datasets:
            log.write("Engineering OSSEC features: " + dataset, "PHASE")
            try:
                metadata, continuity = process_dataset(dataset, DATASETS[dataset], connection, args, log)
                summaries.append(metadata)
                continuity_frames.append(continuity)
            except Exception as error:
                failures += 1
                failure = {"dataset": dataset, "status": "failed", "error": repr(error)}
                summaries.append(failure)
                write_json(args.output / dataset / "last_failure.json", failure)
                log.write(dataset + " failed: " + repr(error), "ERROR", always=True)
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                break
    finally:
        connection.close()

    write_json(args.output / "feature_engineering_summary.json", {
        "feature_engineer_version": FEATURE_ENGINEER_VERSION,
        "feature_artifact_contract": FEATURE_ARTIFACT_CONTRACT,
        "event_lookup_file": str(args.event_lookup),
        "memory_safe_streaming": True,
        "datasets": summaries,
    })
    summary_rows = [{
        "dataset": item.get("dataset"),
        "status": item.get("status", "complete"),
        "lineage_status": item.get("lineage_status", ""),
        "rows": item.get("rows", 0),
        "features": item.get("features", 0),
        "train_lineage_rows": item.get("train_lineage_rows", 0),
        "validation_lineage_rows": item.get("validation_lineage_rows", 0),
        "test_lineage_rows": item.get("test_lineage_rows", 0),
        "duration_seconds": item.get("duration_seconds", 0),
        "error": item.get("error", ""),
    } for item in summaries]
    pd.DataFrame(summary_rows).to_csv(args.output / "lineage_summary.csv", index=False)
    frames = [frame for frame in continuity_frames if len(frame)]
    if frames:
        pd.concat(frames, ignore_index=True).to_csv(args.output / "continuity_summary.csv", index=False)
    if failures:
        log.write("OSSEC Stage 3 failed", "FAILED", always=True)
        return 1
    log.write("OSSEC Stage 3 completed: " + str(args.output / "feature_engineering_summary.json"),
              "COMPLETE", always=True)
    return 0


def main():
    """Acquire the output lock and run the resumable CLI workflow.

    :returns: Process status: zero for success, one for failure, 130 if interrupted.
    :rtype: int
    """
    args = parse_args()
    log = Log(args.quiet, args.verbose, args.progress_interval)
    try:
        with output_lock(args.output):
            return run(args, log)
    except KeyboardInterrupt:
        log.write("Interrupted; committed checkpoints retained. Re-run the same command to continue.",
                  "INTERRUPTED", always=True)
        return 130
    except Exception as error:
        log.write(repr(error), "ERROR", always=True)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
