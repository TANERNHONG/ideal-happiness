"""Resumable Stage 3 feature engineering for large authentication datasets.

Usage
-----
Initial execution and automatic continuation use the same command::

    python pipeline/phase3_features/auth.py --dataset individual --verbose --progress-interval 10

Restart one completed section and its dependent sections::

    python pipeline/phase3_features/auth.py --dataset individual --resume-from stats

``--resume-from`` accepts index, split, stats, shards, merge_train,
merge_validation, merge_test, lineage or metadata. It requires matching completed
prerequisites; omit it for automatic recovery. ``--force`` rebuilds the selected
datasets from indexing. Neither option affects unselected datasets.

Small test runs
---------------
Exercise feature engineering on the first 1,000 individual event rows::

    python pipeline/phase3_features/auth.py --dataset individual --max-rows 1000

``--max-rows N`` selects the first N CSV data rows in file order, before timestamp
validation and chronological splitting. It applies independently to each selected
dataset. For aggregate datasets, N counts observations (sessions/windows/days),
not their contributing raw events. Invalid timestamps count toward N and are
then skipped. Files shorter than N use all available rows. At least three valid
rows and nonempty chronological splits are required; increase N if timestamp
ties or purge gaps leave a split empty. The limit does not change split policy.

Test artifacts, summaries and checkpoints go under ``OUTPUT/subset_first_N``;
for default paths and N=1000 this is
``data/phase3_features/auth/subset_first_1000``. Repeating the same command
resumes that test. Omit ``--max-rows`` to return to full-data processing and its
existing checkpoints. Keep using the base output folder with ``--output``.

All three observation passes stop at N. Aggregate lineage export reads until
the expected memberships of the selected, unpurged observations are collected,
using Stage 2's validated ``event_count``/``total_events`` contract. Links may
occur later in the source lineage file, so this scan can exceed N rows. If the
count column is absent, it scans the complete lineage file and logs a warning.
Early stopping does not validate the remainder of that file.

Stage 3 prepares features and fits preprocessing statistics; it does not train
a predictive model. A successful subset run checks the pipeline on that subset
but cannot rule out errors in later rows or memory limits at full scale.

Duplicate session IDs
---------------------
Older Stage 2 builders could assign the same ID to separate sessions sharing a
grouping key and start second. The updated builder includes the first source
record in the session ID. Rebuild both the sessions CSV and its lineage with
the updated builder, then resume Stage 3 using the same paths and settings::

    python pipeline/phase2_observations/auth.py --sessions-only --force
    python pipeline/phase3_features/auth.py --dataset authentication_sessions

Supply your custom input/output folders to both commands when applicable.
Changed source signatures automatically invalidate the affected dataset's
checkpoints. Unselected datasets retain their completed work. Duplicate errors
include example IDs and one-based CSV data-row numbers (excluding the header);
these are record positions, not physical lines when quoted fields span lines.
Failed chunks roll back without advancing their checkpoint. Do not drop or
rename duplicate rows independently of their source-event lineage.

Durable checkpoints
-------------------
* index: each CSV chunk and its progress commit together in SQLite;
* split: chronological split assignment and counts;
* stats: training numeric means, scales and feature names;
* shards: all sparse chunks and split row manifests;
* merge_train / merge_validation / merge_test: each final CSR matrix;
* lineage: split lineage exports;
* metadata: final artifact bundle and metadata.

Indexing resumes after the last committed chunk. It scans earlier CSV chunks
again without reinserting their rows. Other incomplete stages restart at their
beginning; completed stages and individual matrix merges are reused. SQLite,
numeric statistics and shards are retained by default, including after failures.
``--keep-scratch`` remains accepted for compatibility. This trades disk space for
restart capability. Do not delete checkpoint or scratch files while running.

Reuse checks
------------
``checkpoints.json`` records source paths, byte sizes, nanosecond modification
times, software versions, settings and completed artifact metadata. Files are
reused only with matching completion markers. Missing or changed artifacts cause
the affected stage and dependent stages to be rebuilt. The complete final artifact
set can be reused without intermediate scratch files. The checks do not hash all
file contents and will not detect edits that preserve both size and timestamps.
A source change detected during processing aborts checkpoint completion.

Legacy outputs without these markers are not automatically trusted. In particular,
the previous version's index is retained on disk but rebuilt once because it has
no transactional input/progress identity. A running older process must finish or
be stopped before this revision uses the same output directory. Only this revision
honors the new cross-process OS lock.

Timing and pandas compatibility
------------------------------
The logger reports total elapsed time, per-operation duration and background
heartbeats. SQLite callbacks show execution activity, not completion percentage.
``--quiet`` suppresses routine output; ``--verbose`` includes error tracebacks.
Timestamp conversion normalizes to nanoseconds before integer conversion and
omits pandas' deprecated ``astype(copy=...)`` argument. NumPy and SciPy copy flags
are unchanged. Requires pandas 2.0+ with ``Series.dt.as_unit``, NumPy, SciPy,
scikit-learn and joblib.

The lineage path remains row_manifest_id -> record_id -> authlog_event_lookup.csv.
The exporter records the lookup path but does not validate its record-ID coverage.
Hashing channels have fixed widths; numeric log1p eligibility retains the earlier
chunk-dependent policy and inconsistent feature schemas fail explicitly.
"""
from __future__ import annotations

import argparse
import sys
import csv
import gc
import hashlib
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

INPUT_FOLDER = Path("data/phase2_observations/auth")
OUTPUT_FOLDER = Path("data/phase3_features/auth")
EVENT_LOOKUP_FILE = Path("data/phase1_classify/auth/authlog_event_lookup.csv")
SCRATCH_FOLDER = OUTPUT_FOLDER / "_scratch"
DATABASE_FILE = SCRATCH_FOLDER / "authlog_stage3_index.sqlite"
FEATURE_ENGINEER_VERSION = "2026-10-28-auth-resumable-lineage-04"
# 04 (2026-10-28): no identity as a feature. Server names, usernames and source IPs are not categories here and
# usernames not sequence words: a model that learns names overfits to particular entities and finds a new one unusual
# for its name alone (who an entity is enters through Phase 4g's own baselines; whether it is new, through the novelty
# detectors and Phase 4e). The source port is not a number either (its size means nothing); its category stays.
FEATURE_ARTIFACT_CONTRACT = "authlog_explainable_lineage"

DATASETS = {
    "individual": "authlog_events_all_months.csv",
    "host_5min": "authlog_host_windows_5min.csv",
    "authentication_sessions": "authlog_authentication_sessions.csv",
    "host_behavior_1d": "authlog_host_behavior_1d.csv",
}
PURGE_GAP_SECONDS = {
    "individual": 0,
    "host_5min": 300,
    "authentication_sessions": 900,
    "host_behavior_1d": 86400,
}
TIME_COLUMNS = ("timestamp", "window_start", "session_start", "first_timestamp")
TRAIN_FRACTION = 0.70
VALIDATION_FRACTION = 0.15
DEFAULT_CHUNK_ROWS = 50_000
DEFAULT_CATEGORY_HASH_FEATURES = 256
DEFAULT_TEXT_HASH_FEATURES = 512
DEFAULT_SEQUENCE_HASH_FEATURES = 256
PROGRESS_SECONDS = 15.0

CATEGORICAL_CANDIDATES = (
    "process_name", "facility", "event_type",
    "event_category", "event_outcome", "invalid_user_indicator",
    "authentication_method", "connection_stage", "source_ip_zone",
    "source_port_category", "operation", "dominant_event_type",
    "dominant_process", "first_event_type", "last_event_type", "window_label",
)
NUMERIC_CANDIDATES = (
    "timestamp_epoch", "failure_count", "hour_of_day",
    "day_of_week", "is_weekend", "total_events", "event_count",
    "events_per_minute", "events_per_hour", "active_hours",
    "active_span_seconds", "duration_seconds", "mean_inter_event_seconds",
    "minimum_inter_event_seconds", "maximum_inter_event_seconds",
    "success_count", "postponed_count", "invalid_user_count",
    "account_lock_count", "access_denied_count", "privilege_success_count",
    "privilege_failure_count", "connection_open_count",
    "connection_close_count", "connection_reset_count", "disconnect_count",
    "protocol_error_count", "pam_error_count", "key_error_count",
    "unknown_event_count", "authentication_event_count",
    "connection_event_count", "privilege_event_count", "system_event_count",
    "other_category_count", "unique_event_types", "unique_processes",
    "unique_usernames", "unique_target_usernames", "unique_source_ips",
    "unique_source_ports", "unique_authentication_methods",
    "unique_terminal_paths", "unique_reasons", "event_type_entropy",
    "process_entropy", "username_entropy", "source_ip_entropy",
    "dominant_event_type_count", "dominant_process_count",
    "dominant_username_count", "dominant_source_ip_count",
    "authentication_succeeded", "authentication_failed", "session_closed",
    "new_event_types", "new_processes", "new_usernames",
    "new_target_usernames", "new_source_ips", "new_authentication_methods",
)
MANIFEST_CANDIDATES = (
    "row_manifest_id", "record_id", "authentication_session_id", "timestamp",
    "window_start", "session_start", "first_timestamp", "host_id", "hostname",
    "process_name", "pid", "username", "source_ip", "source_port",
    "event_type", "event_category", "event_outcome", "authentication_method",
)
LINEAGE_REQUIRED = {
    "dataset", "row_manifest_id", "record_id", "event_position",
    "event_timestamp", "relationship_role",
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

    This is a metadata identity check, not a cryptographic content check.
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
        "numeric_candidates": list(NUMERIC_CANDIDATES),
        "categorical_candidates": list(CATEGORICAL_CANDIDATES),
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

    Queries use bounded parameter batches and the existing primary-key index.
    No observation is discarded or renamed; earlier checkpoints remain intact.
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

    Resume rereads earlier CSV chunks sequentially but does not parse their
    timestamps or reinsert their indexed rows. A partially committed chunk is
    rolled back together with its progress marker.
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
                connection.executemany(sql, ((dataset, str(i), float(e)) for i,e in zip(valid_ids,valid_epochs)))
                write_index_state(connection, dataset, next_state)
        except sqlite3.IntegrityError as error:
            details = duplicate_id_details(
                connection, dataset, valid_ids,
                state["source_rows"] + np.flatnonzero(valid) + 1,
            )
            guidance = (
                " Rebuild sessions AND their lineage using the updated Stage 2 builder "
                "with --sessions-only --force, then rerun Stage 3."
                if dataset == "authentication_sessions" else
                " Repair the source dataset and its lineage together before rerunning."
            )
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
        description="Memory-safe authentication Stage 3 feature engineering."
    )
    parser.add_argument("--input", type=Path, default=INPUT_FOLDER)
    parser.add_argument("--output", type=Path, default=OUTPUT_FOLDER)
    parser.add_argument("--chunk-rows", type=int, default=DEFAULT_CHUNK_ROWS)
    parser.add_argument("--max-rows", type=int, default=None,
                        help="Test the first N CSV rows per dataset; outputs go to OUTPUT/subset_first_N.")
    parser.add_argument("--dataset", action="append", default=[])
    parser.add_argument("--category-hash-features", type=int, default=DEFAULT_CATEGORY_HASH_FEATURES)
    parser.add_argument("--text-hash-features", type=int, default=DEFAULT_TEXT_HASH_FEATURES)
    parser.add_argument("--sequence-hash-features", type=int, default=DEFAULT_SEQUENCE_HASH_FEATURES)
    parser.add_argument("--disable-individual-text", action="store_true")
    parser.add_argument("--keep-scratch", action="store_true",
                        help="Compatibility option: checkpoint scratch is now retained by default.")
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
    :raises ValueError: If required input, split or feature validation fails.
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


def choose_columns(header):
    """Select configured numeric and categorical columns present in the header.
    
    :param header: Available CSV column names.
    :returns: Ordered numeric and categorical column lists.
    :rtype: tuple
    """
    numeric = [column for column in NUMERIC_CANDIDATES if column in header]
    categorical = [column for column in CATEGORICAL_CANDIDATES if column in header]
    return numeric, categorical


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

    If interrupted before the split checkpoint commits, split assignment is
    repeated as one stage; previously indexed source rows remain available.
    """
    if index_state.get("split"):
        log.write(dataset + ": reusing completed SQLite split assignments", "RESUME")
        return index_state["split"]
    total = index_state["rows"]
    invalid = index_state["invalid_timestamps"]
    sorted_input = index_state["input_timestamp_sorted"]
    train_offset = min(max(int(total * TRAIN_FRACTION), 1), total - 2)
    validation_offset = min(
        max(int(total * (TRAIN_FRACTION + VALIDATION_FRACTION)), 2), total - 1
    )
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
            (
                train_boundary - gap,
                train_boundary + gap,
                validation_boundary - gap,
                validation_boundary + gap,
                dataset,
            ),
        )
    with log.phase(f"{dataset} pass 1: committing split assignments", connection):
        connection.commit()
    with log.phase(f"{dataset} pass 1: counting split membership", connection):
        counts = dict(
            connection.execute(
                "SELECT data_split,COUNT(*) FROM observations "
                "WHERE dataset=? GROUP BY data_split",
                (dataset,),
            ).fetchall()
        )
    if min(counts.get(name, 0) for name in ("train", "validation", "test")) < 1:
        raise ValueError(dataset + " has an empty chronological split: " + repr(counts)
                         + ". If using --max-rows, increase it to cover a wider time span; "
                         "timestamp ties and purge gaps can empty small splits.")
    log.progress(
        f"{dataset} pass 1 complete: {total:,} valid rows; splits={counts}",
        force=True,
    )
    result = {
        "rows": total,
        "invalid_timestamps": invalid,
        "input_timestamp_sorted": sorted_input,
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
        batch = unique_ids[start : start + 900]
        placeholders = ",".join("?" for _ in batch)
        query = (
            "SELECT row_manifest_id,data_split FROM observations "
            "WHERE dataset=? AND row_manifest_id IN (" + placeholders + ")"
        )
        for row_id, split in connection.execute(query, [dataset, *batch]):
            mapping[row_id] = split
    return mapping


def numeric_matrix(frame, numeric_columns, timestamps, means=None, scales=None):
    """Build numeric, non-negative log1p and cyclical time features for a chunk.
    
    :param frame: Current chunk of observation rows.
    :param numeric_columns: Ordered configured numeric source columns.
    :param timestamps: Parsed UTC timestamps aligned with frame.
    :param means: Optional training means for imputation and centering.
    :param scales: Training scales used when means are supplied.
    :returns: Float32 matrix and ordered feature names. With means supplied, missing values are imputed and columns scaled.
    :rtype: tuple
    
    .. note::
    
       Every numeric column always emits a log1p companion, so feature widths
       are identical across chunks and passes regardless of missing values.
    """
    arrays = []
    names = []
    seconds = timestamps.dt.hour * 3600 + timestamps.dt.minute * 60 + timestamps.dt.second
    derived = {
        "time_hour": timestamps.dt.hour.astype(float),
        "time_day_of_week": timestamps.dt.dayofweek.astype(float),
        "time_is_weekend": (timestamps.dt.dayofweek >= 5).astype(float),
        "time_sin_day": np.sin(2 * np.pi * seconds / 86400),
        "time_cos_day": np.cos(2 * np.pi * seconds / 86400),
    }
    for column in numeric_columns:
        values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=float)
        arrays.append(values)
        names.append(column)
        # Always emit log1p so the schema never depends on chunk contents.
        # Missing values become 0; negatives (none expected) are clipped to 0.
        arrays.append(np.log1p(np.clip(np.nan_to_num(values, nan=0.0), 0.0, None)))
        names.append(column + "__log1p")
    for name, series in derived.items():
        arrays.append(np.asarray(series, dtype=float))
        names.append(name)
    matrix = np.column_stack(arrays) if arrays else np.empty((len(frame), 0))
    if means is not None and matrix.shape[1]:
        matrix = np.nan_to_num(matrix, nan=means)
        matrix = (matrix - means) / scales
    return matrix.astype(np.float32), names


def fit_numeric_stats(dataset, path, connection, chunk_rows, numeric_columns, log, max_rows=None):
    """Accumulate training-only numeric means and population scales across chunks.
    
    :param dataset: Dataset key from DATASETS.
    :param path: Input or output filesystem path.
    :param connection: Open SQLite observation index.
    :param chunk_rows: Maximum CSV rows loaded per chunk.
    :param numeric_columns: Ordered configured numeric source columns.
    :param log: Configured Log instance.
    :param max_rows: Maximum source CSV data rows; None processes all rows.
    :returns: Means, scales and ordered numeric feature names.
    :rtype: tuple
    """
    total = 0
    sum_values = None
    sum_squares = None
    valid_counts = None
    names = None
    for frame in pd.read_csv(path, chunksize=chunk_rows, nrows=max_rows, low_memory=False):
        ids = frame["row_manifest_id"].fillna("").astype(str).str.strip()
        mapping = lookup_splits(connection, dataset, ids)
        mask = ids.map(mapping).eq("train").to_numpy()
        if not mask.any():
            continue
        _, timestamps = parse_time(frame)
        matrix, current_names = numeric_matrix(
            frame.loc[mask].reset_index(drop=True),
            numeric_columns,
            timestamps.loc[mask].reset_index(drop=True),
        )
        if names is None:
            names = current_names
            sum_values = np.zeros(matrix.shape[1], dtype=np.float64)
            sum_squares = np.zeros(matrix.shape[1], dtype=np.float64)
            valid_counts = np.zeros(matrix.shape[1], dtype=np.int64)
        if current_names != names:
            raise ValueError(dataset + " numeric feature order changed between training chunks")
        finite = np.isfinite(matrix)
        safe = np.where(finite, matrix, 0.0)
        sum_values += safe.sum(axis=0)
        sum_squares += (safe * safe).sum(axis=0)
        valid_counts += finite.sum(axis=0)
        total += matrix.shape[0]
        log.progress(f"{dataset} pass 2: fitted numeric statistics from {total:,} training rows")
        del frame, matrix, safe
        gc.collect()
    if names is None:
        names = ["time_hour", "time_day_of_week", "time_is_weekend", "time_sin_day", "time_cos_day"]
        return np.zeros(len(names)), np.ones(len(names)), names
    means = np.divide(sum_values, np.maximum(valid_counts, 1))
    variances = np.divide(sum_squares, np.maximum(valid_counts, 1)) - means ** 2
    scales = np.sqrt(np.maximum(variances, 1e-12))
    scales[scales < 1e-6] = 1.0
    log.progress(f"{dataset} pass 2 complete: {total:,} training rows", force=True)
    return means, scales, names


def category_documents(frame, columns):
    """Encode categorical columns as normalized column=value tokens.
    
    :param frame: Current chunk of observation rows.
    :param columns: Ordered source or output column names.
    :returns: One categorical document per row.
    :rtype: pandas.Series
    """
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


def text_documents(dataset, frame):
    """Select individual message text or concatenate aggregate sequence columns.
    
    :param dataset: Dataset key from DATASETS.
    :param frame: Current chunk of observation rows.
    :returns: One text/sequence document per observation.
    :rtype: pandas.Series
    """
    if dataset == "individual":
        source = "normalized_message" if "normalized_message" in frame.columns else "raw_message" if "raw_message" in frame.columns else "original_log_line" if "original_log_line" in frame.columns else None
        return frame[source].fillna("").astype(str) if source else pd.Series([""] * len(frame))
    columns = [
        name for name in (
            "event_type_sequence", "outcome_sequence", "authentication_method_sequence",
        ) if name in frame.columns
    ]
    return (
        frame[columns].fillna("").astype(str).agg(" ".join, axis=1)
        if columns else pd.Series([""] * len(frame), index=frame.index)
    )


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
    :param columns: Ordered source or output column names.
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


def build_shards(
    dataset, path, connection, chunk_rows, numeric_columns, categorical_columns,
    means, scales, numeric_names, args, scratch, output, log,
):
    """Transform chunked observations to split shards and preserve row manifests.
    
    :param dataset: Dataset key from DATASETS.
    :param path: Input or output filesystem path.
    :param connection: Open SQLite observation index.
    :param chunk_rows: Maximum CSV rows loaded per chunk.
    :param numeric_columns: Ordered configured numeric source columns.
    :param categorical_columns: Ordered categorical source columns.
    :param means: Optional training means for imputation and centering.
    :param scales: Training scales used when means are supplied.
    :param numeric_names: Expected numeric feature names from training statistics.
    :param args: Parsed CLI configuration.
    :param scratch: Dataset scratch directory.
    :param output: Dataset artifact output directory.
    :param log: Configured Log instance.
    :returns: Ordered names for numeric and hashed feature channels.
    :rtype: list
    :raises ValueError: If required input, split or feature validation fails.
    """
    category_vectorizer = HashingVectorizer(
        n_features=args.category_hash_features,
        alternate_sign=False,
        norm="l2",
        analyzer="word",
        token_pattern=r"[^ ]+",
        lowercase=False,
        dtype=np.float32,
    )
    text_features = 0
    if dataset == "individual" and not args.disable_individual_text:
        text_features = args.text_hash_features
        content_vectorizer = HashingVectorizer(
            n_features=text_features,
            alternate_sign=False,
            norm="l2",
            analyzer="word",
            ngram_range=(1, 2),
            lowercase=True,
            dtype=np.float32,
        )
    elif dataset != "individual":
        text_features = args.sequence_hash_features
        content_vectorizer = HashingVectorizer(
            n_features=text_features,
            alternate_sign=False,
            norm="l2",
            analyzer="word",
            ngram_range=(1, 3),
            lowercase=True,
            dtype=np.float32,
        )
    else:
        content_vectorizer = None

    header = pd.read_csv(path, nrows=0).columns.tolist()
    manifest_columns = [name for name in MANIFEST_CANDIDATES if name in header]
    if "row_manifest_id" not in manifest_columns:
        manifest_columns.insert(0, "row_manifest_id")
    if "data_split" not in manifest_columns:
        manifest_columns.append("data_split")
    writers = open_manifest_writers(output, manifest_columns)
    shard_numbers = defaultdict(int)
    processed = 0

    try:
        for frame in pd.read_csv(path, chunksize=chunk_rows, nrows=getattr(args, "max_rows", None), low_memory=False):
            ids = frame["row_manifest_id"].fillna("").astype(str).str.strip()
            mapping = lookup_splits(connection, dataset, ids)
            frame["data_split"] = ids.map(mapping).fillna("purged")
            _, timestamps = parse_time(frame)
            numeric_values, calculated_names = numeric_matrix(
                frame, numeric_columns, timestamps, means, scales
            )
            if calculated_names != numeric_names:
                raise ValueError(dataset + " numeric feature order changed between passes")
            numeric_sparse = sparse.csr_matrix(numeric_values)
            category_sparse = category_vectorizer.transform(
                category_documents(frame, categorical_columns)
            )
            parts = [numeric_sparse, category_sparse]
            if content_vectorizer is not None:
                parts.append(content_vectorizer.transform(text_documents(dataset, frame)))
            all_features = sparse.hstack(parts, format="csr", dtype=np.float32)

            for split in ("train", "validation", "test"):
                mask = frame["data_split"].eq(split).to_numpy()
                if not mask.any():
                    continue
                shard_numbers[split] += 1
                save_shard(
                    scratch,
                    split,
                    shard_numbers[split],
                    all_features[mask],
                )
                manifest = frame.loc[mask, [column for column in manifest_columns if column in frame.columns]]
                writers[split][2].writerows(manifest.to_dict("records"))
            processed += len(frame)
            log.progress(
                f"{dataset} pass 3: transformed {processed:,} rows; "
                f"shards train={shard_numbers['train']}, "
                f"validation={shard_numbers['validation']}, test={shard_numbers['test']}"
            )
            del frame, numeric_values, numeric_sparse, category_sparse, all_features
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
        + [
            ("text_hash__" if dataset == "individual" else "sequence_hash__")
            + f"{index:04d}"
            for index in range(text_features)
        ]
    )
    log.progress(f"{dataset} pass 3 complete: {processed:,} rows", force=True)
    return feature_names


def merge_shards(shard_folder, output_path, feature_count, log, label):
    """Combine sparse shards through disk-backed CSR arrays into a final NPZ.
    
    :param shard_folder: Directory containing ordered part_*.npz shards.
    :param output_path: Final CSR NPZ output path.
    :param feature_count: Expected number of feature columns.
    :param log: Configured Log instance.
    :param label: Progress label for the current matrix.
    :returns: Rows, columns, nonzero count and density. Final serialization still uses memory and disk buffers.
    :rtype: dict
    :raises ValueError: If required input, split or feature validation fails.
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
    data = np.memmap(work / "data.dat", dtype=np.float32, mode="w+", shape=(nonzero_count,))
    indices = np.memmap(work / "indices.dat", dtype=np.int32, mode="w+", shape=(nonzero_count,))
    indptr = np.memmap(work / "indptr.dat", dtype=np.int64, mode="w+", shape=(row_count + 1,))
    indptr[0] = 0
    row_offset = 0
    nnz_offset = 0
    for index_value, (path, rows, nnz) in enumerate(metadata, start=1):
        matrix = sparse.load_npz(path).tocsr()
        data[nnz_offset : nnz_offset + nnz] = matrix.data.astype(np.float32, copy=False)
        indices[nnz_offset : nnz_offset + nnz] = matrix.indices.astype(np.int32, copy=False)
        indptr[row_offset + 1 : row_offset + rows + 1] = matrix.indptr[1:] + nnz_offset
        row_offset += rows
        nnz_offset += nnz
        log.progress(
            f"{label}: merged shard {index_value:,}/{len(metadata):,}; "
            f"rows={row_offset:,}, nnz={nnz_offset:,}"
        )
        del matrix
    data.flush(); indices.flush(); indptr.flush()
    matrix = sparse.csr_matrix(
        (data, indices, indptr),
        shape=(row_count, feature_count),
        copy=False,
    )
    temporary = output_path.with_suffix(".npz.tmp")
    with open(temporary, "wb") as handle:
        sparse.save_npz(handle, matrix, compressed=False)
    os.replace(temporary, output_path)
    del matrix, data, indices, indptr
    gc.collect()
    shutil.rmtree(work, ignore_errors=True)
    log.progress(
        f"{label}: final matrix rows={row_count:,}, features={feature_count:,}, "
        f"nnz={nonzero_count:,}",
        force=True,
    )
    return {
        "rows": row_count,
        "features": feature_count,
        "nonzero": nonzero_count,
        "density": nonzero_count / (row_count * feature_count)
        if row_count and feature_count else 0.0,
    }


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
    column = "event_count" if dataset == "authentication_sessions" else "total_events"
    if column not in pd.read_csv(path, nrows=0).columns:
        log.write(f"{dataset}: no {column} column; subset lineage requires a full scan", "WARNING")
        return None
    expected = {}
    with pd.read_csv(path, chunksize=chunk_rows, nrows=max_rows, low_memory=False) as reader:
        for frame in reader:
            ids = frame["row_manifest_id"].fillna("").astype(str).str.strip()
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
    :returns: Counts of written links by split. Individual links are reconstructed from row manifests using the upstream one-to-one contract.
    :rtype: collections.Counter
    :raises ValueError: If required input, split or feature validation fails.
    :raises FileNotFoundError: If a required input file is absent.
    
    .. note::
    
       This exporter routes links by observation ID. It does not validate record
       IDs against EVENT_LOOKUP_FILE, which is recorded as downstream provenance.
    """
    path = dataset_path.with_name(dataset_path.stem + "_lineage.csv")
    resources = {}
    output_columns = None
    counts = Counter()

    if dataset == "individual":
        # The individual contract is one-to-one and row_manifest_id=record_id.
        for split in ("train", "validation", "test"):
            rows_path = output / (split + "_rows.csv")
            target = output / (split + "_lineage.csv.tmp")
            with open(target, "w", encoding="utf-8", newline="") as handle:
                fields = [
                    "dataset", "row_manifest_id", "record_id", "event_position",
                    "event_timestamp", "relationship_role",
                ]
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for frame in pd.read_csv(rows_path, chunksize=chunk_rows, low_memory=False):
                    for row in frame.to_dict("records"):
                        record_id = str(row.get("record_id") or row["row_manifest_id"])
                        timestamp = next(
                            (str(row.get(column) or "") for column in TIME_COLUMNS if row.get(column)),
                            "",
                        )
                        writer.writerow({
                            "dataset": "individual",
                            "row_manifest_id": row["row_manifest_id"],
                            "record_id": record_id,
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
    output_columns = header
    for split in ("train", "validation", "test"):
        temporary = output / (split + "_lineage.csv.tmp")
        handle = open(temporary, "w", encoding="utf-8", newline="", buffering=1024 * 1024)
        writer = csv.DictWriter(handle, fieldnames=output_columns)
        writer.writeheader()
        resources[split] = (temporary, handle, writer)
    processed = 0
    try:
        for frame in pd.read_csv(path, chunksize=chunk_rows, low_memory=False):
            ids = frame["row_manifest_id"].fillna("").astype(str).str.strip()
            mapping = lookup_splits(connection, dataset, ids)
            frame["data_split"] = ids.map(mapping).fillna("purged")
            for split in ("train", "validation", "test"):
                selected = frame.loc[frame["data_split"].eq(split), output_columns]
                if len(selected):
                    if remaining is not None:
                        for row_id, count in ids.loc[selected.index].value_counts().items():
                            remaining[row_id] -= int(count)
                            remaining_total -= int(count)
                            if remaining[row_id] < 0:
                                raise ValueError(f"{dataset}: more lineage links than expected for {row_id!r}")
                    resources[split][2].writerows(selected.to_dict("records"))
                    counts[split] += len(selected)
            processed += len(frame)
            log.progress(
                f"{dataset} lineage: streamed {processed:,} links; "
                f"written={sum(counts.values()):,}"
            )
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


def process_dataset(dataset, filename, connection, args, log):
    """Resume a dataset from committed stages, validating inputs and artifacts.

    :param dataset: Dataset key.
    :param filename: Observation CSV filename.
    :param connection: Open persistent SQLite index.
    :param args: CLI configuration.
    :param log: Progress logger.
    :returns: Dataset completion metadata.
    :rtype: dict

    Indexing resumes at committed chunk boundaries. Other interrupted stages
    restart from their beginning. Completed matrix splits are reused separately.
    Files without a matching completion marker are not assumed valid.
    """
    started = time.perf_counter()
    max_rows = getattr(args, "max_rows", None)
    path = args.input / filename
    if not path.is_file():
        raise FileNotFoundError("Missing observation dataset: " + str(path))
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
        return checkpoints.result("metadata")

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

    header = pd.read_csv(path, nrows=0).columns.tolist()
    numeric_columns, categorical_columns = choose_columns(header)
    if not reuse("index"):
        state = index_observations(dataset, path, connection, args.chunk_rows, log, checkpoints.signature, max_rows)
        checkpoints.mark("index", {key: state[key] for key in
                                   ("rows", "source_rows", "invalid_timestamps", "input_timestamp_sorted")})
    if not reuse("split"):
        split_metadata = assign_splits(dataset, connection, read_index_state(connection, dataset), log)
        checkpoints.mark("split", split_metadata)
    else:
        split_metadata = checkpoints.result("split")
    stats_path = output / "numeric_statistics.npz"
    if not reuse("stats"):
        with log.phase(f"{dataset}: fit training numeric statistics"):
            means, scales, numeric_names = fit_numeric_stats(
                dataset, path, connection, args.chunk_rows, numeric_columns, log, max_rows)
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
    if not reuse("shards"):
        shutil.rmtree(shard_root, ignore_errors=True)
        shard_root.mkdir(parents=True, exist_ok=True)
        with log.phase(f"{dataset}: building sparse shards and row manifests"):
            feature_names = build_shards(
                dataset, path, connection, args.chunk_rows, numeric_columns,
                categorical_columns, means, scales, numeric_names, args,
                shard_root, output, log)
        artifacts = list(shard_root.glob("*/part_*.npz")) + [output / (split + "_rows.csv")
                    for split in ("train", "validation", "test")]
        checkpoints.mark("shards", {"feature_names": feature_names}, artifacts)
    else:
        feature_names = checkpoints.result("shards")["feature_names"]
    shapes = {}
    for split in ("train", "validation", "test"):
        stage = "merge_" + split
        matrix_path = output / ("X_" + split + ".npz")
        if not reuse(stage):
            with log.phase(f"{dataset}/{split}: merging and saving sparse matrix"):
                shape = merge_shards(shard_root / split, matrix_path,
                                     len(feature_names), log, split)
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
        return checkpoints.result("metadata")
    pd.DataFrame({"feature_index": np.arange(len(feature_names)), "feature_name": feature_names}).to_csv(
        output / "feature_names.csv", index=False)
    selection = {"mode": "first_csv_rows" if max_rows is not None else "all",
                 "max_rows": max_rows,
                 "source_rows_read": checkpoints.result("index")["source_rows"]}
    bundle = {
        "data_selection": selection,
        "feature_engineer_version": FEATURE_ENGINEER_VERSION,
        "feature_artifact_contract": FEATURE_ARTIFACT_CONTRACT,
        "dataset": dataset,
        "numeric_columns": numeric_columns,
        "numeric_feature_names": numeric_names,
        "numeric_means": means,
        "numeric_scales": scales,
        "categorical_columns": categorical_columns,
        "category_hash_features": args.category_hash_features,
        "text_hash_features": 0 if args.disable_individual_text else args.text_hash_features,
        "sequence_hash_features": args.sequence_hash_features,
        "split_metadata": split_metadata,
        "lineage_contract": "row_manifest_id_to_record_id",
        "event_lookup_file": str(EVENT_LOOKUP_FILE),
        "streaming": True,
    }
    joblib.dump(bundle, output / "preprocessing_bundle.joblib", compress=3)
    policy_rows = [
        {"source_column": name, "feature_type": "numeric", "model_channel": "tabular"}
        for name in numeric_names
    ] + [
        {"source_column": name, "feature_type": "categorical", "model_channel": "hashed_categorical"}
        for name in categorical_columns
    ]
    pd.DataFrame(policy_rows).to_csv(output / "feature_policy_inputs.csv", index=False)

    metadata = {
        "data_selection": selection,
        "dataset": dataset,
        "feature_artifact_contract": FEATURE_ARTIFACT_CONTRACT,
        "feature_engineer_version": FEATURE_ENGINEER_VERSION,
        "source_dataset": str(path),
        "rows": split_metadata["rows"],
        "features": len(feature_names),
        "split_metadata": split_metadata,
        "split_shapes": shapes,
        "lineage_status": "complete",
        "lineage_contract": "row_manifest_id_to_record_id",
        "train_lineage_rows": lineage_counts["train"],
        "validation_lineage_rows": lineage_counts["validation"],
        "test_lineage_rows": lineage_counts["test"],
        "memory_safe_streaming": True,
        "engineered_dataset_written": False,
        "duration_seconds": time.perf_counter() - started,
    }
    write_json(output / "metadata.json", metadata)

    final_files = [output / name for name in (
        "feature_names.csv", "feature_policy_inputs.csv", "preprocessing_bundle.joblib", "metadata.json")]
    final_files += [output / name for split in ("train", "validation", "test")
                    for name in ("X_" + split + ".npz", split + "_rows.csv", split + "_lineage.csv")]
    checkpoints.mark("metadata", metadata, final_files)
    (output / "last_failure.json").unlink(missing_ok=True)
    log.write(f"{dataset} complete; checkpoints retained for future runs", "DONE")
    return metadata


def run(args, log):
    """Execute requested datasets while preserving completed checkpoint state.

    :param args: Parsed CLI configuration.
    :param log: Progress logger.
    :returns: Zero for success, one for a failed dataset.
    :rtype: int
    """
    global SCRATCH_FOLDER, DATABASE_FILE
    SCRATCH_FOLDER = args.output / "_scratch"
    DATABASE_FILE = SCRATCH_FOLDER / "authlog_stage3_index.sqlite"
    args.output.mkdir(parents=True, exist_ok=True)
    SCRATCH_FOLDER.mkdir(parents=True, exist_ok=True)
    datasets = list(dict.fromkeys(args.dataset or list(DATASETS)))
    unknown = set(datasets).difference(DATASETS)
    if unknown:
        raise ValueError("Unknown datasets: " + ", ".join(sorted(unknown)))
    connection = create_database(DATABASE_FILE)
    summaries = []
    failures = 0
    log.write("Memory-safe authentication Stage 3 starting", "START")
    log.write("Datasets: " + ", ".join(datasets))
    log.write("Output folder: " + str(args.output))
    if getattr(args, "max_rows", None) is not None:
        log.write(f"SUBSET TEST: first {args.max_rows:,} CSV rows per dataset; "
                  "chronological splitting and purge gaps remain active", "TEST")
    try:
        for dataset in datasets:
            if dataset not in DATASETS:
                raise ValueError("Unknown dataset: " + dataset)
            log.write("Engineering authentication features: " + dataset, "PHASE")
            try:
                summaries.append(
                    process_dataset(dataset, DATASETS[dataset], connection, args, log)
                )
            except Exception as error:
                failures += 1
                failure = {
                    "dataset": dataset,
                    "status": "failed",
                    "error": repr(error),
                }
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
        "event_lookup_file": str(EVENT_LOOKUP_FILE),
        "memory_safe_streaming": True,
        "datasets": summaries,
    })
    summary_rows = []
    for item in summaries:
        summary_rows.append({
            "dataset": item.get("dataset"),
            "status": item.get("status", "complete"),
            "rows": item.get("rows", 0),
            "features": item.get("features", 0),
            "train_lineage_rows": item.get("train_lineage_rows", 0),
            "validation_lineage_rows": item.get("validation_lineage_rows", 0),
            "test_lineage_rows": item.get("test_lineage_rows", 0),
            "duration_seconds": item.get("duration_seconds", 0),
            "error": item.get("error", ""),
        })
    pd.DataFrame(summary_rows).to_csv(args.output / "lineage_summary.csv", index=False)
    if failures:
        log.write("Authentication Stage 3 failed", "FAILED", always=True)
        return 1
    log.write(
        "Authentication Stage 3 completed: "
        + str(args.output / "feature_engineering_summary.json"),
        "COMPLETE",
        always=True,
    )
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
