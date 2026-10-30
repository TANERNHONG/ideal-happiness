"""OSSEC explainable anomaly experiment runner with exact source lineage.

Step 4 of the OSSEC anomaly-detection workflow.

Consumes only the artifacts produced by
``pipeline/phase3_features/ossec.py`` under
``data/phase3_features/ossec``.

The runner evaluates four OSSEC observation representations:

* individual
* host_5min
* episodes
* host_behavior_1d

Three complementary detector channels are used:

1. Robust multifeature deviation scoring for stable continuous features.
2. Isolation Forest for unusual multivariate combinations.
3. Rarity scoring for sparse, binary, text, sequence, and categorical features.

Thresholds are chosen from validation data using a population-aware budget.
Test data is never used for feature selection or threshold selection.

Every test anomaly is resolved through:

    row_manifest_id
    -> split lineage
    -> event_id
    -> data/phase1_classify/ossec/ossec_event_lookup.csv
    -> original_log_line / source file / source line / archive member

Command-line usage
------------------
Run with timestamped INFO checkpoints and ten-second activity updates::

    python pipeline/phase4_detection/ossec_detectors.py

Enable detailed feature, threshold and evidence messages and five-second
updates::

    python pipeline/phase4_detection/ossec_detectors.py --verbose --progress-interval 5

Suppress routine progress with ``--quiet``. Both switches are mutually
exclusive. Use ``--help`` to view the logging options.

Runtime reporting
-----------------
Each log record includes elapsed time since module startup in ``HH:MM:SS.s``
format using ``time.monotonic()``. Timed stages report their own duration.
A background heartbeat reports the active stage during long scoring, fitting
and evidence-resolution work. Loop checkpoints also report item counts and
throughput. CLI runs report total runtime on completion, errors and
interruption. Each dataset also records its own ``total_seconds`` in
``summary.json`` using ``time.perf_counter()``.

.. note::

   Heartbeats indicate activity, not a percentage or an estimated finish time.
   They may be delayed by native code holding the interpreter lock. Abrupt
   process termination cannot emit a final summary. Quiet mode suppresses
   routine timing messages; warnings and errors remain visible.
   Imported callers can configure logging and use
   ``with runlog.run(): main()`` for the same runtime reporting.

Configuration
-------------
Budget, threshold and feature-policy constants retain their original
defaults. ``--features``, ``--output`` and ``--event-lookup`` select the
folders (defaults unchanged). A dataset that fails is recorded in its own
``summary.json`` and does not stop the remaining datasets.

Outputs are written beneath ``data/phase4_detection/ossec/detectors``.

Memory use (revision 2026-09-28, ported from the authentication runner)
-----------------------------------------------------------------------
The training split is never held in memory in full:

* ``X_train.npz`` is streamed from its zip archive in chunks, keeping only the
  policy-selected columns of a random sample of ``--train-sample`` rows
  (default 500,000) as float32, together with the per-feature presence counts
  of the whole training split.
* Feature diagnostics, robust medians and scales, the Isolation Forest and the
  training-quantile fallback thresholds use that sample. The Isolation Forest
  only draws 256 rows per tree, so fitting it on a sample changes nothing
  statistically. Rarity presence counts still use every training row, so rare
  values stay rare. With fewer training rows than the sample size, results
  match the in-memory version. ``train_rows`` in ``summary.json`` is the full
  training population; ``train_sample_*`` describe the fitted sample.
* Validation is scored, written and released before test is loaded.
* Robust and rarity scores are computed in vectorised row blocks. Explanation
  strings are built only for rows that alert on at least one detector, which
  keeps every alert-population attribution report intact; non-alerting rows
  have empty explanations.
* Only time and entity columns of ``train_rows.csv`` are read, and split
  lineage files are read in chunks keeping only alerted rows.

Feature channels (revision 2026-09-28)
--------------------------------------
Stage 3 now emits ``numeric__*``, ``category_hash__*``, ``text_hash__*`` and
``sequence_hash__*`` features. The policy admits hashed categorical features
(they hash exactly the categorical columns this policy admitted before) and
recognises both ``text__``/``sequence__`` and ``text_hash__``/``sequence_hash__``
prefixes. Text and sequence features always go to the rarity channel, never
to robust z-scores, as in the authentication runner.

Usage with explicit folders and a smaller training sample::

    python pipeline/phase4_detection/ossec_detectors.py --features data/phase3_features/ossec \\
        --output data/phase4_detection/ossec/detectors --train-sample 250000
"""

from __future__ import annotations

import time
import argparse
import json
import logging
import re
import sys
import threading
import zipfile
from collections import Counter
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from sources import change_window_mask, load_change_windows, train_rows_in_change_windows  # noqa: E402
from scipy import sparse, stats
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
import calibration  # noqa: E402  the test alert rate against the budget
from runlog import progress_items, stage, timed_stage  # noqa: E402

LOGGER = runlog.LOGGER

FEATURE_FOLDER = Path("data/phase3_features/ossec")
OUTPUT_FOLDER = Path("data/phase4_detection/ossec/detectors")
LABEL_FOLDER = Path("data/review_labels/ossec")
EVENT_LOOKUP_FILE = Path("data/phase1_classify/ossec/ossec_event_lookup.csv")

EXPECTED_FEATURE_CONTRACT = "ossec_explainable_lineage"
# Identity tag written into, and checked against, earlier phases' metadata. It is the
# producer's historical file name, not a path: keep it unless all phases are rerun.
EXPECTED_FEATURE_PRODUCER = "feature_engineer_ossec_logs_explainable_lineage.py"
REQUIRE_LINEAGE = True
REQUIRE_COMPLETE_EVENT_LOOKUP = True
EVENT_LOOKUP_CHUNK_ROWS = 200_000
RAW_EVIDENCE_PREVIEW_MESSAGES = 5
RAW_EVIDENCE_PREVIEW_CHARACTERS = 4_000
LINEAGE_FILES = ("train_lineage.csv", "validation_lineage.csv", "test_lineage.csv")

RANDOM_STATE = 42
ISOLATION_TREES = 300
DEFAULT_TRAIN_SAMPLE = 500_000
TRAIN_SAMPLE = DEFAULT_TRAIN_SAMPLE
SCORE_BLOCK_ROWS = 100_000
STREAM_CHUNK_ENTRIES = 5_000_000
CSV_CHUNK_ROWS = 500_000
BASELINE_QUANTILE = 0.995
ROBUST_Z_CAP = 100.0
RATIO_CAP = 100.0
MINIMUM_TRAIN_ROWS = 100
SKIP_ROWS_PER_FEATURE_BELOW = 5.0
WARN_ROWS_PER_FEATURE_BELOW = 20.0
MINIMUM_VALIDATION_DAYS_FOR_BUDGET = 3
MINIMUM_VALIDATION_ALERTS = 1
TRAINING_QUANTILE_IS_FLOOR = False

TARGET_ALERTS_PER_DAY = {
    "individual": 20,
    "host_5min": 10,
    "episodes": 10,
    "host_behavior_1d": 5,
}

MAX_VALIDATION_ALERT_FRACTION = {
    "individual": 0.01,
    "host_5min": 0.05,
    "episodes": 0.05,
    "host_behavior_1d": 0.05,
}

MINIMUM_BUDGET_CANDIDATES = {
    "individual": 100,
    "host_5min": 30,
    "episodes": 30,
    "host_behavior_1d": 20,
}

MINIMUM_VALIDATION_ROWS = {
    "individual": 200,
    "host_5min": 60,
    "episodes": 60,
    "host_behavior_1d": 30,
}

MINIMUM_TEST_ROWS = {
    "individual": 200,
    "host_5min": 60,
    "episodes": 60,
    "host_behavior_1d": 30,
}

MAX_DAILY_RATE_RATIO = 3.0
MINIMUM_OBSERVED_VALIDATION_DAYS = 5
MINIMUM_OBSERVED_TEST_DAYS = 5
SKIP_INVALID_TEMPORAL_COVERAGE = True

MIN_ROBUST_DISTINCT_VALUES = 3
MIN_ROBUST_MINORITY_COUNT = 10
MIN_ROBUST_NONZERO_COUNT = 10
MIN_RELATIVE_SCALE = 1e-6
MAX_TRAIN_CAPPED_Z_RATE = 0.005
SPARSE_PREVALENCE_MAX = 0.10
RARE_FEATURE_ALPHA = 0.5
RARITY_TOP_N = 5

ROBUST_RULES = {
    "individual": {"top_k": 1, "minimum_support": 1, "support_z": 4.0},
    "host_5min": {"top_k": 3, "minimum_support": 2, "support_z": 3.5},
    "episodes": {"top_k": 3, "minimum_support": 2, "support_z": 3.5},
    "host_behavior_1d": {"top_k": 3, "minimum_support": 2, "support_z": 3.5},
}

MODEL_CHANNELS = {"individual": ("tabular",)}
DEFAULT_MODEL_CHANNELS = ("tabular", "text", "sequence")
NOVELTY_CHANNELS = {
    "individual": ("text", "sequence"),
    "host_5min": ("sequence",),
    "episodes": ("sequence",),
    "host_behavior_1d": ("sequence",),
}

EXPERIMENTS = (
    "episodes",
    "individual",
    "host_5min",
    "host_behavior_1d",
)

TIME_COLUMNS = (
    "timestamp", "window_start", "episode_start", "first_timestamp",
)

ENTITY_COLUMNS = (
    "host_id", "hostname", "agent_name", "episode_id", "source_ip",
    "destination_ip", "process_name", "event_category", "username",
)

REVIEW_COMBINATIONS = (
    "robust+isolation+novelty",
    "robust+isolation",
    "robust+novelty",
    "isolation+novelty",
    "robust_only",
    "isolation_only",
    "novelty_only",
)

REVIEW_BUCKET_SIZE = {
    "episodes": 25,
    "individual": 20,
    "host_5min": 20,
    "host_behavior_1d": 15,
}

MEANINGFUL_LABELS = {"security_relevant", "operationally_interesting"}
DATA_QUALITY_LABEL = "data_quality_issue"
VALID_REVIEW_LABELS = MEANINGFUL_LABELS | {
    DATA_QUALITY_LABEL, "expected_behavior", "insufficient_context",
}
TARGET_RELEVANCE = 0.25

ALWAYS_EXCLUDE = (
    r"(^|__)time__?epoch(?:_seconds)?(?:__log1p)?$",
    r"(^|__)timestamp_epoch(?:__log1p)?$",
    r"(^|__)time_?(?:sin|cos)_(?:day|week)$",
    r"(^|__)(?:source|destination)_port(?:__log1p)?$",
)

BASELINE_SUPPORT_EXCLUDE = (
    r"__prior_mean$",
    r"__prior_std$",
    r"__rolling_\d+d_mean$",
    r"history_?_?prior_observations$",
)

COMMON_ALLOW = (
    r"(?:^|__)(?:total_events|event_count|events_per_minute|events_per_hour|duration_seconds|active_span_seconds|mean_inter_event_seconds|maximum_inter_event_seconds)(?:__log1p)?$",
    r"(?:^|__)(?:severity_rank|severity_rank_sum|mean_severity_rank|maximum_severity_rank|severity_increase|high_severity_count)(?:__log1p)?$",
    r"(?:^|__)(?:debug|info|notice|warning|error|critical|alert|emergency|unknown_severity|unknown_event|authentication|rootcheck|syscheck|connection|agent|server|queue|rules|file|active_response|other_category)_count(?:__log1p)?$",
    r"(?:^|__)unique_[a-z0-9_]+(?:__log1p)?$",
    r"(?:^|__)new_[a-z0-9_]+(?:__log1p)?$",
    r"(?:^|__)(?:event_type|process|severity|source_ip)_entropy$",
    r"__ratio$",
    r"__prior_z$",
    r"__rolling_\d+d_ratio$",
    r"(?:^|__)time_?(?:hour|day_of_week|is_weekend)$",
    r"__(?:zone|version|subnet|range)(?:_|$)",
)

# Stage 3 hashes exactly the categorical columns each dataset admits below, so
# every category_hash__ bucket is admitted. The one-hot patterns remain for
# feature folders written by the in-memory Stage 3 (version 01).
DATASET_ALLOW = {
    "individual": COMMON_ALLOW + (
        r"^text(?:_hash)?__",
        r"^category_hash__",
        r"(?:^|__)(?:severity|event_type|event_category|process_name|hostname|agent_name|authentication_method|connection_stage|scan_mode|operation)(?:_|$)",
        r"(?:^|__)severity_is_(?:high|critical)$",
        r"(?:^|__)event_is_unknown$",
    ),
    "host_5min": COMMON_ALLOW + (
        r"^sequence(?:_hash)?__",
        r"^category_hash__",
        r"(?:^|__)(?:dominant_event_type|dominant_process|dominant_severity|host_identity_type)(?:_|$)",
        r"(?:^|__)maximum_severity_is_(?:high|critical)$",
    ),
    "episodes": COMMON_ALLOW + (
        r"^sequence(?:_hash)?__",
        r"^category_hash__",
        r"(?:^|__)(?:process_name|event_category|host_identity_type)(?:_|$)",
        r"(?:^|__)maximum_severity_is_(?:high|critical)$",
    ),
    "host_behavior_1d": COMMON_ALLOW + (
        r"^sequence(?:_hash)?__",
        r"^category_hash__",
        r"(?:^|__)(?:dominant_event_type|dominant_process|dominant_severity|host_identity_type)(?:_|$)",
        r"(?:^|__)maximum_severity_is_(?:high|critical)$",
    ),
}
TEXT_PREFIXES = ("text__", "text_hash__")
SEQUENCE_PREFIXES = ("sequence__", "sequence_hash__")


# =============================================================================
# Logging, timing and progress reporting
# =============================================================================


def parse_args():
    """Parse verbosity and heartbeat interval settings.

    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", type=Path, default=FEATURE_FOLDER,
                        help="Stage 3 feature folder.")
    parser.add_argument("--output", type=Path, default=OUTPUT_FOLDER,
                        help="Experiment output folder.")
    parser.add_argument("--event-lookup", type=Path, default=EVENT_LOOKUP_FILE,
                        help="Stage 1 OSSEC event lookup.")
    parser.add_argument("--train-sample", type=int, default=DEFAULT_TRAIN_SAMPLE,
                        help="Training rows kept in memory for fitting (default 500000).")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    if args.train_sample < 1:
        parser.error("--train-sample must be positive")
    return args


# =============================================================================
# Value helpers
# =============================================================================

def sanitize_json(value):
    """Convert NumPy, Path and non-finite values into JSON-safe values.

    :param value: Value, mapping or sequence to convert.
    :returns: Structure containing only JSON-serializable values.
    :rtype: object
    """
    if isinstance(value, dict):
        return {str(key): sanitize_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_json(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        number = float(value)
        return number if np.isfinite(number) else None
    if isinstance(value, np.ndarray):
        return value.tolist()
    return value


def write_json(path, value):
    """Write a sanitized value as indented UTF-8 JSON.

    :param path: Destination file path.
    :param value: Value to serialize.
    :rtype: None
    """
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sanitize_json(value), handle, indent=2, allow_nan=False)


def truthy(series):
    """Interpret boolean or textual truth values as booleans.

    :param series: Input pandas Series.
    :returns: Boolean Series with missing values treated as False.
    :rtype: pandas.Series
    """
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return (
        series.fillna("").astype(str).str.strip().str.lower()
        .isin({"1", "true", "yes", "y"})
    )


def matches(name, patterns):
    """Test a feature name against case-insensitive regular expressions.

    :param name: Feature name to test.
    :param patterns: Regular expression patterns.
    :returns: True if any pattern matches.
    :rtype: bool
    """
    return any(re.search(pattern, name, flags=re.IGNORECASE) for pattern in patterns)


# =============================================================================
# Artifact and identity validation
# =============================================================================

@timed_stage
def validate_feature_artifacts(folder, dataset):
    """Require a complete explainable-lineage feature artifact set.

    :param folder: Dataset feature folder.
    :param dataset: Dataset key in EXPERIMENTS.
    :returns: Feature metadata recorded by the feature engineering step.
    :rtype: dict
    :raises ValueError: If the metadata contract or lineage status is unsupported.
    :raises FileNotFoundError: If any required artifact is absent.
    """
    required = [
        "feature_names.csv", "preprocessing_bundle.joblib", "metadata.json",
        "X_train.npz", "X_validation.npz", "X_test.npz",
        "train_rows.csv", "validation_rows.csv", "test_rows.csv",
        "train_lineage.csv", "validation_lineage.csv", "test_lineage.csv",
    ]
    missing = [filename for filename in required if not (folder / filename).is_file()]
    if missing:
        raise FileNotFoundError(
            "Incomplete OSSEC explainable-lineage artifacts for " + dataset
            + ": " + ", ".join(missing)
        )
    with open(folder / "metadata.json", "r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    if metadata.get("dataset") != dataset:
        raise ValueError("Feature metadata dataset mismatch for " + dataset)
    if metadata.get("feature_artifact_contract") != EXPECTED_FEATURE_CONTRACT:
        raise ValueError(
            "Unsupported feature artifact contract for " + dataset + ": "
            + str(metadata.get("feature_artifact_contract"))
        )
    if metadata.get("lineage_status") not in {"complete", "validated"}:
        raise ValueError("Feature lineage is not complete for " + dataset)
    LOGGER.debug("%s feature artifacts validated: producer=%s, version=%s",
                 dataset, EXPECTED_FEATURE_PRODUCER,
                 metadata.get("feature_engineer_version"))
    return metadata


def validate_manifest_identity(manifest, split_name):
    """Require unique non-blank observation IDs and normalize them in place.

    :param manifest: Split manifest dataframe.
    :param split_name: Split or dataset/split label used in error messages.
    :rtype: None
    :raises ValueError: If identifiers are missing, blank or duplicated.
    """
    if "row_manifest_id" not in manifest.columns:
        raise ValueError(split_name + " manifest is missing row_manifest_id")
    values = manifest["row_manifest_id"].fillna("").astype(str).str.strip()
    if values.eq("").any():
        raise ValueError(split_name + " manifest has blank row_manifest_id values")
    if values.duplicated().any():
        examples = values.loc[values.duplicated(keep=False)].head(10).tolist()
        raise ValueError(
            split_name + " manifest has duplicate row_manifest_id values: "
            + ", ".join(examples)
        )
    manifest["row_manifest_id"] = values


def _read_npy(archive, name):
    """Read a small array from an ``.npz`` archive in full.

    :param archive: Open zip archive.
    :param name: Member name.
    :returns: Array.
    :rtype: numpy.ndarray
    """
    with archive.open(name) as handle:
        return np.lib.format.read_array(handle, allow_pickle=False)


def _iter_npy(archive, name, chunk):
    """Yield (offset, block) pieces of a large array without loading it whole.

    :param archive: Open zip archive.
    :param name: Member name.
    :param chunk: Maximum entries per block.
    :yields: Offset and block.
    :rtype: iterator
    """
    handle = archive.open(name)
    try:
        version = np.lib.format.read_magic(handle)
        reader = (np.lib.format.read_array_header_1_0 if version == (1, 0)
                  else np.lib.format.read_array_header_2_0)
        shape, fortran_order, dtype = reader(handle)
        if fortran_order and len(shape) > 1:
            raise ValueError("Fortran-ordered array not supported: " + name)
        total, dtype = int(np.prod(shape)), np.dtype(dtype)
        offset = 0
        while offset < total:
            count = min(chunk, total - offset)
            yield offset, np.frombuffer(handle.read(count * dtype.itemsize), dtype=dtype, count=count)
            offset += count
    finally:
        handle.close()


def matrix_rows(path):
    """Read the row count of a saved CSR matrix without loading it.

    :param path: ``X_<split>.npz`` path.
    :returns: Number of rows.
    :rtype: int
    """
    with zipfile.ZipFile(path) as archive:
        if "shape.npy" in archive.namelist():
            return int(_read_npy(archive, "shape.npy")[0])
    return int(sparse.load_npz(path).shape[0])


def load_sparse(path, keep_columns, rows=None, count_presence=False):
    """Stream a CSR ``.npz`` into float32, keeping selected rows and columns.

    :param path: ``X_<split>.npz`` path.
    :param keep_columns: Column indices to keep, in output order.
    :param rows: Sorted row indices to keep, or None for every row.
    :param count_presence: Also count non-zero entries per kept column over
        every row of the file (not only the kept rows).
    :returns: Matrix, total file rows and presence counts (or None).
    :rtype: tuple
    """
    keep_columns = np.asarray(keep_columns, dtype=np.int64)
    with zipfile.ZipFile(path) as archive:
        members = set(archive.namelist())
        fmt = str(_read_npy(archive, "format.npy")) if "format.npy" in members else ""
        if fmt != "csr":
            matrix = sparse.load_npz(path).tocsr()
            total = matrix.shape[0]
            presence = (np.bincount(matrix.indices[matrix.data != 0], minlength=matrix.shape[1])
                        .astype(float)[keep_columns] if count_presence else None)
            if rows is not None:
                matrix = matrix[np.asarray(rows, dtype=np.int64)]
            return matrix[:, keep_columns].astype(np.float32), total, presence
        shape = _read_npy(archive, "shape.npy")
        total, width = int(shape[0]), int(shape[1])
        indptr = _read_npy(archive, "indptr.npy").astype(np.int64)
        column_map = np.full(width, -1, dtype=np.int64)
        column_map[keep_columns] = np.arange(len(keep_columns))
        if rows is None:
            positions, entry_rows, out_rows = None, None, total
            capacity = int(indptr[-1])
        else:
            rows = np.asarray(rows, dtype=np.int64)
            starts, lengths = indptr[rows], indptr[rows + 1] - indptr[rows]
            capacity = int(lengths.sum())
            positions = (np.arange(capacity, dtype=np.int64)
                         + np.repeat(starts - (np.cumsum(lengths) - lengths), lengths))
            entry_rows = np.repeat(np.arange(len(rows), dtype=np.int64), lengths)
            out_rows = len(rows)
        out_columns = np.empty(capacity, dtype=np.int32)
        out_data = np.empty(capacity, dtype=np.float32)
        row_counts = np.zeros(out_rows, dtype=np.int64)
        presence = np.zeros(width, dtype=np.int64) if count_presence else None
        filled = 0
        for (offset, columns), (_, values) in zip(_iter_npy(archive, "indices.npy", STREAM_CHUNK_ENTRIES),
                                                   _iter_npy(archive, "data.npy", STREAM_CHUNK_ENTRIES)):
            if count_presence:
                presence += np.bincount(columns[values != 0], minlength=width)
            if positions is None:
                local = slice(None)
                block_rows = np.searchsorted(indptr, np.arange(offset, offset + len(columns)), side="right") - 1
            else:
                low, high = np.searchsorted(positions, [offset, offset + len(columns)])
                if low == high:
                    continue
                local = positions[low:high] - offset
                block_rows = entry_rows[low:high]
            mapped = column_map[columns[local]]
            keep = mapped >= 0
            count = int(keep.sum())
            out_columns[filled:filled + count] = mapped[keep]
            out_data[filled:filled + count] = values[local][keep]
            row_counts += np.bincount(block_rows[keep], minlength=out_rows)
            filled += count
        new_indptr = np.concatenate([[0], np.cumsum(row_counts)])
        matrix = sparse.csr_matrix((out_data[:filled], out_columns[:filled], new_indptr),
                                   shape=(out_rows, len(keep_columns)))
    presence = presence[keep_columns].astype(float) if count_presence else None
    return matrix, total, presence


def load_manifest(folder, split_name, columns=None):
    """Load and validate one split manifest, optionally only some columns.

    :param folder: Dataset feature folder.
    :param split_name: Train, validation or test split name.
    :param columns: Optional column names to read; row_manifest_id is always read.
    :returns: Validated manifest dataframe.
    :rtype: pandas.DataFrame
    """
    path = folder / (split_name + "_rows.csv")
    usecols = None
    if columns is not None:
        header = pd.read_csv(path, nrows=0).columns
        usecols = [column for column in header if column == "row_manifest_id" or column in columns]
    manifest = pd.read_csv(path, usecols=usecols, dtype={"row_manifest_id": str}, low_memory=False)
    manifest["__source_split"] = split_name
    validate_manifest_identity(manifest, split_name)
    return manifest


# =============================================================================
# Temporal diagnostics
# =============================================================================

def time_series(manifest):
    """Select the first manifest column containing parseable UTC timestamps.

    :param manifest: Manifest or scored dataframe.
    :returns: Column name or None, and the parsed timestamp Series.
    :rtype: tuple
    """
    for column in TIME_COLUMNS:
        if column in manifest.columns:
            parsed = pd.to_datetime(manifest[column], errors="coerce", utc=True)
            if parsed.notna().any():
                return column, parsed
    return None, pd.Series(pd.NaT, index=manifest.index, dtype="datetime64[ns, UTC]")


def temporal_metrics(manifest):
    """Summarize row counts, observed days and the observed time range.

    :param manifest: Manifest dataframe for one split.
    :returns: Temporal coverage metrics.
    :rtype: dict
    """
    time_column_name, timestamps = time_series(manifest)
    good = timestamps.dropna()
    observed_days = int(good.dt.floor("D").nunique()) if len(good) else 0
    return {
        "time_column": time_column_name or "",
        "rows": int(len(manifest)),
        "observed_days": observed_days,
        "rows_per_observed_day": len(manifest) / observed_days if observed_days else np.nan,
        "first_timestamp": str(good.min()) if len(good) else "",
        "last_timestamp": str(good.max()) if len(good) else "",
    }


@timed_stage
def split_diagnostics(dataset, parts, output):
    """Write per-split density and per-day continuity diagnostics.

    :param dataset: Dataset key in EXPERIMENTS.
    :param parts: Split name, feature count and manifest triples.
    :param output: Dataset output directory.
    :returns: One row per split with temporal coverage metrics.
    :rtype: pandas.DataFrame
    """
    rows = []
    daily_frames = []
    for split_name, feature_count, manifest in parts:
        metrics = temporal_metrics(manifest)
        rows.append({
            "dataset": dataset,
            "split": split_name,
            "features": int(feature_count),
            **metrics,
        })
        _, timestamps = time_series(manifest)
        work = pd.DataFrame({"timestamp": timestamps.dropna()})
        if len(work):
            work["date"] = work["timestamp"].dt.floor("D")
            work["hour"] = work["timestamp"].dt.hour
            entity = next(
                (column for column in ENTITY_COLUMNS
                 if column in manifest.columns and manifest[column].notna().any()),
                None,
            )
            if entity:
                work["entity"] = manifest.loc[
                    work.index, entity
                ].fillna("__missing__").astype(str)
            grouped = work.groupby("date", sort=True)
            daily = grouped.agg(
                rows=("timestamp", "size"),
                observed_hours=("hour", "nunique"),
            ).reset_index()
            daily["unique_entities"] = (
                grouped["entity"].nunique().to_numpy() if entity else np.nan
            )
            daily["dataset"] = dataset
            daily["split"] = split_name
            daily["date"] = daily["date"].dt.strftime("%Y-%m-%d")
            daily_frames.append(daily)
    summary = pd.DataFrame(rows)
    summary.to_csv(output / "split_density_summary.csv", index=False)
    daily = pd.concat(daily_frames, ignore_index=True) if daily_frames else pd.DataFrame()
    daily.to_csv(output / "daily_continuity.csv", index=False)
    return summary


def temporal_split_valid(dataset, validation_manifest, test_manifest):
    """Check validation and test coverage, population and daily-rate balance.

    :param dataset: Dataset key in EXPERIMENTS.
    :param validation_manifest: Validation manifest dataframe.
    :param test_manifest: Test manifest dataframe.
    :returns: Validity flag, failure reasons and the underlying metrics.
    :rtype: tuple
    """
    validation = temporal_metrics(validation_manifest)
    test = temporal_metrics(test_manifest)
    validation_rate = validation["rows_per_observed_day"]
    test_rate = test["rows_per_observed_day"]
    ratio = (
        max(validation_rate / test_rate, test_rate / validation_rate)
        if np.isfinite(validation_rate) and np.isfinite(test_rate)
        and validation_rate > 0 and test_rate > 0
        else np.inf
    )
    reasons = []
    if validation["observed_days"] < MINIMUM_OBSERVED_VALIDATION_DAYS:
        reasons.append("too_few_observed_validation_days")
    if test["observed_days"] < MINIMUM_OBSERVED_TEST_DAYS:
        reasons.append("too_few_observed_test_days")
    if validation["rows"] < MINIMUM_VALIDATION_ROWS[dataset]:
        reasons.append("too_few_validation_rows")
    if test["rows"] < MINIMUM_TEST_ROWS[dataset]:
        reasons.append("too_few_test_rows")
    if ratio > MAX_DAILY_RATE_RATIO:
        reasons.append("validation_test_daily_rate_mismatch")
    return not reasons, reasons, {
        "validation": validation,
        "test": test,
        "validation_test_daily_rate_ratio": float(ratio),
    }


# =============================================================================
# Feature policy and diagnostics
# =============================================================================

@timed_stage
def feature_policy(dataset, feature_names):
    """Select security-relevant features and record an inclusion audit.

    :param dataset: Dataset key in EXPERIMENTS.
    :param feature_names: Ordered feature names from the feature artifacts.
    :returns: Selected feature indices and the full audit dataframe.
    :rtype: tuple
    :raises ValueError: If the policy removes every feature.
    """
    allowed_patterns = DATASET_ALLOW[dataset]
    indices = []
    audit = []
    for index, name in enumerate(progress_items(feature_names, dataset + " feature policy names checked")):
        if matches(name, ALWAYS_EXCLUDE):
            include, reason = False, "misleading_raw_or_time_feature"
        elif matches(name, BASELINE_SUPPORT_EXCLUDE):
            include, reason = False, "baseline_support_not_anomaly_input"
        elif matches(name, allowed_patterns):
            include, reason = True, "security_or_behavior_feature"
        else:
            include, reason = False, "outside_ossec_security_policy"
        if include:
            indices.append(index)
        audit.append({
            "original_feature_index": index,
            "feature_name": name,
            "included": include,
            "reason": reason,
        })
    if not indices:
        raise ValueError("Feature policy removed all features for " + dataset)
    LOGGER.debug("%s feature policy: %s of %s features retained",
                 dataset, len(indices), len(feature_names))
    return np.asarray(indices, dtype=int), pd.DataFrame(audit)


def cap_ratio_features(matrix, feature_names):
    """Clip ratio and rate feature values to a fixed magnitude.

    :param matrix: Sparse feature matrix restricted to selected features.
    :param feature_names: Ordered names matching the matrix columns.
    :returns: Capped compressed sparse row matrix and the capped feature names.
    :rtype: tuple
    """
    result = matrix.tocsc(copy=True)
    capped = []
    for index, name in enumerate(feature_names):
        if not any(token in name.lower() for token in ("ratio", "per_event", "per_minute", "per_hour")):
            continue
        start = result.indptr[index]
        end = result.indptr[index + 1]
        result.data[start:end] = np.clip(result.data[start:end], -RATIO_CAP, RATIO_CAP)
        capped.append(name)
    return result.tocsr(), capped


def channel_of(name):
    """Classify a feature name into its model channel.

    :param name: Feature name.
    :returns: Channel name: text, sequence or tabular.
    :rtype: str
    """
    lowered = name.lower()
    if lowered.startswith(TEXT_PREFIXES):
        return "text"
    if lowered.startswith(SEQUENCE_PREFIXES):
        return "sequence"
    return "tabular"


@timed_stage
def inspect_features(matrix, names):
    """Classify each training feature as robust, rarity or excluded.

    Text and sequence features are never robust-eligible; they go to the
    rarity channel regardless of their spread.

    :param matrix: Training feature matrix (or sample) restricted to selected features.
    :param names: Ordered names matching the matrix columns.
    :returns: One diagnostic row per feature.
    :rtype: pandas.DataFrame
    """
    matrix = matrix.tocsc()
    diagnostics = []
    for index, name in enumerate(progress_items(names, "Feature spread diagnostics computed")):
        values = matrix.getcol(index).toarray().ravel().astype(float)
        finite = values[np.isfinite(values)]
        if not len(finite):
            diagnostics.append({
                "feature_name": name,
                "role": "excluded",
                "reason": "no_finite_values",
            })
            continue
        unique = np.unique(finite)
        nonzero = int(np.count_nonzero(finite))
        zero = len(finite) - nonzero
        median = float(np.median(finite))
        mad = float(np.median(np.abs(finite - median)))
        scale = 1.4826 * mad
        fallback = float(np.quantile(np.abs(finite - median), 0.75))
        if not np.isfinite(scale) or scale <= 1e-9:
            scale = fallback
        minority = min(nonzero, zero)
        prevalence = nonzero / len(finite)
        relative_scale = (
            scale / max(abs(median), float(np.quantile(np.abs(finite), 0.75)), 1.0)
            if np.isfinite(scale) else 0.0
        )
        tabular = channel_of(name) == "tabular"
        categorical_like = len(unique) <= 2 or prevalence <= SPARSE_PREVALENCE_MAX or not tabular
        robust_eligible = (
            tabular
            and len(unique) >= MIN_ROBUST_DISTINCT_VALUES
            and nonzero >= MIN_ROBUST_NONZERO_COUNT
            and minority >= MIN_ROBUST_MINORITY_COUNT
            and np.isfinite(scale)
            and scale > 1e-9
            and relative_scale >= MIN_RELATIVE_SCALE
        )
        role = "robust_continuous" if robust_eligible else "rarity" if categorical_like else "excluded"
        reason = (
            "eligible_continuous" if robust_eligible else
            "binary_or_sparse" if categorical_like else
            "insufficient_stable_spread"
        )
        capped_rate = (
            float(np.mean(np.abs((finite - median) / scale) >= ROBUST_Z_CAP))
            if robust_eligible else np.nan
        )
        if robust_eligible and capped_rate > MAX_TRAIN_CAPPED_Z_RATE:
            role, reason = "excluded", "excessive_training_z_cap_rate"
        diagnostics.append({
            "feature_name": name,
            "role": role,
            "reason": reason,
            "finite_count": int(len(finite)),
            "nonzero_count": nonzero,
            "distinct_values": int(len(unique)),
            "minority_count": minority,
            "prevalence": float(prevalence),
            "median": median,
            "mad": mad,
            "scale": scale,
            "relative_scale": relative_scale,
            "train_z_cap_rate": capped_rate,
        })
    return pd.DataFrame(diagnostics)


# =============================================================================
# Detector channels
# =============================================================================

@timed_stage
def fit_robust(matrix):
    """Fit per-feature medians and scaled median absolute deviations.

    :param matrix: Training matrix restricted to robust-eligible features.
    :returns: Median and scale arrays; degenerate scales use a quantile fallback.
    :rtype: tuple
    """
    matrix = matrix.tocsc()
    medians = np.zeros(matrix.shape[1])
    scales = np.zeros(matrix.shape[1])
    for index in progress_items(range(matrix.shape[1]), "Robust baseline features fitted"):
        values = matrix.getcol(index).toarray().ravel().astype(float)
        medians[index] = np.median(values)
        mad = np.median(np.abs(values - medians[index]))
        scale = 1.4826 * mad
        if not np.isfinite(scale) or scale <= 1e-9:
            scale = np.quantile(np.abs(values - medians[index]), 0.75)
        scales[index] = scale
    return medians, scales


def _robust_z(block, medians, scales):
    """Capped absolute robust z-scores for a dense row block.

    :param block: Dense rows restricted to robust features.
    :param medians: Training feature medians.
    :param scales: Training feature scales.
    :returns: Z-scores clipped to [0, ROBUST_Z_CAP].
    :rtype: numpy.ndarray
    """
    with np.errstate(divide="ignore", invalid="ignore"):
        z_scores = np.abs((block - medians) / scales)
    z_scores = np.nan_to_num(z_scores, nan=0.0, posinf=ROBUST_Z_CAP, neginf=ROBUST_Z_CAP)
    return np.clip(z_scores, 0.0, ROBUST_Z_CAP, out=z_scores)


def robust_score(matrix, medians, scales, rule):
    """Score rows by their strongest robust deviations and count support.

    :param matrix: Matrix restricted to robust-eligible features.
    :param medians: Training feature medians.
    :param scales: Training feature scales.
    :param rule: Dataset rule with top_k, minimum_support and support_z.
    :returns: Top-k mean score and supporting-feature count per row.
    :rtype: tuple
    """
    rows = matrix.shape[0]
    scores = np.zeros(rows)
    supports = np.zeros(rows, dtype=int)
    top_k = min(rule["top_k"], matrix.shape[1])
    if top_k <= 0:
        return scores, supports
    matrix = matrix.tocsr()
    for start in range(0, rows, SCORE_BLOCK_ROWS):
        z_scores = _robust_z(matrix[start:start + SCORE_BLOCK_ROWS].toarray(), medians, scales)
        supports[start:start + len(z_scores)] = np.count_nonzero(z_scores >= rule["support_z"], axis=1)
        scores[start:start + len(z_scores)] = np.partition(z_scores, -top_k, axis=1)[:, -top_k:].mean(axis=1)
    return scores, supports


def robust_explain(matrix, names, medians, scales, rule, rows):
    """Explanation strings (strongest deviations) for the selected rows only.

    :param matrix: Matrix restricted to robust-eligible features.
    :param names: Ordered names matching the matrix columns.
    :param medians: Training feature medians.
    :param scales: Training feature scales.
    :param rule: Dataset rule with top_k.
    :param rows: Boolean mask of rows to explain.
    :returns: One explanation per row; unselected rows are empty.
    :rtype: numpy.ndarray
    """
    explanations = np.full(matrix.shape[0], "", dtype=object)
    top_k = min(rule["top_k"], matrix.shape[1])
    chosen_rows = np.flatnonzero(rows)
    if top_k <= 0 or not len(chosen_rows):
        return explanations
    matrix = matrix.tocsr()
    for start in range(0, len(chosen_rows), SCORE_BLOCK_ROWS):
        chosen = chosen_rows[start:start + SCORE_BLOCK_ROWS]
        z_scores = _robust_z(matrix[chosen].toarray(), medians, scales)
        order = np.argsort(-z_scores, axis=1, kind="stable")[:, :top_k]
        for row, values, top in zip(chosen, z_scores, order):
            explanations[row] = "; ".join(names[index] + "=" + format(values[index], ".4g")
                                          for index in top[:5] if values[index] > 0)
    return explanations


def fit_rarity(presence, training_rows):
    """Smoothed per-feature surprisal from presence counts over every training row.

    :param presence: Non-zero counts per rarity feature over the training split.
    :param training_rows: Number of training rows.
    :returns: Presence counts and surprisal values.
    :rtype: tuple
    """
    presence = np.asarray(presence, dtype=float)
    probability = (presence + RARE_FEATURE_ALPHA) / (training_rows + 2 * RARE_FEATURE_ALPHA)
    return presence, -np.log(np.clip(probability, 1e-15, 1.0))


def rarity_score(matrix, presence, surprisal):
    """Score rows by their rarest active feature and count unseen features.

    :param matrix: Matrix restricted to rarity-eligible features.
    :param presence: Training presence counts.
    :param surprisal: Training surprisal values.
    :returns: Highest surprisal and unseen-feature count per row.
    :rtype: tuple
    """
    matrix = matrix.tocsr()
    matrix.eliminate_zeros()
    rows = matrix.shape[0]
    scores = np.zeros(rows)
    unseen = np.zeros(rows, dtype=int)
    for start in range(0, rows, SCORE_BLOCK_ROWS * 10):
        block = matrix[start:start + SCORE_BLOCK_ROWS * 10]
        starts = block.indptr[:-1]
        nonempty = np.diff(block.indptr) > 0
        if not nonempty.any():
            continue
        targets = start + np.flatnonzero(nonempty)
        scores[targets] = np.maximum.reduceat(surprisal[block.indices], starts[nonempty])
        unseen[targets] = np.add.reduceat((presence[block.indices] == 0).astype(np.int64), starts[nonempty])
    return scores, unseen


def rarity_explain(matrix, names, presence, surprisal, rows):
    """Explanation strings (rarest active features) for the selected rows only.

    :param matrix: Matrix restricted to rarity-eligible features.
    :param names: Ordered names matching the matrix columns.
    :param presence: Training presence counts.
    :param surprisal: Training surprisal values.
    :param rows: Boolean mask of rows to explain.
    :returns: One explanation per row; unselected rows are empty.
    :rtype: numpy.ndarray
    """
    matrix = matrix.tocsr()
    matrix.eliminate_zeros()
    explanations = np.full(matrix.shape[0], "", dtype=object)
    for row in np.flatnonzero(rows):
        columns = matrix.indices[matrix.indptr[row]:matrix.indptr[row + 1]]
        if not len(columns):
            continue
        ordered = columns[np.argsort(-surprisal[columns], kind="stable")[:RARITY_TOP_N]]
        explanations[row] = "; ".join(
            names[index] + "=" + format(surprisal[index], ".4g")
            + ("(unseen_in_training)" if presence[index] == 0 else "")
            for index in ordered
        )
    return explanations


# =============================================================================
# Threshold selection
# =============================================================================

def validation_allowance(dataset, manifest, candidate_count):
    """Return the smaller of the daily operational budget and population cap.

    :param dataset: Dataset key in EXPERIMENTS.
    :param manifest: Validation manifest dataframe.
    :param candidate_count: Number of eligible validation candidates.
    :returns: Allowance counts, effective fraction and the binding source.
    :rtype: dict
    """
    _, timestamps = time_series(manifest)
    observed_days = int(timestamps.dropna().dt.floor("D").nunique())
    fraction = MAX_VALIDATION_ALERT_FRACTION[dataset]
    if candidate_count <= 0 or observed_days <= 0:
        return {
            "observed_days": observed_days,
            "allowed_alerts": 0,
            "daily_budget_alerts": 0,
            "population_cap_alerts": 0,
            "effective_alert_fraction": np.nan,
            "allowance_source": "no_eligible_validation_candidates",
        }
    daily_budget = max(
        int(TARGET_ALERTS_PER_DAY[dataset] * observed_days),
        MINIMUM_VALIDATION_ALERTS,
    )
    population_cap = max(
        int(np.floor(fraction * candidate_count)),
        MINIMUM_VALIDATION_ALERTS,
    )
    allowed = min(daily_budget, population_cap, candidate_count)
    return {
        "observed_days": observed_days,
        "allowed_alerts": int(allowed),
        "daily_budget_alerts": int(daily_budget),
        "population_cap_alerts": int(population_cap),
        "effective_alert_fraction": float(allowed / candidate_count),
        "allowance_source": (
            "validation_population_fraction_cap"
            if population_cap < daily_budget else "alerts_per_day_budget"
        ),
    }


def choose_threshold(dataset, scores, manifest, training_threshold, eligible=None):
    """Select a validation-budget threshold and deterministically break ties.

    :param dataset: Dataset key in EXPERIMENTS.
    :param scores: Validation scores for one detector channel.
    :param manifest: Validation manifest dataframe.
    :param training_threshold: Training-quantile threshold retained as a counterfactual.
    :param eligible: Optional boolean mask of usable validation candidates.
    :returns: Selected threshold, its source and the supporting budget metrics.
    :rtype: dict

    When the Nth score is tied and ``>= threshold`` would exceed the allowance,
    the deployable threshold moves to the next representable float. This
    accepts fewer than N alerts rather than silently exceeding the budget.
    """
    scores = np.asarray(scores, dtype=float)
    mask = (
        np.ones(len(scores), dtype=bool)
        if eligible is None else np.asarray(eligible, dtype=bool)
    )
    mask &= np.isfinite(scores)
    eligible_scores = scores[mask]
    allowance = validation_allowance(dataset, manifest, len(eligible_scores))
    minimum_candidates = MINIMUM_BUDGET_CANDIDATES[dataset]
    nominal = float(training_threshold)
    source = "training_quantile_fallback"
    if allowance["observed_days"] < MINIMUM_VALIDATION_DAYS_FOR_BUDGET:
        source = "training_quantile_fallback_too_few_validation_days"
    elif len(eligible_scores) < minimum_candidates:
        source = "training_quantile_fallback_too_few_candidates"
    elif allowance["allowed_alerts"] <= 0:
        source = "training_quantile_fallback_no_allowed_alerts"
    else:
        allowed = allowance["allowed_alerts"]
        index = len(eligible_scores) - allowed
        nominal = float(np.partition(eligible_scores, index)[index])
        source = allowance["allowance_source"]
    finite = np.isfinite(nominal)
    tied = int(np.count_nonzero(eligible_scores == nominal)) if finite else 0
    realized_nominal = (
        int(np.count_nonzero(eligible_scores >= nominal)) if finite else 0
    )
    deployable = nominal
    tie_adjusted = False
    if source in {"validation_population_fraction_cap", "alerts_per_day_budget"} and realized_nominal > allowance["allowed_alerts"]:
        deployable = float(np.nextafter(nominal, np.inf))
        tie_adjusted = True
    realized = (
        int(np.count_nonzero(eligible_scores >= deployable))
        if np.isfinite(deployable) else 0
    )
    if np.isfinite(training_threshold) and np.isfinite(deployable):
        floored = max(float(training_threshold), float(deployable))
    elif np.isfinite(training_threshold):
        floored = float(training_threshold)
    else:
        floored = float(deployable)
    selected = floored if TRAINING_QUANTILE_IS_FLOOR else deployable
    selected_source = source
    if tie_adjusted and not TRAINING_QUANTILE_IS_FLOOR:
        selected_source += "_tie_excluded"
    if TRAINING_QUANTILE_IS_FLOOR and selected > deployable:
        selected_source += "_raised_to_training_quantile"
    LOGGER.debug("%s threshold: selected=%.6g, source=%s, candidates=%s, allowed=%s",
                 dataset, selected, selected_source,
                 len(eligible_scores), allowance["allowed_alerts"])
    return {
        "selected": float(selected),
        "source": selected_source,
        "nominal_threshold": nominal,
        "budget_only": deployable,
        "training_quantile": float(training_threshold),
        "floored_counterfactual": floored,
        "eligible_candidates": int(len(eligible_scores)),
        "minimum_candidates_required": int(minimum_candidates),
        "threshold_tie_count": tied,
        "tie_adjusted": tie_adjusted,
        "realized_alerts_at_nominal_threshold": realized_nominal,
        "realized_selected_alerts": realized,
        "budget_overshoot": max(realized - allowance["allowed_alerts"], 0),
        **allowance,
    }


def detector_combination(robust, isolation, novelty):
    """Label each row with the combination of detectors that alerted.

    :param robust: Robust alert mask.
    :param isolation: Isolation Forest alert mask.
    :param novelty: Rarity alert mask.
    :returns: Combination labels, or not_alerted.
    :rtype: numpy.ndarray
    """
    return np.select(
        [
            robust & isolation & novelty,
            robust & isolation,
            robust & novelty,
            isolation & novelty,
            robust,
            isolation,
            novelty,
        ],
        REVIEW_COMBINATIONS,
        default="not_alerted",
    )


def build_scored(
    manifest,
    robust_scores,
    supports,
    robust_explanations,
    isolation_scores,
    robust_threshold,
    isolation_threshold,
    robust_rule,
    rarity_pack=None,
):
    """Attach detector scores, alert flags and explanations to a manifest.

    :param manifest: Split manifest dataframe.
    :param robust_scores: Robust deviation scores.
    :param supports: Robust supporting-feature counts.
    :param robust_explanations: Robust explanation strings.
    :param isolation_scores: Isolation Forest scores.
    :param robust_threshold: Selected robust threshold.
    :param isolation_threshold: Selected Isolation Forest threshold.
    :param robust_rule: Dataset rule with top_k, minimum_support and support_z.
    :param rarity_pack: Optional rarity scores, unseen counts, explanations and threshold.
    :returns: Scored dataframe with per-detector and combined alert columns.
    :rtype: pandas.DataFrame
    """
    result = manifest.copy().reset_index(drop=True)
    robust_alert = (
        (robust_scores >= robust_threshold)
        & (supports >= robust_rule["minimum_support"])
    )
    isolation_alert = isolation_scores >= isolation_threshold
    result["robust_score"] = robust_scores
    result["robust_supporting_feature_count"] = supports
    result["robust_alert"] = robust_alert
    result["robust_explanation"] = robust_explanations
    result["isolation_score"] = isolation_scores
    result["isolation_alert"] = isolation_alert
    if rarity_pack is not None:
        novelty_scores, unseen, novelty_explanations, novelty_threshold = rarity_pack
        novelty_alert = novelty_scores >= novelty_threshold
        result["novelty_score"] = novelty_scores
        result["novelty_unseen_feature_count"] = unseen
        result["novelty_explanation"] = novelty_explanations
        result["novelty_alert"] = novelty_alert
    else:
        novelty_alert = np.zeros(len(result), dtype=bool)
        result["novelty_score"] = 0.0
        result["novelty_unseen_feature_count"] = 0
        result["novelty_explanation"] = ""
        result["novelty_alert"] = False
    result["either_model_alert"] = robust_alert | isolation_alert | novelty_alert
    result["detector_combination"] = detector_combination(
        robust_alert, isolation_alert, novelty_alert
    )
    result["alert_tier"] = result["detector_combination"]
    return result


def detector_status(threshold_result, validation_alerts, test_alerts, feature_count):
    """Classify a detector as calibrated, fallback, inactive or invalid.

    :param threshold_result: Threshold selection result for the detector.
    :param validation_alerts: Realized validation alert count.
    :param test_alerts: Realized test alert count.
    :param feature_count: Number of features available to the detector.
    :returns: Calibration status label.
    :rtype: str
    """
    if feature_count <= 0:
        return "inactive_no_features"
    threshold = threshold_result.get("selected", np.nan)
    if not np.isfinite(threshold):
        return "inactive_nonfinite_threshold"
    if threshold_result.get("eligible_candidates", 0) <= 0:
        return "inactive_no_validation_candidates"
    source = str(threshold_result.get("source", ""))
    if source.startswith("training_quantile_fallback"):
        if validation_alerts == 0 and test_alerts == 0:
            return "inactive_training_fallback_no_alerts"
        return "training_fallback"
    if threshold_result.get("budget_overshoot", 0) > 0:
        return "invalid_budget_overshoot"
    if validation_alerts != threshold_result.get("realized_selected_alerts"):
        return "invalid_realized_count_mismatch"
    return "calibrated"


# =============================================================================
# Alert reporting
# =============================================================================

def leading_feature(value):
    """Extract the first feature name from an explanation string.

    :param value: Explanation string.
    :returns: Leading feature name, or empty text.
    :rtype: str
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    return value.split(";")[0].split("=")[0].strip()


def explanation_attribution(result, output):
    """Count the dominant explanation features for each alert population.

    :param result: Scored test dataframe.
    :param output: Dataset output directory.
    :returns: Attribution counts and shares per population and channel.
    :rtype: pandas.DataFrame
    """
    masks = {
        "robust_alerts": result["robust_alert"],
        "isolation_only_alerts": result["isolation_alert"] & ~result["robust_alert"],
        "novelty_only_alerts": (
            result["novelty_alert"]
            & ~result["robust_alert"]
            & ~result["isolation_alert"]
        ),
        "all_alerts": result["either_model_alert"],
    }
    rows = []
    for population, mask in masks.items():
        for column in ("robust_explanation", "novelty_explanation"):
            features = [
                leading_feature(value)
                for value in result.loc[mask, column].fillna("")
            ]
            features = [value for value in features if value]
            counts = Counter(features)
            total = len(features)
            for feature, count in counts.most_common(10):
                rows.append({
                    "population": population,
                    "explanation_channel": column,
                    "feature_name": feature,
                    "alert_count": count,
                    "share": count / total if total else np.nan,
                })
    frame = pd.DataFrame(rows)
    frame.to_csv(output / "test_explanation_attribution.csv", index=False)
    return frame


def entity_concentration(result, output):
    """Measure how far test alerts concentrate on individual entities.

    :param result: Scored test dataframe.
    :param output: Dataset output directory.
    :returns: One row per available entity column.
    :rtype: pandas.DataFrame
    """
    alerts = result.loc[result["either_model_alert"]].copy()
    rows = []
    _, timestamps = time_series(result)
    days = int(timestamps.dt.floor("D").nunique())
    for column in ENTITY_COLUMNS:
        if column not in result.columns or not result[column].notna().any():
            continue
        counts = alerts[column].fillna("__missing__").astype(str).value_counts()
        total = int(counts.sum())
        rows.append({
            "entity_column": column,
            "alerting_entities": int(len(counts)),
            "alerts": total,
            "top_entity_alert_share": counts.head(1).sum() / total if total else np.nan,
            "top_5_entity_alert_share": counts.head(5).sum() / total if total else np.nan,
            "maximum_alerts_single_entity": int(counts.iloc[0]) if total else 0,
            "alerts_per_day": total / days if days else np.nan,
        })
    frame = pd.DataFrame(rows)
    frame.to_csv(output / "test_entity_concentration.csv", index=False)
    return frame


# =============================================================================
# Evidence resolution
# =============================================================================

@timed_stage
def load_lineage_for_alerts(feature_folder, alert_ids):
    """Load exact event lineage for alerted observations from all splits.

    :param feature_folder: Dataset feature folder containing split lineage files.
    :param alert_ids: Observation IDs that alerted on test data.
    :returns: Sorted lineage rows for the requested observations.
    :rtype: pandas.DataFrame
    :raises ValueError: If lineage links, positions or coverage are invalid.
    :raises FileNotFoundError: If a required split lineage file is absent.
    """
    alert_ids = {str(value).strip() for value in alert_ids if str(value).strip()}
    frames = []
    missing_files = []
    for filename in LINEAGE_FILES:
        path = feature_folder / filename
        if not path.is_file():
            missing_files.append(str(path))
            continue
        required = {"row_manifest_id", "event_id", "event_position"}
        missing = required.difference(pd.read_csv(path, nrows=0).columns)
        if missing:
            raise ValueError(
                "Lineage file lacks columns in " + str(path) + ": "
                + ", ".join(sorted(missing))
            )
        chunks = pd.read_csv(path, dtype={"row_manifest_id": str, "event_id": str},
                             chunksize=CSV_CHUNK_ROWS, low_memory=False)
        for frame in chunks:
            frame["row_manifest_id"] = frame["row_manifest_id"].fillna("").astype(str).str.strip()
            frame = frame.loc[frame["row_manifest_id"].isin(alert_ids)].copy()
            if len(frame):
                frame["event_id"] = frame["event_id"].fillna("").astype(str).str.strip()
                frame["lineage_source_file"] = filename
                frames.append(frame)
    if missing_files and REQUIRE_LINEAGE:
        raise FileNotFoundError("Missing split lineage files: " + "; ".join(missing_files))
    if not frames:
        if alert_ids and REQUIRE_LINEAGE:
            raise ValueError("No lineage rows found for alerted OSSEC observations")
        return pd.DataFrame(columns=["row_manifest_id", "event_id", "event_position"])
    lineage = pd.concat(frames, ignore_index=True, sort=False)
    duplicate_links = lineage.duplicated(["row_manifest_id", "event_id"], keep=False)
    if duplicate_links.any():
        raise ValueError("Duplicate OSSEC observation-to-event lineage links found")
    positions = pd.to_numeric(lineage["event_position"], errors="coerce")
    if positions.isna().any() or positions.lt(1).any():
        raise ValueError("Invalid OSSEC lineage event_position values")
    lineage["event_position"] = positions.astype(int)
    missing_alerts = alert_ids - set(lineage["row_manifest_id"])
    if missing_alerts and REQUIRE_LINEAGE:
        raise ValueError(
            "Alert observations without lineage: " + str(len(missing_alerts))
            + "; examples=" + ", ".join(sorted(missing_alerts)[:10])
        )
    LOGGER.debug("Alert lineage rows loaded: %s for %s observations",
                 f"{len(lineage):,}", f"{len(alert_ids):,}")
    return lineage.sort_values(
        ["row_manifest_id", "event_position", "event_id"], kind="stable"
    ).reset_index(drop=True)


@timed_stage
def load_event_lookup_subset(event_ids):
    """Load only the required classified OSSEC events from the lookup.

    :param event_ids: Event IDs referenced by alert lineage.
    :returns: Lookup rows for the requested events.
    :rtype: pandas.DataFrame
    :raises ValueError: If the lookup duplicates or omits required events.
    :raises FileNotFoundError: If a required lookup file is absent.
    """
    event_ids = {str(value).strip() for value in event_ids if str(value).strip()}
    if not EVENT_LOOKUP_FILE.is_file():
        if REQUIRE_COMPLETE_EVENT_LOOKUP:
            raise FileNotFoundError("OSSEC event lookup is missing: " + str(EVENT_LOOKUP_FILE))
        LOGGER.warning("Optional OSSEC event lookup not found: %s", EVENT_LOOKUP_FILE)
        return pd.DataFrame(columns=["event_id"])
    header = pd.read_csv(EVENT_LOOKUP_FILE, nrows=0)
    if "event_id" not in header.columns:
        raise ValueError("event_id missing from OSSEC event lookup")
    preferred = [
        "event_id", "raw_line_sha256", "timestamp", "partition_month",
        "hostname", "process_name", "pid", "severity", "event_type",
        "username", "source_ip", "source_port", "destination_hostname",
        "destination_ip", "destination_port", "agent_name", "reason",
        "raw_message", "original_log_line", "classification_line",
        "source_file", "source_line", "archive_name", "archive_member",
    ]
    usecols = [column for column in preferred if column in header.columns]
    frames = []
    seen = set()
    chunks = pd.read_csv(
        EVENT_LOOKUP_FILE,
        usecols=usecols,
        chunksize=EVENT_LOOKUP_CHUNK_ROWS,
        low_memory=False,
    )
    for chunk in progress_items(chunks, "Event lookup chunks scanned"):
        chunk["event_id"] = chunk["event_id"].fillna("").astype(str).str.strip()
        selected = chunk.loc[chunk["event_id"].isin(event_ids)].copy()
        if selected.empty:
            continue
        duplicates = set(selected.loc[selected["event_id"].duplicated(keep=False), "event_id"])
        repeated = seen.intersection(set(selected["event_id"]))
        if duplicates or repeated:
            raise ValueError(
                "Duplicate event IDs in OSSEC event lookup: "
                + ", ".join(sorted(duplicates | repeated)[:10])
            )
        seen.update(selected["event_id"])
        frames.append(selected)
    lookup = (
        pd.concat(frames, ignore_index=True, sort=False)
        if frames else pd.DataFrame(columns=usecols)
    )
    missing = event_ids - set(lookup["event_id"])
    if missing and REQUIRE_COMPLETE_EVENT_LOOKUP:
        raise ValueError(
            "Lineage events missing from OSSEC event lookup: "
            + str(len(missing)) + "; examples="
            + ", ".join(sorted(missing)[:10])
        )
    return lookup


def compact_message(value):
    """Collapse whitespace in one original log line.

    :param value: Raw log line or message.
    :returns: Single-line text, or empty text for missing values.
    :rtype: str
    """
    if pd.isna(value):
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


@timed_stage
def attach_alert_evidence(dataset, result, feature_folder, output):
    """Expand test alerts to exact source events and attach review summaries.

    :param dataset: Dataset key in EXPERIMENTS.
    :param result: Scored test dataframe.
    :param feature_folder: Dataset feature folder containing split lineage files.
    :param output: Dataset output directory.
    :returns: Enriched result, raw evidence rows and evidence coverage metrics.
    :rtype: tuple
    :raises ValueError: If lineage or lookup coverage is incomplete.
    """
    validate_manifest_identity(result, dataset + "/test")
    alerts = result.loc[result["either_model_alert"]].copy()
    evidence_path = output / "test_raw_alert_evidence.csv"
    summary_path = output / "test_alert_evidence_summary.csv"
    if alerts.empty:
        LOGGER.info("%s: no test alerts, evidence export skipped", dataset)
        pd.DataFrame().to_csv(evidence_path, index=False)
        pd.DataFrame().to_csv(summary_path, index=False)
        return result, pd.DataFrame(), {
            "evidence_status": "no_alerts",
            "alert_observations": 0,
            "alerts_with_complete_evidence": 0,
            "alerts_with_partial_evidence": 0,
            "alerts_without_evidence": 0,
            "raw_evidence_rows": 0,
        }
    lineage = load_lineage_for_alerts(
        feature_folder, alerts["row_manifest_id"].tolist()
    )
    lookup = load_event_lookup_subset(set(lineage["event_id"]))
    evidence = lineage.merge(
        lookup,
        on="event_id",
        how="left",
        validate="many_to_one",
        indicator=True,
        suffixes=("_lineage", ""),
    )
    evidence["event_lookup_found"] = evidence["_merge"].eq("both")
    evidence = evidence.drop(columns=["_merge"])
    alert_columns = [
        column for column in (
            "row_manifest_id", "detector_combination", "alert_tier",
            "robust_score", "robust_alert", "robust_explanation",
            "isolation_score", "isolation_alert", "novelty_score",
            "novelty_alert", "novelty_explanation", "host_id", "hostname",
            "agent_name", "episode_id", "process_name", "event_category",
        ) if column in alerts.columns
    ]
    evidence = evidence.merge(
        alerts[alert_columns],
        on="row_manifest_id",
        how="left",
        validate="many_to_one",
    )
    # Split lineage already contains a dataset column. Assign canonically
    # instead of calling DataFrame.insert(), which fails when it already exists.
    evidence["dataset"] = dataset
    leading_columns = ["dataset"]
    remaining_columns = [
        column for column in evidence.columns if column not in leading_columns
    ]
    evidence = evidence[leading_columns + remaining_columns]
    evidence = evidence.sort_values(
        ["row_manifest_id", "event_position", "event_id"], kind="stable"
    ).reset_index(drop=True)
    evidence.to_csv(evidence_path, index=False)

    evidence["__message"] = evidence.get(
        "original_log_line",
        evidence.get("raw_message", pd.Series("", index=evidence.index)),
    ).map(compact_message)
    if "timestamp" in evidence.columns:
        evidence["__time"] = pd.to_datetime(
            evidence["timestamp"], errors="coerce", utc=True
        )
    else:
        evidence["__time"] = pd.to_datetime(
            evidence.get("event_timestamp"), errors="coerce", utc=True
        )
    summary_rows = []
    groups = evidence.groupby("row_manifest_id", sort=False)
    for row_id, group in progress_items(groups, dataset + " alert evidence chains summarized"):
        ordered = group.sort_values(
            ["event_position", "event_id"], kind="stable"
        )
        found = ordered["event_lookup_found"].astype(bool)
        messages = [
            value for value in ordered.loc[found, "__message"].tolist() if value
        ]
        preview = " || ".join(messages[:RAW_EVIDENCE_PREVIEW_MESSAGES])
        if len(preview) > RAW_EVIDENCE_PREVIEW_CHARACTERS:
            preview = preview[:RAW_EVIDENCE_PREVIEW_CHARACTERS] + "..."
        total_count = int(len(ordered))
        found_count = int(found.sum())
        missing_count = total_count - found_count
        status = (
            "complete" if total_count and missing_count == 0 else
            "partial" if found_count else "missing"
        )
        times = ordered.loc[found, "__time"].dropna()
        summary_rows.append({
            "row_manifest_id": row_id,
            "raw_evidence_count": total_count,
            "raw_evidence_found_count": found_count,
            "raw_evidence_missing_count": missing_count,
            "evidence_first_timestamp": str(times.min()) if len(times) else "",
            "evidence_last_timestamp": str(times.max()) if len(times) else "",
            "first_original_log_line": messages[0] if messages else "",
            "last_original_log_line": messages[-1] if messages else "",
            "representative_original_log_lines": preview,
            "evidence_status": status,
            "evidence_file": str(evidence_path),
        })
    summary = pd.DataFrame(summary_rows)
    summary.to_csv(summary_path, index=False)
    enriched = result.merge(
        summary, on="row_manifest_id", how="left", validate="one_to_one"
    )
    enriched["evidence_status"] = enriched["evidence_status"].fillna("not_alerted")
    complete = int(summary["evidence_status"].eq("complete").sum())
    partial = int(summary["evidence_status"].eq("partial").sum())
    missing = int(summary["evidence_status"].eq("missing").sum())
    LOGGER.info("%s: alerts=%s, evidence rows=%s, complete=%s, partial=%s, missing=%s",
                dataset, f"{len(alerts):,}", f"{len(evidence):,}",
                complete, partial, missing)
    return enriched, evidence.drop(columns=["__message", "__time"], errors="ignore"), {
        "evidence_status": "complete" if partial == 0 and missing == 0 else "partial",
        "alert_observations": int(len(alerts)),
        "alerts_with_complete_evidence": complete,
        "alerts_with_partial_evidence": partial,
        "alerts_without_evidence": missing,
        "raw_evidence_rows": int(len(evidence)),
        "raw_evidence_lookup_matches": int(evidence["event_lookup_found"].sum()),
        "unique_evidence_events": int(
            evidence.loc[evidence["event_lookup_found"], "event_id"].nunique()
        ),
        "event_lookup_file": str(EVENT_LOOKUP_FILE),
    }


# =============================================================================
# Review queues and labelled precision
# =============================================================================

@timed_stage
def review_queue(dataset, result, raw_evidence, output):
    """Sample an independent review bucket for each detector combination.

    :param dataset: Dataset key in EXPERIMENTS.
    :param result: Scored test dataframe.
    :param raw_evidence: Raw alert evidence rows.
    :param output: Dataset output directory.
    :returns: Population and sample counts per review bucket.
    :rtype: dict
    """
    per_bucket = REVIEW_BUCKET_SIZE[dataset]
    pieces = []
    counts = {"review_bucket_target": per_bucket}
    for combination in REVIEW_COMBINATIONS:
        population = result.loc[
            result["detector_combination"].eq(combination)
        ].copy()
        sort_columns = [
            column for column in
            ("robust_score", "isolation_score", "novelty_score")
            if column in population.columns
        ]
        sample = (
            population.sort_values(sort_columns, ascending=False).head(per_bucket)
            if len(population) else population
        )
        sample["review_bucket"] = combination
        pieces.append(sample)
        counts["review_population_" + combination] = int(len(population))
        counts["review_sampled_" + combination] = int(len(sample))
    queue = (
        pd.concat(pieces, ignore_index=True)
        if pieces else pd.DataFrame(columns=result.columns)
    )
    if "row_manifest_id" in queue.columns:
        queue = queue.drop_duplicates(subset=["row_manifest_id"]).reset_index(drop=True)
    queue["review_label"] = ""
    queue["review_category"] = ""
    queue["review_notes"] = ""
    queue["reviewer"] = ""
    queue["reviewed_at"] = ""
    queue.to_csv(output / "manual_review_queue.csv", index=False)
    review_ids = set(queue.get("row_manifest_id", pd.Series(dtype=str)).astype(str))
    review_evidence = (
        raw_evidence.loc[raw_evidence["row_manifest_id"].astype(str).isin(review_ids)].copy()
        if len(raw_evidence) else raw_evidence.copy()
    )
    review_evidence.to_csv(output / "manual_review_event_evidence.csv", index=False)
    if dataset == "episodes":
        queue.to_csv(output / "episodes_final_review_queue.csv", index=False)
    counts["review_total_sampled"] = int(len(queue))
    final_counts = queue["review_bucket"].value_counts().to_dict() if len(queue) else {}
    for combination in REVIEW_COMBINATIONS:
        counts["review_final_" + combination] = int(final_counts.get(combination, 0))
    LOGGER.debug("%s review queue: %s sampled rows", dataset, len(queue))
    return counts


def precision_from_labels(dataset, output):
    """Estimate alert precision from any completed manual review labels.

    :param dataset: Dataset key in EXPERIMENTS.
    :param output: Dataset output directory used for the label template path.
    :returns: Review counts, estimated precision and label status.
    :rtype: dict
    """
    path = LABEL_FOLDER / (dataset + "_review_labels.csv")
    blank = {
        "reviewed_rows": 0,
        "meaningful_rows": 0,
        "data_quality_rows": 0,
        "estimated_precision": np.nan,
        "meets_relevance_target": False,
        "relevance_target": TARGET_RELEVANCE,
    }
    if not path.is_file():
        return {
            **blank,
            "label_status": "awaiting_labels",
            "label_template": str(output / "manual_review_queue.csv"),
        }
    labels = pd.read_csv(path, low_memory=False)
    if "review_label" not in labels.columns:
        return {**blank, "label_status": "invalid_missing_review_label"}
    normalized = labels["review_label"].fillna("").astype(str).str.strip().str.lower()
    reviewed = normalized.isin(VALID_REVIEW_LABELS)
    meaningful = normalized.isin(MEANINGFUL_LABELS) & reviewed
    data_quality = normalized.eq(DATA_QUALITY_LABEL) & reviewed
    reviewed_count = int(reviewed.sum())
    meaningful_count = int(meaningful.sum())
    data_quality_count = int(data_quality.sum())
    result = {
        "reviewed_rows": reviewed_count,
        "meaningful_rows": meaningful_count,
        "data_quality_rows": data_quality_count,
        "estimated_precision": (
            meaningful_count / reviewed_count if reviewed_count else np.nan
        ),
        "estimated_precision_including_data_quality": (
            (meaningful_count + data_quality_count) / reviewed_count
            if reviewed_count else np.nan
        ),
        "meets_relevance_target": bool(
            reviewed_count
            and meaningful_count / reviewed_count >= TARGET_RELEVANCE
        ),
        "relevance_target": TARGET_RELEVANCE,
        "label_status": "complete" if reviewed_count else "no_valid_labels",
    }
    if "review_bucket" in labels.columns:
        buckets = labels["review_bucket"].fillna("").astype(str).str.strip().str.lower()
        for bucket in REVIEW_COMBINATIONS:
            selected = buckets.eq(bucket) & reviewed
            count = int(selected.sum())
            positives = int((selected & meaningful).sum())
            result["reviewed_" + bucket] = count
            result["precision_" + bucket] = positives / count if count else np.nan
    return result


def correlation(left, right):
    """Calculate a Spearman rank correlation between two score arrays.

    :param left: First score array.
    :param right: Second score array.
    :returns: Correlation statistic, or NaN when undefined.
    :rtype: float
    """
    if len(left) < 2 or np.unique(left).size < 2 or np.unique(right).size < 2:
        return np.nan
    value = stats.spearmanr(left, right, nan_policy="omit").statistic
    return float(value) if np.isfinite(value) else np.nan


def matrix_stats(matrix, prefix):
    """Summarize matrix shape, sparsity and per-row density.

    :param matrix: Sparse feature matrix.
    :param prefix: Metric name prefix, usually the split name.
    :returns: Prefixed shape and density metrics.
    :rtype: dict
    """
    total = matrix.shape[0] * matrix.shape[1]
    return {
        prefix + "_rows": int(matrix.shape[0]),
        prefix + "_features": int(matrix.shape[1]),
        prefix + "_nonzero": int(matrix.nnz),
        prefix + "_density": matrix.nnz / total if total else 0.0,
        prefix + "_nonzero_per_row": (
            matrix.nnz / matrix.shape[0] if matrix.shape[0] else 0.0
        ),
    }


# =============================================================================
# Experiment execution
# =============================================================================

def sample_rows(total, sample_size):
    """Choose sorted training row indices for the in-memory sample.

    :param total: Training rows in the split.
    :param sample_size: Requested sample size.
    :returns: Sorted row indices (every row when the split is small enough).
    :rtype: numpy.ndarray
    """
    if total <= sample_size:
        return np.arange(total)
    return np.sort(np.random.default_rng(RANDOM_STATE).choice(total, sample_size, replace=False))


def score_split(matrix, fitted, rule):
    """Score one split with all three detectors (no explanations).

    :param matrix: Split matrix restricted to policy-selected features.
    :param fitted: Fitted detector state from run_experiment.
    :param rule: Robust rule for the dataset.
    :returns: Robust scores and support, Isolation Forest scores, rarity scores and unseen counts.
    :rtype: dict
    """
    rows = matrix.shape[0]
    if len(fitted["robust_indices"]):
        robust, support = robust_score(matrix[:, fitted["robust_indices"]],
                                       fitted["medians"], fitted["scales"], rule)
    else:
        robust, support = np.zeros(rows), np.zeros(rows, dtype=int)
    isolation = -fitted["model"].score_samples(matrix[:, fitted["isolation_indices"]])
    if len(fitted["rarity_indices"]):
        rarity, unseen = rarity_score(matrix[:, fitted["rarity_indices"]],
                                      fitted["presence"], fitted["surprisal"])
    else:
        rarity, unseen = None, None
    return {"robust": robust, "support": support, "isolation": isolation,
            "rarity": rarity, "unseen": unseen}


def alert_mask(scores, thresholds, rule):
    """Rows that alert on at least one detector.

    :param scores: Output of score_split.
    :param thresholds: Selected robust, isolation and novelty thresholds.
    :param rule: Robust rule for the dataset.
    :returns: Boolean mask.
    :rtype: numpy.ndarray
    """
    mask = ((scores["robust"] >= thresholds["robust"]) & (scores["support"] >= rule["minimum_support"]))
    mask |= scores["isolation"] >= thresholds["isolation"]
    if scores["rarity"] is not None:
        mask |= scores["rarity"] >= thresholds["novelty"]
    return mask


def explain_split(matrix, fitted, rule, scores, thresholds):
    """Robust and rarity explanations for rows alerting on any detector.

    :param matrix: Split matrix restricted to policy-selected features.
    :param fitted: Fitted detector state from run_experiment.
    :param rule: Robust rule for the dataset.
    :param scores: Output of score_split.
    :param thresholds: Selected robust, isolation and novelty thresholds.
    :returns: Robust and novelty explanation arrays.
    :rtype: tuple
    """
    rows = alert_mask(scores, thresholds, rule)
    robust_text = np.full(matrix.shape[0], "", dtype=object)
    novelty_text = np.full(matrix.shape[0], "", dtype=object)
    if len(fitted["robust_indices"]):
        robust_text = robust_explain(matrix[:, fitted["robust_indices"]], fitted["robust_names"],
                                     fitted["medians"], fitted["scales"], rule, rows)
    if scores["rarity"] is not None:
        novelty_text = rarity_explain(matrix[:, fitted["rarity_indices"]], fitted["rarity_names"],
                                      fitted["presence"], fitted["surprisal"], rows)
    return robust_text, novelty_text


def scored_split(manifest, scores, explanations, thresholds, rule):
    """Attach one split's detector columns to its manifest.

    :param manifest: Split manifest dataframe.
    :param scores: Output of score_split.
    :param explanations: Robust and novelty explanation arrays.
    :param thresholds: Selected robust, isolation and novelty thresholds.
    :param rule: Robust rule for the dataset.
    :returns: Scored dataframe.
    :rtype: pandas.DataFrame
    """
    robust_text, novelty_text = explanations
    rarity_pack = None
    if scores["rarity"] is not None:
        rarity_pack = (scores["rarity"], scores["unseen"], novelty_text, thresholds["novelty"])
    return build_scored(manifest, scores["robust"], scores["support"], robust_text,
                        scores["isolation"], thresholds["robust"], thresholds["isolation"],
                        rule, rarity_pack)


def load_split_matrix(source, split_name, selected_indices, selected_names, rows=None, count_presence=False):
    """Stream one split matrix, keep policy-selected columns and cap ratio features.

    :param source: Dataset feature folder.
    :param split_name: Train, validation or test split name.
    :param selected_indices: Policy-selected feature indices.
    :param selected_names: Names of the selected features.
    :param rows: Optional sorted row indices to keep.
    :param count_presence: Count per-feature presence over every row.
    :returns: Capped matrix, total rows, presence counts and capped feature names.
    :rtype: tuple
    """
    with stage(f"{source.name}: stream {split_name} matrix"):
        matrix, total, presence = load_sparse(source / ("X_" + split_name + ".npz"),
                                              selected_indices, rows=rows,
                                              count_presence=count_presence)
    matrix, capped = cap_ratio_features(matrix, selected_names)
    return matrix, total, presence, capped


@timed_stage
def run_experiment(dataset):
    """Evaluate one OSSEC representation and write its artifacts and summary.

    :param dataset: Dataset key in EXPERIMENTS.
    :returns: Experiment summary written to summary.json.
    :rtype: dict
    :raises ValueError: If artifacts, features or identities fail validation.
    :raises FileNotFoundError: If a required artifact is absent.
    """
    started = time.perf_counter()
    source = FEATURE_FOLDER / dataset
    output = OUTPUT_FOLDER / dataset
    output.mkdir(parents=True, exist_ok=True)
    feature_metadata = validate_feature_artifacts(source, dataset)
    feature_names = pd.read_csv(
        source / "feature_names.csv", low_memory=False
    )["feature_name"].astype(str).tolist()
    if len(feature_names) != len(set(feature_names)):
        raise ValueError("Duplicate feature names for " + dataset)

    selected_indices, audit = feature_policy(dataset, feature_names)
    selected_names = [feature_names[index] for index in selected_indices]
    audit.to_csv(output / "feature_policy_audit.csv", index=False)

    with stage(dataset + ": load manifests"):
        light_columns = set(TIME_COLUMNS) | set(ENTITY_COLUMNS)
        train_manifest = load_manifest(source, "train", light_columns)
        validation_manifest = load_manifest(source, "validation")
        test_manifest = load_manifest(source, "test")
    train_total = matrix_rows(source / "X_train.npz")
    if train_total != len(train_manifest):
        raise ValueError("train matrix/manifest row mismatch")
    split_diagnostics(
        dataset,
        [
            ("train", len(feature_names), train_manifest),
            ("validation", len(feature_names), validation_manifest),
            ("test", len(feature_names), test_manifest),
        ],
        output,
    )
    del train_manifest
    temporal_valid, temporal_reasons, temporal = temporal_split_valid(
        dataset, validation_manifest, test_manifest
    )
    write_json(output / "temporal_coverage_validation.json", {
        "valid": temporal_valid,
        "reasons": temporal_reasons,
        **temporal,
    })
    if not temporal_valid:
        LOGGER.warning("%s temporal coverage invalid: %s",
                       dataset, "|".join(temporal_reasons))

    sample = sample_rows(train_total, TRAIN_SAMPLE)
    in_windows = train_rows_in_change_windows(source)    # approved change windows never teach "normal"
    if len(in_windows):
        sample = np.setdiff1d(sample, in_windows)
        LOGGER.info("%s: %s training rows fall in approved change windows and are left out", dataset, f"{len(in_windows):,}")
    LOGGER.info("%s: streaming training matrix (%s rows, keeping %s)",
                dataset, f"{train_total:,}", f"{len(sample):,}")
    train, _, presence_all, capped = load_split_matrix(
        source, "train", selected_indices, selected_names, rows=sample, count_presence=True)

    diagnostics = inspect_features(train, selected_names)
    diagnostics.to_csv(output / "feature_spread_diagnostics.csv", index=False)
    channels = np.asarray([channel_of(name) for name in selected_names])
    roles = diagnostics["role"].to_numpy()
    model_allowed = np.isin(
        channels, MODEL_CHANNELS.get(dataset, DEFAULT_MODEL_CHANNELS)
    )
    robust_indices = np.flatnonzero(
        model_allowed & (roles == "robust_continuous")
    )
    rarity_allowed = (
        np.isin(channels, NOVELTY_CHANNELS.get(dataset, ()))
        | (roles == "rarity")
    )
    rarity_indices = np.flatnonzero(
        rarity_allowed & (roles != "excluded")
    )
    # Hash buckets and flags that never vary in training carry no signal for
    # the Isolation Forest (the one-hot encoder never created such columns);
    # they stay in the rarity channel, where a first appearance is a novelty.
    varying = diagnostics.get("distinct_values", pd.Series(0, index=diagnostics.index)).fillna(0).to_numpy() > 1
    isolation_indices = np.flatnonzero(
        model_allowed & (roles != "excluded") & varying
    )
    if not len(isolation_indices):
        raise ValueError("No Isolation Forest features selected for " + dataset)

    pd.DataFrame({
        "feature_name": [selected_names[index] for index in isolation_indices],
        "role": roles[isolation_indices],
        "channel": channels[isolation_indices],
    }).to_csv(output / "selected_model_features.csv", index=False)

    rows_per_feature = train_total / len(isolation_indices)
    status = (
        "skipped_insufficient_temporal_coverage"
        if SKIP_INVALID_TEMPORAL_COVERAGE and not temporal_valid else
        "skipped_too_few_training_rows"
        if train_total < MINIMUM_TRAIN_ROWS else
        "skipped_insufficient_rows_per_feature"
        if rows_per_feature < SKIP_ROWS_PER_FEATURE_BELOW else
        "warning_low_rows_per_feature"
        if rows_per_feature < WARN_ROWS_PER_FEATURE_BELOW else
        "acceptable_for_evaluation"
    )
    summary = {
        "dataset": dataset,
        "status": status,
        "feature_artifact_contract": feature_metadata.get("feature_artifact_contract"),
        "feature_engineer_version": feature_metadata.get("feature_engineer_version"),
        "temporal_coverage_valid": temporal_valid,
        "temporal_coverage_reasons": "|".join(temporal_reasons),
        "validation_test_daily_rate_ratio": temporal["validation_test_daily_rate_ratio"],
        "validation_observed_days": temporal["validation"]["observed_days"],
        "test_observed_days": temporal["test"]["observed_days"],
        "original_features": len(feature_names),
        "policy_selected_features": len(selected_indices),
        "selected_features": len(isolation_indices),
        "robust_continuous_features": len(robust_indices),
        "rarity_features": len(rarity_indices),
        "rows_per_feature": rows_per_feature,
        "capped_ratio_features": capped,
        **matrix_stats(train[:, isolation_indices], "train_sample"),
        "train_rows": train_total,
        "train_features": len(isolation_indices),
        "validation_rows": len(validation_manifest),
        "test_rows": len(test_manifest),
    }
    if status.startswith("skipped"):
        LOGGER.warning("%s: %s", dataset, status)
        summary["total_seconds"] = time.perf_counter() - started
        write_json(output / "summary.json", summary)
        return summary

    robust_rule = dict(ROBUST_RULES[dataset])
    robust_names = [selected_names[index] for index in robust_indices]
    if len(robust_indices):
        medians, scales = fit_robust(train[:, robust_indices])
    else:
        LOGGER.warning("%s: no robust continuous features available", dataset)
        medians, scales = np.asarray([]), np.asarray([])
    isolation_model = IsolationForest(
        n_estimators=ISOLATION_TREES,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        max_features=min(1.0, 100 / max(len(isolation_indices), 1)),
    )
    with stage(dataset + ": fit IsolationForest (" + str(ISOLATION_TREES) + " trees, "
               + f"{train.shape[0]:,} rows)"):
        isolation_model.fit(train[:, isolation_indices])
    rarity_names = [selected_names[index] for index in rarity_indices]
    presence, surprisal = (fit_rarity(presence_all[rarity_indices], train_total)
                           if len(rarity_indices) else (None, None))
    fitted = {
        "robust_indices": robust_indices, "robust_names": robust_names,
        "medians": medians, "scales": scales, "model": isolation_model,
        "isolation_indices": isolation_indices, "rarity_indices": rarity_indices,
        "rarity_names": rarity_names, "presence": presence, "surprisal": surprisal,
    }
    with stage(dataset + ": score training sample"):
        train_scores = score_split(train, fitted, robust_rule)
    del train

    eligible_training = train_scores["support"] >= robust_rule["minimum_support"]
    robust_training_threshold = (
        float(np.quantile(train_scores["robust"][eligible_training], BASELINE_QUANTILE))
        if len(robust_indices) and eligible_training.any() else float("inf")
    )
    isolation_training_threshold = float(np.quantile(train_scores["isolation"], BASELINE_QUANTILE))
    rarity_training_threshold = (
        float(np.quantile(train_scores["rarity"], BASELINE_QUANTILE))
        if train_scores["rarity"] is not None else float("inf")
    )

    validation, _, _, _ = load_split_matrix(source, "validation", selected_indices, selected_names)
    if validation.shape[0] != len(validation_manifest):
        raise ValueError("validation matrix/manifest row mismatch")
    with stage(dataset + ": score validation"):
        validation_scores = score_split(validation, fitted, robust_rule)
    robust_threshold = choose_threshold(
        dataset,
        validation_scores["robust"],
        validation_manifest,
        robust_training_threshold,
        validation_scores["support"] >= robust_rule["minimum_support"],
    )
    isolation_threshold = choose_threshold(
        dataset,
        validation_scores["isolation"],
        validation_manifest,
        isolation_training_threshold,
    )
    novelty_threshold = None
    rarity_state = None
    if validation_scores["rarity"] is not None:
        novelty_threshold = choose_threshold(
            dataset,
            validation_scores["rarity"],
            validation_manifest,
            rarity_training_threshold,
        )
        rarity_state = {
            "names": rarity_names,
            "presence": presence,
            "surprisal": surprisal,
            "threshold": novelty_threshold["selected"],
        }
    thresholds = {
        "robust": robust_threshold["selected"],
        "isolation": isolation_threshold["selected"],
        "novelty": novelty_threshold["selected"] if novelty_threshold else float("inf"),
    }
    with stage(dataset + ": explain and write validation scores"):
        validation_result = scored_split(
            validation_manifest, validation_scores,
            explain_split(validation, fitted, robust_rule, validation_scores, thresholds),
            thresholds, robust_rule)
        validation_stats = matrix_stats(validation[:, isolation_indices], "validation")
        del validation
        validation_result.to_csv(output / "validation_scores.csv", index=False)
    robust_validation_alerts = int(validation_result["robust_alert"].sum())
    isolation_validation_alerts = int(validation_result["isolation_alert"].sum())
    novelty_validation_alerts = int(validation_result["novelty_alert"].sum())
    del validation_result, validation_manifest

    test, _, _, _ = load_split_matrix(source, "test", selected_indices, selected_names)
    if test.shape[0] != len(test_manifest):
        raise ValueError("test matrix/manifest row mismatch")
    with stage(dataset + ": score and explain test"):
        test_scores = score_split(test, fitted, robust_rule)
        test_result = scored_split(
            test_manifest, test_scores,
            explain_split(test, fitted, robust_rule, test_scores, thresholds),
            thresholds, robust_rule)
        test_stats = matrix_stats(test[:, isolation_indices], "test")
    del test, test_manifest
    test_result, raw_evidence, evidence_metrics = attach_alert_evidence(
        dataset, test_result, source, output
    )
    with stage(dataset + ": write test scores"):
        test_result.to_csv(output / "test_scores.csv", index=False)

    attribution = explanation_attribution(test_result, output)
    entity_concentration(test_result, output)
    review_counts = review_queue(dataset, test_result, raw_evidence, output)
    precision = precision_from_labels(dataset, output)

    robust_test_alerts = int(test_result["robust_alert"].sum())
    isolation_test_alerts = int(test_result["isolation_alert"].sum())
    novelty_test_alerts = int(test_result["novelty_alert"].sum())
    either_test_alerts = int(test_result["either_model_alert"].sum())
    robust_and_isolation = int(
        (test_result["robust_alert"] & test_result["isolation_alert"]).sum()
    )

    robust_detector_status = detector_status(
        robust_threshold,
        robust_validation_alerts,
        robust_test_alerts,
        len(robust_indices),
    )
    isolation_detector_status = detector_status(
        isolation_threshold,
        isolation_validation_alerts,
        isolation_test_alerts,
        len(isolation_indices),
    )
    novelty_detector_status = (
        detector_status(
            novelty_threshold,
            novelty_validation_alerts,
            novelty_test_alerts,
            len(rarity_indices),
        )
        if novelty_threshold is not None else "inactive_no_features"
    )
    LOGGER.info("%s detector status: robust=%s, isolation=%s, novelty=%s",
                dataset, robust_detector_status, isolation_detector_status,
                novelty_detector_status)

    robust_attribution = attribution.loc[
        (attribution.get("population") == "robust_alerts")
        & (attribution.get("explanation_channel") == "robust_explanation")
    ] if len(attribution) else pd.DataFrame()

    summary.update({
        **validation_stats,
        **test_stats,
        "train_sample_rows": int(len(sample)),
        "robust_detector_status": robust_detector_status,
        "isolation_detector_status": isolation_detector_status,
        "novelty_detector_status": novelty_detector_status,
        "robust_rule": robust_rule,
        "robust_threshold": robust_threshold["selected"],
        "robust_threshold_source": robust_threshold["source"],
        "robust_validation_candidates": robust_threshold["eligible_candidates"],
        "robust_allowed_validation_alerts": robust_threshold["allowed_alerts"],
        "robust_realized_validation_alerts": robust_threshold["realized_selected_alerts"],
        "robust_threshold_tie_count": robust_threshold["threshold_tie_count"],
        "robust_threshold_tie_adjusted": robust_threshold["tie_adjusted"],
        "robust_budget_overshoot": robust_threshold["budget_overshoot"],
        "isolation_threshold": isolation_threshold["selected"],
        "isolation_threshold_source": isolation_threshold["source"],
        "isolation_validation_candidates": isolation_threshold["eligible_candidates"],
        "isolation_allowed_validation_alerts": isolation_threshold["allowed_alerts"],
        "isolation_realized_validation_alerts": isolation_threshold["realized_selected_alerts"],
        "isolation_threshold_tie_count": isolation_threshold["threshold_tie_count"],
        "isolation_threshold_tie_adjusted": isolation_threshold["tie_adjusted"],
        "isolation_budget_overshoot": isolation_threshold["budget_overshoot"],
        "novelty_threshold": (
            novelty_threshold["selected"] if novelty_threshold else np.nan
        ),
        "novelty_threshold_source": (
            novelty_threshold["source"] if novelty_threshold else "inactive_no_features"
        ),
        "novelty_validation_candidates": (
            novelty_threshold["eligible_candidates"] if novelty_threshold else 0
        ),
        "novelty_allowed_validation_alerts": (
            novelty_threshold["allowed_alerts"] if novelty_threshold else 0
        ),
        "novelty_realized_validation_alerts": (
            novelty_threshold["realized_selected_alerts"] if novelty_threshold else 0
        ),
        "novelty_threshold_tie_count": (
            novelty_threshold["threshold_tie_count"] if novelty_threshold else 0
        ),
        "novelty_threshold_tie_adjusted": (
            novelty_threshold["tie_adjusted"] if novelty_threshold else False
        ),
        "novelty_budget_overshoot": (
            novelty_threshold["budget_overshoot"] if novelty_threshold else 0
        ),
        "validation_robust_alerts": robust_validation_alerts,
        "validation_isolation_alerts": isolation_validation_alerts,
        "validation_novelty_alerts": novelty_validation_alerts,
        "test_robust_alerts": robust_test_alerts,
        "test_robust_alert_rate": robust_test_alerts / len(test_result),
        "test_isolation_alerts": isolation_test_alerts,
        "test_isolation_alert_rate": isolation_test_alerts / len(test_result),
        "test_novelty_alerts": novelty_test_alerts,
        "test_novelty_alert_rate": novelty_test_alerts / len(test_result),
        "test_either_model_alerts": either_test_alerts,
        "test_either_model_alert_rate": either_test_alerts / len(test_result),
        "test_robust_isolation_overlap": robust_and_isolation,
        "test_model_jaccard": (
            robust_and_isolation / either_test_alerts
            if either_test_alerts else 0.0
        ),
        "test_score_spearman": correlation(test_scores["robust"], test_scores["isolation"]),
        "calibration": {
            name: calibration.rate_check((threshold or {}).get("allowed_alerts", 0), len(validation_manifest), count, len(test_result))
            for name, threshold, count in (("robust", robust_threshold, robust_test_alerts), ("isolation", isolation_threshold, isolation_test_alerts),
                                           ("novelty", novelty_threshold, novelty_test_alerts))},
        "robust_dominant_feature_among_robust_alerts": (
            robust_attribution.iloc[0]["feature_name"]
            if len(robust_attribution) else ""
        ),
        "robust_dominant_share_among_robust_alerts": (
            float(robust_attribution.iloc[0]["share"])
            if len(robust_attribution) else np.nan
        ),
        **evidence_metrics,
        **review_counts,
        **precision,
    })
    summary["total_seconds"] = time.perf_counter() - started
    write_json(output / "summary.json", summary)

    bundle = {
        "dataset": dataset,
        "isolation_forest": isolation_model,
        "isolation_feature_indices": isolation_indices,
        "isolation_feature_names": [
            selected_names[index] for index in isolation_indices
        ],
        "isolation_threshold": isolation_threshold["selected"],
        "policy_feature_indices": selected_indices,
        "robust_feature_indices": robust_indices,
        "robust_feature_names": robust_names,
        "robust_medians": medians,
        "robust_scales": scales,
        "robust_threshold": robust_threshold["selected"],
        "robust_rule": robust_rule,
        "rarity": rarity_state,
        "train_sample_rows": int(len(sample)),
        "detector_status": {
            "robust": robust_detector_status,
            "isolation": isolation_detector_status,
            "novelty": novelty_detector_status,
        },
        "feature_artifact_contract": EXPECTED_FEATURE_CONTRACT,
        "lineage_contract": "row_manifest_id_to_event_id_to_original_log_line",
        "event_lookup_file": str(EVENT_LOOKUP_FILE),
    }
    with stage(dataset + ": write experiment bundle"):
        joblib.dump(bundle, output / "experiment_bundle.joblib", compress=3)
    return summary


def main():
    """Evaluate every configured OSSEC dataset and write the run summaries.

    :rtype: None
    """
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    LABEL_FOLDER.mkdir(parents=True, exist_ok=True)
    LOGGER.info("OSSEC feature folder: %s", FEATURE_FOLDER)
    LOGGER.info("OSSEC event lookup: %s", EVENT_LOOKUP_FILE)
    LOGGER.info("Training sample: %s rows", f"{TRAIN_SAMPLE:,}")
    results = []
    for index, dataset in enumerate(EXPERIMENTS, 1):
        source = FEATURE_FOLDER / dataset
        if not source.is_dir():
            LOGGER.warning("Skipping missing OSSEC feature folder: %s", source)
            continue
        LOGGER.info("Experiment %s/%s: %s", index, len(EXPERIMENTS), dataset)
        try:
            result = run_experiment(dataset)
            results.append(result)
            LOGGER.info("%s: status=%s, selected_features=%s | elapsed %s", dataset,
                        result["status"], result["selected_features"],
                        runlog.format_duration(result["total_seconds"]))
        except Exception as error:
            failure = {
                "dataset": dataset,
                "status": "failed",
                "error": repr(error),
            }
            results.append(failure)
            output = OUTPUT_FOLDER / dataset
            output.mkdir(parents=True, exist_ok=True)
            write_json(output / "summary.json", failure)
            LOGGER.exception("FAILED %s: %s", dataset, repr(error))

    flat = [
        {key: value for key, value in item.items()
         if not isinstance(value, (dict, list))}
        for item in results
    ]
    pd.DataFrame(flat).to_csv(
        OUTPUT_FOLDER / "experiment_summary.csv", index=False
    )
    write_json(OUTPUT_FOLDER / "experiment_summary.json", results)
    LOGGER.info("Complete: %s", OUTPUT_FOLDER / "experiment_summary.csv")


if __name__ == "__main__":
    args = parse_args()
    runlog.configure_from(args)
    FEATURE_FOLDER = args.features
    OUTPUT_FOLDER = args.output
    EVENT_LOOKUP_FILE = args.event_lookup
    TRAIN_SAMPLE = args.train_sample
    try:
        with runlog.run():
            main()
    except KeyboardInterrupt:                    # runlog.run() has logged it
        sys.exit(130)
    except Exception:
        LOGGER.exception("OSSEC experiment runner failed")
        sys.exit(1)
