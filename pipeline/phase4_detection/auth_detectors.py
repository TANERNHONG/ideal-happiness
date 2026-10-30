"""Authentication-log explainable anomaly experiment runner with lineage.

Stage 4 consumes artifacts from
``pipeline/phase3_features/auth.py`` and evaluates:

* authentication_sessions
* individual
* host_5min
* host_behavior_1d

Detector channels
-----------------
1. Robust multifeature deviation for stable continuous features.
2. Isolation Forest for unusual multivariate combinations.
3. Rarity scoring for sparse, categorical, text, and sequence features.

Thresholds are selected using validation data and population-aware alert
budgets. Test data is never used for feature selection or calibration.

Evidence chain
--------------
row_manifest_id -> split lineage -> record_id
-> data/phase1_classify/auth/authlog_event_lookup.csv -> original_log_line

Memory use (revision 2026-09-23)
--------------------------------
The training split is never held in memory in full:

* ``X_train.npz`` is streamed from its zip archive in chunks. Only a random
  sample of ``--train-sample`` rows (default 500,000) is kept, together with
  the per-feature presence counts of the whole training split.
* Feature diagnostics, the robust medians and scales, the Isolation Forest
  and the three training-quantile fallback thresholds use that sample. The
  Isolation Forest only draws 256 rows per tree, so fitting it on a sample
  changes nothing statistically. Rarity presence counts still use every
  training row, so rare values stay rare. With fewer training rows than the
  sample size, results are identical to the previous version.
* Validation and test matrices are streamed the same way, with the
  identity columns dropped while reading (no full-matrix column copy) and
  values stored as float32.
* Robust and rarity scores are computed in vectorised row blocks instead of
  one Python call per row, and no explanation strings are built for training
  rows.
* Explanations are written only for rows that alert on that detector
  (``robust_explanation`` for robust alerts, ``novelty_explanation`` for
  novelty alerts); other rows have empty explanations.
* Validation is scored, written and released before test is loaded.
* Only the row identifier column of ``train_rows.csv`` is read, and only the
  time column of ``test_rows.csv`` is read for the coverage check before
  scoring. Repeated text columns in the validation and test manifests are
  stored as categories.
* Split lineage files are read in chunks, keeping only alerted rows.

Feature channels (revision 2026-09-23)
--------------------------------------
Stage 3 names hashed text and sequence features ``text_hash__`` and
``sequence_hash__``; the policy previously looked only for ``text__`` and
``sequence__``, so the per-dataset channel exclusions never applied and a
dense hash bucket could be scored as a robust continuous feature. Both
prefixes are now recognised, and text and sequence features always go to the
rarity channel.

The runner is verbose by default. Use ``--quiet`` or ``--verbose`` to control
console output.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import time
import traceback
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from sources import change_window_mask, load_change_windows, train_rows_in_change_windows  # noqa: E402
import calibration  # noqa: E402  the test alert rate against the budget
from scipy import sparse, stats
from sklearn.ensemble import IsolationForest

FEATURE_FOLDER = Path("data/phase3_features/auth")
OUTPUT_FOLDER = Path("data/phase4_detection/auth/detectors")
LABEL_FOLDER = Path("data/review_labels/auth")
EVENT_LOOKUP_FILE = Path("data/phase1_classify/auth/authlog_event_lookup.csv")
EXPECTED_FEATURE_CONTRACT = "authlog_explainable_lineage"

EXPERIMENTS = (
    "authentication_sessions", "individual", "host_5min",
    "host_behavior_1d",
)
TIME_COLUMNS = ("timestamp", "window_start", "session_start", "first_timestamp")
ENTITY_COLUMNS = ("host_id", "hostname", "authentication_session_id", "username", "source_ip", "process_name")
LINEAGE_FILES = ("train_lineage.csv", "validation_lineage.csv", "test_lineage.csv")

RANDOM_STATE = 42
ISOLATION_TREES = 300
BASELINE_QUANTILE = 0.995
ROBUST_Z_CAP = 100.0
MINIMUM_TRAIN_ROWS = 100
SKIP_ROWS_PER_FEATURE_BELOW = 5.0
WARN_ROWS_PER_FEATURE_BELOW = 20.0
MIN_ROBUST_DISTINCT_VALUES = 3
MIN_ROBUST_MINORITY_COUNT = 10
MIN_ROBUST_NONZERO_COUNT = 10
SPARSE_PREVALENCE_MAX = 0.10
RARITY_ALPHA = 0.5
RARITY_TOP_N = 5
MAX_DAILY_RATE_RATIO = 3.0
MINIMUM_OBSERVED_VALIDATION_DAYS = 5
MINIMUM_OBSERVED_TEST_DAYS = 5

TARGET_ALERTS_PER_DAY = {
    "individual": 20,
    "host_5min": 10,
    "authentication_sessions": 10,
    "host_behavior_1d": 5,
}
MAX_VALIDATION_ALERT_FRACTION = {
    "individual": 0.01,
    "host_5min": 0.05,
    "authentication_sessions": 0.05,
    "host_behavior_1d": 0.05,
}
MINIMUM_VALIDATION_ROWS = {
    "individual": 200,
    "host_5min": 60,
    "authentication_sessions": 60,
    "host_behavior_1d": 30,
}
MINIMUM_TEST_ROWS = dict(MINIMUM_VALIDATION_ROWS)
MINIMUM_BUDGET_CANDIDATES = {
    "individual": 100,
    "host_5min": 30,
    "authentication_sessions": 30,
    "host_behavior_1d": 20,
}
ROBUST_RULES = {
    "individual": {"top_k": 1, "minimum_support": 1, "support_z": 4.0},
    "host_5min": {"top_k": 3, "minimum_support": 2, "support_z": 3.5},
    "authentication_sessions": {"top_k": 3, "minimum_support": 2, "support_z": 3.5},
    "host_behavior_1d": {"top_k": 3, "minimum_support": 2, "support_z": 3.5},
}
DEFAULT_TRAIN_SAMPLE = 500_000
SCORE_BLOCK_ROWS = 100_000
STREAM_CHUNK_ENTRIES = 5_000_000
CSV_CHUNK_ROWS = 500_000
REVIEW_COMBINATIONS = (
    "robust+isolation+novelty", "robust+isolation", "robust+novelty",
    "isolation+novelty", "robust_only", "isolation_only", "novelty_only",
)
REVIEW_BUCKET_SIZE = {
    "individual": 20, "host_5min": 20,
    "authentication_sessions": 25, "host_behavior_1d": 15,
}


def parse_args():
    parser = argparse.ArgumentParser(description="Run authentication anomaly experiments.")
    parser.add_argument("--features", type=Path, default=FEATURE_FOLDER)
    parser.add_argument("--output", type=Path, default=OUTPUT_FOLDER)
    parser.add_argument("--event-lookup", type=Path, default=EVENT_LOOKUP_FILE)
    parser.add_argument("--train-sample", type=int, default=DEFAULT_TRAIN_SAMPLE,
                        help="Training rows kept in memory for fitting (default 500000).")
    runlog.add_arguments(parser)
    return parser.parse_args()


import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


def clean(value):
    return "" if value is None or (isinstance(value, float) and np.isnan(value)) else str(value).strip()


def truthy(series):
    if pd.api.types.is_bool_dtype(series): return series.fillna(False)
    return series.fillna("").astype(str).str.strip().str.lower().isin({"1", "true", "yes", "y"})


def write_json(path, payload):
    def convert(value):
        if isinstance(value, dict): return {str(k): convert(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)): return [convert(v) for v in value]
        if isinstance(value, Path): return str(value)
        if isinstance(value, np.integer): return int(value)
        if isinstance(value, (np.floating, float)):
            value = float(value); return value if np.isfinite(value) else None
        if isinstance(value, np.ndarray): return value.tolist()
        return value
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(convert(payload), handle, indent=2, allow_nan=False)


def require_columns(frame, columns, source):
    missing = set(columns) - set(frame.columns)
    if missing: raise ValueError(source + " missing columns: " + ", ".join(sorted(missing)))


def load_metadata(folder, dataset):
    path = folder / "metadata.json"
    if not path.is_file(): raise FileNotFoundError("Missing metadata: " + str(path))
    with open(path, "r", encoding="utf-8") as handle: metadata = json.load(handle)
    if metadata.get("dataset") != dataset: raise ValueError("Metadata dataset mismatch: " + dataset)
    if metadata.get("feature_artifact_contract") != EXPECTED_FEATURE_CONTRACT:
        raise ValueError("Unsupported feature contract for " + dataset)
    if metadata.get("lineage_status") not in {"complete", "validated"}:
        raise ValueError("Incomplete feature lineage for " + dataset)
    return metadata


def _open_npy(archive, name):
    """Open one array inside an ``.npz`` archive and read its header."""
    handle = archive.open(name)
    version = np.lib.format.read_magic(handle)
    reader = np.lib.format.read_array_header_1_0 if version == (1, 0) else np.lib.format.read_array_header_2_0
    shape, fortran_order, dtype = reader(handle)
    if fortran_order and len(shape) > 1:
        raise ValueError("Fortran-ordered array not supported: " + name)
    return handle, int(np.prod(shape)), np.dtype(dtype)


def _read_npy(archive, name):
    """Read a small array from an ``.npz`` archive in full."""
    with archive.open(name) as handle:
        return np.lib.format.read_array(handle, allow_pickle=False)


def _iter_npy(archive, name, chunk):
    """Yield (offset, block) pieces of a large array without loading it whole."""
    handle, total, dtype = _open_npy(archive, name)
    try:
        offset = 0
        while offset < total:
            count = min(chunk, total - offset)
            block = np.frombuffer(handle.read(count * dtype.itemsize), dtype=dtype, count=count)
            yield offset, block
            offset += count
    finally:
        handle.close()


def load_sparse(path, keep_columns, rows=None, count_presence=False):
    """Stream a CSR ``.npz`` into float32, keeping selected rows and columns.

    :param path: ``X_<split>.npz`` path.
    :param keep_columns: Sorted column indices to keep (in the output order).
    :param rows: Sorted row indices to keep, or None for every row.
    :param count_presence: Also count non-zero entries per kept column over
        every row of the file (not only the kept rows).
    :returns: (matrix, total_rows, presence or None).
    :rtype: tuple
    """
    keep_columns = np.asarray(keep_columns, dtype=np.int64)
    with zipfile.ZipFile(path) as archive:
        members = set(archive.namelist())
        fmt = str(_read_npy(archive, "format.npy")) if "format.npy" in members else ""
        if fmt != "csr":
            matrix = sparse.load_npz(path).tocsr()
            total = matrix.shape[0]
            presence = (np.bincount(matrix.indices[matrix.data != 0], minlength=matrix.shape[1]).astype(float)[keep_columns]
                        if count_presence else None)
            if rows is not None:
                matrix = matrix[rows]
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
            positions = np.arange(capacity, dtype=np.int64) + np.repeat(starts - (np.cumsum(lengths) - lengths), lengths)
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


def compact_frame(frame):
    """Store repeated text columns as categories to cut manifest memory."""
    for column in frame.columns:
        if column != "row_manifest_id" and frame[column].dtype == object:
            if frame[column].nunique(dropna=False) <= 0.5 * max(len(frame), 1):
                frame[column] = frame[column].astype("category")
    return frame


def load_manifest(folder, split):
    """Read a validation or test manifest and validate its identifiers."""
    path = folder / (split + "_rows.csv")
    manifest = pd.read_csv(path, low_memory=False, dtype={"row_manifest_id": str})
    require_columns(manifest, {"row_manifest_id"}, str(path))
    manifest["row_manifest_id"] = manifest["row_manifest_id"].fillna("").astype(str).str.strip()
    if manifest["row_manifest_id"].eq("").any() or manifest["row_manifest_id"].duplicated().any():
        raise ValueError(split + " manifest has invalid row_manifest_id")
    return compact_frame(manifest)


def count_manifest_rows(folder, split):
    """Count manifest rows (and reject blank IDs) reading only the ID column."""
    path = folder / (split + "_rows.csv")
    rows = 0
    for chunk in pd.read_csv(path, usecols=["row_manifest_id"], dtype=str, chunksize=CSV_CHUNK_ROWS):
        if chunk["row_manifest_id"].fillna("").str.strip().eq("").any():
            raise ValueError(split + " manifest has blank row_manifest_id")
        rows += len(chunk)
    return rows


def manifest_time_metrics(folder, split):
    """Temporal metrics from the time column only, without loading the manifest."""
    path = folder / (split + "_rows.csv")
    header = pd.read_csv(path, nrows=0).columns
    for column in TIME_COLUMNS:
        if column in header:
            frame = pd.read_csv(path, usecols=[column], dtype=str)
            metrics = temporal_metrics(frame)
            if metrics["time_column"]:
                return metrics
    return temporal_metrics(pd.DataFrame(index=range(count_manifest_rows(folder, split))))


def time_series(manifest):
    for column in TIME_COLUMNS:
        if column in manifest.columns:
            values = pd.to_datetime(manifest[column], errors="coerce", utc=True)
            if values.notna().any(): return column, values
    return "", pd.Series(pd.NaT, index=manifest.index, dtype="datetime64[ns, UTC]")


def temporal_metrics(manifest):
    column, timestamps = time_series(manifest); valid = timestamps.dropna()
    days = int(valid.dt.floor("D").nunique()) if len(valid) else 0
    return {"time_column": column, "rows": len(manifest), "observed_days": days,
            "rows_per_observed_day": len(manifest) / days if days else np.nan,
            "first_timestamp": str(valid.min()) if len(valid) else "",
            "last_timestamp": str(valid.max()) if len(valid) else ""}


def temporal_valid(dataset, left, right):
    a, b = left["rows_per_observed_day"], right["rows_per_observed_day"]
    ratio = max(a / b, b / a) if np.isfinite(a) and np.isfinite(b) and a > 0 and b > 0 else np.inf
    reasons = []
    if left["observed_days"] < MINIMUM_OBSERVED_VALIDATION_DAYS: reasons.append("too_few_validation_days")
    if right["observed_days"] < MINIMUM_OBSERVED_TEST_DAYS: reasons.append("too_few_test_days")
    if left["rows"] < MINIMUM_VALIDATION_ROWS[dataset]: reasons.append("too_few_validation_rows")
    if right["rows"] < MINIMUM_TEST_ROWS[dataset]: reasons.append("too_few_test_rows")
    if ratio > MAX_DAILY_RATE_RATIO: reasons.append("validation_test_daily_rate_mismatch")
    return not reasons, reasons, {"validation": left, "test": right, "daily_rate_ratio": ratio}


TEXT_PREFIXES = ("text__", "text_hash__")
SEQUENCE_PREFIXES = ("sequence__", "sequence_hash__")


def channel(name):
    """Feature channel; recognises both named and hashed (Stage 3 streaming) prefixes."""
    lowered = name.lower()
    if lowered.startswith(TEXT_PREFIXES): return "text"
    if lowered.startswith(SEQUENCE_PREFIXES): return "sequence"
    return "tabular"


def feature_policy(dataset, names):
    excluded = ("row_manifest_id", "record_id", "source_event_id", "source_line", "raw_line", "timestamp_epoch")
    selected, rows = [], []
    for index, name in enumerate(names):
        lowered = name.lower()
        include = not any(token in lowered for token in excluded)
        if dataset == "individual" and lowered.startswith(SEQUENCE_PREFIXES): include = False
        if dataset != "individual" and lowered.startswith(TEXT_PREFIXES): include = False
        reason = "behavior_feature" if include else "identity_or_channel_exclusion"
        if include: selected.append(index)
        rows.append({"original_feature_index": index, "feature_name": name, "included": include, "reason": reason, "channel": channel(name)})
    if not selected: raise ValueError("Feature policy removed every feature for " + dataset)
    return np.asarray(selected, dtype=int), pd.DataFrame(rows)


def inspect_features(matrix, names):
    rows = []
    for index, name in enumerate(names):
        values = matrix.getcol(index).toarray().ravel().astype(float)
        values = values[np.isfinite(values)]
        unique = np.unique(values); nonzero = int(np.count_nonzero(values)); zero = len(values) - nonzero
        median = float(np.median(values)) if len(values) else 0.0
        mad = float(np.median(np.abs(values - median))) if len(values) else 0.0
        scale = 1.4826 * mad
        if scale <= 1e-9 and len(values): scale = float(np.quantile(np.abs(values - median), .75))
        prevalence = nonzero / len(values) if len(values) else 0.0
        # Text and sequence hash buckets always go to the rarity channel, never robust z-scores.
        tabular = channel(name) == "tabular"
        robust = tabular and len(unique) >= MIN_ROBUST_DISTINCT_VALUES and nonzero >= MIN_ROBUST_NONZERO_COUNT and min(nonzero, zero) >= MIN_ROBUST_MINORITY_COUNT and scale > 1e-9
        rarity = len(unique) <= 2 or prevalence <= SPARSE_PREVALENCE_MAX or not tabular
        role = "robust_continuous" if robust else "rarity" if rarity else "isolation_only"
        rows.append({"feature_name": name, "role": role, "nonzero_count": nonzero, "distinct_values": len(unique), "prevalence": prevalence, "median": median, "scale": scale, "channel": channel(name)})
    return pd.DataFrame(rows)


def fit_robust(matrix):
    medians, scales = np.zeros(matrix.shape[1]), np.zeros(matrix.shape[1])
    for index in range(matrix.shape[1]):
        values = matrix.getcol(index).toarray().ravel().astype(float)
        medians[index] = np.median(values); mad = np.median(np.abs(values - medians[index]))
        scales[index] = 1.4826 * mad
        if scales[index] <= 1e-9: scales[index] = np.quantile(np.abs(values - medians[index]), .75)
    return medians, scales


def _robust_z(block, medians, scales):
    with np.errstate(divide="ignore", invalid="ignore"):
        z = np.abs((block - medians) / scales)
    z = np.nan_to_num(z, nan=0, posinf=ROBUST_Z_CAP)
    return np.clip(z, 0, ROBUST_Z_CAP, out=z)


def robust_score(matrix, medians, scales, rule):
    """Top-k mean robust z-score and support count, in dense row blocks."""
    rows = matrix.shape[0]; scores = np.zeros(rows); support = np.zeros(rows, dtype=int)
    top_k = min(rule["top_k"], matrix.shape[1])
    for start in range(0, rows, SCORE_BLOCK_ROWS):
        z = _robust_z(matrix[start:start + SCORE_BLOCK_ROWS].toarray(), medians, scales)
        support[start:start + len(z)] = np.count_nonzero(z >= rule["support_z"], axis=1)
        if top_k:
            scores[start:start + len(z)] = np.partition(z, -top_k, axis=1)[:, -top_k:].mean(axis=1)
    return scores, support


def robust_explain(matrix, names, medians, scales, rule, rows):
    """Explanation strings for the given rows only (empty for all others)."""
    explanations = np.full(matrix.shape[0], "", dtype=object)
    top_k = min(rule["top_k"], matrix.shape[1])
    rows = np.flatnonzero(rows)
    for start in range(0, len(rows), SCORE_BLOCK_ROWS):
        chosen = rows[start:start + SCORE_BLOCK_ROWS]
        z = _robust_z(matrix[chosen].toarray(), medians, scales)
        order = np.argsort(-z, axis=1)[:, :top_k]
        for row, values, top in zip(chosen, z, order):
            explanations[row] = "; ".join(names[i] + "=" + format(values[i], ".4g") for i in top[:5] if values[i] > 0)
    return explanations


def fit_rarity(presence, training_rows):
    """Smoothed surprisal from presence counts over every training row."""
    probability = (presence + RARITY_ALPHA) / (training_rows + 2 * RARITY_ALPHA)
    return presence, -np.log(np.clip(probability, 1e-15, 1))


def rarity_score(matrix, presence, surprisal):
    """Highest surprisal and unseen-feature count per row, vectorised over the CSR arrays."""
    matrix = matrix.tocsr(); rows = matrix.shape[0]
    scores = np.zeros(rows); unseen = np.zeros(rows, dtype=int)
    for start in range(0, rows, SCORE_BLOCK_ROWS * 10):
        block = matrix[start:start + SCORE_BLOCK_ROWS * 10]
        starts = block.indptr[:-1]; nonempty = np.diff(block.indptr) > 0
        if not nonempty.any():
            continue
        scores[start + np.flatnonzero(nonempty)] = np.maximum.reduceat(surprisal[block.indices], starts[nonempty])
        unseen[start + np.flatnonzero(nonempty)] = np.add.reduceat((presence[block.indices] == 0).astype(np.int64), starts[nonempty])
    return scores, unseen


def rarity_explain(matrix, names, surprisal, rows):
    """Explanation strings (rarest active features) for the given rows only."""
    matrix = matrix.tocsr(); explanations = np.full(matrix.shape[0], "", dtype=object)
    for row in np.flatnonzero(rows):
        columns = matrix.indices[matrix.indptr[row]:matrix.indptr[row + 1]]
        ordered = columns[np.argsort(-surprisal[columns])[:RARITY_TOP_N]] if len(columns) else []
        explanations[row] = "; ".join(names[i] + "=" + format(surprisal[i], ".4g") for i in ordered)
    return explanations


def choose_threshold(dataset, scores, days, training_threshold, eligible=None):
    scores = np.asarray(scores, dtype=float); mask = np.isfinite(scores)
    if eligible is not None: mask &= np.asarray(eligible, dtype=bool)
    values = scores[mask]
    daily = max(TARGET_ALERTS_PER_DAY[dataset] * days, 1)
    population = max(int(math.floor(MAX_VALIDATION_ALERT_FRACTION[dataset] * len(values))), 1) if len(values) else 0
    allowed = min(daily, population, len(values)) if len(values) else 0
    if len(values) >= MINIMUM_BUDGET_CANDIDATES[dataset] and allowed > 0 and days >= 3:
        index = len(values) - allowed; nominal = float(np.partition(values, index)[index]); source = "validation_budget"
    else:
        nominal = float(training_threshold); source = "training_quantile_fallback"
    realized_nominal = int(np.count_nonzero(values >= nominal)) if np.isfinite(nominal) else 0
    selected = float(np.nextafter(nominal, np.inf)) if source == "validation_budget" and realized_nominal > allowed else nominal
    return {"selected": selected, "source": source, "eligible_candidates": len(values), "allowed_alerts": int(allowed), "realized_alerts": int(np.count_nonzero(values >= selected)) if np.isfinite(selected) else 0, "tie_adjusted": selected != nominal, "training_quantile": training_threshold}


def combinations(robust, isolation, novelty):
    return np.select([robust & isolation & novelty, robust & isolation, robust & novelty, isolation & novelty, robust, isolation, novelty], REVIEW_COMBINATIONS, default="not_alerted")


def scored(manifest, robust_scores, support, robust_explain, isolation_scores, rarity_pack, thresholds, rule):
    """Add detector columns to the manifest in place (no copy) and return it."""
    result = manifest.reset_index(drop=True) if not isinstance(manifest.index, pd.RangeIndex) else manifest
    robust_alert = (robust_scores >= thresholds["robust"]) & (support >= rule["minimum_support"])
    isolation_alert = isolation_scores >= thresholds["isolation"]
    if rarity_pack:
        novelty_scores, unseen, novelty_explain = rarity_pack; novelty_alert = novelty_scores >= thresholds["novelty"]
    else:
        novelty_scores = np.zeros(len(result)); unseen = np.zeros(len(result), dtype=int); novelty_explain = ""; novelty_alert = np.zeros(len(result), dtype=bool)
    result["robust_score"] = robust_scores; result["robust_supporting_feature_count"] = support; result["robust_alert"] = robust_alert; result["robust_explanation"] = robust_explain
    result["isolation_score"] = isolation_scores; result["isolation_alert"] = isolation_alert
    result["novelty_score"] = novelty_scores; result["novelty_unseen_feature_count"] = unseen; result["novelty_alert"] = novelty_alert; result["novelty_explanation"] = novelty_explain
    result["either_model_alert"] = robust_alert | isolation_alert | novelty_alert
    result["detector_combination"] = combinations(robust_alert, isolation_alert, novelty_alert)
    result["alert_tier"] = result["detector_combination"]
    return result


def load_lineage(folder, ids):
    frames = []
    for filename in LINEAGE_FILES:
        path = folder / filename
        if not path.is_file(): raise FileNotFoundError("Missing lineage: " + str(path))
        require_columns(pd.read_csv(path, nrows=0), {"row_manifest_id", "record_id", "event_position"}, str(path))
        for frame in pd.read_csv(path, dtype={"row_manifest_id": str, "record_id": str}, chunksize=CSV_CHUNK_ROWS, low_memory=False):
            frame["row_manifest_id"] = frame["row_manifest_id"].fillna("").astype(str).str.strip()
            selected = frame[frame["row_manifest_id"].isin(ids)].copy()
            if len(selected):
                selected["record_id"] = selected["record_id"].fillna("").astype(str).str.strip()
                selected["lineage_source_file"] = filename; frames.append(selected)
    result = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    if ids - set(result.get("row_manifest_id", [])): raise ValueError("Alert observations lack lineage")
    if result.duplicated(["row_manifest_id", "record_id"]).any(): raise ValueError("Duplicate alert lineage links")
    return result


def lookup_subset(path, ids):
    header = pd.read_csv(path, nrows=0); require_columns(header, {"record_id", "original_log_line"}, str(path))
    preferred = ["record_id", "raw_line_sha256", "source_event_id", "timestamp", "partition_month", "hostname", "process_name", "pid", "facility", "event_type", "username", "target_username", "source_ip", "source_port", "authentication_method", "connection_stage", "reason", "raw_message", "original_log_line", "classification_line", "source_file", "source_line"]
    usecols = [column for column in preferred if column in header.columns]; frames = []
    for chunk in pd.read_csv(path, usecols=usecols, chunksize=200000, low_memory=False):
        chunk["record_id"] = chunk["record_id"].fillna("").astype(str).str.strip(); selected = chunk[chunk["record_id"].isin(ids)]
        if len(selected): frames.append(selected)
    result = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=usecols)
    missing = ids - set(result["record_id"])
    if missing: raise ValueError("Lineage records missing from authlog event lookup: " + str(len(missing)))
    if result["record_id"].duplicated().any(): raise ValueError("Duplicate record_id in authlog event lookup")
    return result


def attach_evidence(dataset, result, feature_folder, event_lookup, output):
    alerts = result[result["either_model_alert"]].copy()
    if alerts.empty:
        pd.DataFrame().to_csv(output / "test_raw_alert_evidence.csv", index=False)
        pd.DataFrame().to_csv(output / "test_alert_evidence_summary.csv", index=False)
        return result, pd.DataFrame(), {"alert_observations": 0, "raw_evidence_rows": 0, "alerts_with_complete_evidence": 0}
    ids = set(alerts["row_manifest_id"].astype(str)); lineage = load_lineage(feature_folder, ids)
    lookup = lookup_subset(event_lookup, set(lineage["record_id"]))
    evidence = lineage.merge(lookup, on="record_id", how="left", validate="many_to_one", indicator=True)
    evidence["event_lookup_found"] = evidence["_merge"].eq("both"); evidence.drop(columns=["_merge"], inplace=True)
    alert_columns = [column for column in ("row_manifest_id", "detector_combination", "alert_tier", "robust_score", "robust_alert", "robust_explanation", "isolation_score", "isolation_alert", "novelty_score", "novelty_alert", "novelty_explanation", "host_id", "authentication_session_id", "username", "source_ip", "process_name") if column in alerts.columns]
    evidence = evidence.merge(alerts[alert_columns], on="row_manifest_id", how="left", validate="many_to_one")
    evidence["dataset"] = dataset
    evidence.to_csv(output / "test_raw_alert_evidence.csv", index=False)
    summaries = []
    for row_id, group in evidence.groupby("row_manifest_id", sort=False):
        messages = group.loc[group["event_lookup_found"], "original_log_line"].fillna("").astype(str).tolist()
        summaries.append({"row_manifest_id": row_id, "raw_evidence_count": len(group), "raw_evidence_found_count": int(group["event_lookup_found"].sum()), "raw_evidence_missing_count": int((~group["event_lookup_found"]).sum()), "first_original_log_line": messages[0] if messages else "", "last_original_log_line": messages[-1] if messages else "", "representative_original_log_lines": " || ".join(messages[:5]), "evidence_status": "complete" if group["event_lookup_found"].all() else "partial"})
    summary = pd.DataFrame(summaries); summary.to_csv(output / "test_alert_evidence_summary.csv", index=False)
    result = result.merge(summary, on="row_manifest_id", how="left", validate="one_to_one")
    result["evidence_status"] = result["evidence_status"].fillna("not_alerted")
    return result, evidence, {"alert_observations": len(alerts), "raw_evidence_rows": len(evidence), "alerts_with_complete_evidence": int(summary["evidence_status"].eq("complete").sum()), "alerts_with_partial_evidence": int(summary["evidence_status"].eq("partial").sum()), "unique_evidence_records": evidence["record_id"].nunique()}


def create_review_queue(dataset, result, evidence, output):
    pieces = []
    for combination in REVIEW_COMBINATIONS:
        population = result[result["detector_combination"].eq(combination)].copy()
        sample = population.sort_values(["isolation_score", "robust_score", "novelty_score"], ascending=False).head(REVIEW_BUCKET_SIZE[dataset])
        sample["review_bucket"] = combination; pieces.append(sample)
    queue = pd.concat(pieces, ignore_index=True).drop_duplicates("row_manifest_id") if pieces else pd.DataFrame()
    for column in ("review_label", "review_category", "review_notes", "reviewer", "reviewed_at"): queue[column] = ""
    queue.to_csv(output / "manual_review_queue.csv", index=False)
    ids = set(queue.get("row_manifest_id", pd.Series(dtype=str)).astype(str))
    evidence[evidence["row_manifest_id"].astype(str).isin(ids)].to_csv(output / "manual_review_event_evidence.csv", index=False) if len(evidence) else pd.DataFrame().to_csv(output / "manual_review_event_evidence.csv", index=False)
    return len(queue)


def correlation(left, right):
    if len(left) < 2 or np.unique(left).size < 2 or np.unique(right).size < 2: return np.nan
    value = stats.spearmanr(left, right, nan_policy="omit").statistic
    return float(value) if np.isfinite(value) else np.nan


def score_split(matrix, fitted, rule, thresholds=None):
    """Score one split with all three detectors (no explanations)."""
    robust_indices, medians, scales, model, rarity_indices, presence, surprisal = fitted
    rows = matrix.shape[0]
    if len(robust_indices):
        robust, support = robust_score(matrix[:, robust_indices], medians, scales, rule)
    else:
        robust, support = np.zeros(rows), np.zeros(rows, dtype=int)
    isolation = -model.score_samples(matrix)
    if len(rarity_indices):
        rarity, unseen = rarity_score(matrix[:, rarity_indices], presence, surprisal)
    else:
        rarity, unseen = None, None
    return robust, support, isolation, rarity, unseen


def explain_split(matrix, fitted, rule, names, robust, support, rarity, thresholds):
    """Explanations for the rows that alert on each detector."""
    robust_indices, medians, scales, _, rarity_indices, _, surprisal = fitted
    if len(robust_indices):
        robust_rows = (robust >= thresholds["robust"]) & (support >= rule["minimum_support"])
        robust_text = robust_explain(matrix[:, robust_indices], [names[i] for i in robust_indices], medians, scales, rule, robust_rows)
    else:
        robust_text = ""
    rarity_text = ""
    if rarity is not None:
        rarity_text = rarity_explain(matrix[:, rarity_indices], [names[i] for i in rarity_indices], surprisal, rarity >= thresholds["novelty"])
    return robust_text, rarity_text


def run_dataset(dataset, args, log):
    started = time.perf_counter(); source = args.features / dataset; output = args.output / dataset; output.mkdir(parents=True, exist_ok=True)
    metadata = load_metadata(source, dataset)
    names = pd.read_csv(source / "feature_names.csv")["feature_name"].astype(str).tolist()
    selected, audit = feature_policy(dataset, names); audit.to_csv(output / "feature_policy_audit.csv", index=False)
    selected_names = [names[i] for i in selected]

    with zipfile.ZipFile(source / "X_train.npz") as archive:
        train_rows_total = int(_read_npy(archive, "shape.npy")[0]) if "shape.npy" in archive.namelist() else sparse.load_npz(source / "X_train.npz").shape[0]
    if count_manifest_rows(source, "train") != train_rows_total: raise ValueError("train matrix/manifest mismatch")
    sample_size = min(max(args.train_sample, 1), train_rows_total)
    sample_rows = (np.arange(train_rows_total) if sample_size == train_rows_total
                   else np.sort(np.random.default_rng(RANDOM_STATE).choice(train_rows_total, sample_size, replace=False)))
    in_windows = train_rows_in_change_windows(source)    # approved change windows never teach "normal"
    if len(in_windows):
        sample_rows = np.setdiff1d(sample_rows, in_windows)
        log.write(f"{dataset}: {len(in_windows):,} training rows fall in approved change windows and are left out")
        sample_size = len(sample_rows)
    log.write(f"{dataset}: streaming training matrix ({train_rows_total:,} rows, keeping {sample_size:,})")
    train, _, presence_all = load_sparse(source / "X_train.npz", selected, rows=sample_rows, count_presence=True)
    validation_metrics = manifest_time_metrics(source, "validation"); test_metrics = manifest_time_metrics(source, "test")
    valid, reasons, temporal = temporal_valid(dataset, validation_metrics, test_metrics)
    write_json(output / "temporal_coverage_validation.json", {"valid": valid, "reasons": reasons, **temporal})

    diagnostics = inspect_features(train.tocsc(), selected_names); diagnostics.to_csv(output / "feature_spread_diagnostics.csv", index=False)
    roles = diagnostics["role"].to_numpy(); robust_indices = np.flatnonzero(roles == "robust_continuous"); rarity_indices = np.flatnonzero(roles == "rarity"); isolation_indices = np.arange(len(selected_names))
    rows_per_feature = train_rows_total / max(len(isolation_indices), 1)
    status = "skipped_insufficient_temporal_coverage" if not valid else "skipped_too_few_training_rows" if train_rows_total < MINIMUM_TRAIN_ROWS else "skipped_insufficient_rows_per_feature" if rows_per_feature < SKIP_ROWS_PER_FEATURE_BELOW else "warning_low_rows_per_feature" if rows_per_feature < WARN_ROWS_PER_FEATURE_BELOW else "acceptable_for_evaluation"
    summary = {"dataset": dataset, "status": status, "feature_artifact_contract": metadata.get("feature_artifact_contract"), "train_rows": train_rows_total, "train_sample_rows": sample_size, "validation_rows": validation_metrics["rows"], "test_rows": test_metrics["rows"], "original_features": len(names), "selected_features": len(selected_names), "robust_continuous_features": len(robust_indices), "rarity_features": len(rarity_indices), "rows_per_feature": rows_per_feature, "temporal_coverage_valid": valid, "temporal_coverage_reasons": "|".join(reasons)}
    if status.startswith("skipped"):
        summary["total_seconds"] = time.perf_counter() - started; write_json(output / "summary.json", summary); return summary

    rule = ROBUST_RULES[dataset]
    robust_names = [selected_names[i] for i in robust_indices]
    if len(robust_indices):
        medians, scales = fit_robust(train[:, robust_indices].tocsc())
        medians, scales = medians.astype(np.float32), scales.astype(np.float32)
    else:
        medians = scales = np.array([], dtype=np.float32)
    model = IsolationForest(n_estimators=ISOLATION_TREES, contamination="auto", random_state=RANDOM_STATE, n_jobs=-1, max_features=min(1.0, 100 / max(len(isolation_indices), 1)))
    log.write(f"{dataset}: fitting Isolation Forest on {sample_size:,} training rows")
    model.fit(train)
    presence, surprisal = fit_rarity(presence_all[rarity_indices], train_rows_total) if len(rarity_indices) else (None, None)
    fitted = (robust_indices, medians, scales, model, rarity_indices, presence, surprisal)
    robust_train, support_train, isolation_train, rarity_train, _ = score_split(train, fitted, rule)
    del train
    eligible = support_train >= rule["minimum_support"]
    robust_training_threshold = float(np.quantile(robust_train[eligible], BASELINE_QUANTILE)) if len(robust_indices) and eligible.any() else float("inf")

    log.write(f"{dataset}: scoring validation")
    validation, _, _ = load_sparse(source / "X_validation.npz", selected)
    robust_validation, support_validation, isolation_validation, rarity_validation, unseen_validation = score_split(validation, fitted, rule)
    days = validation_metrics["observed_days"]
    robust_threshold = choose_threshold(dataset, robust_validation, days, robust_training_threshold, support_validation >= rule["minimum_support"])
    isolation_threshold = choose_threshold(dataset, isolation_validation, days, float(np.quantile(isolation_train, BASELINE_QUANTILE)))
    rarity_threshold = {"selected": float("inf"), "source": "inactive_no_features", "allowed_alerts": 0, "realized_alerts": 0}; rarity_state = None
    if rarity_validation is not None:
        rarity_threshold = choose_threshold(dataset, rarity_validation, days, float(np.quantile(rarity_train, BASELINE_QUANTILE)))
        rarity_state = {"feature_names": [selected_names[i] for i in rarity_indices], "presence": presence, "surprisal": surprisal, "threshold": rarity_threshold["selected"]}
    thresholds = {"robust": robust_threshold["selected"], "isolation": isolation_threshold["selected"], "novelty": rarity_threshold["selected"]}
    robust_text, rarity_text = explain_split(validation, fitted, rule, selected_names, robust_validation, support_validation, rarity_validation, thresholds)
    del validation
    validation_rows = load_manifest(source, "validation")
    if len(validation_rows) != len(robust_validation): raise ValueError("validation matrix/manifest mismatch")
    validation_rarity = (rarity_validation, unseen_validation, rarity_text) if rarity_validation is not None else None
    validation_result = scored(validation_rows, robust_validation, support_validation, robust_text, isolation_validation, validation_rarity, thresholds, rule)
    validation_result.to_csv(output / "validation_scores.csv", index=False)
    del validation_result, validation_rows, robust_text, rarity_text

    log.write(f"{dataset}: scoring test")
    test, _, _ = load_sparse(source / "X_test.npz", selected)
    robust_test, support_test, isolation_test, rarity_test, unseen_test = score_split(test, fitted, rule)
    robust_text, rarity_text = explain_split(test, fitted, rule, selected_names, robust_test, support_test, rarity_test, thresholds)
    del test
    test_rows = load_manifest(source, "test")
    if len(test_rows) != len(robust_test): raise ValueError("test matrix/manifest mismatch")
    test_rarity = (rarity_test, unseen_test, rarity_text) if rarity_test is not None else None
    test_result = scored(test_rows, robust_test, support_test, robust_text, isolation_test, test_rarity, thresholds, rule)
    test_result, evidence, evidence_metrics = attach_evidence(dataset, test_result, source, args.event_lookup, output)
    test_result.to_csv(output / "test_scores.csv", index=False)
    review_rows = create_review_queue(dataset, test_result, evidence, output)
    robust_count = int(test_result["robust_alert"].sum()); isolation_count = int(test_result["isolation_alert"].sum()); novelty_count = int(test_result["novelty_alert"].sum()); union_count = int(test_result["either_model_alert"].sum()); overlap = int((test_result["robust_alert"] & test_result["isolation_alert"]).sum())
    summary.update({"robust_threshold": robust_threshold["selected"], "robust_threshold_source": robust_threshold["source"], "isolation_threshold": isolation_threshold["selected"], "isolation_threshold_source": isolation_threshold["source"], "novelty_threshold": rarity_threshold["selected"], "novelty_threshold_source": rarity_threshold["source"], "test_robust_alerts": robust_count, "test_robust_alert_rate": robust_count / len(test_result), "test_isolation_alerts": isolation_count, "test_isolation_alert_rate": isolation_count / len(test_result), "test_novelty_alerts": novelty_count, "test_novelty_alert_rate": novelty_count / len(test_result), "test_either_model_alerts": union_count, "test_either_model_alert_rate": union_count / len(test_result), "test_robust_isolation_overlap": overlap, "test_model_jaccard": overlap / union_count if union_count else 0, "test_score_spearman": correlation(robust_test, isolation_test), "review_total_sampled": review_rows, **evidence_metrics,
                    "calibration": {name: calibration.rate_check(threshold.get("allowed_alerts", 0), int(validation_metrics["rows"]), count, len(test_result))
                                    for name, threshold, count in (("robust", robust_threshold, robust_count), ("isolation", isolation_threshold, isolation_count),
                                                                   ("novelty", rarity_threshold, novelty_count))}})
    summary["total_seconds"] = time.perf_counter() - started; write_json(output / "summary.json", summary)
    joblib.dump({"dataset": dataset, "isolation_forest": model, "isolation_feature_indices": isolation_indices, "isolation_feature_names": selected_names, "isolation_threshold": isolation_threshold["selected"], "robust_feature_indices": robust_indices, "robust_feature_names": robust_names, "robust_medians": medians, "robust_scales": scales, "robust_threshold": robust_threshold["selected"], "robust_rule": rule, "rarity": rarity_state, "train_sample_rows": sample_size, "feature_artifact_contract": EXPECTED_FEATURE_CONTRACT, "lineage_contract": "row_manifest_id_to_record_id_to_original_log_line", "event_lookup_file": str(args.event_lookup)}, output / "experiment_bundle.joblib", compress=3)
    return summary


def main():
    args = parse_args(); log = Log(args.quiet, args.verbose); args.output.mkdir(parents=True, exist_ok=True); LABEL_FOLDER.mkdir(parents=True, exist_ok=True)
    if not args.event_lookup.is_file(): raise FileNotFoundError("Authentication event lookup missing: " + str(args.event_lookup))
    log.write("Authentication Stage 4 starting", "START"); results = []
    for dataset in EXPERIMENTS:
        source = args.features / dataset
        if not source.is_dir():
            log.write("Skipping missing feature folder: " + str(source), "WARN"); continue
        started = time.perf_counter(); log.write("Evaluating dataset: " + dataset, "PHASE")
        try:
            result = run_dataset(dataset, args, log); results.append(result)
            log.write(f"Completed {dataset} in {log.elapsed(started)}: status={result['status']}, selected_features={result['selected_features']}, alerts={result.get('test_either_model_alerts', 0)}", "DONE")
        except Exception as error:
            failure = {"dataset": dataset, "status": "failed", "error": repr(error)}; results.append(failure); output = args.output / dataset; output.mkdir(parents=True, exist_ok=True); write_json(output / "summary.json", failure); log.write(dataset + " failed: " + repr(error), "ERROR", always=True)
            if args.verbose: traceback.print_exc()
    flat = [{key: value for key, value in item.items() if not isinstance(value, (dict, list))} for item in results]
    pd.DataFrame(flat).to_csv(args.output / "experiment_summary.csv", index=False); write_json(args.output / "experiment_summary.json", results)
    log.write("Authentication Stage 4 completed: " + str(args.output / "experiment_summary.csv"), "COMPLETE", always=True)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
