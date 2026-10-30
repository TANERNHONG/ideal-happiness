"""Model-zoo benchmark for OSSEC Stage 3 artifacts (Stage 4b).

Port of ``pipeline/phase4_detection/auth_model_zoo.py`` to the OSSEC explainable-lineage
features. It runs beside Stage 4 (``pipeline/phase4_detection/ossec_detectors.py``)
and does not replace it; Stage 5 still exports Stage 4 Isolation Forest alerts.

It fits thirteen detector families on the same Stage 3 matrices, then:

1. Feature relevance and selection
   Scores every Stage 3 feature using training and validation data only, then
   fits the zoo on a reduced set of higher-relevance columns. Run it on the
   full set, the selected set, or both for a side-by-side comparison.

2. Memory-safe scoring
   Training rows are sampled before normalisation, validation and test rows
   are scored in chunks, and matrices are loaded as float32.

3. Ensemble pruning
   Models that fail, produce degenerate scores, drift within the validation
   period, agree with no other model, or duplicate another model are dropped
   from the ensemble automatically. Every decision is recorded with a reason.
   Pruning uses validation data only.

4. Consensus alert list
   Every test row flagged by at least N ensemble members (default 3) is
   written out with the list of models that flagged it.

5. Proxy detection rate
   There are no analyst labels yet, so each validation/test row gets a weak
   "monitoring-risk" proxy label. For ``individual`` the event type is in
   ``SECURITY_EVENT_TYPES`` (agent stops, manager-communication failures,
   integrity-baseline gaps, configuration gaps) or the severity is ERROR or
   higher. For aggregates at least one of ``SECURITY_COUNT_COLUMNS`` is
   non-zero, read from the Stage 2 CSV by ``row_manifest_id``; the risk counts
   require Stage 2 builder version 02. The detection rate is the share of
   proxy-positive rows caught within the calibrated alert budget. It measures
   alignment with known monitoring-risk events, not true attack detection.

6. Greedy model selection
   After pruning, models are added one at a time, each step adding the model
   that most improves the ensemble's validation detection rate at a fixed
   alert budget. The ensemble keeps the smallest prefix whose detection rate is
   within ``--min-detection-gain`` of the best prefix. The full curve is saved
   so the diminishing returns are visible.

7. Feature-count sweep
   ``--feature-sweep 10,25,50,100`` fits a fast Isolation Forest probe on the
   top-K features by importance for each K and measures its validation
   detection rate. The best K becomes the ``selected`` feature set.

Correctness fixes carried over from the authentication benchmark
-----------------------------------------------------------------
* Ensemble percentiles use training scores as the reference for BOTH
  validation and test (v1 used validation's own scores for validation).
* LOF training scores use ``negative_outlier_factor_`` and k-NN training
  scores exclude each row's self-match, removing the self-neighbour bias.
* Dense models sample training rows randomly instead of taking the first N.

Feature relevance procedure (per dataset, train/validation only)
-----------------------------------------------------------------
1. Identity exclusion: IDs, timestamps, process IDs, agent counters and raw
   ports (``IDENTITY_TOKENS``). Text and sequence n-grams are never excluded.
2. Constant: zero variance in the training sample. These cannot inform any
   model trained on this data.
3. Drift: two-sample Kolmogorov-Smirnov statistic between training and
   validation samples above ``--drift-max-ks``. Drifting features produce
   alerts that reflect a change in the period, not unusual behaviour.
4. Redundancy: absolute Pearson correlation above ``--redundancy-max-corr``
   with an earlier kept feature (for example a raw column and its log1p).
5. Importance: permutation importance against an Isolation Forest fitted on
   the surviving features. Each feature is shuffled in a validation sample and
   the mean absolute change in anomaly score is recorded.
6. Selection: the smallest top-ranked set covering ``--importance-coverage``
   of total importance, bounded by ``--min-features`` and ``--max-features``.

.. note::

   Importance measures what drives the Isolation Forest score, not what is
   security-relevant. Always compare the selected run with the full run.

Output
------
data/phase4_detection/ossec/model_zoo/
    <dataset>/
        feature_relevance.csv            per-feature statistics and decision
        feature_set_comparison.csv       full vs selected (when both run)
        feature_sweep.csv                probe detection rate per top-K
        <feature_set>/                   full and/or selected
            validation_scores.csv
            test_scores.csv
            model_metrics.csv
            ensemble_membership.csv      kept/dropped models with reasons
            overlap_matrix.csv
            consensus_alerts_min<N>.csv  rows flagged by >= N members
            model_selection_curve.csv    greedy detection-rate curve
            consensus_review_queue.csv
            model_bundle.joblib
            dataset_summary.json
    model_zoo_summary.csv / .json
    all_model_metrics.csv
    all_ensemble_membership.csv
    consensus_alerts_all.csv
    feature_set_comparison.csv
    all_model_selection_curves.csv
    all_feature_sweeps.csv

Usage
-----
    python pipeline/phase4_detection/ossec_model_zoo.py --dataset episodes
    python pipeline/phase4_detection/ossec_model_zoo.py --dataset individual --feature-set selected
    python pipeline/phase4_detection/ossec_model_zoo.py --consensus-min-votes 4 --skip-model rbf_ocsvm
    python pipeline/phase4_detection/ossec_model_zoo.py --dataset host_5min --feature-sweep 10,25,50,100
"""
from __future__ import annotations

import argparse
import json
import math
import os
import time
import traceback
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
from sources import change_window_mask, load_change_windows, train_rows_in_change_windows  # noqa: E402
import calibration  # noqa: E402  validation's earlier half chooses, its later half calibrates
from scipy import sparse, stats
from sklearn.cluster import MiniBatchKMeans
from sklearn.covariance import EllipticEnvelope
from sklearn.decomposition import PCA, TruncatedSVD
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import SGDOneClassSVM
from sklearn.mixture import GaussianMixture
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import Normalizer, StandardScaler
from sklearn.svm import OneClassSVM

DEFAULT_FEATURES = Path("data/phase3_features/ossec")
DEFAULT_OUTPUT = Path("data/phase4_detection/ossec/model_zoo")
EXPECTED_FEATURE_CONTRACT = "ossec_explainable_lineage"
DATASETS = (
    "episodes",
    "individual",
    "host_5min",
    "host_behavior_1d",
)
TIME_COLUMNS = ("timestamp", "window_start", "episode_start", "first_timestamp")
RANDOM_STATE = 42
DEFAULT_QUANTILE = 0.995
MAX_ALERT_FRACTION = {
    "individual": 0.01,
    "host_5min": 0.05,
    "episodes": 0.05,
    "host_behavior_1d": 0.05,
}
DEFAULT_MAX_ALERT_FRACTION = 0.05
DEFAULT_SVD_COMPONENTS = 32
# Sample sizes raised on 2026-09-23 (v1 ran in ~45 minutes at 100k/20k/30k).
DEFAULT_GENERAL_SAMPLE = 250_000
DEFAULT_EXPENSIVE_SAMPLE = 40_000
DEFAULT_COVARIANCE_SAMPLE = 60_000
DEFAULT_NEIGHBORS = 35
DEFAULT_GMM_COMPONENTS = 8
DEFAULT_KMEANS_CLUSTERS = 32
DEFAULT_HBOS_BINS = 20
DEFAULT_AUTOENCODER_SAMPLE = 100_000
DEFAULT_REVIEW_ROWS = 200
SCORE_CHUNK_ROWS = 200_000
EPSILON = 1e-12

# Feature relevance defaults
DEFAULT_RELEVANCE_SAMPLE = 100_000
DEFAULT_IMPORTANCE_ROWS = 10_000
IMPORTANCE_TREES = 100
DEFAULT_DRIFT_MAX_KS = 0.25
DEFAULT_REDUNDANCY_MAX_CORR = 0.98
DEFAULT_IMPORTANCE_COVERAGE = 0.95
DEFAULT_MIN_FEATURES = 10
DEFAULT_MAX_FEATURES = 150

# Ensemble pruning defaults
DEFAULT_MIN_ALERT_FILL = 0.5
DEFAULT_MAX_DRIFT_RATIO = 3.0
DEFAULT_MIN_AGREEMENT = 0.05
DEFAULT_MAX_REDUNDANCY = 0.95
DEFAULT_MIN_ENSEMBLE_MODELS = 2
REDUNDANCY_SAMPLE = 200_000
DRIFT_MIN_ROWS = 2_000
DRIFT_MIN_EXPECTED_ALERTS = 10
DEFAULT_CONSENSUS_MIN_VOTES = 3

# Proxy labels and greedy model selection
DEFAULT_OBSERVATIONS = Path("data/phase2_observations/ossec")
DATASET_FILES = {
    "individual": "ossec_events_all_months.csv",
    "host_5min": "ossec_host_windows_5min.csv",
    "episodes": "ossec_security_episodes.csv",
    "host_behavior_1d": "ossec_host_behavior_1d.csv",
}
# Monitoring-risk event types: agent stops, manager-communication failures,
# integrity-baseline gaps and configuration gaps (Stage 2 RISK_EVENT_GROUPS
# minus agent_start, which is routine after every restart).
SECURITY_EVENT_TYPES = frozenset({
    "OSSEC_SIGNAL_RECEIVED_EXITING", "OSSEC_SHUTDOWN_RESPONSES_DELETED",
    "OSSEC_EMAIL_DISABLED_CLEAN_EXIT",
    "OSSEC_SERVER_UNAVAILABLE_LOCK_SET", "OSSEC_WAITING_FOR_REPLY",
    "OSSEC_NEXT_SERVER", "OSSEC_CONNECTION_CLOSED", "OSSEC_PROCESS_LOCKED",
    "OSSEC_SERVER_MESSAGE_SEND_FAILED", "OSSEC_QUEUE_MESSAGE_SEND_FAILED",
    "OSSEC_SOCKET_ERROR_UNAVAILABLE",
    "OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND", "OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND",
    "OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE",
    "OSSEC_MANAGER_IP_NOT_SET", "OSSEC_ACTIVE_RESPONSE_COMMAND_UNAVAILABLE",
})
# Individual rows at or above this severity rank (ERROR) are also positive.
SECURITY_MIN_SEVERITY_RANK = 5
# Aggregate rows are proxy-positive if any of these Stage 2 counts is non-zero.
SECURITY_COUNT_COLUMNS = (
    "agent_stop_count", "communication_failure_count", "integrity_gap_count",
    "configuration_gap_count", "high_severity_count", "error_count",
    "critical_count", "alert_count", "emergency_count",
)
DEFAULT_MIN_DETECTION_GAIN = 0.005
PROBE_TREES = 200
PROXY_MIN_MATCH_RATE = 0.99

# Substrings of feature names that carry identity rather than behaviour.
# Process IDs, agent counters and raw ports are excluded as in Stage 4.
IDENTITY_TOKENS = (
    "row_manifest_id", "event_id", "source_line", "raw_line",
    "timestamp_epoch", "dataset_id", "episode_id", "session_id",
    "numeric__pid", "indicator_pid", "started_pid", "counter_value",
    "numeric__source_port", "numeric__destination_port",
)
MODEL_ORDER = (
    "isolation_forest", "sgd_ocsvm", "svd_reconstruction", "lof", "rbf_ocsvm",
    "elliptic_envelope", "gaussian_mixture", "knn_distance", "kmeans_distance",
    "pca_reconstruction", "hbos", "ecod", "autoencoder",
)


@dataclass
class Split:
    matrix: sparse.csr_matrix
    rows: pd.DataFrame


import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


def parse_args():
    parser = argparse.ArgumentParser(
        description="OSSEC model-zoo benchmark with feature selection and ensemble pruning."
    )
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dataset", action="append", default=[])
    parser.add_argument("--feature-set", choices=("full", "selected", "both"), default="both",
                        help="Fit on all features, relevance-selected features, or both.")
    parser.add_argument("--quantile", type=float, default=DEFAULT_QUANTILE)
    parser.add_argument("--svd-components", type=int, default=DEFAULT_SVD_COMPONENTS)
    parser.add_argument("--general-sample", type=int, default=DEFAULT_GENERAL_SAMPLE)
    parser.add_argument("--expensive-sample", type=int, default=DEFAULT_EXPENSIVE_SAMPLE)
    parser.add_argument("--covariance-sample", type=int, default=DEFAULT_COVARIANCE_SAMPLE)
    parser.add_argument("--neighbors", type=int, default=DEFAULT_NEIGHBORS)
    parser.add_argument("--gmm-components", type=int, default=DEFAULT_GMM_COMPONENTS)
    parser.add_argument("--kmeans-clusters", type=int, default=DEFAULT_KMEANS_CLUSTERS)
    parser.add_argument("--hbos-bins", type=int, default=DEFAULT_HBOS_BINS)
    parser.add_argument("--enable-autoencoder", action="store_true")
    parser.add_argument("--autoencoder-sample", type=int, default=DEFAULT_AUTOENCODER_SAMPLE)
    parser.add_argument("--review-rows", type=int, default=DEFAULT_REVIEW_ROWS)
    parser.add_argument("--skip-model", action="append", default=[])
    parser.add_argument("--only-model", action="append", default=[])
    # Feature relevance
    parser.add_argument("--relevance-sample", type=int, default=DEFAULT_RELEVANCE_SAMPLE)
    parser.add_argument("--importance-rows", type=int, default=DEFAULT_IMPORTANCE_ROWS)
    parser.add_argument("--drift-max-ks", type=float, default=DEFAULT_DRIFT_MAX_KS)
    parser.add_argument("--redundancy-max-corr", type=float, default=DEFAULT_REDUNDANCY_MAX_CORR)
    parser.add_argument("--importance-coverage", type=float, default=DEFAULT_IMPORTANCE_COVERAGE)
    parser.add_argument("--min-features", type=int, default=DEFAULT_MIN_FEATURES)
    parser.add_argument("--max-features", type=int, default=DEFAULT_MAX_FEATURES)
    # Ensemble pruning
    parser.add_argument("--no-ensemble-pruning", action="store_true")
    parser.add_argument("--min-alert-fill", type=float, default=DEFAULT_MIN_ALERT_FILL,
                        help="Drop models whose validation alerts fall below this share of "
                             "the expected count (tied/degenerate scores).")
    parser.add_argument("--max-drift-ratio", type=float, default=DEFAULT_MAX_DRIFT_RATIO,
                        help="Drop models whose alert rate differs by more than this factor "
                             "between the two halves of validation.")
    parser.add_argument("--min-agreement", type=float, default=DEFAULT_MIN_AGREEMENT,
                        help="Drop models whose best Jaccard overlap with any other model "
                             "is below this value.")
    parser.add_argument("--max-redundancy", type=float, default=DEFAULT_MAX_REDUNDANCY,
                        help="Drop the weaker of two models whose validation score ranks "
                             "correlate above this value.")
    parser.add_argument("--min-ensemble-models", type=int, default=DEFAULT_MIN_ENSEMBLE_MODELS)
    # Proxy labels, greedy model selection and feature sweep
    parser.add_argument("--observations", type=Path, default=DEFAULT_OBSERVATIONS,
                        help="Stage 2 folder, used to build proxy labels for aggregate datasets.")
    parser.add_argument("--no-proxy-labels", action="store_true",
                        help="Disable proxy labels (and therefore greedy selection and sweeps).")
    parser.add_argument("--model-selection", choices=("greedy", "prune-only"), default="greedy",
                        help="After pruning, keep only models that add detection rate (greedy).")
    parser.add_argument("--min-detection-gain", type=float, default=DEFAULT_MIN_DETECTION_GAIN,
                        help="Keep the smallest model prefix within this detection rate of the "
                             "best prefix (absolute, default 0.005 = 0.5 points).")
    parser.add_argument("--feature-sweep", default="",
                        help="Comma-separated top-K feature counts to probe, e.g. 10,25,50,100.")
    # Consensus
    parser.add_argument("--calibration-split", choices=calibration.MODES, default="halves",
                        help="halves: validation's earlier half chooses features and models, its later half sets every "
                             "threshold; all: both on every validation row (before 2026-10-30)")
    parser.add_argument("--consensus-min-votes", type=int, default=DEFAULT_CONSENSUS_MIN_VOTES)
    parser.add_argument("--consensus-scope", choices=("members", "all"), default="members",
                        help="Count votes from ensemble members only, or all completed models.")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    if not 0.5 < args.quantile < 1:
        parser.error("--quantile must be between 0.5 and 1.0")
    if not 0 < args.importance_coverage <= 1:
        parser.error("--importance-coverage must be in (0, 1]")
    if args.min_features < 1 or args.max_features < args.min_features:
        parser.error("require 1 <= --min-features <= --max-features")
    if args.consensus_min_votes < 1:
        parser.error("--consensus-min-votes must be at least 1")
    try:
        args.feature_sweep = sorted({int(value) for value in args.feature_sweep.split(",")
                                     if value.strip()})
    except ValueError:
        parser.error("--feature-sweep must be comma-separated integers")
    if any(value < 1 for value in args.feature_sweep):
        parser.error("--feature-sweep values must be positive")
    return args


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

def write_json(path, payload):
    def convert(value):
        if isinstance(value, dict):
            return {str(key): convert(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [convert(item) for item in value]
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, np.ndarray):
            return convert(value.tolist())
        if isinstance(value, (np.integer,)):
            return int(value)
        if isinstance(value, (np.bool_,)):
            return bool(value)
        if isinstance(value, (np.floating, float)):
            value = float(value)
            return value if math.isfinite(value) else None
        return value

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(convert(payload), indent=2, allow_nan=False),
                         encoding="utf-8")
    os.replace(temporary, path)


def discover_datasets(folder, requested):
    if requested:
        names = requested
    elif folder.is_dir():
        present = [item.name for item in sorted(folder.iterdir())
                   if item.is_dir() and (item / "X_train.npz").is_file()]
        names = [name for name in DATASETS if name in present]
        names += [name for name in present if name not in DATASETS]
    else:
        names = []
    if not names:
        raise FileNotFoundError("No Stage 3 OSSEC datasets found in " + str(folder))
    return names


def validate_feature_metadata(folder, dataset):
    path = folder / "metadata.json"
    if not path.is_file():
        raise FileNotFoundError("Missing Stage 3 metadata (dataset may not have completed): "
                                + str(path))
    with open(path, "r", encoding="utf-8") as handle:
        metadata = json.load(handle)
    if metadata.get("dataset") != dataset:
        raise ValueError("Metadata dataset mismatch for " + dataset)
    if metadata.get("feature_artifact_contract") != EXPECTED_FEATURE_CONTRACT:
        raise ValueError("Unsupported feature contract for " + dataset + ": "
                         + str(metadata.get("feature_artifact_contract")))
    if metadata.get("lineage_status") not in {"complete", "validated"}:
        raise ValueError("Incomplete Stage 3 lineage for " + dataset)
    return metadata


def load_split(folder, name):
    """Load a split as float32 CSR (half the memory of v1's float64)."""
    matrix_path = folder / ("X_" + name + ".npz")
    rows_path = folder / (name + "_rows.csv")
    if not matrix_path.is_file() or not rows_path.is_file():
        raise FileNotFoundError("Missing " + name + " artifacts in " + str(folder))
    matrix = sparse.load_npz(matrix_path).tocsr()
    if matrix.dtype != np.float32:
        matrix = matrix.astype(np.float32)
    rows = pd.read_csv(rows_path, low_memory=False)
    if "row_manifest_id" not in rows.columns:
        raise ValueError(str(rows_path) + " lacks row_manifest_id")
    rows["row_manifest_id"] = rows["row_manifest_id"].fillna("").astype(str).str.strip()
    if rows["row_manifest_id"].eq("").any():
        raise ValueError(str(rows_path) + " contains blank row_manifest_id")
    if rows["row_manifest_id"].duplicated().any():
        raise ValueError(str(rows_path) + " contains duplicate row_manifest_id")
    if matrix.shape[0] != len(rows):
        raise ValueError(name + " matrix and row-manifest sizes differ")
    if name == "train":                     # approved change windows never teach "normal"
        inside = change_window_mask(rows, load_change_windows())
        if inside.any():
            runlog.log(f"{folder.name}: {int(inside.sum()):,} training rows fall in approved change windows and are left out")
            matrix, rows = matrix[~inside], rows.loc[~inside].reset_index(drop=True)
    return Split(matrix, rows)


def load_feature_names(folder, width):
    path = folder / "feature_names.csv"
    frame = pd.read_csv(path)
    if "feature_name" not in frame.columns:
        raise ValueError(str(path) + " lacks feature_name")
    names = frame["feature_name"].astype(str).tolist()
    if len(names) != width:
        raise ValueError("Feature-name count does not equal matrix width")
    return names


def identity_filtered_indices(names):
    selected = [index for index, name in enumerate(names)
                if name.lower().startswith(("text__", "sequence__", "text_hash__", "sequence_hash__"))
                or not any(token in name.lower() for token in IDENTITY_TOKENS)]
    if not selected:
        raise ValueError("Identity exclusion removed every feature")
    return np.asarray(selected, dtype=int)


def model_selection(args):
    selected = set(MODEL_ORDER)
    if args.only_model:
        selected &= set(args.only_model)
    selected -= set(args.skip_model)
    if not args.enable_autoencoder:
        selected.discard("autoencoder")
    unknown = (set(args.only_model) | set(args.skip_model)) - set(MODEL_ORDER)
    if unknown:
        raise ValueError("Unknown model name(s): " + ", ".join(sorted(unknown)))
    return [name for name in MODEL_ORDER if name in selected]


def random_indices(total, maximum, rng):
    if total <= maximum:
        return np.arange(total)
    return np.sort(rng.choice(total, maximum, replace=False))


def sample_rows(matrix, maximum, rng):
    indices = random_indices(matrix.shape[0], maximum, rng)
    return matrix[indices], indices


def score_in_chunks(matrix, scorer, rows=SCORE_CHUNK_ROWS):
    """Apply a scorer to row blocks so large splits never need a full copy."""
    if matrix.shape[0] == 0:
        return np.zeros(0)
    return np.concatenate([np.asarray(scorer(matrix[start:start + rows]), dtype=float)
                           for start in range(0, matrix.shape[0], rows)])


def alert_cap(dataset):
    return MAX_ALERT_FRACTION.get(dataset, DEFAULT_MAX_ALERT_FRACTION)


def calibrate(scores, dataset, quantile):
    values = np.asarray(scores, dtype=float)
    finite = values[np.isfinite(values)]
    if finite.size == 0:
        return {"threshold": float("inf"), "allowed_alerts": 0,
                "realized_alerts": 0, "tie_adjusted": False}
    allowance = max(1, int(math.floor(finite.size * alert_cap(dataset))))
    threshold_quantile = float(np.quantile(finite, quantile))
    budget_index = max(finite.size - allowance, 0)
    threshold_budget = float(np.partition(finite, budget_index)[budget_index])
    nominal = max(threshold_quantile, threshold_budget)
    realized = int(np.count_nonzero(finite >= nominal))
    selected = float(np.nextafter(nominal, np.inf)) if realized > allowance else nominal
    return {
        "threshold": selected,
        "allowed_alerts": allowance,
        "realized_alerts": int(np.count_nonzero(finite >= selected)),
        "tie_adjusted": selected != nominal,
        "quantile_threshold": threshold_quantile,
        "budget_threshold": threshold_budget,
    }


def percentile(reference_sorted, values):
    """Percentile against training scores, extended beyond the training maximum.

    Plain percentiles cap every score above the training maximum at 1.0, so
    strong anomalies tie and the tie rule in :func:`calibrate` can then push
    the threshold above all of them. Scores beyond the maximum get a small,
    monotonic bonus scaled by the training top-1% spread (training data only).
    """
    values = np.asarray(values, dtype=float)
    if reference_sorted.size == 0:
        return np.zeros(values.shape[0])
    base = np.searchsorted(reference_sorted, values, side="right") / reference_sorted.size
    top = reference_sorted[-1]
    spread = top - reference_sorted[int(0.99 * (reference_sorted.size - 1))]
    if not np.isfinite(spread) or spread <= 0:
        spread = max(abs(top), 1.0) * 1e-3
    excess = np.nan_to_num(np.clip((values - top) / spread, 0, None), nan=0.0, posinf=1e6)
    return base + 0.01 * np.log1p(excess)


def time_order(rows):
    """Chronological order of manifest rows, falling back to file order."""
    for column in TIME_COLUMNS:
        if column in rows.columns:
            parsed = pd.to_datetime(rows[column], errors="coerce", utc=True)
            if parsed.notna().mean() > 0.9:
                filled = parsed.fillna(parsed.max())
                return np.argsort(filled.to_numpy(), kind="stable")
    return np.arange(len(rows))


# ---------------------------------------------------------------------------
# Proxy labels and detection metrics
# ---------------------------------------------------------------------------

def load_proxy_labels(dataset, folder, args, log):
    """Build weak security-relevant labels for validation and test rows.

    Returns ``(labels, source)`` where labels maps split name to a boolean
    array aligned with that split's row manifest, or ``(None, reason)``.
    Training rows are never labelled; labels are used for validation-based
    selection and for test reporting only.
    """
    if args.no_proxy_labels:
        return None, "disabled"
    frames = {}
    for split in ("validation", "test"):
        frames[split] = pd.read_csv(folder / (split + "_rows.csv"), low_memory=False,
                                    usecols=lambda c: c in {"row_manifest_id", "event_type",
                                                            "severity_rank"})
        frames[split]["row_manifest_id"] = (
            frames[split]["row_manifest_id"].fillna("").astype(str).str.strip())
    if all("event_type" in frame.columns for frame in frames.values()):
        labels = {}
        for split, frame in frames.items():
            positive = frame["event_type"].fillna("").astype(str).isin(SECURITY_EVENT_TYPES)
            if "severity_rank" in frame.columns:
                rank = pd.to_numeric(frame["severity_rank"], errors="coerce").fillna(0)
                positive |= rank >= SECURITY_MIN_SEVERITY_RANK
            labels[split] = positive.to_numpy()
        return labels, "event_type_or_severity"
    path = args.observations / DATASET_FILES.get(dataset, "__missing__")
    if not path.is_file():
        log.write(f"{dataset}: proxy labels unavailable ({path} not found)", "WARN")
        return None, "stage2_missing"
    header = pd.read_csv(path, nrows=0).columns
    columns = [column for column in SECURITY_COUNT_COLUMNS if column in header]
    if not columns:
        log.write(f"{dataset}: proxy labels unavailable (no security count columns)", "WARN")
        return None, "no_count_columns"
    needed = set(frames["validation"]["row_manifest_id"]) | set(frames["test"]["row_manifest_id"])
    positive, found = set(), set()
    for chunk in pd.read_csv(path, usecols=["row_manifest_id"] + columns,
                             chunksize=500_000, low_memory=False):
        ids = chunk["row_manifest_id"].fillna("").astype(str).str.strip()
        mask = ids.isin(needed).to_numpy()
        if not mask.any():
            continue
        found.update(ids[mask])
        counts = chunk.loc[mask, columns].apply(pd.to_numeric, errors="coerce").fillna(0)
        positive.update(ids[mask][counts.sum(axis=1).to_numpy() > 0])
    match = len(found) / max(len(needed), 1)
    if match < PROXY_MIN_MATCH_RATE:
        log.write(f"{dataset}: only {match:.1%} of rows found in {path.name}; Stage 2 and "
                  "Stage 3 outputs look out of sync, so proxy labels are disabled", "WARN")
        return None, "stage2_out_of_sync"
    labels = {split: frame["row_manifest_id"].isin(positive).to_numpy()
              for split, frame in frames.items()}
    return labels, "stage2_counts"


def top_k_flags(scores, k):
    """Flag the k highest scores (fixed alert budget)."""
    flags = np.zeros(len(scores), dtype=bool)
    k = min(int(k), len(scores))
    if k > 0:
        flags[np.argpartition(-np.nan_to_num(scores, nan=-np.inf), k - 1)[:k]] = True
    return flags


def proxy_metrics(flags, labels):
    """Detection rate, precision and lift of alert flags against proxy labels."""
    flags = np.asarray(flags, dtype=bool)
    labels = np.asarray(labels, dtype=bool)
    positives, alerts = int(labels.sum()), int(flags.sum())
    hits = int((flags & labels).sum())
    base = positives / len(labels) if len(labels) else 0.0
    precision = hits / alerts if alerts else 0.0
    return {
        "alerts": alerts, "hits": hits, "positives": positives, "base_rate": base,
        "detection_rate": hits / positives if positives else np.nan,
        "precision": precision, "lift": precision / base if base else np.nan,
    }


def alert_budget(size, args):
    """Alert count implied by the calibration quantile for ``size`` rows."""
    return max(1, int(round((1 - args.quantile) * size)))


# ---------------------------------------------------------------------------
# Custom detectors (unchanged from v1)
# ---------------------------------------------------------------------------

class HBOS:
    def __init__(self, bins=20):
        self.bins = bins
        self.edges = []
        self.densities = []

    def fit(self, matrix):
        for index in range(matrix.shape[1]):
            values = matrix[:, index]
            edges = np.histogram_bin_edges(values, bins=self.bins)
            if len(np.unique(edges)) < 2:
                edges = np.asarray([values.min() - .5, values.max() + .5])
            counts, edges = np.histogram(values, bins=edges)
            probabilities = (counts + .5) / (len(values) + .5 * len(counts))
            self.edges.append(edges)
            self.densities.append(-np.log(np.clip(probabilities, EPSILON, 1)))
        return self

    def score_samples(self, matrix):
        scores = np.zeros(matrix.shape[0])
        for index in range(matrix.shape[1]):
            bins = np.searchsorted(self.edges[index], matrix[:, index], side="right") - 1
            bins = np.clip(bins, 0, len(self.densities[index]) - 1)
            scores += self.densities[index][bins]
        return scores


class ECODStyle:
    def __init__(self):
        self.sorted_columns = []
        self.skew_right = []

    def fit(self, matrix):
        for index in range(matrix.shape[1]):
            values = np.asarray(matrix[:, index], dtype=float)
            values = values[np.isfinite(values)]
            if values.size == 0:
                values = np.asarray([0.0])
            self.sorted_columns.append(np.sort(values))
            self.skew_right.append(np.mean(values) >= np.median(values))
        return self

    def score_samples(self, matrix):
        contributions = np.zeros_like(matrix, dtype=float)
        for index, reference in enumerate(self.sorted_columns):
            values = np.nan_to_num(matrix[:, index], nan=0.0)
            left = (np.searchsorted(reference, values, side="right") + .5) / (len(reference) + 1)
            right = (len(reference) - np.searchsorted(reference, values, side="left") + .5) / (len(reference) + 1)
            left = np.clip(left, EPSILON, 1)
            right = np.clip(right, EPSILON, 1)
            two_sided = -np.log(np.minimum(left, right))
            directional = -np.log(right if self.skew_right[index] else left)
            contributions[:, index] = np.maximum(two_sided, directional)
        return np.max(contributions, axis=1) + np.mean(contributions, axis=1)


# ---------------------------------------------------------------------------
# Feature relevance
# ---------------------------------------------------------------------------

def feature_relevance(train, validation, names, candidates, args, log, rng):
    """Score features on train/validation samples and choose a reduced set.

    Returns selected column indices (into the Stage 3 matrix) and a per-feature
    decision table. Test data is never read.
    """
    train_rows = random_indices(train.shape[0], args.relevance_sample, rng)
    validation_rows = random_indices(validation.shape[0], args.relevance_sample, rng)
    train_sample = train[train_rows][:, candidates].toarray().astype(np.float32)
    validation_sample = validation[validation_rows][:, candidates].toarray().astype(np.float32)
    count = len(candidates)
    keep = np.ones(count, dtype=bool)
    reason = np.full(count, "", dtype=object)
    detail = np.full(count, "", dtype=object)

    nonzero = np.asarray(train.getnnz(axis=0))[candidates]
    std = train_sample.std(axis=0)
    constant = std < 1e-9
    reason[constant] = "constant_in_training"
    keep &= ~constant
    log.write(f"relevance: {int(constant.sum())} constant features removed")

    ks = np.full(count, np.nan)
    for j in np.flatnonzero(keep):
        ks[j] = stats.ks_2samp(train_sample[:, j], validation_sample[:, j],
                               method="asymp").statistic
    drifted = keep & (ks > args.drift_max_ks)
    reason[drifted] = "drift_train_vs_validation"
    keep &= ~drifted
    log.write(f"relevance: {int(drifted.sum())} drifting features removed "
              f"(KS > {args.drift_max_ks})")

    kept = np.flatnonzero(keep)
    redundant_count = 0
    if len(kept) > 1:
        correlation = np.abs(np.corrcoef(train_sample[:, kept], rowvar=False))
        correlation = np.nan_to_num(correlation, nan=0.0)
        alive = np.ones(len(kept), dtype=bool)
        for i in range(len(kept)):
            if not alive[i]:
                continue
            duplicates = np.flatnonzero(correlation[i, i + 1:] > args.redundancy_max_corr) + i + 1
            for d in duplicates:
                if alive[d]:
                    alive[d] = False
                    reason[kept[d]] = "redundant"
                    detail[kept[d]] = f"with {names[candidates[kept[i]]]}"
                    redundant_count += 1
        keep[kept[~alive]] = False
    log.write(f"relevance: {redundant_count} redundant features removed "
              f"(|r| > {args.redundancy_max_corr})")

    importance = np.full(count, np.nan)
    kept = np.flatnonzero(keep)
    if len(kept):
        model = IsolationForest(n_estimators=IMPORTANCE_TREES, random_state=RANDOM_STATE,
                                n_jobs=-1)
        model.fit(train_sample[:, kept])
        rows = validation_sample[:min(args.importance_rows, len(validation_sample))][:, kept].copy()
        base = -model.score_samples(rows)
        log.write(f"relevance: permutation importance for {len(kept)} features "
                  f"on {len(rows):,} validation rows")
        for position, j in enumerate(kept):
            original = rows[:, position].copy()
            rows[:, position] = rng.permutation(original)
            importance[j] = float(np.mean(np.abs(-model.score_samples(rows) - base)))
            rows[:, position] = original

    ranked = kept[np.argsort(-importance[kept], kind="stable")]
    total = float(np.nansum(importance[kept]))
    if total > 0:
        cumulative = np.cumsum(importance[ranked]) / total
        needed = int(np.searchsorted(cumulative, args.importance_coverage) + 1)
    else:
        needed = len(ranked)
    needed = max(args.min_features, min(args.max_features, needed))
    chosen = ranked[:needed]
    selected_mask = np.zeros(count, dtype=bool)
    selected_mask[chosen] = True
    for j in ranked[needed:]:
        reason[j] = "below_importance_cutoff"
    reason[selected_mask] = "selected"
    rank = np.full(count, np.nan)
    rank[ranked] = np.arange(1, len(ranked) + 1)

    table = pd.DataFrame({
        "feature_index": candidates,
        "feature_name": [names[i] for i in candidates],
        "train_nonzero_rows": nonzero,
        "sample_std": std,
        "drift_ks": ks,
        "importance": importance,
        "importance_rank": rank,
        "selected": selected_mask,
        "decision": reason,
        "detail": detail,
    }).sort_values(["selected", "importance"], ascending=[False, False])
    log.write(f"relevance: selected {int(selected_mask.sum())} of {count} features", "DONE")
    return np.sort(candidates[chosen]), table


def feature_sweep(train, validation, table, candidates, coverage_count, labels, args, log, rng):
    """Probe top-K feature sets with a fast Isolation Forest on validation.

    Returns the chosen feature indices (or None if no sweep was possible) and a
    table with one row per K plus the all-feature baseline.
    """
    ranked = (table.loc[table["importance_rank"].notna()]
              .sort_values("importance_rank")["feature_index"].to_numpy(dtype=int))
    if not len(ranked) or labels is None or not labels.any():
        log.write("feature sweep skipped (no ranked features or no proxy-positive rows)", "WARN")
        return None, pd.DataFrame()
    sizes = sorted({min(size, len(ranked)) for size in args.feature_sweep}
                   | {min(coverage_count, len(ranked))})
    budget = alert_budget(validation.shape[0], args)
    sample, _ = sample_rows(train, args.general_sample, rng)
    rows = []
    for label, columns in [(str(size), np.sort(ranked[:size])) for size in sizes] + \
            [("all_candidates", np.sort(candidates))]:
        started = time.perf_counter()
        model = IsolationForest(n_estimators=PROBE_TREES, random_state=RANDOM_STATE, n_jobs=-1)
        model.fit(sample[:, columns])
        scores = score_in_chunks(validation, lambda block: -model.score_samples(block[:, columns]))
        metrics = proxy_metrics(top_k_flags(scores, budget), labels)
        rows.append({"top_k": label, "features": len(columns),
                     "validation_detection_rate": metrics["detection_rate"],
                     "validation_precision": metrics["precision"],
                     "validation_lift": metrics["lift"],
                     "seconds": time.perf_counter() - started})
        log.write(f"feature sweep: top {label} ({len(columns)} features) -> detection rate "
                  f"{metrics['detection_rate']:.3f}, precision {metrics['precision']:.3f}")
    frame = pd.DataFrame(rows)
    reduced = frame[frame["top_k"] != "all_candidates"].copy()
    reduced["top_k_int"] = reduced["top_k"].astype(int)
    best = reduced.sort_values(["validation_detection_rate", "top_k_int"],
                               ascending=[False, True]).iloc[0]
    frame["chosen"] = frame["top_k"].eq(best["top_k"])
    baseline = frame.loc[frame["top_k"] == "all_candidates", "validation_detection_rate"].iloc[0]
    if baseline > best["validation_detection_rate"]:
        log.write(f"feature sweep: all candidates ({baseline:.3f}) beat the best top-K "
                  f"({best['validation_detection_rate']:.3f}); compare the full run", "WARN")
    log.write(f"feature sweep: chose top {best['top_k']} features", "DONE")
    return np.sort(ranked[:int(best["top_k"])]), frame


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

def build_embedding(train, validation, test, components, sample_limit, rng):
    sampled, sample_indices = sample_rows(train, sample_limit, rng)
    maximum = min(components, sampled.shape[0] - 1, sampled.shape[1] - 1)
    if maximum < 2:
        raise ValueError("Insufficient matrix rank for shared dense embedding")
    reducer = TruncatedSVD(n_components=maximum, random_state=RANDOM_STATE)
    train_sample = reducer.fit_transform(sampled)
    scaler = StandardScaler().fit(train_sample)
    transform = lambda block: scaler.transform(reducer.transform(block))  # noqa: E731
    return (reducer, scaler, scaler.transform(train_sample),
            score_in_chunks_dense(validation, transform),
            score_in_chunks_dense(test, transform), sample_indices)


def score_in_chunks_dense(matrix, transform, rows=SCORE_CHUNK_ROWS):
    if matrix.shape[0] == 0:
        return np.zeros((0, 0))
    return np.vstack([transform(matrix[start:start + rows])
                      for start in range(0, matrix.shape[0], rows)])


def svd_reconstruction_error(model, block):
    block = block.astype(np.float64)
    latent = model.transform(block)
    original = np.asarray(block.multiply(block).sum(axis=1)).ravel()
    return np.sqrt(np.maximum(original - np.sum(latent ** 2, axis=1), 0))


def dense_sample(train_dense, maximum, rng):
    """Random rows of the dense embedding (v1 took the first N rows)."""
    return train_dense[random_indices(train_dense.shape[0], maximum, rng)]


def run_model(model_name, train_sparse, validation_sparse, test_sparse,
              train_dense, validation_dense, test_dense, embedding_reducer, args, rng):
    started = time.perf_counter()

    if model_name == "isolation_forest":
        sample, _ = sample_rows(train_sparse, args.general_sample, rng)
        model = IsolationForest(n_estimators=300, contamination="auto",
                                random_state=RANDOM_STATE, n_jobs=-1)
        model.fit(sample)
        train_scores = -model.score_samples(sample)
        validation_scores = -model.score_samples(validation_sparse)
        test_scores = -model.score_samples(test_sparse)
        fit_rows = sample.shape[0]

    elif model_name == "sgd_ocsvm":
        # Memory fix: sample first, then normalise; score other splits in chunks.
        sample, _ = sample_rows(train_sparse, args.general_sample, rng)
        normalizer = Normalizer()
        sample = normalizer.transform(sample.astype(np.float64))
        model = SGDOneClassSVM(nu=0.05, shuffle=True, random_state=RANDOM_STATE,
                               max_iter=20, tol=1e-4, average=True)
        model.fit(sample)
        scorer = lambda block: -model.decision_function(  # noqa: E731
            normalizer.transform(block.astype(np.float64)))
        train_scores = -model.decision_function(sample)
        validation_scores = score_in_chunks(validation_sparse, scorer)
        test_scores = score_in_chunks(test_sparse, scorer)
        fit_rows = sample.shape[0]

    elif model_name == "svd_reconstruction":
        model = embedding_reducer
        sample, _ = sample_rows(train_sparse, args.general_sample, rng)
        scorer = lambda block: svd_reconstruction_error(model, block)  # noqa: E731
        train_scores = scorer(sample)
        validation_scores = score_in_chunks(validation_sparse, scorer)
        test_scores = score_in_chunks(test_sparse, scorer)
        fit_rows = sample.shape[0]

    elif model_name == "lof":
        sample = dense_sample(train_dense, args.expensive_sample, rng)
        neighbors = min(args.neighbors, max(2, sample.shape[0] - 1))
        model = LocalOutlierFactor(n_neighbors=neighbors, novelty=True,
                                   contamination="auto", n_jobs=-1)
        model.fit(sample)
        # Fit-time LOF excludes each row from its own neighbourhood.
        train_scores = -model.negative_outlier_factor_
        validation_scores = -model.score_samples(validation_dense)
        test_scores = -model.score_samples(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "rbf_ocsvm":
        sample = dense_sample(train_dense, args.expensive_sample, rng)
        model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05, cache_size=1024)
        model.fit(sample)
        train_scores = -model.decision_function(sample)
        validation_scores = -model.decision_function(validation_dense)
        test_scores = -model.decision_function(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "elliptic_envelope":
        sample = dense_sample(train_dense, args.covariance_sample, rng)
        model = EllipticEnvelope(contamination=0.05, random_state=RANDOM_STATE,
                                 support_fraction=None)
        with warnings.catch_warnings():
            # Near-singular covariance triggers thousands of "determinant has
            # increased" warnings; the pruning step judges the model instead.
            warnings.simplefilter("ignore", RuntimeWarning)
            model.fit(sample)
        train_scores = -model.score_samples(sample)
        validation_scores = -model.score_samples(validation_dense)
        test_scores = -model.score_samples(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "gaussian_mixture":
        sample = dense_sample(train_dense, args.general_sample, rng)
        components = min(args.gmm_components, max(1, sample.shape[0] // 100))
        model = GaussianMixture(n_components=components, covariance_type="diag",
                                reg_covar=1e-5, random_state=RANDOM_STATE, max_iter=200)
        model.fit(sample)
        train_scores = -model.score_samples(sample)
        validation_scores = -model.score_samples(validation_dense)
        test_scores = -model.score_samples(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "knn_distance":
        sample = dense_sample(train_dense, args.expensive_sample, rng)
        neighbors = min(args.neighbors, max(2, sample.shape[0] - 2))
        model = NearestNeighbors(n_neighbors=neighbors, n_jobs=-1)
        model.fit(sample)
        # Ask for one extra neighbour on training rows and drop the self-match.
        train_scores = model.kneighbors(sample, n_neighbors=neighbors + 1)[0][:, -1]
        validation_scores = model.kneighbors(validation_dense)[0][:, -1]
        test_scores = model.kneighbors(test_dense)[0][:, -1]
        fit_rows = sample.shape[0]

    elif model_name == "kmeans_distance":
        sample = dense_sample(train_dense, args.general_sample, rng)
        clusters = min(args.kmeans_clusters, max(2, sample.shape[0] // 100))
        model = MiniBatchKMeans(n_clusters=clusters, random_state=RANDOM_STATE,
                                batch_size=min(4096, sample.shape[0]), n_init="auto")
        model.fit(sample)
        train_scores = np.min(model.transform(sample), axis=1)
        validation_scores = np.min(model.transform(validation_dense), axis=1)
        test_scores = np.min(model.transform(test_dense), axis=1)
        fit_rows = sample.shape[0]

    elif model_name == "pca_reconstruction":
        sample = dense_sample(train_dense, args.general_sample, rng)
        components = min(max(2, train_dense.shape[1] // 2), train_dense.shape[1] - 1)
        model = PCA(n_components=components, random_state=RANDOM_STATE).fit(sample)
        error = lambda values: np.sqrt(np.mean(  # noqa: E731
            (values - model.inverse_transform(model.transform(values))) ** 2, axis=1))
        train_scores = error(sample)
        validation_scores = error(validation_dense)
        test_scores = error(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "hbos":
        sample = dense_sample(train_dense, args.general_sample, rng)
        model = HBOS(args.hbos_bins).fit(sample)
        train_scores = model.score_samples(sample)
        validation_scores = model.score_samples(validation_dense)
        test_scores = model.score_samples(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "ecod":
        sample = dense_sample(train_dense, args.general_sample, rng)
        model = ECODStyle().fit(sample)
        train_scores = model.score_samples(sample)
        validation_scores = model.score_samples(validation_dense)
        test_scores = model.score_samples(test_dense)
        fit_rows = sample.shape[0]

    elif model_name == "autoencoder":
        sample = dense_sample(train_dense, args.autoencoder_sample, rng)
        hidden = max(4, min(32, train_dense.shape[1] // 2))
        model = MLPRegressor(hidden_layer_sizes=(hidden, max(2, hidden // 4), hidden),
                             activation="relu", solver="adam",
                             batch_size=min(512, sample.shape[0]), learning_rate_init=0.001,
                             max_iter=100, early_stopping=True, validation_fraction=0.1,
                             random_state=RANDOM_STATE)
        model.fit(sample, sample)
        error = lambda values: np.sqrt(np.mean(  # noqa: E731
            (values - model.predict(values)) ** 2, axis=1))
        train_scores = error(sample)
        validation_scores = error(validation_dense)
        test_scores = error(test_dense)
        fit_rows = sample.shape[0]

    else:
        raise ValueError("Unsupported model: " + model_name)

    return {
        "model": model,
        "train_scores": np.asarray(train_scores, dtype=float),
        "validation_scores": np.asarray(validation_scores, dtype=float),
        "test_scores": np.asarray(test_scores, dtype=float),
        "fit_rows": fit_rows,
        "fit_score_seconds": time.perf_counter() - started,
    }


# ---------------------------------------------------------------------------
# Ensemble pruning
# ---------------------------------------------------------------------------

def jaccard(left, right):
    union = np.count_nonzero(left | right)
    return np.count_nonzero(left & right) / union if union else 0.0


def overlap_matrix(alerts):
    names = list(alerts)
    return pd.DataFrame([[jaccard(alerts[a], alerts[b]) for b in names] for a in names],
                        index=names, columns=names)


def ensemble_membership(results, failed, validation_rows, dataset, args, rng):
    """Decide ensemble members from validation evidence only."""
    names = list(results)
    n = len(validation_rows)
    expected = max((1 - args.quantile) * n, 1.0)
    order = time_order(validation_rows)
    first_half = np.zeros(n, dtype=bool)
    first_half[order[: n // 2]] = True
    alerts = {name: results[name]["validation_alert"] for name in names}

    records = {}
    for name in names:
        scores = results[name]["validation_scores"]
        realized = int(alerts[name].sum())
        finite_share = float(np.isfinite(scores).mean()) if n else 0.0
        fill = realized / expected
        drift_ratio = np.nan
        if n >= DRIFT_MIN_ROWS and expected / 2 >= DRIFT_MIN_EXPECTED_ALERTS:
            first = alerts[name][first_half].mean()
            second = alerts[name][~first_half].mean()
            floor = 1.0 / max(n // 2, 1)
            drift_ratio = max(first, second) / max(min(first, second), floor)
        others = [jaccard(alerts[name], alerts[o]) for o in names if o != name]
        records[name] = {
            "model": name, "status": "completed",
            "validation_alerts": realized, "alert_fill": fill,
            "finite_score_share": finite_share, "validation_drift_ratio": drift_ratio,
            "max_agreement": max(others) if others else np.nan,
            "mean_agreement": float(np.mean(others)) if others else np.nan,
            "redundant_with": "", "max_rank_correlation": np.nan,
            "included": True, "reason": "kept",
        }

    def drop(name, reason):
        records[name]["included"] = False
        records[name]["reason"] = reason

    if not args.no_ensemble_pruning:
        for name in names:
            r = records[name]
            if r["finite_score_share"] < 0.99 or r["alert_fill"] < args.min_alert_fill:
                drop(name, "degenerate_scores")
            elif np.isfinite(r["validation_drift_ratio"]) and \
                    r["validation_drift_ratio"] > args.max_drift_ratio:
                drop(name, "unstable_within_validation")
            elif len(names) > 1 and r["max_agreement"] < args.min_agreement:
                drop(name, "no_agreement_with_other_models")

        survivors = [n_ for n_ in names if records[n_]["included"]]
        if len(survivors) > 1:
            rows = random_indices(n, REDUNDANCY_SAMPLE, rng)
            ranks = np.vstack([stats.rankdata(results[s]["validation_scores"][rows])
                               for s in survivors])
            correlation = np.nan_to_num(np.corrcoef(ranks), nan=0.0)
            priority = sorted(range(len(survivors)),
                              key=lambda i: -records[survivors[i]]["mean_agreement"])
            kept = []
            for i in priority:
                partner = next((k for k in kept if correlation[i, k] > args.max_redundancy), None)
                records[survivors[i]]["max_rank_correlation"] = float(
                    max((correlation[i, k] for k in kept), default=np.nan))
                if partner is None:
                    kept.append(i)
                else:
                    records[survivors[i]]["redundant_with"] = survivors[partner]
                    drop(survivors[i], "redundant")

        members = [n_ for n_ in names if records[n_]["included"]]
        if len(members) < args.min_ensemble_models:
            for name in names:
                if records[name]["reason"] in {"redundant", "no_agreement_with_other_models",
                                               "unstable_within_validation"}:
                    records[name]["included"] = True
                    records[name]["reason"] = "reinstated_min_ensemble_size"

    table = pd.DataFrame(list(records.values()))
    for name in failed:
        table = pd.concat([table, pd.DataFrame([{
            "model": name, "status": "failed", "included": False, "reason": "failed"}])],
            ignore_index=True)
    table.insert(0, "dataset", dataset)
    members = table.loc[table["included"], "model"].tolist()
    return members, table


def greedy_model_selection(results, candidates, labels, args):
    """Forward-select models by validation detection rate at a fixed budget.

    Every candidate is ranked (the full curve is returned for reporting). The
    kept set is the smallest prefix whose detection rate is within
    ``--min-detection-gain`` of the best prefix, and at least
    ``--min-ensemble-models`` long.
    """
    budget = alert_budget(len(labels), args)
    percentiles = {m: percentile(results[m]["train_reference"],
                                 results[m]["validation_scores"]).astype(np.float32)
                   for m in candidates}
    remaining, chosen, total, curve, previous = list(candidates), [], None, [], 0.0
    while remaining:
        best = None
        for model in remaining:
            trial = percentiles[model] if total is None else total + percentiles[model]
            metrics = proxy_metrics(top_k_flags(trial / (len(chosen) + 1), budget), labels)
            if best is None or metrics["detection_rate"] > best[1]["detection_rate"] + 1e-12:
                best = (model, metrics)
        model, metrics = best
        chosen.append(model)
        remaining.remove(model)
        total = percentiles[model].astype(np.float64) if total is None else total + percentiles[model]
        curve.append({"step": len(chosen), "model_added": model,
                      "validation_detection_rate": metrics["detection_rate"],
                      "validation_precision": metrics["precision"],
                      "validation_lift": metrics["lift"],
                      "gain": metrics["detection_rate"] - previous})
        previous = metrics["detection_rate"]
    frame = pd.DataFrame(curve)
    target = frame["validation_detection_rate"].max() - args.min_detection_gain
    eligible = frame[(frame["step"] >= min(args.min_ensemble_models, len(frame)))
                     & (frame["validation_detection_rate"] >= target)]
    cutoff = int(eligible["step"].min()) if len(eligible) else len(frame)
    frame["selected"] = frame["step"] <= cutoff
    return frame.loc[frame["selected"], "model_added"].tolist(), frame


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate_feature_set(dataset, folder, output, feature_indices, feature_set, metadata,
                         args, log, labels=None, label_source="unavailable"):
    started = time.perf_counter()
    rng = np.random.default_rng(RANDOM_STATE)
    splits = {}
    for name in ("train", "validation", "test"):
        split = load_split(folder, name)
        matrix = split.matrix[:, feature_indices]
        split.matrix = None  # release the unsliced matrix before loading the next split
        splits[name] = Split(matrix, split.rows)
    train, validation, test = splits["train"], splits["validation"], splits["test"]
    models = model_selection(args)
    log.write(f"{dataset}/{feature_set}: train={train.matrix.shape[0]:,}, "
              f"validation={validation.matrix.shape[0]:,}, test={test.matrix.shape[0]:,}, "
              f"features={len(feature_indices):,}")

    log.write(f"{dataset}/{feature_set}: fitting shared sampled SVD embedding", "PREP")
    reducer, scaler, train_dense, validation_dense, test_dense, sample_indices = build_embedding(
        train.matrix, validation.matrix, test.matrix,
        args.svd_components, args.general_sample, rng)

    validation_frame = validation.rows.copy().reset_index(drop=True)
    test_frame = test.rows.copy().reset_index(drop=True)
    choose, calibrate_rows = calibration.halves(time_order(validation_frame), args.calibration_split)
    validation_frame["validation_part"] = calibration.part(choose, calibrate_rows)
    results, failed, metrics = {}, [], []
    bundle = {
        "dataset": dataset, "feature_set": feature_set,
        "feature_artifact_contract": EXPECTED_FEATURE_CONTRACT,
        "feature_engineer_version": metadata.get("feature_engineer_version"),
        "feature_indices": feature_indices,
        "embedding_reducer": reducer, "embedding_scaler": scaler,
        "embedding_sample_indices": sample_indices,
        "lineage_contract": "row_manifest_id_to_event_id",
        "models": {}, "thresholds": {}, "train_score_reference": {},
    }

    for model_name in models:
        log.write(f"{dataset}/{feature_set}: fitting {model_name}", "MODEL")
        model_started = time.perf_counter()
        try:
            result = run_model(model_name, train.matrix, validation.matrix, test.matrix,
                               train_dense, validation_dense, test_dense, reducer, args, rng)
            threshold = calibrate(result["validation_scores"][calibrate_rows], dataset, args.quantile)
            result["validation_alert"] = result["validation_scores"] >= threshold["threshold"]
            result["test_alert"] = result["test_scores"] >= threshold["threshold"]
            result["train_reference"] = np.sort(result["train_scores"])
            results[model_name] = result
            validation_frame[model_name + "_score"] = result["validation_scores"]
            validation_frame[model_name + "_alert"] = result["validation_alert"]
            test_frame[model_name + "_score"] = result["test_scores"]
            test_frame[model_name + "_alert"] = result["test_alert"]
            bundle["models"][model_name] = result["model"]
            bundle["thresholds"][model_name] = threshold
            bundle["train_score_reference"][model_name] = result["train_reference"]
            metrics.append({
                "dataset": dataset, "feature_set": feature_set, "model": model_name,
                "status": "completed", "fit_rows": result["fit_rows"],
                "validation_alerts": int(result["validation_alert"].sum()),
                "validation_alert_rate": float(result["validation_alert"].mean()),
                "test_alerts": int(result["test_alert"].sum()),
                "test_alert_rate": float(result["test_alert"].mean()),
                "threshold": threshold["threshold"],
                "allowed_validation_alerts": threshold["allowed_alerts"],
                **calibration.rate_check(threshold["allowed_alerts"], int(calibrate_rows.sum()),
                                         int(result["test_alert"].sum()), len(result["test_alert"])),
                "fit_score_seconds": result["fit_score_seconds"],
            })
            if labels is not None:
                for split, flags in (("validation", result["validation_alert"]),
                                     ("test", result["test_alert"])):
                    proxy = proxy_metrics(flags, labels[split])
                    metrics[-1].update({
                        split + "_detection_rate": proxy["detection_rate"],
                        split + "_proxy_precision": proxy["precision"],
                        split + "_proxy_lift": proxy["lift"],
                    })
            log.write(f"{dataset}/{feature_set}/{model_name}: test alerts="
                      f"{int(result['test_alert'].sum()):,} "
                      f"({result['test_alert'].mean() * 100:.2f}%) | "
                      f"elapsed {runlog.format_duration(time.perf_counter() - model_started)}", "DONE")
        except Exception as error:
            failed.append(model_name)
            metrics.append({"dataset": dataset, "feature_set": feature_set,
                            "model": model_name, "status": "failed", "error": repr(error),
                            "fit_score_seconds": time.perf_counter() - model_started})
            log.write(f"{dataset}/{feature_set}/{model_name} failed: {error!r}", "WARN")
            if args.verbose:
                traceback.print_exc()

    chosen = {name: {**r, "validation_alert": r["validation_alert"][choose], "validation_scores": r["validation_scores"][choose]}
              for name, r in results.items()}
    members, membership = ensemble_membership(
        chosen, failed, validation_frame[choose].reset_index(drop=True), dataset, args, rng)
    selection_method = "prune_only"
    curve = pd.DataFrame()
    if (args.model_selection == "greedy" and labels is not None
            and labels["validation"][choose].any() and len(members) > 1):
        pruned_members = list(members)
        members, curve = greedy_model_selection(chosen, pruned_members, labels["validation"][choose], args)
        selection_method = "greedy_detection_rate"
        steps = curve.set_index("model_added")
        membership["greedy_step"] = membership["model"].map(steps["step"])
        membership["greedy_detection_rate"] = membership["model"].map(
            steps["validation_detection_rate"])
        membership["greedy_gain"] = membership["model"].map(steps["gain"])
        dropped_by_greedy = membership["model"].isin(pruned_members) & \
            ~membership["model"].isin(members)
        membership.loc[dropped_by_greedy, "included"] = False
        membership.loc[dropped_by_greedy, "reason"] = "little_detection_gain"
        curve.insert(0, "feature_set", feature_set)
        curve.insert(0, "dataset", dataset)
        best = curve.loc[curve["selected"]].iloc[-1]
        log.write(f"{dataset}/{feature_set}: greedy selection kept {len(members)} of "
                  f"{len(pruned_members)} models; validation detection rate "
                  f"{best['validation_detection_rate']:.3f} (best possible "
                  f"{curve['validation_detection_rate'].max():.3f})", "SELECT")
    elif args.model_selection == "greedy":
        log.write(f"{dataset}/{feature_set}: greedy selection skipped "
                  f"(proxy labels: {label_source})", "WARN")
    if labels is not None:
        for split, frame in (("validation", validation_frame), ("test", test_frame)):
            frame["proxy_security_relevant"] = labels[split]
            if len(results):
                membership[split + "_detection_rate"] = membership["model"].map(
                    {m: proxy_metrics(results[m][split + "_alert"], labels[split])["detection_rate"]
                     for m in results})
    membership.insert(1, "feature_set", feature_set)
    dropped = membership.loc[~membership["included"], ["model", "reason"]]
    log.write(f"{dataset}/{feature_set}: ensemble members ({len(members)}): "
              + ", ".join(members))
    for row in dropped.itertuples():
        log.write(f"{dataset}/{feature_set}: dropped {row.model} ({row.reason})", "PRUNE")
    bundle["ensemble_members"] = members

    if members:
        # Both splits use each member's training scores as the percentile reference.
        validation_ensemble = np.mean([percentile(results[m]["train_reference"],
                                                  results[m]["validation_scores"])
                                       for m in members], axis=0)
        test_ensemble = np.mean([percentile(results[m]["train_reference"],
                                            results[m]["test_scores"])
                                 for m in members], axis=0)
        ensemble_threshold = calibrate(validation_ensemble[calibrate_rows], dataset, args.quantile)
        bundle["ensemble_threshold"] = ensemble_threshold
    else:
        validation_ensemble = np.zeros(len(validation_frame))
        test_ensemble = np.zeros(len(test_frame))
        ensemble_threshold = {"threshold": float("inf")}
    for frame, values in ((validation_frame, validation_ensemble), (test_frame, test_ensemble)):
        frame["model_zoo_ensemble_score"] = values
        frame["model_zoo_ensemble_alert"] = values >= ensemble_threshold["threshold"]

    completed = list(results)
    for frame in (validation_frame, test_frame):
        frame["all_model_vote_count"] = (frame[[m + "_alert" for m in completed]].sum(axis=1)
                                         if completed else 0)
        frame["member_vote_count"] = (frame[[m + "_alert" for m in members]].sum(axis=1)
                                      if members else 0)
        frame["any_member_alert"] = frame["member_vote_count"] > 0
    vote_column = "member_vote_count" if args.consensus_scope == "members" else "all_model_vote_count"
    voters = members if args.consensus_scope == "members" else completed

    output.mkdir(parents=True, exist_ok=True)
    validation_frame.to_csv(output / "validation_scores.csv", index=False)
    test_frame.to_csv(output / "test_scores.csv", index=False)
    metrics_frame = pd.DataFrame(metrics)
    metrics_frame["ensemble_member"] = metrics_frame["model"].isin(members)
    metrics_frame.to_csv(output / "model_metrics.csv", index=False)
    membership.to_csv(output / "ensemble_membership.csv", index=False)
    if len(curve):
        curve.to_csv(output / "model_selection_curve.csv", index=False)
    (overlap_matrix({m: results[m]["test_alert"] for m in completed}) if completed
     else pd.DataFrame()).to_csv(output / "overlap_matrix.csv")

    # A smaller ensemble cannot reach the requested vote count; cap it.
    required_votes = min(args.consensus_min_votes, max(len(voters), 1))
    if required_votes < args.consensus_min_votes:
        log.write(f"{dataset}/{feature_set}: only {len(voters)} voting models; consensus "
                  f"requires {required_votes} votes instead of {args.consensus_min_votes}", "WARN")
    consensus = test_frame[test_frame[vote_column] >= required_votes].copy()
    if len(consensus) and voters:
        flags = consensus[[m + "_alert" for m in voters]].to_numpy(dtype=bool)
        consensus["flagged_by"] = ["|".join(m for m, hit in zip(voters, row) if hit)
                                   for row in flags]
    else:
        consensus["flagged_by"] = ""
    consensus = consensus.sort_values([vote_column, "model_zoo_ensemble_score"],
                                      ascending=False)
    lead = ["row_manifest_id", vote_column, "flagged_by", "model_zoo_ensemble_score",
            "model_zoo_ensemble_alert"]
    consensus = consensus[lead + [c for c in consensus.columns if c not in lead]]
    consensus_path = output / f"consensus_alerts_min{args.consensus_min_votes}.csv"
    consensus.to_csv(consensus_path, index=False)
    log.write(f"{dataset}/{feature_set}: {len(consensus):,} rows flagged by "
              f">= {required_votes} {args.consensus_scope} -> {consensus_path.name}")

    queue = test_frame[test_frame["any_member_alert"] | test_frame["model_zoo_ensemble_alert"]]
    queue = queue.sort_values(["member_vote_count", "model_zoo_ensemble_score"],
                              ascending=False).head(args.review_rows).copy()
    for column in ("review_label", "review_category", "review_notes", "reviewer", "reviewed_at"):
        queue[column] = ""
    queue.to_csv(output / "consensus_review_queue.csv", index=False)
    joblib.dump(bundle, output / "model_bundle.joblib", compress=3)

    summary = {
        "dataset": dataset, "feature_set": feature_set, "status": "completed",
        "feature_artifact_contract": EXPECTED_FEATURE_CONTRACT,
        "feature_engineer_version": metadata.get("feature_engineer_version"),
        "train_rows": train.matrix.shape[0],
        "validation_rows": validation.matrix.shape[0],
        "test_rows": test.matrix.shape[0],
        "features": len(feature_indices),
        "embedding_dimensions": train_dense.shape[1],
        "models_completed": completed, "models_failed": failed,
        "ensemble_members": members,
        "ensemble_dropped": dropped["model"].tolist(),
        "test_any_member_alerts": int(test_frame["any_member_alert"].sum()),
        "test_consensus_two_or_more": int((test_frame[vote_column] >= 2).sum()),
        "test_consensus_three_or_more": int((test_frame[vote_column] >= 3).sum()),
        "test_consensus_min_votes": required_votes,
        "test_consensus_alerts": len(consensus),
        "test_ensemble_alerts": int(test_frame["model_zoo_ensemble_alert"].sum()),
        "review_queue_rows": len(queue),
        "calibration_split": args.calibration_split,
        "validation_selection_rows": int(choose.sum()),
        "validation_calibration_rows": int(calibrate_rows.sum()),
        "ensemble_calibration": calibration.rate_check(ensemble_threshold.get("allowed_alerts", 0), int(calibrate_rows.sum()),
                                                       int(test_frame["model_zoo_ensemble_alert"].sum()), len(test_frame)),
        "model_selection": selection_method,
        "proxy_label_source": label_source,
        "duration_seconds": time.perf_counter() - started,
    }
    if labels is not None:
        for split, frame in (("validation", validation_frame), ("test", test_frame)):
            ensemble = proxy_metrics(frame["model_zoo_ensemble_alert"].to_numpy(), labels[split])
            summary[split + "_proxy_base_rate"] = ensemble["base_rate"]
            summary[split + "_ensemble_detection_rate"] = ensemble["detection_rate"]
            summary[split + "_ensemble_precision"] = ensemble["precision"]
            summary[split + "_ensemble_lift"] = ensemble["lift"]
        consensus_flags = (test_frame[vote_column] >= required_votes).to_numpy()
        consensus_proxy = proxy_metrics(consensus_flags, labels["test"])
        summary["test_consensus_detection_rate"] = consensus_proxy["detection_rate"]
        summary["test_consensus_precision"] = consensus_proxy["precision"]
    write_json(output / "dataset_summary.json", summary)
    alert_ids = {m: set(test_frame.loc[results[m]["test_alert"], "row_manifest_id"])
                 for m in completed}
    alert_ids["__consensus__"] = set(consensus["row_manifest_id"])
    alert_ids["__ensemble__"] = set(test_frame.loc[test_frame["model_zoo_ensemble_alert"],
                                                   "row_manifest_id"])
    consensus.insert(0, "feature_set", feature_set)
    consensus.insert(0, "dataset", dataset)
    return summary, metrics, membership, consensus, alert_ids, curve


def compare_feature_sets(dataset, alert_ids, summaries):
    full, selected = alert_ids["full"], alert_ids["selected"]
    by_set = {s["feature_set"]: s for s in summaries}
    rows = []
    for key in sorted(set(full) | set(selected)):
        a, b = full.get(key), selected.get(key)
        label = {"__consensus__": "consensus", "__ensemble__": "ensemble"}.get(key, key)
        rows.append({
            "dataset": dataset, "item": label,
            "full_test_alerts": len(a) if a is not None else np.nan,
            "selected_test_alerts": len(b) if b is not None else np.nan,
            "shared_alerts": len(a & b) if a is not None and b is not None else np.nan,
            "jaccard": (len(a & b) / len(a | b) if a is not None and b is not None and (a | b)
                        else np.nan),
            "full_member": label in by_set["full"]["ensemble_members"],
            "selected_member": label in by_set["selected"]["ensemble_members"],
        })
    rows.insert(0, {"dataset": dataset, "item": "feature_count",
                    "full_test_alerts": by_set["full"]["features"],
                    "selected_test_alerts": by_set["selected"]["features"]})
    return pd.DataFrame(rows)


def process_dataset(dataset, args, log):
    folder = args.features / dataset
    output = args.output / dataset
    metadata = validate_feature_metadata(folder, dataset)
    header = pd.read_csv(folder / "feature_names.csv")
    names = header["feature_name"].astype(str).tolist()
    candidates = identity_filtered_indices(names)
    sets = ["full", "selected"] if args.feature_set == "both" else [args.feature_set]

    labels, label_source = load_proxy_labels(dataset, folder, args, log)
    if labels is not None:
        log.write(f"{dataset}: proxy labels from {label_source}; security-relevant share "
                  f"validation={labels['validation'].mean():.3%}, test={labels['test'].mean():.3%}")

    indices = {"full": candidates}
    sweep = pd.DataFrame()
    if "selected" in sets:
        log.write(f"{dataset}: scoring feature relevance on train/validation samples", "PHASE")
        rng = np.random.default_rng(RANDOM_STATE)
        train = load_split(folder, "train").matrix
        validation_split = load_split(folder, "validation")
        choose, _ = calibration.halves(time_order(validation_split.rows), args.calibration_split)
        validation = validation_split.matrix[np.flatnonzero(choose)]
        del validation_split
        selected, table = feature_relevance(train, validation, names, candidates, args, log, rng)
        if args.feature_sweep:
            log.write(f"{dataset}: sweeping top-K feature counts {args.feature_sweep}", "PHASE")
            swept, sweep = feature_sweep(train, validation, table, candidates, len(selected),
                                         None if labels is None else labels["validation"][choose],
                                         args, log, rng)
            if swept is not None:
                selected = swept
                table["selected"] = table["feature_index"].isin(selected)
                table.loc[table["selected"], "decision"] = "selected"
                table.loc[~table["selected"] & table["decision"].eq("selected"),
                          "decision"] = "below_sweep_cutoff"
        del train, validation
        output.mkdir(parents=True, exist_ok=True)
        table.insert(0, "dataset", dataset)
        table.to_csv(output / "feature_relevance.csv", index=False)
        if len(sweep):
            sweep.insert(0, "dataset", dataset)
            sweep.to_csv(output / "feature_sweep.csv", index=False)
        indices["selected"] = selected

    summaries, metrics, memberships, consensus, alert_ids, curves = [], [], [], [], {}, []
    for feature_set in sets:
        log.write(f"{dataset}: evaluating feature set '{feature_set}'", "PHASE")
        summary, m, membership, c, ids, curve = evaluate_feature_set(
            dataset, folder, output / feature_set, indices[feature_set], feature_set,
            metadata, args, log, labels, label_source)
        summaries.append(summary)
        metrics.extend(m)
        memberships.append(membership)
        consensus.append(c)
        alert_ids[feature_set] = ids
        if len(curve):
            curves.append(curve)

    comparison = None
    if len(sets) == 2:
        comparison = compare_feature_sets(dataset, alert_ids, summaries)
        comparison.to_csv(output / "feature_set_comparison.csv", index=False)
        row = comparison[comparison["item"] == "consensus"].iloc[0]
        log.write(f"{dataset}: consensus alerts full={int(row.full_test_alerts):,}, "
                  f"selected={int(row.selected_test_alerts):,}, jaccard={row.jaccard:.2f}",
                  "COMPARE")
    return summaries, metrics, memberships, consensus, comparison, curves, sweep


def write_global(output, summaries, metrics, memberships, consensus, comparisons,
                 curves=(), sweeps=()):
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "model_zoo_summary.json", {
        "feature_artifact_contract": EXPECTED_FEATURE_CONTRACT,
        "datasets": summaries, "model_metrics": metrics})
    pd.DataFrame([{k: (v if not isinstance(v, list) else "|".join(map(str, v)))
                   for k, v in item.items()} for item in summaries]).to_csv(
        output / "model_zoo_summary.csv", index=False)
    pd.DataFrame(metrics).to_csv(output / "all_model_metrics.csv", index=False)
    if memberships:
        pd.concat(memberships, ignore_index=True).to_csv(
            output / "all_ensemble_membership.csv", index=False)
    if consensus:
        pd.concat(consensus, ignore_index=True, sort=False).to_csv(
            output / "consensus_alerts_all.csv", index=False)
    if comparisons:
        pd.concat(comparisons, ignore_index=True).to_csv(
            output / "feature_set_comparison.csv", index=False)
    if curves:
        pd.concat(curves, ignore_index=True).to_csv(
            output / "all_model_selection_curves.csv", index=False)
    if sweeps:
        pd.concat(sweeps, ignore_index=True).to_csv(
            output / "all_feature_sweeps.csv", index=False)


def main():
    args = parse_args()
    log = Log(args.quiet, args.verbose)
    args.output.mkdir(parents=True, exist_ok=True)
    datasets = discover_datasets(args.features, args.dataset)
    log.write("OSSEC model-zoo benchmark starting", "START")
    log.write("Datasets: " + ", ".join(datasets))
    log.write("Models: " + ", ".join(model_selection(args)))
    log.write("Feature set(s): " + args.feature_set)
    summaries, metrics, memberships, consensus, comparisons = [], [], [], [], []
    curves, sweeps = [], []
    failures = 0
    for dataset in datasets:
        log.write("Evaluating " + dataset, "PHASE")
        try:
            s, m, mb, c, comp, curve_list, sweep = process_dataset(dataset, args, log)
            summaries.extend(s)
            metrics.extend(m)
            memberships.extend(mb)
            consensus.extend(c)
            curves.extend(curve_list)
            if len(sweep):
                sweeps.append(sweep)
            if comp is not None:
                comparisons.append(comp)
        except Exception as error:
            failures += 1
            summaries.append({"dataset": dataset, "status": "failed", "error": repr(error)})
            (args.output / dataset).mkdir(parents=True, exist_ok=True)
            write_json(args.output / dataset / "dataset_summary.json",
                       {"dataset": dataset, "status": "failed", "error": repr(error)})
            log.write(f"{dataset} failed: {error!r}", "ERROR", always=True)
            if args.verbose:
                traceback.print_exc()
    write_global(args.output, summaries, metrics, memberships, consensus, comparisons,
                 curves, sweeps)
    level = "FAILED" if failures else "COMPLETE"
    log.write(f"OSSEC model-zoo benchmark finished ({failures} dataset failure(s)): "
              + str(args.output / "model_zoo_summary.csv"), level, always=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
