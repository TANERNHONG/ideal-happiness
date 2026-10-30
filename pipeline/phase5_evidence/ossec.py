"""Export original OSSEC log chains for Isolation Forest test outliers.

Step 5 of the OSSEC explainable-lineage anomaly-detection workflow.

The script consumes experiments produced by
``pipeline/phase4_detection/ossec_detectors.py`` and explainable features
produced by ``pipeline/phase3_features/ossec.py``.

Outputs
-------
data/phase5_evidence/ossec/
    ossec_isolation_forest_outlier_message_chains.csv
    ossec_isolation_forest_outlier_events_detailed.csv
    ossec_isolation_forest_outlier_export_summary.csv
    ossec_isolation_forest_outlier_categories.csv

Evidence resolution order
-------------------------
1. Reuse ``test_raw_alert_evidence.csv`` written by the experiment runner.
2. Otherwise join the alert's ``row_manifest_id`` to the union of
   ``train_lineage.csv``, ``validation_lineage.csv``, and ``test_lineage.csv``.
3. Join each lineage ``event_id`` to ``data/phase1_classify/ossec/ossec_event_lookup.csv``.

Only observations where ``isolation_alert`` is true are exported. The default
policy requires complete source evidence. Use ``--allow-partial-evidence`` only
when an intentional partial export is acceptable.

Command-line usage
------------------
Run with timestamped INFO checkpoints and ten-second activity updates::

    python pipeline/phase5_evidence/ossec.py

Point at non-default folders, allow partial evidence, and show detailed
per-run evidence-resolution and chain-building messages with five-second
updates::

    python pipeline/phase5_evidence/ossec.py --experiments custom_experiments \\
        --allow-partial-evidence --verbose --progress-interval 5

Suppress routine progress with ``--quiet``. ``--verbose`` and ``--quiet`` are
mutually exclusive. Use ``--help`` to view every option.

Runtime reporting
-----------------
Each log record includes elapsed time since module startup in ``HH:MM:SS.s``
format using ``time.monotonic()``. Timed stages report their own duration.
A background heartbeat reports the active stage during long lineage and
event-lookup reads. Loop checkpoints also report item counts and throughput.
The CLI run reports total runtime on completion, errors and interruption.

.. note::

   Heartbeats indicate activity, not a percentage or an estimated finish time.
   They may be delayed by native code holding the interpreter lock. Abrupt
   process termination cannot emit a final summary. Quiet mode suppresses
   routine timing messages; warnings and errors remain visible.

This revision safely reuses experiment evidence that already contains
``dataset`` or ``run_key`` columns.
"""
from __future__ import annotations

import time
import argparse
import csv
import json
import logging
import re
import sys
import threading
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import progress_items, stage, timed_stage  # noqa: E402

LOGGER = runlog.LOGGER

DEFAULT_EXPERIMENT_FOLDER = Path("data/phase4_detection/ossec/detectors")
DEFAULT_FEATURE_FOLDER = Path("data/phase3_features/ossec")
DEFAULT_EVENT_LOOKUP = Path("data/phase1_classify/ossec/ossec_event_lookup.csv")
DEFAULT_OUTPUT_FOLDER = Path("data/phase5_evidence/ossec")

# Identity tag written into, and checked against, earlier phases' metadata. It is the
# producer's historical file name, not a path: keep it unless all phases are rerun.
EXPECTED_EXPERIMENT_RUNNER = "ossec_experiment_runner_explainable_lineage.py"
EXPECTED_FEATURE_PRODUCER = "feature_engineer_ossec_logs_explainable_lineage.py"
EXPECTED_FEATURE_CONTRACT = "ossec_explainable_lineage"

RUNS = (
    ("episodes", "episodes"),
    ("individual", "individual"),
    ("host_5min", "host_5min"),
    ("host_behavior_1d", "host_behavior_1d"),
)

LINEAGE_FILES = (
    "train_lineage.csv",
    "validation_lineage.csv",
    "test_lineage.csv",
)

EVENT_LOOKUP_CHUNK_ROWS = 200_000
CHAIN_SEPARATOR = "\n--- OSSEC EVENT ---\n"
PREVIEW_MESSAGE_LIMIT = 5
MAX_CHAIN_CHARACTERS = 250_000

CHAIN_OUTPUT_COLUMNS = (
    "run_key",
    "dataset",
    "row_manifest_id",
    "isolation_score",
    "isolation_threshold",
    "isolation_detector_status",
    "detector_combination",
    "alert_tier",
    "observation_timestamp",
    "observation_entity",
    "observation_process",
    "observation_category",
    "source_event_count",
    "source_event_found_count",
    "source_event_missing_count",
    "first_event_timestamp",
    "last_event_timestamp",
    "first_event_id",
    "last_event_id",
    "maximum_source_severity_rank",
    "source_event_types",
    "source_processes",
    "source_users",
    "source_ips",
    "first_original_log_line",
    "last_original_log_line",
    "representative_original_log_lines",
    "original_log_line_chain",
    "event_id_chain",
    "relationship_role_chain",
    "evidence_status",
    "evidence_resolution_method",
    "chain_truncated",
)

DETAILED_OUTPUT_COLUMNS = (
    "run_key",
    "dataset",
    "row_manifest_id",
    "isolation_score",
    "isolation_threshold",
    "isolation_detector_status",
    "detector_combination",
    "alert_tier",
    "event_position",
    "relationship_role",
    "event_id",
    "event_timestamp",
    "timestamp",
    "partition_month",
    "hostname",
    "agent_name",
    "process_name",
    "pid",
    "severity",
    "severity_rank",
    "event_type",
    "event_category",
    "username",
    "source_ip",
    "source_port",
    "destination_hostname",
    "destination_ip",
    "destination_port",
    "reason",
    "raw_message",
    "original_log_line",
    "classification_line",
    "raw_line_sha256",
    "source_file",
    "source_line",
    "archive_name",
    "archive_member",
    "event_lookup_found",
    "lineage_source_file",
    "evidence_resolution_method",
)

CATEGORY_OUTPUT_COLUMNS = (
    "run_key",
    "dataset",
    "event_category",
    "isolation_alerts",
    "source_event_rows",
    "unique_event_types",
    "unique_processes",
    "unique_hosts",
    "maximum_isolation_score",
    "mean_isolation_score",
)


# =============================================================================
# Logging, timing and progress reporting
# =============================================================================


def parse_args():
    """Parse folder overrides, evidence policy and logging settings.

    :returns: Validated command-line settings.
    :rtype: argparse.Namespace
    """
    parser = argparse.ArgumentParser(
        description=(
            "Export original OSSEC log chains for Isolation Forest test alerts."
        )
    )
    parser.add_argument(
        "--experiments",
        type=Path,
        default=DEFAULT_EXPERIMENT_FOLDER,
    )
    parser.add_argument(
        "--features",
        type=Path,
        default=DEFAULT_FEATURE_FOLDER,
    )
    parser.add_argument(
        "--event-lookup",
        type=Path,
        default=DEFAULT_EVENT_LOOKUP,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FOLDER,
    )
    parser.add_argument(
        "--allow-partial-evidence",
        action="store_true",
        help=(
            "Write outputs when some observations or event IDs lack evidence. "
            "Without this flag, incomplete evidence causes a failure."
        ),
    )
    parser.add_argument(
        "--maximum-chain-characters",
        type=int,
        default=MAX_CHAIN_CHARACTERS,
        help=(
            "Maximum characters retained in one combined original-log chain. "
            "Detailed source-event output is never truncated."
        ),
    )
    runlog.add_arguments(parser)
    args = parser.parse_args()
    return args


# =============================================================================
# Value helpers
# =============================================================================

def text(value):
    """Convert a value to text, mapping missing values to empty text.

    :param value: Input value to transform.
    :returns: Text representation, or empty text for null-like input.
    :rtype: str
    """
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value)


def compact_text(value):
    """Collapse internal whitespace and strip a value's text form.

    :param value: Input value to transform.
    :returns: Single-line, trimmed text.
    :rtype: str
    """
    return re.sub(r"\s+", " ", text(value)).strip()


def truthy(series):
    """Interpret boolean or textual truth values as booleans.

    :param series: Input pandas Series.
    :returns: Boolean Series with missing values treated as False.
    :rtype: pandas.Series
    """
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return (
        series.fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
        .isin({"1", "true", "yes", "y"})
    )


def require_columns(frame, required, source_name):
    """Require that a dataframe contains every column in a required set.

    :param frame: Dataframe to check.
    :param required: Required column names.
    :param source_name: File or object label used in the error message.
    :rtype: None
    :raises ValueError: If any required column is absent.
    """
    missing = sorted(set(required) - set(frame.columns))
    if missing:
        raise ValueError(
            source_name + " is missing columns: " + ", ".join(missing)
        )


def read_json(path):
    """Read a JSON object from disk.

    :param path: JSON file path.
    :returns: Parsed object, or an empty dict when absent or non-object.
    :rtype: dict
    """
    if not path.is_file():
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    return value if isinstance(value, dict) else {}


# =============================================================================
# Artifact contract validation
# =============================================================================

@timed_stage
def validate_artifact_contract(args):
    """Require complete experiment and feature artifacts before exporting.

    :param args: Parsed command-line settings.
    :rtype: None
    :raises ValueError: If any run has unsupported or incomplete artifacts.
    :raises FileNotFoundError: If a required top-level folder or file is absent.
    """
    if not args.experiments.is_dir():
        raise FileNotFoundError(
            "OSSEC experiment folder is missing: " + str(args.experiments)
        )
    if not args.features.is_dir():
        raise FileNotFoundError(
            "OSSEC explainable feature folder is missing: " + str(args.features)
        )
    if not args.event_lookup.is_file():
        raise FileNotFoundError(
            "OSSEC event lookup is missing: " + str(args.event_lookup)
        )

    lookup_header = pd.read_csv(args.event_lookup, nrows=0)
    require_columns(
        lookup_header,
        {"event_id", "original_log_line", "source_file", "source_line"},
        str(args.event_lookup),
    )

    problems = []
    for run_key, dataset in progress_items(RUNS, "Runs checked for artifact contract"):
        run_folder = args.experiments / run_key
        feature_folder = args.features / dataset
        if run_folder.is_dir():
            score_path = run_folder / "test_scores.csv"
            if score_path.is_file():
                score_header = pd.read_csv(score_path, nrows=0)
                missing = {
                    "row_manifest_id",
                    "isolation_alert",
                    "isolation_score",
                }.difference(score_header.columns)
                if missing:
                    problems.append(
                        str(score_path) + " missing " + ",".join(sorted(missing))
                    )
            summary = read_json(run_folder / "summary.json")
            contract = text(summary.get("feature_artifact_contract")).strip()
            if contract and contract != EXPECTED_FEATURE_CONTRACT:
                problems.append(
                    run_key + " has unsupported feature_artifact_contract="
                    + contract
                )
        if feature_folder.is_dir():
            metadata = read_json(feature_folder / "metadata.json")
            contract = text(metadata.get("feature_artifact_contract")).strip()
            if contract and contract != EXPECTED_FEATURE_CONTRACT:
                problems.append(
                    dataset + " feature metadata contract=" + contract
                )
            for filename in LINEAGE_FILES:
                if not (feature_folder / filename).is_file():
                    problems.append(str(feature_folder / filename) + " is missing")

    if problems:
        raise ValueError(
            "OSSEC explainable-lineage artifact validation failed. Expected "
            + EXPECTED_EXPERIMENT_RUNNER + " and "
            + EXPECTED_FEATURE_PRODUCER + ". Problems: "
            + "; ".join(problems)
        )
    LOGGER.debug("Artifact contract validated for %s configured runs", len(RUNS))


def load_run_summary(run_folder):
    """Read one experiment run's summary.json.

    :param run_folder: Experiment output folder for this run.
    :returns: Parsed summary, or an empty dict when absent.
    :rtype: dict
    """
    return read_json(run_folder / "summary.json")


# =============================================================================
# Alert and evidence loading
# =============================================================================

@timed_stage
def read_isolation_alerts(run_key, run_folder):
    """Load Isolation Forest test alerts and attach run-level metadata.

    :param run_key: Configured run identifier.
    :param run_folder: Experiment output folder for this run.
    :returns: Alert rows and a status label, or None and a status when scores are absent.
    :rtype: tuple
    :raises ValueError: If scores are missing required columns or malformed identifiers.
    """
    score_path = run_folder / "test_scores.csv"
    if not score_path.is_file():
        return None, "missing_test_scores"
    scores = pd.read_csv(score_path, low_memory=False)
    require_columns(
        scores,
        {"row_manifest_id", "isolation_alert", "isolation_score"},
        str(score_path),
    )
    scores["row_manifest_id"] = (
        scores["row_manifest_id"].fillna("").astype(str).str.strip()
    )
    if scores["row_manifest_id"].eq("").any():
        raise ValueError(str(score_path) + " contains blank row_manifest_id")
    if scores["row_manifest_id"].duplicated().any():
        raise ValueError(str(score_path) + " contains duplicate row_manifest_id")

    alerts = scores.loc[truthy(scores["isolation_alert"])].copy()
    summary = load_run_summary(run_folder)
    if "isolation_threshold" not in alerts.columns:
        alerts["isolation_threshold"] = summary.get(
            "isolation_threshold", np.nan
        )
    alerts["isolation_detector_status"] = summary.get(
        "isolation_detector_status", ""
    )
    alerts["feature_artifact_contract"] = summary.get(
        "feature_artifact_contract", ""
    )
    alerts.insert(0, "run_key", run_key)
    LOGGER.debug("%s: %s isolation alerts loaded", run_key, len(alerts))
    return alerts, "available"


def load_existing_evidence(run_folder, alert_ids):
    """Reuse the experiment runner's raw alert evidence when available.

    :param run_folder: Experiment output folder for this run.
    :param alert_ids: Observation IDs to keep from the evidence file.
    :returns: Filtered evidence rows, or None when the file is absent.
    :rtype: pandas.DataFrame or None
    :raises ValueError: If the evidence file lacks required columns.
    """
    path = run_folder / "test_raw_alert_evidence.csv"
    if not path.is_file():
        return None
    evidence = pd.read_csv(path, low_memory=False)
    if evidence.empty:
        return evidence
    require_columns(
        evidence,
        {"row_manifest_id", "event_id"},
        str(path),
    )
    evidence["row_manifest_id"] = (
        evidence["row_manifest_id"].fillna("").astype(str).str.strip()
    )
    evidence["event_id"] = (
        evidence["event_id"].fillna("").astype(str).str.strip()
    )
    evidence = evidence.loc[
        evidence["row_manifest_id"].isin(alert_ids)
    ].copy()
    evidence["evidence_resolution_method"] = (
        "experiment_test_raw_alert_evidence"
    )
    return evidence


@timed_stage
def load_split_lineage(feature_folder, alert_ids):
    """Load lineage rows for the requested observations from all splits.

    :param feature_folder: Dataset feature folder containing split lineage files.
    :param alert_ids: Observation IDs to resolve.
    :returns: Sorted lineage dataframe and observation IDs still missing lineage.
    :rtype: tuple
    :raises ValueError: If lineage identifiers, links or positions are invalid.
    :raises FileNotFoundError: If no split lineage file yields any row.
    """
    frames = []
    missing_files = []
    for filename in LINEAGE_FILES:
        path = feature_folder / filename
        if not path.is_file():
            missing_files.append(filename)
            continue
        frame = pd.read_csv(path, low_memory=False)
        require_columns(
            frame,
            {"row_manifest_id", "event_id", "event_position"},
            str(path),
        )
        frame["row_manifest_id"] = (
            frame["row_manifest_id"].fillna("").astype(str).str.strip()
        )
        frame["event_id"] = (
            frame[["event_id"]]["event_id"]
            .fillna("").astype(str).str.strip()
        )
        frame = frame.loc[
            frame["row_manifest_id"].isin(alert_ids)
        ].copy()
        frame["lineage_source_file"] = filename
        if len(frame):
            frames.append(frame)

    if not frames:
        raise FileNotFoundError(
            "No lineage rows found in " + str(feature_folder)
            + "; missing_files=" + ",".join(missing_files)
        )
    lineage = pd.concat(frames, ignore_index=True, sort=False)
    if lineage["row_manifest_id"].eq("").any() or lineage["event_id"].eq("").any():
        raise ValueError("Blank identifier in OSSEC split lineage")
    duplicate_links = lineage.duplicated(
        ["row_manifest_id", "event_id"], keep=False
    )
    if duplicate_links.any():
        examples = lineage.loc[
            duplicate_links, ["row_manifest_id", "event_id"]
        ].head(10).astype(str).agg(" -> ".join, axis=1).tolist()
        raise ValueError(
            "Duplicate OSSEC lineage links: " + "; ".join(examples)
        )
    positions = pd.to_numeric(lineage["event_position"], errors="coerce")
    if positions.isna().any() or positions.lt(1).any():
        raise ValueError("Invalid event_position in OSSEC split lineage")
    lineage["event_position"] = positions.astype(int)
    missing_alerts = sorted(set(alert_ids) - set(lineage["row_manifest_id"]))
    LOGGER.debug("Split lineage loaded: rows=%s, missing_alerts=%s",
                 f"{len(lineage):,}", len(missing_alerts))
    return lineage, missing_alerts


@timed_stage
def load_event_lookup_subset(path, event_ids):
    """Load only the requested classified OSSEC events from the lookup.

    :param path: OSSEC event lookup CSV path.
    :param event_ids: Event IDs referenced by alert lineage.
    :returns: Lookup rows for the requested events.
    :rtype: pandas.DataFrame
    :raises ValueError: If the lookup contains duplicate event IDs.
    """
    wanted = {
        str(value).strip() for value in event_ids if str(value).strip()
    }
    if not wanted:
        return pd.DataFrame(columns=["event_id", "original_log_line"])
    header = pd.read_csv(path, nrows=0)
    require_columns(
        header,
        {"event_id", "original_log_line"},
        str(path),
    )
    preferred = list(DETAILED_OUTPUT_COLUMNS)
    usecols = [
        column for column in preferred
        if column in header.columns
    ]
    if "event_id" not in usecols:
        usecols.append("event_id")
    if "original_log_line" not in usecols:
        usecols.append("original_log_line")

    frames = []
    seen = set()
    chunks = pd.read_csv(
        path,
        usecols=usecols,
        chunksize=EVENT_LOOKUP_CHUNK_ROWS,
        low_memory=False,
    )
    for chunk in progress_items(chunks, "Event lookup chunks scanned"):
        chunk["event_id"] = (
            chunk["event_id"].fillna("").astype(str).str.strip()
        )
        selected = chunk.loc[chunk["event_id"].isin(wanted)].copy()
        if selected.empty:
            continue
        duplicate_ids = set(
            selected.loc[
                selected["event_id"].duplicated(keep=False), "event_id"
            ]
        )
        repeated = seen.intersection(set(selected["event_id"]))
        if duplicate_ids or repeated:
            raise ValueError(
                "Duplicate event_id values in OSSEC event lookup: "
                + ", ".join(sorted(duplicate_ids | repeated)[:20])
            )
        seen.update(selected["event_id"])
        frames.append(selected)
    if not frames:
        return pd.DataFrame(columns=usecols)
    return pd.concat(frames, ignore_index=True, sort=False)


@timed_stage
def reconstruct_evidence(feature_folder, event_lookup_path, alert_ids):
    """Reconstruct raw alert evidence from split lineage and the event lookup.

    :param feature_folder: Dataset feature folder containing split lineage files.
    :param event_lookup_path: OSSEC event lookup CSV path.
    :param alert_ids: Observation IDs to resolve.
    :returns: Merged evidence dataframe and observation IDs missing lineage.
    :rtype: tuple
    """
    lineage, missing_alerts = load_split_lineage(
        feature_folder, alert_ids
    )
    lookup = load_event_lookup_subset(
        event_lookup_path, lineage["event_id"]
    )
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
    evidence["evidence_resolution_method"] = (
        "split_lineage_and_ossec_event_lookup"
    )
    return evidence, missing_alerts


def add_alert_metadata(evidence, alerts, run_key, dataset):
    """Safely attach alert metadata to new or reused evidence.

    :param evidence: Evidence dataframe from either resolution path.
    :param alerts: Alert rows for this run.
    :param run_key: Configured run identifier.
    :param dataset: Dataset key backing this run.
    :returns: Evidence with run and dataset columns leading and alert metadata merged.
    :rtype: pandas.DataFrame
    :raises ValueError: If alert metadata contains duplicate row_manifest_id values.
    """
    evidence = evidence.copy()
    candidate_columns = [
        column for column in (
            "row_manifest_id",
            "isolation_score",
            "isolation_threshold",
            "isolation_detector_status",
            "detector_combination",
            "alert_tier",
            "timestamp",
            "window_start",
            "episode_start",
            "first_timestamp",
            "host_id",
            "hostname",
            "agent_name",
            "episode_id",
            "process_name",
            "event_category",
            "source_ip",
            "destination_ip",
            "username",
        ) if column in alerts.columns
    ]
    metadata_columns = [
        column for column in candidate_columns
        if column == "row_manifest_id" or column not in evidence.columns
    ]
    if len(metadata_columns) > 1:
        metadata = alerts[metadata_columns].copy()
        if metadata["row_manifest_id"].duplicated().any():
            raise ValueError(
                "OSSEC alert metadata contains duplicate row_manifest_id"
            )
        evidence = evidence.merge(
            metadata,
            on="row_manifest_id",
            how="left",
            validate="many_to_one",
        )

    evidence["dataset"] = dataset
    evidence["run_key"] = run_key
    leading = ["run_key", "dataset"]
    remaining = [
        column for column in evidence.columns if column not in leading
    ]
    evidence = evidence[leading + remaining]

    if "event_lookup_found" not in evidence.columns:
        original = evidence.get(
            "original_log_line",
            evidence.get(
                "raw_message",
                pd.Series(index=evidence.index, dtype=object),
            ),
        )
        evidence["event_lookup_found"] = original.notna()
    else:
        evidence["event_lookup_found"] = truthy(
            evidence["event_lookup_found"]
        )
    return evidence


# =============================================================================
# Chain and summary construction
# =============================================================================

def observation_timestamp(row):
    """Select the first available observation-level timestamp.

    :param row: One alert row.
    :returns: Timestamp text, or empty text if no candidate column is set.
    :rtype: str
    """
    for column in (
        "timestamp", "window_start", "episode_start", "first_timestamp",
    ):
        if column in row.index and text(row[column]):
            return text(row[column])
    return ""


def observation_entity(row):
    """Select the first available observation-level entity identifier.

    :param row: One alert row.
    :returns: Entity text, or empty text if no candidate column is set.
    :rtype: str
    """
    for column in (
        "host_id", "hostname", "agent_name", "episode_id", "source_ip",
    ):
        if column in row.index and text(row[column]):
            return text(row[column])
    return ""


def event_times(frame):
    """Parse the first available event-level timestamp column.

    :param frame: Evidence rows for one or more observations.
    :returns: Parsed UTC timestamp Series.
    :rtype: pandas.Series
    """
    for column in ("event_timestamp", "timestamp", "timestamp_text"):
        if column in frame.columns:
            parsed = pd.to_datetime(
                frame[column], errors="coerce", utc=True
            )
            if parsed.notna().any():
                return parsed
    return pd.Series(
        pd.NaT,
        index=frame.index,
        dtype="datetime64[ns, UTC]",
    )


def ordered_unique(values, maximum=100):
    """Deduplicate compact text values while preserving first-seen order.

    :param values: Input values to deduplicate.
    :param maximum: Maximum number of values retained.
    :returns: Ordered unique non-empty text values.
    :rtype: list
    """
    result = []
    seen = set()
    for value in values:
        item = compact_text(value)
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
        if len(result) >= maximum:
            break
    return result


def severity_numeric(value):
    """Rank a severity label or numeric text for comparison.

    :param value: Severity text.
    :returns: Integer rank; unrecognized text falls back to 0.
    :rtype: int
    """
    value = compact_text(value).upper()
    ranks = {
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
    if value in ranks:
        return ranks[value]
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


@timed_stage
def build_chain_rows(
    run_key,
    dataset,
    alerts,
    evidence,
    maximum_chain_characters,
):
    """Build one output row per alert with its ordered original-log chain.

    :param run_key: Configured run identifier.
    :param dataset: Dataset key backing this run.
    :param alerts: Alert rows for this run.
    :param evidence: Evidence rows for this run's alerts.
    :param maximum_chain_characters: Maximum characters kept in one combined chain.
    :returns: One row per alert following CHAIN_OUTPUT_COLUMNS.
    :rtype: pandas.DataFrame
    """
    rows = []
    grouped = (
        {
            key: group.copy()
            for key, group in evidence.groupby(
                "row_manifest_id", sort=False
            )
        }
        if len(evidence) else {}
    )
    for _, alert in progress_items(alerts.iterrows(), run_key + " alert chains built"):
        row_id = text(alert["row_manifest_id"])
        group = grouped.get(row_id, pd.DataFrame())
        if len(group):
            if "event_position" not in group.columns:
                group["event_position"] = np.arange(1, len(group) + 1)
            group["__position"] = pd.to_numeric(
                group["event_position"], errors="coerce"
            )
            group["__time"] = event_times(group)
            group = group.sort_values(
                ["__position", "__time", "event_id"],
                kind="stable",
                na_position="last",
            )
            found = (
                truthy(group["event_lookup_found"])
                if "event_lookup_found" in group.columns
                else group.get(
                    "original_log_line",
                    pd.Series(index=group.index, dtype=object),
                ).notna()
            )
            message_column = (
                "original_log_line"
                if "original_log_line" in group.columns
                else "raw_message"
            )
            messages = [
                text(value)
                for value in group.loc[found, message_column]
                if text(value)
            ] if message_column in group.columns else []
            event_ids = [
                text(value) for value in group["event_id"] if text(value)
            ]
            roles = [
                text(value)
                for value in group.get(
                    "relationship_role",
                    pd.Series(index=group.index, dtype=object),
                )
                if text(value)
            ]
            times = group.loc[found, "__time"].dropna()
            found_count = int(found.sum())
            missing_count = int(len(group) - found_count)
            status = (
                "complete" if len(group) and missing_count == 0
                else "partial" if found_count
                else "missing"
            )
            methods = ordered_unique(
                group.get(
                    "evidence_resolution_method",
                    pd.Series(index=group.index, dtype=object),
                )
            )
            event_types = ordered_unique(
                group.get(
                    "event_type",
                    pd.Series(index=group.index, dtype=object),
                )
            )
            processes = ordered_unique(
                group.get(
                    "process_name",
                    pd.Series(index=group.index, dtype=object),
                )
            )
            users = ordered_unique(
                group.get(
                    "username",
                    pd.Series(index=group.index, dtype=object),
                )
            )
            source_ips = ordered_unique(
                group.get(
                    "source_ip",
                    pd.Series(index=group.index, dtype=object),
                )
            )
            severity_values = [
                severity_numeric(value)
                for value in group.get(
                    "severity",
                    pd.Series(index=group.index, dtype=object),
                )
            ]
            message_chain = CHAIN_SEPARATOR.join(messages)
            chain_truncated = False
            if (
                maximum_chain_characters > 0
                and len(message_chain) > maximum_chain_characters
            ):
                message_chain = (
                    message_chain[:maximum_chain_characters]
                    + "\n...[CHAIN TRUNCATED; SEE DETAILED CSV]"
                )
                chain_truncated = True
        else:
            messages = []
            event_ids = []
            roles = []
            times = pd.Series(dtype="datetime64[ns, UTC]")
            found_count = 0
            missing_count = 0
            status = "missing"
            methods = ["no_lineage"]
            event_types = []
            processes = []
            users = []
            source_ips = []
            severity_values = []
            message_chain = ""
            chain_truncated = False

        rows.append({
            "run_key": run_key,
            "dataset": dataset,
            "row_manifest_id": row_id,
            "isolation_score": alert.get("isolation_score", np.nan),
            "isolation_threshold": alert.get(
                "isolation_threshold", np.nan
            ),
            "isolation_detector_status": alert.get(
                "isolation_detector_status", ""
            ),
            "detector_combination": alert.get(
                "detector_combination", ""
            ),
            "alert_tier": alert.get("alert_tier", ""),
            "observation_timestamp": observation_timestamp(alert),
            "observation_entity": observation_entity(alert),
            "observation_process": alert.get("process_name", ""),
            "observation_category": alert.get("event_category", ""),
            "source_event_count": int(len(group)),
            "source_event_found_count": found_count,
            "source_event_missing_count": missing_count,
            "first_event_timestamp": str(times.min()) if len(times) else "",
            "last_event_timestamp": str(times.max()) if len(times) else "",
            "first_event_id": event_ids[0] if event_ids else "",
            "last_event_id": event_ids[-1] if event_ids else "",
            "maximum_source_severity_rank": (
                max(severity_values) if severity_values else 0
            ),
            "source_event_types": "|".join(event_types),
            "source_processes": "|".join(processes),
            "source_users": "|".join(users),
            "source_ips": "|".join(source_ips),
            "first_original_log_line": messages[0] if messages else "",
            "last_original_log_line": messages[-1] if messages else "",
            "representative_original_log_lines": CHAIN_SEPARATOR.join(
                messages[:PREVIEW_MESSAGE_LIMIT]
            ),
            "original_log_line_chain": message_chain,
            "event_id_chain": "|".join(event_ids),
            "relationship_role_chain": "|".join(roles),
            "evidence_status": status,
            "evidence_resolution_method": "|".join(methods),
            "chain_truncated": chain_truncated,
        })
    return pd.DataFrame(rows, columns=CHAIN_OUTPUT_COLUMNS)


def detailed_columns(frame):
    """Reindex evidence to the fixed detailed-output column order.

    :param frame: Evidence dataframe.
    :returns: Dataframe restricted and ordered to DETAILED_OUTPUT_COLUMNS.
    :rtype: pandas.DataFrame
    """
    result = frame.copy()
    for column in DETAILED_OUTPUT_COLUMNS:
        if column not in result.columns:
            result[column] = ""
    return result[list(DETAILED_OUTPUT_COLUMNS)]


@timed_stage
def category_summary(chains, detailed):
    """Summarize alert and source-event counts by event category.

    :param chains: Combined chain rows across all runs.
    :param detailed: Combined detailed evidence rows across all runs.
    :returns: One row per run, dataset and event category.
    :rtype: pandas.DataFrame
    """
    if chains.empty:
        return pd.DataFrame(columns=CATEGORY_OUTPUT_COLUMNS)
    rows = []
    for (run_key, dataset), alert_group in chains.groupby(
        ["run_key", "dataset"], sort=False
    ):
        evidence = detailed.loc[
            detailed["run_key"].eq(run_key)
            & detailed["dataset"].eq(dataset)
        ].copy()
        if evidence.empty:
            rows.append({
                "run_key": run_key,
                "dataset": dataset,
                "event_category": "unknown",
                "isolation_alerts": int(len(alert_group)),
                "source_event_rows": 0,
                "unique_event_types": 0,
                "unique_processes": 0,
                "unique_hosts": 0,
                "maximum_isolation_score": pd.to_numeric(
                    alert_group["isolation_score"], errors="coerce"
                ).max(),
                "mean_isolation_score": pd.to_numeric(
                    alert_group["isolation_score"], errors="coerce"
                ).mean(),
            })
            continue
        if "event_category" not in evidence.columns:
            evidence["event_category"] = "unknown"
        evidence["event_category"] = (
            evidence["event_category"]
            .fillna("unknown")
            .astype(str)
            .str.strip()
            .replace("", "unknown")
        )
        for category, group in evidence.groupby(
            "event_category", sort=True
        ):
            alert_ids = set(group["row_manifest_id"].astype(str))
            related_alerts = alert_group.loc[
                alert_group["row_manifest_id"].astype(str).isin(alert_ids)
            ]
            scores = pd.to_numeric(
                related_alerts["isolation_score"], errors="coerce"
            )
            host_column = next(
                (
                    column
                    for column in ("hostname", "agent_name", "source_ip")
                    if column in group.columns
                ),
                None,
            )
            rows.append({
                "run_key": run_key,
                "dataset": dataset,
                "event_category": category,
                "isolation_alerts": int(len(alert_ids)),
                "source_event_rows": int(len(group)),
                "unique_event_types": int(
                    group["event_type"].nunique(dropna=True)
                    if "event_type" in group.columns else 0
                ),
                "unique_processes": int(
                    group["process_name"].nunique(dropna=True)
                    if "process_name" in group.columns else 0
                ),
                "unique_hosts": int(
                    group[host_column].nunique(dropna=True)
                    if host_column else 0
                ),
                "maximum_isolation_score": scores.max(),
                "mean_isolation_score": scores.mean(),
            })
    return pd.DataFrame(rows, columns=CATEGORY_OUTPUT_COLUMNS)


# =============================================================================
# Per-run orchestration
# =============================================================================

@timed_stage
def process_run(run_key, dataset, args):
    """Resolve alerts, evidence and chains for one configured run.

    :param run_key: Configured run identifier.
    :param dataset: Dataset key backing this run.
    :param args: Parsed command-line settings.
    :returns: Chain rows, detailed evidence rows and a per-run status summary.
    :rtype: tuple
    :raises ValueError: If evidence is incomplete and partial export is not allowed.
    """
    run_folder = args.experiments / run_key
    alerts, score_status = read_isolation_alerts(run_key, run_folder)
    if alerts is None:
        LOGGER.warning("%s: %s", run_key, score_status)
        return (
            pd.DataFrame(columns=CHAIN_OUTPUT_COLUMNS),
            pd.DataFrame(columns=DETAILED_OUTPUT_COLUMNS),
            {
                "run_key": run_key,
                "dataset": dataset,
                "status": score_status,
                "isolation_detector_status": "",
                "isolation_alerts": 0,
                "alerts_with_complete_evidence": 0,
                "alerts_with_partial_evidence": 0,
                "alerts_without_evidence": 0,
                "alerts_with_truncated_chains": 0,
                "source_event_rows": 0,
            },
        )

    alert_ids = set(alerts["row_manifest_id"])
    evidence = load_existing_evidence(run_folder, alert_ids)
    missing_lineage_alerts = []
    if evidence is None:
        LOGGER.debug("%s: reconstructing evidence from split lineage", run_key)
        evidence, missing_lineage_alerts = reconstruct_evidence(
            args.features / dataset,
            args.event_lookup,
            alert_ids,
        )
    evidence = add_alert_metadata(
        evidence, alerts, run_key, dataset
    )
    chains = build_chain_rows(
        run_key,
        dataset,
        alerts,
        evidence,
        args.maximum_chain_characters,
    )
    detailed = detailed_columns(evidence)

    complete = int(chains["evidence_status"].eq("complete").sum())
    partial = int(chains["evidence_status"].eq("partial").sum())
    missing = int(chains["evidence_status"].eq("missing").sum())
    truncated = int(truthy(chains["chain_truncated"]).sum())

    if (
        (partial or missing or missing_lineage_alerts)
        and not args.allow_partial_evidence
    ):
        raise ValueError(
            run_key
            + " has incomplete OSSEC evidence: partial=" + str(partial)
            + ", missing=" + str(missing)
            + ", missing_lineage=" + str(len(missing_lineage_alerts))
            + ". Use --allow-partial-evidence only when intentional."
        )

    detector_status = (
        compact_text(alerts["isolation_detector_status"].iloc[0])
        if len(alerts) and "isolation_detector_status" in alerts.columns
        else ""
    )
    LOGGER.debug(
        "%s: complete=%s, partial=%s, missing=%s, truncated=%s",
        run_key, complete, partial, missing, truncated,
    )
    return chains, detailed, {
        "run_key": run_key,
        "dataset": dataset,
        "status": "complete" if not (partial or missing) else "partial",
        "isolation_detector_status": detector_status,
        "isolation_alerts": int(len(alerts)),
        "alerts_with_complete_evidence": complete,
        "alerts_with_partial_evidence": partial,
        "alerts_without_evidence": missing,
        "alerts_with_truncated_chains": truncated,
        "source_event_rows": int(len(detailed)),
        "unique_source_events": int(
            detailed["event_id"].nunique(dropna=True)
            if "event_id" in detailed.columns else 0
        ),
    }


def write_csv(frame, path):
    """Write a dataframe to CSV, creating parent directories as needed.

    :param frame: Dataframe to write.
    :param path: Destination CSV path.
    :rtype: None
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)


def main(args):
    """Export isolation-evidence chains for every configured OSSEC run.

    :param args: Parsed command-line settings.
    :rtype: None
    :raises ValueError: If artifact validation or evidence resolution fails.
    """
    validate_artifact_contract(args)
    args.output.mkdir(parents=True, exist_ok=True)

    LOGGER.info("OSSEC experiments: %s", args.experiments)
    LOGGER.info("OSSEC explainable features: %s", args.features)
    LOGGER.info("OSSEC event lookup: %s", args.event_lookup)
    LOGGER.info("Output folder: %s", args.output)

    chains = []
    details = []
    summaries = []
    for index, (run_key, dataset) in enumerate(RUNS, 1):
        LOGGER.info("Run %s/%s: exporting OSSEC Isolation Forest evidence: %s",
                    index, len(RUNS), run_key)
        chain, detail, summary = process_run(
            run_key, dataset, args
        )
        chains.append(chain)
        details.append(detail)
        summaries.append(summary)
        LOGGER.info(
            "%s: status=%s, alerts=%s, evidence_rows=%s", run_key,
            summary["status"], summary["isolation_alerts"],
            summary["source_event_rows"],
        )

    with stage("combine and write export outputs"):
        chain_frame = (
            pd.concat(chains, ignore_index=True, sort=False)
            if chains else pd.DataFrame(columns=CHAIN_OUTPUT_COLUMNS)
        )
        detail_frame = (
            pd.concat(details, ignore_index=True, sort=False)
            if details else pd.DataFrame(columns=DETAILED_OUTPUT_COLUMNS)
        )
        summary_frame = pd.DataFrame(summaries)
        category_frame = category_summary(chain_frame, detail_frame)

        chain_path = (
            args.output
            / "ossec_isolation_forest_outlier_message_chains.csv"
        )
        detail_path = (
            args.output
            / "ossec_isolation_forest_outlier_events_detailed.csv"
        )
        summary_path = (
            args.output
            / "ossec_isolation_forest_outlier_export_summary.csv"
        )
        category_path = (
            args.output
            / "ossec_isolation_forest_outlier_categories.csv"
        )

        write_csv(chain_frame, chain_path)
        write_csv(detail_frame, detail_path)
        write_csv(summary_frame, summary_path)
        write_csv(category_frame, category_path)

    LOGGER.info("Complete")
    LOGGER.info("Message chains: %s", chain_path)
    LOGGER.info("Detailed events: %s", detail_path)
    LOGGER.info("Export summary: %s", summary_path)
    LOGGER.info("Category summary: %s", category_path)


if __name__ == "__main__":
    args = parse_args()
    runlog.configure_from(args)
    try:
        with runlog.run():
            main(args)
    except KeyboardInterrupt:                    # runlog.run() has logged it
        sys.exit(130)
    except Exception:
        LOGGER.exception("OSSEC isolation evidence export failed")
        sys.exit(1)