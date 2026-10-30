"""Export original authentication-log evidence for Isolation Forest outliers.

Stage 5 of the authentication-log explainable-lineage workflow.

Inputs
------
data/phase4_detection/auth/detectors/<dataset>/test_scores.csv
data/phase3_features/auth/<dataset>/*_lineage.csv
data/phase1_classify/auth/authlog_event_lookup.csv

Datasets
--------
* authentication_sessions
* individual
* host_5min
* host_behavior_1d

Outputs
-------
data/phase5_evidence/auth/
    authlog_isolation_forest_outlier_message_chains.csv
    authlog_isolation_forest_outlier_events_detailed.csv
    authlog_isolation_forest_outlier_export_summary.csv
    authlog_isolation_forest_outlier_categories.csv
    authlog_isolation_forest_review_queue.csv

The default policy requires complete evidence. Use
``--allow-partial-evidence`` only for an intentional partial export.

The script is verbose by default. Use ``--quiet`` or ``--verbose`` to control
console output.
"""
from __future__ import annotations

import argparse
import sys
import csv
import json
import re
import time
import traceback
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

DEFAULT_EXPERIMENTS = Path("data/phase4_detection/auth/detectors")
DEFAULT_FEATURES = Path("data/phase3_features/auth")
DEFAULT_LOOKUP = Path("data/phase1_classify/auth/authlog_event_lookup.csv")
DEFAULT_OUTPUT = Path("data/phase5_evidence/auth")
EXPECTED_FEATURE_CONTRACT = "authlog_explainable_lineage"
LOOKUP_CHUNK_ROWS = 200_000
DEFAULT_MAX_CHAIN_CHARACTERS = 250_000
PREVIEW_EVENT_LIMIT = 5
CHAIN_SEPARATOR = "\n--- AUTHENTICATION EVENT ---\n"

RUNS = (
    ("authentication_sessions", "authentication_sessions"),
    ("individual", "individual"),
    ("host_5min", "host_5min"),
    ("host_behavior_1d", "host_behavior_1d"),
)
LINEAGE_FILES = ("train_lineage.csv", "validation_lineage.csv", "test_lineage.csv")

CHAIN_COLUMNS = [
    "run_key", "dataset", "row_manifest_id", "isolation_score",
    "isolation_threshold", "detector_combination", "alert_tier",
    "observation_timestamp", "observation_entity", "observation_process",
    "observation_username", "observation_source_ip", "source_record_count",
    "source_record_found_count", "source_record_missing_count",
    "first_event_timestamp", "last_event_timestamp", "first_record_id",
    "last_record_id", "source_event_types", "source_processes",
    "source_usernames", "source_ips", "authentication_methods",
    "event_outcomes", "first_original_log_line", "last_original_log_line",
    "representative_original_log_lines", "original_log_line_chain",
    "record_id_chain", "relationship_role_chain", "evidence_status",
    "evidence_resolution_method", "chain_truncated",
]

DETAIL_COLUMNS = [
    "run_key", "dataset", "row_manifest_id", "isolation_score",
    "isolation_threshold", "detector_combination", "alert_tier",
    "event_position", "relationship_role", "record_id", "event_timestamp",
    "timestamp", "partition_month", "hostname", "process_name", "pid",
    "facility", "event_type", "event_category", "event_outcome", "username",
    "target_username", "invalid_user_indicator", "source_ip", "source_port",
    "source_location", "authentication_method", "connection_stage",
    "terminal_path", "failure_count", "failure_code", "disconnect_code",
    "operation", "reason", "raw_message", "original_log_line",
    "classification_line", "raw_line_sha256", "source_event_id",
    "source_file", "source_line", "event_lookup_found",
    "lineage_source_file", "evidence_resolution_method",
]

CATEGORY_COLUMNS = [
    "run_key", "dataset", "event_category", "event_outcome",
    "isolation_alerts", "source_record_rows", "unique_event_types",
    "unique_processes", "unique_usernames", "unique_source_ips",
    "maximum_isolation_score", "mean_isolation_score",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export original authentication events for Isolation Forest alerts."
    )
    parser.add_argument("--experiments", type=Path, default=DEFAULT_EXPERIMENTS)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--event-lookup", type=Path, default=DEFAULT_LOOKUP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--allow-partial-evidence", action="store_true")
    parser.add_argument(
        "--maximum-chain-characters",
        type=int,
        default=DEFAULT_MAX_CHAIN_CHARACTERS,
    )
    runlog.add_arguments(parser)
    return parser.parse_args()


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


def clean(value):
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def compact(value):
    return re.sub(r"\s+", " ", clean(value)).strip()


def truthy(series):
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return (
        series.fillna("").astype(str).str.strip().str.lower()
        .isin({"1", "true", "yes", "y"})
    )


def require_columns(frame, columns, source):
    missing = set(columns) - set(frame.columns)
    if missing:
        raise ValueError(source + " missing columns: " + ", ".join(sorted(missing)))


def read_json(path):
    if not path.is_file():
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    return value if isinstance(value, dict) else {}


def observation_timestamp(row):
    for column in ("timestamp", "window_start", "session_start", "first_timestamp"):
        if column in row.index and clean(row[column]):
            return clean(row[column])
    return ""


def observation_entity(row):
    for column in (
        "authentication_session_id", "host_id", "hostname", "username",
        "source_ip",
    ):
        if column in row.index and clean(row[column]):
            return clean(row[column])
    return ""


def ordered_unique(values, maximum=100):
    output, seen = [], set()
    for value in values:
        item = compact(value)
        if not item or item in seen:
            continue
        seen.add(item)
        output.append(item)
        if len(output) >= maximum:
            break
    return output


def validate_inputs(args):
    if not args.experiments.is_dir():
        raise FileNotFoundError("Experiment folder missing: " + str(args.experiments))
    if not args.features.is_dir():
        raise FileNotFoundError("Feature folder missing: " + str(args.features))
    if not args.event_lookup.is_file():
        raise FileNotFoundError("Authentication event lookup missing: " + str(args.event_lookup))
    header = pd.read_csv(args.event_lookup, nrows=0)
    require_columns(
        header,
        {"record_id", "original_log_line", "source_file", "source_line"},
        str(args.event_lookup),
    )
    problems = []
    for run_key, dataset in RUNS:
        feature_folder = args.features / dataset
        if feature_folder.is_dir():
            metadata = read_json(feature_folder / "metadata.json")
            contract = clean(metadata.get("feature_artifact_contract"))
            if contract and contract != EXPECTED_FEATURE_CONTRACT:
                problems.append(dataset + " has unsupported feature contract " + contract)
            for filename in LINEAGE_FILES:
                if not (feature_folder / filename).is_file():
                    problems.append(str(feature_folder / filename) + " missing")
        score_path = args.experiments / run_key / "test_scores.csv"
        if score_path.is_file():
            score_header = pd.read_csv(score_path, nrows=0)
            missing = {"row_manifest_id", "isolation_alert", "isolation_score"}.difference(
                score_header.columns
            )
            if missing:
                problems.append(str(score_path) + " missing " + ",".join(sorted(missing)))
    if problems:
        raise ValueError("Stage 5 input validation failed: " + "; ".join(problems))


def load_alerts(run_key, run_folder):
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
    summary = read_json(run_folder / "summary.json")
    if "isolation_threshold" not in alerts.columns:
        alerts["isolation_threshold"] = summary.get("isolation_threshold", np.nan)
    alerts["isolation_detector_status"] = summary.get(
        "isolation_detector_status", summary.get("status", "")
    )
    alerts["run_key"] = run_key
    return alerts, "available"


def load_existing_evidence(run_folder, alert_ids):
    path = run_folder / "test_raw_alert_evidence.csv"
    if not path.is_file():
        return None
    evidence = pd.read_csv(path, low_memory=False)
    if evidence.empty:
        return evidence
    require_columns(evidence, {"row_manifest_id", "record_id"}, str(path))
    evidence["row_manifest_id"] = (
        evidence["row_manifest_id"].fillna("").astype(str).str.strip()
    )
    evidence["record_id"] = evidence["record_id"].fillna("").astype(str).str.strip()
    evidence = evidence.loc[evidence["row_manifest_id"].isin(alert_ids)].copy()
    evidence["evidence_resolution_method"] = "stage4_test_raw_alert_evidence"
    return evidence


def load_lineage(feature_folder, alert_ids):
    frames = []
    for filename in LINEAGE_FILES:
        path = feature_folder / filename
        if not path.is_file():
            raise FileNotFoundError("Missing split lineage: " + str(path))
        frame = pd.read_csv(path, low_memory=False)
        require_columns(
            frame,
            {"row_manifest_id", "record_id", "event_position"},
            str(path),
        )
        frame["row_manifest_id"] = (
            frame["row_manifest_id"].fillna("").astype(str).str.strip()
        )
        frame["record_id"] = frame["record_id"].fillna("").astype(str).str.strip()
        selected = frame.loc[frame["row_manifest_id"].isin(alert_ids)].copy()
        selected["lineage_source_file"] = filename
        if len(selected):
            frames.append(selected)
    if not frames:
        return pd.DataFrame(), sorted(alert_ids)
    lineage = pd.concat(frames, ignore_index=True, sort=False)
    positions = pd.to_numeric(lineage["event_position"], errors="coerce")
    if positions.isna().any() or positions.lt(1).any():
        raise ValueError("Invalid authentication lineage event_position")
    lineage["event_position"] = positions.astype(int)
    if lineage.duplicated(["row_manifest_id", "record_id"]).any():
        raise ValueError("Duplicate authentication observation-to-record lineage links")
    missing = sorted(alert_ids - set(lineage["row_manifest_id"]))
    return lineage, missing


def lookup_subset(path, record_ids):
    record_ids = {clean(value) for value in record_ids if clean(value)}
    if not record_ids:
        return pd.DataFrame(columns=["record_id", "original_log_line"])
    header = pd.read_csv(path, nrows=0)
    preferred = [
        "record_id", "raw_line_sha256", "source_event_id", "timestamp",
        "partition_month", "hostname", "process_name", "pid", "facility",
        "event_type", "event_category", "event_outcome", "username",
        "target_username", "invalid_user_indicator", "source_ip", "source_port",
        "source_location", "authentication_method", "connection_stage",
        "terminal_path", "failure_count", "failure_code", "disconnect_code",
        "operation", "reason", "raw_message", "original_log_line",
        "classification_line", "source_file", "source_line",
    ]
    usecols = [column for column in preferred if column in header.columns]
    require_columns(header, {"record_id", "original_log_line"}, str(path))
    frames, seen = [], set()
    for chunk in pd.read_csv(
        path,
        usecols=usecols,
        chunksize=LOOKUP_CHUNK_ROWS,
        low_memory=False,
    ):
        chunk["record_id"] = chunk["record_id"].fillna("").astype(str).str.strip()
        selected = chunk.loc[chunk["record_id"].isin(record_ids)].copy()
        if selected.empty:
            continue
        duplicates = set(
            selected.loc[selected["record_id"].duplicated(keep=False), "record_id"]
        ) | seen.intersection(set(selected["record_id"]))
        if duplicates:
            raise ValueError("Duplicate record IDs in authentication lookup")
        seen.update(selected["record_id"])
        frames.append(selected)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=usecols)


def reconstruct_evidence(feature_folder, lookup_path, alert_ids):
    lineage, missing_observations = load_lineage(feature_folder, alert_ids)
    lookup = lookup_subset(lookup_path, set(lineage.get("record_id", [])))
    if lineage.empty:
        return lineage, missing_observations
    evidence = lineage.merge(
        lookup,
        on="record_id",
        how="left",
        validate="many_to_one",
        indicator=True,
    )
    evidence["event_lookup_found"] = evidence["_merge"].eq("both")
    evidence.drop(columns=["_merge"], inplace=True)
    evidence["evidence_resolution_method"] = "split_lineage_and_authlog_event_lookup"
    return evidence, missing_observations


def attach_alert_metadata(evidence, alerts, run_key, dataset):
    evidence = evidence.copy()
    metadata_columns = [
        column for column in (
            "row_manifest_id", "isolation_score", "isolation_threshold",
            "detector_combination", "alert_tier", "timestamp", "window_start",
            "session_start", "first_timestamp", "authentication_session_id",
            "host_id", "hostname", "process_name", "username", "source_ip",
            "event_category", "event_outcome",
        )
        if column in alerts.columns
        and (column == "row_manifest_id" or column not in evidence.columns)
    ]
    if len(metadata_columns) > 1:
        evidence = evidence.merge(
            alerts[metadata_columns],
            on="row_manifest_id",
            how="left",
            validate="many_to_one",
        )
    evidence["run_key"] = run_key
    evidence["dataset"] = dataset
    if "event_lookup_found" not in evidence.columns:
        evidence["event_lookup_found"] = evidence.get(
            "original_log_line", pd.Series(index=evidence.index, dtype=object)
        ).notna()
    else:
        evidence["event_lookup_found"] = truthy(evidence["event_lookup_found"])
    return evidence


def event_times(frame):
    for column in ("event_timestamp", "timestamp"):
        if column in frame.columns:
            values = pd.to_datetime(frame[column], errors="coerce", utc=True)
            if values.notna().any():
                return values
    return pd.Series(pd.NaT, index=frame.index, dtype="datetime64[ns, UTC]")


def chain_rows(run_key, dataset, alerts, evidence, max_characters):
    grouped = {
        key: value.copy()
        for key, value in evidence.groupby("row_manifest_id", sort=False)
    } if len(evidence) else {}
    output = []
    for _, alert in alerts.iterrows():
        row_id = clean(alert["row_manifest_id"])
        group = grouped.get(row_id, pd.DataFrame())
        if len(group):
            if "event_position" not in group.columns:
                group["event_position"] = np.arange(1, len(group) + 1)
            group["__position"] = pd.to_numeric(group["event_position"], errors="coerce")
            group["__time"] = event_times(group)
            group = group.sort_values(
                ["__position", "__time", "record_id"],
                kind="stable",
                na_position="last",
            )
            found = truthy(group["event_lookup_found"])
            messages = [
                clean(value)
                for value in group.loc[found, "original_log_line"]
                if clean(value)
            ]
            record_ids = [clean(value) for value in group["record_id"] if clean(value)]
            roles = ordered_unique(group.get("relationship_role", pd.Series(dtype=str)))
            times = group.loc[found, "__time"].dropna()
            event_types = ordered_unique(group.get("event_type", pd.Series(dtype=str)))
            processes = ordered_unique(group.get("process_name", pd.Series(dtype=str)))
            usernames = ordered_unique(group.get("username", pd.Series(dtype=str)))
            source_ips = ordered_unique(group.get("source_ip", pd.Series(dtype=str)))
            methods = ordered_unique(
                group.get("authentication_method", pd.Series(dtype=str))
            )
            outcomes = ordered_unique(group.get("event_outcome", pd.Series(dtype=str)))
            found_count = int(found.sum())
            missing_count = len(group) - found_count
            status = "complete" if len(group) and missing_count == 0 else "partial" if found_count else "missing"
            resolution = "|".join(
                ordered_unique(group.get("evidence_resolution_method", pd.Series(dtype=str)))
            )
            combined = CHAIN_SEPARATOR.join(messages)
            truncated = False
            if max_characters > 0 and len(combined) > max_characters:
                combined = combined[:max_characters] + "\n...[CHAIN TRUNCATED; SEE DETAILED CSV]"
                truncated = True
        else:
            messages = []; record_ids = []; roles = []; times = pd.Series(dtype="datetime64[ns, UTC]")
            event_types = []; processes = []; usernames = []; source_ips = []
            methods = []; outcomes = []; found_count = 0; missing_count = 0
            status = "missing"; resolution = "no_lineage"; combined = ""; truncated = False
        output.append({
            "run_key": run_key,
            "dataset": dataset,
            "row_manifest_id": row_id,
            "isolation_score": alert.get("isolation_score", np.nan),
            "isolation_threshold": alert.get("isolation_threshold", np.nan),
            "detector_combination": alert.get("detector_combination", ""),
            "alert_tier": alert.get("alert_tier", ""),
            "observation_timestamp": observation_timestamp(alert),
            "observation_entity": observation_entity(alert),
            "observation_process": alert.get("process_name", ""),
            "observation_username": alert.get("username", ""),
            "observation_source_ip": alert.get("source_ip", ""),
            "source_record_count": len(group),
            "source_record_found_count": found_count,
            "source_record_missing_count": missing_count,
            "first_event_timestamp": str(times.min()) if len(times) else "",
            "last_event_timestamp": str(times.max()) if len(times) else "",
            "first_record_id": record_ids[0] if record_ids else "",
            "last_record_id": record_ids[-1] if record_ids else "",
            "source_event_types": "|".join(event_types),
            "source_processes": "|".join(processes),
            "source_usernames": "|".join(usernames),
            "source_ips": "|".join(source_ips),
            "authentication_methods": "|".join(methods),
            "event_outcomes": "|".join(outcomes),
            "first_original_log_line": messages[0] if messages else "",
            "last_original_log_line": messages[-1] if messages else "",
            "representative_original_log_lines": CHAIN_SEPARATOR.join(
                messages[:PREVIEW_EVENT_LIMIT]
            ),
            "original_log_line_chain": combined,
            "record_id_chain": "|".join(record_ids),
            "relationship_role_chain": "|".join(roles),
            "evidence_status": status,
            "evidence_resolution_method": resolution,
            "chain_truncated": truncated,
        })
    return pd.DataFrame(output, columns=CHAIN_COLUMNS)


def detail_rows(frame):
    output = frame.copy()
    for column in DETAIL_COLUMNS:
        if column not in output.columns:
            output[column] = ""
    return output[DETAIL_COLUMNS]


def category_summary(chains, details):
    rows = []
    if chains.empty:
        return pd.DataFrame(columns=CATEGORY_COLUMNS)
    for (run_key, dataset), chain_group in chains.groupby(["run_key", "dataset"]):
        evidence = details.loc[
            details["run_key"].eq(run_key) & details["dataset"].eq(dataset)
        ].copy()
        if evidence.empty:
            continue
        evidence["event_category"] = (
            evidence["event_category"].fillna("unknown").astype(str).str.strip()
            .replace("", "unknown")
        )
        evidence["event_outcome"] = (
            evidence["event_outcome"].fillna("unknown").astype(str).str.strip()
            .replace("", "unknown")
        )
        for (category, outcome), group in evidence.groupby(
            ["event_category", "event_outcome"], sort=True
        ):
            alert_ids = set(group["row_manifest_id"].astype(str))
            related = chain_group.loc[
                chain_group["row_manifest_id"].astype(str).isin(alert_ids)
            ]
            scores = pd.to_numeric(related["isolation_score"], errors="coerce")
            rows.append({
                "run_key": run_key,
                "dataset": dataset,
                "event_category": category,
                "event_outcome": outcome,
                "isolation_alerts": len(alert_ids),
                "source_record_rows": len(group),
                "unique_event_types": group["event_type"].nunique(dropna=True),
                "unique_processes": group["process_name"].nunique(dropna=True),
                "unique_usernames": group["username"].nunique(dropna=True),
                "unique_source_ips": group["source_ip"].nunique(dropna=True),
                "maximum_isolation_score": scores.max(),
                "mean_isolation_score": scores.mean(),
            })
    return pd.DataFrame(rows, columns=CATEGORY_COLUMNS)


def review_queue(chains):
    if chains.empty:
        result = pd.DataFrame(columns=CHAIN_COLUMNS)
    else:
        pieces = []
        for (dataset, status), group in chains.groupby(
            ["dataset", "evidence_status"], sort=False
        ):
            pieces.append(
                group.sort_values("isolation_score", ascending=False).head(50)
            )
        result = pd.concat(pieces, ignore_index=True).drop_duplicates(
            ["dataset", "row_manifest_id"]
        )
    for column in (
        "review_label", "review_category", "review_notes", "reviewer",
        "reviewed_at",
    ):
        result[column] = ""
    return result


def process_run(run_key, dataset, args, log):
    run_folder = args.experiments / run_key
    alerts, status = load_alerts(run_key, run_folder)
    if alerts is None:
        return (
            pd.DataFrame(columns=CHAIN_COLUMNS),
            pd.DataFrame(columns=DETAIL_COLUMNS),
            {
                "run_key": run_key,
                "dataset": dataset,
                "status": status,
                "isolation_alerts": 0,
                "complete_evidence_alerts": 0,
                "partial_evidence_alerts": 0,
                "missing_evidence_alerts": 0,
                "source_record_rows": 0,
            },
        )
    log.write(f"{run_key}: {len(alerts):,} Isolation Forest alert(s) selected")
    alert_ids = set(alerts["row_manifest_id"])
    evidence = load_existing_evidence(run_folder, alert_ids)
    missing_observations = []
    if evidence is None:
        log.debug(run_key + ": reconstructing evidence from split lineage")
        evidence, missing_observations = reconstruct_evidence(
            args.features / dataset,
            args.event_lookup,
            alert_ids,
        )
    else:
        log.debug(run_key + ": reusing Stage 4 raw alert evidence")
    evidence = attach_alert_metadata(evidence, alerts, run_key, dataset)
    chains = chain_rows(
        run_key,
        dataset,
        alerts,
        evidence,
        args.maximum_chain_characters,
    )
    details = detail_rows(evidence)
    complete = int(chains["evidence_status"].eq("complete").sum())
    partial = int(chains["evidence_status"].eq("partial").sum())
    missing = int(chains["evidence_status"].eq("missing").sum())
    truncated = int(truthy(chains["chain_truncated"]).sum())
    if (partial or missing or missing_observations) and not args.allow_partial_evidence:
        raise ValueError(
            run_key + " has incomplete evidence: partial=" + str(partial)
            + ", missing=" + str(missing)
            + ", missing_lineage=" + str(len(missing_observations))
        )
    return chains, details, {
        "run_key": run_key,
        "dataset": dataset,
        "status": "complete" if not (partial or missing) else "partial",
        "isolation_alerts": len(alerts),
        "complete_evidence_alerts": complete,
        "partial_evidence_alerts": partial,
        "missing_evidence_alerts": missing,
        "truncated_message_chains": truncated,
        "source_record_rows": len(details),
        "unique_source_records": details["record_id"].nunique(dropna=True),
    }


def write_csv(frame, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)


def main():
    args = parse_args()
    log = Log(args.quiet, args.verbose)
    validate_inputs(args)
    args.output.mkdir(parents=True, exist_ok=True)
    log.write("Authentication Stage 5 starting", "START")
    log.debug("Experiments: " + str(args.experiments.resolve()))
    log.debug("Features: " + str(args.features.resolve()))
    log.debug("Event lookup: " + str(args.event_lookup.resolve()))

    chains, details, summaries = [], [], []
    for run_key, dataset in RUNS:
        started = time.perf_counter()
        log.write("Exporting Isolation Forest evidence: " + run_key, "PHASE")
        try:
            chain, detail, summary = process_run(run_key, dataset, args, log)
            chains.append(chain)
            details.append(detail)
            summaries.append(summary)
            log.write(
                f"Completed {run_key} in {log.elapsed(started)}: "
                f"alerts={summary['isolation_alerts']:,}, "
                f"source records={summary['source_record_rows']:,}, "
                f"status={summary['status']}",
                "DONE",
            )
        except Exception as error:
            log.write(run_key + " failed: " + repr(error), "ERROR", always=True)
            if args.verbose:
                traceback.print_exc()
            raise

    chain_frame = pd.concat(chains, ignore_index=True) if chains else pd.DataFrame(columns=CHAIN_COLUMNS)
    detail_frame = pd.concat(details, ignore_index=True) if details else pd.DataFrame(columns=DETAIL_COLUMNS)
    summary_frame = pd.DataFrame(summaries)
    category_frame = category_summary(chain_frame, detail_frame)
    queue_frame = review_queue(chain_frame)

    paths = {
        "chains": args.output / "authlog_isolation_forest_outlier_message_chains.csv",
        "details": args.output / "authlog_isolation_forest_outlier_events_detailed.csv",
        "summary": args.output / "authlog_isolation_forest_outlier_export_summary.csv",
        "categories": args.output / "authlog_isolation_forest_outlier_categories.csv",
        "review": args.output / "authlog_isolation_forest_review_queue.csv",
    }
    write_csv(chain_frame, paths["chains"])
    write_csv(detail_frame, paths["details"])
    write_csv(summary_frame, paths["summary"])
    write_csv(category_frame, paths["categories"])
    write_csv(queue_frame, paths["review"])

    log.write(
        f"Exported {len(chain_frame):,} Isolation Forest observations and "
        f"{len(detail_frame):,} original authentication records",
        "SUMMARY",
    )
    for key, path in paths.items():
        log.write(key + ": " + str(path), "SUMMARY")
    log.write("Authentication Stage 5 completed successfully", "COMPLETE", always=True)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
