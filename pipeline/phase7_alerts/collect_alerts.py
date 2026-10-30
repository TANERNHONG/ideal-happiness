"""Phase 7: collect every alert of each type into four simple CSV files.

  python pipeline/phase7_alerts/collect_alerts.py --source auth
  python pipeline/phase7_alerts/collect_alerts.py --source pf --reset

Phase 4 writes alerts into many run folders, one per dataset and detector, in
formats built for debugging. This phase flattens them into four CSVs per log
source that an analyst (or Phase 8) can read directly:

    data/phase7_alerts/<source>/<prefix>_cumulative_robust_alerts.csv
    data/phase7_alerts/<source>/<prefix>_cumulative_isolation_forest_alerts.csv
    data/phase7_alerts/<source>/<prefix>_cumulative_novelty_alerts.csv
    data/phase7_alerts/<source>/<prefix>_cumulative_model_zoo_consensus_alerts.csv

Auth, OSSEC and PF also write two files from the coverage checks (Phases 4d and 4e):

``<prefix>_cumulative_silence_alerts.csv``
    one alert per run of days on which a host logged nothing in this source
    while other logs show it was up (``data/phase4_detection/<source>/silence``).
    ``raw_messages`` is a written description, because the alert is the absence
    of lines.
``<prefix>_cumulative_first_seen_alerts.csv``
    one alert per (host, kind, value) first seen in the test period, such as an
    event type or a login source address the host never showed before
    (``data/phase4_detection/<source>/first_seen``).
Both rank their alerts among themselves (rank 1.0 = most unusual).

Auth and OSSEC also write ``<prefix>_cumulative_sequence_alerts.csv`` from the
Phase 4f sequence detector (``data/phase4_detection/<source>/sequences``): one
alert per session or episode whose steps came in an order rarely or never seen
on that host in training. Its probability is the usual percentile.

And ``<prefix>_cumulative_activity_alerts.csv`` from the Phase 4g activity
detectors (``data/phase4_detection/<source>/activity``): one alert per episode
of unusual activity of the whole log, or of one server, source IP, username or
destination IP, judged on amounts and timing only, not on what the lines say.
``raw_messages`` starts with a written description, then the peak step's
lines. Ranked among themselves.

Detector runs whose ``summary.json`` says ``"status": "failed"`` are skipped, so
an old ``test_scores.csv`` left in a failed run's folder is never collected.

The IPFilter and PF sources (``ipf``, ``pf``), whose normal state is an empty or
nearly empty log (the presence method), also write
``<prefix>_cumulative_presence_alerts.csv``: one alert per flow episode, raised
because there was any activity at all. Its ``rank`` is the alert's rank
among those alerts by how unlike the rest of the activity it is (1.0 = least
like the rest), because every one of them is already an alert by policy. A
Phase 4 run asks for this with ``"probability_rule": "rank_within_alerts"`` in
its summary.json.

Each CSV has six columns:

``rank``
    How unusual the alert is, from 0 to 1: the share of observations in the
    same run that scored lower (0.998 = more unusual than 99.8% of them). For
    model-zoo consensus alerts it is the ensemble score, the mean percentile of
    the ensemble models against training scores. It ranks alerts; it is not a
    calibrated probability of an attack.
``probability``
    The same value under its old name (until 2026-10-30), kept for one release so that older readers still work.
    Read ``rank``.
``flagged_by``
    What raised the alert. Detector alerts list every detector that flagged the
    observation (Robust deviation, Isolation Forest, Novelty), so an Isolation
    Forest alert that novelty also flagged reads ``Isolation Forest + Novelty``.
    Model-zoo alerts list the voting models and their count, e.g.
    ``lof + hbos + ecod (3 models)``.
``dataset``
    Which view of the logs produced the alert: single events (``individual``),
    time windows, sessions or episodes, or daily behaviour. Model-zoo alerts
    also name the feature set (full or selected).
``raw_messages``
    The original log lines behind the alert, in event order, separated by
    `` | ``. Chains longer than 32,000 characters (Excel's cell limit is
    32,767) end with ``... [N more messages]``; the full chain is in the Phase 5
    detailed evidence.
``row_manifest_ids``
    The observations behind the alert, as ``<view>:<row_manifest_id>``,
    separated by ``; `` (one alert can come from several views). With the
    view's Phase 2/3 lineage they lead to every original event; for silence and
    first-seen alerts the ID names the episode or the (host, kind, value) item.
    Added 2026-10-01; files in the older four-column layout are started again.

Rows are sorted by rank, highest first.

Sources
-------
* Phase 4 detectors (``data/phase4_detection/<source>/detectors``): robust,
  Isolation Forest and novelty test alerts from every run's ``test_scores.csv``,
  with messages from the run's ``test_raw_alert_evidence.csv``.
* Phase 4 model zoo (``data/phase4_detection/<source>/model_zoo``): consensus
  alerts from every ``<dataset>/<feature_set>/consensus_alerts_min<N>.csv``,
  with messages resolved through the Phase 3 split lineage
  (``data/phase3_features/<source>``) and the Phase 1 event lookup
  (``data/phase1_classify/<source>/<prefix>_event_lookup.csv``).

Accumulation
------------
Each run merges the current alerts into the existing CSVs, so they grow as the
pipeline is rerun on new logs. Identical message chains are kept once, with the
highest probability seen; ``flagged_by`` and ``dataset`` then list every
detector and view that flagged those lines, separated by ``; ``. CSVs written
by an earlier layout are started again automatically. ``--reset`` starts the
four files again from the current outputs.

This one script replaces the three per-source copies
(``authlogs_/osseclogs_/pflogs_stage7_cumulative_alerts.py``), which differed
only in the settings now held in ``SOURCES``.
"""
from __future__ import annotations

import argparse
import sys
import json
import os
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# Per log source: display name, file-name prefix, and the Phase 1 event-lookup
# columns that link an observation's events back to their original lines.
SOURCES = {
    "auth": {"label": "Authentication", "prefix": "authlog",
             "lineage_key": "record_id", "message_column": "original_log_line",
             "alert_types": ("robust", "isolation_forest", "novelty", "model_zoo_consensus", "silence", "first_seen", "sequence",
                             "activity")},
    "ossec": {"label": "OSSEC", "prefix": "ossec",
              "lineage_key": "event_id", "message_column": "original_log_line",
              "alert_types": ("robust", "isolation_forest", "novelty", "model_zoo_consensus", "silence", "first_seen", "sequence",
                              "activity")},
    "pf": {"label": "PF", "prefix": "pflog",
           "lineage_key": "event_id", "message_column": "raw_message",
           "alert_types": ("presence", "robust", "isolation_forest", "novelty", "first_seen")},
    "ipf": {"label": "IPFilter", "prefix": "ipflog",
            "lineage_key": "event_id", "message_column": "raw_message",
            "alert_types": ("presence", "robust", "isolation_forest", "novelty")},
}
# Set from --source in main(); the lineage readers below use them.
LINEAGE_KEY = MESSAGE_COLUMN = None


def default_paths(source):
    prefix = SOURCES[source]["prefix"]
    return {
        "experiments": Path("data/phase4_detection") / source / "detectors",
        "extra_runs": [Path("data/phase4_detection") / source / name
                       for name in ("silence", "first_seen", "sequences", "activity")],
        "zoo": Path("data/phase4_detection") / source / "model_zoo",
        "features": Path("data/phase3_features") / source,
        "event_lookup": Path("data/phase1_classify") / source / f"{prefix}_event_lookup.csv",
        "output": Path("data/phase7_alerts") / source,
    }


ALERT_TYPES = ("robust", "isolation_forest", "novelty", "model_zoo_consensus")
# Stage 4 alert type: (alert flag column, score column)
STAGE4_DETECTORS = {
    "robust": ("robust_alert", "robust_score"),
    "isolation_forest": ("isolation_alert", "isolation_score"),
    "novelty": ("novelty_alert", "novelty_score"),
    "presence": ("presence_alert", "presence_score"),
    "silence": ("silence_alert", "silence_score"),
    "first_seen": ("first_seen_alert", "first_seen_score"),
    "sequence": ("sequence_alert", "sequence_score"),
    "activity": ("activity_alert", "activity_score"),
}
OUTPUT_COLUMNS = ["rank", "probability", "flagged_by", "dataset", "raw_messages", "row_manifest_ids"]
DETECTOR_NAMES = {"robust": "Robust deviation", "isolation": "Isolation Forest", "novelty": "Novelty",
                  "presence": "Presence (empty baseline)", "silence": "Silence (host up, log empty)",
                  "first_seen": "First seen on this host", "sequence": "Sequence (unusual order)",
                  "activity_robust": "Activity: robust deviation", "activity_forest": "Activity: Isolation Forest"}
LIST_SEPARATOR = "; "
MESSAGE_SEPARATOR = " | "
# Excel shows at most 32,767 characters per cell; longer chains are shortened.
MAX_MESSAGE_CHARACTERS = 32_000
CHUNK_ROWS = 200_000


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", required=True, choices=sorted(SOURCES), help="Log source to collect.")
    parser.add_argument("--experiments", type=Path,
                        help="Phase 4 detector folder (robust, Isolation Forest and novelty alerts).")
    parser.add_argument("--zoo", type=Path, help="Phase 4 model-zoo folder (consensus alerts).")
    parser.add_argument("--extra-runs", type=Path, nargs="*",
                        help="Further Phase 4 folders laid out like the detector folder (silence, first-seen, sequences, activity).")
    parser.add_argument("--features", type=Path, help="Phase 3 feature folder (split lineage for model-zoo alerts).")
    parser.add_argument("--event-lookup", type=Path, help="Phase 1 event lookup holding the original log lines.")
    parser.add_argument("--output", type=Path, help="Folder holding the four cumulative CSVs.")
    parser.add_argument("--reset", action="store_true",
                        help="Discard the existing cumulative CSVs and start again from the current outputs.")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    for name, path in default_paths(args.source).items():
        if getattr(args, name) is None:
            setattr(args, name, path)
    return args


def truthy(series):
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.fillna("").astype(str).str.strip().str.lower().isin({"1", "true", "yes", "y"})


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def percentile(all_scores, scores):
    """Share of the run's observations scoring strictly lower than each score."""
    reference = np.sort(all_scores[np.isfinite(all_scores)])
    if not reference.size:
        return np.full(len(scores), np.nan)
    return np.searchsorted(reference, scores, side="left") / reference.size


def rank_among(scores):
    """Rank of each alert among the alerts themselves: the highest gets 1.0, the lowest 1/n."""
    reference = np.sort(scores[np.isfinite(scores)])
    if not reference.size:
        return np.full(len(scores), np.nan)
    return np.searchsorted(reference, scores, side="right") / reference.size


def stage4_alerts(experiments, log):
    """Alerts per type from every Stage 4 run: (run folder, row ID, probability)."""
    collected = {name: [] for name in STAGE4_DETECTORS}
    if not experiments.is_dir():
        log.write(f"Stage 4 folder not found: {experiments}", "WARN")
        return collected
    for run in sorted(path for path in experiments.iterdir() if (path / "test_scores.csv").is_file()):
        if read_json(run / "summary.json").get("status") == "failed":
            log.write(f"{run.name}: skipped (its last run failed; test_scores.csv is from an earlier run)", "WARN")
            continue
        path = run / "test_scores.csv"
        header = pd.read_csv(path, nrows=0).columns
        detectors = {name: spec for name, spec in STAGE4_DETECTORS.items()
                     if spec[0] in header and spec[1] in header}
        usecols = (["row_manifest_id"] + [column for spec in detectors.values() for column in spec]
                   + (["detector_combination"] if "detector_combination" in header else []))
        frames = [chunk for chunk in pd.read_csv(path, usecols=usecols, dtype={"row_manifest_id": str},
                                                 chunksize=CHUNK_ROWS, low_memory=False)]
        if not frames:
            continue
        scores = pd.concat(frames, ignore_index=True)
        rank_within_alerts = read_json(run / "summary.json").get("probability_rule") == "rank_within_alerts"
        counts = []
        for alert_type, (flag, score) in detectors.items():
            values = pd.to_numeric(scores[score], errors="coerce").to_numpy(dtype=float)
            mask = truthy(scores[flag]).to_numpy()
            if mask.any():
                combination = (scores.loc[mask, "detector_combination"] if "detector_combination" in scores
                               else pd.Series(alert_type, index=scores.index[mask]))
                probability = (rank_among(values[mask]) if rank_within_alerts
                               else percentile(values, values[mask]))
                collected[alert_type].append(pd.DataFrame({
                    "run": run.name, "run_path": str(run),
                    "row_manifest_id": scores.loc[mask, "row_manifest_id"].str.strip().to_numpy(),
                    "probability": probability,
                    "flagged_by": combination.map(describe_combination).to_numpy(),
                    "dataset": run.name,
                }))
            counts.append(f"{alert_type}={int(mask.sum()):,}")
        log.write(f"{run.name}: " + ", ".join(counts))
    return collected


def describe_combination(value):
    """Readable Stage 4 detector list, e.g. isolation+novelty -> Isolation Forest + Novelty."""
    parts = str(value or "").replace("_only", "").split("+")
    names = [DETECTOR_NAMES.get(part.strip(), part.strip().replace("_", " ")) for part in parts if part.strip()]
    return " + ".join(names) or "unknown"


def describe_models(flagged, votes):
    """Readable model-zoo voters, e.g. 'lof + hbos + ecod (3 models)'."""
    models = [model for model in str(flagged or "").split("|") if model and model != "nan"]
    text = " + ".join(models) or "ensemble"
    count = pd.to_numeric(votes, errors="coerce")
    return f"{text} ({int(count)} models)" if pd.notna(count) else text


def zoo_alerts(zoo, log):
    """Consensus alerts from every model-zoo dataset and feature set."""
    frames = []
    if not zoo.is_dir():
        log.write(f"Model-zoo folder not found: {zoo}; consensus CSV keeps earlier alerts only", "WARN")
        return frames
    for folder in sorted(path for path in zoo.glob("*/*") if path.is_dir()):
        families = folder / "consensus_alerts_families.csv"                 # one vote per family (zoo_families.py)
        files = [families] if families.is_file() else sorted(folder.glob("consensus_alerts_min*.csv"), key=lambda path: path.stat().st_mtime)
        if not files:
            continue
        frame = pd.read_csv(files[-1], usecols=lambda column: column in {
            "row_manifest_id", "model_zoo_ensemble_score", "flagged_by", "member_vote_count", "all_model_vote_count"},
                            dtype={"row_manifest_id": str}, low_memory=False)
        if frame.empty:
            continue
        # The ensemble score is the mean percentile against training scores
        # (with a small bonus above the training maximum), so it is clipped to 1.
        frames.append(pd.DataFrame({
            "dataset": folder.parent.name,
            "row_manifest_id": frame["row_manifest_id"].str.strip(),
            "probability": pd.to_numeric(frame["model_zoo_ensemble_score"], errors="coerce").clip(0, 1),
            "flagged_by": [describe_models(flagged, votes) for flagged, votes in zip(
                frame.get("flagged_by", pd.Series("", index=frame.index)),
                frame.get("member_vote_count", frame.get("all_model_vote_count", pd.Series(np.nan, index=frame.index))))],
            "view": folder.parent.name + " (" + folder.name + " features)",
        }))
        log.write(f"{folder.parent.name}/{folder.name}: model_zoo_consensus={len(frame):,}")
    return frames


def join_messages(frame):
    """Order each observation's events and join their original lines."""
    frame = frame.assign(__position=pd.to_numeric(frame["event_position"], errors="coerce"))
    frame = frame.sort_values(["row_manifest_id", "__position"], kind="stable")
    frame["message"] = frame["message"].fillna("").astype(str).str.replace(r"\s+", " ", regex=True).str.strip()
    frame = frame[frame["message"].ne("")]
    result = {}
    for row_id, messages in frame.groupby("row_manifest_id", sort=False)["message"]:
        text, used = "", 0
        for message in messages:
            addition = (MESSAGE_SEPARATOR if text else "") + message
            if len(text) + len(addition) > MAX_MESSAGE_CHARACTERS:
                break
            text += addition
            used += 1
        if used < len(messages):
            text += f"{MESSAGE_SEPARATOR}... [{len(messages) - used:,} more messages]"
        result[row_id] = text
    return result


def stage4_messages(run, ids):
    """Message chains for Stage 4 alerts from the run's resolved alert evidence."""
    path = run / "test_raw_alert_evidence.csv"
    if not ids or not path.is_file() or path.stat().st_size == 0:
        return {}
    header = pd.read_csv(path, nrows=0).columns
    if MESSAGE_COLUMN not in header or "row_manifest_id" not in header:
        return {}
    frames = []
    for chunk in pd.read_csv(path, usecols=["row_manifest_id", "event_position", MESSAGE_COLUMN],
                             dtype={"row_manifest_id": str}, chunksize=CHUNK_ROWS, low_memory=False):
        chunk["row_manifest_id"] = chunk["row_manifest_id"].fillna("").str.strip()
        selected = chunk[chunk["row_manifest_id"].isin(ids)]
        if len(selected):
            frames.append(selected.rename(columns={MESSAGE_COLUMN: "message"}))
    return join_messages(pd.concat(frames, ignore_index=True)) if frames else {}


def lineage_links(folder, ids):
    """Lineage rows (observation -> source event) for the requested observations."""
    frames, remaining = [], set(ids)
    for name in ("test_lineage.csv", "validation_lineage.csv", "train_lineage.csv"):
        path = folder / name
        if not remaining or not path.is_file():
            continue
        for chunk in pd.read_csv(path, usecols=["row_manifest_id", LINEAGE_KEY, "event_position"],
                                 dtype=str, chunksize=CHUNK_ROWS, low_memory=False):
            chunk["row_manifest_id"] = chunk["row_manifest_id"].fillna("").str.strip()
            selected = chunk[chunk["row_manifest_id"].isin(remaining)]
            if len(selected):
                frames.append(selected)
        if frames:
            remaining -= set(pd.concat(frames)["row_manifest_id"])
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=["row_manifest_id", LINEAGE_KEY, "event_position"])


def lookup_messages(path, event_ids):
    """Original log line for each requested event ID, scanning the lookup once."""
    messages = {}
    if not event_ids or not path.is_file():
        return messages
    for chunk in pd.read_csv(path, usecols=[LINEAGE_KEY, MESSAGE_COLUMN], dtype=str,
                             chunksize=CHUNK_ROWS, low_memory=False):
        keys = chunk[LINEAGE_KEY].fillna("").str.strip()
        mask = keys.isin(event_ids)
        messages.update(zip(keys[mask], chunk.loc[mask, MESSAGE_COLUMN].fillna("")))
    return messages


def lineage_messages(features, event_lookup, wanted, log):
    """Message chains through Stage 3 lineage and the Stage 1 lookup.

    :param wanted: Mapping of dataset folder name to observation IDs.
    :returns: Mapping of (dataset, row_manifest_id) to joined messages.
    """
    links = []
    for dataset, ids in wanted.items():
        frame = lineage_links(features / dataset, ids)
        if len(frame):
            frame["dataset"] = dataset
            links.append(frame)
    if not links:
        return {}
    links = pd.concat(links, ignore_index=True)
    links[LINEAGE_KEY] = links[LINEAGE_KEY].fillna("").str.strip()
    lookup = lookup_messages(event_lookup, set(links[LINEAGE_KEY]))
    if not lookup:
        log.write(f"No source messages resolved from {event_lookup}", "WARN")
    links["message"] = links[LINEAGE_KEY].map(lookup)
    result = {}
    for dataset, frame in links.groupby("dataset", sort=False):
        result.update({(dataset, row_id): text for row_id, text in join_messages(frame).items()})
    return result


def missing_text(row_id):
    return f"[source messages not found; row_manifest_id={row_id}]"


def merge_lists(values):
    """Distinct entries of '; '-separated lists, in first-seen order."""
    seen = []
    for value in values:
        for item in str(value or "").split(LIST_SEPARATOR):
            item = item.strip()
            if item and item != "nan" and item not in seen:
                seen.append(item)
    return LIST_SEPARATOR.join(seen)


def accumulate(path, current, reset, log):
    """Merge current alerts into the cumulative CSV, one row per message chain."""
    frames = [current[OUTPUT_COLUMNS[1:]]]                                 # "rank" is added on the way out
    if path.is_file() and not reset:
        previous = pd.read_csv(path, dtype=str, keep_default_na=False)
        if "rank" not in previous.columns and list(previous.columns) == OUTPUT_COLUMNS[1:]:
            previous.insert(0, "rank", previous["probability"])               # the layout before 2026-10-30
        if list(previous.columns) == OUTPUT_COLUMNS:
            frames.insert(0, previous.drop(columns="rank"))
        else:
            log.write(f"{path.name} has an older layout; starting it again from the current outputs", "WARN")
    combined = pd.concat(frames, ignore_index=True)
    combined["probability"] = pd.to_numeric(combined["probability"], errors="coerce")
    combined = (combined.groupby("raw_messages", sort=False, as_index=False)
                .agg(probability=("probability", "max"), flagged_by=("flagged_by", merge_lists),
                     dataset=("dataset", merge_lists), row_manifest_ids=("row_manifest_ids", merge_lists))
                .sort_values("probability", ascending=False, kind="stable"))
    combined["probability"] = combined["probability"].round(6)
    combined.insert(0, "rank", combined["probability"])                     # its name; "probability" is the old one
    combined = combined[OUTPUT_COLUMNS]
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    combined.to_csv(temporary, index=False)
    os.replace(temporary, path)
    return len(combined)


def main():
    global LINEAGE_KEY, MESSAGE_COLUMN
    args = parse_args()
    source = SOURCES[args.source]
    LINEAGE_KEY, MESSAGE_COLUMN = source["lineage_key"], source["message_column"]
    log = Log(args.quiet)
    log.write(source["label"] + " Phase 7 starting: cumulative alert CSVs", "START")
    stage4 = stage4_alerts(args.experiments, log)
    for folder in args.extra_runs or []:
        if folder.is_dir():
            for alert_type, frames in stage4_alerts(folder, log).items():
                stage4[alert_type].extend(frames)
    chains = {}
    runs = {(frame["run"].iloc[0], frame["run_path"].iloc[0]) for frames in stage4.values() for frame in frames}
    for run, run_path in sorted(runs):
        ids = set().union(*(set(frame.loc[frame["run_path"].eq(run_path), "row_manifest_id"])
                            for frames in stage4.values() for frame in frames))
        found = stage4_messages(Path(run_path), ids)
        missing = ids - set(found)
        if missing:
            dataset = read_json(Path(run_path) / "summary.json").get("dataset") or run
            resolved = lineage_messages(args.features, args.event_lookup, {dataset: missing}, log)
            found.update({row_id: text for (_, row_id), text in resolved.items()})
        chains.update({(run, row_id): text for row_id, text in found.items()})
    zoo = zoo_alerts(args.zoo, log) if "model_zoo_consensus" in source.get("alert_types", ALERT_TYPES) else []
    wanted = {}
    for frame in zoo:
        wanted.setdefault(frame["dataset"].iloc[0], set()).update(frame["row_manifest_id"])
    zoo_chains = lineage_messages(args.features, args.event_lookup, wanted, log) if wanted else {}
    for alert_type in source.get("alert_types", ALERT_TYPES):
        if alert_type == "model_zoo_consensus":
            current = pd.concat(zoo, ignore_index=True) if zoo else pd.DataFrame(columns=OUTPUT_COLUMNS + ["row_manifest_id"])
            keys = zip(current["dataset"], current["row_manifest_id"])
            current["raw_messages"] = [zoo_chains.get(key) or missing_text(key[1]) for key in keys]
            current["row_manifest_ids"] = current["dataset"].astype(str) + ":" + current["row_manifest_id"].astype(str)
            current["dataset"] = current.get("view", current["dataset"])
        else:
            frames = stage4[alert_type]
            current = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=OUTPUT_COLUMNS + ["run", "row_manifest_id"])
            keys = zip(current["run"], current["row_manifest_id"])
            current["raw_messages"] = [chains.get(key) or missing_text(key[1]) for key in keys]
            current["row_manifest_ids"] = current["run"].astype(str) + ":" + current["row_manifest_id"].astype(str)
        path = args.output / (source["prefix"] + f"_cumulative_{alert_type}_alerts.csv")
        total = accumulate(path, current, args.reset, log)
        unresolved = int(current["raw_messages"].str.startswith("[source messages not found").sum()) if len(current) else 0
        log.write(f"{alert_type}: {len(current):,} current alerts, {total:,} cumulative rows"
                  + (f", {unresolved:,} without source messages" if unresolved else "") + f" -> {path}", "DONE")
    log.write(source["label"] + " Phase 7 completed: " + str(args.output), "COMPLETE", always=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
