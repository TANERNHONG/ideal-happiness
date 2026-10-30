"""Phase 4f shared pieces: paths, chronological splits and the sequence store.

Every step of Phase 4f reads the store written by ``streams.py``:

    data/phase4f_sequences/<source>/streams/sequences.sqlite

    units      one row per AUTH session or OSSEC episode (the Phase 2 observation, same row_manifest_id):
               its host, times, Phase 3 split, close reason, censoring, duplicate and order flags, and
               the ID of its token sequence with the length of each run
    sequences  each distinct token sequence once: event types in source order, consecutive repeats
               collapsed into one token (the run lengths stay on the unit)
    aliases    the copies of a line from another (rotated) file that were merged into the kept line

Tokens are event types only (decision 2026-10-08). The Phase 3 split rule is reproduced here from
its metadata: train before the training boundary minus the purge gap, validation between the two
boundaries (inside the gaps), test from the validation boundary plus the gap; the rest is purged.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "auth": {
        "prefix": "authlog", "key": "record_id", "dataset": "authentication_sessions",
        "store": ROOT / "data/phase2_observations/auth/authlog_observation_store.sqlite",
        "observations": ROOT / "data/phase2_observations/auth/authlog_authentication_sessions.csv",
        "features": ROOT / "data/phase3_features/auth/authentication_sessions",
        "inactivity_seconds": 15 * 60,
    },
    "ossec": {
        "prefix": "ossec", "key": "event_id", "dataset": "episodes",
        "store": ROOT / "data/phase2_observations/ossec/ossec_observation_store.sqlite",
        "observations": ROOT / "data/phase2_observations/ossec/ossec_security_episodes.csv",
        "lineage": ROOT / "data/phase2_observations/ossec/ossec_security_episodes_lineage.csv",
        "features": ROOT / "data/phase3_features/ossec/episodes",
        "inactivity_seconds": 15 * 60,
    },
}
OUTPUT = ROOT / "data/phase4f_sequences"
DETECTION_OUTPUT = ROOT / "data/phase4_detection"
SPLITS = ("train", "validation", "test")
BEGIN, END = "<start>", "<end>"


def stream_folder(source):
    return OUTPUT / source / "streams"


def routine_folder(source):
    return OUTPUT / source / "routines"


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
    temporary.replace(path)


def split_rule(source):
    """(train_boundary, validation_boundary, gap) from the Phase 3 metadata of the source's view."""
    meta = read_json(SOURCES[source]["features"] / "metadata.json")["split_metadata"]
    return float(meta["train_boundary_epoch"]), float(meta["validation_boundary_epoch"]), float(meta["purge_gap_seconds"])


def split_of(epoch, rule):
    """Phase 3's split for an observation starting at ``epoch`` (see the module docstring)."""
    train, validation, gap = rule
    if epoch < train - gap:
        return "train"
    if train + gap <= epoch < validation - gap:
        return "validation"
    if epoch >= validation + gap:
        return "test"
    return "purged"


def phase3_split_counts(source):
    return read_json(SOURCES[source]["features"] / "metadata.json")["split_metadata"]["split_rows"]


def open_store(source, folder=None):
    """Read-only connection to a finished sequence store."""
    path = Path(folder or stream_folder(source)) / "sequences.sqlite"
    if not path.is_file():
        raise FileNotFoundError(f"No sequence store at {path}; run streams.py --source {source} first")
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


def load_sequences(connection):
    """sequence_id -> tuple of tokens."""
    return {sid: tuple(tokens.split(" ")) if tokens else () for sid, tokens in
            connection.execute("SELECT sequence_id, tokens FROM sequences")}


def positions(text):
    """'3 7' -> {3, 7}: token positions whose step from the previous token is uncertain."""
    return {int(item) for item in str(text or "").split()}
