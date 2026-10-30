"""Frequent subsequences: the Phase 4f sequence detector on uploaded lines.

The pipeline scores the year's AUTH sessions and OSSEC episodes in ``pipeline/phase4f_sequences/score.py``;
Review reads those scores through cluster_index. This module scores an upload the same way, with the pipeline's own
code: the upload's Phase 2 store becomes the same token streams (``streams.py``: Phase 2's session assignment
replayed for AUTH, the episode lineage for OSSEC), and each is scored against the saved step model and rules
(``score.py``) at the saved threshold.

As in the pipeline, an observation starting within the inactivity limit of the upload's first line has no scored
start, and one still open at its last line has no scored end (left- and right-censored).

"Never occurred on this host in training" needs the training sequences, read once from the stream store and cached
in ``var/cache/sequence_seen_<source>.json``, because the store is gone once data/ is purged. Without it the note
is left out; the score does not depend on it.
"""
from __future__ import annotations

import csv
import json
import sqlite3
import sys
import threading
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from .config import CACHE, DATA, FROZEN, PIPELINE
from .pipeline_code import module

VIEWS = {"auth": "authentication_sessions", "ossec": "episodes"}
OSSEC_FILES = ("ossec_security_episodes.csv", "ossec_security_episodes_lineage.csv")     # Phase 2's, in its output folder
_lock = threading.Lock()


class _Unknown:
    """Stands in for the training sequences when they are not available: every sequence counts as seen."""
    def __contains__(self, item) -> bool:
        return True


def _code():
    """streams.py and score.py. They import their sibling common.py as ``common``; Phase 8 has one too."""
    folder = PIPELINE / "phase4f_sequences"
    held = sys.modules.get("common")
    if held is not None and Path(getattr(held, "__file__", "") or "").parent != folder:
        del sys.modules["common"]
    try:
        return module("phase4f_sequences/streams.py"), module("phase4f_sequences/score.py")
    finally:
        if held is not None:
            sys.modules["common"] = held


def paths(source: str) -> dict[str, Path]:
    routines = DATA / "phase4f_sequences" / source / "routines"
    return {"model": routines / "model.json", "rules": routines / "rules.csv",
            "summary": DATA / "phase4_detection" / source / "sequences" / VIEWS[source] / "summary.json",
            "streams": DATA / "phase4f_sequences" / source / "streams" / "sequences.sqlite"}


def _stamp(path: Path) -> str:
    return f"{path.stat().st_size}:{int(path.stat().st_mtime)}" if path.exists() else ""


@lru_cache(maxsize=4)
def _detector(source: str, stamp: str):
    _, sc = _code()
    p = paths(source)
    summary = json.loads(p["summary"].read_text(encoding="utf-8"))
    return sc.Model(sc.read_json(p["model"])), sc.load_rules(p["rules"]), float(summary["threshold"])


def detector(source: str):
    """(model, rules, threshold), or None when Phase 4f has not run for this source."""
    if source not in VIEWS:
        return None
    p = paths(source)
    if not all(p[k].exists() for k in ("model", "rules", "summary")):
        return None
    return _detector(source, ";".join(_stamp(p[k]) for k in ("model", "rules", "summary")))


def seen(source: str):
    """(host, tokens) of every usable training observation, or an _Unknown when they cannot be read."""
    p = paths(source)
    cache = CACHE / f"sequence_seen_{source}.json"
    stamp = _stamp(p["streams"])
    with _lock:
        try:
            stored = json.loads(cache.read_text(encoding="utf-8"))
            if stored["stamp"] == stamp or FROZEN or not stamp:      # frozen or purged: kept as read
                return _seen_set(cache.as_posix(), stored["stamp"])
        except (OSError, ValueError, KeyError):
            pass
        if not stamp:
            return _Unknown()
        _, sc = _code()
        connection = sc.open_store(source, p["streams"].parent)
        try:
            sequences = sc.load_sequences(connection)
            groups, _ = sc.training_groups(connection)
        finally:
            connection.close()
        pairs = sorted({(host, sequences[sid]) for host, sid, _, _ in groups})
        CACHE.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"stamp": stamp, "seen": [[h, list(t)] for h, t in pairs]}), encoding="utf-8")
        _seen_set.cache_clear()
        return _seen_set(cache.as_posix(), stamp)


@lru_cache(maxsize=4)
def _seen_set(path: str, stamp: str) -> frozenset:
    stored = json.loads(Path(path).read_text(encoding="utf-8"))
    return frozenset((h, tuple(t)) for h, t in stored["seen"])


def _units(source: str, folder: Path) -> list[tuple]:
    """(observation ID, host, events, close reason) of the upload's sessions or episodes, from its Phase 2 output."""
    streams, _ = _code()
    units = []
    connection = sqlite3.connect(folder / "store.sqlite")
    try:
        if source == "auth":
            connection.row_factory = sqlite3.Row
            streams.replay_auth_sessions(connection, module("phase2_observations/auth.py"),
                                         lambda s, reason: units.append((s["id"], s["host"], s["events"], reason)))
            return units
        events = streams.ossec_events(connection)
    finally:
        connection.close()
    episodes_csv, lineage_csv = (folder / name for name in OSSEC_FILES)
    members = defaultdict(list)
    with lineage_csv.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            members[row["row_manifest_id"]].append(row["event_id"])
    with episodes_csv.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            found = [events[i] for i in members.get(row["row_manifest_id"], []) if i in events]
            if found:
                units.append((row["row_manifest_id"], row["host_id"], found, row["close_reason"]))
    return units


def score_upload(source: str, folder: Path) -> dict[str, dict]:
    """observation ID -> score, alert and explanation for the upload's sessions (AUTH) or episodes (OSSEC), from
    the Phase 2 output in ``folder``; empty when Phase 4f has not run for this source."""
    found = detector(source)
    if found is None:
        return {}
    model, rules, threshold = found
    streams, sc = _code()
    units = _units(source, folder)
    if not units:
        return {}
    known = seen(source)
    first = min(e["epoch"] for _, _, events, _ in units for e in events)
    limit = streams.SOURCES[source]["inactivity_seconds"]
    out = {}
    for unit_id, host, events, reason in units:
        built = streams.build_unit(events)
        left = min(e["epoch"] for e in events) < first + limit
        score, step, _, _, _, _, why = sc.score_one(built["tokens"], host, set(built["uncertain"]), left,
                                                    reason == "end_of_data", model, rules, known)
        alert = score >= threshold
        out[unit_id] = {"score": float(score), "alert": bool(alert), "rarest_step": step, "explanation": why if alert else ""}
    return out
