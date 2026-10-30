"""Sigma in Review: the enabled rules run over the year's validation and test periods, as a fifth detector.

A hit flags every observation that holds one of its lines, in every view (the line itself, its session or
episode, its 5-minute window, its day), named by the rule's title. Review lists any group that holds one,
whatever its lift (clusters.review_queue).

The events are read from Phase 2's store, whose columns are Phase 1's own fields, as an upload's lines are
read. All servers are read together, because a correlation may group by address across servers. The period
is read in chunks of CHUNK, each with the rules' longest window before it (up to MAX_OVERLAP; a longer window
is cut to that), so a correlation also sees the events before a chunk starts. Lines map to observations
through Phase 3's validation and test lineage.

cluster_index runs this in its background pass and keeps the result in its tables (sigma_flags, sigma_views);
sigma.py asks for a new pass when the rules change.

training(source, ...) runs the same rules over the training period instead, on request (Sigma page, Training
period): a known attack pattern there was learned by the models as normal. It counts events per rule only.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from . import analyze, sigma
from .config import CACHE, DATA

VERSION = "1"
CHUNK = timedelta(days=2)
MAX_OVERLAP = timedelta(days=1)
SPLITS = ("validation", "test")
NOT_FIELDS = {"original_log_line"}         # the line itself is Event.line


def _stamp(*paths: Path) -> str:
    return ";".join(f"{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in paths)


def _lineages(source: str, views: list[str]) -> dict[str, list[Path]]:
    return {v: [p for s in SPLITS if (p := DATA / "phase3_features" / source / v / f"{s}_lineage.csv").exists()]
            for v in views if v != "individual"}


def stamp(source: str, store: Path, views: list[str]) -> str | None:
    """Changes with the rules, the event store and the lineage; None when the store is not on this laptop."""
    if not store.exists():
        return None
    _, rules = sigma.enabled_docs()
    lineage = [p for paths in _lineages(source, views).values() for p in paths]
    return f"v{VERSION};{rules};" + _stamp(store, *lineage)


def validation_start(source: str, views: list[str]) -> float | None:
    """The first epoch of the validation period, from Phase 3's split (its training boundary plus the purge gap)."""
    for view in views:
        path = DATA / "phase3_features" / source / view / "metadata.json"
        if path.exists():
            meta = json.loads(path.read_text(encoding="utf-8"))["split_metadata"]
            return float(meta["train_boundary_epoch"]) + float(meta["purge_gap_seconds"])
    return None


def _event(row: sqlite3.Row, source: str, n: int) -> sigma.Event:
    fields = {k: row[k] for k in row.keys() if k not in NOT_FIELDS and row[k] not in (None, "")}
    fields["host"] = fields.get("hostname") or fields.get("host_id", "")       # as Analyze names it
    fields["timestamp"] = row["timestamp_text"]
    return sigma.Event(n, row["original_log_line"] or "", fields, analyze._time(row["timestamp_text"]), source)


def _hits(source: str, store: Path, key: str, docs, begin: float | None, end: float | None, progress) -> dict[str, set]:
    """Event ID -> titles of the hits holding it, for events from ``begin`` up to ``end`` (None: the store's first
    or last). Read in chunks, each with the rules' longest window before it, so a correlation sees what came before."""
    overlap = min(sigma.longest_window(docs), MAX_OVERLAP).total_seconds()
    chunk = CHUNK.total_seconds()
    titles: dict[str, set] = defaultdict(set)
    con = sqlite3.connect(f"file:{store.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        first, last = con.execute("SELECT MIN(timestamp_epoch), MAX(timestamp_epoch) FROM events").fetchone()
        at = start = first if begin is None else begin
        stop = last if end is None else min(end, last) if last is not None else None
        while at is not None and stop is not None and at <= stop:
            progress(f"Sigma: {datetime.fromtimestamp(at, timezone.utc):%Y-%m-%d}")      # the store's local time, read as UTC
            rows = con.execute("SELECT * FROM events WHERE timestamp_epoch >= ? AND timestamp_epoch < ? ORDER BY timestamp_epoch, "
                               f"{key}", (at - overlap, at + chunk)).fetchall()
            events = [_event(r, source, i + 1) for i, r in enumerate(rows)]
            for i, names in sigma.hit_titles(docs, events).items():
                epoch = rows[i]["timestamp_epoch"]
                if epoch >= start and (end is None or epoch < end):            # inside the range (a hit across chunks, whole)
                    titles[rows[i][key]] |= names
            at += chunk
    finally:
        con.close()
    return titles


def training(source: str, store: Path, key: str, views: list[str], progress=lambda text: None) -> dict | None:
    """{"events": events in training that a rule matches, "rules": {title: events}}; None without a split."""
    docs, _ = sigma.enabled_docs()
    end = validation_start(source, views)
    if end is None or not store.exists():
        return None
    titles = _hits(source, store, key, docs, None, end, progress) if docs else {}
    rules: dict[str, int] = defaultdict(int)
    for names in titles.values():
        for name in names:
            rules[name] += 1
    return {"events": len(titles), "rules": dict(sorted(rules.items(), key=lambda kv: -kv[1]))}


TRAINING_FILE = CACHE / "sigma_training.json"
_training = {"state": "idle", "progress": ""}
_training_lock = threading.Lock()


def training_status() -> dict:
    """The last training-period check per log type, and whether it still matches the rules and the store."""
    from . import cluster_index
    try:
        saved = json.loads(TRAINING_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    sources = {}
    for source, (store, _) in cluster_index.STORES.items():
        current = stamp(source, store, cluster_index._source_views(source))
        found = saved.get(source)
        if found:
            sources[source] = {**{k: v for k, v in found.items() if k != "stamp"}, "current": found.get("stamp") == current}
    with _training_lock:
        return {**_training, "sources": sources}


def start_training() -> dict:
    """Runs training() for every log type with a store, in a background thread (one at a time)."""
    from . import cluster_index
    with _training_lock:
        if _training["state"] == "running":
            return {**_training}
        _training.update(state="running", progress="starting")

    def run():
        out = {}
        try:
            for source, (store, key) in cluster_index.STORES.items():
                views = cluster_index._source_views(source)
                result = training(source, store, key, views, lambda text: _training.__setitem__("progress", f"{source}: {text}"))
                if result is not None:
                    out[source] = {**result, "stamp": stamp(source, store, views), "checked_at": datetime.now().isoformat(timespec="seconds")}
            CACHE.mkdir(parents=True, exist_ok=True)
            TRAINING_FILE.write_text(json.dumps(out), encoding="utf-8")
            with _training_lock:
                _training.update(state="ready", progress="")
        except Exception as error:                     # shown on the Sigma page; never fatal
            with _training_lock:
                _training.update(state="failed", progress=f"{type(error).__name__}: {error}")

    threading.Thread(target=run, name="sigma-training", daemon=True).start()
    return {**_training}


def scan(source: str, store: Path, key: str, views: list[str], progress=lambda text: None) -> dict[str, dict[str, set]]:
    """view -> observation ID -> titles of the hits it holds, over the validation and test periods."""
    docs, _ = sigma.enabled_docs()
    begin = validation_start(source, views)
    if not docs or begin is None:
        return {v: {} for v in views}
    titles = _hits(source, store, key, docs, begin, None, progress)
    out = {"individual": dict(titles)} if "individual" in views else {}
    hit = set(titles)
    for view, paths in _lineages(source, views).items():
        found: dict[str, set] = defaultdict(set)
        for path in paths:
            progress(f"Sigma: {view} ({path.stem})")
            column = "record_id" if "record_id" in pd.read_csv(path, nrows=0).columns else "event_id"
            for part in pd.read_csv(path, usecols=["row_manifest_id", column], dtype=str, chunksize=2_000_000):
                for row_id, event_id in part[part[column].isin(hit)].itertuples(index=False):
                    found[row_id] |= titles[event_id]
        out[view] = dict(found)
    return out
