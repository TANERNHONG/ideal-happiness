"""Message variants per event type: distinct messages once addresses, numbers,
hex values and fingerprints are replaced by placeholders (the pipeline's own
Phase 2 normalisation). Counted once over the whole year in the background and
cached in ``var/cache/variants.json``.
"""
from __future__ import annotations

import csv
import json
import sqlite3
import sys
import threading
from collections import defaultdict

from .config import CACHE, DATA, FROZEN
from .pipeline_code import module

CACHE_FILE = CACHE / "variants.json"
_state = {"status": "idle", "progress": "", "counts": None}
_lock = threading.Lock()


def _inputs():
    p1, p2 = DATA / "phase1_classify", DATA / "phase2_observations"
    return {
        "auth": [p2 / "auth" / "authlog_observation_store.sqlite"],
        "ossec": [p2 / "ossec" / "ossec_observation_store.sqlite"],
        "pf": sorted((p1 / "pf").glob("classified_pflog_events_????-??.csv")),
        "ipf": sorted((p1 / "ipf").glob("ipflog_events_????-??.csv")),
    }


def _stamp() -> dict:
    return {s: [[p.name, p.stat().st_size, int(p.stat().st_mtime)] for p in ps if p.exists()] for s, ps in _inputs().items()}


def _count(set_progress) -> dict:
    normalize = module("phase2_observations/auth.py").normalize_message
    counts = {}
    for source, paths in _inputs().items():
        sets = defaultdict(set)
        for path in paths:
            if not path.exists():
                continue
            if path.suffix == ".sqlite":
                con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
                for n, (event_type, message) in enumerate(con.execute("SELECT event_type, raw_message FROM events"), 1):
                    sets[event_type].add(hash(normalize(message)))
                    if n % 1_000_000 == 0:
                        set_progress(f"{source}: {n / 1e6:.0f} million lines")
                con.close()
            else:
                csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
                with path.open(encoding="utf-8", newline="") as handle:
                    for row in csv.DictReader(handle):
                        message = row.get("classification_message") or row.get("raw_message") or ""
                        message = message.split("]: ", 1)[-1]          # drop syslog prefix where present
                        sets[row.get("event_type") or "UNKNOWN"].add(hash(normalize(message)))
        counts[source] = {t: len(s) for t, s in sets.items()}
        set_progress(f"{source}: done")
    return counts


def start_background() -> None:
    def run():
        stamp = json.loads(json.dumps(_stamp()))
        try:
            cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if cached.get("stamp") == stamp or FROZEN:      # frozen: kept as counted, the inputs are gone
                with _lock:
                    _state.update(status="ready", counts=cached["counts"])
                return
        except (OSError, ValueError):
            pass
        if FROZEN:
            with _lock:
                _state.update(status="failed", progress="Not in the frozen runtime.")
            return
        with _lock:
            _state.update(status="counting", progress="starting")
        try:
            counts = _count(lambda text: _state.__setitem__("progress", text))
            CACHE.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps({"stamp": stamp, "counts": counts}), encoding="utf-8")
            with _lock:
                _state.update(status="ready", counts=counts)
        except Exception as error:
            with _lock:
                _state.update(status="failed", progress=str(error))

    threading.Thread(target=run, daemon=True, name="variants").start()


def get() -> dict:
    with _lock:
        return dict(_state)
