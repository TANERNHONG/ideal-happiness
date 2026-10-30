"""Outliers on the Dashboard: of the test rows in the views that every mechanism scores (AUTH sessions, OSSEC
episodes), how many were flagged, and by which mechanisms: Isolation Forest, the model zoo's consensus, Novelty, and
frequent subsequences (the Phase 4f sequence detector). Each row gets a 4-bit mask, one bit per mechanism, and the
masks are counted, so the Dashboard can draw the share flagged and every overlap. Each flagged row's mask is kept
too (masks(source)), for the label yield per mechanism (yields.py).

Counted once in the background and cached in ``var/cache/outliers.json``; counted again when an input changes.
"""
from __future__ import annotations

import csv
import json
import sys
import threading
from collections import Counter

from .config import CACHE, DATA, FROZEN

CACHE_FILE = CACHE / "outliers.json"
VIEWS = {"auth": "authentication_sessions", "ossec": "episodes"}
MECHANISMS = [("isolation_forest", "Isolation Forest"), ("model_zoo", "Model zoo"), ("novelty", "Novelty"),
              ("sequence", "Frequent subsequences")]                                        # bits 1, 2, 4, 8
_state = {"status": "idle", "progress": "", "sources": None}
_lock = threading.Lock()


def _inputs(source: str) -> list:
    root, view = DATA / "phase4_detection" / source, VIEWS[source]
    return [root / "detectors" / view / "test_scores.csv", root / "sequences" / view / "test_scores.csv",
            *sorted((root / "model_zoo" / view).glob("*/consensus_alerts_min*.csv"))]


def _stamp() -> dict:
    return {s: [[str(p.relative_to(DATA)), p.stat().st_size, int(p.stat().st_mtime)] for p in _inputs(s) if p.exists()] for s in VIEWS}


def _flagged(path, flag_columns: list[str]) -> tuple[int, dict[str, set]]:
    """Rows in a scores file, and the IDs flagged in each of ``flag_columns``."""
    sets = {c: set() for c in flag_columns}
    rows = 0
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        at = header.index("row_manifest_id")
        columns = [(c, header.index(c)) for c in flag_columns if c in header]
        for row in reader:
            rows += 1
            for name, i in columns:
                if row[i].strip().lower() in ("true", "1"):
                    sets[name].add(row[at])
    return rows, sets


def _count_source(source: str) -> dict | None:
    scores, sequences, *zoo_files = _inputs(source)
    if not scores.exists():
        return None
    rows, detectors = _flagged(scores, ["isolation_alert", "novelty_alert"])
    sequence = _flagged(sequences, ["sequence_alert"])[1]["sequence_alert"] if sequences.exists() else set()
    zoo = set()
    for path in zoo_files:
        with path.open(encoding="utf-8", newline="") as handle:
            zoo |= {row["row_manifest_id"] for row in csv.DictReader(handle)}
    sets = [detectors["isolation_alert"], zoo, detectors["novelty_alert"], sequence]
    masks = {row_id: sum(1 << bit for bit, members in enumerate(sets) if row_id in members) for row_id in set().union(*sets)}
    regions = Counter(masks.values())
    return {"source": source, "view": VIEWS[source], "rows": rows, "flagged": sum(regions.values()),
            "totals": {key: len(members) for (key, _), members in zip(MECHANISMS, sets)},
            "regions": {str(mask): n for mask, n in sorted(regions.items())}, "masks": masks}


def _count(set_progress) -> list:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    out = []
    for source in VIEWS:
        set_progress(f"{source}: counting")
        result = _count_source(source)
        if result:
            out.append(result)
    return out


def start_background() -> None:
    def run():
        stamp = _stamp()
        try:
            cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            complete = all("masks" in s for s in cached["sources"])        # counted before masks were kept: again
            if (cached.get("stamp") == stamp and complete) or FROZEN:      # frozen: kept as counted, the inputs are gone
                with _lock:
                    _state.update(status="ready", sources=cached["sources"])
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
            sources = _count(lambda text: _state.__setitem__("progress", text))
            CACHE.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps({"stamp": stamp, "sources": sources}), encoding="utf-8")
            with _lock:
                _state.update(status="ready", sources=sources)
        except Exception as error:                    # shown on the Dashboard as unavailable, never fatal
            with _lock:
                _state.update(status="failed", progress=str(error))

    threading.Thread(target=run, daemon=True, name="outliers").start()


def get() -> dict:
    """The counts for the Dashboard (without each row's mask)."""
    with _lock:
        sources = [{k: v for k, v in s.items() if k != "masks"} for s in _state["sources"]] if _state["sources"] else _state["sources"]
        return {**_state, "sources": sources, "mechanisms": [{"key": k, "label": label} for k, label in MECHANISMS]}


def masks(source: str) -> dict[str, int] | None:
    """{row_manifest_id: mechanism bits} for the flagged rows of the source's scored view; None until counted."""
    with _lock:
        found = next((s for s in _state["sources"] or [] if s["source"] == source), None)
        return found.get("masks") if found else None
