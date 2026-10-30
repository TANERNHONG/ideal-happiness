"""Drift at scoring time (Analyze and uploads): how far new lines sit from the baseline the models learned.

The models were fitted on the study year and are not refitted when lines arrive, so two questions come with every
score:

* scores(percentiles, source, view): under no drift, a score's percentile among the validation scores is uniform on
  [0, 1] (the probability integral transform). D is the Kolmogorov-Smirnov distance of the new observations'
  Isolation Forest percentiles from Uniform(0, 1): an effect size. Observations are not independent (windows
  overlap, one server's sessions follow each other), so D is judged against its own null instead of a p-value:
  D for contiguous blocks of the same size drawn from validation itself, ordered by server and then time as an
  upload is (null(); cached per view). Drift is D above that null's 99th percentile, from MIN_N observations up.
* new_entities(source, rows): the share of observations naming a server, an account or a source address that
  Phase 4h never saw on a training day. A model scores the new as unusual for being new.

Counts and statistics only.
"""
from __future__ import annotations

import json
from contextlib import closing
from functools import lru_cache

import numpy as np
import pandas as pd
from scipy import stats

from . import activity, profiles
from .config import CACHE, DATA, FROZEN

MIN_N = 20
QUANTILE = 0.99
SIZES = (20, 50, 100, 200, 500, 1000, 2000, 5000)
DRAWS = 200
SEED = 20261030
NULL_VERSION = "1"
FIELDS = {"server": ("host_id", "hostname"), "username": ("username",), "source_ip": ("source_ip",)}
HOSTS = ("host_id", "hostname")
TIMES = ("timestamp", "session_start", "episode_start", "window_start", "start")


def _d(values: np.ndarray) -> float:
    return float(stats.kstest(values, "uniform").statistic)


def null_table(percentiles: np.ndarray, sizes=SIZES, draws: int = DRAWS, seed: int = SEED) -> dict[int, float]:
    """{block size: the QUANTILE of D over ``draws`` contiguous blocks of that size}, for the sizes that fit."""
    rng = np.random.default_rng(seed)
    out = {}
    for size in sizes:
        if size > len(percentiles) // 2:
            break
        starts = rng.integers(0, len(percentiles) - size + 1, draws)
        out[size] = float(np.quantile([_d(percentiles[s:s + size]) for s in starts], QUANTILE))
    return out


def threshold(table: dict[int, float], n: int) -> float | None:
    """The null's QUANTILE of D for n observations, interpolated in log n (the largest block size beyond it)."""
    if not table or n < MIN_N:
        return None
    sizes = np.array(sorted(table))
    values = np.array([table[s] for s in sizes])
    return float(np.interp(np.log(n), np.log(sizes), values))


def null(source: str, view: str) -> dict[int, float]:
    """The cached null for one view, from the detectors' validation scores; {} when they are not on this laptop."""
    path = DATA / "phase4_detection" / source / "detectors" / view / "validation_scores.csv"
    cache = CACHE / f"drift_null_{source}_{view}.json"
    stamp = f"v{NULL_VERSION};{path.stat().st_size}:{int(path.stat().st_mtime)}" if path.exists() else ""
    try:
        saved = json.loads(cache.read_text(encoding="utf-8"))
        if saved.get("stamp") == stamp or (FROZEN and saved.get("table")):    # frozen: the scores are gone
            return {int(k): v for k, v in saved["table"].items()}
    except (OSError, ValueError):
        pass
    if not path.exists():
        return {}
    from . import scoring
    header = pd.read_csv(path, nrows=0).columns
    order = [c for c in HOSTS if c in header][:1] + [c for c in TIMES if c in header][:1]
    frame = pd.read_csv(path, usecols=["isolation_score", *order])
    frame = frame.sort_values(order, kind="stable") if order else frame
    scores = pd.to_numeric(frame["isolation_score"], errors="coerce").dropna().to_numpy()
    percentiles = scoring._percentile(scoring._reference(source, view).get("isolation_forest"), scores)
    table = null_table(np.asarray(percentiles, dtype=float)) if len(percentiles) else {}
    CACHE.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"stamp": stamp, "table": table}), encoding="utf-8")
    return table


def scores(percentiles, source: str = "", view: str = "") -> dict | None:
    """{"d", "n", "null", "drift"} for the finite percentiles; None when there are none. "null" is the validation
    null's 99th percentile of D for this n (None without it, or below MIN_N)."""
    values = np.asarray([p for p in percentiles if p is not None and np.isfinite(p)], dtype=float)
    if not len(values):
        return None
    d = _d(values)
    limit = threshold(null(source, view), len(values)) if source and view else None
    return {"d": d, "n": int(len(values)), "null": limit, "drift": bool(limit is not None and d > limit)}


def _known(source: str) -> dict[str, frozenset] | None:
    file = profiles.path(source)
    return _known_cached(source, activity._stamp(file)) if file.is_file() else None


@lru_cache(maxsize=8)
def _known_cached(source: str, stamp: tuple) -> dict[str, frozenset]:
    """Per entity type, the entities first seen before the end of training (Phase 4h), lower case."""
    with closing(profiles._connect(source)) as con:
        row = con.execute("SELECT value FROM meta WHERE key = 'train_end_day'").fetchone()
        end = json.loads(row[0]) if row else None
        if end is None:
            return {}
        found: dict[str, set] = {}
        for kind, entity in con.execute("SELECT entity_type, entity FROM entities WHERE first_day < ?", (end,)):
            found.setdefault(kind, set()).add(str(entity).lower())
    return {kind: frozenset(values) for kind, values in found.items()}


def new_entities(source: str, rows: list[dict]) -> dict | None:
    """{kind: {"new": observations naming one first seen after training, "named": observations naming one}};
    None without Phase 4h's output."""
    known = _known(source)
    if not known:
        return None
    out = {}
    for kind, columns in FIELDS.items():
        if kind not in known:
            continue
        named = new = 0
        for row in rows:
            value = next((str(row[c]).lower() for c in columns if row.get(c)), "")
            if value:
                named += 1
                new += value not in known[kind]
        if named:
            out[kind] = {"new": new, "named": named}
    return out
