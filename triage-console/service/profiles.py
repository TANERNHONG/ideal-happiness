"""Profiles (FR-PRO): every server, source IP, username and destination IP against its own normal, on any day.

Phase 4h (pipeline/phase4_detection/activity_profiles.py) writes data/phase4_detection/<source>/profiles/
profiles.sqlite: lines per hour and per day for every entity, alerted or not, the P10 / median / P90 of its daily
totals on each weekday's training days (public holidays apart), and who it shared lines with each day. This module
reads it, read-only and with a connection per call so a new run can swap the file in. The pictures come from the
pipeline's own activity_explain.profile (loaded through pipeline_code), so a profile and an Explain record agree.

Normal is the training period for AUTH and OSSEC, and no activity for PF and IPFilter (the presence method):
there, every line counts and nothing is compared with a median.

* meta(source)                         the method, split and days; None without Phase 4h output
* overview(source, kind, day, query)   the entities active that day or usually active on its weekday (all that
                                       match, with a query), furthest from their normal first
                                       (activity_explain.strength, against 0 without a baseline), with 56 days of
                                       daily totals each
* entity(source, kind, name, day)      one entity on one day: Explain's day, week, 8 weeks and history, its whole
                                       timeline, who it shared lines with up to that day, and its activity alerts
* watched() / watch(...)               the watch list (store.watchlist) with each entity's last day, for the Dashboard
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import date, timedelta
from functools import lru_cache
from pathlib import Path

import numpy as np

from . import activity, store
from .config import DATA
from .pipeline_code import module

KINDS = ("all", "server", "source_ip", "username", "destination_ip")
WHO = activity.WHO
LIMIT = 300
SPARK_DAYS = 56
TOUCHED = 200
EPOCH = date(1970, 1, 1)


def _code():
    return module("phase4_detection/activity_explain.py")


def path(source: str) -> Path:
    return DATA / "phase4_detection" / source / "profiles" / "profiles.sqlite"


def _connect(source: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path(source).as_posix()}?mode=ro", uri=True, timeout=10)


def iso(day: int) -> str:
    return str(EPOCH + timedelta(days=int(day)))


@lru_cache(maxsize=8)
def _meta(source: str, stamp: tuple) -> dict:
    with closing(_connect(source)) as con:
        meta = {key: json.loads(value) for key, value in con.execute("SELECT key, value FROM meta")}
        meta["counts"] = dict(con.execute("SELECT entity_type, COUNT(*) FROM entities GROUP BY entity_type").fetchall())
    meta["holiday_days"] = {int(day): name for day, name in meta["holidays"].items()}
    meta["log_day_set"] = frozenset(meta["log_days"])
    return meta


def meta(source: str) -> dict | None:
    file = path(source)
    return _meta(source, activity._stamp(file)) if file.is_file() else None


def _day(m: dict, text: str) -> int:
    """A day number from YYYY-MM-DD, within the profiles' days; the last day when none is given."""
    if not text:
        return m["last_day"]
    try:
        day = (date.fromisoformat(text) - EPOCH).days
    except ValueError:
        raise ValueError("A day is written YYYY-MM-DD.") from None
    if not m["first_day"] <= day <= m["last_day"]:
        raise ValueError(f"The profiles cover {iso(m['first_day'])} to {iso(m['last_day'])}.")
    return day


def _kind(kind: str) -> str:
    if kind not in KINDS:
        raise ValueError(f"Unknown entity type {kind!r}.")
    return kind


def name_of(kind: str, entity: str) -> str:
    return WHO[kind] if kind == "all" else f"{WHO[kind]} {entity}"


def _alerts(source: str) -> Counter:
    return Counter((i["entity_type"], i["entity"]) for i in activity.items(source))


def _rows(con, source: str, m: dict, kind: str, day: int, where: str = "", params: tuple = ()) -> list[dict]:
    """The entities of one type matching `where`, each on `day` against its weekday's training days (P10 / median /
    P90 of their daily totals, n), how far from it (activity_explain.strength) and its 56 days of daily totals."""
    code = _code()
    basis = code.basis_of(day, m["holiday_days"])
    found = con.execute(
        "SELECT e.id, e.entity, e.first_day, e.training_days, COALESCE(d.lines, 0), u.basis_name, u.days, u.low, u.median, u.high "
        "FROM entities e LEFT JOIN daily d ON d.id = e.id AND d.day = ? LEFT JOIN usual u ON u.id = e.id AND u.basis = ? "
        f"WHERE e.entity_type = ? AND e.first_day <= ? {where}", (day, basis, kind, day, *params)).fetchall()
    training = m["method"] == "training"
    alerts = _alerts(source)
    watched = {(w["entity_type"], w["entity"]) for w in store.watchlist() if w["source"] == source}
    out = []
    for code_id, entity, first, training_days, x, basis_name, days, low, median, high in found:
        usual = {"low": low, "median": median, "high": high, "days": days, "basis": basis_name} if days else None
        against = usual or {"low": 0, "median": 0, "high": 0}
        out.append({"id": code_id, "entity": entity, "name": name_of(kind, entity), "x": x, "usual": usual,
                    "strength": round(code.strength(x, against), 4),
                    "direction": "above" if x > against["high"] else "below" if x < against["low"] else "within",
                    "first_seen": iso(first), "new_today": first == day,
                    "in_training": bool(first < m["train_end_day"]) if training else None,
                    "training_days": training_days, "alerts": alerts.get((kind, entity), 0),
                    "watched": (kind, entity) in watched})
    return out


def _sparks(con, m: dict, rows: list[dict], day: int) -> None:
    """Each row's daily totals for the 56 days to `day` (None before it was first seen or with no log that day)."""
    start = day - SPARK_DAYS + 1
    found: dict[int, dict[int, int]] = {r["id"]: {} for r in rows}
    ids = list(found)
    for at in range(0, len(ids), 500):
        part = ids[at:at + 500]
        for code_id, d, n in con.execute(f"SELECT id, day, lines FROM daily WHERE id IN ({','.join('?' * len(part))}) "
                                         "AND day BETWEEN ? AND ?", (*part, start, day)):
            found[code_id][d] = n
    for r in rows:
        first = (date.fromisoformat(r["first_seen"]) - EPOCH).days
        r["spark"] = [found[r["id"]].get(d, 0) if d >= first and d in m["log_day_set"] else None for d in range(start, day + 1)]


def _summary(m: dict) -> dict:
    return {"method": m["method"], "source_label": m["label"], "first_day": iso(m["first_day"]), "last_day": iso(m["last_day"]),
            "train_end": iso(m["train_end_day"]) if m["method"] == "training" else None, "split_basis": m["split_basis"],
            "types": [{"id": k, "label": WHO[k], "count": m["counts"].get(k, 0)} for k in m["entity_types"]],
            "log_days": [iso(d) for d in (m["log_days"][0], m["log_days"][-1])], "min_days": m["min_days"]}


def overview(source: str, kind: str, day_text: str = "", query: str = "", limit: int = LIMIT) -> dict:
    m = meta(source)
    if m is None:
        return {"ready": False}
    kind, day = _kind(kind), _day(m, day_text)
    query = query.strip().lower()[:200]
    where, params = (" AND instr(lower(e.entity), ?) > 0", (query,)) if query else (" AND (d.lines > 0 OR u.median > 0)", ())
    with closing(_connect(source)) as con:
        rows = _rows(con, source, m, kind, day, where, params)
        rows.sort(key=lambda r: (-r["strength"], -r["x"], r["entity"]))
        shown = rows[:limit]
        _sparks(con, m, shown, day)
    code = _code()
    return {"ready": True, **_summary(m), "day": iso(day), "weekday": code.WEEKDAYS[int(code.weekday(day))],
            "holiday": m["holiday_days"].get(day), "rows": shown, "total": len(rows), "limit": limit}


def entity(source: str, kind: str, name: str, day_text: str = "") -> dict:
    m = meta(source)
    if m is None:
        raise KeyError("No profiles for this log type. Run Phase 4h.")
    kind, day = _kind(kind), _day(m, day_text)
    code = _code()
    with closing(_connect(source)) as con:
        row = con.execute("SELECT id, first_day, last_day, lines, active_days, training_days FROM entities "
                          "WHERE entity_type = ? AND entity = ?", (kind, name)).fetchone()
        if row is None:
            raise KeyError("No profile for this entity.")
        code_id, first, last, lines, active_days, training_days = row
        hourly = np.array(con.execute("SELECT hour, lines FROM hourly WHERE id = ? ORDER BY hour", (code_id,)).fetchall(),
                          dtype=np.int64).reshape(-1, 2)
        daily = dict(con.execute("SELECT day, lines FROM daily WHERE id = ?", (code_id,)).fetchall())
        touched = con.execute(
            "SELECT e.entity_type, e.entity, SUM(p.lines), MIN(p.day), MAX(p.day), SUM(CASE WHEN p.day = ? THEN p.lines ELSE 0 END) "
            "FROM pairs p JOIN entities e ON e.id = p.other WHERE p.id = ? AND p.day <= ? GROUP BY p.other",
            (day, code_id, day)).fetchall()
    series = code.Series(hourly[:, 0] * code.STEPS_PER_HOUR, hourly[:, 1], np.asarray(m["log_days"], dtype=np.int64),
                         m["holiday_days"], m["train_end_day"])
    view = code.profile(series, day, {"holidays": m["holiday_days"], "log_day_set": m["log_day_set"],
                                      "train_end_day": m["train_end_day"]})
    training = m["method"] == "training"
    touched.sort(key=lambda t: (-t[5], -t[2], t[0], t[1]))
    alerts = [{k: i[k] for k in ("view", "item_id", "start", "end", "peak", "score")}
              for i in activity.items(source) if i["entity_type"] == kind and i["entity"] == name]
    days = range(m["first_day"], m["last_day"] + 1)
    watched = any(w["source"] == source and w["entity_type"] == kind and w["entity"] == name for w in store.watchlist())
    return {
        **view, "source": source, "entity_type": kind, "entity": name, "name": name_of(kind, name),
        "label": code.LABELS.get(kind, kind), **_summary(m), "watched": watched,
        "context": {"history": view["history"] if training else None},
        "stats": {"lines": lines, "active_days": active_days, "first_seen": iso(first), "last_seen": iso(last),
                  "training_days": training_days},
        "timeline": {"start": iso(m["first_day"]),
                     "totals": [daily.get(d, 0) if d >= first and d in m["log_day_set"] else None for d in days]},
        "touched": [{"entity_type": t[0], "entity": t[1], "name": name_of(t[0], t[1]), "lines": t[2], "on_day": t[5],
                     "first_seen": iso(t[3]), "last_seen": iso(t[4]), "new_today": t[3] == day,
                     "after_training": bool(t[3] >= m["train_end_day"]) if training else None}
                    for t in touched[:TOUCHED]],
        "touched_total": len(touched), "alerts": sorted(alerts, key=lambda a: a["start"]),
    }


def watch(source: str, kind: str, name: str, on: bool, actor: str) -> dict:
    m = meta(source)
    if m is None:
        raise KeyError("No profiles for this log type. Run Phase 4h.")
    _kind(kind)
    with closing(_connect(source)) as con:
        if con.execute("SELECT 1 FROM entities WHERE entity_type = ? AND entity = ?", (kind, name)).fetchone() is None:
            raise KeyError("No profile for this entity.")
    store.set_watched(source, kind, name, on, actor)
    return {"watched": on}


def watched() -> list[dict]:
    """Each watched entity on its log type's last day, against its normal, with its 56 days of daily totals."""
    out = []
    for w in store.watchlist():
        source, kind, name = w["source"], w["entity_type"], w["entity"]
        base = {"source": source, "entity_type": kind, "entity": name, "name": name_of(kind, name) if kind in WHO else name}
        m = meta(source)
        if m is None:
            out.append({**base, "ready": False})
            continue
        with closing(_connect(source)) as con:
            rows = _rows(con, source, m, kind, m["last_day"], " AND e.entity = ?", (name,))
            _sparks(con, m, rows, m["last_day"])
        out.append({**base, "ready": bool(rows), "method": m["method"], "day": iso(m["last_day"]), **(rows[0] if rows else {})})
    return out
