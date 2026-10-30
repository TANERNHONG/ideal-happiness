"""Context for reviewing an anomaly: the observation, how unusual it is, and the logs around it.

* flagged(): a cluster's flagged observations, most unusual first, with their server, time and scores.
* observation(): one observation: when and where it happened, its original lines, and how unusual it
  is. Each detector's score is given as a percentile of the validation period (the yardstick the
  Analyze page uses), with which detectors and how many model-zoo members flagged it, and Phase 4's
  own explanation. Firewall activity (PF, IPFilter) uses the presence method instead: a flow
  episode, its rank among the activity, and its start and end.
* around(): every log line from the same server in a window before and after the observation,
  across the log types, fetched with one read-only SQL query. The query is returned so the analyst
  can see it and refine it in the SQL console; it runs through the console's SQL guardrails.
  An activity alert (Phase 4g, activity.py) of a source IP, username or destination IP looks at
  that entity's lines in its own log instead (every line, for a whole-log alert).

Time: the auth and OSSEC stores keep local time in ``timestamp_text`` and index ``timestamp_epoch``
computed as if that local time were UTC; the firewall tables keep local time as text (indexed).
Each part of the query filters on its own store's convention, so the windows line up.
"""
from __future__ import annotations

import calendar
import csv
import json
import re
from datetime import datetime, timedelta
from functools import lru_cache

import numpy as np

from . import activity, cluster_index, scoring, sql, whitelist
from .catalog import SOURCES
from .config import DATA

LOGS = ("auth", "ossec", "pf", "ipf")
SERVER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")        # anything else never reaches a query
MAX_MINUTES = 24 * 60
DETECTORS = (("robust", "Robust deviation"), ("isolation_forest", "Isolation Forest"),
             ("novelty", "Novelty"), ("ensemble", "Model-zoo ensemble"),
             ("sequence", "Frequent subsequences"))            # Phase 4f: AUTH sessions and OSSEC episodes only
SIGMA = "Sigma"                                                  # the enabled Sigma rules (sigma_review.py): no score, a rule title


def _when(text: str) -> datetime:
    return datetime.strptime(str(text)[:19], "%Y-%m-%d %H:%M:%S")


def _text(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _percentiles(source: str, view: str, row: dict) -> list[dict]:
    reference = scoring._reference(source, view)
    out = []
    for key, label in DETECTORS:
        value = row.get(key)
        if value is None and reference.get(key) is None:          # a detector this view does not have
            continue
        share = None
        if value is not None and reference.get(key) is not None:
            share = float(scoring._percentile(reference[key], np.array([value], dtype=float))[0])
        why = row.get(f"{key}_why") or ""                                  # Phase 4 explains robust and novelty flags
        out.append({"key": key, "label": label, "score": value, "percentile": share,
                    "flagged": bool(row.get(f"{key}_alert")), "explanation": why or ""})
    if row.get("sigma_alert"):                                             # a known pattern: named, not scored
        out.append({"key": "sigma", "label": SIGMA, "score": None, "percentile": None, "flagged": True,
                    "explanation": "; ".join(_sigma_rules(row))})
    return out


def _sigma_rules(row: dict) -> list[str]:
    try:
        return json.loads(row.get("sigma_why") or "[]")
    except ValueError:
        return []


def _anomaly(detectors: list[dict]) -> float | None:
    """The highest percentile among the detectors: how far into the unusual tail the observation sits."""
    values = [d["percentile"] for d in detectors if d["percentile"] is not None]
    return max(values) if values else None


def flagged(source: str, view: str, cluster: str, limit: int = 120, filters=None) -> dict:
    """The group's flagged observations, ranked by anomaly score over all of them (not a sample)."""
    validation = cluster.startswith(cluster_index.VALIDATION_PREFIX)
    status = cluster_index.validation_status(source, view) if validation else cluster_index.scores_status(source, view)
    if status != "ready":
        return {"status": status, "items": []}
    rows = cluster_index.flagged_scores(source, view, cluster, limit=None)
    if filters:
        from . import review_filters
        allowed = review_filters.rows(source, view, filters)
        rows = [r for r in rows if r['row_id'] in allowed]
    if not rows:
        return {"status": "ready", "items": [], "total": 0}
    reference = scoring._reference(source, view)
    shares = []
    for key, _ in DETECTORS:
        values = np.array([np.nan if r.get(key) is None else r[key] for r in rows], dtype=float)
        share = scoring._percentile(reference.get(key), values)
        shares.append(np.where(np.isnan(values), np.nan, share))               # no score is no score, not the top
    grid = np.vstack(shares)
    anomaly = np.fmax.reduce(grid, axis=0)
    agree = np.nan_to_num(grid).mean(axis=0)                                    # ties at the top: more detectors agreeing first
    alerts = [sum(bool(r.get(f"{k}_alert")) for k, _ in DETECTORS) + bool(r.get("sigma_alert")) for r in rows]
    # a known pattern (Sigma) first, then the rarest
    order = sorted(range(len(rows)), key=lambda i: (not rows[i].get("sigma_alert"), -(0 if np.isnan(anomaly[i]) else anomaly[i]),
                                                     -alerts[i], -agree[i], str(rows[i]["t"])))
    labels = dict(DETECTORS)
    covered = whitelist.row_ids(source, view)
    items = [{"row_id": rows[i]["row_id"], "server": rows[i]["host"], "time": str(rows[i]["t"])[:19],
              "whitelisted": rows[i]["row_id"] in covered,
              "anomaly": None if np.isnan(anomaly[i]) else float(anomaly[i]),
              "flagged_by": [labels[k] for k, _ in DETECTORS if rows[i].get(f"{k}_alert")] + ([SIGMA] if rows[i].get("sigma_alert") else []),
              "sigma": _sigma_rules(rows[i]), "votes": rows[i].get("votes")}
             for i in order[:limit]]
    return {"status": "ready", "items": items, "total": len(rows)}


# --- firewall activity (presence method) ------------------------------------------------------

@lru_cache(maxsize=4)
def _episodes(source: str, stamp: str) -> dict[str, dict]:
    path = DATA / "phase2_observations" / source / f"{SOURCES[source]['prefix']}_flow_episodes.csv"
    with path.open(encoding="utf-8", newline="") as handle:
        return {r["row_manifest_id"]: r for r in csv.DictReader(handle)}


@lru_cache(maxsize=4)
def _episode_events(source: str, stamp: str) -> dict[str, list[str]]:
    path = DATA / "phase2_observations" / source / f"{SOURCES[source]['prefix']}_flow_episodes_lineage.csv"
    out: dict[str, list[str]] = {}
    if path.exists():
        with path.open(encoding="utf-8", newline="") as handle:
            for r in csv.DictReader(handle):
                out.setdefault(r["row_manifest_id"], []).append(r.get("event_id") or r.get("record_id") or "")
    return out


def _presence(source: str, row_id: str) -> dict:
    path = DATA / "phase2_observations" / source / f"{SOURCES[source]['prefix']}_flow_episodes.csv"
    if not path.exists():
        raise KeyError("No flow episodes for this log type.")
    stamp = f"{path.stat().st_size}:{int(path.stat().st_mtime)}"
    row = _episodes(source, stamp).get(row_id)
    if row is None:
        raise KeyError("No such flow episode.")
    return {"source": source, "view": "flow_episodes", "row_id": row_id, "server": row.get("hostname", ""),
            "start": str(row.get("start", ""))[:19], "end": str(row.get("end", ""))[:19], "method": "presence",
            "facts": {k: row.get(k) for k in ("flow", "source_ip", "destination_ip", "attempts", "lines", "packets", "actions", "duration_hours") if k in row},
            "event_ids": _episode_events(source, stamp).get(row_id, [])[:5000], "detectors": [], "anomaly": None, "lines": []}


# --- one observation --------------------------------------------------------------------------

def observation(source: str, view: str, row_id: str) -> dict:
    if SOURCES[source]["method"] == "presence":
        return _presence(source, row_id)
    if view in activity.VIEWS:                     # Phase 4g: an unusual amount of activity, content ignored
        return activity.observation(source, view, row_id)
    row = cluster_index.score_row(source, view, row_id)
    events = cluster_index.observation_events(source, view, row_id)
    times = sorted(t for _, t in events if t)
    detectors = _percentiles(source, view, row) if row else []
    server = (row or {}).get("host") or ""
    start = times[0][:19] if times else str((row or {}).get("t") or "")[:19]
    end = times[-1][:19] if times else start
    try:
        lines = cluster_index.point_lines(source, view, row_id, "test", limit=40)
    except ValueError:                              # the log lines were purged: the scores and times remain
        lines = {"lines": [], "line_count": None, "status": "purged"}
    return {"lines_status": lines.get("status", "ready"),"source": source, "view": view, "row_id": row_id, "server": server, "start": start, "end": end, "method": "baseline",
            "scores_status": cluster_index.scores_status(source, view) if row is None else "ready",
            "detectors": detectors, "anomaly": _anomaly(detectors), "votes": (row or {}).get("votes"),
            "event_ids": [e for e, _ in events], "lines": lines.get("lines", []), "line_count": lines.get("line_count")}


# --- the logs before and after it ----------------------------------------------------------------

def query(server: str, start: str, end: str, before: int, after: int, logs: list[str]) -> str:
    """One read-only query: every line from `server` between `before` minutes before `start` and
    `after` minutes after `end`, from each chosen log, oldest first."""
    if not SERVER.fullmatch(server or ""):
        raise ValueError("This observation does not name a server, so there is nothing to look around.")
    before, after = int(before), int(after)
    if not (0 <= before <= MAX_MINUTES and 0 <= after <= MAX_MINUTES):
        raise ValueError(f"Before and After must each be between 0 and {MAX_MINUTES} minutes.")
    chosen = [log for log in LOGS if log in set(logs)]
    if not chosen:
        raise ValueError("Choose at least one log.")
    a, b = _when(start) - timedelta(minutes=before), _when(end) + timedelta(minutes=after)
    ea, eb = calendar.timegm(a.timetuple()), calendar.timegm(b.timetuple()) + 1         # local time read as UTC
    ta, tb = _text(a), _text(b) + ".999999"
    parts = {
        "auth": f"SELECT 'auth' AS log, timestamp_text AS time, host_id AS server, event_type, original_log_line AS line, record_id AS id, "
                f"raw_line_sha256 AS sha256\n"
                f"  FROM auth.events WHERE host_id = '{server}' AND timestamp_epoch >= {ea} AND timestamp_epoch < {eb}",
        "ossec": f"SELECT 'ossec' AS log, timestamp_text AS time, host_id AS server, event_type, original_log_line AS line, event_id AS id, "
                 f"raw_line_sha256 AS sha256\n"
                 f"  FROM ossec.events WHERE host_id = '{server}' AND timestamp_epoch >= {ea} AND timestamp_epoch < {eb}",
        "pf": f"SELECT 'pf' AS log, substr(timestamp, 1, 19) AS time, '{server}' AS server, event_type, raw_message AS line, event_id AS id, "
              f"raw_message_sha256 AS sha256\n"
              f"  FROM fw.pf_events WHERE timestamp BETWEEN '{ta}' AND '{tb}' AND source_file LIKE '%pflog_{server}%'",
        "ipf": f"SELECT 'ipf' AS log, substr(timestamp, 1, 19) AS time, hostname AS server, event_type, raw_message AS line, event_id AS id, "
               f"raw_message_sha256 AS sha256\n"
               f"  FROM fw.ipf_events WHERE hostname = '{server}' AND timestamp BETWEEN '{ta}' AND '{tb}'",
    }
    comment = " ".join(f"{server}, {before} min before {start} to {after} min after {end}".split())     # one line, always
    return f"-- {comment}\n" + "\nUNION ALL\n".join(parts[log] for log in chosen) + "\nORDER BY time, log"


ENTITY_TABLES = {"auth": ("auth.events", "record_id"), "ossec": ("ossec.events", "event_id")}
ENTITY_VALUES = {"source_ip": re.compile(r"^[0-9A-Fa-f:.]{2,45}$"), "destination_ip": re.compile(r"^[0-9A-Fa-f:.]{2,45}$"),
                 "username": re.compile(r"^[A-Za-z0-9._@$-]{1,64}$")}     # anything else never reaches a query
ENTITY_WHERE = {"source_ip": "source_ip = '{v}'", "destination_ip": "destination_ip = '{v}'", "username": "username = '{v}'",
                "all": "1 = 1"}


def entity_query(source: str, scope: str, entity: str, start: str, end: str, before: int, after: int) -> str:
    """One read-only query: an activity alert's own log, the lines of that source IP, username or destination IP
    (every line for a whole-log alert) between `before` minutes before `start` and `after` minutes after `end`."""
    if source not in ENTITY_TABLES or scope not in ENTITY_WHERE:
        raise ValueError("This alert names nothing to look around.")
    if scope != "all" and not ENTITY_VALUES[scope].fullmatch(entity or ""):
        raise ValueError("This alert's name cannot be searched safely, so there is nothing to look around.")
    before, after = int(before), int(after)
    if not (0 <= before <= MAX_MINUTES and 0 <= after <= MAX_MINUTES):
        raise ValueError(f"Before and After must each be between 0 and {MAX_MINUTES} minutes.")
    a, b = _when(start) - timedelta(minutes=before), _when(end) + timedelta(minutes=after)
    ea, eb = calendar.timegm(a.timetuple()), calendar.timegm(b.timetuple()) + 1         # local time read as UTC
    table, key = ENTITY_TABLES[source]
    who = "the whole log" if scope == "all" else f"{scope} {entity}"
    comment = " ".join(f"{who}, {before} min before {start} to {after} min after {end}".split())
    return (f"-- {comment}\nSELECT '{source}' AS log, timestamp_text AS time, host_id AS server, event_type, original_log_line AS line, "
            f"{key} AS id, raw_line_sha256 AS sha256\n  FROM {table} WHERE {ENTITY_WHERE[scope].format(v=entity)} AND timestamp_epoch >= {ea} AND timestamp_epoch < {eb}"
            f"\nORDER BY time, log")


def around(source: str, view: str, row_id: str, before: int, after: int, logs: list[str]) -> dict:
    obs = observation(source, view, row_id)
    if obs.get("method") == "activity" and obs["scope"] != "server":      # an entity's own lines, in its own log
        text = entity_query(source, obs["scope"], obs["entity"], obs["start"], obs["end"], before, after)
    else:
        text = query(obs["server"], obs["start"], obs["end"], before, after, logs)
    result = sql.run(text)
    return {"query": text, "observation": {k: obs[k] for k in ("server", "start", "end")},
            "own": obs["event_ids"], "own_log": source, **result}
