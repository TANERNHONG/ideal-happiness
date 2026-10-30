"""Phase 4g activity alerts in the console: Review items, their facts and Review filters (never whitelisted).

Phase 4g (pipeline/phase4_detection/activity_detectors.py) flags unusual AMOUNTS of activity for AUTH and OSSEC,
with what the lines say ignored: the whole log, or one server, source IP, username or destination IP, over
one or more 5-minute steps. Each alert is one Review item, read from Phase 4g's own outputs
(data/phase4_detection/<source>/activity/<view>/test_scores.csv and test_raw_alert_evidence.csv), so Review
lists the current run's alerts; Phase 7's cumulative file keeps older runs' alerts as well.

* items(source)              every alert as an item, most unusual first (Profiles counts them per entity)
* incident_items(source)     Review's and Explain's items: one per incident (Phase 4g's incidents.csv: an event's alerts
                             on several entities, a routine's alerts on several days), its lead alert's item with the
                             incident's title and members; every alert when the output has no incidents
* observation(source, view, id)  one alert as Review's detail panel shows it; review_context.around() looks
                             around it: a server's lines across the logs, or an entity's lines in its own log
* matches(item, filters)     whether an alert passes Review's filters (server, account, address)
"""
from __future__ import annotations

import csv
import json
from functools import lru_cache
from pathlib import Path

from .config import DATA

VIEWS = {"activity": {"label": "Activity, whole log", "unit": "the whole log over 5-minute steps"},
         "activity_by_entity": {"label": "Activity, per entity",
                                "unit": "one server, source IP, username or destination IP over 5-minute steps"}}
WHO = {"all": "Whole log", "server": "Server", "source_ip": "Source IP", "username": "Username",
       "destination_ip": "Destination IP"}
TOP_KEYS = {"server": "host_id", "source_ip": "source_ip", "username": "username", "destination_ip": "destination_ip"}
CHIPS = {"all": "server", "server": "server", "source_ip": "ip", "destination_ip": "ip", "username": "user"}
DETECTORS = {"activity_robust": "robust deviation", "activity_forest": "Isolation Forest"}
LINES = 40


def _folder(source: str, view: str) -> Path:
    return DATA / "phase4_detection" / source / "activity" / view


def _stamp(path: Path) -> tuple:
    try:
        stat = path.stat()
        return (stat.st_size, int(stat.st_mtime))
    except OSError:
        return (0, 0)


def available_views(source: str) -> list[dict]:
    """The activity views with Phase 4g output, for Review's view picker."""
    return [{"id": view, **meta} for view, meta in VIEWS.items() if (_folder(source, view) / "summary.json").is_file()]


@lru_cache(maxsize=8)
def _rows(source: str, view: str, stamp: tuple) -> dict[str, dict]:
    path = _folder(source, view) / "test_scores.csv"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8", newline="") as handle:
        return {row["row_manifest_id"]: row for row in csv.DictReader(handle)}


@lru_cache(maxsize=8)
def _evidence(source: str, view: str, stamp: tuple) -> dict[str, dict]:
    """{alert id: {"description", "lines", "ids"}} from the alert's evidence, in event order."""
    path = _folder(source, view) / "test_raw_alert_evidence.csv"
    out: dict[str, dict] = {}
    if not path.is_file():
        return out
    csv.field_size_limit(2 ** 31 - 1)
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        message = next((c for c in reader.fieldnames or [] if c not in ("row_manifest_id", "event_position", "event_ref")), "")
        for row in reader:
            entry = out.setdefault(row["row_manifest_id"], {"description": "", "lines": [], "ids": [], "positions": []})
            position = int(float(row.get("event_position") or 0))
            if position == 0:
                entry["description"] = row.get(message, "")
            else:
                entry["positions"].append(position)
                entry["lines"].append(row.get(message, ""))
                entry["ids"].append(row.get("event_ref", ""))
    for entry in out.values():
        order = sorted(range(len(entry["positions"])), key=entry["positions"].__getitem__)
        entry["lines"] = [entry["lines"][i] for i in order]
        entry["ids"] = [entry["ids"][i] for i in order if entry["ids"][i]]
        del entry["positions"]
    return out


@lru_cache(maxsize=8)
def _explanations(source: str, view: str, stamp: tuple) -> dict[str, dict]:
    path = _folder(source, view) / "explanations.jsonl"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        return {r["row_manifest_id"]: r for r in (json.loads(line) for line in handle if line.strip())}


def explanations(source: str, view: str) -> dict[str, dict]:
    """Phase 4g's plain-language record per alert (activity_explain.py), for Explain and for Review's usual range."""
    return _explanations(source, view, _stamp(_folder(source, view) / "explanations.jsonl"))


def usual_text(usual: dict | None) -> str:
    if not usual:
        return ""
    low, high = round(usual["low"]), round(usual["high"])
    return f"{low:,}" if low == high else f"{low:,}–{high:,}"


def rows(source: str, view: str) -> dict[str, dict]:
    return _rows(source, view, _stamp(_folder(source, view) / "test_scores.csv"))


def evidence(source: str, view: str) -> dict[str, dict]:
    return _evidence(source, view, _stamp(_folder(source, view) / "test_raw_alert_evidence.csv"))


def _float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _int(value) -> int:
    return int(_float(value))


def _detectors(row: dict) -> str:
    return " + ".join(DETECTORS.get(d, d) for d in str(row.get("detector_combination", "")).split("+") if d)


def _item(view: str, row: dict, found: dict, record: dict | None = None) -> dict:
    kind, entity = row.get("entity_type", ""), row.get("entity", "")
    big = (record or {}).get("big") or {}
    minutes, peak = _int(row.get("peak_window_minutes")), _int(row.get("peak_window_lines"))
    noun = {"failures": "failure", "new partners": "new partner"}.get(row.get("peak_channel") or "lines", "line")
    key = TOP_KEYS.get(kind)
    return {
        "item_id": row["row_manifest_id"], "kind": "activity_alert", "view": view, "view_label": VIEWS[view]["label"],
        "period": "test", "name": WHO.get(kind, kind) + ("" if kind == "all" else f" {entity}"),
        "entity_type": kind, "entity": entity, "top": {key: entity} if key else {},
        "start": str(row.get("start", ""))[:19], "end": str(row.get("end", ""))[:19],
        "first_seen": str(row.get("start", ""))[:10], "last_seen": str(row.get("end", ""))[:10],
        "peak_lines": peak, "peak_minutes": minutes, "peak": f"{peak:,} {noun}{'s' if peak != 1 else ''} in {minutes} min",
        "usual": _float(row.get("usual_window_lines")), "steps": _int(row.get("steps")),
        "usual_text": usual_text(big.get("usual")) if big and not big.get("little_history") else "",
        "baseline": row.get("baseline", ""), "flagged_by": _detectors(row), "score": _float(row.get("activity_score")),
        "compared_with": f"{row['calendar_basis']} at this time" if row.get("calendar_basis") else "its level when active",
        "description": found.get("description", ""), "lines": found.get("lines", [])[:LINES],
        "line_count": _int(row.get("peak_lines_5m")), "row_manifest_ids": f"{view}:{row['row_manifest_id']}",
        "channel": row.get("peak_channel") or "lines",
    }


def items(source: str) -> list[dict]:
    """Every current activity alert of a log type, most unusual first (its rank among them)."""
    out = []
    for view in VIEWS:
        found, records = evidence(source, view), explanations(source, view)
        out += [_item(view, row, found.get(row_id, {}), records.get(row_id)) for row_id, row in rows(source, view).items()]
    out.sort(key=lambda item: -item["score"])
    for rank, item in enumerate(out, start=1):
        item["rank"] = rank
    return out


@lru_cache(maxsize=8)
def _incidents(source: str, stamp: tuple) -> list[dict]:
    path = DATA / "phase4_detection" / source / "activity" / "incidents.csv"
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return [{**row, "members": [tuple(m.split(":", 1)) for m in (row.get("members") or "").split(";") if ":" in m]}
                for row in csv.DictReader(handle)]


def incidents(source: str) -> list[dict]:
    """Phase 4g's incidents (activity_incidents.py), most unusual first."""
    return _incidents(source, _stamp(DATA / "phase4_detection" / source / "activity" / "incidents.csv"))


MEMBER_KEYS = ("view", "view_label", "item_id", "name", "entity_type", "entity", "start", "end", "peak", "channel", "score")


def incident_items(source: str) -> list[dict]:
    """One item per incident: its lead alert's item, named by the incident (a routine: its clock time and days; an
    event on several entities: the lead with the others), its dates spanning every member, with the incident's kind and
    members. A label given to the item is the incident's (the item keeps the lead alert's id). Alerts no incident holds
    (an older output) stay items of their own."""
    every = {(i["view"], i["item_id"]): i for i in items(source)}
    out, held = [], set()
    for incident in incidents(source):
        lead = every.get((incident["lead_view"], incident["lead_id"]))
        members = [every[key] for key in incident["members"] if key in every]
        if lead is None or not members:
            continue
        held.update((m["view"], m["item_id"]) for m in members)
        out.append({**lead, "name": incident["title"] if incident["kind"] != "single" else lead["name"],
                    "first_seen": min(m["first_seen"] for m in members), "last_seen": max(m["last_seen"] for m in members),
                    "score": max(m["score"] for m in members),
                    "incident": {"id": incident["incident_id"], "kind": incident["kind"], "title": incident["title"],
                                 "size": len(members), "days": _int(incident.get("days")), "clock": incident.get("clock") or "",
                                 "members": [{k: m.get(k) for k in MEMBER_KEYS} for m in members]}})
    out += [i for key, i in every.items() if key not in held]
    out.sort(key=lambda item: -item["score"])
    for rank, item in enumerate(out, start=1):
        item["rank"] = rank
    return out


def observation(source: str, view: str, row_id: str) -> dict:
    """One alert for Review's detail panel; 'scope' tells review_context.around() where to look."""
    row = rows(source, view).get(row_id)
    if row is None:
        raise KeyError("No such activity alert.")
    item = _item(view, row, evidence(source, view).get(row_id, {}), explanations(source, view).get(row_id))
    kind = item["entity_type"]
    usual = item["usual"]
    return {
        "source": source, "view": view, "row_id": row_id, "method": "activity", "scope": kind,
        "server": item["entity"].lower() if kind == "server" else "", "entity": item["entity"],
        "who": {"kind": CHIPS.get(kind, "server"), "value": item["name"] if kind == "all" else item["entity"], "label": WHO.get(kind, kind)},
        "start": item["start"], "end": item["end"],
        "facts": {"peak": item["peak"], "usual": item["usual_text"] or (f"{usual:,.0f}" if usual >= 10 else f"{usual:,.1f}"),
                  "compared with": item["compared_with"], "steps": f"{item['steps']} of 5 minutes", "baseline": item["baseline"],
                  "flagged by": item["flagged_by"]},
        "description": item["description"], "event_ids": evidence(source, view).get(row_id, {}).get("ids", []),
        "detectors": [], "anomaly": None, "lines": item["lines"], "line_count": item["line_count"], "lines_status": "ready",
    }


def matches(item: dict, filters: dict) -> bool:
    """Review filters on an alert: its entity must satisfy every chosen field (alerts carry no program). An incident
    matches when any of its alerts does."""
    members = (item.get("incident") or {}).get("members") or []
    if members:
        return any(matches({k: v for k, v in member.items()}, filters) for member in members)
    kind, entity = item.get("entity_type", ""), str(item.get("entity", ""))
    for field, values in filters.items():
        if field == "host" and not (kind == "server" and entity.lower() in {v.lower() for v in values}):
            return False
        if field == "username" and not (kind == "username" and entity in values):
            return False
        if field == "address" and not (kind in ("source_ip", "destination_ip") and entity in values):
            return False
        if field == "program":
            return False
    return True
