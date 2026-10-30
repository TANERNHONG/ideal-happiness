"""Phase 7b clusters: the cluster table, its messages, and flagged clusters for review.

Clusters exist for auth and OSSEC; the firewall sources use the presence method
and have none, so their review items are the Phase 7 presence alerts.
"""
from __future__ import annotations

import csv
import hashlib
import sys
from functools import lru_cache
from pathlib import Path

from . import activity, cluster_index, store, whitelist
from .catalog import SOURCES, VIEWS, model_status

ANOMALOUS_LIFT = 2.0      # flagged at least twice as often as the view as a whole
VALIDATION_MIN_FLAGGED = 3   # a validation group needs this many flagged observations (one stray flag in a tiny group is not a pattern)
from .config import DATA

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
SUMMARY_COLUMNS = ("cluster_id", "rows", "flagged_rows", "alert_rate", "lift_vs_view", "first_seen", "last_seen",
                   "first_month_on_map", "zoo_flagged", "detector_alerts")
TOP_COLUMNS = ("top_hostname", "top_host_id", "top_username", "top_source_ip", "top_process_name", "top_event_type",
               "top_first_event_type", "top_event_category", "top_agent_name", "top_episode_family")


def _read(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


@lru_cache(maxsize=32)
def _summary(source: str, view: str, mtime: float) -> list[dict]:
    return _read(DATA / "phase7b_clusters" / source / view / "cluster_summary.csv")


def summary_rows(source: str, view: str) -> list[dict]:
    path = DATA / "phase7b_clusters" / source / view / "cluster_summary.csv"
    return _summary(source, view, path.stat().st_mtime if path.exists() else 0.0)


def default_name(row: dict) -> str:
    """A readable name from the cluster's dominant values, until someone renames it."""
    parts = []
    for column in ("top_event_type", "top_first_event_type", "top_event_category", "top_hostname", "top_host_id",
                   "top_username", "top_source_ip"):
        value = (row.get(column) or "").split(" (")[0].strip()
        if value and value not in parts:
            parts.append(value)
        if len(parts) == 2:
            break
    return " · ".join(parts) or row["cluster_id"]


def _num(value, cast=float):
    try:
        return cast(value)
    except (TypeError, ValueError):
        return None


def composition_name(mix: list[tuple[str, int]]) -> str:
    """One event type: its name. Several: the two largest, and how many more."""
    if len(mix) == 1:
        return mix[0][0]
    name = " + ".join(t for t, _ in mix[:2])
    return name + (f" (+{len(mix) - 2})" if len(mix) > 2 else "")


def list_clusters(source: str, view: str) -> list[dict]:
    names = store.cluster_names(source, view)
    counts = store.comment_counts(source, view)
    reviews = store.latest_reviews(source)
    mixes = cluster_index.composition(source, view)
    out = []
    for row in summary_rows(source, view):
        cid = row["cluster_id"]
        review = reviews.get((source, view, cid))
        mix = mixes.get(cid, [])
        total = sum(n for _, n in mix)
        out.append({
            "cluster_id": cid, "number": int(cid.split("#")[-1]) if "#" in cid else None,
            "name": names.get(cid) or (composition_name(mix) if mix else default_name(row)), "renamed": cid in names,
            "event_types": [{"event_type": t, "lines": n, "share": n / total} for t, n in mix[:8]] if mix else None,
            "type_count": len(mix) or None, "pure": len(mix) == 1 if mix else None,
            "rows": _num(row.get("rows"), int), "flagged_rows": _num(row.get("flagged_rows"), int),
            "alert_rate": _num(row.get("alert_rate")), "lift": _num(row.get("lift_vs_view")),
            "first_seen": (row.get("first_seen") or "")[:10], "last_seen": (row.get("last_seen") or "")[:10],
            "first_month_on_map": row.get("first_month_on_map", ""),
            "top": {c.removeprefix("top_"): row[c] for c in TOP_COLUMNS if row.get(c)},
            "comments": counts.get(cid, 0), "verdict": review["verdict"] if review else None,
        })
    return out


@lru_cache(maxsize=8)
def _alerts_by_cluster(source: str, mtime: float) -> dict[str, list[dict]]:
    prefix = SOURCES[source]["prefix"]
    grouped: dict[str, list[dict]] = {}
    for row in _read(DATA / "phase7b_clusters" / source / f"{prefix}_alerts_by_cluster.csv"):
        grouped.setdefault(row["cluster_id"], []).append(row)
    return grouped


def messages(source: str, view: str, cluster_id: str, limit: int = 200) -> dict:
    """The cluster's example lines and the original lines of its flagged observations."""
    row = next((r for r in summary_rows(source, view) if r["cluster_id"] == cluster_id), None)
    if row is None:
        raise KeyError(f"No cluster {cluster_id} in {source}/{view}.")
    examples = [group.split(" | ") for group in (row.get("example_log_lines") or "").split(" || ") if group]
    path = DATA / "phase7b_clusters" / source / f"{SOURCES[source]['prefix']}_alerts_by_cluster.csv"
    flagged = _alerts_by_cluster(source, path.stat().st_mtime if path.exists() else 0.0).get(cluster_id, [])
    return {
        "cluster_id": cluster_id, "rows": _num(row.get("rows"), int),
        "examples": examples,
        "flagged": [{"probability": _num(a.get("rank", a.get("probability"))), "flagged_by": a.get("flagged_by", ""),
                     "row_manifest_id": a.get("row_manifest_id", ""), "lines": a.get("raw_messages", "").split(" | ")}
                    for a in sorted(flagged, key=lambda a: -(_num(a.get("rank", a.get("probability"))) or 0))[:limit]],
        "flagged_total": len(flagged),
    }


def alert_id(raw_messages: str) -> str:
    return hashlib.sha1(raw_messages.encode("utf-8")).hexdigest()[:16]


@lru_cache(maxsize=8)
def _presence_items(source: str, mtime: float) -> list[dict]:
    prefix = SOURCES[source]["prefix"]
    rows = _read(DATA / "phase7_alerts" / source / f"{prefix}_cumulative_presence_alerts.csv")
    items = []
    for rank, row in enumerate(rows, start=1):
        lines = row.get("raw_messages", "").split(" | ")
        items.append({"item_id": alert_id(row.get("raw_messages", "")), "kind": "presence_alert",
                      "view": row.get("dataset", ""), "rank": rank, "probability": _num(row.get("rank", row.get("probability"))),
                      "flagged_by": row.get("flagged_by", ""), "lines": lines[:40], "line_count": len(lines),
                      "row_manifest_ids": row.get("row_manifest_ids", "")})
    return items


def _validation_item(source: str, view: str, g: dict, review: dict | None) -> dict:
    top = {k: v for k, v in (("host_id", g["host"]), ("username", g["username"]), ("source_ip", g["source_ip"])) if v}
    return {"cluster_id": g["gid"], "item_id": g["gid"], "kind": "cluster", "period": "validation", "number": None,
            "name": " · ".join(x for x in (g["host"], g["source_ip"]) if x) or "Unknown server", "renamed": True,
            "rows": g["rows"], "flagged_rows": g["flagged"], "alert_rate": g["alert_rate"], "lift": g["lift"],
            "first_seen": (g["first_t"] or "")[:10], "last_seen": (g["last_t"] or "")[:10], "top": top,
            "view": view, "view_label": VIEWS[view]["label"], "review": review, "verdict": review["verdict"] if review else None}


def _sigma(hit: dict | None) -> list[dict]:
    """A group's Sigma rules, the one flagging most observations first."""
    return [{"title": t, "observations": n} for t, n in sorted((hit or {}).get("rules", {}).items(), key=lambda kv: (-kv[1], kv[0]))]


def review_queue(source: str, view: str = "") -> list[dict]:
    """Anomalous clusters (auth, OSSEC) or presence alerts (PF, IPFilter), with their latest verdict.

    A cluster is anomalous when the models flag it at least ANOMALOUS_LIFT times as often as
    its view overall, in a view used for alerts. Clusters with only a few stray flags are left
    out; those observations remain Phase 7 alerts.

    The test period comes first (Phase 7b clusters). Then the validation period, which Phase 7b
    does not cluster: its flagged observations grouped by server and source address
    (cluster_index), under the same rule and with at least VALIDATION_MIN_FLAGGED flagged.

    A group holding an observation that a Sigma rule flags (sigma_review.py) is listed whatever its
    lift: a known pattern is worth a look on its own. Its rules come with it ('sigma').

    Phase 4g's activity alerts (an unusual amount of activity of the whole log, or of one server, source IP,
    username or destination IP; activity.py) follow the test-period groups, most unusual first.

    Each item says how many of its flagged observations whitelisted accounts cover ('whitelisted'), and
    whether that is all of them ('overridden'): such a group no longer needs review (whitelist.py). An
    activity alert of a username is covered when that account is whitelisted on every server.
    """
    reviews = store.latest_reviews(source)
    out = []
    if SOURCES[source]["method"] == "baseline":
        for v in [view] if view else SOURCES[source]["views"]:
            if not model_status(source, v)["used"]:
                continue
            known = cluster_index.sigma_groups(source, v)          # a Sigma hit is listed whatever the lift
            for c in list_clusters(source, v):
                hit = known.get(c["cluster_id"])
                if hit or ((c["flagged_rows"] or 0) > 0 and (c["lift"] or 0) >= ANOMALOUS_LIFT):
                    r = reviews.get((source, v, c["cluster_id"]))
                    out.append({**c, "item_id": c["cluster_id"], "kind": "cluster", "view": v, "period": "test",
                                "flagged_rows": (c["flagged_rows"] or 0) + (hit["only"] if hit else 0),
                                "sigma": _sigma(hit), "view_label": VIEWS[v]["label"], "review": r})
            for g in cluster_index.validation_groups(source, v):
                hit = known.get(g["gid"])
                if hit or (g["flagged"] >= VALIDATION_MIN_FLAGGED and g["lift"] >= ANOMALOUS_LIFT):
                    out.append({**_validation_item(source, v, g, reviews.get((source, v, g["gid"]))), "sigma": _sigma(hit)})
        out.sort(key=lambda c: (c["period"] != "test", -(c["lift"] or 0), -(c["flagged_rows"] or 0)))
        alerts = [{**item, "review": reviews.get((source, item["view"], item["item_id"]))}     # Phase 4g's incidents, after the test groups
                  for item in activity.incident_items(source)
                  if not view or view in {m["view"] for m in (item.get("incident") or {}).get("members") or [item]}]
        tested = sum(1 for c in out if c["period"] == "test")
        out[tested:tested] = alerts
    else:
        path = DATA / "phase7_alerts" / source / f"{SOURCES[source]['prefix']}_cumulative_presence_alerts.csv"
        for item in _presence_items(source, path.stat().st_mtime if path.exists() else 0.0):
            if view and item["view"] != view:
                continue
            out.append({**item, "view_label": VIEWS.get(item["view"], {}).get("label", item["view"]),
                        "review": reviews.get((source, item["view"], item["item_id"]))})
    return whitelist.mark(source, out)
