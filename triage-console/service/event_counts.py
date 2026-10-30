"""Event counts by source, month and event type: the Sankey chart and rarity.

Counted once from the Phase 1 and Phase 2 outputs and cached in
``var/cache/event_counts.json``; recounted when an input file changes.
"""
from __future__ import annotations

import csv
import json
import sqlite3
import sys
import threading
from collections import Counter, defaultdict

from . import variants
from .config import CACHE, DATA, FROZEN
from .pipeline_code import event_category

CACHE_FILE = CACHE / "event_counts.json"
_lock = threading.Lock()
_memory: dict | None = None


def _inputs() -> dict:
    p1, p2 = DATA / "phase1_classify", DATA / "phase2_observations"
    return {
        "auth": [p1 / "auth" / "authlog_lineage_summary.json"],
        "ossec": [p2 / "ossec" / "ossec_observation_store.sqlite"],
        "pf": sorted((p1 / "pf").glob("classified_pflog_events_????-??.csv")),
        "ipf": sorted((p1 / "ipf").glob("ipflog_events_????-??.csv")),
    }


def _signature(inputs) -> dict:
    return {src: [[p.name, p.stat().st_size, int(p.stat().st_mtime)] for p in paths if p.exists()]
            for src, paths in inputs.items()}


def _count_csv(paths) -> dict:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    months: dict = defaultdict(Counter)
    for path in paths:
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                months[row.get("partition_month") or path.stem[-7:]][row.get("event_type") or "UNKNOWN"] += 1
    return months


def _count() -> dict:
    inputs = _inputs()
    counts = {}
    summary = json.loads(inputs["auth"][0].read_text(encoding="utf-8")) if inputs["auth"][0].exists() else {}
    counts["auth"] = {m["year_month"]: m.get("event_counts", {}) for m in summary.get("monthly_results", [])}
    store = inputs["ossec"][0]
    ossec: dict = defaultdict(dict)
    if store.exists():
        con = sqlite3.connect(f"file:{store}?mode=ro", uri=True)
        for month, event_type, n in con.execute(
                "SELECT partition_month, event_type, COUNT(*) FROM events GROUP BY 1, 2"):
            ossec[month][event_type] = n
        con.close()
    counts["ossec"] = ossec
    counts["pf"] = _count_csv(inputs["pf"])
    counts["ipf"] = _count_csv(inputs["ipf"])
    types = {src: sorted({t for month in by_month.values() for t in month}) for src, by_month in counts.items()}
    categories = {src: {t: event_category(src, t) for t in names} for src, names in types.items()}
    return {"signature": _signature(inputs), "counts": counts, "categories": categories}


def load() -> dict:
    global _memory
    with _lock:
        signature = _signature(_inputs())
        if _memory and _memory["signature"] == signature:
            return _memory
        try:
            cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if cached.get("signature") == json.loads(json.dumps(signature)) or FROZEN:   # frozen: the counts are kept, the inputs are gone
                _memory = cached
                return cached
        except (OSError, ValueError):
            pass
        if FROZEN:
            _memory = {"signature": {}, "counts": {}, "categories": {}}
            return _memory
        _memory = _count()
        CACHE.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(_memory), encoding="utf-8")
        return _memory


def months() -> list[str]:
    data = load()["counts"]
    return sorted({m for by_month in data.values() for m in by_month})


def first_day(source: str) -> str:
    present = sorted(m for m, types in load()["counts"].get(source, {}).items() if sum(types.values()))
    return f"{present[0]}-01" if present else ""


def sankey(sources: list[str], start: str = "", end: str = "") -> dict:
    """Nodes and links: source -> category -> event type, for months in [start, end]."""
    data = load()
    nodes, index, links = [], {}, Counter()
    variant_state = variants.get()
    variant_counts = variant_state["counts"] or {}

    def node(key, label, level, source):
        if key not in index:
            index[key] = len(nodes)
            entry = {"id": key, "label": label, "level": level, "source": source}
            if level == 2:
                entry["variants"] = variant_counts.get(source, {}).get(label)
            nodes.append(entry)
        return index[key]

    totals = Counter()
    for src in sources:
        for month, types in data["counts"].get(src, {}).items():
            if (start and month < start) or (end and month > end):
                continue
            for event_type, n in types.items():
                category = data["categories"].get(src, {}).get(event_type, "other")
                s = node(f"s:{src}", src, 0, src)
                c = node(f"c:{src}:{category}", category, 1, src)
                t = node(f"t:{src}:{event_type}", event_type, 2, src)
                links[(s, c)] += n
                links[(c, t)] += n
                totals[src] += n
    return {"nodes": nodes, "links": [{"source": s, "target": t, "value": v, "kind": nodes[s]["source"]}
                                      for (s, t), v in links.items()],
            "totals": dict(totals), "months": months(),
            "variants_status": variant_state["status"], "variants_progress": variant_state["progress"]}


def history(source: str, event_type: str) -> dict:
    """How often an event type was seen over the whole period."""
    by_month = load()["counts"].get(source, {})
    total = sum(sum(t.values()) for t in by_month.values())
    seen = sum(t.get(event_type, 0) for t in by_month.values())
    months_seen = sum(1 for t in by_month.values() if t.get(event_type))
    return {"count": seen, "share": seen / total if total else 0.0, "months_seen": months_seen,
            "months": len(by_month)}
