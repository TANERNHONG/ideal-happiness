"""Traffic by address: where lines come from and where they go, per month.

Counted once in the background with each full address (SQL in the stores for
auth and OSSEC, the Phase 1 CSVs for the firewalls), cached in
``var/cache/ip_flows.json``. The chart groups addresses when it is drawn, at
one of four levels: ``a.x.x.x``, ``a.b.x.x``, ``a.b.c.x`` (the default) or the
full ``a.b.c.d``. IPv6 addresses are grouped by their first one, two or three
groups, or kept whole. Lines without an address are left out.

* auth: source address -> server
* OSSEC: agent (or source address) -> manager address (or agent)
* PF, IPFilter: source address -> destination address

``selection_query`` writes the read-only SQL that returns the lines behind a box
or band of the chart, for Data -> SQL or a CSV download.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
import sqlite3
import sys
import threading
from collections import Counter

from .config import CACHE, DATA, FROZEN

CACHE_FILE = CACHE / "ip_flows.json"
CACHE_VERSION = 2                     # 2: full addresses (grouped when drawn); 1 held a.b.c.x only
LEVELS = (1, 2, 3, 4)                 # parts of the address kept: a.x.x.x, a.b.x.x, a.b.c.x, a.b.c.d
OTHER_A, OTHER_B = "other addresses", "other destinations"
_state = {"status": "idle", "progress": "", "flows": None}
_lock = threading.Lock()


def address(value: str) -> str:
    """The address as written in the log when it is one, else ''."""
    value = (value or "").strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return ""
    return value


def group(value: str, level: int = 3) -> str:
    """An address grouped at a level (1-4); anything that is not an address (a server name) as it is."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value
    if level >= 4:
        return value
    if ip.version == 4:
        return ".".join(value.split(".")[:level] + ["x"] * (4 - level))
    return ":".join(ip.exploded.split(":")[:level]) + f"::/{16 * level}"


def _inputs():
    p1, p2 = DATA / "phase1_classify", DATA / "phase2_observations"
    return {
        "auth": [p2 / "auth" / "authlog_observation_store.sqlite"],
        "ossec": [p2 / "ossec" / "ossec_observation_store.sqlite"],
        "pf": sorted((p1 / "pf").glob("classified_pflog_events_????-??.csv")),
        "ipf": sorted((p1 / "ipf").glob("ipflog_events_????-??.csv")),
    }


def _stamp():
    stamp = {s: [[p.name, p.stat().st_size, int(p.stat().st_mtime)] for p in ps if p.exists()] for s, ps in _inputs().items()}
    return {"version": CACHE_VERSION, **stamp}


def _count(progress) -> list:
    flows = Counter()
    inputs = _inputs()
    for source in ("ossec", "pf", "ipf", "auth"):            # small ones first
        progress(f"{source}: counting")
        for path in inputs[source]:
            if not path.exists():
                continue
            if source == "auth":
                con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
                for month, ip, host, n in con.execute(
                        "SELECT partition_month, source_ip, host_id, COUNT(*) FROM events "
                        "WHERE source_ip IS NOT NULL AND source_ip <> '' GROUP BY 1, 2, 3"):
                    origin = address(ip)
                    if origin:
                        flows[(month, source, origin, host)] += n
                con.close()
            elif source == "ossec":
                con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
                for month, src, dst, host, n in con.execute(
                        "SELECT partition_month, source_ip, destination_ip, hostname, COUNT(*) FROM events "
                        "WHERE COALESCE(source_ip, '') <> '' OR COALESCE(destination_ip, '') <> '' GROUP BY 1, 2, 3, 4"):
                    origin = address(src) or host or "unknown"
                    target = address(dst) or host or "unknown"
                    flows[(month, source, origin, target)] += n
                con.close()
            else:
                csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
                with path.open(encoding="utf-8", newline="") as handle:
                    for row in csv.DictReader(handle):
                        origin, target = address(row.get("source_ip")), address(row.get("destination_ip"))
                        if origin and target:
                            flows[(row.get("partition_month") or path.stem[-7:], source, origin, target)] += 1
        progress(f"{source}: done")
    return [[*key, n] for key, n in flows.items()]


def start_background() -> None:
    def run():
        stamp = json.loads(json.dumps(_stamp()))
        try:
            cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if cached.get("stamp") == stamp or FROZEN:      # frozen: kept as counted, the inputs are gone
                with _lock:
                    _state.update(status="ready", flows=cached["flows"])
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
            flows = _count(lambda text: _state.__setitem__("progress", text))
            CACHE.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps({"stamp": stamp, "flows": flows}), encoding="utf-8")
            with _lock:
                _state.update(status="ready", flows=flows)
        except Exception as error:
            with _lock:
                _state.update(status="failed", progress=str(error))

    threading.Thread(target=run, daemon=True, name="ip-flows").start()


def _grouped(sources: list[str], start: str, end: str, level: int, top: int):
    """The cached flows in range, grouped; and the groups kept on each side (the rest are 'other')."""
    with _lock:
        status, progress, flows = _state["status"], _state["progress"], _state["flows"] or []
    rows = [(src, a, b, group(a, level), group(b, level), n) for month, src, a, b, n in flows
            if src in sources and (not start or month >= start) and (not end or month <= end)]
    origins, targets = Counter(), Counter()
    for src, _, _, ga, gb, n in rows:
        origins[ga] += n
        targets[gb] += n
    keep_a = {a for a, _ in origins.most_common(top)}
    keep_b = {b for b, _ in targets.most_common(top)}
    return rows, keep_a, keep_b, status, progress


def sankey(sources: list[str], start: str = "", end: str = "", top: int = 25, level: int = 3) -> dict:
    """Nodes and links: origin -> log type -> destination; the smaller ends merged into 'other'."""
    rows, keep_a, keep_b, status, progress = _grouped(sources, start, end, level, top)
    nodes, index, links, totals, paths = [], {}, Counter(), Counter(), Counter()

    def node(key, label, level_, kind):
        if key not in index:
            index[key] = len(nodes)
            nodes.append({"id": key, "label": label, "level": level_, "source": kind})
        return index[key]

    for src, _, _, a, b, n in rows:
        a = a if a in keep_a else OTHER_A
        b = b if b in keep_b else OTHER_B
        i = node(f"a:{a}", a, 0, src)
        j = node(f"s:{src}", src, 1, src)
        k = node(f"b:{b}", b, 2, src)
        links[(i, j, src)] += n
        links[(j, k, src)] += n
        paths[(i, j, k)] += n
        totals[src] += n
    return {"nodes": nodes, "links": [{"source": i, "target": j, "value": v, "kind": s} for (i, j, s), v in links.items()],
            "paths": [[i, j, k, n] for (i, j, k), n in paths.items()],     # whole from -> log -> to routes, for highlighting
            "totals": dict(totals), "status": status, "progress": progress, "level": level}


# --- the lines behind a selection, as SQL ---------------------------------------------------------

def _quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _ip_match(column: str, label: str, members: set[str]) -> str:
    """An address group as a condition: a range for IPv4 prefixes (the stores can use an index), the
    address itself when whole, and the addresses seen in it otherwise (IPv6 groups)."""
    parts = label.split(".")
    if len(parts) == 4 and parts[-1] == "x":
        prefix = ".".join(p for p in parts if p != "x") + "."
        return f"({column} >= {_quote(prefix)} AND {column} < {_quote(prefix[:-1] + '/')})"
    if label in members or len(parts) == 4:
        return f"{column} = {_quote(label)}"
    return f"{column} IN ({', '.join(_quote(m) for m in sorted(members))})" if members else "0"


IPV4_GROUP = re.compile(r"^\d{1,3}(\.(\d{1,3}|x)){3}$")


def _is_ip_group(label: str, members: set[str]) -> bool:
    return bool(IPV4_GROUP.match(label)) or "::/" in label or any(address(m) for m in members)


# per log type: the table, the columns behind each end, and what every row returns
TABLES = {
    "auth": {"table": "auth.events", "a": ("source_ip", None), "b": (None, "host_id"), "time": "epoch",
             "select": "'auth' AS log, timestamp_text AS time, host_id AS server, event_type, source_ip, '' AS destination_ip, original_log_line AS line",
             "base": "COALESCE(source_ip, '') <> ''"},
    "ossec": {"table": "ossec.events", "a": ("source_ip", "hostname"), "b": ("destination_ip", "hostname"), "time": "epoch",
              "select": "'ossec' AS log, timestamp_text AS time, host_id AS server, event_type, source_ip, destination_ip, original_log_line AS line",
              "base": "(COALESCE(source_ip, '') <> '' OR COALESCE(destination_ip, '') <> '')"},
    "pf": {"table": "fw.pf_events", "a": ("source_ip", None), "b": ("destination_ip", None), "time": "month",
           "select": "'pf' AS log, substr(timestamp, 1, 19) AS time, '' AS server, event_type, source_ip, destination_ip, raw_message AS line",
           "base": "source_ip <> '' AND destination_ip <> ''"},
    "ipf": {"table": "fw.ipf_events", "a": ("source_ip", None), "b": ("destination_ip", None), "time": "month",
            "select": "'ipf' AS log, substr(timestamp, 1, 19) AS time, hostname AS server, event_type, source_ip, destination_ip, raw_message AS line",
            "base": "source_ip <> '' AND destination_ip <> ''"},
}


def _end_match(source: str, side: str, label: str, members: set[str]) -> str:
    """One end of a flow (a group label) as a condition on this log type's table."""
    ip_column, name_column = TABLES[source][side]
    if ip_column and _is_ip_group(label, members):
        return _ip_match(ip_column, label, members)
    if not name_column:
        return "0"
    blank = f"COALESCE({ip_column}, '') = ''" if ip_column else "1"
    if label == "unknown":
        return f"({blank} AND COALESCE({name_column}, '') = '')"
    return f"({blank} AND {name_column} = {_quote(label)})" if ip_column else f"{name_column} = {_quote(label)}"


def _next_month(month: str) -> str:
    year, m = int(month[:4]), int(month[5:7])
    return f"{year + m // 12}-{m % 12 + 1:02d}"


def selection_query(sources: list[str], start: str = "", end: str = "", top: int = 25, level: int = 3,
                    a: str = "", source: str = "", b: str = "") -> str:
    """The SQL for the lines behind a box (a, source or b) or a band (a and source, or source and b)."""
    rows, keep_a, keep_b, _, _ = _grouped(sources, start, end, level, top)
    members = {"a": {}, "b": {}}
    for src, ra, rb, ga, gb, _ in rows:
        members["a"].setdefault(ga, set()).add(ra)
        members["b"].setdefault(gb, set()).add(rb)
    chosen = [s for s in sources if s in TABLES and (not source or s == source)]
    if not chosen or not (a or source or b):
        raise ValueError("Pick a box or a band on the chart first.")
    parts = []
    for src in chosen:
        spec = TABLES[src]
        where = [spec["base"]]
        for side, label, keep in (("a", a, keep_a), ("b", b, keep_b)):
            if not label:
                continue
            if label in (OTHER_A, OTHER_B):                    # every group not drawn on its own
                kept = [_end_match(src, side, k, members[side].get(k, set())) for k in sorted(keep)]
                kept = [k for k in kept if k != "0"]
                if kept:
                    # NULL-safe: a line with no address at that end matches none of the kept groups
                    where.append("NOT COALESCE(" + "\n       OR ".join(kept) + ", 0)")
            else:
                where.append(_end_match(src, side, label, members[side].get(label, set())))
        if spec["time"] == "epoch":
            if start:
                where.append(f"timestamp_epoch >= strftime('%s', {_quote(start + '-01')})")
            if end:
                where.append(f"timestamp_epoch < strftime('%s', {_quote(_next_month(end) + '-01')})")
        else:
            if start:
                where.append(f"partition_month >= {_quote(start)}")
            if end:
                where.append(f"partition_month <= {_quote(end)}")
        if "0" in where:
            continue                                           # this log type has nothing at that end
        parts.append(f"SELECT {spec['select']}\n  FROM {spec['table']}\n WHERE " + "\n   AND ".join(where))
    if not parts:
        raise ValueError("No log has lines for this selection.")
    title = " → ".join(x for x in (a, source, b) if x)
    comment = f"Traffic by address: {title}" + (f" ({start or 'start'} to {end or 'end'})" if start or end else "")
    return f"-- {' '.join(comment.split())}\n" + "\nUNION ALL\n".join(parts)        # one line: nothing in it can start SQL
