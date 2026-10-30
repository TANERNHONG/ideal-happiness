"""Uploads kept for review (Simple mode).

Simple mode runs an upload through Analyze, then keeps it as a review item: its
unusual events, each with the uploaded lines around it (the year's tables do not
hold new logs, so the context comes from the upload itself). Everything stays in
``var/console.sqlite3`` on this laptop; clearing needs the activity-log password.

An unusual event whose accounts are all whitelisted (whitelist.py) is kept but marked: it does not count
as unusual and needs no review. Whether it is covered is decided when the upload is read, so adding or
removing an account applies to uploads already kept.

Sending to a reviewer names who should look at it. Today the name is whatever
that person set in Settings (or typed as an e-mail address); once SSO is set up,
it is their signed-in account. Either way the item shows as *Waiting for you*
for them (decision Q28).
"""
from __future__ import annotations

import json
import re
import statistics
import threading
import time
import uuid
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta

from . import analyze, store, whitelist
from .catalog import SOURCES, VIEWS

MAX_ITEMS = 50                  # unusual events kept per upload, rarest first
MAX_CANDIDATES = 1000           # flagged observations looked at before merging
# Which view speaks for lines flagged in several: a session or episode first (what happened), then the
# line itself, then the windows around it.
VIEW_RANK = {"session": 0, "line": 1, "5min": 2, "1h": 3, "1d": 4}
CONTEXT_MINUTES = 10            # uploaded lines kept before and after each event
MAX_CONTEXT = 200               # lines kept per event
PENDING_SECONDS = 3600          # an analysis not sent for review is forgotten after an hour
WINDOW = {"5min": 300, "1h": 3600, "1d": 86400}
SESSION_SECONDS = 1800          # a session or episode has a start only; its own lines are looked for this far on
TIME_KEYS = ("timestamp", "window_start", "session_start", "episode_start")

_pending: dict[str, dict] = {}
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY, created_at TEXT, created_by TEXT, name TEXT, source TEXT, month TEXT,
    host TEXT, lines INTEGER, recognised INTEGER, summary TEXT, assigned_to TEXT, assigned_by TEXT, assigned_at TEXT);
CREATE TABLE IF NOT EXISTS upload_items (
    upload_id INTEGER, item_id TEXT, view TEXT, rank INTEGER, data TEXT, context TEXT,
    PRIMARY KEY (upload_id, item_id));
"""


def _connect():
    con = store.connect()
    con.executescript(SCHEMA)
    return con


# --- from an analysis to items ------------------------------------------------------------------

def _when(row: dict) -> str:
    return next((row[k] for k in TIME_KEYS if row.get(k)), "")


def _items(result: dict) -> list[dict]:
    """The unusual events of the views used for alerts, rarest first."""
    rows = []
    for block in result["views"]:
        if not block["used"]:
            continue
        for row in block["rows"]:
            if row["flags"]:
                rows.append({"item_id": f"{block['view']}:{row['id']}", "view": block["view"], "view_label": block["label"],
                             "when": _when(row)[:19], "host": row.get("host_id") or row.get("hostname") or result["host"],
                             "event": row.get("event_type") or row.get("first_event_type") or "",
                             "username": row.get("username", ""), "source_ip": row.get("source_ip", ""),
                             "unusual": row.get("unusual"), "flags": row["flags"], "sigma": row.get("sigma", []),
                             "map": row.get("map"),
                             "group": (row.get("map") or {}).get("cluster_id", "")})
    rows.sort(key=lambda r: -(r["unusual"] or 0))
    return rows[:MAX_CANDIDATES]


def _presence_items(result: dict, parsed: list) -> list[dict]:
    """Firewall logs: any traffic is unusual, so one item per server, its first lines as the event."""
    by_host, known_patterns = defaultdict(list), defaultdict(set)
    hits = result.get("sigma_lines") or {}
    for n, (line, event, known) in enumerate(parsed, start=1):
        if known:
            host = event.get("host") or result["host"] or ""
            by_host[host].append((event.get("timestamp", ""), line))
            known_patterns[host].update(hits.get(n, []))
    items = []
    for host, lines in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
        sigma = sorted(known_patterns[host])
        items.append({"item_id": f"presence:{host or 'unknown'}", "view": SOURCES[result["source"]]["views"][0],
                      "view_label": "Firewall activity", "when": str(lines[0][0])[:19], "host": host, "event": "",
                      "unusual": None, "flags": ["presence"] + (["sigma"] if sigma else []), "sigma": sigma,
                      "group": "", "line_count": len(lines),
                      "context": [{"time": str(t)[:19], "line": line, "own": True} for t, line in lines[:MAX_CONTEXT]]})
    return items[:MAX_ITEMS]


def _context(item: dict, events: list) -> list[dict]:
    """The uploaded lines from the same server within CONTEXT_MINUTES of the event; its own lines marked."""
    start = analyze._time(item["when"])
    if start is None:
        return []
    needs = VIEWS[item["view"]]["needs"]
    end = start + timedelta(seconds=WINDOW.get(needs, 0))
    look = start + timedelta(seconds=SESSION_SECONDS) if needs == "session" else end
    lo, hi = start - timedelta(minutes=CONTEXT_MINUTES), max(end, look) + timedelta(minutes=CONTEXT_MINUTES)
    marks = [m for m in (item.get("username"), item.get("source_ip")) if m]
    out = []
    times = [e[0] for e in events] if not isinstance(events, _Events) else events.times
    for at, host, event_type, line in events[bisect_left(times, lo):bisect_right(times, hi)]:
        if item["host"] and host and host != item["host"]:
            continue
        if needs == "line":
            own = at == start and (not item["event"] or event_type == item["event"])
        elif needs == "session":
            own = start <= at <= look and (any(m in line for m in marks) if marks else event_type == item["event"])
        else:
            own = start <= at < end
        out.append({"time": at.isoformat(sep=" "), "line": line, "own": own})
    if len(out) > MAX_CONTEXT:                           # keep the event's own lines in view
        first = next((i for i, x in enumerate(out) if x["own"]), len(out) // 2)
        lo_i = max(0, min(first - MAX_CONTEXT // 4, len(out) - MAX_CONTEXT))
        out = out[lo_i:lo_i + MAX_CONTEXT]
    return out


class _Events(list):
    """The upload's recognised lines in time order, with their times for bisecting."""
    def __init__(self, rows):
        super().__init__(sorted(rows, key=lambda x: x[0]))
        self.times = [x[0] for x in self]


def _merge(items: list[dict]) -> list[dict]:
    """One item per thing that happened: an observation whose own lines overlap one already kept (a
    session, its lines, the 5-minute window around them) is folded into it as "also seen in"."""
    order = sorted(items, key=lambda i: (VIEW_RANK.get(VIEWS[i["view"]]["needs"], 9), -(i["unusual"] or 0)))
    kept, owners = [], {}
    for item in order:
        own = {(c["time"], c["line"]) for c in item.get("context", []) if c["own"]}
        home = next((owners[k] for k in own if k in owners), None)
        if home is None:
            item["also"] = []
            kept.append(item)
            for k in own:
                owners[k] = item
            continue
        if item["view_label"] not in home["also"] and item["view_label"] != home["view_label"]:
            home["also"].append(item["view_label"])
        home["flags"] = sorted(set(home["flags"]) | set(item["flags"]))
        home["sigma"] = sorted(set(home.get("sigma", [])) | set(item.get("sigma", [])))
        if (item["unusual"] or 0) > (home["unusual"] or 0):
            home["unusual"] = item["unusual"]
    kept.sort(key=lambda i: -(i["unusual"] or 0))
    return kept[:MAX_ITEMS]


def _facts(source: str, month: str, item: dict) -> list[dict]:
    """Server, account, program and address of the event's own lines (review_filters.py)."""
    from .review_filters import facts_for_lines
    return facts_for_lines(source, [c["line"] for c in item.get("context", []) if c.get("own")], month, item.get("host", ""))


def _summary(result: dict, items: list[dict]) -> dict:
    allowed = whitelist.active()
    covered = [i for i in items if whitelist.covers(i.get("facts", []), allowed, result.get("source") or "auth")]
    unusual = [i for i in items if i not in covered]
    hosts = sorted({i["host"] for i in unusual if i["host"]})
    rated = [i["unusual"] for i in unusual if i["unusual"] is not None]
    used = [v for v in result["views"] if v["used"] and v["observations"]]
    best = max(used, key=lambda v: (v["flagged"] or 0, v["max_unusual"] or 0), default=None)
    accounts = sorted({f["username"] for i in covered for f in i.get("facts", []) if f.get("username")})
    return {"unusual": len(unusual), "whitelisted": len(covered), "accounts": accounts[:12],
            "flagged": result["verdict"]["flagged"], "hosts": hosts or result["hosts"][:20],
            "rarest": max(rated) if rated else None, "method": result["verdict"]["method"],
            "span": result["span"], "view": best["view"] if best else "", "view_label": best["label"] if best else ""}


def run(text: str = "", source: str = "auto", month: str = "", host: str = "", path: str = "", name: str = "", raw: str = "",
        progress=lambda step, detail: None) -> dict:
    """Analyze, then prepare the upload's items; they are kept only when sent for review (keep()).
    ``raw`` names the raw-line column of a table (service/tabular.py); found by itself when empty."""
    result = analyze.analyze(text=text, source=source, month=month, host=host, path=path, raw=raw, name=name, progress=progress)
    lines, _ = analyze.read_input(text, path, raw)
    parsed = analyze._parse(result["source"], lines, result["month"])
    if result["verdict"]["method"] == "presence":
        items = _presence_items(result, parsed)
    else:
        items = _items(result)
        events = _Events((t, e.get("host") or result["host"], e.get("event_type", ""), line) for line, e, ok in parsed
                         if ok and (t := analyze._time(e.get("timestamp", ""))))
        for item in items:
            item["context"] = _context(item, events)
        items = _merge(items)
    for item in items:
        item["facts"] = _facts(result["source"], result["month"], item)
    token = uuid.uuid4().hex
    with _lock:
        for old in [k for k, v in _pending.items() if time.time() - v["at"] > PENDING_SECONDS]:
            _pending.pop(old)
        _pending[token] = {"at": time.time(), "name": name, "result": result, "items": items}
    result["keep"] = token
    result["summary"] = _summary(result, items)
    return result


# --- kept uploads -------------------------------------------------------------------------------

def keep(token: str, actor: str) -> int:
    with _lock:
        pending = _pending.pop(token, None)
    if pending is None:
        raise KeyError("This analysis has expired. Run it again.")
    result, items = pending["result"], pending["items"]
    summary = _summary(result, items)
    with store._lock, _connect() as con:
        cur = con.execute("INSERT INTO uploads (created_at, created_by, name, source, month, host, lines, recognised, summary) "
                          "VALUES (?,?,?,?,?,?,?,?,?)",
                          (store.now(), actor, pending["name"][:200] or "Pasted lines", result["source"], result["month"],
                           result["host"], result["lines"], result["recognised"], json.dumps(summary)))
        upload_id = cur.lastrowid
        con.executemany("INSERT INTO upload_items VALUES (?,?,?,?,?,?)",
                        [(upload_id, i["item_id"], i["view"], rank, json.dumps({k: v for k, v in i.items() if k != "context"}),
                          json.dumps(i.get("context", []))) for rank, i in enumerate(items)])
        store.audit(con, actor, "upload_kept", f"upload/{upload_id}", {"items": len(items), "lines": result["lines"]})
    return upload_id


def _review_id(upload_id: int, item_id: str) -> str:
    return f"upload-{upload_id}/{item_id}"


def time_to_label() -> dict:
    """Minutes from an upload being kept to the first label on any of its items (the Dashboard's Time to label):
    n uploads labelled, and the median, P10 and P90."""
    with _connect() as con:
        rows = con.execute("SELECT u.created_at, MIN(r.created_at) FROM uploads u JOIN reviews r "
                           "ON r.item_id LIKE 'upload-' || u.id || '/%' GROUP BY u.id").fetchall()
    minutes = sorted(max(0.0, (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds() / 60)
                     for first, last in rows if first and last)
    if not minutes:
        return {"n": 0}
    cuts = statistics.quantiles(minutes, n=10, method="inclusive") if len(minutes) > 1 else [minutes[0]] * 9
    return {"n": len(minutes), "median": statistics.median(minutes), "p10": cuts[0], "p90": cuts[8]}


def _same(a: str, b: str) -> bool:
    return bool(a) and a.strip().lower() == (b or "").strip().lower()


def list_uploads(me: str) -> dict:
    with _connect() as con:
        uploads = [dict(r) for r in con.execute("SELECT * FROM uploads ORDER BY id DESC")]
        keys = defaultdict(list)
        for r in con.execute("SELECT upload_id, item_id, view, data, context FROM upload_items"):
            keys[r["upload_id"]].append((r["view"], r["item_id"], r["data"], r["context"]))
    reviews = store.latest_reviews()
    allowed = whitelist.active()
    for u in uploads:
        u["summary"] = json.loads(u["summary"] or "{}")
        done = covered = 0
        for view, item, data, context in keys[u["id"]]:
            if (u["source"], view, _review_id(u["id"], item)) in reviews:
                done += 1
            elif allowed and whitelist.covers(_item_facts(u, json.loads(data), context), allowed, u["source"]):
                covered += 1
        u.update(items=len(keys[u["id"]]), reviewed=done, whitelisted=covered,
                 waiting=_same(u["assigned_to"], me) and done + covered < len(keys[u["id"]]))
    return {"me": me, "uploads": uploads}


def _item_facts(upload: dict, data: dict, context: str) -> list[dict]:
    """Facts kept with the item, or (uploads kept before they were) read again from its lines."""
    if "facts" in data:
        return data["facts"]
    return _facts(upload["source"], upload.get("month", ""), {**data, "context": json.loads(context or "[]")})


def get_upload(upload_id: int) -> dict:
    with _connect() as con:
        row = con.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone()
        if row is None:
            raise KeyError(f"No upload #{upload_id}.")
        upload = dict(row)
        items = [{**json.loads(r["data"]), "context": json.loads(r["context"])}
                 for r in con.execute("SELECT data, context FROM upload_items WHERE upload_id=? ORDER BY rank", (upload_id,))]
    reviews = store.latest_reviews(upload["source"])
    allowed = whitelist.active()
    for item in items:
        item["review_id"] = _review_id(upload_id, item["item_id"])
        item["review"] = reviews.get((upload["source"], item["view"], item["review_id"]))
        if "facts" not in item:
            item["facts"] = _facts(upload["source"], upload.get("month", ""), item)
        item["whitelisted"] = whitelist.covers(item["facts"], allowed, upload["source"])
    upload["summary"] = json.loads(upload["summary"] or "{}")
    return {**upload, "items": items}


EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def assign(upload_id: int, reviewer: str, actor: str) -> dict:
    reviewer = reviewer.strip()[:120]
    if not reviewer:
        raise ValueError("Name the reviewer.")
    with store._lock, _connect() as con:
        if con.execute("SELECT 1 FROM uploads WHERE id=?", (upload_id,)).fetchone() is None:
            raise KeyError(f"No upload #{upload_id}.")
        con.execute("UPDATE uploads SET assigned_to=?, assigned_by=?, assigned_at=? WHERE id=?",
                    (reviewer, actor, store.now(), upload_id))
        store.audit(con, actor, "send_to_reviewer", f"upload/{upload_id}", {"reviewer": reviewer})
    return {"assigned_to": reviewer, "email": bool(EMAIL.match(reviewer))}


def reviewers() -> list[str]:
    """Names sent to before, most recent first (for the reviewer box)."""
    with _connect() as con:
        rows = con.execute("SELECT assigned_to, MAX(assigned_at) at FROM uploads WHERE assigned_to IS NOT NULL "
                           "GROUP BY lower(assigned_to) ORDER BY at DESC LIMIT 20")
        return [r["assigned_to"] for r in rows]


def clear(upload_id: int, password: str, actor: str) -> None:
    if not store.check_password(password):
        raise PermissionError("Wrong password.")
    with store._lock, _connect() as con:
        con.execute("DELETE FROM upload_items WHERE upload_id=?", (upload_id,))
        gone = con.execute("DELETE FROM uploads WHERE id=?", (upload_id,)).rowcount
        if not gone:
            raise KeyError(f"No upload #{upload_id}.")
        store.audit(con, actor, "upload_cleared", f"upload/{upload_id}", {})
