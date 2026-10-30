"""Whitelisted users: accounts an administrator vouches for, as an override on the anomalies.

The models still score everything and nothing is deleted. An observation is *covered* when every account
it names is whitelisted, on its server or on every server; a covered observation stops asking for
attention: it leaves Review's *Needs review* list and the Dashboard's count, it does not make an upload or
an analysis *Unusual*, and it is shown under *Whitelisted* instead. An observation that names no account,
or names another account as well, is never covered: a whitelist cannot hide what it does not name.

A group of the year's flagged observations is whitelisted when all of them are covered; the accounts of
each observation come from Review's facts table (review_filters.py), so the match is exact, not by the
group's top three values. Uploads use the facts of their own lines; Analyze uses each observation's
account.

Never silenced: a whitelisted account is the one an intruder wants, so some of its observations still ask for
review whatever the whitelist says (sentinel()):

* a source address the account never used on a training day (Phase 4h's pairs);
* a server the account never logged on to on a training day;
* a switch to root (su, sudo, pfexec), unless the entry includes privilege switches (its ``privileged`` flag);
* an activity alert (Phase 4g) on the account: unusual amounts or timing against its own normal.

Without Phase 4h's output for the log type there is no training baseline, and the first two are not applied.

Each entry has a reason, who added it and when, and optionally a server and a last day (after which it
no longer applies). Adding or removing one needs the admin password (the activity log's) and is written to
the activity log; a removed entry is kept, marked removed.
"""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import date
from functools import lru_cache

from . import activity, cluster_index, profiles, store
from .catalog import SOURCES

ACCOUNT = re.compile(r"^[A-Za-z0-9._@$-]{1,64}$")
SERVER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_REASON = 300
PRIVILEGED = frozenset({"su", "sudo", "pfexec"})     # programs that switch to root
SCHEMA = """
CREATE TABLE IF NOT EXISTS whitelist_users (
    id INTEGER PRIMARY KEY, username TEXT, host TEXT, reason TEXT, until TEXT,
    added_by TEXT, added_at TEXT, removed_by TEXT, removed_at TEXT, privileged INTEGER DEFAULT 0);
"""


def _connect():
    con = store.connect()
    con.executescript(SCHEMA)
    if "privileged" not in {r["name"] for r in con.execute("PRAGMA table_info(whitelist_users)")}:
        con.execute("ALTER TABLE whitelist_users ADD COLUMN privileged INTEGER DEFAULT 0")      # entries before 2026-10-30
    return con


class Allowed(frozenset):
    """(account, server) pairs in force (server '' = every server); .privileged: those whose entry includes su."""
    privileged: frozenset = frozenset()


def entries() -> list[dict]:
    """The entries in force or expired (not removed), with how many of the year's flagged observations name each."""
    today = date.today().isoformat()
    with _connect() as con:
        rows = [dict(r) for r in con.execute(
            "SELECT id, username, host, reason, until, added_by, added_at, privileged FROM whitelist_users "
            "WHERE removed_at IS NULL ORDER BY lower(username), host")]
    named = _named()
    for r in rows:
        r["expired"] = bool(r["until"]) and r["until"] < today
        r["flagged"] = named.get((r["username"], r["host"])) if named is not None else None
    return rows


def active() -> Allowed:
    """(account, server) pairs in force; server '' means every server."""
    today = date.today().isoformat()
    with _connect() as con:
        rows = con.execute("SELECT username, host, privileged FROM whitelist_users WHERE removed_at IS NULL "
                           "AND (until = '' OR until >= ?)", (today,)).fetchall()
    allowed = Allowed((r["username"], r["host"]) for r in rows)
    allowed.privileged = frozenset((r["username"], r["host"]) for r in rows if r["privileged"])
    return allowed


def add(username: str, host: str, reason: str, until: str, password: str, actor: str, privileged: bool = False) -> dict:
    username, host, reason, until = (str(x or "").strip() for x in (username, host, reason, until))
    host = host.lower()
    if not ACCOUNT.fullmatch(username):
        raise ValueError("Name one account: letters, digits and . _ - @ $ only.")
    if host and not SERVER.fullmatch(host):
        raise ValueError("A server name has letters, digits and . _ - only.")
    if not reason:
        raise ValueError("Say why this account is whitelisted.")
    if until:
        try:
            last = date.fromisoformat(until)
        except ValueError:
            raise ValueError("The last day must be a date (YYYY-MM-DD).") from None
        if last < date.today():
            raise ValueError("The last day is already past.")
    if not store.check_password(password):
        raise PermissionError("Wrong password.")
    with store._lock, _connect() as con:
        if con.execute("SELECT 1 FROM whitelist_users WHERE removed_at IS NULL AND username=? AND host=?", (username, host)).fetchone():
            raise ValueError(f"{username} is already whitelisted{' on ' + host if host else ''}.")
        cur = con.execute("INSERT INTO whitelist_users (username, host, reason, until, added_by, added_at, privileged) "
                          "VALUES (?,?,?,?,?,?,?)", (username, host, reason[:MAX_REASON], until, actor, store.now(), int(bool(privileged))))
        store.audit(con, actor, "whitelist_add", f"whitelist/{username}",
                    {"server": host or "all", "until": until or "none", "reason": reason[:MAX_REASON], "su": bool(privileged)})
        entry_id = cur.lastrowid
    _cover_cached.cache_clear()
    return next(e for e in entries() if e["id"] == entry_id)


def remove(entry_id: int, password: str, actor: str) -> None:
    if not store.check_password(password):
        raise PermissionError("Wrong password.")
    with store._lock, _connect() as con:
        row = con.execute("SELECT username, host FROM whitelist_users WHERE id=? AND removed_at IS NULL", (entry_id,)).fetchone()
        if row is None:
            raise KeyError("No such whitelisted account.")
        con.execute("UPDATE whitelist_users SET removed_by=?, removed_at=? WHERE id=?", (actor, store.now(), entry_id))
        store.audit(con, actor, "whitelist_remove", f"whitelist/{row['username']}", {"server": row["host"] or "all"})
    _cover_cached.cache_clear()


# --- matching ------------------------------------------------------------------------------------

def _allowed(user: str, host: str, allowed: frozenset) -> bool:
    return (user, "") in allowed or bool(host) and (user, host.lower()) in allowed


def usual(source: str) -> dict[str, frozenset] | None:
    """Per account, the (kind, value) source addresses and servers it shared lines with on training days (Phase 4h);
    None without Phase 4h's output for this log type."""
    file = profiles.path(source) if source in SOURCES else None
    return _usual(source, activity._stamp(file)) if file is not None and file.is_file() else None


@lru_cache(maxsize=8)
def _usual(source: str, stamp: tuple) -> dict[str, frozenset]:
    with closing(profiles._connect(source)) as con:
        row = con.execute("SELECT value FROM meta WHERE key = 'train_end_day'").fetchone()
        train_end = json.loads(row[0]) if row else None
        if train_end is None:
            return {}
        found: dict[str, set] = {}
        for account, kind, value in con.execute(
                "SELECT u.entity, o.entity_type, o.entity FROM pairs p JOIN entities u ON u.id = p.id "
                "JOIN entities o ON o.id = p.other WHERE u.entity_type = 'username' "
                "AND o.entity_type IN ('source_ip', 'server') AND p.day < ?", (train_end,)):
            found.setdefault(account, set()).add((kind, str(value).lower()))
    return {account: frozenset(pairs) for account, pairs in found.items()}


def sentinel(fact: dict, allowed: frozenset, known: dict | None) -> bool:
    """True when this fact of a whitelisted account still asks for review (the module's *Never silenced*): a switch to
    root its entry does not include, or an address or server new to the account since training."""
    user, host = fact.get("username") or "", (fact.get("host") or "").lower()
    if (fact.get("program") or "").lower() in PRIVILEGED:
        privileged = getattr(allowed, "privileged", frozenset())
        if not ((user, "") in privileged or (host and (user, host) in privileged)):
            return True
    baseline = known.get(user) if known else None
    if baseline:
        address = (fact.get("address") or "").lower()
        if address and ("source_ip", address) not in baseline:
            return True
        if host and ("server", host) not in baseline:
            return True
    return False


def covers(facts: list[dict], allowed: frozenset | None = None, source: str = "auth") -> bool:
    """Every account named in these facts ({'username', 'host', 'program', 'address'}) is whitelisted, at least one is
    named, and none of them is a sentinel()."""
    allowed = active() if allowed is None else allowed
    named = [f for f in facts if f.get("username")]
    if not (allowed and named and all(_allowed(f["username"], f.get("host") or "", allowed) for f in named)):
        return False
    known = usual(source)
    return not any(sentinel(f, allowed, known) for f in named)


def covers_row(row: dict, host: str = "", allowed: frozenset | None = None, source: str = "auth") -> bool:
    """An analysed observation (scoring.py): its account, on its server, with its program and source address."""
    return covers([{"username": row.get("username") or "", "host": row.get("host_id") or row.get("hostname") or host,
                    "program": row.get("process_name") or row.get("program") or "", "address": row.get("source_ip") or ""}],
                  allowed, source)


# --- the year's flagged groups (Review) ------------------------------------------------------------

def _index_stamp() -> tuple:
    path = cluster_index.INDEX_FILE
    try:
        stat = path.stat()
    except OSError:
        return (str(path), 0, 0)
    return (str(path), stat.st_size, stat.st_mtime_ns)


def _has_facts(con) -> bool:
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='review_facts'").fetchone() is not None


COVERED = """EXISTS (SELECT 1 FROM review_facts f WHERE f.view_key=m.view_key AND f.row_id=m.row_id AND f.username<>'')
 AND NOT EXISTS (SELECT 1 FROM review_facts f WHERE f.view_key=m.view_key AND f.row_id=m.row_id AND f.username<>''
   AND NOT EXISTS (SELECT 1 FROM w WHERE w.username=f.username AND (w.host='' OR w.host=lower(f.host))))"""


def _cover(source: str, allowed: frozenset, stamp: tuple) -> tuple[dict, dict]:
    file = profiles.path(source) if source in SOURCES else None
    usual_stamp = activity._stamp(file) if file is not None and file.is_file() else None
    return _cover_cached(source, allowed, getattr(allowed, "privileged", frozenset()), stamp, usual_stamp)


@lru_cache(maxsize=16)
def _cover_cached(source: str, allowed: frozenset, privileged: frozenset, stamp: tuple, usual_stamp) -> tuple[dict, dict]:
    """({(view, group): (flagged, covered)}, {view: covered row ids}) for one log type."""
    groups, rows = {}, {}
    if not allowed or SOURCES[source]["method"] != "baseline" or not cluster_index.INDEX_FILE.exists():
        return groups, rows
    allowed = Allowed(allowed)
    allowed.privileged = privileged
    known = usual(source)
    values = ",".join("(?,?)" for _ in allowed)
    params = [x for pair in sorted(allowed) for x in pair]
    with closing(cluster_index._connect()) as con:
        if not _has_facts(con):
            return groups, rows
        for view in SOURCES[source]["views"]:
            key = f"{source}/{view}"
            found = con.execute(f"WITH w(username, host) AS (VALUES {values}) "
                                f"SELECT m.cluster, m.row_id, {COVERED} FROM members m WHERE m.view_key=? AND (m.flagged=1 OR m.sigma=1)",
                                [*params, key]).fetchall()
            candidates = {row_id for _, row_id, ok in found if ok}
            loud = {row_id for row_id, user, host, program, address in con.execute(
                        "SELECT f.row_id, f.username, f.host, f.program, f.address FROM review_facts f JOIN members m "
                        "ON m.view_key = f.view_key AND m.row_id = f.row_id WHERE m.view_key = ? "
                        "AND (m.flagged = 1 OR m.sigma = 1) AND f.username <> ''", (key,))
                    if row_id in candidates and sentinel({"username": user, "host": host, "program": program, "address": address},
                                                         allowed, known)} if candidates else set()
            counts: dict[str, list[int]] = {}
            covered = set()
            for cluster, row_id, ok in found:
                ok = ok and row_id not in loud
                c = counts.setdefault(cluster, [0, 0])
                c[0] += 1
                if ok:
                    c[1] += 1
                    covered.add(row_id)
            groups.update({(view, cluster): (n, k) for cluster, (n, k) in counts.items() if k})
            rows[view] = frozenset(covered)
    return groups, rows


def coverage(source: str) -> dict[tuple[str, str], tuple[int, int]]:
    """For the year's flagged groups: (flagged observations, of which whitelisted), where any are whitelisted."""
    try:
        return _cover(source, active(), _index_stamp())[0]
    except sqlite3.Error:
        return {}


def row_ids(source: str, view: str) -> frozenset[str]:
    try:
        return _cover(source, active(), _index_stamp())[1].get(view, frozenset())
    except sqlite3.Error:
        return frozenset()


def mark(source: str, items: list[dict]) -> list[dict]:
    """Review's queue items with 'whitelisted' (flagged observations covered) and 'overridden' (all of them)."""
    cover = coverage(source)
    for item in items:
        if item.get("kind") == "activity_alert":          # Phase 4g: never silenced (the module docstring)
            flagged, covered = 1, 0
        else:
            flagged, covered = cover.get((item.get("view", ""), item.get("item_id", "")), (0, 0)) if item.get("kind") == "cluster" else (0, 0)
        item["whitelisted"] = covered
        item["overridden"] = bool(covered) and covered >= flagged
    return items


def _named() -> dict[tuple[str, str], int] | None:
    """How many of the year's flagged observations name each whitelisted (account, server); None without the facts."""
    try:
        with _connect() as con:
            pairs = [(r["username"], r["host"]) for r in con.execute("SELECT DISTINCT username, host FROM whitelist_users WHERE removed_at IS NULL")]
        if not pairs:
            return {}
        if not cluster_index.INDEX_FILE.exists():
            return None
        with closing(cluster_index._connect()) as con:
            if not _has_facts(con):
                return None
            return {(u, h): con.execute("SELECT COUNT(*) FROM (SELECT DISTINCT view_key, row_id FROM review_facts "
                                        "WHERE username=? AND (?='' OR lower(host)=?))", (u, h, h)).fetchone()[0]
                    for u, h in pairs}
    except sqlite3.Error:
        return None
