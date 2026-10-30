"""The console's own SQLite store: cluster names, comments, reviews, audit log.

Names, comments and reviews are kept indefinitely (decision Q8). The activity (audit) log is one hash chain: each
entry carries the hash of the one before, so an edit, a deletion or a reordering made outside the application breaks
it, and verify_audit() says where. Clearing it with the admin password (Q14) archives it instead: the entries move,
hashes and all, to var/audit_archive/, and the next entry continues the chain from the last archived one. Every
exported report carries the chain's latest hash (audit_head), so copies outside the console pin what the log held.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

from .config import STORE_FILE, VAR

ADMIN_FILE = VAR / "admin.json"
DEFAULT_PASSWORD = "123456"
SQL_PASSWORD_FILE = VAR / "sql_password.json"   # running SQL queries (sql_lock.py)
DEFAULT_SQL_PASSWORD = "1234"
PBKDF2_ROUNDS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS cluster_names (
    source TEXT, view TEXT, cluster_id TEXT, name TEXT, updated_at TEXT, updated_by TEXT,
    PRIMARY KEY (source, view, cluster_id));
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY, source TEXT, view TEXT, cluster_id TEXT,
    author TEXT, body TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS comments_cluster ON comments (source, view, cluster_id);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY, source TEXT, view TEXT, item_id TEXT, item_kind TEXT,
    verdict TEXT, note TEXT, reviewer TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS reviews_item ON reviews (source, view, item_id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, at TEXT, actor TEXT, action TEXT, object TEXT,
    detail TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS audit_meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS usage (
    day TEXT, event TEXT, n INTEGER, PRIMARY KEY (day, event)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dashboard_results (
    widget TEXT PRIMARY KEY, query TEXT, result TEXT, refreshed_at TEXT, refreshed_by TEXT);
CREATE TABLE IF NOT EXISTS watchlist (
    source TEXT, entity_type TEXT, entity TEXT, added_by TEXT, added_at TEXT,
    PRIMARY KEY (source, entity_type, entity)) WITHOUT ROWID;
"""
# Review labels, most serious first. Four match the triage categories of Phases 8 and 9; Suspicious
# sits between Security relevant and the rest, for what needs a closer look.
VERDICTS = ("security_relevant", "suspicious", "operationally_interesting", "expected_behavior", "insufficient_evidence")
NOTE_NEEDED = {
    "security_relevant": "Say what you found when marking something security relevant.",
    "suspicious": "Say what should be checked next when marking something suspicious.",
    "insufficient_evidence": "Say what is missing when the evidence is insufficient.",
}
_lock = threading.Lock()
_usage_seeded = False


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class _Connection(sqlite3.Connection):
    """A transaction context also releases its handle (important on Windows)."""
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect() -> sqlite3.Connection:
    global _usage_seeded
    VAR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(STORE_FILE, timeout=10, factory=_Connection)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    if not _usage_seeded:                      # first run with usage counts: start them from the activity log
        _usage_seeded = True
        if not con.execute("SELECT 1 FROM usage LIMIT 1").fetchone():
            con.execute("INSERT OR IGNORE INTO usage SELECT substr(at, 1, 10), action, COUNT(*) FROM audit GROUP BY 1, 2")
            con.commit()
    return con


# --- usage counts ------------------------------------------------------------------
# Daily counts per kind of action (and page views), for the Dashboard. Only counts:
# no names, no content. Clearing the activity log does not reset them.

def bump(con, event: str) -> None:
    con.execute("INSERT INTO usage VALUES (date('now', 'localtime'), ?, 1) "
                "ON CONFLICT (day, event) DO UPDATE SET n = n + 1", (event,))


def record_usage(event: str) -> None:
    with _lock, connect() as con:
        bump(con, event)


def usage_summary(days: int = 30) -> dict:
    with connect() as con:
        recent = [dict(r) for r in con.execute(
            "SELECT day, event, n FROM usage WHERE day >= date('now', 'localtime', ?) ORDER BY day",
            (f"-{days - 1} days",))]
        total = {r["event"]: r["n"] for r in con.execute("SELECT event, SUM(n) AS n FROM usage GROUP BY event")}
        first = con.execute("SELECT MIN(day) FROM usage").fetchone()[0]
    return {"days": days, "recent": recent, "all_time": total, "since": first}


AUDIT_FIELDS = ("at", "actor", "action", "object", "detail")


def _entry_hash(prev_hash: str, entry) -> str:
    return hashlib.sha256("|".join((prev_hash, *(entry[k] for k in AUDIT_FIELDS))).encode()).hexdigest()


def _chain_head(con) -> str:
    """The hash the next entry follows: the last entry's, or after an archive the last archived one's."""
    row = con.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        return row["hash"]
    row = con.execute("SELECT value FROM audit_meta WHERE key = 'archived_head'").fetchone()
    return row["value"] if row else ""


def audit(con, actor: str, action: str, obj: str, detail: dict) -> None:
    prev_hash = _chain_head(con)
    at, text = now(), json.dumps(detail, sort_keys=True)
    digest = _entry_hash(prev_hash, {"at": at, "actor": actor, "action": action, "object": obj, "detail": text})
    con.execute("INSERT INTO audit (at, actor, action, object, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (at, actor, action, obj, text, prev_hash, digest))
    bump(con, action)


def cluster_names(source: str, view: str) -> dict[str, str]:
    with connect() as con:
        rows = con.execute("SELECT cluster_id, name FROM cluster_names WHERE source=? AND view=?", (source, view))
        return {r["cluster_id"]: r["name"] for r in rows}


def rename_cluster(source, view, cluster_id, name, actor) -> None:
    name = name.strip()[:120]
    with _lock, connect() as con:
        old = con.execute("SELECT name FROM cluster_names WHERE source=? AND view=? AND cluster_id=?",
                          (source, view, cluster_id)).fetchone()
        con.execute("INSERT OR REPLACE INTO cluster_names VALUES (?,?,?,?,?,?)",
                    (source, view, cluster_id, name, now(), actor))
        audit(con, actor, "rename_cluster", f"{source}/{cluster_id}", {"old": old["name"] if old else "", "new": name})


def comments(source, view, cluster_id) -> list[dict]:
    with connect() as con:
        rows = con.execute("SELECT id, author, body, created_at FROM comments WHERE source=? AND view=? AND cluster_id=? "
                           "ORDER BY id", (source, view, cluster_id))
        return [dict(r) for r in rows]


def comment_counts(source, view) -> dict[str, int]:
    with connect() as con:
        rows = con.execute("SELECT cluster_id, COUNT(*) n FROM comments WHERE source=? AND view=? GROUP BY cluster_id",
                           (source, view))
        return {r["cluster_id"]: r["n"] for r in rows}


def add_comment(source, view, cluster_id, author, body) -> dict:
    body = body.strip()
    if not body:
        raise ValueError("A comment cannot be empty.")
    with _lock, connect() as con:
        cur = con.execute("INSERT INTO comments (source, view, cluster_id, author, body, created_at) VALUES (?,?,?,?,?,?)",
                          (source, view, cluster_id, author.strip()[:60] or "local-user", body[:5000], now()))
        audit(con, author, "comment", f"{source}/{cluster_id}", {"comment_id": cur.lastrowid})
        return dict(con.execute("SELECT id, author, body, created_at FROM comments WHERE id=?", (cur.lastrowid,)).fetchone())


def latest_reviews(source=None) -> dict[tuple, dict]:
    query = ("SELECT r.* FROM reviews r JOIN (SELECT MAX(id) id FROM reviews GROUP BY source, view, item_id) m "
             "ON r.id = m.id")
    with connect() as con:
        rows = [dict(r) for r in con.execute(query)]
    return {(r["source"], r["view"], r["item_id"]): r for r in rows if source in (None, r["source"])}


def add_review(source, view, item_id, item_kind, verdict, note, reviewer) -> dict:
    if verdict not in VERDICTS:
        raise ValueError(f"Verdict must be one of {', '.join(VERDICTS)}.")
    if verdict in NOTE_NEEDED and not note.strip():
        raise ValueError(NOTE_NEEDED[verdict])
    with _lock, connect() as con:
        cur = con.execute("INSERT INTO reviews (source, view, item_id, item_kind, verdict, note, reviewer, created_at) "
                          "VALUES (?,?,?,?,?,?,?,?)",
                          (source, view, item_id, item_kind, verdict, note.strip()[:5000], reviewer, now()))
        audit(con, reviewer, "review", f"{source}/{view}/{item_id}", {"verdict": verdict})
        return dict(con.execute("SELECT * FROM reviews WHERE id=?", (cur.lastrowid,)).fetchone())


def review_history(source, view, item_id) -> list[dict]:
    with connect() as con:
        rows = con.execute("SELECT * FROM reviews WHERE source=? AND view=? AND item_id=? ORDER BY id DESC",
                           (source, view, item_id))
        return [dict(r) for r in rows]


def audit_log(limit=200) -> list[dict]:
    with connect() as con:
        return [dict(r) for r in con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


def audit_archives() -> list:
    return sorted((VAR / "audit_archive").glob("activity_*.jsonl"))


def verify_audit() -> dict:
    """Walks the whole chain, archives first (oldest first), then the live log. ok, the entries checked, the head;
    when broken, where: the archive file or "live", and the entry's id."""
    prev, checked = "", 0

    def broken(where, entry_id):
        return {"ok": False, "checked": checked, "where": where, "entry": entry_id, "head": prev}
    for path in audit_archives():
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                    ok = entry["prev_hash"] == prev and _entry_hash(prev, entry) == entry["hash"]
                except (ValueError, KeyError, TypeError):
                    ok, entry = False, {}
                if not ok:
                    return broken(path.name, entry.get("id"))
                prev, checked = entry["hash"], checked + 1
    with connect() as con:
        archived = con.execute("SELECT value FROM audit_meta WHERE key = 'archived_head'").fetchone()
        if (archived["value"] if archived else "") != prev:
            return broken("archive", None)                     # an archive file is missing or was replaced
        for entry in con.execute("SELECT * FROM audit ORDER BY id"):
            if entry["prev_hash"] != prev or _entry_hash(prev, entry) != entry["hash"]:
                return broken("live", entry["id"])
            prev, checked = entry["hash"], checked + 1
    return {"ok": True, "checked": checked, "head": prev}


def audit_head() -> dict:
    """The chain's latest hash and when it was written: printed on every exported report."""
    with connect() as con:
        row = con.execute("SELECT at, hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return {"hash": row["hash"], "at": row["at"]} if row else {"hash": _chain_head(con), "at": ""}


def save_widget_result(widget: str, query: str, result: dict, actor: str) -> dict:
    """A Dashboard SQL table's result, kept (with the query that made it) until the table is refreshed again."""
    at = now()
    with _lock, connect() as con:
        con.execute("INSERT OR REPLACE INTO dashboard_results VALUES (?,?,?,?,?)",
                    (widget, query, json.dumps(result, default=str, allow_nan=False), at, actor))
    return {**result, "query": query, "refreshed_at": at, "refreshed_by": actor}


def widget_results() -> dict:
    with connect() as con:
        return {r["widget"]: {**json.loads(r["result"]), "query": r["query"], "refreshed_at": r["refreshed_at"],
                              "refreshed_by": r["refreshed_by"]} for r in con.execute("SELECT * FROM dashboard_results")}


def watchlist() -> list[dict]:
    """The entities watched in Profiles, oldest first (the Dashboard's Watched card)."""
    with connect() as con:
        return [dict(r) for r in con.execute("SELECT * FROM watchlist ORDER BY added_at, source, entity_type, entity")]


def set_watched(source: str, entity_type: str, entity: str, on: bool, actor: str) -> None:
    """Watch or stop watching an entity. The activity log names the log type and entity type, not the entity."""
    with _lock, connect() as con:
        if on:
            con.execute("INSERT OR IGNORE INTO watchlist VALUES (?,?,?,?,?)", (source, entity_type, entity, actor, now()))
        else:
            con.execute("DELETE FROM watchlist WHERE source=? AND entity_type=? AND entity=?", (source, entity_type, entity))
        audit(con, actor, "watch" if on else "unwatch", f"{source}/{entity_type}", {})


def log_action(actor, action, obj, detail) -> None:
    with _lock, connect() as con:
        audit(con, actor, action, obj, detail)


# --- passwords: the admin password (clearing the activity log, the whitelist) and the SQL password ---------------
# Each is kept as a salted PBKDF2 hash in its own file under var/; until it is changed, its default applies.

def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS).hex()


def _secret(path, default: str) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        salt = os.urandom(16)
        return {"salt": salt.hex(), "hash": _hash(default, salt), "is_default": True}


_guessing = threading.Lock()                  # one password check at a time, across every request


def _matches(path, default: str, password: str) -> bool:
    with _guessing:                           # parallel requests queue, so the wait below cannot be shared out
        record = _secret(path, default)
        ok = hmac.compare_digest(_hash(password or "", bytes.fromhex(record["salt"])), record["hash"])
        if not ok:
            time.sleep(1.0)                   # slows guessing: at most one wrong guess a second
        return ok


class DefaultPassword(PermissionError):
    """The right password, but still the default: it opens nothing until it is changed. which: "admin" or "sql"."""

    def __init__(self, which: str):
        self.which = which
        super().__init__(f"The {'admin' if which == 'admin' else 'SQL'} password is still the default: set a new one first.")


def _usable(path, default: str, password: str, which: str) -> bool:
    """True for the right password; DefaultPassword when it is right but still the default."""
    if not _matches(path, default, password):
        return False
    if _secret(path, default).get("is_default"):
        raise DefaultPassword(which)
    return True


def _replace(path, default: str, old: str, new: str) -> None:
    if not _matches(path, default, old):
        raise PermissionError("The current password is wrong.")
    if len(new or "") < 6:
        raise ValueError("Use at least 6 characters.")
    if new in (DEFAULT_PASSWORD, DEFAULT_SQL_PASSWORD):
        raise ValueError("Choose a password other than a default one.")
    salt = os.urandom(16)
    VAR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"salt": salt.hex(), "hash": _hash(new, salt), "is_default": False}), encoding="utf-8")
    tmp.replace(path)


def check_password(password: str) -> bool:
    return _usable(ADMIN_FILE, DEFAULT_PASSWORD, password, "admin")


def password_is_default() -> bool:
    return bool(_secret(ADMIN_FILE, DEFAULT_PASSWORD).get("is_default"))


def change_password(old: str, new: str, actor: str) -> None:
    _replace(ADMIN_FILE, DEFAULT_PASSWORD, old, new)
    log_action(actor, "change_password", "activity_log", {})


def check_sql_password(password: str) -> bool:
    return _usable(SQL_PASSWORD_FILE, DEFAULT_SQL_PASSWORD, password, "sql")


def sql_password_is_default() -> bool:
    return bool(_secret(SQL_PASSWORD_FILE, DEFAULT_SQL_PASSWORD).get("is_default"))


def change_sql_password(old: str, new: str, actor: str) -> None:
    _replace(SQL_PASSWORD_FILE, DEFAULT_SQL_PASSWORD, old, new)
    log_action(actor, "change_sql_password", "sql", {})


def clear_audit(password: str, actor: str) -> int:
    """Archives the live log (var/audit_archive/activity_<time>.jsonl, every field and hash) and empties it; the
    next entry, which records the archiving, continues the chain. Returns how many entries were archived."""
    if not check_password(password):
        raise PermissionError("Wrong password.")
    with _lock, connect() as con:
        rows = [dict(r) for r in con.execute("SELECT * FROM audit ORDER BY id")]
        if rows:
            folder = VAR / "audit_archive"
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f"activity_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.jsonl"
            tmp = path.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
            tmp.replace(path)
            con.execute("INSERT OR REPLACE INTO audit_meta VALUES ('archived_head', ?)", (rows[-1]["hash"],))
            con.execute("DELETE FROM audit")
        audit(con, actor, "archive_activity_log", "activity_log", {"entries_archived": len(rows)})
    return len(rows)
