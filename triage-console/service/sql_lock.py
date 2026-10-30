"""The SQL password: running a query (Data → SQL, a report's table, a chart's CSV) or reading the schema needs it.

The password is asked once per sitting: unlocking gives a random token, and every SQL request carries it. A token
lapses after IDLE_SECONDS without a query, when the password changes, and when the service restarts (tokens live in
memory only). The password itself is kept like the admin password (store.py: salted PBKDF2 in
var/sql_password.json, 1234 until changed; a wrong guess costs a second). Queries the console writes and runs
itself (Review's logs around an event) are not behind it.
"""
from __future__ import annotations

import secrets
import threading
import time

from . import store

IDLE_SECONDS = 30 * 60
_lock = threading.Lock()
_tokens: dict[str, float] = {}           # token -> when it lapses (time.monotonic)


class Locked(PermissionError):
    """An SQL request without a valid token: the browser asks for the password and tries again."""


def unlock(password: str, actor: str) -> dict:
    if not store.check_sql_password(password):
        store.log_action(actor, "sql_unlock_refused", "sql", {})
        raise PermissionError("Wrong SQL password.")
    token = secrets.token_urlsafe(32)
    with _lock:
        now = time.monotonic()
        for old, until in list(_tokens.items()):
            if until < now:
                del _tokens[old]
        _tokens[token] = now + IDLE_SECONDS
    store.log_action(actor, "sql_unlock", "sql", {})
    return {"token": token, "idle_minutes": IDLE_SECONDS // 60}


def require(token: object) -> None:
    """Refuses unless ``token`` is current; each use keeps it for another IDLE_SECONDS."""
    key = token if isinstance(token, str) else ""
    with _lock:
        now = time.monotonic()
        until = _tokens.get(key)
        if until is None or until < now:
            _tokens.pop(key, None)
            raise Locked("SQL password needed.")
        _tokens[key] = now + IDLE_SECONDS


def change(old: str, new: str, actor: str) -> None:
    store.change_sql_password(old, new, actor)
    with _lock:
        _tokens.clear()                     # everyone unlocks again with the new password
