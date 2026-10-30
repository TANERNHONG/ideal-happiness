"""How long the console keeps its own copies of log lines (Settings → Retention, retention_months).

The logs themselves live in data/ and follow their own purge. The console copies lines in three places:

* uploads: up to 200 lines around each event (upload_items.context). Past the limit the lines go; the item, its
  scores, labels and comments stay.
* the Dashboard's SQL tables: a saved result can hold lines. Past the limit it goes; Refresh runs the query again.
* reports: a Log lines block keeps the lines as retrieved, in immutable saved versions. Reports are investigation
  records with a records schedule of their own, so they are never changed here; status() counts those holding
  lines past the limit, for the data owner to decide.

apply() runs when the service starts and once a day (start_background), and from Settings; each run that removes
something is written to the activity log, with counts only.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import date, timedelta

from . import store
from .config import load_settings

DAY_SECONDS = 24 * 60 * 60
_lock = threading.Lock()


def cutoff(months: int | None = None, today: date | None = None) -> str:
    """The first day kept, YYYY-MM-DD: anything copied before it is past the limit."""
    months = months or load_settings()["retention_months"]
    return ((today or date.today()) - timedelta(days=round(months * 30.44))).isoformat()


def _reports_past(con, before: str) -> int:
    """Reports whose saved versions hold a Log lines block saved before the cutoff."""
    try:
        rows = con.execute("SELECT report_id, document FROM report_versions WHERE substr(saved_at, 1, 10) < ?", (before,))
    except sqlite3.OperationalError:             # no reports table yet
        return 0
    found = set()
    for report_id, document in rows:
        if report_id not in found and _has_lines(json.loads(document)):
            found.add(report_id)
    return len(found)


def _has_lines(node) -> bool:
    if isinstance(node, dict):
        return node.get("type") == "lines" or any(_has_lines(v) for v in node.values())
    return isinstance(node, list) and any(_has_lines(v) for v in node)


def status() -> dict:
    before = cutoff()
    with store.connect() as con:
        due = con.execute("SELECT COUNT(*) FROM upload_items WHERE context != '[]' AND upload_id IN "
                          "(SELECT id FROM uploads WHERE substr(created_at, 1, 10) < ?)", (before,)).fetchone()[0] \
            if _has(con, "upload_items") else 0
        widgets = con.execute("SELECT COUNT(*) FROM dashboard_results WHERE substr(refreshed_at, 1, 10) < ?",
                              (before,)).fetchone()[0]
        reports = _reports_past(con, before)
    return {"months": load_settings()["retention_months"], "cutoff": before, "upload_items_due": due,
            "dashboard_results_due": widgets, "reports_with_lines_past": reports}


def _has(con, table: str) -> bool:
    return con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone() is not None


def apply(actor: str = "retention") -> dict:
    """Removes the copies past the limit; returns the counts (and writes them to the activity log when not zero)."""
    before = cutoff()
    with _lock, store._lock, store.connect() as con:
        items = con.execute("UPDATE upload_items SET context = '[]' WHERE context != '[]' AND upload_id IN "
                            "(SELECT id FROM uploads WHERE substr(created_at, 1, 10) < ?)", (before,)).rowcount \
            if _has(con, "upload_items") else 0
        widgets = con.execute("DELETE FROM dashboard_results WHERE substr(refreshed_at, 1, 10) < ?", (before,)).rowcount
        removed = {"upload_items": items, "dashboard_results": widgets, "before": before}
        if items or widgets:
            store.audit(con, actor, "retention_applied", "log_lines", removed)
    return removed


def start_background() -> None:
    """apply() now and then once a day, in a daemon thread (a failure is printed and tried again the next day)."""
    def loop():
        while True:
            try:
                apply()
            except Exception as error:          # keep serving; the next day tries again
                print(f"Retention: {type(error).__name__}: {error}")
            stop.wait(DAY_SECONDS)
    stop = threading.Event()
    threading.Thread(target=loop, name="retention", daemon=True).start()
