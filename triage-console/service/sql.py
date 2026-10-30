"""Read-only SQL over the log stores.

Schemas available to a query:

* ``auth.events``  - every authlog line (Phase 2 store, about 26 million rows)
* ``ossec.events`` - every OSSEC line (Phase 2 store)
* ``fw.pf_events``, ``fw.ipf_events`` - every PF and IPFilter line, loaded once
  from the Phase 1 CSVs into ``var/cache/firewall.sqlite``

Queries may only read. Guardrails (see sql_guard.py): a text check before
running (one statement, SELECT/WITH only, no write, schema, attach, settings or
transaction keywords, no file or extension functions); an engine-level read-only
connection (query_only, an allow-list authorizer, size limits, no extensions);
and the stores attached read-only. Queries stop after a time limit and return
at most ``MAX_ROWS`` rows.
"""
from __future__ import annotations

import csv
import sqlite3
import sys
import threading
import time

from .config import CACHE, DATA, FROZEN
from .sql_guard import QueryRejected, check, harden

MAX_ROWS = 1000
TIME_LIMIT = 60.0
EXPORT_ROWS = 100_000          # a CSV download (the same guardrails, more rows)
EXPORT_TIME_LIMIT = 180.0
FIREWALL_DB = CACHE / "firewall.sqlite"
_build_lock = threading.Lock()

STORES = {
    "auth": DATA / "phase2_observations" / "auth" / "authlog_observation_store.sqlite",
    "ossec": DATA / "phase2_observations" / "ossec" / "ossec_observation_store.sqlite",
}
FIREWALL_INPUTS = {
    "pf_events": ("pf", "classified_pflog_events_????-??.csv"),
    "ipf_events": ("ipf", "ipflog_events_????-??.csv"),
}
EXAMPLES = [
    {"title": "Failed SSH logins by source address",
     "sql": "SELECT source_ip, COUNT(*) AS failures, MIN(timestamp_text) AS first, MAX(timestamp_text) AS last\n"
            "FROM auth.events\nWHERE event_type = 'SSH_LOGIN_FAILED'\nGROUP BY source_ip\nORDER BY failures DESC\nLIMIT 50"},
    {"title": "OSSEC events per server and category",
     "sql": "SELECT hostname, event_category, COUNT(*) AS n\nFROM ossec.events\nGROUP BY 1, 2\nORDER BY n DESC"},
    {"title": "IPFilter blocks by destination port",
     "sql": "SELECT destination_port, protocol, COUNT(*) AS packets\nFROM fw.ipf_events\nWHERE action = 'block'\n"
            "GROUP BY 1, 2\nORDER BY packets DESC\nLIMIT 50"},
    {"title": "One day of root logins on a server",
     "sql": "SELECT timestamp_text, source_ip, authentication_method, raw_message\nFROM auth.events\n"
            "WHERE host_id = 'mm04kco' AND username = 'root' AND event_type = 'SSH_LOGIN_SUCCESS'\n"
            "  AND timestamp_epoch BETWEEN strftime('%s','2026-07-01') AND strftime('%s','2026-07-02')\nLIMIT 200"},
]


def _build_firewall_db() -> None:
    """Load the PF and IPFilter Phase 1 CSVs into one cache database (once, or after they change)."""
    if FROZEN:                                       # the CSVs are gone: keep whatever was loaded, never empty it
        return
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    sources = {table: sorted((DATA / "phase1_classify" / folder).glob(pattern))
               for table, (folder, pattern) in FIREWALL_INPUTS.items()}
    stamp = ";".join(f"{p.name}:{p.stat().st_size}:{int(p.stat().st_mtime)}" for ps in sources.values() for p in ps)
    with _build_lock:
        if FIREWALL_DB.exists():
            con = sqlite3.connect(FIREWALL_DB)
            try:
                if con.execute("SELECT value FROM meta WHERE key='stamp'").fetchone() == (stamp,):
                    return
            except sqlite3.Error:
                pass
            finally:
                con.close()
        CACHE.mkdir(parents=True, exist_ok=True)
        tmp = FIREWALL_DB.with_suffix(".tmp")
        tmp.unlink(missing_ok=True)
        con = sqlite3.connect(tmp)
        for table, paths in sources.items():
            columns = None
            for path in paths:
                with path.open(encoding="utf-8", newline="") as handle:
                    reader = csv.reader(handle)
                    header = next(reader, None)
                    if not header:
                        continue
                    if columns is None:
                        columns = header
                        con.execute(f"CREATE TABLE {table} ({', '.join(f'\"{c}\" TEXT' for c in columns)})")
                    marks = ",".join("?" * len(columns))
                    con.executemany(f"INSERT INTO {table} VALUES ({marks})",
                                    (row + [""] * (len(columns) - len(row)) for row in reader if row))
            if columns:
                for column in ("timestamp", "event_type", "source_ip", "destination_ip", "hostname"):
                    if column in columns:
                        con.execute(f"CREATE INDEX {table}_{column} ON {table} (\"{column}\")")
        con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        con.execute("INSERT INTO meta VALUES ('stamp', ?)", (stamp,))
        con.commit()
        con.close()
        tmp.replace(FIREWALL_DB)


def _connect(locked: bool = True) -> sqlite3.Connection:
    """The stores attached read-only. Locked (the default, and always for user queries): the whole
    connection is then held to reading by sql_guard.harden. Unlocked only for the app's own schema listing."""
    _build_firewall_db()
    con = sqlite3.connect(":memory:", uri=True, check_same_thread=False)
    for name, path in {**STORES, "fw": FIREWALL_DB}.items():
        if path.exists():
            con.execute(f"ATTACH DATABASE ? AS {name}", (f"file:{path.as_posix()}?mode=ro",))
    if locked:
        harden(con)                                 # after attaching: from here on nothing can attach or write
    return con


def schema() -> dict:
    con = _connect(locked=False)                    # fixed internal queries only, no user text
    out = {}
    try:
        for name in ("auth", "ossec", "fw"):
            try:
                tables = [r[0] for r in con.execute(f"SELECT name FROM {name}.sqlite_master WHERE type='table'")]
            except sqlite3.Error:
                continue
            for table in tables:
                if table in ("meta", "known_record_ids", "known_event_ids"):
                    continue
                columns = con.execute(f"SELECT name FROM pragma_table_info(?, ?)", (table, name)).fetchall()
                out[f"{name}.{table}"] = [r[0] for r in columns]
    finally:
        con.close()
    return {"tables": out, "examples": EXAMPLES, "max_rows": MAX_ROWS, "time_limit": TIME_LIMIT, "export_rows": EXPORT_ROWS}


def run(query: str, max_rows: int = MAX_ROWS, time_limit: float = TIME_LIMIT) -> dict:
    query = check(query)                            # raises QueryRejected for anything but a single read
    con = _connect()
    started = time.monotonic()
    con.set_progress_handler(lambda: 1 if time.monotonic() - started > time_limit else 0, 10_000)
    try:
        cursor = con.execute(query)
        columns = [d[0] for d in cursor.description or []]
        rows = cursor.fetchmany(max_rows + 1)
    except sqlite3.OperationalError as error:
        if "not authorized" in str(error) or "readonly" in str(error) or "query_only" in str(error):
            raise QueryRejected("This console can only read data, never change it.") from None
        if FROZEN and "no such table" in str(error):
            raise ValueError("That table's log lines were purged with data/; the log stores are not on this laptop any more.") from None
        if "interrupted" in str(error):
            raise ValueError(f"The query took longer than {time_limit:.0f} seconds and was stopped. "
                             "Filter on an indexed column (timestamp_epoch, host_id) or add LIMIT.") from None
        raise ValueError(str(error)) from None
    except sqlite3.DatabaseError as error:
        raise ValueError(str(error)) from None
    finally:
        con.close()
    return {"columns": columns, "rows": [list(r) for r in rows[:max_rows]], "truncated": len(rows) > max_rows,
            "seconds": round(time.monotonic() - started, 3)}
