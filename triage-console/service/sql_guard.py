"""Guardrails for the SQL console: queries may only read.

Layered, so that no single mistake opens a write path:

1. Text check (this module, before anything runs). Comments, string literals and
   quoted names are removed first, so nothing can hide inside them. Then the query
   must be one statement, must start with SELECT or WITH, and must not contain any
   keyword that writes, changes the schema, attaches files, changes settings or
   controls transactions.
2. Engine (``harden``, applied to every console connection): ``PRAGMA query_only``,
   an authorizer that allows only reading and refuses dangerous functions, no
   extension loading, and size limits on strings, blobs and the query itself.
3. The stores are attached read-only (``mode=ro``), so even a missed case cannot
   change a file. The server also logs refused queries in the activity log.
"""
from __future__ import annotations

import re
import sqlite3

MAX_QUERY_CHARS = 20_000

# Statements and clauses that write, change the schema, attach files, change settings
# or control transactions - refused anywhere in the query (as whole words, outside
# strings and comments). INTO also covers INSERT INTO / REPLACE INTO in every form.
FORBIDDEN_KEYWORDS = frozenset("""
    INSERT UPDATE DELETE REPLACE UPSERT MERGE INTO TRUNCATE
    CREATE DROP ALTER RENAME REINDEX VACUUM ANALYZE
    ATTACH DETACH PRAGMA
    BEGIN COMMIT ROLLBACK SAVEPOINT RELEASE TRANSACTION
    GRANT REVOKE EXEC EXECUTE CALL
""".split())
# REPLACE is also an ordinary string function: REPLACE(text, 'a', 'b') is allowed.
FUNCTION_LIKE = frozenset({"REPLACE"})

# Functions refused even inside a SELECT: file access, extension loading, schema or
# tokenizer tampering, and huge allocations.
FORBIDDEN_FUNCTIONS = frozenset({
    "load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "sqlite_offset",
    "zeroblob", "randomblob", "sqlite_compileoption_get", "sqlite_compileoption_used",
})

ALLOWED_ACTIONS = frozenset({sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE})
LIMITS = {                                              # sqlite3 run-time limits for console connections
    getattr(sqlite3, "SQLITE_LIMIT_LENGTH", 0): 10_000_000,          # largest string or blob
    getattr(sqlite3, "SQLITE_LIMIT_SQL_LENGTH", 1): MAX_QUERY_CHARS,
    getattr(sqlite3, "SQLITE_LIMIT_EXPR_DEPTH", 3): 200,
    getattr(sqlite3, "SQLITE_LIMIT_COMPOUND_SELECT", 4): 50,
}

_TOKEN = re.compile(r"""
      (?P<line_comment>--[^\n]*)
    | (?P<block_comment>/\*.*?\*/)
    | (?P<string>'(?:[^']|'')*')
    | (?P<quoted>"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\])
    | (?P<open>/\*|'|"|`|\[)
""", re.S | re.X)
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")


class QueryRejected(ValueError):
    """The query was refused before running; the message says why, in plain words."""


def _strip(query: str) -> str:
    """Replace comments, string literals and quoted names so that keywords cannot hide in them."""
    def replace(match: re.Match) -> str:
        if match.group("open"):
            raise QueryRejected("The query has an unclosed comment, quote or bracket.")
        if match.group("line_comment") or match.group("block_comment"):
            return " "
        return " ''' " if match.group("string") else ' "q" '
    return _TOKEN.sub(replace, query)


def check(query: str) -> str:
    """Return the query (trimmed) if it only reads; otherwise raise QueryRejected."""
    if not isinstance(query, str) or not query.strip():
        raise QueryRejected("Write a query first.")
    if len(query) > MAX_QUERY_CHARS:
        raise QueryRejected(f"The query is longer than {MAX_QUERY_CHARS:,} characters.")
    if "\x00" in query:
        raise QueryRejected("The query contains a null character.")
    bare = _strip(query)
    statements = [s for s in bare.split(";") if s.strip()]
    if len(statements) != 1:
        raise QueryRejected("Run one statement at a time.")
    words = [w.upper() for w in _WORD.findall(statements[0])]
    if not words or words[0] not in ("SELECT", "WITH"):
        raise QueryRejected("Only reading queries can run here: start with SELECT (or WITH … SELECT).")
    for i, word in enumerate(words):
        if word in FORBIDDEN_KEYWORDS:
            if word in FUNCTION_LIKE and re.search(rf"\b{word}\s*\(", statements[0], re.I) and "INTO" not in words:
                continue                                  # REPLACE(...) the string function
            raise QueryRejected(f"“{word}” is not allowed: this console can only read data, never change it.")
    lowered = statements[0].lower()
    for name in FORBIDDEN_FUNCTIONS:
        if re.search(rf"\b{name}\s*\(", lowered):
            raise QueryRejected(f"The function {name}() is not allowed in this console.")
    return query.strip().rstrip(";").strip()


def harden(con: sqlite3.Connection) -> None:
    """Make a console connection read-only at the engine level, whatever the text check missed."""
    con.execute("PRAGMA query_only = ON")
    try:
        con.enable_load_extension(False)
    except AttributeError:                               # Python built without extension support
        pass
    for limit, value in LIMITS.items():
        try:
            con.setlimit(limit, value)
        except (AttributeError, sqlite3.ProgrammingError):
            pass

    def authorizer(action, arg1, arg2, database, trigger):
        if action not in ALLOWED_ACTIONS:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in FORBIDDEN_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    con.set_authorizer(authorizer)
