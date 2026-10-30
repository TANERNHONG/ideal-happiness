"""Tests for the SQL console guardrails (service/sql_guard.py, service/sql.py).

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import sql, sql_guard  # noqa: E402
from service.sql_guard import QueryRejected, check, harden  # noqa: E402

ALLOWED = [
    "SELECT 1",
    "select count(*) from ossec.events",
    "SELECT * FROM fw.ipf_events WHERE action = 'block' LIMIT 5;",
    "WITH x AS (SELECT 1 AS n) SELECT n FROM x",
    "SELECT 'DELETE FROM events; DROP TABLE x' AS text_only",          # keywords inside a string are just text
    "SELECT 1 -- DROP TABLE x\n",                                       # ...or inside a comment
    "SELECT /* INSERT INTO t */ 2",
    "SELECT REPLACE(raw_message, 'a', 'b') FROM ossec.events LIMIT 1",  # REPLACE the string function
    'SELECT "delete" FROM (SELECT 1 AS "delete")',                      # a quoted name that looks like a keyword
    "SELECT deleted_count, insert_time, updated FROM (SELECT 1 AS deleted_count, 2 AS insert_time, 3 AS updated)",
]

REJECTED = [
    "INSERT INTO auth.events (record_id) VALUES ('x')",
    "insert into fw.pf_events values (1)",
    "REPLACE INTO fw.pf_events VALUES (1)",
    "UPDATE ossec.events SET hostname = 'x'",
    "DELETE FROM auth.events",
    "dElEtE fRoM auth.events",
    "DROP TABLE fw.pf_events",
    "CREATE TABLE t (a)",
    "CREATE TEMP TABLE t AS SELECT 1",
    "CREATE VIEW v AS SELECT 1",
    "CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END",
    "ALTER TABLE fw.pf_events ADD COLUMN x",
    "ATTACH DATABASE 'C:/temp/x.db' AS x",
    "DETACH DATABASE fw",
    "PRAGMA query_only = OFF",
    "PRAGMA writable_schema = 1",
    "VACUUM",
    "VACUUM INTO 'C:/temp/copy.db'",
    "REINDEX",
    "ANALYZE",
    "BEGIN; DELETE FROM auth.events; COMMIT",
    "SELECT 1; DELETE FROM auth.events",                     # second statement
    "SELECT 1;\nDROP TABLE x;",
    "WITH x AS (SELECT 1) DELETE FROM auth.events",          # CTE that writes
    "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",
    "SELECT * FROM auth.events WHERE 1 = 1; --",             # tail after the statement is fine... but see below
    "SELECT load_extension('evil')",
    "SELECT writefile('C:/temp/x', 'data')",
    "SELECT readfile('C:/Windows/win.ini')",
    "SELECT zeroblob(1000000000)",
    "SELECT 'unterminated",
    "SELECT /* unclosed comment",
    "",
    "   ;   ",
    "EXPLAIN SELECT 1",
    "VALUES (1)",
    "SAVEPOINT a",
    "SELECT 1 INTO t",
    "SELECT * FROM x ON CONFLICT DO UPDATE SET a = 1",
    "SELECT 1\x00",
    "SELECT " + "1," * 12_000 + "1",                          # too long
]
REJECTED.remove("SELECT * FROM auth.events WHERE 1 = 1; --")   # a trailing comment after one statement is allowed


class TextCheck(unittest.TestCase):
    def test_reading_queries_pass(self):
        for query in ALLOWED:
            with self.subTest(query=query):
                self.assertTrue(check(query))

    def test_writes_and_admin_statements_are_refused(self):
        for query in REJECTED:
            with self.subTest(query=query[:60]):
                with self.assertRaises(QueryRejected):
                    check(query)

    def test_trailing_semicolon_and_comment_are_fine(self):
        self.assertEqual(check("SELECT 1;"), "SELECT 1")
        self.assertTrue(check("SELECT * FROM auth.events WHERE 1 = 1; --"))


class EngineLayer(unittest.TestCase):
    """Even if the text check were bypassed, a hardened connection must refuse every write."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        path = Path(self.folder.name) / "store.sqlite"
        setup = sqlite3.connect(path)
        setup.execute("CREATE TABLE events (a)")
        setup.execute("INSERT INTO events VALUES (1)")
        setup.commit()
        setup.close()
        self.con = sqlite3.connect(":memory:", uri=True)
        self.con.execute("ATTACH DATABASE ? AS s", (f"file:{path.as_posix()}?mode=ro",))
        harden(self.con)

    def tearDown(self):
        self.con.close()
        self.folder.cleanup()

    def test_reads_work(self):
        self.assertEqual(self.con.execute("SELECT a FROM s.events").fetchall(), [(1,)])

    def test_writes_fail_at_the_engine(self):
        for statement in ["INSERT INTO s.events VALUES (2)", "UPDATE s.events SET a = 3", "DELETE FROM s.events",
                          "DROP TABLE s.events", "CREATE TABLE t (a)", "CREATE TEMP TABLE t (a)",
                          "ATTACH DATABASE ':memory:' AS x", "PRAGMA query_only = OFF", "VACUUM",
                          "SELECT load_extension('x')", "SELECT zeroblob(10)"]:
            with self.subTest(statement=statement):
                with self.assertRaises(sqlite3.DatabaseError):
                    self.con.execute(statement)
        self.assertEqual(self.con.execute("SELECT a FROM s.events").fetchall(), [(1,)])   # unchanged


class ConsoleEndToEnd(unittest.TestCase):
    """sql.run on the real stores (skipped when the pipeline data is not present)."""

    @classmethod
    def setUpClass(cls):
        if not sql.STORES["ossec"].exists():
            raise unittest.SkipTest("OSSEC store not found")

    def test_a_read_runs(self):
        result = sql.run("SELECT hostname, COUNT(*) AS n FROM ossec.events GROUP BY 1 ORDER BY n DESC LIMIT 3")
        self.assertEqual(result["columns"], ["hostname", "n"])
        self.assertEqual(len(result["rows"]), 3)

    def test_writes_are_refused(self):
        for query in ["DELETE FROM ossec.events", "DROP TABLE fw.ipf_events", "PRAGMA query_only = OFF",
                      "SELECT 1; DELETE FROM ossec.events"]:
            with self.subTest(query=query):
                with self.assertRaises(QueryRejected):
                    sql.run(query)


if __name__ == "__main__":
    unittest.main()
