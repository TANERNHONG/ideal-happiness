"""Tests for the review process: the labels and their note rules (service/store.py) and the
before-and-after query (service/review_context.py).

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import calendar
import gc
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import review_context, sql, store  # noqa: E402
from service.sql_guard import check, harden  # noqa: E402

SERVER, START, END = "host10", "2026-06-08 13:55:14", "2026-06-08 13:57:00"


def epoch(text: str) -> int:
    """The stores' convention: local time read as if it were UTC."""
    return calendar.timegm(datetime.strptime(text, "%Y-%m-%d %H:%M:%S").timetuple())


class Labels(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()                       # store.connect() leaves closing to the garbage collector
        self.folder.cleanup()

    def review(self, verdict, note=""):
        return store.add_review("auth", "individual", "individual#3", "cluster", verdict, note, "tester")

    def test_the_five_labels(self):
        self.assertEqual(store.VERDICTS, ("security_relevant", "suspicious", "operationally_interesting",
                                          "expected_behavior", "insufficient_evidence"))

    def test_old_and_unknown_labels_are_refused(self):
        for verdict in ("malicious", "not_malicious", "needs_investigation", "", "Security relevant"):
            with self.subTest(verdict=verdict):
                with self.assertRaises(ValueError):
                    self.review(verdict, "a note")

    def test_a_note_is_needed_where_it_matters(self):
        for verdict in ("security_relevant", "suspicious", "insufficient_evidence"):
            with self.subTest(verdict=verdict):
                with self.assertRaises(ValueError):
                    self.review(verdict, "   ")
                self.assertEqual(self.review(verdict, "seen from 10.x")["verdict"], verdict)

    def test_no_note_needed_for_the_rest(self):
        for verdict in ("operationally_interesting", "expected_behavior"):
            with self.subTest(verdict=verdict):
                self.assertEqual(self.review(verdict)["verdict"], verdict)

    def test_latest_decision_wins_and_history_keeps_all(self):
        self.review("insufficient_evidence", "no firewall logs for that hour")
        self.review("expected_behavior")
        latest = store.latest_reviews("auth")[("auth", "individual", "individual#3")]
        self.assertEqual(latest["verdict"], "expected_behavior")
        self.assertEqual([r["verdict"] for r in store.review_history("auth", "individual", "individual#3")],
                         ["expected_behavior", "insufficient_evidence"])


class BeforeAfterQuery(unittest.TestCase):
    def test_window_bounds(self):
        text = review_context.query(SERVER, START, END, 10, 5, ["auth", "pf"])
        self.assertIn(f"timestamp_epoch >= {epoch('2026-06-08 13:45:14')}", text)
        self.assertIn(f"timestamp_epoch < {epoch('2026-06-08 14:02:00') + 1}", text)        # the last second is kept
        self.assertIn("BETWEEN '2026-06-08 13:45:14' AND '2026-06-08 14:02:00.999999'", text)
        self.assertEqual(text.count("UNION ALL"), 1)
        self.assertNotIn("ossec.events", text)
        self.assertTrue(text.rstrip().endswith("ORDER BY time, log"))

    def test_every_log_by_default_order(self):
        text = review_context.query(SERVER, START, END, 0, 0, ["ipf", "ossec", "auth", "pf", "nonsense"])
        self.assertEqual(text.count("UNION ALL"), 3)
        positions = [text.index(t) for t in ("auth.events", "ossec.events", "fw.pf_events", "fw.ipf_events")]
        self.assertEqual(positions, sorted(positions))

    def test_it_passes_the_sql_guard(self):
        for logs in (["auth"], ["ossec", "ipf"], list(review_context.LOGS)):
            with self.subTest(logs=logs):
                self.assertTrue(check(review_context.query(SERVER, START, END, 30, 30, logs)))

    def test_bad_servers_never_reach_a_query(self):
        for server in ("", "x' OR '1'='1", "a;DROP TABLE x", "host name", "a" * 65, "ab'--", "%", "名前"):
            with self.subTest(server=server):
                with self.assertRaises(ValueError):
                    review_context.query(server, START, END, 10, 10, ["auth"])

    def test_window_limits(self):
        for before, after in ((-1, 10), (10, -5), (1441, 0), (0, 100_000)):
            with self.subTest(before=before, after=after):
                with self.assertRaises(ValueError):
                    review_context.query(SERVER, START, END, before, after, ["auth"])
        self.assertTrue(review_context.query(SERVER, START, END, 1440, 1440, ["auth"]))

    def test_at_least_one_log(self):
        with self.assertRaises(ValueError):
            review_context.query(SERVER, START, END, 10, 10, [])
        with self.assertRaises(ValueError):
            review_context.query(SERVER, START, END, 10, 10, ["syslog"])


class QueryOnSmallStores(unittest.TestCase):
    """The query on tiny stores shaped like the real ones: only the server's lines, only inside the window."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        folder = Path(self.folder.name)
        lines = [  # (time, server)
            ("2026-06-08 13:44:59", SERVER),   # just before the window (10 min before 13:55:14 is 13:45:14)
            ("2026-06-08 13:45:14", SERVER),   # first second of the window
            ("2026-06-08 13:55:14", SERVER),   # the observation
            ("2026-06-08 13:56:00", "other"),  # another server
            ("2026-06-08 14:02:00", SERVER),   # last second of the window (5 min after 13:57:00)
            ("2026-06-08 14:02:01", SERVER),   # just after
        ]
        for name, key in (("auth", "record_id"), ("ossec", "event_id")):
            con = sqlite3.connect(folder / f"{name}.sqlite")
            con.execute(f"CREATE TABLE events (timestamp_text, timestamp_epoch, host_id, event_type, original_log_line, {key}, raw_line_sha256)")
            con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                            [(t, epoch(t), s, "E", f"{name} {t} {s}", f"{name}{i}", f"{i:064x}") for i, (t, s) in enumerate(lines)])
            con.commit()
            con.close()
        con = sqlite3.connect(folder / "fw.sqlite")
        con.execute("CREATE TABLE pf_events (timestamp, event_type, raw_message, event_id, source_file, raw_message_sha256)")
        con.execute("CREATE TABLE ipf_events (timestamp, hostname, event_type, raw_message, event_id, raw_message_sha256)")
        con.executemany("INSERT INTO pf_events VALUES (?,?,?,?,?,?)",
                        [(f"{t}.123456", "block", f"pf {t} {s}", f"pf{i}", f"logs/pflog_{s}.txt", f"{i:064x}") for i, (t, s) in enumerate(lines)])
        con.executemany("INSERT INTO ipf_events VALUES (?,?,?,?,?,?)",
                        [(f"{t}.000001", s, "block", f"ipf {t} {s}", f"ipf{i}", f"{i:064x}") for i, (t, s) in enumerate(lines)])
        con.commit()
        con.close()
        self.con = sqlite3.connect(":memory:", uri=True)
        for name in ("auth", "ossec", "fw"):
            self.con.execute(f"ATTACH DATABASE ? AS {name}", (f"file:{(folder / f'{name}.sqlite').as_posix()}?mode=ro",))
        harden(self.con)                                       # as the console runs it

    def tearDown(self):
        self.con.close()
        self.folder.cleanup()

    def test_only_the_window_and_the_server(self):
        rows = self.con.execute(review_context.query(SERVER, START, END, 10, 5, list(review_context.LOGS))).fetchall()
        for log in review_context.LOGS:
            with self.subTest(log=log):
                times = [r[1] for r in rows if r[0] == log]
                self.assertEqual(times, ["2026-06-08 13:45:14", "2026-06-08 13:55:14", "2026-06-08 14:02:00"])
        self.assertTrue(all(r[2] == SERVER for r in rows))
        self.assertEqual([r[1] for r in rows], sorted(r[1] for r in rows))     # oldest first


class OnTheRealStores(unittest.TestCase):
    """review_context.query through sql.run (skipped when the pipeline data is not present)."""

    @classmethod
    def setUpClass(cls):
        if not sql.STORES["auth"].exists():
            raise unittest.SkipTest("auth store not found")

    def test_lines_around_a_login(self):
        # Any login in the store, so that no server name or time is written into the test
        found = sql.run("SELECT host_id, timestamp_epoch FROM auth.events WHERE event_type = 'SSH_LOGIN_SUCCESS' LIMIT 1")["rows"]
        if not found:
            self.skipTest("no login in the auth store")
        server, epoch = found[0][0], found[0][1]
        at = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        result = sql.run(review_context.query(server, at, at, 30, 30, ["auth"]))
        self.assertEqual(result["columns"], ["log", "time", "server", "event_type", "line", "id", "sha256"])
        self.assertTrue(all(len(row[6]) == 64 for row in result["rows"]))          # Phase 2's fingerprint of each line
        self.assertTrue(result["rows"])
        for row in result["rows"]:
            self.assertEqual(row[2], server)


if __name__ == "__main__":
    unittest.main()
