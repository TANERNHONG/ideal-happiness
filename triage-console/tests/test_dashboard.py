"""The Dashboard's Next to review order (service/server.py): Sigma matches first, then each log type in turn.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_dashboard -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import server  # noqa: E402


def item(source, item_id, sigma=0):
    return {"source": source, "item_id": item_id, "sigma": [{"title": "Rule", "observations": sigma}] if sigma else []}


class NextToReview(unittest.TestCase):
    def test_sigma_matches_first_most_matches_first(self):
        queues = [[item("auth", "a1"), item("auth", "a2", sigma=2)], [item("ossec", "o1", sigma=5)]]
        self.assertEqual([i["item_id"] for i in server._next_to_review(queues)][:2], ["o1", "a2"])

    def test_then_each_log_type_in_turn_in_its_own_order(self):
        queues = [[item("auth", "a1"), item("auth", "a2"), item("auth", "a3")], [item("ossec", "o1")], [], [item("ipf", "i1"), item("ipf", "i2")]]
        self.assertEqual([i["item_id"] for i in server._next_to_review(queues)], ["a1", "o1", "i1", "a2", "i2", "a3"])

    def test_waiting_item_keeps_only_what_the_dashboard_shows(self):
        row = server._waiting("auth", {**item("auth", "a1", sigma=1), "view": "authentication_sessions", "kind": "cluster",
                                       "name": "Night logins", "top": {"host_id": "host-a", "username": "svc"}, "lines": ["x"]})
        self.assertEqual(row["sigma"], ["Rule"])
        self.assertEqual(row["server"], "host-a")
        self.assertNotIn("lines", row)
        self.assertNotIn("top", row)


class SqlTables(unittest.TestCase):
    """The Dashboard's own SQL tables: refreshing needs the SQL password; the result is kept until the next refresh."""

    def setUp(self):
        import tempfile
        from unittest import mock
        from service import sql_lock, store
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", root / "console.sqlite"), mock.patch.object(store, "VAR", root),
                        mock.patch.dict(sql_lock._tokens, clear=True)]
        for p in self.patches:
            p.start()
        self.store, self.sql_lock = store, sql_lock

    def tearDown(self):
        import gc
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def test_refresh_needs_the_sql_password(self):
        with self.assertRaises(self.sql_lock.Locked):
            server.ROUTES[("POST", "/api/dashboard/widget")]({}, {"id": "sql_k1", "query": "SELECT 1"})

    def test_only_a_dashboard_tables_name(self):
        from unittest import mock
        with mock.patch.object(self.sql_lock, "require"):
            for widget in ("open", "../x", "sql_K1", ""):
                with self.subTest(widget=widget), self.assertRaises(ValueError):
                    server.ROUTES[("POST", "/api/dashboard/widget")]({}, {"id": widget, "query": "SELECT 1"})

    def test_refresh_runs_through_the_guardrails_and_keeps_the_result(self):
        from unittest import mock
        result = {"columns": ["n"], "rows": [[1]], "truncated": False, "seconds": 0.01}
        with mock.patch.object(self.sql_lock, "require"), mock.patch.object(server.sql, "run", return_value=result) as run:
            kept = server.ROUTES[("POST", "/api/dashboard/widget")]({}, {"id": "sql_k1", "query": "SELECT 1 AS n"})
        run.assert_called_once_with("SELECT 1 AS n")
        self.assertEqual(kept["rows"], [[1]])
        again = self.store.widget_results()["sql_k1"]
        self.assertEqual((again["rows"], again["query"], again["refreshed_at"]), ([[1]], "SELECT 1 AS n", kept["refreshed_at"]))


if __name__ == "__main__":
    unittest.main()
