"""Retention (service/retention.py): copies of log lines past the limit go; items, labels and reports stay.
Made-up store and lines only."""
from __future__ import annotations

import gc
import json
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import config, reports, retention, store, uploads  # noqa: E402
from tests.test_reports import document  # noqa: E402

LINES = json.dumps([{"time": "2025-01-01 10:00:00", "line": "made-up line", "own": True}])


def days_ago(n: int) -> str:
    return (date.today() - timedelta(days=n)).isoformat() + "T10:00:00+08:00"


class Retention(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", root / "console.sqlite"), mock.patch.object(store, "VAR", root),
                        mock.patch.object(config, "VAR", root), mock.patch.object(config, "SETTINGS_FILE", root / "settings.json")]
        for p in self.patches:
            p.start()
        with uploads._connect() as con:
            for upload_id, age in ((1, 500), (2, 120)):
                con.execute("INSERT INTO uploads (id, created_at, created_by, name, source) VALUES (?, ?, 'ops-1', 'made-up.log', 'auth')",
                            (upload_id, days_ago(age)))
                con.execute("INSERT INTO upload_items VALUES (?, 'item-1', 'individual', 0, '{}', ?)", (upload_id, LINES))
            con.execute("INSERT INTO dashboard_results VALUES ('sql_old', 'SELECT 1', '{}', ?, 'ops-1')", (days_ago(500),))
            con.execute("INSERT INTO dashboard_results VALUES ('sql_new', 'SELECT 1', '{}', ?, 'ops-1')", (days_ago(3),))

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def contexts(self):
        with uploads._connect() as con:
            return dict(con.execute("SELECT upload_id, context FROM upload_items").fetchall())

    def test_status_counts_what_is_past_the_limit(self):
        result = retention.status()
        self.assertEqual(result["months"], 12)
        self.assertEqual((result["upload_items_due"], result["dashboard_results_due"]), (1, 1))

    def test_apply_removes_old_copies_only_and_logs_counts(self):
        removed = retention.apply("tester")
        self.assertEqual((removed["upload_items"], removed["dashboard_results"]), (1, 1))
        self.assertEqual(self.contexts(), {1: "[]", 2: LINES})
        self.assertEqual(set(store.widget_results()), {"sql_new"})
        entry = store.audit_log(1)[0]
        self.assertEqual(entry["action"], "retention_applied")
        self.assertNotIn("made-up line", entry["detail"])
        self.assertEqual(retention.apply("tester")["upload_items"], 0)       # nothing left: nothing logged
        self.assertEqual(store.audit_log(1)[0]["id"], entry["id"])

    def test_a_shorter_limit_reaches_further(self):
        config.save_settings({"retention_months": 3})
        self.assertEqual(retention.status()["upload_items_due"], 2)          # the 120-day-old upload too
        with self.assertRaises(ValueError):
            config.save_settings({"retention_months": 0})

    def test_reports_are_counted_never_changed(self):
        doc = document()
        doc["sections"][0]["blocks"].append({"id": "b2", "type": "lines", "data": {"lines": ["made-up line"]}})
        saved = reports.save(doc, "tester")
        with store.connect() as con:
            con.execute("UPDATE report_versions SET saved_at = ?", (days_ago(500),))
        self.assertEqual(retention.status()["reports_with_lines_past"], 1)
        retention.apply("tester")
        self.assertIn("made-up line", json.dumps(reports.get(saved["id"])["document"]))


if __name__ == "__main__":
    unittest.main()
