"""The activity log's hash chain (store.py): verified end to end, archived instead of cleared, and pinned by the
latest hash on every exported report. Isolated store only."""
from __future__ import annotations

import base64
import gc
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import reports, store  # noqa: E402
from tests.test_reports import document  # noqa: E402

PASSWORD = "made-up-admin"


class AuditChain(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", root / "console.sqlite"), mock.patch.object(store, "VAR", root),
                        mock.patch.object(store, "ADMIN_FILE", root / "admin.json"), mock.patch.object(store.time, "sleep")]
        for p in self.patches:
            p.start()
        store.change_password(store.DEFAULT_PASSWORD, PASSWORD, "tester")
        for i in range(4):
            store.log_action("tester", "made_up_action", f"object/{i}", {"i": i})

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def edit(self, sql, *args):
        """A change made outside the application."""
        with closing(sqlite3.connect(store.STORE_FILE)) as con, con:
            con.execute(sql, args)

    def test_an_untouched_log_verifies(self):
        result = store.verify_audit()
        self.assertTrue(result["ok"])
        self.assertEqual(result["checked"], 5)                     # the password change and four actions
        self.assertEqual(result["head"], store.audit_head()["hash"])

    def test_archiving_keeps_the_chain(self):
        self.assertEqual(store.clear_audit(PASSWORD, "tester"), 5)
        store.log_action("tester", "after", "object/x", {})
        self.assertEqual(store.clear_audit(PASSWORD, "tester"), 2)  # the archiving entry and one more
        self.assertEqual(len(store.audit_archives()), 2)
        self.assertEqual([e["action"] for e in store.audit_log()], ["archive_activity_log"])
        result = store.verify_audit()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["checked"], 8)
        archived = [json.loads(line) for line in store.audit_archives()[0].read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(archived), 5)
        self.assertEqual({"id", "at", "actor", "action", "object", "detail", "prev_hash", "hash"}, set(archived[0]))

    def test_an_edit_in_the_live_log_is_found(self):
        self.edit("UPDATE audit SET actor = 'someone else' WHERE id = 3")
        result = store.verify_audit()
        self.assertFalse(result["ok"])
        self.assertEqual((result["where"], result["entry"]), ("live", 3))

    def test_a_deleted_entry_is_found(self):
        self.edit("DELETE FROM audit WHERE id = 2")
        self.assertEqual(store.verify_audit()["entry"], 3)

    def test_an_edited_or_missing_archive_is_found(self):
        store.clear_audit(PASSWORD, "tester")
        path = store.audit_archives()[0]
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace("made_up_action", "other_action", 1), encoding="utf-8")
        self.assertEqual(store.verify_audit()["where"], path.name)
        path.unlink()
        self.assertEqual(store.verify_audit()["where"], "archive")

    def test_the_wrong_password_archives_nothing(self):
        with self.assertRaises(PermissionError):
            store.clear_audit("wrong", "tester")
        self.assertEqual(store.audit_archives(), [])

    def test_an_exported_report_carries_the_latest_hash(self):
        saved = reports.save(document(), "tester")
        head = store.audit_head()["hash"]
        page = base64.b64decode(reports.export(saved["id"], 1, "html", "tester")["content"]).decode("utf-8")
        self.assertIn(f"Activity log {head[:16]}", page)


if __name__ == "__main__":
    unittest.main()
