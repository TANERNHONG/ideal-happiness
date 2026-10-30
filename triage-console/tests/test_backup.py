"""Backups of var/ (service/backup.py) on a made-up console folder: create, verify, restore, rehearse."""
from __future__ import annotations

import gc
import json
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import backup, store  # noqa: E402

PASSWORD = "made-up-admin"


class Backups(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.var = Path(self.folder.name) / "var"
        self.var.mkdir()
        self.db = self.var / "console.sqlite3"
        self.patches = [mock.patch.object(store, "STORE_FILE", self.db), mock.patch.object(store, "VAR", self.var),
                        mock.patch.object(store, "ADMIN_FILE", self.var / "admin.json"), mock.patch.object(store.time, "sleep")]
        for p in self.patches:
            p.start()
        store.change_password(store.DEFAULT_PASSWORD, PASSWORD, "tester")
        for i in range(3):
            store.log_action("tester", "made_up_action", f"object/{i}", {})
        store.clear_audit(PASSWORD, "tester")
        store.log_action("tester", "after_archive", "object/x", {})
        (self.var / "settings.json").write_text(json.dumps({"display_name": "Analyst A"}), encoding="utf-8")
        (self.var / "cache").mkdir()
        (self.var / "cache" / "big.npz").write_bytes(b"0" * 1000)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def make(self):
        return backup.create(Path(self.folder.name) / "out", self.var, self.db)

    def test_create_and_verify(self):
        path = self.make()
        names = set(zipfile.ZipFile(path).namelist())
        self.assertIn("console.sqlite3", names)
        self.assertIn("settings.json", names)
        self.assertTrue(any(n.startswith("audit_archive/") for n in names))
        self.assertFalse(any(n.startswith("cache/") for n in names))
        result = backup.verify(path)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["chain"]["ok"])
        self.assertEqual(result["chain"]["checked"], 6)      # 4 archived, the archiving entry, one after

    def test_a_changed_backup_does_not_verify(self):
        path = self.make()
        tampered = path.with_name("tampered.zip")
        with zipfile.ZipFile(path) as src, zipfile.ZipFile(tampered, "w") as dst:
            for item in src.infolist():
                data = src.read(item)
                dst.writestr(item, data.replace(b"Analyst A", b"Analyst B") if item.filename == "settings.json" else data)
        result = backup.verify(tampered)
        self.assertFalse(result["ok"])
        self.assertIn("hash differs: settings.json", result["problems"])

    def test_a_path_outside_the_folder_is_refused(self):
        path = self.make()
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("../escape.txt", "x")
        self.assertFalse(backup.verify(path)["ok"])
        self.assertFalse((Path(self.folder.name) / "escape.txt").exists())

    def test_restore_puts_it_back_and_keeps_what_it_replaces(self):
        path = self.make()
        store.log_action("tester", "later_change", "object/y", {})
        gc.collect()
        result = backup.restore(path, self.var, check_service=False)
        self.assertGreaterEqual(result["moved_aside"], 2)
        self.assertTrue((result["aside"] / "console.sqlite3").is_file())
        with closing(sqlite3.connect(self.db)) as con:
            actions = [a for (a,) in con.execute("SELECT action FROM audit")]
        self.assertNotIn("later_change", actions)
        self.assertTrue(store.verify_audit()["ok"])

    def test_restore_refuses_while_the_service_runs(self):
        path = self.make()
        with mock.patch.object(backup, "service_running", return_value=True), self.assertRaises(RuntimeError):
            backup.restore(path, self.var)
        self.assertTrue(self.db.is_file())

    def test_rehearsal(self):
        result = backup.rehearse(self.var, self.db)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["same_tables_and_rows"])


if __name__ == "__main__":
    unittest.main()
