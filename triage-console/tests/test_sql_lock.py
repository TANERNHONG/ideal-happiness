"""The SQL password (service/sql_lock.py, store.py): unlocking, tokens, lapsing, changing; and the SQL routes refuse
without a token. Each test has its own store and password file.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_sql_lock -v
"""
from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import server, sql_lock, store  # noqa: E402


class SqlLock(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", root / "console.sqlite"), mock.patch.object(store, "VAR", root),
                        mock.patch.object(store, "SQL_PASSWORD_FILE", root / "sql_password.json"),
                        mock.patch.object(store.time, "sleep"), mock.patch.dict(sql_lock._tokens, clear=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def test_the_default_opens_nothing_until_changed(self):
        self.assertTrue(store.sql_password_is_default())
        with self.assertRaises(store.DefaultPassword) as refused:
            sql_lock.unlock("1234", "tester")
        self.assertEqual(refused.exception.which, "sql")
        with self.assertRaises(PermissionError):
            sql_lock.unlock("0000", "tester")                    # a wrong guess still says only that
        with self.assertRaises(ValueError):
            sql_lock.change("1234", "123456", "tester")         # the other default is no better
        sql_lock.change("1234", "made-up-pw", "tester")
        sql_lock.require(sql_lock.unlock("made-up-pw", "tester")["token"])

    def test_wrong_password_and_missing_token_refused(self):
        with self.assertRaises(PermissionError):
            sql_lock.unlock("0000", "tester")
        for token in (None, "", "made-up", 7):
            with self.subTest(token=token), self.assertRaises(sql_lock.Locked):
                sql_lock.require(token)

    def test_token_lapses_when_idle(self):
        sql_lock.change("1234", "made-up-pw", "tester")
        with mock.patch.object(sql_lock.time, "monotonic", return_value=1000.0):
            token = sql_lock.unlock("made-up-pw", "tester")["token"]
        with mock.patch.object(sql_lock.time, "monotonic", return_value=1000.0 + sql_lock.IDLE_SECONDS - 1):
            sql_lock.require(token)                              # still in time, and kept for another stretch
        with mock.patch.object(sql_lock.time, "monotonic", return_value=1000.0 + 2 * sql_lock.IDLE_SECONDS + 1):
            with self.assertRaises(sql_lock.Locked):
                sql_lock.require(token)

    def test_change_password_locks_everyone_out(self):
        sql_lock.change("1234", "made-up-pw", "tester")
        token = sql_lock.unlock("made-up-pw", "tester")["token"]
        with self.assertRaises(PermissionError):
            sql_lock.change("wrong", "longer-one", "tester")
        with self.assertRaises(ValueError):
            sql_lock.change("made-up-pw", "12345", "tester")    # under 6 characters
        sql_lock.change("made-up-pw", "longer-one", "tester")
        self.assertFalse(store.sql_password_is_default())
        with self.assertRaises(sql_lock.Locked):
            sql_lock.require(token)
        with self.assertRaises(PermissionError):
            sql_lock.unlock("made-up-pw", "tester")
        sql_lock.require(sql_lock.unlock("longer-one", "tester")["token"])

    def test_sql_routes_refuse_without_a_token(self):
        for route in ("/api/sql", "/api/sql/export", "/api/sql/schema"):
            with self.subTest(route=route), self.assertRaises(sql_lock.Locked):
                server.ROUTES[("POST", route)]({}, {"query": "SELECT 1"})

    def test_admin_password_unchanged_by_sql_password(self):
        with mock.patch.object(store, "ADMIN_FILE", Path(self.folder.name) / "admin.json"):
            sql_lock.change("1234", "longer-one", "tester")
            with self.assertRaises(store.DefaultPassword):       # still the admin default: right, but refused
                store.check_password(store.DEFAULT_PASSWORD)
            self.assertTrue(store.password_is_default())


if __name__ == "__main__":
    unittest.main()
