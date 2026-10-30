"""Tests for whitelisted users (service/whitelist.py): an override on the anomalies, set in Settings.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_whitelist -v
"""
from __future__ import annotations

import gc
import json
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import cluster_index, store, uploads, whitelist  # noqa: E402

PASSWORD = "made-up-admin"


class Whitelist(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(whitelist, "usual", return_value=None), mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                        mock.patch.object(store, "ADMIN_FILE", folder / "admin.json"),
                        mock.patch.object(cluster_index, "CACHE", folder), mock.patch.object(cluster_index, "INDEX_FILE", folder / "index.sqlite"),
                        mock.patch.object(store.time, "sleep")]
        for p in self.patches:
            p.start()
        store.change_password(store.DEFAULT_PASSWORD, PASSWORD, "tester")    # the default opens nothing
        whitelist._cover_cached.cache_clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        whitelist._cover_cached.cache_clear()
        gc.collect()
        self.folder.cleanup()

    def index(self, rows):
        """members (view_key, cluster, row_id, flagged) and review_facts (view_key, row_id, host, username)."""
        with closing(cluster_index._connect()) as con, con:
            con.execute("CREATE TABLE IF NOT EXISTS review_facts(view_key TEXT,row_id TEXT,host TEXT,username TEXT,program TEXT,address TEXT,"
                        " PRIMARY KEY(view_key,row_id,host,username,program,address)) WITHOUT ROWID")
            for view_key, cluster, row_id, flagged, facts in rows:
                con.execute("INSERT INTO members (view_key, cluster, row_id, flagged, t) VALUES (?,?,?,?, '2026-07-01')", (view_key, cluster, row_id, flagged))
                con.executemany("INSERT INTO review_facts VALUES (?,?,?,?,'sshd','')", [(view_key, row_id, h, u) for h, u in facts])

    # --- entries -------------------------------------------------------------------------------

    def test_add_needs_password_reason_and_a_valid_account(self):
        with self.assertRaises(PermissionError):
            whitelist.add("backup", "", "nightly job", "", "wrong", "ops-1")
        for bad in (("", "", "why", ""), ("two words", "", "why", ""), ("backup", "bad host!", "why", ""), ("backup", "", "", ""),
                    ("backup", "", "why", "not-a-date"), ("backup", "", "why", (date.today() - timedelta(days=1)).isoformat())):
            with self.assertRaises(ValueError, msg=bad):
                whitelist.add(*bad, PASSWORD, "ops-1")
        entry = whitelist.add("backup", "host06", "nightly job", "", PASSWORD, "ops-1")
        self.assertEqual((entry["username"], entry["host"], entry["added_by"]), ("backup", "host06", "ops-1"))
        with self.assertRaises(ValueError):                                # the same account on the same server twice
            whitelist.add("backup", "host06", "again", "", PASSWORD, "ops-1")
        self.assertEqual(store.audit_log(1)[0]["action"], "whitelist_add")

    def test_remove_needs_password_and_keeps_the_record(self):
        entry = whitelist.add("backup", "", "nightly job", "", PASSWORD, "ops-1")
        with self.assertRaises(PermissionError):
            whitelist.remove(entry["id"], "wrong", "ops-1")
        whitelist.remove(entry["id"], PASSWORD, "ops-2")
        self.assertEqual((whitelist.entries(), whitelist.active()), ([], frozenset()))
        with closing(store.connect()) as con:
            self.assertEqual(con.execute("SELECT removed_by FROM whitelist_users").fetchone()[0], "ops-2")
        self.assertEqual(store.audit_log(1)[0]["action"], "whitelist_remove")

    def test_an_entry_ends_after_its_last_day(self):
        whitelist.add("backup", "", "until today", date.today().isoformat(), PASSWORD, "ops-1")
        self.assertEqual(whitelist.active(), frozenset({("backup", "")}))
        with mock.patch.object(whitelist, "date", mock.Mock(wraps=date, today=lambda: date.today() + timedelta(days=1))):
            self.assertEqual(whitelist.active(), frozenset())
            self.assertTrue(whitelist.entries()[0]["expired"])

    # --- matching ------------------------------------------------------------------------------

    def test_every_account_named_must_be_whitelisted_on_its_server(self):
        allowed = frozenset({("backup", ""), ("deploy", "host06")})
        self.assertTrue(whitelist.covers([{"username": "backup", "host": "any"}], allowed))
        self.assertTrue(whitelist.covers([{"username": "deploy", "host": "host06"}, {"username": "", "host": "host06"}], allowed))
        self.assertFalse(whitelist.covers([{"username": "deploy", "host": "host07"}], allowed))               # another server
        self.assertFalse(whitelist.covers([{"username": "backup", "host": "a"}, {"username": "root", "host": "a"}], allowed))
        self.assertFalse(whitelist.covers([{"username": "", "host": "a"}], allowed))                          # names no account
        self.assertFalse(whitelist.covers([{"username": "Backup", "host": "a"}], allowed))                    # accounts are case-sensitive
        self.assertTrue(whitelist.covers_row({"username": "deploy", "hostname": "host06"}, allowed=allowed))
        self.assertTrue(whitelist.covers_row({"username": "deploy"}, host="host06", allowed=allowed))

    # --- never silenced ------------------------------------------------------------------------

    def test_a_switch_to_root_needs_an_entry_that_includes_it(self):
        allowed = whitelist.Allowed({("deploy", "")})
        su = {"username": "deploy", "host": "host06", "program": "su", "address": ""}
        self.assertFalse(whitelist.covers([su], allowed))
        self.assertTrue(whitelist.covers([{**su, "program": "sshd"}], allowed))
        allowed.privileged = frozenset({("deploy", "")})
        self.assertTrue(whitelist.covers([su], allowed))
        self.assertTrue(whitelist.covers([{**su, "program": "SUDO"}], allowed))

    def test_a_new_address_or_server_still_asks_for_review(self):
        allowed = whitelist.Allowed({("deploy", "")})
        known = {"deploy": frozenset({("source_ip", "192.0.2.5"), ("server", "host06")})}
        usual = {"username": "deploy", "host": "HOST06", "program": "sshd", "address": "192.0.2.5"}
        with mock.patch.object(whitelist, "usual", return_value=known):
            self.assertTrue(whitelist.covers([usual], allowed))
            self.assertFalse(whitelist.covers([{**usual, "address": "192.0.2.99"}], allowed))      # a new address
            self.assertFalse(whitelist.covers([{**usual, "host": "host07"}], allowed))             # a new server
            self.assertFalse(whitelist.covers_row({"username": "deploy", "hostname": "host06", "source_ip": "192.0.2.99"},
                                                  allowed=allowed))
        with mock.patch.object(whitelist, "usual", return_value={}):                             # no training activity
            self.assertTrue(whitelist.covers([{**usual, "address": "192.0.2.99"}], allowed))

    def test_the_su_option_is_kept_and_logged(self):
        whitelist.add("deploy", "", "release job", "", PASSWORD, "ops-1", privileged=True)
        whitelist.add("backup", "", "nightly job", "", PASSWORD, "ops-1")
        allowed = whitelist.active()
        self.assertEqual(allowed, frozenset({("deploy", ""), ("backup", "")}))
        self.assertEqual(allowed.privileged, frozenset({("deploy", "")}))
        self.assertEqual({e["username"]: e["privileged"] for e in whitelist.entries()}, {"deploy": 1, "backup": 0})
        self.assertIn('"su": true', store.audit_log(2)[1]["detail"])

    def test_a_group_with_a_switch_to_root_is_not_whitelisted(self):
        whitelist.add("staff08", "", "ops", "", PASSWORD, "ops-1")
        self.index([("auth/individual", "c1", "r1", 1, [("host-a", "staff08")]),
                    ("auth/individual", "c2", "r2", 1, [("host-a", "staff08")])])
        with closing(cluster_index._connect()) as con, con:
            con.execute("UPDATE review_facts SET program = 'su' WHERE row_id = 'r2'")
        whitelist._cover_cached.cache_clear()
        cover = whitelist.coverage("auth")
        self.assertEqual(cover.get(("individual", "c1")), (1, 1))
        self.assertIsNone(cover.get(("individual", "c2")))
        self.assertEqual(whitelist.row_ids("auth", "individual"), frozenset({"r1"}))

    def test_analyze_matches_a_window_by_the_accounts_of_its_lines(self):
        from service import analyze
        allowed = frozenset({("staff08", "")})
        event = lambda t, user, host="host-a": ("line", {"timestamp": f"2026-07-14 {t}", "host": host, "username": user}, True)
        parsed = [event("16:20:37", "staff08"), event("16:21:00", ""), event("16:30:00", "root"), event("16:21:30", "root", "host-b")]
        covered = analyze._covered(parsed, "", allowed)
        window = lambda start: {"window_start": f"2026-07-14 {start}", "host_id": "host-a"}
        self.assertTrue(covered("host_5min", window("16:20:00")))          # staff08 and a line with no account
        self.assertFalse(covered("host_5min", window("16:30:00")))         # root
        self.assertFalse(covered("host_5min", window("16:40:00")))         # no lines: names no account
        self.assertTrue(covered("individual", {"username": "staff08", "hostname": "host-a"}))
        self.assertFalse(covered("authentication_sessions", {"session_start": "2026-07-14 16:20:37"}))   # names no account
        self.assertFalse(analyze._covered(parsed, "", frozenset())("host_5min", window("16:20:00")))

    def test_a_group_is_whitelisted_only_when_all_its_flagged_events_are_covered(self):
        view = "auth/authentication_sessions"
        self.index([(view, "g1", "s1", 1, [("a", "backup")]), (view, "g1", "s2", 1, [("a", "backup"), ("a", "")]),
                    (view, "g1", "s3", 0, [("a", "root")]),                                 # not flagged: does not count
                    (view, "g2", "s4", 1, [("a", "backup")]), (view, "g2", "s5", 1, [("a", "backup"), ("a", "root")]),
                    (view, "g3", "s6", 1, [("a", "")])])
        self.assertEqual(whitelist.coverage("auth"), {})                                   # nothing whitelisted yet
        whitelist.add("backup", "", "nightly job", "", PASSWORD, "ops-1")
        self.assertEqual(whitelist.coverage("auth"), {("authentication_sessions", "g1"): (2, 2), ("authentication_sessions", "g2"): (2, 1)})
        self.assertEqual(whitelist.row_ids("auth", "authentication_sessions"), {"s1", "s2", "s4"})
        items = whitelist.mark("auth", [{"kind": "cluster", "view": "authentication_sessions", "item_id": g} for g in ("g1", "g2", "g3")])
        self.assertEqual([(i["whitelisted"], i["overridden"]) for i in items], [(2, True), (1, False), (0, False)])
        self.assertEqual(whitelist.entries()[0]["flagged"], 4)                             # flagged observations naming backup

    def test_without_the_facts_table_nothing_is_overridden(self):
        with closing(cluster_index._connect()) as con, con:
            con.execute("INSERT INTO members (view_key, cluster, row_id, flagged, t) VALUES ('auth/individual', 'g', 'r', 1, '')")
        whitelist.add("backup", "", "nightly job", "", PASSWORD, "ops-1")
        self.assertEqual(whitelist.coverage("auth"), {})
        self.assertIsNone(whitelist.entries()[0]["flagged"])

    # --- uploads --------------------------------------------------------------------------------

    def test_upload_events_of_whitelisted_accounts_need_no_review(self):
        whitelist.add("backup", "", "nightly job", "", PASSWORD, "ops-1")
        line = {"time": "2026-07-14 16:20:37", "line": "x", "own": True}
        items = [{"item_id": "individual:1", "view": "individual", "view_label": "Individual lines", "host": "a", "unusual": 0.99,
                  "flags": ["robust"], "context": [line], "facts": [{"host": "a", "username": "backup", "program": "sshd", "address": ""}]},
                 {"item_id": "individual:2", "view": "individual", "view_label": "Individual lines", "host": "a", "unusual": 0.9,
                  "flags": ["robust"], "context": [line], "facts": [{"host": "a", "username": "root", "program": "su", "address": ""}]}]
        result = {"source": "auth", "month": "2026-07", "host": "", "lines": 2, "recognised": 2, "hosts": ["a"], "span": {},
                  "verdict": {"flagged": True, "method": "baseline"}, "views": []}
        summary = uploads._summary(result, items)
        self.assertEqual((summary["unusual"], summary["whitelisted"], summary["accounts"], summary["rarest"]), (1, 1, ["backup"], 0.9))
        uploads._pending["t"] = {"at": 1e12, "name": "x", "result": result, "items": items}
        upload_id = uploads.keep("t", "ops-1")
        uploads.assign(upload_id, "reviewer", "ops-1")
        listed = uploads.list_uploads("reviewer")["uploads"][0]
        self.assertEqual((listed["items"], listed["reviewed"], listed["whitelisted"], listed["waiting"]), (2, 0, 1, True))
        got = uploads.get_upload(upload_id)["items"]
        self.assertEqual([i["whitelisted"] for i in got], [True, False])
        store.add_review("auth", got[1]["view"], got[1]["review_id"], "upload", "expected_behavior", "", "reviewer")
        self.assertFalse(uploads.list_uploads("reviewer")["uploads"][0]["waiting"])       # the rest is whitelisted


if __name__ == "__main__":
    unittest.main()
