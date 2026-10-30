"""Tests for Simple mode's uploads (service/uploads.py): an analysis kept as a review item, the
uploaded lines kept around each event, sending to a reviewer (Waiting for you) and clearing.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import store, uploads, whitelist  # noqa: E402

LINES = [
    "2026-07-14 16:15:00 host-a sshd: noise before",
    "2026-07-14 16:20:37 host-a sshd: Failed password for invalid user staff08 from 192.0.2.17",
    "2026-07-14 16:20:41 host-a sshd: Failed password for invalid user staff08 from 192.0.2.17",
    "2026-07-14 16:25:00 host-b sshd: another server",
    "2026-07-14 17:00:00 host-a sshd: long after",
]


def events():
    out = []
    for line in LINES:
        day, clock, host = line.split()[:3]
        out.append((datetime.fromisoformat(f"{day} {clock}"), host, "AUTH_FAILED" if "Failed" in line else "OTHER", line))
    return out


def fake_result():
    row = {"id": "7", "timestamp": "2026-07-14 16:20:37", "hostname": "host-a", "event_type": "AUTH_FAILED",
           "flags": ["robust"], "unusual": 0.9999, "map": {"cluster_id": "auth/individual#3"}}
    calm = {**row, "id": "8", "flags": [], "unusual": 0.4}
    return {"source": "auth", "month": "2026-07", "host": "", "lines": 5, "recognised": 5, "hosts": ["host-a", "host-b"],
            "span": {"first": "", "last": "", "hours": 1.0},
            "verdict": {"flagged": True, "method": "baseline"},
            "views": [{"view": "individual", "label": "Individual lines", "used": True, "observations": 2, "flagged": 1,
                       "max_unusual": 0.9999, "rows": [row, calm]},
                      {"view": "host_5min", "label": "5-minute windows", "used": False, "observations": 1, "flagged": 1,
                       "max_unusual": 0.99, "rows": [{**row, "id": "w1"}]}]}


class Uploads(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(whitelist, "usual", return_value=None), mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                        mock.patch.object(store, "ADMIN_FILE", folder / "admin.json")]     # never the real password file
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def kept(self):
        result = fake_result()
        items = uploads._items(result)
        for item in items:
            item["context"] = uploads._context(item, events())
        token = "t1"
        uploads._pending[token] = {"at": 1e12, "name": "authlog_host-a.txt", "result": result, "items": items}
        return uploads.keep(token, "ops-1")

    def test_time_to_label_runs_from_keeping_to_the_first_label(self):
        self.assertEqual(uploads.time_to_label(), {"n": 0})
        for upload_id, (kept_at, labels) in enumerate([("2026-10-01T09:00:00+08:00", ["2026-10-01T09:30:00+08:00", "2026-10-01T11:00:00+08:00"]),
                                                      ("2026-10-02T09:00:00+08:00", ["2026-10-02T13:00:00+08:00"]),
                                                      ("2026-10-03T09:00:00+08:00", [])], start=1):
            with uploads._connect() as con:
                con.execute("INSERT INTO uploads (id, created_at, created_by, name, source) VALUES (?, ?, 'ops-1', 'made-up.log', 'auth')",
                            (upload_id, kept_at))
                for n, at in enumerate(labels):
                    con.execute("INSERT INTO reviews (source, view, item_id, item_kind, verdict, note, reviewer, created_at) "
                                "VALUES ('auth', 'individual', ?, 'upload', 'expected_behavior', '', 'ops-1', ?)",
                                (f"upload-{upload_id}/individual:{n}", at))
        result = uploads.time_to_label()
        self.assertEqual(result["n"], 2)                                     # the third upload has no label yet
        self.assertEqual(result["median"], (30 + 240) / 2)                    # the first label of each: 30 and 240 minutes
        self.assertEqual((result["p10"], result["p90"]), (30 + 0.1 * 210, 30 + 0.9 * 210))

    def test_only_unusual_events_of_alert_views(self):
        items = uploads._items(fake_result())
        self.assertEqual([i["item_id"] for i in items], ["individual:7"])
        self.assertEqual(items[0]["host"], "host-a")

    def test_context_is_same_server_within_ten_minutes(self):
        item = uploads._items(fake_result())[0]
        context = uploads._context(item, events())
        lines = [c["line"] for c in context]
        self.assertIn(LINES[0], lines)                 # 5 minutes before, same server
        self.assertNotIn(LINES[3], lines)              # another server
        self.assertNotIn(LINES[4], lines)              # 40 minutes later
        self.assertEqual([c["line"] for c in context if c["own"]], [LINES[1]])

    def test_overlapping_views_merge_into_one_item(self):
        line = {"time": "2026-07-14 16:20:37", "line": LINES[1], "own": True}
        session = {"item_id": "authentication_sessions:1", "view": "authentication_sessions", "view_label": "Sessions",
                   "unusual": 0.99, "flags": ["novelty"], "context": [line]}
        single = {"item_id": "individual:7", "view": "individual", "view_label": "Individual lines",
                  "unusual": 0.9999, "flags": ["robust"], "context": [line]}
        other = {"item_id": "individual:9", "view": "individual", "view_label": "Individual lines",
                 "unusual": 0.5, "flags": ["robust"], "context": [{**line, "line": LINES[2]}]}
        merged = uploads._merge([single, other, session])
        self.assertEqual([i["item_id"] for i in merged], ["authentication_sessions:1", "individual:9"])
        self.assertEqual((merged[0]["also"], merged[0]["unusual"], merged[0]["flags"]), (["Individual lines"], 0.9999, ["novelty", "robust"]))

    def test_keep_list_assign_waiting(self):
        upload_id = self.kept()
        listed = uploads.list_uploads("someone-else")["uploads"]
        self.assertEqual((listed[0]["items"], listed[0]["reviewed"], listed[0]["waiting"]), (1, 0, False))
        sent = uploads.assign(upload_id, "Reviewer@example.org", "ops-1")
        self.assertTrue(sent["email"])
        self.assertTrue(uploads.list_uploads("reviewer@example.org")["uploads"][0]["waiting"])   # case does not matter
        self.assertEqual(uploads.reviewers(), ["Reviewer@example.org"])
        item = uploads.get_upload(upload_id)["items"][0]
        store.add_review("auth", item["view"], item["review_id"], "upload", "expected_behavior", "", "reviewer@example.org")
        self.assertFalse(uploads.list_uploads("reviewer@example.org")["uploads"][0]["waiting"])  # all reviewed
        self.assertEqual(uploads.get_upload(upload_id)["items"][0]["review"]["verdict"], "expected_behavior")

    def test_expired_analysis_cannot_be_kept(self):
        with self.assertRaises(KeyError):
            uploads.keep("missing", "ops-1")

    def test_clear_needs_the_password(self):
        upload_id = self.kept()
        with mock.patch.object(store.time, "sleep"):
            with self.assertRaises(PermissionError):
                uploads.clear(upload_id, "wrong", "ops-1")
        with mock.patch.object(store.time, "sleep"), self.assertRaises(store.DefaultPassword):
            uploads.clear(upload_id, store.DEFAULT_PASSWORD, "ops-1")                  # the default opens nothing
        store.change_password(store.DEFAULT_PASSWORD, "made-up-admin", "ops-1")
        uploads.clear(upload_id, "made-up-admin", "ops-1")
        self.assertEqual(uploads.list_uploads("ops-1")["uploads"], [])
        self.assertEqual(store.audit_log(1)[0]["action"], "upload_cleared")


if __name__ == "__main__":
    unittest.main()
