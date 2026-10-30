"""Sigma as a fifth detector: hits flag the observations that hold their lines, in uploads (service/scoring.py,
analyze.py) and over the year's validation and test periods (service/sigma_review.py, cluster_index.py), and
Review lists any group holding one whatever its lift (service/clusters.py).

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_sigma_review -v
"""
from __future__ import annotations

import csv
import gc
import json
import sqlite3
from contextlib import closing
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import analyze, cluster_index, clusters, scoring, sigma, sigma_review, store, whitelist  # noqa: E402

AUTH = "Jul 14 {t} host-a sshd[{pid}]: [ID 800047 auth.info] {msg}"
GUESSING = (sigma.STARTER / "10_auth_ssh_guessing.yml").read_text(encoding="utf-8")


def guesses(n: int = 9, pid: int = 100) -> list[str]:
    return [AUTH.format(t=f"12:04:{30 + i * 3:02d}", pid=pid + i, msg="Failed password for root from 192.0.2.17 port 5000 ssh2")
            for i in range(n)]


def write(path: Path, columns: list[str], rows: list[list]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        writer.writerows(rows)


class Temporary(unittest.TestCase):
    """A console store and a cluster index of its own; Review's pass never starts on data/."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.folder.name)
        self.patches = [mock.patch.object(whitelist, "usual", return_value=None), mock.patch.object(store, "STORE_FILE", self.root / "console.sqlite"), mock.patch.object(store, "VAR", self.root),
                        mock.patch.object(store, "ADMIN_FILE", self.root / "admin.json"),
                        mock.patch.object(cluster_index, "DATA", self.root), mock.patch.object(cluster_index, "CACHE", self.root / "cache"),
                        mock.patch.object(cluster_index, "INDEX_FILE", self.root / "cache" / "index.sqlite"),
                        mock.patch.object(sigma_review, "DATA", self.root), mock.patch.object(cluster_index, "refresh")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()


class Uploads(Temporary):
    def test_the_enabled_rules_name_the_lines_they_hit(self):
        lines = guesses() + [AUTH.format(t="12:30:00", pid=300, msg="Accepted publickey for ops from 192.0.2.20 port 5100 ssh2")]
        hits = sigma.line_hits("auth", analyze._parse("auth", lines, "2026-07"), "")
        self.assertEqual(sorted(hits), list(range(1, 10)))                      # not the later login
        self.assertIn("SSH password guessing from one source", hits[1])

    def test_a_hit_flags_its_lines_and_every_observation_holding_them(self):
        lines = guesses(2) + [AUTH.format(t="12:30:00", pid=300, msg="Accepted publickey for ops from 192.0.2.20 port 5100 ssh2")]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            scoring._phase1_auth(lines, "2026-07", folder)
            lineages: dict = {}
            frames = scoring._phase2("auth", folder, lineages)
            known = scoring._sigma_rows("auth", folder, {1: ["guessing"], 2: ["guessing"]}, lineages)
        self.assertEqual(len(known["individual"]), 2)                           # the two guessed lines, not the login
        self.assertEqual(len(known["authentication_sessions"]), 1)              # the guesses' session (one address), not the login's
        self.assertEqual(len(frames["authentication_sessions"]), 2)
        self.assertEqual(list(known["host_5min"].values()), [["guessing"]])     # both in one 5-minute window
        self.assertEqual(scoring._sigma_rows("auth", Path(tmp), {}, lineages), {})


class YearPass(Temporary):
    """Phase 2's store, Phase 3's split and lineage, read in chunks."""

    VIEWS = ["individual", "authentication_sessions"]

    def setUp(self):
        super().setUp()
        self.begin = datetime(2026, 6, 1)                                       # the validation period starts here
        epoch = lambda t: t.replace(tzinfo=timezone.utc).timestamp()           # local time read as UTC, as Phase 2 does
        meta = {"split_metadata": {"train_boundary_epoch": epoch(self.begin) - 3600, "purge_gap_seconds": 3600,
                                   "validation_boundary_epoch": epoch(self.begin) + 30 * 86400}}
        for view in self.VIEWS:
            path = self.root / "phase3_features" / "auth" / view / "metadata.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(meta), encoding="utf-8")
        self.store = self.root / "store.sqlite"
        con = sqlite3.connect(self.store)
        con.execute("CREATE TABLE events (record_id TEXT PRIMARY KEY, timestamp_text TEXT, timestamp_epoch REAL, hostname TEXT, host_id TEXT, "
                    "process_name TEXT, username TEXT, source_ip TEXT, event_type TEXT, original_log_line TEXT)")
        boundary = self.begin + sigma_review.CHUNK                            # the second chunk starts here
        rows, lineage = [], []
        # 8 guesses within 2 minutes across the chunk boundary, one before the validation period, one far away
        times = [boundary + timedelta(seconds=s) for s in range(-40, 40, 10)] + [self.begin - timedelta(hours=3), boundary + timedelta(days=1)]
        for i, t in enumerate(times):
            rows.append((f"r{i}", f"{t:%Y-%m-%d %H:%M:%S}", epoch(t), "host-a", "host-a", "sshd", "root", "192.0.2.17", "SSH_LOGIN_FAILED",
                         f"{t:%b %d %H:%M:%S} host-a sshd[{i}]: Failed password for root from 192.0.2.17"))
            lineage.append([f"s{i // 2}", "1", f"r{i}", f"{t:%Y-%m-%d %H:%M:%S}"])
        con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
        con.close()
        write(self.root / "phase3_features" / "auth" / "authentication_sessions" / "test_lineage.csv",
              ["row_manifest_id", "event_position", "record_id", "event_timestamp"], lineage)
        self.docs = mock.patch.object(sigma, "enabled_docs", return_value=(sigma.parse(GUESSING, 1), "rules-1"))
        self.docs.start()

    def tearDown(self):
        self.docs.stop()
        super().tearDown()

    def test_a_correlation_across_chunks_is_found_whole(self):
        found = sigma_review.scan("auth", self.store, "record_id", self.VIEWS)
        self.assertEqual(sorted(found["individual"]), [f"r{i}" for i in range(8)])            # not the training line, not the stray
        self.assertEqual(sorted(found["authentication_sessions"]), ["s0", "s1", "s2", "s3"])
        self.assertEqual(found["individual"]["r0"], {"SSH password guessing from one source"})

    def test_the_training_period_is_checked_on_its_own(self):
        epoch = lambda t: t.replace(tzinfo=timezone.utc).timestamp()
        early = self.begin - timedelta(days=10)                               # 8 guesses inside training
        with closing(sqlite3.connect(self.store)) as con, con:
            con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", [
                (f"t{i}", f"{t:%Y-%m-%d %H:%M:%S}", epoch(t), "host-a", "host-a", "sshd", "root", "192.0.2.17", "SSH_LOGIN_FAILED",
                 f"{t:%b %d %H:%M:%S} host-a sshd[{i}]: Failed password for root from 192.0.2.17")
                for i, t in enumerate(early + timedelta(seconds=10 * k) for k in range(8))])
        result = sigma_review.training("auth", self.store, "record_id", self.VIEWS)
        self.assertEqual(result, {"events": 8, "rules": {"SSH password guessing from one source": 8}})   # not validation's
        self.assertIsNone(sigma_review.training("auth", self.root / "gone.sqlite", "record_id", self.VIEWS))

    def test_the_stamp_follows_the_rules(self):
        first = sigma_review.stamp("auth", self.store, self.VIEWS)
        with mock.patch.object(sigma, "enabled_docs", return_value=([], "rules-2")):
            self.assertNotEqual(sigma_review.stamp("auth", self.store, self.VIEWS), first)
        self.assertIsNone(sigma_review.stamp("auth", self.root / "gone.sqlite", self.VIEWS))

    def test_the_index_marks_members_and_scores(self):
        key = "auth/authentication_sessions"
        con = cluster_index._connect()
        try:
            con.executemany("INSERT INTO members (view_key, cluster, row_id, flagged) VALUES (?,?,?,?)",
                            [(key, "c#1", "s0", 0), (key, "c#1", "s1", 1), (key, "c#2", "s4", 0)])
            con.execute("INSERT INTO scores (view_key, row_id) VALUES (?, 's0')", (key,))
            con.commit()
            with mock.patch.object(cluster_index, "_source_views", return_value=self.VIEWS), \
                    mock.patch.dict(cluster_index.STORES, {"auth": (self.store, "record_id")}):
                cluster_index._build_sigma(con, "auth", "stamp-1")
            cluster_index._add_sigma_scores(con, key)
            con.commit()
            marked = dict(con.execute("SELECT row_id, sigma FROM members WHERE view_key=?", (key,)).fetchall())
            why = con.execute("SELECT sigma_alert, sigma_why FROM scores WHERE row_id='s0'").fetchone()
            built = cluster_index._sigma_built(con, "auth")
        finally:
            con.close()
        self.assertEqual(marked, {"s0": 1, "s1": 1, "s4": 0})
        self.assertEqual((why[0], json.loads(why[1])), (1, ["SSH password guessing from one source"]))
        self.assertEqual(built, "stamp-1")
        groups = cluster_index.sigma_groups("auth", "authentication_sessions")
        self.assertEqual(groups, {"c#1": {"rules": {"SSH password guessing from one source": 2}, "only": 1}})   # s0: Sigma alone


class Queue(unittest.TestCase):
    """Review lists a group holding a Sigma hit whatever its lift."""

    def queue(self, sigma_groups: dict) -> list[dict]:
        listed = [{"cluster_id": "c#1", "flagged_rows": 0, "lift": 0.4}, {"cluster_id": "c#2", "flagged_rows": 5, "lift": 3.0},
                  {"cluster_id": "c#3", "flagged_rows": 2, "lift": 1.1}]
        with mock.patch.object(clusters, "list_clusters", return_value=listed), \
                mock.patch.object(clusters, "model_status", return_value={"used": True}), \
                mock.patch.object(clusters.store, "latest_reviews", return_value={}), \
                mock.patch.object(clusters.cluster_index, "validation_groups", return_value=[]), \
                mock.patch.object(clusters.cluster_index, "sigma_groups", return_value=sigma_groups), \
                mock.patch.object(clusters.whitelist, "mark", side_effect=lambda source, items: items):
            return clusters.review_queue("auth", "authentication_sessions")

    def test_lift_alone_without_sigma(self):
        self.assertEqual([c["cluster_id"] for c in self.queue({})], ["c#2"])

    def test_a_sigma_hit_lists_its_group_with_its_rules(self):
        out = {c["cluster_id"]: c for c in self.queue({"c#1": {"rules": {"guessing": 3, "spraying": 1}, "only": 3}})}
        self.assertEqual(set(out), {"c#1", "c#2"})
        self.assertEqual(out["c#1"]["flagged_rows"], 3)                         # the ones only Sigma flags count as unusual
        self.assertEqual(out["c#1"]["sigma"], [{"title": "guessing", "observations": 3}, {"title": "spraying", "observations": 1}])
        self.assertEqual(out["c#2"]["sigma"], [])


if __name__ == "__main__":
    unittest.main()
