"""Frequent subsequences (Phase 4f) in the console: uploads scored with the saved step model (service/sequences.py),
and Review's index keeping the detector's flags, scores and explanations (service/cluster_index.py).

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_sequences -v
"""
from __future__ import annotations

import csv
import gc
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import cluster_index as ci  # noqa: E402
from service import scoring, sequences  # noqa: E402

AUTH = ["Jul 14 16:20:37 host-a sshd[27857]: [ID 800047 auth.info] Failed password for invalid user staff08 from 192.0.2.17 port 50123 ssh2",
        "Jul 14 16:20:44 host-a sshd[27857]: [ID 800047 auth.info] Connection closed by 192.0.2.17 port 50123 [preauth]",
        "Jul 14 16:21:02 host-a sshd[27900]: [ID 800047 auth.info] Accepted publickey for ops from 192.0.2.20 port 50200 ssh2",
        "Jul 14 16:33:08 host-a su: [ID 366847 auth.notice] 'su root' succeeded for root on /dev/pts/2"]
OSSEC = ["2026/07/14 16:20:37 ossec-agentd: INFO: Trying to connect to server (ossec-server/192.0.2.1:1514).",
         "2026/07/14 16:20:38 ossec-agentd: INFO: Using IPv4 for: 192.0.2.1 .",
         "2026/07/14 16:30:00 ossec-syscheckd: INFO: Starting syscheck scan.",
         "2026/07/14 16:41:00 ossec-syscheckd: INFO: Ending syscheck scan."]


def write(path: Path, columns: list[str], rows: list[list]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        writer.writerows(rows)


class Uploads(unittest.TestCase):
    """The upload's Phase 2 output read into Phase 4f's streams and scored at the saved threshold."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.data = Path(self.folder.name)
        self.patches = [mock.patch.object(sequences, "DATA", self.data), mock.patch.object(sequences, "CACHE", self.data / "cache")]
        for p in self.patches:
            p.start()
        sequences._detector.cache_clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        sequences._detector.cache_clear()
        gc.collect()
        self.folder.cleanup()

    def trained(self, source: str, transitions: dict, unigrams: dict, threshold: float = 8.0) -> None:
        """A stand-in for mine.py's model.json and rules.csv, and score.py's summary.json."""
        p = sequences.paths(source)
        p["model"].parent.mkdir(parents=True, exist_ok=True)
        p["model"].write_text(json.dumps({"transitions": transitions, "unigrams": unigrams}), encoding="utf-8")
        write(p["rules"], ["scope", "antecedent", "then", "confidence"], [])
        p["summary"].parent.mkdir(parents=True, exist_ok=True)
        p["summary"].write_text(json.dumps({"threshold": threshold}), encoding="utf-8")

    def upload(self, source: str, lines: list[str]):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (scoring._phase1_auth(lines, "2026-07", folder) if source == "auth"
             else scoring._phase1_ossec(lines, "2026-07", folder, "host-a"))
            frame = scoring._phase2(source, folder)[sequences.VIEWS[source]]
            return frame, sequences._units(source, folder), sequences.score_upload(source, folder)

    def test_the_replay_gives_phase2s_own_observations(self):
        for source, lines in (("auth", AUTH), ("ossec", OSSEC)):
            frame, units, _ = self.upload(source, lines)
            self.assertEqual(sorted(u[0] for u in units), sorted(frame["row_manifest_id"]), source)

    def test_without_phase4f_nothing_is_scored(self):
        self.assertEqual(self.upload("auth", AUTH)[2], {})

    def test_a_step_never_seen_is_flagged_and_explained(self):
        self.trained("auth", {"*": {"SSH_LOGIN_FAILED": {"<end>": 500}}, "host-a": {"SSH_LOGIN_FAILED": {"<end>": 50}}},
                     {"SSH_LOGIN_FAILED": 500, "SSH_CONNECTION_CLOSED": 500, "SSH_LOGIN_SUCCESS": 500, "SU_SESSION_SUCCESS": 500, "<end>": 1500})
        frame, units, scored = self.upload("auth", AUTH)
        failed = next(u[0] for u in units if u[2][0]["type"] == "SSH_LOGIN_FAILED")
        self.assertTrue(scored[failed]["alert"])
        self.assertEqual(scored[failed]["rarest_step"], "SSH_LOGIN_FAILED > SSH_CONNECTION_CLOSED")
        self.assertIn("never seen in training on any host", scored[failed]["explanation"])

    def test_a_usual_routine_is_not_flagged(self):
        usual = {"SSH_LOGIN_FAILED": {"SSH_CONNECTION_CLOSED": 5000}, "SSH_CONNECTION_CLOSED": {"<end>": 5000},
                 "SU_SESSION_SUCCESS": {"<end>": 5000}, "SSH_LOGIN_SUCCESS": {"<end>": 5000}}
        self.trained("auth", {"*": usual, "host-a": usual},
                     {"SSH_LOGIN_FAILED": 5000, "SSH_CONNECTION_CLOSED": 5000, "SSH_LOGIN_SUCCESS": 5000, "SU_SESSION_SUCCESS": 5000, "<end>": 15000})
        _, _, scored = self.upload("auth", AUTH)
        self.assertTrue(scored)
        self.assertFalse(any(s["alert"] for s in scored.values()))
        self.assertTrue(all(s["explanation"] == "" for s in scored.values()))

    def test_the_uploads_own_start_and_open_end_are_not_scored(self):
        # every session starts within 15 minutes of the upload's first line, and the login is still open at the end:
        # a model that has never seen any of it still has nothing to say about that one-step session
        self.trained("auth", {"*": {}}, {"<end>": 1}, threshold=1.0)
        _, units, scored = self.upload("auth", AUTH)
        login = next(u[0] for u in units if u[2][0]["type"] == "SSH_LOGIN_SUCCESS")
        self.assertEqual(scored[login]["score"], 0.0)
        self.assertFalse(scored[login]["alert"])

    def test_ossec_episodes_are_scored(self):
        self.trained("ossec", {"*": {}}, {"<end>": 100_000}, threshold=5.0)      # its event types: never seen in training
        _, units, scored = self.upload("ossec", OSSEC)
        self.assertEqual(set(scored), {u[0] for u in units})
        self.assertTrue(any(s["alert"] for s in scored.values()))


class ReviewIndex(unittest.TestCase):
    """The sequence detector's flags, scores and explanations in Review's index."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.folder.name)
        self.patches = [mock.patch.object(ci, "DATA", self.root), mock.patch.object(ci, "CACHE", self.root / "cache"),
                        mock.patch.object(ci, "INDEX_FILE", self.root / "cache" / "index.sqlite")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def test_an_index_from_before_phase4f_gains_the_columns(self):
        (self.root / "cache").mkdir()
        old = sqlite3.connect(self.root / "cache" / "index.sqlite")
        old.execute("CREATE TABLE scores (view_key TEXT, row_id TEXT, host TEXT, t TEXT, robust REAL, robust_alert INTEGER, robust_why TEXT, "
                    "isolation_forest REAL, isolation_forest_alert INTEGER, novelty REAL, novelty_alert INTEGER, novelty_why TEXT, "
                    "ensemble REAL, ensemble_alert INTEGER, votes INTEGER, PRIMARY KEY (view_key, row_id)) WITHOUT ROWID")
        old.execute("INSERT INTO scores (view_key, row_id) VALUES ('auth/authentication_sessions', 'kept')")
        old.commit()
        old.close()
        con = ci._connect()
        try:
            columns = {row[1] for row in con.execute("PRAGMA table_info(scores)")}
            kept = con.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
        finally:
            con.close()
        self.assertTrue({"sequence", "sequence_alert", "sequence_why"} <= columns)
        self.assertEqual(kept, 1)

    def test_test_period_scores_carry_the_sequence_detector(self):
        view, key = "authentication_sessions", "auth/authentication_sessions"
        p4 = self.root / "phase4_detection" / "auth"
        write(p4 / "detectors" / view / "test_scores.csv",
              ["row_manifest_id", "host_id", "session_start", "robust_score", "robust_alert", "isolation_score", "isolation_alert",
               "novelty_score", "novelty_alert"],
              [["s1", "host02", "2026-06-17 02:00:00", "0.1", "False", "0.2", "False", "0.1", "False"],
               ["s2", "host02", "2026-06-17 02:05:00", "0.1", "False", "0.9", "True", "0.1", "False"]])
        write(self.root / "phase7b_clusters" / "auth" / view / "row_clusters.csv",
              ["row_manifest_id", "cluster_id", "zoo_votes", "ensemble_score", "ensemble_alert"],
              [["s1", f"{view}#1", "0", "0.1", "False"], ["s2", f"{view}#1", "0", "0.1", "False"]])
        write(p4 / "sequences" / view / "test_scores.csv", ci.SEQUENCE_COLUMNS,
              [["s1", "14.2", "True", "rarest step A > B: never on host02 in training"], ["s2", "1.1", "False", ""]])
        con = ci._connect()
        try:
            con.executemany("INSERT INTO members (view_key, cluster, row_id, flagged) VALUES (?,?,?,1)",
                            [(key, f"{view}#1", "s1"), (key, f"{view}#1", "s2")])
            con.commit()
            ci._build_scores(con, "auth", view)
            stamp = con.execute("SELECT stamp FROM score_views WHERE view_key=?", (key,)).fetchone()[0]
        finally:
            con.close()
        rows = {r["row_id"]: r for r in ci.flagged_scores("auth", view, f"{view}#1", limit=None)}
        self.assertEqual((rows["s1"]["sequence_alert"], rows["s1"]["sequence"]), (1, 14.2))
        self.assertEqual((rows["s2"]["sequence_alert"], rows["s2"]["isolation_forest_alert"]), (0, 1))
        self.assertEqual(ci.score_row("auth", view, "s1")["sequence_why"], "rarest step A > B: never on host02 in training")
        self.assertEqual(stamp, ci._scores_stamp(ci._connect(), "auth", ci._score_inputs("auth", view)))    # a later start finds it current

    def test_validation_observations_flagged_only_by_order_are_grouped(self):
        view = "individual"                                    # the mechanics; Phase 4f itself scores sessions and episodes
        p4 = self.root / "phase4_detection" / "auth"
        columns = ["row_manifest_id", "timestamp", "host_id", "username", "source_ip", "robust_score", "robust_alert",
                   "robust_explanation", "isolation_score", "isolation_alert", "novelty_score", "novelty_alert", "novelty_explanation"]
        write(p4 / "detectors" / view / "validation_scores.csv", columns,
              [[f"v{i}", "2026-04-16 10:18:10", "host02", "staff03", "203.0.113.2", "0.1", "False", "", "0.1", "False", "0.1", "False", ""]
               for i in range(4)])
        write(p4 / "model_zoo" / view / "selected" / "validation_scores.csv",
              ["row_manifest_id", "model_zoo_ensemble_score", "model_zoo_ensemble_alert", "member_vote_count"],
              [[f"v{i}", "0.1", "False", "0"] for i in range(4)])
        write(p4 / "sequences" / view / "validation_scores.csv", ci.SEQUENCE_COLUMNS,
              [["v0", "12.5", "True", "rarest step (start) > SSH_LOGIN_FAILED: 1 in 4,000 on host02"]]
              + [[f"v{i}", "0.5", "False", ""] for i in range(1, 4)])
        con = ci._connect()
        try:
            ci._build_validation(con, "auth", view)
        finally:
            con.close()
        ci._status[f"auth/{view}:validation"] = "ready"
        groups = ci.validation_groups("auth", view)
        self.assertEqual([(g["rows"], g["flagged"]) for g in groups], [(4, 1)])
        rows = ci.flagged_scores("auth", view, groups[0]["gid"], limit=None)
        self.assertEqual([(r["row_id"], r["sequence_alert"], r["sequence"]) for r in rows], [("v0", 1, 12.5)])


if __name__ == "__main__":
    unittest.main()
