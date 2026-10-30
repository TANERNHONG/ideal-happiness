"""Tests for the validation period in Review (service/cluster_index.py, fourth pass): flagged
validation observations grouped by server and source address, with how often each group and the
view were flagged, the accounts as top values, scores and votes kept, and stable group IDs.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import csv
import gc
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import cluster_index as ci  # noqa: E402

DETECTOR_COLUMNS = ["row_manifest_id", "timestamp", "host_id", "username", "source_ip", "robust_score", "robust_alert",
                    "robust_explanation", "isolation_score", "isolation_alert", "novelty_score", "novelty_alert", "novelty_explanation"]


def write(path: Path, columns: list[str], rows: list[list]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        writer.writerows(rows)


class ValidationGroups(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        self.patches = [mock.patch.object(ci, "DATA", root), mock.patch.object(ci, "CACHE", root / "cache"),
                        mock.patch.object(ci, "INDEX_FILE", root / "cache" / "index.sqlite")]
        for p in self.patches:
            p.start()
        rows, zoo = [], []
        # 203.0.113.2 on host02: 4 lines, 3 flagged (two by a detector, one by the zoo's ensemble only)
        for i, (alert, zoo_alert, user) in enumerate([("True", "False", "staff03"), ("True", "False", "staff03"), ("False", "True", "staff04"),
                                                      ("False", "False", "staff03")]):
            rows.append([f"a{i}", f"2026-04-16 10:18:1{i}", "host02", user, "203.0.113.2", "0.9", alert, "why", "0.5", "False", "0.1", "False", ""])
            zoo.append([f"a{i}", "0.99" if zoo_alert == "True" else "0.2", zoo_alert, "2" if zoo_alert == "True" else "0"])
        # busy and calm: 96 lines from 10.200.0.6, one flagged
        for i in range(96):
            flagged = "True" if i == 0 else "False"
            rows.append([f"b{i}", "2026-05-01 00:00:00", "host06", "staff03", "10.200.0.6", "0.1", flagged, "", "0.1", "False", "0.1", "False", ""])
            zoo.append([f"b{i}", "0.1", "False", "0"])
        p4 = root / "phase4_detection" / "auth"
        write(p4 / "detectors" / "individual" / "validation_scores.csv", DETECTOR_COLUMNS, rows)
        write(p4 / "model_zoo" / "individual" / "selected" / "validation_scores.csv",
              ["row_manifest_id", "model_zoo_ensemble_score", "model_zoo_ensemble_alert", "member_vote_count"], zoo)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def build(self):
        con = ci._connect()
        try:
            ci._build_validation(con, "auth", "individual")
        finally:
            con.close()
        ci._status["auth/individual:validation"] = "ready"
        return {g["source_ip"]: g for g in ci.validation_groups("auth", "individual")}

    def test_groups_counts_and_lift(self):
        groups = self.build()
        odd, calm = groups["203.0.113.2"], groups["10.200.0.6"]
        self.assertEqual((odd["host"], odd["rows"], odd["flagged"]), ("host02", 4, 3))
        self.assertEqual((calm["rows"], calm["flagged"]), (96, 1))
        self.assertAlmostEqual(odd["lift"], (3 / 4) / (4 / 100))          # the view: 4 of 100 flagged
        self.assertLess(calm["lift"], 1)
        self.assertEqual(odd["username"], "staff03 (67%); staff04 (33%)")   # accounts among the flagged

    def test_scores_votes_and_members(self):
        self.build()
        gid = ci.group_id("individual", ("host02", "203.0.113.2"))
        rows = {r["row_id"]: r for r in ci.flagged_scores("auth", "individual", gid, limit=None)}
        self.assertEqual(sorted(rows), ["a0", "a1", "a2"])
        self.assertEqual((rows["a2"]["ensemble_alert"], rows["a2"]["votes"], rows["a2"]["robust_alert"]), (1, 2, 0))

    def test_rebuild_keeps_ids_and_replaces_members(self):
        first = self.build()["203.0.113.2"]["gid"]
        again = self.build()["203.0.113.2"]
        self.assertEqual(again["gid"], first)
        self.assertEqual(len(ci.flagged_scores("auth", "individual", first, limit=None)), 3)


if __name__ == "__main__":
    unittest.main()
