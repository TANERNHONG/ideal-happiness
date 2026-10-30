"""Label yield per mechanism (service/yields.py) on a made-up index and made-up labels."""
from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import cluster_index, outliers, store, yields  # noqa: E402

MASKS = {"r1": 0b0001, "r2": 0b0110, "r3": 0b1000}          # Isolation Forest; model zoo + Novelty; subsequences


def review(verdict: str) -> dict:
    return {"verdict": verdict}


class Yields(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", root / "console.sqlite"), mock.patch.object(store, "VAR", root),
                        mock.patch.object(cluster_index, "CACHE", root), mock.patch.object(cluster_index, "INDEX_FILE", root / "index.sqlite"),
                        mock.patch.object(outliers, "masks", lambda source: MASKS if source == "auth" else None)]
        for p in self.patches:
            p.start()
        with closing(cluster_index._connect()) as con, con:
            con.executemany("INSERT INTO members (view_key, cluster, row_id, flagged, t) VALUES (?,?,?,?, '2026-07-01')",
                            [("auth/authentication_sessions", "c1", "r1", 1), ("auth/authentication_sessions", "c1", "r2", 1),
                             ("auth/authentication_sessions", "c1", "r3", 0),           # not flagged: its mechanism does not count
                             ("auth/authentication_sessions", "c2", "r3", 1)])

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def test_an_item_counts_for_every_mechanism_behind_it(self):
        with closing(cluster_index._connect()) as con:
            group = {"kind": "cluster", "view": "authentication_sessions", "period": "test", "item_id": "c1"}
            self.assertEqual(yields.mechanisms("auth", group, MASKS, con), ["isolation_forest", "model_zoo", "novelty"])
            self.assertEqual(yields.mechanisms("auth", {**group, "sigma": ["rule"]}, MASKS, con)[0], "sigma")
            self.assertEqual(yields.mechanisms("auth", {**group, "view": "individual"}, MASKS, con), ["other_views"])
        self.assertEqual(yields.mechanisms("ossec", {"kind": "activity_alert"}, None), ["activity"])
        self.assertEqual(yields.mechanisms("pf", {"kind": "presence_alert"}, None), ["presence"])

    def test_precision_per_mechanism(self):
        queues = {"auth": [
            {"kind": "cluster", "view": "authentication_sessions", "period": "test", "item_id": "c1", "review": review("security_relevant")},
            {"kind": "cluster", "view": "authentication_sessions", "period": "test", "item_id": "c2", "review": review("expected_behavior")},
            {"kind": "cluster", "view": "authentication_sessions", "period": "test", "item_id": "c3"},              # not labelled
            {"kind": "activity_alert", "review": review("suspicious")}]}
        store.add_review("auth", "individual", "upload-1/individual:0", "upload", "expected_behavior", "", "ops-1")
        store.add_review("auth", "individual", "upload-1/individual:0", "upload", "security_relevant", "made-up note", "ops-1")
        rows = {r["key"]: r for r in yields.summary(queues)}
        self.assertEqual(rows["isolation_forest"]["n"], 1)
        self.assertEqual(rows["isolation_forest"]["precision"], 1.0)
        self.assertEqual((rows["sequence"]["n"], rows["sequence"]["precision"], rows["sequence"]["expected"]), (1, 0.0, 1.0))
        self.assertEqual(rows["activity"]["precision"], 1.0)
        self.assertEqual((rows["uploads"]["n"], rows["uploads"]["security_relevant"]), (1, 1))      # the latest label only
        self.assertNotIn("other_views", rows)


if __name__ == "__main__":
    unittest.main()
