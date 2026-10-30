"""Validation's two halves (shared/calibration.py) in the model zoo, run end to end on a made-up Phase 3 folder with a
few fast models; and the helper itself.

    .venv/Scripts/python.exe -m unittest discover -s pipeline/phase4_detection -p "test_*.py" -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd
from scipy import sparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "shared"))
import calibration  # noqa: E402

MODELS = ("isolation_forest", "pca_reconstruction", "hbos", "ecod")


def made_up_features(folder: Path, dataset: str, rows=(600, 200, 200), width=12, seed=0):
    rng = np.random.default_rng(seed)
    folder = folder / dataset
    folder.mkdir(parents=True)
    start = pd.Timestamp("2026-01-01")
    offset = 0
    for name, n in zip(("train", "validation", "test"), rows):
        matrix = rng.gamma(2.0, 1.0, size=(n, width)).astype(np.float32)
        sparse.save_npz(folder / f"X_{name}.npz", sparse.csr_matrix(matrix))
        times = start + pd.to_timedelta(np.arange(offset, offset + n), unit="h")
        pd.DataFrame({"row_manifest_id": [f"{name}{i:04d}" for i in range(n)], "session_start": times.astype(str)}) \
            .to_csv(folder / f"{name}_rows.csv", index=False)
        offset += n
    pd.DataFrame({"feature_name": [f"count_{j}" for j in range(width)]}).to_csv(folder / "feature_names.csv", index=False)
    (folder / "metadata.json").write_text(json.dumps({"dataset": dataset, "feature_artifact_contract": "authlog_explainable_lineage",
                                                       "lineage_status": "complete"}), encoding="utf-8")


class Helper(unittest.TestCase):
    def test_halves_follow_time_not_file_order(self):
        order = np.array([3, 1, 0, 2])                     # row 3 is earliest
        choose, calibrate = calibration.halves(order)
        self.assertEqual(choose.tolist(), [False, True, False, True])
        self.assertEqual(calibrate.tolist(), [True, False, True, False])
        self.assertEqual(calibration.part(choose, calibrate).tolist(), ["calibration", "selection", "calibration", "selection"])
        both = calibration.halves(order, "all")
        self.assertTrue(both[0].all() and both[1].all())

    def test_rate_check(self):
        check = calibration.rate_check(10, 1000, 30, 1000)
        self.assertAlmostEqual(check["ratio"], 3.0)
        self.assertTrue(np.isnan(calibration.rate_check(0, 0, 3, 10)["ratio"]))


class ZooEndToEnd(unittest.TestCase):
    def run_zoo(self, mode):
        import auth_model_zoo
        tmp = Path(self.tmp.name)
        out = tmp / f"out_{mode}"
        argv = ["auth_model_zoo.py", "--features", str(tmp / "features"), "--output", str(out), "--dataset", "authentication_sessions",
                "--feature-set", "both", "--no-proxy-labels", "--calibration-split", mode, "-q",
                *[x for m in MODELS for x in ("--only-model", m)]]
        with mock.patch.object(sys, "argv", argv):
            auth_model_zoo.main()
        return out / "authentication_sessions"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        made_up_features(Path(self.tmp.name) / "features", "authentication_sessions")
        empty = Path(self.tmp.name) / "windows.csv"
        empty.write_text("start,end,hosts,reason\n", encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {"HUH_CHANGE_WINDOWS": str(empty)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_choosing_and_calibrating_halves(self):
        folder = self.run_zoo("halves")
        for feature_set in ("full", "selected"):
            summary = json.loads((folder / feature_set / "dataset_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["calibration_split"], "halves")
            self.assertEqual((summary["validation_selection_rows"], summary["validation_calibration_rows"]), (100, 100))
            self.assertIn("ratio", summary["ensemble_calibration"])
            parts = pd.read_csv(folder / feature_set / "validation_scores.csv")["validation_part"]
            self.assertEqual(parts.value_counts().to_dict(), {"selection": 100, "calibration": 100})
        relevance = pd.read_csv(folder / "feature_relevance.csv")
        self.assertGreater(len(relevance), 0)

    def test_all_is_the_earlier_behaviour(self):
        folder = self.run_zoo("all")
        summary = json.loads((folder / "full" / "dataset_summary.json").read_text(encoding="utf-8"))
        self.assertEqual((summary["validation_selection_rows"], summary["validation_calibration_rows"]), (200, 200))
        self.assertEqual(set(pd.read_csv(folder / "full" / "validation_scores.csv")["validation_part"]), {"all"})


if __name__ == "__main__":
    unittest.main()


class Families(unittest.TestCase):
    def test_near_copies_form_one_family(self):
        import zoo_families
        rng = np.random.default_rng(5)
        base, other = rng.normal(size=2000), rng.normal(size=2000)
        scores = pd.DataFrame({"pca": base, "svd": base + rng.normal(scale=0.05, size=2000), "iforest": other})
        alerts = scores >= scores.quantile(0.98)
        sim = zoo_families.similarity(alerts, scores, rng)
        self.assertGreater(sim.loc["pca", "svd"], 0.9)
        self.assertLess(sim.loc["pca", "iforest"], 0.2)
        self.assertEqual(zoo_families.families(sim, 0.6), [["pca", "svd"], ["iforest"]])
        self.assertEqual(zoo_families.families(sim.loc[["pca"], ["pca"]], 0.6), [["pca"]])

    def test_the_step_runs_on_a_zoo_and_phase7_prefers_it(self):
        import zoo_families
        tmp = Path(tempfile.mkdtemp())
        made_up_features(tmp / "features", "authentication_sessions")
        empty = tmp / "windows.csv"
        empty.write_text("start,end,hosts,reason\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"HUH_CHANGE_WINDOWS": str(empty)}):
            import auth_model_zoo
            argv = ["auth_model_zoo.py", "--features", str(tmp / "features"), "--output", str(tmp / "zoo"), "--dataset",
                    "authentication_sessions", "--feature-set", "full", "--no-proxy-labels", "-q",
                    *[x for m in MODELS for x in ("--only-model", m)]]
            with mock.patch.object(sys, "argv", argv):
                auth_model_zoo.main()
        self.assertEqual(zoo_families.main(["--source", "auth", "--zoo", str(tmp / "zoo"), "-q"]), 0)
        folder = tmp / "zoo" / "authentication_sessions" / "full"
        found = json.loads((folder / "families.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(m for family in found["families"] for m in family), sorted(found["members"]))
        consensus = pd.read_csv(folder / "consensus_alerts_families.csv")
        self.assertTrue((consensus["family_vote_count"] >= found["min_families"]).all())
        self.assertTrue((tmp / "zoo" / "families_summary.csv").is_file())
        sys.path.insert(0, str(HERE.parent / "phase7_alerts"))
        import collect_alerts

        class Log:
            def write(self, *a, **k):
                pass
        frames = collect_alerts.zoo_alerts(tmp / "zoo", Log())
        self.assertEqual(len(frames[0]), len(consensus))                          # the family consensus, not the vote file
