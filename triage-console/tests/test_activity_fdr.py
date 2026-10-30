"""Phase 4g's false-discovery step and shrunk baselines (activity_detectors: null_p, fdr_pass, shrink,
choose_shrinkage) on made-up numbers, and their record in the run summary."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests import test_activity as made_up  # noqa: E402

activity = made_up.activity


class NullP(unittest.TestCase):
    def test_body_is_empirical_and_the_tail_keeps_falling(self):
        rng = np.random.default_rng(1)
        null = np.sort(np.abs(rng.normal(size=5000)))
        p = activity.null_p(null, np.array([0.0, 1.0, null.max() + 2, null.max() + 6]))
        self.assertAlmostEqual(p[0], 1.0, places=3)
        self.assertAlmostEqual(p[1], np.mean(null >= 1.0), delta=0.01)
        self.assertLess(p[2], 1 / len(null))                         # beyond every null step: below 1 / (n + 1)
        self.assertLess(p[3], p[2] * 1e-3)

    def test_ties_still_give_a_tail(self):
        null = np.sort(np.repeat([0.0, 0.5, 1.0, 1.39, 2.02], [400, 300, 120, 15, 5]))
        self.assertLess(activity.null_p(null, np.array([6.0]))[0], 1 / (len(null) + 1) / 100)   # far below the empirical floor


class FdrPass(unittest.TestCase):
    def frame(self, z, day):
        return pd.DataFrame({"robust_z": z, "step": np.asarray(day) * activity.STEPS_PER_DAY})

    def test_a_strong_burst_is_found_and_null_like_days_are_not(self):
        rng = np.random.default_rng(2)
        null = np.abs(rng.normal(size=20000))
        quiet = np.abs(rng.normal(size=288))
        burst = quiet.copy()
        burst[100:110] = 8.0
        z = np.concatenate([null, quiet, burst])
        day = np.concatenate([np.zeros(20000), np.ones(288), np.full(288, 2)]).astype(int)
        null_rows = day == 0
        passed, size = activity.fdr_pass(self.frame(z, day), null_rows, ~null_rows, 0.05)
        self.assertEqual(size, 20000)
        self.assertEqual(int(passed[day == 1].sum()), 0)              # an ordinary day discovers nothing
        found = set(np.flatnonzero(passed[day == 2]).tolist())
        self.assertTrue(set(range(100, 110)) <= found)                # the whole burst
        self.assertLessEqual(len(found - set(range(100, 110))), 2)    # BH bounds the share of false discoveries, not their number
        self.assertTrue(passed[null_rows].all())                      # what is not tested passes

    def test_off_or_without_a_null_every_step_passes(self):
        z, day = np.array([9.0, 0.1]), np.array([1, 1])
        self.assertTrue(activity.fdr_pass(self.frame(z, day), np.array([False, False]), np.array([True, True]), 0.05)[0].all())
        self.assertTrue(activity.fdr_pass(self.frame(z, day), np.array([True, False]), np.array([False, True]), 0.0)[0].all())


class Shrinkage(unittest.TestCase):
    def test_weight_n_over_n_plus_k(self):
        median, mad = np.array([[4.0], [4.0]]), np.array([[1.0], [1.0]])
        every_median, every_mad = np.array([[2.0], [2.0]]), np.array([[0.5], [0.5]])
        shrunk, scale = activity.shrink(median, mad, every_median, every_mad, np.array([4.0, 36.0]), 4)
        self.assertAlmostEqual(shrunk[0, 0], 3.0)                    # 4 days: halfway to every day's
        self.assertAlmostEqual(shrunk[1, 0], 4 * 0.9 + 2 * 0.1)       # 36 days: mostly its own
        self.assertAlmostEqual(scale[0, 0], 0.75)
        same = activity.shrink(median, mad, every_median, every_mad, np.array([4.0, 36.0]), 0)
        self.assertTrue((same[0] == median).all())

    def test_k_is_chosen_when_sparse_series_alert_for_their_sparseness(self):
        rng = np.random.default_rng(3)
        rows = 400
        series = np.repeat(np.arange(6), rows)
        n = np.where(series < 3, 4.0, 40.0)                           # three series with few comparable days
        seen = rng.normal(2.0, 0.3, size=(len(series), 1))
        every_median, every_mad = np.full_like(seen, 2.0), np.full_like(seen, 0.2)
        median = np.where(n[:, None] < 10, 2.0 + rng.normal(0, 0.6, size=seen.shape), 2.0)     # noisy where sparse
        mad = np.where(n[:, None] < 10, 0.05, 0.2)
        k = activity.choose_shrinkage(seen, median, mad, every_median, every_mad, n, series, np.ones(len(series), bool), 0.0)
        self.assertGreater(k, 0)


class RunSummary(unittest.TestCase):
    def test_the_summary_records_the_choices(self):
        folder = made_up.tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        data = Path(folder.name) / "data"
        made_up.made_up_log(data)
        activity.main(["--source", "ossec", "--data", str(data), "--quiet"])
        summary = json.loads((data / "phase4_detection" / "ossec" / "activity" / "activity_by_entity" / "summary.json").read_text(encoding="utf-8"))
        scored = [row for row in summary["types"] if row.get("status") == "scored"]
        self.assertTrue(scored)
        for row in scored:
            self.assertEqual((row["calibration_split"], row["fdr"]), ("halves", 0.05))
            self.assertIn(row["shrinkage_days"], activity.SHRINK_GRID)
            self.assertGreaterEqual(row["test_robust_steps_bar_only"], row["test_robust_steps"])
        made_up.gc.collect()
        folder.cleanup()


if __name__ == "__main__":
    unittest.main()
