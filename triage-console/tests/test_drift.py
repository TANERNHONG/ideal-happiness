"""Drift at scoring time (service/drift.py), on made-up percentiles and entities."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import drift  # noqa: E402


class Null(unittest.TestCase):
    def test_independent_percentiles_give_the_classical_bound(self):
        table = drift.null_table(np.random.default_rng(1).uniform(size=20000), sizes=(100, 400), draws=400)
        self.assertAlmostEqual(table[100], 1.63 / np.sqrt(100), delta=0.04)        # the asymptotic 1% KS bound
        self.assertAlmostEqual(table[400], 1.63 / np.sqrt(400), delta=0.02)

    def test_dependent_percentiles_widen_the_null(self):
        rng = np.random.default_rng(2)
        walk = np.zeros(20000)
        for i in range(1, len(walk)):                                             # strongly autocorrelated
            walk[i] = 0.98 * walk[i - 1] + rng.normal()
        from scipy import stats
        dependent = stats.rankdata(walk) / len(walk)                              # uniform overall, clumped in time
        independent = drift.null_table(rng.uniform(size=20000), sizes=(200,))
        self.assertGreater(drift.null_table(dependent, sizes=(200,))[200], 2 * independent[200])

    def test_threshold_interpolates_in_log_n(self):
        table = {20: 0.4, 200: 0.2}
        self.assertIsNone(drift.threshold(table, 10))                             # below MIN_N
        self.assertAlmostEqual(drift.threshold(table, 63), 0.3, places=2)
        self.assertEqual(drift.threshold(table, 1000), 0.2)
        self.assertIsNone(drift.threshold({}, 100))


class NullFromValidation(unittest.TestCase):
    def test_read_once_from_the_validation_scores_and_cached(self):
        import tempfile
        import pandas as pd
        from service import scoring
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "data" / "phase4_detection" / "auth" / "detectors" / "individual"
            folder.mkdir(parents=True)
            rng = np.random.default_rng(4)
            pd.DataFrame({"host_id": rng.choice(["host-a", "host-b"], 3000), "timestamp": pd.date_range("2026-06-01", periods=3000, freq="min").astype(str),
                          "isolation_score": rng.normal(size=3000)}).to_csv(folder / "validation_scores.csv", index=False)
            grid = np.linspace(0, 1, 1001)
            reference = {"isolation_forest": np.vstack([np.quantile(rng.normal(size=20000), grid), grid])}
            with mock.patch.object(drift, "DATA", root / "data"), mock.patch.object(drift, "CACHE", root / "cache"), \
                    mock.patch.object(scoring, "_reference", return_value=reference) as ref:
                first = drift.null("auth", "individual")
                second = drift.null("auth", "individual")
            self.assertEqual(sorted(first), [20, 50, 100, 200, 500, 1000])            # blocks up to half the rows
            self.assertEqual(first, second)
            self.assertEqual(ref.call_count, 1)                                       # the second came from the cache
            self.assertTrue((root / "cache" / "drift_null_auth_individual.json").is_file())


class Scores(unittest.TestCase):
    def test_drift_is_d_above_the_null(self):
        piled = np.random.default_rng(1).beta(5, 1, size=400)
        with mock.patch.object(drift, "null", return_value={20: 0.3, 500: 0.08}):
            result = drift.scores(piled, "auth", "individual")
            self.assertTrue(result["drift"])
            self.assertGreater(result["d"], result["null"])
            calm = drift.scores(np.random.default_rng(3).uniform(size=400), "auth", "individual")
            self.assertFalse(calm["drift"])
        self.assertIsNone(drift.scores([None, float("nan")]))
        self.assertFalse(drift.scores(piled)["drift"])                            # no null, no verdict


class NewEntities(unittest.TestCase):
    def test_share_of_observations_naming_something_new(self):
        known = {"server": frozenset({"host-a"}), "username": frozenset({"staff01"}), "source_ip": frozenset({"192.0.2.5"})}
        rows = [{"host_id": "HOST-A", "username": "staff01", "source_ip": "192.0.2.5"},
                {"host_id": "host-b", "username": "staff02", "source_ip": "192.0.2.5"},
                {"hostname": "host-a"}]
        with mock.patch.object(drift, "_known", return_value=known):
            result = drift.new_entities("auth", rows)
        self.assertEqual(result["server"], {"new": 1, "named": 3})
        self.assertEqual(result["username"], {"new": 1, "named": 2})
        self.assertEqual(result["source_ip"], {"new": 0, "named": 2})
        with mock.patch.object(drift, "_known", return_value=None):
            self.assertIsNone(drift.new_entities("auth", rows))


if __name__ == "__main__":
    unittest.main()
