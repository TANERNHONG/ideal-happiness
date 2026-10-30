"""The OSSEC history cache (scoring._history): hashed keys, plain arrays, no pickle. Made-up keys only."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import scoring  # noqa: E402
from service.pipeline_code import module  # noqa: E402

COLUMNS = ["lines", "levels"]


class HistoryCache(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m3 = module("phase3_features/ossec.py")
        cls.hashed = scoring._hashed_history(cls.m3)

    def chunk(self, seed):
        rng = np.random.default_rng(seed)
        keys = np.array(["host01|agent-a", "host02|agent-b", "host01|agent-a", "host03|agent-c"] * 5, dtype=object)
        return keys, rng.normal(size=(len(keys), len(COLUMNS)))

    def test_hashed_keys_give_the_same_statistics(self):
        plain, hashed = self.m3.HistoryState(COLUMNS), self.hashed(COLUMNS)
        for seed in (1, 2):
            keys, values = self.chunk(seed)
            for a, b in zip(plain.update(keys, values), hashed.update(keys, values)):
                np.testing.assert_allclose(a, b)
        self.assertTrue(all(len(k) == 16 for k in hashed.index))

    def test_round_trip_without_pickle_or_names(self):
        plain, hashed = self.m3.HistoryState(COLUMNS), self.hashed(COLUMNS)
        keys, values = self.chunk(1)
        plain.update(keys, values)
        hashed.update(keys, values)
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "ossec_history_test.npz"
            scoring._save_history(cache, "123:456", hashed)
            raw = cache.read_bytes()
            self.assertNotIn(b"host01", raw)
            self.assertNotIn("host01".encode("utf-32-le"), raw)
            stamp, loaded = scoring._load_history(cache, self.hashed, COLUMNS)
        self.assertEqual(stamp, "123:456")
        keys, values = self.chunk(2)
        for a, b in zip(plain.update(keys, values), loaded.update(keys, values)):
            np.testing.assert_allclose(a, b)

    def test_an_unreadable_cache_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "ossec_history_test.npz"
            cache.write_bytes(b"not an npz")
            self.assertIsNone(scoring._load_history(cache, self.hashed, COLUMNS))
            self.assertIsNone(scoring._load_history(Path(tmp) / "missing.npz", self.hashed, COLUMNS))


if __name__ == "__main__":
    unittest.main()
