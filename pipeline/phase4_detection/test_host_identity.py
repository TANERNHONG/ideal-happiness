"""host_identity_check.py on made-up servers: a server that is flagged for being rare, and one that is not."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "shared"))
import host_identity_check as check  # noqa: E402


class Volume(unittest.TestCase):
    def test_less_training_more_alerts_is_a_negative_rho(self):
        test = pd.DataFrame({"host_id": ["a"] * 100 + ["b"] * 100 + ["c"] * 100,
                             "isolation_alert": ["True"] * 60 + ["False"] * 40 + ["True"] * 10 + ["False"] * 90 + ["True"] * 2 + ["False"] * 98})
        train = pd.Series(["a"] * 10 + ["b"] * 500 + ["c"] * 5000)
        rho, table = check.volume_check(test, train)
        self.assertEqual(list(table.index), ["a", "b", "c"])
        self.assertAlmostEqual(rho, -1.0)


class LeaveOneOut(unittest.TestCase):
    def test_a_server_unlike_the_rest_alerts_more_without_its_own_training(self):
        rng = np.random.default_rng(0)
        tmp = Path(tempfile.mkdtemp())

        def rows(n_common, n_odd):
            common = rng.normal(0, 1, size=(n_common, 4))
            odd = rng.normal(0, 1, size=(n_odd, 4)) + 6.0                         # the odd server's own routine, apart in every feature
            return np.vstack([common, odd]).astype(np.float32), np.array(["common"] * n_common + ["odd"] * n_odd)
        hosts = {}
        for split, (n_common, n_odd) in {"train": (3000, 2000), "validation": (800, 150), "test": (800, 150)}.items():
            x, h = rows(n_common, n_odd)
            sparse.save_npz(tmp / f"X_{split}.npz", sparse.csr_matrix(x))
            hosts[split] = h
        found = check.leave_one_out(tmp, {"isolation_feature_indices": [0, 1, 2, 3]}, "odd", hosts["train"], hosts["validation"],
                                    hosts["test"], 0.02, 10_000, np.random.default_rng(1))
        self.assertLess(found["rate_with"], 0.5)                        # learned with its own rows: mostly usual
        self.assertGreater(found["rate_without"], found["rate_with"] + 0.4)   # without them: unusual for being itself
        self.assertEqual(found["test_rows_of_server"], 150)


if __name__ == "__main__":
    unittest.main()
