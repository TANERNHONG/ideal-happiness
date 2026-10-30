"""The feature-ablation diagnostic (service/feature_ablation.py) with a stand-in zoo: made-up lines, no model read."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import feature_ablation, inject_eval  # noqa: E402
from tests.test_inject_eval import DAY  # noqa: E402


class Ablation(unittest.TestCase):
    def test_planted_rows_by_identity(self):
        scenario = inject_eval.Scenario("x", "x", [], {"203.0.113.11"}, {"evalops"})
        frame = pd.DataFrame({"source_ip": ["203.0.113.11", "192.0.2.5", ""], "username": ["root", "staff01", "evalops"]})
        self.assertEqual(feature_ablation.planted_rows(frame, scenario).tolist(), [True, False, True])

    def test_a_feature_that_carries_the_detection_loses_it(self):
        # stand-ins: three features, the zoo flags a row when feature 1 is above 1
        frame = pd.DataFrame({"source_ip": ["203.0.113.11"] * 3 + ["192.0.2.5"] * 5, "username": [""] * 8})
        matrix = np.zeros((8, 3))
        matrix[:3, 1] = 5.0

        class Sparse:
            def __init__(self, a):
                self.a = a

            def toarray(self):
                return self.a.copy()
        bundle = {"feature_indices": [0, 1, 2]}
        zoo = lambda source, view, m, feature_set: {"consensus": m[:, 1] > 1, "ensemble_alert": np.zeros(len(m), bool)}  # noqa: E731
        with mock.patch.object(feature_ablation.scoring, "_zoo_bundle", return_value=bundle), \
                mock.patch.object(feature_ablation.scoring, "_preprocessing", return_value=(None, ["a", "b", "c"])), \
                mock.patch.object(feature_ablation.scoring, "_phase1_auth"), \
                mock.patch.object(feature_ablation.scoring, "_phase2", return_value={"authentication_sessions": frame}), \
                mock.patch.object(feature_ablation.scoring, "features", return_value=Sparse(matrix)), \
                mock.patch.object(feature_ablation.scoring, "zoo", side_effect=zoo), \
                mock.patch.object(feature_ablation.inject_eval, "scenarios",
                                  return_value=[inject_eval.Scenario("g", "g", [DAY[0]], {"203.0.113.11"})]):
            table = feature_ablation.ablate([DAY], "2026-07")
        self.assertEqual(table["planted_lost"].tolist(), [0, 3, 0])
        rho, merged = feature_ablation.compare(table, pd.DataFrame({"feature_index": [0, 1, 2], "importance": [0.9, 0.1, 0.5]}))
        self.assertLess(rho, 0)                                         # the zoo's ranking disagrees with detection
        self.assertEqual(merged.iloc[0]["feature_name"], "b")           # the largest disagreement first


if __name__ == "__main__":
    unittest.main()
