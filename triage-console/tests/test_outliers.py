"""The Dashboard's outlier counts: rows flagged per mechanism, and the overlaps."""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from service import outliers


def write(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


class OutlierCounts(unittest.TestCase):
    def test_masks_and_totals(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            det = data / "phase4_detection" / "auth"
            write(det / "detectors" / "authentication_sessions" / "test_scores.csv", ["row_manifest_id", "isolation_alert", "novelty_alert"],
                  [["a", "True", "False"], ["b", "False", "True"], ["c", "True", "True"], ["d", "False", "False"], ["e", "False", "False"]])
            write(det / "sequences" / "authentication_sessions" / "test_scores.csv", ["row_manifest_id", "sequence_alert"],
                  [["a", "False"], ["b", "True"], ["c", "False"], ["d", "True"], ["e", "False"]])
            write(det / "model_zoo" / "authentication_sessions" / "full" / "consensus_alerts_min3.csv", ["row_manifest_id"], [["a"], ["d"]])
            with mock.patch.object(outliers, "DATA", data):
                result = outliers._count_source("auth")
        self.assertEqual(result["rows"], 5)
        self.assertEqual(result["flagged"], 4)                                    # e is the only row nobody flagged
        self.assertEqual(result["totals"], {"isolation_forest": 2, "model_zoo": 2, "novelty": 2, "sequence": 2})
        # a: forest + zoo (1+2), b: novelty + sequence (4+8), c: forest + novelty (1+4), d: zoo + sequence (2+8)
        self.assertEqual(result["regions"], {"3": 1, "5": 1, "10": 1, "12": 1})

    def test_missing_scores_mean_no_source(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(outliers, "DATA", Path(tmp)):
            self.assertIsNone(outliers._count_source("ossec"))


if __name__ == "__main__":
    unittest.main()
