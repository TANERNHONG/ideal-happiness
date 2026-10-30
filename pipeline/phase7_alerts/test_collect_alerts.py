"""Phase 7's cumulative files: the 'rank' column, with 'probability' kept as its old name for one release; files in the
layout before 2026-10-30 are read, not started again. Made-up rows only.

    .venv/Scripts/python.exe -m unittest discover -s pipeline/phase7_alerts -p "test_*.py" -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import collect_alerts  # noqa: E402


class Log:
    def write(self, *args, **kwargs):
        pass


def rows(*items):
    return pd.DataFrame([{"probability": p, "flagged_by": "Isolation Forest", "dataset": "individual",
                          "raw_messages": text, "row_manifest_ids": rid} for p, text, rid in items])


class Accumulate(unittest.TestCase):
    def test_rank_written_and_the_old_layout_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x_cumulative_isolation_alerts.csv"
            rows((0.9, "line a", "r1")).to_csv(path, index=False)           # the layout before 2026-10-30
            collect_alerts.accumulate(path, rows((0.95, "line a", "r2"), (0.5, "line b", "r3")), False, Log())
            out = pd.read_csv(path)
            self.assertEqual(list(out.columns), collect_alerts.OUTPUT_COLUMNS)
            self.assertEqual(out["raw_messages"].tolist(), ["line a", "line b"])
            self.assertEqual(out["rank"].tolist(), [0.95, 0.5])
            self.assertEqual(out["rank"].tolist(), out["probability"].tolist())
            self.assertIn("r1", out.loc[0, "row_manifest_ids"])               # the old file's row was kept
            collect_alerts.accumulate(path, rows((0.4, "line c", "r4")), False, Log())
            self.assertEqual(len(pd.read_csv(path)), 3)                       # the new layout is read back too


if __name__ == "__main__":
    unittest.main()
