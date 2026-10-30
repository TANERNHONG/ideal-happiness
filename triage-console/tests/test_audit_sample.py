"""The audit sample (service/audit.py): a stratified, deterministic, blind draw and its estimates. Made-up scores
and labels; an isolated store."""
from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import audit, outliers, server, store  # noqa: E402

ROWS = [f"s{i:03d}" for i in range(200)]
MASKS = {row: 0b0001 for row in ROWS[150:180]} | {row: 0b0010 for row in ROWS[180:]}       # IF; model zoo


class AuditSample(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.folder.name)
        scores = root / "data" / "phase4_detection" / "auth" / "detectors" / "authentication_sessions"
        scores.mkdir(parents=True)
        robust = ["True" if 140 <= i < 150 else "False" for i in range(200)]                  # 10 robust-only
        pd.DataFrame({"row_manifest_id": ROWS, "robust_alert": robust,
                      "isolation_score": np.linspace(0, 1, 200)}).to_csv(scores / "test_scores.csv", index=False)
        self.patches = [mock.patch.object(store, "STORE_FILE", root / "console.sqlite"), mock.patch.object(store, "VAR", root),
                        mock.patch.object(audit, "DATA", root / "data"),
                        mock.patch.object(outliers, "masks", lambda source: MASKS if source == "auth" else None)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def items(self):
        with store.connect() as con:
            return pd.read_sql_query("SELECT * FROM audit_items", con)

    def test_the_draw_is_stratified_once_a_month_and_repeatable(self):
        self.assertTrue(audit.draw("2026-10")["drawn"])
        self.assertFalse(audit.draw("2026-10")["drawn"])                       # drawn once
        items = self.items()
        self.assertEqual(items["stratum"].value_counts().to_dict(), {"unflagged": 10, "flagged_lower": 10, "flagged_upper": 5})
        self.assertEqual(int(items.loc[items["stratum"] == "unflagged", "population"].iloc[0]), 140)
        flagged = items[items["stratum"] != "unflagged"]
        self.assertTrue(flagged["mechanisms"].ne("").all())
        self.assertTrue(items.loc[items["stratum"] == "unflagged", "mechanisms"].eq("").all())
        first = sorted(items["row_id"])
        with store.connect() as con:
            con.execute("DELETE FROM audit_items")
        audit.draw("2026-10")
        self.assertEqual(sorted(self.items()["row_id"]), first)                 # the same seed, the same sample
        audit.draw("2026-11")
        self.assertNotEqual(sorted(self.items().query("month == '2026-11'")["row_id"]), first)

    def test_the_page_sees_no_stratum_score_or_flag(self):
        audit.draw("2026-10")
        listing = audit.listing("2026-10")
        self.assertEqual(len(listing["items"]), 25)
        self.assertEqual(set(listing["items"][0]), {"n", "source", "view", "row_id", "item_id", "verdict", "note"})
        observation = {"server": "host-a", "start": "s", "end": "e", "lines": ["made-up"], "line_count": 1, "lines_status": "ready",
                       "detectors": [{"name": "isolation_forest"}], "anomaly": 0.99, "votes": 3}
        with mock.patch.object(server.review_context, "observation", return_value=observation):
            item = server.ROUTES[("GET", "/api/audit-sample/item")]({"source": "auth", "view": "authentication_sessions", "row": "s001"}, None)
        self.assertEqual(set(item), {"server", "start", "end", "lines", "line_count", "lines_status"})

    def test_estimates_from_blind_labels(self):
        audit.draw("2026-10")
        items = self.items()
        for row in items.itertuples():
            verdict = {"unflagged": "expected_behavior", "flagged_lower": "expected_behavior"}.get(row.stratum, "security_relevant")
            store.add_review("auth", row.view, audit.item_id(row.row_id), "audit", verdict, "made-up note", "tester")
        one = items[items["stratum"] == "flagged_lower"].iloc[0]
        store.add_review("auth", one.view, audit.item_id(one.row_id), "audit", "insufficient_evidence", "made-up", "tester")
        e = audit.estimates()
        self.assertEqual(e["labelled"], 24)                                     # insufficient evidence is not a label
        o = e["overall"]
        self.assertGreater(o["precision"]["estimate"], 0.3)                     # half the flagged population is all relevant
        self.assertLess(o["precision"]["estimate"], 0.7)
        self.assertLessEqual(o["precision"]["low"], o["precision"]["estimate"])
        self.assertLess(o["miss_rate"]["estimate"], 0.1)                        # none of 10 unflagged was relevant...
        self.assertGreater(o["miss_rate"]["high"], 0.05)                        # ...which does not prove none is
        self.assertLess(o["recall"]["low"], o["recall"]["high"])
        self.assertIn("isolation_forest", e["mechanisms"])
        self.assertEqual(audit.listing("2026-10")["estimates"]["labelled"], 24)

    def test_without_scores_nothing_is_drawn(self):
        with mock.patch.object(audit, "DATA", Path(self.folder.name) / "nowhere"):
            self.assertFalse(audit.draw("2026-10")["drawn"])
        self.assertEqual(audit.estimates()["drawn"], 0)


if __name__ == "__main__":
    unittest.main()
