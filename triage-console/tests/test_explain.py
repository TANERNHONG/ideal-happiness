"""Explain (service/explain.py): the activity alerts' explanations listed and served, and the local model's rewording kept
only when it keeps every number.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_explain -v
"""
from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import activity, explain, store  # noqa: E402
from tests import test_activity as made_up  # noqa: E402

BURST_IP = made_up.BURST_IP


class ExplainService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.data = Path(cls.folder.name) / "data"
        made_up.made_up_log(cls.data)
        made_up.activity.main(["--source", "ossec", "--data", str(cls.data), "--quiet"])

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        cls.folder.cleanup()

    def setUp(self):
        self.var = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.var.name)
        self.patches = [mock.patch.object(activity, "DATA", self.data),
                        mock.patch.object(explain, "REWORD_FILE", folder / "explain_reword.json"),
                        mock.patch.object(explain, "load_settings", lambda: {"llm_model": "test-model"}),
                        mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.var.cleanup()

    def burst(self):
        return next(i for i in explain.items("ossec") if i["entity_type"] == "source_ip" and i["entity"] == BURST_IP)

    def test_the_list_carries_the_headline_and_the_day(self):
        items = explain.items("ossec")
        self.assertEqual(len(items), len(activity.incident_items("ossec")))           # one entry per incident
        self.assertLess(len(items), len(activity.items("ossec")))
        burst = self.burst()
        self.assertTrue(burst["headline"].startswith("Much busier than usual for this source IP"))
        self.assertEqual((burst["when"]["weekday"], burst["when"]["day_type"]), ("Saturday", "non_working"))
        self.assertGreater(burst["observed"], 10 * burst["median"])
        self.assertEqual(explain.items("pf"), [])

    def oracle(self):
        """The username first seen in the burst: one alert of the burst's incident, not a list entry of its own."""
        alert = next(i for i in activity.items("ossec") if i["entity_type"] == "username" and i["entity"] == "oracle")
        return explain.item("ossec", alert["view"], alert["item_id"])

    def test_little_history_says_what_it_was_compared_with(self):
        oracle = self.oracle()
        self.assertTrue(oracle["headline"].startswith("Much busier than a typical username"), oracle["headline"])
        self.assertTrue(oracle["big"]["little_history"])

    def test_entities_without_training_data_are_marked(self):
        flags = {(i["entity_type"], i["entity"]): i["in_training"] for i in explain.items("ossec")}
        self.assertFalse(self.oracle()["context"]["history"]["in_training"])
        self.assertTrue(flags[("source_ip", BURST_IP)])
        record = dict(explain.records("ossec", "activity_by_entity")[self.burst()["item_id"]])
        record["context"] = {k: v for k, v in record["context"].items() if k != "history"}   # an older record
        self.assertTrue(explain.first_known(record))

    def test_an_item_carries_its_summary(self):
        burst = self.burst()
        summary = explain.item("ossec", burst["view"], burst["item_id"])["summary"]
        self.assertTrue(summary and all(isinstance(line, str) and line.endswith(".") for line in summary))

    def test_the_list_carries_each_alerts_window(self):
        items = explain.items("ossec")
        self.assertTrue(items and all(i["window_minutes"] in (5, 30, 120, 720) for i in items))
        burst = self.burst()
        record = explain.records("ossec", burst["view"])[burst["item_id"]]
        self.assertEqual(burst["window_minutes"], record["big"]["window_minutes"])

    def test_the_list_compares_with_the_median(self):
        for item in explain.items("ossec"):
            record = explain.records("ossec", item["view"])[item["item_id"]]
            self.assertEqual((item["observed"], item["median"]), (record["big"]["observed"], record["big"]["usual"]["median"]))

    def test_an_item_has_its_pictures_and_lines(self):
        burst = self.burst()
        r = explain.item("ossec", burst["view"], burst["item_id"])
        self.assertEqual(r["reasons"][0]["kind"], "volume")
        self.assertEqual(len(r["day"]["hours"]), 24)
        self.assertTrue(r["lines"] and all(BURST_IP in line for line in r["lines"]))
        self.assertIsNone(r["reworded"])
        with self.assertRaises(KeyError):
            explain.item("ossec", "activity_by_entity", "no-such-alert")

    def test_a_rewording_that_keeps_the_numbers_is_kept(self):
        burst = self.burst()
        record = explain.records("ossec", burst["view"])[burst["item_id"]]
        facts = explain.facts(record)
        observed = str(record["big"]["observed"])
        self.assertIn(observed, facts)
        answer = f"On a quiet Saturday night this address suddenly sent {observed} lines in a quarter of an hour."
        with mock.patch.object(explain.llm, "chat", lambda system, user, **kw: answer):
            saved = explain.reword("ossec", burst["view"], burst["item_id"], "tester")
        self.assertEqual(saved, {"text": answer, "model": "test-model"})
        self.assertEqual(explain.item("ossec", burst["view"], burst["item_id"])["reworded"]["text"], answer)

    def test_a_rewording_that_changes_a_number_is_refused(self):
        burst = self.burst()
        with mock.patch.object(explain.llm, "chat", lambda system, user, **kw: "It sent 99999 lines, which looks like an attack."):
            with self.assertRaises(ValueError):
                explain.reword("ossec", burst["view"], burst["item_id"], "tester")
        self.assertIsNone(explain.item("ossec", burst["view"], burst["item_id"])["reworded"])

    def test_check_allows_the_facts_own_numbers_only(self):
        self.assertEqual(explain.check("224 lines in 15 minutes; usually 1–6.", "  It sent 224 lines in 15 minutes. "),
                         "It sent 224 lines in 15 minutes.")
        with self.assertRaises(ValueError):
            explain.check("224 lines in 15 minutes.", "It sent 225 lines.")
        with self.assertRaises(ValueError):
            explain.check("224 lines.", "")


if __name__ == "__main__":
    unittest.main()
