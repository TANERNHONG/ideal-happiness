"""Profiles: Phase 4h (pipeline/phase4_detection/activity_profiles.py) on made-up OSSEC and PF logs, and the console's
service/profiles.py on its output: every line counted once, weekday baselines with quiet days as zeros, the same week as
Explain's, the presence method for the firewalls, and the watch list.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_profiles -v
"""
from __future__ import annotations

import gc
import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import activity, profiles, store  # noqa: E402
from tests import test_activity_explain as made_up  # noqa: E402

import activity_profiles  # noqa: E402  (pipeline/phase4_detection is on the path through tests.test_activity)

WORKER, HOLIDAY = made_up.WORKER, made_up.HOLIDAY
PF_ADDRESS, PF_ONCE, PF_TMP = "198.51.100.7", "203.0.113.9", "203.0.113.99"


def pf_log(data: Path) -> None:
    """A made-up PF log: one address blocked a few times a day from 20 January, another once on 8 February, and a
    leftover *_tmp capture that must be left out."""
    rows = []
    for day in pd.date_range("2026-01-20", "2026-02-09"):
        rows += [(day + pd.Timedelta(hours=8 + k), PF_ADDRESS, "192.0.2.1", "2026-01/pflog/pflog_fwa.txt") for k in range(3)]
    rows.append((pd.Timestamp("2026-02-08 23:10"), PF_ONCE, "192.0.2.1", "2026-02/pflog/pflog_fwb.txt"))
    rows.append((pd.Timestamp("2026-02-08 23:15"), PF_TMP, "192.0.2.1", "2026-02/pflog/pflog_fwb_tmp.txt"))
    frame = pd.DataFrame(rows, columns=["when", "source_ip", "destination_ip", "source_file"])
    frame["timestamp"] = frame["when"].dt.strftime("%Y-%m-%d %H:%M:%S")
    frame["raw_message"] = frame["timestamp"] + " block in on em0: " + frame["source_ip"]
    folder = data / "phase1_classify" / "pf"
    folder.mkdir(parents=True)
    frame.drop(columns="when").to_csv(folder / "classified_pflog_events_2026-01.csv", index=False)


class Profiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.data = Path(cls.folder.name) / "data"
        made_up.with_worker(cls.data)
        pf_log(cls.data)
        holidays = lambda: {HOLIDAY: "Test Day"}  # noqa: E731
        with mock.patch.object(made_up.made_up.activity, "load_public_holidays", holidays), \
             mock.patch.object(activity_profiles, "load_public_holidays", holidays):
            made_up.made_up.activity.main(["--source", "ossec", "--data", str(cls.data), "--quiet"])
            for source in ("ossec", "pf"):
                activity_profiles.main(["--source", source, "--data", str(cls.data), "--quiet"])
        with (cls.data / "phase4_detection" / "ossec" / "activity" / "activity_by_entity" / "explanations.jsonl").open(encoding="utf-8") as handle:
            cls.records = [json.loads(line) for line in handle]

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        cls.folder.cleanup()

    def setUp(self):
        self.var = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.var.name)
        self.patches = [mock.patch.object(profiles, "DATA", self.data), mock.patch.object(activity, "DATA", self.data),
                        mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.var.cleanup()

    def query(self, source, sql, *params):
        con = sqlite3.connect(self.data / "phase4_detection" / source / "profiles" / "profiles.sqlite")
        try:
            return con.execute(sql, params).fetchall()
        finally:
            con.close()

    def test_every_line_is_counted_once(self):
        lines = len(pd.read_csv(self.data / "phase1_classify" / "ossec" / "ossec_events_2026-01.csv", usecols=["timestamp"]))
        self.assertEqual(self.query("ossec", "SELECT lines FROM entities WHERE id = 0")[0][0], lines)
        hourly = dict(self.query("ossec", "SELECT e.entity_type, SUM(h.lines) FROM hourly h JOIN entities e ON e.id = h.id GROUP BY 1"))
        self.assertEqual(hourly["server"], lines)                    # every made-up line names a server
        daily = self.query("ossec", "SELECT SUM(lines) FROM daily WHERE id = 0")[0][0]
        self.assertEqual(daily, lines)

    def test_weekday_baselines_count_quiet_days_as_zero(self):
        (code_id,), = self.query("ossec", "SELECT id FROM entities WHERE entity_type = 'source_ip' AND entity = ?", WORKER)
        usual = {basis: (name, days, median) for basis, name, days, median in
                 self.query("ossec", "SELECT basis, basis_name, days, median FROM usual WHERE id = ?", code_id)}
        self.assertEqual(usual[0], ("Mondays", 4, 192.0))             # 09:00-17:00, two lines every 5 minutes
        self.assertEqual(usual[5], ("Saturdays", 4, 0.0))             # never at weekends: zeros, not "no data"
        self.assertEqual(usual[7][0], "non-working days")             # a holiday, with no past holidays in training

    def test_the_week_is_explains_week(self):
        record = next(r for r in self.records if r["entity"] == WORKER and r["when"]["date"] == str(HOLIDAY))
        profile = profiles.entity("ossec", "source_ip", WORKER, str(HOLIDAY))
        for key in ("monday", "counts", "kinds", "usual", "usual_days", "usual_basis", "usual_totals", "holidays"):
            self.assertEqual(profile["week"][key], record["week"][key], key)
        self.assertEqual(profile["big"]["observed"], sum(record["day"]["hours"]))
        self.assertEqual(profile["big"]["basis"], "non-working days")
        self.assertEqual(profile["big"]["usual"]["median"], 0)
        self.assertEqual(len(profile["daily"]["per_day"]), 56)
        self.assertEqual(profile["daily"]["per_day"][-2]["basis"], "Tuesdays")
        self.assertTrue(any(a["item_id"] == record["row_manifest_id"] for a in profile["alerts"]))

    def test_the_list_puts_the_furthest_from_normal_first(self):
        listed = profiles.overview("ossec", "source_ip", str(HOLIDAY))
        first = listed["rows"][0]
        self.assertEqual((first["entity"], first["x"], first["direction"]), (WORKER, 200, "above"))
        self.assertEqual(len(first["spark"]), 56)
        self.assertIsNone(first["spark"][0])                          # before the made-up log starts
        self.assertGreaterEqual(first["alerts"], 1)
        self.assertEqual([r["entity"] for r in profiles.overview("ossec", "source_ip", str(HOLIDAY), query="2.50")["rows"]], [WORKER])

    def test_entities_without_training_data_are_marked(self):
        oracle = next(r for r in profiles.overview("ossec", "username", "2026-02-07")["rows"] if r["entity"] == "oracle")
        self.assertEqual((oracle["in_training"], oracle["new_today"], oracle["usual"]), (False, True, None))
        history = profiles.entity("ossec", "username", "oracle", "2026-02-07")["context"]["history"]
        self.assertEqual((history["in_training"], history["training_days"]), (False, 0))

    def test_shared_lines_up_to_the_day(self):
        touched = {(t["entity_type"], t["entity"]): t for t in profiles.entity("ossec", "source_ip", WORKER, str(HOLIDAY))["touched"]}
        self.assertEqual(set(touched), {("server", "host-b"), ("username", "svc"), ("destination_ip", "192.0.2.1")})
        self.assertEqual(touched[("server", "host-b")]["on_day"], 200)
        self.assertFalse(touched[("server", "host-b")]["after_training"])

    def test_the_firewalls_use_the_presence_method(self):
        meta = profiles.meta("pf")
        self.assertEqual(meta["method"], "presence")
        self.assertEqual(self.query("pf", "SELECT COUNT(*) FROM usual")[0][0], 0)
        names = dict(self.query("pf", "SELECT entity, entity_type FROM entities"))
        self.assertNotIn(PF_TMP, names)                               # the *_tmp capture is left out
        self.assertEqual(sorted(n for n, k in names.items() if k == "server"), ["fwa", "fwb"])
        listed = profiles.overview("pf", "source_ip", "2026-02-08")
        self.assertEqual([r["entity"] for r in listed["rows"]], [PF_ADDRESS, PF_ONCE])
        self.assertTrue(all(r["usual"] is None and r["in_training"] is None for r in listed["rows"]))
        page = profiles.entity("pf", "source_ip", PF_ONCE, "2026-02-08")
        self.assertIsNone(page["context"]["history"])
        self.assertEqual(page["big"]["observed"], 1)

    def test_the_watch_list(self):
        profiles.watch("ossec", "source_ip", WORKER, True, "tester")
        watched = profiles.watched()
        self.assertEqual([(w["entity"], w["ready"], len(w["spark"])) for w in watched], [(WORKER, True, 56)])
        self.assertTrue(profiles.entity("ossec", "source_ip", WORKER)["watched"])
        self.assertEqual([r["entity"] for r in profiles.overview("ossec", "source_ip")["rows"] if r["watched"]], [WORKER])
        entry = store.audit_log()[0]
        self.assertEqual((entry["action"], entry["object"], entry["detail"]), ("watch", "ossec/source_ip", "{}"))   # no address
        profiles.watch("ossec", "source_ip", WORKER, False, "tester")
        self.assertEqual(profiles.watched(), [])
        with self.assertRaises(KeyError):
            profiles.watch("ossec", "source_ip", "192.0.2.254", True, "tester")

    def test_days_outside_the_profiles_are_refused(self):
        with self.assertRaises(ValueError):
            profiles.overview("ossec", "source_ip", "2025-01-01")
        with self.assertRaises(ValueError):
            profiles.overview("ossec", "source_ip", "7 Feb")
        with self.assertRaises(ValueError):
            profiles.overview("ossec", "hostname", "")
        self.assertEqual(profiles.overview("auth", "source_ip"), {"ready": False})

    def test_the_runner_includes_4h_for_every_source(self):
        spec = importlib.util.spec_from_file_location("run_pipeline_for_tests", Path(__file__).resolve().parents[2] / "run_pipeline.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        self.assertIn("4h", runner.ORDER)
        self.assertTrue(all("4h" not in skipped for skipped in runner.UNSUPPORTED.values()))


if __name__ == "__main__":
    unittest.main()
