"""Planted attacks for recall (service/inject_eval.py): made-up lines only; the scoring is a stand-in, so no model
or data/ is read."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import analyze, inject_eval  # noqa: E402

DAY = [f"Jul 14 {h:02d}:{m:02d}:00 host-a sshd[{100 + h}]: [ID 800047 auth.info] Accepted publickey for staff01 from 192.0.2.5 port 5{h:02d}{m:02d} ssh2"
       for h in range(8, 18) for m in (0, 30)]
EXPECTED = {"guessing": {"SSH_LOGIN_FAILED"}, "spraying": {"SSH_LOGIN_FAILED"}, "enumeration": {"SSH_INVALID_USER"},
            "guess_then_login": {"SSH_LOGIN_FAILED", "SSH_LOGIN_SUCCESS"}, "night_root": {"SSH_LOGIN_SUCCESS"},
            "su_root": {"SSH_LOGIN_SUCCESS", "SU_SESSION_SUCCESS"}, "low_and_slow": {"SSH_LOGIN_FAILED"},
            "insider_night_login": {"SSH_LOGIN_SUCCESS"}, "insider_burst": {"SSH_LOGIN_SUCCESS"},
            "insider_guessing": {"SSH_LOGIN_FAILED"}, "insider_su_root": {"SU_SESSION_SUCCESS"}}


class Scenarios(unittest.TestCase):
    def test_every_planted_line_is_read_as_intended(self):
        found = inject_eval.scenarios("host-a", datetime(2026, 7, 14), 0, ("staff01", "192.0.2.5"))
        for scenario in found:
            with self.subTest(scenario=scenario.name):
                parsed = analyze._parse("auth", scenario.lines, "2026-07")
                self.assertTrue(all(known for _, _, known in parsed))
                expected = EXPECTED.get(scenario.name) or {"SSH_LOGIN_FAILED"}                  # the sweeps
                self.assertEqual({event["event_type"] for _, event, _ in parsed}, expected)
                if scenario.family != "insider":
                    self.assertTrue(all(a.startswith("203.0.113.") for a in scenario.addresses))
        sweep = [s for s in found if s.family == "sweep"]
        self.assertEqual([len(s.lines) for s in sweep if s.name.startswith("guessing_x")], [3, 5, 10, 20, 50])
        self.assertEqual([len(s.lines) for s in sweep if s.name.startswith("slow_")], [96, 24, 8])

    def test_insider_scenarios_reuse_the_days_own_identity(self):
        self.assertEqual(inject_eval.usual_pair(DAY, "2026-07"), ("staff01", "192.0.2.5"))
        insiders = [s for s in inject_eval.scenarios("host-a", datetime(2026, 7, 14), 0, ("staff01", "192.0.2.5")) if s.family == "insider"]
        self.assertEqual(len(insiders), 4)
        self.assertTrue(all("staff01" in line for s in insiders for line in s.lines))
        self.assertFalse(any(s.family == "insider" for s in inject_eval.scenarios("host-a", datetime(2026, 7, 14))))

    def test_repeats_move_the_start_time(self):
        first = inject_eval.scenarios("host-a", datetime(2026, 7, 14), 0)[0].lines[0]
        second = inject_eval.scenarios("host-a", datetime(2026, 7, 14), 1)[0].lines[0]
        self.assertNotEqual(first[:15], second[:15])

    def test_planting_keeps_time_order(self):
        planted = inject_eval.plant(DAY, ["Jul 14 08:15:00 host-a sshd[1]: [ID 800047 auth.info] made-up"], 2026)
        self.assertEqual(planted[1], "Jul 14 08:15:00 host-a sshd[1]: [ID 800047 auth.info] made-up")
        self.assertEqual(len(planted), len(DAY) + 1)

    def test_the_day_and_its_server(self):
        self.assertEqual(inject_eval.day_of(DAY, 2026), ("host-a", datetime(2026, 7, 14)))
        with self.assertRaises(ValueError):
            inject_eval.day_of(["not a log line"], 2026)


class Detections(unittest.TestCase):
    def test_only_what_the_planting_added_counts(self):
        scenario = inject_eval.Scenario("x", "x", [], {"203.0.113.11"}, {"evalops"})
        baseline = {"views": [{"view": "host_5min", "rows": [{"host_id": "host-a", "window_start": "2026-07-14 14:00:00", "flags": ["robust"]}]}]}
        result = {"views": [
            {"view": "individual", "rows": [{"source_ip": "203.0.113.11", "flags": ["sigma", "novelty"]},
                                            {"source_ip": "192.0.2.5", "flags": ["isolation_forest"]}]},     # not the scenario's
            {"view": "host_5min", "rows": [{"host_id": "host-a", "window_start": "2026-07-14 14:00:00", "flags": ["robust", "isolation_forest"]},
                                           {"host_id": "host-a", "window_start": "2026-07-14 20:00:00", "flags": ["novelty"]}]}]}   # outside the span
        found = inject_eval.detections(baseline, result, scenario, (datetime(2026, 7, 14, 14), datetime(2026, 7, 14, 14, 3)))
        self.assertEqual(found, {"individual": ["novelty", "sigma"], "host_5min": ["isolation_forest"]})

    def test_insider_counts_only_new_flags_on_its_own_identity(self):
        scenario = inject_eval.Scenario("i", "i", [], family="insider")
        row = {"host_id": "host-a", "timestamp": "2026-07-14 02:40:00", "username": "staff01", "source_ip": "192.0.2.5"}
        baseline = {"views": [{"view": "individual", "rows": []}]}
        result = {"views": [{"view": "individual", "rows": [{**row, "flags": ["isolation_forest"]},
                                                            {**row, "timestamp": "2026-07-14 09:00:00", "flags": ["novelty"]}]}]}
        found = inject_eval.detections(baseline, result, scenario, (datetime(2026, 7, 14, 2, 40), datetime(2026, 7, 14, 2, 40)))
        self.assertEqual(found, {"individual": ["isolation_forest"]})

    def test_recall_with_intervals_and_a_stand_in_scorer(self):
        def run(text, month, host):
            rows = [{"source_ip": "203.0.113.11", "flags": ["sigma"]}] if "203.0.113.11" in text else []
            return {"views": [{"view": "individual", "rows": rows}]}
        result = inject_eval.evaluate([DAY, DAY], "2026-07", repeats=2, run=run)
        guessing = result["scenarios"]["guessing"]
        self.assertEqual((guessing["hits"], guessing["trials"]), (4, 4))
        self.assertLess(guessing["low"], 1.0)                                    # 4 of 4 is not certainty
        self.assertEqual(result["scenarios"]["low_and_slow"]["hits"], 0)
        self.assertEqual(result["mechanisms"]["sigma"]["hits"], 4)
        self.assertIn("insider", result["families"])
        self.assertEqual(len(result["trials"]), 2 * 2 * len(inject_eval.scenarios("h", datetime(2026, 7, 14), 0, ("u", "a"))))

    def test_wilson(self):
        self.assertEqual(inject_eval.wilson(0, 0), (0.0, 1.0))
        low, high = inject_eval.wilson(8, 10)
        self.assertAlmostEqual(low, 0.49, places=2)
        self.assertAlmostEqual(high, 0.94, places=2)


if __name__ == "__main__":
    unittest.main()
