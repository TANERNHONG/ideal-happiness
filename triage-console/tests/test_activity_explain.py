"""Phase 4g explanations (pipeline/phase4_detection/activity_explain.py) on a made-up OSSEC log: the usual range counts
quiet days as zeros, holidays are non-working days, and a burst on a holiday by an address that only works on working
days is explained by its volume and by the kind of day.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_activity_explain -v
"""
from __future__ import annotations

import gc
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import test_activity as made_up  # noqa: E402

explain = sys.modules.get("activity_explain") or __import__("activity_explain")
WORKER, HOLIDAY = "192.0.2.50", date(2026, 2, 4)          # a Wednesday in the made-up log's test period


def with_worker(folder: Path) -> None:
    """The made-up log, plus an address busy 09:00-17:00 on working days only, and a burst on the holiday."""
    made_up.made_up_log(folder)
    path = folder / "phase1_classify" / "ossec" / "ossec_events_2026-01.csv"
    frame = pd.read_csv(path, dtype=str)
    rows = []
    for day in pd.date_range("2026-01-01", "2026-02-09"):
        if day.weekday() >= 5 or day.date() == HOLIDAY:
            continue
        for step in range(9 * 12, 17 * 12):
            when = day + pd.Timedelta(minutes=5 * step)
            rows += [(when + pd.Timedelta(seconds=30 * i), "host-b", WORKER, "svc") for i in range(2)]
    burst = pd.Timestamp(f"{HOLIDAY} 10:00")
    rows += [(burst + pd.Timedelta(seconds=4 * i), "host-b", WORKER, "svc") for i in range(200)]
    extra = pd.DataFrame(rows, columns=["when", "hostname", "source_ip", "username"])
    extra["timestamp"] = extra["when"].dt.strftime("%Y/%m/%d %H:%M:%S")
    extra["destination_ip"] = "192.0.2.1"
    extra["original_log_line"] = extra["timestamp"] + " host-b sshd: event from " + WORKER
    extra["event_id"] = [f"w{n}" for n in range(len(extra))]
    pd.concat([frame, extra.drop(columns="when")], ignore_index=True).sort_values("timestamp").to_csv(path, index=False)


class Calendar(unittest.TestCase):
    def test_weekends_and_holidays_are_non_working(self):
        days = [explain.day_number(f"2026-02-0{d}") for d in (2, 4, 7)]          # Mon, Wed, Sat
        self.assertEqual(explain.non_working(days, {}).tolist(), [False, False, True])
        self.assertEqual(explain.non_working(days, {days[1]: "Test Day"}).tolist(), [False, True, True])

    def test_quiet_days_count_as_zeros(self):
        first = explain.day_number("2026-01-05")
        steps = np.array([first * 288 + 36, (first + 1) * 288 + 36, (first + 1) * 288 + 37])     # 03:00 on two days
        series = explain.Series(steps, np.array([4, 2, 1]), np.arange(first, first + 10), {}, first + 7)
        days = series.days(explain.WORKING)
        self.assertEqual(len(days), 5)                                            # Mon-Fri of the training week
        self.assertEqual(len(series.days(explain.NON_WORKING)), 2)
        self.assertEqual(series.window(days, 38, 2).tolist(), [4, 3, 0, 0, 0])

    def test_words(self):
        self.assertEqual(explain.span(0.4, 6.2), "0–6")
        self.assertEqual(explain.span(3.2, 2.9), "3")
        self.assertEqual(explain.minutes_words(720), "12 hours")
        self.assertEqual(explain.aspect("rel_hour_60m"), "lines in 1 hour for this hour")
        self.assertEqual(explain.aspect("rel_distinct_server_5m"), "how many servers")
        self.assertEqual(explain.aspect("rel_log_gap_minutes"), "the silence before it")


class HolidayBurst(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.data = Path(cls.folder.name) / "data"
        with_worker(cls.data)
        with mock.patch.object(made_up.activity, "load_public_holidays", lambda: {HOLIDAY: "Test Day"}):
            made_up.activity.main(["--source", "ossec", "--data", str(cls.data), "--quiet"])
        out = cls.data / "phase4_detection" / "ossec" / "activity" / "activity_by_entity"
        with (out / "explanations.jsonl").open(encoding="utf-8") as handle:
            cls.records = [json.loads(line) for line in handle]
        cls.decisions = pd.read_csv(out / "feature_decisions_source_ip.csv")

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        cls.folder.cleanup()

    def worker(self):
        return next(r for r in self.records if r["entity"] == WORKER and r["when"]["date"] == str(HOLIDAY))

    def test_every_alert_has_a_record_in_the_scores_order(self):
        scores = pd.read_csv(self.data / "phase4_detection" / "ossec" / "activity" / "activity_by_entity" / "test_scores.csv")
        self.assertEqual([r["row_manifest_id"] for r in self.records], scores["row_manifest_id"].tolist())

    def test_the_holiday_is_a_non_working_day(self):
        r = self.worker()
        self.assertEqual((r["when"]["day_type"], r["when"]["holiday"], r["context"]["holiday"]), ("non_working", "Test Day", "Test Day"))
        self.assertIn("time_is_non_working", set(self.decisions["feature_name"]))

    def test_volume_first_then_the_kind_of_day(self):
        r = self.worker()
        kinds = [reason["kind"] for reason in r["reasons"]]
        self.assertEqual(kinds[0], "volume")
        self.assertIn("day_type", kinds)
        volume = r["reasons"][0]
        self.assertEqual(volume["direction"], "higher")
        self.assertGreaterEqual(volume["observed"], 70)             # the burst's busiest 5 minutes
        self.assertEqual(volume["usual"]["high"], 0)              # it never logs on a weekend: zeros, not "no data"
        self.assertIn("on non-working days", volume["text"])          # the days the detector compared it with
        day = next(reason for reason in r["reasons"] if reason["kind"] == "day_type")
        self.assertTrue(day["text"].startswith("Weekends and holidays are quiet for this source IP"))
        self.assertEqual(r["headline"], "Much busier than usual for this source IP in those 5 minutes, at a time it is usually quiet")

    def test_every_check_is_shown_whether_or_not_it_supports(self):
        r = self.worker()
        evidence = r["evidence"]
        self.assertEqual([e["title"] for e in evidence if e["group"] == "lines"],
                         ["5 min", "30 min", "2 h", "12 h"])
        self.assertEqual({e["basis"] for e in evidence if e["group"] in ("lines", "day") and "basis" in e}, {"non-working days"})
        self.assertTrue({e["stance"] for e in evidence} <= {"supports", "against", "neutral"})
        self.assertEqual({e["group"] for e in evidence}, {"lines", "time", "day", "who", "models"})
        window = next(e for e in evidence if e["group"] == "lines" and e.get("peak"))
        self.assertEqual((window["title"], window["stance"]), ("5 min", "supports"))
        self.assertEqual(len(window["distribution"]), window["usual"]["days"])
        hour = next(e for e in evidence if e["group"] == "time" and e["title"] == "10:00")
        self.assertEqual((hour["active_days"], hour["stance"]), (0, "supports"))
        models = {e["title"]: e for e in evidence if e["group"] == "models"}
        self.assertTrue(models["Robust deviation"]["flagged"])
        self.assertIn(models["Isolation Forest"]["stance"], ("supports", "neutral"))
        self.assertTrue(any(e["stance"] == "neutral" for e in evidence))     # e.g. who else: nothing unusual, still listed

    def test_the_median_week_is_by_weekday_with_holidays_apart(self):
        r = self.worker()
        week = r["week"]
        self.assertEqual(week["usual_basis"][0], "Mondays")
        self.assertEqual(week["usual_basis"][5], "Saturdays")
        self.assertEqual(week["usual_basis"][2], "non-working days")        # the holiday: no past holidays in training
        self.assertGreater(week["usual"][0][10], 0)                           # it works on Monday mornings
        self.assertEqual(week["usual"][5][10], 0)                             # never on Saturdays
        self.assertTrue(all(n >= 4 for n in week["usual_days"]))
        self.assertEqual(next(e for e in r["evidence"] if e["title"] == "Day total")["basis"], "non-working days")
        self.assertFalse(any(" vs " in e["title"] for e in r["evidence"]))         # one comparison, the detector's
        self.assertEqual((r["big"]["basis"], r["context"]["basis"]), ("non-working days", "non-working days"))
        self.assertEqual(r["daily"]["per_day"][-2]["basis"], "Tuesdays")

    def test_history_says_when_an_entity_has_no_training_data(self):
        worker = self.worker()["context"]["history"]
        self.assertTrue(worker["in_training"])
        self.assertFalse(worker["first_this_week"])
        oracle = next(r for r in self.records if r["entity"] == "oracle")["context"]["history"]   # only in the test burst
        self.assertEqual((oracle["in_training"], oracle["first_seen"], oracle["first_this_day"]), (False, "2026-02-07", True))
        self.assertEqual(oracle["training_days"], 0)

    def test_a_long_silence_is_judged_against_past_resumptions(self):
        """Its nights (about 16 hours) and weekends (about 64) are its usual resumptions, not the 5 minutes between lines
        inside a working day: a night's silence before the holiday morning is not unusual."""
        r = self.worker()
        item = next(e for e in r["evidence"] if e["title"] == "Silence before")
        self.assertEqual((item["rule"], item["basis"]), ("resume", "past resumptions"))
        self.assertGreaterEqual(item["usual"]["median"], 15 * 60)
        self.assertGreaterEqual(item["usual"]["high"], 60 * 60)
        self.assertEqual((item["status"], item["stance"]), ("within", "neutral"))
        self.assertEqual(item["threshold"], item["usual"]["high"])
        self.assertFalse(any(line.startswith("It started after") for line in explain.summary(r)))
        self.assertNotIn("sudden", [reason["kind"] for reason in r["reasons"]])

    def test_the_summary_keeps_to_the_supporting_evidence(self):
        lines = explain.summary(self.worker())
        self.assertTrue(lines[0].startswith("75 lines in 5 minutes") or "lines in" in lines[0])
        self.assertIn("against a usual 0 on non-working days", lines[0])
        self.assertTrue(any(line.startswith("Active at 10:00") for line in lines))
        self.assertTrue(lines[-1].startswith("Flagged by its robust deviation"))

    def test_the_charts_have_their_shapes(self):
        r = self.worker()
        self.assertEqual(len(r["day"]["hours"]), 24)
        self.assertEqual(r["day"]["alert_hours"], [10])
        self.assertEqual(len(r["day"]["band"]["high"]), 24)
        self.assertEqual((len(r["week"]["counts"]), len(r["week"]["counts"][0])), (7, 24))
        self.assertEqual(r["week"]["alert"], [2, 10])
        self.assertEqual(r["week"]["holidays"][2], "Test Day")
        self.assertEqual(r["week"]["kinds"][2], "non_working")
        self.assertEqual(len(r["daily"]["totals"]), 56)
        self.assertEqual(r["daily"]["dates"][-1], str(HOLIDAY))
        self.assertIsNone(r["daily"]["totals"][0])               # before the made-up log starts: no data, not zero


if __name__ == "__main__":
    unittest.main()
