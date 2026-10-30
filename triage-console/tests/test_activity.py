"""Phase 4g activity detectors (pipeline/phase4_detection/activity_detectors.py) on a made-up OSSEC log.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_activity -v
"""
from __future__ import annotations

import gc
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

PIPELINE = Path(__file__).resolve().parents[2] / "pipeline"
for folder in ("phase4_detection", "phase6_report", "phase7_alerts"):
    sys.path.insert(0, str(PIPELINE / folder))

import activity_detectors as activity  # noqa: E402
import activity_explain  # noqa: E402
import collect_alerts  # noqa: E402
import coverage_sections  # noqa: E402

DAYS = 40
BURST_IP, BURST_START = "192.0.2.17", pd.Timestamp("2026-02-07 03:00")


def made_up_log(folder: Path) -> None:
    """Steady background on two servers, a nightly backup, and one burst from a known IP in the test period."""
    rng = np.random.default_rng(7)
    start = pd.Timestamp("2026-01-01")
    rows = []
    for step in range(DAYS * 288):
        when = start + pd.Timedelta(minutes=5 * step)
        for host, rate in (("host-a", 2.0), ("host-b", 1.0)):
            for _ in range(rng.poisson(rate)):
                ip = ("192.0.2.17", "192.0.2.20", "192.0.2.21")[rng.integers(3)]
                rows.append((when + pd.Timedelta(seconds=int(rng.integers(300))), host, ip, "ops", "192.0.2.1"))
        if when.hour == 2 and when.minute < 30:
            rows += [(when + pd.Timedelta(seconds=10 * i), "host-a", "192.0.2.30", "backup", "192.0.2.1") for i in range(5)]
    rows += [(BURST_START + pd.Timedelta(seconds=4 * i), "host-a", BURST_IP, "oracle", "192.0.2.1") for i in range(220)]
    frame = pd.DataFrame(rows, columns=["when", "hostname", "source_ip", "username", "destination_ip"]).sort_values("when")
    frame["timestamp"] = frame["when"].dt.strftime("%Y/%m/%d %H:%M:%S")
    frame["original_log_line"] = frame["timestamp"] + " " + frame["hostname"] + " sshd: event from " + frame["source_ip"]
    frame["event_id"] = [f"e{n}" for n in range(len(frame))]
    path = folder / "phase1_classify" / "ossec"
    path.mkdir(parents=True)
    frame.drop(columns="when").to_csv(path / "ossec_events_2026-01.csv", index=False)


class Trailing(unittest.TestCase):
    def test_sums_the_last_steps_of_the_same_series_only(self):
        counts = activity.trailing(np.array([0, 0, 0, 1]), np.array([10, 11, 13, 11]), np.array([1, 2, 3, 4]), [2])
        self.assertEqual(counts[2].tolist(), [1, 3, 3, 4])


class CalendarBaseline(unittest.TestCase):
    """The calendar half of robust deviation: the same clock window on the same weekday's training days, else the same
    kind of day's, as activity_explain.Series.comparable (Explain's and Profiles' comparable days)."""

    def setUp(self):
        self.first = activity_explain.day_number("2026-01-05")                   # a Monday
        days = range(35)
        late = range(14, 35)                                                       # a series first seen two weeks in
        self.frame = pd.DataFrame({"series": [0] * 35 + [1] * 21,
                                   "step": [(self.first + d) * 288 + 120 for d in days] + [(self.first + d) * 288 + 120 for d in late],
                                   "lines": 6})
        self.context = {"holidays": {}, "log_days": np.arange(self.first, self.first + 35), "train_end_day": self.first + 28}

    def test_the_same_clock_window_on_the_same_weekday(self):
        friday = self.first + 32
        row = int(np.flatnonzero((self.frame["series"] == 0) & (self.frame["step"] // 288 == friday))[0])
        median, mad, group, days = activity.calendar(self.frame, np.array([row]), self.context)
        self.assertEqual((int(days[0]), activity_explain.GROUP_NAMES[group[0]]), (4, "Fridays"))
        self.assertTrue(np.allclose(median[0], np.log1p(6)))                       # 10:00-10:05 holds the 6 lines in every window
        self.assertTrue(np.allclose(mad[0], 0))
        series = activity_explain.Series(self.frame["step"][:35], self.frame["lines"][:35], self.context["log_days"], {}, self.first + 28)
        comparable, basis = series.comparable(friday)
        self.assertEqual((len(comparable), basis), (4, "Fridays"))

    def test_too_few_weekdays_fall_back_to_the_kind_of_day(self):
        friday = self.first + 32
        row = int(np.flatnonzero((self.frame["series"] == 1) & (self.frame["step"] // 288 == friday))[0])
        _, _, group, days = activity.calendar(self.frame, np.array([row]), self.context)
        self.assertEqual((int(days[0]), activity_explain.GROUP_NAMES[group[0]]), (10, "working days"))    # 2 Fridays only


class MadeUpLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.root = Path(cls.folder.name)
        cls.data = cls.root / "data"
        made_up_log(cls.data)
        activity.main(["--source", "ossec", "--data", str(cls.data), "--quiet"])
        cls.out = cls.data / "phase4_detection" / "ossec" / "activity"

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        cls.folder.cleanup()

    def alerts(self, view):
        return pd.read_csv(self.out / view / "test_scores.csv")

    def test_the_burst_is_one_episode_for_its_ip(self):
        alerts = self.alerts("activity_by_entity")
        mine = alerts[alerts["entity_type"].eq("source_ip") & alerts["entity"].eq(BURST_IP)
                      & (pd.to_datetime(alerts["start"]) <= BURST_START + pd.Timedelta(minutes=15))
                      & (pd.to_datetime(alerts["end"]) >= BURST_START)]
        self.assertEqual(len(mine), 1)
        self.assertGreater(mine["peak_window_lines"].iloc[0], 10 * max(mine["usual_window_lines"].iloc[0], 1))   # 76 in 5 min
        self.assertTrue(mine["activity_alert"].all())

    def test_the_whole_log_sees_the_burst(self):
        alerts = self.alerts("activity")
        hit = alerts[(pd.to_datetime(alerts["start"]) <= BURST_START + pd.Timedelta(minutes=15))
                     & (pd.to_datetime(alerts["end"]) >= BURST_START)]
        self.assertEqual(len(hit), 1)

    def test_evidence_starts_with_a_description_then_lines_of_the_peak(self):
        alerts = self.alerts("activity_by_entity")
        row_id = alerts[alerts["entity"].eq(BURST_IP)].sort_values("activity_score").iloc[-1]["row_manifest_id"]
        evidence = pd.read_csv(self.out / "activity_by_entity" / "test_raw_alert_evidence.csv")
        mine = evidence[evidence["row_manifest_id"].eq(row_id)].sort_values("event_position")
        self.assertTrue(mine["original_log_line"].iloc[0].startswith("[activity] source IP " + BURST_IP))
        self.assertEqual(len(mine), 21)
        self.assertTrue(mine["original_log_line"].iloc[1:].str.contains(BURST_IP).all())
        self.assertTrue(mine["event_ref"].iloc[1:].str.startswith("e").all())

    def test_entities_are_judged_against_their_own_normal(self):
        decisions = pd.read_csv(self.out / "activity_by_entity" / "feature_decisions_source_ip.csv")
        names = set(decisions["feature_name"])
        self.assertTrue({"time_day_of_week", "time_is_non_working", "rel_distinct_server_5m", "rel_hour_30m"} <= names)
        self.assertFalse(any(name.startswith(("lines_", "log_", "distinct_")) for name in names))
        self.assertTrue(decisions["decision"].eq("kept").any())
        self.assertFalse(decisions["feature_name"].str.contains("entity|hash").any())

    def test_the_whole_log_uses_counts_with_their_log_twins(self):
        whole = pd.read_csv(self.out / "activity" / "feature_decisions_all.csv").set_index("feature_name")
        self.assertTrue({"log_30m", "lines_30m", "distinct_source_ip_5m", "burst_5_60"} <= set(whole.index))
        self.assertFalse({"log_15m", "log_60m", "log_360m"} & set(whole.index))          # four windows: 5, 30, 120, 720

    def test_the_nightly_backup_ranks_far_below_the_burst(self):
        alerts = self.alerts("activity_by_entity")
        burst = alerts.loc[alerts["entity"].eq(BURST_IP), "activity_score"].max()
        routine = alerts[alerts["entity"].isin(["backup", "192.0.2.30"])]
        self.assertTrue((routine["activity_score"] < burst / 2).all())
        self.assertFalse(routine["detector_combination"].str.contains("robust").any())

    def test_only_the_planted_burst_alerts(self):
        """The made-up log's one anomaly is the burst: every alert, in both views, is that burst, and nothing else (a
        routine nightly backup, a Poisson dip in the background, a quiet hour) is flagged."""
        for view in ("activity", "activity_by_entity"):
            starts = pd.to_datetime(self.alerts(view)["start"])
            self.assertTrue(len(starts))
            self.assertTrue(((starts >= BURST_START - pd.Timedelta(minutes=15)) & (starts <= BURST_START + pd.Timedelta(minutes=15))).all(), view)

    def test_the_forest_is_a_second_opinion(self):
        alerts = pd.concat([self.alerts("activity"), self.alerts("activity_by_entity")])
        self.assertFalse(alerts["detector_combination"].eq("activity_forest").any())     # never alone below its strict bar
        burst = alerts[alerts["entity"].eq(BURST_IP)].iloc[0]
        self.assertEqual(burst["detector_combination"], "activity_robust+activity_forest")
        self.assertGreater(burst["activity_score"], 2)                                   # agreement adds 1
        summary = json.loads((self.out / "activity_by_entity" / "summary.json").read_text(encoding="utf-8"))
        for row in summary["types"]:
            self.assertGreaterEqual(row["forest_alone_threshold"], row["forest_threshold"])
            self.assertGreaterEqual(row["robust_threshold"], 3.0)
            self.assertGreater(row["calendar_share"], 0.9)

    def test_alerts_name_the_days_they_were_compared_with(self):
        alerts = self.alerts("activity_by_entity")
        burst = alerts[alerts["entity"].eq(BURST_IP)].iloc[0]
        self.assertEqual((burst["calendar_basis"], burst["direction"]), ("Saturdays", "higher"))
        self.assertGreaterEqual(burst["calendar_days"], 4)
        newcomer = alerts[alerts["entity"].eq("oracle")].iloc[0]                        # first seen in the burst
        self.assertTrue(pd.isna(newcomer["calendar_basis"]))
        self.assertEqual(newcomer["baseline"], "pooled")

    def test_summary_is_ranked_within_alerts(self):
        summary = json.loads((self.out / "activity_by_entity" / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["probability_rule"], "rank_within_alerts")
        self.assertEqual(summary["split_basis"], "70 / 15 / 15 of the study period")
        experiments = pd.read_csv(self.out / "experiment_summary.csv")
        self.assertEqual(set(experiments["entity_type"]), {"all", "server", "source_ip", "username", "destination_ip"})


    def test_phase7_collects_them_as_activity_alerts_only(self):
        collect_alerts.LINEAGE_KEY, collect_alerts.MESSAGE_COLUMN = "event_id", "original_log_line"
        collected = collect_alerts.stage4_alerts(self.out, collect_alerts.Log(quiet=True))
        self.assertEqual(sum(len(frame) for frame in collected["activity"]), len(self.alerts("activity"))
                         + len(self.alerts("activity_by_entity")))
        self.assertFalse(any(collected[name] for name in ("robust", "isolation_forest", "novelty")))
        frame = next(f for f in collected["activity"] if f["dataset"].iloc[0] == "activity_by_entity")
        self.assertTrue(frame["flagged_by"].str.startswith("Activity: ").all())
        self.assertAlmostEqual(frame["probability"].max(), 1.0)
        chains = collect_alerts.stage4_messages(self.out / "activity_by_entity", set(frame["row_manifest_id"]))
        self.assertTrue(all(text.startswith("[activity] ") for text in chains.values()))

    def test_the_report_section_lists_the_alerts(self):
        with mock.patch.object(coverage_sections, "ROOT", self.root):
            html = coverage_sections.activity_section("ossec")
        self.assertIn('id="activity"', html)
        self.assertIn(BURST_IP, html)
        self.assertIn("Source IP", html)


if __name__ == "__main__":
    unittest.main()
