"""Phase 4g's outcome, relations, context and regularity features (pipeline/phase4_detection/activity_detectors.py) on a
made-up auth log, and Phase 3 without identity as a feature.

The made-up log: a busy HMI server (srv-a), a server one IT address logs into every day (srv-b: a routine zone crossing),
a jump host with a nightly job (srv-c), and, in the test period, three planted events: a burst of failed logins inside
srv-a's normal traffic; the deploy account reaching five servers it never touched, three of them new; and an outside
address guessing admin's password 25 times on srv-c, then getting in.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_activity_features -v
"""
from __future__ import annotations

import gc
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests import test_activity as made_up  # noqa: E402  (puts pipeline/phase4_detection on the path)

import activity_detectors as activity  # noqa: E402
from sources import Assets  # noqa: E402

PIPELINE = Path(__file__).resolve().parents[2] / "pipeline"
FAILED, SUCCESS = "SSH_LOGIN_FAILED", "SSH_LOGIN_SUCCESS"
BURST = pd.Timestamp("2026-02-05 10:00")          # failures inside srv-a's normal traffic (a Thursday)
SPREAD = pd.Timestamp("2026-02-06 14:00")         # deploy reaches five servers (a Friday)
GUESS = pd.Timestamp("2026-02-07 03:00")          # 25 failures, then a success (a Saturday)
ASSETS = """match,zone,role,criticality
srv-a,OT,HMI,high
srv-b,OT,HMI,medium
srv-c,OT,jump host,low
srv-d,OT,HMI,high
10.2.0.0/16,OT,,
10.1.0.0/16,IT,,
"""


def auth_log(folder: Path) -> None:
    rng = np.random.default_rng(11)
    rows = []

    def lines(start, count, host, ip, user, event, seconds=300):
        for i in range(count):
            rows.append((start + pd.Timedelta(seconds=int(rng.integers(seconds))), host, ip, user, event))

    for day in pd.date_range("2026-01-01", "2026-02-09"):
        for step in range(288):
            when = day + pd.Timedelta(minutes=5 * step)
            hour = when.hour
            if day.weekday() < 5 and 8 <= hour < 18:
                for ip, user in (("10.2.0.1", "alice"), ("10.2.0.2", "bob"), ("10.2.0.3", "ops")):
                    lines(when, rng.poisson(4), "srv-a", ip, user, SUCCESS)
                    lines(when, rng.poisson(0.07), "srv-a", ip, user, FAILED)
            lines(when, rng.poisson(1.5), "srv-b", "10.2.0.4", "carol", SUCCESS)
            lines(when, rng.poisson(1.5), "srv-b", "10.1.0.5", "ops", SUCCESS)
            if hour == 2 and when.minute < 30:
                lines(when, rng.poisson(4), "srv-c", "10.2.0.6", "deploy", SUCCESS)
    rows += [(BURST + pd.Timedelta(seconds=15 * i), "srv-a", "10.2.0.2", "bob", FAILED) for i in range(60)]
    rows += [(SPREAD + pd.Timedelta(minutes=8 * i), host, "10.2.0.6", "deploy", SUCCESS)
             for i, host in enumerate(("srv-a", "srv-b", "srv-d", "srv-e", "srv-f"))]
    rows += [(GUESS + pd.Timedelta(seconds=22 * i), "srv-c", "203.0.113.5", "admin", FAILED) for i in range(25)]
    rows.append((GUESS + pd.Timedelta(seconds=22 * 25), "srv-c", "203.0.113.5", "admin", SUCCESS))
    frame = pd.DataFrame(rows, columns=["when", "hostname", "source_ip", "username", "event_type"]).sort_values("when")
    frame["timestamp"] = frame["when"].dt.strftime("%Y-%m-%d %H:%M:%S")
    frame["original_log_line"] = frame["timestamp"] + " " + frame["hostname"] + " sshd: " + frame["event_type"] + " " + frame["username"]
    frame["record_id"] = [f"r{n}" for n in range(len(frame))]
    path = folder / "phase1_classify" / "auth"
    path.mkdir(parents=True)
    frame.drop(columns="when").to_csv(path / "classified_authlog_events_2026-01.csv", index=False)


class MadeUpAuthLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(cls.folder.name)
        cls.data = root / "data"
        auth_log(cls.data)
        (root / "assets.csv").write_text(ASSETS, encoding="utf-8")
        with mock.patch.object(activity, "Assets", lambda: Assets(root / "assets.csv")), \
             mock.patch.object(activity, "load_public_holidays", lambda: {}), \
             mock.patch.object(activity, "load_change_windows", lambda: []):
            activity.main(["--source", "auth", "--data", str(cls.data), "--quiet"])
        out = cls.data / "phase4_detection" / "auth" / "activity" / "activity_by_entity"
        cls.alerts = pd.read_csv(out / "test_scores.csv", keep_default_na=False)
        with (out / "explanations.jsonl").open(encoding="utf-8") as handle:
            cls.records = {r["row_manifest_id"]: r for r in map(json.loads, handle)}
        cls.decisions = pd.read_csv(out / "feature_decisions_server.csv")
        cls.summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        cls.folder.cleanup()

    def alert(self, kind, entity, around):
        start = pd.to_datetime(self.alerts["start"])
        mine = self.alerts[self.alerts["entity_type"].eq(kind) & self.alerts["entity"].eq(entity)
                           & (start <= around + pd.Timedelta(hours=1)) & (pd.to_datetime(self.alerts["end"]) >= around)]
        self.assertEqual(len(mine), 1, f"{kind} {entity}")
        return mine.iloc[0]

    def test_a_failure_burst_inside_normal_traffic_is_found_by_its_failures(self):
        a = self.alert("server", "srv-a", BURST)
        self.assertEqual(a["peak_channel"], "failures")
        self.assertGreater(a["peak_window_lines"], 20)
        r = self.records[a["row_manifest_id"]]
        self.assertTrue(r["headline"].startswith("Many more failures than usual for this server"))
        self.assertEqual((r["big"]["channel"], r["big"]["noun"]), ("failures", "failure"))
        failures = [e for e in r["evidence"] if e["group"] == "failures"]
        self.assertEqual([e["title"] for e in failures], ["5 min", "30 min", "2 h", "12 h"])
        self.assertTrue(any(e.get("peak") for e in failures))

    def test_new_partners_are_found_and_named(self):
        a = self.alert("username", "deploy", SPREAD)
        self.assertEqual(a["peak_channel"], "new partners")
        r = self.records[a["row_manifest_id"]]
        named = {p["partner"] for p in r["partners"]}
        self.assertTrue({"srv-d", "srv-e", "srv-f"} <= named)
        self.assertIn("for the first time", r["headline"])
        item = next(e for e in r["evidence"] if e["title"] == "New partners, 2 h")
        self.assertEqual((item["status"], item["stance"]), ("above", "supports"))

    def test_a_success_after_failures_is_shown_for_the_actor_only(self):
        a = self.alert("username", "admin", GUESS)
        r = self.records[a["row_manifest_id"]]
        item = next(e for e in r["evidence"] if e["title"] == "Success after failures")
        self.assertGreaterEqual(item["observed"], 20)
        self.assertIn("outcome", [reason["kind"] for reason in r["reasons"]])
        server = self.records[self.alert("server", "srv-c", GUESS)["row_manifest_id"]]       # a server mixes people
        self.assertFalse(any(e["title"] == "Success after failures" for e in server["evidence"]))

    def test_the_summary_says_why_in_words(self):
        explain = sys.modules.get("activity_explain") or __import__("activity_explain")
        burst = explain.summary(self.records[self.alert("server", "srv-a", BURST)["row_manifest_id"]])
        self.assertIn("failures in", burst[0])
        self.assertIn("against a usual", burst[0])
        self.assertFalse(any("successful login" in line for line in burst))
        self.assertTrue(burst[-1].startswith("Flagged by"))
        guess = explain.summary(self.records[self.alert("username", "admin", GUESS)["row_manifest_id"]])
        self.assertTrue(any(line.startswith("A successful login came after") for line in guess))
        spread = explain.summary(self.records[self.alert("username", "deploy", SPREAD)["row_manifest_id"]])
        self.assertTrue(spread[0].startswith("Shared lines for the first time with 5 servers"))
        self.assertLessEqual(max(len(s) for s in (burst, guess, spread)), 6)

    def test_the_asset_inventory_names_zone_role_and_criticality(self):
        a = self.alert("server", "srv-a", BURST)
        self.assertEqual((a["zone"], a["role"], a["criticality"]), ("OT", "HMI", "high"))
        r = self.records[a["row_manifest_id"]]
        self.assertEqual(r["context"]["asset"], {"zone": "OT", "role": "HMI", "criticality": "high"})
        self.assertTrue(any(e["title"] == "Asset" for e in r["evidence"]))
        titles = [(e["group"], e["title"]) for e in r["evidence"]]
        self.assertFalse([t for _, t in titles if "_" in t])                  # every check named in words, once a group
        self.assertEqual(len(titles), len(set(titles)))
        self.assertIn("rel_cross_zone_5m", set(self.decisions["feature_name"]))          # srv-b's daily IT logins

    def test_only_the_planted_events_alert(self):
        """Every alert, in both views, is one of the three planted events: not a handful of everyday failed logins, nor
        the routine nightly job or the daily logins from the IT zone."""
        for view in ("activity", "activity_by_entity"):
            alerts = pd.read_csv(self.data / "phase4_detection" / "auth" / "activity" / view / "test_scores.csv")
            self.assertTrue(len(alerts), view)
            for _, a in alerts.iterrows():
                start, end = pd.Timestamp(a["start"]), pd.Timestamp(a["end"])
                self.assertTrue(any(start <= event + pd.Timedelta(hours=1) and end >= event for event in (BURST, SPREAD, GUESS)),
                                f"{view}: {a['entity_type']} at {a['start']}")

    def test_each_planted_event_is_one_incident(self):
        table = pd.read_csv(self.data / "phase4_detection" / "auth" / "activity" / "incidents.csv")
        self.assertEqual((len(table), set(table["kind"])), (3, {"linked"}))
        burst = table[pd.to_datetime(table["start"]).dt.date == BURST.date()].iloc[0]
        self.assertEqual(burst["size"], 4)                                         # the whole log, srv-a, bob, 10.2.0.2
        members = burst["members"].split(";")
        self.assertTrue(any(m.startswith("activity:") for m in members))
        self.assertEqual(set(self.alerts["incident_kind"]), {"linked"})

    def test_the_new_features_are_candidates_and_names_are_not(self):
        names = set(self.decisions["feature_name"])
        self.assertTrue({"rel_fail_5m", "rel_new_source_ip_5m", "rel_new_partners_120m",
                         "rel_count_cv_60m", "rel_gap_cv_720m", "rel_gap_minutes", "rel_distinct_failed_username_5m"} <= names)
        self.assertNotIn("rel_success_after_failures", names)                     # one actor's guesses only
        users = set(pd.read_csv(self.data / "phase4_detection" / "auth" / "activity" / "activity_by_entity"
                                / "feature_decisions_username.csv")["feature_name"])
        self.assertIn("rel_success_after_failures", users)
        self.assertFalse(any("hostname" in n or "srv-" in n or "10." in n for n in names))
        self.assertTrue(self.summary["outcome_features"])
        self.assertEqual(self.summary["channels"], ["lines", "failures", "new partners"])


class Regularity(unittest.TestCase):
    def test_a_steady_beat_has_no_variation_and_a_burst_has_much(self):
        steps = np.arange(100, 124, dtype=np.int64)
        frame = pd.DataFrame({"series": [0] * 24 + [1] * 24, "step": np.r_[steps, steps],
                              "lines": [2] * 24 + [0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0, 12] * 2})
        frame = frame[frame["lines"] > 0].reset_index(drop=True)
        activity.add_regularity(frame, frame["series"].to_numpy(), frame["step"].to_numpy(), frame["lines"].to_numpy())
        steady = frame[frame["series"] == 0]["count_cv_60m"].iloc[-1]
        bursty = frame[frame["series"] == 1]["count_cv_60m"].iloc[-1]
        self.assertAlmostEqual(float(steady), 0.0, places=5)
        self.assertGreater(float(bursty), 1.0)
        self.assertAlmostEqual(float(frame[frame["series"] == 0]["gap_cv_720m"].iloc[-1]), 0.0, places=5)   # every 5 minutes


class PeerBaseline(unittest.TestCase):
    def test_an_entity_without_history_is_compared_with_its_role(self):
        rows = []
        for series, role, n in ((0, "HMI", 60), (1, "HMI", 60), (2, "HMI", 2), (3, "", 2)):
            rows += [(series, f"e{series}", 1000 + i * 3, 5 if series < 2 else 1, role) for i in range(n)]
        frame = pd.DataFrame(rows, columns=["series", "entity", "step", "lines", "role"])
        frame = activity.add_features(frame, "server", ["server"], {}, {}, ())
        train = np.ones(len(frame), dtype=bool)
        frame, _, _, has_own, _ = activity.own_normal(frame, train, SimpleNamespace(min_history=30, robust_floor=0.5))
        baseline = frame.groupby("series")["baseline"].first().to_dict()
        self.assertEqual(baseline, {0: "own", 1: "own", 2: "role", 3: "pooled"})
        self.assertEqual(frame.loc[frame["series"] == 2, "peer"].iloc[0], "HMI")


class AssetInventory(unittest.TestCase):
    def test_names_addresses_and_the_most_specific_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "assets.csv"
            path.write_text("match,zone,role,criticality\n# a comment, with commas\nSRV-A,OT,HMI,high\n10.0.0.0/8,IT,,\n"
                            "10.2.0.0/16,OT,,medium\n10.2.0.9,OT,engineering workstation,\nbad,DMZ,,urgent\n", encoding="utf-8")
            assets = Assets(path)
            self.assertEqual(assets.of("srv-a"), ("OT", "HMI", "high"))
            self.assertEqual(assets.of("10.2.3.4"), ("OT", "", "medium"))
            self.assertEqual(assets.of("10.9.9.9"), ("IT", "", ""))
            self.assertEqual(assets.of("10.2.0.9"), ("OT", "engineering workstation", ""))
            self.assertEqual(assets.of("bad"), ("DMZ", "", ""))                  # criticality only low, medium or high
            self.assertEqual(assets.of("192.0.2.1"), ("", "", ""))
            self.assertFalse(Assets(Path(tmp) / "none.csv"))


class Phase3WithoutIdentity(unittest.TestCase):
    def load(self, name):
        spec = importlib.util.spec_from_file_location(f"phase3_{name}_for_tests", PIPELINE / "phase3_features" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_names_and_port_numbers_are_not_features(self):
        auth, ossec = self.load("auth"), self.load("ossec")
        names = {"hostname", "host_id", "agent_name", "dominant_username", "dominant_source_ip", "username", "source_ip"}
        self.assertFalse(names & set(auth.CATEGORICAL_CANDIDATES))
        self.assertNotIn("source_port", auth.NUMERIC_CANDIDATES)
        self.assertIn("source_port_category", auth.CATEGORICAL_CANDIDATES)
        for view, columns in ossec.CATEGORICAL_CANDIDATES.items():
            self.assertFalse(names & set(columns), view)
        self.assertNotIn("username_sequence", ossec.SEQUENCE_SOURCES)


if __name__ == "__main__":
    unittest.main()
