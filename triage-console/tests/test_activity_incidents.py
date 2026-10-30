"""Phase 4g incidents (pipeline/phase4_detection/activity_incidents.py): one event's alerts on several entities, and one
routine's alerts on several days, grouped so each is reviewed once.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_activity_incidents -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pipeline" / "phase4_detection"))
import activity_incidents as incidents  # noqa: E402


def alert(row_id, kind, entity, start, minutes=15, channel="lines", score=2.0, view=None):
    start = pd.Timestamp(start)
    return {"row_manifest_id": row_id, "view": view or ("activity" if kind == "all" else "activity_by_entity"),
            "entity_type": kind, "entity": entity, "start": str(start), "end": str(start + pd.Timedelta(minutes=minutes)),
            "peak_step": str(start), "peak_channel": channel, "activity_score": score}


def shared(*pairs):
    """Pair hours for (type, entity, type, entity, time) tuples: they shared a line in that hour."""
    keys = [incidents.pair_hashes(a, [x], b, [y], [int((pd.Timestamp(t) - pd.Timestamp("1970-01-01")) // pd.Timedelta(hours=1))])[0]
            for a, x, b, y, t in pairs]
    return np.unique(np.asarray(keys, dtype=np.uint64))


class Recurring(unittest.TestCase):
    def test_the_same_entity_at_the_same_time_on_three_days_is_one_routine(self):
        frame = pd.DataFrame([alert(f"r{d}", "server", "srv-x", f"2026-03-0{d} 07:{2 * d:02d}") for d in range(1, 5)]
                             + [alert("other", "server", "srv-x", "2026-03-02 15:00")])
        grouped, table = incidents.group(frame, shared())
        routine = table[table["kind"] == "recurring"].iloc[0]
        self.assertEqual((routine["size"], routine["days"]), (4, 4))
        self.assertTrue(routine["title"].startswith("Server srv-x: lines at about 07:0"))
        self.assertIn("on 4 days since 01 Mar", routine["title"])
        self.assertEqual(grouped.set_index("row_manifest_id").at["other", "incident_kind"], "single")

    def test_a_routine_around_midnight_is_one(self):
        times = ["2026-03-01 23:50", "2026-03-03 00:05", "2026-03-04 23:55"]
        _, table = incidents.group(pd.DataFrame([alert(f"m{i}", "username", "batch", t) for i, t in enumerate(times)]), shared())
        self.assertEqual(list(table["kind"]), ["recurring"])

    def test_an_entitys_routines_on_one_channel_are_one_incident_with_each_time(self):
        frame = pd.DataFrame([alert(f"am{d}", "server", "srv-x", f"2026-03-0{d} 07:05") for d in range(1, 5)]
                             + [alert(f"pm{d}", "server", "srv-x", f"2026-03-0{d} 21:05") for d in range(1, 5)])
        _, table = incidents.group(frame, shared())
        self.assertEqual(len(table), 1)
        self.assertIn("at about 07:05 and 21:05 on 4 days", table.iloc[0]["title"])

    def test_an_event_linked_to_a_routine_joins_it(self):
        frame = pd.DataFrame([alert(f"r{d}", "server", "srv-x", f"2026-03-0{d} 07:00", score=3.0) for d in range(1, 5)]
                             + [alert("ip", "source_ip", "10.2.0.9", "2026-03-02 07:10")])
        _, table = incidents.group(frame, shared(("server", "srv-x", "source_ip", "10.2.0.9", "2026-03-02 07:00")))
        self.assertEqual((len(table), table.iloc[0]["kind"], table.iloc[0]["size"]), (1, "recurring", 5))

    def test_two_routines_linked_at_one_time_stay_two_incidents(self):
        frame = pd.DataFrame([alert(f"s{d}", "server", "srv-x", f"2026-03-0{d} 07:00", score=3.0) for d in range(1, 5)]
                             + [alert(f"u{d}", "username", "svc", f"2026-03-0{d} 07:05", channel="failures") for d in range(1, 5)])
        pairs = shared(*[("server", "srv-x", "username", "svc", f"2026-03-0{d} 07:00") for d in range(1, 5)])
        _, table = incidents.group(frame, pairs)
        self.assertEqual(sorted(zip(table["kind"], table["size"])), [("recurring", 4), ("recurring", 4)])

    def test_two_days_are_not_a_routine_and_other_channels_are_apart(self):
        frame = pd.DataFrame([alert("a", "server", "srv-x", "2026-03-01 07:00"), alert("b", "server", "srv-x", "2026-03-02 07:00"),
                              alert("c", "server", "srv-x", "2026-03-03 07:00", channel="failures")])
        _, table = incidents.group(frame, shared())
        self.assertEqual(sorted(table["kind"]), ["single", "single", "single"])


class Linked(unittest.TestCase):
    def frame(self):
        return pd.DataFrame([alert("srv", "server", "srv-a", "2026-03-05 10:00", score=3.0),
                             alert("bob", "username", "bob", "2026-03-05 10:05", score=5.0),
                             alert("ip", "source_ip", "10.2.0.2", "2026-03-05 10:10", score=1.0)])

    def test_entities_that_shared_lines_meanwhile_are_one_event(self):
        pairs = shared(("server", "srv-a", "username", "bob", "2026-03-05 10:00"),
                       ("source_ip", "10.2.0.2", "username", "bob", "2026-03-05 10:00"))
        grouped, table = incidents.group(self.frame(), pairs)
        self.assertEqual(len(table), 1)
        event = table.iloc[0]
        self.assertEqual((event["kind"], event["size"], event["incident_id"]), ("linked", 3, "bob"))   # the lead: the top score
        self.assertEqual((event["title"], event["clock"]), ("Username bob with server srv-a, source IP 10.2.0.2", ""))
        self.assertEqual(grouped["incident_lead"].sum(), 1)

    def test_a_long_episode_does_not_link_an_alert_hours_later(self):
        frame = pd.DataFrame([alert("job", "server", "srv-a", "2026-03-05 07:00", minutes=240, score=3.0),
                              alert("late", "username", "bob", "2026-03-05 10:00", score=2.0)])
        _, table = incidents.group(frame, shared(("server", "srv-a", "username", "bob", "2026-03-05 10:00")))
        self.assertEqual(len(table), 2)                                     # peaks three hours apart: two events

    def test_overlapping_alerts_that_never_met_stay_apart(self):
        _, table = incidents.group(self.frame(), shared(("server", "srv-z", "username", "bob", "2026-03-05 10:00")))
        self.assertEqual(len(table), 3)


class WholeLog(unittest.TestCase):
    def test_the_whole_log_joins_the_strongest_entity_alert_on_its_channel(self):
        frame = pd.DataFrame([alert("all", "all", "all", "2026-03-05 10:00", minutes=30, channel="failures"),
                              alert("weak", "username", "carol", "2026-03-05 10:05", channel="failures", score=1.5),
                              alert("strong", "username", "bob", "2026-03-05 10:10", channel="failures", score=4.0),
                              alert("lines", "server", "srv-a", "2026-03-05 10:00", channel="lines", score=9.0)])
        grouped = incidents.group(frame, shared())[0].set_index("row_manifest_id")
        self.assertEqual(grouped.at["all", "incident_id"], "strong")
        self.assertEqual(grouped.at["weak", "incident_id"], "weak")          # not joined to bob through the whole log
        self.assertEqual(grouped.at["lines", "incident_id"], "lines")        # another channel: apart

    def test_a_whole_log_explained_by_a_routine_joins_it(self):
        frame = pd.DataFrame([alert(f"u{d}", "username", "svc", f"2026-03-0{d} 15:00", channel="failures", score=3.0) for d in range(1, 5)]
                             + [alert(f"all{d}", "all", "all", f"2026-03-0{d} 15:05", channel="failures") for d in range(1, 5)])
        _, table = incidents.group(frame, shared())
        self.assertEqual([(r["kind"], r["size"], r["entity_type"]) for _, r in table.iterrows()], [("recurring", 8, "username")])

    def test_a_whole_log_routine_no_entity_explains_stays_one(self):
        frame = pd.DataFrame([alert(f"all{d}", "all", "all", f"2026-03-0{d} 02:10") for d in range(1, 4)])
        _, table = incidents.group(frame, shared())
        self.assertEqual((len(table), table.iloc[0]["kind"], table.iloc[0]["clock"]), (1, "recurring", "02:10"))

    def test_a_one_off_entity_alert_joins_a_whole_log_routine(self):
        frame = pd.DataFrame([alert(f"all{d}", "all", "all", f"2026-03-0{d} 02:10") for d in range(1, 4)]
                             + [alert("srv", "server", "srv-m", "2026-03-01 02:12", score=4.0)])
        _, table = incidents.group(frame, shared())
        self.assertEqual([(r["kind"], r["size"], r["entity_type"]) for _, r in table.iterrows()], [("recurring", 4, "all")])

    def test_a_whole_log_alert_alone_leads_itself(self):
        grouped, table = incidents.group(pd.DataFrame([alert("all", "all", "all", "2026-03-05 10:00")]), shared())
        self.assertEqual((table.iloc[0]["title"], grouped.iloc[0]["incident_lead"]), ("Whole log", True))


if __name__ == "__main__":
    unittest.main()
