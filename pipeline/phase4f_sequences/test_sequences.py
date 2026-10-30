"""Synthetic tests for Phase 4f steps 1-3 and the alert profile (no project data needed).

  .venv/Scripts/python.exe -m unittest discover -s pipeline/phase4f_sequences -p test_*.py -v
"""
import math
import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BEGIN, END, split_of  # noqa: E402
from mine import contains, mine_scope, rules_from, transition_counts  # noqa: E402
from profile_alerts import family, hour_band, profile, source_class, steps_band  # noqa: E402
from score import Model, score_one  # noqa: E402
from streams import build_unit  # noqa: E402


def event(i, epoch, kind, file="a", line=None, sha=None):
    return {"id": f"e{i}", "epoch": float(epoch), "file": ("", "", file), "line": line, "type": kind, "sha": sha or f"s{i}"}


class Streams(unittest.TestCase):
    def test_numeric_line_order_within_a_second(self):
        unit = build_unit([event(1, 5, "B", line=10), event(2, 5, "A", line=2)])
        self.assertEqual(unit["tokens"], ("A", "B"))
        self.assertEqual(unit["uncertain"], [])

    def test_cross_file_copy_is_merged_and_listed(self):
        unit = build_unit([event(1, 5, "A", "x.4", 1, "h1"), event(2, 5, "A", "x.10", 7, "h1"), event(3, 6, "B", "x.4", 2, "h2")])
        self.assertEqual(unit["tokens"], ("A", "B"))
        self.assertEqual(unit["kept"], 2)
        self.assertEqual(unit["aliases"], [("e2", "e1")])      # file names sort as text: x.10 comes first and is kept

    def test_repeats_within_one_file_are_kept(self):
        unit = build_unit([event(1, 5, "F", "x", 1, "h"), event(2, 5, "F", "x", 2, "h")])
        self.assertEqual(unit["kept"], 2)
        self.assertEqual(unit["runs"], [2])

    def test_only_as_many_copies_as_the_first_file_holds_are_merged(self):
        unit = build_unit([event(1, 5, "F", "a", 1, "h"), event(2, 5, "F", "b", 1, "h"), event(3, 5, "F", "b", 2, "h")])
        self.assertEqual(len(unit["aliases"]), 1)
        self.assertEqual(unit["kept"], 2)

    def test_same_second_across_files_is_uncertain(self):
        unit = build_unit([event(1, 5, "A", "a", 1), event(2, 5, "B", "b", 1), event(3, 6, "C", "b", 2)])
        self.assertEqual(unit["tokens"], ("A", "B", "C"))
        self.assertEqual(unit["uncertain"], [1])

    def test_runs_collapse(self):
        unit = build_unit([event(i, i, "F", line=i) for i in range(1, 5)] + [event(9, 9, "S", line=9)])
        self.assertEqual(unit["tokens"], ("F", "S"))
        self.assertEqual(unit["runs"], [4, 1])

    def test_phase3_split_rule(self):
        rule = (100.0, 200.0, 10.0)
        self.assertEqual([split_of(e, rule) for e in (89, 95, 110, 150, 189.9, 195, 210)],
                         ["train", "purged", "validation", "validation", "validation", "purged", "test"])


class Mining(unittest.TestCase):
    def test_contains_allows_gaps_but_keeps_order(self):
        self.assertTrue(contains(("A", "X", "B"), ("A", "B")))
        self.assertFalse(contains(("B", "A"), ("A", "B")))

    def test_weighted_support_counts_observations(self):
        patterns, _ = mine_scope([("A", "B"), ("A",)], [30, 10], 40)
        found = dict((p, c) for c, p in patterns)
        self.assertEqual(found[("A", "B")], 30)
        self.assertEqual(found[("A",)], 40)

    def test_rule_from_a_prefix(self):
        sequences, weights = [("S", "E"), ("S",)], [99, 1]
        patterns, minimum = mine_scope(sequences, weights, 100)
        rules = rules_from(patterns, sequences, weights, minimum)
        self.assertAlmostEqual(rules[(("S",), "E")][0], 0.99)

    def test_transitions_skip_uncertain_steps(self):
        counts, _ = transition_counts([("h", 1, {1}, 5)], {1: ("A", "B")})
        self.assertEqual(counts["h"][BEGIN]["A"], 5)
        self.assertNotIn("A", counts["h"])
        self.assertEqual(counts["h"]["B"][END], 5)


class Scoring(unittest.TestCase):
    def setUp(self):
        transitions = {"*": {BEGIN: {"A": 100}, "A": {"B": 99, END: 1}, "B": {END: 100}}}
        transitions["h"] = transitions["*"]
        self.model = Model({"transitions": transitions, "unigrams": {"A": 100, "B": 99, END: 101}})
        self.rules = {"h": [(("A",), "B", 0.99)]}

    def test_common_routine_is_not_surprising(self):
        score = score_one(("A", "B"), "h", set(), False, False, self.model, self.rules, {("h", ("A", "B"))})[0]
        self.assertLess(score, 1.0)

    def test_ending_early_breaks_the_rule(self):
        score, step, _, _, _, broken, text = score_one(("A",), "h", set(), False, False, self.model, self.rules, set())
        self.assertGreater(score, 5.0)
        self.assertEqual(step, "A > (end)")
        self.assertIn("A => B", broken)
        self.assertIn("never occurred on this host", text)

    def test_right_censored_end_is_not_scored(self):
        score, _, _, _, _, broken, _ = score_one(("A",), "h", set(), False, True, self.model, self.rules, set())
        self.assertLess(score, 1.0)
        self.assertEqual(broken, "")

    def test_unknown_event_type_is_described(self):
        _, _, p, _, _, _, text = score_one(("Z",), "h", set(), False, False, self.model, self.rules, set())
        self.assertLess(p, 1e-3)
        self.assertIn("Z never occurred in training", text)

    def test_probabilities_sum_to_one(self):
        total = sum(self.model.probability("A", nxt, "h") for nxt in ("A", "B", END)) + self.model.unseen * 0
        self.assertTrue(math.isclose(total, 1.0, rel_tol=0.02))


class Profile(unittest.TestCase):
    def test_items(self):
        self.assertEqual(family("stn09abc"), "stn")
        self.assertEqual(family("stnabc"), "stnabc")
        self.assertEqual(hour_band(13), "12-18")
        self.assertEqual(steps_band(5), "4-6")
        self.assertEqual(source_class("10.1.2.3"), "private")
        self.assertEqual(source_class(""), "none")

    def test_lift_and_duplicate_combinations(self):
        n = 1000
        host = np.zeros(n, dtype=bool); host[:100] = True
        twin = host.copy()
        other = np.zeros(n, dtype=bool); other[::2] = True
        flags = np.zeros(n, dtype=bool); flags[:50] = True; flags[500:510] = True
        rows, alerts, base = profile("X", flags, {"host=a": host, "has=T": twin, "day=weekday": other})
        self.assertEqual(alerts, 60)
        kept = {row["items"]: row for row in rows}
        self.assertEqual(sum(item in kept for item in ("has=T", "host=a")), 1)
        best = max(rows, key=lambda row: row["lift"])
        self.assertAlmostEqual(best["alert_rate_with_items"], 0.5)


if __name__ == "__main__":
    unittest.main()
