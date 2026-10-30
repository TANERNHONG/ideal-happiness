"""ATT&CK for ICS visibility (service/coverage.py) on the shipped offline copy (attack_ics.json, MITRE's public data)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import coverage  # noqa: E402


class Coverage(unittest.TestCase):
    def test_status_rule(self):
        have, planned = {"Logon Session Creation": ["AUTH"]}, {"Device Alarm": ["SCS event logs"]}
        self.assertEqual(coverage.status([], have, planned), "none")
        self.assertEqual(coverage.status(["Logon Session Creation"], have, planned), "visible")
        self.assertEqual(coverage.status(["Logon Session Creation", "Process Creation"], have, planned), "partly")
        self.assertEqual(coverage.status(["Device Alarm", "Process Creation"], have, planned), "planned")
        self.assertEqual(coverage.status(["Process Creation"], have, planned), "blind")

    def test_the_matrix_follows_mitre_order_and_counts_every_technique_once(self):
        m = coverage.matrix()
        self.assertEqual([t["short"] for t in m["tactics"]][:2], ["initial-access", "execution"])
        self.assertEqual(len(m["tactics"]), 12)
        total = len({t["id"] for tactic in m["tactics"] for t in tactic["techniques"]})
        self.assertEqual(sum(m["counts"].values()), total)
        valid = next(t for tactic in m["tactics"] for t in tactic["techniques"] if t["name"] == "Valid Accounts")
        self.assertIn(valid["status"], ("visible", "partly"))                  # SSH logins are in the AUTH log
        self.assertTrue(any("AUTH" in c["by"] for c in valid["components"]))
        self.assertIn("MITRE", m["notice"])


if __name__ == "__main__":
    unittest.main()
