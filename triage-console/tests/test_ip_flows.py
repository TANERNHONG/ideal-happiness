"""Tests for Traffic by address (service/ip_flows.py): grouping addresses at four levels, and the SQL
for the lines behind a box or band of the chart (it passes the SQL guard and selects the right rows).

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import ip_flows  # noqa: E402
from service.sql_guard import check  # noqa: E402

FLOWS = [  # month, log, from, to, lines
    ["2026-06", "pf", "10.1.2.3", "10.9.9.9", 5],
    ["2026-06", "pf", "10.1.7.8", "10.9.9.9", 3],
    ["2026-06", "pf", "10.20.0.1", "172.16.0.5", 2],
    ["2026-07", "pf", "192.168.1.1", "172.16.0.5", 1],
    ["2026-06", "auth", "10.1.2.3", "host09", 4],
    ["2026-06", "ossec", "unknown", "172.16.0.5", 6],
]


class Grouping(unittest.TestCase):
    def test_levels(self):
        self.assertEqual([ip_flows.group("10.1.2.3", n) for n in (1, 2, 3, 4)], ["10.x.x.x", "10.1.x.x", "10.1.2.x", "10.1.2.3"])
        self.assertEqual(ip_flows.group("host09", 1), "host09")                      # names stay as they are
        self.assertEqual(ip_flows.group("2001:db8::1", 2), "2001:0db8::/32")

    def test_sankey_merges_at_the_chosen_level(self):
        with mock.patch.dict(ip_flows._state, {"status": "ready", "flows": FLOWS}):
            nodes = {n["label"] for n in ip_flows.sankey(["pf"], level=1)["nodes"] if n["level"] == 0}
            self.assertEqual(nodes, {"10.x.x.x", "192.x.x.x"})
            nodes = {n["label"] for n in ip_flows.sankey(["pf"], level=2)["nodes"] if n["level"] == 0}
            self.assertEqual(nodes, {"10.1.x.x", "10.20.x.x", "192.168.x.x"})
            nodes = {n["label"] for n in ip_flows.sankey(["pf"], level=2, top=1)["nodes"] if n["level"] == 0}
            self.assertEqual(nodes, {"10.1.x.x", "other addresses"})


class SelectionQuery(unittest.TestCase):
    """The query run on a small database shaped like the firewall table."""

    def setUp(self):
        self.patch = mock.patch.dict(ip_flows._state, {"status": "ready", "flows": FLOWS})
        self.patch.start()
        self.con = sqlite3.connect(":memory:")
        self.con.execute("ATTACH ':memory:' AS fw")
        self.con.execute("CREATE TABLE fw.pf_events (timestamp TEXT, event_type TEXT, source_ip TEXT, destination_ip TEXT, "
                         "raw_message TEXT, partition_month TEXT)")
        rows = [("2026-06-01 00:00:00", "PF", s, d, f"{s}>{d}", m) for m, log, s, d, n in FLOWS if log == "pf" for _ in range(n)]
        self.con.executemany("INSERT INTO fw.pf_events VALUES (?,?,?,?,?,?)", rows)

    def tearDown(self):
        self.patch.stop()
        self.con.close()

    def lines(self, **selection) -> int:
        query = ip_flows.selection_query(["pf"], **selection)
        check(query)                                                     # read-only, one statement
        return len(self.con.execute(query).fetchall())

    def test_a_group_at_each_level(self):
        self.assertEqual(self.lines(level=1, a="10.x.x.x"), 10)
        self.assertEqual(self.lines(level=2, a="10.1.x.x"), 8)
        self.assertEqual(self.lines(level=3, a="10.1.2.x"), 5)
        self.assertEqual(self.lines(level=4, a="10.1.7.8"), 3)
        self.assertEqual(self.lines(level=2, a="10.20.x.x"), 2)                # not the 10.2.x.x range

    def test_band_destination_and_months(self):
        self.assertEqual(self.lines(level=3, source="pf", b="172.16.0.x"), 3)
        self.assertEqual(self.lines(level=3, b="172.16.0.x", start="2026-07", end="2026-07"), 1)

    def test_other(self):
        self.assertEqual(self.lines(level=2, top=1, a="other addresses"), 3)    # everything but 10.1.x.x

    def test_nothing_chosen(self):
        with self.assertRaises(ValueError):
            ip_flows.selection_query(["pf"])


if __name__ == "__main__":
    unittest.main()
