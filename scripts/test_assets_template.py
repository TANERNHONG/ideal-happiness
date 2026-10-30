"""assets_template.py on a made-up entity list: missing rows are added blank, existing rows are kept as written."""
from __future__ import annotations

import csv
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import assets_template  # noqa: E402


class Template(unittest.TestCase):
    def test_adds_blanks_and_keeps_what_is_filled_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "data" / "phase4_detection" / "auth" / "profiles" / "profiles.sqlite"
            store.parent.mkdir(parents=True)
            with closing(sqlite3.connect(store)) as con, con:
                con.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, entity_type TEXT, entity TEXT)")
                con.executemany("INSERT INTO entities (entity_type, entity) VALUES (?, ?)",
                                [("server", "Host-A"), ("server", "host-b"), ("source_ip", "10.20.30.5"), ("source_ip", "10.20.30.9"),
                                 ("destination_ip", "172.16.40.1"), ("source_ip", "203.0.113.7"), ("username", "staff01")])
            out = root / "assets.csv"
            out.write_text("match,zone,role,criticality\nhost-a,OT,SCADA server,high\n", encoding="utf-8")
            assets_template.main(["--data", str(root / "data"), "--out", str(out), "-q"])
            rows = list(csv.DictReader(out.open(encoding="utf-8")))
        self.assertEqual(rows[0], {"match": "host-a", "zone": "OT", "role": "SCADA server", "criticality": "high"})
        self.assertEqual([r["match"] for r in rows[1:]], ["host-b", "10.20.30.0/24", "172.16.40.0/24"])   # not the documentation one
        self.assertTrue(all(r["zone"] == r["role"] == r["criticality"] == "" for r in rows[1:]))


if __name__ == "__main__":
    unittest.main()
