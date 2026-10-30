"""Tests for logs that come as a table (service/tabular.py): one column the raw line, the others fields.
Recognising a table and its raw-line, time and host columns; plain logs left alone; reading rows; Analyze,
Simple mode's detector and Patterns reading the raw column; Patterns counting fields per value.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import csv
import gc
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import analyze, patterns, store, tabular  # noqa: E402

AUTH = [
    "Jul 14 16:20:37 host-a sshd[27857]: [ID 800047 auth.info] Failed password for invalid user staff08 from 192.0.2.17 port 50123 ssh2",
    "Jul 14 16:20:44 host-a sshd[27857]: [ID 800047 auth.info] Connection closed by 192.0.2.17 port 50123 [preauth]",
    "Jul 14 16:33:08 host-a su: [ID 366847 auth.notice] 'su root' succeeded for root on /dev/pts/2",
]
IPF = "Nov 27 10:15:44 host-c ipmon[172]: [ID 702911 local0.warning] 10:15:43.941525 e1000g0 @0:2 b 192.0.2.111,49758 -> 192.0.2.255,161 PR udp len 20 69 IN"


def table(header: list[str], rows: list[list[str]], delimiter: str = ",") -> str:
    out = io.StringIO()
    writer = csv.writer(out, delimiter=delimiter, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue()


def export_rows(days=range(1, 5)) -> list[list[str]]:
    """A Splunk-like export: AUTH lines (known to Phase 1) and lines of a made-up type (not known), by sourcetype."""
    rows = []
    for d in days:
        for k, line in enumerate(AUTH):
            rows.append([f"2026-07-{d:02d}T16:2{k}:00.000+08:00", "host-a", "/var/adm/authlog", "linux_secure", line])
        rows.append([f"2026-07-{d:02d}T10:00:00.000+08:00", "nas-1", "/var/log/radius", "radius",
                     f"2026-07-{d:02d}T10:00:00 nas-1 radiusd[1]: Login OK: [user{d}] (from client sw1 port {d})"])
    return rows


HEADER = ["_time", "host", "source", "sourcetype", "_raw"]
MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def xlsx(rows: list[list]) -> bytes:
    """A minimal Excel workbook: shared strings, numbers, a date style (numFmtId 22) for floats, one rich-text cell."""
    strings: list[str] = []

    def cell(ref: str, value) -> str:
        if isinstance(value, float):
            return f'<c r="{ref}" s="1"><v>{value}</v></c>'
        if value == "":
            return ""
        strings.append(str(value))
        return f'<c r="{ref}" t="s"><v>{len(strings) - 1}</v></c>'

    body = "".join(f'<row r="{i}">' + "".join(cell(f"{chr(65 + j)}{i}", v) for j, v in enumerate(row)) + "</row>"
                   for i, row in enumerate(rows, 1))
    shared = "".join(f"<si><t>{escape(s)}</t></si>" if k else f"<si><r><t>{escape(s[:2])}</t></r><r><t>{escape(s[2:])}</t></r></si>"
                     for k, s in enumerate(strings))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as book:
        book.writestr("xl/workbook.xml", f'<workbook xmlns="{MAIN}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                                         '<sheets><sheet name="Export" sheetId="1" r:id="rId1"/></sheets></workbook>')
        book.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                                                    '<Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>')
        book.writestr("xl/sharedStrings.xml", f'<sst xmlns="{MAIN}">{shared}</sst>')
        book.writestr("xl/styles.xml", f'<styleSheet xmlns="{MAIN}"><cellXfs><xf numFmtId="0"/><xf numFmtId="22"/></cellXfs></styleSheet>')
        book.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="{MAIN}"><sheetData>{body}</sheetData></worksheet>')
    return out.getvalue()


class Sniff(unittest.TestCase):
    def test_export_with_named_columns(self):
        text = table(HEADER, export_rows())
        layout = tabular.sniff(text.splitlines())
        self.assertEqual((layout["format"], layout["raw"], layout["time"], layout["host"]), ("CSV", "_raw", "_time", "host"))
        self.assertEqual(layout["fields"], ["_time", "host", "source", "sourcetype"])
        lines = tabular.raw_lines(text, layout)
        self.assertEqual(lines[0], AUTH[0])                       # quoted, with its commas and quotes intact
        self.assertEqual(len(lines), 16)

    def test_unnamed_raw_column_is_the_one_a_parser_knows(self):
        text = table(["when", "server", "note", "payload"], [["2026-07-14 16:20:37", "host-a", "a b c d e f g h", line] for line in AUTH * 3])
        layout = tabular.sniff(text.splitlines(), recognise=analyze.recognised)
        self.assertEqual((layout["raw"], layout["time"], layout["host"]), ("payload", "when", "server"))
        layout = tabular.sniff(text.splitlines(), raw="note")    # chosen by hand
        self.assertEqual(layout["raw"], "note")

    def test_tabs_and_plain_logs(self):
        self.assertEqual(tabular.sniff(table(HEADER, export_rows(), "\t").splitlines())["format"], "TSV")
        self.assertIsNone(tabular.sniff(AUTH))
        self.assertIsNone(tabular.sniff([IPF] * 5))              # the same commas on every line, but no header
        self.assertIsNone(tabular.sniff(["only one line"]))

    def test_rows_spanning_lines_and_repeated_headers(self):
        text = table(HEADER, export_rows(days=[1])) + "\n" + table(HEADER, [["2026-07-02", "h", "s", "t", "first\nsecond"]])
        layout = tabular.sniff(text.splitlines())
        lines = tabular.raw_lines(text, layout)
        self.assertEqual(lines[-1], "first second")
        self.assertNotIn("_raw", lines)

    def test_dates(self):
        self.assertEqual(tabular.date_of("2026-07-14T16:20:37.000+08:00"), "2026-07-14")
        self.assertEqual(tabular.date_of("1784000000"), tabular.date_of("1784000000123"))
        self.assertIsNone(tabular.date_of("yesterday"))


class Reading(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                        mock.patch.dict(patterns._workspaces, clear=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()

    def test_analyze_reads_the_raw_column(self):
        text = table(HEADER, [r for r in export_rows() if r[3] == "linux_secure"])
        lines, layout, hosts = analyze.read_table(text)
        self.assertEqual(lines[:3], AUTH)
        self.assertEqual(set(hosts), {"host-a"})
        path = Path(self.folder.name) / "export.csv"
        path.write_text("﻿" + text, encoding="utf-8")
        self.assertEqual(analyze.read_table(path=str(path))[0], lines)

    def test_detector_reads_the_raw_column(self):
        text = table(HEADER, [r for r in export_rows() if r[3] == "linux_secure"])
        found = patterns.detect(text.splitlines())
        self.assertEqual(found["source"], "auth")
        self.assertFalse(found["negligible"])
        self.assertEqual(found["layout"]["raw"], "_raw")
        self.assertEqual(found["host"], "host-a")
        self.assertEqual(found["month"], "2026-07")                   # from the time column

    def test_patterns_count_fields_and_filter_by_them(self):
        text = table(HEADER, export_rows())
        result = patterns.scan(text=text, family="auth", actor="me")
        self.assertEqual(result["lines"], 16)
        self.assertEqual(result["counts"]["builtin"], 12)
        self.assertEqual(result["time"]["mode"], "time")              # by the _time column
        self.assertEqual(result["time"]["field"], "_time")
        self.assertEqual(len(result["time"]["buckets"]), 4)
        by = {f["name"]: f for f in result["fields"]}
        self.assertEqual(result["fields"][0]["name"], "host")         # the host column first
        self.assertNotIn("_time", by)
        kinds = {v["value"]: (v["lines"], v["known"]) for v in by["sourcetype"]["values"]}
        self.assertEqual(kinds, {"linux_secure": (12, 12), "radius": (4, 0)})
        view = patterns.lines_view(result["workspace"], show="all", field="sourcetype", value="radius")
        self.assertEqual(len(view["lines"]), 4)
        self.assertEqual(view["lines"][0]["fields"]["host"], "nas-1")
        self.assertIn("a CSV table: the raw line in column '_raw'", patterns.export("auth")["phase1"])

    def test_preview_checks_the_first_rows(self):
        good = patterns.preview(text=table(HEADER, export_rows()))
        self.assertTrue(good["table"])
        self.assertIsNone(good["problem"])
        self.assertEqual((good["format"], good["raw"], good["rows"]), ("CSV", "_raw", 16))
        self.assertEqual([c["name"] for c in good["columns"]], HEADER)
        self.assertEqual(good["columns"][1]["sample"], "host-a")
        self.assertEqual([c["type"] for c in good["columns"]], ["date/time", "text", "text", "text", "text"])
        self.assertEqual(good["columns"][1]["head"], ["host-a"] * 3 + ["nas-1", "host-a"])     # the first five values
        typed = patterns.preview(text=table(["n", "x", "ok", "ip", "nothing", "when", "line"],
                                            [["1", "1.5", "true", "192.0.2.1", "", "1784000000", "a b"],
                                             ["-2", "3", "No", "192.0.2.2:22", "", "2026-07-01", "c d"]]))
        self.assertEqual([c["type"] for c in typed["columns"]],
                         ["integer", "decimal", "true/false", "IP address", "empty", "date/time", "text"])
        rows = export_rows()
        rows[2] = rows[2][:4]                                       # a row one value short
        bad = patterns.preview(text=table(HEADER, rows))
        self.assertEqual(bad["problem"], "Row 4 has 4 values; the header has 5.")
        self.assertEqual(bad["raw"], "")
        self.assertEqual(patterns.preview(text="\n".join(AUTH)), {"table": False})
        plain = patterns.preview(text="\n".join(AUTH), name="logs.csv")    # a .csv whose first row is no header
        self.assertTrue(plain["table"])
        self.assertIn("header", plain["problem"])
        unclear = patterns.preview(text=table(["a", "b"], [["x y", "1"], ["z w", "2"]]))
        self.assertEqual(unclear["raw"], "")                        # nothing named for it, nothing a parser knows

    def test_scan_keeps_the_columns_chosen(self):
        text = table(HEADER, export_rows())
        result = patterns.scan(text=text, family="auth", raw="_raw", fields=["host"], actor="me")
        self.assertEqual([f["name"] for f in result["fields"]], ["host"])
        self.assertEqual(result["layout"]["time"], "")              # _time not kept: dated by the lines
        view = patterns.lines_view(result["workspace"], show="all")
        self.assertEqual(set(view["lines"][0]["fields"]), {"host"})
        with self.assertRaises(ValueError):
            patterns.scan(text=text, raw="nope", actor="me")
        rows = export_rows()
        rows[0] = rows[0][:3]
        with self.assertRaises(ValueError):
            patterns.scan(text=table(HEADER, rows), raw="_raw", actor="me")

    def test_excel_workbooks(self):
        path = Path(self.folder.name) / "export.xlsx"
        path.write_bytes(xlsx([HEADER] + [[46204.5, r[1], r[2], r[3], r[4]] for r in export_rows()] + [["", "", "", "", ""]]))
        rows = list(tabular.xlsx_rows(path))
        self.assertEqual(rows[0], HEADER)
        self.assertEqual(rows[1][0], "2026-07-01 12:00:00")         # a date cell, as ISO text
        self.assertEqual(rows[1][4], AUTH[0])
        self.assertEqual(len(rows), 17)                              # the empty row skipped
        found = patterns.preview(path=str(path))
        self.assertEqual((found["format"], found["raw"], found["problem"]), ("Excel", "_raw", None))
        result = patterns.scan(path=str(path), family="auth", raw="_raw", fields=["_time", "sourcetype"], actor="me")
        self.assertEqual(result["counts"]["builtin"], 12)
        self.assertEqual(result["time"]["field"], "_time")
        self.assertEqual(analyze.read_table(path=str(path))[0][0], AUTH[0])
        old = Path(self.folder.name) / "old.xls"
        old.write_bytes(b"\xd0\xcf\x11\xe0 not a zip")
        with self.assertRaises(ValueError):
            patterns.preview(path=str(old))

    def test_a_folder_of_tables_and_plain_files(self):
        root = Path(self.folder.name) / "in"
        root.mkdir()
        (root / "a.csv").write_text(table(HEADER, export_rows(days=[1])), encoding="utf-8")
        (root / "b.log").write_text("\n".join(AUTH) + "\n", encoding="utf-8")
        result = patterns.scan(path=str(root), family="auth", actor="me")
        self.assertEqual(result["lines"], 7)                          # 4 rows of the table, 3 plain lines
        self.assertEqual(result["layout"]["raw"], "_raw")
        self.assertEqual(result["counts"]["builtin"], 6)


if __name__ == "__main__":
    unittest.main()
