"""Security checks: who can call the service (Host, Origin, Sec-Fetch-Site, JSON only, the page's headers), and the
inputs that could carry code or exhaust memory (a crafted workbook, a regex written into the Phase 1 export, very long
lines, the model's address, parallel password guesses). The server runs in-process on a spare port; nothing touches
data/ or var/.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_security -v
"""
from __future__ import annotations

import ast
import http.client
import io
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import config, patterns, server, store, tabular  # noqa: E402

OWN = "http://127.0.0.1:8765"


class RequestGate(unittest.TestCase):
    """Real HTTP requests to the console's handler."""

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        dist = Path(cls.folder.name) / "dist"
        dist.mkdir()
        (dist / "index.html").write_text("<!doctype html><title>app</title>", encoding="utf-8")
        cls.patch = mock.patch.object(server, "WEB_DIST", dist)
        cls.patch.start()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.patch.stop()
        cls.folder.cleanup()

    def ask(self, path="/api/health", method="GET", headers=None, body=None):
        con = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        sent = {"Host": f"127.0.0.1:{self.port}", server.API_HEADER: "1", **(headers or {})}   # as the app's scripts send it
        con.request(method, path, body=body, headers=sent)
        response = con.getresponse()
        response.read()
        con.close()
        return response

    def test_the_apps_own_requests_pass_with_safe_headers(self):
        for headers in ({}, {"Origin": OWN, "Sec-Fetch-Site": "same-origin"}):   # an address typed in: test_server_access
            with self.subTest(headers=headers):
                r = self.ask(headers=headers)
                self.assertEqual(r.status, 200)
                self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
                self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
                self.assertEqual(r.getheader("Cross-Origin-Resource-Policy"), "same-origin")
                self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))      # no other site may read answers

    def test_other_hosts_refused_dns_rebinding(self):
        for host in ("evil.example", "evil.example:8765", "192.168.1.5:8765"):
            with self.subTest(host=host):
                self.assertEqual(self.ask(headers={"Host": host}).status, 403)

    def test_other_origins_refused(self):
        for origin in ("https://evil.example", "null", "http://127.0.0.1.evil.example"):
            with self.subTest(origin=origin):
                self.assertEqual(self.ask(headers={"Origin": origin}).status, 403)

    def test_requests_from_other_sites_refused(self):
        for site in ("cross-site", "same-site"):
            with self.subTest(site=site):
                self.assertEqual(self.ask(headers={"Sec-Fetch-Site": site}).status, 403)
                self.assertEqual(self.ask("/auth/logout", headers={"Sec-Fetch-Site": site}).status, 403)

    def test_page_opens_from_a_link_but_cannot_be_framed_or_run_others_scripts(self):
        r = self.ask("/", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"})
        self.assertEqual(r.status, 200)
        policy = r.getheader("Content-Security-Policy") or ""
        for part in ("frame-ancestors 'none'", "script-src 'self'", "object-src 'none'", "base-uri 'none'"):
            self.assertIn(part, policy)

    def test_changes_only_as_json_and_no_cross_origin_preflight(self):
        r = self.ask("/api/usage", "POST", {"Content-Type": "text/plain"}, b'{"event": "view:dashboard"}')
        self.assertEqual(r.status, 415)
        r = self.ask("/api/sql", "OPTIONS", {"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertNotIn(r.status, (200, 204))
        self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))

    def test_static_files_stay_inside_the_app(self):
        for path in ("/../service/config.py", "/..%2F..%2Fservice%2Fconfig.py", "/assets/../../service/config.py"):
            with self.subTest(path=path):
                self.assertEqual(self.ask(path).status, 404)                            # not the file, nor the app


def workbook(sheet_xml: str, strings: list[str] | None = None) -> bytes:
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as book:
        book.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="{main}"><sheetData>{sheet_xml}</sheetData></worksheet>')
        if strings is not None:
            items = "".join(f"<si><t>{s}</t></si>" for s in strings)
            book.writestr("xl/sharedStrings.xml", f'<sst xmlns="{main}">{items}</sst>')
    return buffer.getvalue()


class CraftedInputs(unittest.TestCase):
    def test_workbook_cell_far_past_the_last_column_is_ignored(self):
        data = workbook('<row r="1"><c r="A1" t="inlineStr"><is><t>ok</t></is></c>'
                        '<c r="ZZZZZZZZZZZZZZ1" t="inlineStr"><is><t>far</t></is></c></row>')
        self.assertEqual(list(tabular.xlsx_rows(io.BytesIO(data))), [["ok"]])        # quick, and no trillion-cell row

    def test_workbook_part_unpacking_too_large_is_refused(self):
        data = workbook('<row r="1"><c r="A1" t="s"><v>0</v></c></row>', ["x" * 5000])
        with mock.patch.object(tabular, "MAX_PART", 1000):
            with self.assertRaises(ValueError):
                list(tabular.xlsx_rows(io.BytesIO(data)))
            with self.assertRaises(ValueError):
                tabular.capped(io.BytesIO(b"x" * 1001))

    def test_regex_with_a_line_break_cannot_become_phase1_code(self):
        for regex in ("x\nimport os; os.system('calc')#", "a\rb", 'say "hi"\n', "tab\there", "end\\"):
            with self.subTest(regex=regex):
                literal = patterns._python(regex)
                self.assertNotIn("\n", literal)
                self.assertNotIn("\r", literal)
                self.assertEqual(ast.literal_eval(literal), regex)                 # reads back as the same text
                comment = f"# auth: prefix {literal}"
                self.assertEqual(ast.parse(comment).body, [])                       # still only a comment

    def test_very_long_line_is_cut(self):
        pieces = list(patterns._decoded(io.BytesIO(b"x" * (3 * patterns.MAX_LINE) + b"\nend\n")))
        self.assertTrue(all(len(p) <= 2 * patterns.MAX_LINE + 1 for p in pieces))
        self.assertEqual(pieces[-1], "end\n")

    def test_model_address_must_be_http_on_this_laptop(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(config, "VAR", Path(folder)), mock.patch.object(config, "SETTINGS_FILE", Path(folder) / "s.json"):
            for endpoint in ("file://localhost/C:/Windows/win.ini", "ftp://localhost/", "http://evil.example:11434",
                             "http://127.0.0.1@evil.example/", "gopher://127.0.0.1/"):
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    config.save_settings({"llm_endpoint": endpoint})
            self.assertEqual(config.save_settings({"llm_endpoint": "http://localhost:11434"})["llm_endpoint"], "http://localhost:11434")

    def test_password_guesses_wait_one_at_a_time(self):
        held = []
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(store, "SQL_PASSWORD_FILE", Path(folder) / "p.json"), \
                mock.patch.object(store.time, "sleep", side_effect=lambda s: held.append(store._guessing.locked())):
            threads = [threading.Thread(target=store.check_sql_password, args=("wrong",)) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(held, [True] * 4)              # every wait happened inside the one-at-a-time lock


if __name__ == "__main__":
    unittest.main()
