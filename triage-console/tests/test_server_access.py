"""Who can reach the service over HTTP (service/server.py, NFR-SEC-10, NFR-SEC-17): only the app's own scripts reach the
API. An /api/ address typed into the browser, a bookmark, a link or another site is refused, and only the built app's
files are served, by exact name. A real server on a free port, over a stand-in build and stand-in routes, so a failing
check never reads the console's own data.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_server_access -v
"""
from __future__ import annotations

import http.client
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import server  # noqa: E402

HEADER = "X-Console-Request"                # web/src/api.ts adds it to every request
# What a browser sends for an address typed in, a bookmark or a link followed.
TYPED = {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
# What the app's own fetch() sends.
APP = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", HEADER: "1"}
ROUTES = [("GET", "/api/health"), ("GET", "/api/audit"), ("GET", "/api/settings"), ("GET", "/api/whitelist"),
          ("GET", "/api/uploads/item"), ("GET", "/api/docs/page"), ("POST", "/api/usage")]


class Access(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        dist = Path(cls.folder.name) / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<!doctype html><title>app</title>", encoding="utf-8")
        (dist / "assets" / "index.js").write_text("console.log(1)", encoding="utf-8")
        (Path(cls.folder.name) / "secret.txt").write_text("not for the browser", encoding="utf-8")
        cls.patches = [mock.patch.object(server, "WEB_DIST", dist),
                       mock.patch.dict(server.ROUTES, {r: lambda q, body: {"ok": True} for r in ROUTES}, clear=True)]
        for p in cls.patches:
            p.start()
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        for p in cls.patches:
            p.stop()
        cls.folder.cleanup()

    def request(self, method: str, path: str, headers: dict | None = None, body: bytes | None = None) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.http.server_address[1], timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_the_app_reaches_the_api(self):
        self.assertEqual(self.request("GET", "/api/health", APP), (200, b'{"ok": true}'))
        post = {**APP, "Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.PORT}"}
        self.assertEqual(self.request("POST", "/api/usage", post, b'{"event": "view:test"}'), (200, b'{"ok": true}'))

    def test_the_app_sends_the_header(self):
        self.assertEqual(server.API_HEADER, HEADER)
        client = (Path(server.__file__).resolve().parents[1] / "web" / "src" / "api.ts").read_text(encoding="utf-8")
        self.assertIn(f'"{HEADER}": "1"', client)

    def test_a_typed_address_is_refused(self):
        for path in ("/api/health", "/api/audit", "/api/settings", "/api/whitelist", "/api/uploads/item?id=1",
                     "/api/docs/page?id=app/README", "/api/no-such-api"):
            with self.subTest(path=path):
                status, body = self.request("GET", path, TYPED)
                self.assertEqual(status, 403, body)

    def test_a_typed_address_is_refused_even_with_the_header(self):
        """A browser extension that adds headers to every request still cannot open the API from the address bar."""
        self.assertEqual(self.request("GET", "/api/health", {**TYPED, HEADER: "1"})[0], 403)

    def test_without_the_header_is_refused(self):
        """An older browser that sends no Sec-Fetch-* headers, a link, an image or a script tag on another page."""
        for headers in ({}, {"Sec-Fetch-Site": "same-origin"}, {**APP, HEADER: "0"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("GET", "/api/health", headers)[0], 403)

    def test_writes_need_the_header_too(self):
        headers = {"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "Origin": f"http://127.0.0.1:{server.PORT}"}
        self.assertEqual(self.request("POST", "/api/usage", headers, b'{"event": "view:test"}')[0], 403)

    def test_another_site_is_refused_even_with_the_header(self):
        for headers in ({**APP, "Sec-Fetch-Site": "cross-site"}, {**APP, "Sec-Fetch-Site": "same-site"},
                        {**APP, "Origin": "http://evil.example"}, {**APP, "Host": f"evil.example:{server.PORT}"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("GET", "/api/health", headers)[0], 403)

    def test_cors_preflight_is_never_answered(self):
        """Another site's script may add a custom header only after the browser asks (OPTIONS) and is allowed."""
        self.assertFalse(hasattr(server.Handler, "do_OPTIONS"))
        status, _ = self.request("OPTIONS", "/api/health", {"Origin": "http://evil.example", "Access-Control-Request-Method": "GET",
                                                            "Access-Control-Request-Headers": HEADER.lower()})
        self.assertGreaterEqual(status, 400)

    def test_the_built_app_is_served(self):
        for path in ("/", "/index.html", "/assets/index.js"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path, TYPED)[0], 200)
        self.assertIn(b"<title>app", self.request("GET", "/", TYPED)[1])

    def test_nothing_else_is_served(self):
        """Pages are #/ routes, so any other address is not found (not the app), and never reaches the file system."""
        for path in ("/sql", "/datasets", "/admin", "/api", "/API/audit", "//elsewhere/api/audit", "/assets", "/assets/", "/favicon.ico",
                     "/../secret.txt", "/assets/../../secret.txt", "/%2e%2e/secret.txt", "/..\\secret.txt",
                     "/C:/Windows/win.ini", "/index.html/"):
            with self.subTest(path=path):
                status, body = self.request("GET", path, TYPED)
                self.assertEqual(status, 404, body[:80])
                self.assertNotIn(b"not for the browser", body)


if __name__ == "__main__":
    unittest.main()
