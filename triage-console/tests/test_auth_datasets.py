"""Tests for SSO (service/auth.py) and the admin-only dataset actions (service/datasets.py).

A small fake OpenID Connect provider runs on localhost, with its own signing key,
so the whole sign-in flow (Authlib for the request and code exchange, joserfc for
the ID token) is exercised without a real identity provider or network.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from joserfc import jwt  # noqa: E402
from joserfc.jwk import KeySet, RSAKey  # noqa: E402

from service import auth, datasets, sso_check, store  # noqa: E402


def b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


class FakeProvider:
    """Discovery, keys and token endpoints. The test sets the next token's claims, and can make the
    provider sign with a key it does not publish, send an unsigned token, or rotate its key."""

    def __init__(self):
        self.claims: dict = {}
        self.key = RSAKey.generate_key(2048, parameters={"kid": "key-1"})
        self.signing_key = None                  # sign with this instead of the published key
        self.unsigned = False
        self.token_error = None                  # answer the code exchange with this OAuth error
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _json(self, data):
                body = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/jwks":
                    return self._json(KeySet([provider.key]).as_dict(private=False))
                self._json({"issuer": provider.issuer, "authorization_endpoint": provider.issuer + "/authorize",
                            "token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/jwks",
                            "end_session_endpoint": provider.issuer + "/logout",
                            "id_token_signing_alg_values_supported": ["RS256"]})

            def do_POST(self):
                form = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                provider.last_form = {k: v[0] for k, v in form.items()}
                if provider.token_error:
                    body = json.dumps(provider.token_error).encode()
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    return self.wfile.write(body)
                self._json({"id_token": provider.id_token(), "access_token": "at", "token_type": "Bearer"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.issuer = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def id_token(self) -> str:
        if self.unsigned:
            return b64({"alg": "none", "typ": "JWT"}) + "." + b64(self.claims) + "."
        key = self.signing_key or self.key
        return jwt.encode({"alg": "RS256", "kid": key.kid}, self.claims, key)

    def rotate(self):
        self.key = RSAKey.generate_key(2048, parameters={"kid": f"key-{time.time_ns()}"})

    def close(self):
        self.server.shutdown()


class SignIn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = FakeProvider()

    @classmethod
    def tearDownClass(cls):
        cls.provider.close()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.saved = (auth.AUTH_FILE, store.log_action)
        auth.AUTH_FILE = Path(self.folder.name) / "auth.json"
        store.log_action = lambda *args, **kwargs: None
        auth._discovery.clear()
        auth._keys.clear()
        self.provider.signing_key, self.provider.unsigned, self.provider.token_error = None, False, None
        self.configure(mode="oidc")

    def tearDown(self):
        auth.AUTH_FILE, store.log_action = self.saved
        auth.bind(None)
        self.folder.cleanup()

    def configure(self, **changes):
        settings = {"mode": "oidc", "issuer": self.provider.issuer, "client_id": "console",
                    "redirect_uri": "http://localhost:8765/auth/callback", "admin_claim": "roles",
                    "admin_values": ["OT-Console-Admin"], **changes}
        auth.AUTH_FILE.write_text(json.dumps(settings), encoding="utf-8")

    def start(self) -> dict:
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth.login_redirect()).query))
        self.assertEqual(query["code_challenge_method"], "S256")
        return query

    def good_claims(self, query, **changes):
        now = int(time.time())
        return {"iss": self.provider.issuer, "aud": "console", "exp": now + 600, "iat": now, "nonce": query["nonce"],
                "sub": "u1", "name": "Ada", "email": "ada@example.org", "roles": ["OT-Console-Admin"], **changes}

    def finish(self, query) -> str:
        return auth.complete_login({"state": query["state"], "code": "abc"})

    def test_admin_signs_in_and_is_admin(self):
        query = self.start()
        self.provider.claims = self.good_claims(query)
        session = auth.complete_login({"state": query["state"], "code": "abc"})
        self.assertIn("code_verifier", self.provider.last_form)                 # PKCE verifier sent to the token endpoint
        auth.bind(f"{auth.COOKIE}={session}")
        self.assertEqual(auth.require_admin().email, "ada@example.org")
        self.assertTrue(auth.status()["admin"])

    def test_signed_in_but_not_admin(self):
        query = self.start()
        self.provider.claims = self.good_claims(query, roles=["Reader"])
        auth.bind(f"{auth.COOKIE}={auth.complete_login({'state': query['state'], 'code': 'abc'})}")
        with self.assertRaises(PermissionError):
            auth.require_admin()

    def test_bad_answers_are_refused(self):
        cases = {"nonce": {"nonce": "other"}, "audience": {"aud": "someone-else"}, "issuer": {"iss": "https://evil.example"},
                 "expired": {"exp": int(time.time()) - 600},          # past the clock leeway
                 "issued in the future": {"iat": int(time.time()) + 3600},
                 "two audiences, other party": {"aud": ["console", "other-app"], "azp": "other-app"}}
        for label, change in cases.items():
            with self.subTest(label):
                query = self.start()
                self.provider.claims = self.good_claims(query, **change)
                with self.assertRaises(PermissionError):
                    auth.complete_login({"state": query["state"], "code": "abc"})

    def test_forged_signature_is_refused(self):
        query = self.start()
        self.provider.claims = self.good_claims(query)
        self.provider.signing_key = RSAKey.generate_key(2048, parameters={"kid": "key-1"})   # same name, wrong key
        with self.assertRaises(PermissionError):
            self.finish(query)

    def test_unsigned_token_is_refused(self):
        query = self.start()
        self.provider.claims = self.good_claims(query)
        self.provider.unsigned = True
        with self.assertRaises(PermissionError):
            self.finish(query)

    def test_rotated_provider_key_is_fetched_again(self):
        query = self.start()
        self.provider.claims = self.good_claims(query)
        self.finish(query)                                  # the console now holds key-1
        self.provider.rotate()
        query = self.start()
        self.provider.claims = self.good_claims(query)
        auth.bind(f"{auth.COOKIE}={self.finish(query)}")
        self.assertTrue(auth.status()["admin"])

    def test_sign_in_shows_the_account_picker(self):
        self.assertEqual(self.start().get("prompt"), "select_account")      # the default: never a silent sign-in
        self.configure(prompt="login")
        self.assertEqual(self.start().get("prompt"), "login")
        self.configure(prompt="")
        self.assertNotIn("prompt", self.start())

    def test_sign_out_also_signs_out_at_the_provider(self):
        query = self.start()
        self.provider.claims = self.good_claims(query)
        cookie = f"{auth.COOKIE}={self.finish(query)}"
        target = auth.logout(cookie)
        self.assertTrue(target.startswith(self.provider.issuer + "/logout?"))
        sent = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(target).query))
        self.assertEqual(sent["client_id"], "console")
        self.assertIn("id_token_hint", sent)
        auth.bind(cookie)
        self.assertIsNone(auth.current())                                   # the console session is gone
        self.assertIsNone(auth.logout(cookie))                              # nothing left to sign out

    def test_missing_secret_gets_a_plain_hint(self):
        query = self.start()
        self.provider.token_error = {"error": "invalid_client", "error_description":
                                     "AADSTS7000218: The request body must contain 'client_assertion' or 'client_secret'."}
        with self.assertRaises(PermissionError) as refused:
            self.finish(query)
        self.assertIn("public client", str(refused.exception))

    def test_settings_check(self):
        results = {item: status for status, item, _ in sso_check.checks()}
        self.assertNotIn(sso_check.FAIL, results.values(), results)
        self.assertEqual(results["sign-out at provider"], sso_check.OK)
        self.configure(issuer="https://login.microsoftonline.com/common/v2.0")
        self.assertEqual({i: s for s, i, _ in sso_check.checks()}["issuer"], sso_check.FAIL)
        self.configure(redirect_uri="http://localhost:9999/callback")
        self.assertEqual({i: s for s, i, _ in sso_check.checks()}["redirect URI"], sso_check.FAIL)

    def test_unknown_or_reused_state_is_refused(self):
        query = self.start()
        self.provider.claims = self.good_claims(query)
        auth.complete_login({"state": query["state"], "code": "abc"})
        with self.assertRaises(PermissionError):
            auth.complete_login({"state": query["state"], "code": "abc"})       # used once already
        with self.assertRaises(PermissionError):
            auth.complete_login({"state": "made-up", "code": "abc"})

    def test_provider_error_is_refused(self):
        with self.assertRaises(PermissionError):
            auth.complete_login({"error": "access_denied"})

    def test_sso_off_means_no_admin_actions(self):
        self.configure(mode="off")
        auth.bind(None)
        self.assertEqual(auth.status()["mode"], "off")
        with self.assertRaises(PermissionError):
            auth.require_admin()
        with self.assertRaises(PermissionError):
            auth.login_redirect()

    def test_cookie_is_httponly_and_samesite(self):
        cookie = auth.cookie("abc")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)


class Datasets(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.saved = (datasets.REGISTRY, store.log_action)
        datasets.REGISTRY = Path(self.folder.name) / "datasets.json"
        store.log_action = lambda *args, **kwargs: None
        self.archives = Path(self.folder.name) / "incoming"
        self.archives.mkdir()
        (self.archives / "2026-08 NSEWL SCS.zip").write_bytes(b"PK")
        (self.archives / "notes.txt").write_text("not an archive")

    def tearDown(self):
        datasets.REGISTRY, store.log_action = self.saved
        self.folder.cleanup()

    def test_add_counts_only_monthly_archives(self):
        entry = datasets.add({"id": "auth-aug", "name": "August auth", "log_type": "auth", "folder": str(self.archives)}, "ada")
        self.assertEqual(entry["archives"], 1)
        self.assertTrue(any(d["id"] == "auth-aug" and d["trainable"] for d in datasets.listing()["datasets"]))

    def test_add_validates(self):
        bad = [{"id": "A!", "name": "x", "log_type": "auth", "folder": str(self.archives)},
               {"id": "auth", "name": "clash with built-in", "log_type": "auth", "folder": str(self.archives)},
               {"id": "newone", "name": "", "log_type": "auth", "folder": str(self.archives)},
               {"id": "newone", "name": "x", "log_type": "unknown", "folder": str(self.archives)},
               {"id": "newone", "name": "x", "log_type": "auth", "folder": str(Path(self.folder.name) / "missing")}]
        for body in bad:
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    datasets.add(body, "ada")

    def test_other_log_types_cannot_train(self):
        datasets.add({"id": "scada", "name": "SCADA logs", "log_type": "other", "folder": str(self.archives)}, "ada")
        with self.assertRaises(ValueError):
            datasets.train("scada", "1", "ada")

    def test_training_arguments_are_allow_listed(self):
        with self.assertRaises(ValueError):
            datasets.train("auth", "1; rm -rf /", "ada")
        with self.assertRaises(KeyError):
            datasets.train("nope", "1", "ada")


if __name__ == "__main__":
    unittest.main()
