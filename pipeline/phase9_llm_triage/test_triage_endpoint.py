"""Phase 9 sends prompts with log lines, accounts and addresses only to a model server on this machine.

    .venv/Scripts/python.exe -m unittest discover -s pipeline/phase9_llm_triage -p "test_*.py" -v
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage  # noqa: E402


class Endpoint(unittest.TestCase):
    def test_this_machine_only(self):
        for url in ("http://localhost:11434/v1", "http://127.0.0.1:8080", "http://[::1]:11434/v1", "https://LOCALHOST/v1"):
            self.assertTrue(triage.local_endpoint(url), url)
        for url in ("https://api.example.com/v1", "http://192.0.2.5:11434", "http://localhost.example.com",
                    "http://127.0.0.1.nip.io", "ftp://localhost", "localhost:11434", ""):
            self.assertFalse(triage.local_endpoint(url), url)

    def test_chat_refuses_before_sending(self):
        with self.assertRaises(ValueError):
            triage.chat("https://api.example.com/v1", "model", [{"role": "user", "content": "x"}], 1, "")

    def test_redirects_are_not_followed(self):
        handler = triage._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://api.example.com/"))


if __name__ == "__main__":
    unittest.main()
