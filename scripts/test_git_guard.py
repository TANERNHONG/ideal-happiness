"""The git guard and the name filter, in a throwaway repository with made-up names only.

    .venv/Scripts/python.exe -m unittest discover -s scripts -p "test_*.py" -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import git_guard  # noqa: E402

KEY = "made-up-key"
NAMES = {"stnalpha": "server", "stnbravo": "server", "10.9.8.7": "source_ip", "jdoe.made": "username"}
TEXT = "Login to stnalpha from 10.9.8.7 by jdoe.made.\r\nSTNALPHA again; stnbravo/10.9.8.7 too.\r\nroot and srv stay.\r\n"


class GuardRepo(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="huh-guard-"))
        self.repo = self.tmp / "repo"
        for rel in ("scripts/git_guard.py", "scripts/git_names_filter.py", "pipeline/shared/runlog.py",
                    ".gitattributes", ".gitignore", ".githooks/pre-commit", ".githooks/pre-push"):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, self.repo / rel)
        (self.repo / "scripts" / "check.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("config", "core.autocrlf", "true")
        self.git("config", "core.hooksPath", ".githooks")
        self.git("config", "filter.huh-names.process", f'"{Path(sys.executable).as_posix()}" scripts/git_names_filter.py')
        self.git("config", "filter.huh-names.required", "true")
        hashes = {git_guard._digest(KEY, value): kind for value, kind in NAMES.items()}
        (self.repo / ".git" / "identifier_hashes.json").write_text(json.dumps({"key": KEY, "hashes": hashes}), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def git(self, *args, check=True, input=None):
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        return subprocess.run(["git", *args], cwd=self.repo, capture_output=True, text=True, check=check, input=input, env=env)

    def test_names_become_pseudonyms_in_git_and_come_back(self):
        (self.repo / "notes.md").write_bytes(TEXT.encode("utf-8"))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "notes")
        stored = self.git("show", "HEAD:notes.md").stdout
        for value in ("stnalpha", "STNALPHA", "stnbravo", "10.9.8.7", "jdoe.made"):
            self.assertNotIn(value, stored)
        self.assertIn("srv-01", stored)
        self.assertRegex(stored, r"198\.18\.0\.\d")
        self.assertIn("acct-01", stored)
        self.assertIn("root and srv stay.", stored)
        (self.repo / "notes.md").unlink()
        self.git("checkout", "--", "notes.md")
        self.assertEqual((self.repo / "notes.md").read_bytes(), TEXT.encode("utf-8"))
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_commit_refuses_data_and_site_lists(self):
        for rel in ("triage-console/var/console.sqlite3", "pipeline/phase9_llm_triage/site/assets.csv", "cache.pkl"):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text("x\n", encoding="utf-8")
            self.git("add", "-f", rel)
            result = self.git("commit", "-q", "-m", "data", check=False)
            self.assertNotEqual(result.returncode, 0, rel)
            self.assertIn("Refused", result.stderr)
            self.assertNotIn("x\n", result.stderr)
            self.git("rm", "-q", "--cached", rel)

    def test_push_refuses_a_name_that_slipped_past_the_filter(self):
        remote = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True)
        self.git("remote", "add", "origin", str(remote))
        self.git("config", "--unset", "filter.huh-names.process")
        self.git("config", "--unset", "filter.huh-names.required")
        (self.repo / "leak.md").write_text("stnalpha\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "--no-verify", "-m", "leak")
        result = self.git("push", "-q", "origin", "main", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Identifier in leak.md", result.stderr)
        self.assertNotIn("stnalpha", result.stderr)

    def test_push_without_the_identifier_list_is_refused(self):
        remote = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True)
        self.git("remote", "add", "origin", str(remote))
        (self.repo / "a.md").write_text("hello\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "a")
        (self.repo / ".git" / "identifier_hashes.json").unlink()
        result = self.git("push", "-q", "origin", "main", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no identifier list", result.stderr)


class Rules(unittest.TestCase):
    def test_refused_paths(self):
        self.assertTrue(git_guard.refused("data/phase1/x.csv"))
        self.assertTrue(git_guard.refused("triage-console/web/node_modules/a/b.js"))
        self.assertTrue(git_guard.refused("whitepaper/figures/review.jpg"))
        self.assertIsNone(git_guard.refused("pipeline/phase9_llm_triage/site/public_holidays.csv"))
        self.assertIsNone(git_guard.refused("triage-console/auth.example.json"))

    def test_common_words_and_short_values_are_not_identifiers(self):
        self.assertFalse(git_guard._keep("root"))
        self.assertFalse(git_guard._keep("abc"))
        self.assertFalse(git_guard._keep("127.0.0.1"))
        self.assertTrue(git_guard._keep("stnalpha"))
        self.assertTrue(git_guard._keep("10.9.8.7"))


if __name__ == "__main__":
    unittest.main()
