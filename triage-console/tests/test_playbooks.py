"""Every section Review's Playbook button can open (web/src/playbooks.ts) is a heading of docs/user/07_playbooks.md,
as the Docs page slugs it (lower case, punctuation dropped, spaces to hyphens)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1]


def slug(text: str) -> str:
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", text.strip().lower()))


class Playbooks(unittest.TestCase):
    def test_every_anchor_is_a_heading(self):
        headings = {slug(line.lstrip("#")) for line in (APP / "docs" / "user" / "07_playbooks.md").read_text(encoding="utf-8").splitlines()
                    if line.startswith("## ")}
        anchors = set(re.findall(r'"([a-z-]+)"', (APP / "web" / "src" / "playbooks.ts").read_text(encoding="utf-8")))
        anchors -= {"activity_alert", "presence_alert", "pf", "ipf"}
        self.assertTrue(anchors)
        self.assertEqual(anchors - headings, set())


if __name__ == "__main__":
    unittest.main()
