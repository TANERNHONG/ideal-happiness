"""Tests for the event log's device-types document (service/event_log_docs.py): built from the pipeline's own
groups, with the counts of the last run when there is one.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import event_log_docs  # noqa: E402
from service.pipeline_code import module  # noqa: E402


class DeviceTypes(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.counts = Path(self.folder.name) / "event_log_devices_summary.json"
        self.patch = mock.patch.object(event_log_docs, "COUNTS", self.counts)
        self.patch.start()
        self.devices = module("phase1_classify/event_log_devices.py")
        self.groups = list(self.devices.check_groups(self.devices.STATE_GROUPS))

    def tearDown(self):
        self.patch.stop()
        self.folder.cleanup()

    def test_every_group_and_status_of_the_code(self):
        text = event_log_docs.markdown()
        self.assertTrue(text.startswith("# Event log device types\n"))
        for group in self.groups:
            self.assertRegex(text, rf"\| {group} \| .+ \| – \|")
        self.assertIn("| Transformer | 01–20 | – |", text)
        self.assertIn("| ON/OFF | ON · OFF | – |", text)
        for status in self.devices.STATUSES:
            self.assertEqual(f"| {status} |" in text, status != self.devices.GROUPED, status)
        self.assertIn("No counts yet", text)

    def test_the_counts_of_the_last_run(self):
        run = {"created_at": "2026-10-21 09:00:00", "months": ["2026-09", "2026-10"], "lines": 1200, "devices": 30,
               "statuses": {"grouped": 20, "ungrouped": 10}, "groups": {"ON/OFF": 20}, "state_groups": self.groups}
        self.counts.write_text(json.dumps(run), encoding="utf-8")
        text = event_log_docs.markdown()
        self.assertIn("Last run 2026-10-21 09:00:00 · 30 devices · 1,200 lines · 2 months", text)
        self.assertIn("| ON/OFF | ON · OFF | 20 |", text)
        self.assertIn("| OPEN/CLOSE | OPEN · CLOSE | 0 |", text)
        self.assertRegex(text, r"\| ungrouped \| .* \| 10 \|")
        self.assertNotIn("changed", text)
        self.counts.write_text(json.dumps({**run, "state_groups": self.groups[:-1]}), encoding="utf-8")
        self.assertIn("Groups changed since the last run", event_log_docs.markdown())


if __name__ == "__main__":
    unittest.main()
