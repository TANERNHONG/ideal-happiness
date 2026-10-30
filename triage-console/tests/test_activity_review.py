"""Phase 4g activity alerts in Review (service/activity.py): the queue, labels, whitelisting, filters, the detail
panel and the logs around an alert, on Phase 4g's output for a made-up OSSEC log.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_activity_review -v
"""
from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import activity, catalog, clusters, review_context, review_filters, store, whitelist  # noqa: E402
from tests import test_activity as made_up  # noqa: E402

BURST_IP = made_up.BURST_IP


class ActivityInReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.data = Path(cls.folder.name) / "data"
        made_up.made_up_log(cls.data)
        made_up.activity.main(["--source", "ossec", "--data", str(cls.data), "--quiet"])

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        cls.folder.cleanup()

    def setUp(self):
        self.store = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.store.name)
        self.allowed = frozenset()
        self.patches = [mock.patch.object(module, "DATA", self.data) for module in (activity, catalog, clusters)] + \
                       [mock.patch.object(whitelist, "usual", return_value=None)]
        self.patches += [mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                         mock.patch.object(whitelist, "coverage", lambda source: {}),
                         mock.patch.object(whitelist, "active", lambda: self.allowed)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.store.cleanup()

    def burst(self, items):
        return next(i for i in items if i["entity_type"] == "source_ip" and i["entity"] == BURST_IP and i["peak_lines"] > 50)

    def test_each_alert_is_a_review_item_most_unusual_first(self):
        items = clusters.review_queue("ossec")
        alerts = [i for i in items if i["kind"] == "activity_alert"]
        self.assertTrue(alerts)
        self.assertEqual([i["rank"] for i in alerts], sorted(i["rank"] for i in alerts))
        burst = self.burst(alerts)
        self.assertTrue(burst["name"].startswith(f"Source IP {BURST_IP}"))              # the incident's title
        self.assertGreaterEqual(burst["incident"]["size"], 2)                         # the burst's server, user, the whole log
        self.assertEqual(len(alerts), len({i["incident"]["id"] for i in alerts if i.get("incident")}))
        self.assertEqual(burst["view"], "activity_by_entity")
        self.assertEqual(burst["top"], {"source_ip": BURST_IP})
        self.assertRegex(burst["peak"], r"^\d[\d,]* lines in \d+ min$")
        self.assertTrue(all(BURST_IP in line for line in burst["lines"]))
        self.assertIsNone(burst["review"])

    def test_a_label_is_kept_like_any_other(self):
        burst = self.burst(activity.items("ossec"))
        store.add_review("ossec", burst["view"], burst["item_id"], "activity_alert", "expected_behavior", "", "tester")
        again = self.burst(clusters.review_queue("ossec"))
        self.assertEqual(again["review"]["verdict"], "expected_behavior")

    def test_an_activity_alert_is_never_silenced_by_the_whitelist(self):
        # whitelisted on every server, the account's activity alert still asks for review: it is the account's own
        # normal that it left (whitelist.py, Never silenced)
        self.allowed = frozenset({("oracle", "")})
        oracle = next(i for i in activity.items("ossec") if i["entity_type"] == "username" and i["entity"] == "oracle")
        self.assertEqual(whitelist.mark("ossec", [oracle])[0]["whitelisted"], 0)
        incident = next(i for i in clusters.review_queue("ossec")
                        if any(m["entity"] == "oracle" for m in (i.get("incident") or {}).get("members", [])))
        self.assertFalse(incident["overridden"])

    def test_filters_keep_the_alerts_of_the_chosen_entity(self):
        items = activity.items("ossec")
        kept = review_filters.filter_queue("ossec", items, {"address": [BURST_IP]})
        self.assertTrue(kept)
        self.assertTrue(all(i["entity"] == BURST_IP for i in kept))
        self.assertEqual(review_filters.filter_queue("ossec", items, {"program": ["sshd"]}), [])
        servers = review_filters.filter_queue("ossec", items, {"host": ["HOST-A"]})
        self.assertTrue(servers and all(i["entity_type"] == "server" and i["entity"] == "host-a" for i in servers))

    def test_the_detail_panel_names_the_entity_and_its_lines(self):
        burst = self.burst(activity.items("ossec"))
        o = review_context.observation("ossec", burst["view"], burst["item_id"])
        self.assertEqual((o["method"], o["scope"], o["who"]["value"]), ("activity", "source_ip", BURST_IP))
        self.assertEqual(o["server"], "")
        self.assertTrue(o["event_ids"] and all(e.startswith("e") for e in o["event_ids"]))
        self.assertIn("peak", o["facts"])
        with self.assertRaises(KeyError):
            review_context.observation("ossec", "activity_by_entity", "no-such-alert")

    def test_around_an_ip_reads_its_own_lines_and_around_a_server_every_log(self):
        asked = []
        with mock.patch.object(review_context.sql, "run", lambda text: asked.append(text) or {"rows": [], "columns": []}):
            burst = self.burst(activity.items("ossec"))
            result = review_context.around("ossec", burst["view"], burst["item_id"], 10, 10, ["auth", "ossec"])
            self.assertIn(f"FROM ossec.events WHERE source_ip = '{BURST_IP}'", asked[-1])
            self.assertNotIn("auth.events", asked[-1])
            self.assertEqual(result["own_log"], "ossec")
            server = next(i for i in activity.items("ossec") if i["entity_type"] == "server")
            review_context.around("ossec", server["view"], server["item_id"], 10, 10, ["auth", "ossec"])
            self.assertIn("host_id = 'host-a'", asked[-1])
            self.assertIn("auth.events", asked[-1])

    def test_a_name_that_is_not_safe_never_reaches_a_query(self):
        for scope, name in (("username", "x' OR '1'='1"), ("source_ip", "1.2.3.4; DROP"), ("nothing", "a")):
            with self.assertRaises(ValueError):
                review_context.entity_query("ossec", scope, name, "2026-02-07 03:00:00", "2026-02-07 03:15:00", 10, 10)

    def test_the_catalog_offers_the_activity_views_to_review(self):
        sources = catalog.catalog()["sources"]
        self.assertEqual([v["id"] for v in sources["ossec"]["review_views"]], ["activity", "activity_by_entity"])
        self.assertEqual(sources["auth"]["review_views"], [])
        self.assertEqual(sources["pf"]["review_views"], [])
        only = clusters.review_queue("ossec", "activity")
        self.assertTrue(only and all("activity" in {m["view"] for m in (i.get("incident") or {}).get("members") or [i]}
                                     for i in only))                                  # incidents holding a whole-log alert


if __name__ == "__main__":
    unittest.main()
