"""Tests for the console settings (service/config.py): the animation choices.

    cd triage-console
    ..\.venv\Scripts\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import config  # noqa: E402


class AnimationSettings(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(config, "VAR", folder), mock.patch.object(config, "SETTINGS_FILE", folder / "settings.json")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.folder.cleanup()

    def test_defaults(self):
        settings = config.load_settings()
        self.assertEqual((settings["animations"], settings["animation_pack"]), ("all", "transit"))

    def test_packs(self):
        for pack in config.ANIMATION_PACKS:
            with self.subTest(pack=pack):
                self.assertEqual(config.save_settings({"animation_pack": pack})["animation_pack"], pack)
                self.assertEqual(config.load_settings()["animation_pack"], pack)

    def test_unknown_pack_refused(self):
        for pack in ("", "Desk", "monkey", None):
            with self.subTest(pack=pack):
                with self.assertRaises(ValueError):
                    config.save_settings({"animation_pack": pack})
        self.assertEqual(config.load_settings()["animation_pack"], "transit")

    def test_review_filter_time_limit(self):
        self.assertEqual(config.load_settings()["review_filter_seconds"], 120)
        self.assertEqual(config.save_settings({"review_filter_seconds": 300})["review_filter_seconds"], 300)
        self.assertEqual(config.save_settings({"review_filter_seconds": 45.0})["review_filter_seconds"], 45)
        for value in (9, 3601, 0, -5, "120", None, True, float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    config.save_settings({"review_filter_seconds": value})
        self.assertEqual(config.load_settings()["review_filter_seconds"], 45)

    def test_fonts(self):
        saved = config.save_settings({"font_family": "installed", "font_installed": "  LTA Identity  "})
        self.assertEqual((saved["font_family"], saved["font_installed"]), ("installed", "LTA Identity"))
        self.assertEqual(config.save_settings({"font_family": "roboto"})["font_family"], "roboto")

    def test_font_names_cannot_carry_css(self):
        for name in ('x"; } body { display: none', "url(http://example.com/f.woff)", "a" * 65, "-leading"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    config.save_settings({"font_installed": name})
        with self.assertRaises(ValueError):
            config.save_settings({"font_family": "comic"})

    def test_dashboard_layout_saved_and_reset(self):
        self.assertIsNone(config.load_settings()["dashboard_layout"])
        layout = {"cards": [{"id": "next", "span": 12}, {"id": "open", "span": 3}], "hidden": ["activity"], "widgets": {}, "tiles": {}, "packed": False}
        self.assertEqual(config.save_settings({"dashboard_layout": layout})["dashboard_layout"], layout)
        self.assertEqual(config.load_settings()["dashboard_layout"], layout)
        self.assertIsNone(config.save_settings({"dashboard_layout": None})["dashboard_layout"])

    def test_dashboard_layout_refused(self):
        for layout in ("next", {"cards": "next"}, {"cards": [{"id": "next", "span": 2}]}, {"cards": [{"id": "next", "span": 13}]},
                       {"cards": [{"id": "next", "span": 6.5}]}, {"cards": [{"id": "next", "span": True}]},
                       {"cards": [{"id": "Next<", "span": 6}]}, {"cards": [{"id": "next", "span": 6}, {"id": "next", "span": 6}]},
                       {"cards": [{"id": "next", "span": 6}], "hidden": ["next"]}, {"cards": [], "hidden": [7]},
                       {"cards": [{"id": f"c{i}", "span": 3} for i in range(101)]}, {"cards": [{"id": "sql_k1", "span": 1}]},
                       {"cards": [], "packed": "yes"}, {"cards": [], "packed": 1}):
            with self.subTest(layout=layout):
                with self.assertRaises(ValueError):
                    config.save_settings({"dashboard_layout": layout})
        self.assertIsNone(config.load_settings()["dashboard_layout"])

    def test_dashboard_sql_tables_saved(self):
        widget = {"title": "Failed logins", "description": "Per server, this month", "query": "SELECT 1", "height": 420}
        layout = {"cards": [{"id": "sql_k1", "span": 6}], "hidden": ["sql_k2"],
                  "widgets": {"sql_k1": widget, "sql_k2": {"title": "", "description": "", "query": "", "height": 360}}, "tiles": {}, "packed": False}
        self.assertEqual(config.save_settings({"dashboard_layout": layout})["dashboard_layout"], layout)
        missing_height = {"cards": [], "hidden": [], "widgets": {"sql_k3": {"title": "t", "description": "", "query": "SELECT 2"}}}
        self.assertEqual(config.save_settings({"dashboard_layout": missing_height})["dashboard_layout"]["widgets"]["sql_k3"]["height"], 360)

    def test_dashboard_sql_tables_refused(self):
        good = {"title": "", "description": "", "query": "SELECT 1", "height": 360}
        for widgets in ({"open": good}, {"sql_": good}, {"sql_A1": good}, {"sql_k1": "SELECT 1"},
                        {"sql_k1": {**good, "height": 100}}, {"sql_k1": {**good, "height": 2000}}, {"sql_k1": {**good, "height": 360.5}},
                        {"sql_k1": {**good, "title": "x" * 81}}, {"sql_k1": {**good, "description": "x" * 2001}},
                        {"sql_k1": {**good, "query": "x" * 20_001}}, {"sql_k1": {**good, "query": 7}},
                        {f"sql_k{i}": good for i in range(21)}, ["sql_k1"]):
            with self.subTest(widgets=str(widgets)[:60]):
                with self.assertRaises(ValueError):
                    config.save_settings({"dashboard_layout": {"cards": [], "hidden": [], "widgets": widgets}})

    def test_dashboard_tiles_saved_down_to_one_column(self):
        tile = {"icon": "check-circle", "link": "review", "heading": "All clear", "text": "Nothing waiting\nsince Monday",
                "size": "l", "tone": "green", "align": "center", "height": 100}
        layout = {"cards": [{"id": "tile_a1", "span": 1}, {"id": "open", "span": 3}], "hidden": [], "widgets": {}, "tiles": {"tile_a1": tile},
                  "packed": True}
        self.assertEqual(config.save_settings({"dashboard_layout": layout})["dashboard_layout"], layout)
        bare = config.save_settings({"dashboard_layout": {"cards": [], "hidden": [], "tiles": {"tile_b": {}}}})["dashboard_layout"]["tiles"]["tile_b"]
        self.assertEqual(bare, {"icon": "", "link": "", "heading": "", "text": "", "size": "s", "tone": "", "align": "left", "height": 100})

    def test_dashboard_tiles_refused(self):
        good = {"icon": "star", "link": "", "heading": "h", "text": "t", "size": "m", "tone": "", "align": "left", "height": 100}
        for tiles in ({"open": good}, {"tile_": good}, {"tile_A": good}, {"tile_a": "text"}, {"tile_a": {**good, "icon": "Star!"}},
                      {"tile_a": {**good, "link": "javascript:alert(1)"}}, {"tile_a": {**good, "link": "https://evil.example"}},
                      {"tile_a": {**good, "heading": "x" * 81}}, {"tile_a": {**good, "text": "x" * 1001}}, {"tile_a": {**good, "size": "xl"}},
                      {"tile_a": {**good, "tone": "#ff0000"}}, {"tile_a": {**good, "align": "right"}}, {"tile_a": {**good, "height": 59}},
                      {"tile_a": {**good, "height": 1201}}, {f"tile_{i}": good for i in range(41)}):
            with self.subTest(tiles=str(tiles)[:60]):
                with self.assertRaises(ValueError):
                    config.save_settings({"dashboard_layout": {"cards": [], "hidden": [], "tiles": tiles}})


if __name__ == "__main__":
    unittest.main()
