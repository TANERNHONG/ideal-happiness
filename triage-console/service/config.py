"""Paths and user settings for the local service.

Settings live in ``var/settings.json`` (created on first save). Everything the
browser can change goes through :func:`save_settings`, which keeps only known
keys and checks that the language-model endpoint stays on this machine.
"""
from __future__ import annotations

import filecmp
import json
import os
import re
import shutil
import threading
from pathlib import Path
from urllib.parse import urlparse

APP = Path(__file__).resolve().parents[1]          # triage-console/
ROOT = APP.parent                                    # Project-Huh/
PIPELINE = ROOT / "pipeline"
VAR = APP / "var"
CACHE = VAR / "cache"

# The frozen runtime (scripts/freeze_runtime.py): the trained models, preprocessing, maps and summaries copied
# out of data/, without log lines, accounts or addresses, so the console keeps analysing uploads and drawing
# the maps after data/ is purged. It is used when data/ has no trained models (or HUH_FROZEN=1 forces it);
# a new pipeline run that trains models in data/ switches the console back.
RUNTIME = ROOT / "runtime"
_TRAINED = ROOT / "data" / "phase4_detection"
FROZEN = (RUNTIME / "data").is_dir() and (
    os.environ.get("HUH_FROZEN") == "1"
    or not any(_TRAINED.glob("*/detectors/*/experiment_bundle.joblib")))
DATA = RUNTIME / "data" if FROZEN else ROOT / "data"


def restore_frozen_caches() -> list[str]:
    """In frozen mode, put back the derived caches (counts, score references, OSSEC history) as they were frozen:
    nothing can rebuild them once the inputs are gone, and a copy in var/cache that differs was rewritten without
    its inputs (an older console recounting after the purge), so the frozen copy wins. The cluster index is put
    back only when missing: var/cache's own copy holds more than the frozen one."""
    restored = []
    if FROZEN and (RUNTIME / "cache").is_dir():
        CACHE.mkdir(parents=True, exist_ok=True)
        for path in (RUNTIME / "cache").iterdir():
            target = CACHE / path.name
            if not path.is_file():
                continue
            if target.exists() and (path.name == "cluster_index.sqlite" or filecmp.cmp(path, target, shallow=False)):
                continue
            shutil.copy2(path, target)
            restored.append(path.name)
    return restored
WEB_DIST = APP / "web" / "dist"
DOCS = APP / "docs"
SETTINGS_FILE = VAR / "settings.json"
STORE_FILE = VAR / "console.sqlite3"

HOST = "127.0.0.1"
PORT = 8765
DEV_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")   # Vite dev server

DEFAULTS = {
    "language": "en",
    "theme": "system",              # light | dark | system
    "font_family": "inter",         # inter | roboto | helvetica | system | serif | mono | readable | installed
    "font_installed": "",           # a font installed on this laptop (e.g. a licensed corporate typeface), used when font_family is "installed"
    "font_scale": 1.0,
    "display_name": "local-user",   # actor on comments, reviews and the audit log
    "llm_endpoint": "http://127.0.0.1:11434",
    "llm_model": "qwen2.5:3b-instruct",
    "feature_set": "selected",      # model zoo feature set shown on the Models tab
    "animations": "all",            # all | no-arrival (skip the ending: arriving, the final clap, the files found) | none
    "animation_pack": "transit",    # transit (MRT train, SG bus) | desk (cymbal monkey, filing cabinets) | commuter (first person: phone at a platform, a bus stop)
    "console_mode": "simple",       # simple (Upload → Analyze → Map → Review, US-35) | advanced (every page)
    "dashboard_layout": None,       # Settings → Dashboard: {"cards": [{"id", "span"}, …] in order, "hidden": [id, …], "widgets": {id: {…}}}; None is the default
    "review_filter_seconds": 120,   # Settings → Review: a Review filter is stopped after this long (review_filters.Deadline)
    "retention_months": 12,         # Settings → Retention: copies of log lines older than this are removed (retention.py)
}
FONT_FAMILIES = ("inter", "roboto", "helvetica", "system", "serif", "mono", "readable", "installed")
FONT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")      # a family name only: it is put into CSS
ANIMATIONS = ("all", "no-arrival", "none")
ANIMATION_PACKS = ("transit", "desk", "commuter")
CONSOLE_MODES = ("simple", "advanced")
CARD_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")                     # a Dashboard card's name (web/src/dashboard-layout.ts)
WIDGET_ID = re.compile(r"^sql_[a-z0-9]{1,24}$")                     # a Dashboard SQL table of the person's own
WIDGET_TEXT = {"title": 80, "description": 2000, "query": 20_000}   # most characters of each
WIDGET_HEIGHT = (160, 1200)                                          # pixels
TILE_ID = re.compile(r"^tile_[a-z0-9]{1,24}$")                       # a Dashboard tile: an icon and text of the person's own
TILE_TEXT = {"heading": 80, "text": 1000}
TILE_CHOICES = {"size": ("s", "m", "l"), "tone": ("", "red", "amber", "green", "blue", "grey"), "align": ("left", "center")}
TILE_NAME = re.compile(r"^[a-z0-9-]{0,32}$")                         # its icon's name, or the console page it opens ("" for none)
TILE_HEIGHT = (60, 1200)                                             # pixels
REVIEW_FILTER_SECONDS = (10, 3600)                                   # the filter time limit, at least and at most
RETENTION_MONTHS = (3, 6, 12, 24, 36)                                # the choices for how long copies of log lines are kept
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_lock = threading.Lock()


def load_settings() -> dict:
    try:
        stored = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        stored = {}
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def dashboard_layout(value) -> dict | None:
    """The Dashboard's cards in order, each with its width in columns (3 to 12 of 12; a tile 1 to 12), and the hidden
    cards; each card at most once. The person's own SQL tables ("widgets", up to 20) carry a title, a description, a
    query and a height; their tiles ("tiles", up to 40) an icon, a heading and its size, text, a colour, an alignment,
    a console page to open and a height. "packed" (true or false) is Pack tightly. None restores the default. Card, icon and page names are the browser's; only
    their form is checked here (the page draws only the ones it knows). A widget's query is stored as text only: it
    runs, through the SQL guardrails and the SQL password, when its table is refreshed."""
    if value is None:
        return None
    tiles = value.get("tiles", {}) if isinstance(value, dict) else None
    if not isinstance(tiles, dict) or len(tiles) > 40:
        raise ValueError("At most 40 tiles on the Dashboard.")
    kept_tiles = {}
    for tile_id, tile in tiles.items():
        if not isinstance(tile_id, str) or not TILE_ID.fullmatch(tile_id) or not isinstance(tile, dict):
            raise ValueError("A Dashboard tile needs a name such as tile_1.")
        entry = {}
        for key in ("icon", "link"):
            name = tile.get(key, "")
            if not isinstance(name, str) or not TILE_NAME.fullmatch(name):
                raise ValueError(f"A Dashboard tile's {key} is a name of letters, digits and dashes.")
            entry[key] = name
        for key, most in TILE_TEXT.items():
            text = tile.get(key, "")
            if not isinstance(text, str) or len(text) > most:
                raise ValueError(f"A Dashboard tile's {key} is text of at most {most:,} characters.")
            entry[key] = text
        for key, options in TILE_CHOICES.items():
            choice = tile.get(key, options[0])
            if choice not in options:
                raise ValueError(f"A Dashboard tile's {key} is one of {', '.join(o or 'none' for o in options)}.")
            entry[key] = choice
        height = tile.get("height", 100)
        if type(height) is not int or not TILE_HEIGHT[0] <= height <= TILE_HEIGHT[1]:
            raise ValueError(f"A Dashboard tile is {TILE_HEIGHT[0]} to {TILE_HEIGHT[1]} pixels high.")
        entry["height"] = height
        kept_tiles[tile_id] = entry
    widgets = value.get("widgets", {}) if isinstance(value, dict) else None
    if not isinstance(widgets, dict) or len(widgets) > 20:
        raise ValueError("At most 20 SQL tables on the Dashboard.")
    kept = {}
    for widget_id, widget in widgets.items():
        if not isinstance(widget_id, str) or not WIDGET_ID.fullmatch(widget_id) or not isinstance(widget, dict):
            raise ValueError("A Dashboard SQL table needs a name such as sql_1.")
        entry = {}
        for key, most in WIDGET_TEXT.items():
            text = widget.get(key, "")
            if not isinstance(text, str) or len(text) > most:
                raise ValueError(f"A Dashboard SQL table's {key} is text of at most {most:,} characters.")
            entry[key] = text
        height = widget.get("height", 360)
        if type(height) is not int or not WIDGET_HEIGHT[0] <= height <= WIDGET_HEIGHT[1]:
            raise ValueError(f"A Dashboard SQL table is {WIDGET_HEIGHT[0]} to {WIDGET_HEIGHT[1]} pixels high.")
        entry["height"] = height
        kept[widget_id] = entry
    cards = value.get("cards") if isinstance(value, dict) else None
    hidden = value.get("hidden", []) if isinstance(value, dict) else None
    if not isinstance(cards, list) or not isinstance(hidden, list) or len(cards) + len(hidden) > 100:
        raise ValueError("The dashboard layout must list its cards.")
    seen, out = set(), []
    for card in cards:
        card_id = card.get("id") if isinstance(card, dict) else None
        span = card.get("span") if isinstance(card, dict) else None
        narrowest = 1 if isinstance(card_id, str) and card_id.startswith("tile_") else 3
        if not isinstance(card_id, str) or not CARD_ID.fullmatch(card_id) or card_id in seen or type(span) is not int or not narrowest <= span <= 12:
            raise ValueError("Each dashboard card needs a name and a width of 3 to 12 columns (a tile 1 to 12), and appears once.")
        seen.add(card_id)
        out.append({"id": card_id, "span": span})
    for card_id in hidden:
        if not isinstance(card_id, str) or not CARD_ID.fullmatch(card_id) or card_id in seen:
            raise ValueError("Each dashboard card needs a name and a width of 3 to 12 columns, and appears once.")
        seen.add(card_id)
    packed = value.get("packed", False)
    if not isinstance(packed, bool):
        raise ValueError("Pack tightly is on or off.")
    return {"cards": out, "hidden": list(hidden), "widgets": kept, "tiles": kept_tiles, "packed": packed}


def save_settings(changes: dict) -> dict:
    with _lock:
        current = load_settings()
        for key, value in changes.items():
            if key not in DEFAULTS:
                continue
            if key == "llm_endpoint" and (urlparse(str(value)).scheme not in ("http", "https") or urlparse(str(value)).hostname not in LOCAL_HOSTS):
                raise ValueError("The language-model endpoint must be an http address on this laptop (localhost).")
            if key == "font_family" and value not in FONT_FAMILIES:
                raise ValueError(f"The font must be one of {', '.join(FONT_FAMILIES)}.")
            if key == "font_installed":
                value = str(value).strip()
                if value and not FONT_NAME.fullmatch(value):
                    raise ValueError("A font name may use letters, digits, spaces, dots, dashes and underscores (up to 64).")
            if key == "font_scale":
                value = min(1.5, max(0.8, float(value)))
            if key == "retention_months" and value not in RETENTION_MONTHS:
                raise ValueError(f"Keep log lines for {', '.join(map(str, RETENTION_MONTHS))} months.")
            if key == "animations" and value not in ANIMATIONS:
                raise ValueError(f"Animations must be one of {', '.join(ANIMATIONS)}.")
            if key == "animation_pack" and value not in ANIMATION_PACKS:
                raise ValueError(f"The animation pack must be one of {', '.join(ANIMATION_PACKS)}.")
            if key == "console_mode" and value not in CONSOLE_MODES:
                raise ValueError(f"The console mode must be one of {', '.join(CONSOLE_MODES)}.")
            if key == "dashboard_layout":
                value = dashboard_layout(value)
            if key == "review_filter_seconds":
                low, high = REVIEW_FILTER_SECONDS
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                    raise ValueError(f"The filter time limit is {low} to {high:,} seconds.")
                value = int(value)
            current[key] = value
        VAR.mkdir(parents=True, exist_ok=True)
        tmp = SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
        tmp.replace(SETTINGS_FILE)
        return current
