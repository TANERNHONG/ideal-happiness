"""Load the pipeline's own modules, so the console reuses its rules, not copies.

The pipeline folders are scripts, not packages, so modules are loaded by path
and cached.
"""
from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache

from .config import PIPELINE, ROOT

for folder in (str(ROOT), str(PIPELINE)):
    if folder not in sys.path:
        sys.path.insert(0, folder)


@lru_cache(maxsize=None)
def module(relative: str):
    """``module("phase1_classify/auth.py")`` -> the loaded module."""
    path = PIPELINE / relative
    name = "huh_" + relative.replace("/", "_").removesuffix(".py")
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


def event_category(source: str, event_type: str) -> str:
    """The Phase 2 category of an event type; for the firewalls, the action."""
    try:
        if source == "auth":
            return module("phase2_observations/auth.py").event_category(event_type)
        if source == "ossec":
            return module("phase2_observations/ossec.py").event_category(event_type)
    except Exception:                               # a pipeline import problem must not stop the console
        return "other"
    parts = event_type.split("_")
    return parts[1].lower() if len(parts) > 2 else "other"
