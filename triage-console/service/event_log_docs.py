"""The event log's device types, as a document built from the pipeline's own code (event_log_devices.py) each time
it is opened, so it always shows the groups the code uses; with the device counts of the last run, when there is one
(event_log_devices_summary.json: counts only, never an identifier).
"""
from __future__ import annotations

import json

from .config import DATA
from .pipeline_code import module

DOC_ID = "pipeline/phase1_classify/event_log_devices"
AFTER = "pipeline/phase1_classify/event_log"                    # listed after the event log's README
SOURCE = "pipeline/phase1_classify/event_log_devices.py"        # the path its links resolve against
COUNTS = DATA / "phase1_classify" / "event_log" / "event_log_devices_summary.json"


def _last_run() -> dict | None:
    try:
        return json.loads(COUNTS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _states(states) -> str:
    """A run of numbers as its ends (01–20); other states one by one (ON · OFF)."""
    if all(s.isdigit() for s in states) and [int(s) for s in states] == list(range(int(states[0]), int(states[0]) + len(states))):
        return f"{states[0]}–{states[-1]}"
    return " · ".join(states)


def markdown() -> str:
    devices = module("phase1_classify/event_log_devices.py")
    named = devices.check_groups(devices.STATE_GROUPS)
    groups = list(named)
    run = _last_run()
    count = (lambda kind, key: f"{run.get(kind, {}).get(key, 0):,}") if run else (lambda kind, key: "–")
    fields = " · ".join(f.replace("_", " ") for f in devices.DEVICE_FIELDS)
    out = ["# Event log device types", "",
           f"A device is one signal: {fields}. The group of states it shows is its type "
           "([Event logs](README_event_log.md#devices-by-their-states)).", ""]
    if run:
        months = len(run.get("months", []))
        out += [f"Last run {run.get('created_at', '')} · {run.get('devices', 0):,} devices · {run.get('lines', 0):,} lines · "
                f"{months} month{'' if months == 1 else 's'}", ""]
        if run.get("state_groups") != groups:
            out += ["**Groups changed since the last run: run `event_log_devices.py`.**", ""]
    else:
        out += ["No counts yet: run `event_log.py`.", ""]
    out += ["## Types", "", "| Type | States | Devices |", "|---|---|---:|"]
    out += [f"| {g} | {_states(states)} | {count('groups', g)} |" for g, states in named.items()]
    out += ["", "## Not typed yet", "", "| Status | When | Devices |", "|---|---|---:|"]
    out += [f"| {s} | {when} | {count('statuses', s)} |" for s, when in devices.STATUSES.items() if s != devices.GROUPED]
    out += ["", "Their states together, the most devices first: `event_log_state_sets.csv`."]
    return "\n".join(out) + "\n"
