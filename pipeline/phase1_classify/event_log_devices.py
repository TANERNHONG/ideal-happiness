"""The event log's devices, classified by their states: run at the end of event_log.py, or alone.

    .venv/Scripts/python.exe pipeline/phase1_classify/event_log_devices.py
    .venv/Scripts/python.exe pipeline/phase1_classify/event_log_devices.py --output "D:/event_log" --quiet

The event log gathers the events of many kinds of device. A device is one signal: one code 1, code 2, identifier 1,
identifier 2, location and identifier 3 (DEVICE_FIELDS). Every event of a device uses the states of one group: a pair
(ON/OFF) or a larger group (Transformer: 01 to 20). So the states a device shows, over all its lines, say which group it belongs to,
and that group classifies it. A device that no group covers is for review, and the states such devices show together
are the groups to add to STATE_GROUPS next. Changing the groups needs no new parse: run this file alone.

Statuses:
  grouped     one group holds every state the device shows: its group
  ambiguous   more than one group holds them all (STOP alone: RUN/STOP or START/STOP); more lines may settle it
  ungrouped   a state it shows is in no group yet
  mixed       its states are each in a group, but no one group holds them all (ON, OFF and FAULT)
  no_state    none of its lines has a state

Reads   <output>/event_log_events_<YYYY-MM>.csv, every month there: the lines parsed, parsed with warnings or
        unclassified (invalid lines, which are in the exceptions files, and system messages are left out and counted)
Writes  <output>/event_log_devices.csv          one row per device: its fields, lines, the states it shows (lines each),
                                                status, group and reason; the most lines first
        <output>/event_log_devices_review.csv   the devices not grouped, with the reason: for review
        <output>/event_log_state_sets.csv       the states the devices for review show together, the most devices
                                                first: the groups to add next
        <output>/event_log_devices_summary.json counts only: devices per status and per group, lines, months, the
                                                groups used (the console's device-types page shows them)
Progress goes to stderr as in event_log.py. No identifier value is logged; the device files hold them, as the events
files do.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from collections import Counter, defaultdict
from operator import itemgetter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from event_log_parser import IDENTIFIER_3_STATES, PARSED, PARSED_WITH_WARNINGS, STATES, UNCLASSIFIED  # noqa: E402

# --- Values you maintain: the groups of states -----------------------------------------------------------------------
# Every event of one device uses the states of one group, by its name: the device's type, as the device files and the
# console show it. A pair is a group of two. A state may be in more than one group (STOP). Each state must be in
# STATES or IDENTIFIER_3_STATES (event_log_parser.py), written as stored: in upper case.
STATE_GROUPS: dict[str, tuple[str, ...]] = {
    "ON/OFF": ("ON", "OFF"),
    "OPEN/CLOSE": ("OPEN", "CLOSE"),
    "RUN/STOP": ("RUN", "STOP"),
    "UP/DOWN": ("UP", "DOWN"),
    "START/STOP": ("START", "STOP"),
    "OK/FAULT": ("OK", "FAULT"),
    "Transformer": ("01", "02", "03", "04", "05", "06", "07", "08", "09", "10",       # up to 20 (your note, 2026-10-21)
                    "11", "12", "13", "14", "15", "16", "17", "18", "19", "20"),
}

DEVICE_FIELDS = ("code_1", "code_2", "identifier_1", "identifier_2", "location", "identifier_3")   # one signal
READ_STATUSES = (PARSED, PARSED_WITH_WARNINGS, UNCLASSIFIED)        # the lines whose fields are read
GROUPED, AMBIGUOUS, UNGROUPED, MIXED, NO_STATE = "grouped", "ambiguous", "ungrouped", "mixed", "no_state"
STATUSES = {GROUPED: "one group holds all its states: that group is its type",
            AMBIGUOUS: "more than one group holds all its states (STOP alone)",
            UNGROUPED: "a state in no group yet",
            MIXED: "each state in a group, but no one group holds them all",
            NO_STATE: "no line with a state"}
DEVICES_FILE, REVIEW_FILE, STATE_SETS_FILE = "event_log_devices.csv", "event_log_devices_review.csv", "event_log_state_sets.csv"
SUMMARY_FILE = "event_log_devices_summary.json"           # counts only, never an identifier
DEVICE_COLUMNS = [*DEVICE_FIELDS, "lines", "states", "status", "state_group", "reason"]
LOGGER = runlog.LOGGER


def group_name(group) -> str:
    """A set of states written like a group: ON/OFF."""
    return "/".join(group)


def _named(groups) -> list[tuple[str, tuple[str, ...]]]:
    """(name, states) for each group: a dict by its names, a list of groups by their states (ON/OFF)."""
    pairs = groups.items() if isinstance(groups, dict) else ((group_name(g), g) for g in groups)
    return [(name, tuple(group)) for name, group in pairs]


class GroupIndex:
    """The groups with an inverted index, state -> the groups holding it. A device's groups are the intersection of its
    states' sets, rather than a check of every group for every device; group order is kept for the messages."""

    def __init__(self, groups):
        self.named = _named(groups)
        self.order = {name: i for i, (name, _) in enumerate(self.named)}
        self.holding: dict[str, set[str]] = {}
        for name, group in self.named:
            for state in group:
                self.holding.setdefault(state, set()).add(name)

    def in_order(self, names) -> list[str]:
        return sorted(names, key=self.order.__getitem__)


def check_groups(groups, allowed=(*STATES, *IDENTIFIER_3_STATES)) -> dict[str, tuple[str, ...]]:
    """The groups by name. A ValueError for a blank name, a group of fewer than two states, a state twice in a group, a
    state not in the allowed states, or the same group twice."""
    checked: dict[str, tuple[str, ...]] = {}
    for name, group in _named(groups):
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"State group {group_name(group)}: a group needs a name.")
        if len(group) < 2 or len(set(group)) < len(group):
            raise ValueError(f"State group {name}: a group needs two or more different states.")
        unknown = [s for s in group if s not in allowed]
        if unknown:
            raise ValueError(f"State group {name}: not in STATES (event_log_parser.py): {', '.join(unknown)}.")
        if name in checked or any(set(group) == set(g) for g in checked.values()):
            raise ValueError(f"State group {name} is there twice.")
        checked[name] = group
    return checked


def other_states(state: str, groups=STATE_GROUPS) -> tuple[str, ...]:
    """The other states of every group a state is in, in group order (STOP: RUN, START; 03: 01, 02 and 04 to 20)."""
    others: list[str] = []
    for _, group in _named(groups):
        if state in group:
            others += [s for s in group if s != state and s not in others]
    return tuple(others)


def classify(states, groups=STATE_GROUPS) -> tuple[str, str, str]:
    """(status, group, reason) for a device showing these states; the group only when it is grouped. groups may be a
    GroupIndex, built once for many devices."""
    states = set(states)
    if not states:
        return NO_STATE, "", "none of its lines has a state"
    index = groups if isinstance(groups, GroupIndex) else GroupIndex(groups)
    loose = sorted(s for s in states if s not in index.holding)
    if loose:
        return UNGROUPED, "", f"in no group yet: {', '.join(loose)}"
    holding = index.in_order(set.intersection(*(index.holding[s] for s in states)))
    if len(holding) == 1:
        return GROUPED, holding[0], ""
    if holding:
        return AMBIGUOUS, "", f"more than one group holds all its states: {', '.join(holding)}"
    return MIXED, "", "no one group holds them all: " + "; ".join(
        f"{s} in {' or '.join(index.in_order(index.holding[s]))}" for s in sorted(states))


def classify_folder(folder: Path, groups=STATE_GROUPS, step=None) -> dict:
    """Every events file in the folder -> the three device files; returns the counts (no identifier values). step, if
    given, is called once per line read (progress)."""
    groups = check_groups(groups)
    index = GroupIndex(groups)
    paths = sorted(folder.glob("event_log_events_*.csv"))
    result = {"months": [p.stem.rsplit("_", 1)[1] for p in paths], "lines": 0, "lines_left_out": {}, "devices": 0,
              "statuses": {}, "groups": {}, "state_sets_for_review": 0,
              "files": [DEVICES_FILE, REVIEW_FILE, STATE_SETS_FILE, SUMMARY_FILE]}
    if not paths:
        return result
    devices: defaultdict[tuple, Counter] = defaultdict(Counter)   # device -> lines per state ("" for none)
    left_out = Counter()
    for path in paths:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
            missing = [n for n in (*DEVICE_FIELDS, "parse_status", "state") if n not in header]
            if missing:
                raise ValueError(f"{path.name} has no {', '.join(missing)} column; run event_log.py again.")
            key_of = itemgetter(*(header.index(n) for n in DEVICE_FIELDS))    # the device's fields, as a tuple
            status_at, state_at = header.index("parse_status"), header.index("state")
            for row in reader:
                if row[status_at] in READ_STATUSES:
                    devices[key_of(row)][row[state_at]] += 1
                else:
                    left_out[row[status_at]] += 1
                if step:
                    step()
    rows, sets = [], {}
    for key, seen in devices.items():
        states = sorted(s for s in seen if s)
        status, group, reason = classify(states, index)
        lines = sum(seen.values())
        rows.append([*key, lines, "; ".join(f"{s} {seen[s]}" for s in states), status, group, reason])
        if status != GROUPED and states:
            entry = sets.setdefault(group_name(states), [0, 0, status, reason])
            entry[0] += 1
            entry[1] += lines
    rows.sort(key=lambda r: (-r[6], r[:6]))
    _write(folder / DEVICES_FILE, DEVICE_COLUMNS, rows)
    _write(folder / REVIEW_FILE, DEVICE_COLUMNS, [r for r in rows if r[8] != GROUPED])
    _write(folder / STATE_SETS_FILE, ["states", "devices", "lines", "status", "reason"],
           sorted(([s, *entry] for s, entry in sets.items()), key=lambda r: (-r[1], -r[2], r[0])))
    result.update(lines=sum(r[6] for r in rows), lines_left_out=dict(left_out), devices=len(rows),
                  statuses=dict(Counter(r[8] for r in rows).most_common()),
                  groups=dict(Counter(r[9] for r in rows if r[9]).most_common()), state_sets_for_review=len(sets))
    summary = {"created_at": time.strftime("%Y-%m-%d %H:%M:%S"), "state_groups": list(groups), **result}
    tmp = folder / (SUMMARY_FILE + ".tmp")
    tmp.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    tmp.replace(folder / SUMMARY_FILE)
    return result


def _write(path: Path, header: list, rows) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)
    tmp.replace(path)


def log_result(result: dict) -> None:
    """The counts on stderr: devices, statuses and groups (state names only, never an identifier)."""
    left_out = ", ".join(f"{k} {v:,}" for k, v in sorted(result["lines_left_out"].items())) or "none"
    LOGGER.info("Devices: %s, from %s lines in %s months (lines left out: %s)", f"{result['devices']:,}",
                f"{result['lines']:,}", len(result["months"]), left_out)
    LOGGER.info("Devices by status: %s", ", ".join(f"{k} {v:,}" for k, v in result["statuses"].items()) or "none")
    LOGGER.info("Devices by group: %s", ", ".join(f"{k} {v:,}" for k, v in result["groups"].items()) or "none")
    LOGGER.info("For review: %s devices (%s); state sets to group next: %s (%s)",
                f"{result['devices'] - result['statuses'].get(GROUPED, 0):,}", REVIEW_FILE,
                f"{result['state_sets_for_review']:,}", STATE_SETS_FILE)


def main(argv=None) -> int:
    import event_log                                    # its logging and progress (here, since it imports this module)
    parser = argparse.ArgumentParser(description="Classify the event log's devices by the group their states fall in.")
    parser.add_argument("--output", type=Path, default=event_log.DEFAULT_OUTPUT,
                        help="the folder of event_log_events_<YYYY-MM>.csv; the device files are written there "
                             "(default: data/phase1_classify/event_log)")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    with runlog.run(args) as outcome:
        with runlog.stage(f"grouping the devices by their states in {args.output}"):
            result = classify_folder(args.output, step=runlog.Progress("Event lines read").step)
        if not result["months"]:
            LOGGER.error("No event_log_events_<YYYY-MM>.csv in %s; run event_log.py first.", args.output)
            outcome["status"] = "stopped"
            return 1
        log_result(result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:                    # runlog.run() has logged it
        raise SystemExit(130)
    except Exception:
        LOGGER.exception("The device grouping failed")
        raise SystemExit(1)
