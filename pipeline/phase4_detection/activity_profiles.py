"""Phase 4h: activity profiles. How much every server, source IP, username and destination IP logs, hour by hour,
against its own normal, for the console's Profiles tab.

  python pipeline/phase4_detection/activity_profiles.py --source auth
  python pipeline/phase4_detection/activity_profiles.py --source pf

Counts only, with what a line says ignored, as in Phase 4g (activity_detectors.py): a line is one unit of activity
at a time, on a server, from a source IP, for a username, to a destination IP. Every entity gets a profile, alerted
or not; nothing here alerts.

Entities, as Phase 4g keeps them (server names and usernames in lower case):
    all             the whole log
    server          hostname; for PF the host in the source file's name (PF's *_tmp captures are left out, as in
                    sources.host_day_counts)
    source_ip, username, destination_ip   when the log has them

Normal:
    auth, OSSEC     the TRAINING period of the source's Phase 3 split (else the first 70% of the study period), as in
                    Phase 4g. A day is compared with the same weekday's training days, public holidays apart, from
                    the entity's first line, on days the log has lines, hours with no line counted as 0
                    (activity_explain.Series.same_day): Explain's median week
    PF, IPFilter    the presence method: normal is no activity (their Phase 3 splits by regime, not by date), so
                    there are no training days and every line counts

Output: data/phase4_detection/<source>/profiles/profiles.sqlite (written whole, then swapped in)
    meta        key, value (JSON): source, method, train_end, split_basis, first_day, last_day, log_days, holidays,
                entity types; days are days since 1970-01-01, hours hours since then
    entities    id, entity_type, entity, first_day, last_day, lines, active_days, training_days
    hourly      id, hour, lines                  one row per hour with lines
    daily       id, day, lines                   one row per day with lines
    usual       id, basis (0-6 Monday to Sunday, 7 public holiday), basis_name, days, low, median, high: P10,
                median and P90 of the daily totals on those training days (training method; n >= 4 only)
    pairs       id, other, day, lines            lines naming both entities, per day (who an entity touched)
The file holds addresses and usernames, like the Phase 1 files it is counted from; the log shows counts only.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime
from itertools import combinations
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from sources import ROOT, SOURCES, host_from_path, load_public_holidays  # noqa: E402

import activity_detectors as detectors  # noqa: E402
import activity_explain  # noqa: E402

PHASE1 = {**detectors.PHASE1, "pf": ("pf", "classified_pflog_events_*.csv"), "ipf": ("ipf", "ipflog_events_*.csv")}
PRESENCE = {"pf", "ipf"}                  # normal is no activity (pipeline/phase3_features/presence.py)
KINDS = ("server", "source_ip", "username", "destination_ip")
STEPS_PER_HOUR = 60 // detectors.STEP_MINUTES
SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE entities (id INTEGER PRIMARY KEY, entity_type TEXT, entity TEXT, first_day INTEGER, last_day INTEGER,
                       lines INTEGER, active_days INTEGER, training_days INTEGER);
CREATE TABLE hourly (id INTEGER, hour INTEGER, lines INTEGER, PRIMARY KEY (id, hour)) WITHOUT ROWID;
CREATE TABLE daily (id INTEGER, day INTEGER, lines INTEGER, PRIMARY KEY (id, day)) WITHOUT ROWID;
CREATE TABLE usual (id INTEGER, basis INTEGER, basis_name TEXT, days INTEGER, low REAL, median REAL, high REAL,
                    PRIMARY KEY (id, basis)) WITHOUT ROWID;
CREATE TABLE pairs (id INTEGER, other INTEGER, day INTEGER, lines INTEGER, PRIMARY KEY (id, day, other)) WITHOUT ROWID;
"""
INDEXES = """
CREATE UNIQUE INDEX entities_name ON entities (entity_type, entity);
CREATE INDEX daily_day ON daily (day, id);
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(PHASE1))
    parser.add_argument("--data", type=Path, default=ROOT / "data")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    args.output = args.data / "phase4_detection" / args.source / "profiles" / "profiles.sqlite"
    return args


def phase1_files(args):
    folder, pattern = PHASE1[args.source]
    return sorted((args.data / "phase1_classify" / folder).glob(pattern))


def count(files, source):
    """Lines per hour for the whole log and per (entity type, entity); lines per day for each pair of entities;
    the first and last 5-minute step with a line."""
    columns = ["timestamp"] + sorted({detectors.ENTITY_TYPES[k] for k in KINDS}) + (["source_file"] if source == "pf" else [])
    whole, single, pairs, bounds = [], {k: [] for k in KINDS}, {}, []
    for chunk in detectors.read_chunks(files, columns):
        if source == "pf":
            chunk = chunk[~chunk["source_file"].str.contains("_tmp", regex=False)]
            chunk = chunk.assign(hostname=host_from_path(chunk["source_file"]).fillna(""))
        if chunk.empty:
            continue
        steps = chunk["step"].to_numpy(dtype=np.int64)
        bounds += [int(steps.min()), int(steps.max())]
        hours = steps // STEPS_PER_HOUR
        days = hours // 24
        whole.append(pd.Series(hours).value_counts())
        values = {kind: detectors.entity_values(chunk, kind).to_numpy(dtype=object)
                  for kind in KINDS if detectors.ENTITY_TYPES[kind] in chunk}
        for kind, value in values.items():
            ok = value != ""
            if ok.any():
                single[kind].append(pd.DataFrame({"entity": value[ok], "hour": hours[ok]}).groupby(["entity", "hour"]).size())
        for kind, other in combinations(values, 2):
            both = (values[kind] != "") & (values[other] != "")
            if both.any():
                pairs.setdefault((kind, other), []).append(pd.DataFrame(
                    {"a": values[kind][both], "b": values[other][both], "day": days[both]}).groupby(["a", "b", "day"]).size())
    total = pd.concat(whole).groupby(level=0).sum().sort_index() if whole else pd.Series(dtype=np.int64)
    single = {kind: pd.concat(parts).groupby(level=[0, 1]).sum() for kind, parts in single.items() if parts}
    pairs = {key: pd.concat(parts).groupby(level=[0, 1, 2]).sum() for key, parts in pairs.items()}
    return total, single, pairs, (min(bounds), max(bounds)) if bounds else None


def split(args, steps):
    """(train end, split basis): Phase 4g's split (detectors.split_bounds) for auth and OSSEC; none for the presence
    sources, whose normal is no activity."""
    if args.source in PRESENCE:
        return None, "presence method: normal is no activity"
    train_end, _, basis = detectors.split_bounds(SimpleNamespace(data=args.data, source=args.source),
                                                 pd.Series(1, index=list(steps)))
    return train_end, basis


def entity_table(total, single):
    """One row per entity (id 0: the whole log) and its hourly counts, sorted by id, then hour."""
    rows, hourly = [("all", "all")], [pd.DataFrame({"id": 0, "hour": total.index.to_numpy(dtype=np.int64),
                                                    "lines": total.to_numpy(dtype=np.int64)})]
    for kind in KINDS:
        if kind not in single:
            continue
        counts = single[kind]
        names = counts.index.get_level_values(0).unique().sort_values()
        codes = pd.Series(np.arange(len(rows), len(rows) + len(names)), index=names)
        rows += [(kind, name) for name in names]
        hourly.append(pd.DataFrame({"id": codes.reindex(counts.index.get_level_values(0)).to_numpy(),
                                    "hour": counts.index.get_level_values(1).to_numpy(dtype=np.int64),
                                    "lines": counts.to_numpy(dtype=np.int64)}))
    hourly = pd.concat(hourly, ignore_index=True).sort_values(["id", "hour"], kind="stable").reset_index(drop=True)
    return pd.DataFrame(rows, columns=["entity_type", "entity"]), hourly


def usual_rows(hourly, entities, context):
    """(id, basis, basis_name, days, low, median, high) for each entity seen in training and each weekday / holiday
    basis with at least activity_explain.MIN_DAYS training days."""
    out = []
    ids = hourly["id"].to_numpy()
    starts = np.flatnonzero(np.r_[True, ids[1:] != ids[:-1]])
    ends = np.r_[starts[1:], len(ids)]
    hours, lines = hourly["hour"].to_numpy(), hourly["lines"].to_numpy()
    for start, end in zip(starts, ends):
        code = int(ids[start])
        if entities.at[code, "first_day"] >= context["train_end_day"]:
            continue
        series = activity_explain.Series(hours[start:end] * STEPS_PER_HOUR, lines[start:end], context["log_days"],
                                         context["holidays"], context["train_end_day"])
        for basis, (name, usual) in activity_explain.usual_days(series, context["holidays"]).items():
            if usual:
                out.append((code, basis, name, usual["days"], usual["low"], usual["median"], usual["high"]))
    return out


def plain(frame, index=False):
    """A frame's rows as tuples of Python values (sqlite3 cannot bind numpy's)."""
    columns = ([frame.index.tolist()] if index else []) + [frame[c].tolist() for c in frame.columns]
    return list(zip(*columns))


def write(path, meta, entities, hourly, daily, usual, pair_rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.unlink(missing_ok=True)
    con = sqlite3.connect(temporary)
    try:
        con.executescript("PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;" + SCHEMA)
        con.executemany("INSERT INTO meta VALUES (?, ?)", [(k, json.dumps(v)) for k, v in meta.items()])
        con.executemany("INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?, ?, ?)", plain(entities, index=True))
        con.executemany("INSERT INTO hourly VALUES (?, ?, ?)", plain(hourly))
        con.executemany("INSERT INTO daily VALUES (?, ?, ?)", plain(daily))
        con.executemany("INSERT INTO usual VALUES (?, ?, ?, ?, ?, ?, ?)", usual)
        con.executemany("INSERT INTO pairs VALUES (?, ?, ?, ?)", pair_rows)
        con.executescript(INDEXES)
        con.commit()
    finally:
        con.close()
    os.replace(temporary, path)


def main(argv=None):
    args = parse_args(argv)
    spec = SOURCES[args.source]
    files = phase1_files(args)
    if not files:
        raise SystemExit(f"No Phase 1 files for {args.source} under {args.data / 'phase1_classify'}")
    detectors.log(f"{spec['label']} profiles: counting lines per hour in {len(files)} Phase 1 files", args.quiet)
    total, single, pairs, steps = count(files, args.source)
    if total.empty:
        raise SystemExit(f"No timestamped lines in the {args.source} Phase 1 files")
    train_end, basis = split(args, steps)
    holidays = {activity_explain.day_number(day): name for day, name in load_public_holidays().items()}
    log_days = np.unique(total.index.to_numpy(dtype=np.int64) // 24)
    first_log_day, last_log_day = int(log_days[0]), int(log_days[-1])
    train_end_day = activity_explain.day_number(train_end) if train_end is not None else first_log_day
    context = {"holidays": holidays, "log_days": log_days, "train_end_day": train_end_day}

    entities, hourly = entity_table(total, single)
    hourly["day"] = hourly["hour"] // 24
    daily = hourly.groupby(["id", "day"], sort=True)["lines"].sum().reset_index()
    per = daily.groupby("id").agg(first_day=("day", "min"), last_day=("day", "max"), lines=("lines", "sum"),
                                  active_days=("day", "size"))
    entities = entities.join(per)
    first = entities["first_day"].to_numpy(dtype=np.int64)
    entities["training_days"] = np.where(first < train_end_day, np.searchsorted(log_days, train_end_day)
                                         - np.searchsorted(log_days, first), 0)
    detectors.log(f"{len(entities) - 1:,} entities: " + ", ".join(
        f"{n:,} {activity_explain.LABELS[k]}" for k, n in entities["entity_type"].value_counts().items() if k != "all"),
        args.quiet)
    usual = usual_rows(hourly, entities, context) if args.source not in PRESENCE else []

    codes = {(kind, name): code for code, (kind, name) in enumerate(zip(entities["entity_type"], entities["entity"]))}
    pair_rows = []
    for (kind, other), counts in pairs.items():
        a = np.fromiter((codes[(kind, v)] for v in counts.index.get_level_values(0)), dtype=np.int64, count=len(counts))
        b = np.fromiter((codes[(other, v)] for v in counts.index.get_level_values(1)), dtype=np.int64, count=len(counts))
        day, lines = counts.index.get_level_values(2).to_numpy(dtype=np.int64), counts.to_numpy(dtype=np.int64)
        pair_rows += list(zip(a.tolist(), b.tolist(), day.tolist(), lines.tolist()))
        pair_rows += list(zip(b.tolist(), a.tolist(), day.tolist(), lines.tolist()))

    meta = {"source": args.source, "label": spec["label"], "generated_at": datetime.now().isoformat(timespec="seconds"),
            "method": "presence" if args.source in PRESENCE else "training", "split_basis": basis,
            "train_end": str(train_end) if train_end is not None else None, "train_end_day": train_end_day,
            "first_day": first_log_day, "last_day": last_log_day, "log_days": log_days.tolist(),
            "holidays": {str(day): name for day, name in holidays.items()},
            "entity_types": [k for k in ("all",) + KINDS if k == "all" or k in single],
            "min_days": activity_explain.MIN_DAYS}
    write(args.output, meta, entities[["entity_type", "entity", "first_day", "last_day", "lines", "active_days",
                                       "training_days"]], hourly[["id", "hour", "lines"]], daily, usual, pair_rows)
    detectors.log(f"{spec['label']} profiles done: {len(hourly):,} active entity-hours, {len(usual):,} weekday "
                  f"baselines, {len(pair_rows) // 2:,} entity pairs by day -> {args.output}", args.quiet)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
