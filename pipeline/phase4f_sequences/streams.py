"""Phase 4f step 1: ordered, de-duplicated token streams per AUTH session and OSSEC episode.

  .venv/Scripts/python.exe pipeline/phase4f_sequences/streams.py --source ossec
  .venv/Scripts/python.exe pipeline/phase4f_sequences/streams.py --source auth      # about an hour

Writes data/phase4f_sequences/<source>/streams/sequences.sqlite and summary.json (see common.py).

The observations are Phase 2's own, with the same row_manifest_id, so every later result links to the
existing sessions, episodes, alerts and console records:

* OSSEC episodes come from the Phase 2 episode lineage, which lists every member event.
* AUTH sessions are rebuilt by replaying Phase 2's session assignment (its own functions, in its own
  order: time, then record ID), because the session CSV keeps only the first 96 event types. The
  summary records a check that the replay produced exactly Phase 2's sessions and event counts.

Within each observation the events are put in source order (time, archive, file, numeric line, event
ID; line 2 before line 10), following the 2026-10-08 audit. Then:

* Copies of the same line in another file at the same second (rotated logs that overlap) are merged
  into the first, up to the number of copies the first file holds, so they are not counted twice.
  Repeats within one file are kept. Each merged copy is listed in ``aliases``.
* A step between two events of the same second from different files (or without a line number) has
  no proven order; its token position is recorded as uncertain, and later steps do not score it.
* Tokens are event types; consecutive repeats become one token, with the run length kept.

Splits are Phase 3's (common.split_rule); the summary checks the counts against Phase 3's metadata.
Censoring: an observation starting within the inactivity limit of the first event in the data may
have lost its beginning (left); one closed by the end of the data may be unfinished (right).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, SOURCES, phase3_split_counts, split_of, split_rule, stream_folder, write_json  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

csv.field_size_limit(2**31 - 1)
BATCH = 50_000


log = runlog.log


def line_number(value):
    try:
        number = int(float(value))
        return number if number > 0 else None
    except (TypeError, ValueError):
        return None


# --- one observation's events -> tokens ------------------------------------------------------------------------

def order_key(event):
    """Source order: time, file identity (archive, member, file), numeric line (missing last), event ID."""
    line = event["line"]
    return (event["epoch"], event["file"], line is None, line or 0, event["id"])


def build_unit(events):
    """Order, merge cross-file copies and tokenise one observation's events.

    :param events: dicts with epoch, file (tuple), line (int or None), id, type and sha (raw-line hash).
    :returns: dict with tokens, runs, uncertain (token positions), kept, aliases [(kept_id, alias_id)].
    """
    ordered = sorted(events, key=order_key)
    kept, aliases = [], []
    copies = defaultdict(lambda: defaultdict(list))         # (epoch, sha) -> file -> kept events of that file
    for event in ordered:
        files = copies[(event["epoch"], event["sha"])] if event["sha"] else None
        if files:
            first_file = next(iter(files))
            if event["file"] != first_file:
                # a copy from another file: merge it into the first file's next unmatched copy, if any is left
                matched = files[event["file"]]
                if len(matched) < len(files[first_file]):
                    aliases.append((files[first_file][len(matched)]["id"], event["id"]))
                    matched.append(event)
                    continue
        if files is not None:
            files[event["file"]].append(event)
        kept.append(event)
    tokens, runs, uncertain = [], [], []
    previous = None
    for event in kept:
        unsure = (previous is not None and previous["epoch"] == event["epoch"]
                  and (previous["file"] != event["file"] or previous["line"] is None or event["line"] is None))
        if tokens and tokens[-1] == event["type"]:
            runs[-1] += 1
        else:
            if unsure:
                uncertain.append(len(tokens))
            tokens.append(event["type"])
            runs.append(1)
        previous = event
    return {"tokens": tuple(tokens), "runs": runs, "uncertain": uncertain, "kept": len(kept), "aliases": aliases}


# --- the store ---------------------------------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE units (
    row_manifest_id TEXT PRIMARY KEY, dataset TEXT, host_id TEXT, key_type TEXT,
    start_epoch REAL, end_epoch REAL, split TEXT, close_reason TEXT,
    event_count INTEGER, kept_count INTEGER, merged_copies INTEGER,
    left_censored INTEGER, right_censored INTEGER,
    sequence_id INTEGER, token_count INTEGER, run_lengths TEXT, max_run INTEGER, uncertain_positions TEXT);
CREATE TABLE sequences (sequence_id INTEGER PRIMARY KEY, tokens TEXT UNIQUE, length INTEGER);
CREATE TABLE aliases (row_manifest_id TEXT, kept_id TEXT, alias_id TEXT);
"""


class Store:
    """Writes units in batches into a temporary SQLite file, moved into place by finish()."""

    def __init__(self, folder, source, rule, first_epoch):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.path = self.folder / "sequences.sqlite"
        self.temporary = self.folder / "sequences.sqlite.tmp"
        self.temporary.unlink(missing_ok=True)
        self.db = sqlite3.connect(self.temporary)
        self.db.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;" + SCHEMA)
        self.source, self.rule, self.first_epoch = source, rule, first_epoch
        self.limit = SOURCES[source]["inactivity_seconds"]
        self.sequence_ids = {}
        self.units, self.aliases = [], []
        self.stats = Counter()
        self.splits = Counter()
        self.checksum = 0

    def add(self, unit_id, host, key_type, close_reason, events):
        built = build_unit(events)
        tokens = built["tokens"]
        sid = self.sequence_ids.setdefault(tokens, len(self.sequence_ids) + 1)
        start = min(event["epoch"] for event in events)
        end = max(event["epoch"] for event in events)
        split = split_of(start, self.rule)
        self.splits[split] += 1
        self.stats["units"] += 1
        self.stats["events"] += len(events)
        self.stats["merged_copies"] += len(built["aliases"])
        self.stats["units_with_merged_copies"] += bool(built["aliases"])
        self.stats["units_with_uncertain_steps"] += bool(built["uncertain"])
        self.stats["uncertain_steps"] += len(built["uncertain"])
        left = int(start < self.first_epoch + self.limit)
        right = int(close_reason == "end_of_data")
        self.stats["left_censored"] += left
        self.stats["right_censored"] += right
        self.checksum = (self.checksum + fingerprint(unit_id, len(events), close_reason)) % (1 << 64)
        self.units.append((unit_id, SOURCES[self.source]["dataset"], host, key_type, start, end, split, close_reason,
                           len(events), built["kept"], len(built["aliases"]), left, right, sid, len(tokens),
                           " ".join(map(str, built["runs"])), max(built["runs"], default=0),
                           " ".join(map(str, built["uncertain"]))))
        self.aliases.extend((unit_id, kept, alias) for kept, alias in built["aliases"])
        if len(self.units) >= BATCH:
            self.flush()

    def flush(self):
        self.db.executemany("INSERT INTO units VALUES (" + ",".join("?" * 18) + ")", self.units)
        self.db.executemany("INSERT INTO aliases VALUES (?,?,?)", self.aliases)
        self.db.commit()
        self.units.clear()
        self.aliases.clear()

    def finish(self):
        self.flush()
        self.db.executemany("INSERT INTO sequences VALUES (?,?,?)",
                            ((sid, " ".join(tokens), len(tokens)) for tokens, sid in self.sequence_ids.items()))
        self.db.executescript("CREATE INDEX units_split ON units(split, host_id);"
                              "CREATE INDEX units_sequence ON units(sequence_id);"
                              "CREATE INDEX aliases_unit ON aliases(row_manifest_id);")
        self.db.commit()
        self.db.close()
        self.temporary.replace(self.path)
        self.stats["distinct_sequences"] = len(self.sequence_ids)
        return self.path


def fingerprint(unit_id, event_count, close_reason):
    """Order-independent check value of one observation: summed over all, compared with Phase 2's."""
    digest = hashlib.sha256(f"{unit_id}|{int(event_count)}|{close_reason}".encode()).hexdigest()
    return int(digest[:16], 16)


def phase2_checksum(path, id_column, count_column="event_count", reason_column="close_reason"):
    """Count and summed fingerprints of Phase 2's observation CSV, streamed."""
    total = count = 0
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        i, c, r = header.index(id_column), header.index(count_column), header.index(reason_column)
        for row in reader:
            total = (total + fingerprint(row[i], int(float(row[c])), row[r])) % (1 << 64)
            count += 1
    return count, total


def open_events(source):
    path = SOURCES[source]["store"]
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only=ON")
    return connection


# --- OSSEC: episodes from the Phase 2 lineage ----------------------------------------------------------------------

def ossec_events(connection):
    """event_id -> event dict (for build_unit), from a Phase 2 OSSEC store's ``events`` table."""
    events = {}
    for row in connection.execute("SELECT event_id, timestamp_epoch, archive_name, archive_member, source_file, "
                                  "source_line, event_type, raw_line_sha256 FROM events"):
        event_id, epoch, archive, member, source_file, line, event_type, sha = row
        events[event_id] = {"id": event_id, "epoch": float(epoch),
                            "file": (archive or "", member or "", source_file or ""),
                            "line": line_number(line), "type": (event_type or "").strip() or "OSSEC_UNKNOWN_EVENT",
                            "sha": sha}
    return events


def ossec_streams(folder, rule):
    spec = SOURCES["ossec"]
    connection = open_events("ossec")
    events = ossec_events(connection)
    connection.close()
    first_epoch = min(event["epoch"] for event in events.values())
    members = defaultdict(list)
    with open(spec["lineage"], "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            members[row["row_manifest_id"]].append(row["event_id"])
    store = Store(folder, "ossec", rule, first_epoch)
    missing = 0
    with open(spec["observations"], "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            ids = members.pop(row["row_manifest_id"], [])
            found = [events[i] for i in ids if i in events]
            missing += len(ids) - len(found)
            if found:
                store.add(row["row_manifest_id"], row["host_id"], row["episode_key_type"], row["close_reason"], found)
    if members or missing:
        raise ValueError(f"Lineage does not match the episodes: {len(members)} episodes without a row, {missing} events missing")
    path = store.finish()
    expected = phase2_checksum(spec["observations"], "row_manifest_id")
    return path, store, expected


# --- AUTH: replay Phase 2's session assignment ------------------------------------------------------------------------

def phase2_auth():
    """Phase 2's AUTH module, for its session rules (imported, so the replay cannot drift from it)."""
    path = ROOT / "pipeline/phase2_observations/auth.py"
    spec = importlib.util.spec_from_file_location("phase2_auth", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay_auth_sessions(connection, p2, close, until=None, progress=None):
    """Phase 2's session assignment, replayed over a Phase 2 store's events in Phase 2's own order.

    :param connection: SQLite connection to a store with Phase 2's ``events`` table (row_factory sqlite3.Row).
    :param p2: Phase 2's AUTH module (phase2_auth()), whose session rules are used.
    :param close: called as close(session, reason) for every session as it closes; the session has id, host,
        key_type and events (dicts for build_unit).
    :param until: only events before this epoch.
    :param progress: called as progress(events_read, open_sessions) about every 30 seconds.
    """
    clean = p2.clean
    query = ("SELECT record_id, raw_line_sha256, timestamp_epoch, host_id, process_name, pid, username, source_ip, "
             "source_port, event_type, source_file, source_line FROM events")
    parameters = ()
    if until is not None:
        query += " WHERE timestamp_epoch < ?"
        parameters = (until,)
    query += " ORDER BY timestamp_epoch, record_id"            # Phase 2's own order (event_rows)
    active, pid_owner = {}, {}
    last_sweep = None
    seen = 0
    last_report = time.perf_counter()

    def sweep(epoch):
        expired = []
        for key, session in active.items():
            reason = p2.session_expiry(session, epoch)
            if reason:
                expired.append((session["first_epoch"], session["id"], key, reason))
        for _, _, key, reason in sorted(expired):
            close(active.pop(key), reason)
        for reference in [ref for ref, owner in pid_owner.items() if owner not in active]:
            del pid_owner[reference]

    for row in connection.execute(query, parameters):
        seen += 1
        epoch = float(row["timestamp_epoch"])
        if last_sweep is None:
            last_sweep = epoch
        elif epoch - last_sweep >= p2.SESSION_SWEEP_SECONDS:
            sweep(epoch)
            last_sweep = epoch
        key = p2.resolve_session_key(row, active, pid_owner)
        session = active.get(key)
        if session is not None:
            reason = p2.session_expiry(session, epoch)
            if reason:
                close(active.pop(key), reason)
                session = None
        if session is None:
            session = {"id": p2.stable_id("auth", "session", *key, row["timestamp_epoch"], row["record_id"]),
                       "key_type": key[0], "host": row["host_id"], "first_epoch": epoch, "last_epoch": epoch,
                       "closing_epoch": None, "events": []}
            active[key] = session
        event_type = clean(row["event_type"]) or "AUTHLOG_UNKNOWN_EVENT"
        session["events"].append({"id": row["record_id"], "epoch": epoch, "file": ("", "", row["source_file"] or ""),
                                  "line": line_number(row["source_line"]), "type": event_type,
                                  "sha": row["raw_line_sha256"]})
        session["last_epoch"] = epoch
        if event_type in p2.SESSION_TERMINAL_EVENTS and session["closing_epoch"] is None:
            session["closing_epoch"] = epoch
        now = time.perf_counter()
        if progress and now - last_report >= 30:
            progress(seen, len(active))
            last_report = now
    for _, session in sorted(active.items(), key=lambda item: (item[1]["first_epoch"], item[1]["id"])):
        close(session, "terminal" if session["closing_epoch"] is not None else "end_of_data")


def auth_streams(folder, rule, until=None):
    p2 = phase2_auth()
    connection = open_events("auth")
    connection.row_factory = sqlite3.Row
    first_epoch = connection.execute("SELECT MIN(timestamp_epoch) FROM events").fetchone()[0]
    total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] if until is None else None
    store = Store(folder, "auth", rule, float(first_epoch))
    started = time.perf_counter()

    def progress(seen, open_sessions):
        rate = seen / (time.perf_counter() - started)
        eta = f", about {(total - seen) / rate / 60:.0f} min left" if total else ""
        log(f"AUTH: {seen:,} events{f' of {total:,}' if total else ''}, {store.stats['units']:,} sessions, "
            f"{open_sessions:,} open ({rate:,.0f} events/s{eta})")

    replay_auth_sessions(connection, p2, lambda session, reason: store.add(session["id"], session["host"], session["key_type"],
                                                                          reason, session["events"]), until, progress)
    connection.close()
    path = store.finish()
    expected = None if until is not None else phase2_checksum(SOURCES["auth"]["observations"], "row_manifest_id")
    return path, store, expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(SOURCES))
    parser.add_argument("--output", type=Path, help="Folder for sequences.sqlite (default data/phase4f_sequences/<source>/streams).")
    parser.add_argument("--until-epoch", type=float, help="AUTH only, for trials: stop before this time; the check against Phase 2 is skipped.")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    folder = args.output or stream_folder(args.source)
    rule = split_rule(args.source)
    started = time.perf_counter()
    log(f"{args.source.upper()} streams -> {folder}")
    if args.source == "ossec":
        path, store, expected = ossec_streams(folder, rule)
    else:
        path, store, expected = auth_streams(folder, rule, args.until_epoch)
    phase3 = phase3_split_counts(args.source)
    checks = {
        "phase2_observations_match": None if expected is None else (expected[0] == store.stats["units"] and expected[1] == store.checksum),
        "phase2_observations": None if expected is None else expected[0],
        "phase3_splits_match": None if args.until_epoch else all(store.splits.get(k, 0) == v for k, v in phase3.items()),
        "phase3_splits": phase3,
    }
    summary = {
        "source": args.source, "dataset": SOURCES[args.source]["dataset"], "store": str(path),
        "tokens": "event type; consecutive repeats collapsed (run lengths kept)",
        "order": "time, archive, member, file, numeric line, event ID",
        "duplicates": "same raw line, same second, another file: merged into the first file's copy (aliases table)",
        "split_rule": dict(zip(("train_boundary_epoch", "validation_boundary_epoch", "purge_gap_seconds"), rule)),
        "splits": dict(store.splits), **{k: v for k, v in store.stats.items()}, "checks": checks,
        "until_epoch": args.until_epoch, "seconds": round(time.perf_counter() - started, 1),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    write_json(Path(folder) / "summary.json", summary)
    log(f"{store.stats['units']:,} observations, {store.stats['distinct_sequences']:,} distinct sequences, "
        f"{store.stats['merged_copies']:,} merged copies, {store.stats['uncertain_steps']:,} uncertain steps; "
        f"splits {dict(store.splits)}; checks {checks}")
    failed = [name for name in ("phase2_observations_match", "phase3_splits_match") if checks[name] is False]
    if failed:
        log("CHECK FAILED: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
