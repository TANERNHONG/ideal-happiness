"""Phase 1 for the event logs: every line of every compressed log, parsed into one event (event_log_parser.py).

  .venv/Scripts/python.exe pipeline/phase1_classify/event_log.py
  .venv/Scripts/python.exe pipeline/phase1_classify/event_log.py --root "D:/Event Logs" --config layout.json
  .venv/Scripts/python.exe pipeline/phase1_classify/event_log.py --strict --months "Dec 25" "Jan 26"
  .venv/Scripts/python.exe pipeline/phase1_classify/event_log.py --verbose --progress-interval 5
  .venv/Scripts/python.exe pipeline/phase1_classify/event_log.py --quiet
  .venv/Scripts/python.exe pipeline/phase1_classify/event_log.py --workers 1        # one file after another

Progress goes to stderr, one timestamped line at a time with the runtime so far (HH:MM:SS.s), as in ossec.py:
  (default)   each stage's START and DONE with its time; every month's files and counts; lines read so far and their
              rate; a heartbeat naming the current stage every --progress-interval seconds (default 10); and the total
              runtime at the end, also after an error or an interruption
  --verbose   also every file (read, already processed and copied, or a repeat) and every folder or file left out
  --quiet     only warnings and errors: a damaged archive, an unreadable event_log_processed.json, a missing month
No log line, identifier value or user name is ever logged.

Reads   <root>/<Mmm YY>/*.gz or <root>/<YYYY>/<Mmm YY>/*.gz   (root: data/phase0_raw/event_logs unless --root)
        e.g. event_logs/Dec 25/aru.251201.log.gz. A month folder's name is a month and a year, normalized to YYYY-MM:
        the month whole or its first three letters or more, in any case (Sep, Sept, SEPT, September); then a space,
        a dash, an underscore or nothing; then the year in two digits or four (Dec 25, Sept-25, september_2025,
        SEP2025). In a year folder, the years must match. Two folders of one month are read as one month.
Writes  data/phase1_classify/event_log/      (or --output)
          event_log_events_<YYYY-MM>.csv     one row per line, whatever its status, with the line as it was
          event_log_issues_<YYYY-MM>.jsonl   every warning and error: code, field, value, character offsets
          event_log_exceptions_<YYYY-MM>.csv every line no rule covers yet (an error, or a warning other than
                                             'unclassified'), with its codes, the reasons and the line: for review
          event_log_exceptions_paths.csv     folders and files left out, and damaged archives, with the reason
          event_log_unclassified_values.csv  the values not in the lists yet (code 1, identifier 1, identifier 3), the
                                             most lines first: what to add to event_log_parser.py next
          event_log_summary.json             files, lines and statuses per month, issue counts, the settings used,
                                             and every file or folder left out, with the reason
          event_log_processed.json           what was read from each file: its SHA-256, the parser and settings it was
                                             read with, its lines and counts (no user names)
          event_log_devices.csv              then, from every month's events file (event_log_devices.py): one row per
          event_log_devices_review.csv       device (one signal), classified by the group of states it shows; the
          event_log_state_sets.csv           devices no group covers, for review; and the states they show together

Already processed: a file read before, with the same content and the same parser code and settings (the lists
included), is not read again; its rows are copied from the month's last outputs, in their place, so the outputs are
the same as a full run's. New and changed files are read, and when the parser or settings change every file is read
again. A file with the same content as another is a repeat: left out, and listed in event_log_exceptions_paths.csv.
Delete event_log_processed.json to read everything again.

A line whose code 1, identifier 1 or identifier 3 is not in its list yet is 'unclassified', not an error. Add the
values from event_log_unclassified_values.csv to the lists and run again; the identifier lists are never printed.
An identifier 3 that is not listed and is all lowercase is a user's name: it is written to the user_name column of the
events file only, and the summary counts those lines.

Nothing is left out silently: a folder or file outside the layout, a file that is not .gz, a damaged archive or a
line that is not valid in the chosen encoding is listed in the summary (or the issues file) with why.

Parallel: a month's files are read by --workers processes at once (default: one per core but one, at most 4), each
file streamed line by line into part files on disk, so a worker never holds a file in memory; the month's outputs are
then put together from the parts in file order, the same as reading one file after another (--workers 1).

Each month folder holds that month only: a line dated in another month is flagged DATE_OUTSIDE_FOLDER_MONTH.
Two-digit years are 20xx and times UTC+8 (the parser's defaults, README_event_log.md 'Format decisions').
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import gzip
import hashlib
import json
import logging
import multiprocessing
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import zlib
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from event_log_devices import classify_folder, log_result  # noqa: E402
from event_log_parser import INVALID, ROW_FIELDS, EventRecord, Issue, ParserConfig, parse_line  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_INPUT = ROOT / "data" / "phase0_raw" / "event_logs"
DEFAULT_OUTPUT = ROOT / "data" / "phase1_classify" / "event_log"
EVENT_COLUMNS = ["folder_month", *ROW_FIELDS]
EXCEPTION_COLUMNS = ["source_file", "line_number", "parse_status", "exception_codes", "details", "raw_line"]
PROCESSED_FILE = "event_log_processed.json"                 # what was read from each file, so it is not read again
PROCESSED_FORMAT = 1
MONTH_NAMES = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
               "november", "december")
YEAR_FOLDER = re.compile(r"\d{4}")
MONTH_FOLDER = re.compile(r"([A-Za-z]{3,9})[ _-]?(\d{4}|\d{2})")   # a month, a space, dash, underscore or nothing, a year
MONTH_LIKE = re.compile(r"[A-Za-z]+[ _-]?\d+")              # checked as a month folder, so a bad one says why


def month_number(name: str) -> int | None:
    """1-12 for a month's name in any case, whole or its first three letters or more ('Sep', 'Sept', 'SEPT',
    'september'), else None. Three letters already tell the months apart."""
    name = name.lower()
    return next((n for n, full in enumerate(MONTH_NAMES, start=1) if len(name) >= 3 and full.startswith(name)), None)


def month_key(name: str) -> str | None:
    """The YYYY-MM a month folder's name stands for ('Dec 25', 'Sept-25', 'September 2025', 'sep_25'), else None.
    Two-digit years are 20xx."""
    found = MONTH_FOLDER.fullmatch(name)
    number = month_number(found[1]) if found else None
    if number is None:
        return None
    return f"{found[2] if len(found[2]) == 4 else '20' + found[2]}-{number:02d}"


# --- progress on stderr (as in ossec.py and pf.py) --------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from runlog import Progress, stage, working_on  # noqa: E402

LOGGER = runlog.LOGGER


# --- the folder layout ------------------------------------------------------------------------------------------------

@dataclasses.dataclass
class Month:
    key: str                   # YYYY-MM
    label: str                 # the folder's own name, e.g. "Dec 25"
    files: list


def discover(root: Path) -> tuple[list[Month], list[dict]]:
    """The month folders with their .gz files, in date order, and everything else with the reason it was left out.
    A month folder may sit in a year folder (<root>/2025/Dec 25/) or directly in the root (<root>/Dec 25/)."""
    months, skipped = [], []
    skip = lambda path, reason: skipped.append({"path": path.relative_to(root).as_posix(), "reason": reason})   # noqa: E731

    def month_folder(month_dir: Path, year: str | None = None) -> None:
        key = month_key(month_dir.name)
        if key is None:
            skip(month_dir, "month folder name is not a month and a year, like 'Dec 25', 'Sept-25' or 'September 2025'")
            return
        if year is not None and key[:4] != year:
            skip(month_dir, f"month folder year {key[:4]} does not match the year folder {year}")
            return
        files = []
        for path in sorted(month_dir.iterdir()):
            if path.is_file() and path.name.endswith(".gz"):
                files.append(path)
            else:
                skip(path, "a folder inside a month folder" if path.is_dir() else "not a .gz file")
        months.append(Month(key, month_dir.name, files))

    for entry in sorted(root.iterdir()):
        if entry.is_dir() and YEAR_FOLDER.fullmatch(entry.name):
            for month_dir in sorted(entry.iterdir()):
                if month_dir.is_dir():
                    month_folder(month_dir, entry.name)
                else:
                    skip(month_dir, "not in a <Mmm YY>/ month folder")
        elif entry.is_dir() and MONTH_LIKE.fullmatch(entry.name):                       # month-like: checked in month_folder
            month_folder(entry)
        else:
            skip(entry, "neither a <YYYY> year folder nor a month folder" if entry.is_dir() else "not in a month folder")
    months.sort(key=lambda m: m.key)
    merged: dict[str, Month] = {}                           # two folders of one month ('Sep 25', 'Sept-25'): one month
    for month in months:
        if month.key in merged:
            merged[month.key].label += f" + {month.label}"
            merged[month.key].files += month.files
        else:
            merged[month.key] = month
    return list(merged.values()), skipped


# --- one month ----------------------------------------------------------------------------------------------------------

def _encoding_error(raw: bytes, number: int, source: str, encoding: str, error: UnicodeDecodeError) -> EventRecord:
    """A line the encoding cannot read: kept (undecodable bytes as \\x.. escapes) and invalid. Offsets are byte offsets."""
    text = raw.decode(encoding, errors="backslashreplace")
    return EventRecord(raw_line=text, line_number=number, source_file=source, parse_status=INVALID,
                       errors=[Issue("INVALID_ENCODING", f"The line is not valid {encoding}: {error.reason}.", None, text,
                                     error.start, error.end)])


def read_file(path: Path, source: str, month_key: str, outputs: tuple, config: ParserConfig, encoding: str,
              progress: Progress) -> dict:
    """Parse every line of one file into the month's outputs (events, issues, exceptions); returns what was read, for
    event_log_processed.json: counts, and the values not in their lists yet with their lines and first line."""
    writer, issues_handle, review = outputs
    statuses, codes, unclassified = Counter(), Counter(), {}
    number = exceptions = user_names = 0
    file_error = None
    try:
        with gzip.open(path, "rb") as handle:
            for number, raw in enumerate(handle, start=1):
                raw = raw.rstrip(b"\r\n")
                try:
                    record = parse_line(raw.decode(encoding), number, source, config)
                except UnicodeDecodeError as error:
                    record = _encoding_error(raw, number, source, encoding, error)
                writer.writerow([month_key, *record.to_values()])
                if record.warnings or record.errors:                # most lines have none: nothing more to do for them
                    issues_handle.write(json.dumps({"source_file": source, "line_number": number, "parse_status": record.parse_status,
                                                    "raw_line": record.raw_line, "warnings": [w.to_dict() for w in record.warnings],
                                                    "errors": [e.to_dict() for e in record.errors]}, ensure_ascii=False) + "\n")
                    found = [i for i in record.errors + record.warnings if not i.code.startswith("UNCLASSIFIED_")]
                    if found:                                      # no rule covers it yet: for review
                        exceptions += 1
                        review.writerow([source, number, record.parse_status, ";".join(i.code for i in found),
                                         " | ".join(f"{i.field or 'line'}: {i.message}" for i in found), record.raw_line])
                    codes.update(i.code for i in record.warnings + record.errors)
                    for issue in record.warnings:
                        if issue.code.startswith("UNCLASSIFIED_"):
                            unclassified.setdefault((issue.field, issue.value), [issue.field, issue.value, 0, number])[2] += 1
                statuses[record.parse_status] += 1
                user_names += record.user_name is not None
                progress.step()
    except (OSError, EOFError, zlib.error) as error:              # a damaged or truncated archive: what was read stays
        file_error = {"file": source, "after_line": number, "error": f"{type(error).__name__}: {error}"}
    return {"month": month_key, "lines": number, "statuses": dict(statuses), "exceptions": exceptions,
            "user_name_lines": user_names, "issues": dict(codes), "file_error": file_error, "unclassified": list(unclassified.values())}


# --- reading files in parallel -----------------------------------------------------------------------------------------
# A worker process reads one file with read_file() into three part files (its events, issues and exceptions rows, no
# headers), streaming line by line, so it never holds the file in memory. The month's outputs are put together from the
# parts in file order: the same bytes as reading one file after another. The workers add their lines to one shared
# counter, which the main process turns into the usual progress lines.

PART_KINDS = (("events", "csv"), ("issues", "jsonl"), ("exceptions", "csv"))
_SHARED_LINES = None                                        # in a worker: the lines read so far, all workers together


def default_workers() -> int:
    """One process per core but one (left for the console and the rest of the laptop), at most 4."""
    return max(1, min(4, (os.cpu_count() or 2) - 1))


def _start_worker(counter) -> None:
    global _SHARED_LINES
    _SHARED_LINES = counter


class _CountLines:
    """A worker's progress: its lines, added to the shared counter every few thousand."""

    def __init__(self):
        self.pending = 0

    def step(self, n: int = 1) -> None:
        self.pending += n
        if self.pending >= 4096:
            self.flush()

    def flush(self) -> None:
        if self.pending and _SHARED_LINES is not None:
            with _SHARED_LINES.get_lock():
                _SHARED_LINES.value += self.pending
        self.pending = 0


def read_file_to_parts(path: str, source: str, month_key: str, settings: dict, encoding: str, part: str) -> dict:
    """In a worker: read_file() into <part>.events.csv, <part>.issues.jsonl and <part>.exceptions.csv."""
    config, progress = ParserConfig.from_dict(settings), _CountLines()
    events, issues, exceptions = (Path(f"{part}.{kind}.{ext}") for kind, ext in PART_KINDS)
    with events.open("w", encoding="utf-8", newline="") as events_handle, issues.open("w", encoding="utf-8") as issues_handle, \
            exceptions.open("w", encoding="utf-8", newline="") as exceptions_handle:
        entry = read_file(Path(path), source, month_key, (csv.writer(events_handle), issues_handle, csv.writer(exceptions_handle)),
                          config, encoding, progress)
    progress.flush()
    return entry


class Workers:
    """The worker processes (started on first use) and the shared line counter, for every month of a run."""

    def __init__(self, count: int, folder: Path):
        self.count, self.lines, self.seen = count, multiprocessing.Value("q", 0), 0
        self.pool = ProcessPoolExecutor(max_workers=count, initializer=_start_worker, initargs=(self.lines,))
        self.parts = Path(tempfile.mkdtemp(prefix=".event_log_parts_", dir=folder))     # removed at the end
        self.next = 0

    def submit(self, path: Path, source: str, month_key: str, config: ParserConfig, encoding: str):
        """Start reading a file; returns (the future, the part files' stem)."""
        self.next += 1
        part = self.parts / str(self.next)
        return self.pool.submit(read_file_to_parts, str(path), source, month_key, config.to_dict(), encoding, str(part)), part

    def result(self, future, progress: Progress) -> dict:
        """The file's entry once read, the shared counter turned into progress lines meanwhile."""
        while True:
            try:
                return future.result(timeout=0.5)
            except TimeoutError:
                pass
            finally:
                now = self.lines.value
                if now > self.seen:
                    progress.step(now - self.seen)
                    self.seen = now

    def close(self) -> None:
        self.pool.shutdown(wait=True, cancel_futures=True)
        shutil.rmtree(self.parts, ignore_errors=True)


def _append(handle, path: Path) -> None:
    """A part file's bytes onto the end of an open output, as they are."""
    handle.flush()
    with path.open("rb") as part:
        shutil.copyfileobj(part, handle.buffer, 1 << 20)
    path.unlink()


def parse_month(month: Month, root: Path, output: Path, config: ParserConfig, encoding: str, processed: dict,
                settings: str, hashes: dict, first_copy: dict, workers: Workers | None = None) -> dict:
    """The month's events CSV, issues JSONL and exceptions CSV, written whole, then put in place. A file processed
    before, with the same content and the same parser code and settings, is not read again: its rows are copied from
    the month's last outputs, in their place. A file with the same content as another one is a repeat and is left out.
    processed (event_log_processed.json) is updated for the month's files. With workers, two or more files to read are
    read at once (read_file_to_parts) and their parts put together in file order."""
    paths = tuple(output / f"event_log_{kind}_{month.key}.{ext}"
                  for kind, ext in (("events", "csv"), ("issues", "jsonl"), ("exceptions", "csv")))
    sources = [(path, path.relative_to(root).as_posix()) for path in month.files]
    repeats = [{"file": s, "same_as": first_copy[hashes[s]]} for _, s in sources if first_copy[hashes[s]] != s]
    current = [(p, s) for p, s in sources if first_copy[hashes[s]] == s]
    done = {s: processed[s]["lines"] for _, s in current
            if processed.get(s, {}).get("sha256") == hashes[s] and processed[s].get("settings") == settings
            and processed[s].get("month") == month.key}
    previous = previous_rows(paths, done) if done else {}
    if previous is None:                                          # outputs missing or changed: read every file again
        LOGGER.info("%s: its outputs are missing or changed; every file is read again", month.label)
        done, previous = {}, {}
    removed = {s for s, entry in processed.items() if entry.get("month") == month.key} - {s for _, s in current}
    to_read = [s for _, s in current if s not in done]
    for source, lines in done.items():
        LOGGER.debug("%s: already processed, not read again (%s rows)", source, f"{lines:,}")
    for repeat in repeats:
        LOGGER.debug("%s: a repeat of %s; left out", repeat["file"], repeat["same_as"])
    for source in sorted(removed):
        LOGGER.debug("%s: gone, or now a repeat; its rows are dropped", source)
    if to_read or removed or not all(p.exists() for p in paths):
        progress = Progress(f"{month.label}: lines read")
        jobs = ({source: workers.submit(path, source, month.key, config, encoding) for path, source in current if source in to_read}
                if workers is not None and len(to_read) > 1 else {})
        tmp = {p: p.with_name(p.name + ".tmp") for p in paths}
        with tmp[paths[0]].open("w", encoding="utf-8", newline="") as events_handle, \
                tmp[paths[1]].open("w", encoding="utf-8") as issues_handle, \
                tmp[paths[2]].open("w", encoding="utf-8", newline="") as exceptions_handle:
            writer = csv.writer(events_handle)
            writer.writerow(EVENT_COLUMNS)
            review = csv.writer(exceptions_handle)
            review.writerow(EXCEPTION_COLUMNS)
            for path, source in current:
                if source in done:
                    writer.writerows(previous[source]["events"])
                    issues_handle.writelines(previous[source]["issues"])
                    review.writerows(previous[source]["exceptions"])
                else:
                    working_on(f"{month.label}: reading {source}")
                    started = time.monotonic()
                    if source in jobs:                                   # read by a worker: its parts, in this place
                        future, part = jobs[source]
                        entry = workers.result(future, progress)
                        for handle, (kind, ext) in zip((events_handle, issues_handle, exceptions_handle), PART_KINDS):
                            _append(handle, Path(f"{part}.{kind}.{ext}"))
                    else:
                        entry = read_file(path, source, month.key, (writer, issues_handle, review), config, encoding, progress)
                    if entry["file_error"]:
                        LOGGER.warning("%s: a damaged archive, read up to line %s: %s", source, f"{entry['file_error']['after_line']:,}",
                                       entry["file_error"]["error"])
                    processed[source] = {"sha256": hashes[source], "settings": settings, **entry}
                    LOGGER.debug("%s: read %s lines | elapsed %s", source, f"{entry['lines']:,}",
                                 runlog.format_duration(time.monotonic() - started))
        for final, temporary in tmp.items():
            temporary.replace(final)
        for source in removed:
            del processed[source]
    else:
        LOGGER.debug("%s: nothing new; its outputs stay as they are", month.label)
    entries = [processed[s] for _, s in current]
    statuses, codes = Counter(), Counter()
    for entry in entries:
        statuses.update(entry["statuses"])
        codes.update(entry["issues"])
    return {"folder": month.label, "files": len(month.files), "read_now": len(to_read), "already_processed": len(done),
            "repeats": repeats, "lines": sum(e["lines"] for e in entries), "statuses": dict(statuses),
            "exceptions": sum(e["exceptions"] for e in entries), "user_name_lines": sum(e["user_name_lines"] for e in entries),
            "issues": dict(codes.most_common()), "file_errors": [e["file_error"] for e in entries if e["file_error"]],
            "events": paths[0].name, "issue_file": paths[1].name, "exceptions_file": paths[2].name}


# --- what was processed before (event_log_processed.json) -------------------------------------------------------------

def settings_fingerprint(config: ParserConfig, encoding: str) -> str:
    """The parser's code and settings, the lists included: when any of it changes, every file is read again."""
    digest = hashlib.sha256()
    for source in (HERE / "event_log_parser.py", HERE / "event_log.py"):
        digest.update(source.read_bytes())
    digest.update(json.dumps({"config": config.to_dict(), "encoding": encoding}, sort_keys=True).encode("utf-8"))
    return digest.hexdigest()


def content_fingerprint(path: Path) -> str:
    """The SHA-256 of the file as stored (compressed)."""
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def first_copies(months: list, root: Path, processed: dict) -> tuple[dict, dict]:
    """Every file's SHA-256 (source -> hash), and the one copy of each content that is read (hash -> source): the copy
    processed before, if it is still there, otherwise the first in date order. Every month is hashed, so a copy of a
    file in a month not read this time is still a repeat."""
    hashes, copies = {}, {}
    progress = Progress("Files fingerprinted", sum(len(m.files) for m in months))
    for month in months:
        for path in month.files:
            source = path.relative_to(root).as_posix()
            hashes[source] = content_fingerprint(path)
            copies.setdefault(hashes[source], []).append(source)
            progress.step()
    first = {sha: next((s for s in group if processed.get(s, {}).get("sha256") == sha), group[0]) for sha, group in copies.items()}
    return hashes, first


def load_processed(path: Path) -> dict | None:
    """{source file: what was read from it} from earlier runs: {} on the first run, None when it cannot be read."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("format") != PROCESSED_FORMAT or not isinstance(data.get("files"), dict):
        return None
    return data["files"]


def save_processed(path: Path, files: dict) -> None:
    """Written whole, then put in place, after each month: never ahead of the outputs."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"format": PROCESSED_FORMAT, "files": dict(sorted(files.items()))}, indent=1, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(path)


def previous_rows(paths: tuple, done: dict) -> dict | None:
    """The rows of the files in done (source -> lines) from the month's last outputs, by file, as written; None when the
    outputs are missing, not in the current shape, or hold a different number of rows for a file."""
    rows = {source: {"events": [], "issues": [], "exceptions": []} for source in done}
    try:
        with paths[0].open(encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            if next(reader, None) != EVENT_COLUMNS:
                return None
            at = EVENT_COLUMNS.index("source_file")
            for row in reader:
                if row[at] in rows:
                    rows[row[at]]["events"].append(row)
        with paths[1].open(encoding="utf-8") as handle:
            for line in handle:
                source = json.loads(line)["source_file"]
                if source in rows:
                    rows[source]["issues"].append(line)
        with paths[2].open(encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            if next(reader, None) != EXCEPTION_COLUMNS:
                return None
            for row in reader:
                if row and row[0] in rows:
                    rows[row[0]]["exceptions"].append(row)
    except (OSError, ValueError, KeyError, csv.Error):
        return None
    if any(len(rows[source]["events"]) != lines for source, lines in done.items()):
        return None
    return rows


# --- the run ------------------------------------------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=DEFAULT_INPUT, help="the folder holding the month (or year) folders")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--config", type=Path, help="JSON parser settings (README_event_log.md, 'Configuration')")
    parser.add_argument("--strict", action="store_true", help="unknown units, states and limit codes are errors (default: kept, with warnings)")
    parser.add_argument("--encoding", default="utf-8", help="text encoding of the decompressed logs")
    parser.add_argument("--months", nargs="*", help="only these months, in any form of a folder name or as YYYY-MM "
                                                     "(e.g. 'Dec 25', 'Sept-25', '2025-09')")
    runlog.add_arguments(parser)
    parser.add_argument("--workers", type=int, default=default_workers(),
                        help=f"files read at once, each by its own process (default here: {default_workers()}; 1: one after another)")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be 1 or more")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    runlog.configure_from(args)
    with runlog.run() as outcome:
        code = run(args)
        if code:
            outcome["status"] = "stopped"
    return code


def run(args) -> int:
    started = time.perf_counter()
    if not args.root.is_dir():
        LOGGER.error("No event log folder at %s; give it with --root.", args.root)
        return 1
    config = ParserConfig.from_file(args.config) if args.config else ParserConfig()
    if args.strict:
        config = dataclasses.replace(config, strict_mode=True)
    with stage(f"finding the month folders under {args.root}"):
        discovered, skipped = discover(args.root)
        LOGGER.info("%s month folders, %s .gz files; %s paths left out", len(discovered),
                    f"{sum(len(m.files) for m in discovered):,}", len(skipped))
        for item in skipped:
            LOGGER.debug("Left out: %s (%s)", item["path"], item["reason"])
    months = discovered
    if args.months:
        wanted = {name: month_key(name) or name for name in args.months}         # any form of the name, or YYYY-MM
        months = [m for m in discovered if m.key in wanted.values()]
        missing = sorted(name for name, key in wanted.items() if key not in {m.key for m in months})
        if missing:
            LOGGER.warning("No month folder named %s.", ", ".join(missing))
    if not any(m.files for m in months):
        LOGGER.error("No .gz files under %s in <Mmm YY>/ (or <YYYY>/<Mmm YY>/) folders.%s", args.root,
                     f" Left out: {len(skipped)} (below)." if skipped else "")
        for item in skipped:
            LOGGER.error("Left out %s: %s", item["path"], item["reason"])
        return 1
    args.output.mkdir(parents=True, exist_ok=True)
    summary = {"root": str(args.root), "output": str(args.output), "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
               "encoding": args.encoding, "config": config.to_public_dict(), "months": {}, "skipped": skipped}
    processed_path = args.output / PROCESSED_FILE
    processed = load_processed(processed_path)
    if processed is None:
        LOGGER.warning("%s could not be read: every file is read again.", PROCESSED_FILE)
        processed = {}
    else:
        LOGGER.info("%s: %s files processed before", PROCESSED_FILE, f"{len(processed):,}")
    settings = settings_fingerprint(config, args.encoding)
    with stage(f"fingerprinting {sum(len(m.files) for m in discovered):,} files"):
        hashes, first_copy = first_copies(discovered, args.root, processed)
    workers = Workers(args.workers, args.output) if args.workers > 1 else None
    LOGGER.info("Reading up to %s files at once%s", args.workers, "" if workers else " (one after another)")
    try:
        for month in months:
            month_config = dataclasses.replace(config, expected_month=month.key)
            with stage(f"{month.label}: {len(month.files)} files"):
                result = parse_month(month, args.root, args.output, month_config, args.encoding, processed, settings, hashes,
                                     first_copy, workers)
                save_processed(processed_path, processed)
            summary["months"][month.key] = result
            LOGGER.info("%s: read %s, already processed %s, repeats %s; %s lines; %s", month.label, result["read_now"],
                        result["already_processed"], len(result["repeats"]), f"{result['lines']:,}",
                        ", ".join(f"{k} {v:,}" for k, v in sorted(result["statuses"].items())) or "no lines")
    finally:
        if workers is not None:
            workers.close()
    with stage("grouping the devices by their states (event_log_devices.py)"):
        summary["devices"] = classify_folder(args.output, step=Progress("Event lines read for the devices").step)
    with stage("writing the summary and the review files"):
        missing: dict = {}                                    # (field, value) -> lines, months, first seen
        for month in months:
            for path in month.files:
                source = path.relative_to(args.root).as_posix()
                if first_copy[hashes[source]] != source:
                    continue
                for field, value, lines, first in processed[source]["unclassified"]:
                    seen = missing.setdefault((field, value), {"lines": 0, "months": set(), "first": f"{source}:{first}"})
                    seen["lines"] += lines
                    seen["months"].add(month.key)
        totals = Counter()
        for result in summary["months"].values():
            totals.update(result["statuses"])
        results = summary["months"].values()
        summary["totals"] = {"files": sum(r["files"] for r in results), "lines": sum(r["lines"] for r in results),
                             "statuses": dict(totals), "user_name_lines": sum(r["user_name_lines"] for r in results),
                             "read_now": sum(r["read_now"] for r in results),
                             "already_processed": sum(r["already_processed"] for r in results),
                             "repeats": sum(len(r["repeats"]) for r in results)}
        summary["processed"] = PROCESSED_FILE
        to_add = write_unclassified(args.output / "event_log_unclassified_values.csv", missing)
        summary["unclassified"] = {"lines": totals.get("unclassified", 0), "values_to_add": to_add,
                                   "months_read": [m.key for m in months], "file": "event_log_unclassified_values.csv"}
        summary["exceptions"] = {"lines": sum(r["exceptions"] for r in summary["months"].values()),
                                 "paths": write_path_exceptions(args.output / "event_log_exceptions_paths.csv", skipped, summary["months"])}
        summary["seconds"] = round(time.perf_counter() - started, 1)
        (args.output / "event_log_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    LOGGER.info("Exceptions for review: %s lines (event_log_exceptions_<YYYY-MM>.csv), %s files or folders "
                "(event_log_exceptions_paths.csv)", f"{summary['exceptions']['lines']:,}", summary["exceptions"]["paths"])
    LOGGER.info("Unclassified: %s lines; values to add: %s (event_log_unclassified_values.csv)",
                f"{summary['unclassified']['lines']:,}", ", ".join(f"{field} {n:,}" for field, n in to_add.items()) or "none")
    LOGGER.info("User names: %s lines (user_name, events file only)", f"{summary['totals']['user_name_lines']:,}")
    log_result(summary["devices"])
    LOGGER.info("Files read now: %s; already processed, not read again: %s; repeats left out: %s (%s)",
                summary["totals"]["read_now"], summary["totals"]["already_processed"], summary["totals"]["repeats"], PROCESSED_FILE)
    LOGGER.info("Done: %s lines in %s files -> %s", f"{summary['totals']['lines']:,}", summary["totals"]["files"], args.output)
    return 0


def write_path_exceptions(path: Path, skipped: list, months: dict) -> int:
    """Folders and files left out, repeats, and damaged archives, for review; returns how many."""
    rows = [[s["path"], "left out", s["reason"]] for s in skipped]
    rows += [[r["file"], "repeat", f"the same content as {r['same_as']}; left out"] for m in months.values() for r in m["repeats"]]
    rows += [[e["file"], "damaged archive", f"{e['error']} (after line {e['after_line']})"] for m in months.values() for e in m["file_errors"]]
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "what", "reason"])
        writer.writerows(rows)
    tmp.replace(path)
    return len(rows)


def write_unclassified(path: Path, missing: dict) -> dict:
    """The values not in their lists yet, the most lines first; returns how many distinct values per field."""
    rows = sorted(missing.items(), key=lambda kv: (-kv[1]["lines"], kv[0][0], kv[0][1] or ""))
    tmp = path.with_suffix(".csv.tmp")
    with tmp.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["field", "value", "lines", "months", "first_seen"])
        for (field, value), seen in rows:
            writer.writerow([field, value, seen["lines"], " ".join(sorted(seen["months"])), seen["first"]])
    tmp.replace(path)
    return dict(Counter(field for field, _ in missing))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:                    # runlog.run() has logged it
        raise SystemExit(130)
    except Exception:
        LOGGER.exception("The event log run failed")
        raise SystemExit(1)
