"""Patterns: the regex rules new logs need before the pipeline can read them.

New data can come in a shape no rule knows yet: a new log type (an OSSEC line and an authlog line look
nothing alike), or a known one that has drifted (a new head, a new message). This module finds them.

A *log type* (family) is one the pipeline reads (auth, OSSEC, PF, IPFilter) or one named here. Each can gain,
kept on this laptop in ``var/console.sqlite3``:

* prefixes - a line's head (time, server, process), cut off first;
* suffixes - a tail such as `` [preauth]``, cut off next;
* rules    - an event type and a regex for what is left, the message (case-insensitive, as in Phase 1).

A scan reads the lines (pasted, uploaded, or a file, folder, ZIP or .gz on this laptop) and tells what is
known: the pipeline's own Phase 1 rules first, then these. The unknown lines are grouped into shapes (times,
addresses, numbers and paths masked; shapes differing in a word or two merged), largest first, with their
heads (prefix candidates) and tails (suffix candidates). A pass after new rules are saved reads the data
again; which lines Phase 1 knows is remembered from the first pass. Coverage is kept per pass and over
time (by the dates in the lines, else by position), so drift shows as a dip, as shapes first seen late,
and as rules that stopped matching.

Logs that come as a table (a CSV or Excel export: one column the raw line, the others extra fields; see
``tabular.py``) are first previewed: the first 100 rows checked, the person picks the raw-log column and the
columns to keep (``preview``), then the scan reads them so. The kept fields go with each line: a time column
places the lines in time, every other field is counted per value (how much of each host or source is known),
and the canvas can show the lines of one value. The table's layout is kept with the log type.

Rules are tried on at most a few thousand kept lines while they are written, with a time limit per match
(the ``regex`` package), and nested repeats such as ``(a+)+`` are refused, so a rule cannot hang the
console. Examples kept with a rule have their IPv4 addresses replaced by documentation addresses.

Analyze does not use these rules yet: they are exported (JSON, or lines for Phase 1's RULES) and added to
the pipeline, whose models then learn the new event types.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import random
import re
import threading
import time
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime
from itertools import chain, islice
from pathlib import Path
from re import _parser as sre_parse          # the standard parser: to look inside a pattern before running it

from . import analyze, store, tabular
from .pipeline_code import module

try:                                          # a time limit per match
    import regex as _engine
except ImportError:                           # pragma: no cover - nested repeats are still refused
    _engine = None

BUILTIN = ("auth", "ossec", "pf", "ipf")
LABELS = {"auth": "AUTH", "ossec": "OSSEC", "pf": "PF", "ipf": "IPFilter"}
EVENT_PREFIX = {"auth": "", "ossec": "OSSEC_", "pf": "PF_", "ipf": "IPF_"}
KINDS = ("prefix", "suffix", "rule")
NEGLIGIBLE = 0.05             # below this share of known lines, logs count as unknown (Simple mode stops there)
SAMPLE = 200                  # lines looked at to tell the log type
MAX_SCAN = 5_000_000          # lines read per pass
LINE_CAP = 4000               # characters of a line that rules see
MATCH_SECONDS = 0.05          # per match; a rule over it is set aside for the rest of the pass
UNKNOWN_KEEP = 4000           # unknown lines kept (a uniform sample) for the canvas and for trying rules
KNOWN_KEEP = 800
TRY_LINES = 2000              # kept lines a rule is tried on while it is written
MAX_TEMPLATES = 60_000        # distinct masked shapes counted per pass
MERGED = 8000                 # the largest of them merged into shapes
SHOWN = 300                   # shapes, heads and tails returned
BLOCKS = 4000                 # blocks for coverage over time: they start at 10 lines and double when there are more
POSITION_BUCKETS = 20
FIELD_VALUES = 200            # a field with more values than this is not counted per value
FIELD_SHOWN = 30              # values listed per field
NEW_SHARE = 0.75              # a shape first seen in the last quarter of the buckets is new
WORKSPACES = 4
WORKSPACE_SECONDS = 6 * 3600
PASTED = "Pasted lines"
NAME = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
EVENT = re.compile(r"^[A-Z][A-Z0-9_]{2,80}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS pattern_families (name TEXT PRIMARY KEY, created_at TEXT, created_by TEXT);
CREATE TABLE IF NOT EXISTS pattern_rules (
    id INTEGER PRIMARY KEY, family TEXT, kind TEXT, event_type TEXT, regex TEXT, position INTEGER,
    enabled INTEGER DEFAULT 1, examples TEXT, created_at TEXT, created_by TEXT);
CREATE INDEX IF NOT EXISTS pattern_rules_family ON pattern_rules (family, kind, position);
CREATE TABLE IF NOT EXISTS pattern_layouts (family TEXT PRIMARY KEY, layout TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS pattern_passes (
    id INTEGER PRIMARY KEY, family TEXT, dataset TEXT, workspace TEXT, at TEXT, actor TEXT, lines INTEGER,
    builtin INTEGER, custom INTEGER, sliced INTEGER, rules INTEGER);
"""


def _connect():
    con = store.connect()
    con.executescript(SCHEMA)
    return con


# --- checking and compiling a pattern -----------------------------------------------------------

def _wide(high: int) -> bool:
    return high > 50                                   # MAXREPEAT (no upper bound) included


def _check_repeats(items, inside: bool) -> None:
    """Refuse an unbounded repeat inside another repeat: (a+)+, (?:\\S+\\s+)* and the like can take
    forever on a line that almost matches."""
    for op, av in items:
        name = str(op)
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            low, high, sub = av
            if inside and _wide(high):
                raise ValueError("A repeat inside a repeat can take forever on some lines: repeat one part only.")
            _check_repeats(sub, inside or high > 1)
        elif name == "SUBPATTERN":
            _check_repeats(av[3], inside)
        elif name == "BRANCH":
            for sub in av[1]:
                _check_repeats(sub, inside)
        elif name in ("ASSERT", "ASSERT_NOT"):
            _check_repeats(av[1], inside)
        elif name == "ATOMIC_GROUP":
            _check_repeats(av, inside)
        elif name == "GROUPREF_EXISTS":
            _check_repeats(av[1], inside)
            if av[2]:
                _check_repeats(av[2], inside)


def check(pattern: str) -> None:
    """A pattern Phase 1's ``re`` accepts, of a sane size, without nested repeats; ValueError otherwise."""
    if not pattern or len(pattern) > 2000:
        raise ValueError("A pattern of 1 to 2,000 characters.")
    try:
        parsed = sre_parse.parse(pattern)
        re.compile(pattern)
    except re.error as error:
        raise ValueError(f"Not a valid regex: {error}.") from None
    _check_repeats(parsed, False)


def _compile(pattern: str, kind: str, trusted: bool = False, ignore_case: bool = False):
    if not trusted:
        check(pattern)
    text = f"(?:{pattern})$" if kind == "suffix" else pattern
    flags = re.I if kind == "rule" or ignore_case else 0
    if _engine is not None:
        return _engine.compile(text, _engine.I if flags else 0)
    return re.compile(text, flags)


def _run(method, text: str):
    return method(text, timeout=MATCH_SECONDS) if _engine is not None else method(text)


# --- rules ----------------------------------------------------------------------------------------

def builtin_prefix(family: str) -> str:
    """The head Phase 1 cuts off a line of this log type, taken from its own code."""
    if family == "auth":
        base = module("phase1_classify/auth.py").StandaloneAuthClassifier.BASE.pattern
        return base[:base.index("(?P<raw_message>")]
    if family == "ossec":
        return r"(?:\S+?:(?=\d{4}/))?" + module("phase1_classify/ossec.py").LOG_PREFIX.lstrip("^")
    if family == "pf":
        return module("phase1_classify/pf.py").COMMON_PREFIX
    if family == "ipf":
        line = module("phase1_classify/ipf.py").LINE.pattern
        return line[:line.index("(?P<packet_time>")]
    return ""


class RuleSet:
    """A log type's prefixes, suffixes and rules, compiled, in order; ``read`` cuts a line and names it."""

    def __init__(self, family: str, rows: list[dict]):
        self.family = family
        self.prefixes, self.suffixes, self.rules = [], [], []
        self.events = {}
        self.slow: set = set()
        if family in BUILTIN:
            try:
                self.prefixes.append(("builtin", _compile(builtin_prefix(family), "prefix", trusted=True, ignore_case=family == "pf")))
            except Exception:                         # a pipeline import problem must not stop the console
                pass
        for row in rows:
            if not row["enabled"]:
                continue
            try:
                compiled = _compile(row["regex"], row["kind"])
            except ValueError:
                continue
            {"prefix": self.prefixes, "suffix": self.suffixes, "rule": self.rules}[row["kind"]].append((row["id"], compiled))
            if row["kind"] == "rule":
                self.events[row["id"]] = row["event_type"]

    def _first(self, entries, method: str, text: str):
        for rid, compiled in entries:
            if rid in self.slow:
                continue
            try:
                found = _run(getattr(compiled, method), text)
            except TimeoutError:
                self.slow.add(rid)
                continue
            if found:
                yield rid, found

    def cut(self, text: str) -> tuple[int, int, object, object]:
        """Where the message starts and ends, and which prefix and suffix cut it (None for none)."""
        start, prefix = 0, None
        for rid, found in self._first(self.prefixes, "match", text):
            if 0 < found.end() < len(text):            # a prefix leaves a message
                start, prefix = found.end(), rid
                break
        end, suffix = len(text), None
        rest = text[start:]
        for rid, found in self._first(self.suffixes, "search", rest):
            if found.start() > 0 and rest[:found.start()].strip():
                end, suffix = start + found.start(), rid
                break
        return start, end, prefix, suffix

    def rule_for(self, message: str):
        for rid, _ in self._first(self.rules, "fullmatch", message):
            return rid
        return None

    def read(self, line: str) -> tuple[int, int, object, object, object, str]:
        text = line[:LINE_CAP]
        start, end, prefix, suffix = self.cut(text)
        message = text[start:end].strip()
        return start, end, prefix, suffix, (self.rule_for(message) if message else None), message


def _rows(con, family: str) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT * FROM pattern_rules WHERE family=? ORDER BY CASE kind WHEN 'prefix' THEN 0 WHEN 'suffix' THEN 1 ELSE 2 END, position, id",
        (family,))]


def ruleset(family: str) -> RuleSet:
    with _connect() as con:
        return RuleSet(family, _rows(con, family) if family else [])


def families() -> list[dict]:
    with _connect() as con:
        custom = [r["name"] for r in con.execute("SELECT name FROM pattern_families ORDER BY name")]
        counts = defaultdict(dict)
        for r in con.execute("SELECT family, kind, COUNT(*) n FROM pattern_rules GROUP BY family, kind"):
            counts[r["family"]][r["kind"]] = r["n"]
    return [{"name": f, "label": LABELS.get(f, f), "builtin": f in BUILTIN, "rules": counts.get(f, {})}
            for f in [*BUILTIN, *custom]]


def _known_family(family: str) -> bool:
    return family in BUILTIN or any(f["name"] == family for f in families())


def create_family(name: str, actor: str) -> str:
    name = name.strip().lower().replace(" ", "-")
    if not NAME.match(name):
        raise ValueError("A log type name: 2 to 31 letters, digits, - or _, starting with a letter.")
    if name in BUILTIN or name in LABELS.values():
        raise ValueError(f"{name} is one of the pipeline's log types.")
    with store._lock, _connect() as con:
        if con.execute("SELECT 1 FROM pattern_families WHERE name=?", (name,)).fetchone():
            return name
        con.execute("INSERT INTO pattern_families VALUES (?,?,?)", (name, store.now(), actor))
        store.audit(con, actor, "pattern_family", f"patterns/{name}", {})
    return name


def unapproved() -> list[dict]:
    """The log types made here, not (yet) part of the pipeline: who made them, their rules, their last scan and
    the table they came as (Datasets lists them)."""
    out = []
    with _connect() as con:
        for family in con.execute("SELECT * FROM pattern_families ORDER BY name").fetchall():
            name = family["name"]
            rules = {r["kind"]: r["n"] for r in con.execute(
                "SELECT kind, COUNT(*) AS n FROM pattern_rules WHERE family=? GROUP BY kind", (name,))}
            last = con.execute("SELECT dataset, at, lines, builtin, custom FROM pattern_passes WHERE family=? ORDER BY id DESC LIMIT 1",
                               (name,)).fetchone()
            scans = con.execute("SELECT COUNT(*) FROM pattern_passes WHERE family=?", (name,)).fetchone()[0]
            table = con.execute("SELECT layout FROM pattern_layouts WHERE family=?", (name,)).fetchone()
            layout = json.loads(table["layout"]) if table else None
            out.append({"name": name, "created_at": family["created_at"], "created_by": family["created_by"],
                        "rules": rules, "passes": scans,
                        "last": {"dataset": last["dataset"], "at": last["at"], "lines": last["lines"],
                                 "coverage": (last["builtin"] + last["custom"]) / last["lines"] if last["lines"] else 0} if last else None,
                        "table": {"format": layout["format"], "raw": layout["raw"], "columns": len(layout["columns"])} if layout else None})
    return out


def delete_family(name: str, actor: str) -> dict:
    """Delete a log type made here, with its rules, its table layout and its scans. Anyone at the console may
    (decision Q34: these are not the pipeline's data); the pipeline's four log types cannot be deleted."""
    if name in BUILTIN:
        raise ValueError(f"{LABELS[name]} is one of the pipeline's log types.")
    with store._lock, _connect() as con:
        if con.execute("SELECT 1 FROM pattern_families WHERE name=?", (name,)).fetchone() is None:
            raise KeyError(f"No log type {name!r}.")
        rules = con.execute("DELETE FROM pattern_rules WHERE family=?", (name,)).rowcount
        scans = con.execute("DELETE FROM pattern_passes WHERE family=?", (name,)).rowcount
        con.execute("DELETE FROM pattern_layouts WHERE family=?", (name,))
        con.execute("DELETE FROM pattern_families WHERE name=?", (name,))
        store.audit(con, actor, "pattern_family_deleted", f"patterns/{name}", {"rules": rules, "scans": scans})
    with _ws_lock:                                     # open scans of it carry on without a log type
        for ws in _workspaces.values():
            if ws.family == name:
                ws.family, ws.builtin_known = "", None
    return {"rules": rules, "scans": scans}


IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def censor(lines: list[str]) -> list[str]:
    """IPv4 addresses replaced by documentation addresses (192.0.2.1, .2, ...), the same address the same way."""
    seen: dict[str, str] = {}
    def swap(found):
        return seen.setdefault(found.group(), f"192.0.2.{len(seen) % 254 + 1}")
    return [IPV4.sub(swap, line) for line in lines]


def save_rule(family: str, kind: str, regex: str, event_type: str, examples: list[str], actor: str) -> dict:
    if not _known_family(family):
        raise ValueError("Name the log type first.")
    if kind not in KINDS:
        raise ValueError(f"Unknown kind {kind!r}.")
    regex = regex.strip() if kind != "suffix" else regex.rstrip()
    check(regex)
    event_type = event_type.strip().upper() if kind == "rule" else ""
    if kind == "rule" and not EVENT.match(event_type):
        raise ValueError("An event type in capitals, digits and _, such as RADIUS_LOGIN_OK.")
    kept = censor([str(e)[:500] for e in examples[:5]])
    with store._lock, _connect() as con:
        position = con.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM pattern_rules WHERE family=? AND kind=?",
                               (family, kind)).fetchone()[0]
        cur = con.execute("INSERT INTO pattern_rules (family, kind, event_type, regex, position, enabled, examples, created_at, created_by) "
                          "VALUES (?,?,?,?,?,1,?,?,?)", (family, kind, event_type, regex, position, json.dumps(kept), store.now(), actor))
        store.audit(con, actor, "pattern_saved", f"patterns/{family}/{cur.lastrowid}", {"kind": kind, "event_type": event_type, "regex": regex})
        return {"id": cur.lastrowid}


def update_rule(rule_id: int, actor: str, enabled: bool | None = None, move: str = "") -> None:
    with store._lock, _connect() as con:
        row = con.execute("SELECT * FROM pattern_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise KeyError(f"No rule #{rule_id}.")
        if enabled is not None:
            con.execute("UPDATE pattern_rules SET enabled=? WHERE id=?", (int(enabled), rule_id))
        if move == "up":                               # earlier rules are tried first
            above = con.execute("SELECT id, position FROM pattern_rules WHERE family=? AND kind=? AND position < ? "
                                "ORDER BY position DESC LIMIT 1", (row["family"], row["kind"], row["position"])).fetchone()
            if above:
                con.execute("UPDATE pattern_rules SET position=? WHERE id=?", (row["position"], above["id"]))
                con.execute("UPDATE pattern_rules SET position=? WHERE id=?", (above["position"], rule_id))
        store.audit(con, actor, "pattern_changed", f"patterns/{row['family']}/{rule_id}",
                    {k: v for k, v in (("enabled", enabled), ("move", move)) if v not in (None, "")})


def delete_rule(rule_id: int, actor: str) -> None:
    with store._lock, _connect() as con:
        row = con.execute("SELECT * FROM pattern_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise KeyError(f"No rule #{rule_id}.")
        con.execute("DELETE FROM pattern_rules WHERE id=?", (rule_id,))
        store.audit(con, actor, "pattern_deleted", f"patterns/{row['family']}/{rule_id}",
                    {"kind": row["kind"], "event_type": row["event_type"], "regex": row["regex"]})


def rules(family: str) -> dict:
    with _connect() as con:
        rows = _rows(con, family) if family else []
    for row in rows:
        row["examples"] = json.loads(row["examples"] or "[]")
    return {"families": families(), "family": family, "builtin_prefix": builtin_prefix(family) if family in BUILTIN else "",
            "rules": rows}


def _python(text: str) -> str:
    """``text`` as a Python string literal: a raw one where that reads back exactly (no quote of its kind, no trailing
    backslash, no line break or other control character), else repr, which always does."""
    plain = not text.endswith("\\") and not any(ord(c) < 32 or ord(c) == 127 for c in text)
    if plain and '"' not in text:
        return f'r"{text}"'
    if plain and "'" not in text:
        return f"r'{text}'"
    return repr(text)


def export(family: str) -> dict:
    rows = [r for r in rules(family)["rules"] if r["enabled"]]
    with _connect() as con:
        found = con.execute("SELECT layout FROM pattern_layouts WHERE family=?", (family,)).fetchone()
    table = json.loads(found["layout"]) if found else None
    pack = {"family": family, "exported_at": store.now(), "table": table,
            "prefixes": [r["regex"] for r in rows if r["kind"] == "prefix"],
            "suffixes": [r["regex"] for r in rows if r["kind"] == "suffix"],
            "rules": [{"event_type": r["event_type"], "regex": r["regex"], "flags": "i", "examples": r["examples"]}
                      for r in rows if r["kind"] == "rule"]}
    phase1 = [f"# {family}: a {' '.join(str(table['format']).split())} table: the raw line in column {table['raw']!r}"
              + (f"; time {table['time']!r}" if table["time"] else "") + (f"; host {table['host']!r}" if table["host"] else "")] if table else []
    phase1 += [f"# {family}: prefix {_python(p)}" for p in pack["prefixes"]]
    phase1 += [f"# {family}: suffix {_python(s)}" for s in pack["suffixes"]]
    phase1 += [f'("{r["event_type"]}", {_python(r["regex"])}),' for r in pack["rules"]]
    return {"pack": pack, "phase1": "\n".join(phase1)}


# --- reading lines --------------------------------------------------------------------------------

MAX_LINE = 1 << 20                               # bytes: a longer "line" is cut into pieces (_decoded)


def _decoded(raw):
    """The lines of a byte stream as text, line ends kept (UTF-8, damaged bytes replaced); nothing for a stream
    that is not text (NUL bytes in its first 4 KB)."""
    first = raw.read(4096)
    if b"\x00" in first:
        return
    rest, start = b"", True
    for chunk in chain([first], iter(lambda: raw.read(1 << 20), b"")):
        parts = (rest + chunk).split(b"\n")
        rest = parts.pop()
        if len(rest) > MAX_LINE:                 # a megabyte without a line break is no log line: cut it, so memory stays small
            parts.append(rest)
            rest = b""
        for part in parts:
            line = part.decode("utf-8", "replace") + "\n"
            yield line.lstrip("\ufeff") if start else line
            start = False
    if rest:
        yield rest.decode("utf-8", "replace")


def _streams(path: Path):
    """Each file's name and bytes: a file, a folder (its files in name order), a ZIP (its members) or a .gz."""
    if path.is_dir():
        for file in sorted(p for p in path.rglob("*") if p.is_file()):
            yield from _streams(file)
        return
    name = path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for info in sorted(archive.infolist(), key=lambda i: i.filename):
                if not info.is_dir() and not info.filename.lower().endswith(".zip"):
                    with archive.open(info) as raw:
                        yield info.filename, raw
        return
    opener = gzip.open if name.endswith(".gz") else open
    with opener(path, "rb") as raw:
        yield path.name.removesuffix(".gz"), raw


def open_records(path: Path, layout: dict | None = None):
    """(line, fields) of every line under a path. A file that starts with the table's header is read as the
    table (its raw-line column, and the kept columns' values as fields); any other as plain lines (no fields).
    An Excel workbook is read only as the table."""
    for name, raw in _streams(path):
        if name.lower().endswith((".xlsx", ".xls")):
            if layout and name.lower().endswith(".xlsx"):
                rows = tabular.xlsx_rows(io.BytesIO(tabular.capped(raw)))
                first = next(rows, None)
                if first is not None and tabular.is_header(first, layout):
                    yield from tabular.records_from_rows(rows, layout)
            continue
        lines = _decoded(raw)
        first = next(lines, None)
        if first is None:
            continue
        if layout and tabular.is_header(first, layout):
            yield from tabular.records(lines, layout)
            continue
        for line in chain([first], lines):
            line = line.rstrip("\r\n")
            if line.strip():
                yield line, None


def open_lines(path: Path):
    """The non-blank lines under a path, as text."""
    for line, _ in open_records(path):
        yield line


def _signature(path: Path) -> tuple:
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    return tuple((str(f), f.stat().st_size, f.stat().st_mtime_ns) for f in files)


# --- shapes ---------------------------------------------------------------------------------------

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
SYSLOG_TIME = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
ISO_TIME = r"\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?"
MASK = re.compile(                                  # each token starts with a digit, a month's capital or a path
    r"(?=[\d/\\JFMASOND]|[A-Za-z]:[\\/])(?:"
    rf"(?P<time>{ISO_TIME}|\b{SYSLOG_TIME}|\b\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?)"
    r"|(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)"
    r"|(?P<mac>\b\d[0-9A-Fa-f](?::[0-9A-Fa-f]{2}){5}\b)"
    r"|(?P<hex>\b0x[0-9A-Fa-f]+\b|\b(?=\d[0-9a-fA-F]{7,}\b)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]+\b)"
    r"|(?P<path>(?:[A-Za-z]:)?(?:[\\/][\w.@+-]+){2,}[\\/]?)"
    r"|(?P<n>\b\d+\b))")
DATE = re.compile(r"(?P<y>\d{4})[-/](?P<m>\d{2})[-/](?P<d>\d{2})|\b(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+\d{2}:")
HEAD_WORDS = re.compile(r"\s*(?:\S+\s+){3}")


def _label(found) -> str:
    return f"<{found.lastgroup}>"


def mask(text: str) -> str:
    """A line's shape: times, addresses, ids, paths and numbers replaced by <time>, <ip>, ..., spaces single."""
    return " ".join(MASK.sub(_label, text).split())


def _date_key(line: str):
    found = DATE.search(line, 0, 80)
    if not found:
        return None
    if found["y"]:
        return f"{found['y']}-{found['m']}-{found['d']}"
    return f"{MONTHS.index(found['mon']) + 1:02d}-{int(found['day']):02d}"


def _date_label(key: str) -> str:
    if len(key) == 5:                                  # MM-DD (syslog has no year)
        return f"{MONTHS[int(key[:2]) - 1]} {int(key[3:])}"
    if len(key) == 2:
        return MONTHS[int(key) - 1]
    return key


def _count(table: dict, key: str, example: str, at: int, date=None) -> bool:
    """Count a shape: [lines, examples, first line, last line, earliest date, latest date]."""
    entry = table.get(key)
    if entry is None:
        if len(table) >= MAX_TEMPLATES:
            return False
        table[key] = entry = [0, [], at, at, date, date]
    entry[0] += 1
    entry[3] = at
    if date:
        if entry[4] is None or date < entry[4]:
            entry[4] = date
        if entry[5] is None or date > entry[5]:
            entry[5] = date
    if len(entry[1]) < 3 and example not in entry[1]:
        entry[1].append(example)
    return True


def _earliest(a, b):
    return b if a is None else a if b is None else min(a, b)


def _latest(a, b):
    return b if a is None else a if b is None else max(a, b)


def merge(table: dict) -> tuple[list[dict], int]:
    """Largest first, a shape joins a larger one with as many words that differs in at most a third of them
    (two at most); the words that differ become <*>. Returns the shapes and the lines left in small ones."""
    ordered = sorted(table.items(), key=lambda kv: -kv[1][0])
    left = sum(entry[0] for _, entry in ordered[MERGED:])
    kept, by_length = [], defaultdict(list)
    for key, (count, examples, first, last, early, late) in ordered[:MERGED]:
        tokens = key.split(" ")
        budget = min(2, len(tokens) // 3)
        home, diff = None, []
        if budget:
            for shape in by_length[len(tokens)][:200]:
                diff = []
                for j, (a, b) in enumerate(zip(shape["tokens"], tokens)):
                    if a != b and a != "<*>":
                        diff.append(j)
                        if shape["wild"] + len(diff) > budget:
                            break
                if shape["wild"] + len(diff) <= budget:
                    home = shape
                    break
        if home is None:
            shape = {"tokens": tokens, "wild": 0, "count": count, "examples": list(examples), "first": first, "last": last,
                     "early": early, "late": late}
            by_length[len(tokens)].append(shape)
            kept.append(shape)
            continue
        for j in diff:
            home["tokens"][j] = "<*>"
        home["wild"] += len(diff)
        home["count"] += count
        home["first"], home["last"] = min(home["first"], first), max(home["last"], last)
        home["early"], home["late"] = _earliest(home["early"], early), _latest(home["late"], late)
        home["examples"].extend(e for e in examples if len(home["examples"]) < 3 and e not in home["examples"])
    kept.sort(key=lambda s: -s["count"])
    return kept, left


def fits(template: list[str], tokens: list[str]) -> bool:
    return len(template) == len(tokens) and all(a == b or a == "<*>" for a, b in zip(template, tokens))


# --- workspaces and passes ----------------------------------------------------------------------------

class Workspace:
    """One dataset being worked on: its lines (pasted) or where they are (a path), and the last pass."""

    def __init__(self, name: str, family: str, lines: list | None, path: str | None, layout: dict | None = None):
        self.id = uuid.uuid4().hex[:12]
        self.name, self.family, self.lines, self.path, self.layout = name, family, lines, path, layout
        self.builtin_known: bytearray | None = None
        self.signature = None
        self.passes = 0
        self.unknown_keep: list[tuple] = []           # (line no., line, fields)
        self.known_keep: list[tuple] = []             # (line no., line, known by, fields)
        self.shapes: list[dict] = []
        self.result: dict | None = None
        self.used = time.time()
        self.lock = threading.Lock()

    def records(self):
        """(line, fields): pasted lines are kept as text, or as (line, fields) for a table."""
        if self.lines is None:
            return open_records(Path(self.path), self.layout)
        return iter(self.lines) if self.layout else ((line, None) for line in self.lines)


_workspaces: dict[str, Workspace] = {}
_ws_lock = threading.Lock()


def _keep(ws: Workspace) -> None:
    with _ws_lock:
        for old in [k for k, w in _workspaces.items() if time.time() - w.used > WORKSPACE_SECONDS]:
            _workspaces.pop(old)
        while len(_workspaces) >= WORKSPACES:
            _workspaces.pop(min(_workspaces.values(), key=lambda w: w.used).id)
        _workspaces[ws.id] = ws


def workspace(ws_id: str) -> Workspace:
    with _ws_lock:
        ws = _workspaces.get(ws_id)
    if ws is None:
        raise KeyError("This scan has expired. Scan again.")
    ws.used = time.time()
    return ws


def _builtin_flags(family: str, chunk: list[str], month: str) -> list[bool]:
    parser = analyze.PARSERS[family]
    try:
        return [ok for _, ok in parser(chunk, month)]
    except Exception:                                  # one odd line: go line by line
        flags = []
        for line in chunk:
            try:
                flags.append(next(parser([line], month))[1])
            except Exception:
                flags.append(False)
        return flags


def _reservoir(bag: list, limit: int, seen: int, item, rng: random.Random) -> None:
    if len(bag) < limit:
        bag.append(item)
    else:
        j = rng.randrange(seen)
        if j < limit:
            bag[j] = item


def _buckets(blocks: list[list], block_size: int, days: dict):
    """Coverage over time: by the dates of the lines (a table's time column, else the line) when most lines have
    one, else by position. Returns the mode, the buckets, and where a line falls: ``at(line index, date)``."""
    dated = sum(day[0] for day in days.values())
    total = sum(block[0] for block in blocks)
    if total and dated >= 0.5 * total and len(days) >= 2:
        keys = sorted(days)
        monthly = len(keys) > 62
        group = (lambda k: k[:7] if len(k) == 10 else k[:2]) if monthly else (lambda k: k)
        order = sorted({group(k) for k in keys})
        index = {k: i for i, k in enumerate(order)}
        items = [{"label": _date_label(k), "lines": 0, "known": 0} for k in order]
        for key, (lines, known) in days.items():
            items[index[group(key)]]["lines"] += lines
            items[index[group(key)]]["known"] += known
        of_block, current = [], index[group(keys[0])]
        for block in blocks:
            if block[2]:
                current = index[group(block[2])]
            of_block.append(current)
            items[current]["lines"] += block[3]          # the block's undated lines, with its day
            items[current]["known"] += block[4]
        mode = "time"
        by_date = lambda d: index.get(group(d))
    else:
        n = max(1, min(POSITION_BUCKETS, len(blocks)))
        of_block = [b * n // max(1, len(blocks)) for b in range(len(blocks))]
        items = [{"label": "", "lines": 0, "known": 0} for _ in range(n)]
        for block, bucket in zip(blocks, of_block):
            items[bucket]["lines"] += block[0]
            items[bucket]["known"] += block[1]
        start = 0
        for item in items:
            item["label"] = f"{start + 1:,}"
            start += item["lines"]
        mode = "position"
        by_date = lambda d: None

    def at(i: int, date=None) -> int:
        found = by_date(date) if date else None
        return found if found is not None else of_block[min(i // block_size, len(of_block) - 1)] if of_block else 0
    return mode, items, at


def _shape_rows(shapes: list[dict], at, buckets: int, prefix: str) -> list[dict]:
    rows = []
    for i, s in enumerate(shapes[:SHOWN]):
        first, last = at(s["first"], s["early"]), at(s["last"], s["late"])
        rows.append({"id": f"{prefix}{i}", "template": " ".join(s["tokens"]), "count": s["count"], "examples": s["examples"],
                     "first": first, "last": last, "new": buckets >= 4 and first >= int(buckets * NEW_SHARE)})
    return rows


def run_pass(ws: Workspace, actor: str, progress=lambda step, detail: None) -> dict:
    with ws.lock:
        return _pass(ws, actor, progress)


class _Tally:
    """What one pass counts as it reads."""

    def __init__(self, layout: dict | None = None):
        self.counts = {"builtin": 0, "custom": 0, "sliced": 0, "unknown": 0}
        self.layout = layout
        self.field_names = layout["fields"] if layout else []
        self.time_at = self.field_names.index(layout["time"]) if layout and layout["time"] else None
        self.values: list[dict] = [{} for _ in self.field_names]     # per field: value -> [lines, known]
        self.many: set = set()                          # fields with too many values to count
        self.hits: dict = defaultdict(int)
        self.last_hit: dict = {}                       # rule -> (last line, latest date)
        self.lines, self.heads, self.tails = {}, {}, {}
        self.small = 0                                 # unknown lines past MAX_TEMPLATES shapes
        self.unknown_keep: list = []
        self.known_keep: list = []
        self.blocks: list[list] = []                   # [lines, known, first date, undated, undated known] per `block` lines
        self.days: dict = {}                           # date -> [lines, known]
        self.block = 10
        self.rng = random.Random(7)

    def count_fields(self, values: tuple, known: int) -> None:
        for j, value in enumerate(values):
            if j == self.time_at or j in self.many:
                continue
            table = self.values[j]
            entry = table.get(value[:80])
            if entry is None:
                if len(table) >= FIELD_VALUES:
                    self.many.add(j)
                    table.clear()
                    continue
                table[value[:80]] = entry = [0, 0]
            entry[0] += 1
            entry[1] += known

    def field_rows(self) -> list[dict]:
        """Each field but the time: its values, most lines first, with how many lines of each are known."""
        out = []
        for j, name in enumerate(self.field_names):
            if j == self.time_at:
                continue
            values = sorted(self.values[j].items(), key=lambda kv: -kv[1][0])
            out.append({"name": name, "role": "host" if name == self.layout["host"] else "", "many": j in self.many,
                        "distinct": len(values), "values": [{"value": v, "lines": a, "known": b} for v, (a, b) in values[:FIELD_SHOWN]]})
        out.sort(key=lambda f: (f["role"] != "host", f["many"], not 1 < f["distinct"] <= FIELD_SHOWN, f["distinct"]))
        return out

    def block_for(self, i: int, line: str, values=None) -> list:
        if i // self.block == len(self.blocks):
            if len(self.blocks) >= BLOCKS:                 # pairs merged: the block size doubles
                self.blocks = [[a[0] + b[0], a[1] + b[1], a[2] or b[2], a[3] + b[3], a[4] + b[4]]
                               for a, b in zip(self.blocks[::2], self.blocks[1::2])]
                self.block *= 2
            if i // self.block == len(self.blocks):
                self.blocks.append([0, 0, None, 0, 0])
        block = self.blocks[-1]
        block[0] += 1
        return block

    def date_for(self, line: str, values=None):
        """A line's day: from the table's time column when there is one, else from the line."""
        if values is not None and self.time_at is not None:
            return tabular.date_of(values[self.time_at]) or _date_key(line)
        return _date_key(line)

    def dated(self, block: list, date, known: int) -> None:
        if date:
            day = self.days.get(date)
            if day is None:
                self.days[date] = day = [0, 0]
                block[2] = block[2] or date
            elif block[2] is None:
                block[2] = date
            day[0] += 1
            day[1] += known
        else:
            block[3] += 1
            block[4] += known

    def known(self, i: int, line: str, by, block: list, values=None, date=None) -> None:
        self.counts["builtin" if by == "builtin" else "custom"] += 1
        block[1] += 1
        self.dated(block, date, 1)
        _reservoir(self.known_keep, KNOWN_KEEP, self.counts["builtin"] + self.counts["custom"], (i, line, by, values), self.rng)
        if values is not None:
            self.count_fields(values, 1)

    def hit(self, rid, i: int, date) -> None:
        self.hits[rid] += 1
        was = self.last_hit.get(rid)
        self.last_hit[rid] = (i, _latest(was[1], date) if was else date)

    def unknown(self, i: int, line: str, prefix, suffix, message: str, date, values=None, block=None) -> None:
        self.counts["sliced" if prefix is not None or suffix is not None else "unknown"] += 1
        self.dated(block, date, 0)
        _reservoir(self.unknown_keep, UNKNOWN_KEEP, self.counts["sliced"] + self.counts["unknown"], (i, line, values), self.rng)
        if values is not None:
            self.count_fields(values, 0)
        shape = mask(message) or "<empty>"
        if not _count(self.lines, shape, line, i, date):
            self.small += 1
        if prefix is None:                             # a head no prefix cuts yet: up to ": ", or three words
            text = line[:LINE_CAP]
            colon, raw_colon = shape.find(": ", 0, 120), text.find(": ")
            if colon > 0 and raw_colon > 0:
                _count(self.heads, shape[:colon + 1], text[:raw_colon + 2], i, date)
            elif found := HEAD_WORDS.match(text):
                _count(self.heads, mask(found.group()), found.group(), i, date)
        words = shape.rsplit(" ", 3)
        if len(words) >= 3:                            # a tail: the last word of a message of three or more
            _count(self.tails, words[-1], " " + message.rsplit(None, 1)[-1], i, date)


def _read(ws: Workspace, rules: RuleSet, known_bits: bytearray, reuse: bool, tally: _Tally, progress) -> tuple[int, bool]:
    builtin = ws.family in BUILTIN
    month = datetime.now().strftime("%Y-%m")
    stream = ws.records()
    index = 0
    try:
        while index < MAX_SCAN:
            chunk = list(islice(stream, min(20_000, MAX_SCAN - index)))
            if not chunk:
                return index, False
            if builtin and not reuse:
                known_bits.extend(_builtin_flags(ws.family, [line for line, _ in chunk], month))
            for line, values in chunk:
                i = index
                index += 1
                block = tally.block_for(i, line, values)
                date = tally.date_for(line, values)
                if builtin and known_bits[i]:
                    tally.known(i, line, "builtin", block, values, date)
                    continue
                start, end, prefix, suffix, rule, message = rules.read(line)
                for rid in (prefix, suffix, rule):
                    if rid is not None:
                        tally.hit(rid, i, date)
                if rule is not None:
                    tally.known(i, line, rule, block, values, date)
                else:
                    tally.unknown(i, line, prefix, suffix, message, date, values, block)
            if index // 200_000 != (index - len(chunk)) // 200_000:
                progress("read", f"{index:,} lines")
        return index, next(stream, None) is not None
    finally:
        getattr(stream, "close", lambda: None)()


def _pass(ws: Workspace, actor: str, progress) -> dict:
    started = time.time()
    rules = ruleset(ws.family)
    builtin = ws.family in BUILTIN
    signature = _signature(Path(ws.path)) if ws.path else len(ws.lines)
    reuse = ws.builtin_known is not None and ws.signature == signature
    known_bits = ws.builtin_known if reuse else bytearray()
    tally = _Tally(ws.layout)
    progress("read", "Reading")
    index, truncated = _read(ws, rules, known_bits, reuse, tally, progress)
    if not index:
        raise ValueError("No log lines in the input.")
    progress("shapes", "Shapes")
    mode, buckets, at = _buckets(tally.blocks, tally.block, tally.days)
    shapes, left = merge(tally.lines)
    heads, _ = merge(tally.heads)
    tails, _ = merge(tally.tails)
    counts = tally.counts

    ws.builtin_known, ws.signature = (known_bits if builtin else None), signature
    ws.unknown_keep, ws.known_keep, ws.shapes = tally.unknown_keep, tally.known_keep, shapes[:SHOWN]
    ws.passes += 1
    with store._lock, _connect() as con:
        n_rules = con.execute("SELECT COUNT(*) FROM pattern_rules WHERE family=? AND enabled=1", (ws.family,)).fetchone()[0]
        con.execute("INSERT INTO pattern_passes (family, dataset, workspace, at, actor, lines, builtin, custom, sliced, rules) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)", (ws.family, ws.name, ws.id, store.now(), actor, index, counts["builtin"],
                                                   counts["custom"], counts["sliced"], n_rules))
        # this scan's passes, and earlier ones of the same file or folder and log type (pasted lines have no name to match)
        if ws.layout and ws.family:                    # the log type comes as this table
            con.execute("INSERT OR REPLACE INTO pattern_layouts VALUES (?,?,?)", (ws.family, json.dumps(public_layout(ws.layout)), store.now()))
        history = [dict(r) for r in con.execute(
            "SELECT at, lines, builtin, custom, rules FROM pattern_passes WHERE workspace=? OR (? AND family=? AND family != '' AND dataset=?) "
            "ORDER BY id DESC LIMIT 12", (ws.id, ws.name != PASTED, ws.family, ws.name))][::-1]
    late = len(buckets) >= 4
    ws.result = {
        "workspace": ws.id, "name": ws.name, "family": ws.family, "builtin": builtin, "pass": ws.passes,
        "lines": index, "truncated": truncated, "seconds": round(time.time() - started, 1),
        "counts": counts, "coverage": (counts["builtin"] + counts["custom"]) / index,
        "time": {"mode": mode, "buckets": buckets, "field": ws.layout["time"] if ws.layout else ""},
        "layout": public_layout(ws.layout), "fields": tally.field_rows(),
        "hits": {str(k): {"hits": v, "last": at(*tally.last_hit[k]),
                          "quiet": late and at(*tally.last_hit[k]) < int(len(buckets) * NEW_SHARE)}
                 for k, v in tally.hits.items()},
        "slow": [str(r) for r in rules.slow],
        "shapes": _shape_rows(shapes, at, len(buckets), "s"), "small": left + tally.small,
        "heads": _shape_rows(heads, at, len(buckets), "h"), "tails": _shape_rows(tails, at, len(buckets), "t"),
        "history": [{"at": h["at"], "lines": h["lines"], "rules": h["rules"],
                     "coverage": (h["builtin"] + h["custom"]) / h["lines"] if h["lines"] else 0} for h in history],
    }
    return ws.result


def _find_layout(path: Path, raw: str = "", files: int = 50) -> dict | None:
    """The table layout of the first of a path's files (up to ``files``) that is a table; None when none is."""
    streams = _streams(path)
    try:
        for _, stream in islice(streams, files):
            lines = _decoded(stream)
            head = [line.rstrip("\r\n") for line in islice(lines, tabular.SAMPLE + 1)]
            lines.close()
            layout = tabular.sniff(head, raw=raw, recognise=analyze.recognised)
            if layout:
                return layout
        return None
    finally:
        streams.close()                                # the file left open by the generator, closed now


def _first_rows(text: str = "", path: str = "", name: str = ""):
    """The first rows of a table (the header first) with its format, separator and header line, from pasted or
    uploaded text or the first file under a path; None when the input is not a table."""
    if path:
        where = Path(path.strip().strip('"'))
        if not where.exists():
            raise ValueError(f"Nothing at {where}.")
        streams = _streams(where)
        try:
            first = next(streams, None)
            if first is None:
                raise ValueError(f"No file at {where}.")
            name, raw = first
            if name.lower().endswith(".xls"):
                raise ValueError("An older .xls workbook: save it as .xlsx or .csv.")
            if name.lower().endswith(".xlsx"):
                rows = list(islice(tabular.xlsx_rows(io.BytesIO(tabular.capped(raw))), tabular.PREVIEW_ROWS + 1))
                return (rows, "Excel", "", "") if rows else None
            reader = _decoded(raw)
            lines = list(islice(reader, 2000))
            reader.close()
        finally:
            streams.close()
    else:
        lines = text.splitlines(keepends=True)[:2000]
    plain = [line.rstrip("\r\n") for line in lines if line.strip()]
    delimiter = tabular.delimiter_of(plain[:tabular.PREVIEW_ROWS + 1], name)
    if delimiter is None:
        if not tabular.is_table_file(name) or not plain:
            return None
        delimiter = "\t" if name.lower().endswith(".tsv") else ","   # a table file whose header is not one: say so
    rows = list(islice((r for r in csv.reader(lines, delimiter=delimiter) if r), tabular.PREVIEW_ROWS + 1))
    fmt = "Excel" if name.lower().endswith(".xlsx") else {",": "CSV", "\t": "TSV"}.get(delimiter, "Table")   # an uploaded workbook arrives as CSV text
    return rows, fmt, delimiter, plain[0]


def preview(text: str = "", path: str = "", name: str = "") -> dict:
    """Before a scan: is the input a table, and a well-formed one (its first 100 rows)? Its columns with a sample
    value each, and the raw-log column when it is clear. ``{"table": False}`` for plain logs."""
    found = _first_rows(text, path, name)
    if found is None:
        return {"table": False}
    rows, fmt, delimiter, header = found
    return tabular.check(rows, fmt, delimiter, header, recognise=analyze.recognised)


def public_layout(layout: dict | None) -> dict | None:
    return {k: layout[k] for k in ("format", "columns", "raw", "time", "host")} if layout else None


def scan(text: str = "", path: str = "", family: str = "auto", new_family: str = "", name: str = "", raw: str = "",
         fields: list[str] | None = None, actor: str = "", progress=lambda step, detail: None) -> dict:
    """Read new lines, tell their log type (or take the one given), and run the first pass. A table is read by
    the raw-log column chosen (``raw``) keeping the columns chosen (``fields``; all when None); without a choice,
    a table is read as Analyze reads it."""
    progress("read", "Reading")
    lines = where = layout = None
    if raw:
        found = _first_rows(text, path, name)
        if found is None:
            raise ValueError("Not a table: the first row is not a header of column names.")
        rows, fmt, delimiter, header = found
        problem = tabular.check(rows, fmt, delimiter, header)["problem"]
        if problem:
            raise ValueError(problem)
        layout = tabular.layout(fmt, delimiter, header, tabular.names_of(rows[0]), raw, fields, rows[1:])
    if path:
        where = Path(path.strip().strip('"'))
        if not where.exists():
            raise ValueError(f"Nothing at {where}.")
        layout = layout or _find_layout(where)
        if layout:
            reader = open_records(where, layout)
            head = [line for line, _ in islice(reader, SAMPLE)]
        else:
            reader = open_lines(where)
            head = list(islice(reader, SAMPLE))
        reader.close()
    else:
        lines = [line.rstrip("\r") for line in text.splitlines() if line.strip()]
        layout = layout or tabular.sniff(lines[:SAMPLE + 1], recognise=analyze.recognised)
        if layout:
            lines = list(tabular.text_records(text, layout))
        if len(lines) > analyze.MAX_LINES:
            raise ValueError(f"At most {analyze.MAX_LINES:,} pasted lines ({len(lines):,} given): use a file on this laptop.")
        head = [line for line, _ in lines[:SAMPLE]] if layout else lines[:SAMPLE]
    if not head:
        raise ValueError("No log lines in the input.")
    if new_family:
        family = create_family(new_family, actor)
    elif family in ("", "auto"):
        family = detect(head)["family"] or ""
    elif not _known_family(family):
        raise ValueError(f"Unknown log type {family!r}.")
    ws = Workspace(name or (where.name if where else PASTED), family, lines, str(where) if where else None, layout)
    _keep(ws)
    return run_pass(ws, actor, progress)


def rescan(workspace_id: str, actor: str = "", progress=lambda step, detail: None) -> dict:
    return run_pass(workspace(workspace_id), actor, progress)


def set_family(workspace_id: str, family: str) -> None:
    if not _known_family(family):
        raise ValueError(f"Unknown log type {family!r}.")
    ws = workspace(workspace_id)
    if ws.family != family:
        ws.family, ws.builtin_known = family, None


# --- what is known: the detector -------------------------------------------------------------------

def detect(lines: list[str], month: str = "", raw: str = "", name: str = "") -> dict:
    """The log type of a sample: by Phase 1's rules (what Analyze can read), and with the rules made here.
    ``negligible`` is True when Phase 1 knows next to none of the lines. A table (the header first) is read by
    its raw-line column; ``host`` is its host column's value when the sample has one only."""
    month = month or datetime.now().strftime("%Y-%m")
    layout = tabular.sniff(lines[:SAMPLE + 1], raw=raw, recognise=analyze.recognised)
    if layout and name.lower().endswith(".xlsx"):          # an uploaded workbook arrives as CSV text
        layout["format"] = "Excel"
    host = when = ""
    if layout:
        rows = list(tabular.text_records("\n".join(lines), layout))
        lines = [line for line, _ in rows]
        if layout["host"]:
            hosts = {values[layout["fields"].index(layout["host"])].strip() for _, values in rows[:SAMPLE]}
            host = hosts.pop() if len(hosts) == 1 else ""
        if layout["time"]:                             # the month of the first dated row (syslog lines carry no year)
            at = layout["fields"].index(layout["time"])
            when = next((day[:7] for _, values in rows[:SAMPLE] if len(day := tabular.date_of(values[at]) or "") == 10), "")
    sample = lines[:SAMPLE]
    n = len(sample) or 1
    phase1, combined = {}, {}
    for f in families():
        family = f["name"]
        flags = _builtin_flags(family, sample, month) if family in BUILTIN else [False] * len(sample)
        phase1[family] = sum(flags) if family in BUILTIN else 0
        extra = ruleset(family) if sum(f["rules"].values()) else None
        combined[family] = sum(ok or bool(extra and extra.read(line)[4] is not None) for line, ok in zip(sample, flags))
    source = max(BUILTIN, key=lambda s: phase1[s])
    best = max(combined, key=combined.get)
    coverage = phase1[source] / n
    return {"source": source if phase1[source] else None, "recognised": {s: phase1[s] for s in BUILTIN},
            "lines": len(sample), "coverage": coverage, "negligible": coverage < NEGLIGIBLE,
            "family": best if combined[best] else None, "family_coverage": combined[best] / n,
            "layout": public_layout(layout), "host": host, "month": when}


# --- the canvas: kept lines, cut with the rules as they are now --------------------------------------

def lines_view(workspace_id: str, show: str = "unknown", shape: str = "", search: str = "", limit: int = 150,
               field: str = "", value=None) -> dict:
    ws = workspace(workspace_id)
    rules = ruleset(ws.family)
    picked = next((s for i, s in enumerate(ws.shapes) if f"s{i}" == shape), None) if shape else None
    template = picked["tokens"] if picked else None
    names = ws.layout["fields"] if ws.layout else []
    at = names.index(field) if field in names and value is not None else None
    pool = []
    if show in ("unknown", "all"):
        pool += [(i, line, None, values) for i, line, values in ws.unknown_keep]
    if show in ("known", "all"):
        pool += ws.known_keep
    pool.sort(key=lambda x: x[0])
    if picked:                                         # a shape's own examples first: they may not be among the kept lines
        kept = {line for _, line, _, _ in pool}
        pool = [(-1, e, None, None) for e in picked["examples"] if e not in kept] + pool
    needle = search.strip().lower()
    rows, still_unknown, kept_unknown = [], 0, 0
    for i, line, was, values in pool:
        start, end, prefix, suffix, rule, message = rules.read(line) if was != "builtin" else (0, 0, None, None, None, "")
        known = was == "builtin" or rule is not None
        if was is None and i >= 0:                     # the kept sample only (not a shape's examples)
            kept_unknown += 1
            still_unknown += not known
        if show == "unknown" and known:
            continue
        if needle and needle not in line.lower() and not (values and any(needle in v.lower() for v in values)):
            continue
        if at is not None and (values is None or values[at][:80] != str(value)):
            continue
        # shapes were cut as the rules stood at the last pass: a prefix saved since leaves the whole line to compare
        if template is not None and not (fits(template, mask(message).split(" ")) or fits(template, mask(line[:LINE_CAP].strip()).split(" "))):
            continue
        if len(rows) < limit:
            rows.append({"i": i, "line": line, "cut": [start, end] if was != "builtin" else None,
                         "prefix": str(prefix) if prefix is not None else None, "suffix": str(suffix) if suffix is not None else None,
                         "rule": "builtin" if was == "builtin" else (str(rule) if rule is not None else None),
                         "event_type": rules.events.get(rule, "") if was != "builtin" else "", "known": known,
                         "fields": {n: v[:200] for n, v in zip(names, values)} if values else None})
    covered = []
    for n, s in enumerate(ws.shapes):
        if s["examples"] and all(rules.read(e)[4] is not None for e in s["examples"]):
            covered.append(f"s{n}")
    estimate = None
    if ws.result and kept_unknown:
        c = ws.result["counts"]
        open_lines_ = c["sliced"] + c["unknown"]
        estimate = (c["builtin"] + c["custom"] + open_lines_ * (1 - still_unknown / kept_unknown)) / ws.result["lines"]
    return {"lines": rows, "covered": covered, "estimate": estimate, "family": ws.family}


# --- suggesting a regex from examples ---------------------------------------------------------------

TOKEN = re.compile(
    rf"(?P<time>{ISO_TIME}|{SYSLOG_TIME}|\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?)"
    r"|(?P<ip>\d{1,3}(?:\.\d{1,3}){3}(?![\d.]))"
    r"|(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
    r"|(?P<hex>0x[0-9A-Fa-f]+)"
    r"|(?P<num>\d+(?:\.\d+)?)"
    r"|(?P<word>[A-Za-z_][\w-]*)"
    r"|(?P<space>\s+)"
    r"|(?P<punct>.)", re.S)
CLASS = {"ip": r"\d{1,3}(?:\.\d{1,3}){3}", "mac": r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", "hex": r"0x[0-9A-Fa-f]+",
         "word": r"[\w-]+", "punct": r"\S", "space": r"\s+"}
TYPED = ("time", "ip", "mac", "hex", "num")
SPECIAL = re.compile(r"([.^$*+?{}\[\]\\|()])")
SOURCE_WORDS = {"from", "src", "source", "client", "rhost"}
TARGET_WORDS = {"to", "dst", "destination", "server", "dest"}
USER_WORDS = {"user", "for", "by", "account", "login", "username", "ruser"}


def _escape(text: str) -> str:
    return SPECIAL.sub(r"\\\1", text)


def tokens(text: str) -> list[tuple[str, str]]:
    return [(found.lastgroup, found.group()) for found in TOKEN.finditer(text)]


def _time_class(samples: list[str]) -> str:
    def one(sample: str) -> str:
        if sample[:1].isalpha():
            return r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
        out, after_dot = [], False
        for found in re.finditer(r"(\d+)|(\s+)|(.)", sample):
            if found.group(1):
                out.append(r"\d+" if after_dot else rf"\d{{{len(found.group(1))}}}")
            elif found.group(2):
                out.append(r"\s+")
            else:
                out.append(_escape(found.group(3)))
            after_dot = found.group(3) in (".", ",")
        return "".join(out)
    forms = list(dict.fromkeys(one(s) for s in samples))
    return forms[0] if len(forms) == 1 else "(?:" + "|".join(forms[:4]) + ")"


def _class(kind: str, texts: list[str]) -> str:
    if kind == "time":
        return _time_class(texts)
    if kind == "num":
        return r"\d+(?:\.\d+)?" if any("." in t for t in texts) else r"\d+"
    return CLASS[kind]


class _Names:
    """Group names: the field names of Phase 1 where the words around say so (from <ip> -> source_ip), else by kind."""

    def __init__(self):
        self.used: dict[str, int] = {}
        self.seen: list[str] = []

    def __call__(self, kind: str, before: str, after: str, prefix: bool) -> str:
        before = before.lower()
        if kind == "time":
            base = "timestamp"
        elif kind == "ip":
            base = "source_ip" if before in SOURCE_WORDS else "destination_ip" if before in TARGET_WORDS else "ip"
        elif kind == "num":
            if before == "port":
                base = "source_port" if "source_ip" in self.seen else "destination_port" if "destination_ip" in self.seen else "port"
            elif before in ("pid", "[") and prefix:
                base = "pid"
            else:
                base = "number"
        elif kind == "word":
            if before in USER_WORDS:
                base = "username"
            elif prefix and self.seen[-1:] == ["timestamp"]:
                base = "hostname"
            elif prefix and after in ("[", ":"):
                base = "process_name"
            else:
                base = "word"
        else:
            base = {"hex": "hex", "mac": "mac"}.get(kind, "value")
        self.seen.append(base)
        self.used[base] = self.used.get(base, 0) + 1
        return base if self.used[base] == 1 else f"{base}_{self.used[base]}"


def _word_before(seq: list[tuple[str, str]], j: int) -> str:
    """The nearest word before position j (punctuation right before counts, as in process[pid])."""
    k = j - 1
    while k >= 0 and seq[k][0] == "space":
        k -= 1
    if k >= 0 and seq[k][0] == "punct" and seq[k][1] == "[":
        return "["
    while k >= 0 and seq[k][0] != "word":
        k -= 1
    return seq[k][1] if k >= 0 else ""


def _exact(examples: list[list[tuple[str, str]]], prefix: bool) -> str | None:
    """Every example the same sequence of kinds: what is the same stays, what differs becomes a class."""
    kinds = [k for k, _ in examples[0]]
    if any([k for k, _ in e] != kinds for e in examples[1:]):
        return None
    names, out = _Names(), []
    few = len(examples) < 3
    for j, kind in enumerate(kinds):
        texts = [e[j][1] for e in examples]
        if kind == "space":
            out.append(r"\s+")
        elif len(set(texts)) == 1 and not (kind in TYPED and few):
            out.append(_escape(texts[0]))
        else:
            after = examples[0][j + 1][1] if j + 1 < len(kinds) else ""
            name = names(kind, _word_before(examples[0], j), after, prefix)
            out.append(f"(?P<{name}>{_class(kind, texts)})")
    return "".join(out)


def _field_kind(field: str) -> str | None:
    seq = tokens(field)
    return seq[0][0] if len(seq) == 1 else None


def _fields(examples: list[str], prefix: bool) -> str | None:
    """The same number of space-separated fields: the same ones stay, the others become \\S+."""
    split = [e.split() for e in examples]
    if any(len(s) != len(split[0]) for s in split[1:]):
        return None
    names, out = _Names(), []
    few = len(examples) < 3
    for j in range(len(split[0])):
        texts = [s[j] for s in split]
        kinds = {_field_kind(t) for t in texts}
        kind = kinds.pop() if len(kinds) == 1 else None
        if len(set(texts)) == 1 and not (kind in TYPED and few):
            out.append(_escape(texts[0]))
        else:
            before = split[0][j - 1].strip(":=,").lower() if j else ""
            name = names(kind or "value", before, split[0][j + 1] if j + 1 < len(split[0]) else "", prefix)
            out.append(f"(?P<{name}>{_class(kind, texts) if kind in TYPED else r'\S+'})")
    return r"\s+".join(out)


def _lcs(a: list[str], b: list[str]) -> list[str]:
    table = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        for j in range(len(b) - 1, -1, -1):
            table[i][j] = table[i + 1][j + 1] + 1 if a[i] == b[j] else max(table[i + 1][j], table[i][j + 1])
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            out.append(a[i]); i += 1; j += 1
        elif table[i + 1][j] >= table[i][j + 1]:
            i += 1
        else:
            j += 1
    return out


def _anchors(examples: list[str]) -> tuple[str | None, list[str]]:
    """The fields every example shares, in order, with what lies between them left open."""
    split = [e.split()[:80] for e in examples]
    common = split[0]
    for s in split[1:]:
        common = _lcs(common, s)
    if not common:
        return None, []
    gaps = [[0] * (len(common) + 1) for _ in split]          # fields before each anchor, and after the last
    for e, s in enumerate(split):
        k = 0
        for field in s:
            if k < len(common) and field == common[k]:
                k += 1
            else:
                gaps[e][k] += 1
    names, out = _Names(), []
    for k in range(len(common) + 1):
        sizes = [g[k] for g in gaps]
        lo, hi = min(sizes), max(sizes)
        first, last = k == 0, k == len(common)
        if hi == 0:
            gap = "" if first or last else r"\s+"
        elif lo == hi == 1:
            name = names("value", common[k - 1] if k else "", "", False)
            gap = (f"(?P<{name}>\\S+)\\s+" if first else f"\\s+(?P<{name}>\\S+)" if last else f"\\s+(?P<{name}>\\S+)\\s+")
        elif lo >= 1:
            gap = r".+?\s+" if first else r"\s+.+" if last else r"\s+.+?\s+"
        else:
            gap = r"(?:.*?\s+)?" if first else r"(?:\s+.*)?" if last else r"\s+(?:.*?\s+)?"
        out.append(gap)
        if k < len(common):
            out.append(_escape(common[k]))
    return "".join(out), common


def _start(examples: list[str]) -> str | None:
    """The fields every example starts with, then anything."""
    split = [e.split() for e in examples]
    lead = []
    for column in zip(*split):
        if len(set(column)) > 1 or _field_kind(column[0]) in TYPED:
            break
        lead.append(column[0])
    if not lead or len(lead) == min(len(s) for s in split):
        return None
    return r"\s+".join(map(re.escape, lead)) + r"(?:\s+(?P<rest>.*))?"


def _event_name(family: str, words: list[str]) -> str:
    head = EVENT_PREFIX.get(family, f"{re.sub(r'[^A-Z0-9]+', '_', family.upper()).strip('_')}_" if family else "")
    picked = [w.upper() for w in (re.sub(r"[^A-Za-z0-9]+", " ", " ".join(words)).split()) if w.isalpha()][:3]
    name = re.sub(r"_+", "_", head + "_".join(picked)).strip("_") or "NEW_EVENT"
    return name if name[0].isalpha() else f"E_{name}"


def suggest(kind: str, examples: list[str], family: str = "", workspace_id: str = "") -> dict:
    """Regex candidates that cover the examples, from close to loose, each tried on the examples and on the
    kept unknown lines (``lines``: an estimate over the whole dataset)."""
    if kind not in KINDS:
        raise ValueError(f"Unknown kind {kind!r}.")
    raw = [_as_example(kind, str(e)) for e in examples if str(e).strip()][:40]
    if not raw:
        return {"candidates": [], "event_type": ""}
    clean = [e.strip() for e in raw]
    prefix = kind == "prefix"
    seqs = [tokens(e) for e in clean]
    found: dict[str, str] = {}
    for label, body in (("Exact", _exact(seqs, prefix)), ("Fields", _fields(clean, prefix)),
                        ("Anchors", _anchors(clean)[0] if len({len(e.split()) for e in clean}) > 1 else None), ("Start", _start(clean) if kind == "rule" else None)):
        if not body:
            continue
        pattern = body + r"\s*" if prefix else r"\s+" + body if kind == "suffix" else body
        if pattern not in found.values():
            found[label] = pattern
    out = []
    for label, pattern in found.items():
        try:
            tried = test(kind, pattern, raw, workspace_id)
        except (KeyError, ValueError):
            continue
        if tried["ok"]:
            out.append({"label": label, "regex": pattern, "covers": sum(e["match"] for e in tried["examples"]),
                        "of": len(raw), "lines": tried.get("lines")})
    return {"candidates": out, "event_type": _event_name(family, _leading(clean)) if kind == "rule" else ""}


def _leading(examples: list[str]) -> list[str]:
    """The words every example starts with (else the fields they share): what names the event."""
    lead = []
    for column in zip(*(e.split() for e in examples)):
        if len(set(column)) > 1 or _field_kind(column[0]) in TYPED:
            break
        lead.append(column[0])
    return lead or [w for w in (_anchors(examples)[1] if len(examples) > 1 else examples[0].split()) if _field_kind(w) not in TYPED]


# --- trying a regex -----------------------------------------------------------------------------------

def _as_example(kind: str, text: str) -> str:
    """A suffix is cut where a space starts it: an example without one gets one."""
    text = text[:LINE_CAP]
    return " " + text.lstrip() if kind == "suffix" else text


def _spans(found) -> list[dict]:
    return [{"name": name, "start": found.start(name), "end": found.end(name)}
            for name in found.re.groupindex if found.start(name) >= 0]


def test(kind: str, regex: str, examples: list[str], workspace_id: str = "") -> dict:
    """Where the regex matches each example (with its groups), and how many unknown lines it would take."""
    try:
        compiled = _compile(regex, kind)
    except ValueError as error:
        return {"ok": False, "error": str(error)}
    method = {"prefix": "match", "suffix": "search", "rule": "fullmatch"}[kind]
    out = []
    try:
        for example in examples[:40]:
            text = _as_example(kind, str(example))
            lead = len(text) - len(text.lstrip()) if kind == "rule" else 0
            target = text.strip() if kind == "rule" else text
            found = _run(getattr(compiled, method), target)
            out.append({"text": text, "match": bool(found),
                        "span": [found.start() + lead, found.end() + lead] if found else None,
                        "groups": [{**g, "start": g["start"] + lead, "end": g["end"] + lead} for g in _spans(found)] if found else []})
        result = {"ok": True, "examples": out}
        if workspace_id:
            result.update(_estimate(kind, compiled, workspace(workspace_id)))
    except TimeoutError:
        return {"ok": False, "error": "Too slow on some lines: make the pattern more specific."}
    return result


def _estimate(kind: str, compiled, ws: Workspace) -> dict:
    """The share of kept unknown lines the regex takes (as the next pass would use it), scaled to the dataset."""
    if not ws.result or not ws.unknown_keep:
        return {"lines": 0, "tried": 0}
    rules = ruleset(ws.family)
    pool = ws.unknown_keep[:TRY_LINES]
    taken = 0
    for _, line, _ in pool:
        start, end, prefix, suffix, rule, message = rules.read(line)
        if rule is not None:
            continue
        text = line[:LINE_CAP]
        if kind == "prefix":
            found = _run(compiled.match, text) if prefix is None else None
            taken += bool(found and 0 < found.end() < len(text))
        elif kind == "suffix":
            rest = text[start:]
            found = _run(compiled.search, rest) if suffix is None else None
            taken += bool(found and found.start() > 0)
        else:
            taken += bool(message and _run(compiled.fullmatch, message))
    c = ws.result["counts"]
    open_lines_ = c["sliced"] + c["unknown"]
    return {"lines": round(open_lines_ * taken / len(pool)), "tried": len(pool), "taken": taken}
