"""Sigma: detection rules in the Sigma format, run over logs that Phase 1 can read (Advanced → Sigma).

A **rule** matches single events: named selections of field tests, combined by its condition. A
**correlation** looks across events in a sliding window per group (its ``group-by`` fields):
``event_count`` (at least N matching events), ``value_count`` (at least N distinct values of a field) and
``temporal`` / ``temporal_ordered`` (all the referenced rules within the window, in order for the second).
A correlation may refer to rules or to other correlations, by ``name`` or ``id``. The older aggregation
``selection | count(field) by group > N`` with ``timeframe`` is read as a correlation over the rule itself.

Rules are kept on this laptop in the console's store and run on demand on pasted lines, an upload or a
file read here (the same input as Analyze), or a folder read here: every file of its lowest folders, each told
its log type by its first lines and its month by its folders, the files of one log type and month checked
together (run_folder). They are also a detector beside the models: the enabled rules
run over every Analyze input and upload, and over the year's validation and test periods (sigma_review.py),
and a hit flags the observations that hold its lines, for Review. They change no model's score. Rules
referred to by a correlation report nothing themselves unless the correlation says ``generate: true``, as
in the Sigma specification.

Fields are Phase 1's names (``username``, ``source_ip``, ``event_type``, ...); common Sigma and ECS names
are mapped to them (ALIASES). ``logsource`` picks the log type (SERVICES, PRODUCTS, CATEGORIES); a rule
for a log type the console does not read (Windows, cloud) applies to nothing. Supported: the modifiers in
MODIFIERS, the wildcards ``*`` and ``?``, keyword lists, and conditions with ``and``, ``or``, ``not``,
parentheses, ``1 of`` / ``all of`` (``them`` or a name with ``*``). A hit whose events name only
whitelisted accounts is marked whitelisted (whitelist.py), as elsewhere in the console.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import zipfile
import zlib
from bisect import bisect_left
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import islice
from pathlib import Path

import yaml

try:
    import regex as _regex                    # a time limit per match (as Patterns), so a rule cannot hang the console
except ImportError:                           # pragma: no cover - the pipeline's environment has it
    _regex = None

from . import analyze, patterns, store, tabular, whitelist
from .pipeline_code import module

STARTER = Path(__file__).with_name("sigma_rules")
MAX_TEXT = 200_000                            # characters of YAML in one saved entry
MAX_LINES_PER_HIT = 40
REGEX_SECONDS = 0.05
LEVELS = ("informational", "low", "medium", "high", "critical")
MAX_SPAN = timedelta(days=400)
MAX_TESTED = 1000
_tested: set[str] = set()                     # digests of drafts a test ran to the end on (add and update log whether)
SCHEMA = """
CREATE TABLE IF NOT EXISTS sigma_rules (
    id INTEGER PRIMARY KEY, yaml TEXT, enabled INTEGER, added_by TEXT, added_at TEXT, updated_by TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS sigma_meta (key TEXT PRIMARY KEY, value TEXT);
"""

# Common Sigma, ECS and Windows-style names for the fields Phase 1 gives (lower case).
ALIASES = {
    "user": "username", "pam_user": "username", "targetusername": "username", "user.name": "username",
    "target_user": "target_username", "targetuser": "target_username",
    "src_ip": "source_ip", "srcip": "source_ip", "sourceip": "source_ip", "source.ip": "source_ip", "src": "source_ip",
    "pam_rhost": "source_ip", "rhost": "source_ip", "ipaddress": "source_ip", "client_ip": "source_ip",
    "src_port": "source_port", "sourceport": "source_port", "source.port": "source_port",
    "dst_ip": "destination_ip", "dstip": "destination_ip", "destinationip": "destination_ip", "destination.ip": "destination_ip", "dst": "destination_ip",
    "dst_port": "destination_port", "dstport": "destination_port", "destinationport": "destination_port", "destination.port": "destination_port",
    "hostname": "host", "computername": "host", "computer": "host", "host.name": "host",
    "process": "process_name", "process.name": "process_name", "processname": "process_name", "program": "process_name",
    "message": "raw_message", "msg": "raw_message",
    "eventtype": "event_type", "event.type": "event_type",
    "proto": "protocol", "network.transport": "protocol",
}
LINE_FIELDS = {"line", "raw", "_raw", "log"}      # the whole original line
# Phase 1's fields per log type (the editor offers them; a rule may use others that a line has)
FIELDS = {
    "auth": ["event_type", "host", "process_name", "username", "target_username", "invalid_user_indicator", "source_ip",
             "source_port", "authentication_method", "connection_stage", "terminal_path", "failure_count", "reason", "raw_message"],
    "ossec": ["event_type", "host", "raw_message"],
    "pf": ["event_type", "host", "action", "direction", "interface", "protocol", "source_ip", "source_port",
           "destination_ip", "destination_port", "tcp_flags", "rule_number", "packet_length"],
    "ipf": ["event_type", "host", "action", "direction", "interface", "protocol", "source_ip", "source_port",
            "destination_ip", "destination_port", "rule_number", "packet_length", "is_broadcast"],
}
# logsource → (log types, process) : a service names one daemon's lines
SERVICES = {
    "sshd": ({"auth"}, "sshd"), "ssh": ({"auth"}, "sshd"), "su": ({"auth"}, "su"), "sudo": ({"auth"}, "sudo"),
    "cron": ({"auth"}, "cron"), "login": ({"auth"}, "login"), "gdm": ({"auth"}, None),
    "auth": ({"auth"}, None), "authlog": ({"auth"}, None), "syslog": ({"auth"}, None), "pam": ({"auth"}, None),
    "ossec": ({"ossec"}, None), "wazuh": ({"ossec"}, None),
    "pf": ({"pf"}, None), "pflog": ({"pf"}, None), "ipfilter": ({"ipf"}, None), "ipf": ({"ipf"}, None), "ipmon": ({"ipf"}, None),
}
PRODUCTS = {"solaris": {"auth"}, "linux": {"auth"}, "unix": {"auth"}, "ossec": {"ossec"}, "wazuh": {"ossec"},
            "pf": {"pf"}, "openbsd": {"pf"}, "ipfilter": {"ipf"}, "dad": {"auth", "ossec", "pf", "ipf"}}
CATEGORIES = {"firewall": {"pf", "ipf"}, "network_connection": {"pf", "ipf"}, "authentication": {"auth"}}
MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "gt", "gte", "lt", "lte",
             "exists", "cased"}
COMPARE = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b, "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b}
WINDOW_OPS = {"gt": lambda n, k: n > k, "gte": lambda n, k: n >= k, "eq": lambda n, k: n == k}
KIND_LABEL = {"event": "Event", "event_count": "Count", "value_count": "Distinct", "temporal": "Together",
              "temporal_ordered": "Sequence"}


class SigmaError(ValueError):
    """A rule that cannot be read or run; the message says what to change."""


# --- values and field tests ------------------------------------------------------------------------

def _wildcard(value: str, cased: bool) -> re.Pattern:
    """Sigma's wildcards: * any run, ? one character, \\* and \\? themselves."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("".join(out), re.S if cased else re.S | re.I)


def _text(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _value_test(value, mods: set[str]):
    """One value of a field test, as a function of the event's value (a string, or None when absent)."""
    if "cidr" in mods:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            raise SigmaError(f"{value!r} is not an address range (|cidr).") from None

        def in_range(v):
            try:
                return v is not None and ipaddress.ip_address(str(v).strip()) in network
            except ValueError:
                return False
        return in_range
    for op in ("gt", "gte", "lt", "lte"):
        if op in mods:
            limit = _number(value)
            if limit is None:
                raise SigmaError(f"|{op} needs a number, not {value!r}.")
            return lambda v, op=op, limit=limit: _number(v) is not None and COMPARE[op](_number(v), limit)
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        try:
            compiled = (_regex or re).compile(str(value), flags)
        except Exception as error:                                   # re.error or regex.error
            raise SigmaError(f"Regular expression {value!r}: {error}") from None

        def search(v):
            if v is None:
                return False
            try:
                return bool(compiled.search(v, timeout=REGEX_SECONDS) if _regex else compiled.search(v))
            except TimeoutError:
                return False
        return search
    if value is None:
        return lambda v: v in (None, "")
    text = _text(value)
    if "contains" in mods:
        text = f"*{text}*"
    elif "startswith" in mods:
        text = f"{text}*"
    elif "endswith" in mods:
        text = f"*{text}"
    pattern = _wildcard(text, "cased" in mods)
    return lambda v: v is not None and pattern.fullmatch(v) is not None


@dataclass
class FieldTest:
    field: str | None                          # None: a keyword, searched in the whole line
    test: object                               # (event) -> bool

    def __call__(self, event) -> bool:
        return self.test(event)


def _lookup(event: "Event", name: str | None):
    if name is None or name.lower() in LINE_FIELDS:
        return event.line
    fields = event.fields
    key = ALIASES.get(name.lower(), name)
    if key in fields:
        value = fields[key]
    elif name in fields:
        value = fields[name]
    else:
        lowered = name.lower()
        value = next((v for k, v in fields.items() if k.lower() == lowered), None)
    return None if value is None else _text(value)


def _field_test(key: str, values, keyword: bool = False) -> FieldTest:
    parts = key.split("|")
    name = parts[0] or None
    mods = {m.strip().lower() for m in parts[1:] if m.strip()}
    unknown = sorted(mods - MODIFIERS)
    if unknown:
        raise SigmaError(f"Modifier |{unknown[0]} is not supported here ({key}).")
    values = values if isinstance(values, list) else [values]
    if not values:
        raise SigmaError(f"{key} has no values.")
    if name is None and not mods & {"contains", "startswith", "endswith", "re"}:
        mods.add("contains")                                         # keywords: anywhere in the line
    if "exists" in mods:
        want = values[0] is True or _text(values[0]).lower() == "true"
        return FieldTest(name, lambda e: (_lookup(e, name) not in (None, "")) == want)
    tests = [_value_test(v, mods) for v in values]
    if "all" in mods:
        return FieldTest(name, lambda e: all(t(_lookup(e, name)) for t in tests))
    return FieldTest(name, lambda e: any(t(_lookup(e, name)) for t in tests))


def _selection(name: str, body):
    """A named selection: a map (every field), a list of maps (any of them), or a list of keywords."""
    if isinstance(body, dict):
        if not body:
            raise SigmaError(f"Selection {name} is empty.")
        tests = [_field_test(str(k), v) for k, v in body.items()]
        return lambda e: all(t(e) for t in tests)
    if isinstance(body, list) and body:
        if all(isinstance(x, dict) for x in body):
            parts = [_selection(name, x) for x in body]
            return lambda e: any(p(e) for p in parts)
        if all(not isinstance(x, (dict, list)) for x in body):
            test = _field_test("", body)
            return lambda e: test(e)
        raise SigmaError(f"Selection {name} mixes maps and keywords.")
    if isinstance(body, (str, int, float)):
        test = _field_test("", [body])
        return lambda e: test(e)
    raise SigmaError(f"Selection {name} must be a map or a list.")


# --- conditions ---------------------------------------------------------------------------------

TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _Condition:
    """and, or, not, parentheses, '1 of x*', 'all of them'; names may use * as a wildcard."""

    def __init__(self, text: str, names: list[str]):
        self.tokens = TOKEN.findall(text)
        self.names = names
        self.at = 0
        if not self.tokens:
            raise SigmaError("The condition is empty.")
        self.tree = self._or()
        if self.at < len(self.tokens):
            raise SigmaError(f"Condition: unexpected {self.tokens[self.at]!r}.")

    def _peek(self) -> str:
        return self.tokens[self.at].lower() if self.at < len(self.tokens) else ""

    def _take(self) -> str:
        token = self.tokens[self.at]
        self.at += 1
        return token

    def _or(self):
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def _and(self):
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def _not(self):
        if self._peek() == "not":
            self._take()
            return ("not", self._not())
        return self._atom()

    def _matching(self, pattern: str) -> list[str]:
        if pattern.lower() == "them":
            found = [n for n in self.names if not n.startswith("_")]
        else:
            rx = _wildcard(pattern, cased=True)
            found = [n for n in self.names if rx.fullmatch(n)]
        if not found:
            raise SigmaError(f"Condition: no selection matches {pattern!r}.")
        return found

    def _atom(self):
        token = self._peek()
        if not token:
            raise SigmaError("The condition ends too early.")
        if token == "(":
            self._take()
            tree = self._or()
            if self._peek() != ")":
                raise SigmaError("Condition: a bracket is not closed.")
            self._take()
            return tree
        if token in ("1", "any", "all") and self.at + 1 < len(self.tokens) and self.tokens[self.at + 1].lower() == "of":
            self._take(), self._take()
            if self.at >= len(self.tokens):
                raise SigmaError(f"Condition: '{token} of' needs a name or 'them'.")
            names = self._matching(self._take())
            return ("and" if token == "all" else "or", names)
        name = self._take()
        if name not in self.names:
            raise SigmaError(f"Condition: no selection named {name!r}.")
        return name

    def evaluate(self, check) -> bool:
        def walk(node):
            if isinstance(node, str):
                return check(node)
            op, arg = node
            if op == "not":
                return not walk(arg)
            if op == "and":
                return all(walk(x) for x in arg)
            return any(walk(x) for x in arg)
        return walk(self.tree)


AGGREGATION = re.compile(r"^count\(\s*([\w.]*)\s*\)\s*(?:by\s+([\w.,\s]+?))?\s*(>=|>|==|=)\s*(\d+)$", re.I)


def _span(text) -> timedelta:
    found = re.fullmatch(r"\s*(\d+)\s*([smhdwMy])\s*", _text(text))
    if not found:
        raise SigmaError(f"A time span looks like 30s, 5m, 2h or 1d, not {text!r}.")
    n, unit = int(found.group(1)), found.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "M": 2592000, "y": 31536000}[unit]
    span = timedelta(seconds=n * seconds)
    if span <= timedelta(0) or span > MAX_SPAN:
        raise SigmaError(f"The time span {text!r} is outside 1 second to 400 days.")
    return span


def _threshold(condition, kind: str) -> tuple[list[tuple[str, int]], str | None]:
    if kind in ("temporal", "temporal_ordered"):
        return [], None
    if not isinstance(condition, dict) or not condition:
        raise SigmaError(f"A {kind} correlation needs a condition such as 'gte: 5'.")
    ops, value_field = [], condition.get("field")
    for key, value in condition.items():
        if key == "field":
            continue
        if key in ("lt", "lte"):
            raise SigmaError(f"'{key}' (fewer than) is not supported in a sliding window; use gt, gte or eq.")
        if key not in WINDOW_OPS:
            raise SigmaError(f"Unknown condition {key!r}; use gt, gte or eq.")
        number = _number(value)
        if number is None:
            raise SigmaError(f"The condition {key} needs a number.")
        ops.append((key, int(number)))
    if not ops:
        raise SigmaError("The condition needs gt, gte or eq.")
    if kind == "value_count" and not value_field:
        raise SigmaError("A value_count correlation names the field it counts (condition: field: ...).")
    return ops, str(value_field) if value_field else None


# --- documents -----------------------------------------------------------------------------------

@dataclass
class Doc:
    entry: int
    index: int
    title: str
    name: str
    id: str
    level: str
    status: str
    description: str
    tags: list[str]
    kind: str                                     # event, event_count, value_count, temporal, temporal_ordered
    sources: set[str] = field(default_factory=set)
    process: str | None = None
    selections: dict = field(default_factory=dict)
    condition: _Condition | None = None
    refs: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    span: timedelta | None = None
    ops: list = field(default_factory=list)
    value_field: str | None = None
    generate: bool = False
    inner: "Doc | None" = None                    # the older aggregation: the rule counted is itself

    @property
    def key(self) -> str:
        return f"{self.entry}:{self.index}"

    def techniques(self) -> list[str]:
        return [t[7:].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]

    def tactics(self) -> list[str]:
        return [t[7:] for t in self.tags if t.startswith("attack.") and not re.fullmatch(r"attack\.[tgsc]\d{4}(\.\d{3})?", t)]

    def window(self) -> str:
        if not self.span:
            return ""
        seconds = int(self.span.total_seconds())
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if seconds % size == 0:
                return f"{seconds // size}{unit}"
        return f"{seconds}s"

    def threshold(self) -> str:
        signs = {"gt": ">", "gte": "≥", "eq": "="}
        return " ".join(f"{signs[op]} {n}" for op, n in self.ops)

    def summary(self) -> dict:
        return {"key": self.key, "title": self.title, "name": self.name, "id": self.id, "level": self.level,
                "status": self.status, "description": self.description, "kind": self.kind, "kind_label": KIND_LABEL[self.kind],
                "techniques": self.techniques(), "tactics": self.tactics(), "sources": sorted(self.sources),
                "process": self.process, "window": self.window(), "group_by": self.group_by, "threshold": self.threshold(),
                "value_field": self.value_field, "refs": self.refs, "generate": self.generate}


def _logsource(raw) -> tuple[set[str], str | None]:
    if raw is None:
        return {"auth", "ossec", "pf", "ipf"}, None
    if not isinstance(raw, dict):
        raise SigmaError("logsource must be a map (product, service, category).")
    service, product, category = (_text(raw.get(k)).strip().lower() for k in ("service", "product", "category"))
    if service:
        return SERVICES.get(service, (set(), None))
    if category:
        return set(CATEGORIES.get(category, set())), None
    if product:
        return set(PRODUCTS.get(product, set())), None
    return {"auth", "ossec", "pf", "ipf"}, None


def _doc(raw: dict, entry: int, index: int) -> Doc:
    if not isinstance(raw, dict):
        raise SigmaError(f"Document {index + 1} is not a map.")
    if raw.get("action"):
        raise SigmaError("Rule collections with 'action:' are not supported; write each rule in full.")
    title = _text(raw.get("title")).strip()
    if not title:
        raise SigmaError(f"Document {index + 1} has no title.")
    level = _text(raw.get("level") or "medium").strip().lower()
    if level not in LEVELS:
        raise SigmaError(f"{title}: level must be one of {', '.join(LEVELS)}.")
    tags = [_text(t).strip().lower().replace("_", "-") for t in (raw.get("tags") or [])]     # credential_access → credential-access
    base = dict(entry=entry, index=index, title=title, name=_text(raw.get("name")).strip(), id=_text(raw.get("id")).strip(),
                level=level, status=_text(raw.get("status")).strip(), description=_text(raw.get("description")).strip(), tags=tags)

    if "correlation" in raw:
        c = raw["correlation"]
        if not isinstance(c, dict):
            raise SigmaError(f"{title}: correlation must be a map.")
        kind = _text(c.get("type")).strip().lower()
        if kind not in KIND_LABEL or kind == "event":
            raise SigmaError(f"{title}: correlation type must be event_count, value_count, temporal or temporal_ordered.")
        refs = c.get("rules")
        refs = [refs] if isinstance(refs, str) else refs
        if not refs or not all(isinstance(r, str) and r.strip() for r in refs):
            raise SigmaError(f"{title}: correlation lists the rules it uses (rules: [name, ...]).")
        if kind.startswith("temporal") and len(refs) < 2:
            raise SigmaError(f"{title}: a {kind} correlation needs at least two rules.")
        group = c.get("group-by", c.get("group_by")) or []
        group = [group] if isinstance(group, str) else group
        ops, value_field = _threshold(c.get("condition"), kind)
        if "timespan" not in c and "timeframe" not in c:
            raise SigmaError(f"{title}: correlation needs a timespan such as 5m.")
        return Doc(**base, kind=kind, refs=[r.strip() for r in refs], group_by=[_text(g) for g in group],
                   span=_span(c.get("timespan", c.get("timeframe"))), ops=ops, value_field=value_field,
                   generate=bool(c.get("generate", False)))

    detection = raw.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError(f"{title}: needs a detection (or a correlation).")
    condition = detection.get("condition")
    if isinstance(condition, list):
        if not condition:
            raise SigmaError(f"{title}: the condition is empty.")
        condition = condition[0] if len(condition) == 1 else " or ".join(f"({x})" for x in condition)
    condition = _text(condition).strip()
    if not condition:
        raise SigmaError(f"{title}: detection needs a condition.")
    names = [k for k in detection if k not in ("condition", "timeframe")]
    try:
        selections = {name: _selection(name, detection[name]) for name in names}
    except SigmaError as error:
        raise SigmaError(f"{title}: {error}") from None
    sources, process = _logsource(raw.get("logsource"))
    head, _, aggregation = condition.partition("|")
    try:
        parsed = _Condition(head, names)
    except SigmaError as error:
        raise SigmaError(f"{title}: {error}") from None
    rule = Doc(**base, kind="event", sources=sources, process=process, selections=selections, condition=parsed)
    if not aggregation.strip():
        return rule
    found = AGGREGATION.match(aggregation.strip())
    if not found:
        raise SigmaError(f"{title}: the aggregation reads like 'count() by source_ip > 5' or 'count(username) by source_ip > 5'.")
    counted, by, op, n = found.groups()
    timeframe = raw.get("timeframe", detection.get("timeframe"))
    if not timeframe:
        raise SigmaError(f"{title}: an aggregation needs a timeframe such as 10m.")
    ops = [({">": "gt", ">=": "gte", "=": "eq", "==": "eq"}[op], int(n))]
    group = [g.strip() for g in (by or "").split(",") if g.strip()]
    kind = "value_count" if counted else "event_count"
    return Doc(**base, kind=kind, sources=sources, process=process, group_by=group, span=_span(timeframe),
               ops=ops, value_field=counted or None, inner=rule)


def parse(text: str, entry: int = 0) -> list[Doc]:
    """The documents of one saved entry (several may be separated by ---)."""
    if len(text) > MAX_TEXT:
        raise SigmaError(f"At most {MAX_TEXT:,} characters in one entry.")
    try:
        raw = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark else ""
        raise SigmaError(f"YAML{where}: {getattr(error, 'problem', None) or error}") from None
    if not raw:
        raise SigmaError("No rule in the text.")
    return [_doc(d, entry, i) for i, d in enumerate(raw)]


# --- the saved entries -----------------------------------------------------------------------------

def _connect():
    con = store.connect()
    con.executescript(SCHEMA)
    return con


def _seed(con) -> None:
    """The starter rules, once: then they are ordinary entries to edit, switch off or delete."""
    if con.execute("SELECT 1 FROM sigma_meta WHERE key='seeded'").fetchone():
        return
    for path in sorted(STARTER.glob("*.yml")):
        con.execute("INSERT INTO sigma_rules (yaml, enabled, added_by, added_at, updated_by, updated_at) VALUES (?,?,?,?,?,?)",
                    (path.read_text(encoding="utf-8"), 1, "starter rules", store.now(), "", ""))
    con.execute("INSERT INTO sigma_meta VALUES ('seeded', ?)", (store.now(),))


def _rows() -> list[dict]:
    with store._lock, _connect() as con:
        _seed(con)
        return [dict(r) for r in con.execute("SELECT * FROM sigma_rules ORDER BY id")]


def _entry(row: dict) -> dict:
    try:
        docs, error = [d.summary() for d in parse(row["yaml"], row["id"])], ""
    except SigmaError as e:
        docs, error = [], str(e)
    from . import sigma_form
    return {"id": row["id"], "yaml": row["yaml"], "enabled": bool(row["enabled"]), "added_by": row["added_by"],
            "added_at": row["added_at"], "updated_by": row["updated_by"], "updated_at": row["updated_at"],
            "docs": docs, "error": error, "form": None if error else sigma_form.to_form(row["yaml"])}


def entries() -> dict:
    rows = _rows()
    missing = _unresolved([r for r in rows if r["enabled"]])
    out = [_entry(r) for r in rows]
    for r in out:
        r["missing"] = missing.get(r["id"], [])
    from . import sigma_form
    return {"entries": out, "fields": FIELDS, "levels": list(LEVELS), "event_types": sigma_form.event_types()}


def check(text: str) -> dict:
    """A draft's documents, or what is wrong with it (raises); and the form for it, when the form can show it."""
    from . import sigma_form
    return {"docs": [d.summary() for d in parse(text, 0)], "form": sigma_form.to_form(text)}


def _digest(text: str) -> str:
    return hashlib.sha256((str(text or "").strip() + "\n").encode("utf-8")).hexdigest()


def _mark_tested(draft: str) -> None:
    if draft:
        if len(_tested) >= MAX_TESTED:
            _tested.clear()
        _tested.add(_digest(draft))


def _titles(text: str) -> list[str]:
    return [d.title for d in parse(text, 0)]


def add(text: str, actor: str) -> dict:
    text = str(text or "").strip() + "\n"
    titles = _titles(text)
    with store._lock, _connect() as con:
        _seed(con)
        cur = con.execute("INSERT INTO sigma_rules (yaml, enabled, added_by, added_at, updated_by, updated_at) VALUES (?,?,?,?,?,?)",
                          (text, 1, actor, store.now(), "", ""))
        store.audit(con, actor, "sigma_add", f"sigma/{cur.lastrowid}", {"titles": titles, "tested": _digest(text) in _tested})
        row = dict(con.execute("SELECT * FROM sigma_rules WHERE id=?", (cur.lastrowid,)).fetchone())
    _changed()
    return _entry(row)


def update(entry_id: int, actor: str, text: str | None = None, enabled: bool | None = None) -> dict:
    with store._lock, _connect() as con:
        row = con.execute("SELECT * FROM sigma_rules WHERE id=?", (entry_id,)).fetchone()
        if row is None:
            raise KeyError("No such rule.")
        detail = {}
        if text is not None:
            text = str(text).strip() + "\n"
            detail["titles"] = _titles(text)
            detail["tested"] = _digest(text) in _tested
            con.execute("UPDATE sigma_rules SET yaml=?, updated_by=?, updated_at=? WHERE id=?", (text, actor, store.now(), entry_id))
        if enabled is not None:
            detail["enabled"] = bool(enabled)
            con.execute("UPDATE sigma_rules SET enabled=? WHERE id=?", (int(bool(enabled)), entry_id))
        store.audit(con, actor, "sigma_update", f"sigma/{entry_id}", detail)
        row = dict(con.execute("SELECT * FROM sigma_rules WHERE id=?", (entry_id,)).fetchone())
    _changed()
    return _entry(row)


def delete(entry_id: int, actor: str) -> None:
    with store._lock, _connect() as con:
        row = con.execute("SELECT yaml FROM sigma_rules WHERE id=?", (entry_id,)).fetchone()
        if row is None:
            raise KeyError("No such rule.")
        con.execute("DELETE FROM sigma_rules WHERE id=?", (entry_id,))
        try:
            titles = _titles(row["yaml"])
        except SigmaError:
            titles = []
        store.audit(con, actor, "sigma_delete", f"sigma/{entry_id}", {"titles": titles})
    _changed()


def export() -> dict:
    """Every saved entry, one YAML stream (documents separated by ---)."""
    texts = [r["yaml"].strip() for r in _rows()]
    return {"yaml": "\n---\n".join(texts) + "\n", "entries": len(texts)}


def _changed() -> None:
    """The rules changed: Review's pass over the year runs again in the background (cluster_index)."""
    from . import cluster_index
    cluster_index.refresh()


# --- Sigma as a detector (Review, Analyze, uploads) ------------------------------------------------------------

def enabled_docs() -> tuple[list[Doc], str]:
    """The enabled rules, parsed (an entry that does not parse is left out), and a stamp that changes with them."""
    rows = [r for r in _rows() if r["enabled"]]
    docs = []
    for r in rows:
        try:
            docs.extend(parse(r["yaml"], r["id"]))
        except SigmaError:
            continue
    digest = hashlib.sha1("\n---\n".join(f"{r['id']}:{r['yaml']}" for r in rows).encode("utf-8")).hexdigest()[:16]
    return docs, digest


def longest_window(docs: list[Doc]) -> timedelta:
    return max((d.span for d in docs if d.span), default=timedelta(0))


def hit_titles(docs: list[Doc], events: list[Event]) -> dict[int, set[str]]:
    """Index into ``events`` -> titles of the reported hits that hold that event."""
    out: dict[int, set[str]] = defaultdict(set)
    for hit in evaluate(docs, events)["hits"]:
        for i in hit.events:
            out[i].add(hit.doc.title)
    return out


def line_hits(source: str, parsed: list, host: str) -> dict[int, list[str]]:
    """Analyze's parsed lines: line number (from 1) -> titles of the enabled rules' hits that hold that line."""
    docs, _ = enabled_docs()
    if not docs:
        return {}
    events = _events(source, parsed, host.strip().lower())
    return {events[i].n: sorted(titles) for i, titles in hit_titles(docs, events).items()}


# --- running the rules -----------------------------------------------------------------------------

@dataclass
class Event:
    n: int                                     # line number in the input, from 1
    line: str
    fields: dict
    time: datetime | None
    source: str
    file: str = ""                             # a folder's run: the file (or ZIP member) the line is in


@dataclass
class Item:
    """What a correlation counts: an event, or a hit of another correlation (at its last time)."""
    time: datetime
    events: frozenset
    fields: dict
    ref: int = 0


@dataclass
class Hit:
    doc: Doc
    group: dict
    first: datetime | None
    last: datetime | None
    count: int
    events: set
    upto: int = -1


def _resolve(docs: list[Doc]) -> tuple[dict, dict]:
    """name, id and title → doc; and each doc's refs → docs (missing names listed per doc)."""
    index = {}
    for d in docs:
        for k in (d.name, d.id, d.title):
            if k:
                index.setdefault(k, d)
                index.setdefault(k.lower(), d)
    missing = {}
    for d in docs:
        gone = [r for r in d.refs if r not in index and r.lower() not in index]
        if gone:
            missing[d.key] = gone
    return index, missing


def _unresolved(rows: list[dict]) -> dict[int, list[str]]:
    docs = []
    for r in rows:
        try:
            docs.extend(parse(r["yaml"], r["id"]))
        except SigmaError:
            continue
    _, missing = _resolve(docs)
    out: dict[int, list[str]] = defaultdict(list)
    for key, names in missing.items():
        out[int(key.split(":")[0])].extend(names)
    return dict(out)


def _value(fields: dict, name: str) -> str:
    key = ALIASES.get(name.lower(), name)
    for k in (key, name):
        if k in fields and fields[k] not in (None, ""):
            return _text(fields[k])
    lowered = name.lower()
    return next((_text(v) for k, v in fields.items() if k.lower() in (lowered, key.lower()) and v not in (None, "")), "")


def _merge(hits: list[Hit], hit_for, items: list[Item], left: int, right: int, count: int) -> None:
    """Fire at items[left..right]: extend the last hit of this group when the windows overlap, else start one."""
    current = hit_for()
    if current is not None and items[left].time <= current.last:
        for item in items[current.upto + 1:right + 1]:
            current.events |= item.events
        current.last = items[right].time
        current.count = max(current.count, count)
        current.upto = right
        return
    hit = hit_for(new=True)
    for item in items[left:right + 1]:
        hit.events |= item.events
    hit.first, hit.last, hit.count, hit.upto = items[left].time, items[right].time, count, right
    hits.append(hit)


def _window(doc: Doc, items: list[Item], group: dict) -> list[Hit]:
    hits: list[Hit] = []
    holder: list[Hit | None] = [None]

    def hit_for(new: bool = False):
        if new:
            holder[0] = Hit(doc, group, None, None, 0, set())
        return holder[0]

    ok = lambda n: all(WINDOW_OPS[op](n, k) for op, k in doc.ops)    # noqa: E731
    if doc.kind in ("event_count", "value_count"):
        left, values = 0, Counter()
        for right, item in enumerate(items):
            if doc.kind == "value_count":
                v = _value(item.fields, doc.value_field)
                if v:
                    values[v] += 1
            while item.time - items[left].time > doc.span:
                if doc.kind == "value_count":
                    v = _value(items[left].fields, doc.value_field)
                    if v:
                        values[v] -= 1
                        if not values[v]:
                            del values[v]
                left += 1
            n = right - left + 1 if doc.kind == "event_count" else len(values)
            if ok(n):
                _merge(hits, hit_for, items, left, right, n)
        return hits
    refs = len(doc.refs)
    if doc.kind == "temporal":
        left, seen = 0, Counter()
        for right, item in enumerate(items):
            seen[item.ref] += 1
            while item.time - items[left].time > doc.span:
                seen[items[left].ref] -= 1
                if not seen[items[left].ref]:
                    del seen[items[left].ref]
                left += 1
            if len(seen) == refs:
                _merge(hits, hit_for, items, left, right, right - left + 1)
        return hits
    # temporal_ordered: each rule after the one before, all within the span of the last
    by_ref: dict[int, list[int]] = defaultdict(list)
    for i, item in enumerate(items):
        by_ref[item.ref].append(i)
    for end in by_ref.get(refs - 1, []):
        start_time, bound, chain = items[end].time - doc.span, end, [end]
        for ref in range(refs - 2, -1, -1):
            positions = by_ref.get(ref, [])
            at = bisect_left(positions, bound) - 1                 # the latest of this rule before the next one
            if at < 0 or items[positions[at]].time < start_time:
                chain = []
                break
            bound = positions[at]
            chain.append(bound)
        if not chain:
            continue
        chain.reverse()
        current = holder[0]
        if current is not None and items[chain[0]].time <= current.last:
            for i in chain:
                current.events |= items[i].events
            current.last, current.count = items[end].time, current.count + 1
        else:
            hit = hit_for(new=True)
            for i in chain:
                hit.events |= items[i].events
            hit.first, hit.last, hit.count = items[chain[0]].time, items[end].time, 1
            hits.append(hit)
    return hits


def _correlate(doc: Doc, streams: list[list[Item]]) -> list[Hit]:
    groups: dict[tuple, list[Item]] = defaultdict(list)
    for ref, stream in enumerate(streams):
        for item in stream:
            key = tuple(_value(item.fields, g) for g in doc.group_by)
            groups[key].append(Item(item.time, item.events, item.fields, ref))
    hits = []
    for key, items in groups.items():
        items.sort(key=lambda x: (x.time, x.ref))
        hits.extend(_window(doc, items, dict(zip(doc.group_by, key))))
    return hits


def evaluate(docs: list[Doc], events: list[Event], report: set[str] | None = None) -> dict:
    """Match every rule, then every correlation (after the ones it uses). ``report``: the docs to report
    (default: all that generate)."""
    index, missing = _resolve(docs)
    matches: dict[str, list[int]] = {}
    for d in docs:
        rule = d.inner if d.inner else d if d.kind == "event" else None
        if rule is None:
            continue
        found = []
        for i, e in enumerate(events):
            if e.source not in rule.sources or (rule.process and _text(e.fields.get("process_name")).lower() != rule.process):
                continue
            cache = {}

            def check(name, e=e, cache=cache):
                if name not in cache:
                    cache[name] = rule.selections[name](e)
                return cache[name]
            if rule.condition.evaluate(check):
                found.append(i)
        matches[d.key] = found

    hits: dict[str, list[Hit]] = {}
    untimed: dict[str, int] = {}
    errors: dict[str, str] = {k: f"Missing: {', '.join(v)}" for k, v in missing.items()}
    state: dict[str, str] = {}

    def items_of(d: Doc) -> list[Item]:
        if d.kind == "event":
            out = []
            for i in matches.get(d.key, []):
                if events[i].time is None:
                    untimed[d.key] = untimed.get(d.key, 0) + 1
                    continue
                out.append(Item(events[i].time, frozenset([i]), events[i].fields))
            return out
        return [Item(h.last, frozenset(h.events), h.group) for h in run_correlation(d)]

    def run_correlation(d: Doc) -> list[Hit]:
        if d.key in hits:
            return hits[d.key]
        if state.get(d.key) == "running":
            raise SigmaError(f"{d.title}: correlations refer to each other in a loop.")
        state[d.key] = "running"
        if d.key in errors:
            hits[d.key] = []
        elif d.inner is not None:
            items = []
            for i in matches.get(d.key, []):
                if events[i].time is None:
                    untimed[d.key] = untimed.get(d.key, 0) + 1
                    continue
                items.append(Item(events[i].time, frozenset([i]), events[i].fields))
            hits[d.key] = _correlate(d, [items])
        else:
            used = [index.get(r) or index.get(r.lower()) for r in d.refs]
            hits[d.key] = _correlate(d, [items_of(u) for u in used])
        state[d.key] = "done"
        return hits[d.key]

    for d in docs:
        if d.kind != "event":
            try:
                run_correlation(d)
            except SigmaError as error:
                errors[d.key] = str(error)
                hits[d.key] = []

    referenced = set()                         # rules a correlation uses: they report nothing themselves
    for d in docs if report is None else [d for d in docs if d.key in report]:
        if d.kind != "event" and d.inner is None and not d.generate:
            referenced.update(u.key for u in (index.get(r) or index.get(r.lower()) for r in d.refs) if u)
    out_hits = []
    for d in docs:
        if report is not None and d.key not in report:
            continue
        if d.kind == "event" and d.key in referenced:
            continue
        if d.kind == "event":
            by_host: dict[str, list[int]] = defaultdict(list)
            for i in matches.get(d.key, []):
                by_host[_text(events[i].fields.get("host"))].append(i)
            for host, idx in by_host.items():
                times = [events[i].time for i in idx if events[i].time]
                out_hits.append(Hit(d, {"host": host} if host else {}, min(times, default=None), max(times, default=None), len(idx), set(idx)))
        else:
            out_hits.extend(hits.get(d.key, []))
    return {"matches": matches, "hits": out_hits, "errors": errors, "untimed": untimed, "referenced": referenced, "corr": hits}


def _events(source: str, parsed: list, host: str, file: str = "") -> list[Event]:
    out = []
    for n, (line, event, _known) in enumerate(parsed, start=1):
        fields = {k: v for k, v in event.items() if v not in (None, "")}
        if not fields.get("host") and host:
            fields["host"] = host
        out.append(Event(n, line, fields, analyze._time(fields.get("timestamp", "")), source, file))
    return out


def _hit_json(hit: Hit, events: list[Event], allowed: frozenset) -> dict:
    idx = sorted(hit.events)
    facts = [{"username": _text(events[i].fields.get("username")), "host": _text(events[i].fields.get("host")),
              "program": _text(events[i].fields.get("process_name")), "address": _text(events[i].fields.get("source_ip"))} for i in idx]
    return {"doc": hit.doc.key, "entry": hit.doc.entry, "title": hit.doc.title, "level": hit.doc.level, "kind": hit.doc.kind,
            "kind_label": KIND_LABEL[hit.doc.kind], "techniques": hit.doc.techniques(), "group": hit.group,
            "first": hit.first.isoformat(sep=" ") if hit.first else "", "last": hit.last.isoformat(sep=" ") if hit.last else "",
            "count": hit.count, "events": len(idx), "whitelisted": whitelist.covers(facts, allowed),
            "lines": [{"n": events[i].n, "line": events[i].line, "event_type": _text(events[i].fields.get("event_type")),
                       **({"file": events[i].file} if events[i].file else {})} for i in idx[:MAX_LINES_PER_HIT]],
            "more": max(0, len(idx) - MAX_LINES_PER_HIT)}


def run(text: str = "", path: str = "", source: str = "auto", month: str = "", host: str = "", raw: str = "", name: str = "",
        draft: str = "", entry: int = 0, progress=lambda step, detail: None) -> dict:
    """Run the enabled rules over the input; or a draft (in place of saved entry ``entry`` when it edits one), with
    the enabled rules it may refer to, reporting the draft's hits only."""
    month = month or datetime.now().strftime("%Y-%m")
    folder = Path(path.strip().strip('"')) if path.strip() else None
    if folder is not None and folder.is_dir():
        result = run_folder(folder, source=source, month=month, host=host, raw=raw, draft=draft, entry=entry, progress=progress)
        _mark_tested(draft)
        return result
    progress("read", "Reading input")
    lines, layout, hosts = analyze.read_table(text, path, raw)
    if not host and len(set(hosts)) == 1:
        host = hosts[0].strip().lower()
    if not host and path:
        found = analyze.OSSEC_FILE_HOST.search(Path(path).name)
        host = found.group("host").lower() if found else ""
    detected = analyze.detect_source(lines, month)
    if source == "auto":
        source = detected["source"]
        if not source:
            raise ValueError("None of the four log types recognises these lines.")
    elif source not in analyze.PARSERS:
        raise ValueError(f"Unknown log type {source!r}.")
    progress("parse", "Parsing")
    parsed = analyze._parse(source, lines, month)
    events = _events(source, parsed, host.strip().lower())

    progress("rules", "Rules")
    docs, broken, report = _rule_docs(draft, entry)
    result = evaluate(docs, events, report)
    stats = _new_stats(docs)
    _add_stats(stats, docs, result, source)
    hits, rules = _report(docs, stats, [_hit_json(h, events, whitelist.active()) for h in result["hits"]], report)
    times = sorted(e.time for e in events if e.time)
    _mark_tested(draft)
    progress("done", "Done")
    return {"source": source, "detected": detected, "month": month, "host": host, "draft": bool(draft),
            "lines": len(events), "recognised": sum(1 for _, _, ok in parsed if ok),
            "span": {"first": times[0].isoformat(sep=" ") if times else "", "last": times[-1].isoformat(sep=" ") if times else ""},
            "rules": rules, "hits": hits, "broken": broken}


def _rule_docs(draft: str, entry: int) -> tuple[list[Doc], list[dict], set[str] | None]:
    """The enabled rules' documents, the entries that do not read, and the draft's documents (the ones to report) when
    a draft runs in place of its saved entry."""
    docs, broken = [], []
    for r in (r for r in _rows() if r["enabled"]):
        try:
            docs.extend(parse(r["yaml"], r["id"]))
        except SigmaError as error:
            broken.append({"entry": r["id"], "error": str(error)})
    report = None
    if draft:
        draft_docs = parse(draft, -1)
        docs = draft_docs + [d for d in docs if d.entry != entry]    # first: its names win over the saved ones
        report = {d.key for d in draft_docs}
    return docs, broken, report


def _new_stats(docs: list[Doc]) -> dict:
    return {d.key: {"matched": 0, "untimed": 0, "error": "", "helper": False, "applies": False} for d in docs}


def _add_stats(stats: dict, docs: list[Doc], result: dict, source: str) -> None:
    """One evaluation's counts per document, added to the run's (a folder's run evaluates once per log type and month)."""
    for d in docs:
        s = stats[d.key]
        s["applies"] = s["applies"] or (bool(d.sources & {source}) if (d.kind == "event" or d.inner) else True)
        s["matched"] += len(result["matches"].get(d.key, []))
        s["untimed"] += result["untimed"].get(d.key, 0)
        s["error"] = s["error"] or result["errors"].get(d.key, "")
        s["helper"] = s["helper"] or d.key in result["referenced"]


def _report(docs: list[Doc], stats: dict, hits: list[dict], report: set[str] | None) -> tuple[list[dict], list[dict]]:
    """The hits, the highest level first then the earliest; and each reported document with its counts."""
    order = {lvl: i for i, lvl in enumerate(reversed(LEVELS))}
    hits = sorted(hits, key=lambda h: (order[h["level"]], h["first"] or "~"))
    per_doc = Counter(h["doc"] for h in hits)
    rules = []
    for d in docs:
        if report is not None and d.key not in report:
            continue
        s = stats[d.key]
        rules.append({**d.summary(), "entry": d.entry, "applies": s["applies"],
                      "matched": s["matched"] if (d.kind == "event" or d.inner) else None,
                      "hits": per_doc.get(d.key, 0), "helper": s["helper"], "untimed": s["untimed"], "error": s["error"]})
    return hits, rules


# --- a folder: every file of its lowest folders, one log type and month at a time --------------------------------

SURVEY_LINES = 400                       # read from each file to tell its log type (detect_source looks at 200)
ARCHIVES = (".gz", ".zip")
UNREADABLE = (OSError, EOFError, zlib.error, zipfile.BadZipFile)


def lowest_files(root: Path) -> tuple[list[Path], list[dict]]:
    """The files of the lowest folders under root (with no folder inside; root itself when it has none), in path
    order; and the files beside a folder, left out as not at the lowest level."""
    files, left = [], []
    for folder in [root, *sorted(p for p in root.rglob("*") if p.is_dir())]:
        inside = sorted(folder.iterdir())
        here = [p for p in inside if p.is_file()]
        if any(p.is_dir() for p in inside):
            left += [{"path": p.relative_to(root).as_posix(), "reason": "beside a folder: not at the lowest level"} for p in here]
        else:
            files += here
    return files, left


def path_month(file: Path, root: Path) -> str | None:
    """The month a file's folders name, the nearest first and the chosen folder last: a YYYY-MM start (2026-08,
    2026-08_auth, as the raw archives) or a month and a year in any natural form (Aug 26, Sept-25, September 2025: the
    event logs' month_key)."""
    month_key = module("phase1_classify/event_log.py").month_key
    for part in [*reversed(file.relative_to(root).parts[:-1]), root.name]:
        found = re.match(r"(\d{4})-(\d{2})", part)
        if found and 1 <= int(found[2]) <= 12:
            return found[0]
        if month_key(part):
            return month_key(part)
    return None


def _logs(file: Path, root: Path, raw: str, survey: bool = False):
    """Each log in a file as (name, lines, host column values, error): the file itself, read as a single file on this
    laptop is (tables too); a .gz decompressed, or each text member of a ZIP. survey: only the first lines."""
    rel = file.relative_to(root).as_posix()
    lower = file.name.lower()
    if lower.endswith((".xlsx", ".xls")) or (not survey and not lower.endswith(ARCHIVES)):
        try:
            lines, _, hosts = analyze.read_table(path=str(file), raw=raw)
        except ValueError as error:
            yield rel, [], [], str(error)
            return
        yield (rel, lines[:SURVEY_LINES], hosts[:SURVEY_LINES], "") if survey else (rel, lines, hosts, "")
        return
    for member, stream in patterns._streams(file):
        name = f"{rel}/{member}" if lower.endswith(".zip") else rel
        decoded = patterns._decoded(stream)
        text = "".join(islice(decoded, SURVEY_LINES + tabular.SAMPLE) if survey else decoded)
        try:
            lines, _, hosts = analyze.read_table(text=text, raw=raw, most=analyze.MAX_LINES_PATH)
        except ValueError as error:
            yield name, [], [], str(error)
            continue
        yield name, lines, hosts, ""


def _file_host(host: str, hosts: list[str], name: str) -> str:
    """The server of a file's lines, as for a single file: the one chosen, a table's only host, or an OSSEC file's name."""
    if host:
        return host.strip().lower()
    if hosts and len(set(hosts)) == 1:
        return hosts[0].strip().lower()
    found = analyze.OSSEC_FILE_HOST.search(Path(name).name)
    return found.group("host").lower() if found else ""


def run_folder(root: Path, source: str = "auto", month: str = "", host: str = "", raw: str = "", draft: str = "",
               entry: int = 0, progress=lambda step, detail: None) -> dict:
    """The rules over every log in the lowest folders under root. Each file is told its log type by its first lines
    (or, with a log type chosen, only that type's files are read) and its month by its folders (else month). The
    files of one log type and month are checked together, so a correlation sees all their servers, and only those are
    in memory at a time (at most analyze.MAX_LINES_PATH lines). Files left out are listed, with why."""
    month = month or datetime.now().strftime("%Y-%m")
    files, left = lowest_files(root)
    if not files:
        raise ValueError(f"No files in the lowest folders of {root}.")
    plan: dict[tuple[str, str], list[tuple[Path, str, str]]] = defaultdict(list)
    for i, file in enumerate(files, start=1):
        progress("read", f"Looking at {i:,} of {len(files):,} files")
        file_month = path_month(file, root) or month
        try:
            for name, lines, hosts, error in _logs(file, root, raw, survey=True):
                found = "" if error else analyze.detect_source(lines, file_month)["source"]
                if error or not found:
                    left.append({"path": name, "reason": error or "no log type recognises its lines"})
                elif source not in ("auto", found):
                    left.append({"path": name, "reason": f"another log type ({found})"})
                else:
                    plan[(found, file_month)].append((file, name, _file_host(host, hosts, name)))
        except UNREADABLE as error:
            left.append({"path": file.relative_to(root).as_posix(), "reason": f"unreadable: {error}"})
    if not plan:
        raise ValueError(f"None of the {len(files):,} files in the lowest folders of {root} holds lines that any of the "
                         "four log types recognises.")
    docs, broken, report = _rule_docs(draft, entry)
    stats, allowed, hits, groups, times = _new_stats(docs), whitelist.active(), [], [], []
    for n, ((found, file_month), members) in enumerate(sorted(plan.items()), start=1):
        label = f"{n} of {len(plan)}: {found} {file_month}"
        progress("parse", f"{label}, {len(members):,} files")
        wanted: dict[Path, dict[str, str]] = defaultdict(dict)
        for file, name, file_host in members:
            wanted[file][name] = file_host
        events, recognised, too_many = [], 0, False
        for file, names in wanted.items():
            try:
                for name, lines, _, error in _logs(file, root, raw):
                    if name not in names or error:
                        continue
                    if len(events) + len(lines) > analyze.MAX_LINES_PATH:
                        too_many = True
                        break
                    parsed = analyze._parse(found, lines, file_month)
                    recognised += sum(1 for _, _, ok in parsed if ok)
                    events.extend(_events(found, parsed, names[name], name))
            except UNREADABLE as error:
                left.append({"path": file.relative_to(root).as_posix(), "reason": f"unreadable: {error}"})
            if too_many:
                break
        if too_many:
            left += [{"path": name, "reason": f"more than {analyze.MAX_LINES_PATH:,} {found} lines in {file_month} together: "
                                              "choose a smaller folder"} for _, name, _ in members]
            continue
        progress("rules", f"{label}, rules")
        result = evaluate(docs, events, report)
        _add_stats(stats, docs, result, found)
        hits += [_hit_json(h, events, allowed) for h in result["hits"]]
        known = [e.time for e in events if e.time]
        times += [min(known), max(known)] if known else []
        groups.append({"source": found, "month": file_month, "files": len(members), "lines": len(events), "recognised": recognised})
        del events                                       # one log type and month in memory at a time
    if not groups:
        raise ValueError(f"Every log type and month under {root} holds more than {analyze.MAX_LINES_PATH:,} lines: choose a smaller folder.")
    hits, rules = _report(docs, stats, hits, report)
    progress("done", "Done")
    by_lines = Counter()
    for g in groups:
        by_lines[g["source"]] += g["lines"]
    return {"source": by_lines.most_common(1)[0][0], "detected": None, "month": month, "host": host, "draft": bool(draft),
            "lines": sum(g["lines"] for g in groups), "recognised": sum(g["recognised"] for g in groups),
            "span": {"first": min(times).isoformat(sep=" ") if times else "", "last": max(times).isoformat(sep=" ") if times else ""},
            "rules": rules, "hits": hits, "broken": broken,
            "folder": {"path": str(root), "files": sum(g["files"] for g in groups), "groups": groups, "left": left}}
