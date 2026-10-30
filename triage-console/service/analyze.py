"""Analyze: run pasted lines or a file through the pipeline and say whether it would be flagged.

* auth and OSSEC: the full pipeline (scoring.py) - Phase 1 rules, Phase 2
  observations, Phase 3 features, Phase 4 detectors and model zoo, and the
  nearest clusters on the Phase 4c map.
* PF and IPFilter: the presence method - the normal state is no traffic, so
  every recognised line is flagged.
"""
from __future__ import annotations

import re
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from itertools import islice
from pathlib import Path

from . import event_counts, scoring, tabular, whitelist
from .catalog import SOURCES, VIEWS, model_status
from .pipeline_code import module

MAX_LINES = 400_000            # pasted or uploaded
MAX_LINES_PATH = 3_000_000     # a file read from this laptop (a month of authlog is about 2.2 million)
OSSEC_UNKNOWN = "OSSEC_UNKNOWN_EVENT"
OSSEC_FILE_HOST = re.compile(r"ossec[_-]?logs?[_-](?P<host>[^.\\/]+)", re.I)


def _auth(lines, month):
    m = module("phase1_classify/auth.py")
    classifier = m.StandaloneAuthClassifier()
    for line in lines:
        event = classifier.normalize_event_fields(classifier.classify_line(line))
        event["timestamp"] = classifier.normalize_timestamp(event.get("timestamp"), month)
        event["host"] = event.get("hostname", "")
        yield event, event["event_type"] != classifier.UNKNOWN_EVENT_TYPE


def _ossec(lines, month):
    m = module("phase1_classify/ossec.py")
    for line in lines:
        text = re.sub(r"^\S+?:(?=\d{4}/)", "", line)          # drop a "file:" prefix if present
        for event_type, pattern in m.PATTERNS:
            found = pattern.match(text)
            if found:
                event = {k: v for k, v in found.groupdict().items() if v is not None}
                break
        else:
            found = m.UNKNOWN_EVENT_PATTERN.match(text)
            event, event_type = (found.groupdict() if found else {"raw_message": text}), OSSEC_UNKNOWN
        event["event_type"] = event_type
        event["timestamp"] = (event.get("timestamp") or "").replace("/", "-")
        event["host"] = ""
        yield event, event_type != OSSEC_UNKNOWN


def _pf(lines, month):
    m = module("phase1_classify/pf.py")
    for line in lines:
        event = m.classify_line(line)
        event["host"] = event.get("hostname", "")
        yield event, event["event_type"] != m.UNKNOWN_EVENT_TYPE


def _ipf(lines, month):
    m = module("phase1_classify/ipf.py")
    for line in lines:
        event = m.parse_line(line, month)
        if event is None:
            yield {"event_type": "IPF_UNKNOWN_EVENT", "raw_message": line, "host": ""}, False
        else:
            event["host"] = event.get("hostname", "")
            yield event, True


PARSERS = {"auth": _auth, "ossec": _ossec, "pf": _pf, "ipf": _ipf}


def _parse(source, lines, month):
    return [(line, event, known) for line, (event, known) in zip(lines, PARSERS[source](lines, month))]


def detect_source(lines: list[str], month: str) -> dict:
    """Try every parser on a sample; the one that recognises most lines wins."""
    sample = lines[:200]
    scores = {}
    for source in PARSERS:
        try:
            scores[source] = sum(known for _, _, known in _parse(source, sample, month))
        except Exception:
            scores[source] = 0
    best = max(scores, key=scores.get)
    return {"source": best if scores[best] else None, "recognised": scores}


def _time(value: str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value[:26], fmt)
        except (TypeError, ValueError):
            continue
    return None


def recognised(values: list[str]) -> int:
    """How many of these lines the best of the four log types knows (to pick a table's raw-line column)."""
    month = datetime.now().strftime("%Y-%m")
    return max(detect_source(values[:50], month)["recognised"].values(), default=0)


def read_table(text: str = "", path: str = "", raw: str = "", most: int | None = None) -> tuple[list[str], dict | None, list[str]]:
    """The log lines, the table layout when the input is a table (one column the raw line, the others fields;
    service/tabular.py), and the host column's values. most: the line limit, when not the input's usual one."""
    lines = None
    if path:
        file = Path(path.strip().strip('"'))
        if not file.is_file():
            raise ValueError(f"No file at {file}.")
        if file.suffix.lower() in (".xlsx", ".xls"):          # an Excel export: its first sheet, read as CSV text
            lines, layout, hosts = read_table(text=tabular.xlsx_text(file), raw=raw)
            if len(lines) > MAX_LINES_PATH:
                raise ValueError(f"At most {MAX_LINES_PATH:,} lines at a time ({len(lines):,} given).")
            return lines, layout, hosts
        with file.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
            head = [line.rstrip("\r\n") for line in islice(handle, tabular.SAMPLE + 1)]
            layout = tabular.sniff(head, raw=raw, recognise=recognised)
            handle.seek(0)
            if layout:
                text = handle.read()
            else:
                lines = [line.rstrip("\r\n") for line in handle if line.strip()]
        limit = most or MAX_LINES_PATH
    else:
        lines = [line.rstrip("\r") for line in text.splitlines() if line.strip()]
        layout = tabular.sniff(lines[:tabular.SAMPLE + 1], raw=raw, recognise=recognised)
        limit = most or MAX_LINES
    hosts: list[str] = []
    if layout:
        rows = list(tabular.text_records(text, layout))
        lines = [line for line, _ in rows]
        if layout["host"]:
            at = layout["fields"].index(layout["host"])
            hosts = [values[at] for _, values in rows]
    if not lines:
        raise ValueError("No log lines in the input.")
    if len(lines) > limit:
        raise ValueError(f"At most {limit:,} lines at a time ({len(lines):,} given).")
    return lines, layout, hosts


def read_input(text: str = "", path: str = "", raw: str = "") -> tuple[list[str], int]:
    lines, _, _ = read_table(text, path, raw)
    return lines, MAX_LINES_PATH if path else MAX_LINES


WINDOW_SECONDS = {"5min": 300, "1h": 3600, "1d": 86400}


def _covered(parsed: list, host: str, allowed: frozenset, source: str = "auth"):
    """Whether a flagged observation is whitelisted (whitelist.py): its own account, or, for a time window that
    names none, the accounts of every input line from that server inside the window (as Review does)."""
    by_host: dict[str, list] = defaultdict(list)
    for _, event, ok in parsed:
        when = _time(event.get("timestamp", "")) if ok else None
        if when:
            by_host[(event.get("host") or host or "").lower()].append(
                (when, event.get("username") or "", event.get("process_name") or "", event.get("source_ip") or ""))
    for events in by_host.values():
        events.sort()

    def covered(view: str, row: dict) -> bool:
        if not allowed:
            return False
        if row.get("username"):
            return whitelist.covers_row(row, host, allowed, source)
        seconds, start = WINDOW_SECONDS.get(VIEWS[view]["needs"]), _time(row.get("window_start", ""))
        if not seconds or start is None:
            return False
        server = (row.get("host_id") or row.get("hostname") or host or "").lower()
        end, facts = start + timedelta(seconds=seconds), []
        for name, events in by_host.items():
            if server and name != server:
                continue
            for when, user, program, address in events[bisect_left(events, (start, "", "", "")):]:
                if when >= end:
                    break
                facts.append({"username": user, "host": name, "program": program, "address": address})
        return whitelist.covers(facts, allowed, source)
    return covered


def analyze(text: str = "", source: str = "auto", month: str = "", host: str = "", path: str = "", raw: str = "",
            name: str = "", progress=lambda step, detail: None) -> dict:
    month = month or datetime.now().strftime("%Y-%m")
    progress("read", "Reading input")
    lines, layout, hosts = read_table(text, path, raw)
    if layout and (name or path).lower().endswith(".xlsx"):      # an uploaded workbook arrives as CSV text
        layout["format"] = "Excel"
    if not host and len(set(hosts)) == 1:                 # a table's host column naming one server
        host = hosts[0].strip().lower()
    if not host and path:
        found = OSSEC_FILE_HOST.search(Path(path).name)
        host = found.group("host").lower() if found else ""
    detected = detect_source(lines, month)
    if source == "auto":
        source = detected["source"]
        if not source:
            raise ValueError("None of the four log types recognises these lines.")
    progress("parse", "Parsing")
    parsed = _parse(source, lines, month)
    known = [(line, event) for line, event, ok in parsed if ok]
    times = sorted(t for t in (_time(e.get("timestamp", "")) for _, e in known) if t)
    span_hours = (times[-1] - times[0]).total_seconds() / 3600 if len(times) > 1 else 0.0
    hosts = sorted({e.get("host") for _, e in known if e.get("host")}) or ([host] if host else [])
    types = Counter(e["event_type"] for _, e in known)
    histories = {t: event_counts.history(source, t) for t in types}
    progress("rules", "Sigma rules")
    from . import sigma                           # it reads lines the way this module does
    try:
        sigma_lines = sigma.line_hits(source, parsed, host)
        sigma_error = ""
    except Exception as error:                    # a broken rule must not stop the analysis
        sigma_lines, sigma_error = {}, str(error)

    presence = SOURCES[source]["method"] == "presence"
    views = {}
    if presence:
        verdict = {"flagged": bool(known), "confidence": 1.0 if known else 0.0, "method": "presence",
                   "basis": "Normal state is no traffic; any recognised line is flagged."}
    else:
        if source == "ossec" and not host:
            raise ValueError("OSSEC lines do not name their server. Enter it under Server.")
        views = scoring.score(source, lines, month, host=host, progress=progress,
                              covered=_covered(parsed, host, whitelist.active(), source), sigma_lines=sigma_lines)
        used = [b for v, b in views.items() if b.get("model_used")]
        flagged = sum(b.get("flagged", 0) for b in used)
        whitelisted = sum(b.get("whitelisted", 0) for b in used)
        best = max((b.get("max_unusual") or 0 for b in used), default=0)
        verdict = {"flagged": flagged > whitelisted, "confidence": best, "method": "baseline",
                   "flagged_observations": flagged, "whitelisted": whitelisted,
                   "observations": sum(b.get("observations", 0) for b in used),
                   "basis": "Highest percentile against the validation period, over the views used for alerts."}

    view_rows = []
    for view in SOURCES[source]["views"]:
        status = model_status(source, view)
        block = views.get(view, {})
        view_rows.append({"view": view, "label": VIEWS[view]["label"], "needs": VIEWS[view]["needs"],
                          "used": status["used"], "available": status["available"], "why": status["why"],
                          "observations": block.get("observations"), "flagged": block.get("flagged"), "whitelisted": block.get("whitelisted"),
                          "max_unusual": block.get("max_unusual"), "zoo_members": block.get("zoo_members"),
                          "votes_needed": block.get("votes_needed"), "drift": block.get("drift"), "rows": block.get("rows", [])})
    progress("done", "Done")
    return {
        "source": source, "detected": detected, "month": month, "host": host,
        "layout": {k: layout[k] for k in ("format", "columns", "raw", "time", "host")} if layout else None,
        "lines": len(parsed), "recognised": len(known),
        "span": {"first": times[0].isoformat(sep=" ") if times else "", "last": times[-1].isoformat(sep=" ") if times else "",
                 "hours": round(span_hours, 2)},
        "hosts": hosts[:50], "verdict": verdict, "views": view_rows,
        "sigma_lines": sigma_lines, "sigma_error": sigma_error,
        "event_types": [{"event_type": t, "input_count": n, "year_count": histories[t]["count"],
                         "share": histories[t]["share"], "months_seen": histories[t]["months_seen"],
                         "months": histories[t]["months"]} for t, n in types.most_common()],
        "sample": [{"line": line, "event_type": event.get("event_type"), "known": ok,
                    "fields": {k: v for k, v in event.items() if v not in ("", None) and k not in ("raw_message",)}}
                   for line, event, ok in parsed[:100]],
    }
