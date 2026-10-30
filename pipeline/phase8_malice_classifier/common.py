"""Shared helpers: text normalisation, sequence joining and corpus I/O.

The same normalise() runs on training data and on Phase 7 alerts, so the model
learns message structure (what happened) instead of identifiers (which IP,
which host, which PID). Change it and you must retrain.
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

SEPARATOR = " | "          # Phase 7 joins messages with this
LABELS = ("benign", "malicious")

# Triage categories shared with Phase 9 (pipeline/phase9_llm_triage). Analysts
# label in these; the Phase 8 model stays binary (security_relevant against the
# rest), because the other three differ by context the text does not hold.
CATEGORIES = ("security_relevant", "operationally_interesting", "expected_behavior", "insufficient_context")
_CATEGORY_ALIASES = {
    "security_relevant": CATEGORIES[0], "security": CATEGORIES[0], "malicious": CATEGORIES[0], "mal": CATEGORIES[0],
    "1": CATEGORIES[0], "yes": CATEGORIES[0],
    "operationally_interesting": CATEGORIES[1], "operational": CATEGORIES[1], "ops": CATEGORIES[1],
    "expected_behavior": CATEGORIES[2], "expected_behaviour": CATEGORIES[2], "expected": CATEGORIES[2],
    "benign": CATEGORIES[2], "ben": CATEGORIES[2], "0": CATEGORIES[2], "no": CATEGORIES[2], "fp": CATEGORIES[2],
    "insufficient_context": CATEGORIES[3], "insufficient": CATEGORIES[3], "needs_review": CATEGORIES[3],
    "unknown": CATEGORIES[3],
}
_BINARY = {CATEGORIES[0]: "malicious", CATEGORIES[1]: "benign", CATEGORIES[2]: "benign", CATEGORIES[3]: None}


def canonical_category(value) -> str | None:
    """'Security relevant', 'malicious', 'expected behaviour'... -> one of CATEGORIES, or None if blank/unknown."""
    key = re.sub(r"[\s\-]+", "_", str(value or "").strip().lower())
    return _CATEGORY_ALIASES.get(key)


def binary_label(value) -> str | None:
    """Training label for the Phase 8 model: malicious, benign, or None (skip the row)."""
    return _BINARY.get(canonical_category(value))
CORPUS_COLUMNS = ["text", "label", "group", "source", "unit"]
MAX_LINES_PER_SEQUENCE = 40


def raise_csv_field_limit() -> None:
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
_PATTERNS = [
    # syslog header "Sep 28 12:34:56 host " -> "<TS> <HOST> "
    (re.compile(rf"^{_MONTH}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d+)?\s+\S+\s+"), "<TS> <HOST> "),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    (re.compile(rf"\b{_MONTH}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\b"), "<TS>"),
    (re.compile(r"\b\d{4}/\d{2}/\d{2}(?:\s+\d{2}:\d{2}:\d{2})?"), "<TS>"),       # OSSEC 2026/09/28 10:00:01
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TIME>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"), "<IP6>"),
    (re.compile(r"(?<![\w:])[0-9a-fA-F]{0,4}::(?:[0-9a-fA-F]{1,4}:?)*(?![\w:])"), "<IP6>"),
    (re.compile(r"\[\d+\]"), "[<PID>]"),
    (re.compile(r"\b(?:SHA256|MD5):[A-Za-z0-9+/=:]+"), "<KEYFP>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<HEX>"),
]
# a.b.c.d or a.b.c.d.port (tcpdump/pf style) or a.b.c.d:port
_IPV4_PORT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:[.:](\d{1,5}))?\b")
# Solaris "[ID 800047 auth.info]" message ids name the message type: keep them
_LONG_NUMBER = re.compile(r"(?<!\[ID )\b\d{6,}\b")


def _mask_ip(match: re.Match) -> str:
    port = match.group(1)
    if port is None:
        return "<IP>"
    # Ephemeral client ports carry no meaning; service ports (22, 3389, 4444) do.
    return "<IP>:<EPH>" if int(port) >= 32768 else f"<IP>:{port}"


def normalise(line: str) -> str:
    text = line.strip()
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = _IPV4_PORT.sub(_mask_ip, text)
    # after IP masking so PF "port 22" style numbers survive; long ids go
    text = re.sub(r"\bport (\d+)\b", lambda m: "port <EPH>" if int(m.group(1)) >= 32768 else m.group(0), text)
    text = _LONG_NUMBER.sub("<NUM>", text)
    return re.sub(r"\s+", " ", text)


def to_sequence(lines: list[str], limit: int = MAX_LINES_PER_SEQUENCE) -> str:
    """Normalise and join lines. Long sequences keep head and tail, like Phase 7."""
    lines = [normalise(line) for line in lines if line and line.strip()]
    if len(lines) > limit:
        head = limit // 2
        tail = limit - head
        lines = lines[:head] + [f"<{len(lines) - limit} MORE>"] + lines[-tail:]
    return SEPARATOR.join(lines)


def split_raw_messages(raw: str) -> list[str]:
    """Phase 7 raw_messages -> list of lines (drops the '... [N more messages]' tail)."""
    raw = re.sub(r"\s*\.\.\. \[\d+ more messages\]\s*$", "", raw or "")
    return [part for part in raw.split(SEPARATOR) if part.strip()]


def write_corpus(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CORPUS_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in CORPUS_COLUMNS})
