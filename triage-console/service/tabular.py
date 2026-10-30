"""Logs that come as a table: one column holds the raw line, the other columns are extra fields.

Exports from log tools often look like this (Splunk's ``_raw``, Elastic's ``message``): a header row,
then one row per event, as CSV (or tab, ``;`` or ``|`` separated) or as an Excel workbook (.xlsx, its
first sheet; read here with the standard library, no Excel package needed).

``check`` looks at the first 100 rows: a header of distinct names and as many values in every row, else
it says which row is not. Patterns then asks which column holds the raw logs and which other columns to
keep; ``layout`` records the answer, with a time column and a host column among those kept when there
are ones. ``records`` reads the rows as (raw line, the kept columns' values). Analyze and Simple mode use
``sniff``, which makes the same choice by itself: a column named for the raw line, else the one a log
parser recognises. Plain log files are left as they are: their first line is not a header of names.
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from datetime import datetime, timedelta
from itertools import islice
from xml.etree import ElementTree

csv.field_size_limit(16 * 1024 * 1024)

DELIMITERS = (",", "\t", ";", "|")
PREVIEW_ROWS = 100            # rows checked before a table is read
# A workbook is a zip of XML, which can unpack to far more than it weighs (a "zip bomb"), and a cell can claim any
# column: parts larger than this are refused, cells past Excel's last column ignored, and the CSV kept under a size.
MAX_PART = 256 * 1024 * 1024  # bytes of one part, unpacked (its declared size; the zip reader stops there)
MAX_COLUMNS = 16_384          # Excel's own limit (column XFD)
MAX_CSV = 64 * 1024 * 1024    # characters of CSV text from one workbook
SAMPLE = PREVIEW_ROWS
HEADER_NAME = re.compile(r"^[\w@.\- /:()#\[\]]{1,64}$")
RAW_NAMES = ("_raw", "raw", "raw_message", "raw_line", "rawline", "raw_log", "message", "msg", "log", "log_line",
             "logline", "line", "event", "event_raw", "original", "text")
TIME_NAMES = ("_time", "@timestamp", "timestamp", "time", "datetime", "date_time", "event_time", "eventtime",
              "event.created", "date", "ts")
HOST_NAMES = ("host", "hostname", "host_name", "host.name", "agent.hostname", "computer", "computername",
              "computer_name", "device", "device_name", "server", "source_host")
TABLE_FILES = (".csv", ".tsv", ".xlsx", ".xls")
DATE = re.compile(r"(?P<y>\d{4})[-/](?P<m>\d{2})[-/](?P<d>\d{2})")
EPOCH = re.compile(r"^\s*(?P<s>\d{10})(?P<ms>\d{3})?(?:\.\d+)?\s*$")
DATEISH = re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\b|^\s*\d{10}(?:\d{3})?(?:\.\d+)?\s*$")


def _key(name: str) -> str:
    return name.strip().lstrip("﻿").lower()


def names_of(row: list[str]) -> list[str]:
    return [cell.strip().lstrip("﻿") for cell in row]


def is_table_file(name: str) -> bool:
    return name.lower().endswith(TABLE_FILES)


# --- the first rows: is it a table, and a well-formed one -------------------------------------------

def header_problem(names: list[str]) -> str | None:
    if len(names) < 2:
        return "The first row has one column only: not a table with a header."
    for j, name in enumerate(names):
        if not name:
            return f"Column {j + 1} of the first row has no name."
        if not HEADER_NAME.match(name):
            return "The first row is not a header of column names."
    seen = set()
    for name in names:
        if _key(name) in seen:
            return f"Two columns are called {name!r}."
        seen.add(_key(name))
    return None


def rows_problem(body: list[list[str]], width: int) -> str | None:
    """Every row with as many values as the header (empty values past the end are allowed)."""
    if not body:
        return "No rows under the header."
    for k, row in enumerate(body):
        if len(row) < width or any(cell.strip() for cell in row[width:]):
            return f"Row {k + 2} has {len(row)} values; the header has {width}."
    return None


def delimiter_of(lines: list[str], name: str = "") -> str | None:
    """The separator that makes the first line a header and most rows as wide as it; None when none does."""
    if name.lower().endswith(".tsv"):
        return "\t"
    best = None
    for delimiter in DELIMITERS:
        rows = list(islice(csv.reader(lines, delimiter=delimiter), PREVIEW_ROWS + 1))
        if not rows:
            continue
        names = names_of(rows[0])
        if header_problem(names):
            continue
        body = rows[1:]
        fit = sum(len(r) == len(names) for r in body) / len(body) if body else 0
        score = (fit, len(names))
        if best is None or score > best[0]:
            best = (score, delimiter)
    return best[1] if best else None


TYPES = (                                       # the first a column's every value fits, else text
    ("integer", re.compile(r"^[+-]?\d+$")),
    ("decimal", re.compile(r"^[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?$")),
    ("true/false", re.compile(r"^(?:true|false|yes|no)$", re.I)),
    ("IP address", re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:[:,]\d+)?$")),
    ("date/time", re.compile(                    # the whole value a date or time (not a log line with one in it)
        r"^(?:\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?)?"
        r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:,?\s+\d{4})?(?:\s+\d{2}:\d{2}(?::\d{2})?)?"
        r"|\d{1,2}/\d{1,2}/\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?)?"
        r"|\d{10}(?:\d{3})?(?:\.\d+)?)$", re.I)),
)
HEAD = 5                                         # values shown per column, as a table's head()


def column_type(values: list[str]) -> str:
    """What a column holds, from its non-empty values: integer, decimal, true/false, IP address, date/time or
    text; empty when it has none."""
    filled = [v.strip() for v in values if v.strip()]
    if not filled:
        return "empty"
    for name, pattern in TYPES:
        if all(pattern.search(v) for v in filled):
            return name
    return "text"


def check(rows: list[list[str]], fmt: str, delimiter: str = "", header: str = "", recognise=None) -> dict:
    """The first rows of a table (the header first), checked: its columns with their type and first values, the
    column that holds the raw logs when it is clear (named for it, or a log parser knows its values), and the
    problem that stops it being read, if any."""
    names = names_of(rows[0]) if rows else []
    body = [r for r in rows[1:PREVIEW_ROWS + 1]]
    problem = header_problem(names) or rows_problem(body, len(names))
    columns = []
    for j, n in enumerate(names):
        values = [r[j] if j < len(r) else "" for r in body]
        columns.append({"name": n, "type": column_type(values), "head": [v[:120] for v in values[:HEAD]],
                        "sample": next((v for v in values if v.strip()), "")[:160]})
    return {"table": True, "format": fmt, "delimiter": delimiter, "header": header, "columns": columns,
            "rows": len(body), "problem": problem,
            "raw": "" if problem else clear_raw(names, [r[:len(names)] for r in body], recognise)}


def clear_raw(names: list[str], body: list[list[str]], recognise=None) -> str:
    """The raw-log column when it is clear: named for it, else the one whose values a log parser knows best."""
    keys = [_key(n) for n in names]
    named = next((names[keys.index(o)] for o in RAW_NAMES if o in keys), "")
    if named or not recognise or not body:
        return named
    known = [recognise([r[j] for r in body]) for j in range(len(names))]
    return names[known.index(max(known))] if max(known) else ""


def layout(fmt: str, delimiter: str, header: str, names: list[str], raw: str, fields: list[str] | None,
           body: list[list[str]]) -> dict:
    """How to read the table: the raw-log column, the columns kept as fields (all others when None), and among
    them a time column (named, or dates in 80% of the rows) and a host column (named)."""
    if raw not in names:
        raise ValueError(f"No column called {raw!r}.")
    kept = [n for n in (names if fields is None else fields) if n in names and n != raw]
    keys = {n: _key(n) for n in kept}
    time = next((n for o in TIME_NAMES for n in kept if keys[n] == o), "")
    if not time and body:
        time = next((n for n in kept if sum(bool(DATEISH.search(r[names.index(n)])) for r in body
                                            if len(r) > names.index(n)) >= 0.8 * len(body)), "")
    host = next((n for o in HOST_NAMES for n in kept if keys[n] == o), "")
    return {"format": fmt, "delimiter": delimiter, "header": header, "columns": names, "raw": raw,
            "time": time, "host": host, "fields": kept}


def sniff(lines: list[str], raw: str = "", recognise=None) -> dict | None:
    """For Analyze and Simple mode: the layout of a table given as text (the header first), keeping every
    column; the raw-log column is ``raw``, else the clear one, else the one that reads most like log lines.
    None for a plain log (or a table whose first rows are not well formed)."""
    lines = [line for line in lines[:PREVIEW_ROWS + 1] if line.strip()]
    if len(lines) < 2:
        return None
    delimiter = delimiter_of(lines)
    if delimiter is None:
        return None
    rows = list(csv.reader(lines, delimiter=delimiter))
    names = names_of(rows[0])
    body = [r for r in rows[1:] if len(r) == len(names)]
    if len(body) < 0.9 * (len(rows) - 1):
        return None
    if raw not in names:
        raw = clear_raw(names, body, recognise) or max(names, key=lambda n: _looks_like_lines([r[names.index(n)] for r in body]))
    return layout({",": "CSV", "\t": "TSV"}.get(delimiter, "Table"), delimiter, lines[0], names, raw, None, body)


def _looks_like_lines(values: list[str]):
    return (sum(v.count(" ") for v in values) / max(1, len(values)), sum(map(len, values)) / max(1, len(values)))


# --- reading the rows --------------------------------------------------------------------------------

def is_header(row_or_line, table: dict) -> bool:
    """Is this the table's header (a row of cells, or a line of text)?"""
    if isinstance(row_or_line, str):
        if not table["delimiter"]:
            return False
        row_or_line = next(csv.reader([row_or_line.rstrip("\r\n")], delimiter=table["delimiter"]), [])
    return names_of(row_or_line[:len(table["columns"])]) == table["columns"]


def records_from_rows(rows, table: dict):
    """(raw line, the kept columns' values) per row; header rows and rows without a raw line are skipped, and a
    raw line spanning lines is joined with spaces."""
    names = table["columns"]
    at = names.index(table["raw"])
    keep = [names.index(f) for f in table["fields"]]
    for row in rows:
        if len(row) <= at or is_header(row, table):
            continue
        line = " ".join(row[at].split("\n")).replace("\r", "")
        if line.strip():
            yield line, tuple(row[j] if j < len(row) else "" for j in keep)


def records(lines, table: dict):
    """The same from text lines (line ends kept, so quoted values may span lines)."""
    return records_from_rows(csv.reader(lines, delimiter=table["delimiter"]), table)


def text_records(text: str, table: dict):
    return records(io.StringIO(text, newline=""), table)


def raw_lines(text: str, table: dict) -> list[str]:
    return [line for line, _ in text_records(text, table)]


def date_of(value: str):
    """The day of a time field: ISO or slashed dates, Unix seconds or milliseconds; None otherwise."""
    found = DATE.search(value)
    if found:
        return f"{found['y']}-{found['m']}-{found['d']}"
    found = EPOCH.match(value)
    if found:
        try:
            return datetime.fromtimestamp(int(found["s"])).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return None
    return None


# --- Excel workbooks (.xlsx) ----------------------------------------------------------------------------

MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
RELS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
DOC_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
DATE_FORMATS = {14, 15, 16, 17, 18, 19, 20, 21, 22, 45, 46, 47}       # Excel's built-in date and time formats
EXCEL_EPOCH = datetime(1899, 12, 30)


def _first_sheet(book: zipfile.ZipFile) -> str:
    try:
        with _part(book, "xl/workbook.xml") as handle:
            workbook = ElementTree.fromstring(handle.read())
        first = workbook.find(f"{MAIN}sheets/{MAIN}sheet")
        rel = first.get(f"{DOC_REL}id")
        with _part(book, "xl/_rels/workbook.xml.rels") as handle:
            relations = ElementTree.fromstring(handle.read())
        for item in relations.iter(f"{RELS}Relationship"):
            if item.get("Id") == rel:
                target = item.get("Target", "")
                return target.lstrip("/") if target.startswith("/") else f"xl/{target}"
    except (KeyError, AttributeError, ElementTree.ParseError):
        pass
    sheets = sorted(n for n in book.namelist() if n.startswith("xl/worksheets/") and n.endswith(".xml"))
    if not sheets:
        raise ValueError("No worksheet in this workbook.")
    return sheets[0]


def capped(raw) -> bytes:
    """A workbook's bytes from a stream (a file, or a member of a ZIP), refusing one larger than MAX_PART."""
    data = raw.read(MAX_PART + 1)
    if len(data) > MAX_PART:
        raise ValueError("A workbook larger than 256 MB: save it as CSV instead.")
    return data


def _part(book: zipfile.ZipFile, name: str):
    """One part of the workbook, opened for reading, if its unpacked size is within MAX_PART."""
    if book.getinfo(name).file_size > MAX_PART:
        raise ValueError("This workbook unpacks to more than 256 MB in one part: save it as CSV instead.")
    return book.open(name)


def _shared_strings(book: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in book.namelist():
        return []
    out = []
    with _part(book, "xl/sharedStrings.xml") as handle:
        for _, item in ElementTree.iterparse(handle):
            if item.tag == f"{MAIN}si":
                out.append("".join(t.text or "" for t in item.iter(f"{MAIN}t")))
                item.clear()
    return out


def _date_styles(book: zipfile.ZipFile) -> set[int]:
    """The cell styles that show a number as a date or time."""
    if "xl/styles.xml" not in book.namelist():
        return set()
    with _part(book, "xl/styles.xml") as handle:
        styles = ElementTree.fromstring(handle.read())
    custom = {int(f.get("numFmtId")): f.get("formatCode", "") for f in styles.iter(f"{MAIN}numFmt")}

    def is_date(code: str) -> bool:
        code = re.sub(r'"[^"]*"|\[[^\]]*\]|\\.', "", code).lower()
        return bool(re.search(r"[dyhs]", code)) and "general" not in code

    xfs = styles.find(f"{MAIN}cellXfs")
    out = set()
    for index, xf in enumerate(xfs if xfs is not None else []):
        fmt = int(xf.get("numFmtId", "0"))
        if fmt in DATE_FORMATS or (fmt in custom and is_date(custom[fmt])):
            out.add(index)
    return out


def _column(ref: str) -> int:
    """The column of a cell reference ("C7" → 2); past Excel's last column, MAX_COLUMNS (the cell is ignored)."""
    n = 0
    for ch in ref:
        if not ("A" <= ch.upper() <= "Z"):
            break
        n = n * 26 + ord(ch.upper()) - 64
        if n > MAX_COLUMNS:
            return MAX_COLUMNS
    return n - 1


def _cell(cell, shared: list[str], dates: set[int]) -> str:
    kind = cell.get("t", "n")
    if kind == "inlineStr":
        return "".join(t.text or "" for t in cell.iter(f"{MAIN}t"))
    found = cell.find(f"{MAIN}v")
    text = found.text if found is not None and found.text else ""
    if kind == "s":
        return shared[int(text)] if text.isdigit() and int(text) < len(shared) else ""
    if kind == "b":
        return "TRUE" if text == "1" else "FALSE"
    if kind != "n" or not text:
        return text
    try:
        number = float(text)
    except ValueError:
        return text
    if int(cell.get("s", "0")) in dates:
        moment = EXCEL_EPOCH + timedelta(days=number)
        return moment.strftime("%Y-%m-%d") if number.is_integer() else moment.strftime("%Y-%m-%d %H:%M:%S")
    return str(int(number)) if number.is_integer() and abs(number) < 1e15 else text


def xlsx_rows(source):
    """The rows of an Excel workbook's first sheet as text (``source``: a path or a binary file): strings, numbers
    (whole ones without .0), TRUE/FALSE, dates and times as ISO text. Empty rows are skipped."""
    try:
        book = zipfile.ZipFile(source)
    except zipfile.BadZipFile:
        raise ValueError("Not an .xlsx workbook. An older .xls one: save it as .xlsx or .csv.") from None
    with book:
        shared, dates = _shared_strings(book), _date_styles(book)
        with _part(book, _first_sheet(book)) as handle:
            for _, row in ElementTree.iterparse(handle):
                if row.tag != f"{MAIN}row":
                    continue
                cells = {}
                for cell in row.iter(f"{MAIN}c"):
                    ref = cell.get("r", "")
                    column = _column(ref) if ref else len(cells)
                    if column < MAX_COLUMNS:
                        cells[column] = _cell(cell, shared, dates)
                row.clear()
                if any(v.strip() for v in cells.values()):
                    yield [cells.get(j, "") for j in range(max(cells) + 1)]


def xlsx_text(source) -> str:
    """An Excel workbook's first sheet as CSV text."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for row in xlsx_rows(source):
        writer.writerow(row)
        if out.tell() > MAX_CSV:
            raise ValueError("This workbook holds more than 64 MB of text: save it as CSV and use the file on this laptop.")
    return out.getvalue()
