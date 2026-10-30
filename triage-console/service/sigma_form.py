"""Sigma's form (Advanced → Sigma, the default way to write a rule): the basic fields of a rule, as Sigma YAML and back.

The form holds what most rules need. Required: a title, the log type (for AUTH, optionally the program) and the field
tests an event must pass (Match: a field, a test and values, any one of which may match; every row must hold). Then
the rows that rule an event out (Except, each on its own), an optional count in a sliding window (at least N events,
or N distinct values of a field, within a time, per group), the level, and under More: status, description, ATT&CK
tags and false positives.

to_yaml() writes the form as Sigma. A count becomes a correlation over the event rule, as the starter rules are
written. to_form() reads a rule back into the form when it has that shape and returns None otherwise (the page then
opens the YAML editor). What the form does not show (a rule's ``name``, ``references``, an event rule's own title)
is carried in ``keep`` and written back unchanged, so opening a rule in the form and accepting it loses nothing.
"""
from __future__ import annotations

import re
from datetime import date

import yaml

from . import event_counts, sigma

OPS = ("is", "contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte")
COMPARE = {"gt", "gte", "lt", "lte"}
AUTH_SERVICES = ("sshd", "su", "sudo", "cron", "login")
PRODUCT = {"auth": "solaris", "ossec": "ossec", "pf": "pf", "ipf": "ipfilter"}
STATUSES = ("experimental", "test", "stable", "deprecated", "unsupported")
REQUIRED = ("title", "source", "match")
# The order of a rule's keys, as SigmaHQ writes them; keys the form does not know go after the ones listed.
ORDER = ("title", "id", "name", "status", "description", "references", "author", "date", "modified", "logsource",
         "detection", "correlation", "fields", "falsepositives", "level", "tags")
FORM_KEYS = {"title", "id", "status", "description", "author", "date", "logsource", "detection", "falsepositives",
             "level", "tags"}
MAX_EVENT_TYPES = 120


class _Dumper(yaml.SafeDumper):
    """Lists indented under their key (``  - item``), as Sigma rules are written."""
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _dump(doc: dict) -> str:
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)


def _ordered(doc: dict) -> dict:
    return {**{k: doc[k] for k in ORDER if k in doc}, **{k: v for k, v in doc.items() if k not in ORDER}}


def event_types() -> dict[str, list[str]]:
    """The event types the console's data holds, per log type (the counts the Dashboard and Sankeys use), without the
    lines no pattern read."""
    try:
        counts = event_counts.load()["counts"]
    except Exception:                                  # no data on this laptop: the form still works, without suggestions
        return {}
    return {source: sorted({t for month in by_month.values() for t in month if "UNKNOWN" not in t})[:MAX_EVENT_TYPES]
            for source, by_month in counts.items()}


# --- the form, as YAML ------------------------------------------------------------------------------------

def _text(value) -> str:
    return "" if value is None else str(value).strip()


def _values(row: dict) -> list:
    out = []
    for v in row.get("values") or []:
        v = _text(v)
        if not v:
            continue
        if row.get("op") in COMPARE:
            number = sigma._number(v)
            if number is None:
                raise ValueError(f"{row.get('field')}: {v!r} is not a number.")
            v = int(number) if number == int(number) else number
        out.append(v)
    return out


def _rows(rows) -> list[tuple[str, list]]:
    """Each complete row as (field|modifier, values)."""
    out = []
    for row in rows or []:
        field, op = _text(row.get("field")), _text(row.get("op")) or "is"
        if op not in OPS:
            raise ValueError(f"Unknown test {op!r}.")
        values = _values(row)
        if field and values:
            out.append((field if op == "is" else f"{field}|{op}", values))
    return out


def _one(values: list):
    return values[0] if len(values) == 1 else values


def _detection(form: dict) -> dict:
    selections: list[dict] = [{}]
    for key, values in _rows(form.get("match")):
        if key in selections[-1]:                     # the same test twice: both must hold, so a second selection
            selections.append({})
        selections[-1][key] = _one(values)
    names = ["selection" if i == 0 else f"selection_{i + 1}" for i in range(len(selections))]
    detection = dict(zip(names, selections))
    excluded = _rows(form.get("exclude"))
    for i, (key, values) in enumerate(excluded, start=1):
        detection[f"filter_{i}"] = {key: _one(values)}
    detection["condition"] = " and ".join(names) + (" and not 1 of filter_*" if excluded else "")
    return detection


def _logsource(form: dict) -> dict:
    source = _text(form.get("source"))
    out = {"product": PRODUCT.get(source, source)}
    if source == "auth" and _text(form.get("service")) in AUTH_SERVICES:
        out["service"] = _text(form["service"])
    return out


def _list(values) -> list[str]:
    return [t for t in (_text(v) for v in values or []) if t]


def _slug(form: dict) -> str:
    return "rule_" + (re.sub(r"[^0-9a-f]", "", _text(form.get("id")).lower())[:8] or "draft")


def missing(form: dict) -> list[str]:
    """The required fields still empty."""
    out = []
    if not _text(form.get("title")):
        out.append("title")
    if _text(form.get("source")) not in PRODUCT:
        out.append("source")
    try:
        if not _rows(form.get("match")):
            out.append("match")
    except ValueError:
        pass
    return out


def to_yaml(form: dict, actor: str = "") -> str:
    """The form as Sigma YAML: one rule, or with a count an event rule and the correlation that counts it."""
    keep = form.get("keep") or {}
    head = {"title": _text(form.get("title")) or "Untitled"}
    if _text(form.get("id")):
        head["id"] = _text(form["id"])
    head["status"] = _text(form.get("status")) if _text(form.get("status")) in STATUSES else "experimental"
    if _text(form.get("description")):
        head["description"] = _text(form["description"])
    head["author"] = _text(form.get("author")) or actor or "local-user"
    head["date"] = _text(form.get("date")) or date.today().isoformat()
    tail = {}
    if _list(form.get("falsepositives")):
        tail["falsepositives"] = _list(form["falsepositives"])
    level = _text(form.get("level")).lower()
    tail["level"] = level if level in sigma.LEVELS else "medium"
    if _list(form.get("tags")):
        tail["tags"] = _list(form["tags"])
    body = {"logsource": _logsource(form), "detection": _detection(form)}
    count = form.get("count")
    if not count:
        return _dump(_ordered({**head, **body, **tail, **(keep.get("rule") or {})}))

    event = dict(keep.get("event") or {})
    name = _text(event.get("name")) or _slug(form)
    event.setdefault("title", f"{head['title']} (event)")
    event["name"] = name
    event.setdefault("status", head["status"])
    event.setdefault("level", "informational")
    within = _text(count.get("within")) or "5m"
    sigma._span(within)                                    # 30s, 5m, 2h or 1d; raises with what to write
    minimum = int(sigma._number(count.get("min")) or 0)
    if minimum < 1:
        raise ValueError("A count needs at least 1.")
    condition = {"gte": minimum}
    distinct = _text(count.get("distinct"))
    if distinct:
        condition["field"] = distinct
    correlation = {"type": "value_count" if distinct else "event_count", "rules": [name]}
    by = _list(count.get("by"))
    if by:
        correlation["group-by"] = by
    correlation["timespan"] = within
    correlation["condition"] = condition
    correlation.update(keep.get("correlation") or {})
    first = _ordered({**event, **body})
    second = _ordered({**head, "correlation": correlation, **tail, **(keep.get("rule") or {})})
    return _dump(first) + "---\n" + _dump(second)


def preview(form: dict, actor: str = "") -> dict:
    """The form's YAML, the required fields still empty, and the rule as the engine reads it (or what is wrong)."""
    text = to_yaml(form, actor)
    out = {"yaml": text, "missing": missing(form)}
    try:
        out["docs"] = [d.summary() for d in sigma.parse(text, 0)]
    except sigma.SigmaError as error:
        out["error"] = str(error)
    return out


# --- a rule, read back into the form ----------------------------------------------------------------------------

def _source_of(raw) -> tuple[str, str] | None:
    if not isinstance(raw, dict):
        return None
    service, product, category = (_text(raw.get(k)).lower() for k in ("service", "product", "category"))
    if category:
        found = sigma.CATEGORIES.get(category, set())
        return (next(iter(found)), "") if len(found) == 1 and not service else None
    if service:
        if service in AUTH_SERVICES and product in ("", "solaris", "linux", "unix"):
            return "auth", service
        found, process = sigma.SERVICES.get(service, (set(), None))
        return (next(iter(found)), "") if len(found) == 1 and process is None else None
    found = sigma.PRODUCTS.get(product, set())
    return (next(iter(found)), "") if len(found) == 1 else None


def _row(key: str, value) -> dict | None:
    field, _, op = str(key).partition("|")
    op = op or "is"
    if op not in OPS or not field:
        return None
    values = value if isinstance(value, list) else [value]
    if not values or any(isinstance(v, (dict, list)) or v is None for v in values):
        return None
    return {"field": field, "op": op, "values": [sigma._text(v) for v in values]}


def _read_detection(detection) -> tuple[list, list] | None:
    """Match and Except rows, when the detection is selections joined by 'and', and rows ruled out each on its own."""
    if not isinstance(detection, dict) or set(detection) & {"timeframe"}:
        return None
    condition = re.sub(r"\s+", " ", _text(detection.get("condition")))
    names = [k for k in detection if k != "condition"]
    if not condition or "(" in condition or " or " in f" {condition.lower()} ":
        return None
    match, exclude, used = [], [], []
    for part in condition.split(" and "):
        negated = part.startswith("not ")
        target = part[4:] if negated else part
        if negated and target.startswith("1 of ") and target.endswith("*"):
            group = [n for n in names if n.startswith(target[5:-1])]
        elif target in names:
            group = [target]
        else:
            return None
        for name in group:
            body = detection[name]
            if not isinstance(body, dict) or not body or (negated and len(body) != 1):
                return None
            rows = [_row(k, v) for k, v in body.items()]
            if None in rows:
                return None
            (exclude if negated else match).extend(rows)
            used.append(name)
    if sorted(used) != sorted(names) or not match:
        return None
    return match, exclude


def _rule_form(doc: dict) -> dict | None:
    if not isinstance(doc, dict) or "correlation" in doc:
        return None
    where = _source_of(doc.get("logsource"))
    rows = _read_detection(doc.get("detection"))
    if where is None or rows is None:
        return None
    tags, falsepositives = doc.get("tags") or [], doc.get("falsepositives") or []
    if isinstance(falsepositives, str):
        falsepositives = [falsepositives]
    if not isinstance(tags, list) or not isinstance(falsepositives, list):
        return None
    return {"id": _text(doc.get("id")), "title": _text(doc.get("title")), "source": where[0], "service": where[1],
            "match": rows[0], "exclude": rows[1], "count": None, "level": _text(doc.get("level")).lower() or "medium",
            "status": _text(doc.get("status")), "description": _text(doc.get("description")),
            "tags": [sigma._text(t) for t in tags], "falsepositives": [sigma._text(f) for f in falsepositives],
            "author": _text(doc.get("author")), "date": sigma._text(doc.get("date")), "keep": {}}


def _extra(doc: dict, known: set[str]) -> dict:
    return {k: v for k, v in doc.items() if k not in known}


def to_form(text: str) -> dict | None:
    """The form for a rule written in YAML, or None when the form cannot show it (several rules, an 'or', a sequence)."""
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError:
        return None
    if len(docs) == 1:
        form = _rule_form(docs[0])
        if form is not None:
            form["keep"] = {"rule": _extra(docs[0], FORM_KEYS | {"title"})}
        return form
    if len(docs) != 2 or not all(isinstance(d, dict) for d in docs):
        return None
    event, rule = docs
    correlation = rule.get("correlation")
    form = _rule_form(event)
    if form is None or not isinstance(correlation, dict) or not _text(event.get("name")):
        return None
    kind, refs = _text(correlation.get("type")).lower(), correlation.get("rules")
    condition = correlation.get("condition")
    if (kind not in ("event_count", "value_count") or refs not in ([event["name"]], event["name"])
            or not isinstance(condition, dict) or set(condition) - {"gte", "gt", "field"} or len(set(condition) - {"field"}) != 1
            or (kind == "value_count") != bool(condition.get("field")) or set(rule) & {"detection", "logsource"}):
        return None
    minimum = sigma._number(condition.get("gte", condition.get("gt")))
    if minimum is None:
        return None
    by = correlation.get("group-by", correlation.get("group_by")) or []
    by = [by] if isinstance(by, str) else by
    meta = _rule_form({**_extra(rule, {"correlation"}), "logsource": event.get("logsource"), "detection": event.get("detection")})
    if meta is None:
        return None
    form.update({k: meta[k] for k in ("id", "title", "level", "status", "description", "tags", "falsepositives", "author", "date")})
    form["count"] = {"min": int(minimum) + (1 if "gt" in condition else 0), "within": sigma._text(correlation.get("timespan", correlation.get("timeframe"))),
                     "by": [sigma._text(b) for b in by], "distinct": _text(condition.get("field"))}
    form["keep"] = {"event": _extra(event, {"logsource", "detection"}),
                    "rule": _extra(rule, FORM_KEYS | {"correlation"}),
                    "correlation": _extra(correlation, {"type", "rules", "group-by", "group_by", "timespan", "timeframe", "condition"})}
    return form
