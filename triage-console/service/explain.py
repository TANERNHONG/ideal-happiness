"""Explain (FR-EXP): why each Phase 4g activity alert was raised, in pictures and plain words.

The explanations are computed by the pipeline (pipeline/phase4_detection/activity_explain.py) and written to
data/phase4_detection/<source>/activity/<view>/explanations.jsonl, one record per alert: a headline, ranked
reasons with their numbers, the alert's day against its usual band, its week as a heatmap beside a usual week,
and 56 days of daily totals. This module lists and serves them; the page draws them.

* items(source)             one entry per incident (activity.incident_items), its lead alert's record and the
                            incident's members, most unusual first
* item(source, view, id)    one record, with the alert's lines, any saved rewording, and the summary of its
                            supporting evidence (activity_explain.summary) for Summarize evidence
* reword(...)               the record's facts in plainer words from the local model (llm.chat). Every number in
                            the answer must appear in the facts; otherwise the answer is refused and the
                            pipeline's own wording stays. Accepted answers are kept in var/cache/explain_reword.json.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading

from . import activity, llm, store
from .config import CACHE, load_settings
from .pipeline_code import module

REWORD_FILE = CACHE / "explain_reword.json"
NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")
MAX_REWORD = 900
_lock = threading.Lock()
SYSTEM = ("You rewrite short facts about computer log activity for a reader who does not work with logs. "
          "Write two to four short, plain sentences in British English. Use only the facts given: keep every number "
          "exactly as written, add no numbers, causes, guesses, judgements or advice, and do not say whether it is "
          "an attack. Plain text only, no lists or headings.")


def records(source: str, view: str) -> dict[str, dict]:
    return activity.explanations(source, view)


def items(source: str) -> list[dict]:
    """Each activity alert that has an explanation, as the list shows it."""
    out = []
    for item in activity.incident_items(source):
        record = records(source, item["view"]).get(item["item_id"])
        if record:
            big = record["big"]
            out.append({k: item[k] for k in ("item_id", "view", "view_label", "rank", "name", "entity_type", "entity",
                                             "peak", "first_seen", "last_seen")}
                       | {"headline": record["headline"], "when": record["when"],
                          "observed": big["observed"], "median": (big.get("usual") or {}).get("median", 0),
                          "window_minutes": big["window_minutes"],
                          "in_training": (record["context"].get("history") or {}).get("in_training", first_known(record)),
                          "mix": record["big"].get("mix", record["reasons"][0]["kind"] == "combination"),
                          "direction": record["big"].get("direction", "higher"),
                          "little_history": record["big"]["little_history"], "holiday": record["context"]["holiday"],
                          "incident": item.get("incident")})
    return out


def first_known(record: dict) -> bool:
    """For records written before history was kept: whether the series had any line by the end of training, judged
    from the 56 daily totals (None before the series appears). True when that cannot be told."""
    daily = record.get("daily") or {}
    dates, totals = daily.get("dates") or [], daily.get("totals") or []
    first = next((d for d, t in zip(dates, totals) if t is not None), None)
    return True if first is None or first == dates[0] else first < daily.get("train_end", "")


def _reworded() -> dict:
    try:
        return json.loads(REWORD_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _key(source: str, view: str, record: dict, model: str) -> str:
    digest = hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    return f"{source}/{view}/{record['row_manifest_id']}/{digest}/{model}"


def item(source: str, view: str, row_id: str) -> dict:
    record = records(source, view).get(row_id)
    if record is None:
        raise KeyError("No explanation for this alert. Run Phase 4g again to write one.")
    alert = activity.observation(source, view, row_id)
    model = load_settings()["llm_model"]
    saved = _reworded().get(_key(source, view, record, model))
    return {**record, "source": source, "lines": alert["lines"], "line_count": alert["line_count"],
            "reworded": saved, "model": model, "summary": module("phase4_detection/activity_explain.py").summary(record)}


def facts(record: dict) -> str:
    """The record's facts as plain sentences: what the model may reword, and the numbers it must keep."""
    when = record["when"]
    day = when["holiday"] and f"a public holiday ({when['holiday']})" or when["day_words"]
    lines = [record["headline"] + ".", f"It happened on {when['weekday']} {when['date']}, {when['clock']}, {day}."]
    lines += [r["text"] for r in record["reasons"]]
    if record["context"]["change_windows"]:
        lines.append("It falls inside an approved change window.")
    return "\n".join(lines)


def _numbers(text: str) -> set[str]:
    return {n.replace(",", "").rstrip(".") for n in NUMBER.findall(text)}


def check(original: str, answer: str) -> str:
    """The answer, if it keeps to the facts' numbers; a ValueError otherwise."""
    answer = " ".join(answer.split())
    if not answer or len(answer) > MAX_REWORD:
        raise ValueError("The local model's wording was empty or too long, so the original wording is kept.")
    extra = _numbers(answer) - _numbers(original)
    if extra:
        raise ValueError("The local model's wording changed a number, so the original wording is kept.")
    return answer


def reword(source: str, view: str, row_id: str, actor: str) -> dict:
    record = records(source, view).get(row_id)
    if record is None:
        raise KeyError("No explanation for this alert.")
    model = load_settings()["llm_model"]
    original = facts(record)
    text = check(original, llm.chat(SYSTEM, original, json_mode=False, timeout=120.0))
    saved = {"text": text, "model": model}
    with _lock:
        cache = _reworded()
        cache[_key(source, view, record, model)] = saved
        REWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = REWORD_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(cache, indent=1), encoding="utf-8")
        temporary.replace(REWORD_FILE)
    store.log_action(actor, "explain_reword", f"{source}/{view}/{row_id}", {"model": model, "characters": len(text)})
    return saved
