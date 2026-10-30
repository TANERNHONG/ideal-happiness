"""The report editor's helpers: MITRE ATT&CK, and the local model's two jobs in a report.

* attack(): the offline copy of ATT&CK Enterprise (attack_enterprise.json, built by attack_build.py).
* candidates(): the techniques whose wording is closest to the evidence (TF-IDF over name and
  description, with log words mapped to ATT&CK's terms). Needs no model.
* match_attack(): the local model picks up to three of those candidates and says why. It may only
  choose from the candidates, so it cannot invent a technique ID; anything else it returns is dropped.
* sql_for(): the local model writes one SQLite query for a plain-English question. The query is
  checked by the SQL guardrails but not run: the analyst reads it and runs it (through /api/sql).

The model is the one on this laptop (llm.chat); evidence never leaves it (NFR-SEC-01).
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from . import llm, sql, sql_guard

ATTACK_FILE = Path(__file__).with_name("attack_enterprise.json")
MAX_EVIDENCE = 6000          # characters of evidence sent to the model
CANDIDATES = 15
MATCHES = 3
WORD = re.compile(r"[a-z][a-z0-9]+")
STOP = set("""a an and are as at be been by can could for from has have if in into is it its may might more most
not of on or other such that the their them these they this those to use used using via was were when which while
who will with within without adversaries adversary also""".split())
# Log words, and what ATT&CK calls the same thing
HINTS = {
    "ssh": "remote services ssh", "sshd": "remote services ssh", "login": "valid accounts logon", "logon": "valid accounts",
    "failed": "brute force password guessing", "failure": "brute force password guessing", "invalid": "brute force password guessing",
    "password": "password credentials", "publickey": "ssh authorized keys", "keyboard": "valid accounts", "root": "privileged accounts",
    "sudo": "sudo and sudo caching abuse elevation control mechanism", "su": "abuse elevation control mechanism",
    "pam": "modify authentication process pluggable authentication modules", "cron": "scheduled task cron", "crontab": "scheduled task cron",
    "useradd": "create account local account", "adduser": "create account local account", "passwd": "account manipulation",
    "usermod": "account manipulation", "locked": "account access removal", "scp": "ingress tool transfer", "sftp": "ingress tool transfer",
    "scan": "network service discovery active scanning", "port": "network service discovery", "block": "network service discovery",
    "syscheck": "file and directory permissions modification indicator removal", "integrity": "indicator removal file deletion",
    "rootcheck": "rootkit", "deprecated": "", "reverse": "", "mapping": "",
}


@lru_cache(maxsize=1)
def attack() -> dict:
    return json.loads(ATTACK_FILE.read_text(encoding="utf-8"))


def _words(text: str) -> list[str]:
    return [w for w in WORD.findall(text.lower()) if w not in STOP]


@lru_cache(maxsize=1)
def _index() -> tuple[list[dict], list[Counter], dict[str, float]]:
    techniques = attack()["techniques"]
    docs = [Counter(_words(f"{t['name']} {t['name']} {t['description']}")) for t in techniques]
    df = Counter(w for d in docs for w in d)
    idf = {w: math.log((1 + len(docs)) / (1 + n)) + 1 for w, n in df.items()}
    return techniques, docs, idf


def _vector(counts: Counter, idf: dict[str, float]) -> dict[str, float]:
    v = {w: (1 + math.log(n)) * idf[w] for w, n in counts.items() if w in idf}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    return {w: x / norm for w, x in v.items()}


def candidates(evidence: str, k: int = CANDIDATES) -> list[dict]:
    """The techniques closest in wording to the evidence, best first, each with its score."""
    techniques, docs, idf = _index()
    words = _words(evidence)
    expanded = words + [h for w in words for h in _words(HINTS.get(w, ""))]
    query = _vector(Counter(expanded), idf)
    scored = []
    for t, d in zip(techniques, docs):
        v = _vector(d, idf)
        score = sum(x * v.get(w, 0.0) for w, x in query.items())
        if set(t["platforms"]) & {"Linux", "macOS", "Network Devices"}:          # these logs come from Unix servers and firewalls
            score *= 1.15
        if score > 0:
            scored.append((score, t))
    scored.sort(key=lambda s: -s[0])
    return [{**t, "score": round(s, 4)} for s, t in scored[:k]]


SYSTEM_ATTACK = (
    "You map evidence from security logs to MITRE ATT&CK Enterprise techniques. The evidence is activity that "
    "anomaly-detection models flagged as unusual; it is not confirmed malicious. Choose only from the candidate "
    f"techniques listed, at most {MATCHES}, best first, and only those the evidence actually supports. Reply with JSON: "
    '{"matches": [{"id": "T1110.001", "confidence": "high|medium|low", "reason": "one sentence that cites the evidence"}]}. '
    'If none fits, reply {"matches": []}.')


def match_attack(evidence: str) -> dict:
    evidence = (evidence or "").strip()[:MAX_EVIDENCE]
    if not evidence:
        raise ValueError("Describe the activity, or choose a finding, first.")
    shortlist = candidates(evidence)
    listing = "\n".join(f"{t['id']} {t['name']} [{', '.join(t['tactics'])}]: {t['description'][:300]}" for t in shortlist)
    answer = llm.chat(SYSTEM_ATTACK, f"Evidence:\n{evidence}\n\nCandidate techniques:\n{listing}")
    return {"matches": parse_matches(answer, shortlist), "candidates": [t["id"] for t in shortlist]}


def parse_matches(answer: str, shortlist: list[dict]) -> list[dict]:
    """The model's matches that are among the candidates; anything else is dropped."""
    allowed = {t["id"]: t for t in shortlist}
    try:
        data = json.loads(answer)
    except ValueError:
        return []
    out = []
    for m in (data.get("matches") if isinstance(data, dict) else None) or []:
        tid = str((m or {}).get("id", "")).strip().upper()
        if tid in allowed and tid not in {o["id"] for o in out}:
            confidence = str(m.get("confidence", "")).lower()
            out.append({"id": tid, "confidence": confidence if confidence in ("high", "medium", "low") else "low",
                        "reason": str(m.get("reason", ""))[:400]})
    return out[:MATCHES]


# --- a query for a plain-English question -----------------------------------------------------------

SYSTEM_SQL = (
    "You write one SQLite query for a read-only database of server logs. Use only the tables and columns listed. "
    "Write a single SELECT (or WITH ... SELECT) statement, never anything that changes data. Return at most 200 rows "
    "(use LIMIT) unless the question asks for counts. Times: auth.events and ossec.events have timestamp_text "
    "('YYYY-MM-DD HH:MM:SS', the server's local time) and timestamp_epoch (that local time read as UTC); fw.pf_events "
    "and fw.ipf_events have timestamp as text. host_id (auth) and hostname are the server. The original log line is "
    "original_log_line (auth, ossec) or raw_message (fw). Reply with JSON: "
    '{"sql": "the query", "note": "one sentence on what it returns"}.')


def sql_for(question: str) -> dict:
    question = (question or "").strip()
    if not question:
        raise ValueError("Ask a question first.")
    schema = sql.schema()
    tables = "\n".join(f"{name}({', '.join(columns)})" for name, columns in schema["tables"].items())
    examples = "\n\n".join(f"-- {e['title']}\n{e['sql']}" for e in schema["examples"])
    answer = llm.chat(SYSTEM_SQL, f"Tables:\n{tables}\n\nExamples:\n{examples}\n\nQuestion: {question[:1000]}")
    return checked_sql(answer)


def checked_sql(answer: str) -> dict:
    """The model's query, and whether the SQL guardrails would run it."""
    try:
        data = json.loads(answer)
        query = str(data.get("sql", "")).strip() if isinstance(data, dict) else ""
        note = str(data.get("note", ""))[:300] if isinstance(data, dict) else ""
    except ValueError:
        query, note = answer.strip(), ""
    query = re.sub(r"^```(?:sql)?\s*|\s*```$", "", query).strip()
    if not query:
        raise ValueError("The local model returned no query. Rephrase the question.")
    try:
        sql_guard.check(query)
        rejected = ""
    except sql_guard.QueryRejected as error:
        rejected = str(error)
    return {"sql": query, "note": note, "rejected": rejected}
