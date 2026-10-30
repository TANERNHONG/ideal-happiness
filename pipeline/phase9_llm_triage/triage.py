"""Phase 9: sort alerts into four triage categories with a local small language model.

  python pipeline/phase9_llm_triage/triage.py --source auth --dry-run --limit 5
  python pipeline/phase9_llm_triage/triage.py --source auth --model qwen2.5:3b-instruct --limit 50
  python pipeline/phase9_llm_triage/triage.py --source ossec --representatives \\
      --inputs "data/phase8_malice_classifier/to_label/ossec/*_to_label.csv"

Categories: security_relevant, operationally_interesting, expected_behavior,
insufficient_context (defined in backend/app/prompts/triage_categories.md).

Inputs
    Phase 7 alert CSVs (default), or Phase 8 labelling sheets with
    --representatives to triage one row per cluster. Identical message chains
    are triaged once; the most unusual come first.
Trusted site context (site/, see its README)
    approved_automation_ips.csv   addresses or CIDR ranges of approved
                                  administrative automation, placed in the
                                  system prompt; each alert also states which
                                  of them appear in its lines
    approved_change_windows.csv   planned changes (e.g. a migration): time window,
                                  hosts and flow; placed in the system prompt, and
                                  each alert states how many of its lines fall
                                  inside each window and match its flow
    site_context.md               optional free text for the alert's SITE CONTEXT
Prompt
    system = shared_rules.md + approved_automation.md + approved_change_windows.md
             + triage_categories.md
    user   = alert_context.md, with the source primer and the few knowledge
             entries most similar to the lines (a small model cannot take all)
Model
    Any OpenAI-compatible chat endpoint on this machine: Ollama (default,
    http://localhost:11434/v1), llama.cpp server, LM Studio or vLLM. Any other
    address is refused, and redirects are not followed. Answers are
    validated; one repair attempt is made with repair_json.md.
Output
    data/phase9_llm_triage/<source>/triage.csv, one row per alert, written as it
    goes so an interrupted run resumes. analyst_category is left blank for the
    analyst to confirm; Phase 8 trains on that column. --dry-run writes the
    prompts to prompts/ and calls no model.
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import ipaddress
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

HERE = Path(__file__).resolve().parent
PROMPTS = HERE / "backend" / "app" / "prompts"
KNOWLEDGE = HERE / "backend" / "app" / "knowledge"
SITE = HERE / "site"
CATEGORIES = ("security_relevant", "operationally_interesting", "expected_behavior", "insufficient_context")
SOURCES = {
    "auth": {"prefix": "authlog", "label": "authentication (Solaris syslog)", "primer": "auth.md",
             "patterns": "attack_patterns_auth.md", "herring": "RH-AUTH-"},
    "ossec": {"prefix": "ossec", "label": "OSSEC agent", "primer": "ossec.md",
              "patterns": "attack_patterns_ossec.md", "herring": "RH-OSSEC-"},
    "pf": {"prefix": "pflog", "label": "PF firewall", "primer": "pf.md",
           "patterns": "attack_patterns_pf.md", "herring": "RH-PF-"},
    "ipf": {"prefix": "ipflog", "label": "IPFilter firewall (Solaris ipmon; empty in normal operation)",
            "primer": "ipf.md", "patterns": "attack_patterns_ipf.md", "herring": "RH-IPF-"},
}
ALERT_TYPES = {"robust": "Robust deviation", "isolation_forest": "Isolation Forest", "novelty": "Novelty",
               "model_zoo_consensus": "Model-zoo consensus", "presence": "Presence (empty baseline)",
               "silence": "Silence (host up, log empty)", "first_seen": "First seen on this host",
               "activity": "Activity (amounts and timing, content ignored)"}
RANKED_TYPES = ("presence", "silence", "first_seen", "activity")     # probability is a rank among these alerts
VIEWS = {
    "individual": "a single log event", "host_5min": "all events from one host in a five-minute window",
    "host_behavior_1d": "one host's activity over a day",
    "authentication_sessions": "one SSH connection or local login attempt",
    "episodes": "one OSSEC agent activity (a scan, an outage, a restart)",
    "sessions": "one PF service conversation between two hosts",
    "slots_1d": "all of one host's firewall log lines on one day (a log that is empty in normal operation)",
    "slots_1h": "all of one host's firewall log lines in one hour",
    "slots_5min": "all of one host's firewall log lines in five minutes",
    "flow_episodes": "a run of connection attempts on one flow (source, destination, port, protocol) with no pause "
                     "over 30 minutes",
    "silence_episodes": "a run of days on which this log has nothing from a host while other logs show the host was "
                        "up; the single line is a description written by the pipeline, not a log line",
    "first_seen_pairs": "something a host showed for the first time in the test period (an event type, a login "
                        "source address or account); the first line is a description written by the pipeline, the "
                        "rest are the first log lines",
    "activity": "an unusual amount of activity in this whole log over one or more five-minute steps, judged on "
                "counts and timing only; the first line is a description written by the pipeline, the rest are the "
                "first log lines of the busiest step",
    "activity_by_entity": "an unusual amount of activity for one server, source IP, username or destination IP over "
                          "one or more five-minute steps, judged against that entity's own history on counts and "
                          "timing only; the first line is a description written by the pipeline, the rest are the "
                          "first log lines of the busiest step",
}
MAX_LINES = 40              # head and tail kept when longer
MAX_LINE_CHARS = 400
KNOWLEDGE_PATTERNS, KNOWLEDGE_HERRINGS = 3, 2
IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
OUTPUT_FIELDS = ["alert_id", "source", "probability", "alert_types", "flagged_by", "dataset", "clusters", "line_count",
                 "category", "confidence", "reasoning", "key_lines", "approved_automation_involved",
                 "approved_addresses_in_lines", "missing_context", "attack_technique", "next_step",
                 "knowledge_ids", "status", "error", "model", "prompt_version", "triaged_at", "analyst_category",
                 "analyst_notes", "raw_messages"]


def csv_field_limit():
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


log = runlog.log


# --- inputs ----------------------------------------------------------------------


def alert_type_of(path):
    match = re.search(r"_cumulative_(.+?)_alerts", Path(path).name)
    return ALERT_TYPES.get(match.group(1), match.group(1)) if match else ""


def load_alerts(patterns, representatives):
    """One entry per distinct message chain, most unusual first."""
    alerts = {}
    paths = sorted({path for pattern in patterns for path in glob.glob(pattern)})
    for path in paths:
        with open(path, encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if representatives and str(row.get("representative", "")).strip() not in ("1", "True", "true"):
                    continue
                raw = (row.get("raw_messages") or "").strip()
                if not raw:
                    continue
                entry = alerts.setdefault(raw, {"raw_messages": raw, "probability": 0.0, "alert_types": [],
                                                "flagged_by": [], "dataset": [], "clusters": []})
                try:
                    entry["probability"] = max(entry["probability"], float(row.get("rank") or row.get("probability") or 0))
                except ValueError:
                    pass
                for key, value in (("alert_types", alert_type_of(path)), ("flagged_by", row.get("flagged_by")),
                                   ("dataset", row.get("dataset")), ("clusters", row.get("cluster_id"))):
                    for item in str(value or "").split("; "):
                        if item and item not in entry[key]:
                            entry[key].append(item)
    ordered = sorted(alerts.values(), key=lambda entry: -entry["probability"])
    for entry in ordered:
        entry["alert_id"] = hashlib.sha1(entry["raw_messages"].encode("utf-8")).hexdigest()[:16]
    return ordered, paths


def load_approved(path):
    """[(network, owner, purpose)] from the analysts' CSV; bad rows are reported and skipped."""
    approved = []
    if not path.is_file():
        return approved
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for number, row in enumerate(csv.DictReader(handle), start=2):
            address = (row.get("address") or "").strip()
            if not address or address.startswith("#"):
                continue
            try:
                approved.append((ipaddress.ip_network(address, strict=False),
                                 (row.get("owner") or "").strip(), (row.get("purpose") or "").strip()))
            except ValueError:
                runlog.emit(f"{path.name} line {number}: not an IP address or range; skipped", "WARNING")
    return approved


def approved_in(lines, approved):
    """Approved entries whose network contains an address in the lines (PF a.b.c.d.port handled)."""
    found = {}
    for line in lines:
        for candidate in IPV4.findall(line):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            for network, owner, purpose in approved:
                if address in network:
                    found[str(address)] = (str(network), owner, purpose)
    return found


ISO_TIME = re.compile(r"(\d{4})[-/](\d\d)[-/](\d\d)[ T](\d\d):(\d\d):(\d\d)")
SYSLOG_TIME = re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2}) (\d\d):(\d\d):(\d\d)\b")
MONTH_NUMBER = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def load_change_windows(path):
    """Planned changes from the analysts' CSV: time window plus optional hosts and flow."""
    windows = []
    if not path.is_file():
        return windows
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for number, row in enumerate(csv.DictReader(handle), start=2):
            start, end = (row.get("start") or "").strip(), (row.get("end") or "").strip()
            if not start or start.startswith("#"):
                continue
            try:
                window = {"start": datetime.fromisoformat(start), "end": datetime.fromisoformat(end),
                          "hosts": {h.strip() for h in (row.get("hosts") or "").split(";") if h.strip()},
                          "port": (row.get("port") or "").strip(), "protocol": (row.get("protocol") or "").strip().lower(),
                          "change_ref": (row.get("change_ref") or "").strip() or f"line {number}",
                          "description": (row.get("description") or "").strip()}
                for side in ("source", "destination"):
                    value = (row.get(side) or "").strip()
                    window[side] = ipaddress.ip_network(value, strict=False) if value else None
            except ValueError as problem:
                runlog.emit(f"{path.name} line {number}: not an address, range or time; skipped", "WARNING")
                continue
            windows.append(window)
    return windows


def line_times(line, years):
    """Times a line may carry: an ISO or OSSEC timestamp, or a syslog date tried in each candidate year."""
    match = ISO_TIME.search(line)
    if match:
        return [datetime(*map(int, match.groups()))]
    match = SYSLOG_TIME.search(line)
    if not match:
        return []
    month, day, hour, minute, second = match.groups()
    times = []
    for year in years:
        try:
            times.append(datetime(year, MONTH_NUMBER[month], int(day), int(hour), int(minute), int(second)))
        except ValueError:
            pass
    return times


def in_window(line, window):
    if not any(window["start"] <= when <= window["end"]
               for when in line_times(line, {window["start"].year, window["end"].year})):
        return False
    if window["hosts"] and not any(re.search(rf"\b{re.escape(host)}\b", line) for host in window["hosts"]):
        return False
    addresses = []
    for candidate in IPV4.findall(line):
        try:
            addresses.append(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    for side in ("source", "destination"):     # address order differs between formats, so either position
        if window[side] is not None and not any(address in window[side] for address in addresses):
            return False
    if window["port"] and not re.search(rf"(?:[,.:]|port ){re.escape(window['port'])}\b", line):
        return False
    if (window["protocol"] and re.search(r"\b(?:tcp|udp|icmp)\b", line, re.IGNORECASE)
            and not re.search(rf"\b{re.escape(window['protocol'])}\b", line, re.IGNORECASE)):
        return False
    return True


def windows_in(lines, windows):
    """{change_ref: (lines inside the window and matching its flow, window)} for windows with any match."""
    found = {}
    for window in windows:
        count = sum(in_window(line, window) for line in lines)
        if count:
            found[window["change_ref"]] = (count, window)
    return found


def describe_window(window):
    flow = ", ".join(part for part in (
        f"hosts {'; '.join(sorted(window['hosts']))}" if window["hosts"] else "",
        f"from {window['source']}" if window["source"] else "",
        f"to {window['destination']}" if window["destination"] else "",
        f"port {window['port']}" if window["port"] else "", window["protocol"]) if part) or "any host or flow"
    return (f"{window['change_ref']}: {window['start']:%Y-%m-%d %H:%M} to {window['end']:%Y-%m-%d %H:%M}, {flow}"
            + (f"; {window['description']}" if window["description"] else ""))


def change_windows_text(windows):
    if not windows:
        return "(No change windows have been recorded.)"
    return "\n".join(f"- {describe_window(window)}" for window in windows)


# --- prompt ----------------------------------------------------------------------


def read_prompt(name):
    return (PROMPTS / name).read_text(encoding="utf-8").strip()


def fill(template, values):
    """Plain replacement: the templates contain JSON braces, so never str.format."""
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", str(value))
    return template


def prepare_lines(raw):
    tail = re.search(r"\.\.\. \[([\d,]+) more messages\]\s*$", raw)
    parts = [part for part in re.sub(r"\s*\.\.\. \[[\d,]+ more messages\]\s*$", "", raw).split(" | ") if part.strip()]
    cleaned = []
    for part in parts:
        part = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", part)
        part = "".join(ch for ch in part if ch == "\t" or ch >= " ")
        part = part.replace("<<<", "‹‹‹").replace(">>>", "›››")
        cleaned.append(part if len(part) <= MAX_LINE_CHARS else part[:MAX_LINE_CHARS] + " …")
    notes = []
    if len(cleaned) > MAX_LINES:
        head = MAX_LINES // 2
        omitted = len(cleaned) - MAX_LINES
        cleaned = cleaned[:head] + cleaned[-(MAX_LINES - head):]
        notes.append(f"{omitted:,} lines from the middle of the chain were omitted; the first {head} and last "
                     f"{MAX_LINES - head} are shown, and lines {head} and {head + 1} are not consecutive.")
    if tail:
        notes.append(f"Phase 7 had already truncated the chain: {tail.group(1)} further messages exist.")
    return cleaned, " ".join(notes)


def load_knowledge(source):
    """Attack patterns of this log source and its red herrings, as (id, text) entries."""
    entries = []
    spec = SOURCES[source]
    for name, keep in ((spec["patterns"], lambda identifier: True),
                       ("red_herrings.md", lambda identifier: identifier.startswith(spec["herring"]))):
        path = KNOWLEDGE / name
        if not path.is_file():
            continue
        for block in re.split(r"(?m)^(?=### )", path.read_text(encoding="utf-8")):
            match = re.match(r"### ([A-Z]+(?:-[A-Z]+)?-\d+)", block)
            if match and keep(match.group(1)):
                text = re.split(r"(?m)^## ", block)[0].strip()
                entries.append((match.group(1), text))
    return entries


class KnowledgeSelector:
    """Picks the entries most similar to an alert's lines (TF-IDF cosine)."""

    def __init__(self, entries):
        self.entries = entries
        self.vectorizer = self.matrix = None
        if entries:
            from sklearn.feature_extraction.text import TfidfVectorizer
            self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
            self.matrix = self.vectorizer.fit_transform(text for _, text in entries)

    def select(self, lines):
        if self.matrix is None:
            return []
        scores = (self.matrix @ self.vectorizer.transform([" ".join(lines)]).T).toarray().ravel()
        ranked = sorted(range(len(self.entries)), key=lambda index: -scores[index])
        chosen, patterns, herrings = [], 0, 0
        for index in ranked:
            identifier = self.entries[index][0]
            if scores[index] <= 0.02:
                break
            if identifier.startswith("RH-") and herrings < KNOWLEDGE_HERRINGS:
                herrings += 1
                chosen.append(self.entries[index])
            elif not identifier.startswith("RH-") and patterns < KNOWLEDGE_PATTERNS:
                patterns += 1
                chosen.append(self.entries[index])
        return chosen


def compact_flagged_by(items):
    """Detector names as given; model-zoo vote lists shortened to the largest agreement."""
    detectors, most = [], 0
    for item in items:
        match = re.search(r"\((\d+) models?\)\s*$", item)
        if match:
            most = max(most, int(match.group(1)))
        elif item not in detectors:
            detectors.append(item)
    if most:
        detectors.append(f"model zoo (up to {most} of 13 models agreed)")
    return "; ".join(detectors) or "unknown"


def describe_view(view):
    """Phase 7 dataset value, e.g. 'host_5min (selected features)' or 'entity_5min__with_active_span'."""
    base = view.split(" (")[0].split("__")[0]
    if base in VIEWS:
        return VIEWS[base]
    if base.startswith("entity_"):
        return f"all packets for one IP address or IP pair in a {base[7:]} window"
    if base.startswith("behavior_"):
        return f"one source IP's traffic over {base[9:]}"
    return "see the primer"


def approved_list_text(approved):
    if not approved:
        return "(The list is currently empty: no addresses have been approved yet.)"
    return "\n".join(f"- {network}: {owner or 'owner not recorded'}; {purpose or 'purpose not recorded'}"
                     for network, owner, purpose in approved)


def site_context_text(found, windows_found=None, line_count=0, windows=None):
    parts = []
    path = SITE / "site_context.md"
    if path.is_file() and path.read_text(encoding="utf-8").strip():
        parts.append(path.read_text(encoding="utf-8").strip())
    if found:
        parts.append("Approved administrative automation addresses appearing in these lines: " + "; ".join(
            f"{address} ({owner or 'owner not recorded'}: {purpose or 'purpose not recorded'})"
            for address, (_, owner, purpose) in sorted(found.items())) + ".")
    else:
        parts.append("None of the addresses in these lines are on the approved administrative automation list.")
    if windows_found:
        parts.append("Approved change windows: " + "; ".join(
            f"{count:,} of {line_count:,} lines fall inside {describe_window(window)}, and match its hosts and flow"
            for count, window in windows_found.values()) + ".")
    elif windows:
        parts.append("None of these lines fall inside an approved change window and match its hosts and flow.")
    return "\n\n".join(parts)


def prompt_version(approved_path, model):
    digest = hashlib.sha256()
    for path in sorted(PROMPTS.rglob("*.md")) + sorted(KNOWLEDGE.glob("*.md")) + sorted(SITE.glob("*")):
        if path.is_file() and path.name != "README.md":
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    digest.update(model.encode())
    return digest.hexdigest()[:12]


def probability_note(alert):
    ranked = {ALERT_TYPES[kind] for kind in RANKED_TYPES}
    if alert["alert_types"] and all(kind in ranked for kind in alert["alert_types"]):
        if all(kind == ALERT_TYPES["presence"] for kind in alert["alert_types"]):
            return ("rank among this log's presence alerts by how unlike the rest of the activity it is, 1.0 = least "
                    "like the rest; in this log every activity is an alert by policy")
        if all(kind == ALERT_TYPES["activity"] for kind in alert["alert_types"]):
            return ("rank among this log's activity alerts by how far above its detector's threshold it went, 1.0 = "
                    "the furthest; it measures an unusual amount of activity, not rarity, and is not a probability "
                    "of an attack")
        return ("rank among alerts of the same kind, 1.0 = the most unusual of them (the longest, least likely "
                "silence, or the rarest first-seen item); it is not a probability of an attack")
    return (f"ranks above {alert['probability'] * 100:.2f}% of the observations in its run; this measures rarity, "
            "not the probability of an attack")


def build_messages(alert, source, approved, selector, windows=()):
    lines, truncation = prepare_lines(alert["raw_messages"])
    found = approved_in(lines, approved)
    windows_found = windows_in(lines, windows)
    knowledge = selector.select(lines)
    grouped = {}
    for view in alert["dataset"]:
        grouped.setdefault(describe_view(view), []).append(view)
    views = "; ".join(f"{', '.join(names)} ({description})" for description, names in grouped.items()) or "unknown"
    system = "\n\n".join([
        read_prompt("shared_rules.md"),
        fill(read_prompt("approved_automation.md"), {"approved_automation_list": approved_list_text(approved)}),
        fill(read_prompt("approved_change_windows.md"), {"approved_change_windows": change_windows_text(windows)}),
        read_prompt("triage_categories.md"),
    ])
    user = fill(read_prompt("alert_context.md"), {
        "log_source": SOURCES[source]["label"],
        "alert_types": "; ".join(alert["alert_types"]) or "unknown",
        "flagged_by": compact_flagged_by(alert["flagged_by"]),
        "views": views,
        "probability": f"{alert['probability']:.4f}",
        "probability_percent": f"{alert['probability'] * 100:.2f}%",
        "probability_note": probability_note(alert),
        "line_count": len(lines),
        "truncation_note": truncation,
        "primer": read_prompt(f"primers/{SOURCES[source]['primer']}"),
        "site_context": site_context_text(found, windows_found, len(lines), windows),
        "knowledge": "\n\n".join(text for _, text in knowledge) or "No reference entries matched these events.",
        "delimiter": secrets.token_hex(4),
        "log_lines": "\n".join(f"[{number}] {line}" for number, line in enumerate(lines, start=1)),
    })
    return system, user, lines, found, [identifier for identifier, _ in knowledge]


# --- model -----------------------------------------------------------------------


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def local_endpoint(endpoint):
    """True for an http(s) address on this machine: the prompts carry log lines, accounts and addresses, which never
    leave it (the console's language-model setting has the same rule)."""
    from urllib.parse import urlparse
    parsed = urlparse(str(endpoint))
    return parsed.scheme in ("http", "https") and (parsed.hostname or "").lower() in LOCAL_HOSTS


def chat(endpoint, model, messages, timeout, api_key):
    if not local_endpoint(endpoint):
        raise ValueError("The model endpoint must be on this machine (localhost, 127.0.0.1 or ::1).")
    body = {"model": model, "messages": messages, "temperature": 0, "stream": False,
            "response_format": {"type": "json_object"}}
    request = urllib.request.Request(endpoint.rstrip("/") + "/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json",
                                              **({"Authorization": f"Bearer {api_key}"} if api_key else {})})
    with NO_REDIRECTS.open(request, timeout=timeout) as response:
        return json.load(response)["choices"][0]["message"]["content"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A local model server never redirects; anything that tries is refused rather than followed off the machine."""
    def redirect_request(self, *args, **kwargs):
        return None


NO_REDIRECTS = urllib.request.build_opener(_NoRedirect)


def parse_answer(text, line_count):
    """(answer, None) if valid, else (None, a message the model can act on)."""
    text = re.sub(r"^\s*```(?:json)?|```\s*$", "", text.strip())
    try:
        answer = json.loads(text)
    except ValueError as error:
        return None, f"The answer is not valid JSON ({error})."
    if not isinstance(answer, dict):
        return None, "The answer must be one JSON object."
    problems = []
    if answer.get("category") not in CATEGORIES:
        problems.append(f'"category" must be one of: {", ".join(CATEGORIES)}.')
    confidence = answer.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        problems.append('"confidence" must be a number from 0.0 to 1.0.')
    lines = answer.get("key_lines")
    if not isinstance(lines, list) or not all(isinstance(n, int) and 1 <= n <= line_count for n in lines):
        problems.append(f'"key_lines" must be a list of line numbers between 1 and {line_count}.')
    if not isinstance(answer.get("approved_automation_involved"), bool):
        problems.append('"approved_automation_involved" must be true or false.')
    for field in ("reasoning", "missing_context", "attack_technique", "next_step"):
        if not isinstance(answer.get(field), str):
            problems.append(f'"{field}" must be a string.')
    if isinstance(answer.get("reasoning"), str) and not answer["reasoning"].strip():
        problems.append('"reasoning" must not be empty.')
    return (None, " ".join(problems)) if problems else (answer, None)


def triage(alert, system, user, line_count, args):
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    text = chat(args.endpoint, args.model, messages, args.timeout, args.api_key)
    answer, error = parse_answer(text, line_count)
    if answer is None:
        messages += [{"role": "assistant", "content": text},
                     {"role": "user", "content": fill(read_prompt("repair_json.md"),
                                                      {"error": error, "line_count": line_count})}]
        text = chat(args.endpoint, args.model, messages, args.timeout, args.api_key)
        answer, error = parse_answer(text, line_count)
    return answer, error


# --- run -------------------------------------------------------------------------


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(SOURCES))
    parser.add_argument("--inputs", nargs="+", help="alert CSVs (globs); default: the source's Phase 7 files")
    parser.add_argument("--representatives", action="store_true",
                        help="only rows with representative = 1 (Phase 8 labelling sheets)")
    parser.add_argument("--limit", type=int, default=50, help="alerts to triage, most unusual first (0 = all)")
    parser.add_argument("--endpoint", default="http://localhost:11434/v1",
                        help="OpenAI-compatible base URL on this machine (localhost, 127.0.0.1 or ::1 only)")
    parser.add_argument("--model", default="qwen2.5:3b-instruct")
    parser.add_argument("--api-key", default="", help="only if the local server requires one")
    parser.add_argument("--timeout", type=float, default=600, help="seconds per model call")
    parser.add_argument("--context-tokens", type=int, default=8192,
                        help="the model server's context window; longer prompts are reported (Ollama: set "
                             "OLLAMA_CONTEXT_LENGTH, which otherwise defaults smaller and cuts prompts silently)")
    parser.add_argument("--approved", type=Path, default=SITE / "approved_automation_ips.csv")
    parser.add_argument("--change-windows", type=Path, default=SITE / "approved_change_windows.csv")
    parser.add_argument("--output", type=Path, help="default: data/phase9_llm_triage/<source>")
    parser.add_argument("--dry-run", action="store_true", help="write the prompts, call no model")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    if not local_endpoint(args.endpoint):
        parser.error("--endpoint must be on this machine (localhost, 127.0.0.1 or ::1): the prompts carry log lines, "
                     "accounts and addresses")
    args.inputs = args.inputs or [f"data/phase7_alerts/{args.source}/{SOURCES[args.source]['prefix']}_cumulative_*_alerts.csv"]
    args.output = args.output or Path("data/phase9_llm_triage") / args.source
    return args


def main():
    args = parse_args()
    csv_field_limit()
    alerts, paths = load_alerts(args.inputs, args.representatives)
    if not paths:
        raise SystemExit(f"No files match {args.inputs}")
    approved = load_approved(args.approved)
    windows = load_change_windows(args.change_windows)
    selector = KnowledgeSelector(load_knowledge(args.source))
    version = prompt_version(args.approved, args.model)
    log(f"{len(alerts):,} distinct alerts from {len(paths)} files; {len(approved)} approved automation entries; "
        f"{len(windows)} change windows; "
        f"prompt version {version}", args.quiet)

    args.output.mkdir(parents=True, exist_ok=True)
    result_path = args.output / ("triage_dry_run.csv" if args.dry_run else "triage.csv")
    done = set()
    if result_path.is_file():
        with open(result_path, encoding="utf-8", newline="") as handle:
            done = {(row["alert_id"], row["prompt_version"]) for row in csv.DictReader(handle) if row.get("status") == "ok"}
    todo = [alert for alert in alerts if (alert["alert_id"], version) not in done]
    todo = todo[:args.limit] if args.limit else todo
    log(f"{len(todo):,} to triage ({len(alerts) - len(todo):,} skipped: done with this prompt version or over --limit)",
        args.quiet)

    new_file = not result_path.is_file()
    counts = {}
    with open(result_path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        if new_file:
            writer.writeheader()
        for number, alert in enumerate(todo, start=1):
            system, user, lines, found, knowledge_ids = build_messages(alert, args.source, approved, selector, windows)
            estimate = (len(system) + len(user)) // 4 + 400        # rough tokens, plus room for the answer
            if estimate > args.context_tokens:
                log(f"WARNING {alert['alert_id']}: prompt is about {estimate:,} tokens, above --context-tokens "
                    f"{args.context_tokens:,}; the server may drop its start", args.quiet)
            row = {"alert_id": alert["alert_id"], "source": args.source, "probability": f"{alert['probability']:.6f}",
                   "alert_types": "; ".join(alert["alert_types"]), "flagged_by": "; ".join(alert["flagged_by"]),
                   "dataset": "; ".join(alert["dataset"]), "clusters": "; ".join(alert["clusters"]),
                   "line_count": len(lines),
                   "approved_addresses_in_lines": "; ".join(sorted(found)), "knowledge_ids": "; ".join(knowledge_ids),
                   "model": args.model, "prompt_version": version, "triaged_at": datetime.now().isoformat(timespec="seconds"),
                   "raw_messages": alert["raw_messages"][:32_000]}
            if args.dry_run:
                prompts = args.output / "prompts"
                prompts.mkdir(exist_ok=True)
                (prompts / f"{alert['alert_id']}.txt").write_text(f"=== SYSTEM ===\n{system}\n\n=== USER ===\n{user}\n",
                                                                   encoding="utf-8")
                row["status"] = "dry_run"
            else:
                started = time.perf_counter()
                try:
                    answer, error = triage(alert, system, user, len(lines), args)
                    status = "ok" if answer else "invalid"
                except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as problem:
                    answer, error, status = None, f"model call failed: {problem}", "error"
                if answer is None:
                    row.update(status=status, error=error)
                else:
                    row.update(status="ok", category=answer["category"], confidence=answer["confidence"],
                               reasoning=answer["reasoning"], key_lines=" ".join(map(str, answer["key_lines"])),
                               approved_automation_involved=answer["approved_automation_involved"],
                               missing_context=answer["missing_context"], attack_technique=answer["attack_technique"],
                               next_step=answer["next_step"])
                log(f"{number}/{len(todo)} {alert['alert_id']}: {row.get('category') or row['status']} "
                    f"| elapsed {runlog.format_duration(time.perf_counter() - started)}", args.quiet)
                if row["status"] == "error" and number == 1:
                    writer.writerow(row)
                    raise SystemExit(f"{error}\nIs the model server running at {args.endpoint} with model {args.model}?")
            counts[row.get("category") or row["status"]] = counts.get(row.get("category") or row["status"], 0) + 1
            writer.writerow(row)
            handle.flush()
    log(f"Done: {counts} -> {result_path}", args.quiet)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
