"""What DAD's logs can see of MITRE ATT&CK for ICS (Sigma page, ATT&CK for ICS card). Visibility, not detection:
a technique is visible when the data its detections need is in the logs DAD reads, whether or not a rule or a
model is tuned to it yet. It says which log source to add next.

Per technique, MITRE's detection strategies name the data components their analytics read (attack_ics.json,
built by attack_build.py). Each log type DAD reads provides some of them (SOURCES, from what its Phase 1 parser
records); a technique is

* visible     every component it needs comes from DAD's logs;
* partly      some do;
* planned     none do yet, but the SCS event logs would give one (their parser is built, not yet in the pipeline);
* blind       none do;
* none        MITRE lists no detection for it (mostly effects such as Loss of View).
"""
from __future__ import annotations

import json
from collections import Counter
from functools import lru_cache
from pathlib import Path

ICS_FILE = Path(__file__).with_name("attack_ics.json")
# What each log type DAD reads records, as ATT&CK data components (conservative: what the parser keeps)
SOURCES = {
    "auth": ("AUTH", ("User Account Authentication", "Logon Session Creation", "Logon Session Metadata")),
    "ossec": ("OSSEC", ("Application Log Content",)),                 # the agent's own log: monitoring up or stopped
    "pf": ("PF", ("Network Traffic Flow", "Network Connection Creation")),            # blocked traffic only
    "ipf": ("IPFilter", ("Network Traffic Flow", "Network Connection Creation")),     # blocked traffic only
}
PLANNED = {"event_logs": ("SCS event logs", ("Device Alarm", "Process/Event Alarm"))}
STATUSES = ("visible", "partly", "planned", "blind", "none")


@lru_cache(maxsize=1)
def _attack() -> dict:
    return json.loads(ICS_FILE.read_text(encoding="utf-8"))


def _by(sources: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for label, components in sources.values():
        for component in components:
            out.setdefault(component, []).append(label)
    return out


def status(components: list[str], have: dict, planned: dict) -> str:
    if not components:
        return "none"
    seen = [c for c in components if c in have]
    if len(seen) == len(components):
        return "visible"
    if seen:
        return "partly"
    return "planned" if any(c in planned for c in components) else "blind"


def matrix() -> dict:
    """The ICS matrix, tactic by tactic, each technique with its status and components (who provides each)."""
    data, have, planned = _attack(), _by(SOURCES), _by(PLANNED)
    techniques = {}
    for t in data["techniques"]:
        techniques[t["id"]] = {"id": t["id"], "name": t["name"], "url": t["url"], "tactics": t["tactics"],
                               "status": status(t["components"], have, planned),
                               "components": [{"name": c, "by": have.get(c, []), "planned": planned.get(c, [])} for c in t["components"]]}
    tactics = [{"short": tactic["short"], "name": tactic["name"],
                "techniques": [t for t in techniques.values() if tactic["short"] in t["tactics"]]} for tactic in data["tactics"]]
    return {"source": data["source"], "version": data["version"], "notice": data["notice"],
            "sources": [{"key": k, "label": label, "components": list(c)} for k, (label, c) in SOURCES.items()],
            "planned": [{"key": k, "label": label, "components": list(c)} for k, (label, c) in PLANNED.items()],
            "counts": {s: Counter(t["status"] for t in techniques.values()).get(s, 0) for s in STATUSES},
            "tactics": tactics}
