"""Sigma from plain English (Advanced → Sigma → Describe): the local model drafts a rule; the console checks it.

describe() sends the description, the log types with their fields and event types, and three starter rules as
examples to the model on this laptop (llm.chat; nothing leaves it, NFR-SEC-01). Its answer is untrusted text: read
with yaml.safe_load only (no YAML tag can run code), checked by the Sigma engine, sent back once with the engine's
error when it does not read, shown as text, and never saved here. The person previews it, tests it on data and accepts
it (sigma.add), as with any other draft.
"""
from __future__ import annotations

import json
import re

from . import llm, sigma, sigma_form
from .config import load_settings

MAX_DESCRIPTION = 2000
EXAMPLES = ("10_auth_ssh_guessing.yml", "50_auth_su_failures.yml", "70_firewall_port_scan.yml")
LABELS = {"auth": "AUTH (Solaris authentication log)", "ossec": "OSSEC (alerts and agent log)", "pf": "PF (OpenBSD firewall)",
          "ipf": "IPFilter (Solaris firewall)"}

SYSTEM = """You write detection rules in the Sigma format for a log console. Answer with JSON only:
{"yaml": "<the complete rule as YAML>"}

Write the rule from the person's description:
- title: short and specific. level: informational, low, medium, high or critical. status: experimental.
- logsource: AUTH is product: solaris, with service: sshd, su, sudo, cron or login when the description names the
  program; OSSEC is product: ossec; PF is product: pf; IPFilter is product: ipfilter.
- detection: named selections, each a map of field: value or field|modifier: value (a list of values means any of
  them), and a condition such as "selection" or "selection and not filter". Modifiers: contains, startswith,
  endswith, re, cidr, gt, gte, lt, lte. Use only the fields and event types listed for the log type.
- "N or more ... within T" is two documents separated by ---: first an event rule with a name and level
  informational; then a correlation with type event_count (or value_count with condition field: for N different
  values), rules: [that name], group-by: [fields], timespan such as 10m, condition: gte: N.
- tags: ATT&CK tags (attack.tNNNN.NNN and the tactic, such as attack.credential-access) when the technique is clear.
Do not explain. Do not invent fields."""


def _catalog(source: str) -> str:
    types = sigma_form.event_types()
    out = []
    for s in ([source] if source in sigma.FIELDS else list(sigma.FIELDS)):
        out.append(f"{LABELS[s]}\n  fields: {', '.join(sigma.FIELDS[s])}\n  event types: {', '.join(types.get(s, [])) or 'not known'}")
    return "\n".join(out)


def _examples() -> str:
    return "\n\n".join(f"Example:\n{(sigma.STARTER / name).read_text(encoding='utf-8').strip()}"
                       for name in EXAMPLES if (sigma.STARTER / name).exists())


def _answer_yaml(answer: str) -> str:
    """The rule in the model's answer: the JSON's yaml, or the answer itself without code fences."""
    text = answer.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("yaml"), str):
            text = data["yaml"]
    except ValueError:
        pass
    return re.sub(r"^```(?:ya?ml)?\s*|\s*```$", "", text.strip()).strip() + "\n"


def _checked(text: str) -> dict:
    try:
        return {"docs": [d.summary() for d in sigma.parse(text, 0)]}
    except sigma.SigmaError as error:
        return {"error": str(error)}


def describe(text: str, source: str = "") -> dict:
    """A draft rule for a plain-English description: its YAML, how the engine reads it (or what is wrong), the form
    when the form can show it, and the model that wrote it."""
    text = str(text or "").strip()
    if not text:
        raise ValueError("Describe the rule first.")
    if len(text) > MAX_DESCRIPTION:
        raise ValueError(f"At most {MAX_DESCRIPTION:,} characters.")
    prompt = f"Log types:\n{_catalog(source)}\n\n{_examples()}\n\nDescription: {text}"
    draft = _answer_yaml(llm.chat(SYSTEM, prompt))
    result, tries = _checked(draft), 1
    if "error" in result:                              # once more, with what the engine could not read
        draft = _answer_yaml(llm.chat(SYSTEM, f"{prompt}\n\nYour rule:\n{draft}\nThe console could not read it: "
                                              f"{result['error']}\nCorrect it."))
        result, tries = _checked(draft), 2
    return {"yaml": draft, **result, "form": sigma_form.to_form(draft) if "docs" in result else None,
            "model": load_settings()["llm_model"], "tries": tries}
