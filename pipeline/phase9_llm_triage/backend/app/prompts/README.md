# Triage prompts

Prompt templates for the LLM triage workflows described in the top-level
`README.md` (§6 and §7). The backend loads these files at start-up. Edit them
here; do not hard-code prompt text in Python.

> In this repository these files are Phase 9 of the pipeline (see the
> project [README](../../../../../README.md)). "Top-level README §N" in this
> folder means the triage backend's own README, which is not in this
> repository.

## Files

| File | Role | Sent as |
|---|---|---|
| `shared_rules.md` | Rules every role follows | Start of every system prompt |
| `judge.md` | Judge, **Judge** workflow | System prompt |
| `advocate_for.md` | Advocate arguing **malicious** | System prompt |
| `advocate_against.md` | Advocate arguing **benign** | System prompt |
| `judge_two_sided.md` | Judge, **Two-sided** workflow | System prompt |
| `judge_one_sided.md` | Judge, **One-sided** workflow | System prompt |
| `advocate_rebuttal.md` | Optional second round for Two-sided | Appended to the advocate's system prompt |
| `alert_context.md` | The alert itself | First user message, every role |
| `cases_two_sided.md` | Both advocates' cases | Second user message, Two-sided judge |
| `case_one_sided.md` | The single advocate's case | Second user message, One-sided judge |
| `rebuttal_request.md` | The opposing case to answer | Second user message, rebuttal round |
| `repair_json.md` | Retry after invalid output | Follow-up user message |
| `primers/auth.md`, `primers/ossec.md`, `primers/pf.md`, `primers/ipf.md` | How to read each log type | Inserted into `alert_context.md` |
| `approved_automation.md` | The approved-automation list and how to weigh it (`{{approved_automation_list}}`) | Part of the system prompt, **four-category triage** (`../../../triage.py`) |
| `approved_change_windows.md` | Planned changes (e.g. a migration) and how to weigh them (`{{approved_change_windows}}`) | Part of the system prompt, **four-category triage** |
| `triage_categories.md` | Four-category triage role and JSON schema | End of the system prompt, **four-category triage** |

The four-category triage in `triage.py` uses `shared_rules.md` +
`approved_automation.md` + `approved_change_windows.md` + `triage_categories.md`
as the system prompt, and `alert_context.md` as the user message.
`{{site_context}}` there also states which approved addresses appear in the
lines and how many lines fall inside each change window and match its flow.
`{{probability_note}}` explains the unusualness figure: a percentile for
most alerts, a rank among the alerts for presence alerts.

## How a call is assembled

```
system = shared_rules.md + "\n\n" + <role file>          (+ advocate_rebuttal.md in round 2)
user 1 = alert_context.md with its placeholders filled
user 2 = cases_two_sided.md | case_one_sided.md | rebuttal_request.md   (when the role needs it)
```

| Workflow | Calls |
|---|---|
| Judge | `judge.md` + user 1 |
| Two-sided | `advocate_for.md` + user 1 and `advocate_against.md` + user 1 (in parallel), then `judge_two_sided.md` + user 1 + `cases_two_sided.md` |
| Two-sided with rebuttal | As above, but each advocate first answers the other's case with `advocate_rebuttal.md` + `rebuttal_request.md`, and the judge receives the rebuttals |
| One-sided | `advocate_for.md` or `advocate_against.md` + user 1, then `judge_one_sided.md` + user 1 + `case_one_sided.md` |

## Placeholders

Placeholders are written `{{name}}`. Fill them with plain string replacement
(or Jinja2 with autoescape off), never with `str.format`, because the JSON
examples contain braces.

| Placeholder | Filled with |
|---|---|
| `{{delimiter}}` | A fresh random 8-hex-character token per call, e.g. `7f3a9c1e` |
| `{{log_source}}` | `authentication (Solaris syslog)`, `OSSEC agent` or `PF firewall` |
| `{{alert_types}}` | Which Stage 7 files contained the alert, e.g. `Isolation Forest; Model-zoo consensus` |
| `{{flagged_by}}` | Stage 7 `flagged_by` value |
| `{{views}}` | Stage 7 `dataset` value, expanded with the view descriptions below |
| `{{probability}}` | Stage 7 `probability`, 4 decimals |
| `{{probability_percent}}` | Same as a percentage, e.g. `99.98%` |
| `{{line_count}}` | Number of lines in the block |
| `{{truncation_note}}` | Empty, or e.g. `The chain was truncated: 340 further lines were omitted.` |
| `{{primer}}` | Contents of the matching `primers/*.md` |
| `{{site_context}}` | Contents of `site/site_context.md` (optional), or `No site context was provided.` |
| `{{knowledge}}` | The attack patterns, red herrings and cases selected for this alert from `../knowledge/` (see its README, "How the backend uses it"), or `No reference entries matched these events.` |
| `{{log_lines}}` | Numbered lines, one per line: `[1] …` |
| `{{stance}}` | `for` or `against` (One-sided judge and rebuttal) |
| `{{case_a_label}}`, `{{case_b_label}}` | `FOR (argues malicious)` / `AGAINST (argues benign)`, in randomised order |
| `{{case_a_json}}`, `{{case_b_json}}`, `{{case_json}}`, `{{own_case_json}}`, `{{opposing_case_json}}` | Advocate outputs, re-serialised from the validated object (never the raw model text). With a rebuttal round, the judge's `{{case_a_json}}` / `{{case_b_json}}` are `{"case": …, "rebuttal": …}` |
| `{{opposing_stance}}` | `for` or `against`, the side the opposing case argues (rebuttal round) |
| `{{error}}` | Validation error message for `repair_json.md` |

View descriptions for `{{views}}`:

| Stage 2 view | Description |
|---|---|
| `individual` | a single log event |
| `host_5min` | all events from one host in a five-minute window |
| `host_behavior_1d` | one host's activity over a day |
| `authentication_sessions` | one SSH connection or local login attempt |
| `episodes` | one OSSEC agent activity (a scan, an outage, a restart) |
| `entity_<window>` | all packets for one IP address or IP pair in that window |
| `sessions` | one PF service conversation between two hosts |
| `behavior_<window>` | one source IP's traffic over that window |

## Preparing the log lines

Before filling `{{log_lines}}`:

1. Split Stage 7 `raw_messages` on `" | "`.
2. Remove control characters (except tab) and ANSI escape sequences.
3. Replace any occurrence of `<<<` and `>>>` with `‹‹‹` and `›››` so a log
   line can never imitate the block delimiters.
4. Apply the line budget from the top-level README §7.2 and say what was
   omitted in `{{truncation_note}}`.
5. Number the lines `[1]` to `[N]` in event order.

## Versioning

The backend stores a SHA-256 of the concatenated prompt files **and knowledge
files** (`../knowledge/*.md`) with every verdict (`run.prompt_version`), plus
the IDs of the knowledge entries sent with each alert. Changing any file here starts a new version,
so old and new verdicts are never mixed silently. Re-run the evaluation suite
(top-level README §10) after every change.
