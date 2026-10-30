# Offline threat knowledge for the triage agents

> In this repository this folder is part of Phase 9 (see the project
> [README](../../../../../README.md)). "Top-level README §N" below means the
> triage backend's own README, which is not in this repository.

The triage agents run on a local model with no internet access. This folder
gives them the background an analyst would bring: how known attacks show up in
**our** three log types, which MITRE ATT&CK techniques they correspond to,
real incidents that used them, and **red herrings** (benign sequences that look
like attacks).

| File | Contents |
|---|---|
| `attack_patterns_auth.md` | `AUTH-xx`: attack patterns visible in Solaris authentication logs |
| `attack_patterns_ossec.md` | `OSSEC-xx`: attacks on, or visible through, the OSSEC agent's own log |
| `attack_patterns_pf.md` | `PF-xx`: attack patterns visible in PF firewall packet logs |
| `attack_patterns_ipf.md` | `IPF-xx`: attack patterns in mm06moc's IPFilter log, which is empty in normal operation |
| `red_herrings.md` | `RH-AUTH-xx`, `RH-OSSEC-xx`, `RH-PF-xx`, `RH-IPF-xx`: look-alikes and how to tell them apart |
| `cases.md` | `CASE-xx`: the real incidents cited, with sources |

## ATT&CK version

Technique IDs follow **MITRE ATT&CK Enterprise v19.2** (May 2026). v19 split
the old *Defense Evasion* tactic into **Stealth (TA0005)** and **Defense
Impairment (TA0112)** and renumbered several techniques. The mappings that
matter here:

| Old ID (v18 and earlier) | Current ID (v19) | Name |
|---|---|---|
| T1562.001 Impair Defenses: Disable or Modify Tools | **T1685** | Disable or Modify Tools |
| T1070.002 Indicator Removal: Clear Linux or Mac System Logs | **T1685.006** | Clear Linux or Mac System Logs |
| T1562.004 Impair Defenses: Disable or Modify System Firewall | **T1686** | Disable or Modify System Firewall |
| T1556.003 (Credential Access / Defense Evasion) | **T1556.003** | Pluggable Authentication Modules, now under Defense Impairment and Persistence |

Every ID in these files was checked against the v19.2 tactic pages
(Reconnaissance, Persistence, Stealth, Defense Impairment, Command and Control,
Impact) and the Brute Force page, **except** the IDs marked `†`. Those come
from Discovery, Lateral Movement, Initial Access, Exfiltration and Credential
Access, which were not re-checked when these files were written (September
2026). Confirm them at <https://attack.mitre.org/> before quoting them in a
report.

## Entry format

Every entry is a level-3 heading followed by fixed bullet fields, so the backend
can parse the files without a Markdown library:

```
### AUTH-01 · Short title
- Techniques: T1110.001 Password Guessing (Credential Access)
- Event types: SSH_LOGIN_FAILED, SSH_INVALID_USER
- Stage 2 signals: failure_count, unique_usernames
- Signs: …
- Stronger if: …
- Weaker if: … (see RH-AUTH-01)
- Cases: CASE-RAPPERBOT, CASE-KINSING
```

Red herrings use `Looks like`, `Event types`, `Actually`, `Tell-tale signs`
and `Would be real if` instead.

`Event types` are the exact labels our Stage 1 classifiers assign:
`pipeline/phase1_classify/auth.py` (`RULES`), `pipeline/phase1_classify/ossec.py`
(`PATTERNS`), and `pipeline/phase1_classify/pf.py`
(`PF_<PASS|BLOCK|MATCH>_<PROTOCOL>`, plus `_MALFORMED` for invalid DNS).
`Stage 2 signals` are column names in the Stage 2 datasets.

## How the backend uses it (retrieval)

The whole knowledge base is far too long to send with every alert. For each
alert, `context.py` should:

1. Run the matching Stage 1 classifier over each log line to get its event
   types. Import the classifier's compiled patterns rather than duplicating
   them.
2. Score every entry for the alert's log type: +2 for each event type it lists
   that appears in the lines, +1 for each keyword from its title found in the
   lines. For PF entries, also match on the destination ports and TCP flags
   named in `Signs`.
3. Send the top 3 attack patterns and the top 3 red herrings (score > 0), plus
   the `CASE-` entries they cite, in the `{{knowledge}}` block of
   `alert_context.md`. Cap the block at about 1,500 tokens.
4. Record which entry IDs were sent with the verdict, so reviewers can see what
   background the model had.

If nothing scores above zero, send `No reference entries matched these
events.`

## How the agents are told to use it

`shared_rules.md` tells every role that this material is **background, not
evidence**:

- Matching a pattern does not make an alert malicious, and resembling a red
  herring does not make it benign. The verdict must rest on the log lines.
- The For advocate should use attack patterns and must address the closest red
  herring. The Against advocate should use red herrings and must address the
  closest attack pattern. The judge weighs both.
- Past cases illustrate how a technique looked in the real world. Do not claim
  an alert *is* that campaign unless the lines show that campaign's specific
  indicators.

## Maintaining it

- Add a pattern when an analyst confirms a new kind of true positive; add a red
  herring when the triage app produces a false positive whose cause is
  understood. Both come from the review labels (top-level README §10).
- Keep each entry under about 150 words: the model reads several at a time.
- Changing these files changes the prompt context. Include the knowledge files
  in the prompt version hash, and re-run the evaluation suite.
