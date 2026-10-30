# Sigma: known attack patterns

Workspace of 26 October 2026 · Advanced → Sigma

The models flag what is **rare**. Some attacks are **common** in a busy network and well
described: password guessing, password spraying, trying user names, a port scan. Sigma
rules look for those patterns by name. A rule hit is a reason to look, not a verdict, and it
changes no model's score.

## Run the rules

1. Choose the input as on Analyze: paste lines, upload a file, or give the path of a file
   or a **folder** on this laptop. A folder is read file by file from its lowest folders; each
   file's log type is told from its first lines and its month from its folder names, and the
   files of one log type and month are checked together.
2. Press **Run**. Every rule that is switched on is applied.
3. The hits are listed most serious first (critical, high, medium, low, informational), each
   with its rule, its level and the lines behind it (up to 40 shown per hit). A hit whose
   accounts are all [whitelisted](01_getting_started.md#whitelisted-users) says so.

## The rules

The list on the left holds the rules, each with its level, an on/off switch, and who added it
and on what day (the signed-in account, or the name in Settings). A rule added by someone in
the last week is marked **New**, so everyone sees what has changed. Eight starter rules come
with the console:

| Rule | Looks for |
|---|---|
| SSH password guessing | 8 or more failed SSH logins from one address on one server within 2 minutes |
| Password spraying | failed SSH logins for 10 or more accounts from one address within a day, across all servers |
| User enumeration | 5 or more accounts that do not exist tried from one address within 10 minutes |
| Success after guessing | a successful login from an address that was just guessing |
| `su` failures | repeated failed switches to another account |
| OSSEC agent stopped | an OSSEC agent stopping |
| Port scan | one address reaching 15 or more ports within 5 minutes |
| Address sweep | one address reaching 15 or more hosts within 5 minutes |

Their thresholds are **starting values**: confirm them with the people who run the network,
and replace or add rules with **Import**.

## Write or change a rule

Choose a rule (or **New**). There are three ways to write it, at the top of the editor:

- **Form**, the default. The fields every rule needs carry a red dot and are shaded until
  filled: a **title**, the **log type** (for AUTH, optionally the program, such as `sshd`), and
  **Match**: a field, a test and one or more values. Any one value may match; every Match row
  must hold. **Except** rows each rule an event out. **Count** turns the rule into a count:
  at least N events (or N different values of a field) within a time, per address, account
  or server. **Level** and, under **More**, the status, a description, ATT&CK techniques and
  known false positives. The YAML the form writes is shown beside it, signed with your name
  and today's date.
- **Describe** (new rules only). Write the rule in plain English, for example *five failed
  root logins over SSH from one address within 10 minutes*, and press **Write**. The local
  language model drafts it; the draft is shown as a readable card and its YAML, with the
  model's name. **Edit** opens it in the form. This is a proof of concept: the model on this
  laptop is small, so read every draft before testing it. Nothing is saved until you accept it.
- **YAML**, for rules the form cannot show (an `or`, a sequence, both firewalls at once) or
  for writing by hand. A saved rule opens in the form when the form can show it, and in YAML
  otherwise.

Under the editor, three steps: **Draft → Test → Accept**. **Test** runs the draft alone over
the input above (paste or upload some lines first) and shows its hits. **Accept** stays
locked until the draft, as it now stands, has been tested; any change locks it again. The
accepted rule appears in the list with your name and the date. **Export** saves every rule as
one YAML file; **Delete** removes one. Adding, changing, deleting and exporting rules, and
each AI draft, are recorded in the activity log, including whether a rule was tested before
it was accepted.

A rule matches single lines; a **correlation** counts them in a sliding window. This pair
flags 8 failed SSH logins from one address on one server within 2 minutes:

```yaml
title: SSH login failed
name: ssh_login_failed
logsource:
  service: sshd
detection:
  selection:
    event_type: SSH_LOGIN_FAILED
  condition: selection
level: informational
---
title: SSH password guessing from one source
correlation:
  type: event_count
  rules:
    - ssh_login_failed
  group-by:
    - source_ip
    - host
  timespan: 2m
  condition:
    gte: 8
level: medium
```

Fields are the pipeline's own names (`event_type`, `username`, `source_ip`, `host`, …);
common Sigma names such as `User` or `src_ip` are understood too. `logsource` picks the log
type; a rule for logs the console does not read (Windows, cloud) applies to nothing.
Correlations can also count **distinct values** (`value_count`) or look for several rules in
a window, in any order (`temporal`) or in order (`temporal_ordered`).

## Hits in Review and on the Dashboard

The rules that are switched on also run over every Analyze input and upload, and over the
year's validation and test periods. A hit marks every observation that holds one of its
lines. **Review** then lists any group holding such an observation, however common it is,
with the rule's title and the Σ mark; the **Dashboard** counts these among the items
waiting and lists them first under *Next to review*. Changing the rules starts a new pass in
the background.

## Limits

- Rules written for other systems' logs (Windows, auditd, PAM text) need their fields mapped
  to the pipeline's names before they match these servers' lines.
- A few modifiers (`base64`, `windash`, `fieldref`) and rules for the absence of events are
  refused with a message.
- The year's raw lines were purged: running the rules over that year again needs its logs
  supplied again.

## Training period and ATT&CK for ICS (2026-10-30)

- **Training period** (*Check*): runs the enabled rules over the period the models learned as normal. A match there
  means the baseline may hold a known attack pattern; open the hypothesis register and ask the owner. The result is
  kept until the rules or the stores change (then marked *outdated*).
- **ATT&CK for ICS**: each technique coloured by whether DAD's logs hold the data its detections need: visible, partly,
  with event logs (once the SCS event logs are in the pipeline), not visible, or none listed by MITRE. It is about what
  the logs can show, not about which rules exist. A chip opens the technique's page on attack.mitre.org.

