# Phase 4f: sequential pattern mining

Status: **steps 0–3 built and run on AUTH and OSSEC; alert profiling built**
(2026-10-08). Step 6 is partly built: Phase 7 collects the sequence alerts and Review lists and
explains them (2026-10-19); a Data → Routines view is not built. Steps 4, 5 and 7
(suspicious-sequence templates, injected-attack evaluation, cross-log timelines) remain. The original proposal
further down was drafted on 2026-10-06; the [first audit](AUDIT_2026-10-08.md)
qualified its ordering, deduplication and tokens, and the build follows the audit.

Decisions (2026-10-08): `prefixspan` and `mlxtend` as the libraries; tokens are
**event types only**; sequence alerts use the **existing alert budget**.

New to it? The [plain-English guide](GUIDE.md) explains the method and the
results with pictures (in the console: Documentation → the Routines station).

## Run it

From the project root (PowerShell). Needs `prefixspan` and `mlxtend` in the
environment (tested: prefixspan 0.5.2, mlxtend 0.25.0;
`.\.venv\Scripts\python.exe -m pip install prefixspan mlxtend`).
`run_pipeline.py` runs all three steps as phase **4f** for auth and OSSEC
(after 4e, before 5):

```powershell
.\.venv\Scripts\python.exe run_pipeline.py --source ossec --only-phase 4f
.\.venv\Scripts\python.exe pipeline\phase4f_sequences\run_sequences.py --source auth                 # about 15 min
.\.venv\Scripts\python.exe pipeline\phase4f_sequences\run_sequences.py --source auth --skip-streams  # reuse step 1
.\.venv\Scripts\python.exe pipeline\phase4f_sequences\profile_alerts.py --source auth                # after 4a, 4b and 4f
.\.venv\Scripts\python.exe -m unittest discover -s pipeline\phase4f_sequences -p test_*.py -v
```

| Script | Step | Writes |
|---|---|---|
| `streams.py` | 1. Ordered, de-duplicated token streams | `data/phase4f_sequences/<source>/streams/sequences.sqlite`, `summary.json` |
| `mine.py` | 2. Routine catalogue, rules, step model (training split only) | `data/phase4f_sequences/<source>/routines/routines.csv`, `rules.csv`, `model.json` |
| `score.py` | 3. The sequence detector (validation sets the threshold) | `data/phase4_detection/<source>/sequences/<view>/test_scores.csv`, `test_alerts.csv`, `summary.json` |
| `profile_alerts.py` | Association rules over every detector's test alerts | `data/phase4f_sequences/<source>/alert_profile/alert_profile.md`, `.csv` |

Phase 7 collects the detector's alerts into
`data/phase7_alerts/<source>/<prefix>_cumulative_sequence_alerts.csv`
(*flagged by*: "Sequence (unusual order)").

Review (2026-10-19): Phase 7b counts sequence alerts as flagged, so they join the
clusters and validation groups Review lists, ranked and explained under
*Frequent subsequences*. Uploads (Check logs, Analyze) are scored by the same
code: the console replays `streams.py` on the upload's Phase 2 store and scores
with `model.json`, `rules.csv` and the saved threshold
(`triage-console/service/sequences.py`).

### Step 1: streams

- **The observations are Phase 2's**, with the same `row_manifest_id`, so every
  result links to existing sessions, episodes, alerts and console records.
  OSSEC episodes come from the Phase 2 episode lineage. AUTH sessions are rebuilt
  by replaying Phase 2's own session assignment (its functions, in its order),
  because the session CSV keeps only 96 event types per session. `summary.json`
  records the check that the replay reproduced exactly Phase 2's sessions, event
  counts and close reasons, and Phase 3's split counts.
- **Order within an observation**: time, archive, member, file, numeric line,
  event ID (the audit's order).
- **Rotated-log copies**: the same raw line at the same second in another file
  is merged into the first file's copy, up to as many copies as the first file
  holds; repeats within one file are kept. Every merged copy is listed in the
  `aliases` table, so nothing is lost.
- **Uncertain order**: a step between two events of the same second from
  different files (or without a line number) is recorded by position and never
  scored or counted as a transition.
- **Tokens**: event types; consecutive repeats become one token with the run
  length kept on the observation. Complete sequences, no 96-event limit.
- **Censoring**: an observation starting within 15 minutes of the first event in
  the data is left-censored; one closed by the end of the data is right-censored.
  Both are left out of training, and their cut-off end is not scored.

### Step 2: routines

On the training split, leaving out approved change windows (as Phase 4 does) and
censored observations. Identical sequences are counted once with their
multiplicity and PrefixSpan runs with a weighted support, so support is still the
number of observations.

- `routines.csv`: per scope (all hosts, then each host with at least 200
  training observations), the 15 most common **whole** sequences and the
  **closed patterns** (support at least 0.5% of the scope and 20 observations,
  up to 8 steps, other steps allowed between).
- `rules.csv`: "after A, B follows" rules from the patterns' prefixes with
  confidence at least 95%, e.g. *after a rootcheck scan starts, it ends*.
- `model.json`: step counts (which event type follows which, including start and
  end), overall and per host.

### Step 3: the sequence detector

Score = the surprise of the observation's **rarest step**, −log2 of its
probability on that host (smoothed towards all hosts, then towards how common the
event type is at all); 10 bits is about 1 in 1,000. It catches steps never or
rarely seen after the previous one, and routines that end early. Each alert is
explained in words: the rarest step and its odds ("never on mm03kco in training
(seen 4 times on other hosts)"), any rule it breaks, and whether the whole
sequence is new for the host.

**Threshold.** Phase 4's own `choose_threshold` for the view (alerts per day and
population cap on validation), then raised if needed to the training 99.5%
quantile: Phase 4's `TRAINING_QUANTILE_IS_FLOOR` option, which the other
detectors leave off. Identical sequences score alike, so filling the budget would
reach steps as common as 1 in 11 (OSSEC: 220 validation alerts at 3.5 bits).
The floor means the detector can use less of the budget, never more.

### Alert profile (association rules)

Each test observation becomes a transaction of coarse items (host, server
family, 6-hour band, weekday/weekend, event types present, length band, close
reason, merged copies, named user or not, source address class; no raw
usernames or addresses). For each detector, FP-growth finds the combinations in
at least 5% of its alerts; each is counted over all test observations for its
alert rate and **lift**. Kept when lift is at least 2, clearly above its parts,
and not a duplicate of a combination selecting the same observations.

## First results (2026-10-08)

| | AUTH sessions | OSSEC episodes |
|---|---:|---:|
| Observations (= Phase 2, checked) | 9,475,862 | 29,447 |
| Events | 26,085,863 | 115,288 |
| Distinct complete sequences | 306 | 77 |
| Rotated-file copies merged | 290,396 (all in the training months) | 4,692 |
| Steps of uncertain order | 4,897 | 0 |
| Routines / rules | 409 / 53 | 312 / 81 |
| Threshold (bits) | 11.56 (budget: 10 a day) | 8.81 (training floor) |
| Validation / test alerts | 543 / 608 (0.043%) | 19 / 19 (0.43%) |

- **Routines are few.** One AUTH sequence, *login, disconnect received, user
  disconnected*, is 82% of training sessions; with *connection closed* and *login*
  alone it is 98%. The rule "after a disconnect is received, the user is
  disconnected" holds in all 5.5 million training cases.
- **OSSEC alerts**: all 19 are in two windows: com1kco's agent restarts on
  2026-07-13 02:06–02:28 (a send failure never seen in training, socket errors)
  and mm03kco's 02:00 window on 2026-06-17 (steps never seen on that host).
- **AUTH alerts**, most unusual first: `authorized_keys` permission errors on
  admikco (never seen in training on any host; 3 sessions in June), invalid users
  on com1kco at 02:38 on 2026-07-13 (during the OSSEC restart window) and on
  spadkco on 2026-06-29, empty-password attempts at mm04kco's graphical login
  (GDM) on 2026-06-28. The bulk is two new habits of the test period: sessions that are a
  lone *subsystem not found* line on the com servers (244) and a lone *connection
  closed* on the tc servers (146), worth one look each.
- **Where the other detectors' alerts pile up** (`alert_profile.md`): all 370
  Isolation Forest session alerts are on the `mm` servers and 98.7% contain an
  `SSH_DEPRECATED_OPTION` warning line. Of the 5,653 model-zoo consensus alerts,
  77% are on `mm` servers, and two in three of mm04kco's test sessions are
  flagged; an `mm` login that ends by inactivity is flagged 94% of the time. This
  supports known gap 5: the pile-up follows a few line types that are rare on
  servers with little traffic, not rare behaviour.

## Run the initial audit

From the project root (PowerShell):

```powershell
.\.venv\Scripts\python.exe pipeline\phase4f_sequences\audit.py --source auth --max-events 100000 --write-stream
.\.venv\Scripts\python.exe pipeline\phase4f_sequences\audit.py --source ossec --max-events 0 --write-stream
```

The audit reads the Phase 2 SQLite store with `mode=ro` and `query_only` enabled.
It writes a new run directory under `data/phase4f_sequences/<source>/`, containing
`audit.json`, `audit.md`, and optionally `ordered_events.jsonl`. A directory
without `audit.json` is an incomplete run. Existing directories are never replaced.
Use `--output`, `--store`, `--host`, `--start` (inclusive) and `--end` (exclusive)
to narrow or relocate a run. Time filters use the source log clock without a timezone.

The default limit is 100,000 events, keeping the final timestamp group whole;
`--max-events 0` reads all selected events. Memory holds one timestamp cohort;
`--max-tie-events` defaults to 100,000 and fails explicitly if exceeded. Counts
describe only the selected interval. The audit compares event-ID and source-line
ordering, flags ambiguous ties and duplicate candidates, and preserves every
occurrence. It does not change Phase 2 outputs, assign sessions, deduplicate,
fit models or emit alerts. The extract is not yet mining-ready input.

## Why

Attacks are usually told by **order**, not by single lines: guessing, then a
success; a login from a new address, then `su root`; the OSSEC agent stopping,
then files changing, then the agent starting again. Today the pipeline sees
order only weakly:

- Phase 2 keeps each session's, episode's and window's event types in order
  (`event_type_sequence`; at most 96 events for auth, 64 for OSSEC).
- Phase 3 turns them into word 1–3-grams, hashed into 256 columns, and the
  novelty detector scores how rare those columns are.

Nothing learns which **routines** are normal, nothing says which step of a
routine was skipped or swapped, and nothing names a suspicious sequence in
words a person can check. Hashing also merges different patterns (README,
known gap 4).

## What the data already shows

Measured on 2026-10-06:

| Fact | Figure | Consequence |
|---|---|---|
| Auth events | 26.1 million, 61 event types, 12 months | Enough to learn routines per server |
| OSSEC events | 115,288, 46 event types | Small: mine globally, not per server |
| Auth sessions (first 500,000) | 1,202 distinct whole sequences; 147 pairs, 311 triples | Very concentrated: mining is cheap and exact (no hashing needed) |
| Top 5 sequences | 66% of sessions | A short list of routines explains most activity |
| Same-second order | "login success → user disconnected → disconnect received" and with the last two swapped: 20% each; "user disconnected → login success": 7.5% | Events in the same second are in arbitrary order: **must be fixed first** |
| Tie-break available | Every event has `source_file` and `source_line` | Numeric line order gives the recorded order within a file; ordering across files remains uncertain (2026-10-08 audit) |
| Rotated files | The same message can appear under two syslog file prefixes (`authlog.4`, `authlog.10`) | Check for repeated events by (server, time, message) before mining |
| Firewall | PF 3,415 packets on 41 days; IPFilter similar | Too little to mine alone; useful only as context next to auth |

## The approach, in four layers

### 1. Clean, ordered event streams (a Phase 2 addition)

- **Order**: sort by timestamp and numeric source-line provenance; retain an
  ambiguity marker for same-time events across files or uncertain positions.
- **De-duplicate (proposal revised after audit)**: identify overlapping-file
  copies with provenance before collapsing them; preserve legitimate repetitions
  and all original occurrence IDs. The audit only marks candidates. A blanket
  (server, timestamp, normalised message) collapse is not approved.
- **Tokens**: an event becomes a token at the level people reason at:
  `event_type` plus a few coarse attributes: outcome (ok, failed), account
  class (root, service, named user, invalid), source class (local, internal,
  external, new for this server). Example: `SSH_LOGIN_FAILED:root:external`.
  Exact accounts and addresses stay out of the token, so patterns
  generalise; they stay on the event for display.
- **Runs**: collapse repeats into one token with a count band
  (`SSH_LOGIN_FAILED×3–10`), so 40 failures do not drown the pattern.
- **Streams**: per session (auth), per episode (OSSEC), and a **per-server
  timeline** that interleaves auth, OSSEC and firewall events within a
  window. Cross-log order is where the strongest stories are (PF scan → SSH
  attempts → success → OSSEC change).

### 2. Learn what normal looks like (training months only)

- **Frequent routines**: closed sequential patterns with PrefixSpan (or
  CM-SPADE for speed), minimum support per server and overall, a maximum gap
  between steps. De-duplicate identical sequences with counts first: 9.5
  million sessions reduce to a few thousand distinct ones.
- **Time-bounded episodes**: for the per-server timeline, episode mining
  (WINEPI / MINEPI style): which events occur together within N minutes.
- **Transition model**: a smoothed n-gram (Markov) model of the next token
  given the previous one or two, per server with a global back-off. It gives
  every step a probability.

Output: a **routine catalogue** per server ("login → session opened →
disconnect: 41% of sessions on mm04kco"), with support, typical duration,
accounts and hours.

### 3. Score how unusual a sequence is (validation for thresholds, test for results)

Each session, episode or window gets:

- **Surprise**: the most surprising step (the lowest transition probability)
  and the mean surprise per step. Catches a familiar routine done in an odd
  order, or a step never seen after the previous one.
- **Broken routine**: a frequent routine started but not finished, or
  finished without its usual start (for example, a success with no session
  opening; disconnects with no login).
- **New routine**: the whole sequence, or a closed pattern in it, never seen
  in training on this server.
- **Known suspicious sequences**: templates written from the Phase 9
  knowledge base (`attack_patterns_auth.md`, `attack_patterns_ossec.md`),
  matched with gaps allowed:

  | Template | From |
  |---|---|
  | failures ×N → success, same account and source | AUTH-01, AUTH-05 |
  | invalid users ×N from one source | AUTH-02 |
  | login from a new source → `su root` within minutes | AUTH-10 |
  | password logins → first publickey login for the account | AUTH-06 |
  | PAM or sshd configuration change → login | AUTH-07, AUTH-11 |
  | PF scan from a source → SSH attempts from the same source | AUTH-09, PF-01 |
  | OSSEC agent stopped → integrity changes → agent started | OSSEC-01 |

  These come with a plain name ("guessing, then success"), so Review can say
  what was found, not just that something was rare.

Thresholds: set on the validation months with the same alert budget as the
other detectors, so the alert volume stays workable.

### 4. Use the results

- **Phase 7**: sequence alerts join the alert lists with their pattern name
  and the matched lines (lineage kept, as for every alert).
- **Phase 3 / 4**: exact pattern features (one column per routine or
  template) replace or sit beside the hashed n-grams in the model zoo.
- **Console**:
  - Review: for a selected event, "usual routine on this server" next to
    "this event's sequence", with the odd step marked; the template name when
    one matched.
  - Data: a *Routines* view per server (the catalogue), for operations staff
    to confirm or name routines (feeds approved automation, Phase 9).
- **Phase 8**: once review labels are exported (Q21), contrast mining
  between *Security relevant* and *Expected behaviour* finds the patterns
  that tell them apart.

## How to tell whether it works (there are no labelled attacks)

1. **Injected attacks**: copy test-period sessions and insert the template
   sequences (with realistic timing, accounts and sources); measure how many
   are caught at the alert budget, and how high they rank.
2. **Known incidents in the data**: the November 2025 IPFilter burst on
   mm06moc, OSSEC's log-rotation fault and agent-loss episodes: are they
   found, and named sensibly?
3. **Agreement**: overlap with the existing detectors and the model zoo; new
   alerts are read by a person (Phase 9 triage or the console).
4. **Analyst labels**: once Review labels are exported (Q21), precision of
   sequence alerts on *Security relevant* items.
5. **Stability**: the routine catalogue should change little from month to
   month outside known changes; a drift report flags new routines.

## Risks

- **Clock and order**: one-second timestamps and rotated files; mitigated by
  the (time, file, line) order and de-duplication, and by scoring patterns
  with gaps rather than strict adjacency.
- **Routine noise**: cron jobs and monitoring dominate counts; the catalogue
  must keep them, so they can be recognised, without letting them hide rarer
  routines (minimum support per server, not only overall).
- **Over-specific tokens**: too many attributes and nothing repeats; too few
  and attacks look like routines. Start coarse; add an attribute only if the
  injected attacks need it.
- **OSSEC and firewall volume**: too small for per-server models; global
  models and templates only.

## Steps

| Step | What | Result |
|---|---|---|
| 0 | **Built:** read-only ordering/repetition/vocabulary audit, optional traceable event extract; complete OSSEC and three bounded AUTH samples checked | [Audit report](AUDIT_2026-10-08.md); token policy still to decide |
| 1 | Ordered, de-duplicated token streams (Phase 2) | `<prefix>_sequences.csv` with lineage |
| 2 | Routine catalogue (PrefixSpan, per server and overall) | `routines.csv`, a page in the Phase 6 report |
| 3 | Transition model and surprise / broken-routine scores | Scores per observation; thresholds on validation |
| 4 | Suspicious-sequence templates from the knowledge base | Named matches with their lines |
| 5 | Injected-attack evaluation | Catch rate and rank at the alert budget |
| 6 | Phase 7 alerts and the console (Review, Data → Routines) | Sequence alerts reviewed like the others |
| 7 | Cross-log timelines (auth + OSSEC + firewall per server) | The strongest stories, once 1–6 hold up |

## Decisions needed

1. Token attributes to start with (proposed: event type, outcome, account
   class, source class).
2. Mining library: `prefixspan` (pure Python, simple) or SPMF's CM-SPADE
   (Java, much faster); the de-duplicated input is small, so `prefixspan` is
   likely enough.
3. Whether sequence alerts count towards the shared alert budget or have
   their own.
4. Who confirms routines in the console (operations staff), and whether a
   confirmed routine becomes approved automation for Phase 9.
