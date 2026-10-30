# Project DAD (Data Anomaly Detection) Console: finding suspicious activity in NSEWL SCS server logs

Start here: [QUICKSTART.md](QUICKSTART.md) — launch the local console, review logs and create your first report.

Technical whitepaper: [whitepaper/](whitepaper/README.md) — the LaTeX paper, its appendices, figures and a Colab notebook to compile them.

## In one paragraph

Every month we receive a ZIP of log files from the NSEWL SCS servers
(15 hosts). Nobody has labelled any of it: we do not know which lines, if any,
are attacks. This project reads those logs and **ranks the activity that looks
least like normal behaviour**, so that an analyst reviews a few hundred items
instead of 26 million lines. Every alert can be traced back to the exact
original log lines that caused it.

In machine-learning terms, this is **unsupervised anomaly detection on event
logs**. It parses text into events, aggregates them at several time scales,
builds features, splits by time, scores with unsupervised detectors, and caps
the number of alerts per day. Phase 8 adds a **supervised** model that learns
from analyst labels, once they exist.

```
 Phase 0      Phase 1      Phase 2        Phase 3      Phase 4       Phase 5     Phase 6    Phase 7      Phase 8
 raw ZIPs --> classify --> observations --> features --> detection --> evidence --> report --> alerts --> malice score
 (text)       (events)     (4+ views)       (matrices)   (unsupervised) (trace back) (HTML)    (CSVs)      (supervised, WIP)
                                                                                                             |
                                                                       Phase 9: LLM triage (built, needs a local model)
```

**Where to look at the results.** The **Project DAD (Data Anomaly Detection) Console**
([`triage-console/`](triage-console/README.md)) is a local web app on the
pipeline laptop. It shows the models and data, checks new log lines against
the trained models and against Sigma rules for known attack patterns, leads with
what needs a decision on a Dashboard the analyst can rearrange, lets an analyst
review the flagged groups (each flagged observation with its anomaly score and the
logs before and after it) and write them up as versioned reports, and offers
read-only SQL behind its own password. An administrator signed in with SSO can add
data and retrain.

**What it can and cannot claim.** An alert means "unusual compared with this
host's own history". It does not mean "malicious". Without labels there is no
precision or recall to report. The pipeline has been built so that those
numbers *can* be produced (Phases 5, 7 and 8), not so that it already has them.

---

## A short security primer: the log sources

You do not need security training to follow the pipeline. You only need to
know what each log records and what an attack would look like in it.

| Source | What it is | What one line says | What an attack could look like |
|---|---|---|---|
| **auth** (`authlog_*.txt`) | The Unix/Solaris authentication log. Every login, logout, `su` (switch to root) and failed password on a server. | `Accepted publickey for backup from 10.1.2.3 port 51234 ssh2` | Many failed passwords (password guessing, "brute force"). A login from a new address or at an unusual hour. A user becoming root who normally does not. |
| **ossec** (`osseclog_*.txt`) | OSSEC is a security agent on each server. It checks files for changes (*syscheck*) and looks for rootkits (*rootcheck*). This is the agent's **own** log, not its alerts: it records the agent starting, connecting to its manager, and running scans. | `ossec-agentd: INFO: Trying to connect to server (per1kco/...:1514)` | The agent stopping, restarting or losing its manager, which is what an intruder switching off monitoring looks like. Scans that start but never finish. |
| **pf** (`pflog_*.txt`) | The PF firewall's log of packets it **blocked**. | `block in on net2: 172.16.10.19.60022 > 172.16.10.11.22: Flags [S]` | One address knocking on many ports ("port scan"), repeated attempts on admin ports such as SSH (22), or floods. |
| **ipf** (`ipflog_mm06moc*`) | The IPFilter firewall log of the one server (mm06moc) that runs IPFilter instead of PF. It is **empty in normal operation**. | `@0:1 b 172.16.10.29,40781 -> 172.16.10.26,9711 PR tcp len 20 60 -S IN` | Any line at all. The question is what the traffic was and whether a change explains it. |

Each source needs its own parsing and its own notion of a "session", so
Phases 1 and 2 are written per source. Everything after follows one recipe for
any log: Phases 3 to 6 have a script per source built the same way, and ten
steps (2c, 4c to 4h, 7, 7b, 7c) are shared scripts that take `--source`. A new
log format needs its parser and its observations; the rest is the same framework.

**The data today** (from the Phase 1 outputs, re-run 2026-09-29/30):

| | auth | ossec | pf | ipf |
|---|---|---|---|---|
| Lines | 26,091,162 | 115,288 | 3,955 | 52,231 |
| Months processed | 2025-08 to 2026-07 (12) | 2025-08 to 2026-07 (12) | 2025-08 to 2026-07 (12) | 2025-08 to 2026-07 (12; 11 empty) |
| Event types found | 61 | 46 | 3 | 2 |
| Most common | SSH login / disconnect (93%) | agent connection chatter (79%) | blocked licence-server broadcasts, port 1947 (63%) | blocked connection attempts to port 9711 (99.98%) |
| Lines not recognised | 3,149 (0.012%) | | | 0 |

Most of the volume is routine. The interesting events are rare. For example,
auth has only 7,661 failed logins among 26.1M lines. The whole design follows
from that: find the rare and the unusual.

PF is thin. Two leftover capture files (`pflog_<host>_tmp`) held 93,724 lines
from 2022–24, outside the study period, including nearly all the RIP routing
packets. Phase 1 now leaves them out (`--include-tmp` brings them back). What
remains is 3,955 lines: 3,415 packets on 41 days, 2,475 of them licence-server
broadcasts from 192.168.0.5 in March 2026, plus 540 lines of a `.bat` script
that sits in the pflog folder.

The IPFilter log is emptier still: eleven of its twelve monthly files are
empty, and all its lines fall in November 2025. Both firewall logs are handled
differently from auth and OSSEC (see
[The presence method](#the-presence-method-a-baseline-of-silence-pf-and-ipfilter) below).

---

## The phases

Each phase lives in `pipeline/phaseN_<name>/`, as one script per log source or
one shared script, and writes to `data/phaseN_<name>/<source>/`. The code and
data folders have the same names, so it is always clear which script made which
files. [pipeline/STYLE_GUIDE.md](pipeline/STYLE_GUIDE.md) lists every phase with
its script.

### Phase 0: Raw data (`data/phase0_raw/`)

**Goal:** keep the logs exactly as received.

- `archives/`: the monthly ZIPs, e.g. `2025-08 NSEWL SCS.zip`. Each ZIP holds
  `authlog/`, `ossec/` and `pflog/` folders with one text file per host
  (15 each), plus one `ipflog/` file that is not used.
- `auth/`, `ossec/`, `pf/`: the unzipped files, by month. Phase 1 unzips
  each source's new archives itself and leaves files that are already there.
  From 2026-05 the archives drop the `.txt` extension
  (`authlog_admikco`, `ossec_log_admikco`), and all three Phase 1 scripts
  accept both forms.

Nothing is ever edited here, which is what makes the evidence trail in later
phases trustworthy.

### Phase 1: Classify (`pipeline/phase1_classify/`)

**Goal:** turn free-text log lines into structured events.

Each line is matched against an ordered list of regular expressions and given
an `event_type` (e.g. `SSH_LOGIN_FAILED`, `OSSEC_SYSCHECK_SCAN_STARTED`,
`PF_BLOCK_TCP`). Fields are pulled out: time, host, user, source IP, port,
process and so on.

Every line also gets a permanent ID (`record_id` for auth, `event_id` for the
others) and an entry in `*_event_lookup.csv`. That entry maps the ID back to
the original file, line number and exact text. Lines matching no rule are
kept as `*_UNKNOWN_EVENT` and counted, never dropped.

*Output:* one CSV of events per month, the event lookup, and a summary of
counts per type.

### Phase 2: Observations (`pipeline/phase2_observations/`)

**Goal:** decide *what* a detector should look at. A single line rarely looks
suspicious. A pattern of lines does. The same events are therefore grouped into
several **views** (the code calls them datasets):

| View | auth | ossec | pf, ipf (presence method) | One row is… |
|---|---|---|---|---|
| Single events | `individual` | `individual` | `individual` | one log line |
| Time windows | `host_5min` | `host_5min` | `slots_5min`, `slots_1h` | one host in a 5-minute bucket (presence: every slot of the year, empty ones included) |
| Sessions | `authentication_sessions` | `episodes` | `attempts`, `flow_episodes` | one SSH connection / one agent episode / one connection attempt or flow episode |
| Daily behaviour | `host_behavior_1d` | `host_behavior_1d` | `slots_1d` | one host per day, compared with its own past |

Each row counts things such as failures, distinct users, distinct ports and
first-time-seen values. Each view has a `*_lineage.csv` that lists which Phase 1
events make up each row (`row_manifest_id` to event IDs). Row IDs are hashes
of the row's content, so they stay stable when the data is rebuilt.

Building sessions is the hard part here, and each script's docstring
explains its rules. For example, an SSH session is keyed on
`(host, client IP, client port)` because not every line carries the username.

### Phase 3: Features (`pipeline/phase3_features/`)

**Goal:** turn each view into model-ready matrices without leaking the future.

- **Split by time, not at random:** first 70% train, next 15% validation, last
  15% test. There is a **purge gap** between splits, as long as the window
  (e.g. 5 minutes for `host_5min`, 1 day for daily views), so no window
  straddles two splits.
- **Four feature channels:** `numeric__*` (counts, rates, durations),
  `category_hash__*` (hashed categorical values), `text_hash__*` (hashed
  message tokens) and `sequence_hash__*` (hashed order of event types).
  Scaling and statistics are fitted on train only.
- **Names are not features** (since 2026-10-28): server and agent names,
  usernames and source IPs are no longer hashed in as categories or sequence
  words, and the source port is a category, not a number. Who an entity is
  enters only through its own baseline. OSSEC was retrained this way on
  2026-10-30; auth still has the earlier features until Phase 3 and the
  detectors are re-run (known gap 10).
- Output per view: `X_train/validation/test.npz` (sparse matrices), the row
  manifests, the split lineage and feature metadata.

The run is resumable. Checkpoints let an interrupted run on the 40 GB auth
data continue where it stopped.

### Phase 4: Detection (`pipeline/phase4_detection/`)

**Goal:** score every test row for "how unusual is this?" and decide which
rows become alerts. There are no labels, so every method is unsupervised.

**4a: Detectors** (`<source>_detectors.py`), the main path used downstream:

| Detector | Flags a row when… |
|---|---|
| Robust deviation | a stable numeric feature is far from its training median (a robust z-score) |
| Isolation Forest | the combination of features is easy to isolate from the rest |
| Novelty (rarity) | it contains categories, tokens or sequences rarely or never seen in training |

**Thresholds use an alert budget, not a fixed cut-off.** On the validation
split, each detector's threshold is set so that it would have raised about N
alerts per day (auth: 20 for single events, 10 for windows and sessions, 5 for
daily behaviour), capped at 1–5% of rows. This is how an unsupervised system
controls analyst workload. The test split is never used to choose anything.

Current test-period alerts (auth test period 7 Jun – 31 Jul 2026), auth
example: sessions 370 (Isolation Forest) and 1,202 (novelty) out of
1,421,114. Single events 118 and 1,991 out of 3,912,882.

**4b: Model zoo** (`<source>_model_zoo.py`), optional, run separately. It runs 12
unsupervised models on the same features: Isolation Forest, LOF, two one-class
SVMs, elliptic envelope, Gaussian mixture, kNN and k-means distance,
PCA and SVD reconstruction, HBOS and ECOD. An autoencoder is a 13th with
`--enable-autoencoder`. It drops models that
are broken, unstable or redundant, picks an ensemble, and outputs **consensus
alerts** (rows flagged by at least 3 ensemble members).

To compare models without labels, it uses a **proxy label**: "is this row
security-relevant", e.g. it contains a failure, an invalid user or a
sensitive-port block. That measures agreement with known-risky event types.
It is not true attack detection.

**4c: Model-zoo map** (`model_zoo_map.py --source …`) is a 2-D picture (PCA,
t-SNE or UMAP) of the model-zoo alerts against normal rows. Besides the test
period it holds about 12,000 rows from the earlier months, spread evenly, so
the map covers the whole study period and can be replayed over time in the
report (`--period test` maps the test period only).

With t-SNE, it also lays out the **same points with UMAP** (`map_layouts.py`,
written as `layout_umap.csv` beside the t-SNE files; `--no-layouts` skips it).
UMAP keeps more of the overall shape; both are only pictures, and the Phase 7b
groups stay the ones found on the t-SNE map. The console offers both. UMAP
needs `umap-learn` in the environment (tested: umap-learn 0.5.12, numba 0.68.0,
llvmlite 0.50.0, pynndescent 0.6.0) and takes 10 s to 2 min per view on the
laptop. To add it to existing maps without re-running 4c: `python pipeline/phase4_detection/map_layouts.py --source <auth|ossec>`.

**Reading the map.** t-SNE keeps neighbours together and nothing else: the
distances between islands, their sizes and their *shapes* mean nothing. The
striped, spindle-shaped OSSEC islands show why.

- **What a spindle is.** In each, every point is the same message from the
  same server, so only the time features differ. Each strand is one weekday,
  running from 00h at one tip to 23h at the other: hour and weekday place a
  point to 94–100%.
- **Why the tips pinch.** A point at the end of a strand has neighbours on one
  side only. t-SNE widens its neighbourhood to keep the perplexity (30), to
  almost twice the midday width, and that wider neighbourhood reaches the next
  weekday's strand: 36–40% of its weight, against 7–12% at midday. So the
  strands are tied together at the tips and pushed apart in the middle.
- **The evidence.** In the 32-number input the strands are evenly spaced at
  every hour; the pinch is made by t-SNE.

### Phase 4f: Sequential pattern mining (`pipeline/phase4f_sequences/`), steps 0–3 built

**Goal:** learn the *order* in which things normally happen, per server, and flag
sessions and episodes whose steps come in an order rarely or never seen. The other
detectors see order only as hashed word n-grams (known gap 4).

- **Step 0** (audit): event ordering, rotated-file copies and vocabulary,
  read-only ([findings](pipeline/phase4f_sequences/AUDIT_2026-10-08.md)).
- **Step 1** (streams): every AUTH session and OSSEC episode, Phase 2's own (same
  IDs, checked), as its complete event-type sequence in source order, with
  rotated-file copies merged (kept as aliases) and steps of uncertain order marked.
- **Step 2** (routines, training split only): the routine catalogue per server
  (whole sequences and closed PrefixSpan patterns), "after A, B follows" rules and
  a step-probability model.
- **Step 3** (the sequence detector): the surprise of each observation's rarest
  step, explained in words, under the existing alert budget with the training
  99.5% quantile as a floor. Its alerts go to Phase 7 as a seventh alert type.
- **Alert profile**: association rules (FP-growth) over every detector's test
  alerts, saying where they pile up (lift by server, time, event types).

It runs as phase **4f** of `run_pipeline.py` for auth and OSSEC. The console's
Review lists and explains its alerts (*Frequent subsequences*), and scores uploads
with the same code. Templates for known attack sequences, injected-attack
evaluation and a routines view are next. See the
[Phase 4f guide](pipeline/phase4f_sequences/README.md).

### Phase 5: Evidence (`pipeline/phase5_evidence/`)

**Goal:** make every alert checkable by a human. Each Isolation Forest outlier
is traced back from the row, through the Phase 3 and 2 lineage and the Phase 1
lookup, to the **original log lines**, in order. The phase checks that no link
in that chain is missing. It writes a message chain per alert, a detailed
per-line file, and a **review queue** with empty `review_label` columns for
an analyst.

### Phase 6: Report (`pipeline/phase6_report/`)

**Goal:** one offline HTML page per source for people who will not open CSVs.
Each report is laid out like an IEEE paper
([report_layout.py](pipeline/phase6_report/report_layout.py), shared by all
three). It starts with an Abstract and Index Terms, followed by these chapters:

1. Introduction, with an at-a-glance dashboard
2. Data
3. Methodology
4. Results: detections, model behaviour, model zoo, cluster maps, consensus
   alerts
5. Evidence and Analysis
6. Discussion
7. Recommendations
8. Conclusion

After the chapters come the References and two appendices. Appendix A
explains security, data-science and model-zoo terms in plain language, and
Appendix B explains the terms specific to that log type. Each chapter opens
with a plain-language explanation. The **cluster maps**
([cluster_maps.py](pipeline/phase6_report/cluster_maps.py)) embed the
Phase 4c t-SNE images with captions, link the interactive versions, and show
which category each map's alerts concentrate on.

**Model behaviour** ([model_behaviour.py](pipeline/phase6_report/model_behaviour.py),
shared by all three reports) checks that the detectors separate a thin tail
from the rest rather than flagging everything. It uses every scored
validation and test row: for auth single events that is 7.8M rows. The
training-period scores are not saved. It shows:
- score histograms with the threshold marked;
- how deep in the tail alerts sit, which is why the Phase 7 `probability`,
  a percentile, is always above 0.99;
- how many detectors flag each row;
- alerts per day against the validation average;
- a validation versus test drift table;
- model-zoo vote counts and per-model alert rates.

The first run reads the Phase 4 score files (about 75 seconds for auth's
6 GB) and caches the result in `model_behaviour_cache.json` beside the
report. `--no-model-behaviour` skips the section.

### Phase 7: Alerts (`pipeline/phase7_alerts/collect_alerts.py`)

**Goal:** one simple, stable hand-off format. For each source it writes one
CSV per alert type (robust, Isolation Forest, novelty, model-zoo consensus;
plus presence, silence and first seen where they apply, sequence for auth
and OSSEC from Phase 4f, and activity for auth and OSSEC from Phase 4g). Each
has five columns:

| Column | Meaning |
|---|---|
| `probability` | how unusual, 0–1 (percentile within the run). A ranking, **not** a probability of attack. |
| `flagged_by` | which detectors or models raised it, e.g. `Isolation Forest + Novelty` |
| `dataset` | which view produced it, e.g. `host_5min` |
| `raw_messages` | the original log lines, joined with ` \| ` |
| `row_manifest_ids` | the observations behind it, as `<view>:<row_manifest_id>` joined with `; ` (added 2026-10-01) |

The files accumulate across runs. The same alert seen again is merged, keeping
the highest score; `--reset` starts them afresh. Current sizes: auth 1,446 /
3,407 / 21,500 (IF / novelty / consensus) and no robust alerts, ossec 1,028 /
851 / 195 plus 36 robust, pf 115 / 115 / 115 day alerts plus 296 presence
alerts (flow episodes) on the presence method, ipf 9 / 9 / 9 plus 5. The
coverage checks add silence and first-seen files: auth 8 / 39, ossec 3 / 4,
pf first-seen 14. That is 29,204 rows in all. The files were rebuilt on
2026-10-01 when `row_manifest_ids` was added, and OSSEC now holds the current
run's alerts only; before that the total was 30,257. The activity files
(added 2026-10-27) also keep the alerts of earlier Phase 4g rules: 738 rows for
auth and 515 for OSSEC, against 218 and 14 from the current rule; `--reset`
keeps only the current run's.

### Phase 7b: Behavioural clusters (`pipeline/phase7b_clusters/`)

**Goal:** let analysts work cluster by cluster rather than alert by alert. Every
test-period observation gets a cluster ID, a pseudo-label for "this kind of
activity". HDBSCAN finds the islands on the Phase 4c t-SNE map. Every
unmapped row then takes the island of its nearest mapped neighbours in the
embedding the map was drawn from. A built-in check measured this at 89.5–100%
per view on the maps of 2026-10-01, lowest for daily behaviour. Outputs:
- a per-cluster summary: size, alert rate, dominant servers and events, time
  span, example lines;
- a map labelled with cluster numbers;
- an alert file with cluster IDs that Phases 8 and 9 read directly.

It runs with `--with-model-zoo`, and rebuilds the Phase 6 report, whose Results chapter then shows the numbered cluster maps and the clusters most worth reviewing. See its [README](pipeline/phase7b_clusters/README.md).

In the report, each view's cluster map is **interactive and replayable over
time**: press Play or drag the slider to bring the points in month by month
(or week by week), cumulatively or one period at a time, optionally flagged
points only; hover for a point's date and cluster, click to highlight a
cluster. It is plain JavaScript inside the report file, so it works offline.
The cluster table also says in which month each cluster first appears.

### Phase 8: Maliciousness classifier (`pipeline/phase8_malice_classifier/`), in progress

**Goal:** Phases 1–7 answer "is this unusual?". Phase 8 answers "does this
look malicious?". It is a text classifier (TF-IDF baseline and fine-tuned
BERT/SecureBERT) that reads an alert's `raw_messages` and outputs
`malicious_score`, to sort the Phase 7 alerts before a person looks at them.

It needs labelled examples. The labelling assistant groups near-identical
alerts so that one representative per group is labelled, in
`data/phase8_malice_classifier/to_label/`. On the current 29,204 alerts that
is about 592 rows (auth 508, OSSEC 65, PF 17, IPFilter 2), because normalising
collapses them into 5,893 distinct ones (before the Phase 7 rebuild: 30,257 →
6,328 → 635). Grouping by Phase 7b cluster instead (`--cluster-column
cluster_id`) needs about 130 (auth 90, OSSEC 40). The sheets on disk date from
before the 2026-09-30 re-run and should be regenerated. No model has been
trained yet. See its
[README](pipeline/phase8_malice_classifier/README.md).

Analysts label in the four triage categories shared with Phase 9. The model
itself stays binary: `security_relevant` against the rest. The console's
Review page records the same categories plus *suspicious*; decision Q21 maps
them to Phase 8 labels (security relevant positive; expected behaviour and
operationally interesting negative; the rest unlabelled). The export is not
built yet.

### Phase 9: LLM triage (`pipeline/phase9_llm_triage/`), built, needs a local model

**Goal:** sort alerts into four categories an analyst can act on:
`security_relevant`, `operationally_interesting`, `expected_behavior` and
`insufficient_context`. A local small language model reads each alert's log
lines with:
- a primer for the log type;
- the most relevant attack patterns and **red herrings** (benign activity that
  looks like an attack) from an offline knowledge base;
- a list of **approved administrative automation** IP addresses, given in the
  system prompt.

Approval informs the judgement but does not whitelist: an approved address
behaving unlike automation is still judged on that behaviour.

The prompts carry log lines, accounts and addresses, so `--endpoint` must be on
this machine (localhost, 127.0.0.1 or ::1): any other address is refused, and
redirects are not followed, as in the console's language-model setting.

The runner and prompts are in place and tested in dry-run mode. It needs a
local model server, such as Ollama with `qwen2.5:3b-instruct`, and an
approved-address list from the security team. Both are described in its
[README](pipeline/phase9_llm_triage/README.md). At roughly a minute per alert
on a laptop CPU, it should triage the Phase 8 cluster representatives, not
every alert.

`simulate_triage.py` writes a hand-made baseline in the same format. On the
single-event OSSEC and PF alerts it found nothing malicious: OSSEC's 514
alerts are four benign findings (a log-rotation fault on mm06moc, mm04kco's
agent losing its manager, three 02:00 maintenance windows, an off-schedule
scan), and PF's 2,884 are six findings, four of which need site context
(192.168.0.5, 173.16.10.0/24, 200.1.1.2 and 64.1.1.253, one IEC-104 packet).

---

## The presence method: a baseline of silence (PF and IPFilter)

Both firewall logs are **empty, or nearly, when all is well**. mm06moc runs
IPFilter: 11 of its 12 monthly files have no lines, and all 52,231 lines fall in
November 2025. PF, with the 2022–24 leftover captures left out, has 3,415
packets on 41 of 365 days. Auth and OSSEC learn "normal" from their lines;
here there are hardly any normal lines, and a chronological split either puts
the activity into training or leaves too few active days to judge (PF's old
detectors refused to run for exactly that reason). So both logs use the
**presence method**: Phases 2–6 are the `presence.py` scripts
(`presence_detectors.py` for 4a), run with `--source ipf` or `--source pf`;
Phase 1 stays per source. The old PF scripts and outputs are in
`outdated/pf_classic_2026-10-01/`.

| Phase | What the presence method does |
|---|---|
| 1 | Per source. IPFilter: parses ipmon lines (rule, action, addresses and ports, flags, the "2x" repeat count) and records every monthly file, **including the empty ones**. PF: the existing parser, without the leftover files. |
| 2 | Time **slots** (5 minutes, hour, day) per server over the whole year, empty slots included (IPFilter: 105,120 five-minute slots, 1,672 active; PF: 1,471,680 on 14 servers, 410 active). A server-day counts as quiet only if it is **certified**: the month's file exists and another log shows the server was up (OSSEC for IPFilter; auth or OSSEC for PF). Activity views: connection attempts (a SYN, its retries and the reset) and flow episodes (attempts on one flow with no pause over 30 minutes). A flow is keyed by its service side, so a server's replies to many client ports are one flow. PF lines are normalised to the IPFilter field names. |
| 3 | Count features per slot, without time of day (the baseline is empty at every hour). The split is by **regime**: certified days with no lines are the baseline, whose earliest 85% train and last 15% set thresholds; every other certified slot is scored. |
| 4a | Robust deviation with a floor of one count (the baseline median and spread are both zero), Isolation Forest fitted on all certified slots, novelty against the baseline tokens. **Zero tolerance** replaces the alert budget: alert above the highest quiet validation score. Result: every active slot flagged, no quiet slot flagged, at every time scale. Every active row is an alert by policy, so the detectors also **rank the activity against itself** (rare attributes by share of lines, or odd shape). The model zoo, map and clusters (4b, 4c, 7b) are skipped: an all-zero baseline gives them nothing to fit. |
| 5 | Evidence for every alert (IPFilter: 9 active days, 5 flow episodes; PF: 115 and 296), plus **context from the other logs**: the other firewall log, SSH logins from each address, the name OSSEC gives it, and liveness. |
| 6 | The same IEEE report, with a 12-month timeline, the presence check, the episodes and the within-activity ranking. |
| 7 | One extra file, `<prefix>_cumulative_presence_alerts.csv`: one alert per flow episode, whose `probability` is its rank among those alerts (1.0 = least like the rest of the activity). The daily alerts go to the usual robust, Isolation Forest and novelty files. PF also keeps the first-seen check (4e). |
| 9 | An `ipf` primer, attack patterns and red herrings, and **approved change windows** (`site/approved_change_windows.csv`): planned changes such as a migration, matched to each alert's lines in code. |

What the November activity is: 52,223 lines are one flow, 172.16.10.29
retrying a connection to mm06moc (172.16.10.26) on port 9711 every 75 seconds
for about 140 hours over three bursts (Nov 23, Nov 24–27, Nov 28–30), blocked
every time. Port 9711 is used between many servers in the PF logs, so this
looks like an application that could not reach its peer after a migration.
The other 8 lines are SNMP broadcasts from 172.16.10.111 on Nov 6 and Nov 27,
unrelated to that flow; they rank first within the activity.

What PF's activity is: the bulk (2,475 of 3,415 packets) is the March 2026
licence-server broadcasts from 192.168.0.5, which therefore rank low within
the activity. The top of the ranking is the single IEC-104 telecontrol reset
(10.2.101.11, May 2026), a burst of X11 traffic from 172.16.10.27 to
172.16.10.19 on mm04kco (May 2026), FTP (port 21) from 172.16.10.201 and
172.16.11.201 to admikco (September 2025), and late packets to port 1023.
Recurring port-9711 traffic between the servers ranks at the bottom.

---

## Coverage, silence, first seen and context (auth, OSSEC; PF first seen)

Four steps borrowed from the IPFilter work run for auth and OSSEC. They look at
what the main views cannot: days with no lines, and context from the other
logs. PF runs only 4e: since PF moved to the presence method, its Phase 2 and 5
already cover coverage and context, and the runner skips 2c, 4d and 7c for it
(the scripts still accept `--source pf`).

| Step | Script | What it adds |
|---|---|---|
| 2c coverage | `phase2_observations/coverage.py` | One row per host per day, empty days included: whether the month's file was collected, whether the host logged, and whether the **other** logs show it was up (auth for OSSEC, OSSEC for auth, both for PF). Days are *active*, *quiet* (host up, nothing logged), *collection gap* (host up, file empty or missing) or *unknown* (no log shows the host up). For PF an empty file means nothing was blocked, so it counts as quiet. |
| 4d silence | `phase4_detection/silence_detectors.py` | One alert per run of days on which a host logged nothing while other logs show it was up, when that run is unlikely for that host (a chance under 1 in 1,000, given how often it is silent). Works the same for an auth log with hundreds of lines a day and an OSSEC agent that writes four. |
| 4e first seen | `phase4_detection/first_seen.py` | Zero tolerance, no daily cap: every event type, and for auth every login source and account, that a host shows for the first time in the test period. |
| 7c context | `phase7_alerts/context.py` | For every address in the alerts: SSH logins from it across all servers, PF and IPFilter lines naming it, the name OSSEC gives it, and whether it is approved or public. Rebuilds the report afterwards, like 7b. |

Each report gains a coverage section (Data), silence and first-seen sections
(Results) and a context section (Evidence), and Phase 7 two alert files,
`*_cumulative_silence_alerts.csv` and `*_cumulative_first_seen_alerts.csv`.

What they found on the current data:
- **Auth, 8 silences.** mm05kco logged nothing for 77 days (25 Sep – 10 Dec 2025)
  and 23 days in Aug–Sep while its OSSEC agent kept reporting; its October and
  November auth files in the archive are empty. Six 2–3 day silences on mm
  servers that usually log 200–300 lines a day.
- **OSSEC, 3 silences.** mm03kco's agent was silent for 17 days (19 Dec 2025 –
  4 Jan 2026) while auth shows the server in use, with mm01kco and mm02kco
  silent 19–22 Dec. An agent going quiet is what switched-off monitoring looks
  like; here it looks like a holiday collection issue, but only this check
  could raise it.
- **Coverage.** dewskco has no auth or OSSEC lines from January 2026 except
  February (184 days unknown); devlkco 41 and mm07kco 17 unknown days. So "15
  servers, 12 months" overstates the coverage for those servers.
- **First seen.** Auth: 39, including the failed login for the non-existent
  user `maint1` on com1kco (2026-07-13), accounts `din1` and `sha1` logging in
  to admin servers for the first time, and 172.16.10.157 (1,062 root logins,
  only to mm04kco, on two days from 28 June). OSSEC: 4 new error types, all in
  maintenance windows.
- **Context.** The 12 public-range addresses in the auth alerts are all
  173.16.10.10–.21, mirroring the internal 172.16.10.10–.21 numbering, with
  thousands of logins over months: most likely a second administration
  network, still to be confirmed.

**Change windows in training.** Training rows inside an approved change window
(`pipeline/phase9_llm_triage/site/approved_change_windows.csv`) are left out of
the Phase 4a detectors' and the model zoo's training samples, so a maintenance
night never teaches the models what normal looks like. The file is empty
today, so nothing changes until a window is recorded. `HUH_CHANGE_WINDOWS`
points the pipeline at another file, for testing.

---

## Activity, not lines (auth, OSSEC; Phase 4g)

`phase4_detection/activity_detectors.py`. Every other detector judges a line,
session or window by what it says (event type, words, tokens) and how rare that
is. This step ignores what a line says: a line is one unit of activity, at a
time, on a server, from a source IP, for a username, to a destination IP. It is
the busy-log counterpart of the presence method, which also ignores rarity but
takes normal activity to be none; here normal is learned from training.

| View | One row per | Judged against |
|---|---|---|
| `activity` | 5-minute step of the whole log, empty steps included (steps next to a day with no lines at all are left out) | the log's own training history |
| `activity_by_entity` | 5-minute step in which a server, source IP, username or destination IP (OSSEC) has a line | that entity's own training history (its entity type's pooled history when it has fewer than 30 training rows) |

Features, built as in Phase 3 but from activity only: lines in the trailing 5,
30, 120 and 720 minutes with their log twins (four windows since 2026-10-28: on
the real data they gave the same alerts and caught the same injected anomalies
as the seven used before, 5 to 720 minutes); active steps in the
last hour and 12 hours, minutes since the series' previous line and two burst
ratios; how many other servers, IPs, users and destinations were involved in the
step; each of these less the series' own training median, and less its median at
the same hour of day; and Phase 3's time features plus day-of-week sine and
cosine. Since 2026-10-28 also:

- **Outcome** (auth, with Phase 2's own success and failure rule; OSSEC states
  none): failures in each window, the failure share, failures in the 30 minutes
  before a success (a guess that worked), and how many usernames, IPs or servers
  failed in a step (one IP failing on many usernames is password spraying).
- **Relations**: partners met for the first time (a username on a new server or
  from a new IP, an IP on a new server), per step and over 2 hours, after a
  14-day warm-up in which every pair is new.
- **Context** (with `pipeline/phase9_llm_triage/site/assets.csv`, empty until
  filled): each server's, address's or network's zone, role and criticality.
  Lines crossing zones are counted; an entity without its own history is
  compared with its peers of the same role; a high-criticality asset's alerts
  rank higher (score x1.5, medium x1.2).
- **Regularity**: how even the per-step counts were over the last hour and the
  gaps over 12 hours (0 for a steady beacon, about 1 for random arrivals).

The model zoo's filters drop constant, shifted and near-copy features
(`feature_decisions_<type>.csv`). Names are never features: who an entity is
enters only through its own baseline; neither are addresses as numbers or
locations looked up from them. Phase 3 follows the same rule since 2026-10-28:
server, agent and usernames and source IPs are no longer hashed in as
categories or sequence words, and the source port is a category, not a number
(rerun Phase 3 and the detectors to retrain without them).

Detectors (the rule since 2026-10-28: a step is flagged for being unusual for
that series at that time, not to fill a daily quota):

- **Robust deviation** measures three things: lines (both ways), failures
  (auth, upwards, from 10 failures in the window: a handful is everyday) and new
  partners over 2 hours (upwards, against the level only), each against its own
  threshold, so a noisy channel cannot raise another's bar. Lines and failures compare each of the four windows two ways, as robust
  z-scores of log(1 + lines): with the same clock window on the series'
  comparable training days (the same weekday's, public holidays apart, else the
  same kind of day's; quiet days count as 0), and with its level whenever it is
  active (its entity type's pooled level below 30 active training steps). A
  window counts when both agree, by the smaller, so a routine morning peak or
  nightly job is normal and a few lines at an odd hour are not a burst. Without
  comparable days (first seen late in training or after it), the level alone,
  upwards only. A drop counts only for a series with its own level that usually
  has at least 20 lines in that window.
- **Isolation Forest**, per view and entity type on a balanced sample, is a
  second opinion: it raises the score of an alert it agrees with, and alerts on
  its own only when a step is more isolated than every training step (by
  chance, 1 in n + 1 for n training steps).
- **Thresholds** are a fixed bar (z of 3), with Phase 4a's validation budget (2
  steps a day per detector and entity type, at most 1% of validation rows) only
  as a ceiling; a quiet test period gives no alerts. On the made-up test log with
  one planted burst, only that burst alerts (42 alerts before this rule, 5 after).
- **False discoveries** (2026-10-30): thousands of steps are tested a day, so the
  bar alone lets some through by chance. Each step's z also gets a p-value from
  the null of validation's earlier half (empirical in the body, an exponential
  tail fitted beyond its top values), and Benjamini–Hochberg at 5% across each
  day's steps must pass too. The summary keeps the count the bar alone would raise.
- **Shrinkage** (2026-10-30): a weekday baseline from few comparable days is drawn
  toward the series' all-days baseline at the same clock time, weight n / (n + k),
  k chosen on validation's earlier half. `--fdr 0 --shrinkage-days 0
  --calibration-split all` gives the earlier rule.

Alerting steps of one series less than an hour apart are one alert, whose
evidence is a written description and the peak step's lines. Alerts that are one
event or one routine are grouped into **incidents** (`activity_incidents.py`,
`incidents.csv`): the same entity and channel at about the same clock time on 3+
days, one incident per entity and channel with each clock time (recurring);
entity alerts of different types peaking within 60 minutes whose entities shared a
line in those peak hours (linked; an event joins a routine, but two routines
never merge); and a whole-log alert as context of the strongest same-channel
entity alert peaking within 60 minutes when that alert is part of a routine (a
whole-log routine forms from the rest, and one-off entity alerts join it). Review and Explain list one item per incident. The report gains an *Activity* section
(Results), Phase 7 the file `*_cumulative_activity_alerts.csv`, and the console's
Review lists each alert as an item to label (FR-REV-16).

Each alert also gets a plain-language explanation (`activity_explain.py`,
`explanations.jsonl`): the usual range at that time on the same comparable days
the detector used (quiet days count as zero), up to four ranked
reasons, and the data for the console's **Explain** tab: the day against its usual
band, the week as a heatmap and eight weeks of daily totals. Saturdays, Sundays and
the public holidays in `pipeline/phase9_llm_triage/site/public_holidays.csv` are
non-working days, for the explanations and as a model feature.

On the study data (auth 2026-10-29, OSSEC 2026-10-30): auth gives 218 alerts in
42 incidents (5 recurring, 5 linked, 32 single), OSSEC 14 alerts in 10 incidents
(1 recurring). `python scripts/activity_alert_counts.py <auth|ossec>` breaks
them down by detector, entity type and window, with counts only.

---

## Profiles (every source; Phase 4h)

`phase4_detection/activity_profiles.py`. The same counts as Phase 4g, kept for
every entity whether it alerted or not: lines per hour for the whole log and
each server, source IP, username and destination IP, lines per day for each pair
of them (who touched whom), and the P10, median and P90 of each entity's daily
totals on each weekday's training days (public holidays apart; quiet days count
as zero). One SQLite file per source,
`data/phase4_detection/<source>/profiles/profiles.sqlite`, read by the console's
**Profiles** tab, which draws any entity on any day with Explain's charts
(`activity_explain.profile`) and keeps a watch list for the Dashboard.

| Source | Normal |
|---|---|
| auth, OSSEC | the training period of the Phase 3 split, as for Phase 4g |
| PF, IPFilter | the presence method's: no activity, so every line counts (Phase 3 splits these by regime, not by date) |

PF's server is the host in the source file's name; its `*_tmp` captures are
left out. The file holds addresses and usernames, like the Phase 1 files.
Built for auth, OSSEC and IPFilter so far; PF's is made by its next run.

---

## How to run

Everything runs from the project root, with the virtual environment in `.venv`.

```
python run_pipeline.py --source pf                       # phases 1-7 for PF
python run_pipeline.py --source auth --from-phase 4a     # rerun detection onwards
python run_pipeline.py --source ossec --with-model-zoo   # include 4b, 4c and 7b
python run_pipeline.py --source pf --resume              # skip phases already done
python run_pipeline.py --source auth --dry-run           # show the commands only
python run_pipeline.py --source ipf                      # IPFilter: phases 1-7 in about 30 seconds
python run_pipeline.py --source auth --only-phase 4d     # one step, e.g. the silence check
```

The default run includes the coverage steps (2c, 4d, 4e, 7c) and the activity
step (4g) for auth and OSSEC, 4e for PF, and the profiles (4h) for every source. `--dry-run` prints the plan without running anything or
changing the last run's summary.

Any phase can also be run on its own, e.g.
`python pipeline/phase5_evidence/ossec.py`. Each script's docstring lists its
inputs, outputs and options. Runner transcripts go to
`data/pipeline_runs/<source>/`.

Every script writes the same lines to stderr, `date time | runtime HH:MM:SS.s | LEVEL | message`,
and takes `-v`/`--verbose`, `-q`/`--quiet` and `--progress-interval SECONDS`. The rules for names,
console output and options are in [pipeline/STYLE_GUIDE.md](pipeline/STYLE_GUIDE.md); the one
implementation is `pipeline/shared/runlog.py`.

Rough cost: phases 1–3 for auth take hours (26.1M lines, about 54 GB of
features). PF and OSSEC take minutes, IPFilter seconds. Phases 5–7 take seconds to minutes.

---

## Measuring it: precision, recall and drift

Every number above describes the alerts raised. These say how good they are, and how far the baseline still fits:

| Question | Where | How |
|---|---|---|
| What is the real precision, and what is missed? | Investigate → *Audit*; Dashboard → *Audit* | Each month a blind, stratified random sample of the test period (AUTH sessions, OSSEC episodes: 10 unflagged, 10 lower-ranked and 5 higher-ranked flagged per log type), labelled with no score or flag in view. Population-weighted precision of the flagged, missed relevant per 10,000 unflagged, and recall, with Jeffreys 95% intervals; per mechanism, precision on Kish's effective n. The only unbiased estimates: Review's labels fall on what was surfaced. Audit labels never train anything. |
| Which mechanism's alerts turn out to matter? | Dashboard → *Label yield* | Per mechanism, the labelled Review items it raised (n), the share labelled Security relevant or Suspicious and the share Expected behaviour. Biased toward the top of the queue; read it beside the Audit. |
| What would DAD catch? | `python -m service.inject_eval DAY.log [DAY2.log …] --month YYYY-MM` (in `triage-console`) | Made-up attacks planted one at a time into held-out days of real AUTH lines and scored as an upload is: outsiders (guessing, spraying, enumeration, login after guessing, a night root login, a new account switching to root, low and slow), insiders on the day's own account and address (a night login, a burst, guessing, a switch to root) and sweeps (3 to 50 guesses; one guess every 5, 20 or 60 minutes), each at --repeats start times. Recall per mechanism, scenario and family with Wilson 95% intervals, filed per model version. Use days from the test period or later. |
| Does the baseline still describe new lines? | Analyze, each view | KS D of the new observations' Isolation Forest percentiles against Uniform(0, 1), judged against the 99th percentile of D for validation blocks of the same size (ordered by server and time, as an upload is), and the share naming a server, account or address new since training. |
| Is the alert rate what was budgeted? | Models → each view's Details, *Test ÷ budget* | Validation's earlier half chooses (features, models, ensemble members) and its later half calibrates (every threshold), so the check is honest: the test alert rate over the rate the budget allowed, per detector and for the ensemble (1 = calibrated). |
| Does "consensus" count ideas or near-copies? | Phase 4bf (`zoo_families.py`), Models → *Families* | Ensemble members grouped by agreement on validation (Jaccard or Spearman ≥ 0.6, average linkage); a consensus alert needs two families, not three models. |
| Do the features kept detect attacks? | `python -m service.feature_ablation DAY.log --month YYYY-MM` | Each selected feature neutralised in turn on the planted days: the planted detections lost, against the zoo's ranking (Spearman's rho). A diagnostic; the selection rule changes only if they disagree. |
| Is it the server or the behaviour? | `python pipeline/phase4_detection/host_identity_check.py --source auth` | Each server's flagged share against its training rows (Spearman), and the most-flagged servers' alert rates with and without their own training rows. Servers are numbered in the output, never named (known gap 5). |
| Was an attack learned as normal? | Sigma → *Training period* | The enabled Sigma rules over the training period, events per rule. |
| What can these logs see at all? | Sigma → *ATT&CK for ICS* | Each ICS technique as visible, partly, with event logs, not visible or none listed, from the data components MITRE's detections read and those each log records. Today 3 visible, 65 partly, 21 not visible. |

---

## Version control and data handling

**Once per clone:** `python scripts/git_guard.py setup` (the hooks, the name filter and the identifier list). Then:

- **Never in git:** logs and everything derived from them (`data/`, `runtime/`, `triage-console/var/`, any
  database, pickle, array or model file), the site lists (`site/*.csv` but the public holidays), findings
  (`HYPOTHESIS_REGISTER.md`, `PRESENTATION_PREP.md`), console screenshots, release archives and secrets. A commit
  that holds one is refused, even with `git add -f`.
- **Real names become pseudonyms in git.** The name filter (`.gitattributes`) turns every server, address and account
  that Phase 4h (or, for PF until 4h runs, Phase 1) has seen into a stable pseudonym (`srv-07`, `acct-03`, an address
  in 198.18.0.0/15) as a file enters git, and back as git writes it out. Your files read as before; a clone without
  the key in `.git/` shows only pseudonyms. Rebuild the list after a new Phase 4h run: `python scripts/git_guard.py identifiers`.
- **A push is checked:** every file in the pushed commits for refused paths and real names, then
  `python scripts/check.py` (the console's and the pipeline's tests and the web build). Run that yourself before a release.
- **Releases are tags** (`v0.2.0`), matching VERSIONS.md.
- **Before any push:** confirm that the organisation allows this code, even pseudonymised, in the chosen remote.

**On the laptop:** the logs and everything derived from them stay on this laptop, which is BitLocker-encrypted.
The console keeps its own copies of log lines (uploads' lines, Dashboard SQL results) only as long as Settings →
Retention says (12 months by default; agree the period with the data owner); reports are records and follow the
records schedule. Back up the console's own data with `python -m service.backup create --to <folder>` (and
rehearse a restore with `python -m service.backup rehearse`); a backup holds log lines, so it goes where the logs
may go. **When the project ends**, delete `data/`, `runtime/`, `triage-console/var/` (backups included) and
`.git/identifier_*.json`, or have IT reimage the laptop.

---

## Folder map

```
run_pipeline.py                  one runner for all phases and sources
pipeline/
  phase1_classify/               auth.py  ossec.py  pf.py  ipf.py
  phase2_observations/           auth.py  ossec.py  presence.py (pf, ipf)  coverage.py (2c)
  phase3_features/               auth.py  ossec.py  presence.py (pf, ipf)
  phase4_detection/              auth_/ossec_detectors.py  auth_/ossec_model_zoo.py  model_zoo_map.py
                                 presence_detectors.py (pf, ipf)  silence_detectors.py (4d)  first_seen.py (4e)
                                 activity_detectors.py (4g; auth, ossec)  activity_incidents.py
                                 activity_explain.py  activity_profiles.py (4h)
  phase4f_sequences/             run_sequences.py (4f: streams, mine, score, profile_alerts)
  phase5_evidence/               auth.py  ossec.py  presence.py (pf, ipf)
  phase6_report/                 auth.py  ossec.py  presence.py (pf, ipf)  report_layout.py  coverage_sections.py
                                 model_behaviour.py  cluster_maps.py  timeline_map.py
  phase7_alerts/                 collect_alerts.py  (--source auth|ossec|pf|ipf)  context.py (7c)
  shared/                        sources.py (archive inventory, per-host-day counts, change windows), profiles.py,
                                 runlog.py (console output and options for every script)
  STYLE_GUIDE.md                 names, console output and command-line conventions
  phase7b_clusters/              assign_clusters.py (--source auth|ossec)
  phase8_malice_classifier/      see its README
  phase9_llm_triage/             triage.py (4-category SLM triage), simulate_triage.py, suggest_automation_ips.py,
                                 site/ (approved IPs, change windows, assets, holidays), backend/app/prompts, backend/app/knowledge
scripts/                         git_guard.py and git_names_filter.py (what git may hold), check.py (every test and the
                                 web build), assets_template.py (assets.csv as blanks), activity_alert_counts.py,
                                 freeze_runtime.py, version_control.py, whitepaper tools
data/
  phase0_raw/                    archives/  auth/  ossec/  pf/  ipf/
  phase1_classify/<source>/ … phase7_alerts/<source>/
  phase4_detection/<source>/     detectors/  model_zoo/  model_zoo_map/  silence/  first_seen/  sequences/ (4f scores)
                                 activity/ (4g alerts, incidents.csv, explanations)  profiles/ (4h)
  phase4f_sequences/<source>/    streams/  routines/ (catalogue and rules)
  phase7b_clusters/<source>/     row_clusters, cluster summaries and maps, alerts by cluster
  phase8_malice_classifier/      to_label/
  review_labels/<source>/        analyst labels read by Phase 4a (empty so far)
  pipeline_runs/<source>/        runner transcripts
triage-console/                  Project DAD (Data Anomaly Detection) Console: local web app over these results (see its README)
outdated/                        superseded scripts and results, kept for reference
```

<details>
<summary>Old name → new name (restructure of 2026-09-29)</summary>

| Old | New |
|---|---|
| `inputs/` | `data/phase0_raw/archives/` |
| `extracted_{auth,ossec,pf}logs/` | `data/phase0_raw/{auth,ossec,pf}/` |
| `{auth,ossec,pf}_logs/` | `data/phase1_classify/<source>/` |
| `*_ml_datasets/` | `data/phase2_observations/<source>/` |
| `*_ml_features_explainable/` | `data/phase3_features/<source>/` |
| `*_ml_experiments_*explainable_lineage/` | `data/phase4_detection/<source>/detectors/` |
| `*_ml_model_zoo_experiments[_v2]/` | `data/phase4_detection/<source>/model_zoo/` |
| `*_ml_model_zoo_visuals/` | `data/phase4_detection/<source>/model_zoo_map/` |
| `*_ml_isolation_evidence_explainable_lineage/` | `data/phase5_evidence/<source>/` |
| `*_ml_reports/` | `data/phase6_report/<source>/` |
| `*_ml_cumulative_alerts/` | `data/phase7_alerts/<source>/` |
| `*_ml_review_labels/` | `data/review_labels/<source>/` |
| `<source>logs_stage1_*.py` … `stage6_*.py` | `pipeline/phaseN_<name>/<source>.py` |
| `<source>logs_stage4_experiment_runner.py` | `pipeline/phase4_detection/<source>_detectors.py` |
| `<source>logs_stage[_]4_model_zoo_benchmark.py` | `pipeline/phase4_detection/<source>_model_zoo.py` |
| three `*_stage4.5_visualize_models.py` | `pipeline/phase4_detection/model_zoo_map.py` |
| three `*_stage7_cumulative_alerts.py` | `pipeline/phase7_alerts/collect_alerts.py` |
| `pflogs_/osseclogs_stage1to6.py` | `run_pipeline.py` (now covers auth too) |
| `authlogs_stage2.5_observation_builder.py` | `outdated/` (older copy of the auth Phase 2 builder) |
| `malice_classifier/` | `pipeline/phase8_malice_classifier/` |
| `llm_triage/` | `pipeline/phase9_llm_triage/` |

Inside the code, phases are still called "Stage N" in places. Stage N is Phase
N, and the model-zoo steps were "Stage 4b" and "4.5". A copy of every script
before the restructure is in `outdated/pre_refactor_2026-09-29/`, together
with `moves.json`, which lists every move.
</details>

---

## Status and known gaps

1. **No labelled attacks.** This is the biggest limitation. All quality
   measures so far are proxies. The fastest route to real numbers is labelling
   the Phase 8 sheets (and the Phase 5 review queues), or reviewing in the
   console once its labels can be exported (Q21). Measures that need no
   labelled attacks now exist: the Audit sample (unbiased precision, misses and
   recall, once labelled), planted-attack recall (`service.inject_eval`), and the
   Dashboard's label yield; none has been run on real data yet.
2. **Fixed and re-run (2026-09-29/30).** Auth and OSSEC used to stop at April
   2026, because from May the archives changed their file names and Phase 1
   skipped them. OSSEC events also all had the host `nsewl`, so its per-host
   views treated 15 servers as one. Both are fixed, and all three sources,
   including the model zoo, Phase 4c maps and Phase 7b clusters, were re-run
   on 12 months. Numbers in this README are from that run.
3. **The robust detector is silent on auth** (0 test alerts in every view).
   About 93,000 validation events share the top score, so the budget
   threshold lands on the tie and ends just above all of them. Break the ties
   or drop the feature.
4. **Session event-order hashing is saturated.** Over all 9.5M auth sessions,
   2,422 distinct event-run tokens share 256 columns, up to 27 per column. At
   4,096 columns about 45% would still share. One flag in Phase 3
   (`--sequence-hash-features`), then re-run Phases 3–7. Phase 4f now has the
   exact alternative: the year's sessions are only 306 distinct complete
   event-type sequences, and its routine patterns could replace these columns.
5. **Model-zoo alerts pile on the `mm` servers.** 77% of auth-session ensemble
   alerts (4,420 of 5,772) are on `mm` servers, 46% on `mm04kco` alone. This
   may be "rare server" rather than "rare behaviour"; labels will tell. The
   Phase 4f alert profile (association rules) supports "rare server": two in
   three of mm04kco's test sessions are consensus alerts, an `mm` login ending
   by inactivity is flagged 94% of the time, and 98.7% of the Isolation Forest
   session alerts carry an `SSH_DEPRECATED_OPTION` warning line.
6. **PF moved to the presence method (2026-10-01).** With the leftover
   2022–24 captures left out, PF has 3,415 packets on only 41 days, too few for
   its old detectors (they need 70 active days) and for the model zoo, which
   flagged 81% of its test rows. The earlier PF detector results were learned
   mostly from the leftovers and are archived in `outdated/pf_classic_2026-10-01/`.
   PF now has no model zoo, map or behavioural clusters.
7. **IPFilter activity is unexplained until the change record is checked.**
   The November 2025 burst on mm06moc (port 9711, blocked every time) looks
   like a migration, and the SNMP broadcasts from 172.16.10.111 look like a
   monitoring tool. Neither is confirmed. Record the migration in
   `site/approved_change_windows.csv` once confirmed, and ask whether the
   9711 service should have been reachable.
8. **The time features lay out the repetitive OSSEC islands.** In an island
   of one message from one server, the map spends both of its dimensions on the
   hour and the weekday (see *Reading the map* under Phase 4c). The shape does
   not change which island a point is in, but inside such an island the map
   shows when routine chatter happened, not what it was. The time features
   stay in on purpose (decision Q27, 2026-10-06): when routine activity
   happens is itself part of whether it is routine.
9. **The approved-automation list is empty.** `suggest_automation_ips.py`
   proposes candidates (172.16.10.41, 173.16.10.14, 172.16.11.13); owners
   must confirm them before Phase 9 runs for real.
10. **Auth still uses names as features.** Phase 3 dropped them on 2026-10-28
    and OSSEC was retrained on 2026-10-30; auth needs
    `python run_pipeline.py --source auth --from-phase 3 --with-model-zoo`
    (hours), after which its model-zoo pile-up on the `mm` servers (gap 5) can
    be compared.
11. **The asset list is empty.** `pipeline/phase9_llm_triage/site/assets.csv`
    (zone, role and criticality per server, address or network) needs the
    network inventory; until then Phase 4g has no zone crossings, peer baselines
    or criticality weights. `python scripts/assets_template.py` lists every
    server and /24 network seen, with the three columns blank to fill in.

## Glossary

| Term | Meaning |
|---|---|
| Observation / view | One row of a Phase 2 dataset: an event, window, session or day. |
| `row_manifest_id` | Stable ID of an observation, used to link every phase. |
| Lineage | The mapping from an observation back to its source log lines. |
| Alert budget | The target number of alerts per day, used to set each threshold on validation data. |
| Novelty / rarity | Something that was never, or rarely, seen in the training period. |
| Consensus alert | A row flagged by at least 3 model-zoo ensemble members. |
| Robust deviation | How far a count sits from its usual level, in robust z: \|x − median\| / (1.4826 · MAD). Used by Phase 4a and, on log(1 + lines), by Phase 4g. |
| Incident | Phase 4g alerts that are one event (linked: within 60 minutes, entities that shared a line) or one routine (recurring: the same clock time on 3+ days). Review and Explain list one item per incident. |
| Explain / Profiles | Console tabs: why an activity alert was raised, in pictures; and any entity on any day against its usual range (Phase 4h). |
| runlog | `pipeline/shared/runlog.py`, the one implementation of every script's console output and options ([STYLE_GUIDE](pipeline/STYLE_GUIDE.md)). |
| Proxy label | A rule-based "security-relevant" flag used in place of real labels. |
| Precision (label yield) | Of the labelled items a mechanism raised, the share labelled Security relevant or Suspicious. |
| Recall (planted) | Of the made-up attacks planted into a real day, the share a mechanism flagged. |
| Drift (KS D) | The Kolmogorov-Smirnov distance between new observations' percentiles and Uniform(0, 1); large when the training baseline no longer fits. |
| Visibility (ATT&CK for ICS) | Whether the data a technique's detections need is in the logs DAD reads; not whether a detection is tuned to it. |
| Pseudonym | The stand-in git holds for a real server, address or account (`srv-07`); the key stays on this laptop. |
| Audit sample | A blind, stratified random sample of the test period labelled each month; the only unbiased estimate of precision, misses and recall. |
| Choosing and calibrating halves | Validation split in time order: the earlier half chooses features and models, the later half sets thresholds, so the alert rate on test is an honest check. |
| FDR (Benjamini–Hochberg) | Control of the expected share of false discoveries among the alerts raised from many tests at once; Phase 4g uses 5% across each day's steps. |
| Shrinkage | Drawing a baseline estimated from few days toward a broader one, weight n / (n + k). |
| Model-zoo family | Ensemble members that agree on validation (Jaccard or Spearman ≥ 0.6); one vote each in the consensus. |
| t-SNE map | A 2-D picture that keeps neighbouring observations together. Only who is near whom means anything; the distances between islands, their sizes and their shapes do not. |
| Perplexity | t-SNE's target number of effective neighbours per point (30 here). Points with neighbours on one side only get a wider neighbourhood, which is what pinches the OSSEC spindles. |
| SSH, `su`, PAM | Remote login, switch user (usually to root), and the Unix authentication library. |
| syscheck / rootcheck | OSSEC's file-integrity check and rootkit scan. |
| Brute force | Guessing passwords by trying many of them. |
| Port scan | Probing many ports to find open services. |

## Console releases

The last release is 0.2.0 (2026-10-07): persistent reports with versions, case numbers, maps, timelines, sign-offs and
Word/PDF exports, and exact Review filters. Since then, unreleased: Sigma rules as a fifth detector, the Dashboard
around decisions, whitelisted users, the SQL password, activity alerts and incidents in Review, Explain and Profiles;
and (30 October) precision, recall and drift measures, ATT&CK for ICS visibility, playbooks, ticket numbers, line
fingerprints, a tamper-evident activity log, retention, backups, and passwords and whitelists that cannot be left
open.
[VERSIONS.md](VERSIONS.md) records each change; the [workflow guide](triage-console/docs/user/04_reports_and_review.md)
covers Reports and Review.
#   i d e a l - h a p p i n e s s  
 