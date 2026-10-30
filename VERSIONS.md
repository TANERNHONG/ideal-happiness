# Project version register

Current application release: **0.2.0 — 2026-10-07**.

This file is the human-readable version controller: record each release here,
including its changes, decisions, validation, dependencies and rollback impact.
The matching immutable source ZIP and SHA-256 manifest in `versions/` preserve
the exact release, and a git tag (`v0.2.0`) marks it in history. Report version
history is separate and belongs to `triage-console/var/console.sqlite3`.

## Unreleased — 2026-10-30

Activity, not lines (Phase 4g, `pipeline/phase4_detection/activity_detectors.py`, built 2026-10-27): unusual amounts of
activity for the whole log and each server, source IP, username and destination IP, from counts and timing only. The
decision rule of 2026-10-28 (Q39): robust deviation of log(1 + lines) in 5, 30, 120 and 720-minute windows against the
same weekday's training days at that clock time and against the level when active, the smaller counting, with a bar of
z 3 and the validation budget only as a ceiling; failures and new partners as channels of their own; the Isolation Forest
as a second opinion. Features for outcome, relations, asset context (`site/assets.csv`, still empty) and regularity.
Incidents (2026-10-29, `activity_incidents.py`, Q41): alerts that are one event or one routine are one item; two routines
never merge. Explanations (`activity_explain.py`) against comparable days, with Saturdays, Sundays and
`site/public_holidays.csv` as non-working days. On the study data: AUTH 218 alerts in 42 incidents, OSSEC 14 in 10.

Profiles (Phase 4h, `activity_profiles.py`, 2026-10-28): every entity's hourly and daily lines, its partners and its
weekday P10, median and P90 in one SQLite file per log type; built for AUTH, OSSEC and IPFilter.

Names are not features (2026-10-28, Q40): Phase 3 no longer hashes server and agent names, usernames or source IPs in as
categories or sequence words, and the source port is a category. OSSEC was retrained on 2026-10-30; AUTH keeps its earlier
features until `run_pipeline.py --source auth --from-phase 3 --with-model-zoo` is run.

Console output standard (2026-10-30): [pipeline/STYLE_GUIDE.md](pipeline/STYLE_GUIDE.md) sets the names, console lines and
options for every pipeline script, implemented once in `pipeline/shared/runlog.py`: `date time | runtime HH:MM:SS.s |
LEVEL | message` on stderr; every duration as HH:MM:SS.s; fixed START, DONE, FAILED, progress, heartbeat and end-of-run
lines; library warnings on one line; `-v`/`--verbose`, `-q`/`--quiet` and `--progress-interval` everywhere (`--debug` and
`--progress-seconds` still accepted). Every script refactored onto it; console lines that named servers, accounts or
addresses now give counts and the file that holds them. A full OSSEC run: every line conforms.

Console: Review lists the activity alerts after the test-period groups, one item per incident, with their lines and the
entity's lines around them, labels, filters and the whitelist (FR-REV-16, `service/activity.py`); *Explain* (FR-EXP,
`service/explain.py`, `tabs/explain.ts`): why each was raised, in pictures, and *Summarize evidence*, whose local-model
rewording is kept only when every number survives; *Profiles* (FR-PRO, `service/profiles.py`, `tabs/profiles.ts`) and the
Dashboard's *Watched* card (FR-DSH-10). The console store gains the table `watchlist`; removing it loses only the watch
list. Tests: `test_activity`, `test_activity_features`, `test_activity_explain`, `test_activity_incidents`,
`test_activity_review`, `test_explain`, `test_profiles`. 310 console tests pass (2026-10-30).

Interface restyled (2026-10-30) in the manner of security-research consoles, with the colours unchanged: square corners
(`--r`, 2 px; circles and the drawn scenes keep theirs), hairlines in place of soft shadows, full-height panels on a faint
grid, corner marks on cards, card titles and table headings in monospace capitals with a red marker, titles and figures
in Space Grotesk, labels, log lines and codes in JetBrains Mono (`@fontsource-variable/space-grotesk` and
`/jetbrains-mono` 5.3.0, bundled locally), the page's stage above its title (*03 — Detect*), the current page marked with
a red bar, and an arrow on links that open another page. `web/src/styles.css`, `main.ts`, `sql-editor.ts`, `state.ts`.

Documentation: the README (the dataset-agnostic framework, names not features, the activity results, known gaps 10 and 11,
the glossary and folder map), TODO, QUICKSTART, PRESENTATION_PREP (the restructured deck, its 29 backups by question, the
Explain stop in the demo), the console's requirements, decisions Q39–Q41, architecture and user guides.

Review of the whole project from five roles (2026-10-30): data analyst, computer engineer, IT specialist, cyber associate,
cyber security specialist. Every finding addressed:

- **Git.** History rebuilt (nothing had been pushed): `v0.2.0` from `versions/0.2.0.zip`, then the work since in five
  commits, then one commit per change below. The first commit had held the console store, caches with addresses, a
  report PDF, `node_modules`, the web build and `.pyc` files. `.gitignore` keeps data, site lists, findings, screenshots,
  archives, secrets and build output out; `scripts/git_guard.py` and `.githooks` refuse them at commit and check every
  pushed file for real names (a hashed list in `.git/`); the name filter (`.gitattributes`, `scripts/git_names_filter.py`)
  stores pseudonyms in git and gives the real names back on checkout; `scripts/check.py` runs every test and the web
  build before a push. Tests now hold only made-up servers, accounts and addresses.
- **Passwords.** A default password (admin 123456, SQL 1234) opens nothing until it is changed; the SQL dialog asks for a
  new one; a default cannot be chosen.
- **Activity log.** Clearing archives it (`var/audit_archive/`) and the chain continues; `store.verify_audit()` finds an
  edited, deleted or reordered entry or a missing archive; Settings shows the chain and its latest hash, which every
  exported report also prints.
- **Whitelist.** Never silenced: a new source address or server for the account (Phase 4h), a switch to root unless the
  entry includes *su* (new option), and activity alerts.
- **Data.** Retention for the console's copies of log lines (Settings → Retention, 12 months by default); backups with
  verify, restore and rehearse (`python -m service.backup`); the OSSEC history cache as plain arrays with hashed keys (no
  pickle); Phase 9 sends prompts only to a model server on this machine.
- **Measures.** Label yield per mechanism (Dashboard), planted-attack recall (`python -m service.inject_eval`), drift at
  scoring time (Analyze: KS D against Uniform(0, 1), new entities), Sigma over the training period, ATT&CK for ICS
  visibility (Sigma page; `service/attack_ics.json`, v20.0).
- **Triage.** Playbooks per kind of alert (`docs/user/07_playbooks.md`, Review → Playbook), a ticket number on reports,
  each report line's SHA-256 fingerprint, time to label on the Dashboard, `scripts/assets_template.py`.
- **Operations.** `autostart.ps1` runs the console at sign-in; DOMPurify 3.4.17 and Vite 8.3.5 (`npm audit` clean).

Machine-learning review, stages 1 and 2 (2026-10-30):

- **Measurement.** Investigate → Audit: a blind, stratified monthly random sample of the test period with
  population-weighted precision, missed per 10,000 and recall (Jeffreys 95% intervals; per mechanism on Kish's
  effective n), on the page and a Dashboard card; audit labels are evaluation-only (`service/audit.py`). Planted
  recall v2: insider scenarios on the day's own identity, intensity sweeps, repeats, several days, Wilson
  intervals, results per model version. Drift: D judged against the 99th percentile of D for validation blocks of
  the same size instead of a p-value that assumed independence. Phase 7's score column is `rank` (`probability`
  kept as an alias for one release).
- **Modelling.** `pipeline/shared/calibration.py`: validation's earlier half chooses (the zoo's features, membership
  and greedy steps; Phase 4g's filter, null and shrinkage), its later half calibrates every threshold and quota and
  Analyze's zoo reference; every detector and the ensemble report Test ÷ budget (Models page). Model-zoo families
  (phase 4bf, `zoo_families.py`): one vote per family of similar members, consensus from two families; Phase 7 and
  Analyze use it. Phase 4g: Benjamini–Hochberg at 5% across each day's steps from an empirical null with a fitted
  exponential tail; weekday baselines shrunk toward the all-days one (n / (n + k), k chosen on validation). Options
  restore the earlier rules (`--calibration-split all`, `--fdr 0`, `--shrinkage-days 0`).
- **Diagnostics.** `service/feature_ablation.py` (planted detections lost per neutralised feature against the zoo's
  importance) and `pipeline/phase4_detection/host_identity_check.py` (flagged share against training rows; with and
  without a server's own training).

Validation (2026-10-30): `python scripts/check.py`, 0 failed: 370 console tests, 77 + 28 + 8 + 1 + 3 pipeline tests, 7
guard tests, the web build and type check (after the machine-learning review). A push of the whole rebuilt history to a scratch remote passed the pre-push guard.

## Unreleased — 2026-10-26

Dashboard rebuilt around decisions (FR-DSH-01–09; decision Q38, after DataCamp's dashboard design tutorial): four
headline cards (items waiting; of those, Sigma matches, red while any wait; security relevant, with suspicious; the share
reviewed, with decisions per day), *Next to review* (up to six, Sigma matches first, opening in Review), review progress,
the flagged share and the detectors' Venn diagram, the data and the months it spans, model data and activity. No
explanatory text: an information icon per card and a table view per chart. Settings → Dashboard is the Dashboard itself as
its editor (FR-SET-08): cards dragged, widened (3 to 12 columns) and hidden into a tray; *SQL table* cards (up to 20) of the
analyst's own read-only query, with a title, description and height, the result kept in the console store
(`dashboard_results`) until *Refresh*; *Tile* cards (up to 40) from 1 × 1, with one of 48 icons, a heading, text, a bright
colour, an alignment and a console page to open, resized by their edges; *Pack tightly* (8-pixel rows, dense placement).
Saved as the setting `dashboard_layout`, checked by `config.py`. `web/src/dashboard-layout.ts`, `tabs/dashboard.ts`,
`tabs/dashboard-editor.ts`; `tests/test_dashboard.py`, `tests/test_settings.py`.

Interface: the Advanced menu grouped in the order of an investigation (Overview, Prepare, Detect, Investigate, Report,
Console), each group with its icon, collapsed to one icon per group with its pages in a flyout (FR-SHL-01); Phosphor icons
(`@phosphor-icons/core` 2.1.1, MIT) throughout; one train circling its track in the middle of the screen while a page
waits, leaving no empty box behind (FR-SHL-07); page subtitles removed.

Reports: *Report* on a reviewed item (Review → Reviewed) starts a pre-filled anomaly report with the item's notes as the
analyst comments, exactly as typed (FR-RPT-25, Q37); HTML export beside Word and PDF, under a content security policy that
allows no script and no request (FR-RPT-10).

SQL password (FR-SQL-07, Q36, NFR-SEC-16): every SQL request needs it (default `1234`, flagged until changed in Settings →
Activity log); a salted PBKDF2 hash in `var/sql_password.json`; tokens in memory that lapse after 30 minutes without a
query; unlocks, refusals and changes recorded. `service/sql_lock.py`, `web/src/sql-lock.ts`; `tests/test_sql_lock.py`.

Security review and hardening (NFR-SEC-02, -05, -12, -17 to -20): the API answers only requests that carry the app's
`X-Console-Request` header and are not marked as typed in or from another site (2026-10-23, `tests/test_server_access.py`);
the page's content security policy and its frame, sniffing, referrer and same-origin headers; password checks one at a
time; workbook parts, columns and text capped, and lines over 1 MB cut; a rule exported for Phase 1 written as a string
literal (a regular expression holding a line break could previously end the exported line and add code); CSV cells a
spreadsheet would run as formulas kept as text; comment lines in queries the console writes kept on one line; the model
address `http(s)` on this laptop, with no redirects; ATT&CK links only to MITRE's site. `tests/test_security.py`. No
content-policy violation on any of the 11 Advanced pages in a browser check.

Sigma rules written three ways (FR-SIG-02, FR-SIG-06–09): a form, the default (required fields marked, *Match* and
*Except* rows, an optional count written as a correlation, the YAML shown beside it); a plain-English description from
which the local model drafts a rule (a proof of concept, tested against a stand-in model: the answer is untrusted text,
read with a safe YAML loader, checked by the engine and never saved by itself); or YAML. Every draft goes *Draft → Test →
Accept*, and the activity log records whether the accepted text was tested; each rule shows who added it and when, *New*
for 7 days. `service/sigma_form.py`, `service/sigma_ai.py`, `web/src/sigma-form.ts`; `tests/test_sigma_form.py`.

A time limit on Review's filters (FR-SET-09, NFR-PER-08): Settings → Review → *Filter time limit*, 120 seconds by default
(10 to 3,600). The service stops a filter that runs longer, including the one-time preparation of the filters' facts and a
wait for another request preparing them; a stopped preparation is rolled back whole. `review_filters.Deadline`;
3 tests in `tests/test_review_filters.py`, 1 in `tests/test_settings.py`. 229 tests pass.

Models: an information icon on the model zoo card opens a new guide, *Detection, precision and lift*
(`triage-console/docs/user/06_model_zoo_measures.md`; FR-MOD-02, FR-DOC-06), through a new address that opens a document
directly (`#/docs/<document id>`). The proxy label is now described as known-risky events, not rare event types.

Documentation: every document opens in a reading view (FR-DOC-07, `web/src/doc-reader.ts`): a header with its group,
reading time and sections; a requirements document's version history folded under its latest version; an *On this page*
list that follows the reader; tables that scroll, with IDs, numbers and statuses (as badges) marked; code with a *Copy*
button; and the previous and next documents. The quick start is listed first. A documentation audit brought Getting
started (every page in the menu's order, Settings as its own section), the disclaimers, the decisions' count, the tests
(NFR-MNT-03, NFR-MNT-04), QUICKSTART and the Phase 4f status up to date, and mended two tables that a `|` inside a
cell had broken.

Documentation: FR-SIG and US-39 for Sigma, the guide `docs/user/05_sigma.md`, decisions Q36–Q38, NFR-SEC-18–20, the
architecture's modules and risks; the whitepaper and its appendices (LaTeX) updated for Sigma as a fifth detector, the
event-log source in progress, the API, the security of the local service, the user guide and the version history.

## Unreleased — 2026-10-22

Sigma over a whole folder (FR-SIG-04): every file of its lowest folders, each told its log type by its first lines and
its month by its folder names, the files of one log type and month checked together, one group in memory at a time. The
event-log parser optimised and reading files in parallel (at most four at a time by default).

## Unreleased — 2026-10-19 to 2026-10-21

Sigma as a fifth detector (FR-SIG-05, `service/sigma_review.py`, `tests/test_sigma_review.py`): the enabled rules run
over every Analyze input and upload and over the year's validation and test periods; a hit flags every observation
holding one of its lines, in every view, and Review lists any group holding one whatever its lift, under the rule's
title; no score changes. The fixed-width event-log parser (Phase 1, `pipeline/phase1_classify/event_log_parser.py`,
`event_log.py`, `event_log_devices.py`; not yet in `run_pipeline.py`): only the owner's stated rules, everything else to
an exceptions file for review; incremental runs by file digest and parser fingerprint; devices classified by the states
they show; 77 tests on made-up lines. The console shows its notes and the device types built from its code (FR-DOC-05,
`service/event_log_docs.py`).

## Unreleased — 2026-10-16

Advanced → Sigma (`service/sigma.py`, `web/src/tabs/sigma.ts`, `tests/test_sigma.py`, `tests/browser_sigma.py`): detection
rules and correlations (`event_count`, `value_count`, `temporal`, `temporal_ordered`, the older `count() by`) in sliding
windows over Phase 1's fields, on pasted lines, an upload or a file; eight starter rules from the Phase 9 catalogue; a YAML
editor with a live check, a draft tested alone, import and export; hits whose accounts are all whitelisted marked so. The
hypothesis register for the flagged groups ([HYPOTHESIS_REGISTER.md](HYPOTHESIS_REGISTER.md)).

## Unreleased — 2026-10-12

Whitelisted users (decision Q35; FR-SET-07, FR-REV-15, US-38): Settings gains a *Whitelisted users* card, an override
on the anomalies for accounts an administrator vouches for. An entry names one account (case-sensitive), a server or all
servers, a required reason and an optional last day; adding or removing one needs the activity-log admin password and is
recorded; removed entries are kept, marked removed. An observation is covered when it names at least one account and every
account it names is listed for its server; covered observations are still scored and flagged, and nothing is deleted. Review
moves a group whose flagged observations are all covered from *Needs review* to a *Whitelisted* list (exact, from Review's
facts table; a partly covered group stays, with a count); Check logs and Analyze say *Whitelisted* instead of *Unusual* or
*Would be flagged* when every flagged event is covered (a time window with no account of its own is judged by the accounts of
its uploaded lines); kept uploads count covered events as done, decided when read; the Dashboard counts whitelisted groups
apart. `service/whitelist.py`, changes in `clusters.py`, `review_context.py`, `analyze.py`, `scoring.py`, `uploads.py`,
`server.py` and the Settings, Review, Simple, Analyze and Dashboard pages; `tests/test_whitelist.py` (8 tests; 121 in all).
Checked on a copy of the console store: one busy service account on all servers moved 33 of 192 AUTH groups to
*Whitelisted* and partly covered 94 more, in 0.1 s. The project is renamed **Project DAD (Data Anomaly Detection)
Console** (*Project DAD Console*) in the console, the READMEs, QUICKSTART and the requirements; pipeline folders and script
names keep their names.

Frozen runtime, for purging `data/` (QUICKSTART → Before you purge `data/`). `scripts/freeze_runtime.py` copies
what the console needs into `runtime/` (189 files, about 480 MB, timestamps kept): every AUTH and OSSEC view's
Phase 3 preprocessing bundle and feature names, Phase 4 detector bundle, model-zoo bundles (full and selected) and
summaries; the PF and IPFilter summaries; each map's points, t-SNE embedding, point order and UMAP layout; the
cluster summaries; the PNG renders of the maps (`runtime/maps/`); and the caches nothing can rebuild once the
inputs are gone (event counts, score references, OSSEC history, outlier counts, and a slim cluster index with
group mixes, flagged members and their scores). Account names, addresses, example and raw lines are left out
(columns dropped; the projection reduced to point IDs; the index without line links, validation groups or review
facts). `--check` scores sample AUTH and OSSEC lines through Analyze and loads every map from `runtime/` only.
`service/config.py` uses `runtime/data` when `data/` has no trained models (or `HUH_FROZEN=1`) and restores
missing caches from `runtime/cache` at start-up; in that mode every cache is trusted as kept and never recounted
(event counts, variants, address flows, outliers, score references, OSSEC history, firewall SQL cache, cluster
index). What needs log lines says so: SQL, a group's members and "Around this event" return a clear error; a map
point and an observation show "Lines purged with the data"; Review's list shows "Purged with the data" where its
scores were not kept. `runtime/` is in `.gitignore` and outside source archives. Fixes after the purge: a console started before this
change kept running on the deleted `data/` and rewrote the event counts and the AUTH score references as empty, so
Simple mode's Map step failed ("answered 200 without JSON": the empty references made NaN percentiles, which JSON
cannot carry). Start-up in frozen mode now replaces any frozen cache that differs in `var/cache` (the cluster index
only when missing), and the service never sends NaN or infinity: such numbers go out as null. Review's filter
suggestions (server, account, program, address) failed once the log stores were gone; they now use the facts the
index already holds. `tests/browser_reports_review.py` places a mapped observation when the Phase 3 feature rows
are gone. Post-purge check (2026-10-12): `freeze_runtime.py --check` passes for all 8 views and maps; 141 read-only
API calls on the console (132 ok; 8 a clear "purged" answer; the local model unreachable because Ollama is not
running); the writing paths on a scratch copy (Patterns end to end, labels, comments, renames, uploads with
password-protected clearing, settings, activity-log password checks, PF and IPFilter analysis); the browser over
every page; the reports and Review browser test in full; 113 unit tests pass, 2 skipped (they need the log stores). Checked: `--check` passes for all
8 views and 8 maps; a console run with an empty cache in frozen mode rendered every page without errors; 116 tests
pass.

## Unreleased — 2026-10-09

Datasets lists the *Unapproved log types* (those made in Patterns, not the pipeline's) with their rules, last
scan and table, and deletes one without sign-in (decision Q34; a second click confirms; the activity log
records it; FR-DS-06). The `mssql` log type was deleted with it, at the user's request. Patterns' scans and
passes show the SQL query's waiting animation, captioned with their progress; the Columns step shows each
column's type and first five values; the shape tabs read Prefix · Message · Suffix. Fix: in the regex
builder's examples, a group's name that would run into the previous one (e.g. `username` and `word` over
`OK: [user0]`) is raised a row instead of overlapping it.

Simple mode's Check logs: the four steps are an elevated LRT line in their own card (`web/src/lrt-line.ts`):
a concrete guideway on piers; for each step an LRT station as its platform looks from the track (blue roof over a
white vaulted ceiling with recessed lights, blue columns, a band of blue-framed windows, a platform sign with a
clock, blue half-height platform gates, a terracotta floor with tactile strip and yellow edge line; greys until the
step is open) under a numbered code; and a two-car driverless LRT train (white body, black glazed band and wraparound windscreens, teal and navy dot livery)
that rides from the last step's station to the new one while the running surface behind it turns teal (it jumps
straight there with Animations → None or reduced motion). Station names are the buttons. The Review step is one compact card: the upload's number, name, result and
servers, then Review now beside the reviewer field and Send (the two large choice cards are gone). Analyze shows the SQL query's waiting animation (Settings →
Animation pack) captioned with the stage, instead of the lights board. The upload box is smaller, the verdict's
type is scaled down, and the step cards share one 820 px column (the map step stays full width).

Patterns (US-37, FR-PAT, FR-SMP-10): a page before Analyze in Advanced mode for data the pipeline
cannot read yet. A scan (paste, upload, or a file, folder, ZIP or .gz on the laptop; up to 5 million lines
a pass) gives coverage (Phase 1, rules made here, prefix only, unknown) per pass and over time, the
unknown lines' shapes, heads and tails, and a canvas that slices lines into prefix, message and suffix;
selected text goes to a tray, the console suggests regexes from the examples (Exact, Fields, Anchors,
Start; named groups; examples and lines taken) and tries the one being written live. Rules are kept per
log type in `var/console.sqlite3` (examples with documentation addresses), checked (Python `re`, no
nested repeats, 50 ms per match through the `regex` package, now pinned in `requirements.txt`), audited,
and exported as JSON or Phase 1 `RULES` lines; Analyze and the pipeline do not read them yet. Simple
mode's Upload shows how many of the first lines Phase 1 knows and stops below 5% with *Find patterns*;
Analyze offers the same when no log type recognises the lines. `service/patterns.py`,
`web/src/tabs/patterns.ts`; 15 tests. Measured on one month of authlog (1.06 million lines): 21 s for
the first pass, 3 s for the next; read as an unknown type, 21 s.

Logs that come as a table (FR-TAB): a CSV, TSV, `;` or `|` export, or an Excel workbook (.xlsx, read with
the standard library), with a header row, one column the raw line and the others extra fields
(`service/tabular.py`, `web/src/tables.ts`). Patterns checks the first 100 rows (a header of distinct names,
as many values in every row, else which row is not), asks for the Raw logs column (a dropdown of the headers,
filled in only when clear) and the columns to keep (checkboxes with a sample value each), then scans: the
time column dates the lines, every other kept field is counted per value with how much of it is known
(*By field*), a value shows its lines, and the layout is exported with the log type's rules. Analyze and
Simple mode read the raw-log column by themselves (Simple shows it as a dropdown, takes the month from the
time column and the server from a single-host column). 12 tests (115 in all).

Documentation and Dashboard: a plain-English guide to the sequence mining
(`pipeline/phase4f_sequences/GUIDE.md`), listed with the pipeline's notes and opened from the Phase 4f
station (now built, for auth and OSSEC), drawn in the console as pictures from its own tables and lists
(`web/src/doc-routines.ts`; FR-DOC-04). The Dashboard gains an Outliers card (FR-DSH-05): the share of
test rows flagged (AUTH sessions and OSSEC episodes; 6,670 of 1,425,531, 0.47%) as a pie, and on a click
a four-ellipse Venn diagram of Isolation Forest, the model zoo, Novelty and frequent subsequences, counted
in the background (`service/outliers.py`, cached in `var/cache/outliers.json`); 2 tests (88 in all).

Sequential pattern mining steps 1–3 and the alert profile (decisions: `prefixspan`
0.5.2 and `mlxtend` 0.25.0, installed into `.venv`; event-type tokens; the existing
alert budget). New in `pipeline/phase4f_sequences/`: `streams.py` (Phase 2's own
sessions and episodes, same IDs, as complete source-ordered event-type sequences,
rotated-file copies merged into aliases, uncertain steps marked; checked against
Phase 2 and Phase 3), `mine.py` (routine catalogue with weighted PrefixSpan,
"usually followed by" rules, step model; training split only), `score.py` (the
sequence detector: surprise of the rarest step, explained in words, Phase 4's own
budget threshold with the training 99.5% quantile as a floor), `profile_alerts.py`
(FP-growth association rules locating each detector's alerts), `run_sequences.py`
and 18 tests (28 with the audit's). `run_pipeline.py` gains phase 4f (auth, OSSEC);
Phase 7 collects a seventh alert type, *Sequence (unusual order)*. OSSEC: 29,447
episodes, 77 distinct sequences, 4,692 merged copies; 19 test alerts, all in the
com1kco agent restarts of 2026-07-13 and mm03kco's 02:00 window of 2026-06-17.
AUTH: 9,475,862 sessions (Phase 2's, checked), 306 distinct sequences, 290,396
rotated-file copies merged (all in the training months); 608 test alerts at 11.56
bits (the budget's 10 a day), led by `authorized_keys` permission errors on
admikco and invalid users on com1kco and spadkco. The alert profile shows the
Isolation Forest and model-zoo session alerts concentrate on `mm` servers and
`SSH_DEPRECATED_OPTION` lines (known gap 5). Phase 7 re-collected for auth and
OSSEC: the existing alert files keep their rows; the sequence files are new.
No existing Phase 2–7 output was changed.

Sequential pattern mining begun: added `pipeline/phase4f_sequences/audit.py`,
10 isolated tests and an evidence-based audit report. Read-only source access,
numeric source-line ordering, explicit ambiguous ties and duplicate candidates;
optional JSONL retains all occurrences and original lineage. Audited all 115,288
OSSEC events and three AUTH samples totalling 300,025 events. No Phase 2/3 output,
models, alerts or console records changed. This is step 0; the miner, final token
policy and session/episode reconstruction remain pending. Updated the Phase 4f
README and root TODO. Existing release archives remain unchanged.

Documentation only: added root `QUICKSTART.md` covering the prepared Windows
environment, startup/build commands, first investigation, optional AI/SSO,
troubleshooting and backups. Linked it from both READMEs. Existing release
archives remain unchanged; source verification against 0.2.0 will report these
documentation changes until a new release is recorded.

Interface consistency pass on the 0.2.0 screens (behaviour unchanged):
- Review filters use the console's search boxes, icon buttons and removable chips in
  one slim card; the sentence under the label buttons became a *filtered* badge whose
  tooltip carries it. Search boxes everywhere now share the console's input style.
- The Reports bar shows the open report's number and version (or *unsaved*) beside
  its kind, with save/export feedback inline, and groups its actions (new, saved and
  versions, preview/export/save); version times read `2026-10-08 09:17`. Saved
  reports list as rows with number, title, kind, status and version.
- Preview fixed: blocks no longer collapse into the drag-handle column, and tick boxes
  keep their box (also in the saved print copy used for PDF).
- The target map uses the console map's colours (test grey, validation dark, flagged
  red, targets yellow) with a drawn legend; its target lines use the report's log-line
  style; its caveats are one method note, like rarity's. The timeline uses the report's
  ink and red, with icon controls.
- The paper keeps its form on one line at 1440 px and stacks it when narrow (1280 px).
- Fonts: Roboto added beside Inter (bundled, `@fontsource-variable/roboto` 5.3.0, OFL-1.1), and an
  *installed font* option that uses a font on this laptop by name (e.g. a licensed LTA Identity);
  Settings shows whether it is installed. Names are validated before they reach CSS.
- Fix: Analyze's cluster map stayed empty for the rest of the browser session after one failed request
  (e.g. while the service restarted), because the failed fetch of the view's groups was cached. Failures
  are no longer cached; the map shows the error with *Try again*; "No map for this view" now appears only
  when the service says so (Analyze, Clusters, Simple).
- A third animation pack, *Commuter*: first person, a phone game while you wait; the train or bus arrives and
  opens its doors, or, on failure, leaves while you are still playing. The SQL scene was redrawn the same day
  (`commuter-platform.ts`, `commuter-kit.ts`): an underground EW14 platform with strip maps, station and exit
  signs; screen doors in a regular rhythm (holding door, two leaves, holding door, a long panel two modules
  wide), with the two ads (a café and a bank) in the holding doors' places beside the doors either side of
  you; in one row above, banners one door wide over every door (East West Line, To Changi Airport, and
  "Please do not board when the light is flashing" in four languages around the yellow warning triangle) and
  Raffles Place signs two doors wide; tactile paving (a road of square blocks of bars, and a square of studs
  twice their size a little way out from each door); less palm in view (the floor's queue markings and the
  strip map were taken out); hands and sleeves in proportion, no
  legs in view; the phone goes home, opens Space Invaders, loads and plays from level 1. The bus stop
  (Review) moved onto the same kit (`commuter-busstop.ts`, replacing `commuter-loaders.ts` and its unused
  `.cm-*` styles): standing under the shelter (its canopy, light strip and orange fascia overhead, ending
  a little to your right); past it, in the open and taller than the shelter, a stout bus-stop pole laid
  out as at every stop (blue bus square; wings of one width: code over name, the public-transport symbol;
  green wings of six services, two rows of three); stone paving along the kerb with a yellow line, a
  black-and-white kerb and evenly spaced stone bollards with one black arrow each; a bus bay and two lanes
  each way with a central divider (black-and-white kerbs, grass, shrubs, small trees, green railing); the
  far kerb, a footpath with people walking and the other direction's bus stop (distances past the near
  lanes drawn compressed so the far side reads); rain trees as in the Transit pack, street lamps and
  HDB blocks on their grounds (void decks, block numbers painted top to bottom near the roof); a green double-decker with its front door stopping in front of you, doors folding
  inwards, hubs turning. The dark theme is a heavy tropical downpour rather than night: a low grey sky,
  haze over the estate, lights on, a wet road with puddles, rain in three depths slanting in the wind
  beyond the shelter's roof (which reaches out over the bollards, so you stay dry), water pouring off its
  edge onto the bollard line, splashes, umbrellas, and a faint double flicker of lightning every
  ten seconds or so (none with reduced motion). The Settings preview of the Review scene also runs 9 s now.
- `tests/browser_reports_review.py` follows the shorter labels; it passes in full,
  with the 84 unit tests.

## 0.2.0 — Reports and Review completion

### Reports

- Added transactional case numbering (`IR-YYYY-NNNN`), a saved-report library,
  immutable versions with actor/time/digest, version selection/restoration and
  optimistic conflict checks. Saving an old version creates a new latest version.
- Adopted the user's Q33 decision: any local reviewer can close/reopen a case;
  closed cases stay editable; each save appends a version. No sign-off prerequisite.
- Linked findings to their reports, including references in older versions.
- Added anomaly and malicious-activity templates; timelines with source IDs and
  editable/manual events; non-binding name/role/date acknowledgements. Editing
  signer details clears the acknowledgement.
- Added test/validation target maps in t-SNE/UMAP, exact saved positions or marked
  nearest-neighbour estimates from saved feature vectors, numbered target tables,
  and saved individual line rarity where available. Missing values remain explicit.
  Sparse matrices are read selectively, without a pipeline rerun.
- Added preview and actual Word/PDF downloads. Saved evidence, map images and print
  styling persist with each version. PDF uses inert sanitised HTML, disabled
  JavaScript and blocked network requests. Word preserves editable content, tables,
  highlights and figures; its pagination is independent of PDF.
- Guarded saves during evidence retrieval and prevented repeated pending saves.
  Fixed print form layout and preservation of field values in the static preview.

### Review

- Added exact server/account/program/address filters, suggestions and removable
  chips shared across modes during the app session. OR within a field, AND across
  fields on the same event. Matching counts and unusual-event lists follow filters.
- Indexed full original event facts and aggregate lineage instead of the top-three
  summaries. Added a flagged-member index and explicit join order for queue filtering.
- Preserved whole-group label scope and explained it beside filtered results;
  disabled label buttons while saving to prevent duplicate submissions.
- Added password-protected upload clearing to Simple Review and retained Analyze
  coordinates on new uploads. Older uploads without coordinates stay unavailable.
- Closed console-store SQLite handles deterministically after transactions,
  avoiding Windows file locks in tests and temporary stores.

### Documentation and source control

Updated the root and console READMEs, TODO, product/functional/non-functional
requirements, Q33 decision, architecture and getting-started guide. Added the
[Reports and Review guide](triage-console/docs/user/04_reports_and_review.md) and
[implementation record](triage-console/docs/06_reports_review_release.md), both
available in the console's Documentation page. This version register is listed
there too. Web package and lockfile versions are 0.2.0.

`scripts/version_control.py` provides immutable source snapshots, checksum
verification and release listing. It excludes original data, runtime stores,
caches, environment files, dependencies, build output and previous archives.

### Validation

- Python: **84 unit tests pass**, including save rollback, immutable print content,
  sanitisation, history/conflicts, Word output, exact filtering and sparse rows.
- TypeScript and Vite production build: passed.
- Edge integration: report save/reload/history/restore, preview, real Word/PDF
  downloads, exact Review filter and duplicate-submit protection, real OSSEC
  nearest-neighbour placement; no browser errors. Reports checked at 1440 and
  1280 px. Timeline persistence, acknowledgement invalidation, editable closure,
  map rendering/preview/exports, the malicious-activity template, Simple Review
  filtering/counts and password-protected clearing all passed in the final run.
- Version-controller checks: archive creation and checksum verification, runtime
  exclusions, existing-version refusal and changed-source detection passed in an
  isolated temporary workspace. `pip check` found no broken requirements.
- Export artifacts and screenshots: `triage-console/var/checks/reports-review/`.
  These use an isolated test store and are excluded from source archives.

### Dependencies, migration and limits

Added pinned python-docx 1.2.0, lxml 6.1.3, Playwright 1.63.0 and its dependencies
to `triage-console/requirements.txt`. PDF uses installed Microsoft Edge; no browser
download is needed on this laptop. pypdfium2 5.14.0 was installed only for PDF
inspection, not as an application dependency.

Four report tables are created additively on first access. Review facts and map
placements use disposable caches. No original logs, features or models are
rewritten. Install requirements, rebuild `triage-console/web`, restart the service.
Limits: 24 MB per saved document including print snapshot; 1,500 sections/blocks;
eight subsection levels; 120 map targets; 60,000 background points (all flagged
points are retained if they alone exceed that cap); 40 lines per map target.

The **full-report AI writer remains deferred by the user**. Real Ollama checks
remain pending; helper tests use a stand-in. Enterprise SSO, broad browser/WCAG
coverage and backup/restore rehearsal remain in TODO. Silhouette is omitted from
the report body because 2D separation does not establish maliciousness. Scores
are shown only where available; this release does not backfill every normal line.

## Creating and verifying releases

Run from the project root (PowerShell):

```powershell
.\.venv\Scripts\python.exe scripts\version_control.py snapshot 0.2.0
.\.venv\Scripts\python.exe scripts\version_control.py verify 0.2.0
.\.venv\Scripts\python.exe scripts\version_control.py list
```

Snapshot refuses an existing version. The JSON manifest records every included
file's SHA-256 and the archive checksum. Verify reports added/removed/changed files
and exits with status 1 if the working source differs; runtime data changes do not
affect it. Archives and manifests are integrity records, not signed attestations.

For each future release: finish code/docs and checks, bump the web package and
lockfile version, add a dated entry here, snapshot the new semantic version, then
verify. Use a patch release for fixes, a minor release for compatible features,
and a major release for incompatible storage/interfaces.

For rollback, stop the service and back up `triage-console/var/`. Extract the
selected ZIP into a separate folder and compare before copying source files back;
reinstall its dependencies and rebuild. Never replace runtime state with a source
archive. Earlier code may not understand newer report blocks; keep the matching
database backup. This controller intentionally performs no automatic overwrite.

## Earlier baseline

The inherited web package identified itself as 0.1.0. No pre-change release ZIP
was captured by this workflow; this register does not claim a reproducible 0.1.0
archive. Existing Git history, if available, is independent of these snapshots.
