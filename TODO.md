# TODO

Open items as of 2026-10-30. Release 0.2.0 is recorded in [VERSIONS.md](VERSIONS.md). Decisions referred to as Qn are in
[triage-console/docs/04_open_questions.md](triage-console/docs/04_open_questions.md).

## Working rules

- **SSO last** (2026-10-06). Anything that needs SSO (Authlib) is built first
  on the underlying mechanism (the Settings name, local records); SSO is laid
  over it later, when IT has registered the console.

## Security, data handling and measures (review of 2026-10-30)

Built on 2026-10-30 after a review from five roles (VERSIONS.md has the list): git rebuilt from `v0.2.0` with a guard,
a name filter and checks; defaults that open nothing; an archived, verifiable activity log; whitelist sentinels;
retention; backups; precision, recall and drift measures; ATT&CK for ICS visibility; playbooks; ticket numbers; line
fingerprints. What is left needs you, your data or your organisation:

- [ ] **Before any `git push`:** confirm that the organisation allows this code (pseudonymised) in that remote. The
      pre-push hook checks names and runs `scripts/check.py`; it does not know the policy.
- [ ] **Set the two passwords:** the console refuses the defaults now. The SQL dialog asks for a new one at the first
      query; the admin password is set in Settings → Activity log.
- [ ] **Phase 4h for PF** (below), then `python scripts/git_guard.py identifiers`, so the name filter uses PF's entity
      list instead of Phase 1's addresses.
- [ ] **Agree the retention period** with the data owner (Settings → Retention; 12 months now) and how long reports are
      kept (they follow the records schedule and are never changed by retention).
- [ ] **Rehearse a backup:** `cd triage-console`, `..\.venv\Scripts\python.exe -m service.backup rehearse`; then back up
      to an approved location (`create --to <folder>`) on a schedule.
- [ ] **Measure recall** on a held-out day from the test period or later:
      `..\.venv\Scripts\python.exe -m service.inject_eval <day.log> --month YYYY-MM` (counts only), and record the result.
- [ ] **Check the training period** with Sigma → Training period; any match there was learned as normal.
- [ ] **Fill in the asset list:** `python scripts/assets_template.py`, then zone, role and criticality per row.
- [ ] **Start the console at sign-in:** stop the copy started from a session, then
      `powershell -ExecutionPolicy Bypass -File triage-console\autostart.ps1`.
- [ ] **Re-run `scripts/freeze_runtime.py`** before the next purge: the OSSEC history cache is now `.npz` (no pickle).
- [ ] **Optional:** `git reflog expire --expire=now --all` then `git gc --prune=now` frees about 2 GB held by the old
      first commit (data, caches, `node_modules`); after that it cannot be recovered.
- [ ] **SCS event logs into the pipeline:** ATT&CK for ICS shows 3 more techniques visible with their device alarms.

## Machine-learning review (2026-10-30)

Stages 1 and 2 built (VERSIONS.md): the Audit sample, planted recall v2, drift against a validation null, `rank` in
place of `probability`, validation's choosing and calibrating halves with the Test ÷ budget check, model-zoo families
(phase 4bf), Phase 4g's FDR step and shrinkage, and the feature-ablation and host-identity diagnostics. They change
results only when re-run:

- [ ] **Re-run OSSEC from 4a with the zoo:** `python run_pipeline.py --source ossec --from-phase 4a --with-model-zoo`
      (detectors, zoo with halves, 4bf families, 4g with FDR and shrinkage, 7). Compare Phase 4g's
      `test_robust_steps_bar_only` with `test_robust_steps`, and the Models page's Test ÷ budget.
- [ ] **AUTH:** the same, folded into the pending Phase 3 re-run below (`--from-phase 3 --with-model-zoo`).
- [ ] **Label the Audit sample** each month (Investigate → Audit, about an hour): 25 items per log type.
- [ ] **Recall:** `python -m service.inject_eval <day1.log> <day2.log> --month YYYY-MM --repeats 3`, on days from the test
      period or later; record the result beside the model version.
- [ ] **Diagnostics:** `python -m service.feature_ablation <day.log> --month YYYY-MM`, and
      `python pipeline/phase4_detection/host_identity_check.py --source auth` (then `ossec`); change the feature rule or
      the server features only if they say so.
- [ ] **Stage 3 (not built):** partial windows in Analyze, a pipeline-to-Analyze parity test, the OSSEC history's age.
- [ ] **Stage 4 (not built):** a pinned pipeline environment, a model registry with the version on every label, a
      retraining path (needs the data owner's approval to keep identifier-free features), Phase 8 on audit labels
      with grouped evaluation and calibration, Phase 9 against the audit labels (Cohen's kappa) with order shuffles and
      the model digest.

## Hypothesis register (current priority, 2026-10-16)

[HYPOTHESIS_REGISTER.md](HYPOTHESIS_REGISTER.md): 32 flagged groups, 91 competing hypotheses (benign
and malicious), each with the test that would refute it and the route out of the queue (label,
whitelist, or a change-window / approved-automation entry). All *Open*.

- [ ] **Send the owner questions** (table at the end of the register); start with G05 (root logins
      to mm04kco from 172.16.10.157), G25 (IEC-104 reset), G15 (173.16.10.x) and G07 (mm sshd config).
- [ ] **Record each answer** as a Review label or whitelist entry naming the group ID, or as a row in
      `pipeline/phase9_llm_triage/site/approved_change_windows.csv` / `approved_automation_ips.csv`.
- [ ] **Re-supply logs** for groups that need their raw lines (the study year was purged), or upload
      a current day from the same server to see whether the pattern continues.
- [ ] **Add an OT attack pattern** (IEC-104) to the Phase 9 catalogue (G25).
- [ ] **Then AutoML** (natural extension, whitepaper §3 and Appendix H): per-family tuning against
      reviewed outcomes; a supervised decision model on features plus anomaly scores once labels exist.

## Activity, not lines (Phase 4g, built 2026-10-27)

`pipeline/phase4_detection/activity_detectors.py`: unusual amounts of activity for the whole log
and per server, source IP, username and destination IP, from counts and timing only (README,
*Activity, not lines*). Tests on made-up logs (`triage-console/tests/test_activity.py`,
`test_activity_incidents.py`).

- [x] **Run it** on auth (2026-10-29: 218 alerts, 42 incidents) and OSSEC (2026-10-30: 14 alerts, 10 incidents),
      with the rule of 2026-10-28; breakdown with `python scripts/activity_alert_counts.py <auth|ossec>` (counts only).
- [x] **Incidents** (2026-10-29, `activity_incidents.py`): one event (entities that shared a line, peaks within
      60 minutes) or one routine (the same clock time on 3+ days) is one item in Review and Explain; two routines
      never merge; a whole-log alert joins the routine of the entity that explains it.
- [ ] **Read the alerts** (report section *Activity*; `*_cumulative_activity_alerts.csv`) and tune
      `--alerts-per-day`, `--min-history` and `--merge-gap` if routine jobs crowd the list.
- [x] **Console:** Review lists them for auth and OSSEC after the test-period groups, with their
      peak lines and the entity's lines around them (FR-REV-16, 2026-10-27).
- [x] **Explain** tab (FR-EXP, 2026-10-27): why each alert was raised, in pictures; public
      holidays as non-working days (`site/public_holidays.csv`).
- [ ] **Check the 2026 moon-sighting holidays** (Hari Raya Puasa 21 Mar, Hari Raya Haji 27 May)
      in `site/public_holidays.csv` against the confirmed dates.
- [x] **Explorer (Explain B) → Profiles** (FR-PRO, 2026-10-28): any server, IP, user, destination or the
      whole log, any day, against the same weekday's training days; watch list on the Dashboard.
      Phase 4h (`activity_profiles.py`) for every log type; PF and IPFilter with the presence method.
- [x] **Run Phase 4h on the study data**: auth, OSSEC and IPFilter (2026-10-29/30).
- [ ] **Phase 4h for PF** (`python run_pipeline.py --source pf --only-phase 4h`), then check the Profiles list's size
      and speed on the real entity counts.
- [ ] **Explanation in Reports and the Phase 6 report** (a *Why flagged* block / section).
- [ ] **Read the Dashboard's Label yield** once labels accumulate, and move alert budget toward the mechanisms with
      the best precision.
- [x] **Phase 4g decision rule** (2026-10-28): robust deviation against the same weekday's training days at
      the same time (calendar) and the level when active, the smaller counting; a fixed bar of z 3 with the
      validation quota as a ceiling; the Isolation Forest as a second opinion (alone only above every
      training step's score); drops only for entities with their own level and 20+ usual lines.
      Windows 5, 30, 120 and 720 minutes (from seven), after an evaluation on the real data (counts only):
      the same alerts and detection on every entity type; 5 / 15 / 720 would have missed OSSEC destinations.
- [x] **Phase 4g features** (2026-10-28): outcome (auth), relationship novelty, asset/zone context, regularity;
      failures and new partners as robust channels; Explain shows them.
- [ ] **Fill in `pipeline/phase9_llm_triage/site/assets.csv`** (zone, role, criticality per server, address or
      network) from the network inventory, then rerun 4g: zone crossings, peer baselines and criticality need it.
- [ ] **Rerun Phase 3 and the detectors for auth** (hours): Phase 3 no longer uses names as features (server,
      agent, usernames, source IPs) nor the source port as a number; the models and Analyze follow once retrained
      (`python run_pipeline.py --source auth --from-phase 3 --with-model-zoo`). OSSEC done 2026-10-30.
- [x] **Rerun 4g and 7 for auth and OSSEC** with the new rule (counts above).

## Pipeline console output (2026-10-30)

- [x] **One standard** for every script's lines, times and options: [pipeline/STYLE_GUIDE.md](pipeline/STYLE_GUIDE.md),
      implemented once in `pipeline/shared/runlog.py` (`date time | runtime HH:MM:SS.s | LEVEL | message`;
      `-v`, `-q`, `--progress-interval`). A full OSSEC run: every line conforms, counts only.
- [ ] **Check an auth run** the same way when Phase 3 is re-run (the longest run, with checkpoints and resumes).

## SSO (Authlib, switched 2026-10-05)

Code side done: Authlib sign-in, account picker, sign-out at the provider,
settings check (`python -m service.sso_check`), 18 SSO and dataset tests.
What's left needs IT (steps in `triage-console/docs/user/03_sso_and_datasets.md`):

- [ ] Ask IT for a **public-client** registration (Entra platform "Mobile and
      desktop applications", no secret) or a **confidential** one (platform
      "Web" plus a secret in `SMRT_OT_CONSOLE_CLIENT_SECRET`). Redirect:
      `http://localhost:8765/auth/callback`. App role: `OT-Console-Admin`.
- [ ] Fill in `triage-console/var/auth.json` with the tenant-specific issuer
      (not `common`), then run `..\.venv\Scripts\python.exe -m service.sso_check`
      until it reports no FAIL.
- [ ] Test one real sign-in and sign-out. So far everything is tested only
      against the fake provider in `tests/test_auth_datasets.py`.

## Simple mode (the main workflow)

Built 2026-10-06 (US-35, FR-SMP-01–09, decision Q28): the *Simple · Advanced*
switch (Simple by default), *Check logs* (Upload → Analyze → Map → Review),
uploads kept as review items with the uploaded lines around each event, the
upload Review page, *Send to a reviewer* (mail draft without log lines, then
*Waiting for you* by the Settings name), docs and `tests/test_uploads.py`.

- [ ] **Check:** time from file to label for a day of authlog (not yet timed;
      the 5-line sample takes a few seconds).
- [ ] **Analyze step's waiting animation:** uses the route board; the TODO
      asked for the pack's loader (train or monkey) with the pipeline steps as
      stations.
- [x] **Clear an upload from the page** with the admin password (FR-SMP-09, 0.2.0).
- [ ] **When SSO is set up:** match *Waiting for you* on the signed-in account
      (already the case through `_actor()`), and offer reviewers from the SSO
      directory instead of typed names.
- [x] **Advanced Review:** disable the label buttons while a label saves, as
      the upload page now does (rapid clicks saved repeats, 2026-10-06).

## Reports (investigation report editor)

Release 0.2.0 completes the Reports editor, persistent versions, both exports,
map, timeline, sign-offs and malicious-activity template. Q33 is decided: automatic
IR-YYYY-NNNN numbers; local reviewers may close/reopen and edit closed cases;
every save appends a version. See the [release record](triage-console/docs/06_reports_review_release.md)
and [user guide](triage-console/docs/user/04_reports_and_review.md).

- [x] *Log lines* block (FR-RPT-11): a finding's events rarest first, their
      lines, minutes before and after set apart; *Select all* (AUTH, OSSEC);
      kept as retrieved.
- [x] Printed-report layout in Times New Roman, new default sections,
      subsections, footnotes (FR-RPT-02, 14, 20).
- [x] *Table*: ask AI / SQL / fill in; highlights and comments (FR-RPT-15–16).
- [x] *Metric* tiles; method notes beside every score (FR-RPT-17–18).
- [x] *ATT&CK* block: search, local-model suggestion, offline copy (FR-RPT-19).
- [x] *Target* filled from a finding (FR-RPT-21).
- [ ] Try *Ask AI* and *Match with AI* with Ollama running (built and tested
      against a stand-in model; Ollama was not running on 2026-10-07).
- [ ] Rebuild `attack_enterprise.json` when MITRE releases a new ATT&CK version
      (`python -m service.attack_build enterprise-attack.json`; v19.2 now).
- [x] *Cluster map* (FR-RPT-12): test + validation, numbered targets; saved positions
      or explicitly marked nearest-neighbour estimates; snapshots survive reopening.
- [x] Per-line rarity (FR-RPT-13) uses saved individual scores when available;
      absent scores are labelled unavailable, never copied from aggregate scores.
- [x] Silhouette evaluation: omitted from the report body; map notes explain
      that 2D separation is not a measure of maliciousness.
- [x] Save/list/reopen reports; immutable versions, optimistic conflict detection,
      historical finding links, automatic numbering and editable closed cases (Q33).
- [x] Timeline from a finding plus editable manual events; retained provenance.
- [x] A4 print, preview, Word and PDF downloads of a saved version (FR-RPT-10).
- [x] Non-binding sign-offs; changing signer details clears the acknowledgement.
- [x] Malicious-activity template with confirmation, containment and recovery prompts.
- [ ] Deferred by the user: full-report AI writer (FR-RPT-07, Q31).

## Failure endings for the waiting animations

Built 2026-10-06 (`loader.fail()` beside `arrive()`; FR-SQL-08, FR-REV-10,
FR-SET-06): the train into a depot (buffer stop, red signal, shed, floodlights),
the bus at a red light at a crossroads, a cymbal falls and rolls away, the
red-tagged cabinet topples. Review failures add the developer note and *Copy
details*. Settings has *SQL query fails* and *Review fails* previews.

- [ ] Compare the depot with the reference photo once more on a wide SQL page
      (checked in the narrow Settings preview only).

## Review filters

- [x] Exact multi-value server, account, program and address filters in Advanced
      and Simple Review, typed suggestions and removable chips, matching counts.
- [x] Filter on complete per-observation facts from original events, not the top
      three summaries; narrow the selected group's unusual events too. Values
      within a field are OR; fields are AND on the same original event.
- [x] Firewall host/source/destination facts; uploaded items use retained lines.
- [x] Filters persist while the app is open. Whole-group labels remain whole-group
      labels, with an explicit notice. Tests cover exact matching and SQL safety.
- [x] Label buttons disable during save and recover on error.

## Whitelisted users (Settings, decision Q35)

Built 2026-10-12 (FR-SET-07, FR-REV-15, US-38, `service/whitelist.py`, 8 tests): accounts an
administrator vouches for stop asking for review in Review, Check logs, Analyze, uploads and the
Dashboard; still scored, never deleted; a reason, an optional server and last day, the admin
password and the activity log.

- [ ] **SSO last:** once SSO is set up, require a signed-in admin instead of the shared password.
- [ ] **Addresses:** whitelist source addresses as well as accounts, if wanted (not built; Phase 9's
      approved automation addresses are a different list that only informs the language model).
- [x] **Narrower overrides (2026-10-30):** a whitelisted account still asks for review on a new source address or
      server (Phase 4h), a switch to root unless its entry includes *su*, and any activity alert.
- [ ] **Review the list:** a reminder on the Dashboard when an entry is about to end or has no reason
      recorded by a named person.

## Documentation visuals (one document at a time)

Same elements as Product requirements (chapter links, title cards, step tiles,
To → Do rows, cards), drawn from each document's Markdown in `doc-visuals.ts`.

- [x] SSO and datasets (2026-10-06)
- [x] Running it: setup, caches and tests (console README)
- [ ] Functional requirements (02) and non-functional requirements (03)
- [ ] Finding suspicious activity in NSEWL SCS server logs (project README)
- [ ] Phase 4f (planned): sequential pattern mining
- [ ] Phase 7b: behavioural clusters
- [ ] Phase 8: maliciousness classifier
- [ ] Phase 9: LLM triage into four categories

## Patterns (new log formats)

- [ ] **Read the saved rules in the pipeline:** Phase 1 loads a log type's exported rules
      (`Export` → JSON) after its own, so Analyze and the pipeline see the new event types.
      Until then, copy them into the classifier (*Copy for Phase 1*).
- [ ] **A new log type needs its own Phases 2–4** (observations, features, models) before
      Analyze or Simple mode can score it; Simple mode stops at *Unknown log format* until then.
- [ ] **From Datasets:** offer *Find patterns* on an imported archive.
- [ ] **Tables with several log types** (a `sourcetype` column): decide whether a field value picks the
      log type per row (each row read by its own rules), rather than one log type per scan.
- [ ] **Use a table's extra fields in the pipeline** (Phase 2 hosts and times from the columns, other
      fields as features), once a real export is in hand.
- [ ] **Very large data:** a pass reads up to 5 million lines (about 20 s per million unknown
      lines). Past that, sample for the shapes and count exactly.

## Sigma (Advanced, drafted 2026-10-16)

Built: Advanced → Sigma (`service/sigma.py`, `web/src/tabs/sigma.ts`, 17 tests, `tests/browser_sigma.py`). Sigma rules
and correlations (`event_count`, `value_count`, `temporal`, `temporal_ordered`, chained; the older `count() by`)
run in sliding windows over Phase 1's fields, on pasted lines, an upload or a file; eight starter entries from the
Phase 9 catalogue (guessing, spraying, enumeration, login after guessing, su failures, OSSEC agent stopped, port
scan, sweep); edit, test a draft, import and export YAML; hits marked whitelisted. No new package (PyYAML is in
the pipeline's environment). Changes no score; flags for Review (below).

- [ ] **Confirm the starter thresholds** (8 in 2 min, 10 accounts a day, 5 invalid users in 10 min, 15 ports or
      hosts in 5 min) with the counterparts' rules; replace or add theirs by Import.
- [ ] **Against DAD:** per hit, whether DAD flagged the same lines (the Dashboard's outlier comparison as a fifth
      mechanism: known versus unknown).
- [x] **Sigma as a fifth detector (2026-10-19):** a hit flags the observations holding its lines, in Analyze, uploads
      and the year's validation and test periods (`service/sigma_review.py`, in the cluster index's background pass,
      re-run when rules change); Review lists any group holding one whatever its lift, with the rule titles. 7 tests.
- [ ] **From a hit to Reports**, and to the hypothesis register.
- [ ] **Dashboard Venn:** Sigma as a fifth set beside the four mechanisms (known versus unknown). Its matches already
      have their own headline card and lead *Next to review* (2026-10-26).
- [ ] **SigmaHQ rules:** fields are mapped by name (ALIASES); Linux rules written for PAM text or auditd will not
      match Solaris lines without a mapping per rule. Modifiers `base64`, `windash`, `fieldref` and `lt`/`lte`
      windows (absence) are refused with a message.
- [ ] **The year's data:** run the rules over re-supplied logs (the corpus was purged); a file is read up to
      3 million lines at a time. The stores Review reads are covered: validation and test by Review's pass, the training
      period by Sigma → Training period (2026-10-30).
- [ ] **Editor:** YAML highlighting (no CodeMirror YAML mode is installed; a plain text area for now).
- [ ] **ATT&CK version:** the starter tags follow the Phase 9 catalogue (v19.2, e.g. T1685); agree one version
      with the counterparts.
- [x] **User guide and requirements (2026-10-26):** `triage-console/docs/user/05_sigma.md`; FR-SIG-01–05, US-39.
- [x] **Form, Describe, Test before Accept, stamps (2026-10-26, FR-SIG-06–09):** a new rule opens in a form (required
      fields marked and shaded while empty; Match, Except, Count, Level, More); *Describe* has the local model draft a
      rule from plain English (proof of concept); *Draft → Test → Accept*, Accept locked until the draft as it stands
      is tested; every rule shows who added it and when, *New* for a week. `service/sigma_form.py`,
      `service/sigma_ai.py`, `web/src/sigma-form.ts`; 20 tests (`tests/test_sigma_form.py`); `tests/browser_sigma.py`
      walks both flows in Edge against a stand-in model. In the deck as a proof of concept.
- [ ] **Describe with a real model:** built and tested only against a stand-in; the laptop's qwen2.5:3b is too small to
      rely on. With a capable local model, try ten plain-English rules and count how many read first time, need the
      one retry, and do what was described.
- [ ] **Test on the stored year?** *Test* runs on the page's input (paste, upload, file or folder). Decide whether it
      should also offer the console's own AUTH and OSSEC event stores (a recent window), as Review's pass reads them.
- [ ] **Form coverage:** rules with an `or`, `1 of`, both firewalls or a sequence open in YAML (5 of the 8 starter
      rules). Extend the form only if analysts need those often.
- [ ] **SSO last:** the stamp shows the Settings name until SSO is set up, then the signed-in account (`_actor()`);
      the starter rules show as *starter rules*.

## Dashboard, passwords and the local service (2026-10-26)

Built: the Dashboard around decisions, its editor with SQL tables and tiles, packing (FR-DSH, FR-SET-08); the SQL password
(FR-SQL-07, Q36); a report from Review notes and HTML export (FR-RPT-25); the security review (NFR-SEC-17–20).

- [x] **Defaults open nothing (2026-10-30):** SQL (`1234`) and admin (`123456`) must be changed before first use.
- [ ] **SSO last:** once SSO is set up, decide whether queries need a signed-in role instead of the shared SQL password.
- [ ] **Residual risk:** any program running on the laptop as the user can still call the service; the design assumes a
      single-user laptop with endpoint protection (whitepaper Appendix I).

## Whitepaper (LaTeX updated 2026-10-26)

- [ ] **Screenshots:** retake the Dashboard, Settings and the menu (they predate the redesign) and add one of Sigma;
      Appendix J says which are out of date.
- [ ] **The work of 27–30 October:** Phase 4g's activity alerts and incidents, Explain, Phase 4h and Profiles, names no
      longer used as features, and the pipeline's console output standard are not in the paper yet.
- [ ] **Typst and PDF editions:** `whitepaper/README.md` names Typst sources, a Markdown edition, PDFs and `colab/` that
      are not in this workspace; regenerate them from the LaTeX (`scripts/convert_whitepaper_appendix_typst.py` covers the
      appendices) or compile the LaTeX directly.

## Event logs (Phase 1 parser, 2026-10-19)

Fixed-width parser built from the instructions, the format answers and the sample `data/phase0_raw/event_logs/Dec 25/`:
`pipeline/phase1_classify/event_log_parser.py`, `event_log.py`, `event_log_devices.py`, 77 tests, made-up samples,
[README](pipeline/phase1_classify/README_event_log.md). Only the stated rules; everything else goes to
`event_log_exceptions_<YYYY-MM>.csv` for review. Not yet in `run_pipeline.py`; in the console as documentation only (2026-10-21).

- [ ] **Review the exceptions** (sample: 13,416 lines; most are 12,111 unknown states and 857 unknown limit codes) and add rules.
- [ ] **Keep filling the lists** (code 1, identifier 1, identifier 3) from `event_log_unclassified_values.csv`.
- [ ] **Find out what the lowercase `c` before `POWCON` and `SCBKWH` means** (`cPOWCON`, `cSCBKWH`): read without it for now (`STATE_SPELLINGS` in `event_log_parser.py`).
- [ ] **Group the states** (2026-10-21): add groups to `STATE_GROUPS` (`event_log_devices.py`) from
      `event_log_state_sets.csv`, then run `event_log_devices.py` alone; check the `mixed` devices in
      `event_log_devices_review.csv` (a needed group, or a device that is really two).
- [ ] **Then** decide its Phases 2-4 and whether it joins the console.

## Console

- [ ] **Sankey colours:** OSSEC (olive) and PF (red) fail the colour-blindness
      check (NFR-USE-03). The five review-label colours are not checked yet
      either (they are always shown with their names).
- [ ] **Checks not done yet:**
  - Chrome (only Edge so far, NFR-CMP-02);
  - widths outside the Reports 1280/1440 px Edge checks (NFR-USE-05);
  - an automated WCAG check (NFR-USE-01).
- [ ] **Tests for Analyze scoring and the review queue** (NFR-MNT-04).
- [ ] **Rehearse a backup and restore** of `triage-console/var/` (NFR-DAT-05): built (`python -m service.backup`,
      2026-10-30); run `rehearse` once (above).
- [ ] **Make the console usable without ML knowledge** (US-34, Q26): most users are
      operations engineers. Review done (2026-10-06). Still model-facing: the Models page's vocabulary, Analyze's validation
      percentile and neighbour agreement, "view" / "observation" / "lift", t-SNE / UMAP
      axes. Rework with the `self-explanatory-ui` rule (no explanatory text).
- [ ] **Export review labels to Phase 8** (US-15). Q21 sets the mapping:
      security relevant → positive; expected behaviour and operationally
      interesting → negative; suspicious and insufficient evidence → no label.
      Use each item's latest label, and mark labels given to a whole cluster.
- [ ] **Planned features** (shown as TODO cards):
  - "Ask in plain language" on Data → SQL;
  - an AI summary of a group's comments;
  - model triage (Phase 9) inside the console.
- [ ] **Run the service all day:** `autostart.ps1` (above) starts it at sign-in. A copy started by Claude stops after
      2 hours.

## Pipeline

- [ ] **Regenerate the Phase 8 labelling sheets.** Those in
      `data/phase8_malice_classifier/to_label/` predate the 2026-09-30 re-run and the sequence (4f) and
      activity (4g) alerts.
      On the current alerts, expect about 592 rows to label, or about 130 by
      behavioural cluster.
- [ ] The README's other known gaps:
  - the robust detector is silent on auth;
  - session event-order hashing is saturated;
  - IPFilter activity needs the change record;
  - the approved-automation list is empty.

- [x] **Sequential mining step 0 (2026-10-08):** read-only order/duplicate audit,
      traceable event extract, 10 tests, complete OSSEC audit and three bounded
      AUTH samples. See `pipeline/phase4f_sequences/AUDIT_2026-10-08.md`.
- [x] **Sequential mining steps 1–3 (2026-10-08):** session/episode streams
      (Phase 2's IDs, checked; source order; rotated-file copies merged as
      aliases; uncertain steps marked), routine catalogue and rules (PrefixSpan,
      training only), the sequence detector (existing budget, training-quantile
      floor) collected by Phase 7, and the association-rule alert profile
      (mlxtend). Phase 4f in `run_pipeline.py`; 18 new tests.
      Decisions: prefixspan + mlxtend, event-type tokens, the existing budget.
- [x] **Sequence alerts in Review (2026-10-19):** Phase 7b counts them as flagged; Review ranks and
      explains them (*Frequent subsequences*); uploads are scored by Phase 4f's own code
      (`service/sequences.py`, 9 tests); the frozen runtime keeps the step model.
- [ ] **Sequential mining next:** suspicious-sequence templates from the Phase 9
      knowledge base (step 4), injected-attack evaluation (5: `service.inject_eval` now plants attacks for every
      mechanism, 4f included, through Analyze), console views
      (Review: usual routine beside this sequence; Data → Routines) and the
      report chapter (6), cross-log timelines (7). Phase 7 now holds the
      sequence alerts (auth 608, OSSEC 19); regenerate the Phase 8 labelling
      sheets so they include them.
- [ ] **Exact pattern features in Phase 3:** replace or join the saturated
      `sequence_hash__` columns (known gap 4) with routine-pattern columns, then
      re-run Phases 3–7 and compare the model-zoo pile-up on the `mm` servers.
- [ ] **Routine approval:** who confirms routines, and whether a confirmed
      routine may become approved automation (needs an explicit policy).

## Presentation

- [x] Presenter name on the cover (Shawn Tan); no meeting date (2026-10-27).
- [ ] Rehearse the system demo on a copy of the console store (made-up reviewer and whitelisted
      accounts), and keep fallback screenshots.
- [x] **Deck restructured (2026-10-29/30):** <https://claude.ai/artifact/EZMM562z3ipDXeW9eahdsS> (private until shared).
      Introduction (AS-IS → TO-BE, information-rich but context-poor), mechanisms and scoring, what the console adds,
      engineering (extraction, features, selection and calibration), demo, next steps; 29 backups, each answering
      one question (listed in the *Questions* slide's notes). The from-scratch draft of 2026-10-27
      (<https://claude.ai/artifact/Kia1CMdtTumd7tj4zhRQUH>) has not been updated since.
- [ ] Work through [PRESENTATION_PREP.md](PRESENTATION_PREP.md).
