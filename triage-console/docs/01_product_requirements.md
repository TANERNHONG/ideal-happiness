# Project DAD Console: product requirements and user stories

| | |
|---|---|
| Document | 01 · Product requirements |
| Status | Describes the console as built, plus what is still planned |
| Version | 0.14 (2026-10-30): activity alerts as incidents in Review, Explain and Profiles in the scope and menu (Epic P, US-40, US-41). 0.13 (2026-10-26): Sigma rules for known attack patterns, written in a form, in YAML or from plain English and tested before they are accepted (Epic O, US-39); the Dashboard leads with what needs a decision and can be rearranged, with SQL tables and tiles of one's own (US-21); queries behind their own password (US-27); a report started from a reviewed item's notes, and HTML export (US-36); the menu grouped by investigation stage. 0.12 (2026-10-12): whitelisted users (US-38, Q35). 0.11 (2026-10-07): release 0.2.0 completes Reports and exact Review filters; Q33 resolved. 0.10 (2026-10-07): the report laid out as a printed incident report; tables, metrics, ATT&CK, footnotes, subsections. 0.9 (2026-10-07): the anomaly report; Log lines retrieval; Q29–Q32 decided. 0.8 (2026-10-07): investigation reports (Epic M, US-36; wireframe). 0.7 (2026-10-06): Simple mode (US-35, Q28); *Needs review*. 0.6 (2026-10-06): users are mostly operations engineers (Q26): personas, story actors, US-34; retraining only from Datasets with SSO. 0.5 (2026-10-05): documentation review: labels throughout, US-04/05 status, Settings animations. 0.4: review labels and the review investigation (Q23). 0.3: rewritten for the built application (decisions Q12–Q19); the stories of the earlier plan are kept in §7 with their status |
| Related | [02 Functional requirements](02_functional_requirements.md) · [03 Non-functional requirements](03_nonfunctional_requirements.md) · [04 Decisions](04_open_questions.md) · [05 Architecture](05_architecture.md) |

## 1. Purpose

The Project DAD pipeline (Phases 1–7b) turns 26.3 million server log lines
from 15 servers into about 29,000 alert rows and a few hundred behavioural
groups. Everything is traced back to its original lines. Until now, all of that
sat in CSV files and self-contained HTML reports, with no place to look at it,
check new logs against it, or record what a person decided.

The Project DAD (Data Anomaly Detection) Console is that place, on the pipeline laptop. It lets a person:

1. see at a glance what is waiting for review and what the models were built
   on (Dashboard);
2. check new log lines against the trained models and see whether they would
   be flagged, and where they sit among the year's activity (Analyze);
3. see what was trained, which views raise alerts and how each detector did on
   the test period (Models);
4. explore the year of logs: the time splits, messages by type, traffic by
   address, groups of similar activity on an interactive map, and read-only
   SQL (Data);
5. review the flagged groups and firewall activity: see their servers,
   accounts and dates, how rare each unusual event is, and the logs from the
   same server around it, and record *Security relevant*, *Suspicious*, *Operationally interesting*, *Expected behaviour* or *Insufficient evidence*
   with a note (Review);
6. as an administrator signed in with SSO, add a dataset and train models on
   it (Datasets);
7. run detection rules for known attack patterns over new logs and the
   year's, and see their matches first in Review and on the Dashboard (Sigma).

## 2. Goals and success measures

| Goal | Measure |
|---|---|
| Usable without machine-learning knowledge | An operations engineer can find, read and decide on a flagged item in operations terms (servers, accounts, times, how unusual); model internals are never needed to act (US-34). |
| Make the pipeline's results reviewable | Every flagged group and every firewall activity period can be opened, with its original lines, without opening a CSV or a report. |
| Check new logs quickly | A day of authlog (hundreds of thousands of lines) gets a verdict per view from the same models as the year's logs. |
| Every decision rests on evidence | A review is recorded against a group or period whose lines, scores and surrounding logs were on screen. *Security relevant*, *Suspicious* and *Insufficient evidence* need a note. |
| Keep data on site | No log line, result or decision leaves the laptop. The only outside connection is SSO sign-in, once configured. |
| Nobody changes the data by accident | The SQL console cannot write, and queries need their own password. Adding data and training need an admin signed in with SSO. |
| Know who did what | Reviews, names, comments, queries, sign-ins, imports and training runs are in the activity log. |

## 3. Users

| Persona | Who | What they need |
|---|---|---|
| **Operations engineer** | **Most users.** Keeps the NSEWL SCS servers running: knows the servers, accounts, scheduled jobs and change windows. Not a machine-learning engineer, and usually not a security specialist. | What to look at first, the evidence on one screen, a quick way to record a decision. All of it in operations terms, without model vocabulary. |
| **Security analyst** | Some users. Judges whether activity is hostile. | The same evidence, and the say on *Security relevant* and *Suspicious*. |
| **Pipeline owner** | The ML engineer who runs the pipeline; few, and often not at the console. | To see what was trained and how it behaved; to check new logs; to query the data. |
| **Administrator** | The person allowed to change the data the console relies on. | To add a dataset, import its archives and retrain (the only way to retrain from the console, Q26), signed in with SSO. |
| **Reviewer** | A manager or approver. | Progress and decisions per log type. |

Most people at the laptop are operations engineers; the console must not assume they know machine learning (Q26). One person can hold several of these roles. Without SSO, records carry
the name typed in Settings (default `local-user`). With SSO, they carry the
signed-in account (Q3, narrowed by Q17).

## 4. Scope

### Built

| Page | What it offers |
|---|---|
| Reports | Anomaly and malicious-activity templates; evidence blocks, target maps, timelines, non-binding sign-offs, persistent version history, preview, Word/PDF/HTML export and links from findings; a reviewed item's *Report* starts one with its notes as the analyst comments. Closed cases remain editable (Q33). Full-report AI writing is deferred (Q31). |
| Simple mode | The default (US-35): *Check logs* (Upload → Analyze → Map → Review, one main button per step), *Review* (uploads sent for review, *Waiting for you* first), *Reports* and Settings. A *Simple · Advanced* switch at the top of the menu; Advanced shows every page below |
| Dashboard | What needs a decision (items waiting, Sigma matches, security relevant, share reviewed) and the next items to open; review progress; the share flagged and which detectors agree; lines, months, event types and message variants per log type; training, validation and test observations per model; usage over 30 days. The layout is set in Settings: cards moved, resized and hidden, SQL tables and tiles of one's own, packed tightly or not |
| Patterns | Before Analyze: new data scanned for what the pipeline's Phase 1 rules (and rules made here) know; the unknown lines grouped into shapes, with heads and tails; a canvas that slices lines into prefix, message and suffix; regex candidates from the examples, tried live; rules saved per log type and exported for Phase 1; coverage per pass and over time (drift) |
| Analyze | Paste, upload or read a file on the laptop; detect or choose the log type; verdict and confidence; results per view; map with the new lines (drawn on request); nearest groups; observations; event types never seen in the year |
| Sigma | Detection rules in the Sigma format (rules and correlations over sliding windows) for known attack patterns: eight starter rules; rules written in a form, drafted from plain English by the local model (proof of concept) or in YAML, each checked live and tested before it is accepted; import and export; run on pasted lines, an upload, a file or a folder on the laptop. The enabled rules are also a detector beside the models: their hits flag observations for Review |
| Models | Per view: used for alerts or not and why, test-period alerts per detector, model zoo ensemble and its scores against the proxy label; *Retrain* leads to Datasets (an administrator signed in with SSO, Q26) |
| Data | Time splits; Sankeys of messages by type and traffic by address; clusters with names, make-up, typical lines, members, comments, a group filter and an interactive map drawn on request (open any point; pick a group to see it in yellow); read-only SQL behind its own password |
| Review | Every item needs review until someone reviews it, and is then reviewed with one of five labels (Q11, Q23); the two are kept apart. Each group by its servers, accounts and dates; its unusual events rarest first ("1 in N"), each with its lines and the logs around it; the models' scores under *Model details*; notes and history. Groups whose flagged events all belong to whitelisted accounts are listed apart, under *Whitelisted*. Activity alerts (AUTH, OSSEC) follow, one item per incident (Q41) |
| Explain | Why each activity alert was raised, in pictures: the day against its usual band for comparable days, the week as a heatmap, eight weeks of daily totals, the ranked reasons with their numbers, and *Summarize evidence* |
| Profiles | Any server, source IP, username or destination IP, or the whole log, on any day against the same weekday's training days, alerted or not (every log type); a watch list shown on the Dashboard |
| Datasets | Datasets, sign-in, add a dataset, import archives, train from a chosen phase, run history and output |
| Documentation | The pipeline as an MRT line map (phases are stations; click one); guides, disclaimers, requirements and the pipeline's notes as bus stops |
| Settings | Language (6), theme, font and size, animations, the local model and its address, your name, the Dashboard layout (the Dashboard itself as the editor), whitelisted users, the activity log, the admin password and the SQL password |

Advanced mode groups the pages in the order of an investigation: *Overview* (Dashboard), *Prepare* (Datasets, Patterns, Models), *Detect* (Analyze, Sigma), *Investigate* (Review, Explain, Profiles, Data), *Report* (Reports) and *Console* (Documentation, Settings). Models, Data and Review share one Log type dropdown (Q19).

### Planned (shown as TODO cards)

- Ask in plain language on the SQL page: the local model writes a query for
  the person to check and run.
- An AI summary of a group's comments.

### Not in scope now

- The alert queue, model suggestions, exports and site-context editing of the
  earlier plan (§7). They are not withdrawn unless §7 says so.
- Access from other machines (Q2). SSO protects admin actions on the laptop; it
  does not open the console to the network.
- Live log ingestion, alerting by email or chat, any cloud model.

## 5. Assumptions and constraints

- The console runs on the pipeline laptop only and is opened in a browser on
  that laptop (`127.0.0.1`, Q2).
- The language model is `qwen2.5:3b-instruct` on the laptop's Ollama (Q4).
  JEV is not used (Q12).
- Flags mean *unusual*, not *malicious*. No analyst labels exist yet, so model
  quality is measured against a proxy label.
- Names, comments and reviews are kept indefinitely (Q8). The activity log can
  be cleared with the admin password, and the clearing is recorded (Q14).

## 6. User stories (built)

MoSCoW priority as agreed for the pages; all stories in this section are
built. Acceptance criteria are Given / When / Then.

### Epic G · Overview

**US-21 · See what needs attention** (M) — *Operations engineer, Reviewer*
- When I **open the console**, then the Dashboard shows first **what needs a decision**:
  per log type how many **items are still to review**, how many of them **match a Sigma
  rule**, how many are labelled *Security relevant*, and the share reviewed; then the **next
  items to open**, Sigma matches first, each opening in Review.
- Then it shows how many reviewed items carry each label, and **what share of
  observations was flagged** and by which detectors.
- Then it shows **how many observations trained, validated and tested each
  model**, and how many lines, event types and message variants each log type
  has.
- Then it shows **how often each page and Analyze were used** over 30 days.
- When I **arrange the Dashboard** in Settings (drag cards, widen or hide them, add **a
  table of my own read-only query** or **a tile** with an icon and text), then the
  Dashboard shows that layout once I save it. A table keeps its result until I
  **refresh** it, with the SQL password.

### Epic H · Check new logs

**US-22 · Would these lines be flagged?** (M) — *Operations engineer, Pipeline owner*
- Given auth or OSSEC lines, when I **paste, upload or name a file** and press
  Analyze, then the lines go through the pipeline's Phase 1 rules, Phase 2
  observations, Phase 3 features and Phase 4 detectors and model zoo. Progress
  is shown station by station.
- Then I see **a verdict** (*would be flagged* or not) with how unusual the input
  is, and for each view how many observations were flagged and by which
  detector.
- Given PF or IPFilter lines, then **the presence rule** applies: any recognised
  traffic is flagged.
- Given lines no log type recognises, or an OSSEC input without a server name,
  then the console **says what is missing**.

**US-23 · Where do the new lines sit?** (S) — *Operations engineer*
- Given an auth or OSSEC result, when I **open a view**, then the rest of the
  result appears first and a card says how many points the view's map has.
  When I press *Draw the map*, it shows the year's observations and the new
  ones as rings (filled red when flagged). I can zoom, pan and frame the new
  lines.
- Then a table lists **the nearest groups** with how many new observations each
  took and how far the neighbours agreed. Clicking a row shows that group in
  yellow and greys out the rest, without moving the map; clicking it again
  clears it.
- When I **click a point** of the year's map, then I see **that observation**: its
  period, time, group, votes and original lines.

### Epic I · Models and data

**US-24 · Know what was trained** (M) — *Pipeline owner*
- When I **open Models** for a log type, then each view shows **whether it raises
  alerts** (and why not), the test-period alerts per detector, and the model
  zoo's ensemble with its detection, precision and lift against the proxy
  label.
- Then *Retrain* **takes me to Datasets**, where retraining needs an administrator signed in with SSO (US-30, Q26). No command lines are shown.

**US-25 · See the data** (M) — *Operations engineer, Pipeline owner*
- When I **open Data**, then I see **the training, validation and test spans** per
  view.
- Then I see **Sankeys of messages by type** (log type → category → event type)
  and traffic by address (origin → log type → destination). I can choose
  the months, equal widths and the height, and group addresses by their first
  one, two or three parts or not at all (a.x.x.x, a.b.x.x, a.b.c.x, a.b.c.d).
- When I **click a box or band of the traffic chart**, then I can **open its lines
  in Data → SQL** or **download them as CSV** (up to 100,000 lines).

**US-26 · Explore groups of similar activity** (M) — *Operations engineer*
- When I **open Data → Clusters** for AUTH or OSSEC, then **the list of groups loads
  first**, and the map waits behind a card that says how many data points it has
  and that drawing them can take some time.
- When I **press *Draw the map***, then it shows **every mapped observation** (up to
  60,000; all flagged points kept). I can zoom by wheel, pinch or buttons, pan
  by drag or arrow keys, see t-SNE axes, and show flagged points only. Points
  stay sharp at any zoom. I can make the map fill the screen (button or F) and
  return with Esc.
- When I **click a point**, then I see **that observation**: period (training,
  validation or test), time, group, whether it was flagged, model-zoo votes
  and its original lines, with a button to highlight its group.
- When I **pick a group** in the list, then it **turns yellow** on the map and every
  other point turns grey, without the map moving. I see its make-up, typical
  lines, every member with its original lines and comments; I can rename it,
  and zoom the map to it if I ask.
- Then I can **switch groups on and off** one by one or by kind: named by people,
  automatic names, unnamed (map only), isolated points.
- When I **switch the layout** from t-SNE to UMAP, then **the same points are laid
  out by UMAP**, keeping the groups, flags, highlighted group and clicked point
  (Q24). New lines on Analyze move with them.

**US-27 · Query the logs** (S) — *Pipeline owner, Operations engineer who writes SQL* (plain-language questions are planned, FR-SQL-10)
- When I **write a SELECT** over the event tables and press Run, then I get **up to
  1,000 rows**.
- Given **a query that would change anything**, then it is **refused before it
  runs**, with the reason, and the attempt is recorded.
- When I **run my first query**, then the console **asks for the SQL password** once;
  then queries run without asking until I stop querying for 30 minutes.

**US-33 · Choose the log type once** (S) — *everyone*
- When I **choose a log type** on Models, Data or Review, then **the other two pages
  open on the same log type**.

### Epic J · Review

**US-28 · Review flagged groups** (M) — *Operations engineer, Security analyst*
- When I **open Review** for AUTH or OSSEC, then I see **the groups the models flag
  at least twice as often** as their view overall, most anomalous first. Items
  start as *Needs review* and become *reviewed* once a
  label is recorded (Q11); the two are kept apart.
- Given PF or IPFilter, then I see **the periods and flows with activity**.
- When I **open a group**, then I see **its servers, accounts and addresses**, and
  **its unusual events rarest first**, each with how rare it is ("1 in 50,000").
- When I **open an event**, then I see **its time, server and original lines**; the
  models' own scores are under *Model details* if I want them.
- When I **set *Before* and *After*** (in minutes) and fetch, then I see **every
  line from that server in the window**, across the logs I ticked, with the
  observation's own lines marked. The read-only SQL query that fetched them
  is shown, and I can open it in Data → SQL.
- When I choose *Security relevant*, *Suspicious*, *Operationally interesting*, *Expected behaviour* or *Insufficient evidence*,
  then **the label is recorded** with my name and the time. *Security relevant*,
  *Suspicious* and *Insufficient evidence* need a note.
- When I **change a label**, then **the earlier one stays in the history**.

**US-29 · Name and discuss a group** (S) — *Operations engineer, Security analyst*
- When I **rename a group or add a comment**, then **everyone using the console sees
  it**, with the author and time.

### Epic K · Administration

**US-30 · Add data and retrain** (S) — *Administrator*
- Given SSO is set up and I am signed in with the admin role, when I **add a
  dataset** (log type and folder of monthly archives), import it and start
  training from a phase, then **the pipeline runs** with its output shown, and I
  can stop it.
- Given I am **not signed in, or not an admin**, then these actions are **refused**
  with the reason, and the page stays readable.

**US-31 · Know who did what** (M) — *Reviewer*
- When anyone **reviews, renames, comments, queries, signs in, imports or trains**,
  then **an entry with the person, time and action** is added to the activity log.
  Each entry carries the hash of the previous one.
- When I **clear the log** with the admin password, then **one entry records who
  cleared it** and how many entries went.

**US-38 · Whitelist an account I vouch for** (S) — *Administrator, Security analyst*
- Given an account whose routine activity the models keep flagging (a backup job, a monitoring
  service), when I **add it under Settings → Whitelisted users** with a reason, optionally one
  server and a last day, and the admin password, then **its flagged activity stops asking for
  review**: groups whose flagged events are all its own move from *Needs review* to *Whitelisted*,
  and Check logs and Analyze say *Whitelisted* instead of *Unusual* when nothing else was flagged.
- Then **nothing is hidden or deleted**: the models still score and flag it, the *Whitelisted* list
  and badges show where it applies, and each entry shows how many of the year's flagged
  observations name the account.
- Given an event that **also names an account not on the list**, or **names none**, then it
  **still needs review**.
- When I **add or remove** an entry, then the activity log records it; a wrong password is refused;
  an entry past its last day stops applying.

**US-32 · Make the console readable for me** (C) — *everyone*
- When I **change the language, theme, font, size or animations** in Settings,
  then **the whole console follows**. The model picker at the top right and the one in Settings
  are the same setting.

### Epic L · For operations engineers

**US-34 · Act without machine-learning knowledge** (M) — *Operations engineer*
- When I **open a flagged item, a group, a map or an Analyze result**, then **what it
  tells me is clear from the page itself**, in operations terms: which server,
  which account, when, and how unusual.
- Model internals (detector names, proxy-label scores, feature names, t-SNE and
  UMAP, training and validation splits) are on Models or in details I can
  open; I never need them to decide.
- Status: **Partly.** Review is done (2026-10-06): groups by servers,
  accounts and dates; events by how rare ("1 in N"); model scores under
  *Model details*. Still model-facing: the Models page vocabulary (robust,
  isolation forest, novelty, model zoo, ensemble, consensus, detection,
  precision and lift against a proxy label, feature sets); Analyze's "unusual compared with the validation
  observations" and neighbour agreement; "view", "observation" and "lift" as
  everyday words; the t-SNE / UMAP axes. To work through with the
  `self-explanatory-ui` rule.

**US-35 · Check a log file in four steps** (M) — *Operations engineer*
- When I **open the console**, then **it starts in Simple mode**: *Check logs*,
  *Review*, *Reports* and *Settings* only. A **Simple · Advanced** switch at the top of the
  menu shows every page; the choice is kept.
- When I **drop a log file** (or paste lines), then **its log type and month are
  filled in** for me to change, and the server is asked for only when OSSEC
  lines do not name it.
- When I press **Analyze**, then **one verdict** comes back: *Unusual* or *Nothing
  unusual*, how many unusual events, on which servers, and the rarest as "1 in N".
- When I press **See on the map**, then **the map is drawn straight away** with the
  new lines as rings, and the **two or three nearest groups** say how many new
  lines landed in each and whether that group is usually flagged.
- When I press **Send for review**, then **the upload is kept** on this laptop as a
  review item, with the uploaded lines around each unusual event, and I can
  **Review now** or **Send to a reviewer**.
- When I **send it to a reviewer**, then **it shows as *Waiting for you*** for them,
  and **a mail draft** opens with a summary and no log lines (Q28).
- Status: **Built** (2026-10-06). The reviewer is matched by the name in
  Settings until SSO is set up, then by their signed-in account.

### Epic M · Investigation reports

**US-36 · Write up an investigation from its findings** (M) — *Security analyst, Operations engineer, Reviewer*
- When I **open Reports** (in Simple or Advanced), then **a report starts from the anomaly
  report template**, laid out like a printed incident report in **Times New Roman** (findings of
  malicious activity have a separate template). It now holds the report's details (reported
  by, date, report no., case status, assessment) and I Executive Summary, II Target Analysis, III
  Detection, IV Supporting Evidence, V Impact Assessment, VI Analyst Comments, VII MITRE ATT&CK
  Mapping, VIII Actions (immediate; planned and preventive), IX Conclusion, X Information Sharing,
  XI Sign-offs and footnotes; it began as 1 **Summary**, 2 **Target analysis**, 3 **Supporting evidence**, 4 **Analyst
  comments**, 5 **Conclusion**, 6 **Sign-offs**.
- The **Summary first states whether the case is OPEN or CLOSED**, then gives a **high-level
  executive summary** that the analyst writes and edits. **Full-report AI drafting is deferred** (Q31).
- The report is **modular**: I **drag blocks** (text, target, finding, log lines, table,
  timeline, AI draft, signature) into any section, **drag findings** from Review and the uploads
  into *Supporting evidence*, and **drag blocks and whole sections** to reorder them; sections can
  be added, renamed and removed. Every move can also be made with the keyboard (↑ ↓, remove).
- **Sign-offs** hold e-signature blocks (*Prepared by*, *Reviewed by*, *Approved by*): name,
  role, date. They are **not binding** in the proof of concept (Q32).
- **Visualisations come first** in a report on anomalies: the **test and validation cluster map
  with the targets marked on it**, and **saved per-line rarity where available**; missing individual scores are clearly unavailable.
- A **Log lines** block shows a finding's unusual events, rarest first, with their original lines,
  and the lines around any of them from every log, minutes before and after set apart; *Select
  all* for AUTH and OSSEC (done).
- **Tables** cite evidence from the database, asked in plain English (the local model writes the
  query, I check and run it) or in SQL, or are filled in by hand; I **highlight** and **comment on**
  cells, rows and columns as in Word (done).
- **Metric tiles** ("Rarity: 1 in 50,000"), **subsections**, **footnotes**, and a short note in small
  print on how any score shown is computed (done).
- **MITRE ATT&CK**: I match the activity to a technique myself, or let the local model suggest one
  for me to confirm (done).
- Status: **Built in release 0.2.0**, except the explicitly deferred full-report AI writer.
  Reports survive reload, each save appends an immutable version, historical versions
  can be reopened and restored as a new version, and concurrent stale saves are rejected.
  Numbering is automatic; any local reviewer may close/reopen or edit a closed case.
  Preview, Word/PDF/HTML export, timeline and non-binding acknowledgements are available.
- When I press **Report** on a reviewed item (Review → Reviewed), then **a new anomaly report
  opens about it**, its particulars filled in and **my notes as the analyst comments, exactly
  as I typed them**, for me to edit, save and export (2026-10-26).
- Review acceptance (US-28/35): exact server/account/program/address filters use full
  event facts; both modes show matching counts and removable chips. Group labels still
  apply to the whole group; duplicate clicks during a save create one request.

### Epic N · New log formats

**US-37 · Teach the console a new log format** (M) — *Security analyst, Operations engineer*
- When I **bring in new data** whose lines no rule knows yet (a new log type, or a known one whose
  heads or messages have changed), then **Simple mode stops at Upload** with *Unknown log format*
  and how many of the first lines are known, and **Find patterns** takes the lines to Advanced →
  **Patterns**. Analyze offers the same when no log type recognises the lines.
- When I **scan** them (pasted, uploaded, or a file, folder, ZIP or .gz on the laptop, up to five
  million lines a pass), then I see **how much is known** (Phase 1, my rules, prefix only, unknown),
  **over time** (or through the file), and the **shapes** of the unknown lines, largest first, with
  their heads and tails; shapes first seen late are marked *new*.
- On the **canvas** I see each line **sliced** into prefix, message and suffix, select any part
  of a line and send it to **Prefix**, **Message** or **Suffix**, or paste examples.
- The console **suggests regexes** that cover the examples (Exact, Fields, Anchors, Start), with
  named groups, how many examples each takes and roughly how many lines; I pick or edit one and see
  it **tried live** on the examples, each group's name over its value.
- I **save** it (a message rule with its event type) for the log type, or name a new log type;
  lines it takes leave the unknown list at once, and **Run pass** gives the exact numbers. Passes
  are kept, so coverage climbs pass by pass until most lines are known.
- **Drift**: rules that stopped matching are marked *quiet*; rules can be reordered, switched off
  or deleted; every change is in the activity log.
- The rules are **exported** (JSON, or lines for Phase 1's `RULES`) to be added to the pipeline.
- When the data **comes as a table** (a CSV or Excel export: one column the raw line, the others fields),
  the console first checks its first 100 rows, then I pick the **Raw logs** column from its headers, tick the
  **columns** to keep, and scan. The lines are dated by the time column, and I see how much of each field
  value is known (for example per host or source type); the lines of one value open on the canvas (FR-TAB).
- Status: **Built** (2026-10-09), except that Analyze and the pipeline do not read the saved rules
  yet; a new log type also needs its own Phases 2–4 before it can be scored.

### Epic O · Known attack patterns

**US-39 · Catch the attacks we already know** (S) — *Security analyst, Operations engineer*
- Given activity that is **common but known to be hostile** (password guessing, password
  spraying, user enumeration, a port scan), which a model that ranks rarity may miss, when I
  **run the Sigma rules** on pasted lines, an upload, a file or a folder, then I see **each
  hit, the most serious first**, with its rule, level and the lines behind it.
- When I **write or edit a rule** in the form, from a plain-English description or in YAML, then I
  see **at once how the console reads it** (or what is wrong), and I can **Accept** it only after
  **Test** has run that exact draft.
- Given an **enabled rule**, then **its hits flag the observations** that hold their lines,
  in the year's validation and test periods and in every upload: Review lists **any group
  holding one**, under the rule's title, whatever its rarity, and the Dashboard lists them first.
- Then **no model's score changes**: a hit is a reason to look, not a verdict; a hit whose
  accounts are all whitelisted says so.
- When I **import, export, change or delete** rules, then the activity log records it.
- Status: **Built** (2026-10-16; a detector beside the models since 2026-10-19; whole folders since 2026-10-22). The starter rules' thresholds are starting values
  awaiting operational confirmation.

### Epic P · Unusual amounts of activity

**US-40 · See why an amount of activity was flagged** (M) — *Operations engineer, Security analyst*
- Given a server, source IP, username or destination IP that was **much busier or quieter than
  usual** for that time of that kind of day, when I open **Review**, then I see **one item per
  incident**: an event seen on several entities, or a routine seen on several days, not one item per
  alert (Q41).
- When I open it in **Explain**, then I see **what it was compared with and by how much**: its day
  against the usual band, its week against a usual week, eight weeks of totals and the reasons in
  order, each with its number.
- When I ask to **summarise the evidence**, then the local model may reword it, but only an answer that
  keeps **every number** is shown.
- Status: **Built** (2026-10-27; incidents 2026-10-29). Run on the year's AUTH (218 alerts, 42
  incidents) and OSSEC (14 alerts, 10 incidents).

**US-41 · Look up any entity's normal** (S) — *Operations engineer, Security analyst*
- Given **any entity, alerted or not**, when I open **Profiles** on a day, then I see the entities
  **furthest from their normal first**, each against the same weekday's training days.
- When I open one, then I see its day, week and weeks as Explain draws them, who it shared lines
  with, and its activity alerts.
- When I **watch** it, then the Dashboard shows it on its log type's last day.
- Status: **Built** (2026-10-28). Phase 4h has run for AUTH, OSSEC and IPFilter; PF's is made by its next run.

## 7. From the earlier plan

Stories US-01 to US-20 were written on 2026-10-01 for an alert-queue design.
The console was built around pages instead (Q13). Their status:

| Story | Status |
|---|---|
| US-01 Load a pipeline run | **Replaced.** There is no load step; the console reads the pipeline outputs on disk directly. |
| US-02 See whether a run is healthy | **Partly** (Models, Dashboard). Collection gaps and silences are not shown; they are in the Phase 6 reports. |
| US-03 One queue of alerts | **Replaced** by Review: one queue per log type, of groups and firewall periods rather than single alerts. |
| US-04 Read the evidence | **Partly.** Review opens each flagged observation of a review item with its lines, detector scores and the logs around it (FR-REV-07–11); Clusters show members' original lines. Phase 7 alerts outside the review queue have no screen of their own. |
| US-05 What the other logs know | **Partly.** Review's *Logs before and after* searches all four logs on the same server around an observation (FR-REV-10). Matching by address across servers is planned. |
| US-06 Review a whole cluster | **Built** (Review, Data → Clusters). |
| US-07 Replay the map over time | Planned. The map is interactive but not replayable; the Phase 6 reports replay it. |
| US-08 Ask the local model for a category | Planned. |
| US-09 Choose how the model reasons | Planned. |
| US-10 Accept or overrule a suggestion | **Replaced** by the five Review labels (Q23), without model suggestions. |
| US-11 Keyboard shortcuts | Planned (Enter opens items and observations; labels have no shortcuts). |
| US-12 Approved-automation list | Planned. |
| US-13 Change windows | Planned. |
| US-14 Results of a session | **Partly** (Dashboard review progress). |
| US-15 Export Phase 8 labels | Planned. Which labels become Phase 8 labels is decided (Q21). |
| US-16 Summary for a meeting | Planned. |
| US-17 Know who decided what | **Built** as US-31. The log can be cleared with the admin password (Q14). |
| US-18 Instant JEV suggestion | **Withdrawn** (Q12). |
| US-19 Flag for review | **Replaced** (Q11). *Needs review* is the status of every item until it is reviewed, not a flag an analyst sets. |
| US-20 Trust in each model | Planned, once model suggestions exist. |
