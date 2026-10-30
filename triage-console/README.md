# Project DAD (Data Anomaly Detection) Console

For setup, launch and your first investigation, see the [quick start](../QUICKSTART.md).

A local web application over the Project DAD (Data Anomaly Detection) Console pipeline's
results. It runs on the pipeline laptop only (`127.0.0.1`). The language model
is `qwen2.5:3b-instruct` on the laptop's Ollama. The only outside connection is
to your identity provider during SSO sign-in, and only once SSO is set up.

The folder keeps its original name, `triage-console/`.

| Page | What it does |
|---|---|
| **Check logs** (Simple) | The default mode: Upload → Analyze → Map → Review, one button per step. *Send for review* keeps the upload's unusual events, each with the uploaded lines around it, as a review item; *Send to a reviewer* opens a mail draft without log lines and shows the item as *Waiting for you* to them. The *Simple · Advanced* switch at the top of the menu shows the pages below. |
| **Dashboard** | What needs a decision (waiting, Sigma matches, security relevant, reviewed), the next items to open, review progress, how much is flagged, the data covered, what the models learned from, and usage over the last 30 days. Its layout is set in Settings: cards moved, widened and hidden, SQL tables and tiles of your own, packed tightly or not. |
| **Patterns** | Before Analyze, for data the pipeline cannot read yet (a new log type, or a drifted one): how much of it Phase 1 knows, pass by pass and over time; the unknown lines grouped into shapes; a canvas that slices lines into prefix, message and suffix (select text, send it to a tray); regex suggestions from the examples, tried live with their named groups; rules saved per log type and exported for Phase 1. Simple mode stops at Upload when the pipeline knows under 5% of the lines and offers *Find patterns*. Logs that come as a table (a CSV or Excel export: one column the raw line, the others fields): Patterns checks the first 100 rows, asks for the Raw logs column (a dropdown of the headers) and the columns to keep (checkboxes), then scans; the kept fields date the lines and split the coverage per value. Analyze and Simple mode read the raw-log column by themselves. |
| **Analyze** | Paste lines, upload a file or point at a file on the laptop. Auth and OSSEC lines go through the pipeline's own Phases 1–4 and are placed on the cluster map; the verdict says whether they would be flagged and how unusual they are. PF and IPFilter use the presence rule. The map (drawn on request) shows the new lines as rings among the year's observations. |
| **Sigma** | Detection rules in the Sigma format for known attack patterns (eight starter rules: SSH guessing, spraying, enumeration, success after guessing, `su` failures, a stopped OSSEC agent, port scans, sweeps): written in a form, from a plain-English description (local model, proof of concept) or as YAML, each checked live and tested before it is accepted; import, export; run on pasted lines, a file or a folder. The enabled rules also flag observations for Review and lead the Dashboard ([guide](docs/user/05_sigma.md)). |
| **Models** | One card per view: whether it raises alerts, test-period alerts per detector, the model zoo. *Retrain* goes to Datasets (an administrator signed in with SSO). |
| **Data** | Training/validation/test timeline; Sankeys of messages by type and traffic by address; clusters: the groups, their make-up, typical lines, every member and comments, and an interactive map drawn on request (zoom, pinch, pan, axes, groups on and off, click a point to open it, pick a group to see it in yellow); read-only SQL with highlighting. |
| **Explain** | Why each activity alert (auth, OSSEC) was raised, in pictures: what was seen against its usual range for that time and kind of day (weekends and public holidays apart), the reasons as range plots, its day against the usual band, its week as a heatmap beside a usual week, and eight weeks of daily totals; each chart also as a table; *Reword* in plainer words by the local model, kept only if every number matches. |
| **Profiles** | Every server, source IP, username and destination IP, alerted or not, against its own normal on any day (Phase 4h, every log type): the entities furthest from their normal first, each with eight weeks of daily totals; an entity's whole timeline, its day and week against the same weekday's training days, who it shared lines with and its alerts; *Watch* puts it on the Dashboard. PF and IPFilter: counts only (normal is no activity). |
| **Review** | Flagged groups and activity alerts (auth, OSSEC) or firewall activity (PF, IPFilter), each an investigation: the flagged observations ranked by anomaly score (a percentile of the validation period), each with its lines and detector scores, and the logs from the same server before and after it (you set the minutes; one read-only SQL query, which can be opened in Data → SQL). Each item needs review until someone records a label, then it is reviewed: security relevant, suspicious, operationally interesting, expected behaviour or insufficient evidence. The two are kept apart. |
| **Reports** | Anomaly reports from a set of findings, in both modes (release 0.2.0), laid out like a printed incident report in Times New Roman: details, eleven Roman-numbered sections with subsections, footnotes. Blocks: *Log lines* (select all, before/after), *Table* (ask the local model, SQL, or by hand; highlights and comments), *Metric* tiles, *ATT&CK* (search or the local model's suggestion), *Target*, saved versions, target maps, timelines, non-binding signatures and Word/PDF/HTML exports; *Report* on a reviewed item starts one with its notes; scores carry a note on how they are computed. |
| **Datasets** | Add a dataset, import its archives and train models. Anyone can view; changes need an administrator signed in with SSO ([guide](docs/user/03_sso_and_datasets.md)). |
| **Documentation** | The pipeline as an MRT line map (phases are stations, sub-phases on branch lines; click one), and the guides, disclaimers, requirements and the pipeline's own notes as bus stops with "next bus" boards (reading time as the arrival). |
| **Settings** | Language, light/dark, font, animations (all, skip ending, or none) and the animation pack (Transit: MRT train and SG Bus; Desk: cymbal monkey and filing cabinets; Commuter: first person, playing on your phone while the train or bus comes, with previews), the local model (same as the picker at the top right), your name, whitelisted users (an override on the anomalies: accounts you vouch for stop asking for review, still scored; adding or removing one needs the admin password), the activity log (clearable with the admin password), the SQL password (1234 until changed) and the Dashboard editor. |

Models, Data and Review share one **Log type** dropdown in the page header
(AUTH first). A choice made on one page carries over to the others. The Data
page also offers *All log types* for the timeline and the Sankeys.

**Cluster maps** (Data → Clusters and the Analyze result):

- **Drawn on request.** A map can hold up to 60,000 points, so the page loads
  first. A card says how many points the map has and offers *Draw the map*.
  Once drawn, that view's map is drawn straight away for the rest of the
  session.
- **Points.** Clicking a point opens it: its period (training, validation or
  test), time, group, model-zoo votes and original lines.
- **Groups.** Picking a group in the list beside the map shows it in yellow
  and greys out the rest. The map does not move; *Zoom the map to it* in the
  group's details does that.
- **Fullscreen.** The corner button or the F key fills the screen with the
  map, its legend, and the clicked point's details as a panel. Esc or F leaves
  fullscreen.
- **Layout.** *t-SNE* or *UMAP* under the map: the same points laid out
  another way, with the same groups and flags. Phase 4c writes the UMAP
  layout; for existing maps run
  `python pipeline/phase4_detection/map_layouts.py --source <auth|ossec>` from the project root.
- **Shapes mean nothing.** Only who is near whom does. The striped spindles on
  the OSSEC maps are one message from one server laid out by the clock: one
  strand per weekday, from 00h at one tip to 23h at the other. t-SNE draws the
  pinched tips. See *Reading the map* in the project README.

## Running

```
cd triage-console
..\.venv\Scripts\python.exe -m pip install -r requirements.txt   # once: the service's extra packages (SSO)
cd web
npm install          # once
npm run build        # after changing the web app
cd ..
..\.venv\Scripts\python.exe -m service
```

Open <http://127.0.0.1:8765>. For live editing, also run `npm run dev` in
`web/` and open <http://localhost:5173>.

On first start the service builds these caches in the background, all reused
afterwards:

- message variants per event type (about 5 minutes, mostly authlog);
- the cluster member index (`var/cache/cluster_index.sqlite`). It is built from
  `row_clusters.csv` through the Phase 3 test lineage to the event stores, and
  the large auth views take longest;
- the original lines of the maps' training and validation points, in the same
  index. These are read once from the Phase 3 train and validation lineage,
  about 2.4 GB per auth view;
- the scores of every flagged observation, for Review, in the same index (read
  once from Phase 4's `test_scores.csv`, up to 1.2 GB per view);
- traffic by address for the second Sankey.

The pages say when a cache is still being built.

The admin password (archiving the activity log, clearing an upload, changing the whitelisted users) and the SQL
password are defaults (`123456`, `1234`) that open nothing until changed: the SQL dialog asks for a new one at the
first query, and Settings → Activity log sets the admin one.

To start the console at sign-in without a window (output in `var/service.log`):
`powershell -ExecutionPolicy Bypass -File autostart.ps1` (`-Remove` to stop that).

Back up the console's own data: `..\.venv\Scripts\python.exe -m service.backup create --to <folder>`; check one with
`verify <zip>`, put one back with `restore <zip>` (service stopped), or try the whole round trip on a scratch folder
with `rehearse`. A backup holds log lines: keep it where the logs may be kept.

SSO is off until an administrator copies `auth.example.json` to `var/auth.json`,
fills it in and checks it with `..\.venv\Scripts\python.exe -m service.sso_check`
(see [03 SSO and datasets](docs/user/03_sso_and_datasets.md)).

## Tests

```
cd triage-console
..\.venv\Scripts\python.exe -m unittest discover tests -v
```

Every check at once, from the project root (the pre-push hook runs it): `python scripts/check.py` (the console's
tests, the pipeline's tests and the web build with its type check).

Recall on planted attacks, on a held-out day of real AUTH lines (counts only):
`..\.venv\Scripts\python.exe -m service.inject_eval <day.log> --month YYYY-MM`.

The tests cover:

- the SQL console guardrails (`tests/test_sql_guard.py`): writes refused by the
  text check and by the engine;
- the SSO sign-in flow against a fake provider with its own signing key, and
  the dataset rules (`tests/test_auth_datasets.py`). Refused: a wrong nonce,
  audience or issuer; an expired or future-dated token; another app's token; a
  forged signature; an unsigned token. Followed: the provider rotating its key.
  Also: the account picker, signing out at the provider, the missing-secret
  hint and the settings check.
- the review labels and their note rules, and Review's logs-before-and-after
  query (`tests/test_review.py`): the window bounds, refused server names and
  windows, the query passing the SQL guard, and a run on small stores shaped
  like the real ones (plus one on the real auth store when it is present);
- the animation settings (`tests/test_settings.py`): the packs and refused values;
- Patterns (`tests/test_patterns.py`): masking and merging shapes, refused patterns (nested repeats,
  bad syntax), the regex suggestions (named groups, an event name, anchors for messages of different
  lengths, suffixes without their space), the loop from unknown to known (prefix, rule, estimate, the
  next pass, censored examples, the Phase 1 export), drift (new shapes, quiet rules, by date), Phase 1
  first for the four log types, ordering and switching rules off, the Simple-mode detector, and reading
  folders, ZIPs and .gz files;
- Sigma (`tests/test_sigma.py`): the modifiers, wildcards, keywords and field aliases; conditions (`not`,
  brackets, `1 of`, `all of`); refused rules and what they say; sliding windows (a burst across a 5-minute
  boundary is one hit, grouped by source), distinct values over a day, a sequence chaining a correlation then
  a rule, the older `count() by` syntax, `generate`, log sources; the starter rules seeded once; adding,
  editing and deleting (audited); a run over Solaris lines with whitelisted accounts marked; a draft tested in
  place of its saved version; a folder (the files of its lowest folders: plain, .gz and ZIP members, each told its
  log type and its month by its folders, one log type and month checked together, so a spraying correlation fires
  across three servers' files that one file alone does not; the files left out, with why); the API routes;
- logs as tables (`tests/test_tabular.py`): recognising a table and its raw-line, time and host
  columns, plain logs left alone, rows spanning lines and repeated headers, the 100-row check (a short row,
  a .csv without a header, an unclear raw column), scanning with the columns chosen, Excel workbooks (dates,
  rich text, empty rows, an old .xls refused), Analyze and the detector reading the raw column, Patterns
  counting fields per value and filtering by one, and a folder of tables and plain files;
- Simple mode's uploads (`tests/test_uploads.py`): only unusual events of alert views, the
  lines kept around each, overlapping views merged into one event, sending to a reviewer
  (*Waiting for you*), and clearing with the password;
- the validation period in Review (`tests/test_validation_groups.py`): flagged observations grouped by
  server and address with their counts and the view's rate, the accounts, flags from the zoo alone,
  and group IDs that survive a rebuild;
- traffic by address (`tests/test_ip_flows.py`): grouping at the four levels, and the query for a box
  or band passing the SQL guard and selecting exactly its lines (10.2.x.x never takes 10.20.x.x;
  *other addresses*; months);
- the report editor's helpers (`tests/test_report_ai.py`): the offline ATT&CK copy, the
  shortlist reaching the right techniques from log lines, only shortlisted techniques kept from
  the model, a writing query flagged and not run, and a clear error when the model is not running;
- the map layouts (`tests/test_map_layouts.py`): a UMAP layout counts only
  when built from the current map, keeps the same points, and is matched by
  observation when its order differs;
- the Dashboard (`tests/test_dashboard.py`): *Next to review* (Sigma matches first, then each log type in turn), a
  waiting item keeping only what the page shows, and the SQL tables' refresh (needs the SQL password, runs
  through the guardrails, keeps the result); its outlier counts (`tests/test_outliers.py`);
- the SQL password (`tests/test_sql_lock.py`): unlocking, refused guesses and missing tokens, tokens lapsing,
  a change locking everyone out, every SQL route refusing without a token, the admin password unchanged;
- security (`tests/test_security.py`, `tests/test_server_access.py`): other hosts (DNS rebinding), origins and
  sites refused; the page's headers (it cannot be framed or run others' scripts); JSON-only changes and no
  cross-origin preflight; an `/api/` address typed in, with or without the header; only the app's files served;
  a crafted workbook (a part too large unpacked, a cell past the last column); a regex that cannot become Phase 1
  code; very long lines cut; the model's address; parallel password guesses waiting one at a time;
- reports (`tests/test_reports.py`, `tests/test_report_maps.py`): saving, versions, conflicts, numbering,
  closed cases, finding links, Word export, HTML export (inert, text escaped, the saved paper), refused images
  and formats; the target map's saved feature rows;
- Sigma as a detector (`tests/test_sigma_review.py`): hits flag their lines' observations, a correlation across
  chunks found whole, the index marking members, and Review listing a group by its rules whatever its lift;
- Review's filters (`tests/test_review_filters.py`), the sequence detector on new lines
  (`tests/test_sequences.py`) and the event log's device-types document (`tests/test_event_log_docs.py`);
- activity alerts (Phase 4g) on made-up logs: the detectors (`tests/test_activity.py`), the outcome, relations,
  context and regularity features and Phase 3 without names as features (`tests/test_activity_features.py`), the
  explanations (`tests/test_activity_explain.py`: quiet days as zeros, holidays as non-working days), incidents
  (`tests/test_activity_incidents.py`: one event or one routine, two routines never merged, clock times), Review's
  items, labels, whitelist and filters (`tests/test_activity_review.py`), Explain and its rewording
  (`tests/test_explain.py`), and Phase 4h with Profiles and the watch list (`tests/test_profiles.py`);
- Sigma's form and drafts from plain English (`tests/test_sigma_form.py`): the form as YAML and back, the
  starter rules through the form, a stand-in model's drafts, and who added a rule and whether it was tested;
- whitelisted users (`tests/test_whitelist.py`): the password, refused accounts, servers, reasons and
  past dates, duplicates, removal kept on record, an entry ending after its last day; an event covered
  only when every account it names is listed (server scope, case, events naming no account); a time
  window judged by the accounts of its lines; a group whitelisted only when all its flagged events are,
  nothing overridden without the facts table; upload events needing no review.

## Planned (TODO)

These show in the app as cards marked TODO:

| Where | What |
|---|---|
| Data → SQL | **Ask in plain language:** the local model turns a question into a query and puts it in the editor for you to check; it runs only when you press Run. Needs a service endpoint that prompts the model with the table schema and examples. The read-only guardrails (`service/sql_guard.py`) stay the safeguard. |
| Data → Clusters | **AI summary** of a group's comments: what people agree on, where they differ, what is still open. |

The earlier plan (alert queue, four triage categories, exports for Phase 8,
site-context editing, model workflows) is listed with its status in
[01 Product requirements](docs/01_product_requirements.md#7-from-the-earlier-plan).

## Documents

| Document | What it covers |
|---|---|
| [docs/01_product_requirements.md](docs/01_product_requirements.md) | Purpose, users, user stories, what is built and what is planned |
| [docs/02_functional_requirements.md](docs/02_functional_requirements.md) | `FR-…` requirements per page, with status |
| [docs/03_nonfunctional_requirements.md](docs/03_nonfunctional_requirements.md) | `NFR-…` requirements (security, data, performance, usability), with status |
| [docs/04_open_questions.md](docs/04_open_questions.md) | Decisions Q1–Q38 |
| [docs/05_architecture.md](docs/05_architecture.md) | How the console is built |
| [docs/06_reports_review_release.md](docs/06_reports_review_release.md) | Reports and Review: the implementation record |
| [docs/user/](docs/user/) | In-app guide, disclaimers, SSO and datasets, reports and Review, Sigma |

## Folder layout

```
triage-console/
  README.md
  auth.example.json  SSO settings template (copy to var/auth.json)
  requirements.txt   the service's extra packages, pinned (Authlib, joserfc, requests, regex)
  docs/              requirements, decisions, architecture; docs/user is the in-app guide
  web/               browser app (TypeScript, Vite)
    src/main.ts        shell: sidebar, pages, model picker
    src/tabs/          one module per page (dashboard, patterns, analyze, sigma, models, data, clusters, sankey, review, reports, simple, datasets, docs, settings); dashboard-editor.ts is the Dashboard editor in Settings; docs.ts draws the MRT line map and the bus stops
    src/cluster-map.ts interactive map (t-SNE or UMAP layout), drawn on request (d3-zoom, d3-axis, d3-scale, d3-quadtree)
    src/log-type.ts    the shared Log type dropdown
    src/verdicts.ts    the five review labels: names, colours, which need a note
    src/sql-editor.ts  CodeMirror editor and the client-side read-only warning
    src/route-board.ts, train-loader.ts, splash.ts   progress displays and start-up screen
    src/train-loop.ts  the start-up train lapping its track, also shown centred while any panel is loading
    src/icons.ts       Phosphor icons, bundled at build time
    src/dashboard-layout.ts   the Dashboard's cards and the saved layout (widths, hidden cards, SQL tables, tiles, packing); tabs/dashboard-editor.ts edits it in Settings
    src/sql-lock.ts    every SQL request: asks for the SQL password once and carries the token
    src/tables.ts      tables, CSV export (formula cells kept as text), reading log files
    src/loaders.ts     picks the waiting animation by pack; desk-loaders.ts draws the Desk pack (cymbal monkey, filing cabinets)
    src/doc-reader.ts  the reading view of every document: header, On this page, tables, code, previous and next
    src/doc-visuals.ts persona cards and the epic board on the Product requirements document; words.ts plain words for Review
    src/bus-scenery.ts the Review loader's road, SG Bus double-decker and bus stop, day or night with the theme
    src/scenery.ts     the SQL loader's scrolling town (HDB estates, school, tunnel) and the station it arrives at, day or night with the theme
    public/brand/      logo and train artwork
    scripts/brand_assets.py  regenerates the train SVGs
  service/           local Python service (standard library HTTP server, the pipeline's code, Authlib for SSO)
    server.py          HTTP API and static files, localhost only
    config.py          paths and user settings (var/settings.json)
    auth.py            SSO for admin actions: OpenID Connect through Authlib, ID tokens checked with joserfc
    sso_check.py       checks var/auth.json against the provider, without signing in
    datasets.py        dataset registry, archive import, training runs
    analyze.py         Analyze page; scoring.py runs Phases 1-4 and the map on new lines
    sequences.py       Phase 4f's sequence detector (frequent subsequences) on new lines, with the pipeline's own code
    patterns.py        Patterns page: passes, shapes, regex suggestions and tries, rules per log type, the detector
    sigma.py           Sigma page: rules and correlations (sliding windows) over Phase 1's fields; sigma_rules/ the starter rules
    sigma_review.py    the enabled Sigma rules over the year's validation and test periods: hits flag observations for Review
    tabular.py         logs that come as a table (CSV or .xlsx): the 100-row check, the raw-log column, time and host columns, the rows
    pipeline_code.py   loads the pipeline's own modules by path
    jobs.py            background jobs with step progress
    catalog.py         sources, views, models, time splits
    clusters.py        cluster list, messages, review queue; cluster_index.py builds the member index
    review_context.py  Review's investigation: ranked observations, scores, logs before and after
    event_counts.py    Sankey counts; variants.py message variants; ip_flows.py traffic by address
    sql.py, sql_guard.py  read-only SQL over the event stores, and its guardrails; sql_lock.py the SQL password and its tokens
    store.py           names, comments, reviews, activity log, usage counts, the Dashboard SQL tables' results, the admin and SQL passwords
    whitelist.py       whitelisted users: entries, and which flagged observations they cover
    activity.py        Phase 4g's activity alerts as Review items, one per incident, with their lines, filters and whitelist
    explain.py         Explain: the alerts' explanations (Phase 4g), and the local model's rewording kept only if every number survives
    profiles.py        Profiles: Phase 4h's profiles.sqlite, any entity on any day against its normal, and the watch list
    llm.py             models offered by the local Ollama, and one answer from it (chat)
    report_ai.py       reports: ATT&CK (attack_enterprise.json), the model's table queries and technique picks
    reports.py         reports: versions, case numbers, Word, PDF and HTML export; report_maps.py the target maps
    review_filters.py  Review's exact filters; uploads.py Simple mode's uploads; outliers.py the Dashboard's flagged shares
    event_log_docs.py  the event log's device types, built from the pipeline's code
  tests/             unittest suites for the service
  var/               settings, store, caches, training logs (not in version control)
```

## Release 0.2.0: Reports and Review

Later work (Sigma, the Dashboard, the SQL password, activity alerts, Explain and Profiles) is unreleased and
recorded in the [version register](../VERSIONS.md). See the [user guide](docs/user/04_reports_and_review.md), [technical release record](docs/06_reports_review_release.md), and [version register](../VERSIONS.md). Reports use automatic case numbers and append-only saved versions; closed cases stay editable. Review adds exact multi-value filters and duplicate-submit protection. Full-report AI writing remains deferred.

PDF export requires the pinned Playwright package and installed Microsoft Edge; Word uses python-docx and lxml (all Python packages in triage-console/requirements.txt). Rebuild the web bundle and restart the service after updating. No pipeline rerun is required.

Additional checks from this directory: `..\.venv\Scripts\python.exe -m unittest discover tests -q` and `..\.venv\Scripts\python.exe tests\browser_reports_review.py`. The latter uses headless Edge, an isolated console store and existing dataset caches; its screenshots/downloads go to `var/checks/reports-review/`. It does not alter user reviews, uploads or reports. `..\.venv\Scripts\python.exe tests\browser_sigma.py` does the same for Advanced → Sigma (screenshots in `var/checks/sigma/`); it seeds the starter rules into its own temporary store.
