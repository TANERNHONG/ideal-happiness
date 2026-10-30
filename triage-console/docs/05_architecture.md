# Project DAD Console: architecture

| | |
|---|---|
| Document | 05 · Architecture |
| Status | Describes the console as built |
| Version | 0.13 (2026-10-30): `audit.py`, `feature_ablation.py`; `drift.py`'s validation null; `scoring.py` reads the zoo's calibrating half and its families (`families.json`). 0.12 (2026-10-30): `retention.py`, `backup.py`, `yields.py`, `drift.py`, `coverage.py` with `attack_ics.json`, `inject_eval.py`; the activity log archived (`var/audit_archive/`); the OSSEC history cache as `.npz`; `web/src/playbooks.ts`. 0.11 (2026-10-30): `activity.py`, `explain.py`, `profiles.py`; the Phase 4g and 4h outputs read. 0.10 (2026-10-26): `doc-reader.ts`, the reading view. 0.9 (2026-10-26): the Review filters' time limit. 0.8 (2026-10-26): Sigma's form and drafts from plain English (`sigma_form.py`, `sigma_ai.py`, `sigma-form.ts`). 0.7 (2026-10-26): the grouped menu; `train-loop.ts`, `dashboard-layout.ts`, `tabs/dashboard-editor.ts`, `sql-lock.ts`, `tables.ts`; `sigma.py`, `sigma_review.py`, `sql_lock.py`, `patterns.py`, `tabular.py`, `uploads.py`, `outliers.py`, `sequences.py`, `event_log_docs.py`; the page's headers and the risks they answer. 0.6 (2026-10-12): `whitelist.py`. 0.5 (2026-10-05): documentation review: the Documentation page and its links, inputs, tests, risks. 0.4: review investigation (`review_context.py`, the scores pass, `verdicts.ts`). 0.3: rewritten for the built application; JEV parts removed (Q12) |
| Related | [01 Product requirements](01_product_requirements.md) · [02 Functional](02_functional_requirements.md) · [03 Non-functional](03_nonfunctional_requirements.md) · [04 Decisions](04_open_questions.md) |

## 1. Shape

Everything runs on the pipeline laptop. The only connection that leaves it is
SSO sign-in, and only once an administrator has set SSO up (Q17).

```
┌──────────────────────── Browser (Edge / Chrome) on the laptop ─────────────────────────┐
│  Project DAD Console · TypeScript + Vite                                               │
│  Overview · Prepare · Detect · Investigate · Report · Console: Dashboard, Datasets,    │
│  Patterns, Models, Analyze, Sigma, Review, Data, Reports, Documentation, Settings      │
└───────────────▲────────────────────────────────────────────────────────────────────────┘
                │ HTTP on 127.0.0.1:8765 (JSON API under /api, the built app, /auth/*)
┌───────────────┴──────────────── Local service · Python ─────────────────────────────────┐
│  server.py: routes, Origin/Host checks, JSON-only writes, SSO session per request       │
│  reads pipeline outputs        runs new lines through the     own store (SQLite):       │
│  (catalog, clusters,           pipeline's code (analyze,      names, comments, reviews, │
│  event counts, SQL)            scoring, pipeline_code)        activity log, usage       │
│  datasets: import archives, start run_pipeline.py (admin, SSO)                          │
└──────┬──────────────────────┬────────────────────────┬──────────────────────┬───────────┘
       │ localhost             │ files (read only)      │ subprocess           │ HTTPS, sign-in only
┌──────┴──────┐  ┌─────────────┴──────────────┐  ┌──────┴────────────┐  ┌───────┴────────────┐
│ Ollama      │  │ data/ (Phases 0-7b outputs) │  │ run_pipeline.py   │  │ Identity provider  │
│ qwen2.5:3b- │  │ pipeline/ (code, imported)  │  │ (training runs)   │  │ (OpenID Connect)   │
│ instruct    │  └─────────────────────────────┘  └───────────────────┘  └────────────────────┘
└─────────────┘
```

## 2. Browser application (`triage-console/web/`)

- TypeScript, no framework. Pages are plain functions that build DOM nodes
  through a small helper (`dom.ts`). Text always goes in as text nodes, never
  as HTML, so log lines and comments cannot inject markup. Markdown documents
  are rendered with `marked` and cleaned with `DOMPurify`. Their links are
  then rewired (`tabs/docs.ts`): headings get GitHub-style ids, a link to a
  document the console shows opens it in place, and a link to any other
  project file becomes plain text naming its path.
- **Shell** (`main.ts`): sidebar, its groups in the order of an investigation
  (`GROUPS`: Overview, Prepare, Detect, Investigate, Report, Console), each with
  its icon; collapsed, the sidebar shows one icon per group and its pages in a
  flyout. Hash routing (`#/data/sql` opens a part
  directly), the model picker docked in every page header, and a page-view
  count sent to the service.
- **Pages** (`tabs/`): one module each. Data is split into `data.ts` (timeline
  and SQL), `sankey.ts` and `clusters.ts`. `docs.ts` draws the pipeline as an
  MRT line map (HTML and CSS, keyboard operable) and the documents as bus
  stops.
- **Shared parts:**

  | File | What it is |
  |---|---|
  | `log-type.ts` | The Log type dropdown in the page headers of Models, Data and Review. It holds one choice for the whole app (Q19). |
  | `verdicts.ts` | The five review labels (Q23): names, colours, hints, which need a note, and the label badge used by Review, Data → Clusters and the Dashboard. |
  | `cluster-map.ts` | The interactive map used by Data → Clusters and the Analyze result, drawn only on request (`mapOnDemand`, which first shows the point count from `/api/map/info`). Built with d3-zoom (wheel, pinch, drag), d3-scale and d3-axis (t-SNE axes that rescale with the zoom) and d3-quadtree (finding the point under the pointer). Points are drawn on a canvas with one pixel per screen pixel, as exact circles when up to 8,000 are in view. A picked group is yellow and the rest grey; a clicked point opens its details (`/api/map/point`). Fullscreen uses the browser's Fullscreen API on the map element, so the header, the point panel and the tooltip live inside it. A *Layout* switch swaps in the same points' UMAP positions (`/api/map?layout=umap`) and keeps everything else; the choice is remembered in the browser (Q24). |
  | `sql-editor.ts` | CodeMirror 6 with SQL highlighting, loaded only when the SQL part opens. Includes an early warning for queries that are not read-only; the service makes the actual decision. |
  | `route-board.ts`, `train-loader.ts`, `splash.ts`, `tooltip.ts` | Progress displays, the start-up screen and tooltips. |
  | `train-loop.ts` | The start-up screen's train, a four-car train seen from above lapping a circle of track. `splash.ts` puts the logo inside it; while any panel waits for its data (`loading()` in `dom.ts`), one such train is shown centred on the content pane with that panel's caption, and the panel holds an empty placeholder until its content arrives. It stands still under Settings → Animations → None or the system's reduced-motion request. |
  | `icons.ts` | Phosphor icons (regular weight), read from `@phosphor-icons/core` as text at build time, so only the icons named there are bundled. |
  | `dashboard-layout.ts`, `tabs/dashboard-editor.ts` | The Dashboard's cards (`CARDS`) and the saved layout (`dashboard_layout`: cards with their widths, the hidden ones, SQL tables, tiles and packing), normalised against the cards that exist. The editor in Settings draws the Dashboard itself with handles for order, width and height, the *Hidden* tray, and the tile and SQL-table dialogs; a draft until *Save*. Packing is a CSS grid of 8-pixel rows with `grid-auto-flow: dense`, each card spanning the rows its height needs, kept current by a `ResizeObserver`. |
  | `sigma-form.ts` | Advanced → Sigma's rule form (FR-SIG-06): the required fields marked and shaded while empty (the service says which), Match and Except rows of chips, the count, the level and More; the readable card of a rule (Describe's preview); the stamp of who added a rule and when. `tabs/sigma.ts` holds the three ways to write a rule and *Draft → Test → Accept*. |
  | `sql-lock.ts` | `sqlApi`, used by every SQL request: asks for the SQL password once in a dialog, keeps the token in memory and sends it with each request; when the service answers `sql_locked`, it asks again. |
  | `tables.ts` | Tables with a table view of charts, CSV export (`csvText`: a cell a spreadsheet would run as a formula is written as text), and reading log files with their size limits. |
  | `doc-visuals.ts` | Visuals added to a rendered document from its own Markdown (FR-DOC-04): persona cards with flat, faceted SVG avatars and an epic board for 01 Product requirements. |
  | `doc-reader.ts` | The reading view every document gets after its visuals (FR-DOC-07): the header (group, reading time, sections, series and title; a requirements document's version history folded), tables wrapped to scroll with IDs, numbers and statuses marked, code with a Copy button, the *On this page* list (an `IntersectionObserver` marks the section being read) and the previous and next documents. |
  | `words.ts` | Plain words for operations staff (US-34): readable event names, unit nouns, "1 in N" rarity, date spans, top servers and accounts. |
  | `loaders.ts`, `desk-loaders.ts` | The waiting animations by Settings → Animation pack (Q25): `sqlLoader` and `reviewLoader` give the transit pack's train or bus, or the desk pack's cymbal monkey or filing cabinets. The desk drawings are inline SVG moved on animation frames (the monkey's arms turn about the shoulders and the cymbals turn edge on as they meet; the magnifying glass and the files follow eased paths), so they check *Animations* and reduced motion themselves and show a still picture when motion is off. All loaders share `loaderShell` (caption and timer) and its ending, `arrive({ found })`. |
  | `bus-scenery.ts` | Review's loader (`busLoader` in `train-loader.ts`): the same town (`town()` from `scenery.ts`) with a road in front: far pavement with rain trees and street lamps, a covered linkway, double yellow lines and lane dashes, and, a few seconds into a long wait, an overhead pedestrian bridge drawn side on, as Singapore's are built: a concrete deck on square piers with a planter of shrubs and the height-limit sign, a white tube roof on slim posts (lit underneath at night), a lift tower at one end and a covered staircase at the other; its deck is above the bus's roof, so the bus passes under it. One already in view when the logs arrive stays whole and scrolls past; one still to come is held back, so a quick query goes straight to the stop. An SG Bus double-decker drawn inline (so it is centred from the first frame), its wheels turning at its speed, and the bus stop it pulls into: shelter, benches, a book corner, the blue pole sign, chevron bollards. The bus shows its offside, so no doors. The arrival is the train's (`arrive()`), stopping the bus's front just short of the pole. |
  | `scenery.ts` | The SQL loader's background. The train stands still while layers scroll past at different speeds: far blocks, HDB estates with a school, car park, hawker centre and condo, and the viaduct, with its railing, sound barriers through the estates, and a tunnel. The tunnel is drawn as a cutaway: lining rings, lamps, cable trays, EXIT signs, the fire main, the walkway and the track bed. It is seeded, so it always looks the same, and it is drawn once and cloned. Colours are theme tokens: day in light mode, night in dark mode. When a query succeeds, `train-loader.ts` brings the train into a station: every scrolling layer is moved by the same time step, so the depth holds. The train keeps its cruising speed and then brakes; it never speeds up. That step is skipped under Settings → Animations (stored as `data-motion` on the page) or the system's reduced-motion request. |
  | `i18n.ts` | Menus and headings in English, Malay, Chinese, Tamil, Japanese and Korean. |

- **Libraries.** Pinned in `package.json`: d3-sankey, d3-zoom, d3-selection,
  d3-scale, d3-axis, d3-quadtree, CodeMirror, marked, DOMPurify, Phosphor icons
  (`@phosphor-icons/core`), and Inter, Roboto, Space Grotesk (titles and figures) and JetBrains Mono (labels, log
  lines, codes), all bundled locally (OFL-1.1). The built app loads nothing from the internet.

## 3. Local service (`triage-console/service/`)

The HTTP server is Python's standard library (`ThreadingHTTPServer`). It runs
in the project's virtual environment, so it can import the pipeline's own code
and its libraries (pandas, NumPy, scikit-learn). Its own extra packages are
Authlib, joserfc and requests, for SSO, pinned in `requirements.txt`.

| Module | Responsibility |
|---|---|
| `server.py` | Routes. Refuses requests whose `Host` is not localhost or whose `Origin` is not the app. Answers `/api/` only with the `X-Console-Request` header the app's scripts add (`web/src/api.ts`), never to an address typed into the browser (NFR-SEC-17). Accepts POST and PUT only as JSON, which a web form cannot send. Binds the SSO session for each request. Serves the built app's own files by name, nothing else. Sends the page's content security policy and the other security headers (NFR-SEC-18). |
| `config.py` | Paths and settings (`var/settings.json`). The language-model endpoint must be an `http(s)` address on localhost. Checks `dashboard_layout` (known cards, widths, heights, tile fields and icons, SQL tables, `packed`) and `review_filter_seconds` (10 to 3,600) before saving them. |
| `catalog.py` | Sources, views, model status and time splits, read from the Phase 4 summaries. |
| `analyze.py`, `scoring.py`, `pipeline_code.py`, `jobs.py` | The Analyze page. New lines are classified with the Phase 1 rules and grouped by the Phase 2 builders (on a temporary folder). They are turned into features with the saved Phase 3 bundles and scored by the saved Phase 4 detectors and model zoo. Finally they are placed on the Phase 4c map by nearest neighbours. This runs as a background job with step progress. |
| `clusters.py`, `cluster_index.py` | Phase 7b clusters, their typical lines, and the review queue. A background index (`var/cache/cluster_index.sqlite`) links each cluster to its members and their original lines. A second pass reads the Phase 3 train and validation lineage once and links the maps' earlier points too, so any point on a map can show its lines. A third pass keeps the scores of every flagged observation (Phase 4 `test_scores.csv`, read once; model-zoo votes from `row_clusters.csv`) for Review. |
| `review_context.py` | Review's investigation: a group's flagged observations ranked by anomaly score (percentiles of the validation period, from `scoring.py`), one observation with its lines, and the logs from the same server before and after it. That last part builds one `UNION ALL` query over `auth.events`, `ossec.events`, `fw.pf_events` and `fw.ipf_events` and runs it through `sql.run`, so the SQL guardrails apply. The server name must match `[A-Za-z0-9._-]{1,64}` and the window 0 to 1,440 minutes before anything reaches the query; each store is filtered on its own indexed time column. |
| `event_counts.py`, `variants.py`, `ip_flows.py` | Counts for the Dashboard and the Sankeys, cached in `var/cache/`. |
| `report_ai.py`, `attack_enterprise.json`, `attack_build.py` | The report editor's helpers. MITRE ATT&CK Enterprise is kept on the laptop (`attack_enterprise.json`: techniques, tactics, MITRE's notice), built once from the STIX bundle by `attack_build.py`. `candidates()` shortlists the techniques closest in wording to the evidence (TF-IDF, with log words mapped to ATT&CK's terms); `match_attack()` lets the local model pick from that shortlist only; `sql_for()` has it write one query for a question, which is checked by `sql_guard` but not run (the analyst runs it through `/api/sql`). The model is called through `llm.chat` (Ollama on localhost); if it does not answer, the request fails with a message saying so. |
| `sql.py`, `sql_guard.py` | Read-only SQL over the event stores (§5). |
| `sql_lock.py` | The SQL password: unlock tokens that every SQL request carries (FR-SQL-07). |
| `sigma.py`, `sigma_rules/` | Advanced → Sigma (FR-SIG): the rules (table `sigma_rules` in the console store, seeded once from `sigma_rules/*.yml`), read with a safe YAML loader; rules and correlations over sliding windows on Phase 1's fields; runs on Analyze's inputs or a folder, by log type and month. Regular expressions run with a time limit. |
| `sigma_form.py` | Sigma's form (FR-SIG-06) as YAML and back: the form's fields to one rule, or with a count to an event rule and its correlation; a rule read back into the form when it has that shape (None otherwise), with what the form does not show kept. The event types offered come from the event counts. |
| `sigma_ai.py` | A Sigma rule drafted from plain English by the local model (FR-SIG-07, proof of concept): the prompt carries the log types' fields and event types and three starter rules; the answer is read with `yaml.safe_load` only, checked by the engine, sent back once with its error, and never saved. |
| `sigma_review.py` | Sigma as a fifth detector: the enabled rules over the year's validation and test periods, read from Phase 2's stores in two-day chunks with each rule's window before them; hits map to observations through Phase 3's lineage and are kept in the cluster index (`sigma_flags`, `sigma_views`), which `clusters.review_queue` reads. Run in the index's background pass, again when the rules change. |
| `patterns.py`, `tabular.py` | Patterns (FR-PAT) and logs that come as a table (FR-TAB): passes, shapes, regex suggestions, rules per log type and their Phase 1 export; tables and workbooks with their limits (NFR-SEC-19). |
| `uploads.py` | Simple mode's uploads kept for review (FR-SMP-06–09). |
| `outliers.py`, `sequences.py` | The Dashboard's flagged shares and detector overlaps; Phase 4f's sequence detector on new lines. |
| `activity.py` | Phase 4g's activity alerts as Review items (FR-REV-16): one per incident from `incidents.csv` (the lead alert with the incident's title and members), each alert's facts and lines, Review's filters and the whitelist (a username alert is covered when its account is listed on every server). |
| `explain.py` | Explain (FR-EXP): the pipeline's explanations (`explanations.jsonl`) listed by incident and served with the alert's lines; the local model's rewording, refused unless every number in it is in the facts, kept in `var/cache/explain_reword.json`. |
| `profiles.py` | Profiles (FR-PRO): Phase 4h's `profiles.sqlite`, read only with a connection per call; the pictures from the pipeline's own `activity_explain.profile`, so a profile and an Explain record agree; the watch list (`store.watchlist`) for the Dashboard. |
| `event_log_docs.py` | The event log's device-types document, built from the pipeline's code (FR-DOC-05). |
| `store.py` | The console's SQLite store (`var/console.sqlite3`): cluster names, comments, reviews, the activity log (hash-chained; archived to `var/audit_archive/` when cleared; `verify_audit`), usage counts, and the Dashboard SQL tables' kept results (`dashboard_results`). The admin and SQL password hashes are in `var/admin.json` and `var/sql_password.json`; their checks are made one at a time. |
| `whitelist.py` | Settings → Whitelisted users (FR-SET-07): the entries (table `whitelist_users` in the console store; removed ones kept, marked removed), and whether an observation is covered. For the year's groups one query per view joins the flagged members (`cluster_index.sqlite`) with Review's facts table and the entries in force, giving per group the flagged and covered counts and the covered row IDs; cached by the entries and the index file's size and time. `clusters.review_queue` marks each item (`whitelisted`, `overridden`); `review_context.flagged` marks each event; `analyze.py` passes `scoring.score` a test that judges a time window by its uploaded lines; `uploads.py` keeps each event's facts and decides when the upload is read. |
| `auth.py` | SSO (§6), on Authlib and joserfc. |
| `datasets.py` | Dataset registry, archive import and training runs (§7). |
| `llm.py` | Which models the local Ollama offers, and one answer from it; it follows no redirect. |
| `retention.py` | Settings → Retention (FR-SET-10): removes uploads' retained lines and saved Dashboard SQL results past the period, at start, daily and on change; counts reports holding lines past it. |
| `backup.py` | `python -m service.backup create | verify | restore | rehearse`: one zip of `var/` (the database through SQLite's backup API; caches and test output left out) with a SHA-256 manifest. |
| `yields.py` | The Dashboard's Label yield (FR-DSH-11): per mechanism, labelled items, precision and the expected share, from Review's items and the outlier count's per-row masks. |
| `drift.py` | Drift at scoring time (FR-ANA-12): KS D of Isolation Forest percentiles against Uniform(0, 1), judged against a null of validation blocks (`var/cache/drift_null_<source>_<view>.json`), and entities new since training (Phase 4h). |
| `coverage.py`, `attack_ics.json` | ATT&CK for ICS visibility (FR-SIG-11): MITRE's ICS techniques with the data components their detections read (built by `attack_build.py`), against those each log records. |
| `inject_eval.py` | `python -m service.inject_eval DAY.log … --month YYYY-MM`: outsider, insider and sweep scenarios planted into held-out days and scored through Analyze; recall per mechanism, scenario and family with Wilson intervals, in `var/evaluation/<model version>/`. |
| `audit.py` | The Audit sample (FR-REV-18–20): table `audit_items` in the console store, the monthly draw from the detectors' test scores and the outlier masks, the blind listing and the estimates. |
| `feature_ablation.py` | `python -m service.feature_ablation DAY.log --month YYYY-MM`: planted detections lost per neutralised zoo feature, against the zoo's importance ranking. |

## 4. Data the console reads

Read only, from `data/`:

| Input | Used for |
|---|---|
| `phase1_classify/<src>/` | Firewall lines for SQL (loaded once into `var/cache/firewall.sqlite`), event counts |
| `phase2_observations/<src>/` event stores (SQLite) | SQL over auth and OSSEC; original lines; history for OSSEC scoring; Review's logs before and after |
| `phase2_observations/<src>/` flow episodes and their lineage (PF, IPFilter) | Review's firewall items |
| `phase3_features/<src>/` | Saved preprocessing bundles; test lineage for cluster members; train and validation lineage for the maps' earlier points |
| `phase4_detection/<src>/` | Detector and model-zoo bundles, summaries, validation scores (for percentiles), test scores (Review), the 4c map and its UMAP layout (`layout_umap.csv`, used only when `layout_umap.json` names the current embedding) |
| `phase4_detection/<src>/activity/` (AUTH, OSSEC) | Review's and Explain's activity alerts (Phase 4g): test scores, their lines, `incidents.csv` and `explanations.jsonl` |
| `phase4_detection/<src>/profiles/profiles.sqlite` | Profiles (Phase 4h), every log type |
| `phase7_alerts/<src>/` | Presence alerts for PF and IPFilter review |
| `phase7b_clusters/<src>/` | Cluster summaries, assignments and map points |

The console writes only to `triage-console/var/`. The exceptions are the
admin-only dataset import (into `data/phase0_raw/archives/`) and training runs,
which run the pipeline itself.

## 5. SQL console guardrails

Three layers, so that no single mistake opens a write path (Q18):

1. **Text check** (`sql_guard.check`). Comments, strings and quoted names are
   removed first. The query must then be one statement starting with `SELECT`
   or `WITH`. Keywords that write, change the schema, attach files, change
   settings or control transactions are refused, and so are file and extension
   functions.
2. **Engine** (`sql_guard.harden`, on every console connection):
   - `PRAGMA query_only`;
   - an authorizer that allows only reading and refuses risky functions;
   - extension loading off;
   - size limits.
3. **Files.** The stores are attached read-only (`mode=ro`).

Refused attempts are recorded in the activity log as `sql_blocked`. Results
stop at 1,000 rows and 60 seconds.

## 6. Sign-in (SSO)

Off unless `var/auth.json` exists; nothing in the browser can switch it on.
When it is on:

- **Libraries.** Maintained ones, not hand-written protocol code (Q22):
  - Authlib's requests client builds the sign-in link and exchanges the code;
  - joserfc, Authlib's JOSE library, checks the ID token.
- **Flow.** OpenID Connect authorization code with PKCE (S256), `state` and
  `nonce`.
- **Provider settings.** Fetched from the provider's discovery document, which
  must name the configured issuer. All provider addresses must be https,
  except localhost.
- **ID token.** Its signature is checked against the provider's published keys
  (`jwks_uri`); if the provider has rotated them, the keys are fetched again
  once. Only asymmetric algorithms are accepted: never `none`, never HS*.
  Then the issuer, audience, authorised party, expiry, issue time and nonce
  are checked, allowing 2 minutes of clock difference.
- **Shared laptop.** Sign-in asks for the provider's account picker (`prompt`,
  default `select_account`). Sign-out also ends the provider's session when it
  offers an `end_session_endpoint` (OpenID Connect RP-Initiated Logout), so the
  next person cannot be signed straight back in as the previous admin.
- **Settings check.** `python -m service.sso_check` reads `var/auth.json`,
  fetches the provider's discovery document and keys, and reports each setting
  without signing anyone in.
- **Admin rights.** They come from a role claim (`admin_claim`, `admin_values`).
- **Sessions.** Held in memory and ended by a restart. The cookie is
  `otc_session`: HttpOnly, SameSite=Lax, and Secure when the redirect is
  HTTPS.
- **Client secret.** Read from an environment variable, never from the file.

Reading, analysing, reviewing and querying stay open on the laptop. Only
dataset changes and training require a signed-in admin.

## 7. Datasets and training

- **Registry.** `var/datasets.json` holds the datasets added through the
  console, on top of the four built-in ones.
- **Import.** Copies monthly archives (`YYYY-MM name.zip`) into
  `data/phase0_raw/archives/`. An archive already there with the same size is
  skipped; one that differs is reported and never overwritten.
- **Training.** Runs
  `run_pipeline.py --source <type> --from-phase <phase> --with-model-zoo`
  without a shell, one run at a time, from an allow-listed set of phases. The
  output goes to `var/training/`, and the run can be stopped.
- **Logging.** Every action is recorded with the signed-in account.

## 8. Folder layout

```
triage-console/
  README.md, auth.example.json
  docs/       these documents; docs/user is the in-app guide
  web/        browser app (src/, public/, scripts/)
  service/    local Python service
  tests/      unittest suites for the service, and two browser checks (listed in the README)
  var/        settings, store, caches, training logs; not in version control
```

## 9. Risks

| Risk | Mitigation |
|---|---|
| A query changes the event stores. | Three layers (§5), tests for each, refused attempts logged. |
| Review's before-and-after query is steered by what the page sends. | Only checked values reach it (a server-name pattern, whole minutes 0–1,440, a fixed list of logs), and it runs through the same three layers. |
| Someone without rights adds data or retrains. | Admin role from SSO, checked by the service on every change. Off until configured. |
| Another web page in the same browser drives the service. | Origin and Host checks, JSON-only writes, SameSite cookie. |
| Another site frames the console, or a script gets into the page. | The page runs only its own scripts under a content security policy and cannot be framed (NFR-SEC-18); all text goes in as text (NFR-SEC-05). |
| A crafted workbook or a very long line exhausts memory. | Unpacked parts, columns, text and line lengths are capped (NFR-SEC-19). |
| An exported rule, CSV or report runs as code where it is opened. | Phase 1 exports are string literals, formula cells are written as text, HTML reports allow no script (NFR-SEC-20). |
| Anyone at the laptop queries the sensitive logs. | Queries need the SQL password (FR-SQL-07); its default must be changed. |
| Someone types an `/api/` address into the browser and reads the console's data around the pages. | The API needs a header only the app's scripts send, and refuses what the browser marks as typed in; only the built app's files are served (NFR-SEC-17). |
| Retraining changes cluster numbers that reviews refer to. | Reviews keep their history; the disclaimer says to re-check after retraining. |
| A 3B model gives shallow or wrong text. | It is used only for planned features (TODO cards) and never decides. |
| Large views make the map or index slow. | Maps are drawn only on request, after their size is shown; capped at 60,000 points (all flagged points kept). Indexes and counts are built once in the background and cached. |

## Release 0.2.0: Reports and Review

The authoritative implementation record is [06 ? Reports and Review release](06_reports_review_release.md). `service/reports.py` owns transactional case numbering, immutable version JSON, SHA-256 digests, finding associations and audited exports. Schema creation is additive in `var/console.sqlite3`; original datasets are never migrated. `report_maps.py` reads selected saved CSR feature rows without loading full matrices, uses existing placement code and caches the result. `review_filters.py` builds complete event facts in the disposable index, including aggregate lineage, and filters both groups and observations with parameterised SQL. Each filter runs under a `Deadline` (Settings → Review, 120 s by default): a SQLite progress handler interrupts the statement once it passes, the busy timeout is cut to the time left, and the build of the facts, one transaction, rolls back whole when stopped. Its partial flagged-members index and explicit join order avoid scanning the full lineage for each filter.

The browser uses `report-print.ts` for static paper capture and `review-filters.ts` for shared chips and matching rules. Versions retain portable print nodes for Word plus sanitised HTML and the build stylesheet for PDF. Edge renders PDF with JavaScript disabled and network requests blocked. Upload records now retain Analyze map positions; older records without coordinates stay explicitly unavailable. SQLite store contexts close their connections after commit/rollback, including exceptional exits.

Source releases are recorded in root `VERSIONS.md`; `scripts/version_control.py` creates immutable archives and checksum manifests independent of report history. Runtime state and source versions have separate backups.
