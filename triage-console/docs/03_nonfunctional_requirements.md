# Project DAD Console: non-functional requirements

| | |
|---|---|
| Document | 03 · Non-functional requirements |
| Status | Describes the console as built, plus what is still to check |
| Version | 0.10 (2026-10-30): git holds no data or real names (NFR-SEC-21), defaults open nothing (NFR-SEC-22), Phase 9 stays on this machine (NFR-SEC-23), no pickle caches (NFR-SEC-24), whitelist sentinels (NFR-SEC-25); the archived and verifiable activity log (NFR-DAT-03), backups (NFR-DAT-05), retention (NFR-DAT-07), line fingerprints (NFR-DAT-08). 0.9 (2026-10-26): the tests (NFR-MNT-03, NFR-MNT-04). 0.8 (2026-10-26): Review's filters stop at their time limit (NFR-PER-08). 0.7 (2026-10-26): the page's headers and content security policy (NFR-SEC-18), crafted inputs (NFR-SEC-19), exports that cannot become code (NFR-SEC-20), password checks one at a time (NFR-SEC-12, NFR-SEC-16), the model address (NFR-SEC-02), tiles and notes as text (NFR-SEC-05). 0.6 (2026-10-23): the API answers the app's own scripts only (NFR-SEC-17). 0.5 (2026-10-12): whitelisted users (NFR-SEC-15). 0.4 (2026-10-05): the Review investigation's query (NFR-SEC-14, NFR-PER-07), tests, label colours. 0.3: revised for the built application; JEV requirements withdrawn (Q12); SSO and SQL guardrails added (Q17, Q18) |
| Related | [01 Product requirements](01_product_requirements.md) · [02 Functional requirements](02_functional_requirements.md) · [04 Decisions](04_open_questions.md) · [05 Architecture](05_architecture.md) |

Each requirement states how it is checked. **Status**: *Met* (checked),
*Built, not measured*, *Partly*, *Open* or *Withdrawn*. Figures are for the
**reference machine**: the Windows 11 laptop the pipeline runs on, with the
current pipeline outputs.

## 1. Security and privacy (`NFR-SEC`)

The logs describe the site's servers, accounts and network. They must stay on
site.

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-SEC-01 | No network connection outside the laptop: no telemetry, update checks, fonts, scripts or styles from the internet. The language model only from the local Ollama. The one exception is SSO sign-in to the configured identity provider, once SSO is set up (Q17). | Met | Built bundle has no external URL; the font is bundled. SSO is off by default. |
| NFR-SEC-02 | The language-model endpoint must be an `http` or `https` address on localhost; any other address or scheme is refused, and the model client follows no redirect. | Met | `config.save_settings`, `llm.py`; `tests/test_security.py`. |
| NFR-SEC-03 | The service listens on `127.0.0.1` only, with no setting to listen on the network (Q2). | Met | `config.HOST`. |
| NFR-SEC-04 | Sign-in protects the actions that change data: adding a dataset, importing archives, training. OpenID Connect with PKCE, state and nonce, through Authlib (Q22). The ID token's signature is checked against the provider's published keys (rotation followed; asymmetric algorithms only), then its issuer, audience, authorised party, expiry, issue time and nonce. Admin rights come from a role claim. The session cookie is HttpOnly and SameSite=Lax. The client secret comes from an environment variable. On the shared laptop, sign-in shows the account picker and sign-out also ends the provider's session. Off until configured on the laptop (Q17). | Met | `tests/test_auth_datasets.py` against a fake provider with its own signing key: forged and unsigned tokens, wrong claims and key rotation. |
| NFR-SEC-05 | Log lines, comments, review notes, Dashboard tile and table text, rule text and model output are untrusted text: inserted as text, never as HTML; Markdown sanitised; never used to build file paths or commands. A tile opens only one of the console's own pages, and an ATT&CK link only MITRE's own site. | Met | Code review (`dom.ts`, DOMPurify). |
| NFR-SEC-06 | The SQL console can only read (Q18). Text check, engine-level read-only connection (query_only, allow-list authorizer, no extensions, size limits) and stores attached read-only. Refused attempts are logged. | Met | `tests/test_sql_guard.py`, including writes that get past the text check and are stopped by the engine. |
| NFR-SEC-07 | The console does not modify pipeline outputs. It writes to its own `var/` folder; only an admin's import and training touch `data/`, and an import never overwrites a different file. | Met | Code review; `tests/test_auth_datasets.py`. |
| NFR-SEC-08 | Settings are written atomically (temporary file, then rename). | Met | `config.save_settings`. |
| NFR-SEC-09 | Third-party libraries pinned to exact versions: `web/package.json` and its lock file; `requirements.txt` for the service's own packages. | Met | The pipeline's packages come from the project's environment. |
| NFR-SEC-10 | Only the console's own pages can call the service: another `Origin`, or a `Host` other than localhost, is refused; POST and PUT must be JSON, which a web form cannot send. | Met | `tests/test_security.py` over HTTP (403 and 415). |
| NFR-SEC-17 | No part of the console opens from an address typed into the browser, a bookmark or a link: every `/api/` request must carry the `X-Console-Request` header that only the app's own scripts add, and must not be marked by the browser as typed in or from another site (`Sec-Fetch-Site`). The service answers no CORS preflight, so another site's script cannot add the header. Only `/` and the built app's own files are served, matched by name; any other address (`/sql`, `../`) is not found. Not a sign-in: a program on the laptop can still add the header, so what must stay closed sits behind the passwords or SSO (NFR-SEC-04, 12, 16). | Met | `tests/test_server_access.py`; Edge, 2026-10-23: typed `/api/audit` 403, the app's own requests 200. |
| NFR-SEC-12 | The admin password (clearing the activity log or an upload, changing the whitelist) is stored as a salted PBKDF2 hash; a wrong guess costs a second, and checks are made one at a time across all requests, so parallel guesses cannot share out the delay; the default is flagged until changed. | Met | `store.py`; `tests/test_security.py` (parallel guesses). |
| NFR-SEC-16 | The SQL password (FR-SQL-07) is checked by the service, not the page: it is stored as a salted PBKDF2 hash apart from the admin password, a wrong guess costs a second (one check at a time, NFR-SEC-12), and unlock tokens are random, kept in memory only and lapse when idle. The default (1234) is flagged until changed. | Met | `sql_lock.py`, `store.py`. |
| NFR-SEC-13 | Training runs the pipeline without a shell, from an allow-listed set of phases and log types, one at a time. | Met | `datasets.train`; tests. |
| NFR-SEC-15 | Whitelisted users (FR-SET-07) cannot hide what they do not name: an observation is covered only when every account in it is listed; covered observations stay scored, flagged and visible, never deleted; adding or removing an entry needs the admin password (salted PBKDF2, NFR-SEC-12) and is in the activity log; entries carry a reason and may end on a last day; account and server names are checked before they are stored and are matched through bound query parameters. | Met | `tests/test_whitelist.py`: password, validation, exact matching (server scope, case, unnamed accounts), expiry, group coverage, uploads. |
| NFR-SEC-14 | Review's *Logs before and after* query is built only from checked values: a server name matching `[A-Za-z0-9._-]{1,64}`, whole minutes from 0 to 1,440, and log names from a fixed list. It then runs through the SQL console's guardrails (NFR-SEC-06) and is logged. | Met | `tests/test_review.py`: injection attempts refused, window limits, the query passes the guard and runs on a hardened connection. |
| NFR-SEC-18 | The page runs only its own scripts and cannot be framed: it carries a content security policy (`default-src 'self'`, `script-src 'self'`, no plug-ins, no `<base>`, forms only to itself, `frame-ancestors 'none'`), and every response carries `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and same-origin resource and opener policies. | Met | `server.py` (`PAGE_POLICY`, `_security_headers`); `tests/test_security.py`; no policy violation on any of the 11 Advanced pages in a browser check (2026-10-26). |
| NFR-SEC-19 | Crafted inputs are bounded: a workbook part that unpacks beyond 256 MB is refused, a cell claiming a column past Excel's last is ignored, and at most 64 MB of text is taken from one workbook; its XML is read without external entities and with entity expansion limited (Python's expat); lines longer than 1 MB are cut when files, folders and archives are read; regular expressions in Patterns and Sigma rules run with a time limit per match. | Met | `tabular.py`, `patterns.py`, `sigma.py`; `tests/test_security.py`. |
| NFR-SEC-20 | What the console writes cannot become code elsewhere: a rule exported for Phase 1 is a Python string literal that reads back as the same text; CSV cells a spreadsheet would run as formulas are written as text (FR-SQL-09); an HTML report allows no script and no request; comment lines in the queries the console writes itself stay on one line, so a value cannot end the comment. | Met | `patterns.py` (`_python`), `web/src/tables.ts`, `reports.py`, `ip_flows.py`, `review_context.py`; `tests/test_security.py`, `tests/test_reports.py`. |
| NFR-SEC-21 | Nothing derived from the logs reaches git: data, stores, caches, models, site lists, findings, screenshots and secrets are ignored and refused at commit even when forced; every pushed file is checked against a hashed list of the site's servers, addresses and accounts; real names are stored in git as pseudonyms (`.gitattributes`, `scripts/git_names_filter.py`), the key staying in `.git/`. | Met | `scripts/test_git_guard.py`; a push of the whole history to a scratch remote passed (2026-10-30). |
| NFR-SEC-22 | A default password opens nothing; a default cannot be chosen as the new one. | Met | `tests/test_sql_lock.py`, `test_uploads.py`, `test_whitelist.py`. |
| NFR-SEC-23 | Phase 9 sends prompts (log lines, accounts, addresses) only to a model server on this machine and follows no redirect, as the console's own language-model setting. | Met | `pipeline/phase9_llm_triage/test_triage_endpoint.py`. |
| NFR-SEC-24 | No cache the console writes is a pickle: the OSSEC history is numpy arrays read with `allow_pickle=False`, keyed by SHA-256 digests of the entity keys. Model bundles (`*.joblib`) are loaded only from this laptop's `data/` or `runtime/`; copy a frozen runtime only from a laptop you trust. | Met | `tests/test_scoring_history.py`. |
| NFR-SEC-25 | A whitelisted account still asks for review on a new source address or server, a switch to root its entry does not include, and any activity alert. | Met | `tests/test_whitelist.py`, `test_activity_review.py`. |

## 2. Data integrity and traceability (`NFR-DAT`)

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-DAT-01 | Original log lines are shown as the pipeline stored them (apart from escaping for display). | Met | Members and evidence read from the event stores through the lineage. |
| NFR-DAT-02 | Names, comments, reviews and the activity log survive restarts. | Met | SQLite store in `var/`. |
| NFR-DAT-03 | Each activity-log entry carries the hash of the previous one, so an edit, deletion or reordering made outside the console breaks the chain; `store.verify_audit()` walks archives and the live log and says where. Clearing archives the log (`var/audit_archive/`) and the chain continues; every exported report prints the latest hash. | Met | `tests/test_audit_chain.py`. |
| NFR-DAT-04 | Records carry the time in ISO 8601 with time zone. | Met | `store.now`. |
| NFR-DAT-05 | The console's data is backed up with `python -m service.backup create`: the database through SQLite's backup API (consistent while the service writes), the password, settings and archive files, one zip with a SHA-256 manifest. `verify` checks hashes, integrity and the activity chain; `restore` refuses while the service runs and keeps what it replaces; `rehearse` does the round trip into a scratch folder. | Built, rehearsal to run | `tests/test_backup.py`; `rehearse` on the real store is in TODO. |
| NFR-DAT-06 | Names, comments and reviews are kept indefinitely (Q8). | Met | No deletion path. |
| NFR-DAT-07 | The console's copies of log lines (uploads' retained lines, saved Dashboard SQL results) are removed after the retention period (Settings → Retention, 12 months by default); reports are records and are never changed by it. | Met | `tests/test_retention.py`. |
| NFR-DAT-08 | A report's log line can be matched to the original file: its Phase 1 SHA-256 is printed beside it. | Met | `tests/test_review.py`. |

## 3. Performance (`NFR-PER`)

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-PER-01 | Pages other than Analyze open within 2 seconds once the background caches exist. | Built, not measured | — |
| NFR-PER-02 | The map stays responsive (zoom and pan) with 60,000 points. | Built, not measured | Checked by eye in Edge at 38,080 points; drawn in about 1 second there. |
| NFR-PER-06 | Pages never wait for a map: maps are drawn only on request, after a card states the number of points (FR-MAP-00). | Met | Data → Clusters and Analyze. |
| NFR-PER-03 | Analyze reports progress at every station and does not block other pages. | Met | Background job. |
| NFR-PER-04 | Background caches (variants, cluster index, the maps' earlier points, the scores of flagged observations, traffic by address) are built once and rebuilt only when their inputs change; pages say when one is still being built. | Met | Cache stamps. |
| NFR-PER-05 | A SQL query is stopped after 60 seconds and returns at most 1,000 rows. | Met | `sql.py`. |
| NFR-PER-08 | A Review filter answers or is stopped within its time limit (Settings → Review, 120 s by default): SQLite interrupts the running statement, lock waits end with the limit, and loops check it between items. | Met | `review_filters.py`; `tests/test_review_filters.py` (a long query stopped, a wait for another request's preparation, a preparation stopped part-way rolled back). |
| NFR-PER-07 | Review: a group's ranked observations, an observation, and its logs before and after (±30 minutes) each return within 1 second. | Met | Measured on every log type: 0.04–0.14 s; ranking 3,552 flagged observations 0.05 s. |

## 4. Reliability (`NFR-REL`)

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-REL-01 | A failed request shows its error on the page; the rest of the console keeps working. | Met | Error boxes per card. |
| NFR-REL-02 | A missing pipeline output (no map, no clusters for a view) is reported on that card, not as a failure of the page. | Met | — |
| NFR-REL-03 | Only one training run at a time; a second is refused with the reason. | Met | Tests. |
| NFR-REL-04 | A page whose log type changes while it loads shows the latest choice, not a stale result. | Met | Data → Clusters ignores out-of-date loads. |

## 5. Usability and accessibility (`NFR-USE`)

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-USE-01 | WCAG 2.1 AA: contrast, keyboard use, visible focus, labelled fields. | Partly | Fields, buttons and the map have labels and keyboard use; no automated check yet. |
| NFR-USE-02 | Colour never carries meaning alone: review labels and statuses are always written out; on the map, new lines are rings and flagged ones are filled, and a picked group's points have a dark edge as well as being yellow. | Met | Review in greyscale. |
| NFR-USE-08 | Map points stay sharp at any zoom and screen density (FR-MAP-03). | Met | Screenshots at 100% and 150% scale, ×63 and ×120 zoom. |
| NFR-USE-03 | Chart colours pass a colour-vision-deficiency check. | Partly | Splits pass. The Sankey's log-type colours (olive and red) do not, and are still to change. The five review-label colours (Q23) are not checked yet; the labels are always written out. |
| NFR-USE-04 | Every technical number (percentile, lift, agreement, proxy-label scores) has a plain-language explanation beside it or on hover. | Met | Review. |
| NFR-USE-05 | Screens work from 1280 px wide; layout tested at 1440 px. | Partly | Checked at 1440; 1280 to check. |
| NFR-USE-06 | Long actions (Analyze, SQL, Review's logs before and after, training) show progress; motion is reduced when the system asks for it, or stopped under Settings → Animations. | Met | Route board, train loader, `prefers-reduced-motion`, `data-motion`. |
| NFR-USE-07 | Menus, headings and settings are available in six languages, falling back to English for the rest. | Met | `i18n.ts`. |

## 6. Maintainability and portability (`NFR-MNT`)

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-MNT-01 | Browser app in TypeScript, built with Vite; the service in Python, in the project's environment. | Met | — |
| NFR-MNT-02 | The console reuses the pipeline's own code (Phase 1 rules, Phase 2 builders, saved Phase 3 and 4 bundles) rather than copies of it. | Met | `pipeline_code.py`. Scores for test-period lines match Phase 4's stored scores exactly (Q15). |
| NFR-MNT-03 | Automated tests for every service module: the SQL guardrails and password, SSO and datasets, Review (labels, the logs before and after, filters and their time limit, validation groups), Analyze's scoring of sequences, Sigma (rules, form, the fifth detector), Patterns, tables, uploads, whitelisting, reports and their exports, the Dashboard, settings, and the security of the service over HTTP. | Met (229 tests) | `python -m unittest discover tests`; two browser checks (`tests/browser_reports_review.py`, `tests/browser_sigma.py`). |
| NFR-MNT-04 | Tests for Analyze scoring and the review queue. | Partly | Sequence scoring of uploads (`tests/test_sequences.py`), Sigma hits on uploads and in the queue (`tests/test_sigma_review.py`) and the validation groups (`tests/test_validation_groups.py`) are tested; the detectors' scoring of an upload end to end is not. |
| NFR-MNT-05 | The console starts with one documented command. Node.js is needed only to build the web app. | Met | README. |
| NFR-MNT-06 | Settings live in `var/settings.json` with safe defaults; SSO in `var/auth.json` (template `auth.example.json`). | Met | — |

## 7. Compatibility (`NFR-CMP`)

| ID | Requirement | Status | Check |
|---|---|---|---|
| NFR-CMP-01 | Windows 11 with the project's Python. | Met | — |
| NFR-CMP-02 | Current Microsoft Edge and Google Chrome. | Partly | Edge checked; Chrome to check. |
| NFR-CMP-03 | The language-model endpoint is Ollama on localhost. | Met | `llm.py`. |
| NFR-CMP-04 | SSO with any OpenID Connect provider that offers discovery, published signing keys and the authorization-code flow (for example Microsoft Entra ID, with a tenant-specific issuer). | Built, not measured | Tested against a fake provider only. |

## 8. Withdrawn

NFR-SEC-11 (JEV model hashes), NFR-PER-09–11 (JEV speed
and memory), NFR-MOD-02 (JEV order) and the JEV parts of NFR-MNT and NFR-CMP
are withdrawn with JEV (Q12). The queue and batch performance figures of
version 0.2 (NFR-PER-01–08, NFR-REL-01–04) were written for the alert-queue
design and are replaced by §3 and §4 above.

## Release 0.2.0 verification and limits (2026-10-07)

Reports are local, append-only through the service, with actor/time and SHA-256 per saved version. Optimistic version checks reject stale saves. A digest is an integrity aid, not a cryptographic signature or protection against a user editing the database directly. Non-binding acknowledgements neither lock a case nor establish identity. Save limits: 24 MB including print snapshot, 1,500 sections/blocks, eight nested subsection levels. Back up the console database with SQLite backup or while the service is stopped; source archives exclude it.

PDF export uses installed Edge via pinned Playwright, disables JavaScript and blocks all external requests. Print markup is allowlisted and images are embedded; Word rejects external images. Downloaded reports contain included evidence and log lines. Map caps and unavailable-score behaviour are documented in [06](06_reports_review_release.md). Report exports reuse saved evidence rather than rerunning queries.

Automated checks cover persistence, conflicts, editable closure, numbering, finding links, Word formatting, exact filter semantics and sparse matrix row extraction. Headless Edge exercises the report lifecycle/exports and Review duplicate-click guard at 1440 px, with a Reports screenshot at 1280 px, plus real-data map placement. These checks do not establish full WCAG compliance, Chrome compatibility or all-page responsive coverage. Live Ollama, enterprise SSO and a backup/restore rehearsal remain outstanding. See [the release record](06_reports_review_release.md) and root TODO for scope.
