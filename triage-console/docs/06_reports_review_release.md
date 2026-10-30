# Reports and Review: release 0.2.0 implementation record

Implemented 7 October 2026; final verification 8 October 2026 (Singapore). This record supplements the functional/non-functional
requirements, decisions, architecture and the user guide. The full-report AI
writer remains deferred; Q33 now permits editable, versioned closed cases.

## Report interfaces and storage

`service/reports.py` adds four tables to `var/console.sqlite3` using idempotent
`CREATE TABLE IF NOT EXISTS`. Existing reviews/uploads are untouched:

| Table | Purpose |
|---|---|
| reports | Stable ID, unique assigned number, current version, title/status/template, creator/updater and timestamps |
| report_versions | Immutable JSON document and print evidence, actor/time, SHA-256 digest; key `(report_id, version)` |
| report_findings | Finding keys per saved version, including historical links |
| report_numbers | Monotonic annual counter used inside the save transaction |

Save uses the store lock and `BEGIN IMMEDIATE`; counter allocation, revision,
finding links, current pointer and audit entry commit together. The caller's
`base_version` must equal the latest version. Conflicts leave storage unchanged.
The digest detects content differences; it is not a digital signature. Failed
saves never consume a case number. Sign-offs are ordinary versioned block data.

Document limits: 24 MB including print snapshot, at most 1,500 sections/blocks,
eight subsection levels, unique string IDs, recognised block types, finite JSON
numbers, an open/closed state and a known template. Source data remains read-only.

| API | Contract |
|---|---|
| GET /api/reports | List current report metadata; optional `finding` also matches historical citations |
| GET /api/reports/item?id=N&version=V | Document and version list; absent version means latest |
| POST /api/reports/save | `{id: number or null, base_version, document}`; returns ID, assigned number, version, actor/time and digest |
| POST /api/reports/export | `{id, version, format: pdf, docx or html}`; returns filename, MIME type and base64 content |
| POST /api/reports/map | `{source, view, ids, layout, upload?}`; returns background job ID; existing GET /api/analyze/job polls it |

The browser preserves section/block state and collected evidence. A portable
print-node list supports Word export; a static, sanitised paper clone and the
current compiled CSS are retained for PDF and HTML. An HTML export carries a
Content-Security-Policy that allows no script and no request (pictures are embedded). The browser never renders saved HTML
back into the editor. The PDF renderer only consumes sanitised markup, disables
JavaScript, blocks external requests and embeds the local logo. Word uses
python-docx; PDF uses Playwright and the installed Edge. Export never re-queries
the database or invokes AI. Save/export audit entries contain metadata, not raw
evidence. The API remains protected by the service's Host/Origin/JSON checks.

**A report from Review (2026-10-26, Q37).** A reviewed item in Advanced Review has a *Report* button
(`reportButton` in `tabs/review.ts`). It reads the item's review history, keeps the notes that are not
empty, oldest first, each headed by its time, reviewer and label, and hands them with the item to
`reportOn` in `tabs/reports.ts`, which opens Reports on a new anomaly report: the title, *Target*, the
*Detection* tiles and a *Finding* card come from the item (`findingOf`), and the notes become the
*Analyst Comments* text, exactly as typed. Nothing is saved until the analyst saves; no language model is used.

## Maps, timelines and rarity

`service/report_maps.py` selects the existing map's test/validation points.
Exact target positions are reused. Unmapped observations are located by ID in
the saved split manifest; selected CSR rows are streamed from the compressed
NPZ with bounded memory, embedded with the saved zoo bundle and passed through
Analyze's neighbour placement. Work runs in `jobs`; per-request target count is
1–120. Placement caches are disposable and identified by source/view/input
stamps. Large compressed files still require sequential decompression and can
take minutes even for few targets. No training runs or pipeline output writes.

The editor retains the returned map data and renders a canvas with numbered
targets and a matching evidence table. The canvas becomes an embedded PNG for
export. Test/validation background coverage and unavailable positions are
explicit. New uploads retain their original Analyze positions; legacy upload
positions are unavailable rather than guessed. Presence findings have no map.

Line rarity uses saved individual scores independently of target observation
rarity; absent individual scores are explicitly unavailable. The existing
validation reference/percentile computation is reused. Only stored line scores
are reported; this release does not backfill scores for every normal/training
line. Timelines hold a retrieval snapshot plus editable analyst entries, not a
live feed. Both visuals preserve evidence provenance and sampling limits.

## Exact Review filters

`service/review_filters.py` adds `review_facts` and `review_fact_versions` to the
disposable cluster-index cache. Each flagged observation is linked to distinct
original `(host, username, program, address)` combinations through event IDs and
lineage. This relational representation preserves multiple users/programs in a
session/window; adding just one username field to a score would lose evidence.
The stamp includes score/validation stamps and the original store's size/mtime.
The cache rebuild is transactional. A partial index on flagged members avoids
repeated scans of every observation when matching groups.

`GET /api/review/queue` and `/api/review/flagged` accept JSON `filters` with
`host`, `username`, `program`, `address` arrays. Up to 30 values per field,
160 characters per value. SQL is parameterised: OR within a field, AND across
fields on a single original event. Group selection is existence of one matching
flagged observation, not summary-string matching. Queue counts follow filters;
the recorded review still labels the entire group.

`GET /api/review/options?source=&field=&search=` returns up to 100 matching
values. Simple uploads expose original retained-event facts through item
responses and `/api/uploads/facts`; `/api/uploads?filters=...` returns matching
uploads with matching-item progress. Firewall filtering uses complete episode
metadata for host and both addresses; account/program filters cannot match a
packet. UI filter state is shared in memory across modes, not persisted to disk.

Advanced Review now guards in-flight submissions, disabling every label button
until success or failure. Simple Review also exposes the existing password-
protected upload-clear endpoint. Report links preserve historical citations.
Console-store transaction contexts now close database handles deterministically,
avoiding Windows file locks caused by relying on garbage collection.

## Verification and deployment

Unit suites cover revision immutability, annual number allocation, stale-write
rejection, closed-case edits, historical finding links, invalid documents,
Word text/font/table/highlight output, blocked remote images, exact filter
semantics beyond top-three summaries, parameterisation, sparse row extraction
and invalid map inputs. Existing SQL/SSO/uploads/Review suites are retained.

`tests/browser_reports_review.py` starts a temporary store on localhost:8766
and uses headless Edge against the existing dataset. It checks saving/reload,
history restoration, preview, actual Word/PDF downloads, filtering and repeated
clicks, responsive layout, browser errors and real target placement. User case
records, report numbering and settings are not changed by this test. Its output
and screenshots live under `var/checks/reports-review/`. See [VERSIONS.md](../../VERSIONS.md) for the
final validation results; passing unit tests alone does not claim full model
quality or a real SSO/Ollama integration test.

Install `requirements.txt`, build the web app, and restart the local service.
Tables are added lazily and cache facts rebuilt on first filtered use. No
pipeline rerun or destructive database migration is needed. Back up `var/` with
the service stopped before release rollback; source ZIPs do not contain data.
Old report versions remain immutable, but an old application release may not
understand new block types. Restore code into a separate directory first.

### Final validation · 8 October 2026

All 84 unit tests pass; TypeScript/Vite production build and `pip check` pass.
The final Edge run passes report creation/save/reload/history restoration, editing
closed reports, timeline persistence, sign-off invalidation after editing, preview,
Word/PDF downloads, exact Advanced Review filtering and duplicate-submit protection,
real OSSEC neighbour placement, map rendering/preview/exports, malicious-activity
template creation, and Simple Review filters/counts/password-protected clearing.
No browser page errors occurred. Actual PDF pages were rendered with pypdfium2
and visually checked for form layout, map/table/line evidence and sign-offs.

The release controller passed isolated archive/checksum, runtime-exclusion,
overwrite-refusal and source-change checks. The local service was started with
the production bundle; `/api/reports` and the documentation catalogue responded,
including this record, the user guide and the version register. Test databases
were isolated from the live console store. Original pipeline outputs were not
regenerated. The archived source excludes generated test exports and caches.
