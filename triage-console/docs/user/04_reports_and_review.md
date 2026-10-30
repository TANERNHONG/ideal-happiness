# Reports and Review

Release 0.2.0 · 7 October 2026 · updated 30 October 2026

## Find the events to review

Review has **Server**, **Account**, **Program** and **Address** filters. Type to
see suggestions, choose a value and press **+** or Enter. Add several values to
one field to accept any of them. Different fields must match the same original
event. For example, Account `root` and Program `sshd` finds an event naming both;
a root event elsewhere in the same window does not satisfy the program filter.
Remove a chip with its ×, or use **Clear filters**.

The filters stay while the application is open, including when switching modes.
In Advanced Review they narrow the group list, its Needs review/Reviewed (and
Whitelisted) counts and the unusual events inside the selected group. The group totals and rarity
remain the original findings' totals; **a review label still applies to the
whole group**, not just its filtered events. Filters use all indexed original
events, not the three most common values shown in the summary. Suggestions show
up to 100 matching values; type more letters to narrow them.

A filter that takes longer than the limit in **Settings → Review** (120 seconds
unless you change it) is stopped with a message saying so. The first filter after
the data changes also prepares the filters, which takes longest; if that is what
was stopped, raise the limit and filter again.

In Simple Review the same controls narrow uploads and their event lists. The
progress count follows the matching events. These filters use the original
event lines retained in the upload, not its surrounding context. An old upload
can only be searched over evidence it actually retained. Firewall flows can be
filtered by server and either endpoint address; packets have no account or
program, so those filters return no matches. All comparisons are exact and
case-sensitive after selecting a value.

While a label saves, its buttons are disabled. On failure the buttons become
available again and the error is shown. This prevents repeated rapid clicks
from adding several identical decisions. In Simple mode, **Clear upload** asks
for the activity-log password; it removes the upload and its event data. Saved
report snapshots and previously recorded review/audit history remain.

Groups and upload events whose accounts are all whitelisted (Settings →
Whitelisted users; see [Getting started](01_getting_started.md#whitelisted-users))
need no label: in Advanced Review they sit under **Whitelisted** (the shield),
and in an upload they are marked and count as done. They can still be opened
and labelled; a label moves a group to *Reviewed*.

For AUTH and OSSEC, Advanced Review also lists **activity alerts** after the
groups: unusual amounts of activity, one item per incident (one event across
several entities, or one routine across several days). The same filters apply,
and a label covers the whole incident. **Explain** shows why each was raised; see
[Getting started](01_getting_started.md#activity-alerts).

## Start and save a report

Reports is available in Simple and Advanced modes. Choose **Anomaly** or
**Malicious activity**, then **New report**. The malicious-activity template
adds prompts for confirmed evidence, containment, eradication and recovery.
Choosing that template does not establish that the activity was malicious.

The report paper and exports use Times New Roman. Add blocks from the left by
dragging, or focus a block and press Enter to add it to Supporting Evidence.
Drag a finding from the right onto a compatible block, or use its Finding list.

**Save version** keeps a complete copy in the console's local store. The first
save assigns `IR-YYYY-NNNN`; the number is not editable. Every later save creates
a new version, with who saved it and when. **Saved reports** lists the reports;
**Version history** opens an earlier copy. Editing and saving that copy creates
a new latest version, preserving the earlier ones. If another tab has saved a
newer version, your stale save is refused without overwriting either version.
Open the current version before applying your changes again.

The **OPEN/CLOSED** switch is a case status. Any local reviewer may close or
reopen a case; closed reports remain editable and each save is still versioned.
The browser warns before discarding an unsaved report to open another or create
a new one, and before reloading/closing a tab with edits. Switching pages keeps
the in-memory draft. There is no autosave: use **Save version** before leaving
the application. Save is blocked while report evidence is still loading.

Findings and uploads show links to reports that cite them. A link can remain
when the finding was cited only in an older report version; the history keeps
that association. Clearing an upload does not erase an already saved report.

## Add maps and timelines

A **Cluster map** block accepts an AUTH or OSSEC finding. Choose t-SNE or UMAP,
choose target observations, then **Draw target map**. Uploads containing several
views also offer a view selector. The background contains test and validation
map points; training background points are excluded. Grey is test, blue is
validation, red is flagged, and numbered yellow rings identify targets. The
table beneath the map connects each target number to its server, time, rarity
and placement method. The figure is retained with the report and exported.

Targets already on the saved map use that exact position. Other test/validation
targets are placed using their original saved feature vector and the existing
map's nearest neighbours, as in Analyze. Such positions are labelled estimates.
Reading a large compressed feature file may take minutes; progress is shown and
the placement is cached. No new model or map is trained. Maps show up to 60,000
background points, keeping flagged points; the caption records the coverage.
The target chooser uses the finding's available events (up to 120 rarest).

New uploads retain their Analyze map positions. Uploads saved before this
release did not retain those positions, so their map positions may be
unavailable; re-analyse the original upload to retain them. Missing targets are
counted explicitly, never placed at an invented centre. PF/IPFilter findings
have no learned cluster map: use Timeline for their activity instead.

Rarity belongs to a detector's observation and is compared with its validation
reference. Session/window rarity is **not** a score for every line it contains.
The map's evidence lists show individual-event rarity where a saved line score
exists; otherwise they say **Line rarity unavailable**. They never substitute
the enclosing session's score. Each target shows up to 40 retained original
lines and states when there are more. Rarity measures unusualness, not guilt.
Silhouette is deliberately absent from the report body: separation in a 2-D
projection does not establish either anomaly quality or maliciousness.

A **Timeline** block retrieves the finding's available events and orders them
by their source-log time. Add, edit or remove entries, and add analyst events
for actions or context. Analyst events are identified separately from evidence
observations. Times use the source logs' local-time convention. The retrieval
time and source count remain visible; this is a selected evidence timeline,
not a claim to show every event in the database.

## Acknowledge and export

Signature blocks record name, role, date and acknowledgement time. **Sign** is
non-binding in this proof of concept; it does not authenticate a person or
cryptographically sign the case. Changing its name, role or date clears that
acknowledgement. Other report edits create a new version when saved; the old
acknowledgement remains part of the old saved version.

**Preview** shows the paper without editing controls. Choose **PDF**,
**Word (.docx)** or **HTML** beside **Export**, then export. A new or edited report is saved
first. Exporting an unchanged historical version exports that version. Files
are named `IR-YYYY-NNNN_vN.pdf`, `.docx` or `.html` and downloaded locally.

**Report** on a reviewed item (Review → Reviewed) starts a new report about it:
the title, Target Analysis, the Detection tiles and the finding in Supporting
Evidence come from the item, and VI Analyst Comments holds the item's saved notes
as typed, oldest first, each under who wrote it, when and its label. Only saved
notes are used: save the label and note first.

PDF uses the saved paper and styles, rendered by the installed Microsoft Edge
in headless mode. JavaScript is disabled and external requests are blocked.
Word contains editable headings, paragraphs and tables, cell shading, table
comments as text, footnote text and embedded map figures. Word pagination and
layout adapt to Word; it is not a pixel-identical PDF. Preview is an on-screen
paper preview, not a prediction of Word pagination.

The saved snapshot retains the evidence already retrieved, including any log
lines and query tables you chose. Export does not run SQL again or contact the
language model. Downloads may therefore contain operational log data; the
console does not email or publish them. Report saves and exports are audited.
If Edge is missing, PDF export reports an error; Word and browser printing
remain available. Install the packages in `requirements.txt` for both exporters.

## AI and records

The full-report AI writer remains deferred by decision Q31. The existing table
query helper and ATT&CK suggestions require local Ollama; offline errors are
shown and manual SQL/tables and offline ATT&CK search remain available. A
stand-in model is covered by tests; real-model verification remains pending
while Ollama is unavailable. ATT&CK updates remain a maintenance task.

Back up the complete `triage-console/var/` directory with the service stopped
to preserve case records, version history and evidence. Source-release history
is separate: see the [version register](../../../VERSIONS.md) and `scripts/version_control.py`.
Source snapshots deliberately exclude logs, report stores, settings and caches.

## What else a report carries (2026-10-30)

- **Ticket no.**, beside *Report no.*: the organisation's own incident reference. Enter it when the case goes into the
  incident procedure; it is kept in the version, shown in Saved reports and printed.
- **A fingerprint per log line**: the first 12 characters of the line's SHA-256 (the whole value on hover). The same line
  in the original log file has the same fingerprint, so anyone can check that a quoted line is genuine.
- **The activity log's latest hash** in the footer of every Word, PDF or HTML export. Settings → Activity log shows the
  same hash; if the log were edited later, the chain would no longer lead to the hash printed on reports already sent.
- In Review, **Playbook** opens what to check next for the item's kind of alert
  ([Playbooks](07_playbooks.md)).

