# Getting started

The Project DAD Console runs on this laptop only. It reads what the
pipeline has produced (in `data/`) and keeps its own records in
`triage-console/var/`: reviews, comments, group names, reports, Sigma rules,
whitelisted users, settings and the activity log.

## Simple and Advanced

The console opens in **Simple** mode: four pages in the menu.

| Page | What it is for |
|---|---|
| **Check logs** | Four steps. *Upload*: drop a log file or paste lines; the log type and month are filled in. *Analyze*: one verdict, *Unusual*, *Whitelisted* (only [whitelisted accounts](#whitelisted-users)) or *Nothing unusual*, with the servers and how rare. *Map*: where the new lines sit among the year's groups. *Review*: *Review now*, or *Send to a reviewer*, which opens a mail draft without log lines. |
| **Review** | Uploads sent for review; those sent to you, by your name in Settings, are first under *Waiting for you*. Open one to label its unusual events, each with the uploaded lines around it. |
| **Reports** | Write up an anomaly from its findings: log lines, tables, rarity and ATT&CK (saved with version history, preview and Word, PDF or HTML export). |
| **Settings** | The same page as in Advanced: your preferences, the whitelist and the passwords. See [Settings](#settings). |

The *Simple · Advanced* switch at the top of the menu shows every page
described below. Your choice is kept. In Advanced, the menu is grouped in the order
of an investigation: *Overview* (Dashboard), *Prepare* (Datasets, Patterns, Models),
*Detect* (Analyze, Sigma), *Investigate* (Review, Data), *Report* (Reports) and
*Console* (Documentation, Settings). The arrows at the foot of the menu shrink it to one icon per group: point at one (or click it) for its pages.

**SQL password.** Queries in Data → SQL, in a report's table and behind a chart's CSV ask for the
SQL password once; after 30 minutes without a query, it asks again. It is **1234** until you
change it in Settings → Activity log → *SQL password*.

## The pages

In Advanced mode, in the menu's order:

| Page | What it is for |
|---|---|
| **Dashboard** | The starting page. Across the top: items waiting for review, those matching a Sigma rule, items labelled Security relevant (with Suspicious), and the share reviewed. Then the next items to open (click one to review it), review progress, how much the detectors flag and what data there is. Each card's (i) icon explains it; the table icon shows a chart as a table. |
| **Datasets** | The datasets the pipeline holds and any that were added. An administrator signed in with SSO can add a dataset, import its archives and train models ([03 SSO and datasets](03_sso_and_datasets.md)). |
| **Patterns** | For logs the pipeline cannot read yet: how much of a file Phase 1 recognises, the unknown lines grouped into shapes, regular expressions suggested and tried live, and rules saved per log type and exported for Phase 1. |
| **Models** | What was trained for each view of the chosen log type, which views raise alerts, how many alerts each detector raised on the test period, and the model zoo; its (i) icon explains [detection, precision and lift](06_model_zoo_measures.md). *Retrain* goes to Datasets. |
| **Analyze** | Paste log lines, upload a file, or give the path of a file on this laptop. Auth and OSSEC lines go through the pipeline's own steps and saved models; the result says whether they would be flagged, view by view, and where they land on the cluster map. PF and IPFilter use the presence rule: any traffic is flagged. |
| **Sigma** | Rules for attacks that are already known (password guessing and spraying, user names tried, port scans). Run them on pasted lines, a file or a folder; the hits come most serious first, with their lines. Rules that are on also mark the groups they hit in Review. See [Sigma](05_sigma.md). |
| **Review** | Groups the models flag at least twice as often as usual (auth, OSSEC), and any group holding a match of an enabled Sigma rule, from the test period and (marked *validation*) the validation period, then unusual amounts of activity (auth, OSSEC; see [Activity alerts](#activity-alerts)); or periods and flows with firewall activity (PF, IPFilter). Each one is *Needs review* until you record a label. Groups whose flagged events all belong to [whitelisted users](#whitelisted-users) are under *Whitelisted*. See [Reviewing](#reviewing) below. |
| **Explain** | Why each activity alert (auth, OSSEC) was raised, in pictures: what was seen against the usual for that time and kind of day, the reasons, the day, the week as a heatmap and the last eight weeks. See [Explain](#explain). |
| **Profiles** | Any server, source IP, username or destination IP on any day against its own normal, alerted or not; watch the ones you want on the Dashboard. See [Profiles](#profiles). |
| **Data** | The training, validation and test spans, then *Message types* (two Sankey charts), *Clusters* (the map of similar activity, the groups, their lines, members and comments) and *SQL* (read-only queries over every log line, behind the SQL password). |
| **Reports** | Write up an investigation as a printed-style incident report: details, sections, findings, log lines, tables, rarity, ATT&CK, maps and timelines. Every save is a version; export as Word, PDF or HTML. *Report* on a reviewed item in Review starts one from your notes. See [Reports and Review](04_reports_and_review.md). |
| **Documentation** | The pipeline as an MRT line (click a station) and these documents as bus stops. Links inside a document open it here. |
| **Settings** | Your preferences, the Dashboard's layout, the Review filter limit, whitelisted users, the activity log and the passwords. See [Settings](#settings) below. |

**Log type.** Models, Data and Review have a *Log type* dropdown at the top
(AUTH, OSSEC, PF, IPFilter). It is one choice for the whole console: pick OSSEC
on Models and Data and Review show OSSEC too. On the Data page you can also pick
*All log types* for the timeline and the Sankeys; clusters are always shown for
one log type, and only AUTH and OSSEC have them.

**Model picker.** The picker at the top right of every page and the one in
Settings are the same setting.

## Settings

Settings is one page in both modes. Nothing on it needs a restart.

| To | Do |
|---|---|
| Change the look | *Appearance*: language, theme, font (Inter, Roboto, others, or a font installed on this laptop, typed by name) and text size. |
| Choose the waiting animations | *Animations*: *All*, *Skip ending* or *None* (which stops everything that moves). *Animation pack*: *Transit* (an MRT train, an SG Bus), *Desk* (a cymbal monkey, filing cabinets) or *Commuter* (a phone game at a platform or bus stop). *Preview* plays each, failures included. |
| Pick the local model | *Language model*: the model, and the address of Ollama on this laptop. |
| Put your name on reviews | *Your name*: used on comments, reviews and reports until SSO is set up. |
| Arrange the Dashboard | *Dashboard* shows the Dashboard itself. Drag a card to move it, drag its right edge to resize it, and press × (or drop it on *Hidden*) to hide it. *Tile* adds a small card with an icon, a heading and text; *SQL table* adds the result of a query of your own, kept until you refresh it. *Pack tightly* fills the gaps. Nothing changes until *Save*; *Discard* and *Reset* undo. |
| Stop slow filters | *Review → Filter time limit*: a Review filter that runs longer is stopped (120 seconds unless changed). |
| Vouch for an account | *Whitelisted users*: see [below](#whitelisted-users). |
| Change a password | *Activity log*: the admin password (the activity log, the whitelist, clearing uploads; `123456` until changed) and the SQL password (queries; `1234` until changed). A warning shows while either is the default. |

## The cluster map

The map on Data → Clusters and on an Analyze result places similar
observations close together (a t-SNE map from Phase 4c).

A map can hold tens of thousands of points, so it is **drawn only when you
ask**. A card first says how many points the map has; press *Draw the map*.
After that, the same view's map is drawn straight away until the console is
reloaded.

| To | Do |
|---|---|
| Switch layout | *Layout: t-SNE / UMAP* under the map. The same points, laid out another way: groups, flags, a highlighted group and the clicked point stay; the zoom starts again from the whole map. The choice is remembered for every map in this browser. |
| Zoom | Scroll, pinch on a touch screen, double-click, or the + and − buttons |
| Move | Drag, or the arrow keys |
| See the whole map again | The circular-arrow button, or the 0 key |
| Fill the screen | The four-corners button at the top of the map's buttons, or the F key (with the map selected). The map keeps its place and zoom. A point's details open as a panel on top, with ✕ to close it. While a group is highlighted, a badge names it and has a *Clear* button. Esc or F leaves fullscreen. |
| Open one point | Click it. A ring marks it, and a panel below the map shows its period (training, validation or test), time, group, model-zoo votes and original lines. |
| Pick out a group | Click its row in the list beside the map (or *Highlight its group* on a point). The group turns yellow and every other point turns grey; the map stays where it is. *Clear* (or clicking the row again on Analyze) undoes it. |
| Frame a group | *Zoom the map to it* in the group's details. |
| Show or hide groups | The tick boxes in the list, or the chips for whole kinds: named by people, automatic names, unnamed (map only), isolated points |
| See only flagged points | *Flagged points only* under the map |
| Find the new lines (Analyze) | The target button frames them. They are drawn as rings, filled red when flagged. |

The axes are in t-SNE (or UMAP) units. Nearby points behave alike, but the
axis values and the distances between far-apart groups mean nothing on their
own. t-SNE is only one way to flatten the data into a picture: if an island
looks odd, check it in UMAP before reading anything into its shape.

*Unnamed groups* are islands on the map with no observations in the test
period, so the pipeline wrote no summary for them. *Isolated points* (group 0)
sit on no island.

## Reviewing

An unusual line is hard to judge on its own, so each Review item is an
investigation.

1. Each group shows its servers, accounts and source addresses, and its
   **Unusual events**, rarest first. *How rare* compares an event with the
   validation period: *1 in 50,000* means rarer than all but one in 50,000
   of its events; *rarest* means as rare as anything in it, or rarer.
2. Click an event to see its time, server and original lines. The models'
   own scores are under *Model details*.
3. Under **Around this event**, set *Before* and *After* in minutes (or a
   preset), tick the logs to search and press *Show*. You get
   every line from the same server in that window, oldest first, opening at
   the event. Its own lines are marked **▶ this**; *during* marks other
   lines from the same span; −m:ss and +m:ss say how long before or after.
   At most 1,000 lines: narrow the window if it says so. *Open in SQL* takes
   the query to Data → SQL to refine it.
4. Record a label, with a note where one is needed:

| Label | Use it when | Note |
|---|---|---|
| **Security relevant** | Hostile or unauthorised activity is shown or strongly suggested, even if it was blocked or failed. | What you found |
| **Suspicious** | It could be hostile and nothing explains it yet. | What to check next |
| **Operationally interesting** | Nothing hostile, but something needs fixing: a failing job, a misconfiguration, an outage. | Optional |
| **Expected behaviour** | A specific routine explanation fits every line: maintenance, approved automation, a known job. | Optional |
| **Insufficient evidence** | The logs cannot decide it. | What is missing |

Changing a label adds a new entry; the history keeps every one.

### Activity alerts

For auth and OSSEC, Review also lists **activity alerts**, after the test-period
groups. These ignore what the lines say: an alert means the whole log, or one
server, source IP, username or destination IP, was unusually busy, or unusually
quiet, for *that* one, given its own history and the time of day.

How a step is flagged: its lines in each window (5 minutes, 30 minutes, 2 hours, 12 hours) are
compared with the same clock time on its comparable training days (the same
weekday's, else the same kind of day's) and with its level whenever it is
active, and both must be at least 3 robust z-scores away; a routine peak at its
usual time is not flagged. The Isolation Forest only adds its agreement, unless
it is extremely sure. Drops count only for entities that are usually busy then
(20 lines or more in the window). *Compared with* in the facts names the days.

**Incidents.** One event can raise several alerts (the whole log, the server, the account
and the address involved), and a routine that started after training raises one a day. Review
lists them as one **incident** each, named by it (*Username bob with server srv-a, source IP
10.2.0.2*; *Server srv-x: lines at about 07:05 and 21:05 on 52 days since 9 Jun*), with its
size. Alerts join one event only when they peak within an hour of each other and their entities
shared a line then; such an event joins a routine, but two routines stay two incidents. The
**Incident** card lists every alert in it: click one to see its lines, or **Explain** to open its
explanation. A label applies to the whole incident.

Besides lines, two more counts can raise an alert: **failures** (auth: more
failed logins than usual at that time, even when the total looks normal) and
**new partners** (an account, address or server sharing lines with several
others for the first time within 2 hours). The peak in Review says which
(*60 failures in 5 min*, *5 new partners in 120 min*).

**Asset inventory.** `pipeline/phase9_llm_triage/site/assets.csv` lists each
server (by name), address or network (CIDR) with its zone (OT, IT, DMZ…), role
(HMI, SCADA server, jump host…) and criticality (low, medium, high). With it,
Phase 4g counts logins that cross zones, compares a new server with the others
of its role, and ranks a critical asset's alerts higher. Empty, it changes
nothing. Rerun Phase 4g after editing it.

- The item is named by who it is about, e.g. *Source IP 192.0.2.17*, and shows
  its peak (*224 lines in 15 min*) against the **usual** level, and its dates.
- **This activity** shows the lines of the busiest 5 minutes and the facts.
- **Around this event** for a server reads every log on that server, as for a
  group. For a source IP, username or destination IP it reads that one's lines
  in its own log, on every server; for the whole log, every line.
- *Activity, whole log* and *Activity, per entity* in the view picker show only
  these alerts. A username alert is under *Whitelisted* when the account is
  whitelisted on all servers.

## Explain

**Explain** shows why an activity alert was raised (Phase 4g), as charts and statistics.

Terms. **x** is the observed count. The **comparable days** are the days the detector compared the
alert with: the entity's own training days of the same weekday (public holidays apart), or of the
same kind of day (working, or non-working: Saturday, Sunday, public holiday) when it has fewer than
4 of those, at the same clock window, from its first appearance, on days the log has lines; hours
with no line count as 0. Every check names them (*n = 8 Saturdays*).
**n** is how many there are. **Median** and **P10–P90** (10th and 90th percentile) describe their
counts; percentiles rather than mean ± SD, because the counts are skewed. **x / median** is shown as
*37×* above the median and as a percentage below it (*12%*); *from 0* when the median is 0. With
n < 4 there is no distribution, and the detectors' own baseline (the median over active 5-minute
steps, pooled across the entity type when the entity has fewer than 30) is quoted instead.

- **List**: filter by who, day type and window (each window option shows its count of alerts).
  *new* marks an entity with no training data.
- **Warning**: an amber line above the headline when the entity has no training data (first seen
  after training ended: n = 0 own days, compared with its type's pooled baseline) or no data before
  the alert's week or day. Treat its medians and percentiles as not its own.
- **Summary**: x for the alert's window (e.g. 15 min), the median and n, x / median, and the date.
  The strip under the headline gives the four windows (5 min, 30 min, 2 h, 12 h): black where x is beyond
  P10–P90 in the alert's direction, grey where it is not; hover for the numbers. Hourly charts can
  look ordinary when only a few minutes were unusual.
- **Evidence** lists every check, in or against the alert's direction: x against median, P10–P90
  and n for each window and for the daily total (with its distribution), by day type and also
  against the same weekday (*vs Saturdays*); the share of comparable
  days active in this hour; median daily totals of the two day types; distinct entities in the
  peak 5-minute step against their median over active steps; the gap before the first step; and
  both detectors, max |z| and the Isolation Forest score against their thresholds. Checks not in
  the alert's direction stay listed, greyed, with their result (*within P10–P90*, *n < 4*,
  *< threshold*, *opposite direction*).
- **Distribution, same window**: a histogram of the n comparable days' counts (log scale) with a
  Gaussian kernel density, P10–P90 shaded, the median dashed and x in red.
- **Hourly counts, this day**: x per hour (line), the median (dashed) and P10–P90 (grey area) for
  the day type; the alert's window shaded.
- **Hourly counts, this week**: one heatmap. *Count*: white to black on a power curve between P2
  and P98 of the week's hourly counts. *x / median*: each hour against the median of that hour on
  the same weekday's training days (a public holiday against past holidays, or non-working days
  when there are fewer than 4): blue below, white at the median, red above, from half to double at
  least; dashed where there is no median (n < 4). Hover for x, the median and n; the table view
  lists each day's median and P10–P90. The alert's window is outlined; holidays are named.
- **Summarize evidence** (on the Evidence card) keeps only the checks that point to the alert, as
  blocks, under a short summary in plain sentences: the flagged count against its usual, the hour,
  the silence before it, failures and first-time partners, the day, its rhythm and the detectors.
  It is for sharing with people who do not read the statistics; the choice is remembered.
- **Silence before**: how long the entity had no line before the alert began, against its usual
  gap between active steps. **Regularity, 1 h**: the coefficient of variation (standard deviation
  ÷ mean) of its lines per 5 minutes over the last hour: 0 is a steady beat (an automated
  process), about 1 random, above 1 bursty. **Gap regularity, 12 h**: the same for the gaps between
  its active steps over 12 hours: 0 is a fixed rhythm (a scheduled job, a beacon). Both are judged
  against the entity's own training P10–P90.
- **Daily totals, 8 weeks**: daily x, working and non-working days apart, with the median and
  P10–P90 of the day type over each bar, and where training ends.
- Each chart has a table view. **Reword** turns the reasons into plain English for sharing; it is
  kept only if every number stays the same. **Review** opens the alert to label it.

Public holidays are listed in `pipeline/phase9_llm_triage/site/public_holidays.csv`; check the
moon-sighting holidays there once they are confirmed.

## Profiles

**Profiles** shows every server, source IP, username and destination IP, alerted or not, against its
own normal, on any day. It needs Phase 4h:
`python run_pipeline.py --source ossec --only-phase 4h` (any log type).

Normal, for AUTH and OSSEC, is the entity's training days of the **same weekday** (public holidays
apart: compared with past holidays, or with non-working days when there are fewer than 4), from its
first line, quiet days counted as 0. x is the day's lines; the median, P10–P90 and n are those
training days' daily totals. For PF and IPFilter normal is **no activity** (the presence method), so
the page shows counts only.

- **List**: pick *Who* and the day (or step a day back or forward). It shows the entities with lines
  that day or usually active on that weekday, furthest from their normal first: N× above the
  median, a percentage below it, *≈* within P10–P90, *n < 4* without enough training days. The small
  columns are the last 8 weeks of daily totals. *Search* finds any entity by part of its name.
  *new* marks no training data; the eye, a watched entity; the flag, its activity alerts.
- **An entity**: x, the median and x / median for the day; Explain's warning when it has no training
  data. *Daily totals, whole period*: click a day to move to it; activity alerts are marked above.
  The day, the week and the 8 weeks use the same weekday's training days as the median week.
  *Shared lines*: who it appeared with up to that day (click to open them); *new* that day, or
  *after training*. *Activity alerts* open in Explain or Review.
- **Watch** puts the entity on the Dashboard's *Watched* card, which shows it on the last day with
  data. Explain's *Profile* opens an alert's entity on the alert's day.

## Whitelisted users

Some accounts are known to be harmless but keep being flagged: a nightly
backup job, a monitoring service, a contractor's test account. **Settings →
Whitelisted users** is the override for them.

1. Type the **Account** (suggestions come from the year's flagged events).
2. Leave **Server** empty for every server, or name one. One server is safer.
3. Say why under **Reason**. Set **Until** to the last day it should apply,
   or leave it empty.
4. Enter the admin password (the activity log's) and press **Add**.

What changes:

- An event is **covered** when every account it names is whitelisted, on its
  server or on all servers. An event that names no account, or also names an
  account that is not on the list, is not covered.
- The models still score and flag covered events, and nothing is deleted.
  They just stop asking for review:
  - In **Review**, a group whose flagged events are all covered moves from
    *Needs review* to *Whitelisted* (the shield). A group only partly covered
    stays, with a badge such as *53 of 954 whitelisted*, and its covered events
    are marked.
  - **Check logs** and **Analyze** say *Whitelisted* instead of *Unusual* or
    *Would be flagged* when every flagged event is covered.
  - In an upload, covered events are marked and count as done; this also
    applies to uploads kept before the account was added.
  - The **Dashboard** counts whitelisted groups apart from those that need
    review.
- The list shows how many of the year's flagged events name each account, who
  added it and when. An entry past its *Until* day shows as ended and no longer
  applies. Removing an entry (the bin) also needs the password. Every addition
  and removal is in the activity log.

**Take care.** A whitelist is a blind spot on purpose: it also hides a covered
account's failed logins and its switches to root. If an account's password or
key were stolen, its activity would not ask for review. Prefer one server and a
last day, and review the list now and then. This is different from Phase 9's
list of approved automation addresses, which only informs the language model.

## Starting it

From the `triage-console` folder, with the project's Python environment:

```
..\.venv\Scripts\python.exe -m service
```

then open <http://127.0.0.1:8765>. While developing the web app, also run
`npm run dev` in `triage-console/web` and open <http://localhost:5173>.

## Words used

- **View**: one way of grouping the logs into observations, for example
  single lines, sessions or episodes, 5-minute windows, or whole days.
- **Flagged**: at least one detector scored the observation above its
  threshold.
- **Alert rate** of a cluster: the share of its observations that were flagged.
  **Lift**: that rate divided by the rate for the whole view. (The model zoo's
  lift on Models is a different measure: see
  [Detection, precision and lift](06_model_zoo_measures.md).)
- **Presence method** (PF, IPFilter): normal is no traffic, so any activity is
  flagged.
- **Anomaly score**: the share of the validation period's observations that
  are less unusual than this one (per detector, and overall as the highest).
- **Training / validation / test**: the models are fitted on the training
  months, their thresholds are set on the validation months, and they are
  judged on the test months, which nothing was tuned on.

### Robust deviation

How far a count is from normal, in robust z-scores: (log(1 + x) − median) ÷ (1.4826 × MAD), the
median absolute deviation standing in for the standard deviation so that a few bursts in the history
do not inflate it (at least 0.5, so a perfectly steady history does not make every change huge).
Phase 4g computes it twice for each window, against the same clock time on the comparable days (the
calendar) and against the entity's level whenever it is active, and counts the smaller, so both must
agree. It alerts from 3, or higher when the validation period would otherwise give more than two
alerts a day; each of lines, failures and new partners has its own threshold.

### Isolation Forest

A model that isolates each 5-minute step with random splits of its features; steps that are isolated
in few splits are unusual combinations. In Phase 4g it is a second opinion: it raises an alert's score
when it agrees, and alerts on its own only when a step is more isolated than every training step.

### Comparable days

The training days a day is compared with: the same weekday's (public holidays apart), or the same
kind of day's (working or non-working) when there are fewer than 4. Quiet days count as 0.

### P10, median and P90

The 10th, 50th and 90th percentiles of the comparable days' counts: one day in ten is below P10,
half below the median, nine in ten below P90. Percentiles are used rather than mean ± standard
deviation because counts are skewed.

### Coefficient of variation

Standard deviation ÷ mean. *Regularity, 1 h* uses it on the lines per 5 minutes over the last hour,
*Gap regularity, 12 h* on the gaps between active steps over 12 hours: about 0 is a steady beat or a
fixed rhythm (an automated process, a scheduled job, a beacon), about 1 random arrivals, above 1
bursts. Each is judged against the entity's own training P10–P90.

### Silence before

How long the entity had no line before the alert began, against its past resumptions: the gaps of
an hour or more in training after which it became active again (its nights, weekends and breaks).
It counts when the silence is longer than their P90. A single median gap would not do: inside a
session lines come minutes apart, so every morning would look like a long silence.

### New partners

Other entities it shares a line with for the first time: a username on a new server or from a new
address, an address reaching a new server. Counted over 2 hours, after the log's first 14 days
(when every pair is new).

### Success after failures

A successful login by a username or source IP after failures in the 30 minutes before; from 5
failures it counts. One actor's guess that worked looks like this.

### Peer baseline

For an entity with too little history of its own, the median of the other entities with the same
role in the asset inventory (`site/assets.csv`), rather than of every entity of its type.
