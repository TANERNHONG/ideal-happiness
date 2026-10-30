# Disclaimers

**This is a draft research tool, not a security product.** Read this before
relying on anything it shows.

## What a flag means

- A flag means *unusual compared with the training period*, not *malicious*.
  Most flagged activity in this data turned out to be maintenance, migrations,
  monitoring or misconfiguration.
- Nothing flagged does not mean nothing happened. The models only see what was
  logged. Gaps in collection are blind spots: some servers have weeks without
  logs. The Phase 6 reports list them.
- The models were trained on one site's logs from August 2025 to July 2026.
  They describe what was normal *then*. After changes to servers, accounts or
  automation they will flag the new normal until retrained.

## Model figures

- The model zoo's detection rate, precision and lift are measured against a
  **proxy label** (observations holding a known-risky event, such as a failed
  login), because no analyst labels exist yet. They show how well the models'
  alerts line up with known-risky events, not attacks. See
  [Detection, precision and lift](06_model_zoo_measures.md).
- Thresholds were chosen so that a set share of the validation period would be
  flagged. A different budget gives different alerts.
- PF and IPFilter use the **presence method**: every activity is flagged by
  design, because the agreed normal state is no traffic. A flag there says that
  traffic happened, nothing more.

## The cluster map

- The map is a t-SNE picture: it keeps neighbours together but bends
  everything else. Distances between far-apart groups, the size of a group's
  island and the axis values carry no meaning.
- UMAP (the *Layout* switch) lays out the same points another way. It keeps
  more of the overall shape than t-SNE, but its distances are still only a
  rough guide. The groups were found on the t-SNE map, so in UMAP a group can
  look split in two, or run into its neighbour.
- Many OSSEC islands are striped spindles. In each, every point is the same
  message from the same server, so the map lays them out by the clock: one
  strand per weekday, from midnight at one tip to 23:00 at the other. The
  pinched tips are drawn by t-SNE, not by the logs: the strands are evenly
  spaced in the data. Read a spindle as "this message, at all hours, every
  day", not as structure.
- Groups are found on the map, so they are a convenient way to look at similar
  activity, not proof that two observations have the same cause.
- Training points on the map are never flagged: the models never scored the
  period they learned from. Only validation and test points can be flagged.
- The original lines of training and validation points become available once
  the background index has read the Phase 3 lineage. Until then, a point says
  they are still being indexed.
- On the Analyze page, new lines are placed beside their nearest mapped
  neighbours. Their position is an estimate; the *agreement* figure says how
  many of those neighbours share the group.

## The language model

- The local language model (`qwen2.5:3b-instruct` by default) is small. Its
  summaries and suggestions can be wrong, confident and plausible. Check them
  against the log lines.
- It runs on this laptop; no log text is sent anywhere else.

## Reviewing

- *How rare* compares an event with the validation period, using whichever
  detector finds it rarest. It cannot be finer than one in the number of
  validation events. Identical events share the same value; among equals, the
  order follows how many detectors agree.
- Phase 4's explanations (under *Model details*) name the model features that stood out (for example
  `sequence_hash__0005`), not reasons in plain words. They say which part of
  the model fired, not why the activity happened.
- *Frequent subsequences* (Phase 4f, auth sessions and OSSEC episodes) says it in words: the rarest
  step and its odds on that server in training. An unusual order is not proof of an attack. In an
  upload, a session's first step is not judged if it starts within 15 minutes of the upload's first
  line, nor its last step if it is still open at the upload's last line: the upload may have cut them.
- *Sigma* marks a match of an enabled rule (Advanced → Sigma): a known pattern, not proof of an attack, and
  no score. Over the year it looks at the validation and test periods only; a rule's window reaches back at
  most a day. Changing a rule runs the year's check again in the background; Review updates when it ends.
- A Review filter that runs past its time limit (Settings → Review) is stopped and shows nothing filtered; narrow
  the filter or raise the limit.
- *Around this event* finds lines by server name and time only. Activity
  from the same address on other servers is not included; use Data → SQL for
  that. At most 1,000 lines come back, so a wide window on a busy server can
  be cut short (the page says so).
- PF and IPFilter items have no scores: every firewall flow is flagged by the
  presence rule.

## Your decisions

- Review decisions and comments are recorded with the name set in Settings,
  or with your account when you are signed in with SSO. Without SSO the name is
  typed in, so it is not proof of who made a decision.
- Decisions and comments are never deleted. A changed decision is added as a
  new entry; the earlier one stays in the history.
- The activity log can be cleared with the admin password (Settings). The
  clearing itself is recorded. Change the default passwords (admin `123456`, SQL `1234`) before
  anyone else uses this laptop.

## Checking new logs (Analyze)

- New lines go through the same steps and saved models as the year's logs.
  A session or 5-minute window built from pasted lines contains only those
  lines, so it can look quieter or busier than the real one.
- A server, account or address the models never saw makes lines look unusual.
  That is correct (it is new), but it is not by itself a sign of harm.

## Adding data and training (Datasets)

- Training replaces that log type's results, models and reports in `data/`.
  Reviews and comments made against the old clusters stay, but cluster
  numbers can change after retraining, so check them again.
- Imported archives are copied into the pipeline's raw folder and never
  overwrite a different file. They are not removed by the console.

## SQL

- The SQL console can only read. Queries that would change anything are
  refused, and the refusal is recorded in the activity log.
- Results show at most 1,000 rows, and a query running longer than 60 seconds is stopped.
- Queries need the SQL password, `1234` until changed. It keeps casual readers out; it is not a strong secret.

## Data

The logs describe the site's servers, accounts and network. Keep the console,
its exports and screenshots on site.
