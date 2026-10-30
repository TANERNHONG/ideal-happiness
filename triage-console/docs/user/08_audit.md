# Audit: labelling a random sample

Review shows what the detectors surfaced, most unusual first. Labels given there say how good the top of the
queue is, but nothing about what was missed. The Audit page fixes that with a small random sample each month.

## What to do

1. Open **Investigate → Audit**. If the month has no sample yet, press **Draw**: 25 items per log type are drawn
   from the test period, some the detectors flagged and some they did not.
2. Open each item in turn. You see its server, its time and its lines, and **Lines around** for the logs either
   side. You do not see whether it was flagged, how unusual it scored, or why it was chosen. That is deliberate:
   label what the lines show, not what a model thought.
3. Give the label you would give in Review, with a note where the label asks for one. *Insufficient evidence* is
   fine when the lines cannot decide it; it is left out of the estimates.

About an hour a month keeps the estimates useful. The sample is drawn once per month and stays the same if drawn
again.

## What the estimates mean

- **Precision**: of the observations the detectors flag, the share that are security relevant or suspicious.
- **Missed / 10,000**: of the observations they do not flag, how many in 10,000 would be.
- **Recall**: of all the relevant observations, the share the detectors flag.

Each comes with a 95% interval and the number of labels behind it. With few labels the intervals are wide; that is
the honest answer, and it narrows month by month. Audit labels are used only for these estimates and never to
train a model.
