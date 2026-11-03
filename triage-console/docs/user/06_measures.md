# Measuring the detectors

Two pages say how good the detectors are, in two different ways.

| Page | Compares the alerts with | Gives | Costs |
|---|---|---|---|
| **Models** | a stand-in label: observations holding a known-risky event | detection, precision and lift, after every run | nothing: no one labels anything |
| **Audit** | your labels on a small random sample, given blind | precision, missed per 10,000 and recall, each with a 95% interval | about an hour a month |

The first says whether the alerts are worth reading first. Only the second says how many relevant observations the
detectors catch and how many they miss.

## Models: detection, precision and lift

The model zoo's card on **Models** ends with a line such as
**detection 15% · precision 30% · lift 15×**. Each number answers one question about the zoo's
alerts in the test period.

### The yardstick: a stand-in label

No one has labelled the logs as attack or normal yet, so the zoo is checked against a stand-in
(a *proxy label*). An observation counts as **risky** when it holds a known-risky event:

- **A single line**: an event type such as a failed or invalid login.
- **A session, a 5-minute window or a day**: at least one failure, invalid user, denied access,
  privilege change, protocol error or PAM event.

Risky is not the same as an attack. Most risky observations are harmless, and an attack can avoid
every one of these events.

### The three numbers

An example with round, made-up numbers: 10,000 test sessions, of which 200 are risky (2%). The zoo
raises 100 alerts, and 30 of them are risky.

| Measure | The question | How it is worked out | In the example |
|---|---|---|---|
| **Detection** | Of the risky observations, how many did the zoo flag? | flagged and risky ÷ all risky | 30 ÷ 200 = **15%** |
| **Precision** | Of the zoo's alerts, how many are risky? | flagged and risky ÷ all alerts | 30 ÷ 100 = **30%** |
| **Lift** | How much richer in risky observations are the alerts than the data as a whole? | precision ÷ share of risky in all the data | 30% ÷ 2% = **15×** |

### Reading them together

- **Lift above 1×** means the alerts hold more risky observations than picking at random would;
  **1×** means no better than random.
- **Detection is capped by the alert budget.** The zoo may raise only a set number of alerts, chosen
  so a person can read them. With 100 alerts and 200 risky sessions, detection cannot pass 50%.
- **A high precision is not the aim.** The zoo looks for what is unusual, not for failed logins; a
  rule finds those more simply. A zoo whose alerts were all failed logins would add little.
- **None of the three counts attacks caught.** That needs real labels: the audit below, and the labels
  recorded in Review.

## Audit: labelling a random sample

Review shows what the detectors surfaced, most unusual first. Labels given there say how good the top of the
queue is, but nothing about what was missed. The Audit page fixes that with a small random sample each month.

### What to do

1. Open **Investigate → Audit**. If the month has no sample yet, press **Draw**: 25 items per log type are drawn
   from the test period, some the detectors flagged and some they did not.
2. Open each item in turn. You see its server, its time and its lines, and **Lines around** for the logs either
   side. You do not see whether it was flagged, how unusual it scored, or why it was chosen. That is deliberate:
   label what the lines show, not what a model thought.
3. Give the label you would give in Review, with a note where the label asks for one. *Insufficient evidence* is
   fine when the lines cannot decide it; it is left out of the estimates.

About an hour a month keeps the estimates useful. The sample is drawn once per month and stays the same if drawn
again.

### What the estimates mean

- **Precision**: of the observations the detectors flag, the share that are security relevant or suspicious.
- **Missed / 10,000**: of the observations they do not flag, how many in 10,000 would be.
- **Recall**: of all the relevant observations, the share the detectors flag.

Each comes with a 95% interval and the number of labels behind it. With few labels the intervals are wide; that is
the honest answer, and it narrows month by month. Audit labels are used only for these estimates and never to
train a model. The Dashboard's *Audit* card shows the latest estimates.

## In one line

Lift says the alerts are worth reading first; the audit says how many relevant observations they catch and miss.
Neither says an alert is an attack.
