# Detection, precision and lift

The model zoo's card on **Models** ends with a line such as
**detection 15% · precision 30% · lift 15×**. Each number answers one question about the zoo's
alerts in the test period.

## The yardstick: a stand-in label

No one has labelled the logs as attack or normal yet, so the zoo is checked against a stand-in
(a *proxy label*). An observation counts as **risky** when it holds a known-risky event:

- a single line: an event type such as a failed or invalid login;
- a session, a 5-minute window or a day: at least one failure, invalid user, denied access,
  privilege change, protocol error or PAM event.

Risky is not the same as an attack. Most risky observations are harmless, and an attack can avoid
every one of these events.

## The three numbers

An example with round, made-up numbers: 10,000 test sessions, of which 200 are risky (2%). The zoo
raises 100 alerts, and 30 of them are risky.

| Measure | The question | How it is worked out | In the example |
|---|---|---|---|
| **Detection** | Of the risky observations, how many did the zoo flag? | flagged and risky ÷ all risky | 30 ÷ 200 = **15%** |
| **Precision** | Of the zoo's alerts, how many are risky? | flagged and risky ÷ all alerts | 30 ÷ 100 = **30%** |
| **Lift** | How much richer in risky observations are the alerts than the data as a whole? | precision ÷ share of risky in all the data | 30% ÷ 2% = **15×** |

## Reading them together

- **Lift above 1×** means the alerts hold more risky observations than picking at random would;
  **1×** means no better than random.
- **Detection is capped by the alert budget.** The zoo may raise only a set number of alerts, chosen
  so a person can read them. With 100 alerts and 200 risky sessions, detection cannot pass 50%.
- **A high precision is not the aim.** The zoo looks for what is unusual, not for failed logins; a
  rule finds those more simply. A zoo whose alerts were all failed logins would add little.
- **None of the three counts attacks caught.** That needs real labels, which the labels recorded in
  Review will provide.

## In one line

Lift says the zoo's alerts are worth reading first; it does not say they are attacks.
