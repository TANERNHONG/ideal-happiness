# Routines: how the sequence mining reads the logs

Every session in the logs is a short story told in a fixed order. Phase 4f learns those stories, spots the ones told
wrongly, and says why. This guide shows how, and what it found in a year of logs. For running it, see the
[Phase 4f notes](README.md).

1. **Clean**: one sentence per session, one word per event.
2. **Learn**: the routines that keep coming back, and the rules inside them.
3. **Score**: every new sentence by its least likely step.
4. **Flag**: the most surprising, within the alert budget, each with a reason in words.

## 1. Logs are sentences

Each event type is a word; each session (AUTH) or episode (OSSEC) is a sentence. The year's most common sentence:

`SSH_LOGIN_SUCCESS` → `SSH_DISCONNECT_RECEIVED` → `SSH_USER_DISCONNECTED`

An OSSEC scan, start to finish:

`OSSEC_ROOTCHECK_SCAN_STARTED` → `OSSEC_ROOTCHECK_SCAN_ENDED`

The sessions are Phase 2's own, rebuilt with Phase 2's own rules and checked one by one: same IDs, same events,
same train, validation and test months.

| Stage | AUTH | OSSEC |
|---|---|---|
| Events | 26,085,863 | 115,288 |
| Sessions | 9,475,862 | 29,447 |
| Different sentences | 306 | 77 |

## 2. Cleaning the sentences

| Problem | Fix | Found |
|---|---|---|
| Events in the same second come out in any order | Sort by time, then file, then line number (line 2 before line 10) | Every session |
| Rotated log files overlap, so a line is there twice | Merge the copy into the first, and keep a record of it | 290,396 AUTH lines, all in August 2025 |
| Same second, different files: the true order is unknown | Mark the step uncertain; never score it | 4,897 AUTH steps |
| 40 failed logins in a row drown the pattern | One "failed" word, with the 40 kept beside it | Every run |
| A session cut off by the start or end of the data | Mark it censored; leave it out of learning | 307 AUTH sessions |

## 3. Normal is tiny

Three sentences cover 98% of the training months' AUTH sessions.

| Routine | Share |
|---|---|
| `SSH_LOGIN_SUCCESS` → `SSH_DISCONNECT_RECEIVED` → `SSH_USER_DISCONNECTED` | 82.3% |
| `SSH_CONNECTION_CLOSED` | 11.1% |
| `SSH_LOGIN_SUCCESS` | 4.6% |
| The other 282 sentences | 2.0% |

## 4. Finding routines: PrefixSpan

PrefixSpan finds steps that happen in this order in many sentences, with other steps allowed in between. It grows
each pattern one step at a time:

1. Find the words that are common on their own.
2. For each, look only at what comes **after** it, in every sentence that has it.
3. What is common there becomes the pattern's next step.
4. Repeat until nothing after it is common enough.

A small example:

| Sentence | Sessions |
|---|---|
| `A` → `B` → `C` | 5 |
| `A` → `C` | 1 |
| `B` → `C` | 2 |

| Pattern | Found in |
|---|---|
| `C` | 8 |
| `B` → `C` | 7 |
| `A` → `C` | 6 |
| `A` → `B` → `C` | 5 |

- **Counted once, weighted**: identical sentences are stored once with their count, so 6.6 million sessions become
  285 sentences, and the counts stay true.
- **Closed only**: a pattern is kept only if no longer one is found in exactly as many sessions.
- **Common enough**: at least 0.5% of sessions and at least 20; at most 8 steps.
- **Per server**: one catalogue for all servers, and one for each.

## 5. Rules: after this, that

From each routine come rules: after A, how often does B follow?

| After | Comes | How often | Seen in |
|---|---|---|---|
| `SSH_DISCONNECT_RECEIVED` | `SSH_USER_DISCONNECTED` | 100% | 5,493,782 AUTH sessions |
| `OSSEC_CONNECTION_ATTEMPT` | `OSSEC_USING_IPV4` | 100% | 11,374 OSSEC episodes |
| `OSSEC_ROOTCHECK_SCAN_STARTED` | `OSSEC_ROOTCHECK_SCAN_ENDED` | 99.5% | 204 episodes on com1kco |

Rules at 95% or more are kept. A session that has A without B breaks a routine, and the alert says so.

## 6. The step model: what comes next

Like a phone guessing the next word: for every pair of event types, how often the second follows the first, on each
server and on all of them. The commonest path:

| From | To | Chance |
|---|---|---|
| start | `SSH_LOGIN_SUCCESS` | 87% |
| `SSH_LOGIN_SUCCESS` | `SSH_DISCONNECT_RECEIVED` | 94.5% |
| `SSH_DISCONNECT_RECEIVED` | `SSH_USER_DISCONNECTED` | 100% |
| `SSH_USER_DISCONNECTED` | end | 99.997% |

A quiet server has little history of its own, so its chances lean on all servers' (and an event type never seen in
training still gets a tiny chance, not zero).

## 7. Surprise, in bits

Each halving of a step's chance adds one bit of surprise. A session scores its single most surprising step.

| Chance | Surprise | Example |
|---|---|---|
| 1 in 2 | 1 bit | A coin toss |
| 1 in 450 | 8.8 bits | OSSEC's line |
| 1 in 1,000 | 10 bits | |
| 1 in 3,000 | 11.6 bits | AUTH's line |
| 1 in a million | 20 bits | |
| Never seen anywhere | 30+ bits | A message no server sent in training |

It catches a step never or rarely seen after the one before, and a routine that stops early: "ends right after a
login" is itself a rare step.

## 8. Where to draw the line

| Line | AUTH | OSSEC |
|---|---|---|
| Budget: about 10 alerts a day | 11.6 bits | 3.5 bits |
| Floor: rarer than 99.5% of training | 3.8 bits | 8.8 bits |
| Used: the higher of the two | 11.6 bits | 8.8 bits |
| Test alerts | 608 | 19 |

The budget is Phase 4's own. The floor stops it filling up with ordinary steps: OSSEC's budget alone would flag
steps as common as 1 in 11.

## 9. What it found

### OSSEC: 19 alerts, two incidents

| When | Server | What happened |
|---|---|---|
| 17 Jun, 01:55–02:11 | mm03kco | Steps never seen on this server, in its 02:00 window |
| 13 Jul, 02:06–02:28 | com1kco | The agent restarted again and again; a send failure no server sent in training |

### AUTH: 608 alerts, seven kinds

| Kind | Alerts | What it is |
|---|---|---|
| Worth a look | 57 | `su` sessions, invalid users, access denied, locked and empty-password logins, `authorized_keys` errors |
| New habit | 146 | Lone "connection closed" on the tc servers from 19 June: common on the com servers, never on tc before |
| Maintenance | 57 | sshd stopping and starting, on five days |
| Logins without a disconnect | 45 | devlkco, over 25 days |
| Two connections in one session | 30 | A login right after a disconnect, on the same port |
| Busy-server routine | 244 | Lone "subsystem not found": as common as in training, but 1 in 3,000 on servers with 2 million sessions |
| Other | 29 | |

### Compared with the other detectors

| Also flagged by | Alerts |
|---|---|
| All sequence alerts | 608 |
| Model-zoo consensus | 416 |
| Novelty | 56 |
| Isolation Forest | 0 |
| Only this detector | 192 |

## 10. Where the other alerts pile up

FP-growth (association rules) looks at every test session as a basket of plain facts (its server, the time of day,
which event types it has) and finds the combinations common among a detector's alerts. Lift says how many times more
likely an alert is with them than on average.

| Finding | Share |
|---|---|
| Isolation Forest session alerts on the `mm` servers | 100% |
| ... that contain an `SSH_DEPRECATED_OPTION` line | 98.7% |
| mm04kco's test sessions flagged by the model zoo | 66% |
| `mm` logins that end by going quiet, flagged by the model zoo | 94% |

The pile-up on the `mm` servers follows a few line types that are rare on quiet servers: a rare server, not rare
behaviour.

## 11. What it cannot do yet

- **No labels**: how often an alert is right is unknown until Review labels can be exported.
- **One step of memory**: the step model only looks at the event before.
- **Event types only**: no users or addresses, so guessing that looks like routine failures stays hidden.
- **Busy servers**: a habit that is regular but rare on a server with millions of sessions still scores high.
- **Phase 2's sessions**: it inherits their quirks, such as two connections on one port joined into one session.

## 12. Words

- **Sentence**: one session or episode, its event types in order.
- **Routine**: a sentence, or part of one, that keeps coming back.
- **Support**: how many sessions contain a pattern.
- **Confidence**: of the sessions with A, the share where B follows.
- **Bit**: one halving of the chance; 10 bits is about 1 in 1,000.
- **Budget**: the most alerts a detector may raise a day (Phase 4's rule).
- **Lift**: how many times likelier an alert is with some facts than on average.
- **Censored**: cut off by the start or the end of the data.
