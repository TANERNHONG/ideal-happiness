# Event logs: Phase 1 parser

A parser for the event log: one physical line, one event, in fixed-width columns. It applies only the rules
you have given, and every line those rules do not cover goes to an exceptions file for review. You then add a
rule and run it again. It is not yet part of `run_pipeline.py`; the console shows this document and the device types.

| File | What it is |
|---|---|
| `event_log_parser.py` | The parser. At the top are **the lists you fill in** (code 1, identifier 1, identifier 3), then the layout (`COLUMNS`) and the rules |
| `event_log.py` | The Phase 1 run: every line of every `.gz` under `event_logs/`, then the devices |
| `event_log_devices.py` | The devices, classified by the group of states each shows. At the top: **the state groups you fill in** (`STATE_GROUPS`) |
| `test_event_log.py` | 77 tests on made-up lines |
| `event_log_samples/` | Made-up sample lines (`*.log`), the settings they are read with (`sample_config.json`), and the expected output (`*.expected.json`) |

## Run it

From the project root (PowerShell):

```powershell
.\.venv\Scripts\python.exe pipeline\phase1_classify\event_log.py                       # data\phase0_raw\event_logs
.\.venv\Scripts\python.exe pipeline\phase1_classify\event_log.py --root "D:\Event Logs" --months "Dec 25"
.\.venv\Scripts\python.exe pipeline\phase1_classify\event_log.py --verbose --progress-interval 5
.\.venv\Scripts\python.exe pipeline\phase1_classify\event_log.py --workers 1                         # one file after another
.\.venv\Scripts\python.exe pipeline\phase1_classify\event_log_devices.py               # the devices alone, after changing STATE_GROUPS
.\.venv\Scripts\python.exe -m unittest discover -s pipeline\phase1_classify -p test_event_log.py -v
```

Progress goes to stderr as in every pipeline script (`pipeline/STYLE_GUIDE.md`, written by `pipeline/shared/runlog.py`): one timestamped line at a time, each with the runtime so far.

- **Default:** each stage's `START` and `DONE` with its time, and every month's counts. Also lines read so far
  with their rate, plus a heartbeat naming the current stage, both every `--progress-interval` seconds. The total
  runtime comes at the end, also after an error or an interruption.
- **`--verbose`:** also every file (read, already processed, or a repeat) and every path left out.
- **`--quiet`:** only warnings and errors.

No log line, identifier value or user name is ever logged.

| Option | Meaning |
|---|---|
| `--root` | The folder holding the month folders (`Dec 25/`) or year folders (`2025/Dec 25/`). Default `data/phase0_raw/event_logs` |
| `--output` | Default `data/phase1_classify/event_log/` (excluded from git) |
| `--months` | Only these months, in any form of a folder name or as `YYYY-MM` (`"Dec 25"`, `"Sept-25"`, `2025-09`) |
| `--strict` | Unknown units, states and limit codes are errors (default: kept, with a warning) |
| `--config` | A JSON file of settings overriding the defaults and the lists |
| `--encoding` | Default `utf-8` |
| `-v`, `--verbose` | Also every file and every path left out |
| `-q`, `--quiet` | Only warnings and errors (not with `--verbose`) |
| `--progress-interval` | Seconds between progress lines and heartbeats. Default 10 |
| `--workers` | Files read at once, each by its own process (default: one per core but one, at most 4; `1`: one after another). The outputs are the same either way. Each worker adds about 30 MB of memory, which does not grow with the size of the logs: a file is streamed line by line to part files on disk, then the month's outputs are put together from them in file order |

### Files already processed

`event_log_processed.json` records each `.gz` file:
- its SHA-256;
- a fingerprint of the parser code and settings it was read with (your lists included);
- what was read: lines, status counts, exceptions, and the values not in your lists yet.

On the next run:
- **An unchanged file** (same content, same code and settings) is not read again. Its rows are copied from the
  month's previous outputs, in their place, so the outputs match a full run's.
- **A new or changed file** is read.
- **A change to the parser, the settings or a list** means every file is read again, so every line follows the
  current rules.
- **A file with the same content as another** (the same file delivered twice) is a repeat. It is left out and
  listed in `event_log_exceptions_paths.csv`.
- **A month whose outputs are missing, or don't match the recorded row counts**, is written again.

To read everything again, delete `event_log_processed.json`. It holds no user names. It does hold the values
not in your lists yet, as `event_log_unclassified_values.csv` does.

## What a run writes

| File | For |
|---|---|
| `event_log_exceptions_<YYYY-MM>.csv` | **Every line no rule covers yet**: an error, or any warning other than *unclassified*. Each row has its file and line number, the codes, the reasons, and the line itself. Review these, then add rules. |
| `event_log_exceptions_paths.csv` | Folders and files left out (a name outside the layout, a file that is not `.gz`, a repeat of another file) and damaged archives, with the reason |
| `event_log_unclassified_values.csv` | The code 1, identifier 1 and identifier 3 values not in your lists yet, the most lines first: what to add next |
| `event_log_events_<YYYY-MM>.csv` | Every line, whatever its status: every field, the original line, the timestamp in UTC+8 and in UTC. The only file with a `user_name` column |
| `event_log_issues_<YYYY-MM>.jsonl` | Every warning and error in full, with character positions |
| `event_log_summary.json` | Lines, statuses and exceptions per month, issue counts, lines with a user name (a count only), files read now, already processed and repeated, the settings used (identifier lists as counts only) |
| `event_log_processed.json` | What was read from each file, so that it is not read again (see *Files already processed*) |
| `event_log_devices.csv` | One row per device: its fields, lines, the states it shows (lines each), its status and group (see *Devices*) |
| `event_log_devices_review.csv` | **The devices no group covers yet**, with the reason: for review |
| `event_log_state_sets.csv` | The states the devices for review show together, the most devices first: **the groups to add next** |
| `event_log_devices_summary.json` | Counts only: devices per status and per group, the groups used. The console's *Event log device types* page shows them |

Statuses:
- `parsed`: every rule holds.
- `unclassified`: a code 1, identifier 1 or identifier 3 is not in its list yet. This is not an exception; those
  values go to the unclassified-values file.
- `parsed_with_warnings`: an unknown unit, state or limit code was kept.
- `invalid`: a rule is broken, or the line is one of `ANOMALY_LINES` (its own code alone; no field is read).
- `message`: a system message rather than an event: the line's text begins with `Command Failure :`
  (`message_prefixes`). Its text, with spaces collapsed, is in the `message` column, and no field is read. It is
  not an exception. A **GONG line** is a message too (see *Rules as decided*): its date and time make the timestamp,
  and its alarm type (`ALMTYPE0` to `ALMTYPE7`, or `SYSTEM`), O and N counts (`ALMTYPE0`-`7` only) and user name go to `alarm_type`,
  `o_count`, `n_count` and `user_name` (the `message` column leaves the user name out).

`parsed_with_warnings` and `invalid` lines are listed in the exceptions file.

## Devices, by their states

The event log gathers the events of many kinds of device. A **device is one signal**: one code 1, code 2,
identifier 1, identifier 2, location and identifier 3. Every event of a device uses the states of **one group**: a
pair (`ON`/`OFF`) or a larger group (Transformer: `01` to `20`). So the states a device shows, over all its lines and months, say
which group it belongs to, and that group classifies it.

At the end of each run, `event_log_devices.py` reads every month's events file, leaving out invalid lines and system
messages, and gives each device one status:

| Status | The device's states | For review |
|---|---|---|
| `grouped` | all in one group, and only one: the device's group | no |
| `ambiguous` | all in more than one group (`STOP` alone: `RUN`/`STOP` or `START`/`STOP`); more lines may settle it | yes |
| `ungrouped` | one or more in no group yet | yes |
| `mixed` | each in a group, but no one group holds them all (`ON`, `OFF`, `FAULT`) | yes |
| `no_state` | none: no line of it has a state | yes |

`STATE_GROUPS`, at the top of `event_log_devices.py`: `ON`/`OFF`, `OPEN`/`CLOSE`, `RUN`/`STOP`, `UP`/`DOWN`,
`START`/`STOP`, `OK`/`FAULT`, and Transformer: `01` to `20`. Each group has a name: the device's type in the
device files and the console. To add a group, take a line of `event_log_state_sets.csv` (its
`states` column is written like a group: `LOCAL/REMOTE`) and run `event_log_devices.py` alone: it reads only the
events files, so nothing is parsed again. Each state of a group must be in `STATES`, in upper case.

In the console (Documentation, The pipeline): [Event log device types](event_log_devices.py), built from
`STATE_GROUPS` when opened, with the counts of the last run.

## The lists you fill in

At the top of `event_log_parser.py`: `CODE_1_VALUES`, `IDENTIFIER_1_VALUES`, `IDENTIFIER_3_VALUES`.

- One string per value, in plain text.
- Matching is exact and case-sensitive, like a password: `Fan 4` and `FAN  4` (two spaces) do not match `FAN 4`.
- No message, log or summary prints these lists.
- Code 2 and identifier 2 are not listed: any value of the right characters is accepted, or a blank.
- `IDENTIFIER_2_WITH_SYMBOLS` (for now: `FA_Z6&7`): identifier 2 values accepted although they have a character other
  than letters, digits, `_` and `-`. Exact; the summary shows only how many there are.
- `IDENTIFIER_3_STATES` (`MV_U`, `HUMID`, `MV-PF`): identifier 3 values that are states. Once a line is parsed
  (postprocessing), such a value moves to `state`, replacing any state the line had, and identifier 3 is left blank.
  Each is in `IDENTIFIER_3_VALUES` too, so the line is classified first. A state group may use them.
- `IDENTIFIER_3_KEYWORDS` (`Contactor Energise`, `Live`): an identifier 3 that contains one of them anywhere, in
  exact case, is classified as if listed. This covers numbered points such as `E12Contactor Energise` and
  `E27_E28 Live` without an entry for each.
- An identifier 3 that is not in `IDENTIFIER_3_VALUES`, contains no keyword and is all lowercase is a user's name, so it is not a value
  to add. It goes to `user_name`, and identifier 3 stays blank. A lowercase value you add to the list stays
  identifier 3. When the limit code column holds a different all-lowercase word, that one is the user name and
  identifier 3 keeps its text (unclassified until listed).
- `ANOMALY_LINES`: a line whose whole text (blanks at either end aside) is one of these, exactly, is an
  anomaly with its own code (the first: `IM_LINE`). It is `invalid` with that code alone and listed in the
  exceptions file. The summary shows only how many there are.
- Each list is grouped by assumed function (power, HVAC, switchgear, ...), with `Others` for the rest. The groups
  are for reading only and do not affect matching.

## The layout (measured on the sample `event_logs/Dec 25/`, 2026-10-19)

Every line is exactly 132 characters. Positions count from 0, and each span includes its start and end.

- **Prefix to triplet** are cut at their positions.
- **From code 1 on**, each word goes, whole, to the column it starts in. A word is never split, so a field that
  drifts a little, or runs past its column, still lands in the right place.
- **Identifier 2 and the location** have no gap between them, so there a word running past position 54 is cut,
  as measured.

| Field | Positions | Rule |
|---|---|---|
| prefix | 0–1 | `A` at 0, `G` at 1 (against the date: ` G02/02/25`), both (`AG02/02/25`), or blank |
| date | 2–9 | `DD/MM/YY`, a real date, 20xx |
| time | 11–18 | `HH:mm:ss`, 24-hour, UTC+8 |
| numeric triplet | 20–27 | three numbers, each right-aligned in 2 characters, between slashes (` 1/51/21`); may be blank |
| code 1 | 29–31 | two to six uppercase letters (a longer one runs on past its column); classified by `CODE_1_VALUES`; may be blank |
| code 2 | 33–35 | two to six uppercase letters (a longer one runs on past its column); may be blank |
| identifier 1 | 37–44 | letters, digits, `_`, `-`; classified by `IDENTIFIER_1_VALUES`; may be blank |
| identifier 2 | 46–54 | letters, digits, `_`, `-`, or a value of `IDENTIFIER_2_WITH_SYMBOLS` (may fill all 9 characters, touching the location); may be blank. One word: any more words that start in its column begin the location early (`TSS BGS-LVR`: `TSS`, `BGS-LVR`; `TSS MRB`: `TSS`, `MRB`; `LSC01 TVS OCC`: `LSC01`, `TVS OCC`) |
| location | 55–74 | any text; may be blank |
| identifier 3 | 76–105 | letters, digits, spaces between words, and `- * ( ) _ / & .`; classified by `IDENTIFIER_3_VALUES` or `IDENTIFIER_3_KEYWORDS`; otherwise, if all lowercase: a user name (`user_name`), unless the limit code column holds a different one; may be blank |
| *reading:* identifier 3 | 76–84 | as above |
| *reading:* unit | 85–88 | `A`, `DEGC`, `V`, `%`, `L/S`, `KV`; `-` means no unit |
| *reading:* number 1 | 89–95 | right-aligned to 95: digits, with a minus sign and a decimal point if any (`-483.5`), never a plus; `****.*` means no value |
| *reading:* number 2 | 96–102 | right-aligned to 102, the same |
| state | 107–114 | `APP`, `DISP`, `STOP`, `ON`, `NO`, `RUN`, `OFF`, `CLOSE`, `OPEN`, `YES`, `LOCAL`, `REMOTE`, `UP`, `DOWN`, `START`, `OK`, `FAULT`, `COMPLETE`, `UNTAG`, `INCONSIS`, `REVERSE`, `FORWARD`, `LOGON`, `LOGOFF`, `TAG`, `ONLINE`, `OFFLINE`, `NOTCON`, `EMPTY`, `ACTIVE`, `RUNUP`, `UNREACH`, `DEGRADED`, `END`, `PRI`, `SEC`, `SPAD`, `ADM`, `STDBY`, `COM`, `TC`, `RELEASED`, `FAULTY`, `LOCKED`, `MANUAL`, `AUTO`, `POWCON`, `PARALLEL`, `FALSE`, `TRUE`, `INDIVIDU`, `RESTORE`, `01`, `02`, `03`, `04`, `05`, `06`, `07`, `08`, `09`, `10`, `11`, `12`, `13`, `14`, `15`, `16`, `17`, `18`, `19`, `20`, `LEVEL2`, `ADSP`, `MMI`, `SCBKWH`, `NOTREADY`, `NO SOURC`, `NOT SYNC`, `SLAVE`, `MASTER`, `DISTURBE`; matched in any case and stored in upper case; `cPOWCON` is read as `POWCON` and `cSCBKWH` as `SCBKWH` (`STATE_SPELLINGS`); a space only in a listed state; may be blank |
| limit code | 116–131 | starts with `L1`, `U1`, `L2`, `U2`, `WE`, `MU`, `NT`, `AL`, `NE` or `W*` (an asterisk, as written); any text after the code (with or without a space) is kept as `limit_suffix`; may be blank. A state here (as written, or `cPOWCON`) means no limit code: it is the state when the state column is blank or holds the same state. An all-lowercase word here is a user name (`user_name`) |

Up to code 1, every other position must be blank. From code 1 on, a word may run across the gap after its column,
but a word that starts in a gap is an exception (`WORD_BETWEEN_COLUMNS`). Text past position 131 is an error.

A line is a **reading** when one word starts in the unit column, nothing runs across position 84, and both numbers
end exactly at 95 and 102. Otherwise identifier 3 is every word that starts in 76–105.

## Rules as decided

| Rule | From |
|---|---|
| One line, one event; keep the original line; never split the whole line on whitespace | the instructions |
| From code 1 on, each word goes, whole, to the column it starts in | your answer, 2026-10-19 |
| `****.*` in a reading's number column means no value, not an error | your answer, 2026-10-19 |
| The prefix is `A` at position 0, or blank | answer 1 |
| The prefix may also be `G`, at position 1 against the date, alone or after `A` (`AG`) | your answers, 2026-10-19 |
| The triplet is 8 characters, numbers right-aligned in 2 | answer 2 |
| Codes are two to six uppercase letters | answers 4 and 13 (round 3); your requests, 2026-10-19 |
| Identifiers: letters and digits, plus the symbols seen (`_ -` for 1 and 2; `- * ( ) _ / & .` and spaces for 3) | answer 4, then the sample review |
| An identifier 2 with another symbol is accepted only when listed in `IDENTIFIER_2_WITH_SYMBOLS` (`FA_Z6&7`, for now) | your request, 2026-10-19 |
| Numbers may have decimals | the sample review (answer 6–7 changed) |
| Numbers may have a minus sign (never a plus) | your answer, 2026-10-19 |
| Units: `A`, `DEGC`, `V`, `%`, `L/S`, `KV`; `-` means no unit; any other unit with a symbol is an error | the instructions, the sample review, your request |
| May be blank: triplet, code 1, code 2, identifiers 1, 2 and 3, location, unit, numbers, state, limit code. Required: everything else | answer 12, round 3, the sample review; codes 1 and 2, identifiers 1 to 3, state: your requests, 2026-10-19 |
| A space in identifier 2's column: identifier 2 is the first word, the location is the rest | your answers, 2026-10-19 |
| A state in the limit code column: no limit code; the state, if the state column is blank or the same (different: `TWO_STATES`) | your answer, 2026-10-19 |
| An all-lowercase word in the limit code column is a user's name | your request, 2026-10-19 |
| When identifier 3 and the limit code column hold different all-lowercase text, the limit code's is the user's name and identifier 3's stays identifier 3 | your answer, 2026-10-19 |
| Two-digit years are 20xx; times are UTC+8 | answers 11 and 18 |
| A month folder holds that month only (`DATE_OUTSIDE_FOLDER_MONTH`) | answer 17 |
| Month folders are `Mmm YY` (three letters); others are left out and listed | the instructions |
| A month folder's name is normalized to `YYYY-MM`: the month whole or its first three letters or more, in any case (`Sep`, `Sept`, `SEPT`, `September`); a space, dash, underscore or nothing; a two- or four-digit year (`Dec 25`, `Sept-25`, `september_2025`, `SEP2025`). Two folders of one month are read as one. `--months` takes any of these forms, or `YYYY-MM` | your request, 2026-10-21 |
| Lenient by default: unknown units, states and limit codes are kept with a warning (and listed as exceptions) | answer 13 |
| States also include `YES`, `LOCAL`, `REMOTE`, `UP`, `DOWN`, `START`, `OK`, `FAULT`, `COMPLETE`, `UNTAG`, `INCONSIS`, `REVERSE`, `FORWARD`, `LOGON`, `LOGOFF`, `TAG`, `ONLINE`, `OFFLINE`, `NOTCON`, `EMPTY`, `ACTIVE`, `RUNUP`, `UNREACH`, `DEGRADED`, `END`, `PRI`, `SEC`, `SPAD`, `ADM`, `STDBY`, `COM`, `TC`, `RELEASED`, `FAULTY`, `LOCKED`, `MANUAL`, `AUTO`, `POWCON`, `PARALLEL`, `FALSE`, `TRUE`, `INDIVIDU`, `RESTORE`, `01`, `02`, `03`, `04`, `05`, `06`, `07`, `08`, `09`, `10`, `11`, `12`, `13`, `14`, `15`, `16`, `17`, `18`, `19`, `20`, `LEVEL2`, `ADSP`, `MMI`, `SCBKWH`, `NOTREADY`, `NO SOURC`, `NOT SYNC`, `SLAVE`, `MASTER`, `DISTURBE` (written `disturbe`; for now) | your requests, 2026-10-19 |
| A state in the state column is matched in any case and stored in upper case | your answer, 2026-10-19 |
| `cPOWCON` is read as `POWCON` and `cSCBKWH` as `SCBKWH`; what the `c` means is to be found out (remark in `STATE_SPELLINGS`) | your request and answer, 2026-10-19 |
| States come in groups: pairs (`ON`/`OFF`, `OPEN`/`CLOSE`, `RUN`/`STOP`, `UP`/`DOWN`, `START`/`STOP`, `OK`/`FAULT`) and larger groups (Transformer: `01` to `20`, your note of 2026-10-21); `other_states()` gives the rest of a state's groups (`STOP` → `RUN`, `START`) | the instructions, your requests (groups: 2026-10-21) |
| Every event of one device uses one group of states, which classifies the device; a device is one signal (code 1, code 2, identifiers 1 and 2, location, identifier 3) | your request and answer, 2026-10-21 |
| Limit codes also include `WE`, `MU`, `NT`, `AL`, `NE`, `W*`, and any text may follow a limit code | your requests, 2026-10-19 |
| A line whose text begins with `Command Failure :` is a system message (status `message`), whatever follows | your answer, 2026-10-19 |
| A line with `GONG APPEAR TONE` after its date and time is a message with fields, in one of two forms, any whitespace between the words (`GONG_MESSAGE`): `GONG APPEAR TONE ALMTYPE<0 to 7> O: <count> N: <count> <user name>` (`ALMTYPE0` to `ALMTYPE7`), or `GONG APPEAR TONE SYSTEM <user name>` (`alarm_type` `SYSTEM`, no counts); the triplet is read when it ends before it; other text before it, another form, or no date and time first: `INVALID_GONG_LINE` | your answers, 2026-10-21 |
| A line in `ANOMALY_LINES` is an anomaly with its own code, and nothing else is read from it | your request, 2026-10-19 |
| Code 1, identifier 1 and identifier 3 are classified by your lists; anything else is *unclassified* | your request |
| An identifier 3 not in its list and all lowercase is a user's name (`user_name`, events file only) | your answer, 2026-10-19 |
| `MV_U`, `HUMID`, `MV-PF` are identifier 3 values, then, after parsing, the state (`IDENTIFIER_3_STATES`): identifier 3 left blank, any state the line had replaced | your request and answers, 2026-10-21 |
| An identifier 3 containing `Contactor Energise` or `Live` (exact case) is classified without being listed | your request, 2026-10-19 |

To accept a new unit, state or limit code, add it to `allowed_units`, `allowed_states` or `allowed_limit_codes`
with `--config`. To change the layout, give `columns`, `reading_columns` or `line_width`.

## Exceptions in the sample (Dec 25, 63,884 lines)

Counts only, from the run before the later states, limit codes and `L/S` were added; run it again for current counts:

| Lines | Code | What it is |
|---:|---|---|
| 12,111 | `UNKNOWN_STATE` | a state outside the first 9 (before the later states were added) |
| 857 | `UNKNOWN_LIMIT_CODE` | a limit code outside the first 4 (before `WE`, `MU` were added) |
| 756 | `INVALID_IDENTIFIER_2` | a space inside identifier 2's column (the text runs on into the location) |
| 190 | `EXTRA_TRAILING_CONTENT` | a word in positions 119–126 (now read as text after the limit code) |
| 154 | `MISSING_IDENTIFIER_2` | identifier 2 blank (allowed since 2026-10-19, so no longer an exception) |
| 43 | `MISSING_SEPARATOR` + `INVALID_CODE_2` | one 6-letter word across both code columns |
| 33 / 16 | `MISSING_IDENTIFIER_1` / `_3` | blank |
| 12 | `INVALID_NUMBER_1` + `_2` | `****.*` where the numbers belong |
| 4 | `INVALID_UNIT_OR_TYPE` | a unit with `/` (before `L/S` was added) |
| 1 | date, time, code 1, state | one line that is not an event |

In total, 13,416 lines are in the exceptions file. Another 32,746 lines are unclassified.

## Issue codes

Errors: `EMPTY_LINE`, `UNEXPECTED_LINE_WIDTH`, `EXTRA_TRAILING_CONTENT`, `MISSING_SEPARATOR` (up to code 1),
`WORD_BETWEEN_COLUMNS` (from code 1 on), `INVALID_PREFIX`,
`INVALID_DATE_FORMAT`, `INVALID_CALENDAR_DATE`, `INVALID_TIME_FORMAT`, `INVALID_TIME_VALUE`,
`INVALID_NUMERIC_TRIPLET`, `INVALID_CODE_1` / `_2`, `INVALID_IDENTIFIER_1` / `_2` / `_3`,
`INVALID_UNIT_OR_TYPE`, `INVALID_NUMBER_1` / `_2`, `INVALID_STATE`, `INVALID_LIMIT_CODE`, `MISSING_<FIELD>` (a
required field blank), `INVALID_GONG_LINE`, `INVALID_ENCODING` (the run only), and each code in `ANOMALY_LINES` (`IM_LINE`).

With `--strict`, `INVALID_STATE`, `INVALID_LIMIT_CODE` and `INVALID_UNIT_OR_TYPE` replace the unknown-value
warnings, and `DATE_OUTSIDE_FOLDER_MONTH` becomes an error.

Warnings: `UNKNOWN_UNIT_OR_TYPE`, `UNKNOWN_STATE`, `UNKNOWN_LIMIT_CODE`, `DATE_OUTSIDE_FOLDER_MONTH`,
`BYTE_ORDER_MARK`, `TWO_STATES`, and `UNCLASSIFIED_CODE_1` / `_IDENTIFIER_1` / `_IDENTIFIER_3`. The unclassified warnings
are not exceptions.

Each issue has a code, a message, the field, the value and its character positions in `raw_line`.
