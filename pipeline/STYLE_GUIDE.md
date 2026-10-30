# Pipeline style guide

The nomenclature, console output and command-line conventions every pipeline script follows. When a script and
this guide disagree, the script is wrong. Console output has one implementation, `pipeline/shared/runlog.py`; no
script formats its own log lines.

## 1. Nomenclature

### Phases

One folder per phase, `pipeline/phaseN_name/`, writing to `data/phaseN_name/<source>/`. The names are the ones
`run_pipeline.py` uses.

| Phase | Name | Script | Per source? |
|---|---|---|---|
| 1 | classify | `phase1_classify/<source>.py` | yes |
| 2 | observations | `phase2_observations/<source>.py` | yes |
| 2c | coverage | `phase2_observations/coverage.py` | shared |
| 3 | features | `phase3_features/<source>.py` | yes |
| 4a | detectors | `phase4_detection/<source>_detectors.py` | yes |
| 4b | model_zoo | `phase4_detection/<source>_model_zoo.py` | yes |
| 4c | model_zoo_map | `phase4_detection/model_zoo_map.py` | shared |
| 4d | silence | `phase4_detection/silence_detectors.py` | shared |
| 4e | first_seen | `phase4_detection/first_seen.py` | shared |
| 4f | sequences | `phase4f_sequences/run_sequences.py` | shared |
| 4g | activity | `phase4_detection/activity_detectors.py` | shared |
| 4h | profiles | `phase4_detection/activity_profiles.py` | shared |
| 5 | evidence | `phase5_evidence/<source>.py` | yes |
| 6 | report | `phase6_report/<source>.py` | yes |
| 7 | alerts | `phase7_alerts/collect_alerts.py` | shared |
| 7c | context | `phase7_alerts/context.py` | shared |
| 7b | clusters | `phase7b_clusters/assign_clusters.py` | shared |
| 8 | malice classifier | `phase8_malice_classifier/` | in progress |
| 9 | language-model triage | `phase9_llm_triage/` | needs a model |

The firewall logs (`pf`, `ipf`) use `presence.py` in place of the per-source script in Phases 2, 3, 4a, 5 and 6.
Shared scripts take `--source`.

Historical names are kept on purpose: the `EXPECTED_OBSERVATION_BUILDER`, `EXPECTED_FEATURE_PRODUCER` and
`EXPECTED_EXPERIMENT_RUNNER` constants name the pre-2026-09-29 scripts because existing outputs' metadata records
them. Do not rename them.

### Sources

| Key | File prefix | Label |
|---|---|---|
| `auth` | `authlog` | Authentication |
| `ossec` | `ossec` | OSSEC |
| `pf` | `pflog` | PF |
| `ipf` | `ipflog` | IPFilter |

### Views, splits and entities

- **Views** (Phase 2 onwards): `individual` (one event), `host_5min` (one server, five minutes),
  `authentication_sessions` (auth) or `episodes` (OSSEC), `host_behavior_1d` (one server, one day).
- **Splits**: `train`, `validation`, `test`, in time order, 70 / 15 / 15. Slides call `validation` *Calibrate*;
  code and data keep `validation`.
- **Entity types** (Phase 4g, 4h): `all` (written "whole log"), `server` (column `hostname`), `source_ip`,
  `username`, `destination_ip`.
- **Mechanisms**, as written in messages and documents: Sigma rules, robust deviation, novelty, Isolation Forest,
  model zoo, event order, activity detector, silence, first seen.

## 2. Console output

### Where

Every line goes to **stderr**, one record per line, flushed at once. Stdout is for data a caller reads (for
example JSON printed on request), never for progress.

### The line

```
2026-10-30 09:12:03 | runtime 00:01:23.4 | INFO    | DONE Reading events | stage elapsed 00:00:41.2
```

`<local date and time> | runtime <time since the run started> | <level, padded to 7> | <message>`

### Time

- **Every duration** (runtime, stage elapsed, progress elapsed, a duration inside a message) is written
  `HH:MM:SS.s`: hours at least two digits and unbounded, minutes and seconds two digits, tenths of a second.
  `00:00:04.2`, `01:15:03.0`, `27:00:00.0`. Never `4.2s`, `4m 05s`, `75m 03s` or `1h 02m`.
- Format a duration with `runlog.format_duration(seconds)`; never by hand.
- Measure with `time.monotonic()` (or `time.perf_counter()` for short timings); never `time.time()`.
- Clock times are local, `YYYY-MM-DD HH:MM:SS`, and come only from the line's own timestamp.

### Levels

| Level | Use | Shown |
|---|---|---|
| DEBUG | Every file, every skipped item, every decision | with `--verbose` |
| INFO | Stages, progress, counts, outputs written, heartbeats, the final line | by default |
| WARNING | Something odd that the run survives (a damaged archive, a missing optional input) | always |
| ERROR | A failure, an interruption, a run that stops | always |

`--quiet` shows warnings and errors only: a quiet run that goes well prints nothing.

### Fixed lines

| What | Level | Message |
|---|---|---|
| Stage start | INFO | `START <stage>` |
| Stage end | INFO | `DONE <stage> \| stage elapsed <HH:MM:SS.s>` |
| Stage failure | ERROR | `FAILED <stage> \| stage elapsed <HH:MM:SS.s>` |
| Progress | INFO | `<label>: <count>[/<total> (<share>)] \| elapsed <HH:MM:SS.s> \| <rate> per second` |
| Heartbeat | INFO | `Still running: <stage> \| stage elapsed <HH:MM:SS.s>[ \| <detail>]`, or `Still running` outside a stage |
| Library warning (numpy, scikit-learn, …) | WARNING | `<Category>: <text> (<file>:<line>)`, one line |
| Interruption | ERROR | `Interrupted by user` |
| End of run | INFO, or ERROR when not completed | `Run <completed\|stopped\|failed\|interrupted> \| total runtime <HH:MM:SS.s> (<seconds, 2 decimals> seconds)` |

- Progress lines and heartbeats come at most once every `--progress-interval` seconds (default 10).
- The end-of-run line is written on every exit: success, an early return, an error or Ctrl+C. `stopped` means the
  script returned a non-zero exit code; `failed` means an exception.
- `run_pipeline.py` relays each phase's lines as they come, so in its transcript the runtime column restarts with
  each phase (every script measures its own run); its own `START Phase …` and `DONE Phase …` lines carry the
  pipeline's runtime and each phase's elapsed time.
- `START`, `DONE`, `FAILED`, `SKIP` and `RESUME` are the only upper-case words at the start of a message. Other
  messages start with a capital letter and have no full stop.
- One record, one line: no indented sub-lines and no line breaks. A list of things is either one line
  (`Event types: A 12, B 3`) or one line per item, each naming what it is about (`2026-07: 1,234 events`).

### Message content

- **Counts only.** No log line, account name, address, host-specific value or other identifier appears in console
  output; say how many, never which. File paths are fine.
- Numbers have thousands separators (`26,085,863`); shares one decimal place (`21.7%`), two below 1%
  (`0.47%`); rates no decimals.
- `key=value` pairs for machine-readable details (`status=complete, rows=1,234`), separated by commas.
- Paths relative to the project root where possible.

## 3. Command line

Every script that runs on its own accepts the same three options, through `runlog.add_arguments(parser)`:

| Option | Meaning |
|---|---|
| `-v`, `--verbose` | Also DEBUG lines. `--debug` is accepted as an old name |
| `-q`, `--quiet` | Warnings and errors only. Cannot be combined with `--verbose` |
| `--progress-interval SECONDS` | Seconds between progress lines and heartbeats, a finite number above 0; default 10. `--progress-seconds` is accepted as an old name |

Exit codes: 0 success, 1 failure, 2 wrong arguments (argparse), 130 interrupted.

## 4. Using runlog

```python
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402

LOGGER = runlog.LOGGER


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    runlog.add_arguments(parser)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    with runlog.run(args) as outcome:                  # heartbeat, then the end-of-run line
        with runlog.stage("Reading events"):
            for row in runlog.progress_items(rows, "Events read", total=len(rows)):
                ...
        if problem:
            outcome["status"] = "stopped"
            return 1
    return 0
```

- A script whose `main()` already parses its own arguments can instead end with
  `raise SystemExit(runlog.main(main))`, which reads the three options from the command line and wraps the run.
- `runlog.log(message)` and `runlog.Log` keep older call sites working: they write the same lines. An old level
  word such as `"DONE"` or `"WARN"` becomes the standard level and, for the words in "Fixed lines", the message
  prefix.
- One script calling another's `main()` in the same process gets one heartbeat and one end-of-run line, from the
  outer run.

## 5. Checklist for a new or changed script

- [ ] No `print()` for progress; no hand-made timestamps or durations.
- [ ] `runlog.add_arguments(parser)`, and no other `--quiet`, `--verbose`, `--debug` or `--progress-*` option.
- [ ] Long steps inside `runlog.stage(...)`; long loops through `runlog.progress_items(...)` or `runlog.Progress`.
- [ ] The run inside `runlog.run(...)`, or the entry point through `runlog.main(main)`.
- [ ] Messages carry counts, never identifiers.
