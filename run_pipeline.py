"""Run Phases 1-7 of the log-anomaly pipeline for one log source.

  python run_pipeline.py --source pf                      # phases 1-7
  python run_pipeline.py --source auth --from-phase 4a    # 4a onwards (4d, 4e, 4f, 4g, 4h, 5, 6, 7, 7c)
  python run_pipeline.py --source ossec --with-model-zoo  # also 4b, 4c and 7b
  python run_pipeline.py --source pf --only-phase 7
  python run_pipeline.py --source pf --resume             # skip phases whose output exists
  python run_pipeline.py --source auth --dry-run          # print the commands only
  python run_pipeline.py --source pf --phase-args 3 "--dataset individual --verbose"
  python run_pipeline.py --source ipf                     # IPFilter (empty-baseline) source, phases 1-7

Phases (see README.md for what each one is for):

  1   classify      raw log lines -> one labelled event per line
  2   observations  events -> events, time windows, sessions, daily behaviour
  2c  coverage      every host and day: was the log collected, did the host log, was it up (per the other logs)
  3   features      observations -> numeric matrices, chronological train/validation/test split
  4a  detectors     robust deviation, Isolation Forest and novelty scores
  4b  model_zoo     many unsupervised models and a voting ensemble (--with-model-zoo)
  4c  model_zoo_map 2-D picture of the model-zoo alerts (--with-model-zoo)
  4d  silence       hosts that go silent while other logs show them up
  4e  first_seen    what a host does for the first time in the test period (no daily cap)
  4f  sequences     sequential pattern mining: ordered session/episode streams, the routine catalogue
                    and the sequence detector (auth and OSSEC)
  4g  activity      unusual amounts of activity (whole log, and per server, IP, user, destination),
                    from counts and timing only, ignoring what the lines say (auth and OSSEC)
  4h  profiles      every server, IP, user and destination's hourly activity against its own normal, for the
                    console's Profiles tab (every source; PF and IPFilter with the presence method's empty normal)
  5   evidence      Isolation Forest outliers traced back to their original log lines
  6   report        one self-contained HTML report
  7   alerts        flat alert CSVs per source (also silence and first-seen)
  7c  context       what the other logs know about each address in the alerts; rebuilds the report
  7b  clusters      every test row assigned a behavioural cluster from the 4c map (--with-model-zoo)

IPFilter (ipf) and PF use the PRESENCE method for Phases 2-6, built for logs
that are empty, or nearly, in normal operation: the scripts named presence.py
(presence_detectors.py for 4a), run with --source ipf|pf. Phase 1 stays per
source. These logs have no model zoo, map or clusters (4b, 4c, 7b are skipped
even with --with-model-zoo); their Phase 2 and 5 already do what 2c, 4d and 7c
do for auth and OSSEC, and their presence layer already judges activity, not
lines, which is what 4g adds for auth and OSSEC. PF keeps 4e (first seen); for IPFilter everything is new. See pipeline/phase4_detection/ipf_detectors.py for why.

Phase 8 (the maliciousness classifier) is run separately; see
pipeline/phase8_malice_classifier/README.md.

Each phase is a separate script run from the project root, so it can also be
run on its own. A transcript per phase goes to data/pipeline_runs/<source>/.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "pipeline" / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
SOURCES = {"auth": "authlog", "ossec": "ossec", "pf": "pflog", "ipf": "ipflog"}
LABELS = {"auth": "Authentication", "ossec": "OSSEC", "pf": "PF", "ipf": "IPFilter"}
# Phases a source does not have. The presence-method sources (ipf, pf) have no model zoo, and their
# Phase 2 and 5 already cover coverage, silence and context; for ipf everything is new, so no 4e either.
UNSUPPORTED = {"ipf": {"2c", "4b", "4bf", "4c", "4d", "4e", "4f", "4g", "7b", "7c"},
               "pf": {"2c", "4b", "4bf", "4c", "4d", "4f", "4g", "7b", "7c"}}
# Sources analysed with the presence method, and the scripts it uses instead of the per-source ones
PRESENCE_SOURCES = {"ipf", "pf"}
PRESENCE_SCRIPTS = {
    "2": "pipeline/phase2_observations/presence.py",
    "3": "pipeline/phase3_features/presence.py",
    "4a": "pipeline/phase4_detection/presence_detectors.py",
    "5": "pipeline/phase5_evidence/presence.py",
    "6": "pipeline/phase6_report/presence.py",
}
# (phase, name, script, extra arguments, part of the default run)
PHASES = [
    ("1", "classify", "pipeline/phase1_classify/{source}.py", [], True),
    ("2", "observations", "pipeline/phase2_observations/{source}.py", [], True),
    ("2c", "coverage", "pipeline/phase2_observations/coverage.py", ["--source", "{source}"], True),
    ("3", "features", "pipeline/phase3_features/{source}.py", [], True),
    ("4a", "detectors", "pipeline/phase4_detection/{source}_detectors.py", [], True),
    ("4b", "model_zoo", "pipeline/phase4_detection/{source}_model_zoo.py", [], False),
    ("4bf", "zoo_families", "pipeline/phase4_detection/zoo_families.py", ["--source", "{source}"], False),
    ("4c", "model_zoo_map", "pipeline/phase4_detection/model_zoo_map.py", ["--source", "{source}"], False),
    ("4d", "silence", "pipeline/phase4_detection/silence_detectors.py", ["--source", "{source}"], True),
    ("4e", "first_seen", "pipeline/phase4_detection/first_seen.py", ["--source", "{source}"], True),
    ("4f", "sequences", "pipeline/phase4f_sequences/run_sequences.py", ["--source", "{source}"], True),
    ("4g", "activity", "pipeline/phase4_detection/activity_detectors.py", ["--source", "{source}"], True),
    ("4h", "profiles", "pipeline/phase4_detection/activity_profiles.py", ["--source", "{source}"], True),
    ("5", "evidence", "pipeline/phase5_evidence/{source}.py", [], True),
    ("6", "report", "pipeline/phase6_report/{source}.py", [], True),
    ("7", "alerts", "pipeline/phase7_alerts/collect_alerts.py", ["--source", "{source}"], True),
    ("7c", "context", "pipeline/phase7_alerts/context.py", ["--source", "{source}"], True),
    ("7b", "clusters", "pipeline/phase7b_clusters/assign_clusters.py", ["--source", "{source}"], False),
]
ORDER = [phase for phase, *_ in PHASES]
# A phase counts as done (for --resume and --validate-outputs) when this file is non-empty.
EXPECTED = {
    "1": "data/phase1_classify/{source}/{prefix}_event_lookup.csv",
    "2": "data/phase2_observations/{source}/{prefix}_observation_dataset_summary.json",
    "2c": "data/phase2_observations/{source}/{prefix}_host_days.csv",
    "3": "data/phase3_features/{source}/feature_engineering_summary.json",
    "4a": "data/phase4_detection/{source}/detectors/experiment_summary.csv",
    "4b": "data/phase4_detection/{source}/model_zoo/model_zoo_summary.csv",
    "4bf": "data/phase4_detection/{source}/model_zoo/families_summary.csv",
    "4d": "data/phase4_detection/{source}/silence/experiment_summary.csv",
    "4e": "data/phase4_detection/{source}/first_seen/experiment_summary.csv",
    "4g": "data/phase4_detection/{source}/activity/experiment_summary.csv",
    "4h": "data/phase4_detection/{source}/profiles/profiles.sqlite",
    "5": "data/phase5_evidence/{source}/{prefix}_isolation_forest_outlier_export_summary.csv",
    "6": "data/phase6_report/{source}/{prefix}_threat_analysis_report.html",
    "7": "data/phase7_alerts/{source}/{prefix}_cumulative_isolation_forest_alerts.csv",
    "7c": "data/phase7_alerts/{source}/{prefix}_cross_source_context.csv",
    "7b": "data/phase7b_clusters/{source}/{prefix}_cluster_overview.csv",
}
EXPECTED_OVERRIDES = {
    ("auth", "4f"): "data/phase4_detection/auth/sequences/authentication_sessions/summary.json",
    ("ossec", "4f"): "data/phase4_detection/ossec/sequences/episodes/summary.json",
}


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", required=True, choices=sorted(SOURCES))
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--from-phase", choices=ORDER, default=ORDER[0])
    p.add_argument("--to-phase", choices=ORDER, default=ORDER[-1])
    p.add_argument("--only-phase", choices=ORDER)
    p.add_argument("--skip-phase", choices=ORDER, action="append", default=[])
    p.add_argument("--with-model-zoo", action="store_true", help="Also run phases 4b, 4bf, 4c and 7b (which need the model zoo).")
    p.add_argument("--phase-args", nargs=2, action="append", default=[], metavar=("PHASE", "ARGS"),
                   help='Extra arguments for one phase, e.g. --phase-args 3 "--dataset individual".')
    p.add_argument("--resume", action="store_true", help="Skip phases whose expected output already exists.")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--continue-on-error", action="store_true")
    p.add_argument("--validate-outputs", action="store_true", help="Fail a phase whose expected output is missing.")
    runlog.add_arguments(p)
    args = p.parse_args()
    if ORDER.index(args.from_phase) > ORDER.index(args.to_phase):
        p.error("--from-phase cannot come after --to-phase")
    for phase, _ in args.phase_args:
        if phase not in ORDER:
            p.error(f"--phase-args: unknown phase {phase!r}")
    return args


def log(message, level="INFO", quiet=False, always=False):
    runlog.emit(message, level, quiet=quiet, always=always)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def expected_output(source, phase):
    template = EXPECTED_OVERRIDES.get((source, phase)) or EXPECTED.get(phase)
    return ROOT / template.format(source=source, prefix=SOURCES[source]) if template else None


def complete(source, phase):
    path = expected_output(source, phase)
    return path is not None and path.is_file() and path.stat().st_size > 0


def selected(args):
    if args.only_phase:
        if args.only_phase in UNSUPPORTED.get(args.source, set()):
            raise SystemExit(f"Phase {args.only_phase} does not apply to {args.source}.")
        return [args.only_phase]
    first, last = ORDER.index(args.from_phase), ORDER.index(args.to_phase)
    chosen = []
    unsupported = UNSUPPORTED.get(args.source, set())
    for index, (phase, _, _, _, default) in enumerate(PHASES):
        if first <= index <= last and phase not in args.skip_phase and (default or args.with_model_zoo):
            if phase in unsupported:
                log(f"Phase {phase} does not apply to {args.source}; skipped", "SKIP", args.quiet)
                continue
            chosen.append(phase)
    return chosen


def run_process(command, transcript, quiet):
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("PYTHONIOENCODING", "utf-8")
    with open(transcript, "w", encoding="utf-8", errors="replace") as output:
        output.write("Command: " + " ".join(shlex.quote(x) for x in command) + "\n\n")
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace", bufsize=1)
        for line in process.stdout:
            output.write(line)
            output.flush()
            if not quiet:
                print(line, end="", flush=True)
        return process.wait()


def write_summary(folder, run_id, results, started, failures):
    folder.mkdir(parents=True, exist_ok=True)
    final = {"run_id": run_id, "ended_at_utc": utc_now(), "duration_seconds": round(time.perf_counter() - started, 3),
             "failures": failures, "records": results}
    temporary = folder / "pipeline_run_summary.json.tmp"
    temporary.write_text(json.dumps(final, indent=2), encoding="utf-8")
    os.replace(temporary, folder / "pipeline_run_summary.json")
    fields = ["phase", "name", "status", "start_utc", "end_utc", "duration_seconds", "exit_code", "command", "log_file"]
    with open(folder / "pipeline_run_summary.csv", "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


def main():
    args = parse_args()
    source, label = args.source, LABELS[args.source]
    runs = ROOT / "data" / "pipeline_runs" / source
    runs.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    extra = {phase: shlex.split(value) for phase, value in args.phase_args}
    steps = {phase: (name, script, arguments) for phase, name, script, arguments, _ in PHASES}
    plan = selected(args)
    results, failures, started = [], 0, time.perf_counter()
    log(f"{label} pipeline: phases {', '.join(plan)}", "START", args.quiet)

    for phase in plan:
        name, script, arguments = steps[phase]
        if source in PRESENCE_SOURCES and phase in PRESENCE_SCRIPTS:
            script, arguments = PRESENCE_SCRIPTS[phase], ["--source", "{source}"]
        script = ROOT / script.format(source=source)
        command = [args.python, "-u", str(script), *(a.format(source=source) for a in arguments), *extra.get(phase, [])]
        record = {"phase": phase, "name": name, "status": "pending", "start_utc": "", "end_utc": "",
                  "duration_seconds": 0, "exit_code": "", "command": " ".join(shlex.quote(x) for x in command),
                  "log_file": ""}
        if args.resume and complete(source, phase):
            record["status"] = "skipped_completed"
            results.append(record)
            log(f"Phase {phase} ({name}) skipped: {expected_output(source, phase).relative_to(ROOT)} exists",
                "SKIP", args.quiet)
            continue
        if not script.is_file():
            record.update(status="failed_missing_script", exit_code=127)
            results.append(record)
            failures += 1
            log(f"Phase {phase} script missing: {script}", "ERROR", args.quiet, True)
            if not args.continue_on_error:
                break
            continue

        phase_started = time.perf_counter()
        transcript = runs / f"{run_id}_phase_{phase}_{name}.log"
        record.update(start_utc=utc_now(), log_file=str(transcript.relative_to(ROOT)))
        log(f"Phase {phase} ({name})", "START", args.quiet)
        log("Command: " + record["command"], quiet=args.quiet)
        if args.dry_run:
            code, record["status"] = 0, "dry_run"
        else:
            code = run_process(command, transcript, args.quiet)
            record["status"] = "completed" if code == 0 else "failed"
        record.update(exit_code=code, end_utc=utc_now(), duration_seconds=round(time.perf_counter() - phase_started, 3))
        if (code == 0 and not args.dry_run and args.validate_outputs and phase in EXPECTED
                and not complete(source, phase)):
            code = 2
            record.update(exit_code=code, status="failed_output_validation")
            log(f"Phase {phase} finished but {expected_output(source, phase)} is missing or empty", "ERROR",
                args.quiet, True)
        results.append(record)
        if not args.dry_run:                 # a dry run must not replace the last real run's summary
            write_summary(runs, run_id, results, started, failures)
        if code:
            failures += 1
            log(f"Phase {phase} ({name}) | stage elapsed {runlog.format_duration(record['duration_seconds'])} | "
                f"exit code {code}; transcript {transcript}", "FAILED", args.quiet, True)
            if not args.continue_on_error:
                break
        else:
            log(f"Phase {phase} ({name}) | stage elapsed {runlog.format_duration(record['duration_seconds'])}", "DONE",
                args.quiet)

    if not args.dry_run:
        write_summary(runs, run_id, results, started, failures)
    if failures:
        log(f"{label} pipeline finished with {failures} failure(s). Rerun with --resume after fixing.", "FAILED",
            args.quiet, True)
        return 1
    log(f"{label} pipeline completed", "COMPLETE", args.quiet, True)
    log("Report: " + str(expected_output(source, "6").relative_to(ROOT)), "REPORT", args.quiet, True)
    log("Alerts: data/phase7_alerts/" + source, "REPORT", args.quiet, True)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main, heartbeat=False))        # each phase writes its own heartbeat
