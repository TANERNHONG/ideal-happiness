"""Phase 4f step 3 (scoring): the sequence detector, under the same alert budget as the other detectors.

  .venv/Scripts/python.exe pipeline/phase4f_sequences/score.py --source ossec

Scores every validation and test observation (AUTH session, OSSEC episode) against what mine.py
learned from training, and writes a Phase 4 run that Phase 7 collects like the others:

    data/phase4_detection/<source>/sequences/<dataset>/
        validation_scores.csv, test_scores.csv   every observation, with sequence_score / sequence_alert
        test_alerts.csv                          the test alerts only, most unusual first, explained
        summary.json                             threshold, its source and the counts

The score is the surprise of the observation's rarest step: -log2 of the probability of that step
(event type B after event type A, or starting or ending with it) on this host, learned from training
and smoothed towards all hosts, then towards how common B is at all. 10 bits means about 1 in 1,000.
So it catches steps never or rarely seen after the previous one, and routines that end early (the
step to the end is rare). The mean surprise per step is added at 1/1000 weight to break ties. Steps
of uncertain order are not scored; nor is the start of a left-censored or the end of a right-censored
observation.

Each alert is explained in words: the rarest step with its odds, any "usually followed by" rule the
observation breaks (rules.csv), and whether this exact sequence never occurred on the host in training.

The threshold uses the existing alert budget (decision 2026-10-08): Phase 4's own choose_threshold
for the view, with its alerts-per-day target and population cap on the validation split; test data
never sets anything. It is then raised, if needed, to the training 99.5% quantile, Phase 4's
TRAINING_QUANTILE_IS_FLOOR option (off for the other detectors). The budget is a ceiling on
workload; these scores are discrete (identical sequences score alike), and filling the ceiling would
reach steps as common as 1 in 11 (OSSEC, 2026-10-08). So this detector can only use less of the
budget, never more.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import math
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (BEGIN, DETECTION_OUTPUT, END, ROOT, SOURCES, load_sequences, open_store,  # noqa: E402
                    positions, read_json, routine_folder, write_json)
from mine import contains, training_groups  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

HOST_PRIOR = 10.0          # how many observations' worth of the all-hosts estimate a host's estimate starts from
GLOBAL_PRIOR = 1.0         # the same, from all hosts towards how common the next step is at all
TIE_WEIGHT = 0.001
BASELINE_QUANTILE = 0.995  # the training-quantile fallback, as in Phase 4
VIEW = {"auth": {"time": "session_start", "id": "authentication_session_id", "detectors": "auth_detectors.py"},
        "ossec": {"time": "episode_start", "id": "episode_id", "detectors": "ossec_detectors.py"}}
STEPS_SHOWN = 40


log = runlog.log


class Model:
    """First-order step probabilities per host, smoothed towards all hosts and the overall step frequency."""

    def __init__(self, payload):
        self.table = payload["transitions"]
        self.overall = self.table.get("*", {})
        unigrams = payload["unigrams"]
        self.vocabulary = len(unigrams) + 1                       # +1: an event type never seen in training
        self.total = sum(unigrams.values())
        self.unigram = {token: (count + 1) / (self.total + self.vocabulary) for token, count in unigrams.items()}
        self.unseen = 1 / (self.total + self.vocabulary)
        self.sums = {scope: {prev: sum(nexts.values()) for prev, nexts in table.items()} for scope, table in self.table.items()}

    def probability(self, previous, following, host):
        base = self.unigram.get(following, self.unseen)
        overall = self.overall.get(previous, {})
        p_all = (overall.get(following, 0) + GLOBAL_PRIOR * base) / (self.sums["*"].get(previous, 0) + GLOBAL_PRIOR)
        local = self.table.get(host, {}).get(previous)
        if not local:
            return p_all
        return (local.get(following, 0) + HOST_PRIOR * p_all) / (self.sums[host][previous] + HOST_PRIOR)

    def describe(self, previous, following, host, p):
        """The step's odds in words, from the training counts behind it."""
        if following != END and following not in self.unigram:
            return f"{following} never occurred in training"
        here = self.table.get(host, {}).get(previous, {}).get(following, 0)
        anywhere = self.overall.get(previous, {}).get(following, 0)
        if anywhere == 0:
            return "never seen in training on any host"
        if here == 0 and self.sums.get(host, {}).get(previous, 0) > 0:
            return f"never on {host} in training (seen {anywhere:,} times on other hosts)"
        return f"{odds(p)} on {host}"


def load_rules(path):
    rules = defaultdict(list)
    if path.is_file():
        with open(path, encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                antecedent = tuple(row["antecedent"].split(" > "))
                rules[row["scope"]].append((antecedent, row["then"], float(row["confidence"])))
    return rules


def odds(p):
    return f"1 in {max(1, round(1 / p)):,}" if p > 0 else "never"


def score_one(tokens, host, uncertain, left, right, model, rules, seen):
    """(score, rarest step text, its probability, mean surprise, unseen, broken rules, explanation)."""
    steps = (BEGIN,) + tokens + (END,)
    surprises, worst = [], (-1.0, None, 1.0)
    for k in range(1, len(steps)):
        if (k == 1 and left) or (k == len(steps) - 1 and right) or (k - 1) in uncertain:
            continue
        p = model.probability(steps[k - 1], steps[k], host)
        bits = -math.log2(p)
        surprises.append(bits)
        if bits > worst[0]:
            worst = (bits, (steps[k - 1], steps[k]), p)
    if not surprises:
        return 0.0, "", 1.0, 0.0, False, "", "no step with a known order"
    mean = sum(surprises) / len(surprises)
    score = worst[0] + TIE_WEIGHT * mean
    previous, following = worst[1]
    step = f"{'(start)' if previous == BEGIN else previous} > {'(end)' if following == END else following}"
    scope = host if host in rules else "all hosts"
    broken = [] if right else [(a, then, c) for a, then, c in rules.get(scope, []) if contains(tokens, a) and not contains(tokens, a + (then,))]
    unseen = (host, tokens) not in seen
    parts = [f"rarest step {step}: {model.describe(previous, following, host, worst[2])}"]
    parts += [f"after {' > '.join(a)}, {then} usually follows ({c:.1%}), not here" for a, then, c in broken[:2]]
    if unseen:
        parts.append("this sequence never occurred on this host in training")
    return (score, step, worst[2], mean, unseen,
            "; ".join(f"{' > '.join(a)} => {then}" for a, then, _ in broken), "; ".join(parts))


def detectors_module(source):
    path = ROOT / "pipeline/phase4_detection" / VIEW[source]["detectors"]
    spec = importlib.util.spec_from_file_location(f"phase4_{source}_detectors", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def budget_threshold(source, dataset, scores, starts, training_threshold):
    """Phase 4's own validation-budget threshold for this view (auth and OSSEC take different arguments)."""
    module = detectors_module(source)
    if source == "auth":
        days = len({datetime.fromtimestamp(s, tz=timezone.utc).date() for s in starts})
        return module.choose_threshold(dataset, scores, days, training_threshold)
    manifest = pd.DataFrame({VIEW[source]["time"]: [text_time(s) for s in starts]})
    return module.choose_threshold(dataset, scores, manifest, training_threshold)


def text_time(epoch):
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def weighted_quantile(values, weights, q):
    order = np.argsort(values)
    values, weights = np.asarray(values)[order], np.asarray(weights, dtype=float)[order]
    cumulative = np.cumsum(weights) / weights.sum()
    return float(values[min(np.searchsorted(cumulative, q), len(values) - 1)])


UNIT_COLUMNS = ["row_manifest_id", "host_id", "start_epoch", "close_reason", "event_count", "kept_count", "merged_copies",
                "left_censored", "right_censored", "sequence_id", "token_count", "run_lengths", "max_run", "uncertain_positions"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(VIEW))
    parser.add_argument("--streams", type=Path)
    parser.add_argument("--routines", type=Path)
    parser.add_argument("--output", type=Path)
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    started = time.perf_counter()
    spec, view = SOURCES[args.source], VIEW[args.source]
    dataset = spec["dataset"]
    routines = args.routines or routine_folder(args.source)
    output = args.output or DETECTION_OUTPUT / args.source / "sequences" / dataset
    output.mkdir(parents=True, exist_ok=True)
    model = Model(read_json(routines / "model.json"))
    rules = load_rules(routines / "rules.csv")
    connection = open_store(args.source, args.streams)
    sequences = load_sequences(connection)
    groups, _ = training_groups(connection)
    seen = {(host, sequences[sid]) for host, sid, _, _ in groups}
    cache = {}

    def scored(host, sid, uncertain_text, left, right):
        key = (host, sid, uncertain_text, left, right)
        if key not in cache:
            cache[key] = score_one(sequences[sid], host, positions(uncertain_text), bool(left), bool(right), model, rules, seen)
        return cache[key]

    # the training-quantile fallback threshold, over training observations (weighted by multiplicity)
    train = connection.execute("SELECT host_id, sequence_id, uncertain_positions, left_censored, right_censored, COUNT(*) "
                               "FROM units WHERE split='train' GROUP BY 1,2,3,4,5").fetchall()
    train_scores = [scored(h, s, u, l, r)[0] for h, s, u, l, r, _ in train]
    training_threshold = weighted_quantile(train_scores, [row[-1] for row in train], BASELINE_QUANTILE)
    log(f"{args.source.upper()}: training scores from {sum(row[-1] for row in train):,} observations "
        f"({len(train):,} distinct); {BASELINE_QUANTILE:.1%} quantile {training_threshold:.2f} bits")

    frames = {}
    for split in ("validation", "test"):
        frame = pd.read_sql_query("SELECT " + ", ".join(UNIT_COLUMNS) + " FROM units WHERE split=? ORDER BY start_epoch, row_manifest_id",
                                  connection, params=(split,))
        results = [scored(h, s, u, l, r) for h, s, u, l, r in
                   zip(frame["host_id"], frame["sequence_id"], frame["uncertain_positions"], frame["left_censored"], frame["right_censored"])]
        columns = list(zip(*results)) if results else [[]] * 7
        frame.insert(1, view["id"], frame["row_manifest_id"])
        frame.insert(2, view["time"], [text_time(s) for s in frame["start_epoch"]])
        frame["steps"] = [" > ".join(sequences[s][:STEPS_SHOWN]) + (" > ..." if len(sequences[s]) > STEPS_SHOWN else "") for s in frame["sequence_id"]]
        frame["uncertain_steps"] = [len(positions(u)) for u in frame["uncertain_positions"]]
        frame["sequence_score"] = np.asarray(columns[0], dtype=float)
        frame["sequence_rarest_step"] = columns[1]
        frame["sequence_rarest_step_probability"] = columns[2]
        frame["sequence_mean_surprise"] = columns[3]
        frame["sequence_unseen_on_host"] = columns[4]
        frame["sequence_broken_rules"] = columns[5]
        frame["sequence_explanation"] = columns[6]
        frames[split] = frame
        log(f"{split}: {len(frame):,} observations scored ({len(cache):,} distinct cases so far)")
    connection.close()

    validation = frames["validation"]
    threshold = budget_threshold(args.source, dataset, validation["sequence_score"].to_numpy(),
                                 validation["start_epoch"].to_numpy(), training_threshold)
    cut = max(threshold["selected"], training_threshold)
    source = threshold["source"] + ("_raised_to_training_quantile" if cut > threshold["selected"] else "")
    summary = {"dataset": dataset, "source": args.source, "detector": "sequence", "status": "completed",
               "score": "surprise of the rarest step in bits (+0.001 x mean step surprise)",
               "threshold": cut, "threshold_source": source, "budget_threshold": threshold["selected"], "budget": {k: v for k, v in threshold.items() if k != "selected"},
               "training_quantile_threshold": training_threshold, "host_prior": HOST_PRIOR, "global_prior": GLOBAL_PRIOR}
    for split, frame in frames.items():
        frame["sequence_alert"] = frame["sequence_score"] >= cut
        frame.loc[~frame["sequence_alert"], "sequence_explanation"] = ""
        frame.drop(columns=["start_epoch", "uncertain_positions"]).to_csv(output / f"{split}_scores.csv", index=False)
        alerts = int(frame["sequence_alert"].sum())
        summary[f"{split}_rows"] = len(frame)
        summary[f"{split}_alerts"] = alerts
        summary[f"{split}_alert_rate"] = alerts / max(len(frame), 1)
        summary[f"{split}_alerts_unseen_on_host"] = int((frame["sequence_alert"] & frame["sequence_unseen_on_host"]).sum())
        summary[f"{split}_alerts_breaking_a_rule"] = int((frame["sequence_alert"] & frame["sequence_broken_rules"].astype(bool)).sum())
    test = frames["test"]
    (test[test["sequence_alert"]].sort_values("sequence_score", ascending=False)
     [["row_manifest_id", view["time"], "host_id", "sequence_score", "sequence_explanation", "steps", "run_lengths",
       "close_reason", "merged_copies", "uncertain_steps"]].to_csv(output / "test_alerts.csv", index=False))
    summary["seconds"] = round(time.perf_counter() - started, 1)
    summary["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    write_json(output / "summary.json", summary)
    log(f"threshold {cut:.2f} bits ({source}); validation {summary['validation_alerts']:,} alerts, "
        f"test {summary['test_alerts']:,} alerts ({summary['test_alert_rate']:.3%}) -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
