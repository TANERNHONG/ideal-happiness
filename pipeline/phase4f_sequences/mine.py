"""Phase 4f steps 2-3 (fitting): what normal sequences look like, learned from the training split only.

  .venv/Scripts/python.exe pipeline/phase4f_sequences/mine.py --source ossec

Reads the step-1 store (streams.py) and writes data/phase4f_sequences/<source>/routines/:

routines.csv
    The routine catalogue, overall and per host. ``whole`` rows are complete sequences ("this exact
    session/episode, 41% of mm04kco's"); ``pattern`` rows are closed sequential patterns from
    PrefixSpan (steps in this order, other steps allowed between), with their support.
rules.csv
    "Usually followed by" rules taken from the patterns: after the steps in ``antecedent``, the
    ``then`` step follows later in the same observation in ``confidence`` of cases. An observation
    that has the antecedent but not the follow-up breaks a routine; the detector names the rule.
model.json
    Step counts for the transition model the detector scores with: how often each event type
    follows each other (and starts or ends an observation), overall and per host.
summary.json
    Inputs, parameters and sizes.

Training uses the ``train`` split, leaving out observations inside approved change windows (as
Phase 4 does) and censored ones (start or end cut off by the edge of the data). Identical sequences
are counted once with their multiplicity, so support is still the number of observations: PrefixSpan
runs with a weighted support function. Steps whose order is uncertain (streams.py) are not counted.
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from collections import Counter, defaultdict
from datetime import timezone
from pathlib import Path

from prefixspan import PrefixSpan

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
from common import BEGIN, END, SOURCES, load_sequences, open_store, positions, routine_folder, write_json  # noqa: E402

MIN_SHARE = 0.005          # a routine covers at least 0.5% of its scope's observations ...
MIN_COUNT = 20             # ... and at least 20 of them
MIN_HOST_UNITS = 200       # hosts with fewer training observations only get the overall catalogue
MAX_PATTERN_LENGTH = 8
WHOLE_TOP = 15             # complete sequences listed per scope
RULE_CONFIDENCE = 0.95
MAX_ANTECEDENT = 3


log = runlog.log


def change_window_clause():
    """SQL excluding approved change windows (Phase 4 leaves them out of training), with its parameters."""
    try:
        from sources import load_change_windows
    except ImportError:
        return "", []
    clauses, parameters = [], []
    for start, end, hosts in load_change_windows():
        clause = "(start_epoch BETWEEN ? AND ?"
        parameters += [start.replace(tzinfo=timezone.utc).timestamp(), end.replace(tzinfo=timezone.utc).timestamp()]
        if hosts:
            clause += " AND host_id IN (" + ",".join("?" * len(hosts)) + ")"
            parameters += sorted(hosts)
        clauses.append(clause + ")")
    return (" AND NOT (" + " OR ".join(clauses) + ")") if clauses else "", parameters


def training_groups(connection):
    """[(host, sequence_id, uncertain positions, count)] for usable training observations."""
    extra, parameters = change_window_clause()
    query = ("SELECT host_id, sequence_id, uncertain_positions, COUNT(*) FROM units "
             "WHERE split='train' AND left_censored=0 AND right_censored=0" + extra +
             " GROUP BY host_id, sequence_id, uncertain_positions")
    excluded = connection.execute("SELECT COUNT(*) FROM units WHERE split='train' AND (left_censored=1 OR right_censored=1)"
                                  ).fetchone()[0]
    groups = [(host, sid, positions(uncertain), count) for host, sid, uncertain, count in connection.execute(query, parameters)]
    return groups, excluded


def contains(sequence, pattern):
    """True if ``pattern`` occurs in ``sequence`` in order (gaps allowed)."""
    it = iter(sequence)
    return all(token in it for token in pattern)


def mine_scope(sequences, weights, total):
    """Closed frequent patterns of one scope with weighted support."""
    minimum = max(MIN_COUNT, MIN_SHARE * total)
    if total < minimum:
        return [], minimum
    database = [list(seq) for seq in sequences]
    support = lambda pattern, matches: sum(weights[i] for i, _ in matches)  # noqa: E731
    miner = PrefixSpan(database)
    miner.maxlen = MAX_PATTERN_LENGTH
    found = miner.frequent(minimum, closed=True, key=support, bound=support)
    return [(int(count), tuple(pattern)) for count, pattern in found], minimum


def support_of(pattern, sequences, weights, cache):
    if pattern not in cache:
        cache[pattern] = sum(w for seq, w in zip(sequences, weights) if contains(seq, pattern))
    return cache[pattern]


def rules_from(patterns, sequences, weights, minimum):
    """'After A, X follows' rules from the prefixes of each closed pattern (consequent of one step)."""
    cache, found = {}, {}
    for count, pattern in patterns:
        for k in range(1, min(len(pattern), MAX_ANTECEDENT + 1)):
            antecedent, then = pattern[:k], pattern[k]
            if (antecedent, then) in found:
                continue
            base = support_of(antecedent, sequences, weights, cache)
            both = support_of(antecedent + (then,), sequences, weights, cache)
            if base >= minimum and both / base >= RULE_CONFIDENCE:
                found[(antecedent, then)] = (both / base, base, both)
    return found


def transition_counts(groups, sequences):
    """Step counts overall and per host: counts[host][previous][next], host '*' = overall."""
    counts = defaultdict(lambda: defaultdict(Counter))
    unigrams = Counter()
    for host, sid, uncertain, count in groups:
        steps = (BEGIN,) + sequences[sid] + (END,)
        for k in range(1, len(steps)):
            if k - 1 in uncertain:          # token position k-1 was entered by an uncertain step
                continue
            for scope in ("*", host):
                counts[scope][steps[k - 1]][steps[k]] += count
            unigrams[steps[k]] += count
    return counts, unigrams


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(SOURCES))
    parser.add_argument("--streams", type=Path, help="Folder of sequences.sqlite (default: the source's streams folder).")
    parser.add_argument("--output", type=Path)
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    started = time.perf_counter()
    output = args.output or routine_folder(args.source)
    output.mkdir(parents=True, exist_ok=True)
    connection = open_store(args.source, args.streams)
    sequences = load_sequences(connection)
    groups, censored = training_groups(connection)
    connection.close()
    per_scope = defaultdict(Counter)                     # scope -> sequence_id -> observations
    for host, sid, _, count in groups:
        per_scope["*"][sid] += count
        per_scope[host][sid] += count
    hosts_of = defaultdict(set)
    for host, sid, _, _ in groups:
        hosts_of[sid].add(host)
    scopes = ["*"] + sorted(scope for scope, seqs in per_scope.items()
                            if scope != "*" and sum(seqs.values()) >= MIN_HOST_UNITS)
    log(f"{args.source.upper()}: {sum(per_scope['*'].values()):,} training observations, {len(per_scope['*']):,} distinct "
        f"sequences, {len(per_scope) - 1} hosts ({len(scopes) - 1} with their own catalogue); {censored:,} censored left out")

    routine_rows, rule_rows = [], []
    for scope in scopes:
        sids = list(per_scope[scope])
        seqs = [sequences[sid] for sid in sids]
        weights = [per_scope[scope][sid] for sid in sids]
        total = sum(weights)
        label = "all hosts" if scope == "*" else scope
        for sid, count in per_scope[scope].most_common(WHOLE_TOP):
            routine_rows.append({"scope": label, "kind": "whole", "steps": " > ".join(sequences[sid]) or "(empty)",
                                 "length": len(sequences[sid]), "observations": count, "share": round(count / total, 6),
                                 "hosts": len(hosts_of[sid]) if scope == "*" else 1})
        patterns, minimum = mine_scope(seqs, weights, total)
        for count, pattern in sorted(patterns, key=lambda item: (-item[0], len(item[1]))):
            routine_rows.append({"scope": label, "kind": "pattern", "steps": " > ".join(pattern), "length": len(pattern),
                                 "observations": count, "share": round(count / total, 6),
                                 "hosts": len({h for sid in sids if contains(sequences[sid], pattern) for h in hosts_of[sid]}) if scope == "*" else 1})
        for (antecedent, then), (confidence, base, both) in rules_from(patterns, seqs, weights, minimum).items():
            rule_rows.append({"scope": label, "antecedent": " > ".join(antecedent), "then": then,
                              "confidence": round(confidence, 6), "antecedent_observations": base,
                              "followed_observations": both})
        name = "All servers" if scope == "*" else f"Server {scopes.index(scope)} of {len(scopes) - 1}"
        log(f"{name}: {total:,} observations, {len(patterns):,} closed patterns (support >= {minimum:,.0f}), "
            f"{sum(r['scope'] == label for r in rule_rows):,} rules")

    for name, rows, fields in (("routines.csv", routine_rows, ["scope", "kind", "steps", "length", "observations", "share", "hosts"]),
                               ("rules.csv", rule_rows, ["scope", "antecedent", "then", "confidence", "antecedent_observations", "followed_observations"])):
        temporary = output / (name + ".tmp")
        with open(temporary, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(output / name)

    counts, unigrams = transition_counts(groups, sequences)
    write_json(output / "model.json", {
        "kind": "first-order transition counts over event-type tokens, with start and end",
        "begin": BEGIN, "end": END,
        "transitions": {scope: {prev: dict(nexts) for prev, nexts in table.items()} for scope, table in counts.items()},
        "unigrams": dict(unigrams),
    })
    write_json(output / "summary.json", {
        "source": args.source, "dataset": SOURCES[args.source]["dataset"], "split": "train",
        "training_observations": sum(per_scope["*"].values()), "distinct_sequences": len(per_scope["*"]),
        "censored_left_out": censored, "change_windows_left_out": bool(change_window_clause()[0]),
        "hosts": len(per_scope) - 1, "hosts_with_catalogue": len(scopes) - 1,
        "parameters": {"min_share": MIN_SHARE, "min_count": MIN_COUNT, "min_host_units": MIN_HOST_UNITS,
                       "max_pattern_length": MAX_PATTERN_LENGTH, "rule_confidence": RULE_CONFIDENCE,
                       "max_antecedent": MAX_ANTECEDENT, "closed_patterns": True},
        "routines": len(routine_rows), "rules": len(rule_rows), "event_types": len(unigrams) - 1,
        "seconds": round(time.perf_counter() - started, 1), "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    log(f"Wrote {len(routine_rows):,} routines and {len(rule_rows):,} rules to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
