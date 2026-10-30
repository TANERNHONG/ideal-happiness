"""Phase 4g: activity, not lines. Unusual amounts of activity, by time and by who, with what a line says ignored.

  python pipeline/phase4_detection/activity_detectors.py --source auth
  python pipeline/phase4_detection/activity_detectors.py --source ossec --entities server source_ip

The other detectors judge each line, session or window by what it says: its
event type, words and tokens, and how rare they are. This step ignores what a
line says. A line is one unit of activity: at a time, on a server, from a
source IP, for a username, to a destination IP. It is the counterpart, for busy
logs, of the presence method (IPFilter, PF), which also ignores rarity but takes
normal activity to be none; here normal activity is learned from training.

Two views, one row per 5-minute step:

    activity            the whole log: every 5-minute step of the study period,
                        empty ones included. Steps whose 12-hour look-back
                        touches a day on which the log has no line at all are
                        left out: a whole day missing is a collection question
                        (Phase 4d), not activity.
    activity_by_entity  one series per entity, for each entity type:
                            server          hostname
                            source_ip       source IP of the line
                            username        username in the line
                            destination_ip  destination IP (OSSEC; auth lines have none)
                        one row for each step in which the entity has a line

Features of a row, built as in Phase 3 (counts with log twins, the same time
features) but from activity only:
    volume       lines in the trailing 5, 30, 120 and 720 minutes (WINDOWS)
                 up to the end of the step (lines_<w>m), each with its log twin
                 log(1 + x) (log_<w>m): a short burst and a slow build-up in one row
    shape        steps with any line in the last 60 and 720 minutes, log minutes
                 since the series' previous line, and two burst ratios:
                 log((5 min + 1) / (60 min / 12 + 1)) and log((60 min + 1) / (720 min / 12 + 1))
    who          log(1 + distinct values) of each OTHER entity type in the step:
                 how many servers an IP touched, how many IPs a username came
                 from; for the whole log, how many servers, IPs, users and
                 destinations were active
    outcome      (auth: Phase 2's own event_outcome of each event type; OSSEC states no outcome rule, so
                 none) failures in each window (fail_<w>m, log_fail_<w>m), the failure share of the last
                 30 minutes, failures in the 30 minutes before a success (success_after_failures, for a
                 username or source IP: one actor's guess that worked), and how many usernames, IPs or servers
                 failed in the step
                 (distinct_failed_<other>_5m: one IP failing on many usernames is password spraying)
    relations    partners met for the first time: log(1 + other entities this one shares a line with for
                 the first time in the step), per type (new_<other>_5m), and all types over the last 2 hours
                 (new_partners_120m, log_new_partners_120m); the whole log counts new pairs. Counted from the
                 log's start, so the first --novelty-warmup-days, when every pair is new, count none
    context      (with pipeline/phase9_llm_triage/site/assets.csv) lines whose source address and server (or
                 destination and server) are in different zones (cross_zone_5m); each entity's zone, role and
                 criticality, for peer baselines and the alert's priority. An empty inventory changes nothing
    regularity   how even the per-step counts were over the last hour (count_cv_60m, the coefficient of
                 variation of 12 steps, quiet ones included: 0 for a steady beacon) and how even the gaps
                 between active steps were over 12 hours (gap_cv_720m; 1, as for random arrivals, with fewer
                 than 3 gaps)
    own normal   every volume, shape and who feature less the series' training
                 median (rel_<feature>), and each log twin less its training
                 median at the same hour of day (rel_hour_<w>m; the series median
                 when that hour has fewer than 10 training rows)
    time         time_hour, time_day_of_week, time_sin_day and time_cos_day as in
                 Phase 3, time_sin_week and time_cos_week, and time_is_non_working:
                 a Saturday, Sunday or public holiday (pipeline/phase9_llm_triage/site/
                 public_holidays.csv), so a quiet holiday is as normal as a quiet
                 weekend (--no-time leaves them out)
The whole-log forest uses volume, shape, who, rel_hour and time. The entity
forests use only the own-normal features and time, so an entity is judged
against itself, not against busier or quieter peers. Names are never features:
who an entity is enters only through its own baseline, so the rarity of a name
plays no part; nor are addresses as numbers or locations looked up from them.
Which partners are new is a fact about a relationship, not about a name.

Feature filters, as in the model zoo's relevance step (training and validation
only): a feature is dropped when it is constant (standard deviation below 1e-9
on a sample of up to 100,000 training rows), shifted (Kolmogorov-Smirnov
statistic above 0.25 between training and validation), or a near-copy of a
feature kept before it (absolute correlation above 0.98; log twins come first,
so a raw count goes before its twin). There is no importance cut. The decisions
are written per view and entity type (feature_decisions_<type>.csv).

Detectors (the rule since 2026-10-28; a step is flagged for being unusual for THIS series at THIS time, not to
fill a daily quota):
    Robust deviation  per window, two robust z-scores of log(1 + lines), each (x - median) / max(1.4826 x MAD,
                      --robust-floor):
                        calendar  against the same clock window on the series' comparable training days
                                  (activity_explain.comparable_groups: the same weekday's, public holidays
                                  apart, else the same kind of day's; quiet days count as 0; at least
                                  MIN_DAYS of them), so a routine morning peak or nightly job is normal
                        level     against the series' training median over the steps in which it was
                                  active (an entity with fewer than --min-history such steps: its entity
                                  type's pooled rows), so a few lines at an unusual hour are not a burst
                      A window counts when both point the same way, by the smaller of the two; the score
                      is the largest over the windows. Without comparable days (a series first seen
                      late in training or after it), the level alone, upwards only. A drop counts only for
                      a series with its own level whose calendar median is at least --min-drop-lines lines:
                      a quiet newcomer is not evidence (Phase 4d watches silence, 4e newcomers).
                      Failures (auth) are measured the same way, upwards only and from --min-failures in the
                      window; new partners over 2 hours against the level only, upwards.
    Isolation Forest  one forest per view and entity type, on the kept features, fitted on a balanced sample of
                      the training rows: each entity with its own baseline gives the same number (drawn again
                      when it has fewer), so a nightly job that runs for 30 minutes counts as much as a server
                      that logs all day. A SECOND OPINION: above its validation threshold it agrees with a
                      robust-deviation alert (and raises its score); on its own it alerts only above the
                      --forest-alone-quantile of its training scores as well: by default the most isolated
                      training step, which a new step beats by chance with probability 1/(n + 1).
Split: chronological, at the boundaries of the source's Phase 3 split (train,
validation, test); without them, 70 / 15 / 15 of the study period.
Thresholds: a fixed bar, with the validation quota only as a ceiling, for each robust channel on its own (a noisy
channel cannot raise another's bar; a step's channel is the one furthest above its own). Robust deviation alerts from --min-robust-z
(raised to the validation quota, --alerts-per-day x validation days and at most --max-validation-share of the
validation rows, only when more validation steps than that pass the bar); the forest agrees from its validation
quota and alerts alone from the higher of that and its training quantile. A quiet test period gives no alerts.
Validation's two jobs are kept apart (shared/calibration.py, --calibration-split): its earlier half chooses (the
feature filter, the null below, the shrinkage), its later half sets the quotas.
False discoveries: thousands of steps are tested each day, so passing the bar is not enough. Each step's robust z gets
a p-value from the null of validation's earlier half (the empirical share at or above it, and beyond the null's top
values an exponential tail fitted to their excesses: null_p), and Benjamini-Hochberg at --fdr (0.05) across each
day's steps of a view and entity type must also pass it (fdr_pass). A burst is many steps, so it still stands out.
Shrinkage: a weekday baseline from few comparable days is noisy, so it is drawn toward the series' all-days baseline
at the same clock time with weight n / (n + k) (shrink); k from --shrinkage-days, or chosen on validation's earlier
half to make the share of steps above z 3 most even across series (choose_shrinkage).
Alerts: test steps that robust deviation flags, or the forest alone above its strict bar. Alerting steps of the
same series no more than --merge-gap minutes apart form one EPISODE, which is the alert (a two-hour burst is one
alert, not 24). Its score is the highest step score: the stronger detector's multiple of its threshold, plus 1
when the forest agrees with robust deviation; its evidence a written description
plus the series' first --lines lines in the peak step, with each line's Phase 1 ID
(event_ref: record_id for auth, event_id for OSSEC). Server names and usernames are kept in
lower case, as Phase 2 keeps them.

Incidents (activity_incidents.py): alerts that are one event or one routine are grouped, so each is reviewed once:
recurring (the same entity and channel at about the same clock time on 3+ days; an entity's routines on one channel
are one incident), linked (entity alerts of different types peaking within 60 minutes whose entities shared a line in
those peak hours; an event joins a routine, but two routines never merge), and the whole log as context of the
strongest entity alert on the same channel peaking within 60 minutes (a whole-log routine forms from the whole-log
alerts no entity's routine explains). Each alert carries incident_id (its lead alert's id), incident_kind, incident_size and incident_lead.

Outputs (data/phase4_detection/<source>/activity/):
    activity/test_scores.csv, test_raw_alert_evidence.csv, summary.json, feature_decisions_all.csv
    activity_by_entity/test_scores.csv, test_raw_alert_evidence.csv, summary.json, feature_decisions_<type>.csv
    <view>/explanations.jsonl  one plain-language record per alert, with its chart data, for the
                               console's Explain tab (activity_explain.py says what is in it)
    experiment_summary.csv     one row per view and entity type: rows, features, thresholds, alerts
    incidents.csv              one row per incident: kind, title, lead, start, end, days, size, members (view:id)
Phase 7 reads activity_alert / activity_score and ranks the alerts among themselves.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)
import calibration  # noqa: E402  validation's earlier half chooses, its later half calibrates
from sources import ROOT, SOURCES, Assets, load_change_windows, load_public_holidays  # noqa: E402

import activity_explain  # noqa: E402
import activity_incidents  # noqa: E402

STEP_MINUTES = 5
# The trailing windows (2026-10-28: four, from seven). On the real data, 5, 30, 120 and 720 minutes gave the same alerts
# and caught the same injected anomalies as 5, 15, 30, 60, 120, 360 and 720 on every entity type of auth and OSSEC; the
# 30-minute window carries machine traffic on a fixed cycle (OSSEC destinations), the 2-hour one OSSEC's servers.
WINDOWS = (5, 30, 120, 720)
STEPS_PER_DAY = 24 * 60 // STEP_MINUTES
GAP_CAP_MINUTES = 7 * 24 * 60
ENTITY_TYPES = {"server": "hostname", "source_ip": "source_ip", "username": "username",
                "destination_ip": "destination_ip"}
ENTITY_LABELS = {"all": "whole log", "server": "server", "source_ip": "source IP", "username": "username",
                 "destination_ip": "destination IP"}
PHASE1 = {"auth": ("auth", "classified_authlog_events_*.csv"), "ossec": ("ossec", "ossec_events_*.csv")}
LINE_IDS = {"auth": "record_id", "ossec": "event_id"}          # each line's ID in Phase 1, kept as event_ref
SHAPE_FEATURES = ["active_steps_60m", "active_steps_720m", "log_gap_minutes", "burst_5_60", "burst_60_720"]
REGULARITY_FEATURES = ["count_cv_60m", "gap_cv_720m"]
OUTCOME_RULES = {"auth": "phase2_observations/auth.py"}        # sources whose Phase 2 states an outcome per event type
FAILURE_OUTCOMES = {"failure", "invalid_user", "account_lock", "access_denied"}
SUCCESS_OUTCOMES = {"success"}
SUCCESS_AFTER_STEPS = 30 // 5         # failures in the 30 minutes up to a success
NOVELTY_MINUTES = 120                 # new partners over the last 2 hours: the robust novelty channel
CRITICALITY_WEIGHT = {"high": 1.5, "medium": 1.2, "low": 1.0, "": 1.0}   # an alert's score, by its asset's criticality
ZONED = ("server", "source_ip", "destination_ip")             # entity types the asset inventory can name
TIME_FEATURES = ["time_hour", "time_day_of_week", "time_is_non_working", "time_sin_day", "time_cos_day",
                 "time_sin_week", "time_cos_week"]
CHUNK = 500_000
CALENDAR_CHUNK = 20_000           # calendar baselines computed at once
SHRINK_GRID = (0, 4, 8, 16, 32)   # k tried for a weekday baseline's weight n / (n + k) toward the all-days one
SHRINK_MIN_ROWS = 50              # validation steps a series needs to count in choosing k
FDR_MIN_NULL = 1_000              # null steps needed for the empirical p-values; fewer: no FDR step
TAIL_SHARE = 0.01                 # the null's top share where the fitted exponential tail takes over
TAIL_MIN = 20                     # excesses needed to fit that tail; fewer: the empirical p alone
SEED = 42
TREES = 200
MIN_TRAIN_ROWS = 100
MIN_VALIDATION_ROWS = 30
MIN_HOUR_ROWS = 10
FALLBACK_QUANTILE = 0.995
RELEVANCE_SAMPLE = 100_000
CONSTANT_STD = 1e-9
DRIFT_MAX_KS = 0.25
REDUNDANCY_MAX_CORR = 0.98


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(PHASE1))
    parser.add_argument("--entities", nargs="+", choices=sorted(ENTITY_TYPES), default=list(ENTITY_TYPES))
    parser.add_argument("--no-time", action="store_true", help="Leave the time features out.")
    parser.add_argument("--min-history", type=int, default=30,
                        help="Training rows an entity needs for its own baseline; fewer uses its type's pooled rows.")
    parser.add_argument("--robust-floor", type=float, default=0.5, help="Smallest robust scale, in log(1 + lines).")
    parser.add_argument("--min-robust-z", type=float, default=3.0, help="The fixed bar for robust deviation.")
    parser.add_argument("--min-drop-lines", type=float, default=20.0,
                        help="A drop counts only where the calendar median of the window is at least this many lines: a "
                             "few missing lines in a quiet stretch happen by chance across thousands of steps.")
    parser.add_argument("--min-failures", type=float, default=10.0,
                        help="Failures count in a window only from this many: a handful of failed logins (typos, expired "
                             "passwords) is everyday, and from 0 even 4 would pass the bar.")
    parser.add_argument("--forest-alone-quantile", type=float, default=1.0,
                        help="The Isolation Forest alerts on its own only above this quantile of its training scores; 1 is "
                             "the most isolated training step, which a new step beats by chance with probability 1/(n+1).")
    parser.add_argument("--alerts-per-day", type=float, default=2.0,
                        help="Alerting steps allowed per validation day, per detector, view and entity type.")
    parser.add_argument("--max-validation-share", type=float, default=0.01)
    parser.add_argument("--calibration-split", choices=calibration.MODES, default="halves",
                        help="halves: validation's earlier half chooses (the feature filter, the null for --fdr, k), its "
                             "later half sets the quotas; all: both on every validation row (before 2026-10-30).")
    parser.add_argument("--fdr", type=float, default=0.05,
                        help="Benjamini-Hochberg false-discovery rate across each day's steps of a view and entity type, "
                             "p from the empirical null of validation's earlier half; a robust alert needs both the bar "
                             "and this. 0: no FDR step (before 2026-10-30).")
    parser.add_argument("--shrinkage-days", default="auto",
                        help="k in n / (n + k), the weight of a series' weekday baseline (n comparable days) against its "
                             "all-days baseline at the same clock time: 'auto' picks k from 0, 4, 8, 16, 32 on validation's "
                             "earlier half; 0: no shrinkage (before 2026-10-30).")
    parser.add_argument("--merge-gap", type=int, default=60, help="Minutes between alerting steps of one episode.")
    parser.add_argument("--train-sample", type=int, default=200_000, help="Training rows the Isolation Forest is fitted on.")
    parser.add_argument("--novelty-warmup-days", type=int, default=14,
                        help="Days from the log's start in which no pair counts as new (every pair is new at first).")
    parser.add_argument("--lines", type=int, default=20, help="Original lines kept per alert.")
    parser.add_argument("--data", type=Path, default=ROOT / "data")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    args.output = args.data / "phase4_detection" / args.source / "activity"
    return args


log = runlog.log


def phase1_files(args):
    folder, pattern = PHASE1[args.source]
    return sorted((args.data / "phase1_classify" / folder).glob(pattern))


def read_chunks(files, columns):
    """Phase 1 rows with a parsed time ('when') and a 5-minute step number ('step')."""
    for path in files:
        header = pd.read_csv(path, nrows=0).columns
        use = [c for c in columns if c in header]
        for chunk in pd.read_csv(path, usecols=use, dtype=str, chunksize=CHUNK, keep_default_na=False):
            chunk["when"] = pd.to_datetime(chunk["timestamp"].str[:19].str.replace("/", "-"), errors="coerce")
            chunk = chunk.dropna(subset=["when"])
            chunk["step"] = chunk["when"].to_numpy().astype("datetime64[m]").astype(np.int64) // STEP_MINUTES
            yield chunk


def entity_values(chunk, kind):
    """One entity type's values in a chunk; server names and usernames in lower case, as Phase 2 keeps them."""
    values = chunk[ENTITY_TYPES[kind]].str.strip()
    return values.str.lower() if kind in ("server", "username") else values


def row_hashes(*columns):
    """One 64-bit hash per row of the given columns (entity values as text, steps as int64)."""
    frame = pd.DataFrame({index: np.asarray(column) for index, column in enumerate(columns)})
    return pd.util.hash_pandas_object(frame, index=False).to_numpy()


def distinct_counts(parts):
    """From (unique triple hashes, their pair hashes) per chunk: distinct third values per pair."""
    if not parts:
        return pd.Series(dtype=np.int64)
    triples = np.concatenate([triple for triple, _ in parts])
    pairs = np.concatenate([pair for _, pair in parts])
    _, first = np.unique(triples, return_index=True)
    keys, counts = np.unique(pairs[first], return_counts=True)
    return pd.Series(counts, index=keys)


def outcome_rule(source):
    """Phase 2's own outcome of each event type (its event_outcome) as a function of an array of event types: 1 a
    failure, 2 a success, 0 neither. None for a source whose Phase 2 states no outcome rule (OSSEC)."""
    relative = OUTCOME_RULES.get(source)
    if relative is None:
        return None
    spec = importlib.util.spec_from_file_location(f"huh_phase2_{source}", ROOT / "pipeline" / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    known = {}

    def codes(event_types):
        unique, inverse = np.unique(np.asarray(event_types, dtype=str), return_inverse=True)
        for value in unique:
            if value not in known:
                outcome = module.event_outcome(value)
                known[value] = 1 if outcome in FAILURE_OUTCOMES else 2 if outcome in SUCCESS_OUTCOMES else 0
        return np.array([known[value] for value in unique], dtype=np.int8)[inverse]
    return codes


def count_lines(files, entities, outcome=None, assets=None):
    """Lines per step (whole log) and per (entity, step), with their failures, successes and zone crossings; distinct
    values of the other entity types in each (all lines, and failed lines only); the first step of every pair of
    entities that share a line; and the hours in which each pair shared one (hashed, for the incidents). Returns a
    dict: total, extra (per step), counted, whole_distinct, pair_distinct, fail_distinct, first_pairs, pair_hours."""
    present = {kind: ENTITY_TYPES[kind] for kind in entities}
    whole, whole_extra, by_type = [], [], {kind: [] for kind in entities}
    whole_parts = {kind: [] for kind in entities}
    pair_parts = {(kind, other): [] for kind in entities for other in entities if other != kind}
    fail_parts = {(kind, other): [] for kind in entities for other in entities if other != kind}
    first_parts, hour_parts = {}, []
    columns = ["timestamp"] + sorted(set(present.values())) + (["event_type"] if outcome else [])
    for chunk in read_chunks(files, columns):
        whole.append(chunk["step"].value_counts())
        steps = chunk["step"].to_numpy(dtype=np.int64)
        values = {kind: entity_values(chunk, kind).to_numpy(dtype=object)
                  for kind, column in present.items() if column in chunk}
        filled = {kind: value != "" for kind, value in values.items()}
        codes = outcome(chunk["event_type"].to_numpy(dtype=object)) if outcome and "event_type" in chunk else np.zeros(len(chunk), np.int8)
        failed, succeeded = (codes == 1).astype(np.int32), (codes == 2).astype(np.int32)
        cross = np.zeros(len(chunk), dtype=np.int32)
        if assets and "server" in values:
            zone = {kind: zones(values[kind], assets) for kind in ("server", "source_ip", "destination_ip") if kind in values}
            for other in ("source_ip", "destination_ip"):
                if other in zone:
                    cross |= ((zone["server"] != "") & (zone[other] != "") & (zone["server"] != zone[other])).astype(np.int32)
        whole_extra.append(pd.DataFrame({"step": steps, "failures": failed, "successes": succeeded, "cross": cross})
                           .groupby("step").sum())
        for kind, value in values.items():
            ok = filled[kind]
            if not ok.any():
                continue
            by_type[kind].append(pd.DataFrame({"entity": value[ok], "step": steps[ok], "lines": 1, "failures": failed[ok],
                                               "successes": succeeded[ok], "cross": cross[ok]}).groupby(["entity", "step"]).sum())
            unique, first = np.unique(row_hashes(steps[ok], value[ok]), return_index=True)
            whole_parts[kind].append((unique, steps[ok][first]))
            for other, other_value in values.items():
                both = ok & filled[other] if other != kind else None
                if both is None or not both.any():
                    continue
                pair = row_hashes(value[both], steps[both])
                unique, first = np.unique(row_hashes(value[both], steps[both], other_value[both]), return_index=True)
                pair_parts[(kind, other)].append((unique, pair[first]))
                lost = both & (failed > 0)
                if lost.any():
                    pair = row_hashes(value[lost], steps[lost])
                    unique, first = np.unique(row_hashes(value[lost], steps[lost], other_value[lost]), return_index=True)
                    fail_parts[(kind, other)].append((unique, pair[first]))
        for kind, other in combinations([k for k in entities if k in values], 2):
            both = filled[kind] & filled[other]
            if both.any():
                first_parts.setdefault((kind, other), []).append(pd.DataFrame(
                    {"a": values[kind][both], "b": values[other][both], "step": steps[both]}).groupby(["a", "b"])["step"].min())
                hours = pd.DataFrame({"a": values[kind][both], "b": values[other][both],
                                      "h": steps[both] // (60 // STEP_MINUTES)}).drop_duplicates()
                hour_parts.append(np.unique(activity_incidents.pair_hashes(kind, hours["a"], other, hours["b"], hours["h"])))
    total = pd.concat(whole).groupby(level=0).sum().sort_index() if whole else pd.Series(dtype=np.int64)
    return {
        "total": total,
        "extra": pd.concat(whole_extra).groupby(level=0).sum() if whole_extra else pd.DataFrame(),
        "counted": {kind: pd.concat(parts).groupby(level=[0, 1]).sum().reset_index() for kind, parts in by_type.items() if parts},
        "whole_distinct": {kind: distinct_counts(parts) for kind, parts in whole_parts.items() if parts},
        "pair_distinct": {key: distinct_counts(parts) for key, parts in pair_parts.items() if parts},
        "fail_distinct": {key: distinct_counts(parts) for key, parts in fail_parts.items() if parts},
        "first_pairs": {key: pd.concat(parts).groupby(level=[0, 1]).min().rename("first_step").reset_index()
                        for key, parts in first_parts.items()},
        "pair_hours": np.unique(np.concatenate(hour_parts)) if hour_parts else np.zeros(0, dtype=np.uint64),
    }


def zones(values, assets):
    """The inventory's zone of each value ('' unknown)."""
    unique, inverse = np.unique(np.asarray(values, dtype=str), return_inverse=True)
    return np.array([assets.of(value)[0] for value in unique], dtype=object)[inverse]


def new_partners(first_pairs, warmup_step):
    """From each pair's first step: (per (kind, other) a Series of new partners of that type by (entity, step), per kind
    the new partners of every type by (entity, step), new pairs per step for the whole log, and per kind a table of
    entity, partner type, partner and first step for Explain). Pairs first seen before warmup_step are not new."""
    by_pair, by_kind, whole, tables = {}, {}, [], {}
    for (kind, other), table in first_pairs.items():
        fresh = table[table["first_step"] >= warmup_step]
        whole.append(fresh["first_step"].value_counts())
        for me, them, column, partner in ((kind, other, "a", "b"), (other, kind, "b", "a")):
            counts = fresh.groupby([column, "first_step"]).size()
            counts.index = counts.index.set_names(["entity", "step"])
            by_pair[(me, them)] = counts
            by_kind.setdefault(me, []).append(counts)
            tables.setdefault(me, []).append(pd.DataFrame({"entity": fresh[column].to_numpy(), "type": them,
                                                           "partner": fresh[partner].to_numpy(), "step": fresh["first_step"].to_numpy()}))
    by_kind = {kind: pd.concat(parts).groupby(level=[0, 1]).sum() for kind, parts in by_kind.items()}
    whole = pd.concat(whole).groupby(level=0).sum() if whole else pd.Series(dtype=np.int64)
    tables = {kind: pd.concat(parts, ignore_index=True) for kind, parts in tables.items()}
    return by_pair, by_kind, whole, tables


def trailing(series, steps, values, steps_back):
    """Sum of `values` over the last `steps_back` steps (this one included) of the same series.

    Rows must be sorted by series, then step; steps without a row count as zero.
    """
    stride = int(steps.max() - steps.min()) + max(steps_back) + 2 if len(steps) else 1
    key = series.astype(np.int64) * stride + (steps - steps.min())
    cumulative = np.concatenate([[0], np.cumsum(values, dtype=np.int64)])
    here = np.arange(1, len(key) + 1)
    return {back: cumulative[here] - cumulative[np.searchsorted(key, key - back + 1, side="left")]
            for back in steps_back}


def whole_log_rows(total, extra=None):
    """Every step of the study period, with its failures, successes and zone crossings; steps whose 12-hour look-back
    touches an empty day are not usable."""
    if total.empty:
        return pd.DataFrame()
    first = (int(total.index.min()) // STEPS_PER_DAY) * STEPS_PER_DAY
    last = (int(total.index.max()) // STEPS_PER_DAY + 1) * STEPS_PER_DAY
    steps = np.arange(first, last, dtype=np.int64)
    lines = total.reindex(steps, fill_value=0).to_numpy(dtype=np.int64)
    frame = pd.DataFrame({"series": 0, "entity": "all", "step": steps, "lines": lines})
    for column in ("failures", "successes", "cross"):
        frame[column] = (extra[column].reindex(steps, fill_value=0).to_numpy(dtype=np.int64)
                         if extra is not None and column in extra else 0)
    day_lines = pd.Series(lines).groupby((steps - first) // STEPS_PER_DAY).transform("sum").to_numpy()
    empty = np.concatenate([[0], np.cumsum(day_lines == 0)])
    back = WINDOWS[-1] // STEP_MINUTES
    here = np.arange(1, len(steps) + 1)
    frame["usable"] = (empty[here] - empty[np.maximum(here - back, 0)]) == 0
    return frame


def add_features(frame, kind, entities, whole_distinct, pair_distinct, holidays=(), extra=None):
    """Volume, shape, who, outcome, relations, context, regularity and time features; rows sorted by series, then step.
    extra: outcome (bool), fail_distinct, new_by_pair, new_by_kind, new_whole (count_lines and new_partners)."""
    series, steps, lines = frame["series"].to_numpy(), frame["step"].to_numpy(), frame["lines"].to_numpy()
    steps_back = [minutes // STEP_MINUTES for minutes in WINDOWS]
    counts = trailing(series, steps, lines, sorted(set(steps_back) | {1, 6, 12, 144}))   # 5, 30, 60, 720 min: bursts, shares
    for minutes, back in zip(WINDOWS, steps_back):
        frame[f"lines_{minutes}m"] = counts[back].astype(np.int32)
        frame[f"log_{minutes}m"] = np.log1p(counts[back]).astype(np.float32)
    active = trailing(series, steps, (lines > 0).astype(np.int64), [60 // STEP_MINUTES, 720 // STEP_MINUTES])
    frame["active_steps_60m"] = active[60 // STEP_MINUTES].astype(np.float32)
    frame["active_steps_720m"] = active[720 // STEP_MINUTES].astype(np.float32)
    previous = pd.Series(np.where(lines > 0, steps, np.nan)).groupby(series).shift().groupby(series).ffill().to_numpy()
    gap = np.where(np.isnan(previous), GAP_CAP_MINUTES, (steps - previous) * STEP_MINUTES)
    frame["log_gap_minutes"] = np.log1p(np.minimum(gap, GAP_CAP_MINUTES)).astype(np.float32)
    frame["burst_5_60"] = np.log((counts[1] + 1) / (counts[12] / 12 + 1)).astype(np.float32)
    frame["burst_60_720"] = np.log((counts[12] + 1) / (counts[144] / 12 + 1)).astype(np.float32)
    if kind == "all":
        for other, values in whole_distinct.items():
            frame[f"distinct_{other}_5m"] = np.log1p(values.reindex(steps, fill_value=0).to_numpy()).astype(np.float32)
    else:
        pair = row_hashes(frame["entity"].to_numpy(dtype=object), steps.astype(np.int64))
        for other in entities:
            if (kind, other) in pair_distinct:
                values = pair_distinct[(kind, other)].reindex(pair, fill_value=0).to_numpy()
                frame[f"distinct_{other}_5m"] = np.log1p(values).astype(np.float32)
    if extra is not None:
        add_relations(frame, kind, entities, series, steps, lines, counts, extra)
    add_regularity(frame, series, steps, lines)
    frame["start"] = pd.to_datetime(frame["step"] * STEP_MINUTES, unit="m")
    hour = frame["start"].dt.hour + frame["start"].dt.minute / 60
    weekday = frame["start"].dt.weekday
    frame["time_hour"] = frame["start"].dt.hour.astype(np.float32)
    frame["time_day_of_week"] = weekday.astype(np.float32)
    holiday = frame["start"].dt.normalize().isin(pd.to_datetime(sorted(holidays))) if len(holidays) else False
    frame["time_is_non_working"] = ((weekday >= 5) | holiday).astype(np.float32)
    frame["time_sin_day"] = np.sin(2 * np.pi * hour / 24).astype(np.float32)
    frame["time_cos_day"] = np.cos(2 * np.pi * hour / 24).astype(np.float32)
    frame["time_sin_week"] = np.sin(2 * np.pi * (weekday + hour / 24) / 7).astype(np.float32)
    frame["time_cos_week"] = np.cos(2 * np.pi * (weekday + hour / 24) / 7).astype(np.float32)
    return frame


def split_bounds(args, total):
    """(train end, validation end) from the Phase 3 split, else 70 / 15 / 15 of the study period."""
    path = args.data / "phase3_features" / args.source / "individual" / "metadata.json"
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
        split = meta.get("split_metadata", meta)
        train, validation = split.get("train_boundary_epoch"), split.get("validation_boundary_epoch")
        if train and validation:
            return (pd.Timestamp(datetime.fromtimestamp(float(train))),
                    pd.Timestamp(datetime.fromtimestamp(float(validation))), "Phase 3 split (individual view)")
    except (OSError, ValueError):
        pass
    start = pd.to_datetime(int(total.index.min()) * STEP_MINUTES, unit="m")
    end = pd.to_datetime((int(total.index.max()) + 1) * STEP_MINUTES, unit="m")
    return start + (end - start) * 0.70, start + (end - start) * 0.85, "70 / 15 / 15 of the study period"


def add_relations(frame, kind, entities, series, steps, lines, counts, extra):
    """The outcome, relations and context features (module docstring)."""
    steps_back = [minutes // STEP_MINUTES for minutes in WINDOWS]
    if extra.get("outcome"):
        failures = frame["failures"].to_numpy(dtype=np.int64)
        failed = trailing(series, steps, failures, sorted(set(steps_back) | {SUCCESS_AFTER_STEPS}))
        for minutes, back in zip(WINDOWS, steps_back):
            frame[f"fail_{minutes}m"] = failed[back].astype(np.int32)
            frame[f"log_fail_{minutes}m"] = np.log1p(failed[back]).astype(np.float32)
        frame["fail_share_30m"] = (failed[6] / np.maximum(counts[6], 1)).astype(np.float32)
        if kind in ("username", "source_ip"):             # one actor's failures, then its success (a server's or the
            frame["success_after_failures"] = np.where(          # whole log's mix different people's typos and logins)
                frame["successes"].to_numpy() > 0, np.log1p(failed[SUCCESS_AFTER_STEPS]), 0.0).astype(np.float32)
        if kind != "all":
            pair = row_hashes(frame["entity"].to_numpy(dtype=object), steps.astype(np.int64))
            for other in entities:
                if (kind, other) in extra.get("fail_distinct", {}):
                    values = extra["fail_distinct"][(kind, other)].reindex(pair, fill_value=0).to_numpy()
                    frame[f"distinct_failed_{other}_5m"] = np.log1p(values).astype(np.float32)
    if kind == "all":
        new = extra.get("new_whole", pd.Series(dtype=np.int64)).reindex(steps, fill_value=0).to_numpy(dtype=np.int64)
        frame["new_pairs_5m"] = np.log1p(new).astype(np.float32)
    else:
        keys = pd.MultiIndex.from_arrays([frame["entity"].to_numpy(dtype=object), steps])
        for other in entities:
            if (kind, other) in extra.get("new_by_pair", {}):
                values = extra["new_by_pair"][(kind, other)].reindex(keys, fill_value=0).to_numpy()
                frame[f"new_{other}_5m"] = np.log1p(values).astype(np.float32)
        total = extra.get("new_by_kind", {}).get(kind)
        new = total.reindex(keys, fill_value=0).to_numpy(dtype=np.int64) if total is not None else np.zeros(len(frame), np.int64)
    recent = trailing(series, steps, new, [NOVELTY_MINUTES // STEP_MINUTES])[NOVELTY_MINUTES // STEP_MINUTES]
    frame["new_partners_120m"] = recent.astype(np.int32)
    frame["log_new_partners_120m"] = np.log1p(recent).astype(np.float32)
    frame["cross_zone_5m"] = np.log1p(frame["cross"].to_numpy(dtype=np.int64)).astype(np.float32)


def add_regularity(frame, series, steps, lines):
    """count_cv_60m and gap_cv_720m (module docstring), from this step back, the series' own steps only."""
    hour = 60 // STEP_MINUTES
    sums = trailing(series, steps, lines, [hour])[hour].astype(float)
    squares = trailing(series, steps, lines.astype(np.int64) ** 2, [hour])[hour].astype(float)
    mean = sums / hour
    spread = np.sqrt(np.maximum(squares / hour - mean ** 2, 0.0))
    frame["count_cv_60m"] = np.where(mean > 0, spread / np.maximum(mean, 1e-9), 0.0).astype(np.float32)
    active = lines > 0
    previous = pd.Series(np.where(active, steps, np.nan)).groupby(series).shift().groupby(series).ffill().to_numpy()
    gap = np.where(active & ~np.isnan(previous), steps - np.nan_to_num(previous), 0).astype(np.int64)
    has = (gap > 0).astype(np.int64)
    span = 720 // STEP_MINUTES
    n = trailing(series, steps, has, [span])[span].astype(float)
    g1 = trailing(series, steps, gap, [span])[span].astype(float)
    g2 = trailing(series, steps, gap ** 2, [span])[span].astype(float)
    mean_gap = g1 / np.maximum(n, 1)
    cv = np.sqrt(np.maximum(g2 / np.maximum(n, 1) - mean_gap ** 2, 0.0)) / np.maximum(mean_gap, 1e-9)
    frame["gap_cv_720m"] = np.where(n >= 3, cv, 1.0).astype(np.float32)


def rel_name(column):
    """The name of a feature less the series' normal: rel_5m for log_5m, rel_gap_minutes for log_gap_minutes."""
    return "rel_" + column.removeprefix("log_")


def robust_channels(frame):
    """What robust deviation measures, in order: lines in each window (both ways); failures in each window (auth,
    upwards only: fewer failures is not a threat); new partners over 2 hours (upwards, against the level only: a
    calendar of first meetings means nothing). Each: name, log columns, raw columns, the count the calendar sums
    (None: no calendar), window minutes, whether a drop counts."""
    channels = [{"name": "lines", "logs": [f"log_{m}m" for m in WINDOWS], "raw": [f"lines_{m}m" for m in WINDOWS],
                 "calendar": "lines", "minutes": list(WINDOWS), "drops": True}]
    if all(f"log_fail_{m}m" in frame for m in WINDOWS):
        channels.append({"name": "failures", "logs": [f"log_fail_{m}m" for m in WINDOWS], "raw": [f"fail_{m}m" for m in WINDOWS],
                         "calendar": "failures", "minutes": list(WINDOWS), "drops": False})
    if "log_new_partners_120m" in frame:
        channels.append({"name": "new partners", "logs": ["log_new_partners_120m"], "raw": ["new_partners_120m"],
                         "calendar": None, "minutes": [NOVELTY_MINUTES], "drops": False})
    return channels


def other_features(frame):
    """The relations, context and regularity features this frame has, besides the robust channels' log columns."""
    pairs = sorted(c for c in frame.columns if c.startswith(("distinct_", "new_")) and c.endswith("_5m"))
    return pairs + [c for c in ("fail_share_30m", "success_after_failures", "cross_zone_5m", *REGULARITY_FEATURES) if c in frame]


def own_normal(frame, train, args):
    """Every feature less the series' normal (the forest's rel_ features), and the signed robust deviation of each robust
    channel's log columns from it.

    The normal is the series' training median over the steps in which it was active: its own, with at least
    --min-history training rows; else its PEERS' (the training rows of the entities with its role in the asset
    inventory, when there are --min-history of them); else its entity type's pooled rows. For the lines windows also
    the median at the same hour of day. Returns (frame, deviation, level, has_own, channels): deviation and level are
    rows x robust columns (level in log(1 + count)); has_own is whether the row's series has its own normal.
    """
    channels = robust_channels(frame)
    robust = [c for channel in channels for c in channel["logs"]]
    logs = channels[0]["logs"]
    columns = robust + SHAPE_FEATURES + [c for c in other_features(frame) if c not in robust]
    history = frame.loc[train, ["series"] + columns]
    sizes = history.groupby("series").size()
    own_series = sizes.index[sizes >= args.min_history]
    has_own = frame["series"].isin(own_series).to_numpy()
    mine = history[history["series"].isin(own_series)]
    median = mine.groupby("series")[columns].median()
    pooled_median = history[columns].median()
    pooled_mad = (history[robust] - pooled_median[robust]).abs().median()
    mad = (mine[robust] - median[robust].reindex(mine["series"]).to_numpy()).abs().groupby(mine["series"]).median()
    row_median = np.tile(pooled_median.to_numpy(dtype=float), (len(frame), 1))
    row_mad = np.tile(pooled_mad.to_numpy(dtype=float), (len(frame), 1))
    peer = np.full(len(frame), "", dtype=object)
    if "role" in frame:
        roles = frame["role"].astype(str).to_numpy(dtype=object)
        trained = roles[train]
        for role in sorted(set(roles[~has_own]) - {""}):
            mask = trained == role
            if mask.sum() >= args.min_history:
                part = history[mask]
                middle = part[columns].median()
                spread = (part[robust] - middle[robust]).abs().median()
                rows = ~has_own & (roles == role)
                row_median[rows] = middle.to_numpy(dtype=float)
                row_mad[rows] = spread.to_numpy(dtype=float)
                peer[rows] = role
    if has_own.any():
        row_median[has_own] = median.reindex(frame.loc[has_own, "series"]).to_numpy(dtype=float)
        row_mad[has_own] = mad.reindex(frame.loc[has_own, "series"]).to_numpy(dtype=float)
    values = frame[columns].to_numpy(dtype=float)
    relative = values - row_median
    deviation = relative[:, :len(robust)] / np.maximum(1.4826 * row_mad, args.robust_floor)
    frame["baseline"] = np.where(has_own, "own", np.where(peer != "", "role", "pooled"))
    frame["peer"] = peer
    for index, column in enumerate(columns):
        frame[rel_name(column)] = relative[:, index].astype(np.float32)
    cells = frame.loc[train, ["series", "time_hour"] + logs].groupby(["series", "time_hour"])
    hour_median = cells[logs].median()[cells.size() >= MIN_HOUR_ROWS]
    keys = pd.MultiIndex.from_arrays([frame["series"], frame["time_hour"]])
    seasonal = hour_median.reindex(keys).to_numpy(dtype=float)
    seasonal = np.where(np.isnan(seasonal), row_median[:, :len(logs)], seasonal)
    for index, minutes in enumerate(WINDOWS):
        frame[f"rel_hour_{minutes}m"] = (values[:, index] - seasonal[:, index]).astype(np.float32)
    return frame, deviation, row_median[:, :len(robust)], has_own, channels


def calendar(frame, rows, context, column="lines", minutes=WINDOWS, with_all=False):
    """The calendar baseline of the given rows (positions in frame, which is sorted by series, then step): the median
    and MAD of log(1 + `column`) in each window ending at the same clock time on the series' comparable training days
    (activity_explain.comparable_groups), quiet days counting as 0. Returns (median, mad), rows x windows and NaN with
    fewer than MIN_DAYS comparable days, each row's comparison group and its number of days, and the same median and
    MAD over all the series' training days at that clock time (the target shrink() draws a sparse weekday toward)
    when `with_all`.

    Rows of the same series, comparison and clock time share one baseline, computed once."""
    code = activity_explain
    holidays = context["holidays"]
    groups = code.calendar_groups(context["log_days"], holidays, context["train_end_day"])
    series = frame["series"].to_numpy(dtype=np.int64)
    steps = frame["step"].to_numpy(dtype=np.int64)
    starts = np.flatnonzero(np.r_[True, series[1:] != series[:-1]])
    first_day = np.zeros(int(series.max()) + 1, dtype=np.int64)
    first_day[series[starts]] = steps[starts] // STEPS_PER_DAY
    r_series, r_step = series[rows], steps[rows]
    group, days = code.comparable_groups(r_step // STEPS_PER_DAY, first_day[r_series], groups, holidays)
    median = np.full((len(rows), len(minutes)), np.nan)
    mad = np.full_like(median, np.nan)
    all_median, all_mad = np.full_like(median, np.nan), np.full_like(median, np.nan)
    picked = np.flatnonzero(days >= code.MIN_DAYS)
    if not len(picked):
        return (median, mad, group, days, all_median, all_mad) if with_all else (median, mad, group, days)
    low, high = int(steps.min()), int(steps.max()) + 1
    stride = high - low + 2
    keys = series * stride + (steps - low)
    cumulative = np.concatenate([[0], np.cumsum(frame[column].to_numpy(dtype=np.int64))])

    def lines(of, start, end):
        """The column's sum for series `of` in steps [start, end)."""
        a, b = np.clip(start, low, high) - low, np.clip(end, low, high) - low
        return cumulative[np.searchsorted(keys, of * stride + b)] - cumulative[np.searchsorted(keys, of * stride + a)]

    clock = STEPS_PER_DAY + 1
    offset = r_step % STEPS_PER_DAY + 1                       # the window ends after this step
    unique, inverse = np.unique((r_series[picked] * len(groups) + group[picked]) * clock + offset[picked], return_inverse=True)
    u_series, u_group, u_offset = unique // (len(groups) * clock), (unique // clock) % len(groups), unique % clock
    u_median = np.full((len(unique), len(minutes)), np.nan)
    u_mad = np.full_like(u_median, np.nan)
    lengths = [m // STEP_MINUTES for m in minutes]

    def window_stats(series_of, offset_of, days_of, out_median, out_mad, members):
        """Median and MAD over `days_of` (from each series' first day) of every window ending at its clock time."""
        for at in range(0, len(members), CALENDAR_CHUNK):
            part = members[at:at + CALENDAR_CHUNK]
            k = np.searchsorted(days_of, first_day[series_of[part]])
            n = len(days_of) - k
            if not len(days_of) or n.max() <= 0:
                continue
            j = np.arange(int(n.max()))
            valid = j[None, :] < n[:, None]
            ends = days_of[np.minimum(k[:, None] + j[None, :], len(days_of) - 1)] * STEPS_PER_DAY + offset_of[part, None]
            for w, length in enumerate(lengths):
                values = np.where(valid, np.log1p(lines(series_of[part, None], ends - length, ends)), np.nan)
                middle = np.nanmedian(values, axis=1)
                out_median[part, w] = middle
                out_mad[part, w] = np.nanmedian(np.abs(values - middle[:, None]), axis=1)

    for g in np.unique(u_group):
        window_stats(u_series, u_offset, groups[g], u_median, u_mad, np.flatnonzero(u_group == g))
    median[picked], mad[picked] = u_median[inverse], u_mad[inverse]
    if not with_all:
        return median, mad, group, days
    every = np.unique(np.concatenate([np.asarray(g, dtype=np.int64) for g in groups])) if groups else np.zeros(0, dtype=np.int64)
    whole, back = np.unique(r_series[picked] * clock + offset[picked], return_inverse=True)
    w_median, w_mad = np.full((len(whole), len(minutes)), np.nan), np.full((len(whole), len(minutes)), np.nan)
    window_stats(whole // clock, whole % clock, every, w_median, w_mad, np.arange(len(whole)))
    all_median[picked], all_mad[picked] = w_median[back], w_mad[back]
    return median, mad, group, days, all_median, all_mad


def shrink(median, mad, all_median, all_mad, n, k):
    """The weekday baseline drawn toward the all-days one with weight n / (n + k): a weekday with few comparable days
    leans on the series' every day, one with many keeps its own. k = 0 leaves it as it was."""
    if not k:
        return median, mad
    w = (n / (n + float(k)))[:, None]
    has = ~np.isnan(all_median)
    return (np.where(has & ~np.isnan(median), w * median + (1 - w) * all_median, median),
            np.where(has & ~np.isnan(mad), w * mad + (1 - w) * all_mad, mad))


def choose_shrinkage(seen, median, mad, all_median, all_mad, n, series, tune, floor):
    """k from SHRINK_GRID that makes the share of steps above |z| 3 most even across series on validation's earlier
    half (`tune`): an entity with few comparable days should not alert more often for that alone."""
    best, spread_best = 0, np.inf
    for k in SHRINK_GRID:
        middle, scale = shrink(median, mad, all_median, all_mad, n, k)
        z = np.abs((seen - middle) / np.maximum(1.4826 * scale, floor))         # rows x windows
        exceed = np.nan_to_num(z, nan=0.0).max(axis=1) > 3
        per = pd.DataFrame({"s": series[tune], "e": exceed[tune]}).groupby("s")["e"].agg(["mean", "size"])
        per = per[per["size"] >= SHRINK_MIN_ROWS]
        if len(per) < 2:
            return 0
        spread = float(per["mean"].std())
        if spread < spread_best - 1e-12:
            best, spread_best = k, spread
    return best


def slug(name):
    return name.replace(" ", "_")


def robust_deviation(frame, split, deviation, level, has_own, channels, context, args, tune=None):
    """Each step's robust deviation (the module docstring's rule), over every channel's windows: for validation and test
    steps, per window the smaller of its calendar and level deviations when both point the same way; drops only in the
    lines channel, for a series with its own level and a calendar median of at least --min-drop-lines; failures from
    --min-failures; without comparable days, for the new-partners channel, and for training steps, the level deviation
    upwards only. Returns (frame, signed deviations as rows x columns, what each column is); sets each channel's
    largest |z| (robust_z_<channel>), calendar_days and calendar_basis. pick_channel() then chooses per step.
    The weekday baselines are shrunk toward each series' all-days one (shrink(); k from --shrinkage-days, chosen on
    the `tune` rows, validation's earlier half, when 'auto'); meta["shrinkage_days"] says which k."""
    signed = np.maximum(deviation, 0.0)
    calendar_counts = np.full(deviation.shape, np.nan)
    group = np.full(len(frame), -1, dtype=np.int64)
    days = np.zeros(len(frame), dtype=np.int64)
    rows = np.flatnonzero(np.isin(split, ["validation", "test"]))
    k = None if str(args.shrinkage_days) == "auto" else int(args.shrinkage_days)
    first = 0
    for channel in channels:
        cols = slice(first, first + len(channel["logs"]))
        first += len(channel["logs"])
        if not len(rows) or channel["calendar"] is None:
            continue
        median, mad, g, n, all_median, all_mad = calendar(frame, rows, context, channel["calendar"], channel["minutes"], with_all=True)
        if channel["name"] == "lines":
            group[rows], days[rows] = g, n
        seen = np.log1p(frame[channel["raw"]].to_numpy(dtype=float)[rows])
        if k is None:                                   # chosen once, on the first channel with a calendar
            tune_rows = tune[rows] if tune is not None else np.isin(split[rows], ["validation"])
            k = choose_shrinkage(seen, median, mad, all_median, all_mad, n.astype(float),
                                 frame["series"].to_numpy()[rows], tune_rows, args.robust_floor)
        median, mad = shrink(median, mad, all_median, all_mad, n.astype(float), k)
        against = (seen - median) / np.maximum(1.4826 * mad, args.robust_floor)
        level_z = deviation[rows, cols]
        known = ~np.isnan(against)
        up = known & (level_z > 0) & (against > 0)
        down = (known & (level_z < 0) & (against < 0) & has_own[rows, None] & (np.expm1(median) >= args.min_drop_lines)
                if channel["drops"] else np.zeros_like(known))
        signed[rows, cols] = np.where(known, np.where(up, np.minimum(level_z, against), np.where(down, np.maximum(level_z, against), 0.0)),
                                      np.maximum(level_z, 0.0))
        calendar_counts[rows, cols] = np.expm1(median)
    first = 0
    for channel in channels:
        cols = slice(first, first + len(channel["logs"]))
        first += len(channel["logs"])
        if channel["name"] == "failures":                     # a handful of failures is everyday: no alert below the minimum
            signed[:, cols] = np.where(frame[channel["raw"]].to_numpy() >= args.min_failures, signed[:, cols], 0.0)
    meta = {"names": np.asarray([channel["name"] for channel in channels for _ in channel["logs"]]),
            "minutes": np.asarray([m for channel in channels for m in channel["minutes"]]),
            "raw": frame[[c for channel in channels for c in channel["raw"]]].to_numpy(),
            "usual": np.where(np.isnan(calendar_counts), np.expm1(level), calendar_counts), "shrinkage_days": k or 0}
    for channel in channels:
        frame[f"robust_z_{slug(channel['name'])}"] = np.abs(signed[:, meta["names"] == channel["name"]]).max(axis=1)
    frame["calendar_days"] = days
    groups = np.asarray(activity_explain.GROUP_NAMES + ("",))
    frame["calendar_basis"] = np.where(days >= activity_explain.MIN_DAYS, groups[group], "")
    return frame, signed, meta


def pick_channel(frame, signed, meta, thresholds):
    """Each step's channel and window furthest above its own channel's threshold: robust_ratio (|z| / threshold, an
    alert from 1), robust_z, robust_channel, robust_window, robust_direction, robust_observed (the count there) and
    usual_window_lines (its calendar median, else the level)."""
    bar = np.asarray([thresholds[name] for name in meta["names"]], dtype=float)
    ratio = np.abs(signed) / bar
    column = ratio.argmax(axis=1)
    at = np.arange(len(frame))
    frame["robust_ratio"] = ratio[at, column]
    frame["robust_z"] = np.abs(signed[at, column])
    frame["robust_channel"] = meta["names"][column]
    frame["robust_window"] = meta["minutes"][column]
    frame["robust_direction"] = np.where(signed[at, column] < 0, "lower", "higher")
    frame["robust_observed"] = meta["raw"][at, column]
    frame["usual_window_lines"] = meta["usual"][at, column].round(1)
    return frame


def candidate_features(frame, kind, use_time):
    """The forest's candidates, in the order the near-copy filter keeps them.

    Whole log: volumes (log twins before raw counts), failures, new partners, shape, who, relations, context,
    regularity and time. Entity views: every feature less the entity's own normal, and time, so an entity is judged
    against itself, not against busier or quieter peers.
    """
    robust = [c for channel in robust_channels(frame) for c in channel["logs"]]
    hourly = [f"rel_hour_{m}m" for m in WINDOWS]
    time = TIME_FEATURES if use_time else []
    if kind == "all":
        groups = robust + hourly + SHAPE_FEATURES + other_features(frame) + time + [f"lines_{m}m" for m in WINDOWS]
    else:
        groups = [rel_name(c) for c in robust] + hourly + [rel_name(c) for c in SHAPE_FEATURES + other_features(frame)] + time
    return [c for c in groups if c in frame.columns]


def filter_features(frame, split, columns, rng):
    """Drop constant, shifted and near-copy features (training and validation only); return kept and decisions."""
    def sample(name):
        rows = np.flatnonzero(split == name)
        if len(rows) > RELEVANCE_SAMPLE:
            rows = np.sort(rng.choice(rows, RELEVANCE_SAMPLE, replace=False))
        return frame.iloc[rows][columns].to_numpy(dtype=np.float64)
    train, validation = sample("train"), sample("validation")
    std = train.std(axis=0)
    decision = np.where(std < CONSTANT_STD, "constant_in_training", "")
    ks = np.full(len(columns), np.nan)
    if len(validation):
        for j in np.flatnonzero(decision == ""):
            ks[j] = stats.ks_2samp(train[:, j], validation[:, j], method="asymp").statistic
        decision = np.where((decision == "") & (ks > DRIFT_MAX_KS), "drift_train_vs_validation", decision)
    detail = np.full(len(columns), "", dtype=object)
    kept = np.flatnonzero(decision == "")
    if len(kept) > 1:
        correlation = np.nan_to_num(np.abs(np.corrcoef(train[:, kept], rowvar=False)), nan=0.0)
        alive = np.ones(len(kept), dtype=bool)
        for i in range(len(kept)):
            if alive[i]:
                for d in np.flatnonzero(correlation[i, i + 1:] > REDUNDANCY_MAX_CORR) + i + 1:
                    if alive[d]:
                        alive[d] = False
                        decision[kept[d]] = "redundant"
                        detail[kept[d]] = "with " + columns[kept[i]]
    decision = np.where(decision == "", "kept", decision)
    table = pd.DataFrame({"feature_name": columns, "train_std": std.round(6), "drift_ks": ks.round(4),
                          "decision": decision, "detail": detail})
    return [c for c, d in zip(columns, decision) if d == "kept"], table


def balanced_rows(frame, train, args, rng):
    """Training rows for the forest: each series with its own baseline gives the same number (drawn again when short).

    Without this, an entity type's busiest series would define normal, and a nightly job's routine would look rare.
    Series with fewer than --min-history training rows give what they have.
    """
    rows = np.flatnonzero(train)
    series = frame["series"].to_numpy()[rows]
    names, sizes = np.unique(series, return_counts=True)
    if len(names) == 1:
        return rows if len(rows) <= args.train_sample else np.sort(rng.choice(rows, args.train_sample, replace=False))
    quota = max(args.train_sample // len(names), 1)
    order = np.argsort(series, kind="stable")
    chosen, start = [], 0
    for size in sizes:
        members = rows[order[start:start + size]]
        start += size
        if size >= quota:
            chosen.append(rng.choice(members, quota, replace=False))
        elif size >= args.min_history:
            chosen.append(rng.choice(members, quota, replace=True))
        else:
            chosen.append(members)
    return np.concatenate(chosen)


def forest(frame, train, columns, args, rng):
    rows = balanced_rows(frame, train, args, rng)
    model = IsolationForest(n_estimators=TREES, max_samples=min(256, len(rows)), random_state=SEED, n_jobs=-1)
    model.fit(frame.iloc[rows][columns].to_numpy(dtype=np.float32))
    scores = np.empty(len(frame))
    for start in range(0, len(frame), CHUNK):
        scores[start:start + CHUNK] = -model.score_samples(frame.iloc[start:start + CHUNK][columns].to_numpy(dtype=np.float32))
    frame["forest_score"] = scores
    return frame


def budget_threshold(scores, split, days, args, floor=None):
    """At most alerts-per-day x validation days, and max-validation-share of the validation rows."""
    validation = scores[split == "validation"]
    validation = validation[np.isfinite(validation)]
    allowed = min(int(args.alerts_per_day * days), int(args.max_validation_share * len(validation)))
    if len(validation) >= MIN_VALIDATION_ROWS and allowed >= 1:
        index = len(validation) - allowed
        threshold = float(np.partition(validation, index)[index])
        if np.count_nonzero(validation >= threshold) > allowed:
            threshold = float(np.nextafter(threshold, np.inf))
        source = "validation_budget"
    else:
        training = scores[split == "train"]
        threshold = float(np.quantile(training, FALLBACK_QUANTILE)) if len(training) else float("inf")
        source = "training_quantile_fallback"
    if floor is not None and threshold < floor:
        threshold, source = floor, source + " (raised to the floor)"
    return threshold, source, allowed


def score_type(view, kind, frame, bounds, args, rng, context):
    """Score one view / entity type; return (test alert steps, feature decisions, summary row)."""
    train_end, validation_end, _ = bounds
    split = np.where(frame["start"] < train_end, "train", np.where(frame["start"] < validation_end, "validation", "test"))
    if "usable" in frame:
        split = np.where(frame["usable"].to_numpy(), split, "excluded")
    frame["split"] = split
    train = split == "train"
    row = {"view": view, "entity_type": kind, "series": int(frame["series"].nunique()), "rows": len(frame),
           **{f"{name}_rows": int(np.count_nonzero(split == name)) for name in ("train", "validation", "test", "excluded")}}
    if row["train_rows"] < MIN_TRAIN_ROWS:
        row["status"] = f"skipped: fewer than {MIN_TRAIN_ROWS} training rows"
        return frame.iloc[0:0], pd.DataFrame(), row
    validation = split == "validation"
    if args.calibration_split == "halves" and validation.any():
        middle = train_end + (validation_end - train_end) / 2
        choose = validation & (frame["start"] < middle).to_numpy()
    else:
        choose = validation
    calibrate = validation & ~choose if args.calibration_split == "halves" else validation
    select_split = np.where(validation & ~choose, "validation_calibration", split)   # the filter sees the earlier half
    calibrate_split = np.where(choose & ~calibrate, "validation_selection", split)    # the quotas see the later half
    frame, deviation, level, has_own, channels = own_normal(frame, train, args)
    frame, signed, meta = robust_deviation(frame, split, deviation, level, has_own, channels, context, args, tune=choose)
    days = len(np.unique(frame["step"].to_numpy()[calibrate] // STEPS_PER_DAY))
    thresholds, sources = {}, {}
    for channel in channels:                    # each channel its own bar: a noisy one cannot raise the others'
        thresholds[channel["name"]], sources[channel["name"]], quota = budget_threshold(
            frame[f"robust_z_{slug(channel['name'])}"].to_numpy(), calibrate_split, days, args, floor=args.min_robust_z)
        allowed = quota if channel["name"] == "lines" else allowed
    frame = pick_channel(frame, signed, meta, thresholds)
    candidates = candidate_features(frame, kind, not args.no_time)
    kept, decisions = filter_features(frame, select_split, candidates, rng)
    if not kept:
        kept = [f"log_{minutes}m" for minutes in WINDOWS] if kind == "all" else [f"rel_{minutes}m" for minutes in WINDOWS]
        decisions.loc[decisions["feature_name"].isin(kept), "decision"] = "kept (every feature was filtered out)"
    frame = forest(frame, train, kept, args, rng)
    forest_threshold, forest_source, _ = budget_threshold(frame["forest_score"].to_numpy(), calibrate_split, days, args)
    training_scores = frame.loc[train, "forest_score"].to_numpy()
    forest_alone = max(forest_threshold, float(np.quantile(training_scores, args.forest_alone_quantile)))
    bar = (frame["robust_ratio"] >= 1).to_numpy()
    discovered, null_steps = fdr_pass(frame, choose, calibrate | (split == "test"), args.fdr)
    frame["robust_flag"] = bar & discovered
    frame["forest_flag"] = frame["forest_score"] >= forest_threshold                 # agrees: a second opinion
    frame["forest_alone_flag"] = frame["forest_score"] >= forest_alone               # strong enough to alert on its own
    frame["step_score"] = (np.maximum(frame["robust_ratio"], frame["forest_score"] / forest_alone)
                           + (frame["robust_flag"] & frame["forest_flag"]).astype(float))
    test = split == "test"
    alerting = (frame["robust_flag"] | frame["forest_alone_flag"]).to_numpy()
    alerts = frame[test & alerting].copy()
    scored = np.isin(split, ["validation", "test"])
    row.update({"status": "scored", "features_considered": len(candidates), "features_kept": len(kept),
                "validation_days": int(days), "allowed_validation_alerts": allowed,
                "calibration_split": args.calibration_split, "validation_selection_steps": int(choose.sum()),
                "validation_calibration_steps": int(calibrate.sum()), "fdr": args.fdr, "fdr_null_steps": int(null_steps),
                "shrinkage_days": int(meta.get("shrinkage_days", 0)),
                "test_robust_steps_bar_only": int((bar & (split == "test")).sum()),
                "own_baseline_series": int(frame.loc[frame["baseline"].eq("own"), "series"].nunique()),
                "robust_threshold": round(thresholds["lines"], 6), "robust_threshold_source": sources["lines"],
                **{f"robust_threshold_{slug(name)}": round(value, 6) for name, value in thresholds.items() if name != "lines"},
                **{f"robust_threshold_{slug(name)}_source": value for name, value in sources.items() if name != "lines"},
                "forest_threshold": round(forest_threshold, 6), "forest_threshold_source": forest_source,
                "forest_alone_threshold": round(forest_alone, 6), "forest_alone_quantile": args.forest_alone_quantile,
                "calendar_share": round(float((frame["calendar_days"].to_numpy()[scored] >= activity_explain.MIN_DAYS).mean()), 4)
                if scored.any() else None,
                "validation_robust_alerts": int((frame["robust_flag"] & (split == "validation")).sum()),
                "validation_forest_alerts": int((frame["forest_flag"] & (split == "validation")).sum()),
                "validation_forest_alone_alerts": int((frame["forest_alone_flag"] & (split == "validation")).sum()),
                "test_alert_steps": len(alerts),
                "test_robust_steps": int((frame["robust_flag"].to_numpy() & test).sum()),
                "test_forest_alone_steps": int((frame["forest_alone_flag"].to_numpy() & ~frame["robust_flag"].to_numpy() & test).sum()),
                "test_drop_steps": int((frame["robust_flag"].to_numpy() & test & frame["robust_direction"].eq("lower").to_numpy()).sum()),
                "test_failure_steps": int((frame["robust_flag"].to_numpy() & test & frame["robust_channel"].eq("failures").to_numpy()).sum()),
                "test_new_partner_steps": int((frame["robust_flag"].to_numpy() & test
                                               & frame["robust_channel"].eq("new partners").to_numpy()).sum()),
                "peer_baseline_series": int(frame.loc[frame["baseline"].eq("role"), "series"].nunique())})
    return alerts, decisions, row


def null_p(null, z):
    """p-values of z against the sorted null: the share of the null at or above z in its body; beyond the null's top k
    values (k = TAIL_SHARE of it, at least TAIL_MIN), an exponential tail fitted to their excesses over the next value
    down (peaks over threshold: a generalised Pareto with shape 0, its scale the mean excess), so a step far beyond
    every null step gets a p as small as it deserves rather than 1 / (n + 1). Robust z on counts has many ties, so the
    top k are taken by rank, not by being strictly above a quantile."""
    n = len(null)
    p = (1 + n - np.searchsorted(null, z, side="left")) / (1 + n)
    k = max(int(TAIL_SHARE * n), TAIL_MIN)
    if n > k:
        u = float(null[n - k - 1])
        scale = float((null[n - k:] - u).mean())
        if scale > 0:
            above = z > u
            p[above] = np.minimum(p[above], (k / n) * np.exp(-(z[above] - u) / scale))
    return p


def fdr_pass(frame, null_rows, scored_rows, q):
    """(passed, null size): Benjamini-Hochberg at q across each day's scored steps, each step's p from the null of
    validation's earlier half (null_p). Steps of other days and splits pass; with q 0 or fewer than FDR_MIN_NULL null
    steps, every step passes (no FDR step)."""
    passed = np.ones(len(frame), dtype=bool)
    z = frame["robust_z"].to_numpy(dtype=float)
    null = np.sort(z[null_rows])
    if q <= 0 or len(null) < FDR_MIN_NULL:
        return passed, len(null)
    p = null_p(null, z)
    day = frame["step"].to_numpy() // STEPS_PER_DAY
    passed[scored_rows] = False
    for d in np.unique(day[scored_rows]):
        idx = np.flatnonzero(scored_rows & (day == d))
        order = np.argsort(p[idx], kind="stable")
        below = p[idx][order] <= q * np.arange(1, len(idx) + 1) / len(idx)
        if below.any():
            passed[idx[order[:np.flatnonzero(below).max() + 1]]] = True
    return passed, len(null)


def episodes(steps, source, view, kind, merge_gap):
    """Alerting steps of one series, no more than merge_gap minutes apart, as one alert."""
    if steps.empty:
        return pd.DataFrame()
    steps = steps.sort_values(["series", "step"])
    gap = merge_gap // STEP_MINUTES
    steps["episode"] = (steps["series"].ne(steps["series"].shift()) | steps["step"].diff().gt(gap)).cumsum()
    rows = []
    for _, part in steps.groupby("episode", sort=False):
        peak = part.loc[part["step_score"].idxmax()]
        start, end = part["start"].min(), part["start"].max() + pd.Timedelta(minutes=STEP_MINUTES)
        detectors = [name for name, flag in (("activity_robust", "robust_flag"), ("activity_forest", "forest_flag"))
                     if part[flag].any()]
        entity = str(peak["entity"])
        rows.append({
            "row_manifest_id": hashlib.sha256(f"activity|{source}|{view}|{kind}|{entity}|{start}".encode()).hexdigest()[:24],
            "view": view, "entity_type": kind, "entity": entity, "start": str(start), "end": str(end),
            "steps": len(part), "first_step_value": int(part["step"].min()), "peak_step": str(peak["start"]),
            "peak_step_value": int(peak["step"]),
            "peak_lines_5m": int(peak["lines_5m"]), "peak_window_minutes": int(peak["robust_window"]),
            "peak_channel": peak["robust_channel"], "peak_window_lines": int(peak["robust_observed"]),
            "usual_window_lines": float(peak["usual_window_lines"]), "baseline": peak["baseline"],
            "direction": peak["robust_direction"] if part["robust_flag"].any() else "mix",
            "calendar_basis": peak["calendar_basis"], "calendar_days": int(peak["calendar_days"]), "peer": peak.get("peer", ""),
            "zone": peak.get("zone", ""), "role": peak.get("role", ""), "criticality": peak.get("criticality", ""),
            "robust_z": round(float(part["robust_z"].max()), 4), "forest_score": round(float(part["forest_score"].max()), 6),
            "activity_score": round(float(part["step_score"].max()) * CRITICALITY_WEIGHT.get(str(peak.get("criticality", "")), 1.0), 6),
            "activity_alert": True,
            "detector_combination": "+".join(detectors),
        })
    return pd.DataFrame(rows).sort_values("activity_score", ascending=False)


def describe(alert):
    who = ENTITY_LABELS[alert["entity_type"]] + ("" if alert["entity_type"] == "all" else f" {alert['entity']}")
    end = pd.Timestamp(alert["peak_step"]) + pd.Timedelta(minutes=STEP_MINUTES)
    usual = alert["usual_window_lines"]
    usual_text = f"{usual:,.0f}" if usual >= 10 else f"{usual:,.1f}"
    basis = str(alert.get("calendar_basis") or "")
    against = (f"usual {usual_text} on {basis} at this time" if basis and basis != "nan"
               else f"usual {usual_text} when active, {alert['baseline']} baseline")
    detectors = " and ".join({"activity_robust": "robust deviation", "activity_forest": "Isolation Forest"}[d]
                             for d in alert["detector_combination"].split("+"))
    steps = int(alert["steps"])
    count = int(alert["peak_window_lines"])
    noun = {"failures": "failure", "new partners": "new partner"}.get(str(alert.get("peak_channel") or "lines"), "line")
    return (f"[activity] {who}: {count:,} {noun}{'s' if count != 1 else ''} in the {alert['peak_window_minutes']} minutes to "
            f"{end:%Y-%m-%d %H:%M} ({against}); "
            f"{steps} alerting 5-minute step{'s' if steps != 1 else ''} from {alert['start'][:16]} to {alert['end'][:16]}; "
            f"flagged by {detectors}" + ("; the first lines of the peak step follow." if alert["peak_lines_5m"] else
                                         "; the peak step has no lines."))


def evidence(files, alerts, args, message_column, id_column):
    """A description, then the series' first --lines lines in the peak step, per alert, with each line's ID
    (event_ref) so the console can mark them among the lines around the alert."""
    rows = [(alert["row_manifest_id"], 0, describe(alert), "") for _, alert in alerts.iterrows()]
    wanted = {}
    for _, alert in alerts.iterrows():
        kind = alert["entity_type"]
        key = (kind, "" if kind == "all" else alert["entity"], int(alert["peak_step_value"]))
        wanted.setdefault(key, []).append(alert["row_manifest_id"])
    kept = {row_id: [] for ids in wanted.values() for row_id in ids}
    columns = ["timestamp", message_column, id_column] + sorted({ENTITY_TYPES[kind] for kind, _, _ in wanted if kind != "all"})
    peak_steps = {step for _, _, step in wanted}
    for chunk in read_chunks(files, columns) if wanted else []:
        chunk = chunk[chunk["step"].isin(peak_steps)]
        if chunk.empty:
            continue
        refs = chunk[id_column] if id_column in chunk else pd.Series("", index=chunk.index)
        for (kind, value, step), ids in wanted.items():
            if all(len(kept[row_id]) >= args.lines for row_id in ids):
                continue
            mask = chunk["step"].eq(step) & (entity_values(chunk, kind).eq(value) if kind != "all" else True)
            found = list(zip(chunk.loc[mask, "when"], chunk.loc[mask, message_column], refs[mask]))
            for row_id in ids:
                kept[row_id] += found[:args.lines - len(kept[row_id])]
    for row_id, lines in kept.items():
        for position, (_, message, ref) in enumerate(sorted(lines, key=lambda item: item[0]), start=1):
            rows.append((row_id, position, message, ref))
    return pd.DataFrame(rows, columns=["row_manifest_id", "event_position", message_column, "event_ref"])


def write_view(folder, alerts, evidence_rows, decisions, summary, explanations=()):
    folder.mkdir(parents=True, exist_ok=True)
    with open(folder / "explanations.jsonl", "w", encoding="utf-8") as handle:
        for record in explanations:
            handle.write(json.dumps(record, default=lambda o: o.item() if hasattr(o, "item") else str(o)) + "\n")
    columns = ["row_manifest_id", "view", "entity_type", "entity", "start", "end", "steps", "peak_step", "peak_lines_5m",
               "peak_window_minutes", "peak_channel", "peak_window_lines", "usual_window_lines", "baseline", "peer", "direction",
               "calendar_basis", "calendar_days", "zone", "role", "criticality", "robust_z", "forest_score", "activity_score",
               "activity_alert", "detector_combination", "incident_id", "incident_kind", "incident_size", "incident_lead"]
    (alerts.reindex(columns=columns) if len(alerts) else pd.DataFrame(columns=columns)).to_csv(
        folder / "test_scores.csv", index=False)
    evidence_rows.to_csv(folder / "test_raw_alert_evidence.csv", index=False)
    for kind, table in decisions.items():
        table.to_csv(folder / f"feature_decisions_{kind}.csv", index=False)
    (folder / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")


def explain_alerts(found, frame, decisions, row, context):
    """A plain-language record per alert (activity_explain.explain), from its series' rows."""
    if found is None or not len(found):
        return []
    series = frame["series"].to_numpy()
    kept = decisions.loc[decisions["decision"].str.startswith("kept"), "feature_name"].tolist() if len(decisions) else []
    train_rows = frame[frame["split"].eq("train")]
    if len(train_rows) > 20_000:
        train_rows = train_rows.sample(20_000, random_state=SEED)
    context = {**context, "thresholds": {"robust": row.get("robust_threshold"), "forest": row.get("forest_threshold"),
                                         "forest_alone": row.get("forest_alone_threshold"),
                                         "robust_by_channel": {"lines": row.get("robust_threshold"),
                                                               "failures": row.get("robust_threshold_failures"),
                                                               "new partners": row.get("robust_threshold_new_partners")}}}
    pairs = frame[["entity", "series"]].drop_duplicates("series")
    codes = dict(zip(pairs["entity"].astype(str), pairs["series"]))
    records = []
    for _, alert in found.iterrows():
        code = codes.get(str(alert["entity"]), 0)
        left, right = np.searchsorted(series, code, side="left"), np.searchsorted(series, code, side="right")
        records.append(activity_explain.explain(alert, frame.iloc[left:right], train_rows, kept, context))
    return records


def main(argv=None):
    args = parse_args(argv)
    spec = SOURCES[args.source]
    rng = np.random.default_rng(SEED)
    files = phase1_files(args)
    if not files:
        raise SystemExit(f"No Phase 1 files for {args.source} under {args.data / 'phase1_classify'}")
    log(f"{spec['label']} activity: counting lines per 5-minute step in {len(files)} Phase 1 files", args.quiet)
    outcome, assets = outcome_rule(args.source), Assets()
    counts = count_lines(files, args.entities, outcome, assets)
    total, counted = counts["total"], counts["counted"]
    whole_distinct, pair_distinct = counts["whole_distinct"], counts["pair_distinct"]
    log(f"Outcome features: {'from Phase 2' if outcome else 'none (no stated outcome rule)'}; asset inventory: "
        f"{len(assets.names) + len(assets.addresses) + len(assets.networks)} entries", args.quiet)
    if total.empty:
        raise SystemExit(f"No timestamped lines in the {args.source} Phase 1 files")
    bounds = split_bounds(args, total)
    log(f"Split: train to {bounds[0]:%Y-%m-%d %H:%M}, validation to {bounds[1]:%Y-%m-%d %H:%M} ({bounds[2]})", args.quiet)
    holidays = load_public_holidays()
    log_days = np.unique(total.index[total.to_numpy() > 0].to_numpy(dtype=np.int64) // STEPS_PER_DAY)
    warmup_step = (int(total.index.min()) // STEPS_PER_DAY + args.novelty_warmup_days) * STEPS_PER_DAY
    by_pair, by_kind, new_whole, partner_tables = new_partners(counts["first_pairs"], warmup_step)
    extra = {"outcome": outcome is not None, "fail_distinct": counts["fail_distinct"], "new_by_pair": by_pair,
             "new_by_kind": by_kind, "new_whole": new_whole}
    context = {"holidays": {activity_explain.day_number(day): name for day, name in holidays.items()},
               "log_days": log_days, "log_day_set": set(log_days.tolist()), "change_windows": load_change_windows(),
               "train_end_day": activity_explain.day_number(bounds[0])}
    common = {"generated_at": datetime.now().isoformat(timespec="seconds"), "layer": "activity",
              "probability_rule": "rank_within_alerts", "windows_minutes": list(WINDOWS), "step_minutes": STEP_MINUTES,
              "time_features": not args.no_time, "train_end": str(bounds[0]), "validation_end": str(bounds[1]),
              "split_basis": bounds[2], "merge_gap_minutes": args.merge_gap, "alerts_per_day": args.alerts_per_day,
              "min_history": args.min_history, "robust_floor": args.robust_floor, "min_robust_z": args.min_robust_z,
              "min_drop_lines": args.min_drop_lines, "min_failures": args.min_failures,
              "forest_alone_quantile": args.forest_alone_quantile,
              "rule": "calendar and level robust deviation; forest as second opinion (2026-10-28)",
              "outcome_features": outcome is not None, "asset_entries": len(assets.names) + len(assets.addresses) + len(assets.networks),
              "novelty_warmup_days": args.novelty_warmup_days, "channels": ["lines", "failures", "new partners"]}
    rows, results = [], {"activity": ([], {}), "activity_by_entity": ([], {})}
    explained = {"activity": [], "activity_by_entity": []}
    plan = [("activity", "all")] + [("activity_by_entity", kind) for kind in args.entities]
    for view, kind in plan:
        if kind == "all":
            frame = whole_log_rows(total, counts["extra"])
        elif kind in counted:
            frame = counted[kind]
            frame["series"] = frame["entity"].astype("category").cat.codes.astype(np.int64)
            frame = frame.sort_values(["series", "step"]).reset_index(drop=True)
            names = frame["entity"].astype(str)
            known = {name: assets.of(name) if kind in ZONED else ("", "", "") for name in names.unique()}
            for index, column in enumerate(("zone", "role", "criticality")):
                frame[column] = names.map({name: info[index] for name, info in known.items()}).astype("category")
        else:
            rows.append({"view": view, "entity_type": kind, "status": "skipped: no values in this log"})
            log(f"{view} / {kind}: no values in this log", args.quiet)
            continue
        frame = add_features(frame, kind, args.entities, whole_distinct, pair_distinct, holidays, extra)
        steps, decisions, row = score_type(view, kind, frame, bounds, args, rng, context)
        found = episodes(steps, args.source, view, kind, args.merge_gap)
        rows.append(row)
        results[view][0].append(found)
        explained[view] += explain_alerts(found, frame, decisions, row, {**context, "partners": partner_tables.get(kind)})
        if len(decisions):
            results[view][1][kind] = decisions
        log(f"{view} / {kind}: {row['series']:,} series, {row['rows']:,} steps, "
            f"{row.get('features_kept', 0)} of {row.get('features_considered', 0)} features kept, "
            f"{row.get('test_alert_steps', 0):,} alerting test steps, {len(found):,} episodes", args.quiet)
    found_by_view = {view: [frame for frame in found if len(frame)] for view, (found, _) in results.items()}
    every = [frame for frames in found_by_view.values() for frame in frames]
    grouped, incidents = activity_incidents.group(pd.concat(every, ignore_index=True) if every else pd.DataFrame(),
                                                  counts["pair_hours"])
    incident_columns = ["incident_id", "incident_kind", "incident_size", "incident_lead"]
    args.output.mkdir(parents=True, exist_ok=True)
    (incidents if len(incidents) else pd.DataFrame(columns=["incident_id", "kind", "title", "lead_view", "lead_id", "entity_type",
                                                            "entity", "channel", "start", "end", "days", "clock", "size", "score",
                                                            "members"])).to_csv(args.output / "incidents.csv", index=False)
    kinds = incidents["kind"].value_counts().to_dict() if len(incidents) else {}
    log(f"{len(grouped):,} alerts in {len(incidents):,} incidents ({kinds.get('recurring', 0):,} recurring, "
        f"{kinds.get('linked', 0):,} linked)", args.quiet)
    log("Collecting the lines of each alert's peak step", args.quiet)
    message = spec["message_column"]
    totals = {}
    for view, (found, decisions) in results.items():
        found = found_by_view[view]
        alerts = (pd.concat(found, ignore_index=True).sort_values("activity_score", ascending=False)
                  if found else pd.DataFrame())
        if len(alerts):
            alerts = alerts.merge(grouped[["row_manifest_id", *incident_columns]], on="row_manifest_id", how="left")
        evidence_rows = evidence(files, alerts, args, message, LINE_IDS[args.source]) if len(alerts) else pd.DataFrame(
            columns=["row_manifest_id", "event_position", message, "event_ref"])
        by_type = alerts["entity_type"].value_counts().to_dict() if len(alerts) else {}
        summary = {**common, "dataset": view, "test_activity_alerts": len(alerts),
                   "incidents": {"all_views": len(incidents), "kinds": {k: int(v) for k, v in kinds.items()}},
                   "by_entity_type": {k: int(v) for k, v in by_type.items()},
                   "types": [r for r in rows if r["view"] == view]}
        order = {row_id: n for n, row_id in enumerate(alerts["row_manifest_id"])} if len(alerts) else {}
        records = sorted(explained[view], key=lambda r: order.get(r["row_manifest_id"], 0))
        write_view(args.output / view, alerts, evidence_rows, decisions, summary, records)
        totals[view] = len(alerts)
    pd.DataFrame(rows).to_csv(args.output / "experiment_summary.csv", index=False)
    log(f"{spec['label']} activity done: {totals['activity']:,} whole-log and {totals['activity_by_entity']:,} "
        f"entity alerts -> {args.output}", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
