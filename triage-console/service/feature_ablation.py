"""Does the model zoo's feature ranking match what detects attacks? A diagnostic, not a change.

The zoo ranks its features by how much shuffling each moves an Isolation Forest's score (feature_relevance.csv,
"importance"): the model's own sensitivity, which can favour noisy columns. This measures each selected feature's
value against the planted attacks instead (inject_eval): every outsider and sweep scenario is planted into the day
and run through Phases 1-3 and the zoo exactly as Analyze does; then each selected feature in turn is set to its
median over that day's observations (neutralised), and the planted observations the zoo still flags (ensemble or
consensus) are counted. A feature's value is the planted detections lost without it.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m service.feature_ablation DAY.log [DAY2.log ...] --month 2026-07 [--view authentication_sessions]

Prints the Spearman correlation between the two rankings and the features where they disagree most, by name (the
features are columns, never values); writes the table to var/evaluation/<model version>/ablation_<view>_<time>.csv.
A correlation near 1 says the current selection rule already favours what detects; a low one says change it
(stability, then redundancy, then planted-detection value).
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

from . import inject_eval, scoring
from .config import DATA, VAR

SOURCE = "auth"


def planted_rows(frame: pd.DataFrame, scenario) -> np.ndarray:
    """The observations naming the scenario's address or account."""
    hit = np.zeros(len(frame), dtype=bool)
    for column, values in (("source_ip", scenario.addresses), ("username", scenario.accounts)):
        if values and column in frame:
            hit |= frame[column].astype(str).isin(values).to_numpy()
    return hit


def flagged(matrix, view: str, feature_set: str) -> np.ndarray:
    z = scoring.zoo(SOURCE, view, matrix, feature_set)
    return np.asarray(z["consensus"]) | np.asarray(z["ensemble_alert"]) if z else np.zeros(matrix.shape[0], dtype=bool)


def ablate(days: list[list[str]], month: str, view: str = "authentication_sessions", feature_set: str = "selected") -> pd.DataFrame:
    """Per selected feature: planted detections with every feature, and lost when it is neutralised."""
    bundle = scoring._zoo_bundle(SOURCE, view, feature_set)
    if bundle is None:
        raise ValueError(f"No model-zoo bundle for {SOURCE}/{view}/{feature_set}.")
    _, names = scoring._preprocessing(SOURCE, view)
    selected = list(bundle["feature_indices"])
    found, lost = 0, np.zeros(len(selected))
    year = int(month[:4])
    for lines in days:
        host, day = inject_eval.day_of(lines, year)
        for scenario in inject_eval.scenarios(host, day):
            if scenario.family == "insider":
                continue
            with tempfile.TemporaryDirectory(prefix="huh-ablation-") as tmp:
                folder = Path(tmp)
                scoring._phase1_auth(inject_eval.plant(lines, scenario.lines, year), month, folder)
                frames = scoring._phase2(SOURCE, folder, {})
            frame = frames.get(view)
            if frame is None or not len(frame):
                continue
            rows = planted_rows(frame.reset_index(drop=True), scenario)
            if not rows.any():
                continue
            matrix = scoring.features(SOURCE, view, frame).toarray()
            base = flagged(matrix, view, feature_set)[rows]
            found += int(base.sum())
            for position, column in enumerate(selected):
                neutral = matrix.copy()
                neutral[:, column] = np.median(matrix[:, column])
                lost[position] += int((base & ~flagged(neutral, view, feature_set)[rows]).sum())
    return pd.DataFrame({"feature_index": selected, "feature_name": [names[i] for i in selected],
                         "planted_detected": found, "planted_lost": lost.astype(int)})


def compare(table: pd.DataFrame, relevance: pd.DataFrame) -> tuple[float, pd.DataFrame]:
    """Spearman's rho between planted-detection loss and the zoo's importance, and the table with both ranks."""
    merged = table.merge(relevance[["feature_index", "importance"]], on="feature_index", how="left")
    merged["loss_rank"] = merged["planted_lost"].rank(ascending=False)
    merged["importance_rank"] = merged["importance"].rank(ascending=False)
    rho = stats.spearmanr(merged["planted_lost"], merged["importance"], nan_policy="omit").statistic if len(merged) > 2 else np.nan
    merged["rank_gap"] = (merged["loss_rank"] - merged["importance_rank"]).abs()
    return float(rho), merged.sort_values("rank_gap", ascending=False)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("days", type=Path, nargs="+")
    parser.add_argument("--month", required=True)
    parser.add_argument("--view", default="authentication_sessions")
    parser.add_argument("--feature-set", default="selected")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", args.month):
        parser.error("--month is YYYY-MM")
    days = [path.read_text(encoding="utf-8", errors="replace").splitlines() for path in args.days]
    table = ablate(days, args.month, args.view, args.feature_set)
    relevance = pd.read_csv(DATA / "phase4_detection" / SOURCE / "model_zoo" / args.view / "feature_relevance.csv")
    rho, merged = compare(table, relevance)
    folder = VAR / "evaluation" / inject_eval.model_version()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"ablation_{args.view}_{datetime.now():%Y%m%d-%H%M%S}.csv"
    merged.to_csv(path, index=False)
    print(f"{int(table['planted_detected'].iloc[0]) if len(table) else 0} planted detections; {len(table)} selected features")
    print(f"Spearman rho, planted-detection loss against the zoo's importance: {rho:.2f}")
    for row in merged.head(10).itertuples():
        print(f"  {row.feature_name:<40} lost {row.planted_lost:>4}  rank {row.loss_rank:>5.0f} vs importance rank {row.importance_rank:>5.0f}")
    print(f"Table: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
