"""Model-zoo families: one vote per family of models that agree, so "consensus" counts ideas, not near-copies.

The zoo's thirteen models are not independent: PCA and SVD reconstruction, the two one-class SVMs, and the distance
models (k nearest neighbours, k-means, LOF) often flag the same rows, so "three models agree" can be one idea counted
three times. The zoo already drops the weaker of two members whose ranks almost coincide; this step groups the rest.

For each dataset and feature set of a model-zoo run (data/phase4_detection/<source>/model_zoo/<dataset>/<set>/):

1. On validation's choosing half (validation_part "selection", or every row for an older run), each pair of ensemble
   members' similarity is the larger of the Jaccard index of their alert sets and the Spearman correlation of their
   scores (at most SAMPLE rows).
2. Average-linkage clustering on 1 - similarity, cut at 1 - --min-similarity (default 0.6): a family is a group of
   members at least that similar on average.
3. On the test period, a family votes when any of its members flags the row; a row is a family-consensus alert when
   at least --min-families families vote (default 2; fewer when there are fewer families).

Writes families.json (the families, their similarity and the test counts beside the per-model vote consensus) and
consensus_alerts_families.csv (the same columns as consensus_alerts_min<N>.csv, plus family_vote_count and
flagged_families), which Phase 7 and the console's Analyze use in place of the per-model vote count.

    python pipeline/phase4_detection/zoo_families.py --source auth
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from scipy.cluster.hierarchy import fcluster, linkage
from scipy.spatial.distance import squareform

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  console output: pipeline/STYLE_GUIDE.md

LOGGER = runlog.LOGGER
SAMPLE = 50_000
SEED = 42


def similarity(alerts: pd.DataFrame, scores: pd.DataFrame, rng) -> pd.DataFrame:
    """Pairwise max(Jaccard of alert sets, Spearman of scores, 0) over the given rows."""
    names = list(alerts.columns)
    rows = np.arange(len(scores))
    if len(rows) > SAMPLE:
        rows = np.sort(rng.choice(rows, SAMPLE, replace=False))
    ranks = scores.iloc[rows].rank().fillna(0).to_numpy()
    out = np.eye(len(names))
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = alerts.iloc[:, i].to_numpy(bool), alerts.iloc[:, j].to_numpy(bool)
            union = np.count_nonzero(a | b)
            jaccard = np.count_nonzero(a & b) / union if union else 0.0
            rho = stats.spearmanr(ranks[:, i], ranks[:, j]).statistic if len(rows) > 2 else 0.0
            out[i, j] = out[j, i] = max(jaccard, float(np.nan_to_num(rho)), 0.0)
    return pd.DataFrame(out, index=names, columns=names)


def families(sim: pd.DataFrame, min_similarity: float) -> list[list[str]]:
    names = list(sim.index)
    if len(names) < 2:
        return [names] if names else []
    tree = linkage(squareform(1 - sim.to_numpy(), checks=False), method="average")
    labels = fcluster(tree, t=1 - min_similarity, criterion="distance")
    grouped: dict[int, list[str]] = {}
    for name, label in zip(names, labels):
        grouped.setdefault(int(label), []).append(name)
    return sorted(grouped.values(), key=lambda family: (-len(family), family))


def process(folder: Path, args, rng) -> dict | None:
    summary_path = folder / "dataset_summary.json"
    if not summary_path.is_file() or not (folder / "test_scores.csv").is_file():
        return None
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    members = [m for m in summary.get("ensemble_members", [])]
    if summary.get("status") != "completed" or not members:
        return None
    columns = [f"{m}_{kind}" for m in members for kind in ("score", "alert")]
    validation = pd.read_csv(folder / "validation_scores.csv", usecols=lambda c: c in {*columns, "validation_part"}, low_memory=False)
    if "validation_part" in validation:
        validation = validation[validation["validation_part"].isin(["selection", "all"])]
    sim = similarity(validation[[f"{m}_alert" for m in members]].set_axis(members, axis=1).astype(bool),
                     validation[[f"{m}_score" for m in members]].set_axis(members, axis=1), rng)
    groups = families(sim, args.min_similarity)
    test = pd.read_csv(folder / "test_scores.csv", low_memory=False, dtype={"row_manifest_id": str})
    flags = {f: test[[f"{m}_alert" for m in family]].astype(bool).any(axis=1) for f, family in enumerate(groups)}
    test["family_vote_count"] = np.sum([flags[f].to_numpy() for f in flags], axis=0) if flags else 0
    test["flagged_families"] = ["|".join("+".join(groups[f]) for f in flags if flags[f].iloc[i]) for i in range(len(test))] if flags else ""
    required = min(args.min_families, max(len(groups), 1))
    consensus = test[test["family_vote_count"] >= required].copy()
    voted = [m for m in members if f"{m}_alert" in consensus]
    consensus["flagged_by"] = ["|".join(m for m in voted if bool(row[f"{m}_alert"])) for _, row in consensus.iterrows()] if len(consensus) else ""
    if "member_vote_count" not in consensus:
        consensus["member_vote_count"] = consensus[[f"{m}_alert" for m in voted]].astype(bool).sum(axis=1) if voted else 0
    lead = ["row_manifest_id", "family_vote_count", "member_vote_count", "flagged_families", "flagged_by", "model_zoo_ensemble_score"]
    consensus = consensus.sort_values(["family_vote_count", "model_zoo_ensemble_score"], ascending=False)
    consensus[[c for c in lead if c in consensus] + [c for c in consensus.columns if c not in lead]].to_csv(
        folder / "consensus_alerts_families.csv", index=False)
    vote_consensus = int((test.get("member_vote_count", pd.Series(0, index=test.index)) >= summary.get("test_consensus_min_votes", 3)).sum())
    result = {"dataset": folder.parent.name, "feature_set": folder.name, "members": members, "families": groups,
              "min_similarity": args.min_similarity, "min_families": required,
              "similarity": {f"{a}|{b}": round(float(sim.loc[a, b]), 4) for i, a in enumerate(members) for b in members[i + 1:]},
              "test_family_consensus_alerts": int(len(consensus)), "test_vote_consensus_alerts": vote_consensus,
              "test_rows": int(len(test))}
    (folder / "families.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    LOGGER.info(f"{folder.parent.name}/{folder.name}: {len(members)} members in {len(groups)} families; "
                f"family consensus {len(consensus):,} test rows (vote consensus {vote_consensus:,})")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=("auth", "ossec"))
    parser.add_argument("--zoo", type=Path, help="default: data/phase4_detection/<source>/model_zoo")
    parser.add_argument("--min-similarity", type=float, default=0.6)
    parser.add_argument("--min-families", type=int, default=2)
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    zoo = args.zoo or Path("data/phase4_detection") / args.source / "model_zoo"
    rng = np.random.default_rng(SEED)
    with runlog.run(args) as outcome:
        rows = []
        with runlog.stage("Grouping model-zoo members into families"):
            for folder in sorted(p for p in zoo.glob("*/*") if p.is_dir()):
                found = process(folder, args, rng)
                if found:
                    rows.append({k: v for k, v in found.items() if k not in ("similarity", "members")})
        if not rows:
            LOGGER.error(f"No completed model-zoo run under {zoo}")
            outcome["status"] = "stopped"
            return 1
        pd.DataFrame(rows).assign(families=lambda f: f["families"].map(json.dumps)).to_csv(zoo / "families_summary.csv", index=False)
        LOGGER.info(f"Families written for {len(rows):,} dataset and feature-set runs: {(zoo / 'families_summary.csv').as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
