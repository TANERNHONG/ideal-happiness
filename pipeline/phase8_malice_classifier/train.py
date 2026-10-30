"""Train the baseline and (optionally) a BERT-family model on prepared corpora.

  python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own.csv --run data/phase8_malice_classifier/runs/auth_v1 --baseline-only
  python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own.csv --run data/phase8_malice_classifier/runs/auth_v1 --model distilbert-base-uncased
  python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own.csv --run data/phase8_malice_classifier/runs/auth_v2 --model ehsanaghaei/SecureBERT
  python pipeline/phase8_malice_classifier/train.py ... --test-source stage7          # train on public data, test only on our alerts

Writes <run>/baseline.joblib, <run>/bert/, <run>/metrics.json.
"""

from __future__ import annotations

import argparse
import sys
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_curve,
                             roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

import models
from common import raise_csv_field_limit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)


log = runlog.log


def load_corpora(paths: list[str]) -> pd.DataFrame:
    raise_csv_field_limit()
    frame = pd.concat([pd.read_csv(path, dtype=str, keep_default_na=False, engine="python")
                       for path in paths], ignore_index=True)
    frame = frame[(frame["text"].str.len() > 0) & frame["label"].isin(["benign", "malicious"])]
    # identical text with both labels teaches nothing; report it and drop it
    conflicts = frame.groupby("text")["label"].nunique()
    conflicting = set(conflicts[conflicts > 1].index)
    if conflicting:
        log(f"Dropping {len(conflicting):,} texts labelled both ways (check your labels)")
        frame = frame[~frame["text"].isin(conflicting)]
    frame = frame.drop_duplicates(["text", "label", "group"]).reset_index(drop=True)
    frame["y"] = (frame["label"] == "malicious").astype(int)
    return frame


def group_split(frame: pd.DataFrame, fraction: float, seed: int):
    """Split by group so windows from one host/day never sit on both sides.
    Retries seeds until both sides contain both classes."""
    for attempt in range(50):
        splitter = GroupShuffleSplit(n_splits=1, test_size=fraction, random_state=seed + attempt)
        keep, held = next(splitter.split(frame, groups=frame["group"]))
        if frame["y"].iloc[keep].nunique() == 2 and frame["y"].iloc[held].nunique() == 2:
            return frame.iloc[keep].reset_index(drop=True), frame.iloc[held].reset_index(drop=True)
    raise SystemExit("Could not make a group split with both classes on each side; "
                     "add more groups (hosts, days) or more malicious rows.")


def choose_threshold(y: np.ndarray, scores: np.ndarray, target_precision: float) -> float:
    """Lowest threshold whose validation precision reaches the target (catch the
    most while keeping false alarms acceptable); falls back to the best F1."""
    precision, recall, thresholds = precision_recall_curve(y, scores)
    precision, recall = precision[:-1], recall[:-1]
    meets = np.where(precision >= target_precision)[0]
    if len(meets):
        return float(thresholds[meets[0]])
    f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-9)
    return float(thresholds[int(np.argmax(f1))])


def evaluate(frame: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    y = frame["y"].to_numpy()
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    result = {
        "rows": int(len(y)), "malicious": int(y.sum()),
        "roc_auc": float(roc_auc_score(y, scores)) if len(set(y)) == 2 else None,
        "pr_auc": float(average_precision_score(y, scores)) if y.sum() else None,
        "threshold": threshold,
        "precision": float(tp / max(tp + fp, 1)), "recall": float(tp / max(tp + fn, 1)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "confusion": {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)},
        "by_source": {},
    }
    for source, part in frame.assign(score=scores).groupby("source"):
        py = part["y"].to_numpy()
        pp = (part["score"].to_numpy() >= threshold).astype(int)
        result["by_source"][source] = {
            "rows": int(len(py)), "malicious": int(py.sum()),
            "recall": float((pp & py).sum() / max(py.sum(), 1)),
            "false_positive_rate": float((pp & (1 - py)).sum() / max((1 - py).sum(), 1)),
        }
    return result


def report(name: str, metrics: dict) -> None:
    auc = metrics["pr_auc"]
    log(f"{name}: PR-AUC {auc if auc is None else round(auc, 4)} | at threshold {metrics['threshold']:.3f}: "
        f"precision {metrics['precision']:.3f}, recall {metrics['recall']:.3f}, "
        f"false-positive rate {metrics['false_positive_rate']:.4f}")
    for source, part in metrics["by_source"].items():
        log(f"{source}: {part['rows']:,} rows, recall {part['recall']:.3f}, FPR {part['false_positive_rate']:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", nargs="+", required=True)
    parser.add_argument("--run", required=True, help="output folder")
    parser.add_argument("--model", default="distilbert-base-uncased", help="Hugging Face model id or local folder")
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--test-source", help="hold out every row whose source starts with this as the test set")
    parser.add_argument("--max-train", type=int, default=60_000, help="cap BERT training rows (CPU time)")
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=3e-5)
    parser.add_argument("--target-precision", type=float, default=0.9)
    parser.add_argument("--seed", type=int, default=13)
    runlog.add_arguments(parser)
    args = parser.parse_args()

    run = Path(args.run)
    run.mkdir(parents=True, exist_ok=True)
    frame = load_corpora(args.corpus)
    log(f"Corpus: {len(frame):,} rows, {int(frame['y'].sum()):,} malicious, {frame['group'].nunique():,} groups")

    if args.test_source:
        held = frame["source"].str.startswith(args.test_source)
        if not held.any():
            raise SystemExit(f"No rows with source starting {args.test_source!r}")
        test = frame[held].reset_index(drop=True)
        train, valid = group_split(frame[~held].reset_index(drop=True), 0.15, args.seed)
    else:
        rest, test = group_split(frame, 0.15, args.seed)
        train, valid = group_split(rest, 0.176, args.seed + 1)   # ~70/15/15
    log(f"Split: train {len(train):,} / validation {len(valid):,} / test {len(test):,}")

    metrics = {"corpus": args.corpus, "split": {"train": len(train), "validation": len(valid), "test": len(test)}}

    import joblib
    baseline = models.build_baseline().fit(train["text"].tolist(), train["y"].to_numpy())
    joblib.dump(baseline, run / "baseline.joblib")
    valid_scores = baseline.predict_proba(valid["text"].tolist())[:, 1]
    threshold = choose_threshold(valid["y"].to_numpy(), valid_scores, args.target_precision)
    metrics["baseline"] = {"validation": evaluate(valid, valid_scores, threshold),
                           "test": evaluate(test, baseline.predict_proba(test["text"].tolist())[:, 1], threshold)}
    report("Baseline test", metrics["baseline"]["test"])

    if not args.baseline_only:
        bert_train = train
        if len(train) > args.max_train:
            bert_train = train.sample(args.max_train, random_state=args.seed)
            log(f"BERT trains on a {args.max_train:,}-row sample (--max-train)")
        scorer = models.train_bert(
            bert_train["text"].tolist(), bert_train["y"].tolist(), valid["text"].tolist(), valid["y"].to_numpy(),
            run, model_name=args.model, max_length=args.max_length, epochs=args.epochs,
            batch_size=args.batch_size, learning_rate=args.learning_rate, seed=args.seed, log=log)
        valid_scores = scorer.predict(valid["text"].tolist())
        threshold = choose_threshold(valid["y"].to_numpy(), valid_scores, args.target_precision)
        metrics["bert"] = {"model": args.model,
                           "validation": evaluate(valid, valid_scores, threshold),
                           "test": evaluate(test, scorer.predict(test["text"].tolist()), threshold)}
        report("BERT test", metrics["bert"]["test"])

    (run / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    log(f"Saved to {run}")


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
