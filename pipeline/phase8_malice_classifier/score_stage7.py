"""Add a maliciousness score to Phase 7 cumulative-alert CSVs.

  python pipeline/phase8_malice_classifier/score_stage7.py --run data/phase8_malice_classifier/runs/auth_v1 --kind bert \
      --inputs "data/phase7_alerts/auth/*.csv" --out data/phase8_malice_classifier/scored/auth

Each input gets a copy <name>_scored.csv with two extra columns after
"probability":
  malicious_score   0-1, the classifier's probability that the text is malicious
  malicious_flag    1 if the score reaches the threshold chosen on validation data
Rows are sorted by malicious_score, highest first. The original files are untouched.
"""

from __future__ import annotations

import argparse
import sys
import csv
import glob
import json
from pathlib import Path

import models
from common import raise_csv_field_limit, split_raw_messages, to_sequence
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True, help="folder written by train.py")
    parser.add_argument("--kind", choices=["baseline", "bert"], default="bert")
    parser.add_argument("--inputs", nargs="+", required=True, help="Phase 7 CSVs (globs allowed)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--batch", type=int, default=512)
    runlog.add_arguments(parser)
    args = parser.parse_args()

    raise_csv_field_limit()
    run = Path(args.run)
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    threshold = metrics[args.kind]["validation"]["threshold"]
    scorer = models.load_scorer(run, args.kind)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    paths = sorted({path for pattern in args.inputs for path in glob.glob(pattern)
                    if not path.endswith("_scored.csv")})
    if not paths:
        raise SystemExit(f"No files match {args.inputs}")
    for name in paths:
        with open(name, encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = list(reader.fieldnames or [])
            rows = list(reader)
        texts = [to_sequence(split_raw_messages(row.get("raw_messages", ""))) for row in rows]
        scores = []
        for start in range(0, len(texts), args.batch):
            scores.extend(float(value) for value in scorer.predict(texts[start:start + args.batch]))
        for row, score in zip(rows, scores):
            row["malicious_score"] = f"{score:.4f}"
            row["malicious_flag"] = int(score >= threshold)
        rows.sort(key=lambda row: float(row["malicious_score"]), reverse=True)

        name = "rank" if "rank" in fields else "probability"                 # "probability" before 2026-10-30
        at = fields.index(name) + 1 if name in fields else 0
        fields[at:at] = ["malicious_score", "malicious_flag"]
        target = out / f"{Path(name).stem}_scored.csv"
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        flagged = sum(row["malicious_flag"] for row in rows)
        runlog.log(f"{Path(name).name}: {len(rows):,} alerts, {flagged:,} at or above {threshold:.3f} -> {target}")


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
