"""Turn public datasets and our own labelled alerts into one corpus format.

Output CSV columns: text, label (benign|malicious), group, source, unit.
  text   normalised message, or several joined with " | "
  group  rows sharing a group never straddle train/test (host, scenario, day)
  unit   "line" or "window"

  python pipeline/phase8_malice_classifier/prepare_corpus.py ait     --root D:/data/AIT-LDSv2 --out data/phase8_malice_classifier/corpora/ait_auth.csv
  python pipeline/phase8_malice_classifier/prepare_corpus.py cicids  --root D:/data/CIC-IDS2017/GeneratedLabelledFlows --out data/phase8_malice_classifier/corpora/cicids.csv
  python pipeline/phase8_malice_classifier/prepare_corpus.py stage7  --inputs data/phase7_alerts/auth/*_labelled.csv --out data/phase8_malice_classifier/corpora/own.csv
"""

from __future__ import annotations

import argparse
import sys
import csv
import glob
import json
import math
import random
from collections import Counter
from pathlib import Path

from common import (binary_label, normalise, raise_csv_field_limit, split_raw_messages, to_sequence,
                    write_corpus)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)


def subsample_benign(rows: list[dict], ratio: float, seed: int) -> list[dict]:
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    keep = int(max(len(malicious), 1) * ratio)
    if ratio > 0 and len(benign) > keep:
        benign = random.Random(seed).sample(benign, keep)
    return malicious + benign


def window_rows(lines: list[str], flags: list[bool], group: str, source: str, window: int) -> list[dict]:
    rows = []
    for text, flag in zip(lines, flags):
        rows.append({"text": normalise(text), "label": "malicious" if flag else "benign",
                     "group": group, "source": source, "unit": "line"})
    if window > 1:
        for start in range(0, len(lines), window):
            chunk = lines[start:start + window]
            if len(chunk) < 2:
                continue
            rows.append({"text": to_sequence(chunk),
                         "label": "malicious" if any(flags[start:start + window]) else "benign",
                         "group": group, "source": source, "unit": "window"})
    return rows


# --- AIT Log Data Set V2.x ---------------------------------------------------
# <scenario>/gather/<host>/logs/.../auth.log  with line labels in
# <scenario>/labels/<host>/logs/.../auth.log  (one JSON object per line:
# {"line": 12, "labels": ["attacker_ssh", ...], "rules": {...}}).
# Check the layout of your download; adjust LABEL_DIR / --line-base if needed.
LABEL_DIR = "labels"
GATHER_DIR = "gather"


def load_ait_labels(path: Path, line_base: int) -> dict[int, list[str]]:
    labels = {}
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            raw = raw.strip()
            if raw:
                item = json.loads(raw)
                labels[int(item["line"]) - line_base] = list(item.get("labels", []))
    return labels


def build_ait(args) -> list[dict]:
    root = Path(args.root)
    rows = []
    label_counts = Counter()
    log_files = [path for name in args.files for path in root.rglob(name)
                 if GATHER_DIR in path.parts]
    if not log_files:
        raise SystemExit(f"No {args.files} under {root}/**/{GATHER_DIR}/")
    for log_path in sorted(log_files):
        parts = list(log_path.parts)
        at = len(parts) - 1 - parts[::-1].index(GATHER_DIR)
        scenario = parts[at - 1] if at > 0 else "ait"
        host = parts[at + 1] if at + 1 < len(parts) else "host"
        label_path = Path(*parts[:at], LABEL_DIR, *parts[at + 1:])
        labels = load_ait_labels(label_path, args.line_base) if label_path.exists() else {}
        with log_path.open(encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\n") for line in handle]
        flags = [bool(labels.get(index)) for index in range(len(lines))]
        for names in labels.values():
            label_counts.update(names)
        rows += window_rows(lines, flags, f"ait:{scenario}/{host}", f"ait:{log_path.name}", args.window)
        runlog.log(f"{scenario}/{host}/{log_path.name}: {len(lines):,} lines, {sum(flags):,} labelled"
                   + ("" if label_path.exists() else "; no label file found"))
    runlog.log(f"Attack labels: {dict(label_counts.most_common(12))}")
    return rows


# --- CIC-IDS2017 flows -------------------------------------------------------
# Flows are rendered as short token sentences. They are NOT PF log lines: use
# them to teach "scan / flood / brute force" shapes, and evaluate on our own PF
# alerts before trusting the result (see README).
CIC_COLUMNS = {
    "proto": "Protocol", "dport": "Destination Port", "duration_us": "Flow Duration",
    "fwd_pkts": "Total Fwd Packets", "bwd_pkts": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets", "bwd_bytes": "Total Length of Bwd Packets",
    "syn": "SYN Flag Count", "rst": "RST Flag Count", "fin": "FIN Flag Count",
}
PROTOCOLS = {"6": "tcp", "17": "udp", "1": "icmp"}


def bucket(value: str) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "na"
    if not math.isfinite(number) or number <= 0:
        return "0"
    return f"b{int(math.log2(number + 1))}"   # log2 bucket: b10 is about 1,000


def render_flow(row: dict) -> str:
    port = row.get(CIC_COLUMNS["dport"], "")
    port = "<EPH>" if port.isdigit() and int(port) >= 32768 else port
    fields = [f"proto={PROTOCOLS.get(row.get(CIC_COLUMNS['proto'], ''), row.get(CIC_COLUMNS['proto'], ''))}",
              f"dport={port}"]
    for key in ("duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"):
        fields.append(f"{key}={bucket(row.get(CIC_COLUMNS[key], ''))}")
    flags = [name for name in ("syn", "rst", "fin") if row.get(CIC_COLUMNS[name], "0") not in ("0", "0.0", "")]
    fields.append("flags=" + (",".join(flags) or "none"))
    return "flow " + " ".join(fields)


def build_cicids(args) -> list[dict]:
    rows = []
    attack_counts = Counter()
    files = sorted(Path(args.root).glob("*.csv"))
    if not files:
        raise SystemExit(f"No CSV files in {args.root}")
    for path in files:
        per_source: dict[str, list[tuple[str, bool]]] = {}
        with path.open(encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            header = [name.strip() for name in next(reader)]
            for values in reader:
                row = dict(zip(header, (value.strip() for value in values)))
                label = row.get("Label", "")
                if not label:
                    continue
                malicious = label.upper() != "BENIGN"
                attack_counts[label] += 1
                per_source.setdefault(row.get("Source IP", "all"), []).append((render_flow(row), malicious))
        for source_ip, flows in per_source.items():
            texts = [text for text, _ in flows]
            flags = [flag for _, flag in flows]
            group = f"cicids:{path.stem}"
            # Flow sentences contain no identifiers, so no normalise() needed
            for text, flag in flows:
                rows.append({"text": text, "label": "malicious" if flag else "benign",
                             "group": group, "source": "cicids", "unit": "line"})
            if args.window > 1 and source_ip != "all":
                for start in range(0, len(texts), args.window):
                    chunk = texts[start:start + args.window]
                    if len(chunk) >= 2:
                        rows.append({"text": " | ".join(chunk),
                                     "label": "malicious" if any(flags[start:start + args.window]) else "benign",
                                     "group": group, "source": "cicids", "unit": "window"})
        runlog.log(f"{path.name}: {sum(len(v) for v in per_source.values()):,} flows")
    runlog.log(f"Labels: {dict(attack_counts.most_common(16))}")
    return rows


# --- Our own Phase 7 alerts, labelled by an analyst --------------------------
# Label a copy of a Phase 7 CSV (or a Phase 8 sheet, or Phase 9's analyst_category
# column) with one of the triage categories in common.CATEGORIES; the older
# malicious / benign also work. security_relevant becomes "malicious",
# operationally_interesting and expected_behavior become "benign", and
# insufficient_context and blank rows are skipped. These are the most valuable
# rows in the corpus.


def build_stage7(args) -> list[dict]:
    raise_csv_field_limit()
    rows = []
    paths = sorted({path for pattern in args.inputs for path in glob.glob(pattern)})
    if not paths:
        raise SystemExit(f"No files match {args.inputs}")
    for name in paths:
        path = Path(name)
        kept = 0
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                label = binary_label(row.get(args.label_column))
                if label is None:
                    continue
                text = to_sequence(split_raw_messages(row.get("raw_messages", "")))
                if text:
                    rows.append({"text": text, "label": label,
                                 "group": f"stage7:{path.stem}:{row.get('dataset', '')}",
                                 "source": f"stage7:{path.stem.split('_')[0]}", "unit": "alert"})
                    kept += 1
        runlog.log(f"{path.name}: {kept:,} labelled rows")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="kind", required=True)
    ait = sub.add_parser("ait")
    ait.add_argument("--root", required=True)
    ait.add_argument("--files", nargs="+", default=["auth.log"], help="log file names to use, e.g. auth.log syslog")
    ait.add_argument("--line-base", type=int, default=1, help="first line number used in the label files")
    cic = sub.add_parser("cicids")
    cic.add_argument("--root", required=True, help="folder of CIC-IDS2017 CSVs (GeneratedLabelledFlows has Source IP)")
    own = sub.add_parser("stage7")
    own.add_argument("--inputs", nargs="+", required=True, help="labelled Phase 7 CSVs (globs allowed)")
    own.add_argument("--label-column", default="label")
    for command in (ait, cic, own):
        command.add_argument("--out", required=True)
        command.add_argument("--window", type=int, default=10, help="lines per sequence window (1 = lines only)")
        command.add_argument("--benign-ratio", type=float, default=10.0,
                             help="keep at most this many benign rows per malicious row (0 = keep all)")
        command.add_argument("--seed", type=int, default=13)
    runlog.add_arguments(parser)
    args = parser.parse_args()

    rows = {"ait": build_ait, "cicids": build_cicids, "stage7": build_stage7}[args.kind](args)
    if args.kind != "stage7":
        rows = subsample_benign(rows, args.benign_ratio, args.seed)
    counts = Counter(row["label"] for row in rows)
    write_corpus(rows, Path(args.out))
    runlog.log(f"Wrote {len(rows):,} rows to {args.out}: {dict(counts)}")


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
