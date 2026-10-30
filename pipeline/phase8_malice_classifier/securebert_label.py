"""Labelling assistant built on raw SecureBERT (no fine-tuning).

  python pipeline/phase8_malice_classifier/securebert_label.py check
  python pipeline/phase8_malice_classifier/securebert_label.py suggest --inputs "data/phase7_alerts/auth/*.csv" --out data/phase8_malice_classifier/to_label/auth
  python pipeline/phase8_malice_classifier/securebert_label.py suggest --inputs "data/phase7_alerts/auth/*.csv" --seeds "data/phase8_malice_classifier/labelled/authlog_*.csv" --out data/phase8_malice_classifier/to_label/auth
  python pipeline/phase8_malice_classifier/securebert_label.py propagate --inputs "data/phase8_malice_classifier/to_label/auth/*_to_label.csv"

check      fill-mask sanity test: proves the weights and tokenizer load and behave.
suggest    for every Phase 7 alert, one SecureBERT pass gives
             - an embedding (mean of the alert's token states), used to group
               near-identical alerts into clusters so you label a cluster, not a row;
             - a zero-shot score: how strongly the masked-language head completes
               "Overall, this activity is <mask>." with malicious rather than benign words;
             - with --seeds (alerts you already labelled): the nearest labelled
               alerts and their majority label.
           Writes <name>_to_label.csv with an empty "label" column first.
propagate  after you label the representative row of a cluster, copies that
           label to the cluster's blank rows (only where the cluster agrees).

The labelled files feed straight into prepare_corpus.py stage7. The raw model
was never trained to judge logs: treat every suggestion as a hint to confirm.
"""

from __future__ import annotations

import argparse
import sys
import csv
import glob
import hashlib
import math
import os
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from common import canonical_category, raise_csv_field_limit, split_raw_messages, to_sequence
from models import pick_device
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

MODEL_DIR = Path(os.environ.get("SECUREBERT_DIR", Path.home() / "hf_models" / "SecureBERT"))
PROMPT = "Overall, this activity is"
MALICIOUS_WORDS = ["malicious", "suspicious", "hostile", "unauthorized", "dangerous", "illegal", "fraudulent"]
BENIGN_WORDS = ["normal", "benign", "legitimate", "routine", "expected", "harmless", "authorized"]
SPECIAL_TEXT = ("<mask>", "<s>", "</s>", "<pad>", "<unk>")
EXTRA_COLUMNS = ["label", "suggested_label", "suggestion_confidence", "suggested_by", "zero_shot_malicious",
                 "cluster", "cluster_size", "representative", "nearest_labelled_similarity",
                 "nearest_labelled_example"]


def defuse(text: str) -> str:
    """A log line must never inject a real <mask> or </s> token."""
    for token in SPECIAL_TEXT:
        text = text.replace(token, token.replace("<", "‹"))
    return text


class SecureBERT:
    def __init__(self, model_dir: Path, max_length: int = 256, batch_size: int = 16):
        import torch
        from transformers import AutoModelForMaskedLM, AutoTokenizer

        if not (model_dir / "pytorch_model.bin").exists():
            raise SystemExit(f"No SecureBERT in {model_dir}; run download_securebert.py first")
        self.torch = torch
        self.device = pick_device()
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForMaskedLM.from_pretrained(model_dir).to(self.device).eval()
        self.max_length = max_length
        self.batch_size = batch_size
        tok = self.tokenizer
        self.prompt_ids = ([tok.sep_token_id, tok.sep_token_id]
                           + tok(PROMPT, add_special_tokens=False)["input_ids"]
                           + [tok.mask_token_id]
                           + tok(".", add_special_tokens=False)["input_ids"] + [tok.sep_token_id])
        self.malicious_ids = self.verbaliser(MALICIOUS_WORDS)
        self.benign_ids = self.verbaliser(BENIGN_WORDS)

    def verbaliser(self, words: list[str]) -> list[int]:
        ids = []
        for word in words:
            pieces = self.tokenizer(" " + word, add_special_tokens=False)["input_ids"]
            if len(pieces) == 1:        # the mask predicts one token; skip multi-piece words
                ids.append(pieces[0])
        if not ids:
            raise SystemExit(f"None of {words} is a single token in this vocabulary")
        return ids

    def build(self, text: str) -> tuple[list[int], int]:
        """<s> alert </s></s> Overall, this activity is <mask>. </s>, alert cut head+tail."""
        ids = self.tokenizer(defuse(text), add_special_tokens=False, truncation=False)["input_ids"]
        room = self.max_length - 1 - len(self.prompt_ids)
        if len(ids) > room:
            head = room // 2
            ids = ids[:head] + ids[-(room - head):]
        return [self.tokenizer.cls_token_id, *ids, *self.prompt_ids], len(ids)

    def run(self, texts: list[str], log=print) -> tuple[np.ndarray, np.ndarray]:
        """Returns (embeddings [n, 768], zero-shot P(malicious) [n])."""
        torch = self.torch
        built = [self.build(text) for text in texts]
        order = sorted(range(len(texts)), key=lambda i: len(built[i][0]))   # similar lengths per batch
        embeddings = np.zeros((len(texts), self.model.config.hidden_size), dtype=np.float32)
        scores = np.zeros(len(texts), dtype=np.float32)
        pad = self.tokenizer.pad_token_id
        with torch.inference_mode():
            for start in range(0, len(order), self.batch_size):
                index = order[start:start + self.batch_size]
                width = max(len(built[i][0]) for i in index)
                ids = torch.full((len(index), width), pad, dtype=torch.long)
                attention = torch.zeros_like(ids)
                text_mask = torch.zeros((len(index), width), dtype=torch.float32)
                mask_at = []
                for row, i in enumerate(index):
                    sequence, text_length = built[i]
                    ids[row, :len(sequence)] = torch.tensor(sequence)
                    attention[row, :len(sequence)] = 1
                    text_mask[row, 1:1 + text_length] = 1.0
                    mask_at.append(sequence.index(self.tokenizer.mask_token_id))
                states = self.model.base_model(input_ids=ids.to(self.device),
                                               attention_mask=attention.to(self.device)).last_hidden_state
                weights = text_mask.to(self.device).unsqueeze(-1)
                pooled = (states * weights).sum(1) / weights.sum(1).clamp(min=1.0)
                at_mask = states[torch.arange(len(index), device=self.device),
                                 torch.tensor(mask_at, device=self.device)]
                logits = self.model.lm_head(at_mask).float()        # only the mask position
                malicious = torch.logsumexp(logits[:, self.malicious_ids], dim=-1)
                benign = torch.logsumexp(logits[:, self.benign_ids], dim=-1)
                embeddings[index] = pooled.float().cpu().numpy()
                scores[index] = torch.sigmoid(malicious - benign).cpu().numpy()
                if (start // self.batch_size) % 20 == 0:
                    log(f"Texts embedded: {min(start + self.batch_size, len(order)):,}/{len(order):,}")
        return embeddings, scores


# --- helpers ------------------------------------------------------------------


def expand(patterns: list[str], skip_suffix: str = "") -> list[str]:
    paths = sorted({path for pattern in patterns for path in glob.glob(pattern)})
    paths = [path for path in paths if not (skip_suffix and path.endswith(skip_suffix))]
    if not paths:
        raise SystemExit(f"No files match {patterns}")
    return paths


def read_csv(path: str) -> tuple[list[str], list[dict]]:
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def key(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def embed_with_cache(texts: list[str], cache_path: Path, model_factory) -> tuple[np.ndarray, np.ndarray]:
    """Re-runs (after more labelling) only embed texts not seen before."""
    cache: dict[str, tuple[np.ndarray, float]] = {}
    if cache_path.exists():
        data = np.load(cache_path)
        cache = {k: (e, s) for k, e, s in zip(data["keys"], data["embeddings"], data["scores"])}
    missing = [text for text in dict.fromkeys(texts) if key(text) not in cache]
    if missing:
        runlog.log(f"Running SecureBERT on {len(missing):,} new texts ({len(texts) - len(missing):,} cached)")
        embeddings, scores = model_factory().run(missing)
        for text, embedding, score in zip(missing, embeddings, scores):
            cache[key(text)] = (embedding, float(score))
        keys = list(cache)
        np.savez(cache_path, keys=np.array(keys), embeddings=np.stack([cache[k][0] for k in keys]),
                 scores=np.array([cache[k][1] for k in keys], dtype=np.float32))
    return (np.stack([cache[key(text)][0] for text in texts]),
            np.array([cache[key(text)][1] for text in texts], dtype=np.float32))


def unit_vectors(embeddings: np.ndarray, centre: np.ndarray) -> np.ndarray:
    """Raw BERT embeddings all point roughly the same way; centring first makes
    cosine similarity separate alerts instead of calling everything ~0.95."""
    shifted = embeddings - centre
    return shifted / np.maximum(np.linalg.norm(shifted, axis=1, keepdims=True), 1e-9)


# --- commands -----------------------------------------------------------------


def command_check(args) -> None:
    from transformers import pipeline
    fill = pipeline("fill-mask", model=str(args.model_dir), top_k=5, device=pick_device())
    for sentence in [
        "The attacker used a <mask> attack to guess SSH passwords.",
        "Multiple failed logins from one IP address indicate a <mask> force attack.",
        "The firewall <mask> the incoming connection on port 22.",
        "Failed password for invalid user admin from <IP> port <EPH> ssh2. Overall, this activity is<mask>.",
        "Accepted publickey for backup from <IP> port <EPH> ssh2. Overall, this activity is<mask>.",
    ]:
        guesses = ", ".join(f"{item['token_str'].strip()} ({item['score']:.2f})" for item in fill(sentence))
        print(f"{sentence}\n    -> {guesses}")


def command_suggest(args) -> None:
    raise_csv_field_limit()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    model = None

    def model_factory():
        nonlocal model
        model = model or SecureBERT(args.model_dir, args.max_length, args.batch_size)
        return model

    files = []
    for path in expand(args.inputs, skip_suffix="_to_label.csv"):
        fields, rows = read_csv(path)
        texts = [to_sequence(split_raw_messages(row.get("raw_messages", ""))) for row in rows]
        files.append((path, fields, rows, texts))
    all_texts = [text for *_, texts in files for text in texts]
    unique = list(dict.fromkeys(text for text in all_texts if text))
    runlog.log(f"{len(all_texts):,} alerts, {len(unique):,} distinct after normalising")

    seed_texts, seed_labels = [], []
    if args.seeds:
        for path in expand(args.seeds):
            _, rows = read_csv(path)
            for row in rows:
                label = canonical_category(row.get("label"))
                text = to_sequence(split_raw_messages(row.get("raw_messages", "")))
                if label and text:
                    seed_texts.append(text)
                    seed_labels.append(label)
        runlog.log(f"{len(seed_texts):,} labelled seed alerts: {dict(Counter(seed_labels))}")

    embeddings, zero_shot = embed_with_cache(unique + seed_texts, out / "securebert_cache.npz", model_factory)
    centre = embeddings.mean(axis=0)
    vectors = unit_vectors(embeddings[:len(unique)], centre)
    seed_vectors = unit_vectors(embeddings[len(unique):], centre) if seed_texts else None

    if args.cluster_column:
        # group by an existing column, e.g. Phase 7b's behavioural cluster_id, instead of
        # k-means on the text; a text found in several groups joins its most common one
        votes_by_text = defaultdict(Counter)
        for _, _, rows, texts in files:
            for row, text in zip(rows, texts):
                if text:
                    votes_by_text[text][str(row.get(args.cluster_column) or "none")] += 1
        names = sorted({votes.most_common(1)[0][0] for votes in votes_by_text.values()})
        number = {name: index for index, name in enumerate(names)}
        assignment = np.array([number[votes_by_text[text].most_common(1)[0][0]] for text in unique], dtype=int)
        runlog.log(f"Grouping by column {args.cluster_column!r}: {len(names):,} groups")
    else:
        # clusters of near-identical alerts
        from sklearn.cluster import KMeans
        clusters = max(1, min(len(unique), math.ceil(len(unique) / args.cluster_size)))
        kmeans = KMeans(n_clusters=clusters, n_init=3, random_state=13).fit(vectors) if clusters > 1 else None
        assignment = kmeans.labels_ if kmeans is not None else np.zeros(len(unique), dtype=int)
    sizes = Counter(assignment.tolist())
    representative = {}
    for cluster in sizes:
        members = np.where(assignment == cluster)[0]
        centroid = vectors[members].mean(axis=0)
        representative[cluster] = members[int(np.argmax(vectors[members] @ centroid))]

    suggestion = {}
    for i, text in enumerate(unique):
        info = {"zero_shot_malicious": f"{zero_shot[i]:.3f}", "cluster": int(assignment[i]),
                "cluster_size": sizes[int(assignment[i])], "representative": int(representative[assignment[i]] == i)}
        if seed_vectors is not None and len(seed_vectors):
            similarity = seed_vectors @ vectors[i]
            nearest = np.argsort(-similarity)[:args.neighbours]
            votes = defaultdict(float)
            for j in nearest:
                votes[seed_labels[j]] += max(float(similarity[j]), 0.0)
            label = max(votes, key=votes.get) if votes else ""
            total = sum(votes.values())
            info.update(suggested_label=label, suggested_by=f"nearest {len(nearest)} labelled",
                        suggestion_confidence=f"{votes[label] / total:.2f}" if total else "",
                        nearest_labelled_similarity=f"{similarity[nearest[0]]:.3f}",
                        nearest_labelled_example=f"[{seed_labels[nearest[0]]}] {seed_texts[nearest[0]][:300]}")
        else:
            malicious = zero_shot[i] >= args.zero_shot_threshold
            # the fill-mask score only separates two sides; the other categories need labelled seeds
            info.update(suggested_label="security_relevant" if malicious else "expected_behavior", suggested_by="zero-shot",
                        suggestion_confidence=f"{zero_shot[i] if malicious else 1 - zero_shot[i]:.2f}")
        suggestion[text] = info

    for path, fields, rows, texts in files:
        marked = set()
        for row, text in zip(rows, texts):
            row.update(suggestion.get(text, {}))
            row.setdefault("label", "")
            if row.get("representative") == 1:      # one row per cluster, not every duplicate
                row["representative"] = int(row["cluster"] not in marked)
                marked.add(row["cluster"])
        # cluster by cluster, most malicious-sounding clusters first, representative on top
        rank = defaultdict(float)
        for row in rows:
            rank[row.get("cluster", -1)] = max(rank[row.get("cluster", -1)], float(row.get("zero_shot_malicious") or 0))
        rows.sort(key=lambda row: (-rank[row.get("cluster", -1)], row.get("cluster", -1),
                                   -int(row.get("representative") or 0), -float(row.get("rank") or row.get("probability") or 0)))
        target = out / f"{Path(path).stem}_to_label.csv"
        write_csv(target, EXTRA_COLUMNS + [f for f in fields if f not in EXTRA_COLUMNS], rows)
        runlog.log(f"{Path(path).name}: {len(rows):,} rows in {len({r.get('cluster') for r in rows}):,} clusters -> {target}")


def command_propagate(args) -> None:
    raise_csv_field_limit()
    for path in expand(args.inputs):
        fields, rows = read_csv(path)
        by_cluster = defaultdict(set)
        for row in rows:
            label = canonical_category(row.get("label"))
            if label:
                by_cluster[row.get("cluster")].add(label)
        filled = conflicts = held = 0
        for row in rows:
            if "label_source" not in row or not row["label_source"]:
                row["label_source"] = "analyst" if (row.get("label") or "").strip() else ""
            labels = by_cluster.get(row.get("cluster"), set())
            if not (row.get("label") or "").strip() and len(labels) == 1:
                label = next(iter(labels))
                # a cluster can still mix attack and routine lines: only fill rows
                # whose own suggestion agrees, unless told to trust the cluster
                if args.trust_cluster or canonical_category(row.get("suggested_label")) == label:
                    row["label"] = label
                    row["label_source"] = "propagated"
                    filled += 1
                else:
                    held += 1
            elif len(labels) > 1:
                conflicts += 1
        if "label_source" not in fields:
            fields.insert(fields.index("label") + 1, "label_source")
        write_csv(Path(path), fields, rows)
        disagree = sum(1 for labels in by_cluster.values() if len(labels) > 1)
        runlog.log(f"{Path(path).name}: filled {filled:,} blank labels; {held:,} held back (their suggestion "
                   f"disagrees); {disagree:,} clusters have mixed labels ({conflicts:,} rows left for you)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    suggest = sub.add_parser("suggest")
    suggest.add_argument("--inputs", nargs="+", required=True, help="Phase 7 CSVs (globs allowed)")
    suggest.add_argument("--seeds", nargs="*", help="Phase 7 CSVs with a filled 'label' column")
    suggest.add_argument("--out", required=True)
    suggest.add_argument("--cluster-size", type=int, default=10, help="average distinct alerts per cluster")
    suggest.add_argument("--cluster-column",
                         help="group by this input column instead of text clusters, e.g. cluster_id from "
                              "data/phase7b_clusters/<source>/<prefix>_alerts_by_cluster.csv")
    suggest.add_argument("--neighbours", type=int, default=5)
    suggest.add_argument("--zero-shot-threshold", type=float, default=0.5)
    suggest.add_argument("--max-length", type=int, default=256)
    suggest.add_argument("--batch-size", type=int, default=16)
    propagate = sub.add_parser("propagate")
    propagate.add_argument("--inputs", nargs="+", required=True, help="*_to_label.csv files (edited in place)")
    propagate.add_argument("--trust-cluster", action="store_true",
                           help="fill every blank row in an agreeing cluster, even against its suggestion")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    {"check": command_check, "suggest": command_suggest, "propagate": command_propagate}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
