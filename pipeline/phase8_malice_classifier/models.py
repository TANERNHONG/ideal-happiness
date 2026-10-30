"""The two classifiers: a TF-IDF baseline and a fine-tuned BERT-family model.

Both expose predict(texts) -> probability of "malicious". torch and
transformers are imported lazily so the baseline works without them.
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

import numpy as np

# --- Baseline -----------------------------------------------------------------


def build_baseline():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer

    features = FeatureUnion([
        # keeps <IP>, <IP>:22, sshd[<PID>]: style tokens whole
        ("words", TfidfVectorizer(token_pattern=r"<[A-Z0-9]+>(?::\w+)?|[A-Za-z_][\w.\-/=]*|\d+",
                                  ngram_range=(1, 2), min_df=2, max_features=200_000,
                                  sublinear_tf=True, lowercase=False)),
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                  max_features=200_000, sublinear_tf=True)),
    ])
    return Pipeline([("features", features),
                     ("model", LogisticRegression(class_weight="balanced", C=4.0, max_iter=3000))])


class BaselineScorer:
    def __init__(self, folder: Path):
        import joblib
        self.pipeline = joblib.load(folder / "baseline.joblib")

    def predict(self, texts: list[str]) -> np.ndarray:
        return self.pipeline.predict_proba(texts)[:, 1]


# --- BERT ---------------------------------------------------------------------


def encode(tokenizer, texts: list[str], max_length: int) -> list[list[int]]:
    """Tokenise with head+tail truncation: the start of a sequence shows what
    began, the end shows how it finished (login accepted, agent stopped)."""
    body = max_length - 2
    head = body // 2
    encoded = []
    for text in texts:
        ids = tokenizer(text, add_special_tokens=False, truncation=False)["input_ids"]
        if len(ids) > body:
            ids = ids[:head] + ids[-(body - head):]
        try:
            encoded.append(tokenizer.build_inputs_with_special_tokens(ids))
        except (AttributeError, NotImplementedError):
            encoded.append([tokenizer.cls_token_id, *ids, tokenizer.sep_token_id])
    return encoded


def batches(encoded: list[list[int]], pad_id: int, size: int, labels=None, shuffle=False, seed=0):
    import torch
    order = list(range(len(encoded)))
    if shuffle:
        random.Random(seed).shuffle(order)
    for start in range(0, len(order), size):
        index = order[start:start + size]
        width = max(len(encoded[i]) for i in index)
        ids = torch.full((len(index), width), pad_id, dtype=torch.long)
        mask = torch.zeros((len(index), width), dtype=torch.long)
        for row, i in enumerate(index):
            ids[row, :len(encoded[i])] = torch.tensor(encoded[i])
            mask[row, :len(encoded[i])] = 1
        target = None if labels is None else torch.tensor([labels[i] for i in index], dtype=torch.long)
        yield ids, mask, target


def pick_device():
    import torch
    if torch.cuda.is_available():
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def bert_predict(model, tokenizer, texts, max_length, batch_size, device) -> np.ndarray:
    import torch
    model.eval()
    encoded = encode(tokenizer, texts, max_length)
    scores = []
    with torch.no_grad():
        for ids, mask, _ in batches(encoded, tokenizer.pad_token_id, batch_size):
            logits = model(input_ids=ids.to(device), attention_mask=mask.to(device)).logits
            scores.append(torch.softmax(logits.float(), dim=-1)[:, 1].cpu().numpy())
    return np.concatenate(scores) if scores else np.zeros(0)


def train_bert(train_texts, train_labels, valid_texts, valid_labels, folder: Path, *, model_name: str,
               max_length: int, epochs: int, batch_size: int, learning_rate: float, seed: int, log):
    import torch
    from sklearn.metrics import average_precision_score
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    torch.manual_seed(seed)
    device = pick_device()
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name, num_labels=2, id2label={0: "benign", 1: "malicious"},
        label2id={"benign": 0, "malicious": 1}).to(device)
    log(f"BERT: {model_name} on {device}, {len(train_texts):,} train rows, max_length {max_length}")

    encoded = encode(tokenizer, train_texts, max_length)
    positives = max(sum(train_labels), 1)
    weight = min((len(train_labels) - positives) / positives, 20.0)   # class imbalance
    loss_fn = torch.nn.CrossEntropyLoss(weight=torch.tensor([1.0, weight], device=device))
    optimiser = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    total = epochs * math.ceil(len(encoded) / batch_size)
    warmup = max(1, int(0.06 * total))
    schedule = torch.optim.lr_scheduler.LambdaLR(
        optimiser, lambda step: min((step + 1) / warmup, max(0.0, (total - step) / max(1, total - warmup))))

    best = -1.0
    step = 0
    for epoch in range(1, epochs + 1):
        model.train()
        running = 0.0
        for ids, mask, target in batches(encoded, tokenizer.pad_token_id, batch_size, train_labels,
                                         shuffle=True, seed=seed + epoch):
            logits = model(input_ids=ids.to(device), attention_mask=mask.to(device)).logits
            loss = loss_fn(logits, target.to(device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimiser.step()
            schedule.step()
            optimiser.zero_grad()
            step += 1
            running += loss.item()
            if step % 100 == 0:
                log(f"Epoch {epoch} step {step}/{total} loss {running / 100:.4f}")
                running = 0.0
        scores = bert_predict(model, tokenizer, valid_texts, max_length, batch_size * 2, device)
        pr_auc = average_precision_score(valid_labels, scores)
        log(f"Epoch {epoch}: validation PR-AUC {pr_auc:.4f}")
        if pr_auc > best:
            best = pr_auc
            model.save_pretrained(folder / "bert")
            tokenizer.save_pretrained(folder / "bert")
    (folder / "bert" / "malice_config.json").write_text(
        json.dumps({"base_model": model_name, "max_length": max_length}), encoding="utf-8")
    return BertScorer(folder)


class BertScorer:
    def __init__(self, folder: Path, batch_size: int = 32):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        path = folder / "bert"
        self.config = json.loads((path / "malice_config.json").read_text(encoding="utf-8"))
        self.device = pick_device()
        self.tokenizer = AutoTokenizer.from_pretrained(path)
        self.model = AutoModelForSequenceClassification.from_pretrained(path).to(self.device)
        self.batch_size = batch_size

    def predict(self, texts: list[str]) -> np.ndarray:
        return bert_predict(self.model, self.tokenizer, texts, self.config["max_length"],
                            self.batch_size, self.device)


def load_scorer(folder: Path, kind: str):
    return BaselineScorer(folder) if kind == "baseline" else BertScorer(folder)
