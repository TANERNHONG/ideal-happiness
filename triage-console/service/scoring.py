"""Score new auth or OSSEC lines with the trained pipeline.

The input goes through the pipeline's own code, in order:

1. Phase 1 - the classifier and row builder of the log type.
2. Phase 2 - the observation builders (individual lines, 5-minute windows,
   sessions or episodes, days), run on a temporary folder.
3. Phase 3 - the saved preprocessing bundle of each view: training means and
   scales, the same hashing vectorizers; for OSSEC also the per-entity history,
   rebuilt once from the whole year and cached.
4. Phase 4 - the saved robust, isolation-forest and novelty detectors and the
   model zoo (12 models, ensemble, consensus); for AUTH sessions and OSSEC
   episodes also Phase 4f's sequence detector (sequences.py).
5. Phase 4c / 7b - the nearest mapped observations in the zoo's embedding give
   the map position and the cluster.

Limits that differ from a pipeline run: windows and sessions see only the
input's lines, and daily "new value" counts know only the input's own days.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import Normalizer

from . import drift, sequences
from .catalog import model_status
from .config import CACHE, DATA, FROZEN
from .pipeline_code import module

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
_phase2_lock = threading.Lock()        # the Phase 2 modules keep their folders in module globals
_cache_lock = threading.Lock()

PHASE2_OUTPUTS = {
    "auth": {"individual": "write_individual_dataset", "host_5min": "write_host_windows",
             "authentication_sessions": "write_sessions", "host_behavior_1d": "write_behavior"},
    "ossec": {"individual": "write_individual_dataset", "host_5min": "write_host_window_dataset",
              "episodes": "write_episode_dataset", "host_behavior_1d": "write_behavior_dataset"},
}
PHASE2_FILES = {
    "ossec": {"individual": "ossec_events_all_months.csv", "host_5min": "ossec_host_windows_5min.csv",
              "episodes": "ossec_security_episodes.csv", "host_behavior_1d": "ossec_host_behavior_1d.csv"},
}
DETECTORS = ("robust", "isolation_forest", "novelty")
NEIGHBOURS = 10


# --- Phase 1 --------------------------------------------------------------------------

def _phase1_auth(lines, month, folder: Path) -> Path:
    m = module("phase1_classify/auth.py")
    classifier = m.StandaloneAuthClassifier()
    path = folder / f"classified_authlog_events_{month}.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=m.output_fields(classifier), extrasaction="ignore")
        writer.writeheader()
        for number, physical in enumerate(lines, start=1):
            text = physical.strip()
            event = classifier.classify_line(text)
            writer.writerow(m.prepare_lineage_row(classifier, event, month, "analyze/input.log", "analyze/input.log",
                                                  number, physical, text))
    return path


def _phase1_ossec(lines, month, folder: Path, host: str) -> Path:
    m = module("phase1_classify/ossec.py")
    year, mon = month.split("-")
    extracted = {"archive_name": "analyze", "archive_member": f"ossec_logs_{host or 'unknown-host'}.txt",
                 "archive_year": int(year), "archive_month": int(mon)}
    file_path = os.path.join(m.EXTRACT_FOLDER, "analyze", "input.txt")
    path = folder / f"ossec_events_{month}.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=m.FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for number, physical in enumerate(lines, start=1):
            text = physical.strip()
            for event_type, pattern in m.PATTERNS:
                match = pattern.match(text)
                if match:
                    event = match.groupdict()
                    event["event_type"] = event_type
                    event["raw_message"] = m.extract_raw_message(text)
                    break
            else:
                unknown = m.UNKNOWN_EVENT_PATTERN.match(text)
                event = unknown.groupdict() if unknown else {"timestamp": "", "process_name": "", "pid": "",
                                                             "severity": "", "raw_message": text}
                event["event_type"] = m.UNKNOWN_EVENT_TYPE
            writer.writerow(m.prepare_output_event(event, extracted, file_path, number, physical, text))
    return path


# --- Phase 2 --------------------------------------------------------------------------

def _phase2(source: str, folder: Path, lineages: dict | None = None) -> dict[str, pd.DataFrame]:
    """Each view's observations; ``lineages``, when given, gets each view's lineage file (observation -> events)."""
    m = module(f"phase2_observations/{source}.py")
    files = sorted(str(p) for p in folder.glob("*.csv"))
    out = {}
    with _phase2_lock:
        saved = (m.INPUT_FOLDER, m.OUTPUT_FOLDER)
        m.INPUT_FOLDER = m.OUTPUT_FOLDER = folder
        connection = sqlite3.connect(folder / "store.sqlite")
        try:
            m.create_database(connection)
            m.load_events(connection, files)
            for view, writer in PHASE2_OUTPUTS[source].items():
                dataset_path, lineage_path = getattr(m, writer)(connection)[:2]
                out[view] = pd.read_csv(dataset_path, low_memory=False)
                if lineages is not None:
                    lineages[view] = Path(lineage_path)
        finally:
            connection.close()
            m.INPUT_FOLDER, m.OUTPUT_FOLDER = saved
    return out


def _sigma_rows(source: str, folder: Path, lines: dict[int, list[str]], lineages: dict[str, Path]) -> dict[str, dict[str, list[str]]]:
    """view -> observation ID -> titles of the Sigma rules whose hits hold its lines. ``lines``: input line number
    (from 1, as Phase 1 numbers them) -> titles (sigma.line_hits)."""
    if not lines:
        return {}
    key = "record_id" if source == "auth" else "event_id"
    connection = sqlite3.connect(folder / "store.sqlite")
    try:
        by_event = {}
        for event_id, line in connection.execute(f"SELECT {key}, source_line FROM events"):
            try:
                titles = lines.get(int(float(line)))
            except (TypeError, ValueError):
                continue
            if titles:
                by_event[event_id] = titles
    finally:
        connection.close()
    out = {}
    for view, path in lineages.items():
        rows: dict[str, set] = {}
        with path.open(encoding="utf-8", newline="") as handle:
            for r in csv.DictReader(handle):
                titles = by_event.get(r.get(key))
                if titles:
                    rows.setdefault(r["row_manifest_id"], set()).update(titles)
        out[view] = {row_id: sorted(titles) for row_id, titles in rows.items()}
    return out


# --- Phase 3 --------------------------------------------------------------------------

@lru_cache(maxsize=16)
def _preprocessing(source: str, view: str):
    folder = DATA / "phase3_features" / source / view
    bundle = joblib.load(folder / "preprocessing_bundle.joblib")
    names = pd.read_csv(folder / "feature_names.csv")["feature_name"].astype(str).tolist()
    return bundle, names


def _digests(keys) -> np.ndarray:
    """Entity keys (server|agent|...) as 16-character SHA-256 digests, so the cache holds no name."""
    codes, uniques = pd.factorize(pd.Series(keys, dtype=object), sort=False)
    hashed = np.array([hashlib.sha256(str(u).encode("utf-8")).hexdigest()[:16] for u in uniques], dtype=object)
    return hashed[codes]


@lru_cache(maxsize=1)
def _hashed_history(m3):
    class HashedHistory(m3.HistoryState):
        """Phase 3's HistoryState with each entity known by the digest of its key: the same statistics, no names."""
        def update(self, keys, values):
            return super().update(_digests(keys), values)
    return HashedHistory


def _save_history(cache: Path, stamp: str, state) -> None:
    """Plain arrays (numpy .npz, no pickle): loading the cache can never run code."""
    keys = np.array(sorted(state.index, key=state.index.get), dtype="U16")
    with tempfile.NamedTemporaryFile(dir=cache.parent, suffix=".npz", delete=False) as handle:
        np.savez(handle, stamp=np.array(stamp), keys=keys, count=state.count, sums=state.sums, squares=state.squares)
    os.replace(handle.name, cache)


def _load_history(cache: Path, cls, columns):
    """(stamp, state) from _save_history's file; None when it is missing or unreadable."""
    try:
        with np.load(cache, allow_pickle=False) as stored:
            state = cls(columns)
            state.index = {key: i for i, key in enumerate(stored["keys"].tolist())}
            state.count, state.sums, state.squares = stored["count"].copy(), stored["sums"].copy(), stored["squares"].copy()
            return str(stored["stamp"]), state
    except (OSError, ValueError, KeyError):
        return None


def _history(view: str, plan: dict):
    """OSSEC per-entity history after the whole year, replayed once from Phase 2 and cached."""
    if not plan["history_group"]:
        return None
    m3 = module("phase3_features/ossec.py")
    cls = _hashed_history(m3)
    path = DATA / "phase2_observations" / "ossec" / PHASE2_FILES["ossec"][view]
    stamp = f"{path.stat().st_size}:{int(path.stat().st_mtime)}" if path.exists() else ""
    cache = CACHE / f"ossec_history_{view}.npz"
    with _cache_lock:
        stored = _load_history(cache, cls, plan["history"])
        if stored and (stored[0] == stamp or FROZEN):      # frozen: the history is kept, Phase 2 is gone
            return stored[1]
        if not path.exists():
            raise ValueError(f"The OSSEC history for {view} is missing: run scripts/freeze_runtime.py before purging data.")
        state = cls(plan["history"])
        for frame, _ in m3.read_chunks(path, 50_000, None):
            values = (np.column_stack([np.nan_to_num(pd.to_numeric(frame[c], errors="coerce").to_numpy(dtype=float), nan=0.0)
                                       for c in plan["history"]]) if plan["history"] else np.zeros((len(frame), 0)))
            state.update(m3.entity_keys(frame, plan["history_group"]), values)
        CACHE.mkdir(parents=True, exist_ok=True)
        _save_history(cache, stamp, state)
        return copy.deepcopy(state)


def _hashing(n, analyzer="word", ngram=(1, 1), lowercase=True, token_pattern=None):
    options = {"token_pattern": token_pattern} if token_pattern else {}
    return HashingVectorizer(n_features=n, alternate_sign=False, norm="l2", analyzer=analyzer,
                             ngram_range=ngram, lowercase=lowercase, dtype=np.float32, **options)


def features(source: str, view: str, frame: pd.DataFrame) -> sparse.csr_matrix:
    bundle, names = _preprocessing(source, view)
    m3 = module(f"phase3_features/{source}.py")
    frame = frame.reset_index(drop=True).copy()
    _, timestamps = m3.parse_time(frame)
    if source == "auth":
        numeric, _ = m3.numeric_matrix(frame, bundle["numeric_columns"], timestamps,
                                       bundle["numeric_means"], bundle["numeric_scales"])
        parts = [sparse.csr_matrix(numeric),
                 _hashing(bundle["category_hash_features"], token_pattern=r"[^ ]+", lowercase=False)
                 .transform(m3.category_documents(frame, bundle["categorical_columns"]))]
        if view == "individual" and bundle["text_hash_features"]:
            parts.append(_hashing(bundle["text_hash_features"], ngram=(1, 2)).transform(m3.text_documents(view, frame)))
        elif view != "individual":
            parts.append(_hashing(bundle["sequence_hash_features"], ngram=(1, 3)).transform(m3.text_documents(view, frame)))
    else:
        plan = bundle["feature_plan"]
        numeric, _ = m3.numeric_block(frame, timestamps, plan, _history(view, plan),
                                      bundle["numeric_means"], bundle["numeric_scales"])
        m3.add_derived_categories(frame, plan["categorical"])
        args = SimpleNamespace(category_hash_features=bundle["category_hash_features"],
                               text_hash_features=bundle["text_hash_features"],
                               sequence_hash_features=bundle["sequence_hash_features"],
                               disable_individual_text=not bundle["text_hash_features"])
        category, text, sequence = m3.hashing_vectorizers(view, args)
        parts = [sparse.csr_matrix(numeric), category.transform(m3.category_documents(frame, plan["categorical"]))]
        if text is not None:
            parts.append(text.transform(m3.text_documents(frame)))
        if sequence is not None:
            parts.append(sequence.transform(m3.sequence_documents(frame)))
    matrix = sparse.hstack(parts, format="csr", dtype=np.float32)
    matrix.eliminate_zeros()
    if matrix.shape[1] != len(names):
        raise ValueError(f"{source}/{view}: built {matrix.shape[1]} features, the models expect {len(names)}.")
    return matrix


# --- Phase 4: detectors -----------------------------------------------------------------

@lru_cache(maxsize=16)
def _detector_bundle(source: str, view: str):
    path = DATA / "phase4_detection" / source / "detectors" / view / "experiment_bundle.joblib"
    return joblib.load(path) if path.exists() else None


def _columns(names: list[str], wanted: list[str]) -> list[int]:
    index = {n: i for i, n in enumerate(names)}
    return [index[n] for n in wanted]


def detectors(source: str, view: str, matrix) -> dict | None:
    bundle = _detector_bundle(source, view)
    if bundle is None:
        return None
    _, names = _preprocessing(source, view)
    m4 = module(f"phase4_detection/{source}_detectors.py")
    rule = bundle["robust_rule"]
    status = bundle.get("detector_status") or {}          # e.g. "calibrated"; only explicit off-states disable a detector
    active = lambda key: not any(word in str(status.get(key, "")).lower()  # noqa: E731
                                 for word in ("inactive", "disabled", "skipped", "no_features", "unavailable"))
    rows = matrix.shape[0]
    robust_names = list(bundle["robust_feature_names"])
    if robust_names:
        robust, support = m4.robust_score(matrix[:, _columns(names, robust_names)], bundle["robust_medians"],
                                          bundle["robust_scales"], rule)
    else:
        robust, support = np.zeros(rows), np.zeros(rows, dtype=int)
    iso_names = list(bundle["isolation_feature_names"])
    isolation = -bundle["isolation_forest"].score_samples(matrix[:, _columns(names, iso_names)])
    rarity = bundle.get("rarity") or {}
    rarity_names = list(rarity.get("feature_names") or rarity.get("names") or [])
    if rarity_names:
        novelty, _ = m4.rarity_score(matrix[:, _columns(names, rarity_names)], rarity["presence"], rarity["surprisal"])
    else:
        novelty = np.zeros(rows)
    thresholds = {"robust": bundle["robust_threshold"], "isolation_forest": bundle["isolation_threshold"],
                  "novelty": rarity.get("threshold", float("inf"))}
    alerts = {
        "robust": (robust >= thresholds["robust"]) & (support >= rule["minimum_support"]) & active("robust"),
        "isolation_forest": (isolation >= thresholds["isolation_forest"]) & active("isolation"),
        "novelty": (novelty >= thresholds["novelty"]) & active("novelty"),
    }
    return {"scores": {"robust": robust, "isolation_forest": isolation, "novelty": novelty},
            "thresholds": thresholds, "alerts": alerts}


# --- Phase 4: model zoo -------------------------------------------------------------------

@lru_cache(maxsize=16)
def _families(source: str, view: str, feature_set: str) -> dict | None:
    path = DATA / "phase4_detection" / source / "model_zoo" / view / feature_set / "families.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _zoo_bundle(source: str, view: str, feature_set: str):
    path = DATA / "phase4_detection" / source / "model_zoo" / view / feature_set / "model_bundle.joblib"
    if not path.exists():
        return None
    zoo = module(f"phase4_detection/{source}_model_zoo.py")
    main = sys.modules["__main__"]            # the bundle was pickled from the script, so its classes live in __main__
    for name in dir(zoo):
        value = getattr(zoo, name)
        if isinstance(value, type) and value.__module__ == zoo.__name__ and not hasattr(main, name):
            setattr(main, name, value)
    return joblib.load(path)


def embed(bundle, matrix):
    selected = matrix[:, bundle["feature_indices"]].astype(np.float64)
    return bundle["embedding_scaler"].transform(bundle["embedding_reducer"].transform(selected))


def zoo(source: str, view: str, matrix, feature_set: str = "selected") -> dict | None:
    bundle = _zoo_bundle(source, view, feature_set)
    if bundle is None:
        return None
    z = module(f"phase4_detection/{source}_model_zoo.py")
    sparse_input = matrix[:, bundle["feature_indices"]]
    dense = embed(bundle, matrix)
    scorers = {
        "isolation_forest": lambda m: -m.score_samples(sparse_input),
        "sgd_ocsvm": lambda m: -m.decision_function(Normalizer().transform(sparse_input.astype(np.float64))),
        "svd_reconstruction": lambda m: z.svd_reconstruction_error(m, sparse_input),
        "lof": lambda m: -m.score_samples(dense),
        "rbf_ocsvm": lambda m: -m.decision_function(dense),
        "elliptic_envelope": lambda m: -m.score_samples(dense),
        "gaussian_mixture": lambda m: -m.score_samples(dense),
        "knn_distance": lambda m: m.kneighbors(dense)[0][:, -1],
        "kmeans_distance": lambda m: np.min(m.transform(dense), axis=1),
        "pca_reconstruction": lambda m: np.sqrt(np.mean((dense - m.inverse_transform(m.transform(dense))) ** 2, axis=1)),
        "hbos": lambda m: m.score_samples(dense),
        "ecod": lambda m: m.score_samples(dense),
    }
    scores, alerts = {}, {}
    for name, model in bundle["models"].items():
        if name not in scorers:
            continue
        scores[name] = np.asarray(scorers[name](model), dtype=float)
        alerts[name] = scores[name] >= bundle["thresholds"][name]["threshold"]
    members = [m for m in bundle.get("ensemble_members", []) if m in scores]
    if members:
        ensemble = np.mean([z.percentile(bundle["train_score_reference"][m], scores[m]) for m in members], axis=0)
        ensemble_alert = ensemble >= bundle["ensemble_threshold"]["threshold"]
        votes = np.sum([alerts[m] for m in members], axis=0)
        needed = min(z.DEFAULT_CONSENSUS_MIN_VOTES, len(members))
        families = _families(source, view, feature_set)
        if families:                                      # one vote per family of similar models (zoo_families.py)
            groups = [[m for m in family if m in alerts] for family in families["families"]]
            votes = np.sum([np.any([alerts[m] for m in family], axis=0) for family in groups if family], axis=0)
            needed = min(int(families["min_families"]), max(len(groups), 1))
    else:
        ensemble = np.zeros(matrix.shape[0]); ensemble_alert = np.zeros(matrix.shape[0], bool)
        votes = np.zeros(matrix.shape[0], int); needed = 1
    return {"members": members, "ensemble": ensemble, "ensemble_alert": ensemble_alert,
            "ensemble_threshold": float(bundle["ensemble_threshold"]["threshold"]) if members else None,
            "votes": votes, "votes_needed": needed, "consensus": votes >= needed,
            "model_alerts": {m: alerts[m] for m in alerts}, "dense": dense}


# --- map layouts: t-SNE (the map Phase 7b grouped) and UMAP of the same points --------------------
# Phase 4c's map_layouts.py lays out the t-SNE map's points with UMAP too, in the same order. A layout
# counts only when it was computed from the map's current embedding.

LAYOUTS = ("tsne", "umap")
LAYOUT_COMMAND = "python pipeline/phase4_detection/map_layouts.py --source {source} --dataset {view}"


def _map_folder(source: str, view: str, feature_set: str = "selected") -> Path:
    return DATA / "phase4_detection" / source / "model_zoo_map" / view / feature_set


def _stamp(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_size}:{int(stat.st_mtime)}"


def layout_status(source: str, view: str) -> dict[str, str]:
    """'ready', 'missing' or 'stale' (computed from an earlier embedding) per layout."""
    folder = _map_folder(source, view)
    embedding, csv_path, meta_path = folder / "projection_tsne_embedding.npy", folder / "layout_umap.csv", folder / "layout_umap.json"
    if not (csv_path.exists() and meta_path.exists() and embedding.exists()):
        return {"tsne": "ready", "umap": "missing"}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"tsne": "ready", "umap": "missing"}
    return {"tsne": "ready", "umap": "ready" if meta.get("embedding") == _stamp(embedding) else "stale"}


@lru_cache(maxsize=16)
def _layout_xy(path: str, stamp: str) -> pd.DataFrame:
    return pd.read_csv(path, dtype={"row_manifest_id": str})


def _layout_coordinates(source: str, view: str, layout: str, ids: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """x and y of ``layout`` for the rows ``ids`` (the map's own order when it matches)."""
    if layout not in LAYOUTS[1:]:
        raise ValueError(f"Unknown map layout: {layout}.")
    if layout_status(source, view)[layout] != "ready":
        raise ValueError(f"The {layout.upper()} layout is not built for this view yet. Run: "
                         + LAYOUT_COMMAND.format(source=source, view=view))
    path = _map_folder(source, view) / f"layout_{layout}.csv"
    xy = _layout_xy(str(path), _stamp(path))
    if len(xy) == len(ids) and (xy["row_manifest_id"].to_numpy() == ids).all():
        return xy["x"].to_numpy(), xy["y"].to_numpy()
    by_id = xy.drop_duplicates("row_manifest_id").set_index("row_manifest_id").reindex(ids)
    return by_id["x"].to_numpy(), by_id["y"].to_numpy()


# --- Phase 4c / 7b: place on the map --------------------------------------------------------

@lru_cache(maxsize=8)
def _map(source: str, view: str, feature_set: str = "selected", layouts_key: str = ""):
    folder = DATA / "phase4_detection" / source / "model_zoo_map" / view / feature_set
    points_path = DATA / "phase7b_clusters" / source / view / "map_points.csv"
    embedding_path = folder / "projection_tsne_embedding.npy"
    if not (points_path.exists() and embedding_path.exists()):
        return None
    embedding = np.load(embedding_path, allow_pickle=False)
    points = pd.read_csv(points_path, usecols=["row_manifest_id", "x", "y", "cluster_number", "flagged", "time"])
    projection_ids = pd.read_csv(folder / "projection_tsne.csv", usecols=["row_manifest_id"])["row_manifest_id"]
    if len(projection_ids) != len(points) or not (projection_ids.to_numpy() == points["row_manifest_id"].to_numpy()).all():
        points = points.set_index("row_manifest_id").loc[projection_ids].reset_index()
    for layout in LAYOUTS[1:]:                            # the same neighbours, placed on the other layouts too
        if layout_status(source, view)[layout] == "ready":
            points[f"{layout}_x"], points[f"{layout}_y"] = _layout_coordinates(source, view, layout, points["row_manifest_id"].to_numpy())
    finder = NearestNeighbors(n_neighbors=NEIGHBOURS + 1).fit(embedding)
    sample = np.random.default_rng(7).choice(len(embedding), min(2000, len(embedding)), replace=False)
    typical = float(np.median(finder.kneighbors(embedding[sample])[0][:, 1]))   # nearest other point
    return {"finder": finder, "points": points, "typical": typical or 1.0}


def place(source: str, view: str, dense) -> list[dict] | None:
    mapped = _map(source, view, "selected", ";".join(f"{k}={v}" for k, v in layout_status(source, view).items()))
    if mapped is None:
        return None
    distances, indices = mapped["finder"].kneighbors(dense, n_neighbors=NEIGHBOURS)
    points = mapped["points"]
    out = []
    for dist, idx in zip(distances, indices):
        weights = 1.0 / (dist + 1e-6)
        near = points.iloc[idx]
        votes = pd.Series(weights, index=near["cluster_number"].to_numpy()).groupby(level=0).sum()
        number = int(votes.idxmax())
        layouts = {layout: {"x": float(np.average(near[f"{layout}_x"], weights=weights)), "y": float(np.average(near[f"{layout}_y"], weights=weights))}
                   for layout in LAYOUTS[1:] if f"{layout}_x" in near}
        out.append({"x": float(np.average(near["x"], weights=weights)), "y": float(np.average(near["y"], weights=weights)), "layouts": layouts,
                    "cluster_id": f"{view}#{number}" if number >= 0 else "",
                    "agreement": float(votes.max() / votes.sum()),
                    "distance_ratio": float(dist[0] / mapped["typical"]),
                    "neighbours_flagged": int(near["flagged"].astype(bool).sum())})
    return out


# The map's points as Phase 7b wrote them, without the neighbour search that placing new lines needs,
# so showing the map or one of its points stays cheap. Re-read when the file changes.
@lru_cache(maxsize=8)
def _map_table(path: str, stamp: str) -> pd.DataFrame:
    table = pd.read_csv(path, usecols=["row_manifest_id", "split", "time", "x", "y", "cluster_number", "votes", "category", "flagged"],
                        dtype={"row_manifest_id": str, "category": str})
    table["flagged"] = table["flagged"].astype(str).str.lower().eq("true")
    return table.set_index("row_manifest_id", drop=False)


def map_table(source: str, view: str, layout: str = "tsne") -> pd.DataFrame | None:
    path = DATA / "phase7b_clusters" / source / view / "map_points.csv"
    if not path.exists():
        return None
    table = _map_table(str(path), _stamp(path))
    if layout == "tsne":
        return table
    table = table.copy()
    table["x"], table["y"] = _layout_coordinates(source, view, layout, table["row_manifest_id"].to_numpy())
    return table


def map_info(source: str, view: str, limit: int = 60_000) -> dict | None:
    """How big the map is, before anyone asks to draw it, and how many points each group has."""
    table = map_table(source, view)
    if table is None:
        return None
    counts = table["cluster_number"].astype(int).value_counts()
    return {"points": len(table), "shown": min(len(table), limit), "flagged": int(table["flagged"].sum()),
            "groups": {str(k): int(v) for k, v in counts.items()},
            "layouts": layout_status(source, view), "layout_command": LAYOUT_COMMAND.format(source=source, view=view)}


def map_points(source: str, view: str, limit: int = 12_000, layout: str = "tsne") -> dict | None:
    points = map_table(source, view, layout)
    if points is None:
        return None
    if len(points) > limit:
        flagged = points[points["flagged"]]
        rest = points[~points["flagged"]].sample(max(limit - len(flagged), 0), random_state=1)
        points = pd.concat([flagged, rest])
    return {"id": points["row_manifest_id"].tolist(),
            "x": points["x"].round(2).tolist(), "y": points["y"].round(2).tolist(),
            "cluster": points["cluster_number"].astype(int).tolist(),
            "flagged": points["flagged"].astype(int).tolist()}


def map_point(source: str, view: str, row_id: str) -> dict | None:
    """One map point: when, which period, its group, how the model zoo voted. Lines come from cluster_index."""
    table = map_table(source, view)
    if table is None or row_id not in table.index:
        return None
    row = table.loc[row_id]
    if isinstance(row, pd.DataFrame):          # the same observation drawn twice: take the first
        row = row.iloc[0]
    category = row["category"]
    return {"row_id": row_id, "split": str(row["split"]), "time": str(row["time"]) if pd.notna(row["time"]) else "",
            "cluster": int(row["cluster_number"]), "votes": int(row["votes"]) if pd.notna(row["votes"]) else None,
            "flagged": bool(row["flagged"]), "category": str(category) if pd.notna(category) else ""}


# --- percentiles against the validation period ---------------------------------------------------

REFERENCE_VERSION = "3"     # 2: a finer grid in the rare tail, stored with its probabilities; 3: the zoo's calibrating half


def _grid(n: int) -> np.ndarray:
    """Probabilities to take quantiles at: every 0.1% up to 99%, then finer and finer into the rare
    tail, as far as n validation scores can tell apart, and finally the maximum (1.0)."""
    deepest = max(2.0, np.log10(max(n, 100)))
    tail = 1 - 10 ** -np.linspace(2, deepest, max(2, int((deepest - 2) * 120)))
    return np.unique(np.concatenate([np.linspace(0, 0.99, 991), tail[(tail > 0.99) & (tail < 1)], [1.0]]))


def _reference(source: str, view: str) -> dict[str, np.ndarray]:
    """Per detector, quantiles of its validation scores with the probabilities they sit at (a 2 x k
    array), read once from Phase 4 and cached. The rare tail is resolved finely, so "how rare" can
    say 1 in 50,000 rather than stopping at 1 in 1,000."""
    cache = CACHE / f"reference_{source}_{view}.npz"
    files = {"detectors": DATA / "phase4_detection" / source / "detectors" / view / "validation_scores.csv",
             "zoo": DATA / "phase4_detection" / source / "model_zoo" / view / "selected" / "validation_scores.csv",
             "sequences": DATA / "phase4_detection" / source / "sequences" / view / "validation_scores.csv"}
    stamp = f"v{REFERENCE_VERSION};" + ";".join(f"{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in files.values() if p.exists())
    with _cache_lock:
        if cache.exists():
            stored = np.load(cache, allow_pickle=False)
            if str(stored["stamp"]) == stamp or FROZEN:      # frozen: kept as computed, the scores are gone
                return {k: stored[k] for k in stored.files if k != "stamp"}
        if FROZEN:
            return {}
        out = {}
        quantiles = lambda values: np.vstack([np.quantile(values, _grid(len(values))), _grid(len(values))])
        if files["detectors"].exists():
            frame = pd.read_csv(files["detectors"], usecols=["robust_score", "isolation_score", "novelty_score"])
            for column, key in (("robust_score", "robust"), ("isolation_score", "isolation_forest"), ("novelty_score", "novelty")):
                values = pd.to_numeric(frame[column], errors="coerce").dropna().to_numpy()
                if len(values):
                    out[key] = quantiles(values)
        if files["zoo"].exists():
            header = pd.read_csv(files["zoo"], nrows=0).columns
            zoo = pd.read_csv(files["zoo"], usecols=["model_zoo_ensemble_score", *(["validation_part"] if "validation_part" in header else [])])
            if "validation_part" in zoo:                        # the half that set the thresholds, not the one that chose
                zoo = zoo[zoo["validation_part"].isin(["calibration", "all"])]
            values = pd.to_numeric(zoo["model_zoo_ensemble_score"], errors="coerce").dropna().to_numpy()
            if len(values):
                out["ensemble"] = quantiles(values)
        if files["sequences"].exists():
            values = pd.to_numeric(pd.read_csv(files["sequences"], usecols=["sequence_score"])["sequence_score"],
                                   errors="coerce").dropna().to_numpy()
            if len(values):
                out["sequence"] = quantiles(values)
        CACHE.mkdir(parents=True, exist_ok=True)
        np.savez(cache, stamp=np.asarray(stamp), **out)
        return out


def _percentile(reference, values):
    """Share of the validation scores at or below each value: the probability of the highest quantile
    not above it (a conservative reading between grid points); 1.0 at or above the maximum."""
    if reference is None:
        return np.full(len(values), np.nan)
    if reference.ndim == 1:                                     # an old cache (even grid)
        return np.searchsorted(reference, values, side="right") / len(reference)
    q, grid = reference
    i = np.searchsorted(q, values, side="right")
    return np.where(i > 0, grid[np.clip(i - 1, 0, len(grid) - 1)], 0.0)


# --- the whole run ------------------------------------------------------------------------------

def score(source: str, lines: list[str], month: str, host: str = "", progress=lambda step, detail: None,
          covered=lambda view, row: False, sigma_lines: dict[int, list[str]] | None = None) -> dict:
    """Run the input through Phases 1-4 and the map. Returns one block per view.
    ``covered(view, row)`` says whether a flagged observation's accounts are whitelisted (whitelist.py): it
    stays flagged by the models and is marked 'whitelisted'. ``sigma_lines``: input line number -> titles of
    the Sigma rules whose hits hold it (sigma.line_hits); an observation holding one is flagged 'sigma'."""
    with tempfile.TemporaryDirectory(prefix="huh-analyze-") as tmp:
        folder = Path(tmp)
        progress("phase1", "Classifying lines")
        (_phase1_auth(lines, month, folder) if source == "auth" else _phase1_ossec(lines, month, folder, host))
        progress("phase2", "Building observations")
        lineages: dict[str, Path] = {}
        observations = _phase2(source, folder, lineages)
        progress("phase4", "Frequent subsequences")
        ordered = sequences.score_upload(source, folder)          # these two need the Phase 2 store, so before it goes
        known = _sigma_rows(source, folder, sigma_lines or {}, lineages)
    views = {}
    for view, frame in observations.items():
        status = model_status(source, view)
        block = {"observations": len(frame), "model_used": status["used"], "model_why": status["why"]}
        if not len(frame):
            views[view] = block
            continue
        progress("phase3", f"Features: {view}")
        matrix = features(source, view, frame)
        progress("phase4", f"Detectors and model zoo: {view}")
        det = detectors(source, view, matrix)
        zz = zoo(source, view, matrix)
        progress("map", f"Placing on the map: {view}")
        placed = place(source, view, zz["dense"]) if zz else None
        reference = _reference(source, view)
        rows = []
        for i in range(len(frame)):
            item = {"id": str(frame.at[i, "row_manifest_id"]) if "row_manifest_id" in frame else str(i)}
            for column in ("timestamp", "window_start", "session_start", "episode_start", "host_id", "hostname",
                           "event_type", "first_event_type", "username", "source_ip", "event_count", "total_events"):
                if column in frame.columns and pd.notna(frame.at[i, column]):
                    item[column] = str(frame.at[i, column])
            flags, percentiles = [], {}
            if det:
                for name in DETECTORS:
                    percentiles[name] = float(_percentile(reference.get(name), [det["scores"][name][i]])[0])
                    if det["alerts"][name][i]:
                        flags.append(name)
            if zz:
                percentiles["ensemble"] = float(_percentile(reference.get("ensemble"), [zz["ensemble"][i]])[0])
                item["zoo_votes"] = int(zz["votes"][i])
                item["zoo_models"] = [m for m, a in zz["model_alerts"].items() if a[i]]
                if zz["consensus"][i]:
                    flags.append("model_zoo_consensus")
                if zz["ensemble_alert"][i]:
                    item["ensemble_alert"] = True
            if view == sequences.VIEWS.get(source) and item["id"] in ordered:
                hit = ordered[item["id"]]
                percentiles["sequence"] = float(_percentile(reference.get("sequence"), [hit["score"]])[0])
                item["rarest_step"] = hit["rarest_step"]
                if hit["alert"]:
                    flags.append("sequence")
                    item["sequence_why"] = hit["explanation"]
            if item["id"] in known.get(view, {}):
                flags.append("sigma")
                item["sigma"] = known[view][item["id"]]
            finite = [p for p in percentiles.values() if np.isfinite(p)]
            if flags and covered(view, item):
                item["whitelisted"] = True
            item.update({"flags": flags, "percentiles": percentiles,
                         "unusual": max(finite) if finite else None,
                         "map": placed[i] if placed else None})
            rows.append(item)
        flagged = [r for r in rows if r["flags"]]
        block["drift"] = {"scores": drift.scores([r["percentiles"].get("isolation_forest") for r in rows], source, view),
                          "new": drift.new_entities(source, rows)}
        thresholds = {k: float(v) for k, v in det["thresholds"].items()} if det else None
        if thresholds is not None and view == sequences.VIEWS.get(source) and ordered:
            thresholds["sequence"] = sequences.detector(source)[2]
        block.update({
            "flagged": len(flagged), "whitelisted": sum(bool(r.get("whitelisted")) for r in flagged),
            "max_unusual": max((r["unusual"] for r in rows if r["unusual"] is not None), default=None),
            "thresholds": thresholds,
            "zoo_members": zz["members"] if zz else [], "votes_needed": zz["votes_needed"] if zz else None,
            "rows": sorted(rows, key=lambda r: (-len(r["flags"]), -(r["unusual"] or 0)))[:500],
        })
        views[view] = block
    return views
