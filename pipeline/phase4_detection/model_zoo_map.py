"""Phase 4 (optional view): draw the model-zoo alerts on a two-dimensional map.

  python pipeline/phase4_detection/model_zoo_map.py --source auth --dataset host_5min
  python pipeline/phase4_detection/model_zoo_map.py --source pf --dataset individual --method umap --per-model
  python pipeline/phase4_detection/model_zoo_map.py --source ossec --dataset episodes --feature-set full

Reads the outputs of ``pipeline/phase4_detection/<source>_model_zoo.py`` and
projects test rows into two dimensions so normal behaviour appears as clusters
and anomalies can be seen against them. It changes nothing downstream; it is a
picture for people.

How it works
------------
1. Select test rows: every alerted row (highest vote counts first, capped) plus
   a random sample of non-alerted rows as the "normal" background. With
   ``--period all`` (the default), also take an equal number of rows from every
   month of the training and validation periods (``--history-sample`` in all),
   so the map covers the whole study period and can be replayed month by month.
   Training rows have no model-zoo scores (only validation and test are
   scored), so they carry no votes; validation rows keep theirs.
2. Rebuild each row's 32-dimensional embedding with the SVD and scaler saved
   in ``model_bundle.joblib``. This is the same space the dense models used.
3. Reduce 32 dimensions to 2 with PCA, t-SNE or UMAP.
4. Plot the map coloured by model agreement, by event category, and
   optionally one panel per model.

Projection methods
------------------
``pca``
    Fast and deterministic. Distances and axes are meaningful, but clusters
    often overlap.
``tsne``
    Best at separating clusters. Cluster sizes and the gaps between clusters
    are not meaningful; only "which points are near each other" is.
``umap``
    Separates clusters like t-SNE while keeping more global structure.
    Requires ``pip install umap-learn``.

Outputs (per dataset)
---------------------
data/phase4_detection/<source>/model_zoo_map/<dataset>/<feature-set>/
    projection_<method>.png            agreement and category panels
    projection_<method>_per_model.png  one panel per model (--per-model)
    projection_<method>.html           interactive map with hover (needs plotly)
    projection_<method>.csv            row_manifest_id, split, time, x, y and scores
    projection_<method>_embedding.npy  the 32-number embedding of every mapped row, in csv order
                                       (Phase 7b uses it, so it never has to reload training data)
    layout_umap.csv / .json            with t-SNE: the same rows laid out by UMAP (map_layouts.py;
                                       --no-layouts skips it), for the console's t-SNE / UMAP switch

Runs are read from ``<experiments>/<dataset>/<feature-set>/``, falling back to
the other feature set when the requested one is missing. Votes and panels use
the ensemble members chosen by pruning and greedy selection. Without
``--color-by``, maps are coloured by the first available column in the
source's ``category_columns``.

This one script replaces the three per-source copies
(``authlogs_/osseclogs_/pflogs_stage4.5_visualize_models.py``), which differed
only in the settings now held in ``SOURCES``.
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auth_detectors import load_sparse  # noqa: E402  (streams chosen rows out of a large X_<split>.npz)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# The bundle pickles HBOS and ECODStyle objects, which the model-zoo script
# defined while running as __main__. Unpickling only needs these names to
# exist here; no scoring happens, so empty stand-ins are enough.
class HBOS:  # noqa: D101
    pass


class ECODStyle:  # noqa: D101
    pass


# Per log source: Phase 3 datasets that have a model zoo, columns tried in
# order to colour the category panel, and columns shown on hover.
SOURCES = {
    "auth": {
        "datasets": ("authentication_sessions", "individual", "host_5min", "host_behavior_1d"),
        "category_columns": ("event_type", "dominant_event_type", "first_event_type", "event_category",
                             "host_id"),
        "hover_columns": ("row_manifest_id", "timestamp", "window_start", "session_start",
                          "host_id", "hostname", "username", "source_ip", "process_name", "event_type"),
    },
    "ossec": {
        "datasets": ("episodes", "individual", "host_5min", "host_behavior_1d"),
        "category_columns": ("event_type", "episode_family", "dominant_event_type", "first_event_type",
                             "event_category", "host_id"),
        "hover_columns": ("row_manifest_id", "timestamp", "window_start", "episode_start",
                          "host_id", "hostname", "agent_name", "process_name", "event_type", "severity"),
    },
    "pf": {
        "datasets": ("sessions", "individual", "entity_5min", "behavior_1d"),
        "category_columns": ("protocol", "action", "session_key_type", "entity_type", "event_type"),
        "hover_columns": ("row_manifest_id", "timestamp", "window_start", "session_start",
                          "entity_id", "source_ip", "destination_ip", "initiator_ip", "responder_ip",
                          "service_port", "destination_port", "close_reason"),
    },
}
# Set from --source in parse_args(); the functions below use them.
DATASETS = CATEGORY_CANDIDATES = HOVER_CANDIDATES = ()
RANDOM_STATE = 42
TIME_CANDIDATES = ("timestamp", "session_start", "window_start", "episode_start", "first_timestamp", "start")
CSV_CHUNK = 1_000_000


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

Log = runlog.Log


def parse_args():
    global DATASETS, CATEGORY_CANDIDATES, HOVER_CANDIDATES
    parser = argparse.ArgumentParser(description="Project model-zoo anomalies into 2D.")
    parser.add_argument("--source", required=True, choices=sorted(SOURCES), help="Log source to map.")
    parser.add_argument("--experiments", type=Path,
                        help="Model-zoo folder (default data/phase4_detection/<source>/model_zoo).")
    parser.add_argument("--features", type=Path, help="Phase 3 folder (default data/phase3_features/<source>).")
    parser.add_argument("--output", type=Path,
                        help="Output folder (default data/phase4_detection/<source>/model_zoo_map).")
    parser.add_argument("--dataset", action="append", default=[])
    parser.add_argument("--feature-set", choices=("full", "selected"), default="selected",
                        help="v2 feature set to plot; falls back to the other if missing.")
    parser.add_argument("--method", choices=("pca", "tsne", "umap"), default="tsne")
    parser.add_argument("--normal-sample", type=int, default=15_000,
                        help="Non-alerted test rows plotted as background (default 15,000).")
    parser.add_argument("--alert-sample", type=int, default=10_000,
                        help="Maximum alerted rows plotted, highest votes first (default 10,000).")
    parser.add_argument("--min-votes", type=int, default=3,
                        help="Vote count treated as strong consensus in plots (default 3).")
    parser.add_argument("--color-by", default="",
                        help="Manifest column for the category panel (default: auto).")
    parser.add_argument("--top-categories", type=int, default=12)
    parser.add_argument("--perplexity", type=float, default=30.0)
    parser.add_argument("--period", choices=("all", "test"), default="all",
                        help="Map the whole study period (default) or the test period only.")
    parser.add_argument("--history-sample", type=int, default=12_000,
                        help="Training and validation rows added with --period all, spread evenly over their months.")
    parser.add_argument("--per-model", action="store_true",
                        help="Also draw one panel per model.")
    parser.add_argument("--no-layouts", action="store_true",
                        help="With t-SNE, skip the UMAP layout of the same points (map_layouts.py).")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    if args.normal_sample < 0 or args.alert_sample < 0:
        parser.error("sample sizes must be non-negative")
    args.experiments = args.experiments or Path("data/phase4_detection") / args.source / "model_zoo"
    args.features = args.features or Path("data/phase3_features") / args.source
    args.output = args.output or Path("data/phase4_detection") / args.source / "model_zoo_map"
    settings = SOURCES[args.source]
    DATASETS = settings["datasets"]
    CATEGORY_CANDIDATES = settings["category_columns"]
    HOVER_CANDIDATES = settings["hover_columns"]
    return args


def run_folder_for(experiments, dataset, feature_set):
    """Locate a run folder in the v2 (per feature set) or v1 layout."""
    candidates = [experiments / dataset / feature_set,
                  experiments / dataset / ("full" if feature_set == "selected" else "selected"),
                  experiments / dataset]
    return next((folder for folder in candidates
                 if (folder / "model_bundle.joblib").is_file()), None)


def discover(experiments, requested, feature_set):
    names = requested or DATASETS
    return [name for name in names if run_folder_for(experiments, name, feature_set)]


def load_scores(path, models):
    header = pd.read_csv(path, nrows=0).columns
    wanted = set(HOVER_CANDIDATES) | set(CATEGORY_CANDIDATES) | {
        "model_vote_count", "any_model_alert", "member_vote_count", "any_member_alert",
        "model_zoo_ensemble_score", "model_zoo_ensemble_alert", "proxy_security_relevant",
    }
    for model in models:
        wanted |= {model + "_score", model + "_alert"}
    return pd.read_csv(path, usecols=[c for c in header if c in wanted], low_memory=False)


def truthy(series):
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.astype(str).str.strip().str.lower().isin({"1", "true", "yes"})


def vote_columns(scores):
    """Vote and any-alert columns for v2 (ensemble members) or v1 (all models)."""
    if "member_vote_count" in scores.columns:
        return "member_vote_count", "any_member_alert"
    return "model_vote_count", "any_model_alert"


def select_rows(scores, alert_cap, normal_cap, rng):
    vote_column, any_column = vote_columns(scores)
    alerted = truthy(scores[any_column]) | truthy(scores["model_zoo_ensemble_alert"])
    alert_positions = np.flatnonzero(alerted.to_numpy())
    if len(alert_positions) > alert_cap:
        order = scores.iloc[alert_positions].sort_values(
            [vote_column, "model_zoo_ensemble_score"], ascending=False).index
        alert_positions = np.asarray(order[:alert_cap])
    normal_positions = np.flatnonzero(~alerted.to_numpy())
    if len(normal_positions) > normal_cap:
        normal_positions = rng.choice(normal_positions, normal_cap, replace=False)
    return np.sort(np.concatenate([alert_positions, normal_positions])).astype(int)


def embed(bundle, matrix):
    selected = matrix[:, bundle["feature_indices"]].astype(np.float64)
    latent = bundle["embedding_reducer"].transform(selected)
    return bundle["embedding_scaler"].transform(latent)


def project(method, embedding, normal_mask, perplexity):
    """Return 2D coordinates. PCA and UMAP learn the map from normal rows only."""
    reference = embedding[normal_mask] if normal_mask.sum() >= 10 else embedding
    if method == "pca":
        return PCA(n_components=2, random_state=RANDOM_STATE).fit(reference).transform(embedding)
    if method == "umap":
        try:
            import umap
        except ImportError as error:
            raise ImportError("UMAP needs 'pip install umap-learn'; or use --method tsne") from error
        reducer = umap.UMAP(n_components=2, n_neighbors=30, min_dist=0.1,
                            random_state=RANDOM_STATE)
        return reducer.fit(reference).transform(embedding)
    perplexity = min(perplexity, max(5.0, (len(embedding) - 1) / 3))
    return TSNE(n_components=2, perplexity=perplexity, init="pca",
                random_state=RANDOM_STATE).fit_transform(embedding)


def category_labels(frame, column, top):
    values = frame[column].fillna("unknown").astype(str).replace("", "unknown")
    keep = values.value_counts().index[:top]
    return values.where(values.isin(keep), "Other")


def plot_static(frame, method, dataset, category_column, min_votes, path):
    fig, axes = plt.subplots(1, 2, figsize=(20, 9))
    normal = frame["votes"].eq(0) & ~frame["ensemble_alert"]
    alerts = frame.loc[~normal].sort_values("votes")

    ax = axes[0]
    ax.scatter(frame.loc[normal, "x"], frame.loc[normal, "y"], s=3, c="#cbd5e1",
               alpha=0.5, linewidths=0, label="No alert")
    points = ax.scatter(alerts["x"], alerts["y"], c=alerts["votes"], cmap="inferno_r",
                        vmin=0, vmax=max(frame["votes"].max(), 1),
                        s=6 + 4 * alerts["votes"], alpha=0.85, linewidths=0)
    strong = alerts[alerts["votes"] >= min_votes]
    ax.scatter(strong["x"], strong["y"], s=40, facecolors="none", edgecolors="#dc2626",
               linewidths=0.6, label=f"{min_votes}+ models agree ({len(strong):,})")
    ensemble = frame[frame["ensemble_alert"]]
    ax.scatter(ensemble["x"], ensemble["y"], marker="x", s=14, c="#1d4ed8",
               linewidths=0.6, label=f"Ensemble alert ({len(ensemble):,})")
    fig.colorbar(points, ax=ax, label="Models flagging the row")
    ax.set_title(f"{dataset}: anomalies by model agreement ({method.upper()})")
    ax.legend(loc="best", markerscale=1.5, fontsize=9)

    ax = axes[1]
    labels = frame["category"]
    palette = plt.get_cmap("tab20")
    for index, value in enumerate(labels.value_counts().index):
        subset = frame[labels.eq(value)]
        ax.scatter(subset["x"], subset["y"], s=4, alpha=0.6, linewidths=0,
                   color=palette(index % 20), label=f"{value} ({len(subset):,})")
    ax.scatter(strong["x"], strong["y"], s=40, facecolors="none", edgecolors="black",
               linewidths=0.6, label=f"{min_votes}+ models agree")
    ax.set_title(f"{dataset}: same map coloured by {category_column}")
    ax.legend(loc="center left", bbox_to_anchor=(1.0, 0.5), fontsize=8, markerscale=3)

    for ax in axes:
        ax.set_xticks([]); ax.set_yticks([])
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_per_model(frame, models, method, dataset, path):
    columns = 4
    rows = int(np.ceil(len(models) / columns))
    fig, axes = plt.subplots(rows, columns, figsize=(5 * columns, 4.5 * rows), squeeze=False)
    for ax, model in zip(axes.ravel(), models):
        flagged = frame[model + "_alert"]
        ax.scatter(frame.loc[~flagged, "x"], frame.loc[~flagged, "y"], s=2, c="#cbd5e1",
                   alpha=0.4, linewidths=0)
        ax.scatter(frame.loc[flagged, "x"], frame.loc[flagged, "y"], s=5, c="#dc2626",
                   alpha=0.8, linewidths=0)
        ax.set_title(f"{model} ({int(flagged.sum()):,} plotted alerts)", fontsize=10)
        ax.set_xticks([]); ax.set_yticks([])
    for ax in axes.ravel()[len(models):]:
        ax.axis("off")
    fig.suptitle(f"{dataset}: alerts per model on the shared {method.upper()} map", fontsize=14)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def plot_interactive(frame, method, dataset, category_column, path, log):
    try:
        import plotly.express as px
    except ImportError:
        log.write("plotly not installed; skipping interactive HTML (pip install plotly)", "WARN")
        return False
    hover = [c for c in HOVER_CANDIDATES if c in frame.columns] + ["votes", "ensemble_score"]
    ordered = frame.sort_values("votes")
    by_votes = px.scatter(
        ordered, x="x", y="y", color="votes", color_continuous_scale="Inferno_r",
        hover_data=hover, title=f"{dataset}: anomalies by model agreement ({method.upper()})",
        render_mode="webgl", height=750,
    )
    by_category = px.scatter(
        ordered, x="x", y="y", color="category", hover_data=hover,
        title=f"{dataset}: coloured by {category_column}", render_mode="webgl", height=750,
    )
    for figure in (by_votes, by_category):
        figure.update_traces(marker={"size": 4, "opacity": 0.75})
        figure.update_xaxes(showticklabels=False, title="")
        figure.update_yaxes(showticklabels=False, title="")
    html = (
        "<html><head><meta charset='utf-8'><title>" + dataset + "</title></head><body>"
        + by_votes.to_html(full_html=False, include_plotlyjs=True)
        + by_category.to_html(full_html=False, include_plotlyjs=False)
        + "</body></html>"
    )
    path.write_text(html, encoding="utf-8")
    return True


def first_column(columns, candidates):
    return next((c for c in candidates if c in columns), None)


def history_rows(dataset, args, run_folder, bundle, models, log):
    """(frame, embedding) for rows sampled evenly by month from the training and validation periods."""
    folder = args.features / dataset
    plans = []
    for split in ("train", "validation"):
        path = folder / f"{split}_rows.csv"
        if not path.is_file() or not (folder / f"X_{split}.npz").is_file():
            continue
        header = pd.read_csv(path, nrows=0).columns
        time_column = first_column(header, TIME_CANDIDATES)
        if time_column is None:
            continue
        months = np.concatenate([chunk[time_column].fillna("").str[:7].to_numpy()
                                 for chunk in pd.read_csv(path, usecols=[time_column], dtype=str, chunksize=CSV_CHUNK)])
        plans.append((split, path, header, time_column, months))
    all_months = sorted({m for *_, months in plans for m in np.unique(months) if len(m) == 7 and m[4] == "-"})
    if not all_months:
        return None
    quota = max(1, args.history_sample // len(all_months))
    rng = np.random.default_rng(RANDOM_STATE + 1)
    width = len(pd.read_csv(folder / "feature_names.csv"))
    frames, embeddings = [], []
    for split, path, header, time_column, months in plans:
        chosen = [rng.choice(np.flatnonzero(months == month), min(quota, int((months == month).sum())), replace=False)
                  for month in all_months if (months == month).any()]
        if not chosen:
            continue
        chosen = np.sort(np.concatenate(chosen))
        use = [c for c in header if c in set(HOVER_CANDIDATES) | set(CATEGORY_CANDIDATES) | {time_column, "row_manifest_id"}]
        parts, offset = [], 0
        for chunk in pd.read_csv(path, usecols=use, dtype=str, chunksize=CSV_CHUNK, low_memory=False):
            mask = np.isin(np.arange(offset, offset + len(chunk)), chosen)
            if mask.any():
                parts.append(chunk[mask])
            offset += len(chunk)
        meta = pd.concat(parts, ignore_index=True)
        matrix, _, _ = load_sparse(folder / f"X_{split}.npz", np.arange(width), rows=chosen)
        meta["split"] = split
        votes_column = None
        if split == "validation" and (run_folder / "validation_scores.csv").is_file():
            scores = load_scores(run_folder / "validation_scores.csv", models)
            if len(scores) == len(months):
                picked = scores.iloc[chosen].reset_index(drop=True)
                votes_column, _ = vote_columns(picked)
                meta["votes"] = picked[votes_column].fillna(0).astype(int).to_numpy()
                meta["ensemble_alert"] = truthy(picked["model_zoo_ensemble_alert"]).to_numpy()
                meta["ensemble_score"] = picked["model_zoo_ensemble_score"].to_numpy()
                for model in models:
                    meta[model + "_alert"] = truthy(picked[model + "_alert"]).to_numpy() if model + "_alert" in picked else False
        if votes_column is None:
            meta["votes"], meta["ensemble_alert"], meta["ensemble_score"] = 0, False, np.nan
            for model in models:
                meta[model + "_alert"] = False
        meta["scored"] = votes_column is not None
        frames.append(meta)
        embeddings.append(embed(bundle, matrix))
        log.write(f"{dataset}: added {len(meta):,} {split} rows ({quota:,} per month over {len(all_months)} months)")
    if not frames:
        return None
    return pd.concat(frames, ignore_index=True), np.vstack(embeddings)


def visualise(dataset, args, log):
    started = time.perf_counter()
    run_folder = run_folder_for(args.experiments, dataset, args.feature_set)
    bundle = joblib.load(run_folder / "model_bundle.joblib")
    models = list(bundle.get("ensemble_members") or bundle["models"])
    log.write(f"{dataset}: reading {run_folder} ({len(models)} voting models)")
    scores = load_scores(run_folder / "test_scores.csv", models)
    matrix = sparse.load_npz(args.features / dataset / "X_test.npz").tocsr()
    if matrix.shape[0] != len(scores):
        raise ValueError(f"X_test rows ({matrix.shape[0]:,}) != test_scores rows ({len(scores):,})")

    rng = np.random.default_rng(RANDOM_STATE)
    positions = select_rows(scores, args.alert_sample, args.normal_sample, rng)
    frame = scores.iloc[positions].reset_index(drop=True)
    vote_column, _ = vote_columns(frame)
    log.write(f"{dataset}: plotting {len(frame):,} rows "
              f"({int((frame[vote_column] > 0).sum()):,} alerted)")

    embedding = embed(bundle, matrix[positions])
    frame["votes"] = frame[vote_column].fillna(0).astype(int)
    frame["ensemble_alert"] = truthy(frame["model_zoo_ensemble_alert"])
    frame["ensemble_score"] = frame["model_zoo_ensemble_score"]
    for model in models:
        frame[model + "_alert"] = truthy(frame[model + "_alert"])
    frame["split"], frame["scored"] = "test", True
    if args.period == "all":
        history = history_rows(dataset, args, run_folder, bundle, models, log)
        if history is not None:
            frame = pd.concat([frame, history[0]], ignore_index=True)
            embedding = np.vstack([embedding, history[1]])
    time_column = first_column(frame.columns, TIME_CANDIDATES)
    frame["time"] = frame[time_column] if time_column else ""
    if time_column:
        for column in TIME_CANDIDATES:
            if column in frame.columns and column != time_column:
                frame["time"] = frame["time"].fillna(frame[column])
    frame["votes"] = frame["votes"].fillna(0).astype(int)
    frame["ensemble_alert"] = frame["ensemble_alert"].fillna(False).astype(bool)
    for model in models:
        frame[model + "_alert"] = frame[model + "_alert"].fillna(False).astype(bool)
    normal_mask = (frame["votes"].eq(0) & ~frame["ensemble_alert"]).to_numpy()

    log.write(f"{dataset}: projecting 32 dimensions to 2 with {args.method}")
    coordinates = project(args.method, embedding, normal_mask, args.perplexity)
    frame["x"], frame["y"] = coordinates[:, 0], coordinates[:, 1]

    category_column = args.color_by or next(
        (c for c in CATEGORY_CANDIDATES if c in frame.columns), None)
    frame["category"] = (category_labels(frame, category_column, args.top_categories)
                         if category_column else "all")

    output = args.output / dataset / run_folder.name if run_folder.name in {"full", "selected"} \
        else args.output / dataset
    output.mkdir(parents=True, exist_ok=True)
    stem = output / f"projection_{args.method}"
    plot_static(frame, args.method, dataset, category_column or "none", args.min_votes,
                stem.with_suffix(".png"))
    if args.per_model:
        plot_per_model(frame, models, args.method, dataset,
                       output / f"projection_{args.method}_per_model.png")
    plot_interactive(frame, args.method, dataset, category_column or "none",
                     stem.with_suffix(".html"), log)
    keep = [c for c in HOVER_CANDIDATES if c in frame.columns] + [
        "split", "scored", "time", "category", "x", "y", "votes", "ensemble_alert", "ensemble_score",
    ] + [m + "_alert" for m in models]
    frame[keep].to_csv(stem.with_suffix(".csv"), index=False)
    np.save(output / f"projection_{args.method}_embedding.npy", np.asarray(embedding, dtype=np.float32))
    if args.method == "tsne" and not args.no_layouts:   # the same points laid out by UMAP, for the console's map switch
        try:
            from map_layouts import write as write_layout
            meta = write_layout(output)
            log.write(f"{dataset}: UMAP layout of the same points | elapsed {runlog.format_duration(meta['seconds'])}")
        except ImportError:
            log.write(f"{dataset}: no UMAP layout (install umap-learn, or pass --no-layouts)", "WARN")
    log.write(f"{dataset}: written to {output} | elapsed {runlog.format_duration(time.perf_counter() - started)}", "DONE")


def main():
    args = parse_args()
    log = Log(args.quiet)
    datasets = discover(args.experiments, args.dataset, args.feature_set)
    if not datasets:
        log.write("No model bundles found in " + str(args.experiments), "ERROR")
        return 1
    failures = 0
    for dataset in datasets:
        try:
            visualise(dataset, args, log)
        except Exception as error:
            failures += 1
            log.write(f"{dataset} failed: {error!r}", "ERROR")
    log.write("Visualisation complete: " + str(args.output), "COMPLETE")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
