"""Phase 7b: give every test observation a behavioural cluster (a pseudo-label).

  python pipeline/phase7b_clusters/assign_clusters.py --source auth
  python pipeline/phase7b_clusters/assign_clusters.py --source pf --views sessions individual
  python pipeline/phase7b_clusters/assign_clusters.py --source ossec --min-cluster-share 0.002   # finer clusters

Phase 4c draws each view's test period on a t-SNE map, but only a sample: every
flagged row (up to 10,000) and 15,000 random unflagged ones. t-SNE cannot place
new points, so this works in two steps:

1. Islands. HDBSCAN finds the islands on the map, so a cluster is what an
   analyst sees as one island. Points on no island are "isolated".
2. Everyone else. The map was drawn from a 32-number summary of each row (the
   model-zoo embedding in model_bundle.joblib). That summary is computed for
   every test row, and each unmapped row takes the cluster most common among its
   nearest mapped neighbours (--neighbours, default 5). neighbour_agreement says
   how many of them agreed.

Outputs, in data/phase7b_clusters/<source>/:
  <view>/row_clusters.csv         every test row: cluster_id, how it was assigned,
                                  neighbour agreement, map coordinates if mapped,
                                  model-zoo votes, ensemble and detector alerts
  <view>/cluster_summary.csv      one row per cluster: size, alerts, alert rate and
                                  lift, dominant servers, events, users and
                                  addresses, time span and example log lines
  <view>/cluster_map.png          the map coloured by cluster, with cluster numbers
  <prefix>_cluster_overview.csv   every view's summary together
  <prefix>_alerts_by_cluster.csv  every flagged test row with its cluster and its
                                  original log lines, in the Phase 7 layout, so it
                                  feeds Phase 8 (securebert_label.py suggest) and
                                  Phase 9 (triage.py --inputs) directly

Cluster IDs read "<view>#<n>", numbered by size (1 = largest); "<view>#0" holds
the isolated points. They are pseudo-labels for grouping work, not verdicts, and
they belong to one Phase 4c run: re-running Phase 4c redraws the map and
renumbers the clusters, so record the run date with any notes about a cluster.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import sparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "phase7_alerts"))
import collect_alerts as phase7  # noqa: E402  (lineage and message helpers)

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)


# The model-zoo bundle pickles these classes from the script that wrote it (run
# as __main__); only their names are needed here, no scoring happens.
class HBOS:  # noqa: D101
    pass


class ECODStyle:  # noqa: D101
    pass


PREFIX = {"auth": "authlog", "ossec": "ossec", "pf": "pflog"}
CONTEXT = ("hostname", "host_id", "agent_name", "event_type", "dominant_event_type", "first_event_type",
           "event_category", "episode_family", "username", "dominant_username", "source_ip", "dominant_source_ip",
           "destination_ip", "destination_port", "service_port", "protocol", "action", "process_name", "entity_id",
           "close_reason")
TIME_COLUMNS = ("timestamp", "session_start", "window_start", "episode_start", "first_timestamp")
CHUNK_ROWS = 250_000
EXAMPLES_PER_CLUSTER = 2


def log(message, level="INFO"):
    runlog.emit(message, level)


class Phase7Log:
    """collect_alerts helpers call log.write(message, level)."""
    def write(self, message, level="INFO", always=False):
        log(message, level)


def truthy(series):
    return series.astype(str).str.strip().str.lower().isin({"1", "true", "yes", "1.0"})


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(PREFIX))
    parser.add_argument("--views", nargs="*", help="only these Phase 3 views (default: every mapped view)")
    parser.add_argument("--feature-set", default="selected", choices=("selected", "full"))
    parser.add_argument("--min-cluster-share", type=float, default=0.005,
                        help="smallest island, as a share of mapped points (default 0.005: broad clusters)")
    parser.add_argument("--min-cluster-size", type=int, default=25, help="floor for the smallest island")
    parser.add_argument("--neighbours", type=int, default=5)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-report", action="store_true",
                        help="do not rebuild the Phase 6 report afterwards (it shows these clusters)")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.output = args.output or Path("data/phase7b_clusters") / args.source
    return args


# --- steps -----------------------------------------------------------------------


def find_islands(projection, args):
    """HDBSCAN on the standardised map; clusters renumbered by size, isolated = 0."""
    from sklearn.cluster import HDBSCAN
    xy = projection[["x", "y"]].to_numpy(dtype=float)
    xy = (xy - xy.mean(axis=0)) / xy.std(axis=0)
    size = max(args.min_cluster_size, int(len(projection) * args.min_cluster_share))
    raw = HDBSCAN(min_cluster_size=size, min_samples=10, copy=True).fit_predict(xy)
    order = pd.Series(raw[raw >= 0]).value_counts().index          # largest first
    renumber = {old: new for new, old in enumerate(order, start=1)}
    return np.array([renumber.get(label, 0) for label in raw]), size


def merge_duplicate_islands(islands, mapped_embedding):
    """Rows with identical embeddings are the same behaviour, but t-SNE can scatter
    copies of one row over several islands. Merge islands that share an identical
    row, pull isolated copies into their island, and renumber by size."""
    keys = pd.Series([row.tobytes() for row in np.round(mapped_embedding, 5)])
    parent = {label: label for label in set(islands) if label}

    def root(label):
        while parent[label] != label:
            parent[label] = parent[parent[label]]
            label = parent[label]
        return label

    for _, members in pd.Series(islands).groupby(keys.values):
        labels = sorted(set(members.tolist()) - {0})
        for other in labels[1:]:
            parent[root(other)] = root(labels[0])
    merged = np.array([root(label) if label else 0 for label in islands])
    by_key = pd.Series(merged).groupby(keys.values).transform(lambda group: group[group > 0].mode().iloc[0] if (group > 0).any() else 0)
    merged = by_key.to_numpy()
    order = pd.Series(merged[merged > 0]).value_counts().index
    renumber = {old: new for new, old in enumerate(order, start=1)}
    return np.array([renumber.get(label, 0) for label in merged]), len(set(islands) - {0}) - len(order)


def read_scores(path):
    """Model-zoo test scores in X_test row order: IDs, votes, ensemble, context."""
    header = pd.read_csv(path, nrows=0).columns
    context = [column for column in CONTEXT if column in header]
    time_column = next((column for column in TIME_COLUMNS if column in header), None)
    wanted = ["row_manifest_id", "member_vote_count", "model_zoo_ensemble_score", "model_zoo_ensemble_alert"]
    columns = [column for column in wanted if column in header] + context + ([time_column] if time_column else [])
    frames = []
    for chunk in pd.read_csv(path, usecols=columns, dtype=str, chunksize=CHUNK_ROWS, low_memory=False):
        chunk["member_vote_count"] = pd.to_numeric(chunk.get("member_vote_count"), errors="coerce").fillna(0).astype(np.int16)
        chunk["model_zoo_ensemble_score"] = pd.to_numeric(chunk.get("model_zoo_ensemble_score"), errors="coerce").astype(np.float32)
        chunk["model_zoo_ensemble_alert"] = truthy(chunk.get("model_zoo_ensemble_alert", pd.Series("", index=chunk.index)))
        for column in context:
            chunk[column] = chunk[column].astype("category")
        frames.append(chunk)
    frame = pd.concat(frames, ignore_index=True)
    for column in context:
        frame[column] = frame[column].astype("category")
    return frame, context, time_column


def detector_alerts(detectors_folders, view):
    """row_manifest_id -> detector names that alerted, from every Phase 4a run of this view and the Phase 4f
    sequence detector (laid out like Phase 4a: <folder>/<view>/test_scores.csv)."""
    hits = {}
    names = {"isolation_alert": "Isolation Forest", "novelty_alert": "Novelty", "robust_alert": "Robust deviation",
             "sequence_alert": "Frequent subsequences"}
    for folder in sorted(f for root in detectors_folders for f in Path(root).glob("*")):
        if not (folder.name == view or folder.name.startswith(view + "__")) or not (folder / "test_scores.csv").is_file():
            continue
        header = pd.read_csv(folder / "test_scores.csv", nrows=0).columns
        columns = ["row_manifest_id"] + [column for column in names if column in header]
        for chunk in pd.read_csv(folder / "test_scores.csv", usecols=columns, dtype=str, chunksize=CHUNK_ROWS):
            for column in columns[1:]:
                for row_id in chunk.loc[truthy(chunk[column]), "row_manifest_id"].str.strip():
                    hits.setdefault(row_id, set()).add(names[column])
    return hits


def embed_all(bundle, matrix):
    """The map's 32-number embedding for every row, in chunks, as float32."""
    parts = []
    for start in range(0, matrix.shape[0], CHUNK_ROWS):
        block = matrix[start:start + CHUNK_ROWS][:, bundle["feature_indices"]].astype(np.float64)
        latent = bundle["embedding_reducer"].transform(block)
        parts.append(bundle["embedding_scaler"].transform(latent).astype(np.float32))
    return np.vstack(parts)


def spread_labels(embedding, mapped_positions, mapped_labels, neighbours):
    """Cluster and agreement for every row from its nearest mapped rows."""
    from scipy import stats
    from sklearn.neighbors import NearestNeighbors
    finder = NearestNeighbors(n_neighbors=neighbours, algorithm="brute", n_jobs=-1).fit(embedding[mapped_positions])
    labels = np.zeros(len(embedding), dtype=np.int32)
    agreement = np.zeros(len(embedding), dtype=np.float32)
    for start in range(0, len(embedding), CHUNK_ROWS):
        _, index = finder.kneighbors(embedding[start:start + CHUNK_ROWS])
        mode = stats.mode(mapped_labels[index], axis=1, keepdims=False)    # ties go to the smaller cluster number
        labels[start:start + len(index)] = mode.mode
        agreement[start:start + len(index)] = mode.count / neighbours
    labels[mapped_positions] = mapped_labels
    agreement[mapped_positions] = 1.0
    # Check: hide each mapped point's own label and predict it from its neighbours.
    # A high match means embedding neighbours reproduce the map's islands, so the
    # labels given to unmapped rows can be trusted to the same degree.
    reference = embedding[mapped_positions]
    _, index = NearestNeighbors(n_neighbors=neighbours + 1, algorithm="brute", n_jobs=-1).fit(reference).kneighbors(reference)
    held_out = stats.mode(mapped_labels[index[:, 1:]], axis=1, keepdims=False).mode
    return labels, agreement, float(np.mean(held_out == mapped_labels))


def top_values(series, count=3):
    shares = series.astype(str).replace({"nan": None, "": None}).dropna().value_counts(normalize=True).head(count)
    return "; ".join(f"{value} ({share:.0%})" if share >= 0.005 else f"{value} (<1%)" for value, share in shares.items())


def draw_map(projection, labels, view, path, source, alert_rates):
    """The map coloured by cluster, a number on each island; red numbers = mostly alerts."""
    fig, ax = plt.subplots(figsize=(14, 11), dpi=120, facecolor="white")
    colours = plt.get_cmap("tab20")
    isolated = labels == 0
    ax.scatter(projection.loc[isolated, "x"], projection.loc[isolated, "y"], s=3, c="#cbd5e1", linewidths=0,
               label="isolated (#0)")
    for cluster in sorted(set(labels) - {0}):
        part = projection[labels == cluster]
        ax.scatter(part["x"], part["y"], s=5, color=colours((cluster - 1) % 20), linewidths=0)
    alerts = truthy(projection["ensemble_alert"]) if "ensemble_alert" in projection else pd.Series(False, index=projection.index)
    ax.scatter(projection.loc[alerts, "x"], projection.loc[alerts, "y"], s=6, marker="x", c="#111827", linewidths=0.4,
               alpha=0.3, label="ensemble alert")
    for cluster in sorted(set(labels) - {0}):
        part = projection[labels == cluster]
        hot = alert_rates.get(cluster, 0) > 0.5
        ax.text(part["x"].median(), part["y"].median(), str(cluster), fontsize=12, weight="bold", ha="center",
                va="center", color="white" if hot else "#111827",
                bbox={"boxstyle": "round,pad=0.2", "fc": "#b91c1c" if hot else "white", "ec": "#111827", "lw": 0.5,
                      "alpha": 0.9})
    ax.scatter([], [], marker="s", c="#b91c1c", label="cluster number: mostly alerts")
    ax.scatter([], [], marker="s", c="white", edgecolors="#111827", label="cluster number: mostly normal")
    ax.set_title(f"{source} {view}: behavioural clusters (Phase 7b) on the Phase 4c t-SNE map", fontsize=15)
    ax.set_xticks([]); ax.set_yticks([])
    ax.legend(loc="lower right", fontsize=11, markerscale=2.5, framealpha=0.9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


# --- per view --------------------------------------------------------------------


def process_view(source, view, map_folder, args, detectors_folders, features_folder):
    started = time.perf_counter()
    projection = pd.read_csv(map_folder / "projection_tsne.csv", dtype={"row_manifest_id": str}, low_memory=False)
    if "split" not in projection:
        projection["split"] = "test"
    is_test = projection["split"].eq("test").to_numpy()
    sidecar = map_folder / "projection_tsne_embedding.npy"
    zoo_folder = Path("data/phase4_detection") / source / "model_zoo" / view / map_folder.name
    scores, context, time_column = read_scores(zoo_folder / "test_scores.csv")
    matrix = sparse.load_npz(features_folder / view / "X_test.npz").tocsr()
    if matrix.shape[0] != len(scores):
        log(f"{view}: X_test has {matrix.shape[0]:,} rows but the model zoo scored {len(scores):,}; the model zoo is "
            f"older than Phase 3. Re-run Phases 4b and 4c. Skipped.", "WARN")
        return None
    position = pd.Series(np.arange(len(scores)), index=scores["row_manifest_id"].str.strip())
    position = position[~position.index.duplicated()]
    projection["position"] = projection["row_manifest_id"].str.strip().map(position).where(is_test)
    missing = int(projection.loc[is_test, "position"].isna().sum())
    if missing:
        log(f"{view}: {missing:,} mapped rows not found in the model-zoo scores; the map is older than the zoo. "
            f"Re-run Phase 4c. Skipped.", "WARN")
        return None

    islands, size = find_islands(projection, args)
    log(f"{view}: {islands.max()} islands on the map (smallest {size} points), {np.mean(islands == 0):.1%} isolated")
    bundle = joblib.load(zoo_folder / "model_bundle.joblib")
    embedding = embed_all(bundle, matrix)
    test_positions = projection.loc[is_test, "position"].to_numpy(int)
    mapped_embedding = np.load(sidecar) if sidecar.is_file() else None
    if mapped_embedding is None or len(mapped_embedding) != len(projection):
        if not is_test.all():
            log(f"{view}: the map has non-test points but no matching embedding file; re-run Phase 4c. Skipped.", "WARN")
            return None
        mapped_embedding = embedding[test_positions]
    islands, merged = merge_duplicate_islands(islands, mapped_embedding)
    if merged:
        log(f"{view}: merged {merged} islands that held identical rows; {islands.max()} remain")
    labels, agreement, check = spread_labels(embedding, test_positions, islands[is_test], args.neighbours)
    log(f"{view}: neighbour check: {check:.1%} of mapped points get their own island back from their neighbours")
    del embedding, matrix

    rows = pd.DataFrame({
        "row_manifest_id": scores["row_manifest_id"].str.strip(),
        "cluster_id": [f"{view}#{label}" for label in labels],
        "cluster_number": labels,
        "assignment": "nearest",
        "neighbour_agreement": agreement.round(2),
        "zoo_votes": scores["member_vote_count"],
        "ensemble_alert": scores["model_zoo_ensemble_alert"],
        "ensemble_score": scores["model_zoo_ensemble_score"],
    })
    rows.loc[test_positions, "assignment"] = "map"
    rows["x"] = np.nan
    rows["y"] = np.nan
    rows.loc[test_positions, ["x", "y"]] = projection.loc[is_test, ["x", "y"]].to_numpy()
    hits = detector_alerts(detectors_folders, view)
    rows["detector_alerts"] = rows["row_manifest_id"].map(lambda row_id: "; ".join(sorted(hits.get(row_id, ()))))
    rows["flagged"] = rows["ensemble_alert"] | rows["detector_alerts"].ne("")

    out = args.output / view
    out.mkdir(parents=True, exist_ok=True)
    rows.drop(columns=["cluster_number", "flagged"]).to_csv(out / "row_clusters.csv", index=False)
    # Every map point (all periods) with its island, for the report's timeline viewer.
    points = pd.DataFrame({
        "row_manifest_id": projection["row_manifest_id"], "split": projection["split"],
        "time": projection.get("time", pd.Series("", index=projection.index)), "x": projection["x"].round(3),
        "y": projection["y"].round(3), "cluster_number": islands,
        "votes": projection.get("votes", pd.Series(0, index=projection.index)),
        "ensemble_alert": truthy(projection["ensemble_alert"]) if "ensemble_alert" in projection else False,
        "scored": projection.get("scored", pd.Series(True, index=projection.index)),
        "category": projection.get("category", pd.Series("", index=projection.index)),
    })
    flagged_test = rows.set_index("row_manifest_id")["flagged"]
    points.loc[is_test, "flagged"] = points.loc[is_test, "row_manifest_id"].map(flagged_test).fillna(False).to_numpy()
    points.loc[~is_test, "flagged"] = points.loc[~is_test, "ensemble_alert"]
    points.to_csv(out / "map_points.csv", index=False)
    history = points[~is_test]

    overall_rate = rows["flagged"].mean() or np.nan
    summary = []
    for number, part in rows.groupby("cluster_number", sort=True):
        info = scores.loc[part.index]
        record = {
            "cluster_id": f"{view}#{number}", "view": view, "rows": len(part), "share_of_test": round(len(part) / len(rows), 5),
            "mapped_points": int(part["assignment"].eq("map").sum()),
            "mean_neighbour_agreement": round(float(part.loc[part["assignment"].eq("nearest"), "neighbour_agreement"].mean()), 2)
            if part["assignment"].eq("nearest").any() else 1.0,
            "zoo_flagged": int(part["zoo_votes"].gt(0).sum()), "ensemble_alerts": int(part["ensemble_alert"].sum()),
            "detector_alerts": int(part["detector_alerts"].ne("").sum()), "flagged_rows": int(part["flagged"].sum()),
            "alert_rate": round(float(part["flagged"].mean()), 5),
            "lift_vs_view": round(float(part["flagged"].mean() / overall_rate), 2) if overall_rate == overall_rate else None,
            "map_points_before_test": int((history["cluster_number"] == number).sum()),
            "first_month_on_map": str(points.loc[points["cluster_number"] == number, "time"].dropna().astype(str).str[:7].min() or ""),
            "centre_x": round(float(part["x"].median()), 2) if part["x"].notna().any() else None,
            "centre_y": round(float(part["y"].median()), 2) if part["y"].notna().any() else None,
        }
        if time_column:
            times = info[time_column].dropna().astype(str)
            record["first_seen"], record["last_seen"] = (times.min(), times.max()) if len(times) else ("", "")
        for column in context:
            record[f"top_{column}"] = top_values(info[column])
        summary.append(record)
    summary = pd.DataFrame(summary)
    rates = {int(cid.split("#")[1]): rate for cid, rate in zip(summary["cluster_id"], summary["alert_rate"])}
    draw_map(projection, islands, view, out / "cluster_map.png", source, rates)
    log(f"{view}: {len(rows):,} rows in {len(summary)} clusters; {int((summary['alert_rate'] > 0.5).sum())} clusters "
        f"are mostly alerts | elapsed {runlog.format_duration(time.perf_counter() - started)}")
    return {"view": view, "rows": rows, "summary": summary, "out": out, "neighbour_check": round(check, 4),
            "islands": int(islands.max()), "isolated_share": round(float(np.mean(islands == 0)), 4)}


# --- messages and alert file -------------------------------------------------------


def attach_messages(source, results):
    """Original log lines for flagged rows (all) and example rows (a few per cluster)."""
    phase7.LINEAGE_KEY = phase7.SOURCES[source]["lineage_key"]
    phase7.MESSAGE_COLUMN = phase7.SOURCES[source]["message_column"]
    paths = phase7.default_paths(source)
    wanted, examples = {}, {}
    for result in results:
        rows = result["rows"]
        flagged = rows.loc[rows["flagged"], "row_manifest_id"]
        picked = []
        for number, part in rows.groupby("cluster_number"):
            ranked = part.sort_values(["flagged", "ensemble_score"], ascending=False)
            picked.append(ranked.head(EXAMPLES_PER_CLUSTER)[["cluster_number", "row_manifest_id"]])
        picked = pd.concat(picked)
        examples[result["view"]] = picked
        wanted[result["view"]] = set(flagged) | set(picked["row_manifest_id"])
    log(f"Resolving original log lines for {sum(len(ids) for ids in wanted.values()):,} rows")
    messages = phase7.lineage_messages(paths["features"], paths["event_lookup"], wanted, Phase7Log())
    return messages, examples


def main():
    args = parse_args()
    source = args.source
    map_root = Path("data/phase4_detection") / source / "model_zoo_map"
    detectors = [Path("data/phase4_detection") / source / name for name in ("detectors", "sequences")]
    features = Path("data/phase3_features") / source
    views = sorted(path.parent for path in map_root.glob(f"*/{args.feature_set}/projection_tsne.csv"))
    if args.views:
        views = [path for path in views if path.parent.name in args.views]
    if not views:
        raise SystemExit(f"No Phase 4c maps in {map_root}; run the pipeline with --with-model-zoo first.")
    results = [result for folder in views
               if (result := process_view(source, folder.parent.name, folder, args, detectors, features))]
    if not results:
        raise SystemExit("No view could be clustered.")

    messages, examples = attach_messages(source, results)
    overview, alert_rows = [], []
    for result in results:
        view, rows, summary = result["view"], result["rows"], result["summary"]
        picked = examples[view]
        texts = {number: " || ".join(messages.get((view, row_id), "")[:600] for row_id in group["row_manifest_id"])
                 for number, group in picked.groupby("cluster_number")}
        summary["example_log_lines"] = summary["cluster_id"].map(lambda cid: texts.get(int(cid.split("#")[1]), ""))
        summary.to_csv(result["out"] / "cluster_summary.csv", index=False)
        overview.append(summary)
        flagged = rows[rows["flagged"]].copy()
        # probability as in Phase 7: share of this view's test rows with a lower ensemble score
        ranks = rows["ensemble_score"].rank(pct=True, method="min")
        cluster_rate = summary.set_index("cluster_id")["alert_rate"]
        for index, row in flagged.iterrows():
            parts = ([f"Model-zoo ensemble ({row['zoo_votes']} votes)"] if row["ensemble_alert"] else []) + \
                    ([row["detector_alerts"]] if row["detector_alerts"] else [])
            alert_rows.append({
                "rank": round(float(ranks.loc[index]), 6) if ranks.loc[index] == ranks.loc[index] else "",
                "flagged_by": "; ".join(parts), "dataset": view, "cluster_id": row["cluster_id"],
                "cluster_alert_rate": cluster_rate.get(row["cluster_id"]), "row_manifest_id": row["row_manifest_id"],
                "raw_messages": messages.get((view, row["row_manifest_id"]),
                                             f"[source messages not found; row_manifest_id={row['row_manifest_id']}]"),
            })
    overview = pd.concat(overview, ignore_index=True)
    prefix = PREFIX[source]
    overview.to_csv(args.output / f"{prefix}_cluster_overview.csv", index=False)
    alerts = pd.DataFrame(alert_rows).sort_values(["cluster_id", "rank"], ascending=[True, False])
    alerts["probability"] = alerts["rank"]                                    # the old name, for one release
    alerts.to_csv(args.output / f"{prefix}_alerts_by_cluster.csv", index=False)
    (args.output / "run.json").write_text(json.dumps({
        "created": datetime.now().isoformat(timespec="seconds"), "source": source, "feature_set": args.feature_set,
        "min_cluster_share": args.min_cluster_share, "min_cluster_size": args.min_cluster_size,
        "neighbours": args.neighbours,
        "views": {result["view"]: {"islands": result["islands"], "isolated_share": result["isolated_share"],
                                   "neighbour_check": result["neighbour_check"]} for result in results},
        "note": "Cluster IDs belong to this Phase 4c map; re-running Phase 4c renumbers them.",
    }, indent=2), encoding="utf-8")
    unresolved = int(alerts["raw_messages"].str.startswith("[source messages not found").sum()) if len(alerts) else 0
    log(f"{len(overview)} clusters across {len(results)} views; {len(alerts):,} flagged rows written with their cluster"
        + (f" ({unresolved:,} without source lines)" if unresolved else "") + f" -> {args.output}", "COMPLETE")
    if not args.no_report:
        import subprocess
        report = HERE.parent / "phase6_report" / f"{source}.py"
        log(f"Rebuilding the Phase 6 report so it shows these clusters ({report.name})")
        subprocess.run([sys.executable, str(report), "--quiet"], check=False)


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
