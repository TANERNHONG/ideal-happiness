"""Phase 4c (optional): other layouts of the t-SNE map's points.

  python pipeline/phase4_detection/map_layouts.py --source auth
  python pipeline/phase4_detection/map_layouts.py --source ossec --dataset episodes

t-SNE is one way to flatten the 32-number embedding into a picture; it keeps
neighbours together but says nothing about distances between islands. UMAP is
another, which keeps more of the global structure. This script lays out the
**same points** as the t-SNE map (``projection_tsne.csv`` and its saved
embedding, in the same order) with UMAP, so the two pictures can be compared
point for point. The groups (Phase 7b) stay the ones found on the t-SNE map.

UMAP uses the settings of ``model_zoo_map.py --method umap``: 30 neighbours,
``min_dist`` 0.1, seed 42, learned from the rows no model flagged and then
applied to every row. Needs ``umap-learn``.

Outputs, next to the t-SNE map:
data/phase4_detection/<source>/model_zoo_map/<dataset>/<feature-set>/
    layout_umap.csv    row_manifest_id, x, y (same rows and order as projection_tsne.csv)
    layout_umap.json   settings, the embedding it was computed from (size and time), seconds taken

``model_zoo_map.py`` calls ``write`` after each t-SNE map, so a Phase 4c run
keeps the layout in step. The SMRT OT Console offers it beside t-SNE when
``layout_umap.json`` names the current embedding.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
MAPS = ROOT / "data" / "phase4_detection"
SETTINGS = {"n_neighbors": 30, "min_dist": 0.1, "random_state": 42}   # as model_zoo_map.py --method umap


def stamp(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_size}:{int(stat.st_mtime)}"


def umap_layout(folder: Path) -> tuple[pd.DataFrame, dict]:
    """UMAP coordinates for the points of the t-SNE map in ``folder``, in the same order."""
    import umap                                                     # optional dependency: imported only here

    points = pd.read_csv(folder / "projection_tsne.csv", usecols=["row_manifest_id", "votes", "ensemble_alert"],
                         dtype={"row_manifest_id": str})
    embedding_path = folder / "projection_tsne_embedding.npy"
    embedding = np.load(embedding_path, allow_pickle=False)
    if len(embedding) != len(points):
        raise ValueError(f"{folder}: {len(points)} map points but {len(embedding)} embeddings")
    normal = (pd.to_numeric(points["votes"], errors="coerce").fillna(0).eq(0)
              & ~points["ensemble_alert"].astype(str).str.lower().eq("true")).to_numpy()
    reference = embedding[normal] if normal.sum() >= 10 else embedding
    started = time.perf_counter()
    reducer = umap.UMAP(n_components=2, **SETTINGS)
    xy = reducer.fit(reference).transform(embedding)
    frame = pd.DataFrame({"row_manifest_id": points["row_manifest_id"], "x": xy[:, 0].round(4), "y": xy[:, 1].round(4)})
    meta = {"method": "umap", **SETTINGS, "fitted_on": "rows no model flagged", "rows": int(len(frame)),
            "fitted_rows": int(len(reference)), "embedding": stamp(embedding_path),
            "seconds": round(time.perf_counter() - started, 1)}
    return frame, meta


def folders(source: str, dataset: str = "") -> list[Path]:
    base = MAPS / source / "model_zoo_map"
    return sorted(p.parent for p in base.glob(f"{dataset or '*'}/*/projection_tsne_embedding.npy"))


def write(folder: Path) -> dict:
    frame, meta = umap_layout(folder)
    frame.to_csv(folder / "layout_umap.csv", index=False)
    (folder / "layout_umap.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=("auth", "ossec"))
    parser.add_argument("--dataset", default="", help="one view only (default: every mapped view)")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    found = folders(args.source, args.dataset)
    if not found:
        runlog.emit(f"No t-SNE maps with a saved embedding under {MAPS / args.source / 'model_zoo_map'}", "ERROR")
        return 1
    for folder in found:
        meta = write(folder)
        runlog.log(f"{folder.relative_to(ROOT)}: {meta['rows']:,} points | elapsed {runlog.format_duration(meta['seconds'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
