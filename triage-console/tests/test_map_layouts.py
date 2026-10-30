"""Tests for the map layouts (t-SNE and UMAP of the same points) in service/scoring.py.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import scoring  # noqa: E402


class Layouts(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        data = Path(self.folder.name)
        self.maps = data / "phase4_detection" / "auth" / "model_zoo_map" / "individual" / "selected"
        self.maps.mkdir(parents=True)
        self.embedding = self.maps / "projection_tsne_embedding.npy"
        np.save(self.embedding, np.zeros((3, 32), dtype=np.float32))
        points = data / "phase7b_clusters" / "auth" / "individual"
        points.mkdir(parents=True)
        pd.DataFrame({"row_manifest_id": ["a", "b", "c"], "split": "test", "time": "2026-06-01 00:00:00",
                      "x": [1.0, 2.0, 3.0], "y": [4.0, 5.0, 6.0], "cluster_number": [1, 1, 2], "votes": 0,
                      "category": "E", "flagged": [False, True, False]}).to_csv(points / "map_points.csv", index=False)
        self.patch = mock.patch.object(scoring, "DATA", data)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        scoring._map_table.cache_clear()
        scoring._layout_xy.cache_clear()
        self.folder.cleanup()

    def write_layout(self, ids, embedding_stamp=None):
        pd.DataFrame({"row_manifest_id": ids, "x": [10.0 * (i + 1) for i in range(len(ids))],
                      "y": [-1.0 * (i + 1) for i in range(len(ids))]}).to_csv(self.maps / "layout_umap.csv", index=False)
        stat = self.embedding.stat()
        (self.maps / "layout_umap.json").write_text(json.dumps(
            {"embedding": embedding_stamp or f"{stat.st_size}:{int(stat.st_mtime)}"}), encoding="utf-8")

    def test_missing_until_built(self):
        self.assertEqual(scoring.layout_status("auth", "individual"), {"tsne": "ready", "umap": "missing"})
        with self.assertRaises(ValueError):
            scoring.map_points("auth", "individual", layout="umap")

    def test_stale_when_the_embedding_changed(self):
        self.write_layout(["a", "b", "c"], embedding_stamp="1:1")
        self.assertEqual(scoring.layout_status("auth", "individual")["umap"], "stale")
        with self.assertRaises(ValueError):
            scoring.map_points("auth", "individual", layout="umap")

    def test_same_points_new_positions(self):
        self.write_layout(["a", "b", "c"])
        tsne = scoring.map_points("auth", "individual")
        umap = scoring.map_points("auth", "individual", layout="umap")
        self.assertEqual(umap["id"], tsne["id"])
        self.assertEqual(umap["cluster"], tsne["cluster"])
        self.assertEqual(umap["flagged"], tsne["flagged"])
        self.assertEqual(umap["x"], [10.0, 20.0, 30.0])
        self.assertEqual(tsne["x"], [1.0, 2.0, 3.0])                     # the t-SNE table is not changed

    def test_matched_by_id_when_the_order_differs(self):
        self.write_layout(["c", "a", "b"])                              # c=10, a=20, b=30
        umap = scoring.map_points("auth", "individual", layout="umap")
        self.assertEqual(dict(zip(umap["id"], umap["x"])), {"a": 20.0, "b": 30.0, "c": 10.0})

    def test_unknown_layout(self):
        self.write_layout(["a", "b", "c"])
        with self.assertRaises(ValueError):
            scoring.map_points("auth", "individual", layout="pca")


if __name__ == "__main__":
    unittest.main()
