import sys
import tempfile
import unittest
from pathlib import Path
import numpy as np
from scipy import sparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service.report_maps import sparse_rows, build


class MapFeatures(unittest.TestCase):
    def test_sparse_row_stream_matches_original_including_empty_rows(self):
        matrix = sparse.csr_matrix(np.array([[1,0,2], [0,0,0], [0,3,4], [5,6,0]], dtype=np.float32))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'X.npz'; sparse.save_npz(path, matrix)
            np.testing.assert_array_equal(sparse_rows(path,[0,1,3]).toarray(), matrix[[0,1,3]].toarray())
            with self.assertRaises(ValueError): sparse_rows(path,[4])

    def test_invalid_source_view_targets(self):
        for source, view, ids in [('pf','individual',['a']), ('auth','../escape',['a']), ('auth','individual',[])]:
            with self.assertRaises(ValueError): build(source,view,ids)


if __name__ == '__main__': unittest.main()
