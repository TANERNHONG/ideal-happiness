"""Report maps: test/validation baseline with individually identified targets.

Unmapped targets use their original saved feature rows and the same neighbour
placement as Analyze, never a cluster centroid or a fresh t-SNE fit. Sparse NPZ
rows are streamed with bounded memory; placing a large view runs as a job.
"""
import csv
import hashlib
import json
import zipfile

import numpy as np
from scipy import sparse

from . import scoring, review_context, cluster_index, uploads
from .catalog import SOURCES
from .config import DATA, CACHE


def _array(z, name):
    stream = z.open(name + '.npy')
    version = np.lib.format.read_magic(stream)
    reader = np.lib.format.read_array_header_1_0 if version == (1, 0) else np.lib.format.read_array_header_2_0
    shape, order, dtype = reader(stream)
    if order or dtype.hasobject:
        stream.close()
        raise ValueError('Unsupported saved matrix format.')
    return stream, stream.tell(), shape, dtype


def sparse_rows(path, positions):
    """Read selected CSR rows without loading a multi-GB feature matrix into RAM."""
    with zipfile.ZipFile(path) as z:
        shape = np.load(z.open('shape.npy'), allow_pickle=False)
        with z.open('format.npy') as f:
            if np.load(f, allow_pickle=False).item() != b'csr':
                raise ValueError('The saved feature matrix must use CSR format.')
        stream, offset, _, dtype = _array(z, 'indptr')
        spans = []
        with stream:
            for pos in positions:
                if pos < 0 or pos >= int(shape[0]):
                    raise ValueError('Feature row is outside the saved matrix.')
                stream.seek(offset + pos * dtype.itemsize)
                a, b = np.frombuffer(stream.read(dtype.itemsize * 2), dtype=dtype)
                spans.append((int(a), int(b)))
        arrays = []
        for key in ('data', 'indices'):
            stream, offset, _, dtype = _array(z, key)
            parts = []
            with stream:
                for a, b in spans:
                    stream.seek(offset + a * dtype.itemsize)
                    parts.append(np.frombuffer(stream.read((b-a) * dtype.itemsize), dtype=dtype).copy())
            arrays.append(np.concatenate(parts) if parts else np.array([], dtype=dtype))
        pointer = np.r_[0, np.cumsum([b-a for a, b in spans])]
        return sparse.csr_matrix((arrays[0], arrays[1], pointer), shape=(len(positions), int(shape[1])))


def build(source, view, ids, layout='tsne', upload=None, progress=lambda *args: None):
    if source not in ('auth', 'ossec') or view not in SOURCES[source]['views']:
        raise ValueError('Maps are available for AUTH and OSSEC views only.')
    if layout not in scoring.LAYOUTS:
        raise ValueError('Unknown map layout.')
    if not isinstance(ids, list) or not 1 <= len(ids) <= 120 or any(not isinstance(i, str) or len(i) > 160 for i in ids):
        raise ValueError('Choose 1 to 120 target observations.')
    ids = list(dict.fromkeys(ids))
    table = scoring.map_table(source, view, layout)
    if table is None:
        raise ValueError('This view has no cluster map.')
    baseline = table[table['split'].isin(['test', 'validation'])]
    if len(baseline) > 60000:
        flagged = baseline[baseline['flagged']]
        baseline = __import__('pandas').concat([flagged, baseline[~baseline['flagged']].sample(max(0, 60000-len(flagged)), random_state=1)])
    targets, missing = {}, []
    uploaded = uploads.get_upload(int(upload)) if upload is not None else None
    upload_items = {i['item_id']: i for i in uploaded['items'] if i['view'] == view} if uploaded else {}
    if uploaded and uploaded['source'] != source:
        raise ValueError('Upload source does not match the map.')
    for rid in ids:
        if uploaded:
            item = upload_items.get(rid)
            if item is None:
                raise ValueError('The target does not belong to this upload and view.')
            point = item.get('map') or {}
            xy = point if layout == 'tsne' else point.get('layouts', {}).get(layout, {})
            if 'x' in xy and 'y' in xy:
                targets[rid] = {'x': xy['x'], 'y': xy['y'], 'placement': 'upload nearest-neighbour estimate', 'period': 'upload'}
            else:
                missing.append(rid)
        elif rid in table.index:
            r = table.loc[rid]
            if getattr(r, 'ndim', 1) == 2:
                r = r.iloc[0]
            targets[rid] = {'x': float(r['x']), 'y': float(r['y']), 'placement': 'saved map point', 'period': str(r['split'])}
        else:
            missing.append(rid)
    folder = DATA / 'phase3_features' / source / view
    for period in ('validation', 'test'):
        if not missing or uploaded:
            break
        progress('map', f'Finding {period} feature rows')
        path = folder / f'{period}_rows.csv'
        if not path.exists():
            continue
        selected = []
        with path.open(encoding='utf-8', newline='') as f:
            wanted = set(missing)
            for pos, row in enumerate(csv.DictReader(f)):
                if row['row_manifest_id'] in wanted:
                    selected.append((pos, row['row_manifest_id']))
        if not selected:
            continue
        matrix_path = folder / f'X_{period}.npz'
        stamp = [scoring._stamp(matrix_path), scoring._stamp(scoring._map_folder(source, view) / 'projection_tsne_embedding.npy'),
                 scoring._stamp(DATA / 'phase7b_clusters' / source / view / 'map_points.csv'),
                 scoring._stamp(DATA / 'phase4_detection' / source / 'model_zoo' / view / 'selected' / 'model_bundle.joblib'),
                 scoring._stamp(scoring._map_folder(source, view) / 'layout_umap.csv'),
                 scoring.layout_status(source, view), selected, layout]
        key = hashlib.sha256(json.dumps(stamp).encode()).hexdigest()
        cache = CACHE / f'report_map_{source}_{view}_{key}.json'
        if cache.exists():
            placements = json.loads(cache.read_text(encoding='utf-8'))
        else:
            progress('map', f'Reading saved {period} features; large views can take several minutes')
            matrix = sparse_rows(matrix_path, [pos for pos, _ in selected])
            bundle = scoring._zoo_bundle(source, view, 'selected')
            if bundle is None:
                raise ValueError('The saved model-zoo bundle is missing.')
            placements = scoring.place(source, view, scoring.embed(bundle, matrix))
            if placements is None:
                raise ValueError('The saved map embedding is missing.')
            CACHE.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(placements, allow_nan=False), encoding='utf-8')
        for (_, rid), point in zip(selected, placements):
            xy = point if layout == 'tsne' else point['layouts'][layout]
            targets[rid] = {'x': xy['x'], 'y': xy['y'], 'placement': 'nearest-neighbour estimate', 'period': period}
            missing.remove(rid)
    output = []
    for rid in ids:
        if uploaded:
            item = upload_items[rid]
            obs = {'start': item['when'], 'server': item['host'], 'anomaly': item.get('unusual'),
                   'lines': [c['line'] for c in item.get('context', []) if c.get('own')], 'event_ids': []}
        else:
            obs = review_context.observation(source, view, rid)
        line_rarity = []
        for event_id in obs['event_ids'][:len(obs['lines'])]:
            row = cluster_index.score_row(source, 'individual', event_id)
            line_rarity.append(review_context._anomaly(review_context._percentiles(source, 'individual', row)) if row else None)
        output.append({'id': rid, **targets.get(rid, {'placement': 'unavailable'}), 'time': obs['start'], 'server': obs['server'],
                       'anomaly': obs['anomaly'], 'lines': obs['lines'], 'line_rarity': line_rarity, 'line_count': obs.get('line_count')})
    return {'source': source, 'view': view, 'layout': layout,
            'baseline': {'x': baseline['x'].tolist(), 'y': baseline['y'].tolist(), 'flagged': baseline['flagged'].astype(int).tolist(),
                         'period': baseline['split'].tolist()}, 'baseline_total': int(table['split'].isin(['test', 'validation']).sum()),
            'targets': output, 'missing': missing}
