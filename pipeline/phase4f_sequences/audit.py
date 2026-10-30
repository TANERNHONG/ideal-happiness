"""Phase 4f step 0: read-only order/duplicate audit and traceable event extract.

Run from the project root:
  .venv/Scripts/python.exe pipeline/phase4f_sequences/audit.py --source ossec
  .venv/Scripts/python.exe pipeline/phase4f_sequences/audit.py --source auth --max-events 100000 --write-stream

Never changes Phase 2 stores or existing observations. Output directories must
be new. The optional stream preserves every occurrence: duplicate candidates
are annotated, never deleted, and cross-file ties remain explicitly ambiguous.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import itertools
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {'auth': ('authlog', 'record_id'), 'ossec': ('ossec', 'event_id')}
FIELDS = ('timestamp_epoch', 'timestamp_text', 'host_id', 'event_type',
          'process_name', 'pid', 'username', 'source_ip', 'source_file',
          'source_line', 'raw_message', 'event_outcome', 'invalid_user_indicator',
          'archive_name', 'archive_member', 'original_log_line')
REQUIRED = {'timestamp_epoch', 'timestamp_text', 'host_id', 'event_type', 'source_file', 'source_line'}


def line_number(value):
    try:
        n = int(value)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def file_key(event):
    return tuple(str(event.get(k) or '') for k in ('archive_name', 'archive_member', 'source_file'))


def source_order(event):
    n = line_number(event.get('source_line'))
    return (*file_key(event), n is None, n or 0, event['event_id'])


def candidate_key(event):
    # Whitespace-only normalisation: never remove accounts, addresses or PIDs.
    message = ' '.join(str(event.get('raw_message') or '').split())
    if not message:
        return None
    return (event['host_id'], event['timestamp_epoch'], event.get('process_name'),
            event.get('pid'), event['event_type'], message)


def reference(event):
    return {k: event.get(k) for k in ('event_id', 'event_type', 'source_file', 'source_line', 'archive_name', 'archive_member')}


def parse_time(text):
    """Use Phase 2's UTC-tagged representation of log clock text, without conversion."""
    value = datetime.fromisoformat(text)
    if value.tzinfo is not None:
        raise ValueError('Use the source log clock without a timezone, e.g. 2026-01-01T00:00:00.')
    return value.replace(tzinfo=timezone.utc).timestamp()


def event_groups(connection, source, host=None, start=None, end=None, max_tie_events=100000):
    key = SOURCES[source][1]
    columns = {row[1] for row in connection.execute('PRAGMA table_info(events)')}
    missing = (REQUIRED | {key}) - columns
    if missing:
        raise ValueError('Missing event-store columns: ' + ', '.join(sorted(missing)))
    select = [f'"{key}" AS event_id'] + [f'"{field}"' if field in columns else f"NULL AS {field}" for field in FIELDS]
    clauses, args = [], []
    for clause, value in [('host_id=?', host), ('timestamp_epoch>=?', start), ('timestamp_epoch<?', end)]:
        if value is not None:
            clauses.append(clause); args.append(value)
    query = 'SELECT '+','.join(select)+' FROM events'
    if clauses:
        query += ' WHERE '+' AND '.join(clauses)
    query += ' ORDER BY timestamp_epoch'
    for epoch, group in itertools.groupby(connection.execute(query, args), key=lambda r: r['timestamp_epoch']):
        batch = []
        for row in group:
            batch.append(dict(row))
            if len(batch) > max_tie_events:
                raise ValueError(f'Timestamp {epoch} exceeds --max-tie-events={max_tie_events}; narrow the host/time range or raise the cap.')
        yield batch


def audit(connection, source, *, host=None, start=None, end=None, max_events=100000,
          max_tie_events=100000, stream=None, example_limit=10):
    counts = Counter()
    vocab = {k: Counter() for k in ('event_type', 'event_outcome', 'process_name')}
    hosts, months = Counter(), Counter()
    examples = {'order_changes': [], 'cross_file_candidates': [], 'within_file_repeats': []}
    first = last = None
    truncated = False
    for batch in event_groups(connection, source, host, start, end, max_tie_events):
        if max_events and counts['events'] >= max_events:
            truncated = True
            break
        by_host = defaultdict(list)
        for event in batch:
            if not event['host_id']:
                raise ValueError('An event has no host_id; cannot safely construct a per-host sequence.')
            if first is None:
                first = event['timestamp_text']
            last = event['timestamp_text']
            counts['events'] += 1
            hosts[event['host_id']] += 1
            months[str(event['timestamp_text'])[:7]] += 1
            for field in vocab:
                vocab[field][str(event.get(field) or '(missing)')] += 1
            for field in ('username', 'source_ip', 'raw_message', 'source_file'):
                if not event.get(field): counts['missing_'+field] += 1
            if line_number(event.get('source_line')) is None:
                counts['missing_or_invalid_source_line'] += 1
            by_host[event['host_id']].append(event)
        counts['timestamp_groups'] += 1
        for host_id in sorted(by_host):
            events = by_host[host_id]
            ordered = sorted(events, key=source_order)
            counts['host_timestamp_groups'] += 1
            files = {file_key(e) for e in events}
            incomplete = any(not e.get('source_file') or line_number(e.get('source_line')) is None for e in events)
            positions = [(file_key(e), line_number(e.get('source_line'))) for e in events]
            position_collision = len(positions) != len(set(positions))
            ambiguous = len(events) > 1 and (len(files) > 1 or incomplete or position_collision)
            if len(events) > 1:
                counts['tied_host_timestamp_groups'] += 1
                counts['events_in_ties'] += len(events)
                if len(files) > 1: counts['cross_file_tie_groups'] += 1
                if position_collision: counts['source_position_collision_groups'] += 1
                if ambiguous: counts['ambiguous_tie_groups'] += 1
                before = sorted(events, key=lambda e: e['event_id'])
                if [e['event_id'] for e in ordered] != [e['event_id'] for e in before]:
                    counts['ties_reordered_vs_id'] += 1
                    if len(examples['order_changes']) < example_limit:
                        examples['order_changes'].append({'host': host_id, 'time': events[0]['timestamp_text'],
                            'id_order': [reference(e) for e in before[:12]], 'source_order': [reference(e) for e in ordered[:12]],
                            'events': len(events), 'ambiguous': ambiguous})
            duplicates = defaultdict(list)
            for event in events:
                candidate = candidate_key(event)
                if candidate is not None: duplicates[candidate].append(event)
            groups = {}
            for candidate, matches in duplicates.items():
                if len(matches) < 2: continue
                counts['repeated_message_groups'] += 1
                counts['events_in_repeated_message_groups'] += len(matches)
                per_file = Counter(file_key(e) for e in matches)
                cross_file, within_file = len(per_file) > 1, max(per_file.values()) > 1
                fingerprint = hashlib.sha256(json.dumps(candidate, ensure_ascii=False).encode()).hexdigest()[:24]
                for event in matches: groups[event['event_id']] = fingerprint
                for enabled, name, counter in [(cross_file, 'cross_file_candidates', 'cross_file_candidate_groups'),
                                                (within_file, 'within_file_repeats', 'within_file_repeat_groups')]:
                    if enabled:
                        counts[counter] += 1
                        if len(examples[name]) < example_limit:
                            examples[name].append({'host': host_id, 'time': matches[0]['timestamp_text'],
                                'candidate_id': fingerprint, 'occurrences': len(matches),
                                'files': len(per_file), 'max_occurrences_in_one_file': max(per_file.values()),
                                'references': [reference(e) for e in sorted(matches, key=source_order)[:12]]})
            if stream is not None:
                for event in ordered:
                    record = {**event, 'source': source, 'token': event['event_type'],
                              'timestamp_order_ambiguous': ambiguous,
                              'duplicate_candidate_id': groups.get(event['event_id'])}
                    stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False)+'\n')
        if counts['timestamp_groups'] % 10000 == 0:
            runlog.log(f"Audited {counts['events']:,} {source} events")
    return {'schema_version': 1, 'source': source, 'counts': dict(counts),
            'selection': {'host': host, 'start_epoch_inclusive': start, 'end_epoch_exclusive': end,
                          'max_events': max_events, 'max_tie_events': max_tie_events,
                          'stopped_at_event_limit': truncated, 'first_log_time': first, 'last_log_time': last},
            'hosts': dict(hosts), 'months': dict(months),
            'vocabulary': {k: dict(v.most_common()) for k, v in vocab.items()}, 'examples': examples,
            'policy': {'order': 'timestamp, host, archive, member, file, numeric source line, event ID',
                       'cross_file_order': 'deterministic only; chronology unresolved',
                       'duplicates': 'candidate annotations only; every occurrence retained',
                       'tokens': 'event_type only; attributes not yet approved',
                       'scope': 'audit extract, not session/episode mining input or a fitted model'}}


def markdown(result):
    selection = result['selection']
    lines = ['# Sequential pattern mining: event audit', '', f"Source: **{result['source']}**.", '',
             f"Log times: {selection['first_log_time']} to {selection['last_log_time']}.",
             f"Stopped at event limit: **{selection['stopped_at_event_limit']}**. The final timestamp group is kept whole.", '',
             '| Measure | Count |', '|---|---:|']
    lines += [f'| {k} | {v:,} |' for k, v in sorted(result['counts'].items())]
    lines += ['', '## Interpretation', '',
              'Counts describe the selected source/host/time range only. An earliest-event sample is not representative of a year.',
              'Ordering differences compare source-line order with event-ID order; they do not imply every existing view used event-ID order.',
              'Different files or colliding/missing source positions leave timestamp ties ambiguous. File sorting is not proof of chronology.',
              'Repeated messages are candidates, not proven duplicate physical events. No event was removed.',
              'The optional JSONL contains event-type tokens, original lines and lineage. It is not a session/episode dataset.',
              'No model was fitted, no thresholds selected, and no Phase 2/3 observations or features were changed.', '',
              'See `audit.json` for selection parameters, input identity, vocabulary counts and bounded lineage examples.', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', required=True, choices=SOURCES)
    parser.add_argument('--store', type=Path)
    parser.add_argument('--output', type=Path, help='New output directory; existing directories are never overwritten.')
    parser.add_argument('--host')
    parser.add_argument('--start', type=parse_time, help='Inclusive source-log time, e.g. 2026-01-01.')
    parser.add_argument('--end', type=parse_time, help='Exclusive source-log time.')
    parser.add_argument('--max-events', type=int, default=100000, help='Keep complete timestamp groups; 0 means all selected events.')
    parser.add_argument('--max-tie-events', type=int, default=100000)
    parser.add_argument('--write-stream', action='store_true')
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    if args.max_events < 0 or args.max_tie_events < 1 or (args.start is not None and args.end is not None and args.start >= args.end):
        parser.error('Use nonnegative max-events, positive max-tie-events and start before end.')
    prefix = SOURCES[args.source][0]
    path = (args.store or ROOT/'data'/'phase2_observations'/args.source/f'{prefix}_observation_store.sqlite').resolve()
    if not path.is_file(): parser.error(f'Event store not found: {path}')
    now = datetime.now(timezone(timedelta(hours=8), 'Asia/Singapore'))
    output = args.output or ROOT/'data'/'phase4f_sequences'/args.source/('audit_'+now.strftime('%Y%m%d_%H%M%S_%f'))
    output.mkdir(parents=True, exist_ok=False)
    stream = None
    before = path.stat()
    try:
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA query_only=ON')
            if args.write_stream: stream = (output/'ordered_events.jsonl').open('x', encoding='utf-8')
            result = audit(connection, args.source, host=args.host, start=args.start, end=args.end,
                           max_events=args.max_events, max_tie_events=args.max_tie_events, stream=stream)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError('Input store changed during audit; discard this incomplete run.')
        result['created_at'] = now.isoformat()
        result['input'] = {'path': str(path), 'bytes': before.st_size, 'mtime_ns': before.st_mtime_ns,
                           'identity_note': 'size/mtime metadata, not a full source checksum'}
        if stream: stream.close(); stream = None
        (output/'audit.md').write_text(markdown(result), encoding='utf-8')
        # Completion marker written last. A folder without audit.json is incomplete.
        (output/'audit.json').write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False)+'\n', encoding='utf-8')
        runlog.log(f"Audited {result['counts'].get('events', 0):,} events; output: {output}")
    finally:
        if stream: stream.close()


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
