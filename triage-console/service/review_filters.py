"""Exact, multi-value Review filters, derived from original events rather than top-three summaries.

The separate facts table preserves all account/program combinations in a window.
Values within a field are ORed; fields are ANDed on the same underlying event.
The cache stamp follows the score and validation indexes and source event store.
A filter is stopped once it has run for Settings → Review's time limit (Deadline), including
preparing the facts table and waiting for another request that is preparing it.
"""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import activity, analyze, cluster_index, config

FIELDS = ('host', 'username', 'program', 'address')
_lock = threading.Lock()


class TimedOut(ValueError):
    """A Review filter ran past its time limit and was stopped."""


class Deadline:
    """When a filter must stop: Settings' review_filter_seconds from now. SQLite checks it while a statement runs
    (a progress handler interrupts it, and lock waits end with it); loops in Python check it between items."""

    def __init__(self, seconds=None):
        self.seconds = float(config.load_settings()['review_filter_seconds'] if seconds is None else seconds)
        self.until = time.monotonic() + self.seconds

    def left(self):
        return self.until - time.monotonic()

    def check(self, preparing=False):
        if self.left() <= 0:
            raise TimedOut(self.message(preparing))

    def message(self, preparing=False):
        if preparing:
            return (f'Preparing the filters took longer than {self.seconds:.0f} seconds and was stopped. They are prepared '
                    'once after the data changes: raise the filter time limit in Settings → Review and try again.')
        return (f'The filter took longer than {self.seconds:.0f} seconds and was stopped. '
                'Use fewer values, or raise the filter time limit in Settings → Review.')


@contextmanager
def _index(deadline, preparing=False):
    """The cluster index, its statements interrupted once the deadline passes."""
    con = cluster_index._connect()
    try:
        con.set_progress_handler(lambda: 1 if deadline.left() <= 0 else 0, 10_000)
        con.execute(f'PRAGMA busy_timeout = {max(0, int(deadline.left() * 1000))}')   # a lock wait ends with it too
        yield con
    except sqlite3.OperationalError as error:
        if deadline.left() <= 0 and ('interrupted' in str(error) or 'locked' in str(error)):
            raise TimedOut(deadline.message(preparing)) from None
        raise
    finally:
        con.close()
SCHEMA = """
CREATE TABLE IF NOT EXISTS review_facts(view_key TEXT,row_id TEXT,host TEXT,username TEXT,program TEXT,address TEXT,
 PRIMARY KEY(view_key,row_id,host,username,program,address)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS review_facts_host ON review_facts(host,view_key,row_id);
CREATE INDEX IF NOT EXISTS review_facts_user ON review_facts(username,view_key,row_id);
CREATE INDEX IF NOT EXISTS review_facts_program ON review_facts(program,view_key,row_id);
CREATE INDEX IF NOT EXISTS review_facts_address ON review_facts(address,view_key,row_id);
CREATE TABLE IF NOT EXISTS review_fact_versions(source TEXT PRIMARY KEY, stamp TEXT);
CREATE INDEX IF NOT EXISTS review_flagged_members ON members(view_key,row_id,cluster) WHERE flagged=1;
"""


def parse(value=None):
    if isinstance(value, str):
        value = json.loads(value)
    if value is None:
        return {}
    if not isinstance(value, dict) or any(k not in FIELDS for k in value):
        raise ValueError('Unknown Review filter.')
    out = {}
    for field, values in value.items():
        if not isinstance(values, list) or len(values) > 30 or any(not isinstance(v, str) or len(v) > 160 for v in values):
            raise ValueError('Choose up to 30 values per Review filter, at most 160 characters each.')
        if values:
            out[field] = list(dict.fromkeys(values))
    return out


def predicate(filters, alias='f'):
    clauses, params = [], []
    for field, values in parse(filters).items():
        clauses.append(f"{alias}.{field} IN ({','.join('?' for _ in values)})")
        params.extend(values)
    return ' AND '.join(clauses) or '1=1', params


def ensure(source, deadline=None):
    if source not in cluster_index.STORES:
        return
    deadline = deadline or Deadline()
    path, event_key = cluster_index.STORES[source]
    if not _lock.acquire(timeout=max(0, deadline.left())):     # another request is preparing the facts
        raise TimedOut(deadline.message(preparing=True))
    try:
        _prepare(source, path, event_key, deadline)
    finally:
        _lock.release()


def _prepare(source, path, event_key, deadline):
    """Build the source's facts table, unless it is current. Stopped part-way, it is rolled back whole."""
    with _index(deadline, preparing=True) as con:
        con.executescript(SCHEMA)
        if not path.exists():                            # the logs were purged: the facts stay as last indexed
            return
        stamps = [list(r) for r in con.execute('SELECT view_key,stamp FROM score_views WHERE view_key LIKE ? UNION ALL SELECT view_key,stamp FROM val_views WHERE view_key LIKE ?', (source+'/%', source+'/%'))]
        stamp = json.dumps([2, sorted(stamps), path.stat().st_size, path.stat().st_mtime_ns])
        old = con.execute('SELECT stamp FROM review_fact_versions WHERE source=?', (source,)).fetchone()
        if old and old[0] == stamp:
            return
        con.execute('ATTACH DATABASE ? AS fact_source', (f'file:{path.as_posix()}?mode=ro',))
        columns = {r[1] for r in con.execute('PRAGMA fact_source.table_info(events)')}
        field = lambda key: f"COALESCE(e.{key},'')" if key in columns else "''"
        values = ','.join(field(k) for k in ('host_id', 'username', 'process_name', 'source_ip'))
        with con:
            con.execute('DELETE FROM review_facts WHERE view_key LIKE ?', (source+'/%',))
            con.execute(f'INSERT OR IGNORE INTO review_facts SELECT s.view_key,s.row_id,{values} FROM scores s JOIN fact_source.events e ON e.{event_key}=s.row_id WHERE s.view_key=?', (source+'/individual',))
            con.execute(f'INSERT OR IGNORE INTO review_facts SELECT s.view_key,s.row_id,{values} FROM scores s CROSS JOIN links l ON l.view_key=s.view_key AND l.row_id=s.row_id JOIN fact_source.events e ON e.{event_key}=l.record_id WHERE s.view_key LIKE ? AND s.view_key<>?', (source+'/%', source+'/individual'))
            con.execute('INSERT OR REPLACE INTO review_fact_versions VALUES (?,?)', (source, stamp))


def groups(source, filters, deadline=None):
    deadline = deadline or Deadline()
    ensure(source, deadline)
    clause, args = predicate(filters)
    with _index(deadline) as con:
        return {(r[0].split('/', 1)[1], r[1]) for r in con.execute(
            f'SELECT DISTINCT m.view_key,m.cluster FROM review_facts f CROSS JOIN members m ON f.view_key=m.view_key AND f.row_id=m.row_id WHERE (m.flagged=1 OR m.sigma=1) AND f.view_key LIKE ? AND {clause}', [source+'/%', *args])}


def rows(source, view, filters, deadline=None):
    deadline = deadline or Deadline()
    ensure(source, deadline)
    clause, args = predicate(filters)
    with _index(deadline) as con:
        return {r[0] for r in con.execute(f'SELECT DISTINCT f.row_id FROM review_facts f WHERE f.view_key=? AND {clause}', [source+'/'+view, *args])}


def facts_for_lines(source, lines, month='', host=''):
    facts = []
    for _, event, _ in analyze._parse(source, lines, month):
        facts.append({'host': event.get('host') or event.get('hostname') or host,
                      'username': event.get('username') or '', 'program': event.get('process_name') or event.get('program') or '',
                      'address': event.get('source_ip') or event.get('src_ip') or ''})
        destination = event.get('destination_ip') or event.get('dst_ip')
        if destination:
            facts.append({**facts[-1], 'address': destination})
    return facts


def matches(facts, filters):
    return any(all(str(f.get(key) or '') in values for key, values in filters.items()) for f in facts)


def upload_facts(upload, item):
    return facts_for_lines(upload['source'], [x['line'] for x in item.get('context', []) if x.get('own')], upload.get('month', ''), item.get('host', ''))


def options(source, field, search='', deadline=None):
    if field not in FIELDS:
        raise ValueError('Unknown Review filter.')
    deadline = deadline or Deadline()
    if source not in cluster_index.STORES:
        from . import clusters, review_context
        facts = []
        for item in clusters.review_queue(source):
            deadline.check()
            rid = str(item.get('row_manifest_ids', '')).split(';')[0].split(':')[-1].strip()
            obs = review_context._presence(source, rid)
            for address in (obs['facts'].get('source_ip', ''), obs['facts'].get('destination_ip', '')):
                facts.append({'host': obs['server'], 'username': '', 'program': '', 'address': address})
        return sorted({f[field] for f in facts if f[field] and search.casefold() in f[field].casefold()})[:100]
    ensure(source, deadline)
    with _index(deadline) as con:
        return [r[0] for r in con.execute(f"SELECT DISTINCT {field} FROM review_facts WHERE view_key LIKE ? AND {field}<>'' AND instr(lower({field}),lower(?))>0 ORDER BY {field} LIMIT 100", (source+'/%', search[:160]))]


def filter_queue(source, items, filters, deadline=None):
    filters = parse(filters)
    if not filters:
        return items
    deadline = deadline or Deadline()
    if source in cluster_index.STORES:
        grouped = any(item.get('kind') != 'activity_alert' for item in items)
        kept = groups(source, filters, deadline) if grouped else set()
        # Phase 4g activity alerts are about one entity: kept when that entity satisfies every filter.
        return [item for item in items if (activity.matches(item, filters) if item.get('kind') == 'activity_alert'
                                           else (item['view'], item['item_id']) in kept)]
    from . import review_context
    # Flow metadata covers all packets, including ones outside the 40-line preview.
    out = []
    for item in items:
        deadline.check()
        rid = str(item.get('row_manifest_ids', '')).split(';')[0].split(':')[-1].strip()
        obs = review_context._presence(source, rid)
        if filters.get('host') and obs['server'] not in filters['host']:
            continue
        if any(k in filters for k in ('username', 'program')):
            continue  # firewall packets have neither an account nor a process
        if filters.get('address') and not set(filters['address']).intersection([obs['facts'].get('source_ip'), obs['facts'].get('destination_ip')]):
            continue
        out.append(item)
    return out
