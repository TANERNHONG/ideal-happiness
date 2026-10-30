import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import review_filters as filters, cluster_index


class FilterRules(unittest.TestCase):
    def test_same_event_and_fields_or_values(self):
        facts = [{'host': 'a', 'username': 'root', 'program': 'sshd'}, {'host': 'a', 'username': 'other', 'program': 'su'}]
        self.assertTrue(filters.matches(facts, {'username': ['root', 'third'], 'program': ['sshd']}))
        self.assertFalse(filters.matches(facts, {'username': ['root'], 'program': ['su']}))

    def test_sql_values_parameterised(self):
        text, args = filters.predicate({'username': ["x' OR 1=1--"]})
        self.assertNotIn('OR 1=1', text)
        self.assertEqual(args, ["x' OR 1=1--"])
        for value in ({'bad': ['x']}, {'host': 'x'}, {'host': [1]}):
            with self.assertRaises(ValueError): filters.parse(value)

    def test_exact_index_uses_all_members_not_top_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp); event_store = folder/'events.sqlite'
            with closing(sqlite3.connect(event_store)) as con, con:
                con.execute('CREATE TABLE events(record_id TEXT PRIMARY KEY,host_id TEXT,username TEXT,process_name TEXT,source_ip TEXT)')
                con.executemany('INSERT INTO events VALUES (?,?,?,?,?)', [('e1','a','root','sshd','1.2.3.4'), ('e2','a','fourth-account','su','1.2.3.5')])
            with patch.object(cluster_index, 'CACHE', folder), patch.object(cluster_index, 'INDEX_FILE', folder/'index.sqlite'), patch.dict(cluster_index.STORES, {'auth': (event_store, 'record_id')}):
                con = cluster_index._connect()
                with con:
                    con.execute("INSERT INTO scores(view_key,row_id,host) VALUES ('auth/authentication_sessions','session','a')")
                    con.executemany("INSERT INTO links VALUES ('auth/authentication_sessions','session',?,?)", [(1,'e1'),(2,'e2')])
                    con.execute("INSERT INTO members (view_key, cluster, row_id, flagged, t) VALUES ('auth/authentication_sessions','group','session',1,'2026-01-01')")
                con.close()
                self.assertEqual(filters.groups('auth', {'username': ['fourth-account']}), {('authentication_sessions','group')})
                self.assertEqual(filters.rows('auth', 'authentication_sessions', {'username': ['root'], 'program': ['su']}), set())
                self.assertEqual(filters.options('auth','username','fourth'), ['fourth-account'])


class FilterTimeLimit(unittest.TestCase):
    """Settings → Review → Filter time limit: a filter is stopped at the limit, wherever it is spending its time."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        folder = Path(self.folder.name)
        self.events = folder/'events.sqlite'
        self.patches = [patch.object(cluster_index, 'CACHE', folder), patch.object(cluster_index, 'INDEX_FILE', folder/'index.sqlite'),
                        patch.dict(cluster_index.STORES, {'auth': (self.events, 'record_id')})]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in self.patches: p.stop()
        self.folder.cleanup()

    def test_a_long_query_is_stopped_at_the_limit(self):
        started = time.monotonic()
        with self.assertRaises(filters.TimedOut) as caught:
            with filters._index(filters.Deadline(0.3)) as con:
                con.execute('WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n) SELECT max(i) FROM n').fetchone()
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn('raise the filter time limit', str(caught.exception))

    def test_waiting_for_another_request_preparing_the_facts_counts(self):
        with closing(sqlite3.connect(self.events)) as con, con:
            con.execute('CREATE TABLE events(record_id TEXT PRIMARY KEY,host_id TEXT,username TEXT,process_name TEXT,source_ip TEXT)')
        with filters._lock:                                  # another request is preparing them
            started = time.monotonic()
            with self.assertRaises(filters.TimedOut) as caught:
                filters.groups('auth', {'username': ['root']}, filters.Deadline(0.3))
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn('Preparing the filters', str(caught.exception))

    def test_preparing_stopped_part_way_keeps_the_facts_as_they_were(self):
        rows = [(f'e{i}', 'a', f'user{i}', 'sshd', '192.0.2.1') for i in range(20_000)]
        with closing(sqlite3.connect(self.events)) as con, con:
            con.execute('CREATE TABLE events(record_id TEXT PRIMARY KEY,host_id TEXT,username TEXT,process_name TEXT,source_ip TEXT)')
            con.executemany('INSERT INTO events VALUES (?,?,?,?,?)', rows)
        filters.ensure('auth', filters.Deadline(60))         # the schema, and facts as of an earlier run
        with closing(cluster_index._connect()) as con, con:
            con.execute("INSERT INTO review_facts VALUES ('auth/individual','earlier','a','kept','sshd','')")
            con.execute("INSERT OR REPLACE INTO review_fact_versions VALUES ('auth','earlier')")
            con.executemany("INSERT INTO scores(view_key,row_id,host) VALUES ('auth/individual',?,'a')", [(r[0],) for r in rows])
        with self.assertRaises(filters.TimedOut):
            filters.ensure('auth', filters.Deadline(0))      # already past: the first large statement is stopped
        with closing(cluster_index._connect()) as con:
            self.assertEqual(con.execute("SELECT stamp FROM review_fact_versions WHERE source='auth'").fetchone()[0], 'earlier')
            self.assertEqual(con.execute("SELECT username FROM review_facts").fetchall(), [('kept',)])
        filters.ensure('auth', filters.Deadline(60))         # with time, it finishes
        self.assertEqual(filters.options('auth', 'username', 'user19999'), ['user19999'])


if __name__ == '__main__': unittest.main()
