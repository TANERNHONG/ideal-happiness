"""Small synthetic-store tests; never access production log data."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('sequence_audit', Path(__file__).with_name('audit.py'))
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def connection(rows):
    con = sqlite3.connect(':memory:')
    con.row_factory = sqlite3.Row
    con.execute('CREATE TABLE events(record_id TEXT PRIMARY KEY,timestamp_epoch REAL,timestamp_text TEXT,host_id TEXT,event_type TEXT,source_file TEXT,source_line TEXT,raw_message TEXT,process_name TEXT,pid TEXT,username TEXT,source_ip TEXT)')
    con.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', rows)
    con.commit()
    return con


def row(key, epoch=1, line='1', file='a.log', message='same', host='host-a', kind='LOGIN'):
    return (key,epoch,f'2026-01-01 00:00:{int(epoch):02d}',host,kind,file,line,message,'sshd','10','root','192.0.2.1')


class AuditTests(unittest.TestCase):
    def run_audit(self, rows, **kwargs):
        con = connection(rows)
        try: return audit_module.audit(con,'auth',**kwargs)
        finally: con.close()

    def test_numeric_line_order_instead_of_id_or_string_order(self):
        stream=io.StringIO()
        result=self.run_audit([row('a',line='10'),row('z',line='2')],stream=stream)
        events=[json.loads(s) for s in stream.getvalue().splitlines()]
        self.assertEqual([e['event_id'] for e in events],['z','a'])
        self.assertEqual(result['counts']['ties_reordered_vs_id'],1)
        self.assertFalse(events[0]['timestamp_order_ambiguous'])

    def test_duplicates_are_only_candidates_and_multiplicity_is_preserved(self):
        stream=io.StringIO()
        result=self.run_audit([row('a'),row('b',line='2'),row('c',file='b.log')],stream=stream)
        events=[json.loads(s) for s in stream.getvalue().splitlines()]
        self.assertEqual(len(events),3)
        self.assertEqual(len({e['duplicate_candidate_id'] for e in events}),1)
        self.assertTrue(all(e['timestamp_order_ambiguous'] for e in events))
        self.assertEqual(result['counts']['cross_file_candidate_groups'],1)
        self.assertEqual(result['counts']['within_file_repeat_groups'],1)
        self.assertEqual(result['examples']['cross_file_candidates'][0]['max_occurrences_in_one_file'],2)

    def test_complete_timestamp_group_at_sampling_boundary(self):
        result=self.run_audit([row('a'),row('b'),row('c',epoch=2)],max_events=1)
        self.assertEqual(result['counts']['events'],2)
        self.assertTrue(result['selection']['stopped_at_event_limit'])
        self.assertFalse(self.run_audit([row('a')],max_events=1)['selection']['stopped_at_event_limit'])

    def test_hosts_times_and_distinct_messages_are_not_merged(self):
        result=self.run_audit([row('a'),row('b',host='other'),row('c',epoch=2),row('d',message='other')])
        self.assertEqual(result['counts'].get('repeated_message_groups',0),0)

    def test_bound_parameters_and_half_open_time_selection(self):
        data=[row('a'),row('b',epoch=2),row('c',epoch=3)]
        self.assertEqual(self.run_audit(data,start=2,end=3)['counts']['events'],1)
        self.assertEqual(self.run_audit(data,host="x' OR 1=1--")['counts'].get('events',0),0)

    def test_missing_or_colliding_positions_are_ambiguous(self):
        for rows in ([row('a'),row('b')],[row('a'),row('b',line='bad')]):
            result=self.run_audit(rows)
            self.assertEqual(result['counts']['ambiguous_tie_groups'],1)

    def test_tie_memory_cap_and_missing_host_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError,'max-tie-events'):
            self.run_audit([row('a'),row('b')],max_tie_events=1)
        with self.assertRaisesRegex(ValueError,'host_id'):
            self.run_audit([row('a',host='')])

    def test_ossec_schema_and_archive_provenance(self):
        con=connection([row('a'),row('b')])
        try:
            con.execute('ALTER TABLE events RENAME COLUMN record_id TO event_id')
            con.execute('ALTER TABLE events ADD COLUMN archive_name TEXT')
            con.execute("UPDATE events SET archive_name=event_id")
            result=audit_module.audit(con,'ossec')
            self.assertEqual(result['counts']['cross_file_tie_groups'],1)
        finally: con.close()

    def test_cli_preserves_store_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); path=root/'events.sqlite'; output=root/'audit'
            src=connection([row('a')]); target=sqlite3.connect(path)
            src.backup(target); target.close(); src.close()
            before=hashlib.sha256(path.read_bytes()).hexdigest()
            args=['--source','auth','--store',str(path),'--output',str(output),'--write-stream']
            audit_module.main(args)
            self.assertEqual(before,hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(json.loads((output/'audit.json').read_text())['counts']['events'],1)
            self.assertEqual(len((output/'ordered_events.jsonl').read_text().splitlines()),1)
            with self.assertRaises(FileExistsError): audit_module.main(args)

    def test_source_time_does_not_depend_on_machine_timezone(self):
        self.assertEqual(audit_module.parse_time('1970-01-01'),0)
        with self.assertRaises(ValueError): audit_module.parse_time('2026-01-01T00:00:00+08:00')


if __name__ == '__main__': unittest.main()
