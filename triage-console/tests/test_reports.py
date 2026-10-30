"""Report persistence, immutable revisions, conflicts and portable exports; isolated stores only."""
import base64
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import sys
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import reports, store


def document():
    return {'title': 'Case <literal>', 'status': 'open', 'kind': 'anomaly', 'number': '',
            'sections': [{'id': 's1', 'title': 'Evidence', 'subs': [], 'blocks': [
                {'id': 'b1', 'type': 'finding', 'data': {'finding': {'key': 'auth/individual/test#1'}}}]}],
            'print': [{'type': 'heading', 'text': 'Evidence', 'level': 1},
                      {'type': 'p', 'text': 'Literal <script> is evidence, not executable markup.'},
                      {'type': 'table', 'rows': [[{'text': 'server', 'fill': 'fff099'}], [{'text': 'example'}]]}]}


class Reports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        for name, value in [('VAR', self.folder), ('STORE_FILE', self.folder/'store.sqlite')]:
            p = patch.object(store, name, value); p.start(); self.addCleanup(p.stop)

    def test_save_reopen_version_history_and_audit(self):
        doc = document()
        first = reports.save(doc, 'Alice')
        self.assertRegex(first['number'], r'^IR-\d{4}-0001$')
        doc['title'] = 'Revised'; doc['status'] = 'closed'
        second = reports.save(doc, 'Bob', first['id'], 1)
        self.assertEqual(second['version'], 2)
        self.assertEqual(reports.get(first['id'], 1)['document']['title'], 'Case <literal>')
        latest = reports.get(first['id'])
        self.assertEqual(latest['document']['title'], 'Revised')
        self.assertEqual([r['saved_by'] for r in latest['versions']], ['Bob', 'Alice'])
        self.assertEqual(latest['document']['number'], first['number'])
        with closing(reports._connect()) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM audit WHERE action='report_saved'").fetchone()[0], 2)

    def test_stale_save_does_not_overwrite_or_append(self):
        first = reports.save(document(), 'Alice')
        reports.save(document(), 'Bob', first['id'], 1)
        with self.assertRaisesRegex(ValueError, 'newer saved version'):
            reports.save(document(), 'Alice', first['id'], 1)
        self.assertEqual(len(reports.get(first['id'])['versions']), 2)

    def test_closed_cases_remain_editable_and_can_reopen(self):
        doc = document(); doc['status'] = 'closed'
        first = reports.save(doc, 'Alice')
        doc['status'] = 'open'
        reports.save(doc, 'Alice', first['id'], 1)
        self.assertEqual(reports.get(first['id'])['status'], 'open')
        self.assertEqual(reports.get(first['id'], 1)['document']['status'], 'closed')

    def test_numbers_unique_and_user_number_not_trusted(self):
        doc = document(); doc['number'] = 'arbitrary'
        a, b = reports.save(doc, 'A'), reports.save(doc, 'B')
        self.assertNotEqual(a['number'], b['number'])
        self.assertTrue(b['number'].endswith('0002'))

    def test_finding_links_retain_historical_evidence(self):
        first = reports.save(document(), 'A')
        doc = document(); doc['sections'][0]['blocks'] = []
        reports.save(doc, 'A', first['id'], 1)
        self.assertEqual(len(reports.list_reports('auth/individual/test#1')), 1)
        self.assertEqual(reports.list_reports('absent'), [])

    def test_invalid_documents_and_duplicate_ids_rejected(self):
        for invalid in (None, {}, {'status': 'bad'}):
            with self.assertRaises(ValueError): reports.save(invalid, 'A')
        doc = document(); doc['sections'][0]['blocks'][0]['id'] = 's1'
        with self.assertRaises(ValueError): reports.save(doc, 'A')
        doc = document(); doc['sections'][0]['blocks'][0]['type'] = 'javascript'
        with self.assertRaises(ValueError): reports.save(doc, 'A')

    def test_word_export_preserves_text_font_table_and_highlight(self):
        first = reports.save(document(), 'A')
        exported = reports.export(first['id'], 1, 'docx', 'A')
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(exported['content']))) as z:
            xml = z.read('word/document.xml').decode()
            self.assertIn('&lt;script&gt;', xml)
            self.assertIn('fff099', xml)
            self.assertIn('Times New Roman', z.read('word/styles.xml').decode())
            self.assertIn('example', xml)

    def test_export_refuses_external_images_and_unknown_formats(self):
        doc = document(); doc['print'] = [{'type': 'image', 'src': 'http://remote/image.png'}]
        first = reports.save(doc, 'A')
        with self.assertRaises(ValueError): reports.export(first['id'], 1, 'docx', 'A')
        with self.assertRaises(ValueError): reports.export(first['id'], 1, 'rtf', 'A')

    def test_the_ticket_number_links_the_case_to_the_incident_process(self):
        doc = document(); doc['ticket'] = 'INC-0042'
        saved = reports.save(doc, 'Alice')
        self.assertEqual(reports.list_reports()[0]['ticket'], 'INC-0042')
        self.assertEqual(reports.get(saved['id'])['document']['ticket'], 'INC-0042')
        self.assertIn('"ticket": "INC-0042"', store.audit_log(1)[0]['detail'])
        for bad in ('<script>', 'x' * 65, 7):
            doc['ticket'] = bad
            with self.assertRaises(ValueError, msg=bad): reports.save(doc, 'Alice', saved['id'], 1)
        del doc['ticket']
        self.assertEqual(reports.save(doc, 'Alice', saved['id'], 1)['version'], 2)          # no ticket: still fine

    def test_html_export_is_inert_and_escapes_text(self):
        first = reports.save(document(), 'A')
        exported = reports.export(first['id'], 1, 'html', 'A')
        page = base64.b64decode(exported['content']).decode('utf-8')
        self.assertEqual(exported['mime'], 'text/html; charset=utf-8')
        self.assertTrue(exported['filename'].endswith('_v1.html'))
        self.assertIn("default-src 'none'", page)
        self.assertIn('Literal &lt;script&gt; is evidence', page)
        self.assertNotIn('<script', page)
        self.assertIn('example', page)

    def test_html_export_keeps_the_saved_paper_snapshot(self):
        doc = document()
        doc['print_html'] = '<section class="rp-paper"><p onclick="evil()">Analyst comment kept</p><script>alert(1)</script></section>'
        first = reports.save(doc, 'A')
        page = base64.b64decode(reports.export(first['id'], 1, 'html', 'A')['content']).decode('utf-8')
        self.assertIn('Analyst comment kept', page)
        self.assertIn("default-src 'none'", page)
        for forbidden in ('onclick', '<script'):
            self.assertNotIn(forbidden, page)

    def test_missing_report_or_version(self):
        with self.assertRaises(KeyError): reports.get(99)
        first = reports.save(document(), 'A')
        with self.assertRaises(KeyError): reports.get(first['id'], 99)

    def test_print_snapshot_is_inert_and_kept_in_history(self):
        doc = document()
        doc['print_html'] = '<section onclick="evil()"><script>alert(1)</script><iframe src="https://remote"></iframe><img src="https://remote/x"><p>Original evidence</p></section>'
        first = reports.save(doc, 'A')
        saved = reports.get(first['id'])['document']
        self.assertIn('Original evidence', saved['print_html'])
        for forbidden in ('onclick', '<script', '<iframe', 'https://remote'):
            self.assertNotIn(forbidden, saved['print_html'])
        doc['print_html'] = '<p>New evidence</p>'
        reports.save(doc, 'A', first['id'], 1)
        self.assertEqual(reports.get(first['id'], 1)['document']['print_html'], saved['print_html'])

    def test_failed_save_rolls_back_number_version_and_audit(self):
        with patch.object(store, 'audit', side_effect=RuntimeError('failed audit')):
            with self.assertRaises(RuntimeError): reports.save(document(), 'A')
        self.assertEqual(reports.list_reports(), [])
        first = reports.save(document(), 'A')
        self.assertTrue(first['number'].endswith('0001'))
        self.assertEqual(first['version'], 1)


if __name__ == '__main__': unittest.main()
