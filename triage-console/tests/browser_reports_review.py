r"""Real Edge integration check with an isolated console store and the existing read-only dataset.

Run from triage-console: ..\.venv\Scripts\python.exe tests/browser_reports_review.py
Screenshots and downloaded exports go to var/checks/reports-review. User settings,
reviews, uploads, report numbering and case records are never changed by this check.
"""
import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import config
from playwright.sync_api import sync_playwright

API = {'X-Console-Request': '1'}   # as the app's own requests carry it (web/src/api.ts)


def run():
    artifacts = config.VAR/'checks'/'reports-review'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='huh-browser-') as tmp:
        config.VAR = Path(tmp)
        config.STORE_FILE = config.VAR/'console.sqlite3'
        config.SETTINGS_FILE = config.VAR/'settings.json'
        config.PORT = 8766
        config.save_settings({'console_mode': 'advanced', 'animations': 'none', 'display_name': 'Browser verifier'})
        from service import server, cluster_index, scoring, store
        app = ThreadingHTTPServer(('127.0.0.1', 8766), server.Handler)
        thread = threading.Thread(target=app.serve_forever, daemon=True); thread.start()
        cluster_index.start_background()
        errors = []
        with sync_playwright() as p:
            browser = p.chromium.launch(channel='msedge', headless=True)
            context = browser.new_context(viewport={'width': 1440, 'height': 1000}, accept_downloads=True)
            page = context.new_page(); page.on('pageerror', lambda e: errors.append(str(e)))
            page.on('dialog', lambda d: d.accept('123456') if d.type == 'prompt' else d.accept())
            try:
                page.goto('http://127.0.0.1:8766/#/reports')
                page.get_by_label('Report title', exact=True).fill('Integration investigation')
                page.locator('.rp-chip').filter(has_text='Text').first.focus()
                page.keyboard.press('Enter')
                page.get_by_role('textbox', name='').count()
                page.locator('.rp-text').last.fill('Evidence remains literal: <script>alert(1)</script>.')
                page.locator('.rp-chip').filter(has_text='Timeline').first.focus()
                page.keyboard.press('Enter')
                page.get_by_role('button', name='Add analyst event', exact=True).click()
                page.get_by_label('Timeline time', exact=True).fill('2026-10-07 12:00:00')
                page.get_by_label('Timeline event', exact=True).fill('Analyst verified the source logs')
                page.get_by_label('Timeline note', exact=True).fill('Manual event, retained with the report')
                page.get_by_label('Name', exact=True).first.fill('Browser verifier')
                page.get_by_role('button', name='Sign', exact=True).first.click()
                assert page.locator('.rp-sign-line').first.inner_text() == 'Browser verifier'
                page.get_by_label('Name', exact=True).first.fill('Revised verifier')
                assert page.locator('.rp-sign-line').first.inner_text() == ''
                page.get_by_role('button', name='Sign', exact=True).first.click()
                page.get_by_role('checkbox', name='CLOSED', exact=True).click()
                page.get_by_role('button', name='Save version', exact=True).click()
                page.get_by_role('status').filter(has_text='v1 saved').wait_for()
                number = page.get_by_label('Report no.', exact=True).input_value()
                page.get_by_label('Report title', exact=True).fill('Revised investigation')
                page.get_by_role('button', name='Save version', exact=True).click()
                page.get_by_role('status').filter(has_text='v2 saved').wait_for()
                page.reload()
                page.get_by_label('Report title', exact=True).wait_for()
                assert page.get_by_label('Report title', exact=True).input_value() == 'Revised investigation'
                assert page.get_by_label('Timeline event', exact=True).inner_text() == 'Analyst verified the source logs'
                assert page.locator('.rp-sign-line').first.inner_text() == 'Revised verifier'
                assert page.get_by_role('checkbox', name='CLOSED', exact=True).get_attribute('aria-checked') == 'true'
                page.get_by_label('Report version', exact=True).select_option('1')
                page.wait_for_function("document.querySelector('.rp-doc-title')?.value === 'Integration investigation'")
                page.get_by_role('button', name='Save version', exact=True).click()
                page.get_by_role('status').filter(has_text='v3 saved').wait_for()
                page.get_by_role('button', name='Preview', exact=True).click()
                assert page.get_by_role('dialog').is_visible()
                page.get_by_role('button', name='Close preview', exact=True).click()
                for format in ('docx', 'pdf'):
                    page.get_by_label('Export format').select_option(format)
                    with page.expect_download(timeout=120000) as event:
                        page.get_by_role('button', name='Export', exact=True).click()
                    event.value.save_as(artifacts / f'integration.{format}')
                page.screenshot(path=str(artifacts/'reports.png'), full_page=True)
                print('PASS report lifecycle, editable closure, timeline, sign-off invalidation, preview/Word/PDF', flush=True)
                page.goto('http://127.0.0.1:8766/#/review')
                page.get_by_label('Filter by account').fill('root')
                page.get_by_role('button', name='Add account filter', exact=True).click()
                page.get_by_role('button', name='Account: root', exact=True).wait_for()
                page.locator('.verdict-buttons').first.wait_for(timeout=180000)
                calls = []
                def slow_review(route):
                    calls.append(1); time.sleep(.5); route.continue_()
                page.route('**/api/review', slow_review)
                page.get_by_role('button', name='Expected behaviour', exact=True).evaluate('(el) => {el.click();el.click();}')
                page.wait_for_timeout(1500)
                assert len(calls) == 1, calls
                page.screenshot(path=str(artifacts/'review.png'), full_page=True)
                print('PASS exact Review filter and duplicate-submit guard', flush=True)
                page.set_viewport_size({'width':1280,'height':900})
                page.goto('http://127.0.0.1:8766/#/reports/1')
                page.get_by_label('Report title', exact=True).wait_for()
                page.screenshot(path=str(artifacts/'reports-1280.png'), full_page=True)
                # Exercise the actual saved-vector placement for an unmapped OSSEC observation; once data/ is purged
                # (frozen runtime) the feature rows are gone, so a mapped observation and its saved point instead.
                vectors = (config.DATA/'phase3_features'/'ossec'/'episodes'/'test_rows.csv').exists()
                table = scoring.map_table('ossec', 'episodes')
                deadline = time.time()+120
                while cluster_index.scores_status('ossec','episodes') != 'ready' and time.time()<deadline:
                    time.sleep(.2)
                con = cluster_index._connect()
                candidates = [r[0] for r in con.execute("SELECT row_id FROM scores WHERE view_key='ossec/episodes'")]
                con.close()
                target = next((x for x in candidates if (x not in table.index) == vectors), candidates[0])
                result = context.request.post('http://127.0.0.1:8766/api/reports/map', data={'source':'ossec','view':'episodes','ids':[target]}, headers=API)
                assert result.ok, result.text()
                job = result.json()['job']; deadline = time.time()+180
                while time.time()<deadline:
                    r = context.request.get('http://127.0.0.1:8766/api/analyze/job?id='+job, headers=API).json()
                    if r['status'] != 'running': break
                    time.sleep(.5)
                assert r['status'] == 'done', r
                assert r['result']['targets'][0]['placement'] != 'unavailable', r
                print('PASS real report map: '+r['result']['targets'][0]['placement'], flush=True)
                # Exercise rendering/persistence/export of the real map response, without a second large data job.
                saved = context.request.get('http://127.0.0.1:8766/api/reports/item?id=1', headers=API).json()
                doc = saved['document']
                doc['sections'][0]['blocks'].append({'id':'map-browser-check', 'type':'map', 'data':{'map':r['result'],'retrieved':time.strftime('%Y-%m-%d %H:%M')}})
                response = context.request.post('http://127.0.0.1:8766/api/reports/save', data={'id':1,'base_version':saved['current_version'],'document':doc}, headers=API)
                assert response.ok, response.text()
                page.reload()
                page.locator('canvas.rp-map-image').wait_for()
                page.get_by_role('button', name='Save version', exact=True).click()
                page.get_by_role('status').filter(has_text='v5 saved').wait_for()
                page.get_by_role('button', name='Preview', exact=True).click()
                assert page.get_by_role('dialog').locator('img.rp-map-image').count() == 1
                page.get_by_role('button', name='Close preview', exact=True).click()
                for format in ('docx','pdf'):
                    page.get_by_label('Export format').select_option(format)
                    with page.expect_download(timeout=120000) as event:
                        page.get_by_role('button', name='Export', exact=True).click()
                    event.value.save_as(artifacts/f'map-report.{format}')
                page.locator('canvas.rp-map-image').screenshot(path=str(artifacts/'target-map.png'))
                page.get_by_label('New report template').select_option('malicious')
                page.get_by_role('button', name='New report', exact=True).click()
                page.get_by_text('Malicious-activity report', exact=True).wait_for()
                assert page.locator('.rp-sec-title').evaluate_all("els => els.some(e => e.value === 'Containment and Eradication')")
                print('PASS map rendering/preview/exports and malicious-activity template', flush=True)
                from service import uploads
                from test_uploads import fake_result, events
                fixture = fake_result()
                items = uploads._items(fixture)
                for item in items:
                    item['context'] = uploads._context(item, events())
                    # Use the Solaris AUTH format understood by the actual Phase 1 parser.
                    for line in item['context']:
                        if line['own']:
                            line['line'] = 'Jul 14 16:20:37 host-a sshd[12]: [ID 800047 auth.info] Invalid user staff08 from 192.0.2.17 port 22'
                uploads._pending['browser-fixture'] = {'at':time.time(), 'name':'Filter integration upload', 'result':fixture, 'items':items}
                upload_id = uploads.keep('browser-fixture', 'Browser verifier')
                assert uploads.get_upload(upload_id)['items'][0]['facts'][0]['username'] == 'staff08'
                page.goto('http://127.0.0.1:8766/#/uploads')
                page.get_by_label('Filter by account').wait_for()
                if page.get_by_role('button', name='Clear filters', exact=True).count():
                    page.get_by_role('button', name='Clear filters', exact=True).click()
                page.get_by_label('Filter by account').fill('staff08')
                page.get_by_role('button', name='Add account filter', exact=True).click()
                page.locator('.upload-row').filter(has_text='Filter integration upload').click()
                page.locator('.upload-toolbar .up-progress').wait_for()
                assert page.locator('.upload-toolbar .up-progress').get_attribute('title') == '0 of 1 reviewed'
                page.get_by_label('Filter by program').fill('missing-program')
                page.get_by_role('button', name='Add program filter', exact=True).click()
                page.get_by_text('No events match the current filters.', exact=True).wait_for()
                page.get_by_role('button', name='Clear filters', exact=True).click()
                page.get_by_role('button', name='Clear upload', exact=True).click()
                page.wait_for_url('**/#/uploads')
                assert all(u['id'] != upload_id for u in context.request.get('http://127.0.0.1:8766/api/uploads', headers=API).json()['uploads'])
                page.wait_for_load_state('networkidle')
                print('PASS Simple Review filters, matching counts and password-protected clearing', flush=True)
                assert not errors, errors
                print('PASS no browser page errors', flush=True)
            finally:
                context.close(); browser.close(); app.shutdown(); app.server_close(); thread.join()


if __name__ == '__main__': run()
