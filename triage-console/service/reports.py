"""Versioned local investigation reports. Saved versions and evidence snapshots are immutable.

Q29/30/32/33: each save appends a version, closing never locks a case, sign-offs
are non-binding, and export never re-runs an evidence query. A sanitised static paper snapshot and its stylesheet are kept for PDF and HTML export.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import re
from contextlib import closing
from datetime import datetime
from html import escape

from . import store
from .config import WEB_DIST

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY, number TEXT UNIQUE NOT NULL, current_version INTEGER NOT NULL,
 title TEXT NOT NULL, status TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL,
 created_by TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS report_versions (
 report_id INTEGER NOT NULL REFERENCES reports(id), version INTEGER NOT NULL,
 saved_at TEXT NOT NULL, saved_by TEXT NOT NULL, document TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(report_id, version));
CREATE TABLE IF NOT EXISTS report_findings (
 report_id INTEGER NOT NULL, version INTEGER NOT NULL, finding_key TEXT NOT NULL,
 PRIMARY KEY(report_id, version, finding_key));
CREATE INDEX IF NOT EXISTS report_finding_key ON report_findings(finding_key);
CREATE TABLE IF NOT EXISTS report_numbers (year INTEGER PRIMARY KEY, last_number INTEGER NOT NULL);
"""
MAX_BYTES = 24 * 1024 * 1024
BLOCKS = {'status', 'ai', 'text', 'target', 'finding', 'lines', 'table', 'metric', 'attack', 'timeline', 'signature', 'map'}


# The organisation's own reference for the case (its incident ticket), which links the two systems
TICKET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/#:-]{0,63}$")


def _connect():
    con = store.connect()
    con.executescript(SCHEMA)
    if "ticket" not in {r["name"] for r in con.execute("PRAGMA table_info(reports)")}:
        con.execute("ALTER TABLE reports ADD COLUMN ticket TEXT NOT NULL DEFAULT ''")     # reports before 2026-10-30
    return con


def validate(document):
    if not isinstance(document, dict) or document.get('status') not in ('open', 'closed'):
        raise ValueError('A report needs an open or closed case status.')
    if document.get('kind', 'anomaly') not in ('anomaly', 'malicious'):
        raise ValueError('Unknown report template.')
    if not isinstance(document.get('title'), str) or len(document['title']) > 500:
        raise ValueError('The report title must be text, at most 500 characters.')
    ticket = document.get('ticket', '')
    if not isinstance(ticket, str) or (ticket and not TICKET.fullmatch(ticket)):
        raise ValueError('A ticket number has up to 64 letters, digits, spaces and . _ / # : - only.')
    ids, count = set(), 0

    def sections(values, depth=0):
        nonlocal count
        if not isinstance(values, list) or depth > 8:
            raise ValueError('Invalid report sections (at most eight levels).')
        for section in values:
            if not isinstance(section, dict) or not isinstance(section.get('title'), str):
                raise ValueError('Each section needs a title.')
            if not isinstance(section.get('blocks'), list) or any(not isinstance(b, dict) for b in section['blocks']):
                raise ValueError('Each section needs a list of blocks.')
            for entry in [section, *section.get('blocks', [])]:
                count += 1
                key = entry.get('id')
                if not isinstance(key, str) or not key or key in ids or count > 1500:
                    raise ValueError('Report IDs must be unique; at most 1,500 sections and blocks.')
                ids.add(key)
            for block in section.get('blocks', []):
                if block.get('type') not in BLOCKS or not isinstance(block.get('data'), dict):
                    raise ValueError('Invalid report block.')
            sections(section.get('subs', []), depth + 1)

    sections(document.get('sections'))
    try:
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError('The report contains invalid values.') from error
    if len(raw.encode('utf-8')) > MAX_BYTES:
        raise ValueError('The report exceeds 24 MB. Split large evidence tables into separate reports.')
    return copy.deepcopy(document)


def _finding_keys(value):
    if isinstance(value, dict):
        finding = value.get('finding')
        if isinstance(finding, dict) and isinstance(finding.get('key'), str):
            yield finding['key'][:500]
        for child in value.values():
            yield from _finding_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _finding_keys(child)


def _paper_html(text):
    """Restrict a static print clone to inert markup and embedded local figures."""
    from lxml import html
    root = html.fragment_fromstring(text, create_parent='div')
    allowed = {'div','span','p','br','hr','b','strong','i','em','small','sup','sub','h1','h2','h3','h4','ol','ul','li','table','thead','tbody','tr','th','td','dl','dt','dd','section','header','footer','aside','label','img','a','figure','figcaption'}
    for el in list(root.iterdescendants()):
        if el.tag not in allowed:
            el.drop_tree(); continue
        for attr in list(el.attrib):
            if attr not in ('class', 'style', 'src', 'alt', 'colspan', 'rowspan'):
                del el.attrib[attr]
        if el.tag == 'img':
            src = el.get('src', '')
            if src == '/brand/smrt-logo.svg':
                logo = WEB_DIST/'brand'/'smrt-logo.svg'
                if logo.exists():
                    el.set('src', 'data:image/svg+xml;base64,'+base64.b64encode(logo.read_bytes()).decode())
            elif not src.startswith('data:image/png;base64,'):
                el.drop_tree()
    return html.tostring(root, encoding='unicode')


def save(document, actor, report_id=None, base_version=0):
    if (report_id is not None and (type(report_id) is not int or report_id < 1)) or type(base_version) is not int or base_version < 0:
        raise ValueError('Invalid report ID or base version.')
    doc = validate(document)
    if doc.get('print_html'):
        doc['print_html'] = _paper_html(str(doc['print_html']))
        doc['print_css'] = '\n'.join(p.read_text(encoding='utf-8') for p in sorted((WEB_DIST/'assets').glob('*.css')))
    with store._lock, closing(_connect()) as con, con:
        con.execute('BEGIN IMMEDIATE')
        at = store.now()
        if report_id is None:
            if base_version != 0:
                raise ValueError('A new report starts at version zero.')
            year = datetime.now().year
            con.execute('INSERT INTO report_numbers VALUES (?,1) ON CONFLICT(year) DO UPDATE SET last_number=last_number+1', (year,))
            n = con.execute('SELECT last_number FROM report_numbers WHERE year=?', (year,)).fetchone()[0]
            number = f'IR-{year}-{n:04d}'
            report_id = con.execute('INSERT INTO reports(number,current_version,title,status,kind,created_at,created_by,updated_at,updated_by,ticket) '
                                    'VALUES (?,0,?,?,?,?,?,?,?,?)', (number, doc['title'], doc['status'], doc.get('kind', 'anomaly'), at, actor, at,
                                                                      actor, doc.get('ticket', ''))).lastrowid
            version = 1
        else:
            row = con.execute('SELECT * FROM reports WHERE id=?', (report_id,)).fetchone()
            if row is None:
                raise KeyError('Report not found.')
            if row['current_version'] != base_version:
                raise ValueError('This report has a newer saved version. Open it before saving; your current draft has not been overwritten.')
            number, version = row['number'], row['current_version'] + 1
        doc['number'] = number
        if doc.get('print_html'):
            from lxml import html
            paper = html.fromstring(doc['print_html'])
            for node in paper.xpath('//*[contains(concat(" ",normalize-space(@class)," ")," rp-mast-info ")]'):
                node.text = f"SMRT OT CONSOLE | REPORT NO. {number} | {doc.get('date', '')}"
            for node in paper.xpath('//label[contains(concat(" ",normalize-space(@class)," ")," rp-field ")]'):
                if len(node) >= 2 and ''.join(node[0].itertext()).strip() == 'Report no.':
                    node[1].text = number
            doc['print_html'] = html.tostring(paper, encoding='unicode')
        raw = json.dumps(doc, ensure_ascii=False, sort_keys=True, allow_nan=False)
        if len(raw.encode('utf-8')) > MAX_BYTES:
            raise ValueError('The report and print snapshot exceed 24 MB.')
        digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        con.execute('INSERT INTO report_versions VALUES (?,?,?,?,?,?)', (report_id, version, at, actor, raw, digest))
        con.executemany('INSERT INTO report_findings VALUES (?,?,?)', [(report_id, version, k) for k in set(_finding_keys(doc))])
        con.execute('UPDATE reports SET current_version=?,title=?,status=?,kind=?,updated_at=?,updated_by=?,ticket=? WHERE id=?',
                    (version, doc['title'], doc['status'], doc.get('kind', 'anomaly'), at, actor, doc.get('ticket', ''), report_id))
        store.audit(con, actor, 'report_saved', f'report/{report_id}/{version}',
                    {'number': number, 'status': doc['status'], 'sha256': digest, 'ticket': doc.get('ticket', '')})
    return {'id': report_id, 'version': version, 'number': number, 'saved_at': at, 'saved_by': actor, 'digest': digest}


def list_reports(finding=''):
    with closing(_connect()) as con:
        where, args = ('', []) if not finding else (' WHERE EXISTS (SELECT 1 FROM report_findings f WHERE f.report_id=r.id AND f.finding_key=?)', [finding])
        return [dict(r) for r in con.execute('SELECT r.* FROM reports r' + where + ' ORDER BY r.updated_at DESC,r.id DESC', args)]


def get(report_id, version=None):
    with closing(_connect()) as con:
        report = con.execute('SELECT * FROM reports WHERE id=?', (report_id,)).fetchone()
        if report is None:
            raise KeyError('Report not found.')
        version = report['current_version'] if version is None else version
        row = con.execute('SELECT * FROM report_versions WHERE report_id=? AND version=?', (report_id, version)).fetchone()
        if row is None:
            raise KeyError('Report version not found.')
        versions = [dict(r) for r in con.execute('SELECT version,saved_at,saved_by,digest FROM report_versions WHERE report_id=? ORDER BY version DESC', (report_id,))]
        return {**dict(report), 'version': version, 'document': json.loads(row['document']), 'versions': versions}


def _print_nodes(doc):
    nodes = doc.get('print', [])
    if not isinstance(nodes, list) or len(nodes) > 12000:
        raise ValueError('Invalid print snapshot.')
    for node in nodes:
        if not isinstance(node, dict) or node.get('type') not in ('p', 'heading', 'table', 'image'):
            raise ValueError('Invalid print element.')
        if node['type'] == 'table':
            rows = node.get('rows', [])
            if not isinstance(rows, list) or len(rows) > 2000 or any(not isinstance(r, list) or len(r) > 100 for r in rows):
                raise ValueError('Invalid print table.')
        if node['type'] == 'image':
            png = str(node.get('src', ''))
            if not png.startswith('data:image/png;base64,'):
                raise ValueError('Only embedded PNG figures can be exported.')
            data = base64.b64decode(png.split(',', 1)[1], validate=True)
            if not data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('Invalid PNG figure.')
        yield node


MIMES = {'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'pdf': 'application/pdf',
         'html': 'text/html; charset=utf-8'}
# An exported HTML file is opened straight from disk: it may run nothing and load nothing (its pictures are embedded).
HTML_POLICY = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'">'


def _page(doc, nodes, title):
    """The report as one HTML page: the saved paper snapshot with that version's styles, or else a plain page
    built from its print nodes."""
    if doc.get('print_html'):
        # Styles belong to this saved version; future CSS changes cannot alter it.
        css = doc.get('print_css', '').replace('</style', '<\\/style')
        return ('<!doctype html><meta charset="utf-8"><style>' + css + '</style><style>body{background:white!important;margin:0}'
                '.rp-paper{width:100%;max-width:none}.rp-paper .rp-body{padding:12px 20px} .rp-mast-logo img{max-width:100%}</style>' + doc['print_html'])
    content = []
    for node in nodes:
        if node['type'] == 'image':
            content.append('<img src="' + node['src'] + '">')
        elif node['type'] == 'table':
            rows = []
            for row in node['rows']:
                cells = []
                for value in row:
                    text = str(value.get('text', '') if isinstance(value, dict) else value)
                    color = value.get('fill', '') if isinstance(value, dict) else ''
                    fill = f'background:#{color}' if len(color) == 6 and all(c in '0123456789abcdefABCDEF' for c in color) else ''
                    cells.append(f'<td style="{fill}">{escape(text)}</td>')
                rows.append('<tr>' + ''.join(cells) + '</tr>')
            content.append('<table>' + ''.join(rows) + '</table>')
        else:
            tag = 'h2' if node['type'] == 'heading' else 'p'
            content.append(f'<{tag}>' + escape(str(node.get('text', ''))) + f'</{tag}>')
    return ('<!doctype html><meta charset="utf-8"><style>body{font:11pt "Times New Roman";color:#172633}header{border-top:4px solid #c72d3c;padding:12px 0}'
            'p,td{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:9pt}td{border:1px solid #aaa;padding:5px}'
            'tr{break-inside:avoid}h2{font-size:14pt;border-bottom:1px solid #172633;break-after:avoid}img{width:100%;break-inside:avoid}</style><header>'
            + escape(title) + '</header>' + ''.join(content))


# The activity log's latest hash at export (store.audit_head): a copy outside the console that pins the log
_ANCHOR_HTML = '<footer style="font:7pt monospace;color:#666;margin-top:24px">{}</footer>'


def export(report_id, version, format, actor):
    if format not in MIMES:
        raise ValueError('Choose Word, PDF or HTML.')
    report = get(report_id, version)
    doc = report['document']
    nodes = list(_print_nodes(doc))
    if not nodes:
        raise ValueError('Open and save this report in the editor to create its print snapshot.')
    title = f"{report['number']} · Version {version}"
    head = store.audit_head()
    anchor = f"Activity log {head['hash'][:16] or 'empty'}" + (f" · {head['at'][:16].replace('T', ' ')}" if head['at'] else '')
    if format == 'docx':
        from docx import Document
        from docx.shared import Inches, Pt
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        output = Document()
        for style in output.styles:
            if hasattr(style, 'font'):
                style.font.name = 'Times New Roman'
        output.styles['Normal'].font.size = Pt(11)
        section = output.sections[0]
        section.page_width, section.page_height = Inches(8.27), Inches(11.69)
        section.left_margin = section.right_margin = Inches(.55)
        section.header.paragraphs[0].text = title
        section.footer.paragraphs[0].text = anchor
        for node in nodes:
            kind = node['type']
            if kind == 'heading':
                output.add_heading(str(node.get('text', '')), level=min(3, max(0, int(node.get('level', 1)))))
            elif kind == 'p':
                output.add_paragraph(str(node.get('text', '')))
            elif kind == 'image':
                output.add_picture(io.BytesIO(base64.b64decode(node['src'].split(',', 1)[1])), width=Inches(7))
            elif node.get('rows'):
                table = output.add_table(rows=0, cols=max(map(len, node['rows'])))
                table.style = 'Table Grid'
                for row in node['rows']:
                    for cell, value in zip(table.add_row().cells, row):
                        cell.text = str(value.get('text', '') if isinstance(value, dict) else value)
                        color = value.get('fill', '') if isinstance(value, dict) else ''
                        if len(color) == 6 and all(c in '0123456789abcdefABCDEF' for c in color):
                            shading = OxmlElement('w:shd'); shading.set(qn('w:fill'), color)
                            cell._tc.get_or_add_tcPr().append(shading)
        buf = io.BytesIO(); output.save(buf); data = buf.getvalue()
    elif format == 'html':
        page = _page(doc, nodes, title) + _ANCHOR_HTML.format(escape(anchor))
        data = page.replace('<meta charset="utf-8">', '<meta charset="utf-8">' + HTML_POLICY + '<title>' + escape(title) + '</title>', 1).encode('utf-8')
    else:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(channel='msedge', headless=True)
            try:
                page = browser.new_page(java_script_enabled=False)
                page.route('**/*', lambda route: route.abort())
                page.set_content(_page(doc, nodes, title), wait_until='load')
                data = page.pdf(format='A4', print_background=True, margin={'top': '12mm', 'bottom': '14mm', 'left': '12mm', 'right': '12mm'},
                                display_header_footer=True, header_template='<span></span>',
                                footer_template=f'<div style="font:7pt monospace;color:#666;width:100%;padding:0 12mm">{escape(anchor)}</div>')
            finally:
                browser.close()
    with store._lock, closing(_connect()) as con, con:
        store.audit(con, actor, 'report_exported', f'report/{report_id}/{version}', {'format': format, 'bytes': len(data)})
    return {'filename': f"{report['number']}_v{version}.{format}", 'content': base64.b64encode(data).decode(), 'mime': MIMES[format]}
