"""Convert the preserved LaTeX appendix to editable Typst with native diagrams.

Requires pypandoc_binary. Run after installing it with Python; the output uses
the adjacent typst-style.typ file and existing figures/ directory.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / 'whitepaper'


def braced(text: str, start: int):
    while start < len(text) and text[start].isspace():
        start += 1
    if start >= len(text) or text[start] != '{':
        raise ValueError(f'Expected argument near {text[start:start + 80]!r}')
    depth, index = 1, start + 1
    while depth:
        if index >= len(text):
            raise ValueError('Unclosed LaTeX argument')
        if text[index] == '\\':
            index += 2
            continue
        depth += (text[index] == '{') - (text[index] == '}')
        index += 1
    return text[start + 1:index - 1], index


def replace_macro(text, name, nargs, callback):
    pattern = re.compile(r'\\' + re.escape(name) + r'(?![A-Za-z])')
    output, cursor = [], 0
    for match in pattern.finditer(text):
        if match.start() < cursor:
            continue
        values, end = [], match.end()
        for _ in range(nargs):
            value, end = braced(text, end)
            values.append(value)
        output.append(text[cursor:match.start()])
        output.append(callback(*values))
        cursor = end
    return ''.join(output) + text[cursor:]


def convert():
    import pypandoc

    source = (PAPER / 'TECHNICAL_WHITEPAPER_APPENDICES.tex').read_text(encoding='utf-8')
    # Retain parser macro definitions, but start the content after the original cover.
    preamble = r'\documentclass{article}'
    body = source[source.index(r'\section{Project Evidence Register}'):]
    body = body.replace(r'\end{document}', '')
    body = body.replace(r'\renewcommand{\section}[2]{}', '')
    body = body.replace(r'\begingroup', '').replace(r'\endgroup', '')
    # A heading can carry only one Typst label. Use one canonical guide label.
    body = body.replace(r'\ref{sec:guide}', r'\ref{app:user-guide}').replace(r'\label{sec:guide}', '')
    # This label followed a historical-note paragraph in the LaTeX source.
    body = body.replace(r'\label{app:changes}', '')
    body = body.replace(r'\section{Changes from the Starting Draft}', r'\section{Changes from the Starting Draft}\label{app:changes}')
    # Typst repeats table.header itself; discard LaTeX continuation headers/footers.
    body = re.sub(r'\\endfirsthead.*?\\endlastfoot', '', body, flags=re.S)
    table_widths = []
    table_pattern = re.compile(r'\\begin\{(?:longtable|tabular)\}')
    offsets = []
    for match in table_pattern.finditer(body):
        spec, end = braced(body, match.end())
        widths = re.findall(r'(0\.\d+)(?=\\linewidth)', spec)
        count = len(widths) or len(re.findall(r'[lcr]', spec))
        if not count:
            raise ValueError(f'Cannot determine table columns: {spec}')
        table_widths.append(widths or ['1'] * count)
        offsets.append((match.end(), end, '{' + 'l' * count + '}'))
    for start, end, replacement in reversed(offsets):
        body = body[:start] + replacement + body[end:]
    body = replace_macro(body, 'multicolumn', 3, lambda count, alignment, content:
                         content + ' & ' * (int(count) - 1))

    literals = {}
    def literal(value):
        detokenized = value.startswith(r'\detokenize')
        if detokenized:
            value, _ = braced(value, len(r'\detokenize'))
        value = value.replace(r'\allowbreak{}', '')
        for escaped, plain in [(r'\textquotedbl{}', '"'), (r'\textquotesingle{}', "'"),
                               (r'\textbackslash{}', '\\'), (r'\textasciicircum{}', '^'),
                               (r'\textasciitilde{}', '~')]:
            value = value.replace(escaped, plain)
        if not detokenized:
            value = value.replace('{}', '')
        for escaped, plain in [(r'\_', '_'), (r'\%', '%'), (r'\&', '&'), (r'\#', '#'),
                               (r'\$', '$'), (r'\{', '{'), (r'\}', '}'),
                               (r'\textbackslash{}', '\\'), (r'\textasciicircum{}', '^')]:
            value = value.replace(escaped, plain)
        marker = f'LITERALX{len(literals):06d}X'
        literals[marker] = value
        return marker

    def href(url, title):
        if url.startswith(r'\detokenize'):
            url, _ = braced(url, len(r'\detokenize'))
        return r'\href{' + url + '}{' + title + '}'
    body = replace_macro(body, 'href', 2, href)
    body = replace_macro(body, 'projectref', 2, lambda title, path: title + ' (' + literal(path) + ')')
    for macro in ['tok', 'nolinkurl', 'texttt']:
        body = replace_macro(body, macro, 1, literal)
    body = replace_macro(body, 'screenshot', 4, lambda filename, width, caption, label:
                         '\n\\begin{figure}\n\\includegraphics[width=' + width + '\\linewidth]{figures/' + filename + '}\n'
                         + '\\caption{' + caption + '}\\label{' + label + '}\n\\end{figure}\n')
    body = replace_macro(body, 'cite', 1, lambda keys: '[' + ', '.join(re.sub(r'^ref', '', k.strip()) for k in keys.split(',')) + ']')

    bibliography_pattern = re.compile(r'\\begin\{thebibliography\}\{[^}]+\}(.*?)\\end\{thebibliography\}', re.S)
    def convert_bibliography(match):
        entries = re.findall(r'\\bibitem\{([^}]+)\}(.*?)(?=\\bibitem|$)', match.group(1), re.S)
        return '\\begin{enumerate}\n' + '\n'.join('\\item ' + text.strip() for _, text in entries) + '\n\\end{enumerate}'
    body = bibliography_pattern.sub(convert_bibliography, body)

    diagrams = {}
    def replace_diagram(match):
        text = match.group()
        if r'\begin{tikzpicture}' not in text:
            return text
        label = re.search(r'\\label\{([^}]+)\}', text).group(1)
        caption_match = re.search(r'\\caption', text)
        caption, _ = braced(text, caption_match.end())
        marker = 'NATIVE-DIAGRAM-' + str(len(diagrams) + 1)
        diagrams[marker] = (label, caption)
        return '\n\n' + marker + '\n\n'
    body = re.sub(r'\\begin\{figure\}(?:\[[^]]*\])?.*?\\end\{figure\}', replace_diagram, body, flags=re.S)
    latex = preamble + '\n\\begin{document}\n' + body + '\n\\end{document}\n'
    typst = pypandoc.convert_text(latex, to='typst', format='latex', extra_args=['--wrap=none'])
    typst = typst.replace(' sect ', ' inter ')
    # Restore exact literal values as Typst strings instead of relying on TeX macro expansion.
    for marker, value in literals.items():
        typst = typst.replace(marker, '#tok(' + json.dumps(value, ensure_ascii=False) + ')')
    native_columns = list(re.finditer(r'columns: \d+,', typst))
    if len(native_columns) != len(table_widths):
        raise ValueError(f'Table count changed: {len(native_columns)} vs {len(table_widths)}')
    for match, widths in reversed(list(zip(native_columns, table_widths))):
        typst = typst[:match.start()] + 'columns: (' + ', '.join(w + 'fr' for w in widths) + '),' + typst[match.end():]
    typst = re.sub(r'\)\s*\]\s*<(tab:[^>]+)>', lambda m: ') <' + m[1] + '>\n]', typst)
    typst = re.sub(r'(Section|Figure|Table|Equation|Appendix)~@([\w:.-]*[\w:-])',
                   lambda m: m[1] + '~#ref(<' + m[2] + '>, supplement: none)', typst)

    diagram_content = {
        'fig:novelty-reference': '''grid(columns: (1fr, 1fr), gutter: 8pt,
  stepbox([*Fixed training reference*\\ Common: #tok("backup")\\ Absent feature: #tok("maint1")]),
  stepbox([*Later observations*\\ #tok("maint1") appears 100 times\\ Each uses the same reference]),
)''',
        'fig:architecture': '''stack(dir: ttb, spacing: 4pt,
  stepbox([Source log archives → parsing and retained lineage]),
  stepbox([Events, windows, sessions and daily observations]),
  stepbox([Features and temporal splits · ordered streams · coverage/presence checks]),
  stepbox([Complementary models · routines and transition scoring]),
  stepbox([Alerts linked to evidence → maps, SQL and investigation]),
  stepbox([Human review → versioned reports and exports]),
  stepbox([*Integration still required:* manual parser-rule adoption; approved production rules and future learning labels]),
)''',
        'fig:whitelist-flow': '''stack(dir: ttb, spacing: 7pt,
  stepbox([*Statistically flagged observation*\\ Score and finding retained]),
  stepbox([At least one named account, and every named account actively covered on its server?]),
  grid(columns: (1fr, 1fr), gutter: 10pt,
    stepbox([*Yes → Whitelisted*\\ No outstanding attention request]),
    stepbox([*No → Needs review*\\ Human interpretation required]),
  ),
)''',
    }
    for marker, (label, caption) in diagrams.items():
        caption_typst = pypandoc.convert_text(caption, to='typst', format='latex', extra_args=['--wrap=none']).strip()
        native = '#figure(\n  ' + diagram_content[label] + ',\n  caption: [' + caption_typst + '],\n) <' + label + '>'
        typst = typst.replace(marker, native)
    # All main appendix chapters retain their requested page breaks.
    typst = re.sub(r'(?m)^= ', '#pagebreak(weak: true)\n= ', typst)
    intro = '''// Native Typst companion converted from the preserved LaTeX content.
// All detailed tables, equations, screenshots and reference catalogues are retained.
#import "typst-style.typ": *
#show: whitepaper.with(appendix: true)
#cover(appendix: true)
#outline(title: [Contents], depth: 2)
#pagebreak()
'''
    (PAPER / 'TECHNICAL_WHITEPAPER_APPENDICES.typ').write_text(intro + typst, encoding='utf-8')
    print('Converted appendix:', len(typst), 'characters;', len(diagrams), 'native diagrams')


if __name__ == '__main__':
    convert()
