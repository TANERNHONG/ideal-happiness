"""Compile the native whitepaper sources with the pip-installable typst package."""
from pathlib import Path
import sys

import typst

ROOT = Path(__file__).resolve().parents[1] / 'whitepaper'
DOCUMENTS = ['TECHNICAL_WHITEPAPER.typ', 'TECHNICAL_WHITEPAPER_APPENDICES.typ']


def main():
    selected = sys.argv[1:] or DOCUMENTS
    failed = False
    for filename in selected:
        if filename not in DOCUMENTS:
            raise ValueError(f'Choose one of: {DOCUMENTS}')
        source = ROOT / filename
        output = source.with_suffix('.pdf')
        try:
            typst.compile(str(source), output=str(output), root=str(ROOT))
        except Exception as exc:
            failed = True
            print(f'{filename}: {exc}')
            for name in ['diagnostic', 'diagnostics', 'details', 'trace', 'errors']:
                value = getattr(exc, name, None)
                if value:
                    print(name + ':', value)
        else:
            print(f'Compiled {output.name} ({output.stat().st_size:,} bytes)')
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
