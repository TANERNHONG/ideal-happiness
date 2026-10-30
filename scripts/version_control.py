"""Small local release controller: snapshot, list and verify source releases.

Each release is an immutable ZIP plus SHA-256 manifest. Runtime data, original
logs, secrets and dependencies are excluded. Existing releases are never replaced.
Rollback: extract the selected ZIP to a separate folder and compare before copying
files back. This tool intentionally never overwrites the working project.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RELEASES = ROOT / 'versions'
EXCLUDE = {'.git', '.venv', '.idea', '__pycache__', 'node_modules', 'dist', 'var', 'data', 'runtime', 'outdated', 'versions', '.codex', '.agents', '.aws', '.ssh', '.env'}
EXTENSIONS = {'.py', '.ts', '.css', '.html', '.json', '.md', '.txt', '.svg', '.png', '.jpg', '.jpeg', '.ico', '.woff2', '.toml', '.yml', '.yaml'}


def files():
    def visit(folder):
        for path in sorted(folder.iterdir()):
            if path.name in EXCLUDE or path.is_symlink():
                continue
            if path.is_dir():
                yield from visit(path)
            elif (path.suffix.lower() in EXTENSIONS or path.name == '.gitignore') and not path.name.startswith('.env'):
                yield path
    yield from visit(ROOT)


def digests():
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['snapshot', 'verify', 'list'])
    parser.add_argument('version', nargs='?')
    args = parser.parse_args()
    if args.action == 'list':
        for p in sorted(RELEASES.glob('*.json')):
            meta = json.loads(p.read_text(encoding='utf-8'))
            print(f"{meta['version']} | {meta['created_at']} | {len(meta['files'])} files")
        return
    if not args.version or not re.fullmatch(r'\d+\.\d+\.\d+', args.version):
        parser.error('Use a semantic version such as 0.2.0.')
    manifest = RELEASES / f'{args.version}.json'
    archive = RELEASES / f'{args.version}.zip'
    if args.action == 'snapshot':
        if manifest.exists() or archive.exists():
            parser.error('This release already exists. Use a new version; never overwrite a release.')
        RELEASES.mkdir(exist_ok=True)
        content = digests()
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
            for name in content:
                data = (ROOT/name).read_bytes()
                if hashlib.sha256(data).hexdigest() != content[name]:
                    raise RuntimeError(f'{name} changed while making the release. Release not finalised.')
                z.writestr(name, data)
        result = {'version': args.version, 'created_at': datetime.now().astimezone().isoformat(),
                  'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'files': content}
        manifest.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        print(f'Recorded {args.version}: {len(content)} source/documentation files; logs and runtime data excluded.')
    else:
        expected = json.loads(manifest.read_text(encoding='utf-8'))
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected['archive_sha256']:
            raise SystemExit('Release archive checksum does not match.')
        current = digests()
        changes = [(name, 'added' if name not in expected['files'] else 'removed' if name not in current else 'changed')
                   for name in sorted(current.keys() | expected['files'].keys()) if current.get(name) != expected['files'].get(name)]
        for name, state in changes:
            print(f'{state}: {name}')
        print(f'{len(changes)} differences from {args.version}; archive checksum verified.')
        if changes:
            sys.exit(1)


if __name__ == '__main__': main()
