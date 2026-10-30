"""Backups of the console's own data (var/): reviews, comments, reports, the activity log and its archives, the
whitelist, uploads, settings and the password hashes. Caches (rebuilt from data/) and test output are left out.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m service.backup create [--to FOLDER]     one zip (default var/backups/)
    ..\\.venv\\Scripts\\python.exe -m service.backup verify BACKUP.zip         hashes, database integrity, activity chain
    ..\\.venv\\Scripts\\python.exe -m service.backup restore BACKUP.zip        with the service stopped
    ..\\.venv\\Scripts\\python.exe -m service.backup rehearse                  create, verify, restore into a scratch folder,
                                                                         compare; the live data is not touched

The database is copied with SQLite's backup API, so a backup taken while the service writes is still consistent. A
restore verifies the zip first and moves the files it replaces to var/pre-restore-<time>/ (nothing is deleted).
A backup holds log lines, accounts and addresses: keep it where the logs themselves may be kept. Prints counts only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import socket
import sqlite3
import sys
import tempfile
import zipfile
from contextlib import closing
from datetime import datetime
from pathlib import Path

from . import store
from .config import HOST, PORT, STORE_FILE, VAR

DATABASE = "console.sqlite3"
FILES = ("settings.json", "admin.json", "sql_password.json", "datasets.json", "auth.json")
FOLDERS = ("audit_archive", "reports", "training")
MANIFEST = "manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _members(var: Path):
    """(path in the zip, file on disk) for everything a backup holds, the database apart."""
    for name in FILES:
        if (var / name).is_file():
            yield name, var / name
    for folder in FOLDERS:
        for path in sorted((var / folder).rglob("*")) if (var / folder).is_dir() else []:
            if path.is_file():
                yield path.relative_to(var).as_posix(), path


def create(to: Path | None = None, var: Path = VAR, database: Path = STORE_FILE) -> Path:
    """One zip: the database (SQLite backup API), the files and folders above, and a manifest of SHA-256 hashes."""
    folder = to or var / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"console-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / DATABASE
        if database.is_file():
            with closing(sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)) as source, \
                    closing(sqlite3.connect(copy)) as dest:
                source.backup(dest)
        members = ([(DATABASE, copy)] if copy.is_file() else []) + list(_members(var))
        manifest = {"created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                    "files": {name: _sha256(path) for name, path in members}}
        partial = target.with_suffix(".partial")
        with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, path in members:
                archive.write(path, name)
            archive.writestr(MANIFEST, json.dumps(manifest, indent=1))
        partial.replace(target)
    return target


def _safe(name: str) -> bool:
    return not (name.startswith(("/", "\\")) or ".." in Path(name).parts or ":" in name)


def verify(backup: Path) -> dict:
    """ok, files, the database's tables with their row counts, and the activity chain inside the backup."""
    problems = []
    with zipfile.ZipFile(backup) as archive, tempfile.TemporaryDirectory() as tmp:
        try:
            manifest = json.loads(archive.read(MANIFEST))
        except (KeyError, ValueError):
            return {"ok": False, "problems": ["no manifest"]}
        names = set(archive.namelist()) - {MANIFEST}
        if names != set(manifest["files"]):
            problems.append(f"{len(names ^ set(manifest['files']))} files differ from the manifest")
        for name in sorted(names & set(manifest["files"])):
            if not _safe(name):
                problems.append(f"unsafe path refused: {name}")
                continue
            archive.extract(name, tmp)
            if _sha256(Path(tmp) / name) != manifest["files"][name]:
                problems.append(f"hash differs: {name}")
        tables, chain = {}, None
        database = Path(tmp) / DATABASE
        if database.is_file() and not problems:
            with closing(sqlite3.connect(database)) as con:
                check = con.execute("PRAGMA integrity_check").fetchone()[0]
                if check != "ok":
                    problems.append(f"database integrity: {check}")
                tables = {t: con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                          for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")}
            chain = _chain(Path(tmp), database)
            if not chain["ok"]:
                problems.append(f"activity chain breaks at {chain.get('where')} {chain.get('entry') or ''}".strip())
    return {"ok": not problems, "problems": problems, "files": len(manifest["files"]), "tables": tables, "chain": chain}


def _chain(var: Path, database: Path) -> dict:
    """store.verify_audit over a copy of var/ (its database and archives), never the live one."""
    from unittest import mock
    with mock.patch.object(store, "VAR", var), mock.patch.object(store, "STORE_FILE", database):
        return store.verify_audit()


def service_running() -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((HOST, PORT)) == 0


def restore(backup: Path, var: Path = VAR, check_service: bool = True) -> dict:
    """Puts a verified backup in place. The files it replaces go to var/pre-restore-<time>/."""
    if check_service and service_running():
        raise RuntimeError(f"The console is running on port {PORT}: stop it before restoring.")
    result = verify(backup)
    if not result["ok"]:
        raise RuntimeError("The backup did not verify: " + "; ".join(result["problems"]))
    aside = var / f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    with zipfile.ZipFile(backup) as archive:
        names = [n for n in archive.namelist() if n != MANIFEST]
        moved = 0
        for top in {n.split("/", 1)[0] for n in names} | {DATABASE}:
            current = var / top
            if current.exists():
                aside.mkdir(parents=True, exist_ok=True)
                shutil.move(str(current), str(aside / top))
                moved += 1
        for name in names:
            archive.extract(name, var)
    return {"restored": len(names), "moved_aside": moved, "aside": aside if moved else None, **result}


def rehearse(var: Path = VAR, database: Path = STORE_FILE) -> dict:
    """create → verify → restore into a scratch folder → the same tables and row counts as the live store."""
    with tempfile.TemporaryDirectory() as tmp:
        backup = create(Path(tmp), var, database)
        checked = verify(backup)
        scratch = Path(tmp) / "restored"
        scratch.mkdir()
        restore(backup, scratch, check_service=False)
        with closing(sqlite3.connect(f"file:{(scratch / DATABASE).as_posix()}?mode=ro", uri=True)) as con:
            restored = {t: con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                        for (t,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")}
        same = restored == checked["tables"]
        return {"ok": checked["ok"] and same, "verify": checked, "same_tables_and_rows": same,
                "bytes": backup.stat().st_size}


def _print(result: dict) -> None:
    for problem in result.get("problems", []):
        print(f"[FAIL] {problem}")
    if result.get("tables"):
        print(f"Tables: {len(result['tables'])}, rows: {sum(result['tables'].values()):,}")
    if result.get("chain"):
        print(f"Activity chain: {'intact' if result['chain']['ok'] else 'BROKEN'}, {result['chain']['checked']:,} entries")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("create").add_argument("--to", type=Path, help="folder for the zip (default var/backups/)")
    sub.add_parser("verify").add_argument("backup", type=Path)
    sub.add_parser("restore").add_argument("backup", type=Path)
    sub.add_parser("rehearse")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            path = create(args.to)
            result = verify(path)
            print(f"Backup: {path} ({path.stat().st_size:,} bytes, {result['files']} files)")
        elif args.command == "verify":
            result = verify(args.backup)
        elif args.command == "restore":
            result = restore(args.backup)
            print(f"Restored {result['restored']} files" + (f"; the replaced ones are in {result['aside']}" if result["aside"] else ""))
        else:
            result = rehearse()
            print(f"Rehearsal: backup {result['bytes']:,} bytes; restored copy has the same tables and rows: "
                  f"{'yes' if result['same_tables_and_rows'] else 'NO'}")
            result = {**result["verify"], "ok": result["ok"]}
        _print(result)
        print("OK" if result["ok"] else "FAILED")
        return 0 if result["ok"] else 1
    except (RuntimeError, OSError, zipfile.BadZipFile) as error:
        print(f"[FAIL] {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
