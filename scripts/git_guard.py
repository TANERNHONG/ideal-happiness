"""Keeps logs, derived data, site lists and real identifiers out of git (the hooks in .githooks call it).

    python scripts/git_guard.py setup         once per clone: the hooks, the name filter and the identifier list
    python scripts/git_guard.py identifiers   hashes every server, address and account in Phase 4h's entity lists
                                              (data/phase4_detection/<source>/profiles/profiles.sqlite) and the log
                                              archives' file names into .git/identifier_hashes.json
    python scripts/git_guard.py scan          the identifier check over every file git would hold now
    python scripts/git_guard.py pre-commit    staged files: refused paths, then identifiers (when the list exists)
    python scripts/git_guard.py pre-push      every file in the commits being pushed, then scripts/check.py; refuses
                                              without the identifier list

Real names never reach git: the name filter (.gitattributes, scripts/git_names_filter.py) turns each one into a
stable pseudonym (srv-07, acct-03, an address in 198.18.0.0/15) as a file enters git and back as git writes it out,
from .git/identifier_key.json. Nothing in .git/ is ever pushed. A refusal names the file, the line and the kind of
identifier, never the name or address itself.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import secrets
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline" / "shared"))
import runlog  # noqa: E402  console output: pipeline/STYLE_GUIDE.md

LOGGER = runlog.LOGGER
SOURCES = ("auth", "ossec", "pf", "ipf")
MAX_BYTES = 5_000_000
ZERO = "0" * 40

# Paths that never go into git, whatever .gitignore says (git add -f included): (pattern, reason)
REFUSED = [
    ("data/*", "log data"), ("runtime/*", "frozen runtime with data"), ("outdated/*", "old data"),
    ("triage-console/var/*", "console store, caches and reports"), ("versions/*", "release archives"),
    ("*.sqlite", "database"), ("*.sqlite3", "database"), ("*.db", "database"), ("*.pkl", "pickle"),
    ("*.npz", "array cache"), ("*.parquet", "table cache"), ("*.joblib", "model"), ("*.pyc", "compiled Python"),
    ("*/node_modules/*", "installed packages"), ("triage-console/web/dist/*", "web build"),
    ("pipeline/phase9_llm_triage/site/*.csv", "site list"), ("HYPOTHESIS_REGISTER.md", "site findings"),
    ("PRESENTATION_PREP.md", "site findings"), ("whitepaper/figures/*", "console screenshot"),
    ("*.env", "secrets"), (".env", "secrets"), ("*/auth.json", "SSO settings"), ("auth.json", "SSO settings"),
    ("*.pem", "key"), ("*.key", "key"), ("*id_rsa*", "key"),
]
ALLOWED = ["pipeline/phase9_llm_triage/site/public_holidays.csv"]

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Not identifiers: system accounts, the names attackers try, and anything this short
COMMON = set("""
    root admin administrator user users guest test tester testing demo oracle postgres mysql mongodb redis ftp ftpuser
    sftp ssh sshd nobody daemon bin sys adm uucp nuucp listen smmsp webservd gdm noaccess nobody4 operator support
    ubuntu centos debian pi git deploy jenkins nagios hadoop tomcat apache www www-data backup service default info
    mail email server host local localhost unknown none null true false system console manager monitor
""".split())
SKIP_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}


FILTER = "huh-names"
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*[A-Za-z0-9]|[A-Za-z0-9]")
PSEUDONYM = re.compile(r"\b(?:srv|acct|id)-\d{2,}\b|(?<![\d.])198\.1[89]\.\d{1,3}\.\d{1,3}(?![\d.])")


def git_path(name: str) -> Path:
    found = Path(subprocess.run(["git", "rev-parse", "--git-path", name], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout.strip())
    return found if found.is_absolute() else (ROOT / found).resolve()


def hash_file():
    return git_path("identifier_hashes.json")


def git(*args, binary=False):
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout
    return out if binary else out.decode("utf-8", "replace")


def refused(path: str):
    """Why this path may not be committed, or None."""
    if path in ALLOWED:
        return None
    name = path.rsplit("/", 1)[-1]
    for pattern, reason in REFUSED:
        if fnmatch.fnmatch(path, pattern) or ("/" not in pattern and fnmatch.fnmatch(name, pattern)):
            return reason
    return None


# --- the identifier list ---------------------------------------------------------------------------------------


def _digest(key: str, value: str) -> str:
    return hashlib.sha256(f"{key}\0{value.lower()}".encode("utf-8")).hexdigest()[:32]


def _keep(value: str) -> bool:
    value = value.strip()
    if IPV4.fullmatch(value):
        return value not in SKIP_IPS and not value.startswith(("127.", "255."))
    return len(value) >= 4 and value.lower() not in COMMON and not value.isdigit()


def vocabulary() -> set[str]:
    """Words the code uses as names (Python and TypeScript, outside strings and comments), in parts: an account
    or server that shares a name with the code's own vocabulary (agent, syscheck, manager) is a word, not a secret."""
    import io
    import tokenize
    words: set[str] = set()

    def add(name):
        words.add(name.lower())
        words.update(p.lower() for p in re.split(r"_|(?<=[a-z])(?=[A-Z])", name) if p)

    others = set(git("ls-files", "--others", "--exclude-standard", "-z").split("\0"))
    for path in sorted(set(git("ls-files", "-z").split("\0")) | others):
        file = ROOT / path
        if path.endswith("attack_enterprise.json") and file.is_file():     # MITRE's public text is vocabulary too
            words.update(w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9-]+", file.read_text(encoding="utf-8")))
        elif path.endswith(".py") and file.is_file() and not refused(path):
            try:
                for token in tokenize.generate_tokens(io.StringIO(file.read_text(encoding="utf-8")).readline):
                    if token.type == tokenize.NAME:
                        add(token.string)
            except (tokenize.TokenError, SyntaxError, UnicodeDecodeError):
                continue
        elif path.endswith(".ts") and file.is_file() and not refused(path):
            code = re.sub(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`", " ",
                          file.read_text(encoding="utf-8", errors="replace"), flags=re.S)
            for name in re.findall(r"[A-Za-z_$][\w$]*", code):
                add(name)
    return words


def archive_hosts(data: Path) -> set[str]:
    """Server names from the log archives' file names (pflog_<server>.txt): the names only, no file is read."""
    import zipfile
    from sources import member_host
    hosts = set()
    for archive in sorted((data / "phase0_raw" / "archives").glob("*.zip")):
        try:
            with zipfile.ZipFile(archive) as handle:
                hosts.update(found[1] for found in map(member_host, handle.namelist()) if found)
        except (OSError, zipfile.BadZipFile):
            LOGGER.warning(f"Unreadable archive skipped: {archive.name}")
    return hosts


def phase1_entities(data: Path, source: str) -> list[tuple[str, str]]:
    """(kind, value) for every address and server in a source's Phase 1 files, for a source without Phase 4h."""
    import pandas as pd
    wanted = {"source_ip": "source_ip", "destination_ip": "destination_ip", "hostname": "server", "host_id": "server"}
    found: set[tuple[str, str]] = set()
    prefix = {"auth": "authlog", "ossec": "ossec", "pf": "pflog", "ipf": "ipflog"}[source]
    for path in sorted((data / "phase1_classify" / source).glob(f"classified_{prefix}_events_*.csv")):
        for chunk in pd.read_csv(path, usecols=lambda c: c in wanted, dtype=str, keep_default_na=False, chunksize=1_000_000):
            for column in chunk.columns:
                found.update((wanted[column], value) for value in chunk[column].unique() if value)
    return sorted(found)


def build_identifiers(data: Path) -> int:
    key = secrets.token_hex(16)
    previous = hash_file()
    if previous.is_file():                       # keep the key, so the name filter's pseudonyms stay the same
        key = json.loads(previous.read_text(encoding="utf-8")).get("key") or key
    hashes: dict[str, str] = {}
    words = vocabulary()
    LOGGER.info(f"Code vocabulary: {len(words):,} words (not identifiers)")
    for source in SOURCES:
        path = data / "phase4_detection" / source / "profiles" / "profiles.sqlite"
        if path.is_file():
            with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as con:
                rows = con.execute("SELECT entity_type, entity FROM entities").fetchall()
        else:
            rows = phase1_entities(data, source)
            LOGGER.info(f"{source}: no Phase 4h entity list; addresses from Phase 1 instead")
        kept = 0
        for kind, entity in rows:
            for value in {str(entity).strip(), *str(entity).strip().split("/")}:
                if value and _keep(value) and value.lower() not in words:
                    hashes.setdefault(_digest(key, value), str(kind))
                    kept += 1
        LOGGER.info(f"{source}: {len(rows):,} entities, {kept:,} kept")
    hosts = archive_hosts(data)
    for host in hosts:
        if _keep(host) and host.lower() not in words:
            hashes.setdefault(_digest(key, host), "server")
    LOGGER.info(f"Log archives: {len(hosts):,} servers")
    if not hashes:
        LOGGER.error("No identifiers found: run Phase 4h first")
        return 1
    target = hash_file()
    target.write_text(json.dumps({"key": key, "hashes": hashes}), encoding="utf-8")
    LOGGER.info(f"Identifier list written: {len(hashes):,} hashed values in {target.relative_to(ROOT).as_posix()}")
    return 0


class Identifiers:
    def __init__(self):
        path = hash_file()
        self.ready = path.is_file()
        data = json.loads(path.read_text(encoding="utf-8")) if self.ready else {"key": "", "hashes": {}}
        self.key, self.hashes = data["key"], data["hashes"]
        self._seen: dict[str, str | None] = {}

    def kind(self, value: str):
        if value not in self._seen:
            self._seen[value] = self.hashes.get(_digest(self.key, value)) if self.ready else None
        return self._seen[value]

    def spans(self, text: str):
        """(start, end, kind) of every identifier in text: a whole token (a name, an address, a dotted account), or a
        part of a dotted one (server.domain, user@server)."""
        for match in TOKEN.finditer(text):
            token = match.group()
            kind = self.kind(token)
            if kind:
                yield match.start(), match.end(), kind
            elif "." in token or "@" in token:
                for part in re.finditer(r"[^.@]+", token):
                    kind = self.kind(part.group())
                    if kind:
                        yield match.start() + part.start(), match.start() + part.end(), kind

    def find(self, text: str):
        """(line number, kind) of every identifier in text."""
        for start, _, kind in self.spans(text):
            yield text.count("\n", 0, start) + 1, kind


class NameKey:
    """The name filter's key (.git/identifier_key.json): one pseudonym per identifier as written (case kept), and the
    real value behind each pseudonym, so that clean() then smudge() gives the file back exactly."""

    def __init__(self, identifiers: Identifiers):
        self.ids = identifiers
        self.path = git_path("identifier_key.json")
        data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}
        self.pseudonyms: dict[str, str] = data.get("pseudonyms", {})
        self.plain: dict[str, str] = data.get("plain", {})
        self.dirty = False

    def _new(self, kind: str, value: str) -> str:
        if IPV4.fullmatch(value):
            n = sum(1 for p in self.plain if p.startswith("198.1"))
            return f"198.{18 + n // 65024}.{(n // 254) % 256}.{n % 254 + 1}"
        prefix = "acct" if "user" in kind else "srv" if ("server" in kind or "host" in kind) else "id"
        return f"{prefix}-{sum(1 for p in self.plain if p.startswith(prefix + '-')) + 1:02d}"

    def clean(self, text: str) -> str:
        out, last = [], 0
        for start, end, kind in self.ids.spans(text):
            value = text[start:end]
            exact = hashlib.sha256(f"{self.ids.key}\0{value}".encode("utf-8")).hexdigest()[:32]
            pseudonym = self.pseudonyms.get(exact)
            if pseudonym is None:
                pseudonym = self.pseudonyms[exact] = self._new(kind, value)
                self.plain[pseudonym] = value
                self.dirty = True
            out += [text[last:start], pseudonym]
            last = end
        out.append(text[last:])
        return "".join(out)

    def smudge(self, text: str) -> str:
        return PSEUDONYM.sub(lambda m: self.plain.get(m.group(), m.group()), text)

    def save(self) -> None:
        if self.dirty:
            self.path.write_text(json.dumps({"pseudonyms": self.pseudonyms, "plain": self.plain}), encoding="utf-8")
            self.dirty = False


def filtered_paths(paths) -> set[str]:
    """The paths git passes through the name filter (its attribute is set and the filter is configured)."""
    configured = subprocess.run(["git", "config", f"filter.{FILTER}.process"], cwd=ROOT, capture_output=True).returncode == 0
    if not configured or not paths:
        return set()
    out = subprocess.run(["git", "check-attr", "-z", "--stdin", "filter"], cwd=ROOT, input="\0".join(paths).encode("utf-8"),
                         capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    return {out[i] for i in range(0, len(out) - 2, 3) if out[i + 2] == FILTER}


def _text(blob: bytes):
    if len(blob) > MAX_BYTES or b"\0" in blob[:8000]:
        return None
    return blob.decode("utf-8", "replace")


def check_files(files, identifiers: Identifiers) -> int:
    """files: (label, path, read() -> bytes). Logs every problem; returns how many."""
    problems = 0
    for label, path, read in files:
        reason = refused(path)
        if reason:
            LOGGER.error(f"Refused {label}: {reason}")
            problems += 1
            continue
        blob = read()
        if len(blob) > MAX_BYTES:
            LOGGER.error(f"Refused {label}: {len(blob):,} bytes, over {MAX_BYTES:,} (log data?)")
            problems += 1
            continue
        text = _text(blob)
        if text is None or not identifiers.ready:
            continue
        for number, kind in identifiers.find(text):
            LOGGER.error(f"Identifier in {label}:{number}: {kind}")
            problems += 1
    return problems


# --- the commands ----------------------------------------------------------------------------------------------


def pre_commit() -> int:
    identifiers = Identifiers()
    if not identifiers.ready:
        LOGGER.warning("No identifier list: names and addresses are not checked (python scripts/git_guard.py identifiers)")
    paths = [p for p in git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0") if p]
    files = [(p, p, lambda p=p: git("show", f":{p}", binary=True)) for p in paths]
    problems = check_files(files, identifiers)
    if problems:
        LOGGER.error(f"Commit refused: {problems:,} problems in {len(paths):,} staged files (git restore --staged <file>)")
    return 1 if problems else 0


def pre_push(remote: str) -> int:
    identifiers = Identifiers()
    if not identifiers.ready:
        LOGGER.error("Push refused: no identifier list. Run python scripts/git_guard.py identifiers first")
        return 1
    commits = []
    for line in sys.stdin.read().splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == ZERO:
            continue
        commits += git("rev-list", parts[1], "--not", f"--remotes={remote}").split()
    seen, files = set(), []
    for sha in dict.fromkeys(commits):
        for path in git("diff-tree", "-r", "--root", "--no-commit-id", "--name-only", "--diff-filter=ACMR", "-z", sha).split("\0"):
            blob = path and git("rev-parse", f"{sha}:{path}").strip()
            if path and blob not in seen:
                seen.add(blob)
                files.append((f"{path} @ {sha[:8]}", path, lambda b=blob: git("cat-file", "blob", b, binary=True)))
    problems = check_files(files, identifiers)
    LOGGER.info(f"Checked {len(files):,} files in {len(set(commits)):,} commits")
    if problems:
        LOGGER.error(f"Push refused: {problems:,} problems")
        return 1
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "check.py"), "-q"], cwd=ROOT).returncode


def scan() -> int:
    identifiers = Identifiers()
    if not identifiers.ready:
        LOGGER.error("No identifier list: python scripts/git_guard.py identifiers")
        return 1
    tracked = set(git("ls-files", "-z").split("\0")) - {""}
    ignored = set(git("ls-files", "-c", "-i", "--exclude-standard", "-z").split("\0"))
    others = set(git("ls-files", "--others", "--exclude-standard", "-z").split("\0")) - {""}
    paths = sorted(p for p in (tracked - ignored) | others if (ROOT / p).is_file())
    through_filter = filtered_paths(paths)
    key = NameKey(identifiers)

    def stored(path):                                   # what git would store: the file after the name filter
        blob = (ROOT / path).read_bytes()
        if path in through_filter and _text(blob) is not None:
            return key.clean(blob.decode("utf-8", "replace")).encode("utf-8")
        return blob
    files = [(p, p, lambda p=p: stored(p)) for p in paths]
    problems = check_files(files, identifiers)
    LOGGER.info(f"Scanned {len(files):,} files ({len(through_filter):,} through the name filter): {problems:,} problems")
    return 1 if problems else 0


def setup(data: Path) -> int:
    """The hooks, the name filter and the identifier list, for this clone."""
    git("config", "core.hooksPath", ".githooks")
    script = (ROOT / "scripts" / "git_names_filter.py").as_posix()
    git("config", f"filter.{FILTER}.process", f'"{Path(sys.executable).as_posix()}" "{script}"')
    git("config", f"filter.{FILTER}.required", "true")
    LOGGER.info("Hooks (.githooks) and the name filter set up for this clone")
    return build_identifiers(data)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["setup", "identifiers", "scan", "pre-commit", "pre-push"])
    parser.add_argument("remote", nargs="?", default="origin", help="pre-push: the remote's name (git passes it)")
    parser.add_argument("url", nargs="?", help="pre-push: the remote's URL (git passes it; unused)")
    parser.add_argument("--data", type=Path, default=ROOT / "data", help="identifiers: the pipeline's data folder")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    with runlog.run(args, heartbeat=False) as outcome:
        code = {"setup": lambda: setup(args.data), "identifiers": lambda: build_identifiers(args.data), "scan": scan, "pre-commit": pre_commit,
                "pre-push": lambda: pre_push(args.remote)}[args.command]()
        if code:
            outcome["status"] = "stopped"
    return code


if __name__ == "__main__":
    raise SystemExit(main())
