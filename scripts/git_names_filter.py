"""Git's name filter (.gitattributes: filter=huh-names). Git starts it; you never run it yourself.

clean   a file entering git: every real server, address and account becomes its pseudonym (srv-07, acct-03, an address
        in 198.18.0.0/15)
smudge  a file git writes out: each pseudonym becomes the real value again

The key is .git/identifier_key.json and the list .git/identifier_hashes.json (scripts/git_guard.py identifiers);
without the list every file passes through unchanged and the pre-push hook refuses to push. Git's long-running
filter protocol, version 2: one process for all files.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import git_guard  # noqa: E402

PACKET = 65516
IN, OUT = sys.stdin.buffer, sys.stdout.buffer


def read_packet():
    head = IN.read(4)
    if len(head) < 4:
        raise EOFError
    size = int(head, 16)
    return None if size == 0 else IN.read(size - 4)            # None: a flush packet


def read_list() -> list[str]:
    items = []
    while (packet := read_packet()) is not None:
        items.append(packet.decode("utf-8").rstrip("\n"))
    return items


def read_content() -> bytes:
    parts = []
    while (packet := read_packet()) is not None:
        parts.append(packet)
    return b"".join(parts)


def flush() -> None:
    OUT.write(b"0000")
    OUT.flush()


def write_list(*items: str) -> None:
    for item in items:
        data = (item + "\n").encode("utf-8")
        OUT.write(b"%04x" % (len(data) + 4) + data)
    flush()


def write_content(data: bytes) -> None:
    for i in range(0, len(data), PACKET):
        OUT.write(b"%04x" % (len(data[i:i + PACKET]) + 4) + data[i:i + PACKET])
    flush()


def convert(key, command: str, content: bytes) -> bytes:
    if not key or command not in ("clean", "smudge") or b"\0" in content[:8000]:
        return content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    if command == "smudge":
        return key.smudge(text).encode("utf-8")
    cleaned = key.clean(text)
    key.save()
    return cleaned.encode("utf-8")


def main() -> int:
    hello = read_list()
    if "git-filter-client" not in hello or "version=2" not in hello:
        return 1
    write_list("git-filter-server", "version=2")
    offered = read_list()
    write_list(*[c for c in ("capability=clean", "capability=smudge") if c in offered])
    identifiers = git_guard.Identifiers()
    key = git_guard.NameKey(identifiers) if identifiers.ready else None
    while True:
        try:
            header = dict(item.split("=", 1) for item in read_list() if "=" in item)
            content = read_content()
        except EOFError:
            return 0
        result = convert(key, header.get("command", ""), content)
        write_list("status=success")
        write_content(result)
        flush()                                                 # an empty list: the status stays "success"


if __name__ == "__main__":
    raise SystemExit(main())
