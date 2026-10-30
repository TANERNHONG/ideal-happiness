"""Pre-fill pipeline/phase9_llm_triage/site/assets.csv with every server and internal network DAD has seen, so the
inventory becomes blanks to fill in (zone, role, criticality) rather than a list to type from scratch.

    python scripts/assets_template.py              add the missing rows, keep every existing one as it is
    python scripts/assets_template.py --dry-run    count what would be added; write nothing

Servers come from Phase 4h's entity lists (data/phase4_detection/<source>/profiles/profiles.sqlite); networks are the
/24 networks of the source and destination addresses in them, public ranges included (a site can use those inside),
leaving out loopback, link-local, multicast and documentation addresses. Mark a network's zone as you would a
server's (an external network gets zone "external"). A row already in the file (the same match,
any case) is never changed. The file stays out of git (.gitignore). Prints counts only.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline" / "shared"))
import runlog  # noqa: E402  console output: pipeline/STYLE_GUIDE.md
from sources import ASSETS  # noqa: E402

LOGGER = runlog.LOGGER
SOURCES = ("auth", "ossec", "pf", "ipf")
HEADER = ["match", "zone", "role", "criticality"]
SKIP = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/8", "255.255.255.255/32")]


def seen(data: Path) -> tuple[set[str], set[str]]:
    """(server names, /24 networks) from every log type's entity list."""
    servers, networks = set(), set()
    for source in SOURCES:
        path = data / "phase4_detection" / source / "profiles" / "profiles.sqlite"
        if not path.is_file():
            LOGGER.warning(f"No entity list for {source}: run Phase 4h for it")
            continue
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as con:
            for kind, entity in con.execute("SELECT entity_type, entity FROM entities WHERE entity_type IN "
                                            "('server', 'source_ip', 'destination_ip')"):
                if kind == "server":
                    servers.add(str(entity).lower())
                    continue
                try:
                    address = ipaddress.ip_address(str(entity))
                except ValueError:
                    continue
                if address.version == 4 and not (address.is_loopback or address.is_link_local or address.is_multicast
                                                 or any(address in n for n in SKIP)):
                    networks.add(str(ipaddress.ip_network(f"{address}/24", strict=False)))
    return servers, networks


def existing(path: Path) -> tuple[list[dict], set[str]]:
    if not path.is_file():
        return [], set()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return rows, {(r.get("match") or "").strip().lower() for r in rows}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, default=ROOT / "data", help="the pipeline's data folder")
    parser.add_argument("--out", type=Path, default=ASSETS, help="the inventory file (default: site/assets.csv)")
    parser.add_argument("--dry-run", action="store_true", help="count what would be added; write nothing")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    with runlog.run(args, heartbeat=False):
        servers, networks = seen(args.data)
        rows, have = existing(args.out)
        new = [{"match": m, "zone": "", "role": "", "criticality": ""}
               for m in sorted(servers) + sorted(networks, key=lambda n: ipaddress.ip_network(n)) if m not in have]
        LOGGER.info(f"Seen: {len(servers):,} servers, {len(networks):,} /24 networks; "
                    f"already listed: {len(have):,}; to add: {len(new):,}")
        if args.dry_run or not new:
            return 0
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fields = list(dict.fromkeys([*HEADER, *(k for r in rows for k in r)]))
        with args.out.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows + new)
        LOGGER.info(f"Rows added: {len(new):,} (zone, role and criticality left blank) to {args.out.relative_to(ROOT).as_posix() if args.out.is_relative_to(ROOT) else args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
