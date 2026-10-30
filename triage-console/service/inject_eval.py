"""Recall: which mechanisms catch which attack. Made-up attacks are planted, one at a time, into held-out days of
real AUTH lines and scored exactly as an upload is (Analyze: the detectors, the model zoo, frequent subsequences and
the Sigma rules), and the planted lines' observations are checked for flags.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m service.inject_eval DAY.log [DAY2.log ...] --month 2026-07 [--repeats 3] [--out FOLDER]

DAY.log: one day of AUTH lines from one server, from the test period or later; never the training period, which
the models learned as normal. Several days give more trials.

Scenarios
* outsider: guessing, spraying, enumeration, login after guessing, a 03:12 root login, a new account switching to
  root, low and slow. Made-up accounts (eval…) and documentation addresses (203.0.113.0/24): new to the models, so
  novelty catches them for being new as much as for being an attack.
* insider: the day's own most common account and its usual address (taken from the file, never printed): a login at
  02:40, a burst of 40 logins in 10 minutes, guessing against that account, a switch to root. Nothing about the
  identity is new; only the behaviour is.
* sweeps: guessing at 3, 5, 10, 20 and 50 attempts; low and slow at one attempt every 5, 20 and 60 minutes. Recall
  against intensity, not just yes or no.
Each runs --repeats times at different start times (and on every day given). An observation counts as the
scenario's when it names the scenario's address or account (outsider), or when it is flagged by a mechanism that did
not flag the same observation in the unplanted day (insider, and windows naming no one).

Recall per mechanism and per scenario comes with a 95% Wilson interval. Results go to
<out>/<model version>/recall_<time>.json (default var/evaluation/), the model version being a fingerprint of the
AUTH model bundles, so runs on the same models can be compared and runs on new models kept apart. Prints counts
only: no line, server or account from the file. Phase 4g's activity alerts are a batch over the whole year and are
not part of this; nor is a firewall log.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .config import DATA, VAR

LINE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+")
SSHD = "{ts} {host} sshd[{pid}]: [ID 800047 auth.{level}] {msg}"
SU = "{ts} {host} su: [ID 366847 auth.notice] {msg}"
MECHANISMS = ["sigma", "robust", "isolation_forest", "novelty", "model_zoo_consensus", "sequence"]
TIME_KEYS = ("timestamp", "session_start", "episode_start", "window_start")
Z95 = 1.959964


@dataclass
class Scenario:
    name: str
    label: str
    lines: list[str]
    addresses: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    family: str = "outsider"                  # outsider | insider | sweep
    intensity: float | None = None


def _stamp(t: datetime) -> str:
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def wilson(hits: int, n: int) -> tuple[float, float]:
    """The 95% Wilson interval of hits / n."""
    if n == 0:
        return 0.0, 1.0
    p = hits / n
    centre = (p + Z95 ** 2 / (2 * n)) / (1 + Z95 ** 2 / n)
    half = Z95 * math.sqrt(p * (1 - p) / n + Z95 ** 2 / (4 * n * n)) / (1 + Z95 ** 2 / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def scenarios(host: str, day: datetime, repeat: int = 0, insider: tuple[str, str] | None = None) -> list[Scenario]:
    """The planted attacks, on ``host`` on ``day``; ``repeat`` moves each to another start time. ``insider``: the day's
    own (account, address), for the insider scenarios (none without it). Each scenario has its own made-up
    accounts and address."""
    out = []
    pid = iter(range(7000 + 1000 * repeat, 8000 + 1000 * repeat))
    day_hours = (14, 10, 16, 11, 15)[repeat % 5]
    night = (3, 1, 4, 2, 0)[repeat % 5]

    def sshd(t, msg, level="info"):
        return SSHD.format(ts=_stamp(t), host=host, pid=next(pid), level=level, msg=msg)

    def at(hour, minute=0):
        return day.replace(hour=hour % 24, minute=minute, second=0)

    def add(name, label, lines, address="", accounts=(), family="outsider", intensity=None):
        out.append(Scenario(name, label, lines, {address} if address else set(), set(accounts), family, intensity))

    a = "203.0.113.11"
    add("guessing", "Password guessing: 30 failures for root in 2.5 minutes",
        [sshd(at(day_hours) + timedelta(seconds=5 * i), f"Failed password for root from {a} port {40000 + i} ssh2") for i in range(30)], a)
    a, users = "203.0.113.12", [f"eval{i:02d}" for i in range(1, 26)]
    add("spraying", "Password spraying: one failure each for 25 accounts in 16 minutes",
        [sshd(at(day_hours, 30) + timedelta(seconds=40 * i), f"Failed password for {u} from {a} port {41000 + i} ssh2")
         for i, u in enumerate(users)], a, users)
    a, names = "203.0.113.13", [f"evalprobe{i:02d}" for i in range(15)]
    add("enumeration", "Account enumeration: 15 invalid users in 5 minutes",
        [sshd(at(day_hours + 1) + timedelta(seconds=20 * i), f"Invalid user {u} from {a} port {42000 + i}") for i, u in enumerate(names)], a, names)
    a = "203.0.113.14"
    lines = [sshd(at(day_hours + 1, 30) + timedelta(seconds=6 * i), f"Failed password for evalops from {a} port {43000 + i} ssh2") for i in range(12)]
    lines.append(sshd(at(day_hours + 1, 30) + timedelta(seconds=80), f"Accepted password for evalops from {a} port 43100 ssh2"))
    add("guess_then_login", "Login after guessing: 12 failures, then success, for one account", lines, a, ["evalops"])
    a = "203.0.113.15"
    add("night_root", "Root login at night from a new address",
        [sshd(at(night, 12), f"Accepted password for root from {a} port 44000 ssh2")], a)
    a = "203.0.113.16"
    add("su_root", "A new account logs in and switches to root",
        [sshd(at(day_hours + 2), f"Accepted publickey for evaladm from {a} port 45000 ssh2"),
         SU.format(ts=_stamp(at(day_hours + 2) + timedelta(seconds=40)), host=host, msg="'su root' succeeded for evaladm on /dev/pts/7")],
        a, ["evaladm"])
    a = "203.0.113.17"
    add("low_and_slow", "Low and slow: one failure for root every 20 minutes for 8 hours",
        [sshd(at(9 if repeat % 2 == 0 else 8) + timedelta(minutes=20 * i), f"Failed password for root from {a} port {46000 + i} ssh2")
         for i in range(24)], a)

    for attempts in (3, 5, 10, 20, 50):
        a = f"203.0.113.{100 + attempts}"
        add(f"guessing_x{attempts}", f"Guessing: {attempts} failures for root, 5 seconds apart",
            [sshd(at(day_hours, 45) + timedelta(seconds=5 * i), f"Failed password for root from {a} port {47000 + i} ssh2")
             for i in range(attempts)], a, family="sweep", intensity=attempts)
    for minutes in (5, 20, 60):
        a, count = f"203.0.113.{200 + minutes}", 8 * 60 // minutes
        add(f"slow_every_{minutes}m", f"Low and slow: one failure every {minutes} minutes for 8 hours",
            [sshd(at(9) + timedelta(minutes=minutes * i), f"Failed password for root from {a} port {48000 + i} ssh2")
             for i in range(count)], a, family="sweep", intensity=minutes)

    if insider:
        user, address = insider
        add("insider_night_login", "Insider: the day's usual account, from its usual address, at 02:40",
            [sshd(at(2, 40), f"Accepted publickey for {user} from {address} port 49000 ssh2")], family="insider")
        add("insider_burst", "Insider: the usual account logs in 40 times in 10 minutes",
            [sshd(at(day_hours, 20) + timedelta(seconds=15 * i), f"Accepted publickey for {user} from {address} port {49100 + i} ssh2")
             for i in range(40)], family="insider")
        add("insider_guessing", "Insider: 20 failed passwords for the usual account from its usual address",
            [sshd(at(day_hours + 2, 30) + timedelta(seconds=6 * i), f"Failed password for {user} from {address} port {49200 + i} ssh2")
             for i in range(20)], family="insider")
        add("insider_su_root", "Insider: the usual account switches to root",
            [SU.format(ts=_stamp(at(day_hours + 3, 5)), host=host, msg=f"'su root' succeeded for {user} on /dev/pts/3")], family="insider")
    return out


def _when(line: str, year: int) -> datetime | None:
    match = LINE.match(line)
    if not match:
        return None
    try:
        return datetime.strptime(f"{year} {' '.join(match.group('ts').split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def day_of(lines: list[str], year: int) -> tuple[str, datetime]:
    """The day's most common server and its date."""
    hosts = Counter(m.group("host") for line in lines if (m := LINE.match(line)))
    times = [t for line in lines if (t := _when(line, year))]
    if not hosts or not times:
        raise ValueError("No AUTH lines with a time and a server in this file.")
    return hosts.most_common(1)[0][0], min(times).replace(hour=0, minute=0, second=0)


def usual_pair(lines: list[str], month: str) -> tuple[str, str] | None:
    """The day's most common (account, address) among successful logins, for the insider scenarios; None without
    any. Kept in memory only."""
    from . import analyze
    pairs = Counter((event.get("username"), event.get("source_ip")) for _, event, known in analyze._parse("auth", lines, month)
                    if known and event.get("event_type") == "SSH_LOGIN_SUCCESS" and event.get("username") and event.get("source_ip"))
    return pairs.most_common(1)[0][0] if pairs else None


def plant(lines: list[str], planted: list[str], year: int) -> list[str]:
    """The day with the planted lines in time order (a line without a time keeps its place after the one before)."""
    keyed, last = [], datetime.min
    for n, line in enumerate(lines + planted):
        last = _when(line, year) or last
        keyed.append((last, n, line))
    return [line for _, _, line in sorted(keyed)]


def _key(row: dict) -> tuple:
    return (row.get("host_id") or row.get("hostname") or "", next((row[k] for k in TIME_KEYS if row.get(k)), ""),
            row.get("username") or "", row.get("source_ip") or "")


def detections(baseline: dict, result: dict, scenario: Scenario, span: tuple[datetime, datetime]) -> dict[str, list[str]]:
    """{view: mechanisms that flagged the scenario's observations in that view}. Outsider: observations naming the
    scenario's address or account. Otherwise (insider, and windows naming no one): what a mechanism flags inside the
    scenario's time span that it did not flag on the same observation in the unplanted day."""
    before = {v["view"]: {_key(r): set(r.get("flags") or []) for r in v.get("rows") or []} for v in baseline.get("views", [])}
    lo, hi = (span[0] - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"), span[1].strftime("%Y-%m-%d %H:%M:%S")
    out = {}
    for view in result.get("views", []):
        found = set()
        for row in view.get("rows") or []:
            flags = set(row.get("flags") or [])
            if not flags:
                continue
            named = row.get("source_ip") in scenario.addresses or row.get("username") in scenario.accounts
            if named and scenario.family != "insider":
                found |= flags
            elif (scenario.family == "insider" or not (row.get("source_ip") or row.get("username"))) and lo <= _key(row)[1][:19] <= hi:
                found |= flags - before.get(view["view"], {}).get(_key(row), set())      # only what the planting added
        if found:
            out[view["view"]] = sorted(found)
    return out


def model_version(data: Path = DATA) -> str:
    """A fingerprint of the AUTH model bundles (name, size, time): the same models give the same version."""
    root = data / "phase4_detection" / "auth"
    files = sorted(p for pattern in ("detectors/*/experiment_bundle.joblib", "model_zoo/*/*/model_bundle.joblib",
                                     "sequences/*/*.json", "model_zoo/*/families.json") for p in root.glob(pattern))
    text = ";".join(f"{p.relative_to(root).as_posix()}:{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in files)
    return hashlib.sha256(text.encode()).hexdigest()[:12] if files else "no-models"


def summarise(trials: list[dict]) -> dict:
    """Recall per mechanism (any = any mechanism), per scenario, and per family, each with its Wilson interval."""
    def recall(subset, mechanism=None):
        hits = sum(bool(t["detected_by"]) if mechanism is None else mechanism in t["detected_by"] for t in subset)
        low, high = wilson(hits, len(subset))
        return {"hits": hits, "trials": len(subset), "recall": hits / len(subset) if subset else 0.0, "low": low, "high": high}
    by = lambda key: sorted({t[key] for t in trials})                                         # noqa: E731
    return {"mechanisms": {m: recall(trials, m) for m in MECHANISMS}, "any": recall(trials),
            "scenarios": {s: {**recall([t for t in trials if t["name"] == s]),
                              **{m: recall([t for t in trials if t["name"] == s], m)["recall"] for m in MECHANISMS}} for s in by("name")},
            "families": {f: recall([t for t in trials if t["family"] == f]) for f in by("family")}}


def evaluate(days: list[list[str]], month: str, repeats: int = 3, run=None) -> dict:
    """Plants each scenario alone, ``repeats`` times on every day, and scores it as Analyze does. ``run(text, month,
    host)``: the scoring (tests pass a stand-in); by default analyze.analyze."""
    if run is None:
        from . import analyze
        run = lambda text, month_, host: analyze.analyze(text=text, source="auth", month=month_, host=host)  # noqa: E731
    year = int(month[:4])
    trials = []
    for d, lines in enumerate(days):
        host, day = day_of(lines, year)
        insider = usual_pair(lines, month)
        baseline = run("\n".join(lines), month, host)
        for repeat in range(repeats):
            for scenario in scenarios(host, day, repeat, insider):
                times = [t for line in scenario.lines if (t := _when(line, year))]
                result = run("\n".join(plant(lines, scenario.lines, year)), month, host)
                views = detections(baseline, result, scenario, (min(times), max(times)))
                trials.append({"day": d, "repeat": repeat, "name": scenario.name, "label": scenario.label, "family": scenario.family,
                               "intensity": scenario.intensity, "lines": len(scenario.lines),
                               "detected_by": sorted({m for found in views.values() for m in found}), "views": views})
    return {"days": len(days), "lines": sum(len(x) for x in days), "repeats": repeats, "trials": trials, **summarise(trials),
            "evaluated_at": datetime.now().astimezone().isoformat(timespec="seconds"), "month": month}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("days", type=Path, nargs="+", help="days of AUTH lines, one server each (test period or later)")
    parser.add_argument("--month", required=True, help="YYYY-MM of the days (syslog lines carry no year)")
    parser.add_argument("--repeats", type=int, default=3, help="start times per scenario and day (default 3)")
    parser.add_argument("--out", type=Path, default=VAR / "evaluation", help="folder for the results")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", args.month):
        parser.error("--month is YYYY-MM")
    days = [path.read_text(encoding="utf-8", errors="replace").splitlines() for path in args.days]
    result = evaluate(days, args.month, max(1, args.repeats))
    version = model_version()
    folder = args.out / version
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"recall_{datetime.now():%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps({**result, "model_version": version}, indent=1), encoding="utf-8")
    print(f"{result['lines']:,} lines over {result['days']} day(s); {len(result['trials'])} trials (models {version})")
    for name, r in result["scenarios"].items():
        print(f"  {name:<20} {r['hits']:>3}/{r['trials']:<3} recall {r['recall']:.0%} [{r['low']:.0%}, {r['high']:.0%}]")
    print("Recall by mechanism: " + ", ".join(f"{m} {r['recall']:.0%}" for m, r in result["mechanisms"].items())
          + f"; any {result['any']['recall']:.0%} [{result['any']['low']:.0%}, {result['any']['high']:.0%}]")
    print(f"Result: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
