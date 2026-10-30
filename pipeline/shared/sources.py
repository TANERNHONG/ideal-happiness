"""Helpers shared by the coverage, silence, first-seen and context steps of every log source.

The phase scripts import this with ``sys.path.insert(0, <project>/pipeline/shared)``.

* ``archive_inventory()``    every log file in the monthly archives: month, log type, host, bytes
* ``host_day_counts(src)``   lines per host per calendar day, from that source's Phase 1/2 outputs
* ``study_days()``           the calendar days covered by the archives
* ``load_change_windows()``  approved change windows (pipeline/phase9_llm_triage/site/approved_change_windows.csv)
* ``load_public_holidays()`` public holidays (pipeline/phase9_llm_triage/site/public_holidays.csv)
* ``Assets``                 the site's asset inventory (pipeline/phase9_llm_triage/site/assets.csv): each server,
                             address or network's zone, role and criticality
"""
from __future__ import annotations

import csv
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path

import pandas as pd

import runlog  # console output: pipeline/STYLE_GUIDE.md

ROOT = Path(__file__).resolve().parents[2]
ARCHIVES = ROOT / "data" / "phase0_raw" / "archives"
# HUH_CHANGE_WINDOWS points the pipeline at another file (for tests); the site file is the default.
CHANGE_WINDOWS = Path(os.environ.get("HUH_CHANGE_WINDOWS") or ROOT / "pipeline" / "phase9_llm_triage" / "site" / "approved_change_windows.csv")
# Public holidays (date,name): days that count as non-working, like weekends. HUH_PUBLIC_HOLIDAYS points elsewhere (tests).
PUBLIC_HOLIDAYS = Path(os.environ.get("HUH_PUBLIC_HOLIDAYS") or ROOT / "pipeline" / "phase9_llm_triage" / "site" / "public_holidays.csv")
SOURCES = {
    "auth": {"prefix": "authlog", "label": "Authentication", "kind": "authlog", "message_column": "original_log_line"},
    "ossec": {"prefix": "ossec", "label": "OSSEC", "kind": "ossec", "message_column": "original_log_line"},
    "pf": {"prefix": "pflog", "label": "PF", "kind": "pflog", "message_column": "raw_message"},
    "ipf": {"prefix": "ipflog", "label": "IPFilter", "kind": "ipflog", "message_column": "raw_message"},
}
# Which other logs show that a host was up, for each source
WITNESSES = {"auth": ("ossec",), "ossec": ("auth",), "pf": ("auth", "ossec"), "ipf": ("ossec",)}
MEMBER = re.compile(r"^(?P<kind>authlog|ossec_?logs?|osseclogs?|pflog|ipflog)[_-](?P<host>[A-Za-z0-9]+)(?P<tmp>_tmp)?$",
                    re.IGNORECASE)


def member_host(name):
    """'2025-11 NSEWL SCS/pflog/pflog_dewskco_tmp.txt' -> ('pflog', 'dewskco', True); None if not a log file."""
    stem = Path(name.replace("\\", "/")).name
    stem = stem[:-4] if stem.lower().endswith(".txt") else stem
    match = MEMBER.match(stem)
    if not match:
        return None
    kind = match.group("kind").lower()
    kind = "ossec" if kind.startswith("ossec") else kind
    return kind, match.group("host"), bool(match.group("tmp"))


def archive_inventory(archives=ARCHIVES):
    rows = []
    for archive in sorted(archives.glob("*.zip")):
        with zipfile.ZipFile(archive) as handle:
            for info in handle.infolist():
                parsed = None if info.is_dir() else member_host(info.filename)
                if parsed:
                    kind, host, tmp = parsed
                    rows.append({"partition_month": archive.name[:7], "kind": kind, "hostname": host, "tmp": tmp,
                                 "bytes": info.file_size, "member": info.filename})
    return pd.DataFrame(rows)


def study_days(inventory):
    months = sorted(inventory["partition_month"].unique())
    start = pd.Period(months[0], "M").start_time
    end = pd.Period(months[-1], "M").end_time.normalize()
    return pd.date_range(start, end, freq="D")


def host_from_path(series):
    """Host from a source-file path such as ...pflog/pflog_mm04kco.txt (tmp files keep their host)."""
    names = series.fillna("").astype(str).str.replace("\\", "/", regex=False).str.split("/").str[-1]
    return names.str.extract(r"^(?:pflog|ipflog|authlog|ossec_?logs?|osseclogs?)[_-]([A-Za-z0-9]+)", flags=re.IGNORECASE)[0]


def host_day_counts(source):
    """Lines per host per day for one source (study files only: PF's *_tmp captures are left out)."""
    data = ROOT / "data"
    if source == "auth":
        frame = pd.read_csv(data / "phase2_observations" / "auth" / "authlog_host_behavior_1d.csv",
                            usecols=["host_id", "window_start", "total_events"])
        frame = frame.rename(columns={"host_id": "hostname", "total_events": "lines"})
        frame["day"] = pd.to_datetime(frame["window_start"]).dt.normalize()
        return frame.groupby(["hostname", "day"])["lines"].sum().reset_index()
    if source == "ossec":
        frame = pd.read_csv(data / "phase2_observations" / "ossec" / "ossec_events_all_months.csv",
                            usecols=["hostname", "timestamp"], dtype=str)
    elif source == "pf":
        frame = pd.read_csv(data / "phase2_observations" / "pf" / "pflog_events_all_months.csv",
                            usecols=["timestamp", "source_file"], dtype=str)
        frame = frame[~frame["source_file"].fillna("").str.contains("_tmp")]
        frame["hostname"] = host_from_path(frame["source_file"])
    elif source == "ipf":
        frame = pd.read_csv(data / "phase2_observations" / "ipf" / "ipflog_events_all_months.csv",
                            usecols=["hostname", "timestamp"], dtype=str)
    else:
        raise ValueError(source)
    frame["day"] = pd.to_datetime(frame["timestamp"].str[:10].str.replace("/", "-"), errors="coerce")
    frame = frame.dropna(subset=["day", "hostname"])
    return frame.groupby(["hostname", "day"]).size().rename("lines").reset_index()


def load_change_windows(path=CHANGE_WINDOWS):
    """[(start, end, hosts)] from the analysts' change-window CSV; hosts is an empty set for 'any host'."""
    windows = []
    if not Path(path).is_file():
        return windows
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            start, end = (row.get("start") or "").strip(), (row.get("end") or "").strip()
            if not start or start.startswith("#"):
                continue
            try:
                windows.append((datetime.fromisoformat(start), datetime.fromisoformat(end),
                                {h.strip() for h in (row.get("hosts") or "").split(";") if h.strip()}))
            except ValueError:
                runlog.emit(f"Change window with an unreadable time skipped: {start!r} - {end!r}", "WARNING")
    return windows


def load_public_holidays(path=PUBLIC_HOLIDAYS):
    """{date: name} from the site's public-holiday CSV (date,name); an empty dict when there is none."""
    holidays = {}
    if not Path(path).is_file():
        return holidays
    with open(path, encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            day = (row.get("date") or "").strip()
            if not day or day.startswith("#"):
                continue
            try:
                holidays[datetime.fromisoformat(day).date()] = (row.get("name") or "").strip() or "Public holiday"
            except ValueError:
                runlog.emit(f"Public holiday with an unreadable date skipped: {day!r}", "WARNING")
    return holidays


# The asset inventory (match,zone,role,criticality): HUH_ASSETS points elsewhere (tests).
ASSETS = Path(os.environ.get("HUH_ASSETS") or ROOT / "pipeline" / "phase9_llm_triage" / "site" / "assets.csv")
CRITICALITY = ("", "low", "medium", "high")


class Assets:
    """The site's asset inventory: for a server name, an address or a network (CIDR), its zone (e.g. OT, IT, DMZ), role
    (e.g. HMI, SCADA server, jump host) and criticality (low, medium, high). Only what the file states: a server matches
    by name (any case), an address by itself or the most specific network holding it; anything else is unknown.

    of(value) -> (zone, role, criticality), each '' when unknown."""

    def __init__(self, path=ASSETS):
        import ipaddress
        self._ip = ipaddress
        self.names, self.addresses, self.networks, self._seen = {}, {}, [], {}
        if not Path(path).is_file():
            return
        with open(path, encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                match = (row.get("match") or "").strip()
                if not match or match.startswith("#"):
                    continue
                entry = ((row.get("zone") or "").strip(), (row.get("role") or "").strip(),
                         (row.get("criticality") or "").strip().lower())
                if entry[2] not in CRITICALITY:
                    runlog.emit(f"{path.name} line {reader.line_num}: criticality must be low, medium or high; left unknown", "WARNING")
                    entry = (entry[0], entry[1], "")
                try:
                    if "/" in match:
                        self.networks.append((ipaddress.ip_network(match, strict=False), entry))
                    else:
                        self.addresses[str(ipaddress.ip_address(match))] = entry
                except ValueError:
                    self.names[match.lower()] = entry
        self.networks.sort(key=lambda item: -item[0].prefixlen)              # the most specific first

    def __bool__(self):
        return bool(self.names or self.addresses or self.networks)

    def of(self, value) -> tuple:
        value = str(value or "").strip()
        if value in self._seen:
            return self._seen[value]
        found = self.names.get(value.lower())
        if found is None:
            try:
                address = self._ip.ip_address(value)
                found = self.addresses.get(str(address)) or next(
                    (entry for network, entry in self.networks if address.version == network.version and address in network), None)
            except ValueError:
                found = None
        self._seen[value] = found or ("", "", "")
        return self._seen[value]


TIME_COLUMNS = ("timestamp", "window_start", "session_start", "first_timestamp", "episode_start", "start")
HOST_COLUMNS = ("hostname", "host_id", "entity_id")


def change_window_mask(rows, windows):
    """Boolean array: True where a Phase 3 row (train_rows.csv) falls inside an approved change window.

    The row's time is its first available time column; its host, when the view has one, must match the
    window's hosts (a window without hosts applies to every host)."""
    import numpy as np
    if not windows or rows is None or not len(rows):
        return np.zeros(0 if rows is None else len(rows), dtype=bool)
    time_column = next((c for c in TIME_COLUMNS if c in rows.columns), None)
    if time_column is None:
        return np.zeros(len(rows), dtype=bool)
    times = pd.to_datetime(rows[time_column], errors="coerce")
    host_column = next((c for c in HOST_COLUMNS if c in rows.columns), None)
    hosts = rows[host_column].astype(str) if host_column else None
    mask = np.zeros(len(rows), dtype=bool)
    for start, end, window_hosts in windows:
        inside = (times >= start) & (times <= end)
        if window_hosts and hosts is not None:
            inside &= hosts.isin(window_hosts)
        mask |= inside.fillna(False).to_numpy()
    return mask


def train_rows_in_change_windows(features_folder, windows=None):
    """Positions of training rows inside approved change windows, for a Phase 3 view folder."""
    import numpy as np
    windows = load_change_windows() if windows is None else windows
    path = Path(features_folder) / "train_rows.csv"
    if not windows or not path.is_file():
        return np.zeros(0, dtype=int)
    header = pd.read_csv(path, nrows=0).columns
    columns = [c for c in TIME_COLUMNS + HOST_COLUMNS if c in header][:3]
    positions, offset = [], 0
    for chunk in pd.read_csv(path, usecols=columns, dtype=str, chunksize=500_000):
        positions.append(np.flatnonzero(change_window_mask(chunk, windows)) + offset)
        offset += len(chunk)
    return np.concatenate(positions) if positions else np.zeros(0, dtype=int)
