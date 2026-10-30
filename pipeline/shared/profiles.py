"""Profiles of addresses across the logs, shared by Phase 7c context and the presence method's Phase 5.

    auth_profile()       per source address: SSH logins and failures, accounts, servers, days (cached)
    firewall_profile()   per address: lines in a firewall log (PF or IPFilter), roles, months, ports, hosts
    ossec_profile()      server names OSSEC gives addresses (per1kco/172.16.10.41) and OSSEC lines naming them
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime

import pandas as pd

from sources import ROOT, host_from_path
import runlog  # console output: pipeline/STYLE_GUIDE.md

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
NAMED = re.compile(r"\b([A-Za-z][\w-]{2,})/(\d{1,3}(?:\.\d{1,3}){3})\b")
SHARED = ROOT / "data" / "phase7_alerts" / "_shared"
CHUNK = 1_000_000


log = runlog.log


def auth_profile(quiet):
    """Per source address: SSH logins and failures across all servers (cached)."""
    files = sorted((ROOT / "data" / "phase1_classify" / "auth").glob("classified_authlog_events_*.csv"))
    cache = SHARED / "auth_address_profile.csv"
    newest = max((path.stat().st_mtime for path in files), default=0)
    if cache.is_file() and cache.stat().st_mtime >= newest:
        return pd.read_csv(cache, dtype={"address": str}).set_index("address")
    log(f"Building the auth address profile from {len(files)} monthly files (cached afterwards)", quiet)
    parts = []
    for path in files:
        for chunk in pd.read_csv(path, usecols=["timestamp", "hostname", "event_type", "source_ip", "username"],
                                 dtype=str, chunksize=CHUNK, keep_default_na=False):
            chunk = chunk[chunk["source_ip"].ne("")]
            chunk["day"] = chunk["timestamp"].str[:10]
            chunk["success"] = chunk["event_type"].eq("SSH_LOGIN_SUCCESS")
            chunk["failure"] = chunk["event_type"].isin(["SSH_LOGIN_FAILED", "SSH_INVALID_USER", "SSH_PAM_ACCOUNT_ACCESS_DENIED"])
            chunk = chunk[chunk["success"] | chunk["failure"]]
            parts.append(chunk.groupby(["source_ip", "hostname", "username", "day", "success"]).size().rename("n").reset_index())
    frame = pd.concat(parts, ignore_index=True)
    ok, bad = frame[frame["success"]], frame[~frame["success"]]
    top = lambda s, n: ", ".join(s.groupby(level=0).sum().sort_values(ascending=False).head(n).index) if len(s) else ""
    rows = []
    for address, part in ok.groupby("source_ip"):
        rows.append({"address": address, "auth_logins_from": int(part["n"].sum()),
                     "auth_accounts": top(part.set_index("username")["n"], 4),
                     "auth_servers": top(part.set_index("hostname")["n"], 6),
                     "auth_server_count": part["hostname"].nunique(), "auth_days_active": part["day"].nunique(),
                     "auth_first": part["day"].min(), "auth_last": part["day"].max()})
    profile = pd.DataFrame(rows).set_index("address") if rows else pd.DataFrame()
    failures = bad.groupby("source_ip")["n"].sum().rename("auth_failures_from")
    profile = profile.join(failures, how="outer")
    profile["auth_failures_from"] = profile["auth_failures_from"].fillna(0).astype(int)
    SHARED.mkdir(parents=True, exist_ok=True)
    profile.reset_index().rename(columns={"index": "address", "source_ip": "address"}).to_csv(cache, index=False)
    return profile


def firewall_profile(path, host_column=None, source_file_column=None):
    if not path.is_file():
        return pd.DataFrame()
    header = pd.read_csv(path, nrows=0).columns
    use = [c for c in ("timestamp", "source_ip", "destination_ip", "destination_port", host_column, source_file_column)
           if c and c in header]
    frame = pd.read_csv(path, usecols=use, dtype=str, keep_default_na=False)
    if source_file_column in frame:
        frame = frame[~frame[source_file_column].str.contains("_tmp")]
        frame["host"] = host_from_path(frame[source_file_column])
    else:
        frame["host"] = frame.get(host_column, "")
    rows = []
    for role in ("source_ip", "destination_ip"):
        part = frame[[role, "timestamp", "destination_port", "host"]].rename(columns={role: "address"})
        part["role"] = role.split("_")[0]
        rows.append(part)
    both = pd.concat(rows, ignore_index=True)
    both = both[both["address"].ne("")]
    grouped = both.groupby("address")
    return pd.DataFrame({
        "lines": grouped.size(),
        "roles": grouped["role"].agg(lambda s: ", ".join(sorted(set(s)))),
        "months": grouped["timestamp"].agg(lambda s: ", ".join(sorted(set(s.str[:7])))),
        "ports": grouped["destination_port"].agg(lambda s: ", ".join(s[s.ne("")].value_counts().head(4).index)),
        "hosts": grouped["host"].agg(lambda s: ", ".join(s[s.ne("")].value_counts().head(4).index)),
    })


def ossec_profile():
    path = ROOT / "data" / "phase2_observations" / "ossec" / "ossec_events_all_months.csv"
    names, mentions = {}, Counter()
    if not path.is_file():
        return names, mentions
    header = pd.read_csv(path, nrows=0).columns
    text_column = "original_log_line" if "original_log_line" in header else "raw_message"
    for chunk in pd.read_csv(path, usecols=[text_column], dtype=str, chunksize=CHUNK, keep_default_na=False):
        for line in chunk[text_column]:
            for name, address in NAMED.findall(line):
                names.setdefault(address, name)
            mentions.update(set(IPV4.findall(line)))
    return names, mentions
