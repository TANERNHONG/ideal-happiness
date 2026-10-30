"""Report sections shared by the auth, OSSEC and PF reports: coverage, silence, first seen, context.

Each function returns one <section> (or "" when its input is missing), ready
for a chapter list in report_layout.document():

    coverage_section(source)    Data chapter: which host-days each log covers, and the gaps
    silence_section(source)     Results chapter: hosts silent while other logs show them up (Phase 4d)
    first_seen_section(source)  Results chapter: what a host did for the first time in the test period (4e)
    activity_section(source)    Results chapter: unusual amounts of activity, content ignored (4g; auth, OSSEC)
    context_section(source)     Evidence chapter: what the other logs know about the alerts' addresses (7c)
"""
from __future__ import annotations

import html
import json
import math
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
PREFIX = {"auth": "authlog", "ossec": "ossec", "pf": "pflog"}
LABEL = {"auth": "authentication", "ossec": "OSSEC", "pf": "PF firewall"}
STATUS_TEXT = {"active": "Logged", "quiet": "Quiet, host up", "collection_gap": "Collection gap",
               "unknown": "Unknown", "no_log": "No such log"}


def _esc(value):
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return ""
    return html.escape(str(value))


def _num(value, digits=0):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "–"
    return "–" if math.isnan(value) else f"{value:,.{digits}f}"


def _table(headers, rows):
    if not rows:
        return '<div class="empty">No rows</div>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _section(identifier, title, body):
    return f'<section id="{identifier}"><h2>{_esc(title)}</h2>{body}</section>'


def coverage_section(source):
    folder = ROOT / "data" / "phase2_observations" / source
    days_path, summary_path = folder / f"{PREFIX[source]}_host_days.csv", folder / f"{PREFIX[source]}_coverage_summary.json"
    if not days_path.is_file() or not summary_path.is_file():
        return ""
    days = pd.read_csv(days_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    witnesses = " and ".join(summary.get("witnesses", [])) or "no other log"
    rows = []
    for host, part in days.groupby("hostname"):
        counts = part["status"].value_counts()
        months = part.drop_duplicates("partition_month")["file_status"].value_counts()
        cells = [f"<b>{_esc(host)}</b>"] + [_num(counts.get(s, 0)) for s in STATUS_TEXT]
        cells.append(", ".join(f"{_esc(k)} {v}" for k, v in months.items()))
        rows.append(cells)
    gaps = summary.get("longest_collection_gaps", [])
    gap_text = ("<p><b>Longest collection gaps</b> (host up, this log has nothing): "
                + "; ".join(f"{_esc(h)} {_esc(a)} to {_esc(b)} ({n} days)" for h, a, b, n in gaps[:6]) + ".</p>"
                if gaps else "<p>No collection gaps: whenever another log shows a host up, this log was collected.</p>")
    empty_rule = ("This log only records blocked packets, so an empty monthly file means nothing was blocked "
                  "and counts as quiet" if bool(days["empty_file_is_quiet"].iloc[0]) else
                  "This log is written every day in normal operation, so an empty monthly file counts as a "
                  "collection gap")
    body = (f"<p>The other views only have a row where a host logged something, so a host that goes quiet leaves "
            f"no trace. This table covers every host and day of the study period. <i>Quiet, host up</i> means the "
            f"{LABEL[source]} log has nothing for that day while {witnesses} shows the server was running. "
            f"<i>Collection gap</i> means the server was running but its monthly file is empty or missing. "
            f"<i>Unknown</i> means no log shows the server up, so silence cannot be judged. "
            f"{empty_rule}.</p>" + gap_text
            + _table(["Server"] + list(STATUS_TEXT.values()) + ["Monthly files"], rows))
    return _section("coverage", "Coverage: which server-days this log covers", body)


def silence_section(source):
    folder = ROOT / "data" / "phase4_detection" / source / "silence"
    summary_path = folder / "silence_episodes" / "summary.json"
    if not summary_path.is_file():
        return ""
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    alerts = pd.read_csv(folder / "silence_episodes" / "test_scores.csv")
    runs = pd.read_csv(folder / "silent_runs.csv") if (folder / "silent_runs.csv").is_file() else pd.DataFrame()
    rows = [[f"<b>{_esc(r['hostname'])}</b>", _esc(r["start"]), _esc(r["end"]), _num(r["days"]),
             _num(r["usual_lines_per_day"]), f"{float(r['host_silent_share']):.1%}", f"{float(r['chance_of_run']):.1g}",
             _num(r["collection_gap_days"]), _num(r["witness_lines"])]
            for _, r in alerts.sort_values("silence_score", ascending=False).iterrows()]
    body = (f"<p>A server is <i>silent</i> on a day when this log has nothing from it while other logs show it "
            f"was up. Consecutive silent days are one episode. An episode alerts when that many silent days in a "
            f"row would happen less than once in {10 ** summary['min_surprise']:,.0f} times for that server, given how "
            f"often it is silent (the <i>silent share</i>). This catches an OSSEC agent that writes four lines a day "
            f"going quiet as well as an auth log that writes hundreds. Scored: {summary['host_days_scored']:,} "
            f"server-days on {summary['hosts']} servers; {summary['silent_days']:,} silent days in "
            f"{summary['silent_runs']:,} runs, of which <b>{summary['episodes']} alert</b> "
            f"({summary.get('silent_days_in_alerts', 0):,} days).</p>"
            + _table(["Server", "From", "To", "Days", "Usual lines/day", "Silent share", "Chance of run",
                      "Days with empty or missing file", "Other-log lines"], rows))
    if not len(alerts) and len(runs):
        body += ("<p>No run is unusual for its server: the servers whose log is silent on many days are quiet by "
                 "nature, which is normal for a firewall that only logs blocked packets.</p>")
    return _section("silence", "Silence: servers up, log empty", body)


def first_seen_section(source, top=30):
    folder = ROOT / "data" / "phase4_detection" / source / "first_seen" / "first_seen_pairs"
    if not (folder / "summary.json").is_file():
        return ""
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    alerts = pd.read_csv(folder / "test_scores.csv")
    evidence = pd.read_csv(folder / "test_raw_alert_evidence.csv")
    message = [c for c in evidence.columns if c not in ("row_manifest_id", "event_position")][0]
    example = evidence[evidence["event_position"].eq(1)].set_index("row_manifest_id")[message]
    rows = [[f"<b>{_esc(r['hostname'])}</b>", _esc(str(r["kind"]).replace("_", " ")), f"<code>{_esc(r['value'])}</code>",
             _num(r["occurrences"]), _esc(str(r["first_seen"])[:16]),
             f"<code>{_esc(str(example.get(r['row_manifest_id'], ''))[-160:])}</code>"]
            for _, r in alerts.head(top).iterrows()]
    kinds = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in summary.get("by_kind", {}).items()) or "none"
    body = (f"<p>The novelty detector's alerts are capped by the daily budget, so something genuinely new can be "
            f"crowded out on a busy day. This check has no cap: for each server it lists what appeared for the first "
            f"time in the test period (from {_esc(summary['test_start'][:16])}) that the server never showed before. "
            f"{summary['test_first_seen_alerts']} such items ({kinds}); rarest first. New is not hostile: a new "
            f"administrator account or a maintenance error is new too.</p>"
            + _table(["Server", "Kind", "Value", "Times", "First seen", "First line (end)"], rows)
            + (f"<p>{len(alerts) - top} more in the Phase 7 first-seen alert file.</p>" if len(alerts) > top else ""))
    return _section("first-seen", "First seen on this server", body)


ACTIVITY_WHO = {"all": "Whole log", "server": "Server", "source_ip": "Source IP", "username": "Username",
                "destination_ip": "Destination IP"}
ACTIVITY_BY = {"activity_robust": "robust", "activity_forest": "Isolation Forest"}


def activity_section(source, top=30):
    folder = ROOT / "data" / "phase4_detection" / source / "activity"
    views = [folder / view for view in ("activity", "activity_by_entity") if (folder / view / "summary.json").is_file()]
    if not views:
        return ""
    summary = json.loads((views[0] / "summary.json").read_text(encoding="utf-8"))
    alerts = pd.concat([pd.read_csv(view / "test_scores.csv") for view in views], ignore_index=True)
    alerts = alerts.sort_values("activity_score", ascending=False)
    experiments = pd.read_csv(folder / "experiment_summary.csv") if (folder / "experiment_summary.csv").is_file() else pd.DataFrame()
    counts = alerts["entity_type"].value_counts() if len(alerts) else pd.Series(dtype=int)
    types = [[_esc(ACTIVITY_WHO.get(r["entity_type"], r["entity_type"])), _num(r.get("series")), _num(r.get("test_rows")),
              f"{_num(r.get('features_kept'))} of {_num(r.get('features_considered'))}",
              _num(counts.get(r["entity_type"], 0)), _esc(r.get("status", ""))]
             for _, r in experiments.iterrows()]
    rows = [[f"<b>{_esc(ACTIVITY_WHO.get(r['entity_type'], r['entity_type']))}</b>"
             + ("" if r["entity_type"] == "all" else f" <code>{_esc(r['entity'])}</code>"),
             _esc(str(r["start"])[:16]), _esc(str(r["end"])[:16]), _num(r["steps"]),
             f"{_num(r['peak_window_lines'])} {r['peak_channel'] if isinstance(r.get('peak_channel'), str) else 'lines'} "
             f"in {_num(r['peak_window_minutes'])} min", _num(r["usual_window_lines"], 1),
             _esc(r["calendar_basis"] if isinstance(r.get("calendar_basis"), str) and r["calendar_basis"] else f"{r['baseline']} level"),
             _esc(" + ".join(ACTIVITY_BY.get(d, d) for d in str(r["detector_combination"]).split("+")))]
            for _, r in alerts.head(top).iterrows()]
    windows = ", ".join(str(w) for w in summary.get("windows_minutes", []))
    body = (f"<p>These detectors ignore what a line says and look only at how much activity there is, when, and "
            f"from whom: the lines in the trailing {windows} minutes of each 5-minute step, with log twins, the "
            f"time of day and week, how many other servers, IPs, users and destinations were involved, and how far "
            f"each of these is from the series' own normal. The whole log is one series; every server, source IP, "
            f"username and destination IP is another, judged against its own training history. Robust deviation "
            f"compares each step with the same clock time on the series' comparable training days (the same weekday's, "
            f"else the same kind of day's) and with its level whenever active, and counts the smaller, from a fixed "
            f"bar; the Isolation Forest is a second opinion that alerts on its own only above a strict bar. Alerting "
            f"steps less than {summary.get('merge_gap_minutes', 60)} minutes apart form one alert. Train to {_esc(summary.get('train_end', '')[:16])}, validation to "
            f"{_esc(summary.get('validation_end', '')[:16])}; {len(alerts):,} alerts in the test period.</p>"
            + _table(["Series", "Series count", "Test steps", "Features kept", "Alerts", "Status"], types)
            + _table(["Who", "From", "To", "Steps", "Peak", "Usual", "Compared with", "Flagged by"], rows)
            + (f"<p>{len(alerts) - top:,} more in the Phase 7 activity alert file.</p>" if len(alerts) > top else ""))
    return _section("activity", "Activity: amounts and timing, not content", body)


def context_section(source, top=25):
    path = ROOT / "data" / "phase7_alerts" / source / f"{PREFIX[source]}_cross_source_context.csv"
    if not path.is_file():
        return ""
    context = pd.read_csv(path)
    rows = []
    for _, r in context.head(top).iterrows():
        flags = []
        if not bool(r.get("private_address", True)):
            flags.append('<span class="badge danger">public range</span>')
        if bool(r.get("approved_automation", False)):
            flags.append('<span class="badge success">approved automation</span>')
        rows.append([f"<code>{_esc(r['address'])}</code>", _esc(r.get("known_as")), " ".join(flags),
                     _num(r.get("alerts_naming_it")), _esc(r.get("alert_files")), _num(r.get("auth_logins_from")),
                     _num(r.get("auth_failures_from")), _esc(r.get("auth_accounts")), _esc(r.get("auth_servers")),
                     _num(r.get("auth_days_active")), _num(r.get("pf_lines")), _num(r.get("ipf_lines")),
                     _num(r.get("ossec_lines_naming_it"))])
    body = ("<p>An alert shows lines from one log. What an address is (an administrator's workstation, a "
            "monitoring server, something nobody recognises) usually shows in the others. For the addresses named "
            "most often in this log's alerts: the name OSSEC gives it, SSH logins from it across all servers, and how "
            "often the PF, IPFilter and OSSEC logs name it. <i>Public range</i> marks an address outside the private "
            "ranges (10.x, 172.16–31.x, 192.168.x) used inside the network.</p>"
            + _table(["Address", "Known as", "", "Alerts naming it", "Alert files", "SSH logins from it", "Failed logins",
                      "Accounts", "Servers it logs in to", "Days active", "PF lines", "IPFilter lines", "OSSEC lines"],
                     rows))
    return _section("context", "Context from the other logs", body)
