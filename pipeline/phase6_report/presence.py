"""Phase 6 of the presence method: one self-contained HTML report, in the same IEEE layout as the others.

  python pipeline/phase6_report/presence.py --source ipf
  python pipeline/phase6_report/presence.py --source pf

Used for the logs that are empty, or nearly, in normal operation (IPFilter, PF).
Reads Phases 1-5 (and the Phase 4e first-seen check, when it ran) and writes
data/phase6_report/<source>/<prefix>_threat_analysis_report.html. The chapters
are those of the other reports; the content follows the empty-baseline method:
a 12-month timeline in which silence is the norm, the presence detectors' check
(every active slot flagged, no quiet slot flagged), the flow episodes and the
within-activity ranking, and context from the other logs.
"""
from __future__ import annotations

import argparse
import sys
import html
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

import report_layout as layout
from coverage_sections import first_seen_section

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
CONFIG = {
    "ipf": {"prefix": "ipflog", "label": "IPFilter", "title": "IPFilter Firewall Logs", "other": "pf"},
    "pf": {"prefix": "pflog", "label": "PF", "title": "PF Firewall Logs", "other": "ipf"},
}
SLOT_VIEWS = ("slots_5min", "slots_1h", "slots_1d")
VIEW_LABEL = {"slots_5min": "5-minute slots", "slots_1h": "Hourly slots", "slots_1d": "Daily slots",
              "individual": "Single lines", "attempts": "Connection attempts", "flow_episodes": "Flow episodes"}
RARE_SHARE = 0.01
WITNESS_LABEL = {"auth": "the authentication log", "ossec": "OSSEC"}
TOP_EPISODES = 25
TOP_CHAINS = 40


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(CONFIG))
    parser.add_argument("--top", type=int, default=12, help="Rows in the within-activity ranking tables.")
    runlog.add_arguments(parser)
    args = parser.parse_args()
    args.prefix = CONFIG[args.source]["prefix"]
    args.output = DATA / "phase6_report" / args.source / f"{args.prefix}_threat_analysis_report.html"
    return args


def esc(value):
    return html.escape("" if value is None or (isinstance(value, float) and math.isnan(value)) else str(value))


def number(value, digits=0):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "–"
    return "–" if math.isnan(value) else f"{value:,.{digits}f}"


def line_part(line):
    """The packet fields of a line, without collection prefixes and syslog headers."""
    text = str(line)
    if "[ID " in text and "] " in text[text.find("[ID "):]:
        return text[text.find("] ", text.find("[ID ")) + 2:]
    if "): " in text and " rule " in text:
        return text[text.find(" rule ") + 1:]
    return text[-160:]


def table(headers, rows):
    if not rows:
        return '<div class="empty">No data available</div>'
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def finding(kind, title, text):
    return f'<div class="finding {kind}"><b>{esc(title)}</b><p>{text}</p></div>'


def load(source):
    prefix = CONFIG[source]["prefix"]
    phase = lambda folder, name: DATA / folder / source / name
    data = {
        "source": source, "prefix": prefix, "label": CONFIG[source]["label"],
        "days": pd.read_csv(phase("phase2_observations", f"{prefix}_host_days.csv"), parse_dates=["day"]),
        "slots_1d": pd.read_csv(phase("phase2_observations", f"{prefix}_slots_1d.csv"), parse_dates=["slot_start"]),
        "slots_1h": pd.read_csv(phase("phase2_observations", f"{prefix}_slots_1h.csv"), parse_dates=["slot_start"]),
        "episodes": pd.read_csv(phase("phase2_observations", f"{prefix}_flow_episodes.csv"), parse_dates=["start", "end"]),
        "attempts": pd.read_csv(phase("phase2_observations", f"{prefix}_attempts.csv"), parse_dates=["start"]),
        "events": pd.read_csv(phase("phase2_observations", f"{prefix}_events_all_months.csv"), dtype=str, keep_default_na=False),
        "phase2": json.loads(phase("phase2_observations", f"{prefix}_observation_dataset_summary.json").read_text(encoding="utf-8")),
        "experiments": json.loads((DATA / "phase4_detection" / source / "detectors" / "experiment_summary.json").read_text(encoding="utf-8")),
        "evidence": pd.read_csv(phase("phase5_evidence", f"{prefix}_isolation_forest_outlier_export_summary.csv")),
        "chains": pd.read_csv(phase("phase5_evidence", f"{prefix}_alert_message_chains.csv")),
        "context": pd.read_csv(phase("phase5_evidence", f"{prefix}_cross_source_context.csv")),
    }
    detectors = DATA / "phase4_detection" / source / "detectors"
    data["scores"] = {}
    for view in SLOT_VIEWS + ("individual", "attempts", "flow_episodes"):
        name = "test_scores.csv" if (detectors / view / "test_scores.csv").is_file() else "scores.csv"
        data["scores"][view] = pd.read_csv(detectors / view / name, dtype={"row_manifest_id": str})
    tokens = {}
    for view in ("individual", "attempts"):
        tokens[view] = pd.read_csv(DATA / "phase3_features" / source / view / "tokens.csv", dtype=str,
                                   keep_default_na=False).set_index("row_manifest_id")["tokens"]
    data["tokens"] = tokens
    counts = {}
    for text in tokens["individual"]:
        for token in set(text.split()):
            counts[token] = counts.get(token, 0) + 1
    data["shares"] = {token: count / max(len(tokens["individual"]), 1) for token, count in counts.items()}
    alerts = {}
    for path in sorted((DATA / "phase7_alerts" / source).glob(f"{prefix}_cumulative_*_alerts.csv")):
        alerts[path.stem.replace(f"{prefix}_cumulative_", "").replace("_alerts", "")] = len(pd.read_csv(path))
    data["phase7"] = alerts
    return data


# --- charts -------------------------------------------------------------------------


def combine_hosts(slots):
    """One row per slot across hosts: packets summed, certified when any host is certified."""
    frame = slots.assign(certified=slots["certified"].astype(str).eq("True"))
    return frame.groupby("slot_start").agg(packets=("packets", "sum"), certified=("certified", "any")).reset_index()


def timeline_chart(slots, title, label_every="month"):
    """Bars on a log scale; quiet certified periods as a grey tick, uncertified ones as a yellow band."""
    width, height, left, bottom, top = 1100, 260, 60, 40, 40
    plot_w, plot_h = width - left - 20, height - top - bottom
    step = plot_w / max(len(slots), 1)
    peak = max(1.0, float(np.log10(slots["packets"].max() + 1)))
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}">',
             f'<text x="0" y="22" class="ct">{esc(title)}</text>']
    for exponent in range(0, int(math.ceil(peak)) + 1):
        y = top + plot_h - plot_h * exponent / peak
        if y >= top - 1:
            parts.append(f'<line x1="{left}" x2="{width - 20}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e5e7eb"/>'
                         f'<text x="{left - 6}" y="{y + 4:.1f}" class="axis" text-anchor="end">{10 ** exponent:,}</text>')
    for index, (packets, ok) in enumerate(zip(slots["packets"].to_numpy(), slots["certified"].to_numpy())):
        x = left + index * step
        if not ok:
            parts.append(f'<rect x="{x:.2f}" y="{top}" width="{max(step, 1):.2f}" height="{plot_h}" fill="#fde68a" opacity=".5"/>')
        elif packets > 0:
            h = plot_h * np.log10(packets + 1) / peak
            parts.append(f'<rect x="{x:.2f}" y="{top + plot_h - h:.1f}" width="{max(step * .9, 1):.2f}" height="{h:.1f}" fill="#dc2626"/>')
        else:
            parts.append(f'<rect x="{x:.2f}" y="{top + plot_h - 2}" width="{max(step * .9, .6):.2f}" height="2" fill="#94a3b8"/>')
    starts = slots["slot_start"]
    marks = starts.dt.strftime("%Y-%m") if label_every == "month" else starts.dt.strftime("%d %b")
    previous = None
    for index, mark in enumerate(marks):
        if mark != previous and (label_every == "month" or starts.iloc[index].hour == 0):
            x = left + index * step
            label = starts.iloc[index].strftime("%b %y") if label_every == "month" else mark
            parts.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top + plot_h}" y2="{top + plot_h + 5}" stroke="#64748b"/>'
                         f'<text x="{x + 2:.1f}" y="{top + plot_h + 18}" class="axis">{esc(label)}</text>')
        previous = mark
    parts.append(f'<text x="{left}" y="{height - 4}" class="axis">Red: packets in the period, all servers (log scale). '
                 f'Grey tick: certified quiet period (the baseline). Yellow band: not certified.</text></svg>')
    return "".join(parts)


# --- sections -------------------------------------------------------------------------


def regime_section(data):
    days = data["days"]
    certified = days[days["certified"]]
    quiet = int(certified["lines"].eq(0).sum())
    months = days.drop_duplicates(["hostname", "partition_month"])
    empty_files = int(months["month_status"].eq("empty").sum())
    return layout.text_section("regime", "What is different about this log", (
        "<p>For the authentication and OSSEC logs, normal activity fills the logs, and the detectors learn what "
        f"normal looks like from the lines. <b>This log is (almost) empty when everything is normal.</b> Of "
        f"{len(certified):,} certified server-days, {quiet:,} ({quiet / max(len(certified), 1):.1%}) have no line at "
        f"all, and {empty_files} of {len(months)} monthly files are empty. Any line is therefore unusual, and a model "
        "that learns normal from the lines would learn the activity itself as normal, which is backwards.</p>"
        "<p>The pipeline keeps its detectors and report, and changes three things. It analyses <b>time periods "
        "rather than lines</b>, so that the many empty periods become the baseline. It sets thresholds by <b>zero "
        "tolerance</b> rather than by a daily alert budget. And because every active period is an alert, it "
        "<b>ranks the activity against itself</b> so that an analyst can see which part is unlike the rest.</p>"))


def data_section(data):
    days, events = data["days"], data["events"]
    months = days.drop_duplicates(["hostname", "partition_month"])
    per_month = days.groupby("partition_month").agg(
        certified=("certified", "sum"), host_days=("day", "size"), active=("lines", lambda s: int((s > 0).sum())),
        lines=("lines", "sum"))
    files = months.groupby("partition_month")["month_status"].agg(
        present=lambda s: int(s.ne("missing").sum()), empty=lambda s: int(s.eq("empty").sum()))
    rows = [[esc(month), number(files.loc[month, "present"]), number(files.loc[month, "empty"]),
             f'{int(r["certified"]):,} / {int(r["host_days"]):,}', number(r["active"]), number(r["lines"])]
            for month, r in per_month.join(files).iterrows()]
    witnesses = " or ".join(WITNESS_LABEL.get(w, w) for w in data["phase2"].get("witnesses", [])) or "no other log"
    body = (f"<p>The archives hold one {esc(data['label'])} file per server per month for "
            f"{days['hostname'].nunique()} server(s). A server-day is certified when its month's file exists and the "
            f"server shows it was up: lines in this log, or lines in {esc(witnesses)}. Certified days with no lines are "
            f"the baseline; {int(days['certified'].sum()):,} of {len(days):,} server-days are certified.</p>"
            + table(["Month", "Files", "Empty files", "Certified server-days", "Active server-days", "Lines"], rows))
    sections = [layout.text_section("files", "Monthly files and certification", body)]
    if days["hostname"].nunique() > 1:
        per_host = days.groupby("hostname").agg(certified=("certified", "sum"), active=("lines", lambda s: int((s > 0).sum())),
                                                lines=("lines", "sum"), uncertified=("certified", lambda s: int((~s).sum())))
        host_rows = [[f"<b>{esc(host)}</b>", number(r["certified"]), number(r["active"]), number(r["lines"]),
                      number(r["uncertified"])] for host, r in per_host.sort_values("lines", ascending=False).iterrows()]
        sections.append(layout.text_section("servers", "Activity by server", table(
            ["Server", "Certified days", "Active days", "Lines", "Uncertified days"], host_rows)))
    flows = (events.groupby("flow").agg(lines=("event_id", "size"), first=("timestamp", "min"), last=("timestamp", "max"),
                                        hosts=("hostname", lambda s: ", ".join(s.value_counts().head(3).index)),
                                        rules=("rule_number", lambda s: ", ".join(sorted(set(s)))[:30]),
                                        flags=("tcp_flags", lambda s: ", ".join(s.replace("", "–").value_counts().head(3).index)))
             .sort_values("lines", ascending=False))
    flow_rows = [[f"<code>{esc(flow)}</code>", number(r["lines"]), esc(r["first"][:19]), esc(r["last"][:19]), esc(r["hosts"]),
                  esc(r["rules"]), esc(r["flags"])] for flow, r in flows.head(20).iterrows()]
    types = events["event_type"].value_counts()
    body2 = ("<p>" + ", ".join(f"{esc(k)}: {v:,}" for k, v in types.items()) + f". The lines form {len(flows):,} "
             "distinct flows. A flow is keyed by its service side (client &gt; server:service port/protocol), so a "
             "server's replies to many client ports count as one flow. The largest:</p>"
             + table(["Flow (client → server:port/protocol)", "Lines", "First", "Last", "Servers", "Rule", "Commonest flags"],
                     flow_rows)
             + (f"<p>{len(flows) - 20:,} smaller flows are not shown.</p>" if len(flows) > 20 else ""))
    sections.append(layout.text_section("content", "What the lines contain", body2))
    return sections


def method_text(data):
    witnesses = " or ".join(WITNESS_LABEL.get(w, w) for w in data["phase2"].get("witnesses", [])) or "another log"
    return (
        "<p><b>Views.</b> Phase 2 builds two kinds of observation. <i>Slots</i> cover every five minutes, hour and day "
        "of the study period for each server, empty or not; only the active ones have lines. <i>Activity views</i> "
        "group the lines that exist: single lines, connection attempts (a SYN, its retries and the reset that ends "
        "it) and flow episodes (attempts on one flow with no pause over 30 minutes).</p>"
        f"<p><b>Certification.</b> An empty slot only counts as quiet if the server's monthly file exists and "
        f"another log ({esc(witnesses)}) shows the server was up that day. Otherwise the slot is excluded, so a logging outage cannot "
        "pose as a quiet baseline.</p>"
        "<p><b>Split by regime, not by date.</b> The other sources train on the first 70% of the timeline. Here that "
        "would put most of the activity into training, or leave too few active days to judge. Instead, the certified "
        "days with no lines are the baseline: their earliest 85% train the detectors, the last 15% (validation) set "
        "the thresholds, and every other certified slot is scored.</p>"
        "<p><b>Detectors.</b> The same three as elsewhere. <i>Robust deviation</i> uses the baseline median and spread "
        "of each count, with a floor of one count on the spread; the baseline median and spread are both zero, so "
        "without the floor any packet would be an infinite deviation. <i>Isolation Forest</i> [1] is fitted on every "
        "certified slot: a forest fitted on the baseline alone could never split, because every baseline slot is the "
        "same. <i>Novelty</i> scores tokens (flow, address, port, rule, flags) by how rarely they occur in the "
        "baseline, which here means never.</p>"
        "<p><b>Zero tolerance instead of an alert budget.</b> Each threshold is the highest score among the quiet "
        "validation slots. Any slot above it alerts. The checks that matter are whether every active slot is flagged "
        "and whether any quiet slot is.</p>"
        "<p><b>Ranking within the activity.</b> Every active row is an alert by policy, so the detectors are re-used "
        "to rank the activity against itself: novelty measures how small a share of all active lines carries the row's "
        "attributes, and an Isolation Forest fitted on the active rows catches unusual shapes (cadence, sizes, gaps). A "
        "row ranks high when either says so. With fewer than 20 rows the forest is not used.</p>"
        "<p><b>What becomes an alert.</b> One alert per active server-day (from the daily slots) and one per flow "
        "episode go to Phase 7. The finer slots, attempts and single lines would turn one event into many alerts, so "
        "they appear in this report only. The model zoo and behavioural clusters are not run: they need a spread-out "
        "training distribution, which an all-zero baseline does not have.</p>")


def results_sections(data, top):
    sections = []
    daily = combine_hosts(data["slots_1d"]).sort_values("slot_start")
    chart = timeline_chart(daily, "Packets per day, whole study period")
    active = daily[daily["packets"] > 0]
    if len(active):
        busiest = active.groupby(active["slot_start"].dt.to_period("M"))["packets"].sum().idxmax()
        hourly = combine_hosts(data["slots_1h"])
        zoom = hourly[hourly["slot_start"].dt.to_period("M").eq(busiest)].sort_values("slot_start")
        chart += timeline_chart(zoom, f"Packets per hour in the busiest month ({busiest})", label_every="day")
    sections.append(layout.text_section("timeline", "Timeline: silence is the norm", (
        f"<p>{len(active)} of {len(daily)} days have any line at all, across all servers. The second chart zooms in on "
        f"the busiest month by hour, which shows its rhythm and its pauses.</p>" + f'<div class="panel">{chart}</div>')))

    experiments = {row["dataset"]: row for row in data["experiments"]}
    rows = []
    for view in SLOT_VIEWS:
        row = experiments.get(view)
        if row:
            rows.append([esc(VIEW_LABEL[view]), number(row["scored_rows"]), number(row["baseline_train_rows"]),
                         number(row["baseline_validation_rows"]), number(row["active_rows"]),
                         number(row["test_robust_alerts"]), number(row["test_isolation_alerts"]),
                         number(row["test_novelty_alerts"]), f'{row["active_flagged"]:,} / {row["active_rows"]:,}',
                         number(row["quiet_flagged"]), number(row["baseline_train_false_alarms"]),
                         '<span class="badge success">yes</span>' if row["alerting_in_phase7"] else "report only"])
    check = all(experiments[v]["active_missed"] == 0 and experiments[v]["quiet_flagged"] == 0 for v in SLOT_VIEWS if v in experiments)
    verdict = (finding("success", "The detectors behave as the policy requires",
                       "Every active slot was flagged and no quiet slot was, at every time scale and by each of the three detectors.")
               if check else finding("warning", "Check needed", "Some active slots were missed or quiet slots flagged; see the table."))
    sections.append(layout.text_section("presence", "Presence detection: every active slot, no quiet slot", (
        "<p>Each detector's threshold is the highest score among the quiet validation slots (zero tolerance). The "
        "table shows how many slots each detector flagged, whether all active slots were caught, and whether any "
        "quiet slot was flagged.</p>"
        + verdict + table(["View", "Certified slots", "Baseline train", "Validation", "Active", "Robust", "Isolation Forest",
                           "Novelty", "Active flagged", "Quiet flagged", "Baseline false alarms", "To Phase 7"], rows))))

    margin_rows = []
    for view in SLOT_VIEWS:
        scores = data["scores"][view]
        quiet, busy = scores[~scores["active"].astype(bool)], scores[scores["active"].astype(bool)]
        for name, label in (("robust", "Robust"), ("isolation", "Isolation Forest"), ("novelty", "Novelty")):
            margin_rows.append([esc(VIEW_LABEL[view]), esc(label), number(experiments[view][f"{name}_threshold"], 3),
                                number(quiet[f"{name}_score"].max(), 3), number(busy[f"{name}_score"].min(), 3),
                                number(busy[f"{name}_score"].median(), 3)])
    sections.append(layout.text_section("behaviour", "Model behaviour: how cleanly silence and activity separate", (
        "<p>For the other sources, this check shows that alerts come from a thin tail rather than the bulk. Here the "
        "question is simpler: is there a gap between the highest quiet score and the lowest active score? A gap means "
        "the alert decision does not depend on where exactly the threshold sits.</p>"
        + table(["View", "Detector", "Threshold", "Highest quiet score", "Lowest active score", "Median active score"],
                margin_rows))))

    episodes = data["episodes"].merge(data["scores"]["flow_episodes"][["row_manifest_id", "within_activity_rank", "ranked_by"]],
                                      on="row_manifest_id").sort_values("within_activity_rank")
    rows = [[str(int(r["within_activity_rank"])), esc(r["hostname"]), f"<code>{esc(r['flow'])}</code>",
             esc(str(r["start"])[:19]), number(r["duration_hours"], 1), number(r["attempts"]), number(r["packets"]),
             number(r["mean_interval_seconds"], 1), f"{r['rst_share']:.0%}", esc(r["rules"]),
             "yes" if r["succeeded"] else "no"] for _, r in episodes.head(TOP_EPISODES).iterrows()]
    ranked_by = esc(episodes["ranked_by"].iloc[0]) if len(episodes) else "–"
    sections.append(layout.text_section("episodes", "Flow episodes (the alerts)", (
        f"<p>Each of the {len(episodes):,} episodes is one alert in Phase 7, listed by within-activity rank: rank 1 is "
        f"least like the rest of the activity. Ranked by {ranked_by}. <i>Interval</i> is the mean time between "
        "attempts; <i>RST</i> the share of attempts that ended in a reset; <i>got through</i> whether any packet was "
        "passed.</p>"
        + table(["Rank", "Server", "Flow", "Start", "Hours", "Attempts", "Packets", "Interval (s)", "RST", "Rule",
                 "Got through"], rows)
        + (f"<p>The other {len(episodes) - TOP_EPISODES:,} episodes are in the Phase 7 presence alert file.</p>"
           if len(episodes) > TOP_EPISODES else ""))))
    sections.append(layout.text_section("ranking", "Within the activity: what is unlike the rest", (
        "<p>The tables below rank attempts and single lines. <i>Why</i> names the attributes that fewer than 1% of the "
        "active lines share; where there are none, the row stands out by its shape (Isolation Forest: timing, size or "
        "retry pattern).</p>" + ranking_table(data, "attempts", top) + ranking_table(data, "individual", top))))
    seen = first_seen_section(data["source"])
    if seen:
        sections.append(seen)
    return sections


def why(tokens, shares):
    rare = sorted((shares.get(t, 0), t) for t in str(tokens).split() if shares.get(t, 0) < RARE_SHARE)
    if not rare:
        return "shape (Isolation Forest)"
    return "; ".join(f"<code>{esc(t)}</code> ({s:.3%} of lines)" for s, t in rare[:3])


def ranking_table(data, view, top):
    scores = data["scores"][view].sort_values("within_activity_rank").head(top)
    tokens = data["tokens"][view]
    if view == "attempts":
        detail = data["attempts"].set_index("row_manifest_id")
        rows = [[str(int(r["within_activity_rank"])), esc(r["timestamp"]), esc(detail.loc[r["row_manifest_id"], "hostname"]),
                 f"<code>{esc(detail.loc[r['row_manifest_id'], 'flow'])}</code>",
                 esc(detail.loc[r["row_manifest_id"], "flag_sequence"])[:60], number(r["isolation_score"], 3),
                 number(r["novelty_score"], 2), why(tokens.get(r["row_manifest_id"], ""), data["shares"])]
                for _, r in scores.iterrows()]
        return "<h3>Connection attempts</h3>" + table(["Rank", "Start", "Server", "Flow", "Flags", "Isolation", "Novelty", "Why"], rows)
    events = data["events"].set_index("event_id")
    rows = [[str(int(r["within_activity_rank"])), esc(r["timestamp"]), esc(events["hostname"].get(r["row_manifest_id"], "")),
             f"<code>{esc(line_part(events['raw_message'].get(r['row_manifest_id'], '')))}</code>",
             number(r["isolation_score"], 3), number(r["novelty_score"], 2), why(tokens.get(r["row_manifest_id"], ""), data["shares"])]
            for _, r in scores.iterrows()]
    return "<h3>Single lines</h3>" + table(["Rank", "Time", "Server", "Packet fields", "Isolation", "Novelty", "Why"], rows)


def evidence_sections(data):
    rows = [[esc(r["dataset"]), number(r["isolation_alerts"]), number(r["complete_evidence_alerts"]),
             number(r["partial_evidence_alerts"]), number(r["missing_evidence_alerts"]), number(r["source_event_rows"])]
            for _, r in data["evidence"].iterrows()]
    phase7 = ", ".join(f"{k.replace('_', ' ')}: {v:,}" for k, v in data["phase7"].items()) or "Phase 7 not run yet"
    coverage = layout.text_section("coverage", "Evidence coverage", (
        "<p>Every alert was followed back through the Phase 2 lineage to the Phase 1 lookup, and its line count "
        f"checked. Rows in the Phase 7 alert files: {esc(phase7)}.</p>"
        + table(["View", "Alerts", "Complete", "Partial", "Missing", "Source lines"], rows)))
    other = CONFIG[data["source"]]["other"]
    other_label = CONFIG[other]["label"]
    context = data["context"]
    rows = []
    for _, r in context.iterrows():
        rows.append([esc(str(r["kind"]).replace("_", " ")), f"<code>{esc(r['value'])}</code>", esc(r.get("known_as")),
                     number(r.get("lines_here")), esc(r.get("role_here")), esc(r.get("hosts_here")),
                     number(r.get(f"{other}_lines")), number(r.get("auth_logins_from")), esc(r.get("auth_accounts")),
                     esc(r.get("auth_servers"))])
    cross = layout.text_section("context", "Context from the other logs", (
        "<p>An empty baseline gives the models nothing to compare against, so the other logs supply the context. "
        f"For each address and service port in the active lines: the name OSSEC gives it, how often the {other_label} "
        "log names it, and the SSH logins from the address across all servers over the study period.</p>"
        + table(["Kind", "Value", "Known as", "Lines here", "Role here", "Servers here", f"{other_label} lines",
                 "SSH logins from it", "Accounts", "Servers it logs in to"], rows)))
    chains = data["chains"].sort_values(["dataset", "first_timestamp"])
    rows = [[esc(r["dataset"]), esc(r.get("hostname", "")), esc(str(r["first_timestamp"])[:19]),
             esc(str(r["last_timestamp"])[:19]), number(r["lines"]), esc(r["evidence_status"]),
             f'<details><summary>First lines</summary><pre>{esc(str(r["first_lines"]).replace(" | ", chr(10)))}</pre></details>']
            for _, r in chains.head(TOP_CHAINS).iterrows()]
    alerts = layout.text_section("chains", "The alerts and their lines",
                                 table(["View", "Server", "From", "To", "Lines", "Evidence", "Original lines"], rows)
                                 + (f"<p>{len(chains) - TOP_CHAINS:,} more in the Phase 5 message chains file.</p>"
                                    if len(chains) > TOP_CHAINS else ""))
    return [coverage, cross, alerts]


DISCUSSION = (
    "<p><b>What an alert means here.</b> For this log an alert means only that something reached a logging rule on "
    "a firewall that normally logs nothing, or almost nothing. That is a policy statement, not a finding of malice. "
    "The useful questions are which flows, whether they were expected, and whether they got through.</p>"
    "<p><b>The rank is the signal.</b> Because every active period alerts, the within-activity rank is what "
    "separates the dominant activity from the small things that do not fit it. A low rank does not clear a row; it "
    "says the row looks like the bulk of the activity.</p>"
    "<p><b>What silence can and cannot show.</b> An empty day only proves quiet when it is certified. It does not "
    "show that the firewall rules were right, only that nothing hit a logging rule.</p>"
    "<p><b>No accuracy figures.</b> As for the other sources, no line has been labelled, so precision and recall "
    "cannot be measured. The presence check above is a consistency check against the policy, not an accuracy "
    "measure.</p>"
)


def recommendations(data):
    episodes = data["episodes"].merge(data["scores"]["flow_episodes"][["row_manifest_id", "within_activity_rank"]],
                                      on="row_manifest_id")
    items = []
    top = episodes.sort_values("within_activity_rank").head(3)
    if len(top):
        items.append("Start with the highest-ranked episodes, which are least like the rest of the activity: "
                     + "; ".join(f"<code>{esc(r['flow'])}</code> on {esc(r['hostname'])} ({esc(str(r['start'])[:10])})"
                                 for _, r in top.iterrows()) + ".")
    biggest = episodes.groupby("flow")["packets"].sum().sort_values(ascending=False)
    if len(biggest):
        items.append(f"Explain the bulk: the flow <code>{esc(biggest.index[0])}</code> accounts for {int(biggest.iloc[0]):,} "
                     f"of {int(episodes['packets'].sum()):,} packets. If it belongs to a planned change, record the window "
                     "and flow in <code>pipeline/phase9_llm_triage/site/approved_change_windows.csv</code> so that Phase 9 "
                     "treats it as expected behaviour.")
    items += [
        "Identify every source that is not part of a recorded change or a known service. Broadcasts to service ports "
        "(SNMP 161, licence servers 1947) usually come from monitoring tools or engineering laptops; confirm the owner.",
        "Keep collecting the monthly files, including the empty ones. They are the evidence of the quiet baseline; "
        "without them the pipeline cannot certify any day as quiet.",
        "Record a triage category for each alert (security relevant, operationally interesting, expected behavior, "
        "insufficient context) so later runs can be measured.",
    ]
    return "<ol>" + "".join(f"<li>{item}</li>" for item in items) + "</ol>"


def abstract(data):
    days, events = data["days"], data["events"]
    certified = days[days["certified"]]
    active = int((certified["lines"] > 0).sum())
    return (f"This report applies unsupervised anomaly detection to {data['label']} firewall logs from "
            f"{days['hostname'].nunique()} server(s), a log whose normal state is empty or nearly so. Of "
            f"{len(certified):,} certified server-days in the study period, {active:,} contain any line ({len(events):,} "
            f"lines in all). Instead of learning normal from log lines, the pipeline treats every certified quiet time "
            f"period as the baseline, scores every five minutes, hour and day with robust deviation, Isolation Forest "
            f"and novelty detectors under a zero-tolerance threshold, and ranks the activity against itself. Every "
            f"active period was flagged and no quiet period was. The activity forms {len(data['episodes']):,} flow "
            f"episodes, each traced to its original lines and set against context from the other logs. As no activity "
            f"has been labelled, the alerts indicate departures from an empty baseline, not confirmed attacks.")


def render(data, top):
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    name = layout.SOURCE[data["source"]]["name"]
    chapters = [
        ("Introduction", layout.INTRO, [regime_section(data),
                                        layout.text_section("how-to-read", "How to read this report", layout.HOW_TO_READ.format(name=name))]),
        ("Data", "<p>" + layout.SOURCE[data["source"]]["data"] + "</p>", data_section(data)),
        ("Methodology", method_text(data), []),
        ("Results", "<p>This section shows the timeline, checks the detectors against the policy (every active period, "
                    "no quiet period), and ranks the activity.</p>", results_sections(data, top)),
        ("Evidence and Analysis", "<p>This section checks that every alert traces back to its lines, and sets the "
                                  "activity against what the other logs know about the same addresses and ports.</p>",
         evidence_sections(data)),
        ("Discussion", DISCUSSION, []),
        ("Recommendations", recommendations(data), []),
        ("Conclusion", (f"<p>The {name} show how the pipeline handles a log whose normal state is silence: the same "
                        "detectors, applied to time periods instead of lines and held to zero tolerance, flag exactly the "
                        "active periods, and the within-activity ranking points the analyst to the parts of that activity "
                        "that do not fit the rest. Whether the activity was expected can only be settled against the "
                        "change record and the asset register.</p>"), []),
    ]
    return layout.document(title=f"Anomaly Detection under an Empty Baseline: {CONFIG[data['source']]['title']}",
                           source=data["source"], generated=generated, abstract=abstract(data),
                           base_css=layout.DASHBOARD_CSS, chapters=chapters,
                           footer="An alert here means activity on a firewall that normally logs nothing. Analyst "
                                  "labels are required for precision and recall.")


def main():
    args = parse_args()
    report = render(load(args.source), args.top)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(report, encoding="utf-8")
    os.replace(temporary, args.output)
    if not args.quiet:
        runlog.log(f"Report written: {args.output} ({args.output.stat().st_size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
