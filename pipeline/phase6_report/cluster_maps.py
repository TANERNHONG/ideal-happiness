"""Phase 6, shared by all three reports: the Phase 4 model-zoo cluster maps.

Phase 4c draws each view's test observations on a two-dimensional t-SNE map
(pipeline/phase4_detection/model_zoo_map.py). This embeds those images in the
report (so it stays one offline file), links the larger interactive versions,
and adds a small table per map from its projection CSV: points shown, rows any
model flagged, ensemble alerts, and the category that holds most ensemble alerts.
"""
from __future__ import annotations

import base64
import html
import os
from pathlib import Path

import pandas as pd

from timeline_map import render_timeline_map

LABELS = {
    "individual": "single events", "authentication_sessions": "SSH sessions", "sessions": "firewall conversations",
    "host_5min": "5-minute windows per server", "entity_5min": "5-minute windows per address",
    "host_behavior_1d": "daily behaviour per server", "behavior_1d": "daily behaviour per source address",
    "episodes": "agent episodes",
}
HOW_TO_READ = (
    "<p>Each dot is one observation from the test period, placed by t-SNE [7] so that observations with similar "
    "features sit close together. The map shows the observations that at least one model flagged (at most "
    "10,000, highest agreement first, so the counts below are capped there), plus a random sample of unflagged "
    "ones as the normal background. <b>Left panel:</b> grey dots were not flagged, coloured "
    "dots were flagged by one or more model-zoo models (darker means more models), blue crosses are ensemble "
    "alerts, and red rings mark rows where three or more models agree. <b>Right panel:</b> the same map, coloured "
    "by a category such as the server or the event type, named in its title.</p>"
    "<p><b>What to look for.</b> Alerts that form their own islands are whole kinds of activity the models find "
    "rare; alerts scattered through normal clusters are single odd observations. If the alert islands line up "
    "with one category in the right panel, the models may be flagging that category rather than unusual "
    "behaviour, which is worth checking during review. Only closeness is meaningful: the distances between "
    "islands and their sizes are not.</p>"
)


def esc(value):
    return html.escape(str(value), quote=True)


def truthy(series):
    return series.astype(str).str.strip().str.lower().isin({"1", "true", "yes", "1.0"})


def map_stats(csv_path):
    try:
        frame = pd.read_csv(csv_path, usecols=lambda column: column in {"votes", "ensemble_alert", "category"},
                            low_memory=False)
    except (OSError, ValueError):
        return None
    alerts = truthy(frame["ensemble_alert"]) if "ensemble_alert" in frame else pd.Series(False, index=frame.index)
    flagged = pd.to_numeric(frame.get("votes", 0), errors="coerce").fillna(0).gt(0) | alerts
    top, share = "", None
    if alerts.any() and "category" in frame:
        counts = frame.loc[alerts, "category"].astype(str).value_counts()
        top, share = counts.index[0], counts.iloc[0] / alerts.sum()
    return {"points": len(frame), "flagged": int(flagged.sum()), "alerts": int(alerts.sum()), "top": top, "share": share}


def render_section(map_folder, report_path, source_label):
    """Section HTML with one figure per view; empty-state section if no maps exist."""
    map_folder = Path(map_folder)
    images = sorted(map_folder.glob("*/*/projection_*.png")) if map_folder.is_dir() else []
    images = [path for path in images if not path.stem.endswith("_per_model")]
    if not images:
        globals()["_FIGURES_SO_FAR"] = 0
        return ('<section id="clusters"><h2>Model-zoo cluster maps</h2><div class="empty">No Phase 4c maps found; run '
                'the pipeline with --with-model-zoo.</div></section>')
    global _FIGURES_SO_FAR
    figures, rows = [], []
    _FIGURES_SO_FAR = len(images)
    for number, image in enumerate(images, start=1):
        view, feature_set = image.parent.parent.name, image.parent.name
        method = {"tsne": "t-SNE", "pca": "PCA", "umap": "UMAP"}.get(image.stem.split("_", 1)[-1], "2-D")
        label = LABELS.get(view, view.replace("_", " "))
        encoded = base64.b64encode(image.read_bytes()).decode("ascii")
        interactive = image.with_suffix(".html")
        link = ""
        if interactive.is_file():
            relative = os.path.relpath(interactive, Path(report_path).parent).replace(os.sep, "/")
            link = f' <a href="{esc(relative)}">Open the interactive map</a> (hover to see each row).'
        stats = map_stats(image.with_suffix(".csv"))
        figures.append(
            f'<figure class="cluster-figure"><img src="data:image/png;base64,{encoded}" alt="{esc(method)} map of '
            f'{esc(label)}: flagged observations against a normal background" style="width:100%;height:auto">'
            f'<figcaption><b>Fig. {number}.</b> {esc(source_label)} {esc(label)} ({esc(view)}, {esc(feature_set)} '
            f'features), {esc(method)} projection of the test period.{link}</figcaption></figure>')
        if stats:
            concentration = (f"{esc(stats['top'])} ({stats['share']:.0%})" if stats["share"] is not None else "–")
            rows.append(f"<tr><td>Fig. {number}</td><td>{esc(label)}</td><td>{stats['points']:,}</td>"
                        f"<td>{stats['flagged']:,}</td><td>{stats['alerts']:,}</td><td>{concentration}</td></tr>")
    table = ('<div class="table-wrap"><table><thead><tr><th>Figure</th><th>View</th><th>Points shown</th>'
             '<th>Flagged by any model</th><th>Ensemble alerts</th><th>Category holding most ensemble alerts</th>'
             '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>') if rows else ""
    return (f'<section id="clusters"><h2>Model-zoo cluster maps</h2>{HOW_TO_READ}{table}'
            '<style>.cluster-figure{margin:18px 0 26px;border:1px solid #ccc;border-radius:4px;padding:10px;background:#fff}'
            '.cluster-figure figcaption{font-size:.95rem;margin-top:6px;text-align:justify}</style>'
            + "".join(figures) + "</section>")


# --- Phase 7b behavioural clusters ------------------------------------------------

_FIGURES_SO_FAR = 0          # figure numbers continue after the Phase 4c maps
CLUSTERS_INTRO = (
    "<p>Phase 7b turns each map into <b>behavioural clusters</b>: every island is given a number, and every "
    "observation in the test period, not only the sample drawn on the map, is assigned to the island of its "
    "nearest mapped neighbours. A cluster is a group of observations that look alike to the models, so an "
    "analyst can review one cluster at a time instead of one alert at a time. Cluster <code>#0</code> holds "
    "isolated points that belong to no island. <b>Red numbers</b> on the map mark clusters in which most "
    "observations were flagged.</p>"
    "<p><b>Replaying the map over time.</b> The map now covers the whole study period: besides the test period, it "
    "holds about the same number of observations from every earlier month. Press <i>Play</i> or drag the slider to "
    "bring the points in month by month (or week by week). In <i>Cumulative</i> mode the newest period is bright "
    "and earlier ones are faded, so you can see when an island first appears, whether it grows steadily or "
    "arrives all at once, and whether flagged points arrive inside existing islands or as new ones. Clusters "
    "are still assigned to the test-period observations, which are the ones that raise alerts.</p>"
    "<p>The table lists the clusters with the most flagged observations. <i>Lift</i> is how many times more often "
    "a cluster is flagged than its view as a whole. A cluster is a grouping aid, not a verdict, and its number "
    "is only valid for the map it was drawn from.</p>"
)
SERVER_COLUMNS = ("top_hostname", "top_host_id", "top_agent_name", "top_entity_id", "top_source_ip")
EVENT_COLUMNS = ("top_event_type", "top_dominant_event_type", "top_first_event_type", "top_episode_family",
                 "top_event_category", "top_service_port", "top_protocol")
USER_COLUMNS = ("top_username", "top_dominant_username", "top_source_ip", "top_dominant_source_ip", "top_destination_ip")


def _first(row, columns, used=()):
    for column in columns:
        value = row.get(column)
        if column not in used and isinstance(value, str) and value.strip():
            return column, value
    return None, ""


def render_clusters_section(cluster_folder, map_folder, source_label, top=12):
    """Phase 7b cluster maps and the clusters most worth reviewing, per view."""
    import json
    cluster_folder, map_folder = Path(cluster_folder), Path(map_folder)
    views = sorted(path.parent for path in cluster_folder.glob("*/cluster_summary.csv")) if cluster_folder.is_dir() else []
    if not views:
        return ('<section id="behavioural-clusters"><h2>Behavioural clusters</h2><div class="empty">Phase 7b has not '
                'run for this source yet: python run_pipeline.py --source … --only-phase 7b --with-model-zoo'
                '</div></section>')
    run = {}
    if (cluster_folder / "run.json").is_file():
        run = json.loads((cluster_folder / "run.json").read_text(encoding="utf-8"))
    number = _FIGURES_SO_FAR
    parts = [f'<section id="behavioural-clusters"><h2>Behavioural clusters</h2>{CLUSTERS_INTRO}']
    if run:
        parts.append(f'<p class="lead">Phase 7b run {esc(run.get("created", ""))}; smallest island '
                     f'{esc(run.get("min_cluster_share", ""))} of the mapped points.</p>')
    for folder in views:
        view = folder.name
        label = LABELS.get(view, view.replace("_", " "))
        summary = pd.read_csv(folder / "cluster_summary.csv")
        info = (run.get("views") or {}).get(view, {}) if isinstance(run.get("views"), dict) else {}
        stale = ""
        projection = next(iter(sorted(map_folder.glob(f"{view}/*/projection_tsne.csv"))), None)
        if projection and (folder / "cluster_map.png").is_file() and projection.stat().st_mtime > (folder / "cluster_map.png").stat().st_mtime:
            stale = ('<p class="finding warning"><b>These clusters are older than the current map.</b> Re-run '
                     'Phase 7b so the cluster numbers match.</p>')
        parts.append(f'<h3 style="margin-top:22px">{esc(source_label)} {esc(label)} ({esc(view)})</h3>{stale}')
        facts = [f"{int(summary['rows'].sum()):,} test observations in {len(summary)} clusters",
                 f"{int((summary['alert_rate'] > 0.5).sum())} clusters mostly flagged"]
        if info.get("neighbour_check") is not None:
            facts.append(f"neighbour check {info['neighbour_check']:.1%} (how often a mapped point's neighbours "
                         "give back its own island)")
        parts.append("<p>" + "; ".join(facts) + ".</p>")
        image = folder / "cluster_map.png"
        points = folder / "map_points.csv"
        if points.is_file():
            number += 1
            parts.append(render_timeline_map(points, folder / "cluster_summary.csv",
                                             f"Behavioural clusters of {source_label} {label}", number))
            if image.is_file():
                encoded = base64.b64encode(image.read_bytes()).decode("ascii")
                parts.append(f'<details><summary>Static version with cluster numbers</summary><img '
                             f'src="data:image/png;base64,{encoded}" alt="Behavioural clusters of {esc(label)}, each '
                             f'island numbered" style="width:100%;height:auto"></details>')
        elif image.is_file():
            number += 1
            encoded = base64.b64encode(image.read_bytes()).decode("ascii")
            parts.append(f'<figure class="cluster-figure"><img src="data:image/png;base64,{encoded}" alt="Behavioural '
                         f'clusters of {esc(label)}, each island numbered" style="width:100%;height:auto">'
                         f'<figcaption><b>Fig. {number}.</b> Behavioural clusters of {esc(source_label)} '
                         f'{esc(label)}. Numbers are cluster IDs ({esc(view)}#N); red numbers mark clusters that are '
                         f'mostly flagged.</figcaption></figure>')
        flagged = summary[summary["flagged_rows"] > 0].sort_values(["flagged_rows", "alert_rate"], ascending=False).head(top)
        table = []
        for _, row in flagged.iterrows():
            row = row.to_dict()
            server_column, server = _first(row, SERVER_COLUMNS)
            _, event = _first(row, EVENT_COLUMNS)
            _, user = _first(row, USER_COLUMNS, used=(server_column,))
            first, last = str(row.get("first_seen") or "")[:10], str(row.get("last_seen") or "")[:10]
            seen = "" if first in ("", "nan") else (first if first == last else f"{first} – {last[5:] if last[:4] == first[:4] else last}")
            table.append((row, server, event, user, seen))
        if table:
            show_user = any(user for _, _, _, user, _ in table)
            show_first = "first_month_on_map" in summary.columns
            header = ("<th>Cluster</th><th>Observations</th><th>Flagged</th><th>Alert rate</th><th>Lift</th>"
                      "<th>Main server or source</th><th>Main event</th>"
                      + ("<th>Main user or address</th>" if show_user else "") + "<th>Seen</th>"
                      + ("<th>First on the map</th>" if show_first else ""))
            body = "".join(
                f"<tr><td><b>{esc(row['cluster_id'])}</b></td><td>{int(row['rows']):,}</td>"
                f"<td>{int(row['flagged_rows']):,}</td><td>{row['alert_rate']:.0%}</td>"
                f"<td>{row['lift_vs_view']:,.1f}×</td><td>{esc(server)}</td><td>{esc(event)}</td>"
                + (f"<td>{esc(user)}</td>" if show_user else "")
                + f'<td style="white-space:nowrap">{esc(seen)}</td>'
                + (f'<td style="white-space:nowrap">{esc(row.get("first_month_on_map") or "")}</td>' if show_first else "")
                + "</tr>"
                for row, server, event, user, seen in table)
            parts.append(f'<div class="table-wrap"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>')
        parts.append(f'<p class="lead">All {len(summary)} clusters, with example log lines: '
                     f'<code>{esc(str(folder / "cluster_summary.csv"))}</code>.</p>')
    parts.append("</section>")
    return "".join(parts)
