"""Phase 6, shared by all three reports: do the detectors behave like detectors?

An anomaly detector should give most rows an ordinary score and a thin tail of
rows an extreme one, and only that tail should become alerts. The Phase 7
``probability`` column is each alert's percentile within its run, so it is
above 0.99 by construction; it says how deep in the tail an alert sits, not
how confident a model is. This section shows the whole distribution instead,
from every scored row of the validation and test periods (Phase 4 fits on a
training sample and does not save training-period scores):

* score histogram per detector, validation and test overlaid, log count axis,
  threshold marked, share of rows above it;
* the tail curve: score against "share of rows scoring higher", which is where
  the Phase 7 probability comes from;
* how many detectors flag each test row (0, 1, 2 or 3);
* alerts per day in the test period against the validation average;
* validation versus test alert rate per detector (a drift check);
* model zoo: ensemble members' votes per row, ensemble score histogram and
  each model's alert rate.

Score files reach several GB, so the summaries are cached in a JSON file beside
the report, keyed by each input file's size and modification time.

    from model_behaviour import collect, render_section
    results = collect(detectors_folder, zoo_folder, "selected", cache_path)
    html_section = render_section(results, "Authentication")
"""
from __future__ import annotations

import html
import json
import math
import os
from pathlib import Path

import numpy as np
import pandas as pd

DETECTORS = (("isolation", "Isolation Forest"), ("novelty", "Novelty"), ("robust", "Robust deviation"))
SPLITS = ("validation", "test")
TIME_CANDIDATES = ("timestamp", "session_start", "window_start", "episode_start", "first_timestamp",
                   "event_timestamp", "observation_timestamp")
BINS = 60
TAIL_POINTS = 120
CHUNK_ROWS = 500_000
CACHE_VERSION = 1
COLOURS = {"validation": "#94a3b8", "test": "#2563eb", "threshold": "#dc2626", "bar": "#2563eb",
           "reference": "#f59e0b", "member": "#0f766e"}

CSS = (".mb .mb-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px;margin:12px 0}"
       ".mb svg{width:100%;height:auto}.mb .t{font-size:15px;font-weight:800;fill:#172033}"
       ".mb .a{font-size:11px;fill:#5f6b7d}.mb .v{font-size:11px;font-weight:700;fill:#172033}"
       ".mb .n{font-size:12px;fill:#172033}.mb details{margin:14px 0}.mb details>summary{font-size:1.1rem;padding:6px 0}"
       ".mb .how{columns:2;column-gap:28px}.mb .how li{margin-bottom:6px}.mb .ok{color:#166534;font-weight:700}"
       ".mb .warn{color:#92400e;font-weight:700}@media(max-width:1000px){.mb .how{columns:1}}")


def esc(value):
    return html.escape(str(value), quote=True)


# --- reading -------------------------------------------------------------------


def signature(path):
    stat = Path(path).stat()
    return [stat.st_size, stat.st_mtime_ns]


def truthy(series):
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False).to_numpy()
    return series.astype(str).str.strip().str.lower().isin({"1", "true", "yes", "1.0"}).to_numpy()


def day_keys(series):
    """YYYY-MM-DD from ISO or OSSEC-style (YYYY/MM/DD) timestamps, without a full parse."""
    text = series.astype(str).str.slice(0, 10).str.replace("/", "-", regex=False)
    return text.where(text.str.match(r"^\d{4}-\d{2}-\d{2}$"))


def read_chunks(path, wanted):
    header = pd.read_csv(path, nrows=0).columns
    columns = [column for column in wanted if column in header]
    time_column = next((column for column in TIME_CANDIDATES if column in header), None)
    if time_column and time_column not in columns:
        columns.append(time_column)
    for chunk in pd.read_csv(path, usecols=columns, chunksize=CHUNK_ROWS, low_memory=False,
                             dtype={time_column: str} if time_column else None):
        yield chunk, time_column


def histogram(values_by_split):
    finite = [values[np.isfinite(values)] for values in values_by_split.values()]
    finite = [values for values in finite if values.size]
    if not finite:
        return None
    low = float(min(values.min() for values in finite))
    high = float(max(values.max() for values in finite))
    if high <= low:
        high = low + 1.0
    edges = np.linspace(low, high, BINS + 1)
    return {"edges": edges.round(6).tolist(),
            "counts": {split: np.histogram(values[np.isfinite(values)], edges)[0].astype(int).tolist()
                       for split, values in values_by_split.items()}}


def tail_curve(values):
    """Score at each 'share of rows scoring higher', from 100% down to one row."""
    values = np.sort(values[np.isfinite(values)])[::-1]
    if not values.size:
        return None
    fractions = np.unique(np.concatenate([np.logspace(0, -math.log10(values.size), TAIL_POINTS), [1 / values.size]]))
    indices = np.clip(np.ceil(fractions * values.size).astype(int) - 1, 0, values.size - 1)
    return {"fractions": fractions[::-1].tolist(), "scores": values[indices[::-1]].round(6).tolist()}


def summarise_detector_run(folder):
    """Validation and test score behaviour of one Phase 4 detector run."""
    folder = Path(folder)
    paths = {split: folder / f"{split}_scores.csv" for split in SPLITS}
    if not paths["test"].is_file():
        return None
    summary = {}
    if (folder / "summary.json").is_file():
        summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    wanted = [f"{name}_{kind}" for name, _ in DETECTORS for kind in ("score", "alert")]
    scores = {name: {} for name, _ in DETECTORS}
    alerts = {name: {} for name, _ in DETECTORS}
    rows, agreement, daily = {}, [0, 0, 0, 0], {}
    present = set()
    for split, path in paths.items():
        if not path.is_file():
            continue
        parts = {name: [] for name, _ in DETECTORS}
        flagged = {name: 0 for name, _ in DETECTORS}
        rows[split] = 0
        days = {}
        for chunk, time_column in read_chunks(path, wanted):
            rows[split] += len(chunk)
            votes = np.zeros(len(chunk), dtype=np.int8)
            for name, _ in DETECTORS:
                if f"{name}_score" not in chunk:
                    continue
                present.add(name)
                parts[name].append(pd.to_numeric(chunk[f"{name}_score"], errors="coerce").to_numpy(np.float32))
                if f"{name}_alert" in chunk:
                    hit = truthy(chunk[f"{name}_alert"])
                    flagged[name] += int(hit.sum())
                    votes += hit.astype(np.int8)
            if split == "test":
                for level in range(4):
                    agreement[level] += int((votes == level).sum())
            if time_column:
                keys = day_keys(chunk[time_column])
                frame = pd.DataFrame({"day": keys, "alert": votes > 0}).dropna(subset=["day"])
                grouped = frame.groupby("day")["alert"].agg(["size", "sum"])
                for day, (size, hits) in grouped.iterrows():
                    total = days.setdefault(day, [0, 0])
                    total[0] += int(size)
                    total[1] += int(hits)
        daily[split] = {day: days[day] for day in sorted(days)}
        for name, _ in DETECTORS:
            scores[name][split] = np.concatenate(parts[name]) if parts[name] else np.zeros(0, np.float32)
            alerts[name][split] = flagged[name]
    detectors = {}
    for name, label in DETECTORS:
        hist = histogram(scores[name]) if name in present else None
        if hist is None:          # detector not used for this view (no finite scores)
            continue
        threshold = summary.get(f"{name}_threshold")
        threshold = float(threshold) if isinstance(threshold, (int, float)) and math.isfinite(threshold) else None
        detectors[name] = {
            "label": label, "threshold": threshold,
            "threshold_source": summary.get(f"{name}_threshold_source", ""),
            "histogram": hist,
            "tail": tail_curve(scores[name].get("test", np.zeros(0))),
            "alerts": alerts[name],
        }
    return {"name": folder.name, "rows": rows, "detectors": detectors, "agreement": agreement,
            "daily": daily, "target_per_day": summary.get("target_alerts_per_day")}


def summarise_zoo_run(folder):
    """Validation and test behaviour of one model-zoo run (one dataset, one feature set)."""
    folder = Path(folder)
    paths = {split: folder / f"{split}_scores.csv" for split in SPLITS}
    if not paths["test"].is_file():
        return None
    info = {}
    if (folder / "dataset_summary.json").is_file():
        info = json.loads((folder / "dataset_summary.json").read_text(encoding="utf-8"))
    header = pd.read_csv(paths["test"], nrows=0).columns
    models = [column[:-6] for column in header if column.endswith("_alert")
              and column not in ("model_zoo_ensemble_alert", "any_member_alert") and f"{column[:-6]}_score" in header]
    members = [model for model in (info.get("ensemble_members") or []) if model in models]
    wanted = [f"{model}_alert" for model in models] + ["model_zoo_ensemble_score", "model_zoo_ensemble_alert",
                                                        "member_vote_count"]
    rows, model_alerts, votes, ensemble, ensemble_alerts, threshold = {}, {}, {}, {}, {}, None
    for split, path in paths.items():
        if not path.is_file():
            continue
        rows[split] = 0
        model_alerts[split] = {model: 0 for model in models}
        vote_counts = np.zeros(len(models) + 1, dtype=np.int64)
        parts, flagged = [], 0
        for chunk, _ in read_chunks(path, wanted):
            rows[split] += len(chunk)
            for model in models:
                if f"{model}_alert" in chunk:
                    model_alerts[split][model] += int(truthy(chunk[f"{model}_alert"]).sum())
            if "member_vote_count" in chunk:
                counts = pd.to_numeric(chunk["member_vote_count"], errors="coerce").fillna(0).astype(int).clip(0, len(models))
                vote_counts += np.bincount(counts, minlength=len(models) + 1)[:len(models) + 1]
            if "model_zoo_ensemble_score" in chunk:
                score = pd.to_numeric(chunk["model_zoo_ensemble_score"], errors="coerce").to_numpy(np.float32)
                parts.append(score)
                if "model_zoo_ensemble_alert" in chunk:
                    hit = truthy(chunk["model_zoo_ensemble_alert"])
                    flagged += int(hit.sum())
                    if hit.any():
                        low = float(np.nanmin(score[hit]))
                        threshold = low if threshold is None else min(threshold, low)
        votes[split] = vote_counts[:max(len(members), 1) + 1].tolist()
        ensemble[split] = np.concatenate(parts) if parts else np.zeros(0, np.float32)
        ensemble_alerts[split] = flagged
    return {"name": f"{folder.parent.name} ({folder.name} features)", "rows": rows, "models": models,
            "members": members, "model_alerts": model_alerts, "votes": votes, "ensemble_alerts": ensemble_alerts,
            "ensemble_threshold": threshold, "ensemble_histogram": histogram(ensemble)}


def collect(detectors_folder, zoo_folder=None, zoo_feature_set="selected", cache_path=None, log=print):
    """Summaries for every detector run and model-zoo run, reusing the cache where inputs are unchanged."""
    cache = {}
    if cache_path and Path(cache_path).is_file():
        try:
            cache = json.loads(Path(cache_path).read_text(encoding="utf-8"))
        except ValueError:
            cache = {}
    if cache.get("version") != CACHE_VERSION:
        cache = {"version": CACHE_VERSION, "runs": {}}
    jobs = []
    if detectors_folder and Path(detectors_folder).is_dir():
        jobs += [("detector", folder) for folder in sorted(Path(detectors_folder).iterdir())
                 if (folder / "test_scores.csv").is_file()]
    if zoo_folder and Path(zoo_folder).is_dir():
        for dataset in sorted(path for path in Path(zoo_folder).iterdir() if path.is_dir()):
            folder = next((dataset / name for name in (zoo_feature_set, "selected", "full")
                           if (dataset / name / "test_scores.csv").is_file()), None)
            if folder:
                jobs.append(("zoo", folder))
    results = {"detector": [], "zoo": []}
    for kind, folder in jobs:
        key = f"{kind}:{Path(folder).resolve()}"
        files = {split: str(Path(folder) / f"{split}_scores.csv") for split in SPLITS
                 if (Path(folder) / f"{split}_scores.csv").is_file()}
        stamp = {split: signature(path) for split, path in files.items()}
        entry = cache["runs"].get(key)
        if entry and entry.get("stamp") == stamp:
            results[kind].append(entry["result"])
            continue
        size = sum(value[0] for value in stamp.values()) / 1e6
        log(f"Model behaviour: reading {kind} scores in {folder} ({size:,.0f} MB)")
        result = summarise_detector_run(folder) if kind == "detector" else summarise_zoo_run(folder)
        if result:
            results[kind].append(result)
            cache["runs"][key] = {"stamp": stamp, "result": result}
    if cache_path:
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(str(cache_path) + ".tmp")
        temporary.write_text(json.dumps(cache), encoding="utf-8")
        os.replace(temporary, cache_path)
    return results


# --- drawing -------------------------------------------------------------------

W, H = 640, 300
LEFT, RIGHT, TOP, BOTTOM = 62, 18, 44, 52


def fmt(value, digits=3):
    if value is None or not math.isfinite(value):
        return "–"
    if value != 0 and (abs(value) >= 1e4 or abs(value) < 1e-3):
        return f"{value:.2e}"
    return f"{value:,.{digits}g}"


def pct(part, whole):
    return f"{100 * part / whole:.4g}%" if whole else "–"


def svg_open(title, subtitle=""):
    return [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}">',
            f'<text x="0" y="18" class="t">{esc(title)}</text>',
            f'<text x="0" y="34" class="a">{esc(subtitle)}</text>' if subtitle else ""]


def log_axis(out, maximum, plot_h):
    top_power = max(1, math.ceil(math.log10(maximum + 1)))
    for power in range(top_power + 1):
        y = TOP + plot_h - plot_h * power / top_power
        out.append(f'<line x1="{LEFT}" y1="{y:.1f}" x2="{W-RIGHT}" y2="{y:.1f}" stroke="#e5e7eb"/>')
        label = f"{10**power:,}" if power < 7 else f"1e{power}"
        out.append(f'<text x="{LEFT-6}" y="{y+4:.1f}" text-anchor="end" class="a">{label}</text>')
    return top_power


def histogram_svg(title, hist, threshold, subtitle, splits=SPLITS):
    if not hist:
        return '<div class="empty">No scores</div>'
    edges, counts = hist["edges"], hist["counts"]
    plot_w, plot_h = W - LEFT - RIGHT, H - TOP - BOTTOM
    maximum = max(max(values) for values in counts.values() if values) or 1
    out = svg_open(title, subtitle)
    top_power = log_axis(out, maximum, plot_h)
    low, high = edges[0], edges[-1]
    def x(value):
        return LEFT + (value - low) / (high - low) * plot_w
    def y(count):
        return TOP + plot_h - plot_h * math.log10(count + 1) / top_power
    for split in splits:
        values = counts.get(split)
        if not values:
            continue
        points = [f"M{x(edges[0]):.1f},{TOP+plot_h:.1f}"]
        for index, count in enumerate(values):
            points += [f"L{x(edges[index]):.1f},{y(count):.1f}", f"L{x(edges[index+1]):.1f},{y(count):.1f}"]
        points.append(f"L{x(edges[-1]):.1f},{TOP+plot_h:.1f}")
        if split == "test":
            out.append(f'<path d="{" ".join(points)}Z" fill="{COLOURS["test"]}" fill-opacity=".35" stroke="{COLOURS["test"]}" stroke-width="1.5"/>')
        else:
            out.append(f'<path d="{" ".join(points)}" fill="none" stroke="{COLOURS["validation"]}" stroke-width="2"/>')
    if threshold is not None and low <= threshold <= high:
        tx = x(threshold)
        out += [f'<line x1="{tx:.1f}" y1="{TOP}" x2="{tx:.1f}" y2="{TOP+plot_h}" stroke="{COLOURS["threshold"]}" stroke-width="2" stroke-dasharray="6 4"/>',
                f'<text x="{min(tx+5, W-RIGHT-90):.1f}" y="{TOP+12}" class="v" fill="{COLOURS["threshold"]}">alert threshold</text>']
    for tick in range(5):
        value = low + (high - low) * tick / 4
        out.append(f'<text x="{x(value):.1f}" y="{TOP+plot_h+16}" text-anchor="middle" class="a">{fmt(value)}</text>')
    out.append(f'<text x="{LEFT+plot_w/2:.1f}" y="{H-8}" text-anchor="middle" class="a">score (higher = more unusual) · rows per bin, log scale</text>')
    out += [f'<rect x="{W-RIGHT-190}" y="6" width="12" height="12" fill="{COLOURS["test"]}" fill-opacity=".5"/>',
            f'<text x="{W-RIGHT-174}" y="16" class="a">test</text>',
            f'<line x1="{W-RIGHT-130}" y1="12" x2="{W-RIGHT-112}" y2="12" stroke="{COLOURS["validation"]}" stroke-width="2"/>',
            f'<text x="{W-RIGHT-106}" y="16" class="a">validation</text>', "</svg>"]
    return "".join(out)


def tail_svg(title, tail, threshold, alert_share):
    if not tail:
        return '<div class="empty">No scores</div>'
    fractions, scores = tail["fractions"], tail["scores"]
    plot_w, plot_h = W - LEFT - RIGHT, H - TOP - BOTTOM
    low_power = math.floor(math.log10(min(fractions)))
    low, high = min(scores), max(scores)
    if high <= low:
        high = low + 1
    def x(fraction):
        return LEFT + plot_w * (0 - math.log10(fraction)) / (0 - low_power)
    def y(score):
        return TOP + plot_h - (score - low) / (high - low) * plot_h
    subtitle = "Phase 7 rank = 1 − share of rows scoring higher"
    out = svg_open(title, subtitle)
    if alert_share:
        ax = x(max(alert_share, 10 ** low_power))
        out.append(f'<rect x="{ax:.1f}" y="{TOP}" width="{LEFT+plot_w-ax:.1f}" height="{plot_h}" fill="{COLOURS["threshold"]}" fill-opacity=".08"/>')
        out.append(f'<text x="{min(ax+5, W-RIGHT-70):.1f}" y="{TOP+plot_h-8}" class="v" fill="{COLOURS["threshold"]}">alerts</text>')
    for power in range(0, low_power - 1, -1):
        px = x(10 ** power)
        label = f"{10**power*100:g}%"
        out += [f'<line x1="{px:.1f}" y1="{TOP}" x2="{px:.1f}" y2="{TOP+plot_h}" stroke="#e5e7eb"/>',
                f'<text x="{px:.1f}" y="{TOP+plot_h+16}" text-anchor="middle" class="a">{label}</text>']
    for tick in range(5):
        value = low + (high - low) * tick / 4
        out.append(f'<text x="{LEFT-6}" y="{y(value)+4:.1f}" text-anchor="end" class="a">{fmt(value)}</text>')
    path = " ".join(("M" if i == 0 else "L") + f"{x(f):.1f},{y(s):.1f}" for i, (f, s) in enumerate(zip(fractions, scores)))
    out.append(f'<path d="{path}" fill="none" stroke="{COLOURS["test"]}" stroke-width="2.5"/>')
    if threshold is not None and low <= threshold <= high:
        out.append(f'<line x1="{LEFT}" y1="{y(threshold):.1f}" x2="{W-RIGHT}" y2="{y(threshold):.1f}" stroke="{COLOURS["threshold"]}" stroke-width="2" stroke-dasharray="6 4"/>')
    out.append(f'<text x="{LEFT+plot_w/2:.1f}" y="{H-8}" text-anchor="middle" class="a">share of test rows scoring at least this high (log scale)</text></svg>')
    return "".join(out)


def bars_svg(title, items, subtitle="", log=False, colour=None, total=None):
    items = [(str(label), float(value)) for label, value in items]
    if not items:
        return '<div class="empty">No data</div>'
    step = 26
    height = TOP + len(items) * step + 12
    left, right = 170, 130
    plot_w = W - left - right
    maximum = max(value for _, value in items) or 1
    scale = (lambda v: math.log10(v + 1) / math.log10(maximum + 1)) if log else (lambda v: v / maximum)
    out = [f'<svg viewBox="0 0 {W} {height}" role="img" aria-label="{esc(title)}">',
           f'<text x="0" y="18" class="t">{esc(title)}</text>',
           f'<text x="0" y="34" class="a">{esc(subtitle)}</text>' if subtitle else ""]
    for index, (label, value) in enumerate(items):
        y = TOP + index * step
        bar = plot_w * scale(value) if value else 0
        shown = f"{value:,.0f}" + (f" ({pct(value, total)})" if total else "")
        out += [f'<text x="{left-8}" y="{y+14}" text-anchor="end" class="n">{esc(label[:26])}</text>',
                f'<rect x="{left}" y="{y+2}" width="{plot_w}" height="16" rx="4" fill="#eef2f7"/>',
                f'<rect x="{left}" y="{y+2}" width="{max(bar, 1 if value else 0):.1f}" height="16" rx="4" fill="{colour or COLOURS["bar"]}"/>',
                f'<text x="{left+bar+6:.1f}" y="{y+14}" class="v">{esc(shown)}</text>']
    out.append("</svg>")
    return "".join(out)


def daily_svg(title, daily, reference, target):
    days = list(daily.items())
    if not days:
        return '<div class="empty">No timestamps</div>'
    plot_w, plot_h = W - LEFT - RIGHT, H - TOP - BOTTOM
    counts = [hits for _, (_, hits) in days]
    maximum = max(counts + [reference or 0, target or 0, 1])
    out = svg_open(title, "test period, alerts from any detector")
    for tick in range(5):
        value = maximum * tick / 4
        yy = TOP + plot_h - plot_h * tick / 4
        out += [f'<line x1="{LEFT}" y1="{yy:.1f}" x2="{W-RIGHT}" y2="{yy:.1f}" stroke="#e5e7eb"/>',
                f'<text x="{LEFT-6}" y="{yy+4:.1f}" text-anchor="end" class="a">{value:,.0f}</text>']
    width = plot_w / len(days)
    for index, (day, (_, hits)) in enumerate(days):
        bar = plot_h * hits / maximum
        out.append(f'<rect x="{LEFT+index*width:.1f}" y="{TOP+plot_h-bar:.1f}" width="{max(width-1, 0.6):.1f}" height="{bar:.1f}" fill="{COLOURS["test"]}"><title>{esc(day)}: {hits:,}</title></rect>')
    for value, colour, label in ((reference, COLOURS["reference"], "validation average"), (target, COLOURS["threshold"], "daily budget")):
        if value:
            yy = TOP + plot_h - plot_h * value / maximum
            out += [f'<line x1="{LEFT}" y1="{yy:.1f}" x2="{W-RIGHT}" y2="{yy:.1f}" stroke="{colour}" stroke-width="2" stroke-dasharray="6 4"/>',
                    f'<text x="{W-RIGHT-4}" y="{yy-5:.1f}" text-anchor="end" class="v" fill="{colour}">{label} {value:,.1f}/day</text>']
    for index in (0, len(days) - 1):
        out.append(f'<text x="{LEFT+index*width+width/2:.1f}" y="{TOP+plot_h+16}" text-anchor="{"start" if index == 0 else "end"}" class="a">{esc(days[index][0])}</text>')
    out.append("</svg>")
    return "".join(out)


# --- the section ---------------------------------------------------------------


def drift_badge(validation_rate, test_rate):
    if not validation_rate and not test_rate:
        return '<span class="badge neutral">no alerts</span>'
    if not validation_rate or not test_rate:
        return '<span class="badge warning">one split only</span>'
    ratio = test_rate / validation_rate
    kind = "success" if 0.5 <= ratio <= 2 else "warning" if 0.25 <= ratio <= 4 else "danger"
    return f'<span class="badge {kind}">test ×{ratio:.2f} of validation</span>'


def overview_table(runs):
    rows = []
    for run in runs:
        test_rows = run["rows"].get("test", 0)
        flagged = test_rows - run["agreement"][0] if test_rows else 0
        for name, detector in run["detectors"].items():
            v_rows, t_rows = run["rows"].get("validation", 0), run["rows"].get("test", 0)
            v_rate = detector["alerts"].get("validation", 0) / v_rows if v_rows else 0
            t_rate = detector["alerts"].get("test", 0) / t_rows if t_rows else 0
            rows.append(f"<tr><td>{esc(run['name'])}</td><td>{esc(detector['label'])}</td>"
                        f"<td>{v_rows + t_rows:,}</td><td>{pct(detector['alerts'].get('validation', 0), v_rows)}</td>"
                        f"<td>{pct(detector['alerts'].get('test', 0), t_rows)} ({detector['alerts'].get('test', 0):,})</td>"
                        f"<td>{drift_badge(v_rate, t_rate)}</td><td>{pct(test_rows - flagged, test_rows)}</td></tr>")
    return ('<div class="table-wrap"><table><thead><tr><th>View</th><th>Detector</th><th>Rows scored</th>'
            '<th>Validation alert rate</th><th>Test alert rate</th><th>Stability</th><th>Test rows never flagged</th>'
            '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def detector_block(run, open_block):
    test_rows = run["rows"].get("test", 0)
    panels = []
    for name, detector in run["detectors"].items():
        above = {split: detector["alerts"].get(split, 0) for split in SPLITS}
        subtitle = (f"above threshold: test {pct(above['test'], test_rows)} ({above['test']:,}), "
                    f"validation {pct(above['validation'], run['rows'].get('validation', 0))}")
        panels.append(histogram_svg(f"{detector['label']}: score distribution", detector["histogram"],
                                    detector["threshold"], subtitle))
    primary = next((run["detectors"][name] for name in ("isolation", "novelty", "robust") if name in run["detectors"]), None)
    if primary:
        share = primary["alerts"].get("test", 0) / test_rows if test_rows else 0
        panels.append(tail_svg(f"{primary['label']}: how deep in the tail alerts sit", primary["tail"],
                               primary["threshold"], share))
    agreement = run["agreement"]
    panels.append(bars_svg("Detectors flagging each test row", [(f"{level} detector{'s' if level != 1 else ''}", count)
                                                               for level, count in enumerate(agreement)],
                           "log-length bars; most rows should sit in the first", log=True, total=sum(agreement)))
    validation_days = run["daily"].get("validation", {})
    reference = (sum(hits for _, hits in validation_days.values()) / len(validation_days)) if validation_days else None
    panels.append(daily_svg("Alerts per day", run["daily"].get("test", {}), reference, run.get("target_per_day")))
    body = '<div class="mb-grid">' + "".join(f'<div class="panel">{panel}</div>' for panel in panels) + "</div>"
    label = f"{run['name']}: {test_rows:,} test rows, {run['rows'].get('validation', 0):,} validation rows"
    return f'<details{" open" if open_block else ""}><summary>{esc(label)}</summary>{body}</details>'


def zoo_block(run):
    test_rows = run["rows"].get("test", 0)
    panels = []
    subtitle = (f"ensemble alerts: test {pct(run['ensemble_alerts'].get('test', 0), test_rows)} "
                f"({run['ensemble_alerts'].get('test', 0):,})")
    panels.append(histogram_svg("Ensemble score distribution", run["ensemble_histogram"], run["ensemble_threshold"], subtitle))
    votes = run["votes"].get("test", [])
    if votes:
        panels.append(bars_svg(f"Ensemble members voting per test row ({len(run['members'])} members)",
                               [(f"{count} vote{'s' if count != 1 else ''}", value) for count, value in enumerate(votes)],
                               "log-length bars", log=True, colour=COLOURS["member"], total=sum(votes)))
    rates = []
    for model in run["models"]:
        hits = run["model_alerts"].get("test", {}).get(model, 0)
        rates.append((("★ " if model in run["members"] else "") + model, hits))
    rates.sort(key=lambda item: -item[1])
    panels.append(bars_svg("Test alerts per model (★ = ensemble member)", rates,
                           "each model's own threshold, set on validation", total=test_rows))
    body = '<div class="mb-grid">' + "".join(f'<div class="panel">{panel}</div>' for panel in panels) + "</div>"
    return f'<details><summary>Model zoo · {esc(run["name"])}: {test_rows:,} test rows</summary>{body}</details>'


def render_section(results, source_label):
    if results is None:
        return ('<section id="behaviour"><h2>Model behaviour</h2>'
                '<div class="empty">Skipped (--no-model-behaviour).</div></section>')
    detector_runs = sorted(results.get("detector", []), key=lambda run: (run["name"] != "individual", run["name"]))
    zoo_runs = sorted(results.get("zoo", []), key=lambda run: (not run["name"].startswith("individual"), run["name"]))
    if not detector_runs and not zoo_runs:
        return ('<section id="behaviour"><h2>Model behaviour</h2><div class="empty">No Phase 4 score files found.</div></section>')
    scored = sum(sum(run["rows"].values()) for run in detector_runs)
    how = ('<div class="panel"><h3>How to read this section</h3><ul class="how">'
           '<li>Every row of the validation and test periods is scored; training-period scores are not saved.</li>'
           '<li><b>Healthy:</b> a large body of ordinary scores, a thin tail, and the red threshold far out in that tail.</li>'
           '<li><b>Worrying:</b> the threshold inside the body, or test scores shifted right of validation (drift).</li>'
           '<li>Counts use a log scale, so one bar step is ten times more rows. The tail is tiny in reality.</li>'
           '<li>The Phase 7 <code>probability</code> is a percentile. Alerts are the top sliver of rows, so it is always above 0.99; the tail curve shows how thin that sliver is.</li>'
           '<li>Stability compares the test alert rate with validation, where the threshold was set. Within ×0.5 to ×2 is normal.</li>'
           '</ul></div>')
    detector_html = "".join(detector_block(run, index == 0) for index, run in enumerate(detector_runs))
    zoo_html = "".join(zoo_block(run) for run in zoo_runs)
    return (f'<section id="behaviour" class="mb"><style>{CSS}</style><h2>Model behaviour</h2>'
            f'<p class="lead">Are the {esc(source_label)} detectors separating a thin tail of unusual rows from the rest, '
            f'or flagging everything? Based on {scored:,} scored rows across all views.</p>'
            f'{how}{overview_table(detector_runs)}{detector_html}'
            + (f'<h3 style="margin-top:22px">Model zoo</h3>{zoo_html}' if zoo_html else "") + "</section>")
