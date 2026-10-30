"""Phase 6: an interactive cluster map you can replay over time, embedded in the report (no internet needed).

    render_timeline_map(points_csv, summary_csv, title, figure_number)

Reads Phase 7b's map_points.csv (every point on the Phase 4c map, from every
period, with its island) and the view's cluster_summary.csv, and returns the
HTML for one map: a canvas, a time slider and controls, plus the data packed as
base64 typed arrays. The JavaScript is included once per page.

Controls:
    slider            the period shown; months by default, or weeks
    play / pause      steps through the periods, so points appear month by month
    Cumulative        everything up to the period (new points bright, earlier ones faded)
    Only this period  just the points of that period
    Flagged only      only observations an alert was raised on
    hover             date, cluster, period and whether it was flagged
    click             highlight that point's cluster; click empty space to clear
"""
from __future__ import annotations

import base64
import html
import json
import math

import numpy as np
import pandas as pd

SERVER_COLUMNS = ("top_host_id", "top_hostname", "top_entity_id", "top_source_ip", "top_initiator_ip")
EVENT_COLUMNS = ("top_event_type", "top_dominant_event_type", "top_first_event_type", "top_episode_family",
                 "top_event_category", "top_protocol", "top_service_port", "top_destination_port")
FLAG_FLAGGED, FLAG_TRAIN, FLAG_VALIDATION, FLAG_TEST, FLAG_ENSEMBLE = 1, 2, 4, 8, 16


def _b64(array):
    return base64.b64encode(np.ascontiguousarray(array).tobytes()).decode("ascii")


def _first(row, columns):
    for column in columns:
        value = row.get(column)
        if value is not None and not (isinstance(value, float) and math.isnan(value)) and str(value).strip():
            return str(value).split(" (")[0].split(";")[0].strip()
    return ""


def _scale(values):
    low, high = float(np.nanmin(values)), float(np.nanmax(values))
    span = high - low or 1.0
    return np.clip(np.round((values - low) / span * 65535), 0, 65535).astype(np.uint16)


def pack(points_csv, summary_csv):
    points = pd.read_csv(points_csv, dtype={"row_manifest_id": str}, low_memory=False)
    points["when"] = pd.to_datetime(points["time"].astype(str).str[:19], errors="coerce")
    points = points.dropna(subset=["when", "x", "y"]).sort_values("when").reset_index(drop=True)
    if points.empty:
        return None
    start = points["when"].min().normalize()
    days = ((points["when"].dt.normalize() - start).dt.days).clip(lower=0).astype(np.uint16)
    split = points["split"].astype(str)
    truthy = lambda s: s.astype(str).str.lower().isin({"true", "1", "yes"})
    flags = (truthy(points["flagged"]) * FLAG_FLAGGED + split.eq("train") * FLAG_TRAIN
             + split.eq("validation") * FLAG_VALIDATION + split.eq("test") * FLAG_TEST
             + truthy(points["ensemble_alert"]) * FLAG_ENSEMBLE).astype(np.uint8)
    clusters = points["cluster_number"].fillna(0).astype(int).clip(0, 65535).astype(np.uint16)
    info = {}
    if summary_csv.is_file():
        for _, row in pd.read_csv(summary_csv).iterrows():
            row = row.to_dict()
            number = int(str(row["cluster_id"]).split("#")[-1])
            info[number] = {"rows": int(row.get("rows", 0)), "flagged": int(row.get("flagged_rows", 0)),
                            "rate": round(float(row.get("alert_rate", 0) or 0), 3), "server": _first(row, SERVER_COLUMNS),
                            "event": _first(row, EVENT_COLUMNS), "first": str(row.get("first_month_on_map") or "")}
    counts = clusters.value_counts()
    for number, count in counts.items():
        info.setdefault(int(number), {"rows": 0, "flagged": 0, "rate": 0, "server": "", "event": "", "first": ""})
        info[int(number)]["points"] = int(count)
    return {
        "start": str(start.date()), "n": len(points),
        "x": _b64(_scale(points["x"].to_numpy(float))), "y": _b64(_scale(points["y"].to_numpy(float))),
        "c": _b64(clusters.to_numpy()), "d": _b64(days.to_numpy()), "f": _b64(flags.to_numpy()),
        "clusters": {str(k): v for k, v in info.items()},
        "splits": {k: int(v) for k, v in split.value_counts().items()},
    }


SCRIPT = r"""
<script>
(function () {
  if (window.__timelineMaps) return; window.__timelineMaps = true;
  var PALETTE = ['#2563eb','#dc2626','#16a34a','#9333ea','#ea580c','#0891b2','#db2777','#65a30d','#7c3aed','#ca8a04',
                 '#0d9488','#e11d48','#4f46e5','#059669','#d97706','#0284c7','#c026d3','#15803d','#b91c1c','#1d4ed8'];
  function colour(c) { return c === 0 ? '#94a3b8' : PALETTE[(c * 7) % PALETTE.length]; }
  function decode(text, Type) {
    var bin = atob(text), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Type(bytes.buffer);
  }
  function addDays(start, days) { var d = new Date(start.getTime()); d.setUTCDate(d.getUTCDate() + days); return d; }
  function iso(d) { return d.toISOString().slice(0, 10); }
  function periods(start, maxDay, step) {
    var out = [], d = new Date(start.getTime());
    if (step === 'month') d.setUTCDate(1);
    while (true) {
      var from = Math.round((d - start) / 86400000), next = new Date(d.getTime());
      if (step === 'month') next.setUTCMonth(next.getUTCMonth() + 1); else next.setUTCDate(next.getUTCDate() + 7);
      var to = Math.round((next - start) / 86400000);
      out.push({from: Math.max(from, 0), to: to,
                label: step === 'month' ? d.toISOString().slice(0, 7) : 'week of ' + iso(d)});
      if (to > maxDay) break;
      d = next;
    }
    return out;
  }
  function init(root) {
    var data = JSON.parse(root.querySelector('script[type="application/json"]').textContent);
    var X = decode(data.x, Uint16Array), Y = decode(data.y, Uint16Array), C = decode(data.c, Uint16Array),
        D = decode(data.d, Uint16Array), F = decode(data.f, Uint8Array), n = X.length;
    var start = new Date(data.start + 'T00:00:00Z'), maxDay = 0;
    for (var i = 0; i < n; i++) if (D[i] > maxDay) maxDay = D[i];
    var canvas = root.querySelector('canvas'), ctx = canvas.getContext('2d');
    var slider = root.querySelector('.tl-slider'), label = root.querySelector('.tl-label'),
        stats = root.querySelector('.tl-stats'), tip = root.querySelector('.tl-tip'),
        play = root.querySelector('.tl-play'), stepSel = root.querySelector('.tl-step'),
        modeSel = root.querySelector('.tl-mode'), flaggedOnly = root.querySelector('.tl-flagged'),
        legend = root.querySelector('.tl-legend');
    var state = {step: 'month', mode: 'cumulative', flagged: false, highlight: -1, timer: null};
    var list = periods(start, maxDay, state.step);
    slider.max = list.length - 1; slider.value = list.length - 1;
    var px = new Float32Array(n), py = new Float32Array(n), visible = new Uint8Array(n);
    function layout() {
      var ratio = window.devicePixelRatio || 1, width = canvas.clientWidth, height = Math.round(width * 0.62);
      canvas.style.height = height + 'px'; canvas.width = width * ratio; canvas.height = height * ratio;
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      var m = 14;
      for (var i = 0; i < n; i++) { px[i] = m + X[i] / 65535 * (width - 2 * m); py[i] = m + (1 - Y[i] / 65535) * (height - 2 * m); }
      draw();
    }
    function draw() {
      var p = list[+slider.value], width = canvas.clientWidth, height = canvas.clientHeight;
      ctx.clearRect(0, 0, width, height);
      var shown = 0, flagged = 0, fresh = 0, byCluster = {};
      var passes = [[], [], []];        // earlier, new this period, flagged (drawn last)
      for (var i = 0; i < n; i++) {
        var d = D[i], inPeriod = d >= p.from && d < p.to, upTo = d < p.to;
        var ok = state.mode === 'cumulative' ? upTo : inPeriod;
        if (ok && state.flagged && !(F[i] & 1)) ok = false;
        visible[i] = ok ? 1 : 0;
        if (!ok) continue;
        shown++; if (F[i] & 1) flagged++; if (inPeriod) fresh++;
        byCluster[C[i]] = (byCluster[C[i]] || 0) + 1;
        passes[(F[i] & 1) ? 2 : (inPeriod ? 1 : 0)].push(i);
      }
      var alphaOld = state.mode === 'cumulative' ? 0.28 : 0.9;
      for (var pass = 0; pass < 3; pass++) {
        var items = passes[pass];
        for (var k = 0; k < items.length; k++) {
          var j = items[k], c = C[j], dim = state.highlight >= 0 && c !== state.highlight;
          ctx.globalAlpha = dim ? 0.06 : (pass === 0 ? alphaOld : 0.9);
          ctx.fillStyle = colour(c);
          var r = pass === 2 ? 2.6 : (state.highlight === c ? 2.4 : 1.6);
          ctx.beginPath(); ctx.arc(px[j], py[j], r, 0, 6.2832); ctx.fill();
          if (pass === 2 && !dim) { ctx.globalAlpha = 0.9; ctx.strokeStyle = '#111827'; ctx.lineWidth = 0.8; ctx.stroke(); }
        }
      }
      ctx.globalAlpha = 1;
      label.textContent = (state.mode === 'cumulative' ? 'Up to ' : '') + p.label;
      stats.textContent = shown.toLocaleString() + ' points shown (' + fresh.toLocaleString() + ' from this period), ' +
                          flagged.toLocaleString() + ' flagged';
      var top = Object.keys(byCluster).filter(function (c) { return c !== '0'; })
                  .sort(function (a, b) { return byCluster[b] - byCluster[a]; }).slice(0, 12);
      legend.innerHTML = top.map(function (c) {
        var info = data.clusters[c] || {}, rate = info.rows ? Math.round(info.rate * 100) + '% flagged' : 'no test rows';
        return '<span class="tl-key' + (+c === state.highlight ? ' on' : '') + '" data-c="' + c + '"><i style="background:' +
               colour(+c) + '"></i>#' + c + ' · ' + byCluster[c] + ' pts · ' + rate + '</span>';
      }).join('');
    }
    function nearest(x, y) {
      var best = -1, bestD = 49;
      for (var i = 0; i < n; i++) {
        if (!visible[i]) continue;
        var dx = px[i] - x, dy = py[i] - y, dd = dx * dx + dy * dy;
        if (dd < bestD) { bestD = dd; best = i; }
      }
      return best;
    }
    function where(event) { var r = canvas.getBoundingClientRect(); return [event.clientX - r.left, event.clientY - r.top]; }
    canvas.addEventListener('mousemove', function (event) {
      var at = where(event), i = nearest(at[0], at[1]);
      if (i < 0) { tip.style.display = 'none'; return; }
      var info = data.clusters[C[i]] || {}, period = (F[i] & 8) ? 'test' : (F[i] & 4) ? 'validation' : 'training (not scored)';
      tip.innerHTML = '<b>' + iso(addDays(start, D[i])) + '</b> · cluster #' + C[i] + (C[i] === 0 ? ' (isolated)' : '') +
                      '<br>' + period + ((F[i] & 1) ? ' · <b style="color:#b91c1c">flagged</b>' : '') +
                      (info.event ? '<br>' + info.event : '') + (info.server ? ' · ' + info.server : '') +
                      (info.first ? '<br>first on the map ' + info.first : '');
      tip.style.left = (at[0] + 14) + 'px'; tip.style.top = (at[1] + 10) + 'px'; tip.style.display = 'block';
    });
    canvas.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
    canvas.addEventListener('click', function (event) {
      var at = where(event), i = nearest(at[0], at[1]);
      state.highlight = i < 0 || state.highlight === C[i] ? -1 : C[i]; draw();
    });
    legend.addEventListener('click', function (event) {
      var key = event.target.closest('.tl-key'); if (!key) return;
      var c = +key.getAttribute('data-c'); state.highlight = state.highlight === c ? -1 : c; draw();
    });
    slider.addEventListener('input', draw);
    modeSel.addEventListener('change', function () { state.mode = modeSel.value; draw(); });
    flaggedOnly.addEventListener('change', function () { state.flagged = flaggedOnly.checked; draw(); });
    stepSel.addEventListener('change', function () {
      var current = list[+slider.value].to; state.step = stepSel.value; list = periods(start, maxDay, state.step);
      slider.max = list.length - 1;
      var index = list.findIndex(function (p) { return p.to >= current; });
      slider.value = index < 0 ? list.length - 1 : index; draw();
    });
    play.addEventListener('click', function () {
      if (state.timer) { clearInterval(state.timer); state.timer = null; play.textContent = '▶ Play'; return; }
      if (+slider.value >= list.length - 1) slider.value = 0;
      play.textContent = '❚❚ Pause'; draw();
      state.timer = setInterval(function () {
        if (+slider.value >= list.length - 1) { clearInterval(state.timer); state.timer = null; play.textContent = '▶ Play'; return; }
        slider.value = +slider.value + 1; draw();
      }, state.step === 'month' ? 1100 : 450);
    });
    window.addEventListener('resize', layout);
    layout();
  }
  function start() { document.querySelectorAll('.tl-map').forEach(init); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
</script>
<style>
.tl-map{position:relative;margin:10px 0 18px;border:1px solid #dce3ed;border-radius:12px;background:#fff;padding:12px}
.tl-map canvas{width:100%;display:block;background:#fbfcfe;border-radius:8px;cursor:crosshair}
.tl-controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:8px;font-size:.9rem}
.tl-controls input[type=range]{flex:1;min-width:220px}
.tl-controls button{border:1px solid #cbd5e1;background:#f1f5f9;border-radius:8px;padding:4px 12px;cursor:pointer;font-weight:600}
.tl-controls select{border:1px solid #cbd5e1;border-radius:6px;padding:3px 6px}
.tl-label{font-weight:700;min-width:150px;font-variant-numeric:tabular-nums}
.tl-stats{color:#5f6b7d;font-size:.85rem;margin:4px 0 6px}
.tl-tip{position:absolute;display:none;pointer-events:none;background:#111827;color:#f1f5f9;padding:6px 9px;border-radius:7px;font-size:.78rem;line-height:1.35;max-width:320px;z-index:5}
.tl-legend{display:flex;flex-wrap:wrap;gap:6px 12px;margin-top:8px;font-size:.78rem}
.tl-key{cursor:pointer;padding:2px 6px;border-radius:6px;border:1px solid transparent}
.tl-key.on{border-color:#111827;background:#f1f5f9}
.tl-key i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}
</style>
"""


def render_timeline_map(points_csv, summary_csv, title, figure_number):
    data = pack(points_csv, summary_csv)
    if data is None:
        return ""
    splits = data["splits"]
    caption = (f"<b>Fig. {figure_number}.</b> {html.escape(title)}, replayable over time: {data['n']:,} points "
               f"({splits.get('test', 0):,} from the test period, {splits.get('validation', 0):,} from validation and "
               f"{splits.get('train', 0):,} from training), coloured by cluster; grey points are isolated (#0); points "
               "with a dark ring were flagged. The test period is sampled densely (every flagged row and a large "
               "random sample), earlier months at about the same number of points each, so the jump in density at "
               "the test period is the sampling, not the activity. Training rows were never scored, so they are never "
               "flagged.")
    return (
        '<div class="tl-map">'
        '<div class="tl-controls"><button type="button" class="tl-play">▶ Play</button>'
        '<input type="range" class="tl-slider" min="0" max="0" step="1" value="0" aria-label="Period">'
        '<span class="tl-label"></span>'
        '<select class="tl-step" aria-label="Step"><option value="month">Month by month</option>'
        '<option value="week">Week by week</option></select>'
        '<select class="tl-mode" aria-label="Show"><option value="cumulative">Cumulative</option>'
        '<option value="only">Only this period</option></select>'
        '<label><input type="checkbox" class="tl-flagged"> Flagged only</label></div>'
        '<div class="tl-stats"></div><canvas></canvas><div class="tl-tip"></div><div class="tl-legend"></div>'
        f'<script type="application/json">{json.dumps(data)}</script>'
        f'<figcaption style="margin-top:8px">{caption} Hover for details; click a point or a legend entry to '
        'highlight its cluster.</figcaption></div>' + SCRIPT)
