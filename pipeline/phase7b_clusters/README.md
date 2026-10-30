# Phase 7b: behavioural clusters (pseudo-labels)

Gives every test-period observation a **cluster ID**: a pseudo-label for
"this kind of activity". Analysts can then work cluster by cluster in Phases 8
and 9 instead of alert by alert.

Clusters exist for auth and OSSEC. PF and IPFilter use the presence method and
have no model zoo, map or clusters; PF had them until it moved to the presence
method on 2026-10-01.

```
python pipeline/phase7b_clusters/assign_clusters.py --source auth
python run_pipeline.py --source ossec --from-phase 7b --with-model-zoo
```

## How clusters are found

The Phase 4c t-SNE maps show a sample: every flagged test row (up to 10,000),
15,000 random unflagged test rows, and (since 2026-10-01) about 12,000 rows from
the training and validation periods, spread evenly over their months, so the
map covers the whole study period. t-SNE cannot place new points, so the script
works in two steps.

1. **Islands on the map.** HDBSCAN finds the islands on each map, so a cluster
   is exactly what an analyst sees as one island. Islands that contain
   identical rows are merged: t-SNE can scatter copies of one row over several
   islands, but they are the same behaviour. Points on no island are
   *isolated* and get cluster `#0`. Islands are found on all map points, from
   every period; Phase 4c saves each point's embedding beside the map
   (`projection_tsne_embedding.npy`), so earlier periods need no reloading.
2. **Every other row.** The map was drawn from a 32-number summary of each row
   (the model-zoo embedding in `model_bundle.joblib`). The script computes
   that summary for every test row. Each unmapped row then takes the cluster
   most common among its 5 nearest mapped neighbours; `neighbour_agreement`
   records how many of the 5 agreed.

**Check.** For each view, the log reports how often a mapped point gets its
own island back when predicted from its neighbours (its own label hidden).
This measures whether step 2 can be trusted. On the whole-period maps of
2026-10-01 it was 89.5–99.9% on the auth views and 95.7–100% on the OSSEC
views, lowest for daily behaviour (auth 89.5%, OSSEC 95.7%). The figure is
saved in `run.json`.

**Granularity.** `--min-cluster-share` sets the smallest island as a share of
the mapped points. The default, 0.005, gives broad clusters: 62–99 islands per
auth view and 40–83 per OSSEC view (2026-10-01). Use 0.002 for finer ones.

## Outputs (`data/phase7b_clusters/<source>/`)

| File | Contents |
|---|---|
| `<view>/row_clusters.csv` | Every test row: `cluster_id`, `assignment` (`map` or `nearest`), `neighbour_agreement`, map `x`/`y` when mapped, model-zoo votes, ensemble and detector alerts (Phase 4a's detectors and, since 2026-10-19, Phase 4f's sequence detector as *Frequent subsequences*; any of them makes the row flagged) |
| `<view>/cluster_summary.csv` | One row per cluster: size, alerts, `alert_rate` and `lift_vs_view` (how much more often it is flagged than the view as a whole), dominant servers, events, users, addresses or ports, first and last seen, and example log lines |
| `<view>/cluster_map.png` | The t-SNE map coloured by cluster, with cluster numbers on each island |
| `<view>/map_points.csv` | Every map point from every period: `split` (train, validation, test), `time`, `x`, `y`, `cluster_number`, votes and whether it was flagged. Feeds the report's timeline viewer. |
| `<prefix>_cluster_overview.csv` | All views' summaries in one table |
| `<prefix>_alerts_by_cluster.csv` | Every flagged test row with its `cluster_id` and original log lines, in the Phase 7 layout |
| `run.json` | Settings, islands, isolated share and the neighbour check per view |

## In the Phase 6 report

When it finishes, Phase 7b rebuilds the source's Phase 6 report (skip this
with `--no-report`). The report's Results chapter then has a **Behavioural
clusters** subsection. For each view it shows:
- an **interactive timeline map**: press Play or drag the slider to bring the
  points in month by month (or week by week), cumulatively or one period at a
  time, optionally flagged points only; hover for a point's date and cluster,
  click to highlight a cluster. It is plain JavaScript in the report file, so it
  works offline. The static numbered map is underneath;
- the neighbour check;
- a table of the clusters with the most flagged observations: alert rate,
  lift, main server, event and user, dates seen, and the month the cluster
  first appears on the map.

If the map is newer than the clusters, the report shows a warning to re-run
Phase 7b.

## Using the clusters in Phases 8 and 9

- **Phase 8 labelling by behavioural cluster** (one representative to label per cluster):
  `python pipeline/phase8_malice_classifier/securebert_label.py suggest --inputs data/phase7b_clusters/ossec/ossec_alerts_by_cluster.csv --cluster-column cluster_id --out data/phase8_malice_classifier/to_label/ossec_by_cluster`
  `cluster_id` is kept in the sheet.
- **Phase 9 triage** accepts the same file (`--inputs …_alerts_by_cluster.csv`),
  and writes each alert's cluster to the `clusters` column of `triage.csv`, so
  the categories can be summarised per cluster.
- **Project DAD Console.** Data → Clusters shows every view's map (drawn on
  request; zoomable; groups can be switched on and off, and a picked group is
  shown in yellow), opens any point with its original lines from
  `map_points.csv` and the Phase 3 lineage, shows each cluster's lines,
  members and comments, and lets people rename clusters. Review lists the clusters
  flagged at least twice as often as their view. Islands with no test-period
  rows, which have no summary here, appear there as *unnamed groups*.
- **Analysis.** Start from `cluster_summary.csv`, sorted by `lift_vs_view`.
  Clusters that are mostly alerts, concentrated on one server or source, and
  recent are the ones to open first.

## Cautions

- **Island shapes mean nothing.** t-SNE keeps neighbourhoods, not distances
  or shapes. Many OSSEC islands are striped spindles: one message from one
  server, laid out by the clock, with one strand per weekday, 00h at one tip
  and 23h at the other (hour and weekday place a point to 94–100%; at 00h and 23h the strands sit about 3 times closer together than at midday). The tips pinch because points at
  the end of a strand have neighbours on one side only, so t-SNE widens their
  neighbourhood until it reaches the next weekday's strand. In the input the
  strands are evenly spaced. See *Reading the map* in the project README.
- A cluster is a grouping aid, not a verdict. It says these rows look alike to
  the model zoo, not that they are the same event, or that they are all benign
  or all hostile.
- Cluster IDs belong to one Phase 4c map. Re-running Phase 4c redraws the map
  and renumbers the clusters, so date any notes you keep about a cluster (see
  `run.json`). The whole-period maps of 2026-10-01 renumbered every cluster.
- Training rows were never scored by the model zoo, so on the timeline they are
  never flagged. Only validation and test points can be.
- The test period is sampled more densely than earlier months; the jump in
  point density when the replay reaches it is the sampling, not the activity.
- The script refuses a view whose map or model zoo is older than Phase 3,
  because rows would not line up. Re-run with `--with-model-zoo` first.
