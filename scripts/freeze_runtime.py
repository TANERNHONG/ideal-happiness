"""Freeze what the console needs to keep working after data/ is purged.

Copies, from data/ into runtime/data/ (same relative paths, timestamps kept):

* the trained models: each view's Phase 3 preprocessing bundle and feature names, Phase 4 detector bundle, and
  model-zoo bundles (full and selected features), with the summaries the Models page and Analyze read; Phase 4f's
  step model, rules and threshold (frequent subsequences);
* the maps: each view's map points (t-SNE and UMAP positions, group, period, flags), the embedding new lines are
  placed in, the order of its points, and the cluster tables; plus the PNG renders of each map in runtime/maps/;
* the derived caches nothing can rebuild once the inputs are gone (event counts, the validation-score
  references behind "how rare", the OSSEC per-entity history, the Dashboard's outlier counts), in runtime/cache/.

Left behind on purpose: log lines and their stores, account names, addresses and example lines. The tables that
carry them are copied with those columns removed (cluster summaries) or reduced to IDs (map projections).

Run from the project root, with the console's environment:

    .venv\\Scripts\\python.exe scripts\\freeze_runtime.py            # build or refresh runtime/
    .venv\\Scripts\\python.exe scripts\\freeze_runtime.py --check    # load every model and score sample lines

The console uses runtime/ by itself when data/ holds no trained models (triage-console/service/config.py).
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RUNTIME = ROOT / "runtime"
CACHE = ROOT / "triage-console" / "var" / "cache"

BASELINE = {"auth": ["individual", "authentication_sessions", "host_5min", "host_behavior_1d"],
            "ossec": ["individual", "episodes", "host_5min", "host_behavior_1d"]}
PRESENCE = {"pf": ["individual", "attempts", "flow_episodes", "slots_5min", "slots_1h", "slots_1d"],
            "ipf": ["individual", "attempts", "flow_episodes", "slots_5min", "slots_1h", "slots_1d"]}
FEATURE_SETS = ("full", "selected")
# Columns that name people or addresses, or hold log text: not frozen.
SENSITIVE = {"example_log_lines", "top_username", "top_source_ip", "top_destination_ip", "username", "source_ip",
             "destination_ip", "raw_message", "raw_messages", "original_log_line"}
# Phase 4f's sequence detector, per source: the view it scores
SEQUENCE_VIEWS = {"auth": "authentication_sessions", "ossec": "episodes"}
CACHES = ["event_counts.json", "outliers.json", "variants.json",
          *[f"reference_{s}_{v}.npz" for s, views in BASELINE.items() for v in views],
          *[f"ossec_history_{v}.npz" for v in ("episodes", "host_5min", "host_behavior_1d")],
          *[f"sequence_seen_{s}.json" for s in SEQUENCE_VIEWS],
          *[f"drift_null_{s}_{v}.json" for s, views in BASELINE.items() for v in views]]

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def files_to_copy() -> list[str]:
    """Paths relative to data/ that are copied as they are."""
    out = []
    for source, views in BASELINE.items():
        out.append(f"phase4_detection/{source}/detectors/experiment_summary.json")
        for view in views:
            out += [f"phase3_features/{source}/{view}/preprocessing_bundle.joblib",
                    f"phase3_features/{source}/{view}/feature_names.csv",
                    f"phase3_features/{source}/{view}/checkpoints.json",
                    f"phase4_detection/{source}/detectors/{view}/experiment_bundle.joblib",
                    f"phase4_detection/{source}/detectors/{view}/summary.json",
                    f"phase4_detection/{source}/detectors/{view}/temporal_coverage_validation.json"]
            for fs in FEATURE_SETS:
                out += [f"phase4_detection/{source}/model_zoo/{view}/{fs}/model_bundle.joblib",
                        f"phase4_detection/{source}/model_zoo/{view}/{fs}/dataset_summary.json"]
            m = f"phase4_detection/{source}/model_zoo_map/{view}/selected"
            out += [f"{m}/projection_tsne_embedding.npy", f"{m}/layout_umap.csv", f"{m}/layout_umap.json",
                    f"phase7b_clusters/{source}/{view}/map_points.csv"]
    for source, view in SEQUENCE_VIEWS.items():      # step counts per host and event type, rules; no lines or accounts
        out += [f"phase4f_sequences/{source}/routines/model.json", f"phase4f_sequences/{source}/routines/rules.csv",
                f"phase4_detection/{source}/sequences/{view}/summary.json"]
    for source, views in PRESENCE.items():
        out.append(f"phase4_detection/{source}/detectors/experiment_summary.json")
        out.append(f"phase3_features/{source}/feature_engineering_summary.json")
        for view in views:
            out += [f"phase4_detection/{source}/detectors/{view}/summary.json",
                    f"phase3_features/{source}/{view}/feature_names.csv"]
    return out


def copy(rel: str, log: list) -> None:
    src, dst = DATA / rel, RUNTIME / "data" / rel
    if not src.exists():
        log.append({"file": rel, "status": "not in data/"})
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)                                 # copy2 keeps the timestamps the console's checks compare
    log.append({"file": rel, "status": "copied", "bytes": dst.stat().st_size, "sha256": sha256(dst)})


def copy_columns(rel: str, keep, log: list) -> None:
    """A CSV with only the columns ``keep(name)`` allows; timestamps kept."""
    src, dst = DATA / rel, RUNTIME / "data" / rel
    if not src.exists():
        log.append({"file": rel, "status": "not in data/"})
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open(encoding="utf-8", newline="") as fin, dst.open("w", encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        columns = [c for c in reader.fieldnames or [] if keep(c)]
        writer = csv.DictWriter(fout, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in reader:
            writer.writerow(row)
    shutil.copystat(src, dst)
    dropped = [c for c in (reader.fieldnames or []) if c not in columns]
    log.append({"file": rel, "status": "copied without " + (", ".join(dropped) or "nothing"), "bytes": dst.stat().st_size,
                "sha256": sha256(dst)})


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def freeze() -> dict:
    started = time.time()
    log: list = []
    for rel in files_to_copy():
        copy(rel, log)
    for source, views in BASELINE.items():
        for view in views:
            # the map's point order is all Analyze reads from the projection; its other columns name people
            copy_columns(f"phase4_detection/{source}/model_zoo_map/{view}/selected/projection_tsne.csv",
                         lambda c: c == "row_manifest_id", log)
            copy_columns(f"phase7b_clusters/{source}/{view}/cluster_summary.csv", lambda c: c not in SENSITIVE, log)
    # the maps as pictures, for reading without the console
    maps = RUNTIME / "maps"
    for source, views in BASELINE.items():
        for view in views:
            for src, name in ((DATA / "phase7b_clusters" / source / view / "cluster_map.png", f"{source}_{view}_groups.png"),
                              (DATA / "phase4_detection" / source / "model_zoo_map" / view / "selected" / "projection_tsne.png",
                               f"{source}_{view}_tsne.png")):
                if src.exists():
                    maps.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, maps / name)
                    log.append({"file": f"maps/{name}", "status": "copied", "bytes": src.stat().st_size})
    cache_dir = RUNTIME / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    for name in CACHES:
        src = CACHE / name
        if src.exists():
            shutil.copy2(src, cache_dir / name)
            log.append({"file": f"cache/{name}", "status": "copied", "bytes": src.stat().st_size})
        else:
            log.append({"file": f"cache/{name}", "status": "missing: open Analyze once for that view, then freeze again"})
    slim_cluster_index(cache_dir / "cluster_index.sqlite", log)
    manifest = {"created_at": time.strftime("%Y-%m-%d %H:%M:%S"), "seconds": round(time.time() - started, 1),
                "from": str(DATA), "files": log,
                "copied": sum(1 for e in log if str(e["status"]).startswith("copied")),
                "missing": [e["file"] for e in log if not str(e["status"]).startswith("copied")],
                "bytes": sum(e.get("bytes", 0) for e in log)}
    (RUNTIME / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def slim_cluster_index(target: Path, log: list) -> None:
    """The console's cluster index without what names people or links to log lines: each group's event-type mix
    (its name), the flagged observations' scores (Review's list of unusual events) and which group they are in.
    The line links, the validation groups (by account and address) and the review facts stay behind."""
    import sqlite3
    source = CACHE / "cluster_index.sqlite"
    if not source.exists():
        log.append({"file": "cache/cluster_index.sqlite", "status": "missing: start the console once with data/ present"})
        return
    target.unlink(missing_ok=True)
    con = sqlite3.connect(f"file:{target.as_posix()}", uri=True)   # uri: lets ATTACH open the full index read-only
    con.execute("ATTACH DATABASE ? AS full", (f"file:{source.as_posix()}?mode=ro",))
    for (sql,) in con.execute("SELECT sql FROM full.sqlite_master WHERE type='table' AND sql IS NOT NULL").fetchall():
        con.execute(sql)                                     # every table, so every query still finds its table
    for table, where in (("views", ""), ("score_views", ""), ("composition", ""), ("scores", ""),
                         ("members", " WHERE flagged=1 OR sigma=1"), ("sigma_views", "")):
        con.execute(f"INSERT INTO main.{table} SELECT * FROM full.{table}{where}")
    con.commit()
    con.execute("DETACH DATABASE full")
    con.execute("VACUUM")
    con.close()
    log.append({"file": "cache/cluster_index.sqlite", "status": "copied (group mixes, flagged members and scores only)",
                "bytes": target.stat().st_size})


def warm_caches() -> None:
    """Build any score reference or OSSEC history that var/cache lacks, while data/ still has their inputs."""
    sys.path.insert(0, str(ROOT / "triage-console"))
    from service import scoring, sequences
    for source, views in BASELINE.items():
        for view in views:
            scoring._reference(source, view)
            if source == "ossec":
                bundle, _ = scoring._preprocessing(source, view)
                scoring._history(view, bundle["feature_plan"])
    for source in SEQUENCE_VIEWS:
        sequences.seen(source)


def check() -> int:
    """Load every frozen model and score sample lines through the console's own Analyze path, frozen."""
    import os
    os.environ["HUH_FROZEN"] = "1"
    sys.path.insert(0, str(ROOT / "triage-console"))
    from service import analyze, config, scoring
    assert config.FROZEN and config.DATA == RUNTIME / "data", "the console did not switch to runtime/"
    samples = {
        "auth": ["Jul 14 16:20:37 host-a sshd[27857]: [ID 800047 auth.info] Failed password for invalid user maint1 from 192.0.2.17 port 50123 ssh2",
                 "Jul 14 16:20:44 host-a sshd[27857]: [ID 800047 auth.info] Connection closed by 192.0.2.17 port 50123 [preauth]",
                 "Jul 14 16:21:02 host-a sshd[27900]: [ID 800047 auth.info] Accepted publickey for ops from 192.0.2.20 port 50200 ssh2",
                 "Jul 14 16:33:08 host-a su: [ID 366847 auth.notice] 'su root' succeeded for root on /dev/pts/2"],
        "ossec": ["2026/07/14 16:20:37 ossec-agentd: INFO: Trying to connect to server (ossec-server/192.0.2.1:1514).",
                  "2026/07/14 16:20:38 ossec-agentd: INFO: Using IPv4 for: 192.0.2.1 .",
                  "2026/07/14 16:30:00 ossec-syscheckd: INFO: Starting syscheck scan.",
                  "2026/07/14 16:41:00 ossec-syscheckd: INFO: Ending syscheck scan."],
    }
    failures = 0
    for source, lines in samples.items():
        result = analyze.analyze("\n".join(lines), source=source, month="2026-07", host="host-a")
        for view in result["views"]:
            ok = view["observations"] is not None
            failures += not ok
            print(f"{source:6} {view['view']:24} observations={view['observations']} flagged={view['flagged']} "
                  f"zoo={len(view['zoo_members'] or [])} rows={len(view['rows'])} {'ok' if ok else 'NOT SCORED'}")
        for view in BASELINE[source]:
            info = scoring.map_info(source, view)
            ok = bool(info and info["points"])
            failures += not ok
            print(f"{source:6} {view:24} map points={info and info['points']} layouts={info and info['layouts']} {'ok' if ok else 'NO MAP'}")
    print("all models and maps usable from runtime/" if not failures else f"{failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="score sample lines with the frozen models, nothing copied")
    args = parser.parse_args()
    if args.check:
        sys.exit(check())
    if not DATA.exists():
        sys.exit("data/ is not here: nothing to freeze.")
    warm_caches()
    result = freeze()
    print(f"runtime/: {result['copied']} files, {result['bytes'] / 1e6:.0f} MB, in {result['seconds']} s")
    if result["missing"]:
        print("not frozen: " + ", ".join(result["missing"]))
