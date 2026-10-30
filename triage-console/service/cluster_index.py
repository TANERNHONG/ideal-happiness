"""Index of cluster members: Phase 7b row_clusters.csv -> Phase 3 test lineage
-> the Phase 2 event store.

Built once per view in the background into ``var/cache/cluster_index.sqlite``
and rebuilt when its inputs change. It gives, for every cluster, its member
observations (with time and whether they were flagged), the original lines of
each, and the mix of event types the cluster contains.

A second pass links the map's training and validation points (Phase 7b
``map_points.csv``) to their original lines through the Phase 3 train and
validation lineage, so any point clicked on the map can show its lines. Only
the map's points are kept, so the large lineage files are read once and not
stored.

A third pass keeps the scores of every flagged observation, for the Review
page: its server and time, the three detectors' scores, alerts and Phase 4's
explanations (Phase 4 ``test_scores.csv``, up to 1.2 GB a view, so read once),
the model zoo's ensemble score and votes (Phase 7b ``row_clusters.csv``), and for
AUTH sessions and OSSEC episodes the sequence detector's score, alert and
explanation (Phase 4f, ``sequences/<view>/test_scores.csv``). Phase 7b counts
the sequence alerts as flagged, so they are among the members listed.

A fourth pass does the same for the validation period, which Phase 7b does not
cluster: every validation observation a detector, the model zoo's ensemble or
the sequence detector flagged (Phase 4 and 4f ``validation_scores.csv``), grouped by what the people who run
the servers know (server and source address where the view has one, else the
server; its accounts are listed like a cluster's top values), with how many observations each group had in the period, so
Review can list the groups flagged unusually often. Their members, scores and
lines (Phase 3 ``validation_lineage.csv``) go in the same tables as the test
clusters', under group IDs starting ``val:``.

Between the second and third passes, the enabled Sigma rules run over the validation and test periods
(sigma_review.py): every observation holding a hit's lines is flagged (``members.sigma``, ``sigma_flags``)
beside the models' flags, its scores carry the rules' titles, and the later passes' stamps include this
pass's, so they follow it. sigma.py asks for the pass again (refresh()) when the rules change.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import sys
import threading
import time

import pandas as pd

from .config import CACHE, DATA, FROZEN

INDEX_FILE = CACHE / "cluster_index.sqlite"
STORES = {
    "auth": (DATA / "phase2_observations" / "auth" / "authlog_observation_store.sqlite", "record_id"),
    "ossec": (DATA / "phase2_observations" / "ossec" / "ossec_observation_store.sqlite", "event_id"),
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS views (view_key TEXT PRIMARY KEY, stamp TEXT, members INTEGER, built_at TEXT);
CREATE TABLE IF NOT EXISTS members (view_key TEXT, cluster TEXT, row_id TEXT, flagged INTEGER, t TEXT, sigma INTEGER DEFAULT 0,
    PRIMARY KEY (view_key, cluster, row_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS members_order ON members (view_key, cluster, flagged, t);
CREATE TABLE IF NOT EXISTS links (view_key TEXT, row_id TEXT, position INTEGER, record_id TEXT,
    PRIMARY KEY (view_key, row_id, position)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS composition (view_key TEXT, cluster TEXT, event_type TEXT, lines INTEGER,
    PRIMARY KEY (view_key, cluster, event_type)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS map_views (view_key TEXT PRIMARY KEY, stamp TEXT, points INTEGER, built_at TEXT);
CREATE TABLE IF NOT EXISTS scores (view_key TEXT, row_id TEXT, host TEXT, t TEXT,
    robust REAL, robust_alert INTEGER, robust_why TEXT, isolation_forest REAL, isolation_forest_alert INTEGER,
    novelty REAL, novelty_alert INTEGER, novelty_why TEXT, ensemble REAL, ensemble_alert INTEGER, votes INTEGER,
    sequence REAL, sequence_alert INTEGER, sequence_why TEXT, sigma_alert INTEGER, sigma_why TEXT,
    PRIMARY KEY (view_key, row_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS score_views (view_key TEXT PRIMARY KEY, stamp TEXT, rows INTEGER, built_at TEXT);
CREATE TABLE IF NOT EXISTS vgroups (view_key TEXT, gid TEXT, host TEXT, username TEXT, source_ip TEXT,
    rows INTEGER, flagged INTEGER, first_t TEXT, last_t TEXT, PRIMARY KEY (view_key, gid)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS val_views (view_key TEXT PRIMARY KEY, stamp TEXT, rows INTEGER, flagged INTEGER, built_at TEXT);
CREATE TABLE IF NOT EXISTS sigma_flags (view_key TEXT, row_id TEXT, rules TEXT, PRIMARY KEY (view_key, row_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sigma_views (source TEXT PRIMARY KEY, stamp TEXT, flagged INTEGER, built_at TEXT);
"""
# Columns added since the first index: added to an older index in place
ADDED = {"scores": (("sequence", "REAL"), ("sequence_alert", "INTEGER"), ("sequence_why", "TEXT"),
                    ("sigma_alert", "INTEGER"), ("sigma_why", "TEXT")),
         "members": (("sigma", "INTEGER DEFAULT 0"),)}
_status: dict[str, str] = {}
_write_lock = threading.Lock()


def _views():
    for source in STORES:
        for folder in sorted((DATA / "phase7b_clusters" / source).glob("*/row_clusters.csv")):
            view = folder.parent.name
            lineage = DATA / "phase3_features" / source / view / "test_lineage.csv"
            if lineage.exists():
                yield source, view, folder, lineage


def _connect() -> sqlite3.Connection:
    CACHE.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(INDEX_FILE, timeout=60, check_same_thread=False, uri=True)   # uri: lets ATTACH open stores read-only
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    for table, columns in ADDED.items():
        have = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
        for column, kind in columns:
            if column not in have:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
    return con


def _stamp(*paths) -> str:
    return ";".join(f"{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in paths)


def _build(con, source, view, clusters_csv, lineage_csv) -> None:
    key = f"{source}/{view}"
    store, store_key = STORES[source]
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with _write_lock:
        for table in ("members", "links", "composition", "map_views", "scores", "score_views", "vgroups", "val_views"):   # map and validation links live in links too
            con.execute(f"DELETE FROM {table} WHERE view_key=?", (key,))
        con.execute("DROP TABLE IF EXISTS temp.lin")
        con.execute("CREATE TEMP TABLE lin (row_id TEXT, position INTEGER, record_id TEXT, ts TEXT)")
        _status[key] = "reading lineage"
        with lineage_csv.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            record_column = "record_id" if "record_id" in reader.fieldnames else "event_id"
            batch = []
            for row in reader:
                batch.append((row["row_manifest_id"], int(row["event_position"] or 1), row[record_column], row["event_timestamp"]))
                if len(batch) >= 200_000:
                    con.executemany("INSERT INTO temp.lin VALUES (?,?,?,?)", batch); batch.clear()
            con.executemany("INSERT INTO temp.lin VALUES (?,?,?,?)", batch)
        con.execute("CREATE INDEX temp.lin_row ON lin (row_id, position)")
        _status[key] = "reading clusters"
        with clusters_csv.open(encoding="utf-8", newline="") as handle:
            rows = ((key, r["cluster_id"], r["row_manifest_id"],
                     int(r.get("ensemble_alert") == "True" or bool((r.get("detector_alerts") or "").strip())))
                    for r in csv.DictReader(handle))
            con.executemany("INSERT OR IGNORE INTO members (view_key, cluster, row_id, flagged) VALUES (?,?,?,?)", rows)
        _mark_sigma(con, key)
        con.execute("UPDATE members SET t = lin.ts FROM temp.lin AS lin "
                    "WHERE members.view_key=? AND lin.row_id = members.row_id AND lin.position = 1", (key,))
        if view != "individual":
            _status[key] = "linking lines"
            con.execute("INSERT OR IGNORE INTO links SELECT ?, row_id, position, record_id FROM temp.lin", (key,))
        _status[key] = "counting event types"
        con.execute("ATTACH DATABASE ? AS store", (f"file:{store.as_posix()}?mode=ro",))
        try:
            con.execute(f"""INSERT INTO composition
                SELECT m.view_key, m.cluster, e.event_type, COUNT(*) FROM members m
                JOIN temp.lin l ON l.row_id = m.row_id
                JOIN store.events e ON e.{store_key} = l.record_id
                WHERE m.view_key = ? GROUP BY m.cluster, e.event_type""", (key,))
        finally:
            con.commit()
            con.execute("DETACH DATABASE store")
        count = con.execute("SELECT COUNT(*) FROM members WHERE view_key=?", (key,)).fetchone()[0]
        con.execute("INSERT OR REPLACE INTO views VALUES (?,?,?,?)",
                    (key, _stamp(clusters_csv, lineage_csv), count, time.strftime("%Y-%m-%d %H:%M:%S")))
        con.execute("DROP TABLE temp.lin")
        con.commit()


def _map_inputs(source: str, view: str):
    folder = DATA / "phase3_features" / source / view
    paths = [DATA / "phase7b_clusters" / source / view / "map_points.csv",
             folder / "train_lineage.csv", folder / "validation_lineage.csv"]
    return paths if all(p.exists() for p in paths) else None


def _build_map_links(con, source: str, view: str) -> None:
    """Link the map's training and validation points to their events (test points are linked already)."""
    key = f"{source}/{view}"
    points_csv, *lineages = _map_inputs(source, view)
    points = pd.read_csv(points_csv, usecols=["row_manifest_id", "split"], dtype=str)
    wanted = set(points.loc[points["split"] != "test", "row_manifest_id"])
    with _write_lock:
        for lineage in lineages:
            _status[f"{key}:map"] = f"reading {lineage.name}"
            record_column = "record_id" if "record_id" in pd.read_csv(lineage, nrows=0).columns else "event_id"
            for chunk in pd.read_csv(lineage, usecols=["row_manifest_id", "event_position", record_column], dtype=str,
                                     chunksize=2_000_000):
                hit = chunk[chunk["row_manifest_id"].isin(wanted)]
                if len(hit):
                    con.executemany("INSERT OR IGNORE INTO links VALUES (?,?,?,?)",
                                    ((key, r, int(pos or 1), e) for r, pos, e in
                                     hit[["row_manifest_id", "event_position", record_column]].itertuples(index=False)))
        con.execute("INSERT OR REPLACE INTO map_views VALUES (?,?,?,?)",
                    (key, _stamp(points_csv, *lineages), len(wanted), time.strftime("%Y-%m-%d %H:%M:%S")))
        con.commit()


TIME_COLUMNS = ("timestamp", "session_start", "episode_start", "first_timestamp", "window_start")   # by view


# --- Sigma: the enabled rules as a fifth detector (sigma_review.py) ------------------------------------------------

def _mark_sigma(con, key: str) -> None:
    """members.sigma from sigma_flags, after either changes."""
    con.execute("UPDATE members SET sigma=0 WHERE view_key=? AND sigma=1", (key,))
    con.execute("UPDATE members SET sigma=1 WHERE view_key=? AND row_id IN (SELECT row_id FROM sigma_flags WHERE view_key=?)", (key, key))


def _add_sigma_scores(con, key: str) -> None:
    con.execute("UPDATE scores SET sigma_alert=1, sigma_why=f.rules FROM sigma_flags AS f "
                "WHERE scores.view_key=? AND f.view_key=scores.view_key AND f.row_id=scores.row_id", (key,))


def _sigma_built(con, source: str) -> str:
    """The stamp of the Sigma pass the index holds ('' before the first): part of the later passes' stamps."""
    row = con.execute("SELECT stamp FROM sigma_views WHERE source=?", (source,)).fetchone()
    return row[0] if row else ""


def _source_views(source: str) -> list[str]:
    return [view for s, view, _, _ in _views() if s == source]


def _build_sigma(con, source: str, stamp: str) -> None:
    from . import sigma_review                     # imports Analyze, whose whitelist imports this module
    store, store_key = STORES[source]
    views = _source_views(source)
    found = sigma_review.scan(source, store, store_key, views, lambda text: _status.__setitem__(f"{source}:sigma", text))
    with _write_lock:
        for view in views:
            key = f"{source}/{view}"
            con.execute("DELETE FROM sigma_flags WHERE view_key=?", (key,))
            con.executemany("INSERT INTO sigma_flags VALUES (?,?,?)",
                            ((key, row_id, json.dumps(sorted(titles))) for row_id, titles in found.get(view, {}).items()))
            _mark_sigma(con, key)
        con.execute("INSERT OR REPLACE INTO sigma_views VALUES (?,?,?,?)",
                    (source, stamp, sum(len(rows) for rows in found.values()), time.strftime("%Y-%m-%d %H:%M:%S")))
        con.commit()


def sigma_status(source: str) -> str:
    return _status.get(f"{source}:sigma", MISSING)


def sigma_groups(source: str, view: str) -> dict[str, dict]:
    """Per group (test cluster or validation group): its Sigma rules with how many observations each flags, and how
    many observations only Sigma flags."""
    con = _connect()
    try:
        out: dict[str, dict] = {}
        for cluster, flagged, rules in con.execute(
                "SELECT m.cluster, m.flagged, f.rules FROM members m JOIN sigma_flags f ON f.view_key=m.view_key AND f.row_id=m.row_id "
                "WHERE m.view_key=? AND m.sigma=1", (f"{source}/{view}",)):
            group = out.setdefault(cluster, {"rules": {}, "only": 0})
            group["only"] += not flagged
            for title in json.loads(rules):
                group["rules"][title] = group["rules"].get(title, 0) + 1
        return out
    finally:
        con.close()


def _sequence_scores(source: str, view: str, split: str):
    """The Phase 4f sequence detector's scores of the view (AUTH sessions and OSSEC episodes), or None."""
    path = DATA / "phase4_detection" / source / "sequences" / view / f"{split}_scores.csv"
    return path if path.exists() else None


SEQUENCE_COLUMNS = ["row_manifest_id", "sequence_score", "sequence_alert", "sequence_explanation"]


def _add_sequence_scores(con, key: str, path, wanted: set) -> None:
    for chunk in pd.read_csv(path, usecols=SEQUENCE_COLUMNS, dtype=str, chunksize=400_000, keep_default_na=False):
        hit = chunk[chunk["row_manifest_id"].isin(wanted)]
        con.executemany("UPDATE scores SET sequence=?, sequence_alert=?, sequence_why=? WHERE view_key=? AND row_id=?",
                        ((float(r["sequence_score"]) if r["sequence_score"] else None, int(r["sequence_alert"].lower() == "true"),
                          r["sequence_explanation"], key, r["row_manifest_id"]) for r in hit.to_dict("records")))


def _score_inputs(source: str, view: str):
    paths = [DATA / "phase4_detection" / source / "detectors" / view / "test_scores.csv",
             DATA / "phase7b_clusters" / source / view / "row_clusters.csv"]
    if not all(p.exists() for p in paths):
        return None
    sequence = _sequence_scores(source, view, "test")
    return paths + ([sequence] if sequence else [])


def _scores_stamp(con, source: str, inputs: list) -> str:
    return _stamp(*inputs) + ";sigma=" + _sigma_built(con, source)


def _validation_stamp(con, source: str, inputs: list) -> str:
    return f"v{VALIDATION_VERSION};" + _stamp(*inputs) + ";sigma=" + _sigma_built(con, source)


def _build_scores(con, source: str, view: str) -> None:
    """Scores of the view's flagged observations (the ones the Review page lists)."""
    key = f"{source}/{view}"
    scores_csv, clusters_csv, *sequence_csv = _score_inputs(source, view)
    flagged = {r[0] for r in con.execute("SELECT row_id FROM members WHERE view_key=? AND (flagged=1 OR sigma=1)", (key,))}
    header = list(pd.read_csv(scores_csv, nrows=0).columns)
    when = next((c for c in TIME_COLUMNS if c in header), None)
    wanted = ["row_manifest_id", "host_id", when, "robust_score", "robust_alert", "robust_explanation", "isolation_score",
              "isolation_alert", "novelty_score", "novelty_alert", "novelty_explanation"]
    usecols = [c for c in wanted if c and c in header]
    number = lambda v: None if v is None or v != v or v == "" else float(v)
    yes = lambda v: int(str(v).lower() == "true")
    with _write_lock:
        con.execute("DELETE FROM scores WHERE view_key=?", (key,))
        _status[f"{key}:scores"] = "reading detector scores"
        for chunk in pd.read_csv(scores_csv, usecols=usecols, dtype=str, chunksize=400_000, keep_default_na=False):
            hit = chunk[chunk["row_manifest_id"].isin(flagged)]
            con.executemany("INSERT OR REPLACE INTO scores (view_key, row_id, host, t, robust, robust_alert, robust_why, isolation_forest, "
                            "isolation_forest_alert, novelty, novelty_alert, novelty_why) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                            ((key, r["row_manifest_id"], r.get("host_id", ""), r.get(when, "") if when else "",
                              number(r.get("robust_score")), yes(r.get("robust_alert")), r.get("robust_explanation", ""),
                              number(r.get("isolation_score")), yes(r.get("isolation_alert")),
                              number(r.get("novelty_score")), yes(r.get("novelty_alert")), r.get("novelty_explanation", ""))
                             for r in hit.to_dict("records")))
        _status[f"{key}:scores"] = "reading model-zoo votes"
        zoo_cols = [c for c in ("row_manifest_id", "zoo_votes", "ensemble_score", "ensemble_alert") if c in pd.read_csv(clusters_csv, nrows=0).columns]
        for chunk in pd.read_csv(clusters_csv, usecols=zoo_cols, dtype=str, chunksize=400_000, keep_default_na=False):
            hit = chunk[chunk["row_manifest_id"].isin(flagged)]
            con.executemany("UPDATE scores SET ensemble=?, ensemble_alert=?, votes=? WHERE view_key=? AND row_id=?",
                            ((number(r.get("ensemble_score")), yes(r.get("ensemble_alert")),
                              int(float(r["zoo_votes"])) if r.get("zoo_votes") not in (None, "") else None, key, r["row_manifest_id"])
                             for r in hit.to_dict("records")))
        for path in sequence_csv:
            _status[f"{key}:scores"] = "reading sequence scores"
            _add_sequence_scores(con, key, path, flagged)
        _add_sigma_scores(con, key)
        count = con.execute("SELECT COUNT(*) FROM scores WHERE view_key=?", (key,)).fetchone()[0]
        con.execute("INSERT OR REPLACE INTO score_views VALUES (?,?,?,?)",
                    (key, _scores_stamp(con, source, [scores_csv, clusters_csv, *sequence_csv]), count, time.strftime("%Y-%m-%d %H:%M:%S")))
        con.commit()


GROUP_COLUMNS = ("host_id", "source_ip")       # what a validation group is made of, where the view has it
VALIDATION_PREFIX = "val:"
VALIDATION_VERSION = "3"      # 2: grouped by server and source address; 3: the sequence detector's flags too


def _validation_inputs(source: str, view: str):
    p4 = DATA / "phase4_detection" / source
    paths = [p4 / "detectors" / view / "validation_scores.csv", p4 / "model_zoo" / view / "selected" / "validation_scores.csv"]
    if view != "individual":                                    # a single line is its own observation
        paths.append(DATA / "phase3_features" / source / view / "validation_lineage.csv")
    if not all(p.exists() for p in paths):
        return None
    sequence = _sequence_scores(source, view, "validation")
    return paths + ([sequence] if sequence else [])


def group_id(view: str, key: tuple) -> str:
    """Stable across rebuilds, so a label recorded on a validation group stays with it."""
    return VALIDATION_PREFIX + hashlib.sha1("|".join((view, *key)).encode("utf-8")).hexdigest()[:16]


def _top(counts: dict[str, int], total: int, limit: int = 3) -> str:
    """'spsy (60%); root (40%)', the way Phase 7b writes a cluster's top values."""
    items = sorted(counts.items(), key=lambda kv: -kv[1])[:limit]
    return "; ".join(f"{v} ({round(100 * n / total) if n * 100 >= total else '<1'}%)" for v, n in items)


def _build_validation(con, source: str, view: str) -> None:
    """The validation period's flagged observations, grouped, with their scores and lines."""
    key = f"{source}/{view}"
    inputs = _validation_inputs(source, view)
    scores_csv, zoo_csv = inputs[:2]
    sequence_csv = _sequence_scores(source, view, "validation")
    lineage = [p for p in inputs[2:] if p != sequence_csv]
    progress = f"{key}:validation"
    yes = lambda v: str(v).lower() == "true"
    number = lambda v: None if v is None or v != v or v == "" else float(v)
    # 1. which observations the model zoo's ensemble and the sequence detector flagged
    _status[progress] = "reading model-zoo flags"
    zoo_flagged = set()
    for chunk in pd.read_csv(zoo_csv, usecols=["row_manifest_id", "model_zoo_ensemble_alert"], dtype=str, chunksize=1_000_000, keep_default_na=False):
        zoo_flagged.update(chunk.loc[chunk["model_zoo_ensemble_alert"].str.lower() == "true", "row_manifest_id"])
    sequence_flagged = set()
    if sequence_csv:
        _status[progress] = "reading sequence flags"
        for chunk in pd.read_csv(sequence_csv, usecols=["row_manifest_id", "sequence_alert"], dtype=str, chunksize=1_000_000, keep_default_na=False):
            sequence_flagged.update(chunk.loc[chunk["sequence_alert"].str.lower() == "true", "row_manifest_id"])
    sigma_flagged = {r[0] for r in con.execute("SELECT row_id FROM sigma_flags WHERE view_key=?", (key,))}
    # 2. every observation counted by group; the flagged ones kept with their detector scores
    header = list(pd.read_csv(scores_csv, nrows=0).columns)
    when = next((c for c in TIME_COLUMNS if c in header), None)
    by = [c for c in GROUP_COLUMNS if c in header]
    usecols = [c for c in ["row_manifest_id", when, *by, "username", "robust_score", "robust_alert", "robust_explanation", "isolation_score",
                           "isolation_alert", "novelty_score", "novelty_alert", "novelty_explanation"] if c and c in header]
    totals, flagged_rows = {}, []
    _status[progress] = "reading detector scores"
    for chunk in pd.read_csv(scores_csv, usecols=usecols, dtype=str, chunksize=500_000, keep_default_na=False):
        for k, n in chunk.groupby(by, sort=False).size().items():
            k = k if isinstance(k, tuple) else (k,)
            totals[k] = totals.get(k, 0) + int(n)
        hit = chunk[chunk["robust_alert"].str.lower().eq("true") | chunk["isolation_alert"].str.lower().eq("true")
                    | chunk["novelty_alert"].str.lower().eq("true") | chunk["row_manifest_id"].isin(zoo_flagged)
                    | chunk["row_manifest_id"].isin(sequence_flagged) | chunk["row_manifest_id"].isin(sigma_flagged)]
        flagged_rows.extend(hit.to_dict("records"))
    groups = {}
    for r in flagged_rows:
        k = tuple(r[c] for c in by)
        g = groups.setdefault(k, {"flagged": 0, "first": None, "last": None, "users": {}})
        t = r.get(when, "") if when else ""
        g["flagged"] += 1
        user = r.get("username", "")
        if user:
            g["users"][user] = g["users"].get(user, 0) + 1
        g["first"] = t if g["first"] is None or t < g["first"] else g["first"]
        g["last"] = t if g["last"] is None or t > g["last"] else g["last"]
        r["_gid"] = group_id(view, k)
    with _write_lock:
        old = "SELECT row_id FROM members WHERE view_key=? AND cluster LIKE 'val:%'"
        con.execute(f"DELETE FROM scores WHERE view_key=? AND row_id IN ({old})", (key, key))
        con.execute("DELETE FROM members WHERE view_key=? AND cluster LIKE 'val:%'", (key,))
        con.execute("DELETE FROM vgroups WHERE view_key=?", (key,))
        pick = lambda k, c: k[by.index(c)] if c in by else ""
        con.executemany("INSERT INTO vgroups VALUES (?,?,?,?,?,?,?,?,?)",
                        ((key, group_id(view, k), pick(k, "host_id"), _top(g["users"], g["flagged"]), pick(k, "source_ip"),
                          totals.get(k, g["flagged"]), g["flagged"], g["first"], g["last"]) for k, g in groups.items()))
        con.executemany("INSERT OR IGNORE INTO members (view_key, cluster, row_id, flagged, t) VALUES (?,?,?,1,?)",
                        ((key, r["_gid"], r["row_manifest_id"], r.get(when, "") if when else "") for r in flagged_rows))
        con.executemany("INSERT OR REPLACE INTO scores (view_key, row_id, host, t, robust, robust_alert, robust_why, isolation_forest, "
                        "isolation_forest_alert, novelty, novelty_alert, novelty_why) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        ((key, r["row_manifest_id"], r.get("host_id", ""), r.get(when, "") if when else "",
                          number(r.get("robust_score")), int(yes(r.get("robust_alert"))), r.get("robust_explanation", ""),
                          number(r.get("isolation_score")), int(yes(r.get("isolation_alert"))),
                          number(r.get("novelty_score")), int(yes(r.get("novelty_alert"))), r.get("novelty_explanation", ""))
                         for r in flagged_rows))
        con.commit()
        # 3. the model zoo's ensemble score and member votes of the flagged ones
        _status[progress] = "reading model-zoo votes"
        wanted = {r["row_manifest_id"] for r in flagged_rows}
        for chunk in pd.read_csv(zoo_csv, usecols=["row_manifest_id", "model_zoo_ensemble_score", "model_zoo_ensemble_alert", "member_vote_count"],
                                 dtype=str, chunksize=1_000_000, keep_default_na=False):
            hit = chunk[chunk["row_manifest_id"].isin(wanted)]
            con.executemany("UPDATE scores SET ensemble=?, ensemble_alert=?, votes=? WHERE view_key=? AND row_id=?",
                            ((number(r["model_zoo_ensemble_score"]), int(yes(r["model_zoo_ensemble_alert"])),
                              int(float(r["member_vote_count"])) if r["member_vote_count"] else None, key, r["row_manifest_id"])
                             for r in hit.to_dict("records")))
        if sequence_csv:
            _status[progress] = "reading sequence scores"
            _add_sequence_scores(con, key, sequence_csv, wanted)
        _mark_sigma(con, key)
        _add_sigma_scores(con, key)
        # 4. their lines (multi-line views): the events each one is made of
        for path in lineage:
            _status[progress] = "linking lines"
            record_column = "record_id" if "record_id" in pd.read_csv(path, nrows=0).columns else "event_id"
            for chunk in pd.read_csv(path, usecols=["row_manifest_id", "event_position", record_column], dtype=str, chunksize=2_000_000):
                hit = chunk[chunk["row_manifest_id"].isin(wanted)]
                if len(hit):
                    con.executemany("INSERT OR IGNORE INTO links VALUES (?,?,?,?)",
                                    ((key, r, int(pos or 1), e) for r, pos, e in
                                     hit[["row_manifest_id", "event_position", record_column]].itertuples(index=False)))
        con.execute("INSERT OR REPLACE INTO val_views VALUES (?,?,?,?,?)",
                    (key, _validation_stamp(con, source, inputs), sum(totals.values()), len(flagged_rows), time.strftime("%Y-%m-%d %H:%M:%S")))
        con.commit()


MISSING = "purged" if FROZEN else "missing"       # frozen: what the index lacks can never be built


def validation_status(source: str, view: str) -> str:
    return _status.get(f"{source}/{view}:validation", MISSING)


def validation_groups(source: str, view: str) -> list[dict]:
    """The validation period's groups with flagged observations, with how often the view as a whole was flagged."""
    if validation_status(source, view) != "ready":
        return []
    con = _connect()
    try:
        con.row_factory = sqlite3.Row
        view_row = con.execute("SELECT rows, flagged FROM val_views WHERE view_key=?", (f"{source}/{view}",)).fetchone()
        rate = (view_row["flagged"] / view_row["rows"]) if view_row and view_row["rows"] else 0.0
        out = []
        for r in con.execute("SELECT * FROM vgroups WHERE view_key=?", (f"{source}/{view}",)):
            share = r["flagged"] / r["rows"] if r["rows"] else 0.0
            out.append({**dict(r), "alert_rate": share, "lift": share / rate if rate else 0.0})
        return out
    finally:
        con.close()


def start_background() -> None:
    def run():
        con = _connect()
        if FROZEN:                                    # the inputs are gone: whatever the index holds is ready, as it is
            for table, suffix in (("views", ""), ("map_views", ":map"), ("score_views", ":scores"), ("val_views", ":validation")):
                for (key,) in con.execute(f"SELECT view_key FROM {table}"):
                    _status[key + suffix] = "ready"
            for (source,) in con.execute("SELECT source FROM sigma_views"):
                _status[f"{source}:sigma"] = "ready"
            con.close()
            return
        todo = []
        for source, view, clusters_csv, lineage_csv in _views():
            key = f"{source}/{view}"
            row = con.execute("SELECT stamp FROM views WHERE view_key=?", (key,)).fetchone()
            if row and row[0] == _stamp(clusters_csv, lineage_csv):
                _status[key] = "ready"
            else:
                _status[key] = "waiting"
                todo.append((lineage_csv.stat().st_size, source, view, clusters_csv, lineage_csv))
        for _, source, view, clusters_csv, lineage_csv in sorted(todo):      # smallest first
            key = f"{source}/{view}"
            try:
                _build(con, source, view, clusters_csv, lineage_csv)
                _status[key] = "ready"
            except Exception as error:                     # keep the other views going
                con.rollback()
                _status[key] = f"failed: {error}"
        # then the map's earlier points (single-line views need no links: the point is the line)
        later = []
        for source, view, _, _ in _views():
            key, inputs = f"{source}/{view}", _map_inputs(source, view)
            if view == "individual" or inputs is None:
                continue
            row = con.execute("SELECT stamp FROM map_views WHERE view_key=?", (key,)).fetchone()
            if row and row[0] == _stamp(*inputs):
                _status[f"{key}:map"] = "ready"
            else:
                _status[f"{key}:map"] = "waiting"
                later.append((sum(p.stat().st_size for p in inputs), source, view))
        for _, source, view in sorted(later):
            try:
                _build_map_links(con, source, view)
                _status[f"{source}/{view}:map"] = "ready"
            except Exception as error:
                con.rollback()
                _status[f"{source}/{view}:map"] = f"failed: {error}"
        # then the Sigma rules over the validation and test periods: what they flag counts for the scores and Review
        for source in STORES:
            views = _source_views(source)
            if not views or any(status(source, v) != "ready" for v in views):
                continue
            from . import sigma_review
            stamp = sigma_review.stamp(source, STORES[source][0], views)
            if stamp is None or _sigma_built(con, source) == stamp:     # None: the logs are gone, what was found stays
                _status[f"{source}:sigma"] = "ready" if _sigma_built(con, source) else MISSING
                continue
            _status[f"{source}:sigma"] = "waiting"
            try:
                _build_sigma(con, source, stamp)
                _status[f"{source}:sigma"] = "ready"
            except Exception as error:
                con.rollback()
                _status[f"{source}:sigma"] = f"failed: {error}"
        # then the scores of flagged observations, for the Review page
        later = []
        for source, view, _, _ in _views():
            key, inputs = f"{source}/{view}", _score_inputs(source, view)
            if inputs is None or status(source, view) != "ready":
                continue
            row = con.execute("SELECT stamp FROM score_views WHERE view_key=?", (key,)).fetchone()
            if row and row[0] == _scores_stamp(con, source, inputs):
                _status[f"{key}:scores"] = "ready"
            else:
                _status[f"{key}:scores"] = "waiting"
                later.append((inputs[0].stat().st_size, source, view))
        for _, source, view in sorted(later):
            try:
                _build_scores(con, source, view)
                _status[f"{source}/{view}:scores"] = "ready"
            except Exception as error:
                con.rollback()
                _status[f"{source}/{view}:scores"] = f"failed: {error}"
        # then the validation period's flagged observations, grouped, for the Review page
        later = []
        for source, view, _, _ in _views():
            key, inputs = f"{source}/{view}", _validation_inputs(source, view)
            if inputs is None or status(source, view) != "ready":
                continue
            row = con.execute("SELECT stamp FROM val_views WHERE view_key=?", (key,)).fetchone()
            if row and row[0] == _validation_stamp(con, source, inputs):
                _status[f"{key}:validation"] = "ready"
            else:
                _status[f"{key}:validation"] = "waiting"
                later.append((inputs[0].stat().st_size, source, view))
        for _, source, view in sorted(later):
            try:
                _build_validation(con, source, view)
                _status[f"{source}/{view}:validation"] = "ready"
            except Exception as error:
                con.rollback()
                _status[f"{source}/{view}:validation"] = f"failed: {error}"
        con.close()

    _launch(run)


_runner = {"thread": None, "again": False}
_runner_lock = threading.Lock()


def _launch(run) -> None:
    """One pass at a time. A call during a pass asks for one more after it (the Sigma rules changed while it ran);
    each part of a pass rebuilds only when its inputs changed."""
    with _runner_lock:
        if _runner["thread"] is not None:
            _runner["again"] = True
            return

        def loop():
            while True:
                try:
                    run()
                except Exception as error:            # never fatal: the parts already built stay
                    _status["index"] = f"failed: {error}"
                with _runner_lock:
                    if not _runner["again"]:
                        _runner["thread"] = None
                        return
                    _runner["again"] = False

        _runner["thread"] = threading.Thread(target=loop, daemon=True, name="cluster-index")
        _runner["thread"].start()


def refresh() -> None:
    """Bring the index up to date again in the background (after the Sigma rules change)."""
    start_background()


def status(source: str = "", view: str = "") -> dict | str:
    if source and view:
        return _status.get(f"{source}/{view}", MISSING)
    return dict(_status)


def composition(source: str, view: str) -> dict[str, list[tuple[str, int]]]:
    if status(source, view) != "ready":
        return {}
    con = _connect()
    try:
        out: dict[str, list[tuple[str, int]]] = {}
        for cluster, event_type, lines in con.execute(
                "SELECT cluster, event_type, lines FROM composition WHERE view_key=? ORDER BY cluster, lines DESC",
                (f"{source}/{view}",)):
            out.setdefault(cluster, []).append((event_type, lines))
        return out
    finally:
        con.close()


def _store(source: str) -> tuple:
    """The source's log store, or a clear error once the logs have been purged."""
    store, store_key = STORES[source]
    if not store.exists():
        raise ValueError("The original log lines are not on this laptop any more (data/ was purged); the map and its groups remain.")
    return store, store_key


def members(source: str, view: str, cluster: str, offset: int = 0, limit: int = 25,
            flagged_only: bool = False, lines_per: int = 12) -> dict:
    key = f"{source}/{view}"
    if status(source, view) != "ready":
        return {"status": status(source, view), "total": None, "items": []}
    store, store_key = _store(source)
    con = _connect()
    con.execute("ATTACH DATABASE ? AS store", (f"file:{store.as_posix()}?mode=ro",))
    try:
        where = "view_key=? AND cluster=?" + (" AND (flagged=1 OR sigma=1)" if flagged_only else "")
        total = con.execute(f"SELECT COUNT(*) FROM members WHERE {where}", (key, cluster)).fetchone()[0]
        flagged = con.execute("SELECT COUNT(*) FROM members WHERE view_key=? AND cluster=? AND (flagged=1 OR sigma=1)",
                              (key, cluster)).fetchone()[0]
        rows = con.execute(f"SELECT row_id, MAX(flagged, sigma) AS f, t FROM members WHERE {where} ORDER BY f DESC, t LIMIT ? OFFSET ?",
                           (key, cluster, limit, offset)).fetchall()
        items = []
        for row_id, is_flagged, t in rows:
            if view == "individual":
                found = con.execute(f"SELECT original_log_line, event_type FROM store.events WHERE {store_key}=?", (row_id,)).fetchone()
                lines, count = ([found[0]] if found else []), 1
            else:
                count = con.execute("SELECT COUNT(*) FROM links WHERE view_key=? AND row_id=?", (key, row_id)).fetchone()[0]
                lines = [r[0] for r in con.execute(
                    f"SELECT e.original_log_line FROM links l JOIN store.events e ON e.{store_key} = l.record_id "
                    "WHERE l.view_key=? AND l.row_id=? ORDER BY l.position LIMIT ?", (key, row_id, lines_per))]
            items.append({"row_id": row_id, "flagged": bool(is_flagged), "time": t or "", "lines": lines, "line_count": count})
        return {"status": "ready", "total": total, "flagged": flagged, "items": items}
    finally:
        con.close()


def point_lines(source: str, view: str, row_id: str, split: str, limit: int = 20) -> dict:
    """The original lines of one map point, from any period."""
    store, store_key = _store(source)
    if view == "individual":                      # one observation is one line, and its ID is the line's
        con = sqlite3.connect(f"file:{store.as_posix()}?mode=ro", uri=True)
        try:
            found = con.execute(f"SELECT original_log_line FROM events WHERE {store_key}=?", (row_id,)).fetchone()
        finally:
            con.close()
        return {"status": "ready", "lines": [found[0]] if found else [], "line_count": 1 if found else 0}
    key = f"{source}/{view}"
    progress_key = key if split == "test" else f"{key}:map"
    if status(source, view) != "ready" or _status.get(progress_key) != "ready":
        return {"status": _status.get(progress_key, MISSING), "lines": [], "line_count": None}
    con = _connect()
    con.execute("ATTACH DATABASE ? AS store", (f"file:{store.as_posix()}?mode=ro",))
    try:
        count = con.execute("SELECT COUNT(*) FROM links WHERE view_key=? AND row_id=?", (key, row_id)).fetchone()[0]
        lines = [r[0] for r in con.execute(
            f"SELECT e.original_log_line FROM links l JOIN store.events e ON e.{store_key} = l.record_id "
            "WHERE l.view_key=? AND l.row_id=? ORDER BY l.position LIMIT ?", (key, row_id, limit))]
        return {"status": "ready", "lines": lines, "line_count": count}
    finally:
        con.close()


def scores_status(source: str, view: str) -> str:
    return _status.get(f"{source}/{view}:scores", MISSING)


def flagged_scores(source: str, view: str, cluster: str, limit: int | None = 200) -> list[dict]:
    """A cluster's flagged observations with their scores (empty until the scores pass is done); limit None for all."""
    con = _connect()
    try:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT s.view_key, s.row_id, s.host, s.t, s.robust, s.robust_alert, s.isolation_forest, s.isolation_forest_alert, "
                           "s.novelty, s.novelty_alert, s.ensemble, s.ensemble_alert, s.votes, s.sequence, s.sequence_alert, s.sigma_alert, s.sigma_why "
                           "FROM members m JOIN scores s ON s.view_key = m.view_key AND s.row_id = m.row_id "
                           "WHERE m.view_key=? AND m.cluster=? AND (m.flagged=1 OR m.sigma=1) LIMIT ?", (f"{source}/{view}", cluster, -1 if limit is None else limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def score_row(source: str, view: str, row_id: str) -> dict | None:
    con = _connect()
    try:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM scores WHERE view_key=? AND row_id=?", (f"{source}/{view}", row_id)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def observation_events(source: str, view: str, row_id: str, limit: int = 5000) -> list[tuple[str, str]]:
    """(event id, time) of the events that make up one observation, in order; none once the logs are purged."""
    store, store_key = STORES[source]
    if not store.exists():
        return []
    if view == "individual":
        con = sqlite3.connect(f"file:{store.as_posix()}?mode=ro", uri=True)
        try:
            return [tuple(r) for r in con.execute(f"SELECT {store_key}, timestamp_text FROM events WHERE {store_key}=?", (row_id,))]
        finally:
            con.close()
    con = _connect()
    con.execute("ATTACH DATABASE ? AS store", (f"file:{store.as_posix()}?mode=ro",))
    try:
        return [tuple(r) for r in con.execute(
            f"SELECT l.record_id, e.timestamp_text FROM links l JOIN store.events e ON e.{store_key} = l.record_id "
            "WHERE l.view_key=? AND l.row_id=? ORDER BY l.position LIMIT ?", (f"{source}/{view}", row_id, limit))]
    finally:
        con.close()
