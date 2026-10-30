"""The audit sample (Investigate → Audit): a small random sample of the test period, labelled blind, for the only
unbiased estimates the console has. Review's labels fall on what the detectors surfaced, most unusual first, so they
say nothing about what was missed and flatter precision; the audit sample does neither.

Each month (draw()), per log type, from the test period's observations in the view every mechanism scores (AUTH
sessions, OSSEC episodes), a stratified random sample with a fixed seed per month:

    unflagged        SIZES["unflagged"] of the observations no mechanism flagged
    flagged_lower    SIZES["flagged_lower"] of the flagged ones in the lower half by Isolation Forest score
    flagged_upper    SIZES["flagged_upper"] of the flagged ones in the upper half

Flagged means robust deviation, Isolation Forest, the model zoo's consensus, novelty or frequent subsequences
(outliers.masks and the detectors' robust alert). The Audit page shows an item's lines and nothing else: no stratum,
score or flag, so the label is not anchored. Labels are kept like Review's (store.reviews, item kind "audit", item
"audit:<row>") and are evaluation-only: they never train anything.

estimates(): Security relevant and Suspicious count as relevant; Insufficient evidence counts as unlabelled. Each
stratum's population N and labelled items give its share relevant; with Jeffreys posteriors per stratum (Beta(r + ½,
m − r + ½)) drawn DRAWS times:

    precision   relevant share of flagged observations, the strata weighted by their populations
    miss rate   relevant share of unflagged observations (missed per 10,000)
    recall      flagged relevant / (flagged relevant + unflagged relevant)

each with its 2.5th and 97.5th percentiles. Per mechanism, its weighted precision among the audited flagged items it
flagged, with a Jeffreys interval on Kish's effective n. Counts and shares only; no names.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import date

import numpy as np
import pandas as pd
from scipy import stats

from . import outliers, store
from .config import DATA

VIEWS = outliers.VIEWS                                        # auth: authentication_sessions, ossec: episodes
SIZES = {"unflagged": 10, "flagged_lower": 10, "flagged_upper": 5}
STRATA = tuple(SIZES)
FLAGGED = ("flagged_lower", "flagged_upper")
RELEVANT = ("security_relevant", "suspicious")
DRAWS = 4000
MECHANISMS = [key for key, _ in outliers.MECHANISMS] + ["robust"]
SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_items (
    month TEXT, source TEXT, view TEXT, row_id TEXT, stratum TEXT, population INTEGER, mechanisms TEXT, drawn_at TEXT,
    PRIMARY KEY (month, source, row_id)) WITHOUT ROWID;
"""


def _connect():
    con = store.connect()
    con.executescript(SCHEMA)
    return con


def item_id(row_id: str) -> str:
    return f"audit:{row_id}"


def population(source: str) -> dict[str, pd.DataFrame] | None:
    """{stratum: rows (row_id, mechanisms)} of the test period, or None without the detectors' scores."""
    view = VIEWS[source]
    path = DATA / "phase4_detection" / source / "detectors" / view / "test_scores.csv"
    if not path.is_file():
        return None
    frame = pd.read_csv(path, usecols=lambda c: c in {"row_manifest_id", "robust_alert", "isolation_score"}, dtype=str)
    masks = outliers.masks(source) or {}
    robust = frame.get("robust_alert", pd.Series("", index=frame.index)).str.lower().isin(("true", "1"))
    names = []
    for row_id, is_robust in zip(frame["row_manifest_id"], robust):
        bits = masks.get(row_id, 0)
        found = [key for bit, (key, _) in enumerate(outliers.MECHANISMS) if bits & (1 << bit)] + (["robust"] if is_robust else [])
        names.append("|".join(found))
    frame = pd.DataFrame({"row_id": frame["row_manifest_id"], "mechanisms": names,
                          "score": pd.to_numeric(frame["isolation_score"], errors="coerce")})
    flagged = frame[frame["mechanisms"] != ""]
    middle = flagged["score"].median()
    return {"unflagged": frame[frame["mechanisms"] == ""], "flagged_lower": flagged[flagged["score"] < middle],
            "flagged_upper": flagged[flagged["score"] >= middle]}


def _seed(month: str, source: str) -> int:
    return int(hashlib.sha256(f"audit|{month}|{source}".encode()).hexdigest()[:8], 16)


def draw(month: str | None = None, actor: str = "audit") -> dict:
    """This month's sample (drawn once; later calls return it)."""
    month = month or date.today().strftime("%Y-%m")
    with store._lock, _connect() as con:
        if con.execute("SELECT 1 FROM audit_items WHERE month = ? LIMIT 1", (month,)).fetchone():
            return {"month": month, "drawn": False}
        added = 0
        for source in VIEWS:
            strata = population(source)
            if strata is None:
                continue
            rng = np.random.default_rng(_seed(month, source))
            for stratum, size in SIZES.items():
                rows = strata[stratum]
                if not len(rows):
                    continue
                picked = rows.iloc[rng.choice(len(rows), min(size, len(rows)), replace=False)]
                con.executemany("INSERT OR IGNORE INTO audit_items VALUES (?,?,?,?,?,?,?,?)",
                                [(month, source, VIEWS[source], r.row_id, stratum, len(rows), r.mechanisms, store.now())
                                 for r in picked.itertuples()])
                added += len(picked)
        if added:
            store.audit(con, actor, "audit_sample_drawn", f"audit/{month}", {"items": added})
    return {"month": month, "drawn": bool(added), "items": added}


def _labelled(con) -> pd.DataFrame:
    """Every audit item with its latest label ('' when none)."""
    items = pd.read_sql_query("SELECT * FROM audit_items ORDER BY month, source, row_id", con)
    if not len(items):
        return items.assign(verdict=pd.Series(dtype=str), note=pd.Series(dtype=str))
    labels = pd.read_sql_query(
        "SELECT source, view, item_id, verdict, note FROM reviews r WHERE item_kind = 'audit' AND id = "
        "(SELECT MAX(id) FROM reviews s WHERE s.source = r.source AND s.view = r.view AND s.item_id = r.item_id)", con)
    labels["row_id"] = labels["item_id"].str.removeprefix("audit:")
    items = items.merge(labels[["source", "view", "row_id", "verdict", "note"]], on=["source", "view", "row_id"], how="left")
    return items.fillna({"verdict": "", "note": ""})


def listing(month: str | None = None) -> dict:
    """The month's items for the Audit page (no stratum, score or flag), and the estimates over every month."""
    with closing(_connect()) as con:
        items = _labelled(con)
        months = sorted(items["month"].unique().tolist(), reverse=True) if len(items) else []
    month = month or (months[0] if months else date.today().strftime("%Y-%m"))
    shown = items[items["month"] == month]
    order = np.argsort([hashlib.sha256(r.encode()).hexdigest() for r in shown["row_id"]])   # not by stratum
    return {"month": month, "months": months,
            "items": [{"n": i + 1, "source": r.source, "view": r.view, "row_id": r.row_id, "item_id": item_id(r.row_id),
                       "verdict": r.verdict, "note": r.note} for i, r in enumerate(shown.iloc[order].itertuples())],
            "estimates": estimates(items)}


def _interval(samples: np.ndarray) -> tuple[float, float]:
    finite = samples[np.isfinite(samples)]
    return (float(np.quantile(finite, 0.025)), float(np.quantile(finite, 0.975))) if len(finite) else (0.0, 1.0)


def estimates(items: pd.DataFrame | None = None, draws: int = DRAWS, seed: int = 0) -> dict:
    """Precision, miss rate and recall per log type and overall, and precision per mechanism (module docstring)."""
    if items is None:
        with closing(_connect()) as con:
            items = _labelled(con)
    labelled = items[items["verdict"].ne("") & items["verdict"].ne("insufficient_evidence")] if len(items) else items
    rng = np.random.default_rng(seed)
    out = {"labelled": int(len(labelled)), "drawn": int(len(items)), "sources": {}}
    totals = {"flagged": np.zeros(draws), "flagged_n": 0.0, "missed": np.zeros(draws), "unflagged_n": 0.0}
    for source in VIEWS:
        mine, cells = items[items["source"] == source] if len(items) else items, {}
        if not len(mine):
            continue
        for stratum in STRATA:
            part = mine[mine["stratum"] == stratum]
            done = labelled[(labelled["source"] == source) & (labelled["stratum"] == stratum)] if len(labelled) else labelled
            population = int(part["population"].max()) if len(part) else 0
            r, m = int(done["verdict"].isin(RELEVANT).sum()) if len(done) else 0, int(len(done))
            cells[stratum] = (population, r, m, rng.beta(r + 0.5, m - r + 0.5, draws))
        flagged_n = sum(cells[s][0] for s in FLAGGED)
        relevant_flagged = sum(cells[s][0] * cells[s][3] for s in FLAGGED)
        missed = cells["unflagged"][0] * cells["unflagged"][3]
        precision = relevant_flagged / flagged_n if flagged_n else np.full(draws, np.nan)
        recall = np.where(relevant_flagged + missed > 0, relevant_flagged / np.maximum(relevant_flagged + missed, 1e-12), np.nan)
        m_flagged, m_unflagged = sum(cells[s][2] for s in FLAGGED), cells["unflagged"][2]
        out["sources"][source] = {
            "labelled": {s: cells[s][2] for s in STRATA}, "population": {s: cells[s][0] for s in STRATA},
            "precision": _summary(precision, m_flagged), "miss_rate": _summary(cells["unflagged"][3], m_unflagged),
            "recall": _summary(recall, m_flagged + m_unflagged)}
        totals["flagged"] += relevant_flagged
        totals["flagged_n"] += flagged_n
        totals["missed"] += missed
        totals["unflagged_n"] += cells["unflagged"][0]
    if totals["flagged_n"] or totals["unflagged_n"]:
        n_flagged = int(labelled["stratum"].isin(FLAGGED).sum()) if len(labelled) else 0
        n_unflagged = int((labelled["stratum"] == "unflagged").sum()) if len(labelled) else 0
        both = totals["flagged"] + totals["missed"]
        out["overall"] = {
            "precision": _summary(totals["flagged"] / totals["flagged_n"] if totals["flagged_n"] else np.full(draws, np.nan), n_flagged),
            "miss_rate": _summary(totals["missed"] / totals["unflagged_n"] if totals["unflagged_n"] else np.full(draws, np.nan), n_unflagged),
            "recall": _summary(np.where(both > 0, totals["flagged"] / np.maximum(both, 1e-12), np.nan), n_flagged + n_unflagged)}
    out["mechanisms"] = _by_mechanism(items, labelled)
    return out


def _summary(samples, n: int) -> dict:
    samples = np.asarray(samples, dtype=float)
    low, high = _interval(samples)
    finite = samples[np.isfinite(samples)]
    return {"estimate": float(np.median(finite)) if len(finite) else None, "low": low, "high": high, "n": int(n)}


def _by_mechanism(items: pd.DataFrame, labelled: pd.DataFrame) -> dict:
    """Per mechanism: weighted precision among the audited flagged items it flagged; Jeffreys interval on Kish's n."""
    flagged = labelled[labelled["stratum"].isin(FLAGGED)] if len(labelled) else labelled
    if not len(flagged):
        return {}
    counts = flagged.groupby(["source", "stratum"]).size()
    weight = flagged.apply(lambda r: r["population"] / counts[(r["source"], r["stratum"])], axis=1).to_numpy(dtype=float)
    relevant = flagged["verdict"].isin(RELEVANT).to_numpy()
    out = {}
    for mechanism in MECHANISMS:
        has = flagged["mechanisms"].str.split("|").apply(lambda names: mechanism in names).to_numpy()
        if not has.any():
            continue
        w = weight[has]
        p = float((w * relevant[has]).sum() / w.sum())
        n_eff = float(w.sum() ** 2 / (w ** 2).sum())
        low, high = stats.beta.ppf([0.025, 0.975], p * n_eff + 0.5, (1 - p) * n_eff + 0.5)
        out[mechanism] = {"estimate": p, "low": float(low), "high": float(high), "n": int(has.sum())}
    return out
