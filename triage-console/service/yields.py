"""Label yield per mechanism (the Dashboard's Label yield card): of the items each mechanism raised and a reviewer
labelled, how many were security relevant or suspicious (precision) and how many expected behaviour. It is how a
mechanism earns its share of the alert budget, and it grows with every label.

An item counts for every mechanism behind it:

* a group of the test period in AUTH sessions or OSSEC episodes: each mechanism that flagged any of its flagged rows
  (Isolation Forest, model zoo, Novelty, frequent subsequences; outliers.masks), and Sigma when a rule matched;
* a group in another view: "Other views" (its detectors), and Sigma when a rule matched;
* a Phase 4g activity alert: "Activity"; a firewall presence alert: "Presence";
* an upload's item: "Uploads" (Analyze's scoring).

Labels are each item's latest, as Review shows them. Counts only; no names.
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from contextlib import closing

from . import cluster_index, outliers, store

GROUPS = [("sigma", "Sigma rules"), ("isolation_forest", "Isolation Forest"), ("model_zoo", "Model zoo"),
          ("novelty", "Novelty"), ("sequence", "Frequent subsequences"), ("other_views", "Other views"),
          ("activity", "Activity"), ("presence", "Presence"), ("uploads", "Uploads")]
RELEVANT = ("security_relevant", "suspicious")


def _flagged_rows(con, source: str, view: str, cluster: str) -> list[str]:
    return [r for (r,) in con.execute("SELECT row_id FROM members WHERE view_key = ? AND cluster = ? AND flagged = 1",
                                      (f"{source}/{view}", cluster))]


def mechanisms(source: str, item: dict, masks: dict | None, con=None) -> list[str]:
    """The GROUPS keys behind one Review item."""
    kind = item.get("kind")
    if kind == "activity_alert":
        return ["activity"]
    if kind == "presence_alert":
        return ["presence"]
    keys = ["sigma"] if item.get("sigma") else []
    if kind == "cluster" and item.get("view") == outliers.VIEWS.get(source) and item.get("period") == "test" and masks is not None:
        bits = 0
        if con is not None:
            for row_id in _flagged_rows(con, source, item["view"], str(item.get("item_id"))):
                bits |= masks.get(row_id, 0)
        keys += [key for bit, (key, _) in enumerate(outliers.MECHANISMS) if bits & (1 << bit)]
    elif kind == "cluster":
        keys.append("other_views")
    return keys


def summary(queues: dict[str, list[dict]]) -> list[dict]:
    """queues: {source: Review's items} (clusters.review_queue). One row per mechanism that has labelled items."""
    counts = {key: Counter() for key, _ in GROUPS}
    con = None
    try:
        con = cluster_index._connect() if cluster_index.INDEX_FILE.exists() else None
    except sqlite3.Error:
        con = None
    try:
        for source, items in queues.items():
            masks = outliers.masks(source)
            for item in items:
                if item.get("review"):
                    for key in mechanisms(source, item, masks, con):
                        counts[key][item["review"]["verdict"]] += 1
    finally:
        if con is not None:
            con.close()
    with closing(store.connect()) as con:
        for (verdict,) in con.execute("SELECT verdict FROM reviews r WHERE item_id LIKE 'upload-%' AND id = "
                                      "(SELECT MAX(id) FROM reviews s WHERE s.source = r.source AND s.view = r.view AND s.item_id = r.item_id)"):
            counts["uploads"][verdict] += 1
    out = []
    for key, label in GROUPS:
        n = sum(counts[key].values())
        if n:
            out.append({"key": key, "label": label, "n": n, **{v: counts[key].get(v, 0) for v in store.VERDICTS},
                        "precision": sum(counts[key].get(v, 0) for v in RELEVANT) / n,
                        "expected": counts[key].get("expected_behavior", 0) / n})
    return out
