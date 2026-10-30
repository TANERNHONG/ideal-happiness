"""Is it the server or the behaviour? A diagnostic for alerts that pile up on a few servers (README, known gap 5).

If a model has learned each server's routine rather than what normal looks like, a server with little training
data is unusual for being rare, not for what it did. Two checks, per log type and view:

1. Volume: per server, its share of test rows flagged by the Isolation Forest (the detectors' test_scores.csv)
   against its number of training rows (Phase 3's train_rows.csv). A strongly negative Spearman correlation (less
   training, more alerts) points at identity.
2. Leave one server out: for the --hosts servers with the highest flagged share, an Isolation Forest is fitted on a
   training sample with that server and on one without it (the detectors' features and settings), each thresholded
   at the detectors' own validation alert share on validation rows of the other servers, and the server's test
   alert rate is compared. A rate that jumps without its own training rows means its alerts come from being
   itself. The servers are numbered by flagged share in the output, never named.

    python pipeline/phase4_detection/host_identity_check.py --source auth [--view authentication_sessions] [--hosts 3]

Writes data/phase4_detection/<source>/diagnostics/host_identity_<view>.json (server names stay in that file, on this
laptop); prints counts, shares and correlations only. Mitigations (server-relative time features, Phase 4f's routine
columns in place of event-order hashing) follow only if the evidence says so.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import IsolationForest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shared"))
sys.path.insert(0, str(HERE))
import runlog  # noqa: E402  console output: pipeline/STYLE_GUIDE.md
from auth_detectors import load_sparse  # noqa: E402  the same streaming reader for both log types' features

LOGGER = runlog.LOGGER
VIEWS = {"auth": "authentication_sessions", "ossec": "episodes"}
HOSTS = ("host_id", "hostname")
SEED = 42


def host_column(columns) -> str | None:
    return next((c for c in HOSTS if c in columns), None)


def volume_check(test: pd.DataFrame, train_hosts: pd.Series) -> tuple[float, pd.DataFrame]:
    """(Spearman rho of flagged share against training rows, the per-server table)."""
    column = host_column(test.columns)
    flagged = test["isolation_alert"].astype(str).str.lower().isin(("true", "1"))
    table = pd.DataFrame({"test_rows": test.groupby(column).size(), "flagged": flagged.groupby(test[column]).sum()})
    table["flagged_share"] = table["flagged"] / table["test_rows"]
    table["train_rows"] = train_hosts.value_counts().reindex(table.index).fillna(0).astype(int)
    table = table.sort_values("flagged_share", ascending=False)
    rho = stats.spearmanr(table["train_rows"], table["flagged_share"]).statistic if len(table) > 2 else np.nan
    return float(rho), table


def alert_rate(train_x, valid_x, test_x, share: float) -> float:
    """Test alert rate of an Isolation Forest fitted on train_x, thresholded at `share` of valid_x."""
    model = IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1).fit(train_x)
    threshold = np.quantile(-model.score_samples(valid_x), 1 - share)
    return float(np.mean(-model.score_samples(test_x) >= threshold)) if test_x.shape[0] else float("nan")


def leave_one_out(features: Path, bundle: dict, host: str, train_hosts, valid_hosts, test_hosts, share, sample, rng) -> dict:
    columns = sorted(bundle["isolation_feature_indices"]) if "isolation_feature_indices" in bundle else None

    def rows(hosts, keep, limit):
        picked = np.flatnonzero(keep(hosts))
        return np.sort(rng.choice(picked, min(limit, len(picked)), replace=False)) if len(picked) else picked
    train_with = rows(train_hosts, lambda h: np.ones(len(h), bool), sample)
    train_without = rows(train_hosts, lambda h: h != host, sample)
    valid_other = rows(valid_hosts, lambda h: h != host, sample)
    test_host = rows(test_hosts, lambda h: h == host, sample)
    load = lambda split, r: load_sparse(features / f"X_{split}.npz", columns, rows=r)[0]  # noqa: E731
    x_with, x_without = load("train", train_with), load("train", train_without)
    x_valid, x_test = load("validation", valid_other), load("test", test_host)
    return {"rate_with": alert_rate(x_with, x_valid, x_test, share), "rate_without": alert_rate(x_without, x_valid, x_test, share),
            "train_rows_of_server": int(np.count_nonzero(np.asarray(train_hosts) == host)), "test_rows_of_server": int(len(test_host))}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(VIEWS))
    parser.add_argument("--view", help="default: AUTH sessions, OSSEC episodes")
    parser.add_argument("--hosts", type=int, default=3, help="servers with the highest flagged share to leave out in turn")
    parser.add_argument("--sample", type=int, default=200_000, help="training rows per fit")
    parser.add_argument("--data", type=Path, default=HERE.parents[1] / "data")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    view = args.view or VIEWS[args.source]
    features = args.data / "phase3_features" / args.source / view
    detectors = args.data / "phase4_detection" / args.source / "detectors" / view
    with runlog.run(args) as outcome:
        if not (detectors / "test_scores.csv").is_file() or not (features / "train_rows.csv").is_file():
            LOGGER.error(f"Needs Phase 3 and the detectors for {args.source}/{view}")
            outcome["status"] = "stopped"
            return 1
        with runlog.stage("Volume check"):
            header = pd.read_csv(detectors / "test_scores.csv", nrows=0).columns
            column = host_column(header)
            test = pd.read_csv(detectors / "test_scores.csv", usecols=[column, "isolation_alert"], dtype=str)
            train_hosts = pd.read_csv(features / "train_rows.csv", usecols=[column], dtype=str)[column]
            rho, table = volume_check(test, train_hosts)
            LOGGER.info(f"{args.source}/{view}: {len(table):,} servers; Spearman rho of flagged share against training rows {rho:.2f}")
        summary = json.loads((detectors / "summary.json").read_text(encoding="utf-8"))
        share = summary.get("test_isolation_alert_rate") or 0.01
        bundle = joblib.load(detectors / "experiment_bundle.joblib")
        valid_hosts = pd.read_csv(features / "validation_rows.csv", usecols=[column], dtype=str)[column].to_numpy()
        test_hosts = pd.read_csv(features / "test_rows.csv", usecols=[column], dtype=str)[column].to_numpy()
        rng = np.random.default_rng(SEED)
        results = []
        with runlog.stage("Leave one server out"):
            for number, host in enumerate(table.index[:args.hosts], start=1):
                found = leave_one_out(features, bundle, host, train_hosts.to_numpy(), valid_hosts, test_hosts, share, args.sample, rng)
                results.append({"server": host, "number": number, **found})
                LOGGER.info(f"Server #{number} (flagged share {table.loc[host, 'flagged_share']:.1%}): test alert rate "
                            f"{found['rate_with']:.1%} trained with it, {found['rate_without']:.1%} without it")
        out = args.data / "phase4_detection" / args.source / "diagnostics"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"host_identity_{view}.json").write_text(json.dumps({
            "view": view, "spearman_flagged_share_vs_training_rows": rho,
            "servers": table.reset_index(names="server").to_dict("records"), "leave_one_out": results}, indent=1, default=str), encoding="utf-8")
        LOGGER.info(f"Written: {(out / f'host_identity_{view}.json').as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
