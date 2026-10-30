"""Validation's two jobs, kept apart. Choosing (features, models, ensemble members, the greedy steps) and calibrating
(every threshold, the console's percentile reference, Phase 4g's quota) on the same rows makes the alert rate look
steadier than it is. Validation is split in time order: its earlier half chooses, its later half calibrates.

    halves(order, mode)                  (choose, calibrate) masks over validation rows, from their time order
    part(choose, calibrate)              "selection", "calibration" or "all" per row (the validation_part column)
    rate_check(allowed, rows, alerts, n) the budget's alert rate on the calibration half against the test alert rate

mode "all" is the earlier behaviour (both on every validation row), for comparison: --calibration-split all.
"""
from __future__ import annotations

import math

import numpy as np

MODES = ("halves", "all")


def halves(order, mode: str = "halves") -> tuple[np.ndarray, np.ndarray]:
    """``order``: the validation rows' positions in time order (np.argsort of their times)."""
    order = np.asarray(order)
    n = len(order)
    if mode == "all" or n < 2:
        return np.ones(n, dtype=bool), np.ones(n, dtype=bool)
    choose = np.zeros(n, dtype=bool)
    choose[order[: n // 2]] = True
    return choose, ~choose


def part(choose: np.ndarray, calibrate: np.ndarray) -> np.ndarray:
    return np.where(choose & calibrate, "all", np.where(choose, "selection", "calibration"))


def rate_check(allowed: int, rows: int, test_alerts: int, test_rows: int) -> dict:
    """{"budget_rate", "test_rate", "ratio"}: the share of the calibration half the budget allowed, the share of the
    test period alerted, and their ratio (1 = calibrated; above 1, the test period alerts more than budgeted)."""
    budget = allowed / rows if rows else math.nan
    test = test_alerts / test_rows if test_rows else math.nan
    return {"budget_rate": budget, "test_rate": test,
            "ratio": test / budget if budget and not math.isnan(budget) and not math.isnan(test) else math.nan}
