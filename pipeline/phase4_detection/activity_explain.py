"""Why a Phase 4g activity alert was raised, in plain words and chart data (one record per alert).

Used by activity_detectors.py, which writes the records to explanations.jsonl beside each view's scores;
the console's Explain tab draws them. Everything here is computed from counts and times, nothing is
generated: the same numbers always give the same words. profile() gives the same pictures for any entity
on any day, alerted or not: Phase 4h (activity_profiles.py) keeps the counts, the console's Profiles tab
calls it.

"Usual" is the series' own history in the TRAINING period only, the period the detectors learned from, on
its COMPARABLE DAYS (calendar_groups, comparable_groups): the same weekday's training days, public holidays
apart (a holiday is compared with past public holidays), or, with fewer than MIN_DAYS of those, the same
kind of day's (working days; or non-working days: Saturday, Sunday or a public holiday from
pipeline/phase9_llm_triage/site/public_holidays.csv), at the same time of day. Quiet days count as zeros:
"usually 0-6 at 03:00 on Saturdays" includes the Saturdays it logged nothing. Days on which the whole log
has no line (a collection gap) and days before the series first appeared are left out. With fewer than
MIN_DAYS comparable days the record says so instead of quoting a range. Phase 4g's robust deviation
judges each step against the same days (activity_detectors.calendar), so these are the numbers that
decided the alert.

A record holds:
    headline, when          one sentence, and the alert's day, time and kind of day. An alert whose count is
                            within the usual range for that time says so: the detectors' own baseline (the
                            steps in which the series is active) found it unusual, the calendar does not
    big                     what was seen, the usual range, how many times the usual, and its direction; and
                            the comparable days' own counts (distribution), drawn as a histogram and curve
    evidence                every check, supporting the alert or not (stance: supports, against, neutral): the
                            lines in each of Phase 4g's windows against their usual, and its failures (auth), this
                            hour, the day's total, working against non-working days, who else was involved (how
                            many, how many failed, the partners met for the first time, a success after failures),
                            the silence before it, how regular its activity was, its asset context, and both
                            detectors against their thresholds. Models flag; the checks may disagree
    channel                 what robust deviation flagged: lines, failures (auth) or new partners; the big numbers
                            and headline are about that count; partners lists the new partners (names) of the 2 hours
                            to the peak
    reasons                 up to four, strongest first (the headline and Reword use them):
        volume      lines in the alert's window against the usual range at that time
        day_type    the series' usual day on working against non-working days
        breadth     how many other servers, IPs, users or destinations it touched in 5 minutes
        sudden      the silence before it, against its usual gap
        combination for an alert only the Isolation Forest raised: its most unusual aspects
    day                     the alert's day hour by hour, with the usual band for that kind of day
    week                    the alert's week (7 x 24 hours) beside the median week: each row the hourly medians
                            of that weekday's training days (holidays apart: past public holidays, or non-working
                            days when there are fewer than MIN_DAYS), with n and the daily-total percentiles
    daily                   56 days of daily totals ending on the alert's day, with the usual band
    context                 public holiday, approved change window, little history, pooled baseline, and history:
                            when the series was first seen, its training days, and whether it had any data in
                            training or before the alert's week or day (the console warns when it had none)
    details                 the detectors' own numbers, for analysts
"""
from __future__ import annotations

from datetime import date, datetime, timedelta

import numpy as np

STEP_MINUTES = 5
STEPS_PER_DAY = 24 * 60 // STEP_MINUTES
STEPS_PER_HOUR = 60 // STEP_MINUTES
EPOCH = date(1970, 1, 1)
MIN_DAYS = 4                 # comparable training days needed before a usual range is quoted
DAILY_DAYS = 56
MAX_REASONS = 4
WORKING, NON_WORKING = "working", "non_working"
DAY_WORDS = {WORKING: ("working day", "working days"), NON_WORKING: ("non-working day", "weekends and holidays")}
LABELS = {"all": "whole log", "server": "server", "source_ip": "source IP", "username": "username",
          "destination_ip": "destination IP"}
OTHERS = {"server": "servers", "source_ip": "source IPs", "username": "usernames", "destination_ip": "destinations"}
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def day_number(moment) -> int:
    return int((np.datetime64(moment, "D") - np.datetime64("1970-01-01", "D")).astype(int))


def to_date(day: int) -> date:
    return EPOCH + timedelta(days=int(day))


def weekday(day) -> np.ndarray:
    return (np.asarray(day) + 3) % 7                     # 1970-01-01 was a Thursday


def non_working(days, holiday_days) -> np.ndarray:
    days = np.asarray(days)
    return (weekday(days) >= 5) | np.isin(days, list(holiday_days))


def minutes_words(minutes: float) -> str:
    minutes = int(round(minutes))
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    if minutes % 60 == 0 and minutes < 48 * 60:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''}"
    if minutes < 48 * 60:
        return f"{minutes / 60:.1f} hours"
    return f"{minutes / 1440:.0f} days"


def number(value) -> str:
    value = float(value)
    return f"{value:,.0f}" if value >= 10 or value == int(value) else f"{value:,.1f}"


def span(low, high) -> str:
    """A usual range in whole lines: '0–6', or '3' when both ends round alike."""
    low, high = int(round(low)), int(round(high))
    return f"{low:,}" if low == high else f"{low:,}–{high:,}"


GROUP_NAMES = tuple(f"{name}s" for name in WEEKDAYS) + ("public holidays", "working days", "non-working days")
HOLIDAYS_GROUP, WORKING_GROUP, NON_WORKING_GROUP = 7, 8, 9


def calendar_groups(log_days, holiday_days, train_end_day) -> list:
    """The training days (days the log has lines, before train_end_day) of each comparison, sorted: 0-6 one weekday
    each, public holidays apart; 7 public holidays; 8 working days; 9 non-working days (weekends and public holidays)."""
    days = np.asarray(log_days, dtype=np.int64)
    days = np.sort(days[days < train_end_day])
    holiday = np.isin(days, list(holiday_days))
    wd = weekday(days)
    return ([days[(wd == b) & ~holiday] for b in range(7)]
            + [days[holiday], days[(wd < 5) & ~holiday], days[(wd >= 5) | holiday]])


def comparable_groups(days, first_days, groups, holiday_days):
    """For each day (with the first day of its series): (which of calendar_groups it is compared with, how many of
    those training days the series has). The same weekday's days, public holidays apart (a holiday: past public
    holidays); with fewer than MIN_DAYS, the same kind of day's (working, or non-working)."""
    days, first = np.asarray(days, dtype=np.int64), np.asarray(first_days, dtype=np.int64)
    holiday = np.isin(days, list(holiday_days))
    wd = weekday(days)
    raw = np.where(holiday, HOLIDAYS_GROUP, wd)
    kind = np.where(holiday | (wd >= 5), NON_WORKING_GROUP, WORKING_GROUP)

    def count(chosen):
        n = np.zeros(len(days), dtype=np.int64)
        for g in np.unique(chosen):
            mask = chosen == g
            n[mask] = len(groups[g]) - np.searchsorted(groups[g], first[mask])
        return n
    n_raw = count(raw)
    chosen = np.where(n_raw >= MIN_DAYS, raw, kind)
    return chosen, count(chosen)


class Series:
    """One series' 5-minute counts (every split), and which of its days can be compared with the alert's."""

    def __init__(self, steps, lines, log_days, holiday_days, train_end_day):
        order = np.argsort(steps, kind="stable")
        self.steps = np.asarray(steps, dtype=np.int64)[order]
        self.cumulative = np.concatenate([[0], np.cumsum(np.asarray(lines, dtype=np.int64)[order])])
        self.first_day = int(self.steps[0] // STEPS_PER_DAY) if len(self.steps) else 0
        self.log_days = log_days
        self.holiday_days = holiday_days
        self.train_end_day = train_end_day
        self._groups = None

    def count(self, start, end):
        """Lines in steps [start, end), element-wise."""
        return (self.cumulative[np.searchsorted(self.steps, end, side="left")]
                - self.cumulative[np.searchsorted(self.steps, start, side="left")])

    def training_days(self):
        """Training days since the series first appeared, on which the log has lines."""
        days = np.arange(self.first_day, self.train_end_day, dtype=np.int64)
        return days[np.isin(days, self.log_days)]

    def days(self, kind):
        """Training days of one kind (working, or non-working: weekends and public holidays)."""
        days = self.training_days()
        rest = non_working(days, self.holiday_days)
        return days[rest] if kind == NON_WORKING else days[~rest]

    def comparable(self, day):
        """(training days to compare `day` with, what they are): comparable_groups' choice, from the series' first
        day. Fewer than MIN_DAYS means too few to compare."""
        if self._groups is None:
            self._groups = calendar_groups(self.log_days, self.holiday_days, self.train_end_day)
        group = int(comparable_groups([day], [self.first_day], self._groups, self.holiday_days)[0][0])
        days = self._groups[group]
        return days[days >= self.first_day], GROUP_NAMES[group]

    def window(self, days, end_offset, length):
        """Lines in the clock window of `length` steps ending at `end_offset` steps after midnight, per day."""
        ends = np.asarray(days, dtype=np.int64) * STEPS_PER_DAY + end_offset
        return self.count(ends - length, ends)

    def hours(self, days):
        """days x 24 hourly line counts."""
        starts = np.asarray(days, dtype=np.int64)[:, None] * STEPS_PER_DAY + np.arange(24) * STEPS_PER_HOUR
        return self.count(starts, starts + STEPS_PER_HOUR)

    def totals(self, days):
        starts = np.asarray(days, dtype=np.int64) * STEPS_PER_DAY
        return self.count(starts, starts + STEPS_PER_DAY)


HOLIDAY_BASIS = 7            # usual_days' key for a public holiday; 0-6 are Monday to Sunday


def basis_of(day, holiday_days) -> int:
    """Which training days `day` is compared with (Series.same_day): its weekday, or HOLIDAY_BASIS on a public holiday."""
    return HOLIDAY_BASIS if int(day) in holiday_days else int(weekday(day))


def usual_days(series, holiday_days) -> dict:
    """{basis: (what the days are, P10 / median / P90 of their daily totals, or None with fewer than MIN_DAYS)} for each
    weekday, public holidays apart, and for a public holiday when there are any (Series.comparable)."""
    probes = {int(weekday(day)): day for day in range(4, 11)}         # 5-11 Jan 1970, Monday to Sunday
    if holiday_days:
        probes[HOLIDAY_BASIS] = next(iter(holiday_days))
    out = {}
    for basis, probe in sorted(probes.items()):
        days, name = series.comparable(int(probe))
        out[basis] = (name, quantiles(series.totals(days)) if len(days) >= MIN_DAYS else None)
    return out


def quantiles(values) -> dict | None:
    values = np.asarray(values, dtype=float)
    if not len(values):
        return None
    low, mid, high = np.percentile(values, [10, 50, 90])
    return {"low": round(float(low), 1), "median": round(float(mid), 1), "high": round(float(high), 1),
            "max": float(values.max()), "days": int(len(values))}


def hourly_band(series, days, basis):
    """P10, median and P90 of each hour over the given days (None with fewer than MIN_DAYS)."""
    if len(days) < MIN_DAYS:
        return None
    low, mid, high = np.percentile(series.hours(days), [10, 50, 90], axis=0)
    return {"low": low.round(1).tolist(), "median": mid.round(1).tolist(), "high": high.round(1).tolist(),
            "days": int(len(days)), "basis": basis}


def strength(observed, usual):
    """How far the observed count is from the usual range, in log steps (0 inside it)."""
    if usual is None:
        return 0.0
    spread = max(np.log1p(usual["high"]) - np.log1p(usual["low"]), 0.5)
    return float(abs(np.log1p(observed) - np.log1p(usual["median"])) / spread)


def aspect(feature: str) -> str:
    """A forest feature in plain words."""
    name = feature.removeprefix("rel_hour_").removeprefix("rel_")
    window = name.removeprefix("log_").removeprefix("lines_")
    if window.endswith("m") and window[:-1].isdigit():
        words = f"lines in {minutes_words(int(window[:-1]))}"
        return words + (" for this hour" if feature.startswith("rel_hour_") else "")
    for prefix, other in OTHERS.items():
        if name == f"distinct_{prefix}_5m":
            return f"how many {other}"
    return {"active_steps_60m": "steady activity over the last hour", "active_steps_720m": "steady activity over 12 hours",
            "log_gap_minutes": "the silence before it", "burst_5_60": "a sudden burst", "burst_60_720": "a busy hour within the day",
            "time_hour": "the time of day", "time_sin_day": "the time of day", "time_cos_day": "the time of day",
            "time_day_of_week": "the day of the week", "time_sin_week": "the day of the week", "time_cos_week": "the day of the week",
            "time_is_non_working": "a weekend or holiday"}.get(name, name.replace("_", " "))


WINDOW_MINUTES = (5, 30, 120, 720)        # Phase 4g's WINDOWS


def short_minutes(minutes: int) -> str:
    return f"{minutes} min" if minutes < 60 else f"{minutes // 60} h"


def stance(status: str, direction: str, forest_only: bool) -> str:
    """Whether a check supports the alert: it deviates the alert's way (any way, for an Isolation Forest alert)."""
    if status in ("within", "unknown"):
        return "neutral"
    if forest_only:
        return "supports"
    return "supports" if (status == "above") == (direction != "lower") else "against"


RESUME_MINUTES = 60          # a gap of at least this long before an active step is a resumption
GAP_CAP_MINUTES = 7 * 24 * 60  # Phase 4g's cap on a gap (a series' first line has no gap before it)


def resumptions(rows):
    """The series' past resumptions: its gaps of RESUME_MINUTES or more before an active step in TRAINING, in minutes.
    These are its nights, weekends and breaks, so a long silence is judged against its own working cycle, not against
    the minutes between lines inside a session (whose median says nothing about how long it is usually away)."""
    if "log_gap_minutes" not in rows or "split" not in rows:
        return np.zeros(0)
    train = rows["split"].eq("train").to_numpy() & (rows["lines"].to_numpy() > 0)
    gaps = np.expm1(rows.loc[train, "log_gap_minutes"].to_numpy(dtype=float))
    return gaps[(gaps >= RESUME_MINUTES) & (gaps < GAP_CAP_MINUTES - 1)]


def silence(rows, alert):
    """(gap before the alert's first step in minutes, past resumptions' P10 / median / P90 and n or None)."""
    first = rows.loc[rows["step"].ge(int(alert["first_step_value"])) & (rows["lines"] > 0)].head(1)
    if not len(first) or "log_gap_minutes" not in rows:
        return None, None
    gap = float(np.expm1(first["log_gap_minutes"].iloc[0]))
    past = resumptions(rows)
    if len(past) < MIN_DAYS:
        return gap, None
    low, mid, high = np.percentile(past, [10, 50, 90])
    return gap, {"low": round(float(low)), "median": round(float(mid)), "high": round(float(high)), "max": round(float(past.max())),
                 "days": int(len(past))}


def failure_series(rows, context):
    """The series' failures as a Series (Phase 4g's failures column, auth), else None."""
    if "failures" not in rows or not rows["failures"].any():
        return None
    return Series(rows["step"].to_numpy(), rows["failures"].to_numpy(), context["log_days"], context["holidays"], context["train_end_day"])


def new_partners_of(alert, context):
    """The partners the alert's entity met for the first time in the 2 hours to its peak: [{type, partner, at}]."""
    table = context.get("partners")
    if table is None or not len(table) or alert["entity_type"] == "all":
        return []
    peak = int(alert["peak_step_value"])
    mine = table[(table["entity"].astype(str) == str(alert["entity"])) & (table["step"] > peak - 24) & (table["step"] <= peak)]
    return [{"type": str(r.type), "partner": str(r.partner),
             "at": f"{datetime(1970, 1, 1) + timedelta(minutes=int(r.step) * STEP_MINUTES):%Y-%m-%d %H:%M}"}
            for r in mine.sort_values("step").itertuples()]


def partner_words(partners) -> str:
    """'3 servers (srv-d, srv-e, srv-f) and 1 source IP (10.2.0.9)'."""
    groups = {}
    for p in partners:
        groups.setdefault(p["type"], []).append(p["partner"])
    parts = []
    for kind, names in groups.items():
        noun = OTHERS.get(kind, kind)
        noun = noun if len(names) != 1 else noun[:-1]
        shown = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
        parts.append(f"{len(names)} {noun} ({shown})")
    return " and ".join(parts)


def extra_evidence(add, alert, rows, peak, context, forest_only, comparable, many, end_offset, peak_step):
    """The checks of Phase 4g's outcome, relations, regularity and context features (the module docstring)."""
    fails = failure_series(rows, context)
    channel = str(alert.get("peak_channel") or "lines")
    if fails is not None:
        enough = len(comparable) >= MIN_DAYS
        for minutes in WINDOW_MINUTES:
            length = minutes // STEP_MINUTES
            seen = int(fails.count(np.array([peak_step + 1 - length]), np.array([peak_step + 1]))[0])
            peak_here = channel == "failures" and minutes == int(alert["peak_window_minutes"])
            if not enough:
                add("failures", short_minutes(minutes), "unknown", f"{seen:,} failures; too little history on {many} to compare.",
                    observed=seen, basis=many, peak=peak_here)
                continue
            counts = fails.window(comparable, end_offset, length)
            usual = quantiles(counts)
            status = "above" if seen > usual["high"] else "below" if seen < usual["low"] else "within"
            add("failures", short_minutes(minutes), status,
                f"{seen:,} failures in {minutes_words(minutes)}; on {many} usually {span(usual['low'], usual['high'])}.",
                observed=seen, usual=usual, distribution=counts.astype(int).tolist(), unit=f"failures in {minutes_words(minutes)}",
                basis=many, peak=peak_here, chosen="supports" if status == "above" else "neutral")
    if peak is not None and "success_after_failures" in rows:
        before = int(round(np.expm1(float(peak["success_after_failures"]))))
        add("who", "Success after failures", "above" if before >= 5 else "within",
            f"A success after {before} failures in the 30 minutes before." if before else "No success after failures.",
            observed=before, chosen="supports" if before >= 5 else "neutral", threshold=5,
            tag="success after ≥ 5 failures" if before >= 5 else "none")
    if peak is not None:
        for column in sorted(c for c in rows.columns if c.startswith("distinct_failed_") and c.endswith("_5m")):
            relative = peak.get("rel_" + column)
            if relative is None or not np.isfinite(relative):
                continue
            other = OTHERS.get(column[len("distinct_failed_"):-len("_5m")], column)
            seen = int(round(np.expm1(peak[column])))
            normal = max(int(round(np.expm1(peak[column] - relative))), 0)
            status = "above" if seen >= 3 and seen >= 2 * (normal + 1) - 1 else "within"
            add("who", f"{other[0].upper()}{other[1:]} failed", status,
                f"{seen} {other if seen != 1 else other[:-1]} with failures in the busiest 5 minutes; usually {normal}.",
                observed=seen, usual={"low": normal, "median": normal, "high": normal, "max": normal, "days": 0},
                unit=f"{other} failed in 5 minutes", chosen="supports" if status == "above" else "neutral",
                threshold=max(3, 2 * (normal + 1) - 1))
    if peak is not None and "new_partners_120m" in rows:
        met = new_partners_of(alert, context)
        count = int(peak["new_partners_120m"])
        add("who", "New partners, 2 h", "above" if count else "within",
            (f"Shared lines for the first time with {partner_words(met)} in the 2 hours to the peak." if met else
             f"{count} partners met for the first time in the 2 hours to the peak." if count else "No partner met for the first time."),
            observed=count, partners=met, chosen="supports" if count else "neutral",
            tag="first time" if count else "none")
    train = rows["split"].eq("train").to_numpy() if "split" in rows else np.zeros(len(rows), dtype=bool)
    for column, title, words in (("count_cv_60m", "Regularity, 1 h", "count per step over the last hour"),
                                 ("gap_cv_720m", "Gap regularity, 12 h", "gaps between active steps over 12 hours")):
        if peak is None or column not in rows or train.sum() < MIN_DAYS:
            continue
        values = rows.loc[train, column].to_numpy(dtype=float)
        low, mid, high = np.percentile(values, [10, 50, 90])
        seen = float(peak[column])
        status = "below" if seen < low else "above" if seen > high else "within"
        add("time", title, status,
            f"Coefficient of variation of the {words}: {seen:.2f}; in training usually {low:.2f}–{high:.2f} (0 is a steady beat).",
            observed=round(seen, 3), usual={"low": round(float(low), 3), "median": round(float(mid), 3), "high": round(float(high), 3),
                                            "max": round(float(values.max()), 3), "days": int(train.sum())},
            unit="coefficient of variation", basis="training steps", decimals=2,
            chosen="supports" if status != "within" else "neutral",
            tag="steadier than P10" if status == "below" else "more uneven than P90" if status == "above" else "within P10–P90")
    zone, role, criticality = (str(alert.get(k, "") or "") for k in ("zone", "role", "criticality"))
    zone, role, criticality = ("" if v == "nan" else v for v in (zone, role, criticality))
    if zone or role or criticality:
        add("context", "Asset", "within", f"Zone {zone or 'unknown'}, role {role or 'unknown'}, criticality {criticality or 'unknown'}.",
            chosen="neutral", asset={"zone": zone, "role": role, "criticality": criticality}, tag=criticality or "unknown")
    if str(alert.get("baseline", "")) == "role":
        add("context", "Peer baseline", "within", f"Little history of its own: compared with the other {alert.get('peer') or role} entities.",
            chosen="neutral", tag="peers")
    if peak is not None and "cross" in rows and (zone or rows["cross"].any()):
        seen = int(peak["cross"])
        usual = float(np.median(rows.loc[train, "cross"])) if train.any() else 0.0
        status = "above" if seen > 0 and usual == 0 else "within"
        add("context", "Zone crossings", status, f"{seen} lines in the busiest 5 minutes between zones; usually {number(usual)}.",
            observed=seen, chosen="supports" if status == "above" else "neutral", tag="new crossing" if status == "above" else "usual")


def evidence(series, alert, rows, peak, context, direction, forest_only, aspects):
    """Every check, whether or not it supports the alert, so the analyst sees all of it: the lines in each of the
    windows (5, 30, 120 and 720 minutes), this hour, the day, working against non-working days, who else was involved, the silence
    before it, and both detectors against their thresholds. stance: supports, against (deviates the other way),
    or neutral (within the usual, or not enough history)."""
    kind = alert["entity_type"]
    label = LABELS.get(kind, kind)
    who = "the whole log" if kind == "all" else f"this {label}"
    holiday_days = context["holidays"]
    peak_step = int(alert["peak_step_value"])
    peak_day = peak_step // STEPS_PER_DAY
    day_kind = NON_WORKING if non_working([peak_day], holiday_days)[0] else WORKING
    comparable, many = series.comparable(peak_day)
    enough = len(comparable) >= MIN_DAYS
    end_offset = peak_step % STEPS_PER_DAY + 1
    end_clock = (datetime(1970, 1, 1) + timedelta(minutes=(peak_step + 1) * STEP_MINUTES)).strftime("%H:%M")
    items = []

    def add(group, title, status, text, chosen=None, **extra):
        items.append({"group": group, "title": title, "status": status, "text": text,
                      "stance": chosen or stance(status, direction, forest_only), **extra})

    def judged(seen, usual):
        return "above" if seen > usual["high"] else "below" if seen < usual["low"] else "within"

    for minutes in WINDOW_MINUTES:
        length = minutes // STEP_MINUTES
        seen = int(series.count(np.array([peak_step + 1 - length]), np.array([peak_step + 1]))[0])
        lines = f"{seen:,} line{'s' if seen != 1 else ''} in the {minutes_words(minutes)} to {end_clock}"
        if not enough:
            add("lines", short_minutes(minutes), "unknown", f"{lines}; too little history on {many} to compare.", observed=seen,
                basis=many, peak=minutes == int(alert["peak_window_minutes"]))
            continue
        counts = series.window(comparable, end_offset, length)
        usual = quantiles(counts)
        add("lines", short_minutes(minutes), judged(seen, usual), f"{lines}; on {many} usually {span(usual['low'], usual['high'])}.",
            observed=seen, usual=usual, distribution=counts.astype(int).tolist(), unit=f"lines in {minutes_words(minutes)}",
            peak=minutes == int(alert["peak_window_minutes"]), basis=many)

    hour = (peak_step % STEPS_PER_DAY) // STEPS_PER_HOUR
    seen_hour = int(series.hours([peak_day])[0][hour])
    if enough:
        active = series.hours(comparable)[:, hour] > 0
        share, count = float(active.mean()), int(active.sum())
        status = "above" if seen_hour > 0 and share <= 0.2 else "below" if seen_hour == 0 and share >= 0.8 else "within"
        add("time", f"{hour:02d}:00", status,
            f"At {hour:02d}:00 {who} had lines on {count} of {len(comparable)} {many}; this time {seen_hour:,} in that hour.",
            observed=seen_hour, share=round(share, 3), active_days=count, days=len(comparable), basis=many)
    else:
        add("time", f"{hour:02d}:00", "unknown", f"{seen_hour:,} lines at {hour:02d}:00; too little history on {many} to compare.")

    totals = {k: series.totals(series.days(k)) for k in (WORKING, NON_WORKING)}
    daily = {k: quantiles(v) if len(v) >= MIN_DAYS else None for k, v in totals.items()}
    day_seen = int(series.totals([peak_day])[0])
    weekday_name = WEEKDAYS[int(weekday(peak_day))]
    if enough:
        same_totals = series.totals(comparable)
        usual = quantiles(same_totals)
        add("day", "Day total", judged(day_seen, usual),
            f"{day_seen:,} lines on {weekday_name} {to_date(peak_day):%d %b}; {many} usually {span(usual['low'], usual['high'])}.",
            observed=day_seen, usual=usual, distribution=same_totals.astype(int).tolist(), unit="lines a day", basis=many)
    else:
        add("day", "Day total", "unknown", f"{day_seen:,} lines on {weekday_name}; too little history on {many} to compare.",
            observed=day_seen, basis=many)
    if daily[WORKING] and daily[NON_WORKING]:
        w, n = daily[WORKING]["median"], daily[NON_WORKING]["median"]
        busy, quiet = (w, n) if day_kind == NON_WORKING else (n, w)
        quiet_words = DAY_WORDS[NON_WORKING][1] if day_kind == NON_WORKING else "working days"
        busy_words = "working days" if day_kind == NON_WORKING else "weekends and holidays"
        status = "above" if busy >= 10 and busy >= 3 * max(quiet, 1) and day_seen > daily[day_kind]["high"] else "within"
        text = (f"{quiet_words.capitalize()} are quiet for {who}: about {number(quiet)} lines a day, against {number(busy)} on {busy_words}."
                if busy >= 3 * max(quiet, 1) and busy >= 10 else
                f"Working days and weekends are alike for {who}: about {number(w)} and {number(n)} lines a day.")
        add("day", "Kind of day", status, text, observed=day_seen, usual=daily[day_kind],
            compare={"working": daily[WORKING], "non_working": daily[NON_WORKING]},
            distributions={k: v.astype(int).tolist() for k, v in totals.items()})

    if peak is not None:
        for column in sorted(c for c in rows.columns if c.startswith("distinct_") and c.endswith("_5m")
                            and not c.startswith("distinct_failed_")):      # failed breadth has its own check
            relative = peak.get("rel_" + column)
            if relative is None or not np.isfinite(relative):
                continue
            other = OTHERS.get(column[len("distinct_"):-len("_5m")], column)
            seen = int(round(np.expm1(peak[column])))
            normal = max(int(round(np.expm1(peak[column] - relative))), 0)
            title = other[0].upper() + other[1:]
            status = ("above" if seen >= 2 and seen >= 2 * (normal + 1) - 1 else
                      "below" if normal >= 2 and 2 * seen <= normal else "within")
            add("who", title, status, f"{seen} {other if seen != 1 else other[:-1]} in the busiest 5 minutes; usually {normal} when active.",
                observed=seen, usual={"low": normal, "median": normal, "high": normal, "max": normal, "days": 0}, unit=f"{other} in 5 minutes",
                threshold=max(2, 2 * (normal + 1) - 1))
        gap, past = silence(rows, alert)
        if gap is not None and gap >= GAP_CAP_MINUTES - 1:
            add("time", "Silence before", "unknown", "Its first line: no silence before it to compare.", basis="past resumptions",
                rule="resume", chosen="neutral")
        elif gap is not None and past is not None:
            status = "above" if gap >= RESUME_MINUTES and gap > past["high"] else "within"
            add("time", "Silence before", status,
                f"It began after {minutes_words(gap)} without a line; it usually resumes after {minutes_words(past['median'])} "
                f"(P90 {minutes_words(past['high'])}, n = {past['days']} resumptions in training).",
                observed=round(gap), usual=past, unit="minutes of silence", basis="past resumptions", rule="resume",
                threshold=max(RESUME_MINUTES, past["high"]))
        elif gap is not None:
            add("time", "Silence before", "unknown" if gap >= RESUME_MINUTES else "within",
                f"It began after {minutes_words(gap)} without a line; too few resumptions in training to compare.",
                observed=round(gap), unit="minutes of silence", basis="past resumptions", rule="resume")

    extra_evidence(add, alert, rows, peak, context, forest_only, comparable, many, end_offset, peak_step)

    thresholds = context["thresholds"]
    channel = str(alert.get("peak_channel") or "lines")
    bar = (thresholds.get("robust_by_channel") or {}).get(channel) or thresholds["robust"]       # the alert's channel's own
    robust, forest = float(alert["robust_z"]), float(alert["forest_score"])
    robust_flag = "activity_robust" in str(alert["detector_combination"])
    forest_flag = "activity_forest" in str(alert["detector_combination"])
    calendar = f"{many} at this time" if enough else "no comparable days"
    add("models", "Robust deviation", "above" if robust_flag else "within",
        f"{robust:.1f} at most, on the {short_minutes(int(alert['peak_window_minutes']))} window of {channel}: the smaller of its deviation "
        f"from {calendar} and from its own level when active; {channel} alert from {bar:.1f}."
        + ("" if robust_flag else " Not flagged by this detector."),
        chosen="supports" if robust_flag else "neutral", score=robust, threshold=bar, flagged=robust_flag)
    alone = thresholds.get("forest_alone", thresholds["forest"])
    add("models", "Isolation Forest", "above" if forest_flag else "within",
        f"{forest:.3f} at most; it agrees from {thresholds['forest']:.3f} and alerts on its own from {alone:.3f}."
        + ("" if forest_flag else " Not flagged by this detector."),
        chosen="supports" if forest_flag else "neutral", score=forest, threshold=thresholds["forest"], alone=alone, flagged=forest_flag)
    if aspects:
        add("models", "Unusual mix", "above", "What the Isolation Forest found least usual: " + ", ".join(aspects) + ".",
            chosen="supports" if forest_flag else "neutral", aspects=aspects)
    return items


def week_view(series, day, holiday_days) -> dict:
    """The week of `day` (Monday to Sunday) hour by hour, beside the median week: each row the hourly medians of that
    day's comparable training days (Series.comparable), with n, what the days are and the percentiles of their daily
    totals."""
    monday = day - int(weekday(day))
    week_days = np.arange(monday, monday + 7)
    same = [series.comparable(int(d)) for d in week_days]
    return {"monday": str(to_date(monday)), "counts": series.hours(week_days).tolist(),
            "kinds": [NON_WORKING if k else WORKING for k in non_working(week_days, holiday_days)],
            "usual": [np.median(series.hours(days), axis=0).round(1).tolist() if len(days) >= MIN_DAYS else None
                      for days, _ in same],
            "usual_days": [int(len(days)) for days, _ in same], "usual_basis": [basis for _, basis in same],
            "usual_totals": [quantiles(series.totals(days)) if len(days) >= MIN_DAYS else None for days, _ in same],
            "holidays": [holiday_days.get(int(d)) for d in week_days]}


def history_view(series, day, train_end_day) -> dict:
    """When the series was first seen, and how much of its own history a comparison on `day` can use."""
    monday = day - int(weekday(day))
    return {"first_seen": str(to_date(series.first_day)), "train_end": str(to_date(train_end_day)),
            "training_days": int(len(series.training_days())), "in_training": bool(series.first_day < train_end_day),
            "days_before_alert": int(day - series.first_day),
            "first_this_week": bool(series.first_day >= monday), "first_this_day": bool(series.first_day >= day)}


def per_day(series, days, holiday_days) -> list:
    """Each day's band for the daily-totals chart: P10 / median / P90 of its comparable days' totals, with their name."""
    by_basis = usual_days(series, holiday_days)
    return [{**by_basis[basis_of(d, holiday_days)][1], "basis": by_basis[basis_of(d, holiday_days)][0]}
            if by_basis[basis_of(d, holiday_days)][1] else None for d in days]


def profile(series, day, context) -> dict:
    """Any day of one series against its own normal, alerted or not (the console's Profiles tab, from Phase 4h's hourly
    counts): the day's total and hours against the same weekday's training days (public holidays apart), its week
    beside the median week, 56 days of daily totals each against its own weekday's, and its history. context:
    holidays, log_day_set and train_end_day, as for explain()."""
    holiday_days = context["holidays"]
    same, basis = series.comparable(day)
    enough = len(same) >= MIN_DAYS
    totals = series.totals(same)
    usual = quantiles(totals) if enough else None
    band = hourly_band(series, same, basis)
    daily_days = np.arange(day - DAILY_DAYS + 1, day + 1)
    kind = NON_WORKING if non_working([day], holiday_days)[0] else WORKING
    return {
        "when": {"date": str(to_date(day)), "weekday": WEEKDAYS[int(weekday(day))], "day_type": kind,
                 "day_words": DAY_WORDS[kind][0], "holiday": holiday_days.get(day)},
        "big": {"observed": int(series.totals([day])[0]), "usual": usual, "basis": basis,
                "distribution": totals.astype(int).tolist() if enough else None},
        "day": {"date": str(to_date(day)), "hours": series.hours([day])[0].tolist(), "band": band},
        "week": {**week_view(series, day, holiday_days), "alert": [int(weekday(day)), None]},
        "daily": {"dates": [str(to_date(d)) for d in daily_days],
                  "totals": [int(t) if (d >= series.first_day and d in context["log_day_set"]) else None
                             for d, t in zip(daily_days, series.totals(daily_days))],
                  "kinds": [NON_WORKING if k else WORKING for k in non_working(daily_days, holiday_days)],
                  "per_day": per_day(series, daily_days, holiday_days), "train_end": str(to_date(context["train_end_day"]))},
        "history": history_view(series, day, context["train_end_day"]),
    }


def summary(record) -> list[str]:
    """Why the alert is unusual, in up to six plain sentences for people who do not read the statistics: from its
    SUPPORTING evidence only (stance supports), the flagged count first, then the hour, the silence before it, what
    failed and who was met for the first time, the day, its rhythm and context, and the detectors last. The same
    numbers as the evidence; nothing generated. Works on any record (older ones too)."""
    items = [e for e in record.get("evidence") or [] if e.get("stance") == "supports"]
    big = record.get("big") or {}
    channel = big.get("channel", "lines")
    out = []

    def usual_words(e):
        u = e.get("usual") or {}
        if not u:
            return ""
        median = u.get("median", 0)
        times = f" ({e['observed'] / median:.0f} times the median)" if median and e["observed"] >= 2 * median else ""
        return f"against a usual {span(u['low'], u['high'])} on {e.get('basis', 'comparable days')} at this time{times}"

    group = "failures" if channel == "failures" else "lines"
    windows = [e for e in items if e["group"] == group and " vs " not in e["title"]]
    peak = next((e for e in windows if e.get("peak")), windows[0] if windows else None)
    partners = next((e for e in items if e["title"] == "New partners, 2 h"), None)
    if channel == "new partners" and partners:
        out.append(partners["text"])
    elif peak is not None and peak.get("observed") is not None:
        line = f"{peak['observed']:,} {peak.get('unit') or 'lines'}" + (f" ({record['when']['clock']})" if peak.get("peak") else "")
        words = usual_words(peak)
        others = [e["title"] for e in windows if e is not peak]
        out.append(line + (f", {words}." if words else ".")
                   + (f" Also above its usual over {', '.join(others)}." if others and peak["status"] == "above" else
                      f" Also below its usual over {', '.join(others)}." if others else ""))
    for e in items:
        title, group = e["title"], e["group"]
        if group == "time" and e.get("active_days") is not None:
            out.append(f"Active at {title}, an hour it is active on only {e['active_days']} of {e['days']} {e.get('basis') or 'comparable days'}."
                       if e["status"] == "above" else
                       f"Quiet at {title}, an hour it is usually active ({e['active_days']} of {e['days']} {e.get('basis') or 'comparable days'}).")
        elif title == "Silence before" and e.get("rule") == "resume":
            out.append(f"It started after {minutes_words(e['observed'])} without a line; it usually resumes after "
                       f"{minutes_words(e['usual']['median'])} (P90 {minutes_words(e['usual']['high'])}).")
        elif title == "Silence before":                 # records written before 2026-10-28's resumption rule
            out.append(f"It started after {minutes_words(e['observed'])} without a line.")
        elif title == "Success after failures":
            out.append(f"A successful login came after {e['observed']} failures in the 30 minutes before.")
        elif group == "who" and title.endswith(" failed"):
            out.append(f"{e['observed']} {title[:-len(' failed')].lower()} had failures within 5 minutes; usually "
                       f"{(e.get('usual') or {}).get('median', 0):.0f}.")
        elif title == "New partners, 2 h" and channel != "new partners":
            out.append(e["text"])
        elif group == "who" and e.get("usual"):
            out.append(f"It reached {e['observed']} {title.lower()} within 5 minutes; usually {e['usual']['median']:.0f}.")
        elif group == "day" and title == "Day total":
            out.append(f"{e['observed']:,} lines that day; {e.get('basis') or 'comparable days'} usually have "
                       f"{span(e['usual']['low'], e['usual']['high'])}.")
        elif group == "day" and title == "Kind of day":
            out.append(e["text"])
        elif title == "Regularity, 1 h":
            out.append("Its activity over the last hour was unusually steady, as an automated process's is."
                       if e["status"] == "below" else "Its activity over the last hour came in unusually uneven bursts.")
        elif title == "Gap regularity, 12 h":
            out.append("The gaps between its activity over 12 hours were unusually regular: a fixed rhythm."
                       if e["status"] == "below" else "The gaps between its activity over 12 hours were unusually irregular.")
        elif title == "Zone crossings":
            out.append(f"{e['observed']} lines crossed between network zones, which it usually does not do.")
    robust = next((e for e in items if e["title"] == "Robust deviation"), None)
    forest = next((e for e in items if e["title"] == "Isolation Forest"), None)
    if robust or forest:
        out = out[:5]
        out.append(("Flagged by its robust deviation" + (f" (score {robust['score']:.1f}; alerts from {robust['threshold']:.1f})" if robust else ""))
                   + (" and confirmed by the Isolation Forest." if robust and forest else "." if robust else "")
                   if robust else "Flagged by the Isolation Forest alone: an unusual combination rather than one count.")
    return out[:6]


def explain(alert, rows, train_rows, kept, context):
    """One record. alert: the episode (activity_detectors.episodes); rows: its series' rows (every split), sorted by
    step, with the scoring columns; train_rows: the training rows of its entity type (for unusual aspects); kept:
    the forest's features; context: source, holiday names by day, log days, train end day, change windows,
    thresholds."""
    kind, entity = alert["entity_type"], str(alert["entity"])
    label = LABELS.get(kind, kind)
    holiday_days = context["holidays"]
    series = Series(rows["step"].to_numpy(), rows["lines"].to_numpy(), context["log_days"], holiday_days, context["train_end_day"])
    peak_step = int(alert["peak_step_value"])
    peak_day = peak_step // STEPS_PER_DAY
    day_kind = NON_WORKING if non_working([peak_day], holiday_days)[0] else WORKING
    one = DAY_WORDS[day_kind][0]
    holiday = holiday_days.get(peak_day)
    window_minutes = int(alert["peak_window_minutes"])
    length = window_minutes // STEP_MINUTES
    end_offset = peak_step % STEPS_PER_DAY + 1
    channel = str(alert.get("peak_channel") or "lines")
    channel = channel if channel in ("lines", "failures", "new partners") else "lines"
    measured = failure_series(rows, context) if channel == "failures" else series
    measured = measured if measured is not None else series
    noun = {"failures": "failure", "new partners": "new partner"}.get(channel, "line")
    observed = int(measured.count(np.array([peak_step + 1 - length]), np.array([peak_step + 1]))[0])
    if channel == "new partners":
        observed = int(alert["peak_window_lines"])
    comparable, many = series.comparable(peak_day)             # the days Phase 4g's robust deviation compared it with
    counts = (measured.window(comparable, end_offset, length) if len(comparable) >= MIN_DAYS and channel != "new partners"
              else None)
    usual = quantiles(counts) if counts is not None else None
    distribution = counts.astype(int).tolist() if counts is not None else None
    peak_start = datetime(1970, 1, 1) + timedelta(minutes=(peak_step + 1 - length) * STEP_MINUTES)
    peak_end = peak_start + timedelta(minutes=window_minutes)
    clock = f"{peak_start:%H:%M}–{peak_end:%H:%M}"
    who = "the whole log" if kind == "all" else f"this {label}"

    reasons = []
    met = new_partners_of(alert, context)
    if channel == "new partners":
        reasons.append({"kind": "relations", "title": "New partners", "direction": "higher", "observed": observed,
                        "usual": {"low": 0, "median": 0, "high": 0, "max": 0, "days": 0}, "unit": "new partners in 2 hours",
                        "strength": float(alert.get("robust_z", 0)) / 3, "partners": met,
                        "text": (f"Shared lines for the first time with {partner_words(met)} in the 2 hours to {peak_end:%H:%M}."
                                 if met else f"Met {observed} partners for the first time in the 2 hours to {peak_end:%H:%M}.")})
    elif usual is not None:
        direction = "higher" if observed > usual["high"] else "lower" if observed < usual["low"] else "within"
        lead = "Only " if direction == "lower" else ""
        reasons.append({"kind": "volume" if channel == "lines" else "failures", "title": "Volume" if channel == "lines" else "Failures",
                        "direction": direction, "observed": observed,
                        "usual": usual, "distribution": distribution, "unit": f"{noun}s in {minutes_words(window_minutes)}",
                        "strength": strength(observed, usual),
                        "text": f"{lead}{observed:,} {noun}{'s' if observed != 1 else ''} in {minutes_words(window_minutes)} ({clock}); "
                                f"on {many} {who} usually has {span(usual['low'], usual['high'])} then."})
    else:
        typical = float(alert["usual_window_lines"])
        against = ("a typical " + label if alert["baseline"] == "pooled" else
                   f"a typical {alert.get('peer') or 'peer'}" if alert["baseline"] == "role" else "it")
        reasons.append({"kind": "volume" if channel == "lines" else "failures", "title": "Volume" if channel == "lines" else "Failures",
                        "direction": "higher" if observed > typical else "lower",
                        "observed": observed, "usual": {"low": typical, "median": typical, "high": typical, "max": typical, "days": 0},
                        "unit": f"{noun}s in {minutes_words(window_minutes)}", "strength": abs(float(alert.get("robust_z", 0))) / 3,
                        "text": f"{observed:,} {noun}{'s' if observed != 1 else ''} in {minutes_words(window_minutes)} ({clock}); "
                                f"{who} has little history on {many}, and {against}"
                                + f" has about {number(typical)} in {minutes_words(window_minutes)} when active."})

    day_totals = {k: series.totals(series.days(k)) for k in (WORKING, NON_WORKING)}
    daily = {k: quantiles(v) for k, v in day_totals.items()}
    if all(daily[k] and daily[k]["days"] >= MIN_DAYS for k in daily):
        busy, quiet = (WORKING, NON_WORKING) if day_kind == NON_WORKING else (NON_WORKING, WORKING)
        busy_day, quiet_day = daily[busy]["median"], daily[quiet]["median"]
        if channel == "lines" and reasons[0]["direction"] == "higher" and busy_day >= 10 and busy_day >= 3 * max(quiet_day, 1):
            reasons.append({"kind": "day_type", "title": "Day", "direction": "higher", "observed": int(series.totals([peak_day])[0]),
                            "usual": daily[day_kind], "compare": {"working": daily[WORKING], "non_working": daily[NON_WORKING]},
                            "distributions": {k: v.astype(int).tolist() for k, v in day_totals.items()},
                            "unit": "lines a day", "strength": float(np.log((busy_day + 1) / (quiet_day + 1))),
                            "text": f"{DAY_WORDS[day_kind][1].capitalize()} are quiet for {who}: about {number(quiet_day)} lines a day, "
                                    f"against {number(busy_day)} on {DAY_WORDS[busy][1]}."})

    peak = rows.loc[rows["step"].eq(peak_step)]
    peak = peak.iloc[0] if len(peak) else None
    if peak is not None:
        for column in sorted(c for c in rows.columns if c.startswith("distinct_") and c.endswith("_5m")
                            and not c.startswith("distinct_failed_")):      # failed breadth has its own check
            other = column[len("distinct_"):-len("_5m")]
            relative = peak.get("rel_" + column)
            if relative is None or not np.isfinite(relative):
                continue
            seen = int(round(np.expm1(peak[column])))
            normal = max(int(round(np.expm1(peak[column] - relative))), 0)
            if seen >= 2 and seen >= 2 * (normal + 1) - 1 and relative >= np.log(2):
                words = OTHERS.get(other, other)
                reasons.append({"kind": "breadth", "title": "Breadth", "direction": "higher", "observed": seen,
                                "usual": {"low": normal, "median": normal, "high": normal, "max": normal, "days": 0},
                                "unit": f"{words} in 5 minutes", "strength": float(relative / np.log(2)) * 0.5,
                                "text": (f"{seen} {words} were active in 5 minutes; usually {normal}." if kind == "all"
                                         else f"Reached {seen} {words} in 5 minutes; usually {normal}.")})
        if "success_after_failures" in rows:
            before = int(round(np.expm1(float(peak["success_after_failures"]))))
            if before >= 5:
                reasons.append({"kind": "outcome", "title": "Outcome", "direction": "higher", "observed": before,
                                "usual": {"low": 0, "median": 0, "high": 0, "max": 0, "days": 0}, "unit": "failures before a success",
                                "strength": float(np.log1p(before) / np.log(6)),
                                "text": f"A success after {before} failures in the 30 minutes before: a guess may have worked."})
        if channel != "new partners" and len(met) >= 2:
            reasons.append({"kind": "relations", "title": "New partners", "direction": "higher", "observed": len(met),
                            "usual": {"low": 0, "median": 0, "high": 0, "max": 0, "days": 0}, "unit": "new partners in 2 hours",
                            "strength": 0.5 + 0.1 * len(met), "partners": met,
                            "text": f"Shared lines for the first time with {partner_words(met)} in the 2 hours to the peak."})
        gap, past = silence(rows, alert)
        if gap is not None and past is not None and RESUME_MINUTES <= gap < GAP_CAP_MINUTES - 1 and gap > past["high"]:
            reasons.append({"kind": "sudden", "title": "Sudden", "direction": "higher", "observed": round(gap), "usual": past,
                            "unit": "minutes of silence before", "strength": float(np.log(gap / max(past["high"], 1)) / np.log(4)) * 0.5 + 0.5,
                            "text": f"Came after {minutes_words(gap)} without a line; it usually resumes after "
                                    f"{minutes_words(past['median'])} (P90 {minutes_words(past['high'])})."})

    forest_only = "activity_robust" not in str(alert["detector_combination"])
    if forest_only and peak is not None and len(train_rows) and kept:
        history = train_rows[[c for c in kept if c in train_rows]]
        middle = history.median()
        scale = (history.quantile(0.75) - history.quantile(0.25)).replace(0, np.nan).fillna(history.std()).replace(0, 1.0)
        distance = ((peak[middle.index].astype(float) - middle) / scale).abs().sort_values(ascending=False)
        words = list(dict.fromkeys(aspect(name) for name in distance.index[:6]))[:3]
        if words:
            reasons.append({"kind": "combination", "title": "Mix", "direction": "unusual", "observed": None, "usual": None,
                            "unit": "", "strength": 0.9, "aspects": words,
                            "text": "Unusual together: " + (", ".join(words[:-1]) + " and " + words[-1] if len(words) > 1 else words[0]) + "."})

    head = reasons[0]
    ordered = [head] + sorted(reasons[1:], key=lambda r: -r["strength"])
    if forest_only:
        ordered.sort(key=lambda r: r["kind"] != "combination")
    reasons = ordered[:MAX_REASONS]
    hours_band = hourly_band(series, comparable, many)
    quiet_time = usual is not None and usual["high"] <= 2
    scope = f" in those {minutes_words(window_minutes)}"     # the window every number in the summary is about
    if channel == "new partners":
        headline = (f"{who[0].upper()}{who[1:]} met {observed} partner{'s' if observed != 1 else ''} for the first time "
                    f"in 2 hours")
    elif channel == "failures":
        against = ("usual" if usual is not None else f"a typical {label}" if alert["baseline"] == "pooled" else
                   f"a typical {alert.get('peer') or 'peer'}" if alert["baseline"] == "role" else f"{who} when it is active")
        headline = (f"Many more failures than {against}" + (f" for {who}" if usual is not None else "") + scope
                    + (", at a time it usually has none" if usual is not None and usual["high"] < 1 else ""))
    elif usual is None:                                  # no calendar history: say what it was compared with
        against = (f"a typical {label}" if alert["baseline"] == "pooled" else
                   f"a typical {alert.get('peer') or 'peer'}" if alert["baseline"] == "role" else f"{who} when it is active")
        headline = (f"An unusual mix of activity for {who}" if forest_only else
                    f"Much busier than {against}{scope}" if head["direction"] == "higher" else f"Much quieter than {against}{scope}")
    else:
        headline = (f"An unusual mix of activity for {who}" if forest_only else
                    f"Much busier than usual for {who}{scope}" + (", at a time it is usually quiet" if quiet_time else "")
                    if head["direction"] == "higher" else
                    f"Much quieter than usual for {who}{scope}" if head["direction"] == "lower" else
                    f"Usual for {who}{scope} at this time of day, though unusual against its overall level")
    ratio = (observed + 1) / ((usual or head["usual"])["median"] + 1)

    aspects = next((r["aspects"] for r in reasons if r["kind"] == "combination"), None)
    checks = evidence(series, alert, rows, peak, context, head["direction"], forest_only, aspects)

    monday = peak_day - int(weekday(peak_day))
    daily_days = np.arange(peak_day - DAILY_DAYS + 1, peak_day + 1)
    totals = series.totals(daily_days)
    start_time, end_time = datetime.fromisoformat(str(alert["start"])), datetime.fromisoformat(str(alert["end"]))
    windows = [w for w in context.get("change_windows", []) if w[0] <= end_time and w[1] >= start_time
               and (not w[2] or (kind == "server" and entity in {h.lower() for h in w[2]}))]

    return {
        "row_manifest_id": alert["row_manifest_id"], "view": alert["view"], "entity_type": kind, "entity": entity,
        "label": label, "headline": headline,
        "when": {"date": str(to_date(peak_day)), "weekday": WEEKDAYS[int(weekday(peak_day))], "clock": clock,
                 "day_type": day_kind, "day_words": one, "holiday": holiday, "start": str(alert["start"]), "end": str(alert["end"]),
                 "minutes": int(alert["steps"]) * STEP_MINUTES},
        "big": {"observed": observed, "window_minutes": window_minutes, "usual": usual or head["usual"],
                "ratio": float(f"{ratio:.4g}"), "little_history": usual is None, "direction": head["direction"], "mix": forest_only,
                "distribution": distribution, "basis": many, "channel": channel, "noun": noun},
        "partners": met,
        "reasons": [{k: v for k, v in r.items()} for r in reasons],
        "evidence": checks,
        "day": {"date": str(to_date(peak_day)), "hours": series.hours([peak_day])[0].tolist(), "band": hours_band,
                "alert_hours": sorted({(peak_start + timedelta(minutes=m)).hour for m in range(0, window_minutes, 5)
                                       if (peak_start + timedelta(minutes=m)).date() == to_date(peak_day)})},
        "week": {**week_view(series, peak_day, holiday_days), "alert": [int(peak_day - monday), peak_start.hour]},
        "daily": {"dates": [str(to_date(d)) for d in daily_days],
                  "totals": [int(t) if (d >= series.first_day and d in context["log_day_set"]) else None for d, t in zip(daily_days, totals)],
                  "kinds": [NON_WORKING if k else WORKING for k in non_working(daily_days, holiday_days)],
                  "usual": daily, "per_day": per_day(series, daily_days, holiday_days),
                  "train_end": str(to_date(context["train_end_day"]))},
        "context": {"holiday": holiday, "change_windows": [f"{w[0]:%Y-%m-%d %H:%M} to {w[1]:%Y-%m-%d %H:%M}" for w in windows],
                    "little_history": usual is None, "baseline": alert["baseline"], "compared_days": len(comparable), "basis": many,
                    "peer": str(alert.get("peer", "") or ""),
                    "asset": {k: ("" if str(alert.get(k, "") or "") == "nan" else str(alert.get(k, "") or ""))
                              for k in ("zone", "role", "criticality")},
                    # when the series first appears, and how much of its own history the comparisons could use
                    "history": history_view(series, peak_day, context["train_end_day"])},
        "details": {"robust_deviation": float(alert["robust_z"]),
                    "robust_threshold": (context["thresholds"].get("robust_by_channel") or {}).get(channel) or context["thresholds"]["robust"],
                    "forest_score": float(alert["forest_score"]), "forest_threshold": context["thresholds"]["forest"],
                    "flagged_by": str(alert["detector_combination"]), "peak_window_minutes": window_minutes,
                    "baseline": alert["baseline"], "steps": int(alert["steps"])},
    }
