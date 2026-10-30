"""Phase 4g incidents: alerts that are one event, or one routine, grouped (2026-10-28).

Phase 4g scores the whole log and every server, source IP, username and destination IP on its own, so one event can
raise several alerts (the whole log, the server, the account and the address involved), and a routine that started
after training raises one alert a day. An INCIDENT groups them, so each is reviewed once:

    linked      entity alerts of different types whose PEAKS are within LINK_MINUTES of each other and whose entities
                shared a line in those peak hours (Phase 4g's pair hours: count_lines): the server, account and address
                of one event. Peaks, not whole episodes: an episode can last hours, and overlap alone chained
                unrelated alerts together
    the whole   a whole-log alert joins the entity alert on the same channel with the highest score whose peak is
    log         within LINK_MINUTES of its own: the whole log's excess is usually one entity's, so it is context there.
                A routine of the whole log is found among the whole-log alerts no entity's routine explains, and
                the one-off entity alerts at its times join it (a maintenance window seen on the whole log every
                night, and on one server on some of them)
    recurring   alerts of the same entity on the same channel (lines, failures, new partners) whose peaks fall at about
                the same clock time (within RECUR_MINUTES either side) on at least RECUR_DAYS different days: a job, a
                habit or a misconfiguration that came after training. An entity's routines on one channel are one
                incident (a job at 07:00 and 21:00 is one), and the events linked to them join it; two routines
                never merge (a server's job and an account's failures at the same hour stay two incidents, so
                neither hides under the other's title)

Every alert belongs to exactly one incident (a single alert is an incident of one). The incident's LEAD is its
highest-scoring entity alert (the whole-log alert only when there is no entity alert), and the incident takes the
lead's id, so a label already given to that alert in Review stays with it. Names appear in titles as they do in the
alerts; the log shows counts only.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

RECUR_MINUTES = 30
RECUR_DAYS = 3
LINK_MINUTES = 60
STEPS_PER_HOUR = 12
LABELS = {"all": "whole log", "server": "server", "source_ip": "source IP", "username": "username",
          "destination_ip": "destination IP"}


def who(kind, entity, start=True) -> str:
    """'Server srv-a' at the start of a title, 'server srv-a' after 'with'."""
    label = LABELS.get(kind, kind)
    name = "whole log" if kind == "all" else f"{label} {entity}"
    return f"{name[0].upper()}{name[1:]}" if start else name


def pair_hashes(kind_a, values_a, kind_b, values_b, hours) -> np.ndarray:
    """64-bit hashes of (entity type, entity, other type, other entity, hour), the two in a fixed order (by type name),
    so a pair is found whichever way round it is asked for."""
    values_a, values_b = np.asarray(values_a, dtype=object), np.asarray(values_b, dtype=object)
    if kind_a > kind_b:
        kind_a, kind_b, values_a, values_b = kind_b, kind_a, values_b, values_a
    n = len(values_a)
    frame = pd.DataFrame({0: np.full(n, kind_a, dtype=object), 1: values_a, 2: np.full(n, kind_b, dtype=object),
                          3: values_b, 4: np.asarray(hours, dtype=np.int64)})
    return pd.util.hash_pandas_object(frame, index=False).to_numpy()


def _shared(a, b, pair_hours) -> bool:
    """Whether alerts a and b's entities shared a line in either alert's peak hour."""
    if not len(pair_hours):
        return False
    hours = np.unique([a["p_step"] // STEPS_PER_HOUR, b["p_step"] // STEPS_PER_HOUR]).astype(np.int64)
    keys = pair_hashes(a["entity_type"], [str(a["entity"])] * len(hours), b["entity_type"], [str(b["entity"])] * len(hours), hours)
    at = np.searchsorted(pair_hours, keys)
    return bool((pair_hours[np.minimum(at, len(pair_hours) - 1)] == keys).any())


def _clock(minutes) -> str:
    """The median clock time of minutes of the day, around midnight too (23:50 and 00:10 give 00:00)."""
    minutes = np.asarray(minutes, dtype=float)
    if minutes.max() - minutes.min() > 720:
        minutes = np.where(minutes < 720, minutes + 1440, minutes)
    middle = int(round(np.median(minutes))) % 1440
    return f"{middle // 60:02d}:{middle % 60:02d}"


def group(alerts: pd.DataFrame, pair_hours: np.ndarray) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(alerts with incident_id, incident_kind, incident_size, incident_lead; one row per incident). alerts: both views'
    episodes (row_manifest_id, view, entity_type, entity, start, end, peak_step, peak_channel, activity_score);
    pair_hours: the sorted unique pair_hashes of every pair that shared a line, per hour."""
    if not len(alerts):
        return alerts.assign(incident_id=[], incident_kind=[], incident_size=[], incident_lead=[]), pd.DataFrame()
    a = alerts.reset_index(drop=True).copy()
    start, end, peak = pd.to_datetime(a["start"]), pd.to_datetime(a["end"]), pd.to_datetime(a["peak_step"])
    a["p_step"] = ((peak - pd.Timestamp("1970-01-01")) // pd.Timedelta(minutes=5)).astype(np.int64)
    channel = a["peak_channel"].fillna("lines").astype(str) if "peak_channel" in a else pd.Series("lines", index=a.index)
    kinds, scores, steps = a["entity_type"].to_numpy(), a["activity_score"].to_numpy(dtype=float), a["p_step"].to_numpy()
    link_steps = LINK_MINUTES // 5
    parent = np.arange(len(a))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    holds_routine = np.zeros(len(a), dtype=bool)                     # per root: its group holds a routine

    def union(i, j, merge_routines=False):
        i, j = find(i), find(j)
        if i == j or (holds_routine[i] and holds_routine[j] and not merge_routines):
            return
        parent[i] = j
        holds_routine[j] |= holds_routine[i]

    # the whole log's context: the strongest entity alert on its channel peaking within LINK_MINUTES of it
    entity = np.flatnonzero(kinds != "all")
    context_of = {}
    for i in np.flatnonzero(kinds == "all"):
        near = entity[(np.abs(steps[entity] - steps[i]) <= link_steps) & (channel.to_numpy()[entity] == channel.iat[i])]
        if len(near):
            context_of[i] = near[np.argmax(scores[near])]
    # 1. recurring: the same entity and channel at about the same clock time on RECUR_DAYS days or more; an entity's
    #    routines on one channel are one incident. Entities first; then the whole log, without the alerts an entity's
    #    routine explains (those are its context, step 3)
    recurring = np.zeros(len(a), dtype=bool)
    clocks: dict[tuple, list[str]] = {}
    minute = (peak.dt.hour * 60 + peak.dt.minute).to_numpy()

    def find_routines(rows):
        part = a.iloc[rows]
        for key, members in part.groupby([part["entity_type"], part["entity"].astype(str), channel.iloc[rows]]).groups.items():
            members = np.asarray(members)
            order = members[np.argsort(minute[members], kind="stable")]
            clusters = []
            for i in order:
                if clusters and minute[i] - minute[clusters[-1][0]] <= 2 * RECUR_MINUTES:
                    clusters[-1].append(i)
                else:
                    clusters.append([i])
            if len(clusters) > 1 and minute[clusters[0][-1]] + 1440 - minute[clusters[-1][0]] <= 2 * RECUR_MINUTES:
                clusters[0] += clusters.pop()                                    # around midnight
            routine = [c for c in clusters if peak.iloc[c].dt.normalize().nunique() >= RECUR_DAYS]
            for cluster in routine:
                recurring[cluster] = True
                clocks.setdefault(key, []).append(_clock(minute[cluster]))
            for i in [m for c in routine for m in c][1:]:
                union(i, routine[0][0], merge_routines=True)
            if routine:
                holds_routine[find(routine[0][0])] = True

    find_routines(entity)
    find_routines(np.array([i for i in np.flatnonzero(kinds == "all") if not (i in context_of and recurring[context_of[i]])],
                           dtype=np.int64))
    # 2. linked: entity alerts of different types peaking close together whose entities shared a line then; an event
    #    joins a routine, but two routines stay two incidents (a link between them would hide one under the other)
    by_peak = entity[np.argsort(steps[entity], kind="stable")]
    for n, i in enumerate(by_peak):
        for j in by_peak[n + 1:]:
            if steps[j] - steps[i] > link_steps:
                break
            if kinds[i] != kinds[j] and _shared(a.loc[i], a.loc[j], pair_hours):
                union(i, j)
    # 3. the whole log: into the entity alert that explains it (its context, found above)
    for i, j in context_of.items():
        union(i, j)
    roots = np.array([find(i) for i in range(len(a))])
    rows = []
    for root in np.unique(roots):
        members = np.flatnonzero(roots == root)
        named = members[kinds[members] != "all"]
        regular = members[recurring[members]]
        pool = regular[kinds[regular] != "all"] if len(regular) and (kinds[regular] != "all").any() else regular if len(regular) else named if len(named) else members
        lead = pool[np.argmax(scores[pool])]
        lead_key = (kinds[lead], str(a.at[lead, "entity"]))
        others = list(dict.fromkeys((kinds[m], str(a.at[m, "entity"])) for m in named if (kinds[m], str(a.at[m, "entity"])) != lead_key))
        days = sorted({str(d.date()) for d in peak.iloc[members]})
        kind = "recurring" if len(regular) else "linked" if others else "single"
        lead_name = who(*lead_key)
        clock = " and ".join(sorted(clocks.get((*lead_key, channel.iat[lead]), []))) if kind == "recurring" else ""
        title = (f"{lead_name}: {channel.iat[lead]} at about {clock} on {len(days)} days since {pd.Timestamp(days[0]):%d %b}"
                 if kind == "recurring" else
                 f"{lead_name} with " + ", ".join(who(*o, start=False) for o in others[:3]) + (f" and {len(others) - 3} more" if len(others) > 3 else "")
                 if kind == "linked" else lead_name)
        rows.append({"incident_id": a.at[lead, "row_manifest_id"], "kind": kind, "title": title,
                     "lead_view": a.at[lead, "view"], "lead_id": a.at[lead, "row_manifest_id"],
                     "entity_type": kinds[lead], "entity": a.at[lead, "entity"], "channel": channel.iat[lead],
                     "start": str(start.iloc[members].min()), "end": str(end.iloc[members].max()), "days": len(days), "clock": clock,
                     "size": len(members), "score": float(scores[members].max()),
                     "members": ";".join(f"{a.at[m, 'view']}:{a.at[m, 'row_manifest_id']}" for m in members[np.argsort(steps[members], kind="stable")])})
        a.loc[members, "incident_id"] = a.at[lead, "row_manifest_id"]
        a.loc[members, "incident_kind"] = kind
        a.loc[members, "incident_size"] = len(members)
        a.loc[members, "incident_lead"] = members == lead
    incidents = pd.DataFrame(rows).sort_values("score", ascending=False).reset_index(drop=True)
    a["incident_size"] = a["incident_size"].astype(int)
    a["incident_lead"] = a["incident_lead"].astype(bool)
    return a.drop(columns=["p_step"]), incidents
