"""The console's local HTTP service: a JSON API under /api and the built web app.

Start it with ``python -m service`` from ``triage-console/`` (see the README).
It listens on 127.0.0.1 only and refuses requests from other origins, so other
web pages open in the same browser cannot use it. The API answers the app's own
scripts only: an /api/ address typed into the browser is refused, and nothing
but the built app's files is served.
"""
from __future__ import annotations

import base64
import binascii
import html
import io
import json
import math
import mimetypes
import re
import traceback
from collections import Counter
from itertools import zip_longest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import analyze, auth, catalog, cluster_index, datasets, clusters, event_counts, ip_flows, jobs, llm, report_ai, review_context, scoring, sql, sql_guard, sql_lock, store, uploads, variants
from .config import APP, DATA, DEV_ORIGINS, DOCS, FROZEN, HOST, PORT, ROOT, WEB_DIST, WIDGET_ID, load_settings, restore_frozen_caches, save_settings
from . import outliers, patterns, reports, report_maps, review_filters, sigma, sigma_ai, sigma_form, tabular, whitelist
from . import audit, event_log_docs, explain, profiles, retention, yields

MAX_BODY = 64 * 1024 * 1024
# The app's own page may run only its own scripts, load nothing from elsewhere and never sit inside another site's
# frame; styles may be inline (the app sets them on elements). An exported HTML report carries its own stricter policy.
PAGE_POLICY = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
               "font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
# The header the app's scripts add to every API request (web/src/api.ts). An address typed in, a bookmark, a link, an
# image or a form cannot carry it, and another site's script may add it only after a CORS preflight (OPTIONS), which
# this server never answers (there is no do_OPTIONS).
API_HEADER = "X-Console-Request"
# Sec-Fetch-Site, which browsers add to every request: signing out may also come from the address bar.
OWN_SITES = ("same-origin", "none")
ROUTES: dict[tuple[str, str], callable] = {}


def route(method: str, path: str):
    def register(function):
        ROUTES[(method, path)] = function
        return function
    return register


def _actor() -> str:
    """Who is acting: the signed-in SSO user when there is one, otherwise the name set in Settings."""
    user = auth.current()
    if user is not None:
        return user.email or user.name
    return load_settings()["display_name"] or "local-user"


def _source(q: dict) -> str:
    source = q.get("source", "")
    if source not in catalog.SOURCES:
        raise ValueError(f"Unknown source {source!r}.")
    return source


# --- settings and models ---------------------------------------------------------

@route("GET", "/api/health")
def health(q, body):
    return {"ok": True, "root": str(ROOT), "frozen": FROZEN}


@route("GET", "/api/settings")
def get_settings(q, body):
    return load_settings()


@route("PUT", "/api/settings")
def put_settings(q, body):
    before = load_settings()
    after = save_settings(body or {})
    changed = {k: [before[k], after[k]] for k in after if before.get(k) != after[k]}
    if changed:
        store.log_action(_actor(), "settings", "settings", changed)
    return after


@route("GET", "/api/llm/models")
def llm_models(q, body):
    return llm.models()


@route("GET", "/api/catalog")
def get_catalog(q, body):
    return catalog.catalog()


@route("GET", "/api/models")
def get_models(q, body):
    """The models per view. Retraining is not offered here: it is Datasets → Train, for a signed-in admin (Q26)."""
    return {"models": catalog.models(load_settings()["feature_set"]), "auth": auth.status()}


# --- data -------------------------------------------------------------------------

@route("GET", "/api/data/sankey")
def get_sankey(q, body):
    sources = [s for s in q.get("sources", ",".join(catalog.SOURCES)).split(",") if s in catalog.SOURCES]
    return event_counts.sankey(sources, q.get("from", ""), q.get("to", ""))


@route("GET", "/api/data/ipflow")
def get_ipflow(q, body):
    sources = [s for s in q.get("sources", ",".join(catalog.SOURCES)).split(",") if s in catalog.SOURCES]
    return ip_flows.sankey(sources, q.get("from", ""), q.get("to", ""), top=min(60, int(q.get("top", 25))), level=_level(q))


def _level(q: dict) -> int:
    level = int(q.get("level", 3) or 3)
    if level not in ip_flows.LEVELS:
        raise ValueError("Group addresses by 1 to 4 parts.")
    return level


@route("GET", "/api/data/ipflow/query")
def get_ipflow_query(q, body):
    """The read-only SQL for the lines behind a box or band of the traffic chart."""
    sources = [s for s in q.get("sources", ",".join(catalog.SOURCES)).split(",") if s in catalog.SOURCES]
    return {"query": ip_flows.selection_query(sources, q.get("from", ""), q.get("to", ""), top=min(60, int(q.get("top", 25))),
                                              level=_level(q), a=q.get("a", ""), source=q.get("source", ""), b=q.get("b", ""))}


@route("GET", "/api/data/splits")
def get_splits(q, body):
    return {"splits": catalog.splits()}


@route("GET", "/api/clusters")
def get_clusters(q, body):
    source = _source(q)
    view = q.get("view", "")
    if view not in catalog.SOURCES[source]["views"]:
        raise ValueError(f"Unknown view {view!r} for {source}.")
    return {"clusters": clusters.list_clusters(source, view)}


@route("GET", "/api/clusters/messages")
def get_cluster_messages(q, body):
    return clusters.messages(_source(q), q.get("view", ""), q.get("cluster", ""))


@route("GET", "/api/clusters/members")
def get_cluster_members(q, body):
    return cluster_index.members(_source(q), q.get("view", ""), q.get("cluster", ""),
                                 offset=max(0, int(q.get("offset", 0))), limit=min(100, int(q.get("limit", 25))),
                                 flagged_only=q.get("flagged") == "1")


@route("GET", "/api/status")
def get_status(q, body):
    return {"cluster_index": cluster_index.status(), "variants": {k: v for k, v in variants.get().items() if k != "counts"}}


@route("PUT", "/api/clusters/name")
def put_cluster_name(q, body):
    store.rename_cluster(_source(body), body["view"], body["cluster_id"], body.get("name", ""), _actor())
    return {"ok": True}


@route("GET", "/api/clusters/comments")
def get_comments(q, body):
    return {"comments": store.comments(_source(q), q.get("view", ""), q.get("cluster", ""))}


@route("POST", "/api/clusters/comments")
def post_comment(q, body):
    author = body.get("author") or _actor()
    return store.add_comment(_source(body), body["view"], body["cluster_id"], author, body.get("body", ""))


@route("POST", "/api/sql/unlock")
def post_sql_unlock(q, body):
    """The SQL password, for a token that every SQL request below carries (sql_lock.py)."""
    return sql_lock.unlock(str((body or {}).get("password", "")), _actor())


@route("GET", "/api/sql/password")
def get_sql_password(q, body):
    return {"default": store.sql_password_is_default()}


@route("POST", "/api/sql/password")
def post_sql_password(q, body):
    sql_lock.change(str((body or {}).get("old", "")), str((body or {}).get("new", "")), _actor())
    return {"default": False}


@route("POST", "/api/sql/schema")
def post_sql_schema(q, body):
    sql_lock.require((body or {}).get("token"))
    return sql.schema()


@route("POST", "/api/sql")
def post_sql(q, body):
    sql_lock.require((body or {}).get("token"))
    query = str((body or {}).get("query", ""))
    try:
        result = sql.run(query)
    except sql_guard.QueryRejected as error:        # refused attempts are recorded too
        store.log_action(_actor(), "sql_blocked", "query", {"query": query[:2000], "reason": str(error)})
        raise
    store.log_action(_actor(), "sql", "query", {"query": query[:2000], "rows": len(result["rows"])})
    return result


@route("POST", "/api/sql/export")
def post_sql_export(q, body):
    """A query's rows for a CSV download: the same guardrails as /api/sql, up to EXPORT_ROWS rows."""
    sql_lock.require((body or {}).get("token"))
    query = str((body or {}).get("query", ""))
    try:
        result = sql.run(query, max_rows=sql.EXPORT_ROWS, time_limit=sql.EXPORT_TIME_LIMIT)
    except sql_guard.QueryRejected as error:
        store.log_action(_actor(), "sql_blocked", "query", {"query": query[:2000], "reason": str(error)})
        raise
    store.log_action(_actor(), "sql_export", "query", {"query": query[:2000], "rows": len(result["rows"])})
    return result


# --- analyze, review, docs ----------------------------------------------------------

@route("POST", "/api/analyze")
def post_analyze(q, body):
    """Start an analysis in the background; poll /api/analyze/job for its steps and result."""
    job = jobs.start(analyze.analyze, text=body.get("text", ""), source=body.get("source", "auto"),
                     month=body.get("month", ""), host=body.get("host", ""), path=body.get("path", ""), raw=str(body.get("raw", "")),
                     name=str(body.get("name", "")))
    store.record_usage("analyze")
    return {"job": job}


@route("POST", "/api/analyze/detect")
def post_analyze_detect(q, body):
    """Which log type the first lines are, and how many of them Phase 1 knows (Simple mode shows both as soon
    as a file is chosen, and stops at logs it knows next to nothing of)."""
    lines = [line for line in str(body.get("text", "")).splitlines() if line.strip()][:patterns.SAMPLE + 1]
    if not lines:
        raise ValueError("No log lines.")
    return patterns.detect(lines, body.get("month", ""), raw=str(body.get("raw", "")), name=str(body.get("name", "")))


# --- patterns: rules for logs the pipeline cannot read yet -------------------------------

@route("POST", "/api/patterns/scan")
def post_patterns_scan(q, body):
    """Read new lines and run the first pass in the background; poll /api/analyze/job."""
    job = jobs.start(patterns.scan, text=str(body.get("text", "")), path=str(body.get("path", "")),
                     family=str(body.get("family", "auto")), new_family=str(body.get("new_family", "")),
                     name=str(body.get("name", ""))[:200], raw=str(body.get("raw", "")),
                     fields=[str(f) for f in body["fields"]] if isinstance(body.get("fields"), list) else None, actor=_actor())
    store.record_usage("patterns")
    return {"job": job}


@route("POST", "/api/patterns/preview")
def post_patterns_preview(q, body):
    """Before a scan: is the input a table, are its first 100 rows well formed, and what are its columns."""
    return patterns.preview(text=str(body.get("text", "")), path=str(body.get("path", "")), name=str(body.get("name", "")))


@route("POST", "/api/tables/excel")
def post_tables_excel(q, body):
    """An uploaded Excel workbook (.xlsx, base64) as CSV text: its first sheet. Read on this laptop only."""
    name = str(body.get("name", ""))
    if name.lower().endswith(".xls"):
        raise ValueError("An older .xls workbook: save it as .xlsx or .csv.")
    try:
        data = base64.b64decode(str(body.get("data", "")), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("The workbook did not arrive whole. Try again.") from None
    return {"text": tabular.xlsx_text(io.BytesIO(data))}


@route("POST", "/api/patterns/pass")
def post_patterns_pass(q, body):
    return {"job": jobs.start(patterns.rescan, str(body.get("workspace", "")), actor=_actor())}


@route("POST", "/api/patterns/lines")
def post_patterns_lines(q, body):
    return patterns.lines_view(str(body.get("workspace", "")), show=str(body.get("show", "unknown")),
                               shape=str(body.get("shape", "")), search=str(body.get("search", "")),
                               field=str(body.get("field", "")), value=body.get("value"))


@route("POST", "/api/patterns/suggest")
def post_patterns_suggest(q, body):
    return patterns.suggest(str(body.get("kind", "")), list(body.get("examples") or []), str(body.get("family", "")),
                            str(body.get("workspace", "")))


@route("POST", "/api/patterns/test")
def post_patterns_test(q, body):
    return patterns.test(str(body.get("kind", "")), str(body.get("regex", "")), list(body.get("examples") or []),
                         str(body.get("workspace", "")))


@route("GET", "/api/patterns/rules")
def get_patterns_rules(q, body):
    return patterns.rules(q.get("family", ""))


@route("POST", "/api/patterns/rules")
def post_patterns_rule(q, body):
    return patterns.save_rule(str(body.get("family", "")), str(body.get("kind", "")), str(body.get("regex", "")),
                              str(body.get("event_type", "")), list(body.get("examples") or []), _actor())


@route("POST", "/api/patterns/rules/update")
def post_patterns_rule_update(q, body):
    enabled = body.get("enabled")
    patterns.update_rule(int(body.get("id", 0)), _actor(), enabled=None if enabled is None else bool(enabled),
                         move=str(body.get("move", "")))
    return {"ok": True}


@route("POST", "/api/patterns/rules/delete")
def post_patterns_rule_delete(q, body):
    patterns.delete_rule(int(body.get("id", 0)), _actor())
    return {"ok": True}


@route("POST", "/api/patterns/families")
def post_patterns_family(q, body):
    name = patterns.create_family(str(body.get("name", "")), _actor())
    if body.get("workspace"):
        patterns.set_family(str(body["workspace"]), name)
    return {"family": name}


@route("POST", "/api/patterns/families/delete")
def post_patterns_family_delete(q, body):
    """Delete a log type made in Patterns (unapproved: not the pipeline's). No sign-in needed (decision Q34);
    recorded in the activity log."""
    return patterns.delete_family(str(body.get("name", "")), _actor())


@route("GET", "/api/patterns/export")
def get_patterns_export(q, body):
    result = patterns.export(q.get("family", ""))
    store.log_action(_actor(), "pattern_export", f"patterns/{q.get('family', '')}", {"rules": len(result["pack"]["rules"])})
    return result


# --- Sigma: detection rules run over logs Phase 1 can read --------------------------------

@route("GET", "/api/sigma/rules")
def get_sigma_rules(q, body):
    return sigma.entries()


@route("POST", "/api/sigma/rules")
def post_sigma_rule(q, body):
    return sigma.add(str((body or {}).get("yaml", "")), _actor())


@route("POST", "/api/sigma/rules/update")
def post_sigma_rule_update(q, body):
    body = body or {}
    enabled = body.get("enabled")
    return sigma.update(int(body.get("id", 0)), _actor(), text=None if body.get("yaml") is None else str(body["yaml"]),
                        enabled=None if enabled is None else bool(enabled))


@route("POST", "/api/sigma/rules/delete")
def post_sigma_rule_delete(q, body):
    sigma.delete(int((body or {}).get("id", 0)), _actor())
    return {"ok": True}


@route("GET", "/api/attack/ics")
def get_attack_ics(q, body):
    from . import coverage
    return coverage.matrix()


@route("GET", "/api/sigma/training")
def get_sigma_training(q, body):
    from . import sigma_review
    return sigma_review.training_status()


@route("POST", "/api/sigma/training")
def post_sigma_training(q, body):
    from . import sigma_review
    return sigma_review.start_training()


@route("POST", "/api/sigma/check")
def post_sigma_check(q, body):
    """A draft's documents as the engine reads them, or what is wrong with it; and its form, when the form can show it."""
    return sigma.check(str((body or {}).get("yaml", "")))


@route("POST", "/api/sigma/form")
def post_sigma_form(q, body):
    """The rule form as YAML (signed by whoever is acting), the required fields still empty, and how the engine reads it."""
    form = (body or {}).get("form")
    if not isinstance(form, dict):
        raise ValueError("No form.")
    return sigma_form.preview(form, _actor())


@route("POST", "/api/sigma/describe")
def post_sigma_describe(q, body):
    """A draft rule from a plain-English description, written by the local model; checked, never saved here."""
    body = body or {}
    text = str(body.get("text", ""))
    result = sigma_ai.describe(text, str(body.get("source", "")))
    store.log_action(_actor(), "sigma_ai_draft", "sigma", {"description_chars": len(text), "model": result["model"],
                                                           "reads": "docs" in result, "tries": result["tries"]})
    store.record_usage("sigma_ai")
    return result


@route("POST", "/api/sigma/run")
def post_sigma_run(q, body):
    """Run the enabled rules (or a draft) over new lines in the background; poll /api/analyze/job."""
    body = body or {}
    job = jobs.start(sigma.run, text=str(body.get("text", "")), path=str(body.get("path", "")), source=str(body.get("source", "auto")),
                     month=str(body.get("month", "")), host=str(body.get("host", "")), raw=str(body.get("raw", "")),
                     name=str(body.get("name", ""))[:200], draft=str(body.get("draft", "")), entry=int(body.get("entry", 0) or 0))
    store.record_usage("sigma")
    return {"job": job}


@route("GET", "/api/sigma/export")
def get_sigma_export(q, body):
    result = sigma.export()
    store.log_action(_actor(), "sigma_export", "sigma", {"entries": result["entries"]})
    return result


# --- Simple mode: uploads kept for review ---------------------------------------------

@route("POST", "/api/simple/analyze")
def post_simple_analyze(q, body):
    """Analyze an upload and prepare it as a review item (kept by POST /api/uploads)."""
    job = jobs.start(uploads.run, text=body.get("text", ""), source=body.get("source", "auto"), month=body.get("month", ""),
                     host=body.get("host", ""), name=str(body.get("name", "")), raw=str(body.get("raw", "")))
    store.record_usage("analyze")
    return {"job": job}


@route("GET", "/api/uploads")
def get_uploads(q, body):
    result = uploads.list_uploads(_actor())
    filters = review_filters.parse(q.get("filters"))
    if filters:
        kept, deadline = [], review_filters.Deadline()
        for u in result['uploads']:
            deadline.check()
            items =[i for i in uploads.get_upload(u['id'])['items'] if review_filters.matches(i['facts'], filters)]
            if items:
                kept.append({**u, 'items': len(items), 'reviewed': sum(bool(i['review']) for i in items)})
        result['uploads'] = kept
    return {**result, "reviewers": uploads.reviewers()}


@route("GET", "/api/uploads/facts")
def get_upload_facts(q, body):
    facts = []
    for u in uploads.list_uploads(_actor())['uploads']:
        for item in uploads.get_upload(u['id'])['items']:
            facts.extend(item['facts'])
    return {'facts': [dict(zip(review_filters.FIELDS, values)) for values in sorted({tuple(f[k] for k in review_filters.FIELDS) for f in facts})]}


@route("POST", "/api/uploads")
def post_upload(q, body):
    return {"id": uploads.keep(str(body.get("keep", "")), _actor())}


@route("GET", "/api/uploads/item")
def get_upload(q, body):
    return uploads.get_upload(int(q.get("id", "0") or 0))


@route("POST", "/api/uploads/assign")
def post_upload_assign(q, body):
    return uploads.assign(int(body.get("id", 0)), str(body.get("reviewer", "")), _actor())


@route("POST", "/api/uploads/clear")
def post_upload_clear(q, body):
    uploads.clear(int(body.get("id", 0)), str(body.get("password", "")), _actor())
    return {"ok": True}


@route("GET", "/api/analyze/job")
def get_analyze_job(q, body):
    return jobs.get(q.get("id", ""))


@route("GET", "/api/map")
def get_map(q, body):
    limit = min(60_000, max(1_000, int(q.get("limit", 12_000))))       # the Clusters map asks for every point
    points = scoring.map_points(_source(q), q.get("view", ""), limit=limit, layout=q.get("layout", "tsne"))
    if points is None:
        raise KeyError("No map for this view.")
    return points


@route("GET", "/api/map/info")
def get_map_info(q, body):
    """The map's size and points per group, so the page can offer to draw it (it is drawn on request)."""
    info = scoring.map_info(_source(q), q.get("view", ""))
    if info is None:
        raise KeyError("No map for this view.")
    return info


@route("GET", "/api/map/point")
def get_map_point(q, body):
    """One point clicked on the map: its period, time, group, votes and original lines."""
    source, view = _source(q), q.get("view", "")
    point = scoring.map_point(source, view, q.get("id", ""))
    if point is None:
        raise KeyError("No such point on this map.")
    try:
        lines = cluster_index.point_lines(source, view, point["row_id"], point["split"])
    except ValueError:                              # the log lines were purged: the point itself remains
        lines = {"status": "purged", "lines": [], "line_count": None}
    return {**point, **lines}


@route("GET", "/api/review/queue")
def get_review_queue(q, body):
    source = _source(q)
    return {"items": review_filters.filter_queue(source, clusters.review_queue(source, q.get("view", "")), review_filters.parse(q.get("filters")))}


@route("POST", "/api/review")
def post_review(q, body):
    return store.add_review(_source(body), body["view"], body["item_id"], body.get("kind", "cluster"),
                            body.get("verdict", ""), body.get("note", ""), _actor())


@route("GET", "/api/review/flagged")
def get_review_flagged(q, body):
    """A group's flagged observations, most unusual first, with their scores."""
    return review_context.flagged(_source(q), q.get("view", ""), q.get("cluster", ""), filters=review_filters.parse(q.get("filters")))


@route("GET", "/api/review/options")
def get_review_options(q, body):
    return {"values": review_filters.options(_source(q), q.get("field", "host"), q.get("search", ""))}


@route("GET", "/api/reports")
def get_reports(q, body):
    return {"reports": reports.list_reports(q.get("finding", ""))}


@route("GET", "/api/reports/item")
def get_report(q, body):
    return reports.get(int(q["id"]), int(q["version"]) if q.get("version") else None)


@route("POST", "/api/reports/save")
def save_report(q, body):
    return reports.save(body.get("document"), _actor(), body.get("id"), body.get("base_version", 0))


@route("POST", "/api/reports/export")
def export_report(q, body):
    return reports.export(int(body["id"]), int(body["version"]), body.get("format"), _actor())


@route("POST", "/api/reports/map")
def report_map(q, body):
    return {"job": jobs.start(report_maps.build, source=_source(body), view=body.get("view", ""), ids=body.get("ids"), layout=body.get("layout", "tsne"), upload=body.get("upload"))}


@route("GET", "/api/review/observation")
def get_review_observation(q, body):
    """One observation: when, where, its lines and how unusual it is."""
    return review_context.observation(_source(q), q.get("view", ""), q.get("id", ""))


@route("POST", "/api/review/observations")
def post_review_observations(q, body):
    """Several observations at once (a report's Log lines block with every event chosen)."""
    source, view = _source(body), str(body.get("view", ""))
    ids = [str(x) for x in (body.get("ids") or [])][:200]
    out = []
    for row_id in ids:
        try:
            out.append(review_context.observation(source, view, row_id))
        except KeyError as error:
            out.append({"row_id": row_id, "error": str(error)})
    return {"observations": out}


@route("GET", "/api/audit-sample")
def get_audit_sample(q, body):
    return audit.listing(q.get("month") or None)


@route("POST", "/api/audit-sample/draw")
def post_audit_sample_draw(q, body):
    return audit.draw(actor=_actor())


@route("GET", "/api/audit-sample/item")
def get_audit_sample_item(q, body):
    """One audit item, blind: its server, time and lines, with no score, flag or stratum."""
    source, view, row_id = _source(q), q.get("view", ""), q.get("row", "")
    if view != audit.VIEWS.get(source):
        raise ValueError("Not an audited view.")
    obs = review_context.observation(source, view, row_id)
    return {k: obs.get(k) for k in ("server", "start", "end", "lines", "line_count", "lines_status")}


@route("POST", "/api/review/context")
def post_review_context(q, body):
    """The logs from the same server before and after an observation (one read-only SQL query)."""
    source, view, row_id = _source(body), str(body.get("view", "")), str(body.get("id", ""))
    logs = [str(x) for x in (body.get("logs") or review_context.LOGS)]
    result = review_context.around(source, view, row_id, int(body.get("before", 10)), int(body.get("after", 10)), logs)
    store.log_action(_actor(), "review_context", f"{source}/{view}/{row_id}",
                     {"before": body.get("before"), "after": body.get("after"), "logs": logs, "rows": len(result["rows"])})
    return result


# --- reports: MITRE ATT&CK and the local model's help ---------------------------------------

@route("GET", "/api/attack")
def get_attack(q, body):
    return report_ai.attack()


@route("POST", "/api/report/attack/similar")
def post_attack_similar(q, body):
    """Techniques closest in wording to the evidence (no model needed)."""
    return {"candidates": [t["id"] for t in report_ai.candidates(str(body.get("evidence", "")), k=8)]}


@route("POST", "/api/report/attack")
def post_attack_match(q, body):
    evidence = str(body.get("evidence", ""))
    result = report_ai.match_attack(evidence)
    store.log_action(_actor(), "report_ai_attack", "attack", {"evidence_chars": len(evidence), "matches": [m["id"] for m in result["matches"]]})
    return result


@route("POST", "/api/report/sql")
def post_report_sql(q, body):
    """A query written by the local model for a plain-English question; checked, not run."""
    question = str(body.get("question", ""))
    result = report_ai.sql_for(question)
    store.log_action(_actor(), "report_ai_sql", "query", {"question": question[:1000], "query": result["sql"][:2000], "rejected": result["rejected"]})
    return result


@route("GET", "/api/explain/list")
def get_explain_list(q, body):
    """The activity alerts that have an explanation (Phase 4g), most unusual first."""
    return {"items": explain.items(_source(q))}


@route("GET", "/api/explain/item")
def get_explain_item(q, body):
    """One alert's explanation: reasons, its day, week and recent days, and its lines."""
    return explain.item(_source(q), q.get("view", ""), q.get("id", ""))


@route("POST", "/api/explain/reword")
def post_explain_reword(q, body):
    """The explanation in plainer words from the local model, kept only if every number matches."""
    return explain.reword(_source(body), str(body.get("view", "")), str(body.get("id", "")), _actor())


@route("GET", "/api/profiles/list")
def get_profiles_list(q, body):
    """Profiles (Phase 4h): one entity type on one day, each entity against its own normal, furthest first."""
    return profiles.overview(_source(q), q.get("type", "source_ip"), q.get("day", ""), q.get("q", ""))


@route("GET", "/api/profiles/entity")
def get_profiles_entity(q, body):
    """One entity on one day: its day, week, recent days, timeline, who it shared lines with, and its alerts."""
    return profiles.entity(_source(q), q.get("type", ""), q.get("entity", ""), q.get("day", ""))


@route("POST", "/api/profiles/watch")
def post_profiles_watch(q, body):
    """Watch an entity (the Dashboard's Watched card), or stop watching it."""
    return profiles.watch(_source(body), str(body.get("type", "")), str(body.get("entity", "")), body.get("on") is True, _actor())


@route("GET", "/api/review/history")
def get_review_history(q, body):
    return {"history": store.review_history(_source(q), q.get("view", ""), q.get("item", ""))}


NEXT_ITEMS = 6           # how many waiting items the Dashboard lists


def _waiting(source: str, item: dict) -> dict:
    """A Review item still waiting, as the Dashboard lists it."""
    return {"source": source, **{k: item.get(k) for k in ("view", "view_label", "item_id", "kind", "name", "renamed", "rank",
                                                          "flagged_rows", "line_count", "first_seen", "last_seen", "period")},
            "sigma": [s["title"] for s in item.get("sigma") or []], "server": (item.get("top") or {}).get("host_id", "")}


def _next_to_review(queues: list[list[dict]]) -> list[dict]:
    """Waiting items matching a Sigma rule first (most matching observations first), then each log type's queue in
    turn, in Review's own order."""
    sigma = sorted((i for q in queues for i in q if i.get("sigma")), key=lambda i: -sum(s["observations"] for s in i["sigma"]))
    turns = [i for group in zip_longest(*[[i for i in q if not i.get("sigma")] for q in queues]) for i in group if i]
    return sigma + turns


@route("GET", "/api/dashboard")
def get_dashboard(q, body):
    """Everything the Dashboard shows, in one call."""
    review, queues, every = [], [], {}
    for source, meta in catalog.SOURCES.items():
        items = every[source] = clusters.review_queue(source)
        counts = Counter(i["review"]["verdict"] if i.get("review") else "whitelisted" if i.get("overridden") else "open" for i in items)
        waiting = [i for i in items if not i.get("review") and not i.get("overridden")]
        queues.append([{**i, "source": source} for i in waiting])
        review.append({"source": source, "label": meta["label"], "method": meta["method"], "total": len(items),
                       "sigma_open": sum(1 for i in waiting if i.get("sigma")),
                       **{k: counts.get(k, 0) for k in ("open", "whitelisted", *store.VERDICTS)}})
    models = [{k: m.get(k) for k in ("source", "view", "view_label", "used", "method", "train_rows", "validation_rows", "test_rows")}
              for m in catalog.models(load_settings()["feature_set"])]
    counts = event_counts.load()["counts"]
    variant_state = variants.get()
    data = []
    for source, meta in catalog.SOURCES.items():
        by_month = counts.get(source, {})
        types = {t for month in by_month.values() for t in month}
        source_variants = (variant_state["counts"] or {}).get(source)
        months = sorted(m for m, types in by_month.items() if sum(types.values()))
        data.append({"source": source, "label": meta["label"], "views": len(meta["views"]), "event_types": len(types),
                     "lines": sum(sum(m.values()) for m in by_month.values()),
                     "first_month": months[0] if months else None, "last_month": months[-1] if months else None,
                     "variants": sum(source_variants.values()) if source_variants else None})
    return {"review": review, "next": [_waiting(i["source"], i) for i in _next_to_review(queues)[:NEXT_ITEMS]],
            "models": models, "data": data, "variants_ready": variant_state["status"] == "ready",
            "usage": store.usage_summary(30), "outliers": outliers.get(), "widgets": store.widget_results(),
            "watched": profiles.watched(), "triage": uploads.time_to_label(), "yields": yields.summary(every),
            "audit": audit.estimates()}


@route("POST", "/api/dashboard/widget")
def post_dashboard_widget(q, body):
    """Refreshes one of the Dashboard's SQL tables: its query runs as any other (the SQL password, the read-only
    guardrails, the activity log) and the result is kept until the next refresh."""
    sql_lock.require((body or {}).get("token"))
    widget = str((body or {}).get("id", ""))
    if not WIDGET_ID.fullmatch(widget):
        raise ValueError("Unknown Dashboard SQL table.")
    query = str((body or {}).get("query", ""))
    try:
        result = sql.run(query)
    except sql_guard.QueryRejected as error:
        store.log_action(_actor(), "sql_blocked", "query", {"query": query[:2000], "reason": str(error), "widget": widget})
        raise
    store.log_action(_actor(), "sql", "query", {"query": query[:2000], "rows": len(result["rows"]), "widget": widget})
    return store.save_widget_result(widget, query, result, _actor())


@route("POST", "/api/usage")
def post_usage(q, body):
    """Count a page view (only the count, e.g. 'view:analyze')."""
    event = str((body or {}).get("event", ""))
    if not re.fullmatch(r"view:[a-z]{2,20}", event):
        raise ValueError("Unknown usage event.")
    store.record_usage(event)
    return {"ok": True}


# --- sign-in, datasets and training (changes need a signed-in admin) ---------------------

@route("GET", "/api/auth/me")
def get_auth_me(q, body):
    return auth.status()


@route("GET", "/api/datasets")
def get_datasets(q, body):
    return {**datasets.listing(), "auth": auth.status(), "unapproved": patterns.unapproved()}


@route("POST", "/api/datasets")
def post_dataset(q, body):
    user = auth.require_admin()
    return datasets.add(body or {}, user.email or user.name)


@route("POST", "/api/datasets/import")
def post_dataset_import(q, body):
    user = auth.require_admin()
    return datasets.import_archives(str((body or {}).get("id", "")), user.email or user.name)


@route("POST", "/api/datasets/train")
def post_dataset_train(q, body):
    user = auth.require_admin()
    body = body or {}
    return datasets.train(str(body.get("id", "")), str(body.get("from_phase", "1")), user.email or user.name)


@route("POST", "/api/datasets/stop")
def post_dataset_stop(q, body):
    user = auth.require_admin()
    return datasets.stop(user.email or user.name)


# --- whitelisted users: an override on the anomalies (Settings) ------------------------------

@route("GET", "/api/whitelist")
def get_whitelist(q, body):
    return {"entries": whitelist.entries()}


@route("POST", "/api/whitelist")
def post_whitelist(q, body):
    body = body or {}
    return whitelist.add(body.get("username", ""), body.get("host", ""), body.get("reason", ""), body.get("until", ""),
                         str(body.get("password", "")), _actor(), privileged=body.get("privileged") is True)


@route("POST", "/api/whitelist/remove")
def post_whitelist_remove(q, body):
    whitelist.remove(int((body or {}).get("id", 0)), str((body or {}).get("password", "")), _actor())
    return {"ok": True}


@route("GET", "/api/audit")
def get_audit(q, body):
    return {"entries": store.audit_log(), "default_password": store.password_is_default(), "chain": store.verify_audit(),
            "archives": len(store.audit_archives())}


@route("GET", "/api/retention")
def get_retention(q, body):
    return retention.status()


@route("POST", "/api/retention/apply")
def post_retention_apply(q, body):
    return {**retention.apply(_actor()), **retention.status()}


@route("POST", "/api/audit/clear")
def post_audit_clear(q, body):
    return {"removed": store.clear_audit((body or {}).get("password", ""), _actor())}


@route("POST", "/api/admin/password")
def post_password(q, body):
    store.change_password(body.get("old", ""), body.get("new", ""), _actor())
    return {"ok": True}


def _doc_files() -> dict[str, Path]:
    files = {"app/QUICKSTART": ROOT / "QUICKSTART.md"}                 # first under Using the console: start here
    files.update({f"app/{p.stem}": p for p in sorted((DOCS / "user").glob("*.md"))})
    files["app/README"] = DOCS.parent / "README.md"                  # the console's own README: running it, caches, tests
    files.update({f"requirements/{p.stem}": p for p in sorted(DOCS.glob("*.md"))})
    files["app/VERSIONS"] = ROOT / "VERSIONS.md"
    files["pipeline/README"] = ROOT / "README.md"
    readmes = sorted([*(ROOT / "pipeline").glob("*/README.md"), *(ROOT / "pipeline").glob("*/README_*.md")])  # README_event_log.md
    files.update({f"pipeline/{p.parent.name}{'' if p.stem == 'README' else '/' + p.stem.removeprefix('README_')}": p for p in readmes})
    files.update({f"pipeline/{p.parent.name}/guide": p for p in sorted((ROOT / "pipeline").glob("*/GUIDE.md"))})   # plain-English guides
    return {k: v for k, v in files.items() if v.exists()}


# Documents built from the pipeline's code when opened, so they always match it:
# id -> (the path their links resolve against, the builder, the document listed before them)
GENERATED_DOCS = {event_log_docs.DOC_ID: (event_log_docs.SOURCE, event_log_docs.markdown, event_log_docs.AFTER)}


def _doc_entry(key: str, text: str, path: str, fallback: str) -> dict:
    first = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")), fallback)
    return {"id": key, "group": key.split("/")[0], "title": first, "words": len(text.split()),   # words: reading time
            "path": path}                                                                     # path: resolves links between documents


@route("GET", "/api/docs")
def list_docs(q, body):
    out = [_doc_entry(key, path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix(), path.stem)
           for key, path in _doc_files().items()]
    for key, (source, build, after) in GENERATED_DOCS.items():
        try:
            entry = _doc_entry(key, build(), source, key)
        except Exception:                               # a pipeline import problem must not stop the console
            continue
        out.insert(next((i + 1 for i, d in enumerate(out) if d["id"] == after), len(out)), entry)
    return {"docs": out}


@route("GET", "/api/docs/page")
def get_doc(q, body):
    if q.get("id", "") in GENERATED_DOCS:
        source, build, _ = GENERATED_DOCS[q["id"]]
        return {"id": q["id"], "markdown": build(), "path": source}
    path = _doc_files().get(q.get("id", ""))
    if path is None:
        raise KeyError("No such document.")
    return {"id": q["id"], "markdown": path.read_text(encoding="utf-8"), "path": path.relative_to(ROOT).as_posix()}


# --- HTTP plumbing -------------------------------------------------------------------

def _finite(value):
    """``value`` with every NaN or infinite number replaced by None (null), at any depth."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: _finite(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_finite(v) for v in value]
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "SMRTOTConsole/0.2"

    def log_message(self, fmt, *args):            # quiet console; errors are still printed
        pass

    def _allowed(self, path: str) -> bool:
        """This laptop's name in Host (no DNS rebinding) and no other site's Origin. The API also needs API_HEADER and
        no browser mark of another site or of the address bar (Sec-Fetch-Site), so typing /api/... shows nothing.
        Signing out needs no mark of another site. Opening the app's page from a link elsewhere is fine: it cannot be
        framed (PAGE_POLICY)."""
        host = (self.headers.get("Host") or "").split(":")[0]
        origin = self.headers.get("Origin")
        own = (f"http://{HOST}:{PORT}", f"http://localhost:{PORT}", *DEV_ORIGINS)
        if host not in ("127.0.0.1", "localhost") or (origin is not None and origin not in own):
            return False
        site = self.headers.get("Sec-Fetch-Site")         # absent from non-browser clients on this laptop
        if path.startswith("/api/"):
            return self.headers.get(API_HEADER) == "1" and site in (None, "same-origin")
        return path != "/auth/logout" or site is None or site in OWN_SITES

    def _security_headers(self, content_type: str = "") -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", PAGE_POLICY)

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._security_headers(content_type)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, data) -> None:
        try:
            text = json.dumps(data, default=str, allow_nan=False)
        except ValueError:                           # NaN or infinity somewhere: JSON has no such number, browsers reject it
            text = json.dumps(_finite(data), default=str)
        self._send(status, text.encode("utf-8"), "application/json; charset=utf-8")

    def _redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self._security_headers()
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _auth_route(self, path: str, query: dict) -> None:
        """Browser navigations for SSO: /auth/login, /auth/callback, /auth/logout."""
        try:
            if path == "/auth/login":
                return self._redirect(auth.login_redirect())
            if path == "/auth/callback":
                session = auth.complete_login(query)
                user = auth.session_user(session)
                store.log_action(user.email or user.name if user else "sso", "sign_in", "session", {"admin": bool(user and user.admin)})
                return self._redirect("/#/datasets", auth.cookie(session))
            if path == "/auth/logout":
                user = auth.current()
                provider_logout = auth.logout(self.headers.get("Cookie"))
                if user is not None:
                    store.log_action(user.email or user.name, "sign_out", "session", {"at_provider": bool(provider_logout)})
                # on to the provider's sign-out too, so the next person cannot be signed straight back in
                return self._redirect(provider_logout or "/#/datasets", auth.cookie(None))
        except PermissionError as error:
            message = f"<!doctype html><meta charset=utf-8><title>Sign-in</title><p>{html.escape(str(error))}</p><p><a href='/#/datasets'>Back to the console</a></p>"
            return self._send(HTTPStatus.FORBIDDEN, message.encode("utf-8"), "text/html; charset=utf-8")
        self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def _discard_body(self) -> None:
        """Reads the body of a request that is refused unread, so the answer arrives: closing a connection with data
        still unread makes Windows reset it, and the browser sees a broken connection instead of the refusal."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        if 0 < length <= MAX_BODY:
            self.rfile.read(length)

    def _refuse(self, status: int, data: dict) -> None:
        self._discard_body()
        self._json(status, data)

    def _handle(self, method: str) -> None:
        url = urlparse(self.path)
        if not self._allowed(url.path):
            return self._refuse(HTTPStatus.FORBIDDEN, {"error": "Requests are accepted only from this application."})
        auth.bind(self.headers.get("Cookie"))          # who is signed in (SSO), for this request only
        if url.path.startswith("/auth/") and method == "GET":
            return self._auth_route(url.path, {k: v[-1] for k, v in parse_qs(url.query).items()})
        # Changes must come as JSON from the app's own page: an ordinary web form cannot send that.
        if method in ("POST", "PUT") and not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self._refuse(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Send JSON."})
        if not url.path.startswith("/api/"):
            return self._static(url.path) if method == "GET" else self._refuse(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        function = ROUTES.get((method, url.path))
        if function is None:
            return self._refuse(HTTPStatus.NOT_FOUND, {"error": f"No such API: {method} {url.path}"})
        query = {k: v[-1] for k, v in parse_qs(url.query).items()}
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "The upload is larger than 64 MB."})
            body = json.loads(self.rfile.read(length) or b"null") if length else None
            self._json(HTTPStatus.OK, function(query, body))
        except sql_lock.Locked as error:             # the browser asks for the SQL password and tries again
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error), "code": "sql_locked"})
        except store.DefaultPassword as error:       # the browser asks for a new password instead
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error), "code": "default_password", "which": error.which})
        except PermissionError as error:
            self._json(HTTPStatus.FORBIDDEN, {"error": str(error)})
        except (ValueError, KeyError) as error:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(error).strip("'\"")})
        except Exception as error:                   # report, keep serving
            traceback.print_exc()
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(error).__name__}: {error}"})

    def _static(self, path: str) -> None:
        if not WEB_DIST.exists():
            return self._send(HTTPStatus.OK, b"The web app is not built yet: run `npm run build` in triage-console/web, "
                                             b"or use `npm run dev` and open http://localhost:5173.", "text/plain")
        # The build's own files, matched by name, so the address never reaches the file system. The app's pages are
        # #/ routes, so any other address (/sql, /admin, ../) is not found rather than the app.
        files = {p.relative_to(WEB_DIST).as_posix(): p for p in WEB_DIST.rglob("*") if p.is_file()}
        target = files.get(path.lstrip("/") or "index.html")
        if target is None:
            return self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(HTTPStatus.OK, target.read_bytes(), content_type)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    restored = restore_frozen_caches()
    print(f"SMRT OT Console on http://{HOST}:{PORT}  (data: {DATA}{' - frozen runtime' if FROZEN else ''}, app data: {APP / 'var'})")
    if restored:
        print("Restored from the frozen runtime: " + ", ".join(restored))
    variants.start_background()          # message variants per event type (cached after the first run)
    cluster_index.start_background()     # cluster members and event-type mix (cached after the first run)
    ip_flows.start_background()          # traffic by address for the second Sankey (cached after the first run)
    outliers.start_background()          # rows flagged per mechanism, for the Dashboard's outlier pie and Venn
    retention.start_background()         # copies of log lines past Settings → Retention, now and once a day
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
