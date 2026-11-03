r"""Isolated Edge check of Pipeline Studio against the production web build.

Run from the project root:
    .venv\Scripts\python.exe triage-console\tests\browser_pipeline_studio.py

Serves only web/dist on a free localhost port. Every API response is fabricated, and unexpected API or external
requests fail the check. No console service, database, model or original log is opened. Screenshots contain only
the built-in sample flow and go to var/checks/pipeline-studio; exported test JSON is kept in a temporary folder.
"""
from __future__ import annotations

import functools
import json
import tempfile
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright


APP = Path(__file__).resolve().parents[1]
DIST = APP / "web" / "dist"
ARTIFACTS = APP / "var" / "checks" / "pipeline-studio"
STORAGE_KEY = "dad.pipeline-studio.draft.v1"
SETTINGS = {
    "language": "en", "theme": "light", "font_family": "inter", "font_installed": "", "font_scale": 1,
    "display_name": "Sample analyst", "llm_endpoint": "http://127.0.0.1:11434", "llm_model": "sample-model",
    "feature_set": "selected", "animations": "none", "animation_pack": "transit", "console_mode": "advanced",
    "dashboard_layout": None, "review_filter_seconds": 120, "retention_months": 12,
}
CATALOG = {"sources": {"auth": {"label": "Authentication", "prefix": "authlog", "method": "baseline", "views": []}}}


class StaticFiles(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def run() -> dict:
    if not (DIST / "index.html").is_file():
        raise RuntimeError("Build the web application first: cd triage-console/web; npm.cmd run build")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    handler = functools.partial(StaticFiles, directory=str(DIST))
    http = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server_thread = threading.Thread(target=http.serve_forever, daemon=True)
    server_thread.start()
    origin = f"http://127.0.0.1:{http.server_port}"
    unexpected: list[str] = []
    requests: list[str] = []
    errors: list[str] = []
    passed: list[str] = []
    screenshots: list[str] = []

    def response(route):
        request = route.request
        parsed = urlparse(request.url)
        if parsed.scheme not in ("http", "https"):
            route.continue_()
            return
        if f"{parsed.scheme}://{parsed.netloc}" != origin:
            unexpected.append(f"External request: {request.method} {request.url}")
            route.abort()
            return
        if not parsed.path.startswith("/api/"):
            route.continue_()
            return
        key = f"{request.method} {parsed.path}"
        requests.append(key)
        payloads = {
            "GET /api/settings": SETTINGS,
            "GET /api/catalog": CATALOG,
            "GET /api/llm/models": {"online": False, "models": ["sample-model"], "installed": [], "endpoint": "", "error": ""},
            "POST /api/usage": {"ok": True},
        }
        if key not in payloads:
            unexpected.append(key)
            route.fulfill(status=500, json={"error": f"Unexpected API request in isolated check: {key}"})
            return
        route.fulfill(status=200, json=payloads[key])

    try:
        with tempfile.TemporaryDirectory(prefix="dad-studio-browser-") as scratch, sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="msedge", headless=True)
            try:
                context = browser.new_context(viewport={"width": 1600, "height": 1050}, accept_downloads=True,
                                              reduced_motion="reduce", color_scheme="light")
                page = context.new_page()
                page.set_default_timeout(10_000)
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.route("**/*", response)

                def screenshot(name: str) -> None:
                    target = ARTIFACTS / name
                    page.screenshot(path=str(target), full_page=True)
                    screenshots.append(str(target))
                    print(f"Screenshot: {target}", flush=True)

                def draft() -> dict:
                    return page.evaluate("key => JSON.parse(localStorage.getItem(key))", STORAGE_KEY)

                def nodes(count: int, edges: int | None = None) -> None:
                    expect(page.locator(".ps-node")).to_have_count(count)
                    if edges is not None:
                        expect(page.locator(".ps-edge")).to_have_count(edges)

                def preview() -> None:
                    page.get_by_role("button", name="Preview sample", exact=True).first.click()

                def choose(node_id: str) -> None:
                    page.locator(f'.ps-node[data-id="{node_id}"] .ps-node-title').click(force=True)

                def connect_from(node_id: str) -> None:
                    page.get_by_label("Connect from block", exact=True).select_option(node_id)
                    page.locator(".ps-inspector").get_by_role("button", name="Connect", exact=True).click()

                def add_from_library(kind: str, search: str) -> None:
                    page.get_by_label("Search blocks", exact=True).fill(search)
                    page.locator(f'.ps-library-block[data-kind="{kind}"]').click()
                    page.get_by_label("Search blocks", exact=True).fill("")

                try:
                    page.goto(f"{origin}/#/pipelines", wait_until="networkidle")
                    expect(page.get_by_role("heading", name="Pipeline Studio", exact=True)).to_be_visible()
                    expect(page.locator('.nav-group[aria-label="Develop"] > a[href="#/pipelines"]')).to_be_visible()
                    expect(page.locator('.nav-group[aria-label="Prepare"] > a[href="#/datasets"]')).to_be_visible()
                    expect(page.locator('.nav-group[aria-label="Detect"] > a[href="#/analyze"]')).to_be_visible()
                    nodes(4, 3)
                    expect(page.get_by_role("button", name="Full run", exact=True)).to_be_disabled()
                    preview()
                    expect(page.locator(".ps-preview-summary strong")).to_have_text("5 rows")
                    expect(page.locator(".ps-preview-body tbody tr")).to_have_count(5)
                    screenshot("01-studio-light.png")
                    passed.append("Advanced navigation, starter graph and actual five-row sample output")

                    choose("starter-sql")
                    original_query = page.get_by_label("Query", exact=True).input_value()
                    page.get_by_label("Query", exact=True).fill("DELETE FROM sample_events")
                    page.get_by_label("Query", exact=True).press("Tab")
                    preview()
                    expect(page.locator(".ps-issues")).to_contain_text("Sample SQL supports SELECT")
                    expect(page.locator(".ps-canvas-head")).to_contain_text("Needs attention")
                    page.get_by_role("button", name="Undo", exact=True).click()
                    expect(page.get_by_label("Query", exact=True)).to_have_value(original_query)
                    preview()
                    expect(page.locator(".ps-preview-summary strong")).to_have_text("5 rows")
                    passed.append("Unsupported SQL rejected and Undo restores executable settings")

                    before = next(node for node in draft()["nodes"] if node["id"] == "starter-sql")
                    block = page.locator('.ps-node[data-id="starter-sql"] .ps-node-top')
                    box = block.bounding_box()
                    assert box, "Source block has no draggable bounding box"
                    start = (box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                    page.mouse.move(*start)
                    page.mouse.down()
                    page.mouse.move(start[0] + 64, start[1] - 40, steps=8)
                    page.mouse.up()
                    after = next(node for node in draft()["nodes"] if node["id"] == "starter-sql")
                    assert (after["x"], after["y"]) != (before["x"], before["y"]), "Pointer drag did not move the block"
                    page.reload(wait_until="networkidle")
                    expect(page.locator(".ps-node")).to_have_count(4)
                    restored = next(node for node in draft()["nodes"] if node["id"] == "starter-sql")
                    assert (restored["x"], restored["y"]) == (after["x"], after["y"]), "Block position was not restored"
                    choose("starter-sql")
                    page.get_by_role("button", name="Delete block", exact=True).click()
                    nodes(3, 2)
                    page.get_by_role("button", name="Undo", exact=True).click()
                    nodes(4, 3)
                    passed.append("Pointer drag persists across reload; deleting a block removes edges and can be undone")

                    page.get_by_label("Load a pipeline template", exact=True).select_option("blank")
                    nodes(0, 0)
                    add_from_library("sql", "SQL query")
                    add_from_library("check", "Sanity check")
                    nodes(2, 0)
                    page.get_by_role("button", name="Check flow", exact=True).first.click()
                    expect(page.locator(".ps-issues")).to_contain_text("Connect an upstream block to this input")
                    sql_id = next(node["id"] for node in draft()["nodes"] if node["kind"] == "sql")
                    check_id = next(node["id"] for node in draft()["nodes"] if node["kind"] == "check")
                    connect_from(sql_id)
                    add_from_library("output", "Table output")
                    connect_from(check_id)
                    nodes(3, 2)
                    preview()
                    expect(page.locator(".ps-preview-summary strong")).to_have_text("12 rows")
                    expect(page.locator(".ps-node[data-status=passed]")).to_have_count(3)
                    passed.append("Blank flow: add blocks, detect missing input, connect through inspector and preview twelve rows")

                    portable = draft()
                    with page.expect_download() as download_info:
                        page.get_by_role("button", name="Export JSON", exact=True).click()
                    export = Path(scratch) / "roundtrip.pipeline.json"
                    download_info.value.save_as(export)
                    assert json.loads(export.read_text(encoding="utf-8")) == portable, "Export does not match edited draft"
                    page.get_by_label("Load a pipeline template", exact=True).select_option("blank")
                    nodes(0)
                    page.get_by_label("Import pipeline JSON file", exact=True).set_input_files(str(export))
                    nodes(3, 2)
                    assert draft() == portable, "Import changed the exported graph"
                    page.get_by_label("Import pipeline JSON file", exact=True).set_input_files({
                        "name": "invalid.pipeline.json", "mimeType": "application/json", "buffer": b'{"version":999}',
                    })
                    expect(page.locator(".ps-notice")).to_contain_text("not supported")
                    assert draft() == portable, "Invalid import overwrote the current graph"
                    passed.append("JSON export/import round trip and invalid-import preservation")

                    page.get_by_label("Load a pipeline template", exact=True).select_option("dad")
                    nodes(7, 6)
                    preview()
                    expect(page.locator(".ps-canvas-head")).to_contain_text("Partial preview")
                    expect(page.locator(".ps-node[data-status=skipped]")).to_have_count(6)
                    expect(page.locator(".ps-run-log")).to_contain_text("not connected")
                    passed.append("DAD phase adapters are shown as skipped rather than fabricated execution")

                    page.get_by_label("Load a pipeline template", exact=True).select_option("sanity")
                    preview()
                    SETTINGS["theme"] = "dark"
                    page.reload(wait_until="networkidle")
                    expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                    preview()
                    screenshot("02-studio-dark.png")
                    page.set_viewport_size({"width": 390, "height": 844})
                    page.reload(wait_until="networkidle")
                    expect(page.locator(".ps-node")).to_have_count(4)
                    screenshot("03-studio-mobile.png")
                    dimensions = page.evaluate("({width: innerWidth, content: document.scrollingElement.scrollWidth})")
                    assert dimensions["content"] <= dimensions["width"] + 1, f"Mobile page overflows horizontally: {dimensions}"
                    expect(page.get_by_label("Search blocks", exact=True)).to_be_visible()
                    passed.append("Dark appearance and 390-pixel mobile layout without page horizontal overflow")

                    assert not errors, f"Browser script errors: {errors}"
                    assert not unexpected, f"Unexpected live or external requests: {unexpected}"
                    passed.append("No browser errors and no live database, model, execution or external requests")
                    return {"passed": passed, "screenshots": screenshots, "mocked_api_requests": sorted(set(requests))}
                except BaseException:
                    screenshot("failure.png")
                    print(json.dumps({"passed_before_failure": passed, "browser_errors": errors, "unexpected_requests": unexpected}, indent=2), flush=True)
                    raise
                finally:
                    context.close()
            finally:
                browser.close()
    finally:
        http.shutdown()
        http.server_close()
        server_thread.join(timeout=5)
        SETTINGS["theme"] = "light"


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
