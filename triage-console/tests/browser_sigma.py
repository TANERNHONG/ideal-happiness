r"""Real Edge check of Advanced → Sigma with an isolated console store (the starter rules are seeded into it).

Run from triage-console: ..\.venv\Scripts\python.exe tests/browser_sigma.py
Screenshots go to var/checks/sigma. User settings, rules and the activity log are never changed by this check, and
no data/ is read: the event types offered are made up, the local model is a stand-in (named so on the page), and the
Review pass a saved rule starts is left out.
"""
import json
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import config
from playwright.sync_api import expect, sync_playwright

LINE = "Jul 14 {t} host-a sshd[{pid}]: [ID 800047 auth.info] {msg}"
LINES = ([LINE.format(t=f"12:04:{30 + i * 3:02d}", pid=100 + i, msg="Failed password for root from 192.0.2.17 port 5000 ssh2") for i in range(9)]
         + [LINE.format(t="12:06:10", pid=200, msg="Accepted password for root from 192.0.2.17 port 5001 ssh2")]
         + [LINE.format(t=f"12:1{i}:00", pid=300 + i, msg=f"Invalid user {name} from 192.0.2.40 port 6000")
            for i, name in enumerate(["admin", "oracle", "test", "guest", "pi", "ubuntu"])])
TYPES = {"auth": ["SSH_INVALID_USER", "SSH_LOGIN_FAILED", "SSH_LOGIN_SUCCESS", "SU_SESSION_FAILED"],
         "ossec": ["OSSEC_AGENT_STOPPED"], "pf": ["PF_BLOCK_IN"], "ipf": ["IPF_BLOCK_IN"]}
DESCRIPTION = "Alert when one address tries 5 or more different invalid usernames over SSH within 10 minutes"
# What the stand-in model answers for DESCRIPTION
DRAFTED = """title: Invalid SSH user
name: invalid_ssh_user
status: experimental
logsource:
  product: solaris
  service: sshd
detection:
  selection:
    event_type: SSH_INVALID_USER
  condition: selection
level: informational
---
title: Many invalid usernames from one address
status: experimental
correlation:
  type: value_count
  rules:
    - invalid_ssh_user
  group-by:
    - source_ip
  timespan: 10m
  condition:
    gte: 5
    field: username
level: medium
tags:
  - attack.credential-access
  - attack.t1110.001
"""


def run():
    artifacts = config.VAR / "checks" / "sigma"
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="huh-sigma-") as tmp:
        config.VAR = Path(tmp)
        config.STORE_FILE = config.VAR / "console.sqlite3"
        config.SETTINGS_FILE = config.VAR / "settings.json"
        config.PORT = 8767
        config.save_settings({"console_mode": "advanced", "animations": "none", "display_name": "Analyst A", "llm_model": "stand-in"})
        from service import cluster_index, llm, server, sigma_form
        stand_ins = [mock.patch.object(sigma_form, "event_types", return_value=TYPES),
                     mock.patch.object(llm, "chat", return_value=json.dumps({"yaml": DRAFTED})),
                     mock.patch.object(cluster_index, "refresh")]
        for p in stand_ins:
            p.start()
        app = ThreadingHTTPServer(("127.0.0.1", 8767), server.Handler)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        errors = []
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)
            page = browser.new_page(viewport={"width": 1600, "height": 2400}, device_scale_factor=2)   # tall: nothing scrolls under the header
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("dialog", lambda d: d.accept())
            editor, flow = page.locator(".sg-editor"), page.locator(".sg-flow")
            try:
                page.goto("http://127.0.0.1:8767/#/sigma")
                page.locator(".sg-row").first.wait_for()
                assert page.locator(".sg-row").count() == 8, page.locator(".sg-row").count()
                assert page.locator(".sg-row .sg-stamp-name").first.inner_text() == "starter rules"
                page.screenshot(path=str(artifacts / "1-rules.png"), full_page=True)
                page.get_by_label("Log lines", exact=True).fill("\n".join(LINES))
                page.get_by_label("Month", exact=True).fill("2026-07")
                page.get_by_role("button", name="Run", exact=True).click()
                page.locator(".sg-hit").first.wait_for(timeout=60000)
                titles = page.locator(".sg-hit .sg-hit-title").all_inner_texts()
                assert any("after password guessing" in t for t in titles), titles
                assert any("enumeration" in t for t in titles), titles
                page.locator(".sg-hit").first.click()
                page.locator(".sg-line").first.wait_for()
                page.screenshot(path=str(artifacts / "2-hits.png"), full_page=True)

                # A rule the form can show opens in the form; YAML is one click away and checked live
                page.locator(".sg-row").filter(has_text="Repeated su failures").click()
                expect(page.get_by_role("tab", name="Form", exact=True)).to_have_attribute("aria-selected", "true")
                expect(page.get_by_label("Title", exact=True)).to_have_value("Repeated su failures")
                page.get_by_role("tab", name="YAML", exact=True).click()
                page.locator(".sg-yaml").fill("title: broken\ndetection:\n  s: {a|nope: 1}\n  condition: s\n")
                page.locator(".sg-check .error").wait_for()
                expect(page.get_by_role("tab", name="Form", exact=True)).to_be_disabled()

                # A new rule: the form first, its required fields marked until filled; Accept locked until tested
                page.get_by_role("button", name="New", exact=True).click()
                expect(page.get_by_role("tab", name="Form", exact=True)).to_have_attribute("aria-selected", "true")
                expect(page.locator(".sf-block.missing")).to_have_count(2)                 # title, match
                editor.screenshot(path=str(artifacts / "3-form-new.png"))
                page.get_by_label("Title", exact=True).fill("Root password guessing from one address")
                values = page.get_by_label("Values", exact=True)
                values.first.fill("SSH_LOGIN_FAILED")
                values.first.press("Enter")
                page.get_by_role("button", name="Add match", exact=True).click()
                values.nth(1).fill("root")
                values.nth(1).press("Enter")
                page.get_by_label("Count", exact=True).check()
                page.get_by_role("tab", name="High", exact=True).click()
                expect(page.locator(".sf-block.missing")).to_have_count(0)
                expect(page.locator(".sg-preview")).to_contain_text("type: event_count")
                expect(page.locator(".sg-preview")).to_contain_text("author: Analyst A")
                accept = page.get_by_role("button", name="Accept", exact=True)
                expect(accept).to_be_disabled()
                editor.screenshot(path=str(artifacts / "4-form-filled.png"))
                page.get_by_role("button", name="Test", exact=True).click()
                page.get_by_role("heading", name="Test", exact=True).wait_for(timeout=60000)
                expect(accept).to_be_enabled()
                expect(flow.locator(".sg-step.done")).to_have_count(2)
                editor.screenshot(path=str(artifacts / "5-form-tested.png"))
                accept.click()
                expect(page.locator(".sg-row")).to_have_count(9)
                mine = page.locator(".sg-row.on")
                expect(mine.locator(".sg-stamp-name")).to_have_text("Analyst A")
                expect(mine.locator(".badge", has_text="New")).to_have_count(1)
                expect(editor.locator(".card-head .sg-stamp-name")).to_have_text("Analyst A")

                # Describe: plain English, a stand-in model's draft as a card and YAML, then the same Test → Accept
                page.get_by_role("button", name="New", exact=True).click()
                page.get_by_role("tab", name="Describe", exact=True).click()
                page.get_by_label("Description", exact=True).fill(DESCRIPTION)
                page.get_by_role("button", name="Write", exact=True).click()
                page.locator(".sf-card").wait_for()
                expect(page.locator(".sg-ai-model")).to_have_text("stand-in")
                expect(page.locator(".sf-card")).to_contain_text("distinct username")
                expect(accept).to_be_disabled()
                editor.screenshot(path=str(artifacts / "6-describe-preview.png"))
                page.get_by_role("button", name="Test", exact=True).click()
                page.get_by_role("heading", name="Test", exact=True).wait_for(timeout=60000)
                expect(flow.locator(".sg-test-hits")).to_have_text("hits1")
                editor.screenshot(path=str(artifacts / "7-describe-tested.png"))
                accept.click()
                expect(page.locator(".sg-row")).to_have_count(10)
                expect(page.get_by_role("tab", name="Form", exact=True)).to_have_attribute("aria-selected", "true")
                page.locator(".sg-work").screenshot(path=str(artifacts / "8-accepted.png"))
                expect(page.locator(".sg-row.on .sg-stamp-name")).to_be_in_viewport()          # the list shows the new rule
                page.get_by_role("button", name="New", exact=True).click()                      # the YAML templates are still offered
                page.get_by_role("tab", name="YAML", exact=True).click()
                page.get_by_role("tab", name="Count", exact=True).click()
                page.locator(".sg-check .sg-doc").nth(1).wait_for()
            finally:
                browser.close()
                app.shutdown()
                for p in stand_ins:
                    p.stop()
        assert not errors, errors
        print("Sigma browser check passed; screenshots in", artifacts)


if __name__ == "__main__":
    run()
