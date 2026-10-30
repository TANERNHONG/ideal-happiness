"""Tests for Sigma's form and AI drafting (service/sigma_form.py, sigma_ai.py): the form as YAML and back, the starter
rules through the form, the local model's drafts (against a stand-in model), and the record of who added a rule and
whether it was tested first. Each test that saves has its own store.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_sigma_form -v
"""
from __future__ import annotations

import gc
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import cluster_index, llm, sigma, sigma_ai, sigma_form, store, whitelist  # noqa: E402
from tests.test_sigma import AUTH, event, run, titles  # noqa: E402

TYPES = {"auth": ["SSH_INVALID_USER", "SSH_LOGIN_FAILED", "SSH_LOGIN_SUCCESS"], "pf": ["PF_BLOCK"]}


def form(**changes) -> dict:
    base = {"id": "1f0c2b3a-0000-4000-8000-000000000001", "title": "Root login failed", "source": "auth", "service": "sshd",
            "match": [{"field": "event_type", "op": "is", "values": ["SSH_LOGIN_FAILED"]},
                      {"field": "username", "op": "is", "values": ["root", "admin"]}],
            "exclude": [], "count": None, "level": "high", "status": "", "description": "", "tags": ["attack.t1110.001"],
            "falsepositives": [], "author": "", "date": "", "keep": {}}
    return {**base, **changes}


def docs(text: str) -> list[dict]:
    return [d.summary() for d in sigma.parse(text, 1)]


class FormToYaml(unittest.TestCase):
    def test_an_event_rule(self):
        text = sigma_form.to_yaml(form(), "tester")
        d = docs(text)
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0]["kind"], d[0]["sources"], d[0]["process"], d[0]["level"], d[0]["techniques"]),
                         ("event", ["auth"], "sshd", "high", ["T1110.001"]))
        self.assertIn("author: tester", text)
        self.assertIn("  - root", text)                          # lists indented under their key, as Sigma is written
        result = run(text, [event(event_type="SSH_LOGIN_FAILED", username="root", process_name="sshd"),
                            event(event_type="SSH_LOGIN_FAILED", username="oracle", process_name="sshd")])
        self.assertEqual(titles(result), ["Root login failed"])

    def test_required_fields_still_empty(self):
        self.assertEqual(sigma_form.missing(form()), [])
        empty = form(title=" ", source="", match=[{"field": "event_type", "op": "is", "values": []}])
        self.assertEqual(sigma_form.missing(empty), ["title", "source", "match"])
        preview = sigma_form.preview(empty, "tester")
        self.assertEqual(preview["missing"], ["title", "source", "match"])
        self.assertIn("error", preview)

    def test_except_rows_each_rule_an_event_out(self):
        text = sigma_form.to_yaml(form(match=[{"field": "event_type", "op": "is", "values": ["SSH_LOGIN_FAILED"]}],
                                       exclude=[{"field": "username", "op": "is", "values": ["svc_backup"]},
                                                {"field": "source_ip", "op": "cidr", "values": ["10.0.0.0/8"]}]))
        self.assertIn("condition: selection and not 1 of filter_*", text)
        events = [event(event_type="SSH_LOGIN_FAILED", username="root", source_ip="192.0.2.1", process_name="sshd"),
                  event(event_type="SSH_LOGIN_FAILED", username="svc_backup", source_ip="192.0.2.1", process_name="sshd"),
                  event(event_type="SSH_LOGIN_FAILED", username="root", source_ip="10.1.2.3", process_name="sshd")]
        self.assertEqual(len(run(text, events)["hits"]), 1)

    def test_the_same_test_twice_must_both_hold(self):
        text = sigma_form.to_yaml(form(match=[{"field": "raw_message", "op": "contains", "values": ["root"]},
                                              {"field": "raw_message", "op": "contains", "values": ["port 22"]}]))
        self.assertIn("selection_2:", text)
        self.assertIn("condition: selection and selection_2", text)

    def test_a_count_becomes_a_correlation(self):
        text = sigma_form.to_yaml(form(match=[{"field": "event_type", "op": "is", "values": ["SSH_LOGIN_FAILED"]}],
                                       count={"min": 3, "within": "2m", "by": ["source_ip", "host"], "distinct": ""}))
        d = docs(text)
        self.assertEqual([x["kind"] for x in d], ["event", "event_count"])
        self.assertEqual((d[1]["threshold"], d[1]["window"], d[1]["group_by"], d[1]["refs"]), ("≥ 3", "2m", ["source_ip", "host"], [d[0]["name"]]))
        self.assertEqual(d[0]["level"], "informational")
        failed = [event(i * 10, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.9", process_name="sshd") for i in range(3)]
        self.assertEqual(titles(run(text, failed)), ["Root login failed"])

    def test_a_distinct_count(self):
        text = sigma_form.to_yaml(form(count={"min": 5, "within": "1h", "by": ["source_ip"], "distinct": "username"}))
        d = docs(text)
        self.assertEqual((d[1]["kind"], d[1]["value_field"]), ("value_count", "username"))

    def test_bad_values_say_what_to_change(self):
        with self.assertRaisesRegex(ValueError, "not a number"):
            sigma_form.to_yaml(form(match=[{"field": "failure_count", "op": "gte", "values": ["many"]}]))
        with self.assertRaisesRegex(ValueError, "time span"):
            sigma_form.to_yaml(form(count={"min": 3, "within": "soon", "by": [], "distinct": ""}))
        with self.assertRaisesRegex(ValueError, "at least 1"):
            sigma_form.to_yaml(form(count={"min": 0, "within": "5m", "by": [], "distinct": ""}))
        numbers = sigma_form.to_yaml(form(match=[{"field": "failure_count", "op": "gte", "values": ["3"]}]))
        self.assertIn("failure_count|gte: 3", numbers)


class YamlToForm(unittest.TestCase):
    def test_round_trip(self):
        for f in (form(), form(count={"min": 8, "within": "2m", "by": ["source_ip"], "distinct": ""}),
                  form(exclude=[{"field": "username", "op": "startswith", "values": ["svc_"]}], source="pf", service="",
                       match=[{"field": "event_type", "op": "is", "values": ["PF_BLOCK"]}])):
            with self.subTest(form=f["title"], count=bool(f["count"]), source=f["source"]):
                text = sigma_form.to_yaml(f, "tester")
                back = sigma_form.to_form(text)
                self.assertIsNotNone(back, text)
                self.assertEqual(sigma_form.to_yaml(back, "someone else"), text)            # author and date kept

    def test_starter_rules_through_the_form_read_the_same(self):
        shown = []
        for path in sorted(sigma.STARTER.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            f = sigma_form.to_form(text)
            if f is None:
                continue
            shown.append(path.name)
            with self.subTest(rule=path.name):
                self.assertEqual(docs(sigma_form.to_yaml(f, "tester")), docs(text))
        # The others open as YAML: 20 and 80 count a rule kept in another entry, 30 is "1 of", 70 is both firewalls,
        # 40 a sequence.
        self.assertEqual(shown, ["10_auth_ssh_guessing.yml", "50_auth_su_failures.yml", "60_ossec_agent_stopped.yml"])

    def test_rules_the_form_cannot_show_open_as_yaml(self):
        cases = {
            "or": "title: t\nlogsource: {product: pf}\ndetection:\n  a: {action: block}\n  b: {action: pass}\n  condition: a or b\n",
            "list of maps": "title: t\nlogsource: {product: pf}\ndetection:\n  a:\n    - {action: block}\n    - {action: pass}\n  condition: a\n",
            "two log types": "title: t\nlogsource: {category: firewall}\ndetection:\n  a: {action: block}\n  condition: a\n",
            "aggregation": "title: t\nlogsource: {product: pf}\ndetection:\n  a: {action: block}\n  condition: a | count() by source_ip > 5\n  timeframe: 5m\n",
            "unused selection": "title: t\nlogsource: {product: pf}\ndetection:\n  a: {action: block}\n  b: {action: pass}\n  condition: a\n",
            "not yaml": "title: [unclosed\n",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(sigma_form.to_form(text))
        with_sequence = (sigma.STARTER / "40_auth_ssh_success_after_guessing.yml").read_text(encoding="utf-8")
        self.assertIsNone(sigma_form.to_form(with_sequence))

    def test_what_the_form_does_not_show_is_kept(self):
        text = (sigma.STARTER / "10_auth_ssh_guessing.yml").read_text(encoding="utf-8")
        again = sigma_form.to_yaml(sigma_form.to_form(text), "tester")
        self.assertIn("name: dad_ssh_login_failed", again)          # other rules count it by this name
        self.assertIn("references:", again)


class Describe(unittest.TestCase):
    """The local model's drafts, against a stand-in model."""

    GOOD = {"yaml": "title: Root login failed\nlogsource: {product: solaris, service: sshd}\ndetection:\n"
                    "  selection: {event_type: SSH_LOGIN_FAILED, username: root}\n  condition: selection\nlevel: high\n"}

    def setUp(self):
        self.patches = [mock.patch.object(sigma_form, "event_types", return_value=TYPES),
                        mock.patch.object(sigma_ai, "load_settings", return_value={"llm_model": "stand-in"})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_a_draft_reads_and_fills_the_form(self):
        with mock.patch.object(llm, "chat", return_value=json.dumps(self.GOOD)) as chat:
            result = sigma_ai.describe("Alert when someone fails to log in as root over SSH", "auth")
        self.assertEqual((result["docs"][0]["title"], result["model"], result["tries"]), ("Root login failed", "stand-in", 1))
        self.assertEqual(result["form"]["match"][1], {"field": "username", "op": "is", "values": ["root"]})
        system, prompt = chat.call_args.args
        self.assertIn("SSH_LOGIN_FAILED", prompt)                   # the data's event types, for the log type asked
        self.assertIn("authentication_method", prompt)
        self.assertNotIn("PF (OpenBSD firewall)", prompt)            # only the log type asked for
        self.assertIn("dad_ssh_guessing", prompt)                   # starter rules as examples

    def test_a_draft_that_does_not_read_is_sent_back_once(self):
        answers = [json.dumps({"yaml": "title: t\ndetection: {s: {a|nope: 1}, condition: s}\n"}), json.dumps(self.GOOD)]
        with mock.patch.object(llm, "chat", side_effect=answers) as chat:
            result = sigma_ai.describe("root logins", "auth")
        self.assertEqual((chat.call_count, result["tries"]), (2, 2))
        self.assertIn("could not read it", chat.call_args.args[1])
        self.assertIn("docs", result)

    def test_still_wrong_after_the_second_try_shows_what_is_wrong(self):
        with mock.patch.object(llm, "chat", return_value="not a rule"):
            result = sigma_ai.describe("root logins", "auth")
        self.assertIn("error", result)
        self.assertIsNone(result["form"])

    def test_an_answer_cannot_run_code(self):
        attack = json.dumps({"yaml": "title: !!python/object/apply:os.system ['calc']\ndetection: {s: {a: 1}, condition: s}\n"})
        with mock.patch.object(llm, "chat", return_value=attack), mock.patch("os.system") as system:
            result = sigma_ai.describe("anything", "auth")
        system.assert_not_called()
        self.assertIn("error", result)

    def test_code_fences_and_plain_answers(self):
        fenced = "```yaml\n" + self.GOOD["yaml"] + "```"
        with mock.patch.object(llm, "chat", return_value=fenced):
            self.assertIn("docs", sigma_ai.describe("root logins", "auth"))

    def test_no_description_or_no_model(self):
        with self.assertRaises(ValueError):
            sigma_ai.describe("  ", "auth")
        with mock.patch.object(llm, "chat", side_effect=llm.ModelUnavailable("The local model did not answer.")):
            with self.assertRaisesRegex(ValueError, "did not answer"):
                sigma_ai.describe("root logins", "auth")


class Stamped(unittest.TestCase):
    """Who added a rule and when, whether it was tested first, and the routes."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(whitelist, "usual", return_value=None), mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                        mock.patch.object(store, "ADMIN_FILE", folder / "admin.json"),
                        mock.patch.object(cluster_index, "CACHE", folder), mock.patch.object(cluster_index, "INDEX_FILE", folder / "index.sqlite"),
                        mock.patch.object(store.time, "sleep"), mock.patch.object(cluster_index, "refresh"),
                        mock.patch.object(sigma_form, "event_types", return_value=TYPES), mock.patch.object(sigma, "_tested", set())]
        for p in self.patches:
            p.start()
        whitelist._cover_cached.cache_clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        whitelist._cover_cached.cache_clear()
        gc.collect()
        self.folder.cleanup()

    def audit(self, action: str) -> dict:
        return json.loads(next(e for e in store.audit_log() if e["action"] == action)["detail"])

    def test_who_added_it_and_when(self):
        entry = sigma.add(sigma_form.to_yaml(form(), "Analyst A"), "Analyst A")
        self.assertEqual(entry["added_by"], "Analyst A")
        self.assertRegex(entry["added_at"], r"^\d{4}-\d{2}-\d{2}T")
        listed = next(e for e in sigma.entries()["entries"] if e["id"] == entry["id"])
        self.assertEqual((listed["added_by"], listed["added_at"]), (entry["added_by"], entry["added_at"]))
        self.assertEqual(listed["form"]["title"], "Root login failed")
        starter = sigma.entries()["entries"][0]
        self.assertEqual(starter["added_by"], "starter rules")

    def test_the_activity_log_says_whether_it_was_tested_first(self):
        text = sigma_form.to_yaml(form(), "tester")
        sigma.add(text, "tester")
        self.assertFalse(self.audit("sigma_add")["tested"])
        line = AUTH.format(t="12:04:30", pid=1, msg="Failed password for root from 192.0.2.17 port 5000 ssh2")
        result = sigma.run(text=line, month="2026-07", draft=text)
        self.assertEqual([h["title"] for h in result["hits"]], ["Root login failed"])
        entry = sigma.add(text, "tester")
        self.assertTrue(self.audit("sigma_add")["tested"])
        sigma.update(entry["id"], "tester", text=text.replace("level: high", "level: low"))
        self.assertFalse(self.audit("sigma_update")["tested"])      # changed after the test

    def test_routes(self):
        from service import server
        route = lambda method, path, body=None: server.ROUTES[(method, path)]({}, body)   # noqa: E731
        with mock.patch.object(server, "_actor", return_value="Analyst A"):
            preview = route("POST", "/api/sigma/form", {"form": form()})
        self.assertEqual((preview["missing"], preview["docs"][0]["title"]), ([], "Root login failed"))
        self.assertIn("author: Analyst A", preview["yaml"])
        with self.assertRaises(ValueError):
            route("POST", "/api/sigma/form", {"form": "title: x"})
        self.assertEqual(route("POST", "/api/sigma/check", {"yaml": preview["yaml"]})["form"]["title"], "Root login failed")
        listed = route("GET", "/api/sigma/rules")
        self.assertEqual(listed["event_types"], TYPES)
        with mock.patch.object(llm, "chat", return_value=json.dumps(Describe.GOOD)), \
                mock.patch.object(sigma_ai, "load_settings", return_value={"llm_model": "stand-in"}):
            drafted = route("POST", "/api/sigma/describe", {"text": "root logins over SSH", "source": "auth"})
        self.assertEqual(drafted["docs"][0]["title"], "Root login failed")
        self.assertEqual(self.audit("sigma_ai_draft"), {"description_chars": 20, "model": "stand-in", "reads": True, "tries": 1})
        self.assertEqual(len(sigma.entries()["entries"]), 8)          # a draft is never saved by itself


if __name__ == "__main__":
    unittest.main()
