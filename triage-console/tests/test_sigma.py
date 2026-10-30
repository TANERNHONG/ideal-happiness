"""Tests for Sigma rules (service/sigma.py): parsing, field tests, conditions, sliding windows, the store, a run.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest tests.test_sigma -v
"""
from __future__ import annotations

import gc
import gzip
import sys
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import cluster_index, sigma, store, whitelist  # noqa: E402

T0 = datetime(2026, 7, 14, 12, 4, 30)


def event(seconds: float = 0, source: str = "auth", line: str = "", **fields) -> sigma.Event:
    fields.setdefault("host", "host-a")
    return sigma.Event(0, line or " ".join(f"{k}={v}" for k, v in fields.items()), fields, T0 + timedelta(seconds=seconds), source)


def run(text: str, events: list[sigma.Event]) -> dict:
    for n, e in enumerate(events, start=1):
        e.n = n
    return sigma.evaluate(sigma.parse(text, 1), events)


def titles(result: dict) -> list[str]:
    return [h.doc.title for h in result["hits"]]


FAILED = """
title: failed
name: failed
logsource: {service: sshd}
detection:
  selection: {event_type: SSH_LOGIN_FAILED}
  condition: selection
"""


class FieldTests(unittest.TestCase):
    def matches(self, detection: str, **fields) -> bool:
        doc = sigma.parse(f"title: t\ndetection:\n{detection}", 1)[0]
        e = event(**fields)
        return doc.condition.evaluate(lambda name: doc.selections[name](e))

    def test_modifiers(self):
        self.assertTrue(self.matches("  s: {raw_message|contains: password}\n  condition: s", raw_message="Failed Password for x"))
        self.assertTrue(self.matches("  s: {username|startswith: adm}\n  condition: s", username="admin1"))
        self.assertFalse(self.matches("  s: {username|endswith: adm}\n  condition: s", username="admin1"))
        self.assertTrue(self.matches("  s: {raw_message|contains|all: [failed, root]}\n  condition: s", raw_message="failed for root"))
        self.assertFalse(self.matches("  s: {raw_message|contains|all: [failed, oracle]}\n  condition: s", raw_message="failed for root"))
        self.assertTrue(self.matches("  s: {source_ip|cidr: 192.0.2.0/24}\n  condition: s", source_ip="192.0.2.17"))
        self.assertFalse(self.matches("  s: {source_ip|cidr: 10.0.0.0/8}\n  condition: s", source_ip="192.0.2.17"))
        self.assertTrue(self.matches("  s: {destination_port|gte: 1024}\n  condition: s", destination_port="8080"))
        self.assertTrue(self.matches("  s: {username|re: '^ora.*\\d$'}\n  condition: s", username="oracle1"))
        self.assertTrue(self.matches("  s: {username|exists: true}\n  condition: s", username="x"))
        self.assertTrue(self.matches("  s: {username|exists: false}\n  condition: s"))

    def test_plain_values_are_whole_case_insensitive_with_wildcards(self):
        self.assertTrue(self.matches("  s: {username: ROOT}\n  condition: s", username="root"))
        self.assertFalse(self.matches("  s: {username: roo}\n  condition: s", username="root"))
        self.assertTrue(self.matches("  s: {username: 'r?o*'}\n  condition: s", username="rooted"))
        self.assertTrue(self.matches("  s: {username: [oracle, root]}\n  condition: s", username="root"))

    def test_aliases_keywords_and_the_line(self):
        self.assertTrue(self.matches("  s: {user: root, src_ip: 192.0.2.17}\n  condition: s", username="root", source_ip="192.0.2.17"))
        self.assertTrue(self.matches("  s: [Accepted, Failed]\n  condition: s", line="Jul 14 sshd: Failed password"))
        self.assertTrue(self.matches("  s: {line|contains: sshd}\n  condition: s", line="Jul 14 sshd: x"))

    def test_conditions(self):
        detection = ("  sel_a: {username: root}\n  sel_b: {source_ip: 192.0.2.17}\n  filter: {host: host-b}\n")
        self.assertTrue(self.matches(detection + "  condition: sel_a and not filter", username="root"))
        self.assertTrue(self.matches(detection + "  condition: 1 of sel_*", source_ip="192.0.2.17"))
        self.assertFalse(self.matches(detection + "  condition: all of sel_*", source_ip="192.0.2.17"))
        self.assertTrue(self.matches(detection + "  condition: (sel_a or sel_b) and not filter", source_ip="192.0.2.17"))

    def test_errors_say_what_to_change(self):
        for text, words in [("title: t\ndetection:\n  s: {a|base64: x}\n  condition: s", "base64"),
                            ("title: t\ndetection:\n  s: {a: x}\n  condition: s and other", "other"),
                            ("title: t\ndetection:\n  s: {a: x}\n  condition: (s", "bracket"),
                            ("title: t\ncorrelation: {type: event_count, rules: [x], timespan: 5m, condition: {lt: 3}}", "fewer"),
                            ("title: t\ncorrelation: {type: event_count, rules: [x], timespan: 5 minutes, condition: {gte: 3}}", "time span"),
                            ("detection: {condition: s}", "title"),
                            ("title: [unclosed", "YAML")]:
            with self.subTest(words), self.assertRaisesRegex(ValueError, words):
                sigma.parse(text, 1)


class Windows(unittest.TestCase):
    def test_event_count_across_a_five_minute_boundary_is_one_hit(self):
        text = FAILED + """---
title: guessing
correlation: {type: event_count, rules: [failed], group-by: [source_ip, host], timespan: 2m, condition: {gte: 8}}
"""
        burst = [event(i * 8, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.17", process_name="sshd") for i in range(10)]
        result = run(text, burst)
        self.assertEqual(titles(result), ["guessing"])
        hit = result["hits"][0]
        self.assertEqual((hit.count, len(hit.events), hit.group), (10, 10, {"source_ip": "192.0.2.17", "host": "host-a"}))
        self.assertEqual(titles(run(text, burst[:7])), [])
        slow = [event(i * 60, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.17", process_name="sshd") for i in range(10)]
        self.assertEqual(titles(run(text, slow)), [])                          # never 8 within 2 minutes
        two_sources = burst[:5] + [event(i, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.18", process_name="sshd") for i in range(5)]
        self.assertEqual(titles(run(text, two_sources)), [])                   # grouped by source

    def test_value_count_over_a_day(self):
        text = FAILED + """---
title: spraying
correlation: {type: value_count, rules: [failed], group-by: [source_ip], timespan: 24h, condition: {gte: 10, field: username}}
"""
        spread = [event(i * 7200, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.17", username=f"user{i}", process_name="sshd") for i in range(10)]
        self.assertEqual(titles(run(text, spread)), ["spraying"])
        same = [event(i * 7200, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.17", username="user1", process_name="sshd") for i in range(10)]
        self.assertEqual(titles(run(text, same)), [])

    def test_temporal_ordered_chains_a_correlation_then_a_rule(self):
        text = FAILED + """---
title: guessing
name: guessing
correlation: {type: event_count, rules: [failed], group-by: [source_ip, host], timespan: 2m, condition: {gte: 3}}
---
title: success
name: success
logsource: {service: sshd}
detection: {s: {event_type: SSH_LOGIN_SUCCESS}, condition: s}
---
title: in after guessing
correlation: {type: temporal_ordered, rules: [guessing, success], group-by: [source_ip, host], timespan: 10m}
"""
        fails = [event(i * 5, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.17", process_name="sshd") for i in range(3)]
        ok = event(60, event_type="SSH_LOGIN_SUCCESS", source_ip="192.0.2.17", process_name="sshd")
        self.assertEqual(sorted(titles(run(text, fails + [ok]))), ["guessing", "in after guessing"])
        early = event(-60, event_type="SSH_LOGIN_SUCCESS", source_ip="192.0.2.17", process_name="sshd")
        self.assertEqual(titles(run(text, [early] + fails)), ["guessing"])     # success before the guessing
        late = event(3600, event_type="SSH_LOGIN_SUCCESS", source_ip="192.0.2.17", process_name="sshd")
        self.assertEqual(titles(run(text, fails + [late])), ["guessing"])      # outside 10 minutes

    def test_older_aggregation_syntax(self):
        text = """
title: burst
logsource: {service: sshd}
detection:
  selection: {event_type: SSH_LOGIN_FAILED}
  timeframe: 1m
  condition: selection | count() by source_ip > 3
"""
        burst = [event(i, event_type="SSH_LOGIN_FAILED", source_ip="192.0.2.17", process_name="sshd") for i in range(4)]
        self.assertEqual(titles(run(text, burst)), ["burst"])
        self.assertEqual(titles(run(text, burst[:3])), [])

    def test_referenced_rules_report_nothing_unless_generate(self):
        text = FAILED + """---
title: guessing
correlation: {type: event_count, rules: [failed], timespan: 2m, condition: {gte: 99}, generate: GEN}
"""
        fails = [event(i, event_type="SSH_LOGIN_FAILED", process_name="sshd") for i in range(3)]
        self.assertEqual(titles(run(text.replace("GEN", "false"), fails)), [])
        self.assertEqual(titles(run(text.replace("GEN", "true"), fails)), ["failed"])

    def test_logsource_picks_the_log_and_the_daemon(self):
        windows = "title: w\nlogsource: {product: windows}\ndetection: {s: {event_type: SSH_LOGIN_FAILED}, condition: s}"
        self.assertEqual(titles(run(windows, [event(event_type="SSH_LOGIN_FAILED")])), [])
        su = "title: su\nlogsource: {service: su}\ndetection: {s: {event_type: '*'}, condition: s}"
        lines = [event(event_type="SU_SESSION_FAILED", process_name="su"), event(event_type="SSH_LOGIN_FAILED", process_name="sshd")]
        hits = run(su, lines)["hits"]
        self.assertEqual([len(h.events) for h in hits], [1])
        firewall = "title: fw\nlogsource: {category: firewall}\ndetection: {s: {event_type|startswith: PF_}, condition: s}"
        self.assertEqual(titles(run(firewall, [event(source="pf", event_type="PF_BLOCK_TCP")])), ["fw"])

    def test_missing_reference_is_reported(self):
        result = run("title: c\ncorrelation: {type: event_count, rules: [nowhere], timespan: 5m, condition: {gte: 1}}", [])
        self.assertIn("nowhere", next(iter(result["errors"].values())))


AUTH = "Jul 14 {t} host-a sshd[{pid}]: [ID 800047 auth.info] {msg}"


class Stored(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(whitelist, "usual", return_value=None), mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                        mock.patch.object(store, "ADMIN_FILE", folder / "admin.json"),
                        mock.patch.object(cluster_index, "CACHE", folder), mock.patch.object(cluster_index, "INDEX_FILE", folder / "index.sqlite"),
                        mock.patch.object(store.time, "sleep"),
                        mock.patch.object(cluster_index, "refresh")]          # a rule change starts Review's pass over data/
        for p in self.patches:
            p.start()
        store.change_password(store.DEFAULT_PASSWORD, "made-up-admin", "tester")    # the default opens nothing
        whitelist._cover_cached.cache_clear()

    def test_a_rule_change_brings_review_up_to_date(self):
        entry = sigma.add(FAILED, "tester")
        sigma.update(entry["id"], "tester", enabled=False)
        sigma.delete(entry["id"], "tester")
        self.assertEqual(cluster_index.refresh.call_count, 3)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        whitelist._cover_cached.cache_clear()
        gc.collect()
        self.folder.cleanup()

    def test_starter_rules_are_seeded_once_and_all_read(self):
        first = sigma.entries()["entries"]
        self.assertEqual(len(first), len(list(sigma.STARTER.glob("*.yml"))))
        self.assertEqual([e for e in first if e["error"] or e["missing"]], [])
        sigma.delete(first[0]["id"], "tester")
        self.assertEqual(len(sigma.entries()["entries"]), len(first) - 1)       # not seeded again

    def test_add_update_delete_are_audited(self):
        entry = sigma.add(FAILED, "tester")
        self.assertEqual(entry["docs"][0]["title"], "failed")
        with self.assertRaises(ValueError):
            sigma.update(entry["id"], "tester", text="title: [broken")
        sigma.update(entry["id"], "tester", enabled=False)
        sigma.delete(entry["id"], "tester")
        actions = [a["action"] for a in store.audit_log()]
        self.assertEqual(actions[:3], ["sigma_delete", "sigma_update", "sigma_add"])

    def test_a_run_over_solaris_lines(self):
        lines = [AUTH.format(t=f"12:04:{30 + i * 3:02d}", pid=100 + i, msg="Failed password for root from 192.0.2.17 port 5000 ssh2")
                 for i in range(9)]
        lines.append(AUTH.format(t="12:06:10", pid=200, msg="Accepted password for root from 192.0.2.17 port 5001 ssh2"))
        result = sigma.run(text="\n".join(lines), month="2026-07")
        self.assertEqual(result["source"], "auth")
        found = {h["title"]: h for h in result["hits"]}
        self.assertEqual(set(found), {"SSH password guessing from one source", "SSH login after password guessing"})
        self.assertEqual(found["SSH password guessing from one source"]["events"], 9)
        self.assertEqual(found["SSH login after password guessing"]["techniques"], ["T1110.001", "T1078.003"])
        self.assertEqual(result["hits"][0]["level"], "high")                       # most serious first
        self.assertFalse(any(h["whitelisted"] for h in result["hits"]))
        whitelist.add("root", "host-a", "test", "", "made-up-admin", "tester")
        again = sigma.run(text="\n".join(lines), month="2026-07")
        self.assertTrue(all(h["whitelisted"] for h in again["hits"]))

    def test_a_folder_checks_its_lowest_files_one_log_type_and_month_together(self):
        failed = lambda host, users: "\n".join(                                                  # noqa: E731
            AUTH.replace("host-a", host).format(t=f"12:0{i // 10}:{i % 10 * 5:02d}", pid=100 + i, msg=f"Failed password for {u} from 192.0.2.17 port 5000 ssh2")
            for i, u in enumerate(users)) + "\n"
        root = Path(self.folder.name) / "logs"
        for folder in ("2025-07/host-a", "2025-07/host-b", "2025-07/host-c", "Aug 25/notes"):
            (root / folder).mkdir(parents=True)
        (root / "readme.txt").write_text("not a log", encoding="utf-8")                          # beside a folder
        (root / "2025-07" / "notes.txt").write_text("not a log", encoding="utf-8")               # beside folders
        (root / "2025-07" / "host-a" / "auth.log").write_text(failed("host-a", [f"u{i}" for i in range(5)]), encoding="utf-8")
        with gzip.open(root / "2025-07" / "host-b" / "auth.log.gz", "wt", encoding="utf-8") as handle:
            handle.write(failed("host-b", [f"u{i}" for i in range(5, 10)]))
        with zipfile.ZipFile(root / "2025-07" / "host-c" / "logs.zip", "w") as archive:
            archive.writestr("auth.log", failed("host-c", ["u10"]))
        (root / "Aug 25" / "notes" / "hello.txt").write_text("hello\nworld\n", encoding="utf-8")
        result = sigma.run(path=str(root), month="2026-10")
        self.assertEqual(result["folder"]["groups"], [{"source": "auth", "month": "2025-07", "files": 3, "lines": 11, "recognised": 11}])
        spraying = next(h for h in result["hits"] if h["title"] == "SSH password spraying from one source")    # 11 users, 3 servers
        self.assertEqual(spraying["events"], 11)
        self.assertEqual({line["file"] for line in spraying["lines"]},
                         {"2025-07/host-a/auth.log", "2025-07/host-b/auth.log.gz", "2025-07/host-c/logs.zip/auth.log"})
        self.assertTrue(spraying["first"].startswith("2025-07-14"))                               # the month of its folder
        self.assertEqual({x["path"]: x["reason"].split(":")[0] for x in result["folder"]["left"]},
                         {"readme.txt": "beside a folder", "2025-07/notes.txt": "beside a folder",
                          "Aug 25/notes/hello.txt": "no log type recognises its lines"})
        alone = sigma.run(path=str(root / "2025-07" / "host-a" / "auth.log"), month="2025-07")      # one file: 5 users
        self.assertNotIn("SSH password spraying from one source", {h["title"] for h in alone["hits"]})
        self.assertNotIn("folder", alone)
        with self.assertRaises(ValueError):
            sigma.run(path=str(root), source="pf")                                                # no PF file: nothing to read
        empty = Path(self.folder.name) / "empty"
        empty.mkdir()
        with self.assertRaises(ValueError):
            sigma.run(path=str(empty))

    def test_the_month_of_a_folder(self):
        root = Path(self.folder.name)
        for folder, month in (("2026-08", "2026-08"), ("2026-08_auth/x", "2026-08"), ("Sept-25", "2025-09"),
                              ("logs/September 2025/host", "2025-09"), ("misc", None)):
            (root / folder).mkdir(parents=True, exist_ok=True)
            self.assertEqual(sigma.path_month(root / folder / "f.log", root), month, folder)

    def test_routes(self):
        from service import jobs, server
        route = lambda method, path, body=None: server.ROUTES[(method, path)]({}, body)   # noqa: E731
        listed = route("GET", "/api/sigma/rules")
        self.assertIn("auth", listed["fields"])
        self.assertEqual(route("POST", "/api/sigma/check", {"yaml": FAILED})["docs"][0]["kind"], "event")
        with self.assertRaises(ValueError):
            route("POST", "/api/sigma/check", {"yaml": "title: t\ndetection: {s: {a|nope: 1}, condition: s}"})
        added = route("POST", "/api/sigma/rules", {"yaml": FAILED})
        self.assertFalse(route("POST", "/api/sigma/rules/update", {"id": added["id"], "enabled": False})["enabled"])
        self.assertIn("title: failed", route("GET", "/api/sigma/export")["yaml"])
        job = route("POST", "/api/sigma/run", {"text": AUTH.format(t="12:04:30", pid=1, msg="Failed password for root from 192.0.2.17 port 5000 ssh2"),
                                               "month": "2026-07"})["job"]
        pause = threading.Event()                          # time.sleep is patched out (store.time) in these tests
        for _ in range(400):
            state = jobs.get(job)
            if state["status"] != "running":
                break
            pause.wait(0.05)
        self.assertEqual(state["status"], "done", state.get("error"))
        self.assertEqual(state["result"]["lines"], 1)
        route("POST", "/api/sigma/rules/delete", {"id": added["id"]})

    def test_a_draft_replaces_its_saved_entry_and_reports_alone(self):
        entry = sigma.add(FAILED.replace("title: failed", "title: saved"), "tester")
        line = AUTH.format(t="12:04:30", pid=1, msg="Failed password for root from 192.0.2.17 port 5000 ssh2")
        result = sigma.run(text=line, month="2026-07", draft=FAILED.replace("title: failed", "title: draft"), entry=entry["id"])
        self.assertTrue(result["draft"])
        self.assertEqual([h["title"] for h in result["hits"]], ["draft"])
        self.assertEqual([r["title"] for r in result["rules"]], ["draft"])


if __name__ == "__main__":
    unittest.main()
