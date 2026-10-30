"""Tests for Patterns (service/patterns.py): shapes of unknown lines, regex suggestions, refused patterns,
the pass loop (prefix, then rule, then coverage), drift over time, the Simple-mode detector, and reading
folders and archives.

    cd triage-console
    ..\\.venv\\Scripts\\python.exe -m unittest discover tests -v
"""
from __future__ import annotations

import gc
import gzip
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service import patterns, store  # noqa: E402


def radius(days=range(1, 9), late_from=7) -> list[str]:
    """A made-up log type: a head, then two kinds of message; a third kind appears only from day `late_from`."""
    lines = []
    for d in days:
        for k in range(30):
            head = f"2026-07-{d:02d}T10:{k:02d}:00+08:00 nas-{k % 3} radiusd[{100 + k}]: "
            lines.append(head + f"Login OK: [user{k}] (from client sw{k % 4} port {k} cli 10.20.{k}.7)")
            lines.append(head + f"Login incorrect: [user{k}] (from client sw{k % 4} port {k})")
            if d >= late_from:
                lines.append(head + f"Rejected ignored request from 10.20.{k}.9 port {k} - ID {k}")
    return lines


AUTH = [
    "Jul 14 16:20:37 host-a sshd[27857]: [ID 800047 auth.info] Failed password for invalid user staff08 from 192.0.2.17 port 50123 ssh2",
    "Jul 14 16:20:44 host-a sshd[27857]: [ID 800047 auth.info] Connection closed by 192.0.2.17 port 50123 [preauth]",
    "Jul 14 16:21:00 host-a sshd[27858]: [ID 800047 auth.info] Totally new message 42 from the daemon",
    "Jul 14 16:22:00 host-a sshd[27859]: [ID 800047 auth.info] Totally new message 43 from the daemon",
]


class Store(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        folder = Path(self.folder.name)
        self.patches = [mock.patch.object(store, "STORE_FILE", folder / "console.sqlite"), mock.patch.object(store, "VAR", folder),
                        mock.patch.dict(patterns._workspaces, clear=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        gc.collect()
        self.folder.cleanup()


class Shapes(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(patterns.mask("Jul 14 16:20:37 host-a sshd[27857]: Failed for bob from 192.0.2.17 port 50123 ssh2"),
                         "<time> host-a sshd[<n>]: Failed for bob from <ip> port <n> ssh2")
        self.assertEqual(patterns.mask("2026/07/01 10:00:00 x: 0xdeadbeef /var/log/a.log"), "<time> x: <hex> <path>")

    def test_merge_turns_differing_words_into_wildcards(self):
        table = {}
        for i, user in enumerate(["alice", "bob", "carol", "alice"]):
            patterns._count(table, patterns.mask(f"Login OK for {user} on tty <n> now"), f"line {i}", i)
        patterns._count(table, "Something else entirely here", "other", 9)
        shapes, left = patterns.merge(table)
        self.assertEqual(left, 0)
        self.assertEqual(shapes[0]["count"], 4)
        self.assertEqual(" ".join(shapes[0]["tokens"]), "Login OK for <*> on tty <n> now")
        self.assertTrue(patterns.fits(shapes[0]["tokens"], "Login OK for dave on tty <n> now".split()))


class Refused(unittest.TestCase):
    def test_nested_repeats_and_bad_syntax(self):
        for bad in (r"(a+)+b", r"(?:\S+\s+)*end", r"(x|y*){2,}", "(unclosed", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                patterns.check(bad)
        for good in (r"\d{1,3}(?:\.\d{1,3}){3}", r"Login\s+OK:(?:\s+(?P<rest>.*))?", r"(?:ab)+c"):
            with self.subTest(good=good):
                patterns.check(good)

    def test_try_reports_instead_of_raising(self):
        result = patterns.test("rule", r"(a+)+b", ["aaa"])
        self.assertFalse(result["ok"])
        self.assertIn("repeat", result["error"])


class Suggest(unittest.TestCase):
    def test_prefix_names_the_fields(self):
        heads = [line[:line.index(": ") + 2] for line in radius(days=[1])[:6:2]]
        found = patterns.suggest("prefix", heads)
        exact = found["candidates"][0]
        self.assertEqual(exact["label"], "Exact")
        self.assertEqual(exact["covers"], 3)
        self.assertEqual(set(re.compile(exact["regex"]).groupindex), {"timestamp", "hostname", "pid"})
        self.assertIn("radiusd", exact["regex"])                      # the same in every example: kept as it is

    def test_rule_candidates_and_event_name(self):
        messages = ["Login OK: [user1] (from client sw1 port 1 cli 10.0.0.1)", "Login OK: [user2] (from client sw2 port 2 cli 10.0.0.2)"]
        found = patterns.suggest("rule", messages, "radius")
        self.assertEqual(found["event_type"], "RADIUS_LOGIN_OK")
        labels = [c["label"] for c in found["candidates"]]
        self.assertEqual(labels[0], "Exact")
        self.assertIn("Start", labels)
        for c in found["candidates"]:
            self.assertEqual(c["covers"], 2, c)
            self.assertTrue(re.fullmatch(c["regex"], "Login OK: [user9] (from client sw9 port 9 cli 10.0.0.9)", re.I), c)

    def test_messages_of_different_lengths_use_anchors(self):
        found = patterns.suggest("rule", ["session opened for alice", "session opened for bob by root (uid=0)"])
        anchors = next(c for c in found["candidates"] if c["label"] == "Anchors")
        self.assertEqual(anchors["covers"], 2)

    def test_suffix_without_its_space(self):
        found = patterns.suggest("suffix", ["[preauth]", " [preauth]"])
        self.assertTrue(found["candidates"][0]["regex"].startswith(r"\s+"))
        self.assertEqual(found["candidates"][0]["covers"], 2)


class Passes(Store):
    def test_loop_from_unknown_to_known(self):
        lines = radius()
        first = patterns.scan(text="\n".join(lines), actor="me")
        self.assertEqual(first["family"], "")                          # no log type knows these
        self.assertEqual(first["coverage"], 0)
        self.assertEqual(first["counts"]["unknown"], len(lines))
        self.assertEqual(first["heads"][0]["count"], len(lines))      # one head shape: the prefix to write
        ws = first["workspace"]

        family = patterns.create_family("radius", "me")
        patterns.set_family(ws, family)
        prefix = patterns.suggest("prefix", first["heads"][0]["examples"], family, ws)["candidates"][0]
        self.assertEqual(prefix["lines"], len(lines))                  # estimated from the kept lines
        patterns.save_rule(family, "prefix", prefix["regex"], "", first["heads"][0]["examples"], "me")

        by_shape = patterns.lines_view(ws, shape="s0")                 # a shape from before the prefix: its lines, cut now
        self.assertTrue(by_shape["lines"])
        self.assertTrue(all(r["line"][r["cut"][0]:].startswith("Login") for r in by_shape["lines"]))

        view = patterns.lines_view(ws, search="Login OK")
        cut = view["lines"][0]["cut"]
        messages = [r["line"][r["cut"][0]:r["cut"][1]].strip() for r in view["lines"][:5]]
        self.assertTrue(all(m.startswith("Login OK:") for m in messages), messages)
        self.assertGreater(cut[0], 0)
        found = patterns.suggest("rule", messages, family, ws)
        saved = patterns.save_rule(family, "rule", found["candidates"][0]["regex"], found["event_type"], messages, "me")

        view = patterns.lines_view(ws)
        self.assertFalse(any("Login OK" in r["line"] for r in view["lines"]))     # known now: out of the unknown list
        self.assertIn("s0", view["covered"])                                       # the largest shape is covered
        self.assertAlmostEqual(view["estimate"], 240 / len(lines), delta=0.08)

        second = patterns.rescan(ws, actor="me")
        self.assertEqual(second["pass"], 2)
        self.assertEqual(second["counts"]["custom"], 240)
        self.assertEqual(second["counts"]["sliced"], len(lines) - 240)
        self.assertEqual(second["hits"][str(saved["id"])]["hits"], 240)
        self.assertEqual([round(h["coverage"], 3) for h in second["history"]], [0, round(240 / len(lines), 3)])

        kept = patterns.rules(family)["rules"]
        self.assertTrue(all("10.20." not in e for r in kept for e in r["examples"]))     # addresses replaced
        self.assertIn('("RADIUS_LOGIN_OK", r"', patterns.export(family)["phase1"])

    def test_drift_new_shapes_and_quiet_rules(self):
        lines = radius(days=range(1, 9), late_from=7)
        family = patterns.create_family("radius", "me")
        head = lines[0][:lines[0].index(": ") + 2]
        prefix = patterns.suggest("prefix", [head, lines[1][:lines[1].index(": ") + 2]])["candidates"][0]["regex"]
        patterns.save_rule(family, "prefix", prefix, "", [head], "me")
        old = patterns.save_rule(family, "rule", r"Login incorrect:.*", "RADIUS_LOGIN_BAD", [], "me")
        early = [l.replace("Login incorrect", "Login refused") if "-07-07" in l or "-07-08" in l else l for l in lines]
        result = patterns.scan(text="\n".join(early), family=family, actor="me")
        self.assertEqual(result["time"]["mode"], "time")
        self.assertEqual([b["label"] for b in result["time"]["buckets"]][:2], ["2026-07-01", "2026-07-02"])
        late = {s["template"].split(":")[0].split(" from")[0]: s["new"] for s in result["shapes"]}
        self.assertTrue(late["Rejected ignored request"])                  # first seen on day 7 of 8
        self.assertFalse(late["Login OK"])
        self.assertTrue(result["hits"][str(old["id"])]["quiet"])           # stopped matching in the last days

    def test_builtin_type_counts_phase1_first(self):
        result = patterns.scan(text="\n".join(AUTH), family="auth", actor="me")
        self.assertEqual(result["counts"]["builtin"], 2)
        self.assertEqual(result["counts"]["sliced"], 2)                     # Phase 1's own head cuts them
        self.assertEqual(result["shapes"][0]["template"], "Totally new message <n> from the daemon")
        patterns.save_rule("auth", "rule", r"Totally new message (?P<number>\d+) from the daemon", "SSH_TOTALLY_NEW", [], "me")
        again = patterns.rescan(result["workspace"], actor="me")
        self.assertEqual(again["coverage"], 1.0)

    def test_rules_order_toggle_delete(self):
        family = patterns.create_family("radius", "me")
        a = patterns.save_rule(family, "rule", r"Login.*", "RADIUS_ANY", [], "me")["id"]
        b = patterns.save_rule(family, "rule", r"Login OK.*", "RADIUS_OK", [], "me")["id"]
        patterns.update_rule(b, "me", move="up")
        self.assertEqual([r["id"] for r in patterns.rules(family)["rules"]], [b, a])
        patterns.update_rule(b, "me", enabled=False)
        self.assertEqual(patterns.ruleset(family).rule_for("Login OK now"), a)
        patterns.delete_rule(a, "me")
        self.assertIsNone(patterns.ruleset(family).rule_for("Login OK now"))
        with self.assertRaises(ValueError):
            patterns.save_rule(family, "rule", r"x+", "lower case", [], "me")
        with self.assertRaises(ValueError):
            patterns.create_family("auth", "me")


class Unapproved(Store):
    def test_listed_and_deleted_with_their_rules_and_scans(self):
        family = patterns.create_family("radius", "me")
        patterns.save_rule(family, "rule", r".*Login OK:.*", "RADIUS_LOGIN_OK", [], "me")
        result = patterns.scan(text="\n".join(radius(days=[1])), family=family, actor="me")
        listed = patterns.unapproved()
        self.assertEqual([u["name"] for u in listed], ["radius"])
        self.assertEqual((listed[0]["rules"], listed[0]["passes"]), ({"rule": 1}, 1))
        self.assertAlmostEqual(listed[0]["last"]["coverage"], 0.5)
        self.assertEqual(patterns.delete_family("radius", "someone"), {"rules": 1, "scans": 1})
        self.assertEqual(patterns.unapproved(), [])
        self.assertEqual(patterns.rules("radius")["rules"], [])
        self.assertNotIn("radius", [f["name"] for f in patterns.families()])
        self.assertEqual(patterns.workspace(result["workspace"]).family, "")           # an open scan carries on without it
        self.assertEqual(store.audit_log(1)[0]["action"], "pattern_family_deleted")
        with self.assertRaises(ValueError):
            patterns.delete_family("auth", "someone")                                 # the pipeline's own: never
        with self.assertRaises(KeyError):
            patterns.delete_family("radius", "someone")


class Detector(Store):
    def test_negligible_and_known(self):
        unknown = patterns.detect(radius(days=[1]))
        self.assertTrue(unknown["negligible"])
        self.assertIsNone(unknown["source"])
        self.assertIsNone(unknown["family"])
        known = patterns.detect(AUTH)
        self.assertEqual(known["source"], "auth")
        self.assertFalse(known["negligible"])
        self.assertEqual(known["coverage"], 0.5)

    def test_rules_made_here_name_the_type(self):
        family = patterns.create_family("radius", "me")
        lines = radius(days=[1])
        patterns.save_rule(family, "rule", r".*radiusd\[\d+\]: Login .*", "RADIUS_LOGIN", [], "me")
        found = patterns.detect(lines)
        self.assertTrue(found["negligible"])                               # Phase 1 still knows none: Analyze cannot read them
        self.assertEqual(found["family"], "radius")
        self.assertEqual(found["family_coverage"], 1.0)


class Reading(Store):
    def test_folder_zip_and_gz(self):
        root = Path(self.folder.name) / "in"
        (root / "sub").mkdir(parents=True)
        (root / "a.log").write_text("one\n\ntwo\r\n", encoding="utf-8")
        with gzip.open(root / "sub" / "b.log.gz", "wt", encoding="utf-8") as handle:
            handle.write("three\n")
        with zipfile.ZipFile(root / "sub" / "c.zip", "w") as archive:
            archive.writestr("x/d.txt", "four\nfive")
            archive.writestr("x/bin.dat", b"\x00\x01binary")
        self.assertEqual(list(patterns.open_lines(root)), ["one", "two", "three", "four", "five"])
        result = patterns.scan(path=str(root), actor="me")
        self.assertEqual(result["lines"], 5)
        self.assertEqual(result["name"], "in")


if __name__ == "__main__":
    unittest.main()
