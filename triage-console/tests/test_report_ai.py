"""The report editor's helpers: the offline ATT&CK copy, the shortlist, and what is kept of the local model's answers."""
import json
import unittest
from unittest import mock

from service import llm, report_ai


class AttackData(unittest.TestCase):
    def test_offline_copy_has_techniques_tactics_and_notice(self):
        data = report_ai.attack()
        ids = {t["id"] for t in data["techniques"]}
        self.assertGreater(len(ids), 500)
        self.assertIn("T1110.001", ids)
        self.assertTrue(data["tactics"] and data["version"])
        self.assertIn("MITRE", data["notice"])
        sub = next(t for t in data["techniques"] if t["id"] == "T1110.001")
        self.assertEqual(sub["name"], "Brute Force: Password Guessing")
        self.assertIn("credential-access", sub["tactics"])
        self.assertNotIn("(Citation", sub["description"])


class Shortlist(unittest.TestCase):
    def test_log_words_reach_the_right_techniques(self):
        cases = {
            "sshd: Failed password for invalid user admin from 10.0.0.9 port 4022 ssh2": "T1110",
            "sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash": "T1548",
            "crontab: (root) REPLACE (root) new cron job": "T1053",
        }
        for line, family in cases.items():
            top = [c["id"] for c in report_ai.candidates(line, 5)]
            self.assertTrue(any(t.startswith(family) for t in top), (line, top))

    def test_empty_evidence_is_refused(self):
        with self.assertRaises(ValueError):
            report_ai.match_attack("   ")


class ModelAnswers(unittest.TestCase):
    def test_only_candidates_are_kept(self):
        shortlist = [{"id": "T1110.001"}, {"id": "T1078"}]
        answer = json.dumps({"matches": [{"id": "t1110.001", "confidence": "High", "reason": "failed passwords"},
                                         {"id": "T9999", "confidence": "high", "reason": "invented"},
                                         {"id": "T1078", "confidence": "sure", "reason": "valid login after"},
                                         {"id": "T1110.001", "confidence": "low", "reason": "repeat"}]})
        out = report_ai.parse_matches(answer, shortlist)
        self.assertEqual([m["id"] for m in out], ["T1110.001", "T1078"])
        self.assertEqual(out[0]["confidence"], "high")
        self.assertEqual(out[1]["confidence"], "low")          # an unknown confidence reads as low
        self.assertEqual(report_ai.parse_matches("not json", shortlist), [])

    def test_match_attack_uses_the_model_and_keeps_its_choice(self):
        def fake(system, user, **_):
            self.assertIn("Candidate techniques", user)
            return json.dumps({"matches": [{"id": "T1110.001", "confidence": "medium", "reason": "many failed passwords"}]})
        with mock.patch.object(llm, "chat", side_effect=fake):
            out = report_ai.match_attack("sshd: Failed password for invalid user admin")
        self.assertEqual(out["matches"][0]["id"], "T1110.001")
        self.assertIn("T1110.001", out["candidates"])

    def test_a_query_that_writes_is_flagged_not_run(self):
        out = report_ai.checked_sql(json.dumps({"sql": "DELETE FROM auth.events", "note": "x"}))
        self.assertTrue(out["rejected"])
        ok = report_ai.checked_sql('{"sql": "```sql\\nSELECT host_id FROM auth.events LIMIT 5\\n```"}')
        self.assertEqual(ok["sql"], "SELECT host_id FROM auth.events LIMIT 5")
        self.assertEqual(ok["rejected"], "")
        with self.assertRaises(ValueError):
            report_ai.checked_sql('{"sql": ""}')

    def test_model_offline_is_a_clear_error(self):
        settings = {"llm_endpoint": "http://127.0.0.1:9", "llm_model": "qwen2.5:3b-instruct"}
        with mock.patch.object(llm, "load_settings", return_value=settings):
            with self.assertRaises(llm.ModelUnavailable) as caught:
                llm.chat("s", "u", timeout=2)
        self.assertIn("Start Ollama", str(caught.exception))
        self.assertIsInstance(caught.exception, ValueError)        # the server answers 400 with the message


if __name__ == "__main__":
    unittest.main()
