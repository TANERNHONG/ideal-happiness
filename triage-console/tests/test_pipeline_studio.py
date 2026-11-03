"""Pipeline Studio runs against fabricated inputs and isolated artifact folders, with no live console store."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import pipeline_studio as studio  # noqa: E402


def node(node_id, kind, **config):
    return {"id": node_id, "kind": kind, "label": node_id, "config": config}


def flow(*nodes):
    return {"version": 1, "id": "made-up-flow", "name": "Fabricated pipeline test", "nodes": list(nodes),
            "edges": [{"id": f"edge-{i}", "from": previous["id"], "to": current["id"]}
                      for i, (previous, current) in enumerate(zip(nodes, nodes[1:]))]}


def csv_text(columns, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(columns)
    writer.writerows(rows)
    return output.getvalue()


class PipelineStudio(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.folder.name)
        self.runs = self.root / "runs"
        self.patches = [mock.patch.object(studio, "RUNS", self.runs),
                        mock.patch.object(studio, "load_settings", return_value={"pipeline_storage": "retained"})]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.folder.cleanup()

    def run_flow(self, document, **options):
        result = studio.run(document, **options)
        self.assertTrue(result["valid"], result["issues"])
        return result

    @staticmethod
    def item(result, node_id):
        return next(item for item in result["results"] if item["nodeId"] == node_id)

    def table_flow(self):
        return flow(node("source", "csv", csv="host,event_type,lines\nsample-a,failed,3\nsample-b,accepted,1\nsample-c,failed,2"),
                    node("filter", "filter", field="event_type", operator="equals", value="failed"),
                    node("check", "check", min_rows="2", required_columns="host,event_type"),
                    node("output", "output", name="Failed rows"))

    def test_all_23_registered_operators_have_resolvable_catalog_references(self):
        expected = {"sql", "csv", "api", "database", "raw", "parse", "classify", "transform", "filter", "aggregate",
                    "preprocess", "observations", "features", "labels", "detect", "unsupervised", "supervised", "sigma",
                    "check", "evaluate", "evidence", "report", "output"}
        entries = studio.catalog()["executors"]
        self.assertEqual(set(entries), expected)
        for kind, entry in entries.items():
            with self.subTest(kind=kind):
                self.assertEqual(entry["id"], f"studio.{kind}")
                module, attribute = entry["handler"].rsplit(".", 1)
                self.assertEqual(module, "service.pipeline_studio")
                self.assertIs(getattr(studio, attribute), studio.REGISTRY[kind])
                self.assertTrue(callable(getattr(studio, attribute)))
        self.assertEqual({item["id"] for item in studio.catalog()["evaluation"]},
                         {"classification", "regression", "clustering", "anomaly"})

    def test_document_rejects_bad_imports_before_any_run_folder_is_created(self):
        original = self.table_flow()
        cases = [None, {**original, "version": 2}, {**original, "nodes": [node("same", "csv"), node("same", "output")]},
                 {**original, "edges": [{"id": "bad", "from": "source", "to": "missing"}]},
                 flow(node("source", "shell", command="anything")), flow(node("../outside", "csv", csv="x\n1")),
                 flow(node("source", "csv", csv=42)),
                 {**original, "edges": [original["edges"][0], original["edges"][0]]}]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    studio.run(value)
        self.assertFalse(self.runs.exists())

    def test_validation_rejects_cycles_missing_inputs_and_incompatible_contracts(self):
        circular = flow(node("a", "filter"), node("b", "filter"))
        circular["edges"].append({"id": "back", "from": "b", "to": "a"})
        for document, word in ((circular, "cycle"), (flow(node("a", "filter")), "input"),
                               (flow(node("source", "csv", csv="x\n1"), node("model", "detect")), "features")):
            with self.subTest(word=word):
                result = studio.run(document)
                self.assertFalse(result["valid"])
                self.assertIn(word, " ".join(item["message"] for item in result["issues"]).lower())
                self.assertEqual(result["results"], [])
        self.assertFalse(self.runs.exists())

    def test_generic_recipes_preserve_event_contract_between_phase_blocks(self):
        document = flow(node("source", "raw", text="made-up"), node("parse", "parse", method="manual"),
                        node("filter", "filter", field="event_type", operator="equals", value="UNCLASSIFIED"),
                        node("observations", "observations", source="auth", view="individual"))
        result = studio.validate(document)
        self.assertTrue(result["valid"], result["issues"])
        self.assertEqual(result["contracts"]["filter"], "events")

    def test_retained_run_executes_recipes_and_keeps_every_output(self):
        result = self.run_flow(self.table_flow(), storage="retained")
        self.assertEqual([item["rows"] for item in result["results"]], [3, 2, 2, 2])
        self.assertTrue(all(item["status"] == "passed" and item["retained"] for item in result["results"]))
        output = studio.output(result["id"], "output")
        self.assertEqual([row["host"] for row in output["rows"]], ["sample-a", "sample-c"])
        self.assertEqual(output["total"], 2)
        for node_id in ("source", "filter", "check", "output"):
            self.assertTrue((self.runs / result["id"] / f"{node_id}.jsonl").is_file())
            self.assertTrue((self.runs / result["id"] / f"{node_id}.meta.json").is_file())
        saved = studio.run_info(result["id"])
        self.assertEqual(self.item(saved, "filter")["sample"], self.item(result, "filter")["sample"])
        self.assertEqual(studio.history()["runs"][0]["id"], result["id"])

    def test_memory_run_keeps_only_inputs_and_terminal_outputs_after_completion(self):
        result = self.run_flow(self.table_flow(), storage="memory")
        self.assertEqual([item["retained"] for item in result["results"]], [True, False, False, True])
        self.assertEqual(len(self.item(result, "filter")["sample"]), 2)  # response preview exists while executing
        saved = studio.run_info(result["id"])
        for node_id in ("filter", "check"):
            item = self.item(saved, node_id)
            self.assertEqual(item["sample"], [])
            self.assertEqual(item["meta"], {})
            self.assertEqual(item["rows"], 2)
            self.assertFalse((self.runs / result["id"] / f"{node_id}.jsonl").exists())
            self.assertFalse((self.runs / result["id"] / f"{node_id}.meta.json").exists())
            with self.assertRaisesRegex(ValueError, "not retained"):
                studio.output(result["id"], node_id)
        self.assertEqual(studio.output(result["id"], "source")["total"], 3)
        self.assertEqual(studio.output(result["id"], "output")["total"], 2)
        self.assertEqual(len(saved["rows"]), 2)

    def test_failed_sanity_check_skips_downstream_without_output_artifacts(self):
        document = self.table_flow()
        document["nodes"][2]["config"]["min_rows"] = "3"
        result = studio.run(document, storage="retained")
        self.assertFalse(result["valid"])
        self.assertEqual([item["status"] for item in result["results"]], ["passed", "passed", "failed", "skipped"])
        self.assertIn("received 2", self.item(result, "check")["message"])
        self.assertEqual(result["rows"], [])
        self.assertFalse((self.runs / result["id"] / "output.jsonl").exists())

    def test_targeted_run_executes_ancestors_and_retains_requested_intermediate(self):
        result = self.run_flow(self.table_flow(), storage="memory", stop_at="filter")
        self.assertEqual(result["order"], ["source", "filter"])
        self.assertEqual(studio.output(result["id"], "filter")["total"], 2)
        self.assertEqual(len(result["rows"]), 2)
        self.assertFalse((self.runs / result["id"] / "output.jsonl").exists())

    def test_manual_classification_counts_duplicates_and_keeps_unknown_lines(self):
        document = flow(node("source", "raw", text="ready\nready\nunknown\nready", source="auth", month="2026-07"),
                        node("parse", "parse", method="manual", classifications=json.dumps({"ready": "READY"})),
                        node("output", "output", name="Counts"))
        result = self.run_flow(document)
        rows = studio.output(result["id"], "output")["rows"]
        self.assertEqual([(row["raw_message"], row["event_type"], row["count"]) for row in rows],
                         [("ready", "READY", 3), ("unknown", "UNCLASSIFIED", 1)])
        self.assertEqual(self.item(result, "parse")["meta"]["parser"], "manual")

    def test_regex_named_groups_extract_fields_without_dropping_unmatched_lines(self):
        lines = "sample-host-01 user=operator outcome=accepted\nnot recognized\nsample-host-02 user=guest outcome=failed"
        document = flow(node("source", "raw", text=lines),
                        node("parse", "parse", method="regex", regex=r"(?P<host>sample-host-\d+) user=(?P<username>\w+) outcome=(?P<outcome>\w+)", event_type="LOGIN"),
                        node("output", "output", name="Parsed events"))
        result = self.run_flow(document)
        rows = studio.output(result["id"], "output")["rows"]
        self.assertEqual(len(rows), 3)
        self.assertEqual((rows[0]["host"], rows[0]["username"], rows[0]["event_type"]), ("sample-host-01", "operator", "LOGIN"))
        self.assertEqual((rows[1]["raw_message"], rows[1]["event_type"]), ("not recognized", "UNCLASSIFIED"))
        self.assertEqual(rows[2]["outcome"], "failed")

    def test_sample_sql_runs_real_sqlite_aggregation_and_refuses_writes(self):
        result = self.run_flow(flow(node("source", "sql", query="SELECT event_type, COUNT(*) AS count FROM sample_events GROUP BY event_type ORDER BY event_type")))
        self.assertEqual({row["event_type"]: row["count"] for row in result["rows"]}, {"SSH_LOGIN_ACCEPTED": 7, "SSH_LOGIN_FAILED": 5})
        rejected = studio.run(flow(node("source", "sql", query="DELETE FROM sample_events")))
        self.assertFalse(rejected["valid"])
        self.assertEqual(rejected["results"][0]["status"], "failed")

    def test_local_database_source_is_read_only_and_uses_real_query_results(self):
        database = self.root / "source.sqlite3"
        with closing(sqlite3.connect(database)) as con, con:
            con.execute("CREATE TABLE readings (host TEXT, lines INTEGER)")
            con.executemany("INSERT INTO readings VALUES (?, ?)", [("sample-a", 1), ("sample-b", 5), ("sample-c", 8)])
        result = self.run_flow(flow(node("source", "database", database=str(database), query="SELECT host, lines FROM readings WHERE lines > 2 ORDER BY lines")))
        self.assertEqual(result["rows"], [{"host": "sample-b", "lines": 5}, {"host": "sample-c", "lines": 8}])
        for query in ("DELETE FROM readings", "SELECT * FROM readings; DROP TABLE readings"):
            with self.subTest(query=query):
                rejected = studio.run(flow(node("source", "database", database=str(database), query=query)))
                self.assertFalse(rejected["valid"])
        with closing(sqlite3.connect(database)) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM readings").fetchone()[0], 3)

    def test_api_source_resolves_records_path_with_no_real_network_request(self):
        with mock.patch.object(studio, "_request_json", return_value={"data": {"records": [{"host": "sample-a", "lines": 4}, {"host": "sample-b", "lines": 2}]}}) as request:
            result = self.run_flow(flow(node("source", "api", url="https://example.invalid/events", records_path="data.records", token_env="SAMPLE_API_TOKEN")))
        request.assert_called_once_with("https://example.invalid/events", token_env="SAMPLE_API_TOKEN")
        self.assertEqual(result["rows"], [{"host": "sample-a", "lines": 4}, {"host": "sample-b", "lines": 2}])

    def test_json_request_sends_environment_token_without_putting_it_in_url(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"rows":[{"value":3}]}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.dict("os.environ", {"SAMPLE_STUDIO_TEST_TOKEN": "made-up-token"}), mock.patch.object(studio, "build_opener", return_value=opener):
            result = studio._request_json("https://example.invalid/query", {"limit": 2}, "SAMPLE_STUDIO_TEST_TOKEN")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.invalid/query")
        self.assertEqual(request.get_header("Authorization"), "Bearer made-up-token")
        self.assertEqual(json.loads(request.data), {"limit": 2})
        self.assertEqual(result, {"rows": [{"value": 3}]})

    def test_label_discovery_uses_all_rows_and_preserves_six_class_meanings(self):
        meanings = {str(i): meaning for i, meaning in enumerate(("normal", "login failure", "account change", "maintenance", "monitoring", "unknown"))}
        rows = [(str(i // 25), i) for i in range(150)]
        document = flow(node("source", "csv", csv=csv_text(["class_code", "lines"], rows)),
                        node("labels", "labels", column="class_code", mapping=json.dumps(meanings)))
        result = self.run_flow(document)
        labels = self.item(result, "labels")
        self.assertEqual({row["class_code"] for row in labels["sample"]}, {"0"})
        self.assertEqual(labels["meta"]["unique_labels"], ["0", "1", "2", "3", "4", "5"])
        self.assertEqual(labels["meta"]["label_mapping"], meanings)
        discovered = studio.discover_labels(document, "labels", "class_code")
        self.assertEqual(discovered, {"column": "class_code", "values": ["0", "1", "2", "3", "4", "5"], "rows": 150, "truncated": False})

    def test_preprocessing_statistics_and_categories_are_fitted_on_training_only(self):
        document = flow(node("source", "csv", csv="x,group,__split\n1,alpha,train\n3,beta,train\n100,unseen,test"),
                        node("scale", "preprocess", operation="standard_scale", columns="x"),
                        node("encode", "preprocess", operation="one_hot", columns="group"),
                        node("output", "output", name="Encoded rows"))
        result = self.run_flow(document)
        rows = studio.output(result["id"], "output")["rows"]
        np.testing.assert_allclose([row["x"] for row in rows], [-1, 1, 98])
        self.assertEqual({column for column in rows[0] if column.startswith("group__")}, {"group__alpha", "group__beta"})
        self.assertEqual((rows[2]["group__alpha"], rows[2]["group__beta"]), (0, 0))

    def test_imputation_uses_training_median_without_held_out_values(self):
        result = self.run_flow(flow(node("source", "csv", csv="x,__split\n1,train\n3,train\n,train\n100,test\n,test"),
                                    node("impute", "preprocess", operation="impute", strategy="median", columns="x")))
        np.testing.assert_allclose([row["x"] for row in studio.output(result["id"], "impute")["rows"]], [1, 3, 2, 100, 2])

    def classification_flow(self):
        # The final six labels deliberately reverse the training relationship. Training metrics would be perfect;
        # the held-out confusion matrix must show six errors instead.
        rows = [(f"2026-07-14T09:{i:02d}:00", i % 2, i % 2 if i < 34 else 1 - i % 2) for i in range(40)]
        return flow(node("source", "csv", csv=csv_text(["timestamp", "x", "target"], rows)),
                    node("split", "preprocess", operation="chronological_split", timestamp_column="timestamp", train_fraction="0.7", validation_fraction="0.15"),
                    node("labels", "labels", column="target", mapping='{"0":"normal","1":"review"}'),
                    node("model", "supervised", algorithm="logistic_regression", label_column="target", test_fraction="0.2", features=""),
                    node("metrics", "evaluate", method="classification", label_column="target", prediction_column="prediction", score_column="score"))

    def test_supervised_fit_excludes_target_and_evaluation_uses_only_held_out_period(self):
        from sklearn.linear_model import LogisticRegression
        original = LogisticRegression.fit
        fits = []

        def record_fit(model, matrix, labels, *args, **kwargs):
            fits.append((matrix.copy(), labels.copy()))
            return original(model, matrix, labels, *args, **kwargs)

        with mock.patch.object(LogisticRegression, "fit", autospec=True, side_effect=record_fit):
            result = self.run_flow(self.classification_flow(), persist=False)
        self.assertEqual(len(fits), 1)
        matrix, labels = fits[0]
        self.assertEqual(matrix.shape, (28, 1))
        np.testing.assert_allclose(matrix[:, 0], [i % 2 for i in range(28)])
        self.assertEqual(labels.tolist(), [str(i % 2) for i in range(28)])
        model = self.item(result, "model")["meta"]
        self.assertEqual(model["features"], ["x"])
        self.assertEqual((model["training_rows"], model["held_out_rows"]), (28, 12))
        metrics = self.item(result, "metrics")["meta"]["metrics"]
        self.assertEqual((metrics["evaluated_rows"], metrics["scope"]), (6, "held-out test rows"))
        self.assertEqual(metrics["confusion_matrix"], [[0, 3], [3, 0]])
        self.assertEqual((metrics["accuracy"], metrics["precision_macro"], metrics["recall_macro"], metrics["f1_macro"]), (0, 0, 0, 0))
        self.assertEqual(metrics["label_mapping"], {"0": "normal", "1": "review"})

    def test_target_column_cannot_be_selected_as_model_feature(self):
        document = self.classification_flow()
        document["nodes"][3]["config"]["features"] = "x,target"
        result = studio.run(document, persist=False)
        self.assertFalse(result["valid"])
        self.assertIn("cannot be model features", self.item(result, "model")["message"])
        self.assertEqual(self.item(result, "metrics")["status"], "skipped")

    def test_isolation_forest_evaluation_describes_workload_without_attack_claims(self):
        rows = [(i / 100 if i < 28 else 10 + i, "train" if i < 28 else "test") for i in range(40)]
        document = flow(node("source", "csv", csv=csv_text(["x", "__split"], rows)),
                        node("model", "unsupervised", algorithm="isolation_forest", columns="x", contamination="0.1"),
                        node("metrics", "evaluate", method="anomaly", score_column="score"))
        result = self.run_flow(document)
        self.assertEqual(self.item(result, "model")["meta"]["training_rows"], 28)
        model_rows = studio.output(result["id"], "model")["rows"]
        self.assertTrue(all(np.isfinite(row["score"]) and row["anomaly"] in (0, 1) for row in model_rows))
        self.assertTrue(all(row["prediction"] == row["anomaly"] for row in model_rows))
        metrics = self.item(result, "metrics")["meta"]["metrics"]
        self.assertEqual((metrics["evaluated_rows"], metrics["scope"]), (12, "held-out test rows"))
        self.assertGreaterEqual(metrics["flagged_share"], 0)
        self.assertLessEqual(metrics["flagged_share"], 1)
        self.assertIn("not measured attack precision or recall", metrics["interpretation"])
        self.assertFalse({"accuracy", "precision", "recall", "precision_macro", "recall_macro"}.intersection(metrics))


if __name__ == "__main__":
    unittest.main()
