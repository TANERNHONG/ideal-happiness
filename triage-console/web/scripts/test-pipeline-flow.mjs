import assert from "node:assert/strict";
import test from "node:test";
import { BACKEND_KINDS, BLOCK_FIELDS, BLOCKS, SAMPLE_EVENTS, compatible, createNode, emptyDraft, parseDraft, previewDraft, starterDraft, validateDraft } from "../src/pipeline-flow.ts";

function chain(kinds) {
  const draft = emptyDraft();
  draft.nodes = kinds.map((kind, i) => ({ ...createNode(kind, i * 280, 100), id: `node-${i}` }));
  draft.edges = draft.nodes.slice(1).map((node, i) => ({ id: `edge-${i}`, from: draft.nodes[i].id, to: node.id }));
  return draft;
}
const errors = (draft) => validateDraft(draft).issues.filter((issue) => issue.severity === "error").map((issue) => issue.message).join("\n");

test("starter executes in dependency order and leaves its inputs unchanged", () => {
  const draft = starterDraft(), before = JSON.stringify(draft), sample = JSON.stringify(SAMPLE_EVENTS), result = previewDraft(draft);
  assert.equal(result.valid, true);
  assert.deepEqual(result.order, draft.nodes.map((node) => node.id));
  assert.deepEqual(result.results.map((step) => step.rows), [12, 5, 5, 5]);
  assert.ok(result.results.every((step) => step.status === "passed"));
  assert.ok(result.rows.every((row) => row.event_type === "SSH_LOGIN_FAILED"));
  assert.equal(JSON.stringify(draft), before);
  assert.equal(JSON.stringify(SAMPLE_EVENTS), sample);
});

test("SELECT supports projection, equality, escaped literals and LIMIT", () => {
  const draft = chain(["sql", "output"]);
  draft.nodes[0].config.query = "SELECT host, event_type FROM sample_events WHERE event_type = 'SSH_LOGIN_FAILED' LIMIT 2;";
  const result = previewDraft(draft);
  assert.equal(result.valid, true);
  assert.equal(result.rows.length, 2);
  assert.deepEqual(Object.keys(result.rows[0]), ["host", "event_type"]);
  draft.nodes[0].config.query = "SELECT * FROM sample_events WHERE username = 'sample''operator' LIMIT 2";
  assert.equal(previewDraft(draft).rows.length, 0);
});

test("unsupported SQL and writes are refused", () => {
  for (const query of ["DELETE FROM sample_events", "SELECT * FROM other_table", "SELECT * FROM sample_events; DROP TABLE sample_events", "SELECT * FROM sample_events JOIN users ON 1=1", "SELECT * FROM sample_events LIMIT 1001", "SELECT * FROM sample_events ORDER BY host"]) {
    const draft = chain(["sql", "output"]); draft.nodes[0].config.query = query;
    assert.equal(validateDraft(draft).valid, false, query);
    assert.equal(previewDraft(draft).results.length, 0, query);
  }
});

test("empty query results retain column schema for downstream checks", () => {
  const draft = starterDraft(); draft.nodes[0].config.query = "SELECT * FROM sample_events LIMIT 0"; draft.nodes[2].config.min_rows = "0";
  const result = previewDraft(draft);
  assert.equal(result.valid, true); assert.equal(result.rows.length, 0); assert.ok(result.results[3].columns.includes("event_type"));
});

test("missing SQL columns fail and downstream blocks are skipped", () => {
  const draft = chain(["sql", "output"]); draft.nodes[0].config.query = "SELECT nonexistent FROM sample_events";
  const result = previewDraft(draft);
  assert.equal(result.valid, false); assert.equal(result.results[0].status, "failed"); assert.equal(result.results[1].status, "skipped");
  assert.match(result.results[0].message, /missing column/);
});

test("CSV supports quoted commas, escaped quotes, newlines and aggregation", () => {
  const draft = chain(["csv", "aggregate", "output"]);
  draft.nodes[0].config.csv = 'host,note\r\nsample-host-01,"a,b"\r\nsample-host-01,"a ""quoted"" value"\r\nsample-host-02,"two\nlines"';
  const result = previewDraft(draft);
  assert.equal(result.valid, true);
  assert.deepEqual(result.rows, [{ host: "sample-host-01", count: 2 }, { host: "sample-host-02", count: 1 }]);
  assert.equal(result.results[0].sample[1].note, 'a "quoted" value');
});

test("malformed CSV does not silently lose columns", () => {
  for (const csv of ['host,host\na,b', 'host,note\na', 'host,note\na,"unfinished', 'host,note\na,"closed"extra']) {
    const draft = chain(["csv", "output"]); draft.nodes[0].config.csv = csv; assert.equal(validateDraft(draft).valid, false);
  }
});

test("transform checks rename collisions and preserves selected column order", () => {
  const draft = chain(["sql", "transform", "output"]); draft.nodes[1].config = { operation: "select", columns: "event_type, host" };
  let result = previewDraft(draft); assert.equal(result.valid, true); assert.deepEqual(result.results[1].columns, ["event_type", "host"]);
  draft.nodes[1].config = { operation: "rename", column: "host", new_name: "server" };
  result = previewDraft(draft); assert.equal(result.valid, true); assert.equal(result.rows[0].server, "sample-host-01"); assert.equal(result.rows[0].host, undefined);
  draft.nodes[1].config.new_name = "event_type"; assert.equal(previewDraft(draft).valid, false);
});

test("sanity-check failures stop their downstream branch", () => {
  const draft = starterDraft(); draft.nodes[2].config.min_rows = "6";
  let result = previewDraft(draft); assert.equal(result.valid, false); assert.equal(result.results[2].status, "failed"); assert.equal(result.results[3].status, "skipped");
  const blank = chain(["csv", "check", "output"]); blank.nodes[0].config.csv = "host,note\nsample-host-01,"; blank.nodes[1].config = { min_rows: "1", required_columns: "host, note" };
  result = previewDraft(blank); assert.equal(result.valid, false); assert.match(result.results[1].message, /empty required values/);
  blank.nodes[0].config.csv = "host,note\n,";
  result = previewDraft(blank); assert.equal(result.valid, false); assert.match(result.results[1].message, /empty required values/);
});

test("numeric filters do not interpret empty cells as zero", () => {
  const draft = chain(["csv", "filter", "output"]); draft.nodes[0].config.csv = "host,lines\nsample-host-01,\nsample-host-02,2\nsample-host-03,10";
  draft.nodes[1].config = { field: "lines", operator: "greater_than", value: "3" };
  assert.deepEqual(previewDraft(draft).rows, [{ host: "sample-host-03", lines: "10" }]);
});

test("cycles, missing inputs, multiple inputs, missing blocks and duplicate edges are detected", () => {
  const cycle = chain(["filter", "check"]); cycle.edges.push({ id: "back", from: "node-1", to: "node-0" }); assert.match(errors(cycle), /cycle/);
  assert.match(errors(chain(["filter"])), /upstream/);
  const multi = chain(["sql", "check"]); multi.nodes.push({ ...createNode("sql", 0, 0), id: "second-source" }); multi.edges.push({ id: "extra", from: "second-source", to: "node-1" }); assert.match(errors(multi), /one incoming/);
  const missing = chain(["sql", "output"]); missing.edges[0].from = "gone"; assert.match(errors(missing), /missing block/);
  const duplicate = chain(["sql", "output"]); duplicate.edges.push({ ...duplicate.edges[0], id: "second-edge" }); assert.match(errors(duplicate), /duplicate connection/);
});

test("phase contracts reject wrong inputs and previews never invent detections", () => {
  assert.equal(compatible("sql", "detect"), false); assert.equal(compatible("classify", "observations"), true); assert.match(errors(chain(["sql", "detect"])), /needs features/);
  const result = previewDraft(chain(["sql", "classify", "observations", "features", "detect", "evidence", "report"]));
  assert.equal(result.valid, true); assert.equal(result.results[0].status, "passed"); assert.ok(result.results.slice(1).every((step) => step.status === "skipped"));
  assert.deepEqual(result.rows, []); assert.ok(result.issues.some((issue) => issue.severity === "warning"));
});

test("disconnected workflows are disclosed and empty drafts are incomplete", () => {
  const draft = starterDraft(); draft.nodes.push(createNode("csv", 0, 0)); assert.ok(validateDraft(draft).issues.some((issue) => /disconnected/.test(issue.message)));
  assert.equal(validateDraft(emptyDraft()).valid, false);
});

test("parseDraft restores by value and permits incomplete drafts", () => {
  const draft = starterDraft(), restored = parseDraft(JSON.parse(JSON.stringify(draft))); assert.deepEqual(restored, draft);
  restored.nodes[0].config.query = ""; assert.notEqual(draft.nodes[0].config.query, ""); assert.deepEqual(parseDraft(emptyDraft()).nodes, []);
  const unfinished = starterDraft(); unfinished.nodes[2].config = {}; assert.equal(validateDraft(parseDraft(unfinished)).valid, false);
});

test("parseDraft bounds versions, counts, strings, coordinates, kinds and setting types", () => {
  const edits = [
    (draft) => { draft.version = 2; }, (draft) => { draft.nodes = Array(101).fill(draft.nodes[0]); }, (draft) => { draft.edges = Array(201).fill(draft.edges[0]); },
    (draft) => { draft.name = "x".repeat(121); }, (draft) => { draft.nodes[0].x = Infinity; }, (draft) => { draft.nodes[0].y = 100001; },
    (draft) => { draft.nodes[0].kind = "execute-code"; }, (draft) => { draft.nodes[0].config.query = "x".repeat(20001); }, (draft) => { draft.nodes[0].config.query = {}; },
    (draft) => { draft.nodes[0].id = "<script>"; },
  ];
  for (const edit of edits) { const draft = starterDraft(); edit(draft); assert.throws(() => parseDraft(draft)); }
  assert.throws(() => parseDraft(null)); assert.throws(() => parseDraft([])); assert.equal(new Set(BLOCKS.map((block) => block.kind)).size, BLOCKS.length);
});

test("the execution catalog covers sources, parsing, preprocessing, models, evaluation and outputs", () => {
  assert.deepEqual([...new Set(BLOCKS.map((block) => block.category))], ["Sources & Parsing", "Preprocessing & Features", "Models", "Evaluation", "Outputs"]);
  for (const block of BLOCKS) {
    assert.equal(block.executor, `studio.${block.kind}`);
    assert.ok(Array.isArray(BLOCK_FIELDS[block.kind]));
    assert.equal(parseDraft(chain([block.kind])).nodes[0].kind, block.kind);
  }
  for (const kind of ["api", "database", "raw", "parse", "preprocess", "sigma", "labels", "unsupervised", "supervised", "evaluate"]) assert.equal(BACKEND_KINDS.has(kind), true);
  for (const kind of ["sql", "csv", "transform", "filter", "aggregate", "check", "output"]) assert.equal(BACKEND_KINDS.has(kind), false);
});

test("model workflows connect and offline preview explicitly defers backend execution", () => {
  const supervised = chain(["csv", "preprocess", "labels", "supervised", "evaluate", "output"]);
  assert.ok(Object.values(JSON.parse(supervised.nodes[2].config.mapping)).every((meaning) => typeof meaning === "string"));
  assert.equal(validateDraft(supervised).valid, true);
  assert.equal(validateDraft(supervised).issues.filter((issue) => issue.severity === "warning").length, 0);
  const result = previewDraft(supervised);
  assert.equal(result.valid, true);
  assert.equal(result.results[0].status, "passed");
  assert.ok(result.results.slice(1).every((step) => step.status === "skipped"));
  assert.match(result.results[1].message, /requires backend execution/);
  const unsupervised = chain(["csv", "unsupervised", "check", "evaluate", "output"]);
  unsupervised.nodes[3].config.method = "anomaly";
  assert.equal(validateDraft(unsupervised).valid, true);
});

test("row-preserving recipes retain phase contracts but do not invent them", () => {
  assert.equal(compatible("filter", "observations"), true);
  assert.equal(validateDraft(chain(["raw", "classify", "filter", "check", "preprocess", "observations", "features", "detect"])).valid, true);
  assert.match(errors(chain(["sql", "filter", "observations"])), /outputs table.*needs events/);
  assert.match(errors(chain(["sql", "preprocess", "detect"])), /outputs table.*needs features/);
});

test("source configuration checks addresses, environment names, log dates and SQL presence", () => {
  const api = chain(["api", "output"]);
  assert.match(errors(api), /HTTP or HTTPS/);
  api.nodes[0].config.url = "https://example.invalid/records";
  api.nodes[0].config.token_env = "STUDIO_API_TOKEN";
  assert.equal(validateDraft(api).valid, true);
  api.nodes[0].config.url = "file:///private/file";
  assert.equal(validateDraft(api).valid, false);
  api.nodes[0].config.url = "https://example.invalid/records"; api.nodes[0].config.token_env = "secret token value";
  assert.match(errors(api), /environment variable/);
  const raw = chain(["raw", "output"]); raw.nodes[0].config.month = "2026-13"; assert.match(errors(raw), /YYYY-MM/);
  raw.nodes[0].config.month = "2026-07"; raw.nodes[0].config.text = ""; assert.match(errors(raw), /Raw log text is required/);
  const db = chain(["database", "output"]); db.nodes[0].config.query = ""; assert.match(errors(db), /SQL query is required/);
});

test("manual, regex and LLM parsers validate only their applicable settings", () => {
  const draft = chain(["raw", "parse", "output"]), parser = draft.nodes[1];
  parser.config = { method: "manual", classifications: '{"failure": "LOGIN_FAILED"}' };
  assert.equal(validateDraft(draft).valid, true);
  parser.config.classifications = "[]"; assert.match(errors(draft), /JSON object/);
  parser.config = { method: "regex", regex: "(?P<message>.*)" }; assert.equal(validateDraft(draft).valid, true);
  parser.config.regex = ""; assert.match(errors(draft), /regular expression is required/);
  parser.config = { method: "auto_regex" }; assert.equal(validateDraft(draft).valid, true);
  parser.config = { method: "llm", provider: "api", endpoint: "https://example.invalid/v1", model: "example-model", prompt: "Classify these rows", token_env: "EXAMPLE_MODEL_TOKEN" };
  assert.equal(validateDraft(draft).valid, true);
  parser.config.endpoint = ""; assert.match(errors(draft), /Model endpoint/);
});

test("preprocessing validates split fractions and feature dimensions", () => {
  const draft = chain(["csv", "preprocess", "output"]), config = draft.nodes[1].config;
  config.operation = "chronological_split"; config.train_fraction = "0.8"; config.validation_fraction = "0.3";
  assert.match(errors(draft), /leave a non-empty test split/);
  config.validation_fraction = "0.1"; assert.equal(validateDraft(draft).valid, true);
  config.operation = "hash_text"; config.hash_features = "1"; assert.match(errors(draft), /Hash features/);
  config.hash_features = "128"; assert.equal(validateDraft(draft).valid, true);
  config.operation = "drop_duplicates"; delete config.strategy; assert.equal(validateDraft(draft).valid, true);
});

test("modelling and evaluation reject invalid fractions or missing labels", () => {
  const unsupervised = chain(["csv", "unsupervised", "output"]);
  unsupervised.nodes[1].config.contamination = "0"; assert.match(errors(unsupervised), /anomaly fraction/);
  unsupervised.nodes[1].config.contamination = "0.51"; assert.match(errors(unsupervised), /anomaly fraction/);
  const supervised = chain(["csv", "supervised", "evaluate", "output"]);
  supervised.nodes[1].config.label_column = ""; assert.match(errors(supervised), /Label column is required/);
  supervised.nodes[1].config.label_column = "label"; supervised.nodes[1].config.test_fraction = "1"; assert.match(errors(supervised), /Test fraction/);
  supervised.nodes[1].config.test_fraction = "0.25"; supervised.nodes[2].config.label_column = ""; assert.match(errors(supervised), /True-label column is required/);
});

test("large source payloads can import while ordinary settings remain bounded", () => {
  const raw = chain(["raw", "output"]); raw.nodes[0].config.text = "x".repeat(1_000_000); assert.equal(parseDraft(raw).nodes[0].config.text.length, 1_000_000);
  raw.nodes[0].config.text += "x"; assert.throws(() => parseDraft(raw));
  const csv = chain(["csv", "output"]); csv.nodes[0].config.csv = "host\n" + "sample-host\n".repeat(1001);
  assert.equal(parseDraft(csv).nodes[0].kind, "csv"); assert.equal(validateDraft(csv).valid, true);
  const result = previewDraft(csv); assert.equal(result.valid, false); assert.match(result.results[0].message, /1,000-row limit/);
});

test("imports refuse duplicate identities and invisible connections", () => {
  const node = starterDraft(); node.nodes[1].id = node.nodes[0].id; assert.throws(() => parseDraft(node), /Block IDs must be unique/);
  const edge = starterDraft(); edge.edges[1].id = edge.edges[0].id; assert.throws(() => parseDraft(edge), /Connection IDs must be unique/);
  const dangling = starterDraft(); dangling.edges.push({ id: "invisible", from: "gone-from", to: "gone-to" }); assert.throws(() => parseDraft(dangling), /missing block/);
});

test("numeric configuration boundaries agree with the backend execution limits", () => {
  const supervised = chain(["csv", "supervised", "output"]);
  for (const value of ["0.1", "0.5"]) { supervised.nodes[1].config.test_fraction = value; assert.equal(validateDraft(supervised).valid, true); }
  for (const value of ["0.09", "0.51"]) { supervised.nodes[1].config.test_fraction = value; assert.equal(validateDraft(supervised).valid, false); }
  const unsupervised = chain(["csv", "unsupervised", "output"]);
  unsupervised.nodes[1].config.contamination = "0.001"; assert.equal(validateDraft(unsupervised).valid, true);
  unsupervised.nodes[1].config.contamination = "0.0009"; assert.equal(validateDraft(unsupervised).valid, false);
  const preprocessing = chain(["csv", "preprocess", "output"]), config = preprocessing.nodes[1].config;
  config.operation = "hash_text"; config.hash_features = "8"; assert.equal(validateDraft(preprocessing).valid, true);
  config.hash_features = "7"; assert.equal(validateDraft(preprocessing).valid, false);
  config.operation = "chronological_split"; config.validation_fraction = "0";
  for (const value of ["0.1", "0.9"]) { config.train_fraction = value; assert.equal(validateDraft(preprocessing).valid, true); }
  for (const value of ["0.09", "0.91"]) { config.train_fraction = value; assert.equal(validateDraft(preprocessing).valid, false); }
  const sanity = starterDraft(); sanity.nodes[2].config.min_rows = "100000";
  assert.equal(validateDraft(sanity).valid, true); assert.equal(previewDraft(sanity).valid, false);
  sanity.nodes[2].config.min_rows = "100001"; assert.equal(validateDraft(sanity).valid, false);
});
