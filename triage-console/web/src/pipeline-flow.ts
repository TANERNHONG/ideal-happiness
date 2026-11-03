// Portable pipeline documents, operator metadata and a bounded offline sample executor.
// Live sources, parsers and ML operators execute through the Studio backend, never in this module.

export type BlockKind = "sql" | "csv" | "api" | "database" | "raw" | "parse" | "classify" | "transform" | "filter" | "aggregate" | "preprocess" | "observations" | "features" | "labels" | "detect" | "unsupervised" | "supervised" | "sigma" | "check" | "evaluate" | "evidence" | "report" | "output";
export type DataContract = "table" | "events" | "observations" | "features" | "alerts" | "labelled_table" | "predictions" | "metrics" | "evidence" | "report";
export type BlockCategory = "Sources & Parsing" | "Preprocessing & Features" | "Models" | "Evaluation" | "Outputs";
export type SampleValue = string | number | boolean | null;
export type SampleRow = Record<string, SampleValue>;
export interface PipelineNode { id: string; kind: BlockKind; x: number; y: number; label: string; config: Record<string, string> }
export interface PipelineEdge { id: string; from: string; to: string }
export interface PipelineDraft { version: 1; id: string; name: string; nodes: PipelineNode[]; edges: PipelineEdge[] }
export interface BlockDefinition { kind: BlockKind; label: string; category: BlockCategory; icon: string; description: string; input: DataContract | null; output: DataContract; executor: string; phase?: string }
export interface BlockField { key: string; label: string; type: "text" | "textarea" | "select" | "number"; options?: { value: string; label: string }[]; help?: string; maxLength?: number }
export interface FlowIssue { severity: "error" | "warning"; nodeId?: string; message: string }
export interface ValidationResult { valid: boolean; issues: FlowIssue[]; order: string[] }
export interface PreviewResult { nodeId: string; rows: number; columns: string[]; sample: SampleRow[]; message: string; status: "passed" | "failed" | "skipped" }
export interface PipelinePreview extends ValidationResult { results: PreviewResult[]; rows: SampleRow[] }

export const BLOCKS: BlockDefinition[] = [
  {"kind": "sql", "label": "Sample SQL", "category": "Sources & Parsing", "icon": "query-sql", "description": "Query the example event table to develop a flow locally.", "input": null, "output": "table", "executor": "studio.sql"},
  {"kind": "csv", "label": "CSV table", "category": "Sources & Parsing", "icon": "table", "description": "Read a CSV table with named columns.", "input": null, "output": "table", "executor": "studio.csv"},
  {"kind": "api", "label": "API request", "category": "Sources & Parsing", "icon": "globe", "description": "Fetch JSON records from an HTTP API using a GET request.", "input": null, "output": "table", "executor": "studio.api"},
  {"kind": "database", "label": "Database query", "category": "Sources & Parsing", "icon": "query-sql", "description": "Run a read-only SQL query against the console or a SQLite database.", "input": null, "output": "table", "executor": "studio.database"},
  {"kind": "raw", "label": "Raw log lines", "category": "Sources & Parsing", "icon": "paste", "description": "Bring raw text into the flow before choosing how to parse it.", "input": null, "output": "table", "executor": "studio.raw"},
  {"kind": "parse", "label": "Parse & classify", "category": "Sources & Parsing", "icon": "patterns", "description": "Use built-in, manual, regex or LLM-assisted classification.", "input": "table", "output": "events", "executor": "studio.parse"},
  {"kind": "classify", "label": "Classify events", "category": "Sources & Parsing", "icon": "patterns", "description": "Reuse Project DAD's raw-log classification.", "input": "table", "output": "events", "executor": "studio.classify", "phase": "Phase 1"},
  {"kind": "transform", "label": "Transform columns", "category": "Preprocessing & Features", "icon": "settings", "description": "Select or rename columns without writing code.", "input": "table", "output": "table", "executor": "studio.transform"},
  {"kind": "filter", "label": "Filter rows", "category": "Preprocessing & Features", "icon": "filter", "description": "Keep rows that match a condition.", "input": "table", "output": "table", "executor": "studio.filter"},
  {"kind": "aggregate", "label": "Group & count", "category": "Preprocessing & Features", "icon": "chart", "description": "Count rows for each value of a column.", "input": "table", "output": "table", "executor": "studio.aggregate"},
  {"kind": "preprocess", "label": "Preprocess & encode", "category": "Preprocessing & Features", "icon": "matrix", "description": "Clean, impute, scale, encode or split a table for modelling.", "input": "table", "output": "table", "executor": "studio.preprocess"},
  {"kind": "observations", "label": "Build observations", "category": "Preprocessing & Features", "icon": "session", "description": "Group events into sessions, windows or daily behaviour.", "input": "events", "output": "observations", "executor": "studio.observations", "phase": "Phase 2"},
  {"kind": "features", "label": "Build features", "category": "Preprocessing & Features", "icon": "matrix", "description": "Apply preprocessing and prepare model-ready features.", "input": "observations", "output": "features", "executor": "studio.features", "phase": "Phase 3"},
  {"kind": "labels", "label": "Assign labels", "category": "Preprocessing & Features", "icon": "sign", "description": "Map column values to target labels for training or evaluation.", "input": "table", "output": "labelled_table", "executor": "studio.labels"},
  {"kind": "detect", "label": "Detect anomalies", "category": "Models", "icon": "models", "description": "Score features with the existing trained detectors.", "input": "features", "output": "alerts", "executor": "studio.detect", "phase": "Phase 4"},
  {"kind": "unsupervised", "label": "Unsupervised model", "category": "Models", "icon": "models", "description": "Fit an anomaly detector to selected numeric features.", "input": "table", "output": "predictions", "executor": "studio.unsupervised"},
  {"kind": "supervised", "label": "Supervised model", "category": "Models", "icon": "target", "description": "Train a classifier with labelled rows and a held-out test split.", "input": "table", "output": "predictions", "executor": "studio.supervised"},
  {"kind": "sigma", "label": "Sigma rules", "category": "Models", "icon": "sigma", "description": "Match structured events against a Sigma rule.", "input": "events", "output": "alerts", "executor": "studio.sigma"},
  {"kind": "check", "label": "Sanity check", "category": "Evaluation", "icon": "check-circle", "description": "Check required columns, non-empty values and row counts.", "input": "table", "output": "table", "executor": "studio.check"},
  {"kind": "evaluate", "label": "Evaluate results", "category": "Evaluation", "icon": "chart", "description": "Measure classification, regression, clustering or anomaly results.", "input": "predictions", "output": "metrics", "executor": "studio.evaluate"},
  {"kind": "evidence", "label": "Trace evidence", "category": "Outputs", "icon": "session", "description": "Resolve alert lineage back to original log lines.", "input": "alerts", "output": "evidence", "executor": "studio.evidence", "phase": "Phase 5"},
  {"kind": "report", "label": "Build report", "category": "Outputs", "icon": "reports", "description": "Turn evidence into a pipeline report artifact.", "input": "evidence", "output": "report", "executor": "studio.report", "phase": "Phase 6"},
  {"kind": "output", "label": "Table output", "category": "Outputs", "icon": "table", "description": "Inspect and keep the resulting table.", "input": "table", "output": "table", "executor": "studio.output"},
 ];
const BROWSER_KINDS = new Set<BlockKind>(["sql", "csv", "transform", "filter", "aggregate", "check", "output"]);
export const BACKEND_KINDS = new Set<BlockKind>(BLOCKS.filter((block) => !BROWSER_KINDS.has(block.kind)).map((block) => block.kind));
const PASSTHROUGH_KINDS = new Set<BlockKind>(["transform", "filter", "preprocess", "check", "output"]);

export const BLOCK_FIELDS: Record<BlockKind, BlockField[]> = {
  "sql": [
    {
      "key": "query",
      "label": "Query",
      "type": "textarea",
      "help": "Offline preview supports SELECT columns FROM sample_events with optional WHERE column = literal and LIMIT."
    }
  ],
  "csv": [
    {
      "key": "csv",
      "label": "CSV data",
      "type": "textarea",
      "maxLength": 1000000,
      "help": "The first row supplies column names. Offline preview is limited to 1,000 rows."
    }
  ],
  "api": [
    {
      "key": "url",
      "label": "Request URL",
      "type": "text",
      "help": "HTTP(S) JSON endpoint. This block uses GET."
    },
    {
      "key": "records_path",
      "label": "Records path",
      "type": "text",
      "help": "Dot-separated path to a JSON array; blank uses a top-level array."
    },
    {
      "key": "token_env",
      "label": "Bearer-token environment variable",
      "type": "text"
    }
  ],
  "database": [
    {
      "key": "database",
      "label": "Database",
      "type": "text",
      "help": "Use console, or the path of a local SQLite database."
    },
    {
      "key": "query",
      "label": "Read-only SQL",
      "type": "textarea"
    }
  ],
  "raw": [
    {
      "key": "text",
      "label": "Raw log text",
      "type": "textarea",
      "maxLength": 1000000
    },
    {
      "key": "month",
      "label": "Log month",
      "type": "text",
      "help": "YYYY-MM; used when raw lines omit their year."
    },
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    }
  ],
  "parse": [
    {
      "key": "method",
      "label": "Parsing method",
      "type": "select",
      "options": [
        {
          "value": "builtin",
          "label": "Built-in log parser"
        },
        {
          "value": "manual",
          "label": "Manual classification map"
        },
        {
          "value": "regex",
          "label": "Named-capture regular expression"
        },
        {
          "value": "auto_regex",
          "label": "Automatic REGEX discovery"
        },
        {
          "value": "llm",
          "label": "LLM classification"
        },
        {
          "value": "llm_regex",
          "label": "LLM-generated regular expression"
        }
      ]
    },
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    },
    {
      "key": "month",
      "label": "Log month",
      "type": "text",
      "help": "YYYY-MM; used when raw lines omit their year."
    },
    {
      "key": "regex",
      "label": "Parsing regular expression",
      "type": "textarea",
      "help": "Use named capture groups for extracted columns."
    },
    {
      "key": "event_type",
      "label": "Event type",
      "type": "text"
    },
    {
      "key": "classifications",
      "label": "Manual classifications JSON",
      "type": "textarea",
      "help": "A JSON mapping of matched values to classification labels."
    },
    {
      "key": "prompt",
      "label": "Parsing instruction",
      "type": "textarea"
    },
    {
      "key": "provider",
      "label": "LLM provider",
      "type": "select",
      "options": [
        {
          "value": "local",
          "label": "Local model"
        },
        {
          "value": "api",
          "label": "API provider"
        }
      ]
    },
    {
      "key": "endpoint",
      "label": "Model endpoint",
      "type": "text"
    },
    {
      "key": "model",
      "label": "Model",
      "type": "text"
    },
    {
      "key": "token_env",
      "label": "API token environment variable",
      "type": "text",
      "help": "Name of a server environment variable; never put an API token in the pipeline JSON."
    }
  ],
  "transform": [
    {
      "key": "operation",
      "label": "Operation",
      "type": "select",
      "options": [
        {
          "value": "select",
          "label": "Select columns"
        },
        {
          "value": "rename",
          "label": "Rename a column"
        }
      ]
    },
    {
      "key": "columns",
      "label": "Columns to keep",
      "type": "text",
      "help": "Comma-separated names; used by Select columns."
    },
    {
      "key": "column",
      "label": "Original column",
      "type": "text",
      "help": "Used by Rename a column."
    },
    {
      "key": "new_name",
      "label": "New column name",
      "type": "text"
    }
  ],
  "filter": [
    {
      "key": "field",
      "label": "Column",
      "type": "text"
    },
    {
      "key": "operator",
      "label": "Condition",
      "type": "select",
      "options": [
        {
          "value": "equals",
          "label": "Equals"
        },
        {
          "value": "not_equals",
          "label": "Does not equal"
        },
        {
          "value": "contains",
          "label": "Contains"
        },
        {
          "value": "greater_than",
          "label": "Greater than"
        },
        {
          "value": "less_than",
          "label": "Less than"
        }
      ]
    },
    {
      "key": "value",
      "label": "Value",
      "type": "text"
    }
  ],
  "aggregate": [
    {
      "key": "group_by",
      "label": "Group by column",
      "type": "text"
    }
  ],
  "preprocess": [
    {
      "key": "operation",
      "label": "Operation",
      "type": "select",
      "options": [
        {
          "value": "drop_duplicates",
          "label": "Remove duplicate rows"
        },
        {
          "value": "drop_missing",
          "label": "Remove missing values"
        },
        {
          "value": "impute",
          "label": "Fill missing values"
        },
        {
          "value": "standard_scale",
          "label": "Standard scaling"
        },
        {
          "value": "robust_scale",
          "label": "Robust scaling"
        },
        {
          "value": "minmax_scale",
          "label": "Min-max scaling"
        },
        {
          "value": "one_hot",
          "label": "One-hot encode categories"
        },
        {
          "value": "hash_text",
          "label": "Hash text features"
        },
        {
          "value": "hash_sequence",
          "label": "Hash sequence features"
        },
        {
          "value": "time_features",
          "label": "Extract time features"
        },
        {
          "value": "chronological_split",
          "label": "Chronological split"
        }
      ]
    },
    {
      "key": "columns",
      "label": "Columns",
      "type": "text",
      "help": "Comma-separated column names; blank selects suitable columns automatically."
    },
    {
      "key": "strategy",
      "label": "Imputation strategy",
      "type": "select",
      "options": [
        {
          "value": "median",
          "label": "Median"
        },
        {
          "value": "mean",
          "label": "Mean"
        },
        {
          "value": "most_frequent",
          "label": "Most frequent"
        },
        {
          "value": "constant",
          "label": "Constant"
        }
      ]
    },
    {
      "key": "fill_value",
      "label": "Constant fill value",
      "type": "text"
    },
    {
      "key": "label_column",
      "label": "Label column to preserve",
      "type": "text"
    },
    {
      "key": "text_column",
      "label": "Text column",
      "type": "text"
    },
    {
      "key": "sequence_column",
      "label": "Sequence column",
      "type": "text"
    },
    {
      "key": "timestamp_column",
      "label": "Timestamp column",
      "type": "text"
    },
    {
      "key": "train_fraction",
      "label": "Training fraction",
      "type": "number"
    },
    {
      "key": "validation_fraction",
      "label": "Validation fraction",
      "type": "number"
    },
    {
      "key": "hash_features",
      "label": "Hash features",
      "type": "number"
    }
  ],
  "check": [
    {
      "key": "min_rows",
      "label": "Minimum rows",
      "type": "number"
    },
    {
      "key": "required_columns",
      "label": "Required columns",
      "type": "text",
      "help": "Comma-separated names; required values must be present in every row."
    }
  ],
  "classify": [
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    },
    {
      "key": "month",
      "label": "Log month",
      "type": "text",
      "help": "YYYY-MM; used when raw lines omit their year."
    }
  ],
  "observations": [
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    },
    {
      "key": "view",
      "label": "Observation view",
      "type": "select",
      "options": [
        {
          "value": "individual",
          "label": "Individual events"
        },
        {
          "value": "sessions",
          "label": "Sessions / episodes"
        },
        {
          "value": "host_5min",
          "label": "Five-minute windows"
        },
        {
          "value": "host_behavior_1d",
          "label": "Daily behaviour"
        }
      ]
    }
  ],
  "features": [
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    }
  ],
  "detect": [
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    },
    {
      "key": "detector",
      "label": "Detector",
      "type": "select",
      "options": [
        {
          "value": "isolation_forest",
          "label": "Isolation Forest"
        },
        {
          "value": "robust",
          "label": "Robust deviation"
        },
        {
          "value": "novelty",
          "label": "Novelty"
        },
        {
          "value": "model_zoo",
          "label": "Model zoo"
        }
      ]
    }
  ],
  "sigma": [
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    },
    {
      "key": "yaml",
      "label": "Sigma rule YAML",
      "type": "textarea"
    }
  ],
  "labels": [
    {
      "key": "column",
      "label": "Source column",
      "type": "text"
    },
    {
      "key": "mapping",
      "label": "Label mapping JSON",
      "type": "textarea",
      "help": "Give existing column values readable label names. Original values are preserved for training."
    }
  ],
  "unsupervised": [
    {
      "key": "algorithm",
      "label": "Algorithm",
      "type": "select",
      "options": [
        {
          "value": "isolation_forest",
          "label": "Isolation Forest"
        },
        {
          "value": "local_outlier_factor",
          "label": "Local Outlier Factor"
        },
        {
          "value": "one_class_svm_rbf",
          "label": "One-class SVM / RBF"
        },
        {
          "value": "one_class_svm_linear",
          "label": "One-class SVM / linear"
        },
        {
          "value": "elliptic_envelope",
          "label": "Elliptic envelope"
        },
        {
          "value": "gaussian_mixture",
          "label": "Gaussian mixture"
        },
        {
          "value": "knn_distance",
          "label": "kNN distance"
        },
        {
          "value": "kmeans_distance",
          "label": "k-means distance"
        },
        {
          "value": "pca_reconstruction",
          "label": "PCA reconstruction"
        },
        {
          "value": "svd_reconstruction",
          "label": "SVD reconstruction"
        },
        {
          "value": "hbos",
          "label": "HBOS"
        },
        {
          "value": "ecod",
          "label": "ECOD"
        },
        {
          "value": "autoencoder",
          "label": "Autoencoder"
        },
        {
          "value": "robust",
          "label": "Robust deviation"
        },
        {
          "value": "novelty",
          "label": "Novelty"
        }
      ]
    },
    {
      "key": "columns",
      "label": "Columns",
      "type": "text",
      "help": "Comma-separated column names; blank selects suitable columns automatically."
    },
    {
      "key": "contamination",
      "label": "Expected anomaly fraction",
      "type": "number"
    }
  ],
  "supervised": [
    {
      "key": "algorithm",
      "label": "Algorithm",
      "type": "select",
      "options": [
        {
          "value": "random_forest",
          "label": "Random forest"
        },
        {
          "value": "logistic_regression",
          "label": "Logistic regression"
        },
        {
          "value": "gradient_boosting",
          "label": "Gradient boosting"
        }
      ]
    },
    {
      "key": "label_column",
      "label": "Label column",
      "type": "text"
    },
    {
      "key": "features",
      "label": "Feature columns",
      "type": "text",
      "help": "Comma-separated; blank uses suitable numeric columns."
    },
    {
      "key": "test_fraction",
      "label": "Test fraction",
      "type": "number"
    }
  ],
  "evaluate": [
    {
      "key": "method",
      "label": "Evaluation method",
      "type": "select",
      "options": [
        {
          "value": "classification",
          "label": "Classification"
        },
        {
          "value": "regression",
          "label": "Regression"
        },
        {
          "value": "clustering",
          "label": "Clustering"
        },
        {
          "value": "anomaly",
          "label": "Anomaly detection"
        }
      ]
    },
    {
      "key": "label_column",
      "label": "True-label column",
      "type": "text"
    },
    {
      "key": "prediction_column",
      "label": "Prediction column",
      "type": "text"
    },
    {
      "key": "score_column",
      "label": "Score column",
      "type": "text"
    }
  ],
  "evidence": [
    {
      "key": "source",
      "label": "Log source",
      "type": "select",
      "options": [
        {
          "value": "auth",
          "label": "Authentication"
        },
        {
          "value": "ossec",
          "label": "OSSEC"
        },
        {
          "value": "pf",
          "label": "PF"
        },
        {
          "value": "ipf",
          "label": "IPFilter"
        }
      ]
    }
  ],
  "report": [
    {
      "key": "title",
      "label": "Report title",
      "type": "text"
    }
  ],
  "output": [
    {
      "key": "name",
      "label": "Output name",
      "type": "text"
    }
  ]
};

export const SAMPLE_EVENTS: SampleRow[] = [
  { timestamp: "2026-07-14 09:00:00", host: "sample-host-01", event_type: "SSH_LOGIN_ACCEPTED", username: "sample-operator", source_ip: "192.0.2.10" },
  { timestamp: "2026-07-14 09:01:00", host: "sample-host-01", event_type: "SSH_LOGIN_FAILED", username: "sample-guest", source_ip: "192.0.2.20" },
  { timestamp: "2026-07-14 09:01:05", host: "sample-host-01", event_type: "SSH_LOGIN_FAILED", username: "sample-guest", source_ip: "192.0.2.20" },
  { timestamp: "2026-07-14 09:01:10", host: "sample-host-01", event_type: "SSH_LOGIN_FAILED", username: "sample-guest", source_ip: "192.0.2.20" },
  { timestamp: "2026-07-14 09:02:00", host: "sample-host-02", event_type: "SSH_LOGIN_ACCEPTED", username: "sample-backup", source_ip: "192.0.2.30" },
  { timestamp: "2026-07-14 09:03:00", host: "sample-host-02", event_type: "SSH_DISCONNECTED", username: "sample-backup", source_ip: "192.0.2.30" },
  { timestamp: "2026-07-14 09:04:00", host: "sample-host-03", event_type: "SSH_LOGIN_FAILED", username: "sample-visitor", source_ip: "192.0.2.40" },
  { timestamp: "2026-07-14 09:05:00", host: "sample-host-03", event_type: "SSH_LOGIN_ACCEPTED", username: "sample-operator", source_ip: "192.0.2.10" },
  { timestamp: "2026-07-14 09:06:00", host: "sample-host-01", event_type: "SSH_DISCONNECTED", username: "sample-operator", source_ip: "192.0.2.10" },
  { timestamp: "2026-07-14 09:07:00", host: "sample-host-02", event_type: "SSH_LOGIN_FAILED", username: "sample-visitor", source_ip: "192.0.2.40" },
  { timestamp: "2026-07-14 09:08:00", host: "sample-host-03", event_type: "SSH_DISCONNECTED", username: "sample-operator", source_ip: "192.0.2.10" },
  { timestamp: "2026-07-14 09:09:00", host: "sample-host-02", event_type: "SSH_LOGIN_ACCEPTED", username: "sample-backup", source_ip: "192.0.2.30" },
];

const DEFAULTS: Record<BlockKind, Record<string, string>> = {
  sql: { query: "SELECT timestamp, host, event_type, username, source_ip\nFROM sample_events\nLIMIT 100" },
  csv: { csv: "host,event_type,lines\nsample-host-01,SSH_LOGIN_FAILED,3\nsample-host-02,SSH_LOGIN_ACCEPTED,1\nsample-host-03,SSH_LOGIN_FAILED,1" },
  api: { url: "", records_path: "", token_env: "" },
  database: { database: "console", query: "SELECT * FROM reviews LIMIT 100" },
  raw: { text: "Jul 14 09:01:00 sample-host-01 sshd[1234]: Failed password for invalid user sample-guest from 192.0.2.20 port 50123 ssh2\nJul 14 09:02:00 sample-host-01 sshd[1235]: Accepted publickey for sample-operator from 192.0.2.10 port 50124 ssh2", month: "2026-07", source: "auth" },
  parse: { method: "builtin", source: "auth", month: "2026-07", regex: "^(?P<event_type>\\S+)\\s+(?P<message>.*)$", event_type: "CUSTOM_EVENT", classifications: "{}", prompt: "Classify each log line and extract its timestamp, host and event type.", provider: "local", endpoint: "http://127.0.0.1:11434", model: "qwen2.5:3b-instruct", token_env: "" },
  transform: { operation: "select", columns: "timestamp, host, event_type, username, source_ip", column: "host", new_name: "server" },
  filter: { field: "event_type", operator: "equals", value: "SSH_LOGIN_FAILED" },
  aggregate: { group_by: "host" },
  preprocess: { operation: "drop_duplicates", columns: "", strategy: "median", fill_value: "0", label_column: "label", text_column: "raw_message", sequence_column: "event_type", timestamp_column: "timestamp", train_fraction: "0.7", validation_fraction: "0.15", hash_features: "64" },
  check: { min_rows: "1", required_columns: "timestamp, host, event_type" },
  classify: { source: "auth", month: "2026-07" }, observations: { source: "auth", view: "sessions" }, features: { source: "auth" },
  detect: { source: "auth", detector: "isolation_forest" }, evidence: { source: "auth" },
  sigma: { source: "auth", yaml: "title: Studio failed login\nstatus: experimental\nlogsource:\n  category: authentication\ndetection:\n  selection:\n    event_type: SSH_LOGIN_FAILED\n  condition: selection\nlevel: medium" },
  labels: { column: "event_type", mapping: '{"SSH_LOGIN_FAILED": "Failed login", "SSH_LOGIN_ACCEPTED": "Accepted login"}' },
  unsupervised: { algorithm: "isolation_forest", columns: "", contamination: "0.05" },
  supervised: { algorithm: "random_forest", label_column: "label", features: "", test_fraction: "0.25" },
  evaluate: { method: "classification", label_column: "label", prediction_column: "prediction", score_column: "score" },
  report: { title: "Pipeline investigation" }, output: { name: "Failed login sample" },
};

export function blockOf(kind: BlockKind): BlockDefinition { return BLOCKS.find((block) => block.kind === kind)!; }
/** The editor permits passthrough recipes between phases; validateDraft resolves their upstream contracts. */
export function compatible(from: BlockKind, to: BlockKind): boolean {
  const output = blockOf(from)?.output, input = blockOf(to)?.input;
  return Boolean(input && output && (input === output || input === "table" && output !== "report" || PASSTHROUGH_KINDS.has(from) && input !== "report"));
}
let nextId = 0;
function identifier(prefix: string): string { return `${prefix}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now().toString(36)}-${++nextId}`}`; }
export function createNode(kind: BlockKind, x: number, y: number): PipelineNode {
  return { id: identifier(kind), kind, x, y, label: blockOf(kind).label, config: { ...DEFAULTS[kind] } };
}
export function emptyDraft(): PipelineDraft { return { version: 1, id: identifier("flow"), name: "Untitled pipeline", nodes: [], edges: [] }; }
export function starterDraft(): PipelineDraft {
  const kinds: BlockKind[] = ["sql", "filter", "check", "output"];
  const nodes = kinds.map((kind, index) => ({ ...createNode(kind, 64 + Math.min(index, 2) * 280, index === 3 ? 288 : 80), id: `starter-${kind}` }));
  return { version: 1, id: identifier("flow"), name: "Authentication sanity check", nodes,
    edges: nodes.slice(1).map((node, i) => ({ id: `starter-edge-${i}`, from: nodes[i].id, to: node.id })) };
}

/** Read an untrusted saved/imported document without requiring a finished or runnable graph. */
export function parseDraft(value: unknown): PipelineDraft {
  const object = (input: unknown, label: string): Record<string, unknown> => {
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(`${label} must be an object.`);
    return input as Record<string, unknown>;
  };
  const text = (input: unknown, label: string, max: number): string => {
    if (typeof input !== "string" || input.length > max) throw new Error(`${label} must be text of at most ${max.toLocaleString("en")} characters.`);
    return input;
  };
  const id = (input: unknown, label: string): string => {
    const result = text(input, label, 120);
    if (!result || !/^[A-Za-z0-9_-]+$/.test(result)) throw new Error(`${label} must contain letters, digits, underscores or hyphens.`);
    return result;
  };
  const data = object(value, "Pipeline draft");
  if (data.version !== 1) throw new Error("This pipeline document version is not supported.");
  if (!Array.isArray(data.nodes) || data.nodes.length > 100) throw new Error("A draft can contain at most 100 blocks.");
  if (!Array.isArray(data.edges) || data.edges.length > 200) throw new Error("A draft can contain at most 200 connections.");
  const nodes = data.nodes.map((entry, index): PipelineNode => {
    const node = object(entry, `Block ${index + 1}`), kind = node.kind as BlockKind;
    if (!BLOCKS.some((definition) => definition.kind === kind)) throw new Error(`Block ${index + 1} has an unsupported type.`);
    for (const key of ["x", "y"]) {
      if (typeof node[key] !== "number" || !Number.isFinite(node[key]) || Math.abs(node[key] as number) > 100_000) throw new Error(`Block ${index + 1} has an invalid ${key} coordinate.`);
    }
    const raw = object(node.config, `Block ${index + 1} settings`), settings = Object.entries(raw);
    if (settings.length > 40) throw new Error(`Block ${index + 1} has too many settings.`);
    const config = Object.fromEntries(settings.map(([key, setting]) => [text(key, "Setting name", 80), text(setting, `Setting ${key.slice(0, 80)}`, kind === "csv" && key === "csv" || kind === "raw" && key === "text" ? 1_000_000 : 20_000)]));
    return { id: id(node.id, "Block ID"), kind, x: node.x as number, y: node.y as number, label: text(node.label, "Block name", 120), config };
  });
  const edges = data.edges.map((entry, index): PipelineEdge => {
    const edge = object(entry, `Connection ${index + 1}`);
    return { id: id(edge.id, "Connection ID"), from: id(edge.from, "Connection source"), to: id(edge.to, "Connection target") };
  });
  const nodeIds = new Set(nodes.map((node) => node.id)), edgeIds = new Set(edges.map((edge) => edge.id));
  if (nodeIds.size !== nodes.length) throw new Error("Block IDs must be unique.");
  if (edgeIds.size !== edges.length) throw new Error("Connection IDs must be unique.");
  if (edges.some((edge) => !nodeIds.has(edge.from) || !nodeIds.has(edge.to))) throw new Error("A connection points to a missing block.");
  return { version: 1, id: id(data.id, "Pipeline ID"), name: text(data.name, "Pipeline name", 120), nodes, edges };
}

const columnsOf = (rows: SampleRow[]): string[] => [...new Set(rows.flatMap((row) => Object.keys(row)))];
const list = (value: string | undefined): string[] => (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
const fieldName = /^[A-Za-z_][A-Za-z0-9_]*$/;
const isAdapter = (kind: BlockKind) => BACKEND_KINDS.has(kind);
function requireColumns(columns: string[], available: string[], context: string): void {
  const missing = columns.filter((column) => !available.includes(column));
  if (missing.length) throw new Error(`${context}: missing column${missing.length === 1 ? "" : "s"} ${missing.join(", ")}.`);
}

interface ParsedSql { columns: string[] | null; where?: { field: string; value: SampleValue }; limit: number }
function parseSql(query: string): ParsedSql {
  const expression = query.trim().replace(/;\s*$/, "");
  const match = /^SELECT\s+(\*|[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*)\s+FROM\s+sample_events(?:\s+WHERE\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('(?:[^']|'')*'|-?\d+(?:\.\d+)?|NULL|TRUE|FALSE))?(?:\s+LIMIT\s+(\d+))?\s*$/i.exec(expression);
  if (!match) throw new Error("Sample SQL supports SELECT columns FROM sample_events with optional WHERE column = literal and LIMIT. Other SQL needs the future database adapter.");
  let where: ParsedSql["where"];
  if (match[2]) {
    const literal = match[3];
    const value: SampleValue = literal.startsWith("'") ? literal.slice(1, -1).replace(/''/g, "'") : /^null$/i.test(literal) ? null : /^true$/i.test(literal) ? true : /^false$/i.test(literal) ? false : Number(literal);
    where = { field: match[2], value };
  }
  const limit = match[4] === undefined ? 1000 : Number(match[4]);
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > 1000) throw new Error("Sample SQL LIMIT must be between 0 and 1,000.");
  return { columns: match[1] === "*" ? null : list(match[1]), where, limit };
}

interface Table { rows: SampleRow[]; columns: string[] }
function csvTable(text: string, maxRows = 1000): Table {
  if (text.length > 1_000_000) throw new Error("CSV is limited to 1 MB.");
  const records: string[][] = [];
  let row: string[] = [], value = "", quoted = false, closed = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (quoted && text[i + 1] === '"') { value += '"'; i++; }
      else if (quoted) { quoted = false; closed = true; }
      else if (value === "" && !closed) quoted = true;
      else throw new Error("CSV quotes must surround an entire value.");
    } else if (ch === "," && !quoted) { row.push(value); value = ""; closed = false; }
    else if ((ch === "\n" || ch === "\r") && !quoted) {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(value); if (row.length > 1 || row.some((cell) => cell !== "")) records.push(row); row = []; value = ""; closed = false;
    } else if (closed && !quoted) throw new Error("CSV has text after a closing quote.");
    else value += ch;
  }
  if (quoted) throw new Error("CSV contains an unclosed quoted value.");
  row.push(value); if (row.length > 1 || row.some((cell) => cell !== "")) records.push(row);
  if (!records.length) throw new Error("CSV needs a header row.");
  const columns = records.shift()!.map((column) => column.trim());
  if (columns.some((column) => !column) || new Set(columns).size !== columns.length) throw new Error("CSV column names must be non-empty and unique.");
  if (records.length > maxRows) throw new Error(`CSV exceeds this execution's ${maxRows.toLocaleString("en")}-row limit.`);
  const rows = records.map((values, i) => {
    if (values.length !== columns.length) throw new Error(`CSV row ${i + 2} has ${values.length} values; expected ${columns.length}.`);
    return Object.fromEntries(columns.map((column, at) => [column, values[at]])) as SampleRow;
  });
  return { rows, columns };
}

function configIssues(node: PipelineNode): string[] {
  const c = node.config, errors: string[] = [];
  const required = (key: string, label: string) => { if (!c[key]?.trim()) errors.push(`${label} is required.`); };
  const jsonObject = (key: string, label: string) => {
    try {
      const value: unknown = JSON.parse(c[key] ?? "");
      if (!value || typeof value !== "object" || Array.isArray(value)) errors.push(`${label} must be a JSON object.`);
    } catch { errors.push(`${label} must be valid JSON.`); }
  };
  const fraction = (key: string, label: string, minimum: number, maximum: number) => {
    if (!c[key]?.trim() || !Number.isFinite(Number(c[key])) || Number(c[key]) < minimum || Number(c[key]) > maximum) errors.push(`${label} must be between ${minimum} and ${maximum}.`);
  };
  const url = (key: string, label: string) => {
    try { if (!["http:", "https:"].includes(new URL(c[key]).protocol)) throw new Error(); }
    catch { errors.push(`${label} must be an HTTP or HTTPS URL.`); }
  };
  if (!node.label.trim()) errors.push("Give this block a name.");
  if (node.kind === "sql") { try { parseSql(c.query ?? ""); } catch (error) { errors.push(String((error as Error).message)); } }
  if (node.kind === "csv") { try { csvTable(c.csv ?? "", 100_000); } catch (error) { errors.push(String((error as Error).message)); } }
  if (node.kind === "api") url("url", "API address");
  if (node.kind === "database") { required("database", "Database"); required("query", "Read-only SQL query"); }
  if (node.kind === "raw") required("text", "Raw log text");
  if (["raw", "classify"].includes(node.kind) || node.kind === "parse" && c.method === "builtin") {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(c.month ?? "")) errors.push("Log month must use YYYY-MM.");
  }
  if (node.kind === "parse") {
    if (c.method === "regex") required("regex", "Parsing regular expression");
    if (c.method === "manual") jsonObject("classifications", "Manual classifications");
    if (["llm", "llm_regex"].includes(c.method)) { required("prompt", "Parsing instruction"); required("model", "Model"); url("endpoint", "Model endpoint"); }
  }
  if (c.token_env && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(c.token_env)) errors.push("The token setting must name a server environment variable.");
  if (node.kind === "filter") {
    required("field", "Filter column");
    if (!["equals", "not_equals", "contains", "greater_than", "less_than"].includes(c.operator)) errors.push("Choose a filter condition.");
    if (["greater_than", "less_than"].includes(c.operator) && (!c.value?.trim() || !Number.isFinite(Number(c.value)))) errors.push("A numeric filter needs a numeric value.");
  }
  if (node.kind === "transform") {
    if (c.operation === "select") required("columns", "Columns to keep");
    else if (c.operation === "rename") { required("column", "Original column"); required("new_name", "New column name"); }
    else errors.push("Choose a column transformation.");
  }
  if (node.kind === "aggregate") { required("group_by", "Grouping column"); if (c.group_by === "count") errors.push("Choose a grouping column other than count; count is the output measure."); }
  if (node.kind === "check") {
    if (!c.min_rows?.trim() || !Number.isSafeInteger(Number(c.min_rows)) || Number(c.min_rows) < 0 || Number(c.min_rows) > 100_000) errors.push("Minimum rows must be a whole number from 0 to 100,000.");
  }
  if (node.kind === "preprocess") {
    if (["hash_text", "hash_sequence"].includes(c.operation)) {
      required(c.operation === "hash_text" ? "text_column" : "sequence_column", c.operation === "hash_text" ? "Text column" : "Sequence column");
      if (!Number.isInteger(Number(c.hash_features)) || Number(c.hash_features) < 8 || Number(c.hash_features) > 4096) errors.push("Hash features must be a whole number from 8 to 4,096.");
    }
    if (["time_features", "chronological_split"].includes(c.operation)) required("timestamp_column", "Timestamp column");
    if (c.operation === "chronological_split") {
      fraction("train_fraction", "Training fraction", 0.1, 0.9);
      if (!c.validation_fraction?.trim() || !Number.isFinite(Number(c.validation_fraction)) || Number(c.validation_fraction) < 0 || Number(c.train_fraction) + Number(c.validation_fraction) >= 1) errors.push("Validation fraction must be non-negative and leave a non-empty test split.");
    }
  }
  if (node.kind === "sigma") required("yaml", "Sigma rule");
  if (node.kind === "labels") { required("column", "Source column"); jsonObject("mapping", "Label mapping"); }
  if (node.kind === "unsupervised") fraction("contamination", "Expected anomaly fraction", 0.001, 0.5);
  if (node.kind === "supervised") { required("label_column", "Label column"); fraction("test_fraction", "Test fraction", 0.1, 0.5); }
  if (node.kind === "evaluate") {
    if (["classification", "regression"].includes(c.method)) required("label_column", "True-label column");
    if (c.method === "anomaly") required("score_column", "Score column");
    else required("prediction_column", "Prediction column");
  }
  if (node.kind === "output") required("name", "Output name");
  if (node.kind === "report") required("title", "Report title");
  for (const field of BLOCK_FIELDS[node.kind]) {
    const applicable = !(node.kind === "preprocess" && field.key === "strategy" && c.operation !== "impute")
      && !(node.kind === "parse" && field.key === "provider" && !["llm", "llm_regex"].includes(c.method))
      && !(node.kind === "parse" && field.key === "source" && c.method !== "builtin");
    if (applicable && field.type === "select" && field.options && !field.options.some((option) => option.value === c[field.key])) errors.push(`Choose a valid ${field.label.toLowerCase()}.`);
  }
  return [...new Set(errors)];
}

export function validateDraft(draft: PipelineDraft): ValidationResult {
  const issues: FlowIssue[] = [];
  const error = (message: string, nodeId?: string) => issues.push({ severity: "error", message, nodeId });
  const warning = (message: string, nodeId?: string) => issues.push({ severity: "warning", message, nodeId });
  if (!draft.name.trim()) error("Give the pipeline a name.");
  if (!draft.nodes.length) error("Add a source block to start a pipeline.");
  const byId = new Map<string, PipelineNode>();
  for (const node of draft.nodes) {
    if (byId.has(node.id)) error("Block IDs must be unique.", node.id);
    byId.set(node.id, node);
    if (!blockOf(node.kind)) { error("This draft contains an unknown block type.", node.id); continue; }
    if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) error("Block coordinates must be finite numbers.", node.id);
    for (const message of configIssues(node)) error(message, node.id);
  }
  const incoming = new Map(draft.nodes.map((node) => [node.id, [] as string[]]));
  const outgoing = new Map(draft.nodes.map((node) => [node.id, [] as string[]]));
  const edgeIds = new Set<string>(), pairs = new Set<string>();
  for (const edge of draft.edges) {
    if (edgeIds.has(edge.id)) error("Connection IDs must be unique.");
    edgeIds.add(edge.id);
    const from = byId.get(edge.from), to = byId.get(edge.to), pair = `${edge.from}\u0000${edge.to}`;
    if (!from || !to) { error("A connection points to a missing block."); continue; }
    if (pairs.has(pair)) error("Remove the duplicate connection.", edge.to);
    pairs.add(pair);
    incoming.get(edge.to)!.push(edge.from); outgoing.get(edge.from)!.push(edge.to);
    if (from.id === to.id) error("A block cannot connect to itself.", to.id);
  }
  for (const node of draft.nodes) {
    const definition = blockOf(node.kind);
    if (!definition) continue;
    const inputs = incoming.get(node.id)!;
    if (definition.input && inputs.length !== 1) error(inputs.length ? "This block accepts one incoming connection. Merge blocks are not available yet." : "Connect an upstream block to this input.", node.id);
    if (!definition.input && inputs.length) error("Source blocks cannot have incoming connections.", node.id);
    if (!outgoing.get(node.id)!.length && !["output", "report"].includes(node.kind)) warning("This branch has no output block.", node.id);
  }
  if (draft.nodes.length) {
    const connected = new Set<string>(), queue = [draft.nodes[0].id];
    while (queue.length) {
      const id = queue.shift()!; if (connected.has(id)) continue; connected.add(id);
      queue.push(...incoming.get(id)!, ...outgoing.get(id)!);
    }
    if (connected.size !== byId.size) warning("The canvas has disconnected branches. Connect them or keep each workflow in its own draft.");
  }
  const degree = new Map([...incoming].map(([id, entries]) => [id, entries.length]));
  const ready = draft.nodes.filter((node) => degree.get(node.id) === 0).map((node) => node.id), order: string[] = [];
  while (ready.length) {
    const id = ready.shift()!; order.push(id);
    for (const target of outgoing.get(id)!) { degree.set(target, degree.get(target)! - 1); if (degree.get(target) === 0) ready.push(target); }
  }
  if (order.length !== byId.size) error("The pipeline contains a cycle. Connections must flow in one direction.");
  // Row-preserving recipes retain the upstream phase contract rather than erasing events or features.
  const contracts = new Map<string, DataContract>();
  for (const id of order) {
    const node = byId.get(id)!, definition = blockOf(node.kind);
    if (!definition) continue;
    const source = incoming.get(id)?.[0], upstream = source ? contracts.get(source) : undefined;
    contracts.set(id, PASSTHROUGH_KINDS.has(node.kind) && upstream ? upstream : definition.output);
  }
  for (const edge of draft.edges) {
    const from = byId.get(edge.from), to = byId.get(edge.to);
    if (!from || !to || !blockOf(to.kind)) continue;
    const output = contracts.get(from.id), input = blockOf(to.kind).input;
    if (output && !(input === output || input === "table" && output !== "report")) error(`${from.label} outputs ${output}; ${to.label} needs ${input ?? "no input"}.`, to.id);
  }
  return { valid: !issues.some((issue) => issue.severity === "error"), issues, order };
}

function execute(node: PipelineNode, upstream?: Table): { table: Table; message: string } {
  const c = node.config;
  if (node.kind === "sql") {
    const query = parseSql(c.query);
    const columns = query.columns ?? columnsOf(SAMPLE_EVENTS);
    requireColumns([...columns, ...(query.where ? [query.where.field] : [])], columnsOf(SAMPLE_EVENTS), "SQL query");
    const rows = SAMPLE_EVENTS.filter((row) => !query.where || row[query.where.field] === query.where.value).slice(0, query.limit)
      .map((row) => Object.fromEntries(columns.map((column) => [column, row[column]])));
    return { table: { rows, columns }, message: `${rows.length} rows from the built-in sample database.` };
  }
  if (node.kind === "csv") { const table = csvTable(c.csv); return { table, message: `${table.rows.length} rows parsed from the configured CSV.` }; }
  if (!upstream) throw new Error("No upstream sample data is available.");
  const rows = upstream.rows.map((row) => ({ ...row })), available = upstream.columns;
  if (node.kind === "filter") {
    requireColumns([c.field], available, "Filter");
    const kept = rows.filter((row) => {
      const value = row[c.field];
      if (c.operator === "equals") return String(value ?? "") === c.value;
      if (c.operator === "not_equals") return String(value ?? "") !== c.value;
      if (c.operator === "contains") return String(value ?? "").includes(c.value);
      if (value === null || String(value).trim() === "" || !Number.isFinite(Number(value))) return false;
      return c.operator === "greater_than" ? Number(value) > Number(c.value) : Number(value) < Number(c.value);
    });
    return { table: { rows: kept, columns: available }, message: `Kept ${kept.length} of ${rows.length} rows.` };
  }
  if (node.kind === "transform") {
    if (c.operation === "select") {
      const columns = list(c.columns); requireColumns(columns, available, "Select columns");
      if (new Set(columns).size !== columns.length) throw new Error("Select each column only once.");
      return { table: { rows: rows.map((row) => Object.fromEntries(columns.map((column) => [column, row[column]]))), columns }, message: `Selected ${columns.length} columns.` };
    }
    requireColumns([c.column], available, "Rename column");
    if (!fieldName.test(c.new_name)) throw new Error("The new column name must start with a letter or underscore and contain only letters, digits or underscores.");
    if (c.column !== c.new_name && available.includes(c.new_name)) throw new Error(`Column ${c.new_name} already exists.`);
    const columns = available.map((column) => column === c.column ? c.new_name : column);
    return { table: { rows: rows.map((row) => Object.fromEntries(available.map((column) => [column === c.column ? c.new_name : column, row[column]]))), columns }, message: `Renamed ${c.column} to ${c.new_name}.` };
  }
  if (node.kind === "aggregate") {
    requireColumns([c.group_by], available, "Group & count");
    const groups = new Map<string, { value: SampleValue; count: number }>();
    for (const row of rows) {
      const value = row[c.group_by], key = JSON.stringify(value), group = groups.get(key);
      if (group) group.count++; else groups.set(key, { value, count: 1 });
    }
    return { table: { rows: [...groups.values()].map((group) => ({ [c.group_by]: group.value, count: group.count })), columns: [c.group_by, "count"] }, message: `${rows.length} rows grouped into ${groups.size} values.` };
  }
  if (node.kind === "check") {
    const required = list(c.required_columns); requireColumns(required, available, "Sanity check");
    if (rows.length < Number(c.min_rows)) throw new Error(`Sanity check expected at least ${c.min_rows} rows; received ${rows.length}.`);
    const empty = rows.filter((row) => required.some((column) => row[column] === null || String(row[column]).trim() === "")).length;
    if (empty) throw new Error(`Sanity check found ${empty} rows with empty required values.`);
    return { table: { rows, columns: available }, message: `${rows.length} rows passed; ${required.length} required columns have values.` };
  }
  if (node.kind === "output") return { table: { rows, columns: available }, message: `${c.name}: ${rows.length} sample rows ready to inspect.` };
  throw new Error("This phase adapter is not connected to the pipeline runner yet.");
}

export function previewDraft(draft: PipelineDraft): PipelinePreview {
  const validation = validateDraft(draft), issues = [...validation.issues], results: PreviewResult[] = [];
  if (!validation.valid) return { ...validation, results, rows: [] };
  const tables = new Map<string, Table>(), nodes = new Map(draft.nodes.map((node) => [node.id, node]));
  for (const id of validation.order) {
    const node = nodes.get(id)!, incoming = draft.edges.find((edge) => edge.to === id);
    if (isAdapter(node.kind) || incoming && !tables.has(incoming.from)) {
      const message = isAdapter(node.kind) ? "This operator requires backend execution; the offline sample preview did not run it." : "Upstream block did not produce sample data.";
      if (isAdapter(node.kind)) issues.push({ severity: "warning", nodeId: id, message });
      results.push({ nodeId: id, rows: 0, columns: [], sample: [], status: "skipped", message });
      continue;
    }
    try {
      const { table, message } = execute(node, incoming ? tables.get(incoming.from) : undefined);
      tables.set(id, table);
      results.push({ nodeId: id, rows: table.rows.length, columns: table.columns, sample: table.rows.slice(0, 20), status: "passed", message });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      issues.push({ severity: "error", nodeId: id, message });
      results.push({ nodeId: id, rows: 0, columns: [], sample: [], status: "failed", message });
    }
  }
  const leaves = validation.order.filter((id) => !draft.edges.some((edge) => edge.from === id));
  const rows = leaves.flatMap((id) => tables.get(id)?.rows ?? []);
  return { valid: !issues.some((issue) => issue.severity === "error"), issues, order: validation.order, results, rows };
}
