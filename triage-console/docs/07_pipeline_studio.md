# Pipeline Studio: first increment

Pipeline Studio introduces a visual development platform in the same repository as Project DAD. Its purpose is to
compose independent data-processing steps, inspect a small sanity-check run, then run the complete flow. It begins as
an Advanced-mode page under **Develop**, beside the existing Prepare and Detect pages.

## Scope of this increment

The browser provides a block library, a canvas of nodes and connections, block settings, graph validation, sample
results and portable JSON drafts. Supported table operations run on fabricated in-browser rows. DAD phase blocks
represent intended integration points; their Python execution is not exposed through this prototype.

No service endpoint, database schema, pipeline CLI behaviour or existing analyst workflow changes for this increment.
Drafts stay in browser storage, and full execution remains unavailable until the service layer exists.

## Boundaries

| Part | Responsibility |
|---|---|
| Flow model | Versioned draft structure, block definitions, input/output types, graph validation and deterministic sample execution. |
| Studio page | Canvas interaction, selection, configuration, preview presentation and draft import/export. |
| Future execution service | Resolve inputs, validate permissions, plan dependencies, run supported adapters, and retain run status and artifacts. |
| DAD adapters | Call the existing parsers, observation builders, feature builders and detectors without copying their logic into the editor. |

The flow model does not depend on review labels, report storage or the console's selected log type. This keeps the
platform useful for a generic query-and-transform flow as well as a DAD analysis flow.

## Next increments

1. Define a block execution contract: typed named inputs and outputs, validated configuration, a version, sample
   capability, artifact references and execution status. Keep schemas and provenance with the artifacts.
2. Add a server-side planner and run record. Validate the graph before starting work, support cancellation and
   failure propagation, and keep sample runs distinct from full runs.
3. Connect table sources and transformations first. Reuse the existing SQL password and read-only safeguards for
   live queries; do not introduce an independent SQL execution path.
4. Wrap existing pipeline phases as adapters. Preserve source-specific applicability, chronological splits,
   training-only fitting, evidence lineage and artifact contracts.
5. Add durable flow versions, reusable subflows and run history. Retire individual Prepare or Detect pages only
   after their workflows are covered and their migration is agreed.

## Sample and full execution

A sample run should use a bounded, explicit input with its own artifact location. A later full run should use the
same validated block definitions and configuration. Small previews cannot promise parity for context-dependent
operations such as sessions, complete time windows or training statistics; those blocks need an explicit sampling
strategy before execution is enabled.

Imported JSON is configuration data. It must never become arbitrary Python, JavaScript or shell execution. Real
execution belongs to registered adapters with validated settings and the existing service's authorization checks.
