# Pipeline Studio

Open **Advanced → Develop → Pipeline Studio** to build a flow from connected blocks.
This is the first working interface for the development platform that will grow alongside Project DAD.
Prepare and Detect remain available while the platform develops.

## Build a flow

1. Start with the example flow, or create a blank draft.
2. Drag a block from the library onto the canvas. Blocks represent sources, transformations,
   checks, detection steps and outputs.
3. Connect an output to the next block's input. A block's input and output types show which steps fit together.
4. Select a block to change its name and settings in the panel beside the canvas.
5. Validate the flow, then preview it with the supplied sample rows. Inspect each step's results before changing it.

The first example demonstrates a small sanity check: take a table, transform or filter it,
check the result and inspect the output. The block library also introduces the existing DAD phases as building blocks.

## What a preview does

Validation checks the graph and block settings, including broken connections, incompatible data types and cycles.
A preview runs supported table operations **in this browser**, using the fabricated example rows or a small CSV table
you enter in a CSV block. Its result shows
whether the chosen check passes for those rows; it does not establish that the same check passes on a complete dataset.

The SQL block describes a future query against an existing database. The current preview understands only the
documented sample-query subset and rejects unsupported SQL. It does not open a pipeline database or use the SQL password.
Blocks for DAD's Python phases are planning blocks until execution adapters are connected.

Full pipeline execution, live SQL, model training and scheduled runs are not connected in this first version.

## Keep and share a draft

Drafts are kept in this browser on this computer. They are separate from reports, review labels and the console's
SQLite database. Export a draft as JSON to keep a portable copy, and import that JSON to continue editing it.
Browser storage can be cleared, so export work you want to keep.

A draft records blocks, settings, positions and connections, including any CSV text you entered. It does not include
trained models or execution results. Inspect the CSV contents, paths and query text before sharing the JSON.

## Where this is heading

The next step is an execution service with a small sample run before a full run, reusable adapters for the existing
pipeline phases, and connections to the console's guarded read-only SQL service. The development platform shares this
repository with DAD, but the flow definition and graph rules are kept separate from the analyst's review workflow.

See [Pipeline Studio design](../07_pipeline_studio.md) for the integration plan.
