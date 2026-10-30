# Project DAD Console — core whitepaper content review

Assessment date: 12 October 2026. Reviewed `TECHNICAL_WHITEPAPER.tex` and its companion appendices against published whitepapers and audience guidance. The assessment below records the extended edition; the authorised simplification has now been implemented as described in the final section.

## Finding

The core paper contains more implementation and operating detail than the stated high-level audience needs. It currently combines a capability argument, a methods reference and an application manual. The content is useful, but much of it belongs in the companion document so that the core can focus on the problem, proposed capability, demonstrated evidence, limits and recommended next step.

This assessment is based on purpose and audience, rather than an assumed universal page limit. The current source has **20 user-guide screenshot calls**, **21 displayed equation environments**, and **18 long tables in the numbered chapters**, plus the front-matter version-history table. These are source counts, not rendered page counts. No current PDF was compiled, so an exact page reduction is not claimed.

## Published comparisons

| Source reviewed | Relevant observation | Application to this paper |
|---|---|---|
| [Purdue OWL: White Paper — Purpose and Audience](https://owl.purdue.edu/owl/subject_specific_writing/professional_technical_writing/white_papers/index.html) | Describes a whitepaper as a problem/solution argument shaped around reader needs. | Lead with the internal capability gap and evidence of what the workbench enables. The core need not teach every interface control. |
| [Google Infrastructure Security Design Overview](https://docs.cloud.google.com/docs/security/infrastructure/design/resources/google_infrastructure_whitepaper_fa.pdf), June 2024, 16 PDF pages | Explicitly addresses security executives, architects and auditors; organises the explanation by security layers and points to further detail. | Closest audience comparison: keep meaningful technical explanations and their consequences, while referring engineers to supporting material. |
| [Hybrid Cloud with AWS](https://docs.aws.amazon.com/pdfs/whitepapers/latest/hybrid-cloud-with-aws/hybrid-cloud-with-aws.pdf), 26 PDF pages | Moves from use cases and architectural principles to an implementation framework and an example. The publication is marked as historical reference. | A technical paper can be longer when its detail supports architectural decisions. Its structure is a useful comparison, not current product advice. |
| [An Overview of the AWS Cloud Adoption Framework](https://docs.aws.amazon.com/pdfs/whitepapers/latest/overview-aws-cloud-adoption-framework/overview-aws-cloud-adoption-framework.pdf), 42 PDF pages | Demonstrates that published whitepapers can extend well beyond a short executive brief. | Length alone does not establish bloat; scope and reader purpose matter. |
| [Michael A. Stelzner: How to Write a White Paper](https://www.cla.purdue.edu/academic/english/pw/images/stelzner-whitepapers.pdf), 2007, hosted by Purdue | Advises audience-specific treatment, useful visuals and brevity; suggests 12 pages or fewer. | Helpful historical editorial guidance, not a formal standard or binding length requirement. |

These publications are a small comparison set, not a statistical survey of all whitepapers. The migration recommendations below are my editorial judgement about Project DAD, not requirements imposed by these sources.

## Priority moves from the core

| Priority | Current material | Move to companion appendix | Keep in the core |
|---|---|---|---|
| 1 | Chapter 4, **Application User Guide** | Entire page-by-page guide, its 20 screenshots, navigation instructions, form fields and password/removal steps. Suggested new Appendix G: User guide. | A compact Upload → Analyze → Map → Review diagram and one end-to-end example. At most one or two illustrative console images. |
| 1 | Chapter 2.1, **Observations, Features and Evidence** | Exact matrix shapes, feature-block dimensions, worked hash-bucket table and encoding mechanics. Suggested Appendix H: Feature and projection reference. | The event/session/window distinction, source lineage, three feature categories and a short warning about collisions. |
| 1 | Chapter 2.3, **Feature Selection and Ensembles** | Six-step selection procedure, counts removed at each step and detailed model-screening checks. Suggested Appendix I: Detector and calibration reference. | Why selection is used, why models are combined, how consensus differs from score averaging, and why proxy metrics are not attack recall. |
| 2 | Chapter 2.2, **Complementary Anomaly Detectors** | Full 13-family catalogue, assumptions for each family and general detector equations. | Three or four complementary ideas with a small visual comparison. Mention the model zoo as implemented breadth, not as proof of accuracy. |
| 2 | Chapters 2.4, 3.6 and 3.7, sequence methods | Support/confidence/lift calculations, the five-session exercise, mining settings, transition smoothing/backoff details and equations. Suggested Appendix J: Sequence and alert-profile reference. | A familiar event sequence versus a rare next step. Clearly distinguish routine discovery from the actual transition-surprise alert score. |
| 2 | Chapter 3.1, architecture | Full phase-by-phase worked-example table. | One architecture diagram and a short explanation of batch analytics, the local service and human review. |
| 2 | Chapter 3.3, **Pattern Discovery** | Detailed regex-building walkthrough and workbench function table; consolidate with the moved user guide. | One paragraph: unknown formats are surfaced, people test parser rules, and adoption into Analyze is still manual. |
| 2 | Chapter 3.4, calibration | Million-observation arithmetic, exact purge-gap examples and detailed tie handling. | Chronological train/validation/test design, calibration purpose and the absence of a guaranteed future daily cap. |
| 2 | Front-matter **Version History** | Detailed release chronology and test totals. Suggested Appendix K: Release and implementation record. | Edition date, current release/workspace baseline and a short summary of implemented versus unfinished capability. |
| 3 | Chapter 5, **Results** | Full routine cataloguing/reconstruction tables, complete per-source detector breakdowns, detailed overlap counts and test inventories. Suggested Appendix L: Detailed results. | One population/scope table, one complementary-finding example and a concise account of demonstrated workflow behaviour. Keep denominators and qualifications next to claims. |
| 3 | Chapter 5.6, operational acceptance | Full acceptance-test matrix, owners, procedures and detailed metrics. | The critical acceptance gates: independently reviewed labels, benign-change testing, workload evaluation and deployment governance. |

The appendix already contains the evidence register, metric definitions, draft-change history, API, parsing patterns and mined routines. Retain those as supporting material. Add the new sections once; avoid copying the same material into multiple appendix sections.

## Material to shorten carefully rather than remove

**Novelty.** Keep the fixed-training-reference explanation, including the answer that 100 repetitions in test do not update the baseline. Use either the timeline figure or chronological log illustration as the main example. The formula and extended calibration discussion can move to the detector reference. Retain the warning that unseen behaviour does not necessarily survive encoding/selection or cross the threshold.

**Whitelisting.** Keep the post-scoring branch diagram and a short account of exact user/server scope, active expiry, every-named-account matching and retained scores. Mention that account-level exceptions can also cover failed logins and do not establish benignness. Move the form walkthrough and matching truth table into the user guide. State that IP whitelisting is not implemented; do not obscure this distinction in a technical appendix.

**Frozen runtime.** Keep one clear paragraph about what is retained and what was purged. A reader needs to know that new uploads can be scored and reviewed, while historical raw evidence cannot be recovered. Historical results must remain explicitly historical.

**Reports and governance.** Keep evidence retention, human decisions and versioned reports as outcomes. Move transaction details, optimistic version checks, digest mechanics and exhaustive feature lists to technical reference, while retaining any qualification necessary to interpret a claim.

**Optional AI.** One short status paragraph is sufficient in the core: local assistance is optional, generated interpretations need review, independently trained maliciousness classification and the label feedback loop remain unfinished.

## Proposed revised core structure

Add an unnumbered executive summary before the contents. It should state the problem, what works now, the strongest evidence, the principal limit and the next operational step in roughly one page.

| Core chapter | Purpose | Editorial page budget |
|---|---|---|
| 1. Introduction and practical motivation | Explain the capability gap, intended users and scope. | 1–2 |
| 2. System overview and analyst workflow | Show the architecture and one complete operator-to-review example. | 2 |
| 3. Detection approach | Explain preprocessing, features, complementary models, novelty, sequence surprise and postprocessing at an assessable level. | 3–4 |
| 4. Demonstrated results | State populations, representative findings and implementation evidence with correct qualifications. | 1–2 |
| 5. Limitations and operational acceptance | Make the evidence gaps, exception risks, data availability and acceptance gates explicit. | 1–2 |
| 6. Conclusion and next step | State the justified use of the current workbench and the path to operational validation. | 1 |

Aim for approximately **10–14 numbered core pages**, excluding cover, contents, executive summary and references. This is a proposed target for this audience, not a published standard or a predicted compiled length. Preserve the requested page break before each core chapter, and check the budget after compilation rather than shrinking text or diagrams to force it.

## Migration checks

Move detailed material before deleting it from the core. Keep citations with the claims they support. Consolidate duplicated methods/guide descriptions, while preserving implementation-specific qualifications.

The core and companion appendices compile separately. Ordinary LaTeX `\ref` links do not resolve across them automatically. Replace moved-object references with explicit companion appendix/table titles, or deliberately configure cross-document referencing; do not leave labels pointing to missing objects. Move diagrams with their colour definitions, macros and required TikZ libraries. Both editions need the same screenshot directory available when compiling.

Check that the shortened core still independently explains: anomalies versus attacks; proxy metrics versus independently validated detection; calibration targets versus future workload; maps versus verdicts; whitelist overrides versus reviewed benignness; and retained runtime versus recoverable evidence. Each of these affects the reader's decision and belongs in the core even when supporting mathematics moves.

Finally, compile both documents, verify their contents and cross-references, and assess the rendered page count and diagram readability. The initial assessment did not restructure either document; the subsequent authorised migration is recorded below.

## Implemented simplification

The primary LaTeX source and Markdown core now use six substantive chapters: Introduction and practical motivation; System overview and analyst workflow; Detection approach; Demonstrated results; Limitations and operational acceptance; Conclusion and next step. The LaTeX edition adds an executive summary and retains chapter page breaks and its own references.

The core replaces exhaustive inventories and equations with a workflow diagram, three concise explanatory/result tables and prose. It retains the novelty repetition example, actual user-whitelist semantics, historical result denominators, proxy-metric limitations and frozen-runtime evidence restrictions.

All former core chapter bodies were preserved in the companion, including the extended conclusion within detailed results. The full release table was migrated too. This preserves details for technical review rather than discarding them. Existing Appendices A–F remain, followed by:

| Appendix | Implemented contents |
|---|---|
| G | Detailed requirements and technique reference |
| H | Mathematical methods and feature reference |
| I | Detailed implementation and analyst workflow |
| J | Application user guide and screenshots |
| K | Detailed historical results and acceptance programme |
| L | Application version history |

The implemented grouping preserves the former chapters as coherent reference sections; it differs from the earlier provisional grouping in the migration table above. The companion has its own bibliography, and local references resolve without requiring the core document's auxiliary files. Structural validation checked balanced environments/braces, unique labels, local references, bibliography entries, screenshot files, appendix ordering and chapter breaks. The core has no screenshot calls or displayed-equation environments; all 20 original user-guide screenshots remain in the companion.

PDF compilation and rendered page counts remain unverified. No LaTeX compiler is installed; downloading the official portable Tectonic compiler was blocked by the network's file-download policy. Both sources can be compiled independently with pdfLaTeX on Overleaf or an existing local installation, using the supplied `figures/` directory for the companion. Compile twice to resolve references and contents.
