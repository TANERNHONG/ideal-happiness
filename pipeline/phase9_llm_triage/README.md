# Phase 9: LLM triage into four categories

A local small language model (SLM) reads each alert's original log lines and
places it in one of four categories:

| Category | Meaning |
|---|---|
| `security_relevant` | Hostile or unauthorised activity is shown or reasonably suggested, even if it was blocked or failed |
| `operationally_interesting` | Nothing hostile, but an operator should know: failing jobs, misconfiguration, agent or connectivity trouble |
| `expected_behavior` | A specific routine explanation fits every line, such as approved automation doing its usual work |
| `insufficient_context` | The lines cannot decide it, or it depends on a fact the model does not have; the answer says what is missing |

The answer also carries a confidence, the reasoning with cited line numbers,
whether approved automation was involved, the missing context, an ATT&CK
technique where one is clear, and a next step for the analyst.

## How it fits with Phases 7 and 8

```
Phase 7 alerts ──► Phase 7b: behavioural clusters ──► Phase 8: dedupe, cluster, rank ──► Phase 9: SLM categorises representatives ──► analyst confirms
                          ▲                                                                              │
                          └──────────── confirmed categories become Phase 8 training labels ◄────────────┘
```

Phase 8 is fast and decides which alerts deserve a model's time. Phase 9 is
slow (about a minute per alert on this laptop) but can weigh context, such as
the approved-automation list. Phase 8's model stays binary, `security_relevant`
against the rest, because the other three categories depend on context that
the text alone does not carry.

**The Project DAD Console** (`triage-console/`) does not run this phase yet; model
triage there is planned. Its Review page records the analyst's own label per
cluster or firewall period, using these four categories (`insufficient_context`
is called *insufficient evidence* there) plus *suspicious* (could be hostile,
not yet explained): every item *needs review* until someone
reviews it (the console's decision Q23). The analyst sees each flagged
observation's anomaly score and can fetch the logs before and after it. How
those labels become Phase 8 labels is decided in Q21 (see the Phase 8 README).

## Approved administrative automation

List approved addresses or CIDR ranges in
[site/approved_automation_ips.csv](site/approved_automation_ips.csv) (see
[site/README.md](site/README.md)). The system prompt tells the model that these
are approved administrative automation, and each alert states which of them
appear in its lines. The address matching is done in code, not by the model.

Approval shapes the judgement; it does not whitelist. Automation credentials
are a common target, so an approved address doing something automation does
not normally do (a new or privileged user, `su` to root, repeated failures,
an interactive session) is still judged on that behaviour. See
[approved_automation.md](backend/app/prompts/approved_automation.md).

To seed the list, `python pipeline/phase9_llm_triage/suggest_automation_ips.py`
writes ranked **candidates** to `data/phase9_llm_triage/automation_ip_candidates.csv`.
Confirm each one with its owner before adding it.

## Approved change windows

Planned changes, such as a migration, produce traffic that is unusual but
expected. List them in
[site/approved_change_windows.csv](site/approved_change_windows.csv): a time
window, and optionally the servers and the flow (source, destination, port,
protocol) the change involves. The system prompt lists the windows
([approved_change_windows.md](backend/app/prompts/approved_change_windows.md)),
and each alert states how many of its lines fall inside each window **and**
match its servers and flow. The matching is done in code, not by the model.
A window explains only what it names; anything else in the same period is
judged on its own. The file is empty until the change record confirms a
window.

This matters most for the IPFilter log (`--source ipf`), which is empty in
normal operation: there, the change record is often the only thing that can
say whether a burst of activity was expected.

## Setting up a local model (once)

Nothing is sent off the machine: the model runs locally behind an
OpenAI-compatible endpoint. Any of Ollama, llama.cpp `llama-server`,
LM Studio or vLLM works. With Ollama:

1. Install Ollama (check your organisation's software policy first).
2. Raise its context window **before starting it**. The prompts are about
   4,000–6,000 tokens, and a smaller window silently cuts off their start,
   where the rules and the approved list are:
   `setx OLLAMA_CONTEXT_LENGTH 8192`, then restart Ollama.
3. Pull a model:
   - `ollama pull qwen2.5:3b-instruct`: the default. It is good at strict
     JSON, uses about 2 GB, and suits a 16 GB laptop without a GPU.
   - `phi3.5` or `llama3.2:3b`: similar size, worth comparing.
   - `qwen2.5:7b-instruct`: better judgement, but about 2–3 times slower.

## Running

```
python pipeline/phase9_llm_triage/triage.py --source auth --dry-run --limit 5     # prompts only, no model
python pipeline/phase9_llm_triage/triage.py --source auth --limit 50              # top 50 by unusualness
python pipeline/phase9_llm_triage/triage.py --source ossec --representatives \
    --inputs "data/phase8_malice_classifier/to_label/ossec/*_to_label.csv"        # one alert per Phase 8 cluster
python pipeline/phase9_llm_triage/triage.py --source pf --model qwen2.5:7b-instruct --endpoint http://localhost:8080/v1
python pipeline/phase9_llm_triage/triage.py --source auth --inputs data/phase7b_clusters/auth/authlog_alerts_by_cluster.csv   # keeps cluster_id
```

Results go to `data/phase9_llm_triage/<source>/triage.csv`, one row per
distinct alert, written as the run goes. Re-running resumes; changing any
prompt, knowledge or site file, or the model, starts a new prompt version, so
results are never mixed silently.

**Time.** Expect roughly a minute per alert on this laptop's CPU. Triage the
Phase 8 representatives (about 720 across the three sources, roughly
12 hours) or the top few hundred, not all 16,801 alert rows.

**Confirming.** Fill `analyst_category` with the category you agree with. To
train Phase 8 on those rows, run
`prepare_corpus.py stage7 --inputs data/phase9_llm_triage/*/triage.csv --label-column analyst_category`.
Train only on analyst-confirmed categories, never on the model's own.

## Simulated run (hand-written baseline)

`simulate_triage.py --source ossec|pf` writes `triage_simulated.csv` in the same
layout, from hand-written analyst rules for the single-event alerts of the 2026
test period (model `claude-simulated-analyst`, status `simulated`). It adds a
`verdict` column (benign / suspicious / unknown) and a `finding` column, and
writes `triage_simulated_by_cluster.csv` with counts per Phase 7b cluster. Use it
to see what triage output should look like before a model is set up, to compare
against the SLM once `triage.py` has run, and as a source of few-shot examples.
Its rules match on message content, so they survive cluster renumbering, but they
only describe the 2026 data. Anything new falls through to `unmatched`.

## Files

| Path | Purpose |
|---|---|
| `triage.py` | The runner: inputs, prompt assembly, knowledge selection, model call, validation, output |
| `simulate_triage.py` | Hand-written baseline triage of the 2026 single-event alerts (no model) |
| `suggest_automation_ips.py` | Candidate approved-automation addresses from the auth logs |
| `site/` | Trusted, analyst-maintained context: the approved-automation list, approved change windows and optional `site_context.md` |
| `backend/app/prompts/` | Prompt templates. Triage uses `shared_rules.md`, `approved_automation.md`, `approved_change_windows.md`, `triage_categories.md`, `alert_context.md`, the primers and `repair_json.md` |
| `backend/app/knowledge/` | Attack patterns and red herrings; the entries most similar to each alert (up to 3 plus 2) are included |

The other prompts (`judge*.md`, `advocate*.md`, `cases*.md`) belong to the
original malicious/benign debate design and are not used by `triage.py`.
