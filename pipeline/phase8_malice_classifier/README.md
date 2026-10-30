# Phase 8: maliciousness classifier (BERT)

A small text classifier that reads a log message, or a sequence of messages,
and outputs **the probability that it is malicious** (0 to 1). It is built the
same way as a sentiment model: a pretrained BERT-family encoder with a
two-class head, fine-tuned on labelled examples. An off-the-shelf sentiment
model is no use here, because it scores emotional tone and log lines have none.
The encoder is reused, and the head is trained on "benign" versus "malicious".

It adds one column to the Phase 7 CSVs, `malicious_score`. This is a fast,
cheap first sort before the LLM triage (Phase 9, `../phase9_llm_triage`) or an analyst looks at
an alert. It is **not a verdict**. It only knows the attacks its training data
contained.

## Status (2026-09-29, updated 2026-10-30)

- **Ready:** packages installed, SecureBERT downloaded (`check` passes), and
  `suggest` run for all three sources. The files to label are in
  `data/phase8_malice_classifier/to_label/<source>/`:

  | Source | Phase 7 alerts | Distinct after normalising | Clusters | Rows to label (`representative = 1`) |
  |---|---|---|---|---|
  | pf | 4,413 | 400 | 40 | 41 |
  | ossec | 1,130 | 508 | 51 | 84 |
  | auth | 11,258 | 4,232 | 424 | 595 |

- **Not started:** no labels yet, no public datasets (AIT, CIC-IDS2017)
  downloaded, and no model trained.
- **Since then (2026-10-01):** all sources were re-run on 12 months, PF moved
  to the presence method (no clusters), and Phase 7 was rebuilt with
  `row_manifest_ids` (29,204 rows). The sheets above predate this and should be
  regenerated before labelling. On the current alerts, `suggest` would give
  about 592 rows to label (auth 508, OSSEC 65, PF 17, IPFilter 2) from 5,893
  distinct alerts, or about 130 with `--cluster-column cluster_id` (auth 90,
  OSSEC 40).
- **Since then (2026-10-08 to 2026-10-29):** Phase 7 also holds the sequence
  alerts (Phase 4f: auth 608, OSSEC 19) and the activity alerts (Phase 4g:
  auth 218 and OSSEC 14 from the current rule, with earlier rules' alerts kept
  in the cumulative files). Regenerate the sheets so they include both; an
  activity alert is an amount of lines, so its raw messages are the peak step's
  lines, not a single event.
- **Labels from the Project DAD Console** (`triage-console/`). Its Review page
  records an analyst label per cluster (auth, OSSEC) or firewall period (PF,
  IPFilter). Every item *needs review* until someone reviews it, and is then
  labelled *security relevant*, *suspicious*, *operationally interesting*,
  *expected behaviour* or *insufficient evidence* (decision Q23). Four of these
  are this phase's own categories (*insufficient evidence* is
  `insufficient_context`). How they become labels here was decided
  in Q21: security relevant → positive; expected behaviour and operationally
  interesting → negative; suspicious and insufficient evidence → no label
  until reviewed again. Labels given to a whole cluster will be marked as
  such.
  No export exists yet.
- In the commands below, `stage7` (as in `prepare_corpus.py stage7` or
  `--test-source stage7`) is the corpus name for our own Phase 7 alerts.

**Known issues to settle before training**

1. *The zero-shot suggestions are near 0.5 for everything* (for example, PF
   comes out 4,412 of 4,413 "malicious"). `propagate` only fills rows whose
   suggestion agrees, so on the first round benign labels hardly spread. Use
   `propagate --trust-cluster` and spot-check, or re-run `suggest --seeds`
   first.
2. *Labels do not cross files.* The same cluster gets a representative in each
   Phase 7 file it appears in (OSSEC: 84 representatives for 51 clusters).
3. *Duplicate-text leakage in `train.py`.* 985 distinct auth texts (214 for
   OSSEC) appear in more than one Phase 7 file. The split group is file plus
   view, and duplicates are only dropped within a group, so identical alerts
   can land in both train and test. Dropping duplicates on
   `["text", "label"]` fixes it.
4. *`normalise()` leaves some identifiers in:* `(pid: 1274)`, TCP `win` and
   `TS val` numbers, and dated file names. These split identical events into
   separate clusters. Fix them before labelling at scale, then re-run
   `suggest`.

## How it works

```
Phase 7 raw_messages ──split on " | "──► normalise each line ──join──► text ──► model ──► P(malicious)
public datasets + your labelled alerts ──prepare_corpus.py──► corpus CSV ──train.py──► data/phase8_malice_classifier/runs/<name>/
```

1. **Normalise** ([common.py](common.py)). Timestamps, host names, IPs,
   ephemeral ports, PIDs, MACs, key fingerprints and long IDs are replaced with
   tokens such as `<IP>` or `<PID>`. The model then learns what happened rather
   than who did it, which is the main thing that lets public data transfer to
   our logs. Service ports (`<IP>:22`), user names, Solaris message IDs
   (`[ID 800047 auth.info]`) and OSSEC codes (`ossec-agentd(4101)`) are kept,
   because they carry meaning. Training and scoring use the same function, so
   if you change it you must retrain.
2. **Sequences.** Lines are joined with `" | "`, exactly as in Phase 7.
   Anything over 40 lines keeps the first and last 20. Tokens beyond the
   model's limit (256 by default) are cut from the middle, so the model sees
   how a sequence started and how it ended.
3. **Two models** ([models.py](models.py)):
   - **Baseline:** TF-IDF on words and character n-grams, plus logistic
     regression. It trains in seconds.
   - **BERT:** `distilbert-base-uncased` (fast on a CPU) or
     `ehsanaghaei/SecureBERT` (a RoBERTa model pretrained on cybersecurity
     text). The training loop is plain PyTorch with a class-weighted loss,
     and it keeps the epoch with the best validation PR-AUC.

   Always compare the two. If BERT does not beat the baseline on your own
   alerts, use the baseline.
4. **Threshold.** `malicious_flag` uses the lowest score whose validation
   precision reaches `--target-precision` (default 0.9).

## Datasets

| Dataset | Use for | Labels | Fit with our logs |
|---|---|---|---|
| [AIT Log Data Set V2.0](https://zenodo.org/records/5789064) ([V2.1](https://zenodo.org/records/19483937)) | **auth** | Per line (JSON), including `auth.log` from 8 simulated enterprise testbeds with scans, brute force and privilege escalation | Good. It is Ubuntu OpenSSH/PAM rather than Solaris, but most sshd messages match once normalised. |
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (use `GeneratedLabelledFlows`, which include `Source IP`) | **pf** | Per flow: BENIGN, SSH-Patator, FTP-Patator, PortScan, DoS/DDoS, Bot, and others | Weak. These are flow records, not PF packet lines. They are rendered as token sentences (`flow proto=tcp dport=22 fwd_pkts=b1 flags=syn,rst`), which teach scan and flood shapes but are not our text. Kaggle has mirrors, but prefer the official copy. |
| **Your own Phase 7 alerts**, labelled | **auth, ossec, pf** | You add a `label` column | Exact. These are the rows that matter most, and the only option for OSSEC. I know of no public labelled corpus of OSSEC agent logs. |
| [Loghub OpenSSH](https://github.com/logpai/loghub/tree/master/OpenSSH) | Not for training | None | This is a lab server exposed to the internet, so it is full of brute force. Do **not** treat it as benign data. It is useful only for eyeballing sshd message variety. |

**Labelling your own alerts.** Copy a Phase 7 CSV, add a `label` column and
fill it with one of the four triage categories shared with Phase 9:
`security_relevant`, `operationally_interesting`, `expected_behavior` or
`insufficient_context`. Spaces, capitals and the old `malicious`/`benign` also
work. Leave a row blank to skip it.

The model trains on a binary target: `security_relevant` becomes malicious,
`operationally_interesting` and `expected_behavior` become benign, and
`insufficient_context` rows are skipped. The other three categories differ by
context the text does not carry, which is Phase 9's job (see
[../phase9_llm_triage/README.md](../phase9_llm_triage/README.md)). Phase 9's
`triage.csv` can be used as a labelled input with
`--label-column analyst_category`, once an analyst has confirmed the rows.

- Aim for 200 to 500 rows per log type.
- Include the red herrings on purpose. The entries in
  `../phase9_llm_triage/backend/app/knowledge/red_herrings.md` are exactly the hard
  negatives this model needs, such as scripts retrying an old password,
  internet background scanning, and agent reinstalls.
- Once the LLM triage exists, its verdicts can suggest labels, but train only
  on labels an analyst has confirmed.

## Steps

Run every command from the project root; outputs go under
`data/phase8_malice_classifier/`. Commands are shown for bash; in PowerShell,
put each command on one line.

**1. Set up.** Use Python 3.11+. A GPU is optional.

In a Jupyter notebook cell, use the line magic. It installs into the
notebook's own kernel; restart the kernel afterwards.

```
%pip install torch transformers scikit-learn pandas joblib
```

On a machine without a GPU, the CPU-only PyTorch build is a much smaller
download:

```
%pip install torch --index-url https://download.pytorch.org/whl/cpu
%pip install transformers scikit-learn pandas joblib
```

From a terminal, run the same commands without the `%`, ideally inside a
virtual environment (`python -m venv .venv`).

For an offline machine, download the models once elsewhere and copy the
folders across:

```
python -c "from transformers import AutoTokenizer, AutoModelForSequenceClassification as M; \
[ (AutoTokenizer.from_pretrained(m).save_pretrained('hf/'+m.split('/')[-1]), M.from_pretrained(m, num_labels=2).save_pretrained('hf/'+m.split('/')[-1])) \
  for m in ['distilbert-base-uncased', 'ehsanaghaei/SecureBERT'] ]"
```

Then pass `--model hf/distilbert-base-uncased`. Ignore the warning that the
classifier weights are newly initialised; that is the head you are about to
train.

**2. Download the data.**

- AIT-LDS V2: from Zenodo. Unpack all scenarios under one folder.
- CIC-IDS2017: from UNB (`GeneratedLabelledFlows.zip`).

Before converting AIT, check its layout. The converter expects
`<scenario>/gather/<host>/logs/.../auth.log`, with labels at
`<scenario>/labels/<host>/logs/.../auth.log` (one JSON object per line,
`{"line": N, "labels": [...]}`). If the layout differs, adjust `GATHER_DIR`,
`LABEL_DIR` or `--line-base`.

**3. Build the corpora.** Each command prints how many lines were labelled.
If AIT shows "0 labelled", the layout or line base is wrong.

```
python pipeline/phase8_malice_classifier/prepare_corpus.py ait    --root D:/data/AIT-LDSv2 --out data/phase8_malice_classifier/corpora/ait_auth.csv
python pipeline/phase8_malice_classifier/prepare_corpus.py cicids --root D:/data/CIC-IDS2017/GeneratedLabelledFlows --out data/phase8_malice_classifier/corpora/cicids.csv
python pipeline/phase8_malice_classifier/prepare_corpus.py stage7 --inputs "data/phase8_malice_classifier/labelled/authlog_*.csv" --out data/phase8_malice_classifier/corpora/own_auth.csv
python pipeline/phase8_malice_classifier/prepare_corpus.py stage7 --inputs "data/phase8_malice_classifier/labelled/pflog_*.csv"   --out data/phase8_malice_classifier/corpora/own_pf.csv
python pipeline/phase8_malice_classifier/prepare_corpus.py stage7 --inputs "data/phase8_malice_classifier/labelled/ossec_*.csv"   --out data/phase8_malice_classifier/corpora/own_ossec.csv
```

- `--window 10` also creates 10-line sequences labelled malicious if any line
  is malicious. Use `--window 1` for single lines only.
- `--benign-ratio 10` caps benign rows at ten per malicious row.

**4. Train one model per log type.** Start with the baseline, then BERT.

```
python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own_auth.csv --run data/phase8_malice_classifier/runs/auth_base --baseline-only
python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own_auth.csv --run data/phase8_malice_classifier/runs/auth_distil
python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own_auth.csv --run data/phase8_malice_classifier/runs/auth_secure --model ~/hf_models/SecureBERT --learning-rate 2e-5
python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/cicids.csv   data/phase8_malice_classifier/corpora/own_pf.csv   --run data/phase8_malice_classifier/runs/pf_distil
python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/own_ossec.csv                     --run data/phase8_malice_classifier/runs/ossec_base --baseline-only
```

**5. Measure transfer to our logs.** This is the number to believe.

```
python pipeline/phase8_malice_classifier/train.py --corpus data/phase8_malice_classifier/corpora/ait_auth.csv data/phase8_malice_classifier/corpora/own_auth.csv --run data/phase8_malice_classifier/runs/auth_transfer --test-source stage7
```

This trains on public data only and tests on every labelled alert of ours.
In `metrics.json`, check the test PR-AUC, and the recall and false-positive
rate `by_source`.

- **Public-data scores will look near-perfect.** The testbed attacks are
  scripted and obvious, so do not quote those numbers.
- **If transfer is poor,** train on public plus our data (step 4), and keep
  labelling.

**6. Score the Phase 7 alerts.**

```
python pipeline/phase8_malice_classifier/score_stage7.py --run data/phase8_malice_classifier/runs/auth_distil --kind bert --inputs "data/phase7_alerts/auth/*.csv" --out data/phase8_malice_classifier/scored/auth
```

Each output CSV gains `malicious_score` and `malicious_flag` columns after
`probability`, and is sorted by score, highest first. The originals are left
untouched.

## Labelling with raw SecureBERT

Labelling is the slow part. [securebert_label.py](securebert_label.py) uses
SecureBERT as it comes, **without fine-tuning**, to cut the work down. This
runs before any model is trained.

```
python pipeline/phase8_malice_classifier/download_securebert.py              # once: ~500 MB to ~/hf_models/SecureBERT (or set SECUREBERT_DIR)
python pipeline/phase8_malice_classifier/securebert_label.py check           # fill-mask sanity test
python pipeline/phase8_malice_classifier/securebert_label.py suggest --inputs "data/phase7_alerts/auth/*.csv" --out data/phase8_malice_classifier/to_label/auth
#   open data/phase8_malice_classifier/to_label/auth/*_to_label.csv, fill "label" on the rows with representative = 1
python pipeline/phase8_malice_classifier/securebert_label.py propagate --inputs "data/phase8_malice_classifier/to_label/auth/*_to_label.csv"
#   review, label what is left, then re-run suggest with your labels as seeds:
python pipeline/phase8_malice_classifier/securebert_label.py suggest --inputs "data/phase7_alerts/auth/*.csv" --seeds "data/phase8_malice_classifier/to_label/auth/*_to_label.csv" --out data/phase8_malice_classifier/to_label/auth2
python pipeline/phase8_malice_classifier/prepare_corpus.py stage7 --inputs "data/phase8_malice_classifier/to_label/auth/*_to_label.csv" --out data/phase8_malice_classifier/corpora/own_auth.csv
```

**What `suggest` does.** Each distinct alert, after normalisation, gets one
SecureBERT pass. That pass produces two things:

- **An embedding.** This is the mean of the alert's token states. It is used
  to group near-identical alerts into clusters of about ten (`--cluster-size`),
  so you label one representative per cluster instead of every row.
- **A zero-shot score** (`zero_shot_malicious`). The model's masked-word head
  fills in "Overall, this activity is ___." This column compares how strongly
  it prefers words like *malicious*, *suspicious* or *unauthorized* over
  *normal*, *legitimate* or *routine*. **Nobody trained it to judge logs.**
  Use the score to order clusters, never as a label. Expect it to be noisy.

With `--seeds`, which are alerts you have already labelled, each alert also
gets the majority label of its five nearest labelled alerts. You get the
closest example alongside, so you can see why. This suggestion is far more
useful than the zero-shot score once you have a few dozen labels of each
kind.

**Output file.** `*_to_label.csv` keeps the Phase 7 columns and adds these in
front: `label` (empty, for you), `suggested_label`, `suggestion_confidence`,
`suggested_by`, `zero_shot_malicious`, `cluster`, `cluster_size` (distinct
alerts in the cluster), `representative` and the nearest labelled example.
Rows are grouped by cluster. The clusters that sound most malicious come
first, with the representative at the top of each.

**Labelling by behavioural cluster.** With `--cluster-column cluster_id` on the Phase 7b file `data/phase7b_clusters/<source>/<prefix>_alerts_by_cluster.csv`, `suggest` groups alerts by their Phase 7b cluster instead of by text similarity. It still uses SecureBERT to pick the most typical alert of each cluster as its representative. That gives one label per kind of behaviour (28 for PF), and the sheet keeps `cluster_id`.

**What `propagate` does.** It copies your label to blank rows in the same
cluster, but only when:

- every label in that cluster agrees, **and**
- the row's own suggestion agrees with that label (unless you pass
  `--trust-cluster`).

Filled rows are marked `label_source = propagated`, so you can audit them.
Spot-check the propagated rows before training on them.

The first run caches SecureBERT's outputs in `securebert_cache.npz`, so reruns
only process new alerts. On a CPU, expect roughly 5 to 20 alerts per second,
depending on length.

### Time on a CPU (rough)

- DistilBERT at 256 tokens trains at roughly 10 to 30 rows per second on a
  laptop CPU. The default `--max-train 60000` with 2 epochs therefore takes a
  few hours.
- For a first run, use `--max-train 15000 --epochs 1`.
- SecureBERT is about twice as slow.
- On any CUDA GPU, all of these take minutes.

## What it will and will not catch

- **It will catch** what the corpora contain, and fast: SSH brute force,
  invalid-user guessing, port scans, floods, and patterns you have labelled
  yourself.
- **It will not catch** attacks absent from the data, such as a PAM backdoor,
  a quiet login with stolen keys, or a rootkit. It also cannot see context
  outside the text: whether the source is your scanner, whether it is a patch
  window, or what the host does. That context is the LLM triage's job.
- **A high score means** "this text looks like the malicious examples". A low
  score is **not** clearance. Keep reviewing high-`probability` Phase 7 alerts
  whatever their `malicious_score`.
- **Retrain** when you add labels or change `normalise()`. Keep the run
  folders so you can compare versions.

## Files

| File | Purpose |
|---|---|
| `common.py` | `normalise()`, sequence joining, Phase 7 message splitting |
| `prepare_corpus.py` | AIT, CIC-IDS2017 and labelled Phase 7 to corpus CSV (`text,label,group,source,unit`) |
| `models.py` | TF-IDF baseline; BERT encoding (head+tail), training loop, scorer |
| `train.py` | Group-aware 70/15/15 split (or `--test-source` hold-out), training, threshold, `metrics.json` |
| `score_stage7.py` | Adds `malicious_score` and `malicious_flag` to Phase 7 CSVs |
| `download_securebert.py` | Fetches SecureBERT at a pinned revision and verifies every file's hash (standard library only) |
| `securebert_label.py` | Labelling assistant on raw SecureBERT: `check`, `suggest`, `propagate` |

**Group-aware split.** `group` is the scenario and host for AIT, the capture
day for CIC, and the file and view for Phase 7. Rows sharing a group never
land on both sides of the split, so neighbouring windows cannot leak between
training and test.
