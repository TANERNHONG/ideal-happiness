# Project DAD (Data Anomaly Detection) Console — slide amendments

> **Historical (superseded).** These amendments were written on 12 October 2026 against the earlier PDF deck. The deck
> was rebuilt and then restructured on 29–30 October 2026; see [PRESENTATION_PREP.md](PRESENTATION_PREP.md) for the
> current deck, its storyline and its backups. Kept for the record; do not work through it.

Prepared 12 October 2026 against the current workspace and the supplied 24-page **Project Huh — Features and results.pdf**. PDF page numbers below identify the existing slides. The supplied deck is reference material; this document follows the requested presentation structure and corrects claims against the implementation.

## Presentation direction

Tell one story: **an operator brings a log excerpt, the console identifies activity worth attention, an analyst checks the evidence, and the organisation keeps the decision.** Lead with internal capability and practical use. Engineering explains what the audience has just seen.

Use the full project name on the cover and first mention; use **Project DAD Console** in slide footers. Replace the old project and console names in editable slide text and presenter notes. Refresh screenshots with the new branding when rehearsing. Historical filenames and source paths can retain their original names.

Aim for a 20-minute presentation: introduction 2 minutes, practical motivation 3, system demo 8, engineering 5, conclusion 2. These are proposed timings. Give the demo the largest share; omit engineering backup slides when time is short.

Slide design rules:

- One claim per slide; at most three short bullets or three short explanatory sentences.
- If that cannot explain the concept, use a visual first, then a concrete example. Put a formula and a source paper in backup material only when they add understanding.
- Keep definitions, assumptions, source paths and caveats in speaker notes. Use progressive reveals, consistent example accounts and hosts, and explicit units for every result.

Red means **flagged for attention**, with a marker and caption so colour is not the only cue. It must not mean “confirmed attack.” Grey means surrounding context; a separate badge indicates **Whitelisted**. A map's position or group colour is context, not a security judgement.

## Proposed main deck and Agenda

| New slide | Section / title | Visible content | Visual and presenter direction |
|---|---|---|---|
| 1 | Cover | **Project DAD (Data Anomaly Detection) Console**; “From server logs to evidence-led review”; presenter and meeting date | Use one clean console image, without a collage. |
| 2 | Agenda | **1. Introduction · 2. Practical motivation · 3. System demo · 4. Engineering details · 5. Conclusion** | Under item 4, a small ribbon: “Preprocessing → Feature engineering → Models used → Postprocessing”. Reuse the five-section ribbon on subsequent slides. |
| 3 | Introduction: What does Project DAD do? | “Bring logs. Find unusual activity. Keep the review decision.” | Three-panel picture: log excerpt → highlighted finding → reviewed case. Explain that it is a local investigation and detection-engineering workbench. |
| 4 | Practical motivation: Why build this capability internally? | “Understand our own systems”; “Investigate beyond fixed rules”; “Retain knowledge from each review” | Before/after workflow: scattered telemetry and interpretations → shared evidence and recorded decisions. Explain supplier dependence and local operating context without claiming measured cost savings. |
| 5 | Practical motivation: Volume hides the question | “26.3 million historical lines”; “Four different log sources”; “No independently labelled attack dataset” | A mass of grey lines with one highlighted excerpt. Say that models prioritise review; anomaly counts are not attack counts. |
| 6 | System demo | **System demo** | Only those two words on the slide. Switch to Simple mode. No subtitle, bullets, screenshots or agenda ribbon on this divider. |
| 7 | Engineering details: Preprocessing steps | “Read the line”; “Group related events”; “Preserve the evidence link” | One raw line becomes time / host / account / event, then a session bracket. Show train → validation → test as a small chronological strip in notes or a reveal. |
| 8 | Engineering details: Feature engineering techniques | “How much?”; “Who and what?”; “When and in what order?” | A miniature session becomes three cards: count, category and sequence. A clock ring illustrates midnight neighbours. Move hash widths and matrix dimensions to backup. |
| 9 | Engineering details: Models used | “Unusual amount”; “Unusual combination”; “Rare feature or next step” | Three visual lenses on the same behaviour. Name robust deviation, Isolation Forest, token novelty and transition surprise in concise captions. The third panel distinguishes feature rarity from host-conditioned next-step rarity. Mention the 13-family model zoo verbally. |
| 10 | Engineering details: Novelty — rare compared with which past? | “Compared with the fixed training reference”; “Rare can mean seen before”; “Repeating in test does not teach the baseline” | Training timeline above the chronological log example below. Reveal the likely candidate line in red with **candidate for review**. The detailed 100-occurrence explanation is in speaker notes and backup. |
| 11 | Engineering details: Postprocessing steps | “Apply calibrated thresholds”; “Check user exceptions”; “Review and retain evidence” | Branch diagram: scored finding → covered by active user whitelist? → **Whitelisted** / **Needs review**. Both branches retain the score and finding. Show a mixed-account example beneath it. |
| 12 | Conclusion: What we can do now | “Check a supported log excerpt locally”; “Review findings with evidence”; “Build and retain internal detection knowledge” | Return to the three panels from slide 3, now showing the completed review. Say that operational acceptance needs independently reviewed labels and deployment governance. |

On slides 7–11, highlight the relevant engineering subsection in the ribbon. Do not insert detailed models or results ahead of the demo. For an executive audience, slides 7–11 should take about five minutes collectively; extra explanations belong in discussion.

## System demo storyline: one question, four stops

**Scenario:** “An operator asks whether this morning's authentication activity needs attention. We will show what the console can establish, what needs a person, and how an approved account changes the queue.” Use a sanitised excerpt from supported AUTH logs, with documentation addresses such as `192.0.2.17`. Keep original relative timing, event order and relevant context when sanitising.

The demonstration should contain an ordinary reference session, a rehearsed flagged session needing investigation, and a separate flagged session involving an approved service account. Use a known supported host for scoring; arbitrary invented hosts can change the result. Display aliases in explanatory slide artwork. Never promise a particular verdict from an invented line before running it through the saved models.

| Beat | Screen / action | Suggested narration | Evidence to show |
|---|---|---|---|
| 0 · Set the question | Open Simple mode, **Check logs** | “We start with the operator's file, rather than a model configuration.” | Four stops: Upload, Analyze, Map, Review. |
| 1 · Upload | Drop or paste the rehearsed excerpt; check detected source and month; choose raw-log column if it is a table | “It identifies a supported format and shows how much it recognises.” | Coverage and source. Avoid a parser tutorial. |
| 2 · Analyze | Run the check; pause on the result | “These observations differ from the saved reference. That makes them worth checking.” | **Unusual**, its count and server context. Counts may refer to observations or deduplicated findings, not raw log lines. The upload does not retrain the model. |
| 3 · Map | Select one flagged point or nearby group | “This gives us related behaviour to explore; it does not establish what happened.” | Selected point, relevant group and any available recorded review. Do not promise historical line retrieval after the purge. |
| 4 · Review | Keep the upload for review; open its item and its uploaded context | “Now we read the actual sequence, including what happened before and after.” | A short chronological excerpt, timestamps and the **▶ this** marker. Explain whether the selected finding is an event, session or window. |
| 5 · Human decision | Choose a supported review label and write a concise reason | “A person records the interpretation and what evidence supports it.” | Use **Suspicious** or **Insufficient evidence** when warranted; a failed login alone does not establish an attack. |
| 6 · Approved-account contrast | Open the prepared service-account upload; briefly show its scoped, reasoned whitelist entry in Advanced → Settings; return to the upload | “The score remains. This active account exception changes whether it asks for attention.” | **Whitelisted** badge and retained finding. Show removal on a scratch store or replay the before/after recording if useful. |
| 7 · Close the loop | Briefly show a prepared saved report if time permits | “The evidence and review become a versioned record we can revisit.” | Case identifier and saved version. Keep this to 30 seconds; it is an optional extension beyond the four-stop flow. |

Keep reviewer assignment within the demo store. **Send to a reviewer** opens a mail draft; saving or assigning an upload is not proof that an email was delivered. Rehearse the local path and close any mail draft without sending it.

### Rehearsal requirements and fallback

The original corpus has been purged. New uploads retain their own excerpt context, but historical SQL, group-member lines and **Around this event** cannot recover the old lines. Build the live walkthrough around a retained upload, not those historical queries. Historical Review whitelist coverage needs retained exact account facts; if absent, it does not suppress the group.

Prepare the demo on an isolated copy of the console store, with made-up reviewer names and scoped whitelist entries. Rehearse the complete sequence on the same runtime used for the meeting. Capture the actual verdicts, number of findings, map placement and context before writing the final narration. Do not mutate the operational whitelist merely to obtain a cleaner presentation.

Keep three fallback screenshots or a short recording: Analyze result, uploaded Review context and the covered service-account finding. If a sample does not flag, choose a different verified excerpt and record its actual detector/view; do not force a false screenshot. The illustrative examples below explain concepts and are not measured detection results.

## Chronological log example and red highlighting

Use this **illustrative artwork** on slide 10, not as a guaranteed runnable fixture. Assume `backup` is common in training and `maint1` contributes a retained rarity feature that was absent or rare in training. The same address and host keep the account change easy to see.

```text
01  08:00:00 host-a sshd[4101]: Accepted publickey for backup from 192.0.2.17 port 51001 ssh2
02  08:00:03 host-a sshd[4101]: Received disconnect from 192.0.2.17 port 51001:11: disconnected by user
03  08:00:03 host-a sshd[4101]: Disconnected from user backup 192.0.2.17 port 51001
04  08:05:00 host-a sshd[4102]: Accepted publickey for backup from 192.0.2.17 port 51002 ssh2
05  08:05:03 host-a sshd[4102]: Disconnected from user backup 192.0.2.17 port 51002
06  08:10:00 host-a sshd[4103]: Accepted publickey for maint1 from 192.0.2.17 port 51003 ssh2
07  08:10:03 host-a sshd[4103]: Disconnected from user maint1 192.0.2.17 port 51003
```

Reveal lines 1–5 in grey. Reveal line **06 in red**, with **▶ candidate for review** and “Account rare in training”. Keep line 07 as context. Ask rhetorically, “New maintenance account, or an unexpected login?” Then show the training timeline that explains why its feature is rare. Successful public-key login is not intrinsically hostile.

For a slide mockup or HTML-rendered console excerpt, use this rendering direction:

```html
<pre class="demo-log"><span>08:05:00 host-a ... Accepted publickey for backup ...</span>
<span style="color:#b42318;font-weight:700">▶ 08:10:00 host-a ... Accepted publickey for maint1 ...  [candidate for review]</span>
<span>08:10:03 host-a ... Disconnected from user maint1 ...</span></pre>
```

In the actual console, the selected observation's source lines are marked **▶ this**; the current style uses a coloured marker and a tinted background, not red text across the entire log line. For the deck, annotate a genuine screenshot or use the clearly labelled illustration above to achieve the requested red line. A session-level finding can own multiple lines: bracket the session and explain that line 06 is the explanatory cue, rather than claiming the model flagged only that line. Changing live console highlighting is a separate interface amendment if desired.

## Novelty speaker notes: answer the 100-occurrence question

**Does it work only on data unseen in training?** No. The project's novelty channel considers rarely active features as well as features with no training presence. It does not compare complete raw lines against a list of previously seen strings.

**If a new behaviour appears 100 times in test, does it stop flagging?** Test repetitions do not update the fixed fitted presence counts. All 100 observations can receive high scores if they activate the retained rare feature, and can flag when those scores meet the saved threshold. “New but repeated in test” does not mean “normal in training.”

**Why might it still miss them?** The new behaviour may not produce a distinct retained feature; hash collisions can map it to a common bucket; feature selection can remove the distinction; or threshold calibration can exclude its score. Discrete rarity scores can tie. If the same change already occurs heavily in validation, budget-based calibration can move the threshold and exclude tied observations. This is a threshold/representation effect, not the model learning from test repetitions.

**What does regime change do?** A fixed baseline can flag a large amount of newly legitimate behaviour. The analyst must investigate the operating change before deciding to recalibrate, retrain or apply a justified scoped exception. Future daily workloads are not hard-capped by validation targets. The console does not automatically learn that all test behaviour is safe.

**How does first-seen differ?** First-seen checks identify an exact account/address appearing for the first time in their historical scope. Token novelty evaluates encoded-feature rarity. Hashed sequence fragments are also different from the separate host-conditioned transition-surprise detector.

Backup formula only if asked:

\[
p_j=\frac{n_j+\alpha}{N+2\alpha},\qquad
s(x)=\max_{j:x_j\ne0}[-\ln p_j].
\]

Here `n_j` counts training observations activating retained rarity feature `j`, `N` is the training population and `α` is the implementation's smoothing constant. Empty active-feature sets receive zero. Flagging compares the score with the saved threshold. Do not label this an attack probability.

For this exact formula, cite the project implementation, AUTH and OSSEC `fit_rarity` / `rarity_score`, rather than inventing a matching paper: [AUTH](pipeline/phase4_detection/auth_detectors.py), [OSSEC](pipeline/phase4_detection/ossec_detectors.py). If the audience asks about the separate Isolation Forest visual, provide its original [Liu, Ting and Zhou paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf) in backup reading.

## Concept-by-concept direction for discussion

Each row proposes one example the presenter can explain in a few sentences. Treat these as directions to review one at a time; refine the examples before expanding slide copy.

| Concept | Proposed practical example / visual | Short narration | Detail to retain in notes |
|---|---|---|---|
| Parsing | Colour the timestamp, host, account and event in one login line | “We turn a sentence into facts, keeping its source link.” | Recognised syntax does not establish security meaning; unknown formats go to Patterns. |
| Grouping | Bracket login → disconnect as one session; compare a five-minute window | “Several lines can describe one activity.” | Sessions are constructed heuristically; windows, sessions and days answer different questions. |
| Chronological splits | Past → later → latest, with narrow gaps at boundaries | “Learn from the past, set thresholds on the next period, inspect the later period.” | Approximately 70/15/15 by observations; purge gaps reduce leakage. |
| Counts and durations | Two failed logins beside fifty in a comparable window | “A count makes scale comparable.” | Illustration only; high volume alone does not guarantee a flag. |
| Categories and hashing | Account/event tokens dropped into a fixed tray of numbered buckets | “We encode names and event types in a bounded feature space.” | Hash collisions are possible; widths differ by block/view. Avoid collision arithmetic in the main deck. |
| Cyclic time | Clock face with 23:59 adjacent to 00:01 | “Midnight's neighbours should stay neighbours.” | Sine/cosine represent periodic time; an unusual hour is not automatically hostile. |
| Robust deviation | A stable historical count with one distant bar | “This value moved far from its resistant baseline.” | AUTH robust alerts can be absent because of tied scores/calibration; do not promise it catches every spike. |
| Isolation Forest | Ordinary observations in a dense area, one point isolated by a few cuts | “Unusual combinations can be easier to separate.” | Use the paper only in backup; an isolated point is not a maliciousness label. |
| Token novelty | Common `backup` sessions, then the red `maint1` line | “Its features are rare compared with training.” | Use the fixed-reference explanation above; repeated test data do not update it. |
| Event-order surprise | Familiar login → disconnect beside a rare next event | “The next step is uncommon after this previous step on this host.” | Score uses the rarest host-conditioned transition; mined routines and alert scoring are distinct. |
| Model zoo and agreement | Several lenses voting on the same session | “Different models supply complementary candidates.” | Thirteen families; full/selected features; effective consensus requirement depends on available voters. Agreement is not ground truth. |
| Maps | Related observations grouped around a selected uploaded point | “The map helps us find comparable behaviour.” | Projection shapes and distances need care; uploading uses saved placement rather than refitting the map. |
| Thresholds and budgets | Horizontal line above a validation score distribution | “We choose a review threshold using a later calibration period.” | Targets are per detector/view, not a shared global or guaranteed future daily cap. |
| Whitelist postprocessing | Flagged `backup`/`host-a` branches to Whitelisted; `backup` + `root` stays Needs review | “Every named account must be covered on its server; the finding remains scored.” | User scope, reason, inclusive expiry, password and audit. No IP override currently. |
| Evidence and human review | Chronological excerpt → note → saved decision | “The finding is a prompt to investigate; the person records the conclusion.” | Whitelisted is an override status, not a human benign judgement. |
| Reports | One finding carried into a case with version number | “We retain evidence and reasoning for later review.” | Saved versions and digests preserve history; they do not validate detection accuracy. |

Suggested discussion order: parsing/grouping → counts/categories/time → novelty → event order → other models → thresholds → whitelisting → human review. Novelty can be the first detailed discussion if the presenter wants to settle the drift question before choosing the remaining examples.

## Amendments to the existing 24 slides

| Existing page / title | Amendment |
|---|---|
| 1 · Project Huh | Rename and simplify into new slide 1. Avoid “finding suspicious activity” as though suspiciousness has been validated. |
| 2 · Millions of lines, no labels, rare signals | Use in new slide 5, with three facts rather than four numerical tiles. |
| 3 · The four log sources | Move the full source table to backup; mention the four sources briefly in slide 5. |
| 4 · A pipeline that finds, a console that decides | Rebuild as new slide 3. The analyst decides; the console supports the decision. |
| 5 · The pipeline at a glance | Move the phase-by-phase diagram to backup; use a simpler three-step picture for slide 7. |
| 6 · From text to comparable observations | Retain its raw-line transformation as the core of slide 7; move four-view definitions into notes. |
| 7 · Each observation becomes one row of numbers | Rebuild as slide 8 with three feature questions. Put widths, hashing arithmetic and matrix dimensions in backup. |
| 8 · Four unsupervised detectors, one alert budget | Split into slide 9's visual lenses and slide 11's calibration. Correct “one budget”: thresholds use per-detector/per-view validation targets. |
| 9 · Learning the usual order of events | Use its sequence picture as a reveal in slide 9; keep measured counts and formula in backup. Explain the transition score separately from routine mining. |
| 10 · They flag a thin tail, not everything | Backup. Replace “probability” with a correctly labelled score percentile where appropriate; it is not attack probability. |
| 11 · Alerts form islands, mostly on the mm servers | Backup. One map image supports the live demo, but a cluster is not a security verdict. |
| 12 · Every alert leads back to the original lines | Use the chronological evidence style in the demo; qualify historical retrieval after the purge. Remove “or Phase 9 has to judge”: generated suggestions require human review. |
| 13 · Check a log file in four stops | Convert into demo notes and fallback screenshots. The section divider itself says only **System demo**. |
| 14 · Teaching it a log format it has never seen | Backup or optional question response. Rules are suggested, tested and saved by people, and need adoption into Phase 1 before Analyze uses them. |
| 15 · From a flagged group to a numbered case | Use for the demo's final optional beat. Distinguish historical group review from uploaded individual findings. |
| 16 · Whitelisted users | Rebuild as slide 11's branch picture with one practical example; retain scope/expiry and the all-accounts rule in notes. |
| 17 · Offline and after the purge | Demo rehearsal notes / backup. Do not claim that every console store contains zero accounts or IPs merely because the runtime omits them. |
| 18 · Alerts produced for the test period | Backup, preserving source/view/population units. Avoid combining unlike observation counts into incidents. |
| 19 · Four detectors, mostly different catches | Optional backup visual. Explain 0.47% as selected test sessions/episodes, not a detection accuracy or general false-positive rate. |
| 20 · 26 million lines become about 590 rows to label | Backup, explicitly dated and labelled as a deduplicated preparation workload. It does not measure end-to-end analyst savings. |
| 21 · What an alert can and cannot claim | Put the essential boundary into slide 12's notes. Remove the claim that future alert volume stays inside a hard daily budget. Phase 8 preparation does not itself create validated attack labels. |
| 22 · Known gaps | Backup. Keep approved-automation IP context distinct from the implemented user whitelist. |
| 23 · From unusual to actionable | Roadmap backup only: classifier training, label export and operational validation remain unfinished. |
| 24 · Triage categories | Backup. Distinguish four Phase 9 suggestion categories from the five human Review labels, including Suspicious. |

Insert a new Agenda slide and a new Practical motivation slide. Finish with a new Conclusion slide. Keep backup slides after Conclusion so the main narrative stays in the Agenda order.

## Acceptance checks for the revised deck

- Cover, footer and first introduction use Project DAD branding; Agenda and section order match the requested five sections and four engineering subsections.
- The System demo divider contains only **System demo**, and the walkthrough receives the largest time allocation.
- Each engineering concept has a visual/example direction; dense equations and detailed result tables are in backup. The chronological excerpt has one explicitly marked red candidate with grey context.
- Whitelisting is described as implemented user-account postprocessing. IP exceptions are a possible future extension, distinct from approved-automation context. Scores/evidence remain retained; mixed-account and no-account findings do not receive blanket coverage.
- Rehearsal verifies the actual sample verdicts and uploaded context on the current frozen runtime. Statistical unusualness, model agreement, percentiles and whitelist status are never presented as confirmed maliciousness or benignness.

Supporting current documentation: [whitepaper](whitepaper/TECHNICAL_WHITEPAPER.md), [primary LaTeX edition](whitepaper/TECHNICAL_WHITEPAPER.tex), [appendices](whitepaper/TECHNICAL_WHITEPAPER_APPENDICES.tex), [Simple workflow](triage-console/web/src/tabs/simple.ts), [user whitelist](triage-console/service/whitelist.py), [analysis](triage-console/service/analyze.py) and [retained uploads](triage-console/service/uploads.py).
