# Project DAD (Data Anomaly Detection) Console: quick start

Run the **Project DAD (Data Anomaly Detection) Console** locally to check logs, review findings and write
investigation reports. These steps use Windows PowerShell and the existing
pipeline laptop. Updated 30 October 2026 (Singapore).

## Open the console

If it is already running, open **<http://127.0.0.1:8765>**.

Otherwise, start it in PowerShell:

```powershell
cd C:\Users\shawn10\Documents\Project-Huh\triage-console
..\.venv\Scripts\python.exe -m service
```

Keep that terminal open while using the console. Press **Ctrl+C** in the same
terminal to stop it. The service listens only on this laptop.

## Set up or rebuild the console

Skip this section if the existing installation and web build are ready.

You need the project's **prepared `.venv`**, the trained models (the pipeline's
**`data/`** outputs, or the frozen **`runtime/`** copy once `data/` is purged; see
the last section), and **Node.js/npm** for the web build. PDF export
also needs **Microsoft Edge**. The console requirements file adds packages to
the pipeline environment; it is **not a complete fresh-machine pipeline setup**.
A source release ZIP excludes `.venv`, `data/` and runtime records.

Run from the project root; adjust the path if your checkout is elsewhere:

```powershell
cd C:\Users\shawn10\Documents\Project-Huh
.\.venv\Scripts\python.exe -m pip install -r triage-console\requirements.txt
cd triage-console\web
npm.cmd ci
npm.cmd run build
cd ..
..\.venv\Scripts\python.exe -m service
```

Open <http://127.0.0.1:8765>. Initial cache building can take several minutes,
especially for AUTH; pages show when their data is still being prepared.
Starting the console does not require rerunning the pipeline. To run the pipeline
itself, see *How to run* in the [project README](README.md#how-to-run).

## Your first investigation

1. In **Settings**, set your display name so reviews and report versions record
   the right local reviewer.
2. In **Simple** mode, open **Check logs**, upload supported AUTH, OSSEC, PF or
   IPFilter logs, then follow **Analyze → Map → Review**. **Send for review**
   retains unusual events as an upload you can reopen. If the log format is
   unknown, **Find patterns** opens the lines in **Advanced → Patterns**, where
   you can write and test parsing rules for it.
3. Open **Review**, inspect the original evidence and record a label. Filter by
   server, account, program or address. Switch to **Advanced** to review the
   existing pipeline's flagged groups and firewall activity. A group label
   applies to the whole group, including when its event list is filtered.
4. If an account you trust keeps being flagged (a backup job, a monitoring
   service), add it in **Settings → Whitelisted users** with a reason, ideally
   one server and a last day, and the admin password. Its flagged events then
   move to *Whitelisted* instead of *Needs review*; they are still scored.
5. In Advanced, **Sigma** runs rules for known attack patterns (password
   guessing, spraying, port scans) over the same logs; a group holding a rule's
   hit is listed in Review whatever its rarity.
6. For AUTH and OSSEC, Advanced Review also lists **activity alerts** (a server,
   address or account much busier or quieter than usual for that time), one item
   per incident. **Explain** shows why each was raised; **Profiles** shows any of
   them, alerted or not, against its usual week.
7. **Report** on a reviewed item starts a report with your notes as its analyst
   comments. Or open **Reports**, choose **Anomaly** or **Malicious activity**, then **New
   report**. Add findings and evidence blocks; use maps, timelines and tables
   where they help explain the investigation.
8. Select **Save version**. The first save assigns an `IR-YYYY-NNNN` number;
   every subsequent save preserves another version. Closed cases remain
   editable. Use **Preview**, choose **PDF**, **Word** or **HTML**, then **Export**.

An anomaly means unusual activity, not proof of maliciousness. Report sign-offs
are non-binding acknowledgements. See the [Reports and Review guide](triage-console/docs/user/04_reports_and_review.md)
for filters, evidence limits, history and exports.

## Optional features

- **Local AI helpers:** table-query assistance and ATT&CK suggestions use Ollama
  on `http://127.0.0.1:11434`, with `qwen2.5:3b-instruct` selected by default.
  Configure the endpoint/model in Settings. Manual reports and reviews work
  without Ollama. The full-report AI writer remains deferred.
- **SSO:** not required for local review or reports. Dataset changes and
  retraining require an administrator signed in with configured SSO. Follow
  [SSO and datasets](triage-console/docs/user/03_sso_and_datasets.md).
- **Web development:** keep the Python service running, then use a second
  terminal to run `npm.cmd run dev` from `triage-console/web`. Open
  <http://127.0.0.1:5173>. Rebuild for changes to appear on port 8765.

## Common problems

| Symptom | What to check |
|---|---|
| Port 8765 is already in use | Try opening the console before starting another copy. |
| Browser cannot connect | Start the Python service and inspect its terminal for errors. |
| Page is missing or shows old UI | Run `npm.cmd run build` in `triage-console/web`, then refresh. Restart the service after Python changes. |
| Missing module, model or dataset | Use the prepared project `.venv`, and keep either `data/` or `runtime/` beside `triage-console/`. The console package list alone does not recreate the pipeline environment. |
| Review or maps are still loading | Allow the initial caches or placement job to finish; large views can take minutes. |
| PDF export fails | Check that Microsoft Edge and the console requirements are installed. Word export is also available. |
| AI helper fails | Check the local Ollama service and selected model; use manual SQL/tables or offline ATT&CK search meanwhile. |

## Keep your work

Reports, reviews and upload records live in `triage-console/var/`, including
`console.sqlite3`. Stop the service before copying the complete `var/` folder
for a backup. Keep original pipeline data separately. Clearing an upload and
changing the whitelisted users ask for the activity-log admin password, initially
`123456` until changed in Settings. Queries (Data → SQL, a report's table, a
chart's CSV, refreshing a Dashboard SQL table) ask for a separate SQL password,
initially `1234`: change it in Settings → Activity log → *SQL password*. Change
both before anyone else uses the laptop.

[VERSIONS.md](VERSIONS.md) records application releases and explains the source
snapshot controller. Source archives exclude your runtime records and datasets;
report version history stays in the console database.

## Before you purge `data/`

`data/` (about 168 GB) holds the logs and every intermediate table. The console can keep analysing uploads and
drawing the maps without it, from a frozen copy of the trained models, maps and summaries in `runtime/`
(about 480 MB, no log lines, accounts or addresses):

```powershell
.\.venv\Scripts\python.exe scripts\freeze_runtime.py            # copy what the console needs into runtime\
.\.venv\Scripts\python.exe scripts\freeze_runtime.py --check    # score sample lines and load every map from runtime\ only
```

Run both, and back up `runtime\` with `triage-console\var\`, before deleting `data\`. The console switches to
`runtime\` by itself when `data\` has no trained models, and back when a new pipeline run trains them.

After the purge these still work: Analyze and Check logs (all AUTH and OSSEC models and views), the maps and their
groups (t-SNE and UMAP), Models, the Dashboard's outlier counts, Data → Message types, Review's test-period groups
with their rarest events, Reports, Patterns. These do not, because they read log lines: Data → SQL, the lines
behind a map point or group, Review's "Around this event", the validation-period and firewall review items, the
firewall address chart, and retraining (it needs the archives again). `triage-console\var\cache\` keeps copies
derived from the logs (`cluster_index.sqlite` with account names and addresses, `firewall.sqlite` with the firewall
lines, `ip_flows.json` with addresses): delete those too if the purge must remove all log data; the console
restores what it needs from `runtime\cache\`.

For detailed setup and checks, see the [console README](triage-console/README.md).
For the pipeline itself, see the [project README](README.md).
