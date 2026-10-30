# Site context for Phase 9 (trusted, maintained by the analysts)

Everything in this folder is sent to the triage model as **trusted** context,
so only the security team should edit it. Changing any file here starts a new
prompt version, so earlier triage results are never silently mixed with new
ones.

| File | What it holds | Where it goes |
|---|---|---|
| `approved_automation_ips.csv` | IP addresses or CIDR ranges of approved administrative automation, one per row: `address,owner,purpose,approved_by,approved_on` | The system prompt, as approved administrative automation. Each alert also states which approved addresses appear in its lines. |
| `approved_change_windows.csv` | Planned changes such as a migration, one per row: `start,end,hosts,source,destination,port,protocol,change_ref,description,approved_by,approved_on`. Only `start` and `end` are required; the others narrow the window to particular servers and a flow. Times are ISO (`2025-11-23T00:00`); `hosts` is `;`-separated; `source` and `destination` take an address or CIDR range. | The system prompt, as approved changes. Each alert also states how many of its lines fall inside each window and match its hosts and flow. |
| `public_holidays.csv` | Public holidays, one per row: `date,name` (ISO dates; Singapore's gazetted holidays 2024–2026 with the Mondays given in lieu). Hari Raya Puasa and Hari Raya Haji 2026 are the gazetted dates, which depend on the moon sighting: correct them if they moved. | Not the prompt: Phase 4g treats these days as non-working, like weekends (its `time_is_non_working` feature and its explanations). Changing the file still starts a new prompt version. |
| `assets.csv` | Zone, role and criticality (high, medium, low) per server, address or network, from the network inventory. Empty until filled in | Phase 4g: zone crossings, peer baselines for entities without their own history, and criticality weights (high ×1.5, medium ×1.2) |
| `site_context.md` (optional) | Free-text facts: patch windows, authorised scanners, server roles | The alert's SITE CONTEXT block |

Example rows:

```
address,owner,purpose,approved_by,approved_on
10.0.5.20,Backup team,Nightly backup over SSH with key,J. Tan,2026-09-29
10.0.6.0/28,Monitoring,Health checks every 5 minutes,J. Tan,2026-09-29
```

Example change window (the November 2025 traffic on mm06moc's IPFilter log,
**if** the change record confirms it was a migration):

```
start,end,hosts,source,destination,port,protocol,change_ref,description,approved_by,approved_on
2025-11-23T00:00,2025-11-30T23:59:59,mm06moc,172.16.10.29,172.16.10.26,9711,tcp,CHG-xxxx,Application migration to mm06moc,J. Tan,2026-10-01
```

A window explains only the traffic it names: other sources, ports or servers,
and the same flow outside the window, are judged on their own. A change that
leaves a needed service blocked is still operationally interesting.

To seed the list, run `python pipeline/phase9_llm_triage/suggest_automation_ips.py`.
It writes **candidates** from the auth logs: addresses that log in often, on a
steady schedule, with keys and almost no failures. That is the pattern of
automation, but it is not approval. Confirm each candidate with its owner
before copying it here.

Approval shapes the model's judgement; it does not whitelist. The prompt
tells the model to treat behaviour that automation does not normally show,
such as `su` to root, new users or repeated failures, as security relevant
even from an approved address.
