# Attack patterns: IPFilter firewall logs (mm06moc)

One line per packet, written by Solaris ipmon. Event types come from
`pipeline/phase1_classify/ipf.py`: `IPF_<BLOCK|PASS|LOG|SHORT|NOMATCH>_<PROTOCOL>`.
Phase 2 signals are columns of `ipflog_slots_*.csv` (every 5 minutes, hour or
day, empty ones included), `ipflog_attempts.csv` (one connection attempt) and
`ipflog_flow_episodes.csv` (attempts on one flow with no pause over 30 minutes).

This log is EMPTY in normal operation, so any of the patterns below starts from
"something reached a logging rule that normally logs nothing". IDs marked † were
not re-checked against ATT&CK v19.2.

### IPF-01 · Probing a server whose firewall normally logs nothing
- Techniques: T1046† Network Service Discovery; T1595.001 Scanning IP Blocks (Reconnaissance)
- Event types: IPF_BLOCK_TCP, IPF_BLOCK_UDP
- Phase 2 signals: distinct_destination_ports, attempts_started, syn_packets (slots); several flows in one episode window
- Signs: one source tries many different destination ports on the server within minutes; single SYNs with no retries; ports that no internal service uses.
- Stronger if: the source is not a known internal server, appears in no change record, or later logs in over SSH (AUTH-01, AUTH-05).
- Weaker if: one port only, retried on a fixed schedule (a stuck client, RH-IPF-01).

### IPF-02 · Internal host sweeping the subnet
- Techniques: T1046† Network Service Discovery; T1210† Exploitation of Remote Services (worms)
- Event types: IPF_BLOCK_TCP, IPF_BLOCK_UDP, often to broadcast addresses
- Phase 2 signals: distinct_sources, broadcast_packets, udp_packets (slots)
- Signs: one internal address sends to every host or to the broadcast address on administrative or database ports, or SNMP (161) queries asking every device to answer.
- Stronger if: the source is a workstation or a server with no monitoring role, the requests use default community strings (not visible here), or the same source probes several servers in the PF logs at the same time.
- Weaker if: the source is a monitoring or inventory tool on its usual schedule (RH-IPF-02).

### IPF-03 · Connection to a blocked service that keeps trying (beaconing)
- Techniques: T1071† Application Layer Protocol; T1029† Scheduled Transfer
- Event types: IPF_BLOCK_TCP with -SEC, -S and -R in a fixed cycle
- Phase 2 signals: mean_interval_seconds, interval_cv (episodes), retries
- Signs: a source contacts one port at a fixed interval for hours or days, never succeeding.
- Stronger if: the port is not used by any known application, the source is not part of a recorded change, or the cadence continues after the change is closed.
- Weaker if: the port is an application port used elsewhere on the site (check the PF context), and the activity falls inside a recorded change such as a migration (RH-IPF-01). That is a configuration problem: operationally interesting, not hostile.

### IPF-04 · Firewall rules loosened or logging switched off
- Techniques: T1686 Disable or Modify System Firewall
- Event types: IPF_PASS_* lines where only blocks were ever seen; or the log stopping mid-activity
- Phase 2 signals: passed_packets (slots); a certified empty day straight after heavy activity
- Signs: traffic that was blocked starts to be passed with no change record; or the log goes silent while other logs show the same traffic continuing.
- Stronger if: no change record covers the rule change; authentication logs show root activity on the server shortly before.
- Weaker if: the change record covers a rule update for exactly that flow.
