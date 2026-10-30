# Attack patterns: OSSEC agent logs

The OSSEC agent log records the agent's own operation, not the security
alerts it forwards. Attackers therefore appear here mainly through what they
do **to monitoring**: stopping the agent, cutting it off from the manager,
resetting integrity baselines or excluding files. Stage 2 signals are columns
of `ossec_security_episodes.csv`, `ossec_host_windows_5min.csv` and
`ossec_host_behavior_1d.csv`; the risk counts come from Stage 2's
`RISK_EVENT_GROUPS`.

### OSSEC-01 · Agent stopped or killed (blinding monitoring)
- Techniques: T1685 Disable or Modify Tools (Defense Impairment); T1489 Service Stop (Impact)
- Event types: OSSEC_SIGNAL_RECEIVED_EXITING, OSSEC_SHUTDOWN_RESPONSES_DELETED, OSSEC_EMAIL_DISABLED_CLEAN_EXIT, OSSEC_PROCESS_STARTED
- Stage 2 signals: agent_stop_count, agent_start_count, episode_family=lifecycle, close_reason=interrupted, long gaps (maximum_inter_event_seconds)
- Signs: "SIGNAL Received. Exit Cleaning…" or "Shutdown received" with no "Started (pid: N)" soon after; a stop that interrupts a scan in progress; the host going silent for hours after the stop; stops on one host only, outside maintenance.
- Stronger if: preceded on the same host by a suspicious login, su to root or PAM errors (AUTH-05, AUTH-07, AUTH-10); followed by integrity-baseline resets (OSSEC-03) or new exclusions (OSSEC-04); repeated stop/start cycles.
- Weaker if: every OSSEC process stops and restarts within minutes, several hosts do the same at the same time, or it falls in a patch window (RH-OSSEC-01).
- Cases: CASE-TEAMTNT, CASE-ROCKE

### OSSEC-02 · Agent cut off from the manager
- Techniques: T1686 Disable or Modify System Firewall (Defense Impairment); T1685 Disable or Modify Tools
- Event types: OSSEC_SERVER_UNAVAILABLE_LOCK_SET, OSSEC_WAITING_FOR_REPLY, OSSEC_NEXT_SERVER, OSSEC_CONNECTION_ATTEMPT, OSSEC_SERVER_MESSAGE_SEND_FAILED, OSSEC_QUEUE_MESSAGE_SEND_FAILED, OSSEC_SOCKET_ERROR_UNAVAILABLE, OSSEC_SERVER_CONNECTED
- Stage 2 signals: communication_failure_count, episode_family=connectivity, close_reason (inactivity or end_of_data instead of terminal), duration_seconds
- Signs: "Server unavailable. Setting lock." with no "Connected to the server" for a long time; repeated "Unable to send message to server"; cycling through servers ("Trying next server ip"). Events raised while disconnected may never reach the manager.
- Stronger if: only this host is affected while others stay connected; it starts just after an administrative login or su; PF logs show the host's traffic to the manager port (1514/udp by default) being blocked or stopping.
- Weaker if: many agents lose the manager at the same moment and recover together (RH-OSSEC-02).
- Cases: CASE-UNC2891 (defenders blinded by rootkit and log cleaning)

### OSSEC-03 · Integrity baseline reset or files vanishing
- Techniques: T1685 Disable or Modify Tools; T1070.004 File Deletion (Stealth); T1685.006 Clear Linux or Mac System Logs
- Event types: OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND, OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND, OSSEC_SYSCHECK_DATABASE_PRESCAN_STARTED, OSSEC_SYSCHECK_DATABASE_PRESCAN_COMPLETED
- Stage 2 signals: integrity_gap_count, syscheck_count, new_files
- Signs: "No previous md5|sha1 checksum found … Starting over" means the file-integrity database was lost or deleted, so changes made before the reset cannot be detected. "File … not found. MD5 checksum skipped" means monitored files disappeared, notably logs or binaries.
- Stronger if: the missing files are logs (/var/adm, /var/log), authentication files (/etc/pam.conf, authorized_keys), or system binaries; the reset follows an agent stop (OSSEC-01) with no package change; it happens on one host only.
- Weaker if: it occurs right after an agent install or upgrade across many hosts (RH-OSSEC-03), or the missing files are rotated logs (RH-OSSEC-06).
- Cases: CASE-UNC2891 (log cleaner and wiper tools), CASE-TEAMTNT

### OSSEC-04 · New monitoring exclusions or active-response allowlisting
- Techniques: T1564.012 File/Path Exclusions (Stealth); T1685 Disable or Modify Tools
- Event types: OSSEC_FILE_IGNORED, OSSEC_ACTIVE_RESPONSE_IP_ALLOWLISTED, OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLISTED, OSSEC_ACTIVE_RESPONSE_IP_ALLOWLIST_COUNT, OSSEC_RULES_ENABLED_TOTAL, OSSEC_DIRECTORY_MONITORING_STARTED
- Stage 2 signals: configuration_gap_count, new_files, unique_monitored_paths
- Signs: at start-up the agent lists an "Ignoring file" path it did not ignore before, fewer monitored directories, fewer enabled rules, or an unfamiliar IP or hostname in the active-response allowlist. An attacker who allowlists their own address stops OSSEC from blocking them.
- Stronger if: the new allowlisted IP is external or appears in PF or authentication alerts; the change follows a suspicious login; it happens on one host only.
- Weaker if: the same ignore list and allowlist appear at every restart (RH-OSSEC-05), or the change matches a documented configuration rollout.
- Cases: none directly; see CASE-TEAMTNT for tampering with monitoring tools.

### OSSEC-05 · Configuration gaps and removed response capability
- Techniques: T1685 Disable or Modify Tools
- Event types: OSSEC_MANAGER_IP_NOT_SET, OSSEC_ACTIVE_RESPONSE_COMMAND_UNAVAILABLE, OSSEC_AUTHENTICATION_KEYS_READING, OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE
- Stage 2 signals: configuration_gap_count, integrity_gap_count
- Signs: "Manager IP not set" (the agent cannot report); "Active response command not present" (a response script such as firewall-drop was removed, so automatic blocking stops working); lost agent counters after a restart (the agent state directory was wiped).
- Stronger if: the configuration worked on earlier days and changed without a deployment; it co-occurs with OSSEC-01 or OSSEC-03.
- Weaker if: a new or re-imaged host during provisioning, or a command intentionally absent on this platform and reported identically at every start-up.
- Cases: CASE-ROCKE, CASE-TEAMTNT

### OSSEC-06 · Rootkit-check anomalies
- Techniques: T1014 Rootkit (Stealth); T1547.006 Kernel Modules and Extensions (Persistence)
- Event types: OSSEC_ROOTCHECK_SCAN_STARTED, OSSEC_ROOTCHECK_SCAN_ENDED, OSSEC_UNKNOWN_EVENT
- Stage 2 signals: episode_family=rootcheck, episode_completed=0, close_reason=scan_timeout or interrupted, duration_seconds far above normal
- Signs: rootcheck scans that start but never end, take far longer than usual, or are interrupted by an agent stop; unusual rootcheck lines at ERROR or CRITICAL severity. Kernel rootkits hide files and processes and can interfere with the tools that look for them.
- Stronger if: the host is a Solaris server holding sensitive functions (payment, authentication); combined with PAM anomalies (AUTH-07) or baseline resets (OSSEC-03).
- Weaker if: the scan simply had not finished when the logs were collected, or large file systems make scans long (RH-OSSEC-04).
- Cases: CASE-UNC2891

### OSSEC-07 · Unexpected host shutdown or reboot
- Techniques: T1529 System Shutdown/Reboot (Impact)
- Event types: OSSEC_SIGNAL_RECEIVED_EXITING for all processes, then OSSEC_PROCESS_STARTED, OSSEC_AUTHENTICATION_KEYS_READING, OSSEC_RULES_FILE_READING (start-up sequence)
- Stage 2 signals: episode_key_type=lifecycle, agent_stop_count and agent_start_count together
- Signs: every OSSEC process stops at once and the full start-up sequence follows: the host restarted. Attackers reboot to load kernel modules, complete implant installation or cause disruption.
- Stronger if: outside a maintenance window, on one host only, and after suspicious activity (AUTH-05, AUTH-07); followed by integrity or rootcheck anomalies.
- Weaker if: part of a scheduled patch cycle across many hosts (RH-OSSEC-01).
- Cases: CASE-UNC2891 (kernel-module rootkit)

### OSSEC-08 · Event loss during floods
- Techniques: T1499 Endpoint Denial of Service (Impact); T1685 Disable or Modify Tools
- Event types: OSSEC_EVENT_COUNTER_UPDATED, OSSEC_QUEUE_MESSAGE_SEND_FAILED, OSSEC_PROCESS_LOCKED
- Stage 2 signals: communication_failure_count, events_per_minute
- Signs: event-count lines showing a low retained percentage, queue send failures and processes waiting for locks: the agent is dropping events. A flood of noise can be used to hide a real action inside the gap.
- Stronger if: the flood coincides with other alerts on the same host or a known attack window.
- Weaker if: it matches a routine heavy job such as a backup or log burst (RH-OSSEC-07). On its own this is usually needs_review, not malicious.
- Cases: none cited

### OSSEC-09 · Unfamiliar errors from OSSEC processes
- Techniques: none by default; map only if the text shows a technique.
- Event types: OSSEC_UNKNOWN_EVENT
- Stage 2 signals: unknown_event_count, error_count, critical_count, new_event_types
- Signs: an ERROR or CRITICAL line the classifier does not recognise. It may be a new fault, a tampered binary, or an agent reacting to changes on the host.
- Stronger if: the error mentions missing or changed files, keys, queues or permissions, or appears right after OSSEC-01, OSSEC-03 or a suspicious login.
- Weaker if: it repeats on many hosts running the same agent version (a software bug). Isolated unfamiliar errors are needs_review, not malicious.
- Cases: none cited
