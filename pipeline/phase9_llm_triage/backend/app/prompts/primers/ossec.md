OSSEC host-agent logs (the agent's own operational log, not the security alerts it forwards):

    2026/04/18 08:54:00 ossec-syscheckd(1200): INFO: Starting syscheck scan.

Fields: timestamp, OSSEC process and PID, severity (INFO, WARNING, ERROR, CRITICAL), then the message. The host comes from the archive the log was collected from.

Processes:
- ossec-agentd: keeps the connection to the OSSEC manager and forwards events.
- ossec-syscheckd: file-integrity monitoring (scans and checksum baselines).
- ossec-rootcheck: rootkit and policy checks.
- ossec-logcollector: reads monitored log files and passes them to the agent.
- ossec-execd: runs active-response commands (for example blocking an IP).

Routine messages (normally benign on their own):
- "Starting|Ending syscheck scan" and "Starting|Ending rootcheck scan": scheduled scans. A start without a matching end can simply mean the scan was still running when the logs were collected.
- "Server unavailable. Setting lock." → "Waiting for server reply" → "Trying to connect to server" → "Connected to the server": a brief loss and recovery of manager connectivity.
- "Started (pid: N)", "Reading authentication keys file", "Reading rules file", "Monitoring directory", "Analyzing file": start-up after a restart or reboot.
- "Event count after 'N': X->Y (Z%)": event-rate statistics.
- "Assigning counter for agent", "Assigning sender counter": message counters after a restart.

Messages that deserve attention:
- "SIGNAL Received. Exit Cleaning...", "Shutdown received. Deleting responses.", "E-Mail notification disabled. Clean Exit.": the agent stopped. Expected during patching or reboots; suspicious when unplanned, repeated, or followed by a long silence, because stopping the agent blinds monitoring.
- Repeated "Unable to send message to server", "Error sending message to queue" or long unresolved "Server unavailable" periods: events may have been lost.
- "No previous md5|sha1 checksum found ... Starting over" and "File ... not found. MD5|SHA1 checksum skipped": the integrity baseline was reset or files disappeared; changes made in between cannot be detected.
- "Manager IP not set", "Active response command not present": a configuration gap.
- "Ignoring file": a file excluded from monitoring; expected when configured, suspicious when new.
- ERROR or CRITICAL lines with unfamiliar text: an unusual fault. Treat as needs review unless the surrounding lines explain it.

Key question for OSSEC alerts: did monitoring keep working? Tampering usually shows up as agent stops, lost connectivity, baseline resets or new exclusions, especially close together in time. Isolated routine scan or reconnect lines are rarely malicious.
