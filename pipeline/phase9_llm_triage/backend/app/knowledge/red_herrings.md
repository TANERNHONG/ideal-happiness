# Red herrings: benign sequences that look like attacks

Each entry describes routine activity that resembles an attack pattern, the
signs that separate it from the real thing, and what would make it real after
all. A red herring is a hypothesis to test against the lines, not a reason to
dismiss an alert: attackers deliberately imitate routine activity.

## Authentication logs

### RH-AUTH-01 · Automation retrying stale credentials
- Looks like: AUTH-01 password guessing, AUTH-12 lockouts
- Event types: SSH_LOGIN_FAILED, SSH_PAM_CONVERSATION_FAILURE, AUTH_ACCOUNT_LOCKED
- Actually: a script, monitoring check, backup job or configuration-management tool (such as Ansible) still using an old password after a rotation, or pointed at the wrong account.
- Tell-tale signs: one internal source; one account (a service account); the same number of failures each run at exact intervals (every 5 minutes, hourly); started at a known password change; never followed by a success with a different password.
- Would be real if: the source is external or new; several accounts are tried; timing is irregular or speeds up; a success follows from the same source.

### RH-AUTH-02 · SSH client trying several keys
- Looks like: AUTH-01 guessing, AUTH-06 key abuse
- Event types: SSH_LOGIN_FAILED (publickey), SSH_LOGIN_SUCCESS (publickey)
- Actually: an SSH client offers each key in the user's agent until one is accepted; each rejected key is logged as a failure.
- Tell-tale signs: all within one connection (same PID and source port), within a second or two; ends in "Accepted publickey" for the same user; the source is the user's usual machine.
- Would be real if: the failures span many connections, users or sources, or the accepted key fingerprint is new for that account.

### RH-AUTH-03 · Health checks and monitoring probes
- Looks like: AUTH-09 scanning, AUTH-08 pre-authentication exploitation
- Event types: SSH_CONNECTION_CLOSED [preauth], SSH_KEX_CONNECTION_CLOSED, SSH_KEX_INVALID_BANNER, SSH_KEX_CONNECTION_RESET, SSH_CONNECTION_RESET
- Actually: a load balancer, uptime monitor or monitoring plug-in (such as check_ssh) opening a TCP connection to port 22 and closing it, or sending a non-SSH probe string.
- Tell-tale signs: one or two fixed internal addresses; a strict interval (every 30 or 60 seconds) around the clock; never any username or authentication attempt.
- Would be real if: the source is external or new, the interval is irregular, or authentication attempts follow.

### RH-AUTH-04 · Authorised vulnerability scan
- Looks like: AUTH-02 enumeration, AUTH-08 exploitation, AUTH-09 scanning
- Event types: SSH_INVALID_USER, SSH_PROTOCOL_VERSION_MISMATCH, SSH_BAD_PACKET_LENGTH, SSH_KEX_INVALID_PROTOCOL_IDENTIFIER, SSH_DISPATCH_PROTOCOL_ERROR
- Actually: the organisation's vulnerability scanner testing sshd for weak algorithms, default accounts and known flaws.
- Tell-tale signs: the source is the scanner address named in the site context; the activity falls in its scan window and hits many hosts in the same order; it stops at the window's end.
- Would be real if: the scanner address is not listed, the timing is outside the window, or a login succeeds.

### RH-AUTH-05 · A user mistyping or with an expired password
- Looks like: AUTH-01 guessing, AUTH-12 lockouts, AUTH-02 invalid users
- Event types: SSH_LOGIN_FAILED, SSH_INVALID_USER, GDM_ACCOUNT_LOCKED, LOGIN_REPEATED_CONSOLE_FAILURES, PAM_PASSWORD_CHANGE_CONVERSATION_FAILURE, PAM_AUTHENTICATION_TOKEN_MANIPULATION_ERROR
- Actually: a person getting the password wrong a few times (often after a change), mistyping the username, or failing to complete a forced password change.
- Tell-tale signs: two to five failures then success for the same user from their usual machine or console; working hours; an invalid username that differs from the real one by a character or two; a password-change error at the first login after expiry.
- Would be real if: failures continue past the lockout, come from an unusual source, or target several accounts.

### RH-AUTH-06 · Cron job owned by a locked account
- Looks like: AUTH-12 lockout attack
- Event types: CRON_LOCKED_ACCOUNT_VALIDATION
- Actually: an account was deliberately locked (leaver, retired service) but still owns a crontab, so cron logs a validation failure at every scheduled run.
- Tell-tale signs: exact recurring times (every hour, daily at 02:00); "from local host"; no remote source; the account has no recent logins.
- Would be real if: the account was not supposed to be locked, several accounts started locking together, or remote failures preceded it.

### RH-AUTH-07 · Administrator switching to root during a change
- Looks like: AUTH-10 privilege escalation
- Event types: SU_SESSION_INITIATED, SU_SESSION_SUCCESS, SU_SESSION_FAILED
- Actually: a named administrator using su to perform approved work.
- Tell-tale signs: the user is in the administrators group per site context; their usual terminal and source; working hours or a documented change window; at most one or two mistypes.
- Would be real if: the account never uses su, the login came from a new source minutes earlier, or it happens at night with no change record.

### RH-AUTH-08 · sshd restarted during patching or upgrade
- Looks like: AUTH-11 sshd tampering, AUTH-07 PAM tampering
- Event types: SSH_DAEMON_RESTARTING, SSH_DAEMON_TERMINATING, SSH_DAEMON_EXITING_SIGNAL, SSH_SERVER_LISTENING, SSH_DEPRECATED_OPTION, SSH_HOST_KEY_LOAD_FAILED, PAM_MODULE_STAT_FAILED
- Actually: operating-system patching or an OpenSSH upgrade restarts sshd, and the new version warns about options the old configuration still contains; removed packages leave pam.conf pointing at modules that no longer exist.
- Tell-tale signs: many hosts show the same messages within the same maintenance window; "Server listening" on the normal port and addresses; the same deprecated options everywhere; the missing PAM module belongs to a known removed package.
- Would be real if: only one host changed, it listens on a new port, the missing module has an unusual name or path, or it follows a suspicious login.

### RH-AUTH-09 · Shared jump host, VPN or NAT address
- Looks like: AUTH-03 password spraying, AUTH-02 enumeration
- Event types: SSH_LOGIN_SUCCESS, SSH_LOGIN_FAILED from one source for many users
- Actually: many people connect through one bastion, VPN concentrator or NAT gateway, so every user appears to come from the same address.
- Tell-tale signs: the address is listed as a jump host or VPN pool in the site context; most logins succeed; the users are real staff logging in at normal times; the failures are scattered typos.
- Would be real if: failures dominate, the usernames are generic or invalid, or accounts that never log in suddenly do.

### RH-AUTH-10 · Desktop keyring and D-Bus noise
- Looks like: credential theft or privilege abuse
- Event types: GNOME_KEYRING_STORE_OPEN_FAILED, GNOME_KEYRING_NO_PRIVATE_KEYS, GNOME_KEYRING_INVALID_PRIVATE_SSH_KEY, GNOME_KEYRING_SIGNING_FAILED, GNOME_KEYRING_SECURE_MEMORY_ALLOCATION_FAILED, GNOME_KEYRING_INTERNAL_ASSERTION_FAILED, DBUS_SEND_MESSAGE_REJECTED
- Actually: a desktop session's keyring cannot unlock after a password change, file permissions in a home directory are wrong, or an application sends a D-Bus message the policy does not allow.
- Tell-tale signs: happens at graphical login; the same user and host repeatedly; no remote source; no other alerts.
- Would be real if: keyring access errors appear for another user's store, or accompany a remote login and su on the same host.

### RH-AUTH-11 · Broken pipes and resets from unstable networks
- Looks like: AUTH-08 exploitation, AUTH-09 scanning
- Event types: SSH_INTERNAL_MESSAGE_SEND_BROKEN_PIPE, SSH_PACKET_SEND_DEBUG_BROKEN_PIPE, SSH_PROCESS_OUTPUT_BROKEN_PIPE, SSH_KEX_WRITE_BROKEN_PIPE, SSH_CONNECTION_RESET, SSH_SOCKET_OPTION_ERROR
- Actually: a client dropped mid-session (laptop sleep, Wi-Fi loss, an interrupted scp) or a network device reset the connection.
- Tell-tale signs: follows a successful login by a known user; isolated; the user reconnects shortly after.
- Would be real if: many resets come from unknown sources before authentication, or they are paired with protocol errors (AUTH-08).

## OSSEC agent logs

### RH-OSSEC-01 · Planned patching or reboot
- Looks like: OSSEC-01 agent stopped, OSSEC-07 unexpected reboot
- Event types: OSSEC_SIGNAL_RECEIVED_EXITING, OSSEC_SHUTDOWN_RESPONSES_DELETED, OSSEC_EMAIL_DISABLED_CLEAN_EXIT, OSSEC_PROCESS_STARTED, OSSEC_AUTHENTICATION_KEYS_READING
- Actually: the host or agent restarted during maintenance.
- Tell-tale signs: every OSSEC process stops and the full start-up sequence follows within minutes; many hosts do the same in the same window; the site context lists a patch window at that time.
- Would be real if: the agent stays down, only one host is affected outside a window, or integrity resets and exclusions appear afterwards.

### RH-OSSEC-02 · Manager outage or network blip
- Looks like: OSSEC-02 agent cut off from the manager
- Event types: OSSEC_SERVER_UNAVAILABLE_LOCK_SET, OSSEC_WAITING_FOR_REPLY, OSSEC_CONNECTION_ATTEMPT, OSSEC_SERVER_CONNECTED, OSSEC_SERVER_RESPONDED_LOCK_RELEASED
- Actually: the manager restarted or a network path was briefly unavailable.
- Tell-tale signs: many agents lose the manager at the same moment and reconnect together; the gap is short; the same manager address is reconnected.
- Would be real if: only this host is affected, the gap is long, or it coincides with suspicious activity on the host.

### RH-OSSEC-03 · Agent install, reinstall or upgrade
- Looks like: OSSEC-03 integrity baseline reset, OSSEC-05 configuration gaps
- Event types: OSSEC_PREVIOUS_CHECKSUM_NOT_FOUND, OSSEC_SYSCHECK_DATABASE_PRESCAN_STARTED, OSSEC_SYSCHECK_DATABASE_PRESCAN_COMPLETED, OSSEC_PREVIOUS_AGENT_COUNTER_UNAVAILABLE, OSSEC_AGENT_COUNTER_ASSIGNED
- Actually: a new or upgraded agent has no previous integrity database or counters, so it builds them from scratch.
- Tell-tale signs: the host is new, or many hosts show the same messages during a rollout; a full start-up sequence precedes it; no prior stop without restart.
- Would be real if: a long-running agent on one host loses its database with no upgrade, especially after a stop or a suspicious login.

### RH-OSSEC-04 · Long scans and scans cut off by collection
- Looks like: OSSEC-06 rootcheck anomalies
- Event types: OSSEC_SYSCHECK_SCAN_STARTED, OSSEC_ROOTCHECK_SCAN_STARTED without a matching end
- Actually: large file systems make scans long, or the logs were collected before the scan finished.
- Tell-tale signs: the missing end is at the very end of the collected data; the host's scans are always long; ends are present on other days.
- Would be real if: scans stop completing on a host that used to finish them, or a stop interrupts them repeatedly.

### RH-OSSEC-05 · Configured ignore lists and allowlists
- Looks like: OSSEC-04 new exclusions or allowlisting
- Event types: OSSEC_FILE_IGNORED, OSSEC_ACTIVE_RESPONSE_IP_ALLOWLISTED, OSSEC_ACTIVE_RESPONSE_HOSTNAME_ALLOWLISTED
- Actually: the agent prints its configured ignore list and active-response allowlist at every start-up.
- Tell-tale signs: the same paths and addresses appear at every restart on this and similar hosts; they are standard (volatile files, the manager's own address, localhost).
- Would be real if: a path or address appears for the first time, is external, or relates to logs, authentication files or binaries.

### RH-OSSEC-06 · Log rotation removing monitored files
- Looks like: OSSEC-03 files vanishing
- Event types: OSSEC_CHECKSUM_SOURCE_FILE_NOT_FOUND
- Actually: log rotation renamed or compressed a monitored file before the integrity check reached it.
- Tell-tale signs: the file names end in a rotation suffix or are logs; it happens at the usual rotation time; the file reappears later.
- Would be real if: the missing files are binaries or configuration, or rotation is not scheduled then.

### RH-OSSEC-07 · Heavy but legitimate workloads
- Looks like: OSSEC-08 event loss during floods
- Event types: OSSEC_EVENT_COUNTER_UPDATED, OSSEC_QUEUE_MESSAGE_SEND_FAILED, OSSEC_PROCESS_LOCKED
- Actually: backups, batch jobs or log bursts overwhelm the agent queue.
- Tell-tale signs: recurs at the same time as a known job; affects hosts running that job; clears when it ends.
- Would be real if: it appears at an unusual time together with other alerts on the host.

## PF firewall logs

### RH-PF-01 · Internet background scanning
- Looks like: PF-01 vertical scan, PF-02 sweep, PF-03 coordinated scanning
- Event types: PF_BLOCK_TCP, PF_BLOCK_UDP to 22, 23, 445, 3389, 5900 and similar
- Actually: every public address receives constant automated scanning from botnets, researchers and search engines for exposed devices.
- Tell-tale signs: every packet blocked; no replies; sources spread across unrelated networks; targets spread across the public range, not one important host; the same pattern every day.
- Would be real if: anything is passed, one internal host is singled out, or the source later appears in authentication logs. Even when routine, this is hostile activity: classify as malicious with low severity, not benign, unless it is a known research scanner in the site context.

### RH-PF-02 · Backscatter from attacks on someone else
- Looks like: PF-04 stealth scans, PF-09 denial of service
- Event types: PF_BLOCK_TCP carrying [S.] or [R] packets, PF_BLOCK_ICMP unreachable messages
- Actually: an attacker flooding a third party spoofed your addresses as the source, so the victim's replies (SYN-ACKs, RSTs, ICMP errors) arrive at your firewall.
- Tell-tale signs: packets are replies (SYN-ACK or RST) to connections your hosts never started; sources are the victims' service ports (80, 443, 53); thin and sporadic; no pattern of destination ports.
- Would be real if: the packets are requests (SYN) rather than replies, or volume is high enough to affect you.

### RH-PF-03 · Authorised scanners and asset discovery
- Looks like: PF-01 vertical scan, PF-02 sweep
- Event types: PF_PASS_TCP, PF_BLOCK_TCP, PF_PASS_ICMP from an internal source to many hosts and ports
- Actually: the vulnerability scanner, network-inventory tool or monitoring system doing its job.
- Tell-tale signs: the source is listed in the site context; activity follows its schedule; the sweep order is consistent between runs.
- Would be real if: the source is not listed, the timing is unusual, or a normal workstation behaves like a scanner.

### RH-PF-04 · Late packets after firewall state expired
- Looks like: PF-04 stealth scans with FIN, RST or ACK
- Event types: PF_BLOCK_TCP carrying [F.], [R], [R.] or [.]
- Actually: a legitimate connection went idle past the firewall's state timeout, and its final FIN, RST or keep-alive ACK was blocked because PF no longer remembers the connection.
- Tell-tale signs: one or two packets between hosts that normally talk to each other; ports match a real service; no sequence across many ports.
- Would be real if: odd-flag packets cover many ports or hosts from one source.

### RH-PF-05 · Infrastructure chatter
- Looks like: PF-09 floods, PF-12 legacy protocols, PF-07 unusual protocols
- Event types: PF_PASS_UDP (NTP 123, DNS 53), PF_*_DHCP, PF_*_RIP, PF_*_ISAKMP, PF_*_SNMP, PF_*_TFTP
- Actually: time sync, name resolution, address assignment, routing updates, VPN key exchange, monitoring polls and network devices loading configuration.
- Tell-tale signs: internal sources and destinations; known servers and devices; regular timing; bursts at boot.
- Would be real if: the traffic crosses to or from the internet (external SNMP or TFTP), or a host that never used the protocol starts.

### RH-PF-06 · Troubleshooting ICMP
- Looks like: PF-01 or PF-02 host discovery
- Event types: PF_PASS_ICMP, PF_BLOCK_ICMP, PF_PASS_ICMP6
- Actually: ping and traceroute by administrators and monitoring, and path-MTU discovery messages ("need to fragment").
- Tell-tale signs: internal monitoring source; a handful of hosts; echo request and reply pairs; regular intervals.
- Would be real if: one source pings whole address ranges in sequence, especially from outside or from a workstation.

### RH-PF-07 · Browsers and applications using many cloud addresses
- Looks like: PF-02 horizontal sweep, PF-07 command and control
- Event types: PF_PASS_TCP to port 443, PF_PASS_UDP to port 443
- Actually: web browsing and cloud applications connect to many content-delivery and cloud addresses on HTTPS.
- Tell-tale signs: outbound to 443 with replies; addresses from large providers; follows working hours; the host is a workstation.
- Would be real if: a server that never browses starts, connections are at exact intervals around the clock to one rare address, or the port is non-standard.

### RH-PF-08 · Scheduled updates, backups and polling
- Looks like: PF-05 brute force at network level, PF-07 beaconing
- Event types: PF_PASS_TCP, PF_PASS_UDP
- Actually: backup agents, update services and monitoring poll or connect at regular intervals, sometimes with many short connections.
- Tell-tale signs: the destination is a known internal or vendor service; many hosts share the schedule; the timing matches configuration.
- Would be real if: only one host does it, the destination is unknown, or the schedule appeared without a deployment.

### RH-PF-09 · Large or unusual DNS parsed as malformed
- Looks like: PF-08 DNS abuse
- Event types: PF_BLOCK_DNS_MALFORMED, PF_PASS_DNS_MALFORMED
- Actually: DNSSEC or EDNS responses larger than the logged snapshot are recorded as "(invalid)" because the packet was truncated in the log, not on the wire.
- Tell-tale signs: from well-known resolvers; to the internal resolver or clients that queried them; spread across many hosts.
- Would be real if: one internal host sends a steady stream of large queries to an unusual external resolver.

### RH-PF-10 · NAT gateway traffic
- Looks like: PF-01 scanning or PF-05 brute force from one source
- Event types: PF_PASS_TCP, PF_BLOCK_TCP from a single address
- Actually: many internal clients behind a NAT gateway or proxy share one source address, so their combined traffic looks like one very busy host.
- Tell-tale signs: the address is a gateway or proxy in the site context; destinations and ports match normal client traffic.
- Would be real if: the combined traffic includes sweeps of internal hosts or sensitive ports that no client uses.

## IPFilter firewall logs

### RH-IPF-01 · Client retrying a service blocked after a change
- Looks like: IPF-03 beaconing or IPF-01 probing
- Event types: IPF_BLOCK_TCP with -SEC, -S, -R repeating
- Actually: after a migration or cutover, an application keeps trying to reach a peer service whose firewall rule was not added. The client gives up after about a minute and tries again, so one stuck connection produces thousands of lines at a perfectly regular interval.
- Tell-tale signs: one source, one destination, one port; the port is an application port used between servers elsewhere (PF logs); the activity starts and stops with a recorded change; the source is a known internal server that also logs in over SSH.
- Would be real if: the port is not used by any application on the site, the source is not part of the change, other ports are tried as well, or the attempts continue long after the change is closed.

### RH-IPF-02 · Monitoring or discovery broadcasts
- Looks like: IPF-02 subnet sweep
- Event types: IPF_BLOCK_UDP to x.x.x.255, port 161 (SNMP)
- Actually: network-management and inventory tools broadcast SNMP queries so that every device answers; a server that does not run SNMP blocks and logs them.
- Tell-tale signs: a handful of packets in a few seconds; the source is an administration or monitoring host (it logs in to servers as an administrator in the auth logs); it recurs occasionally rather than continuously.
- Would be real if: the source is not a monitoring host, the same source also probes other ports, or the broadcasts become frequent.

### RH-IPF-03 · Late packets after a rule reload
- Looks like: IPF-01 probing
- Event types: IPF_BLOCK_TCP with -A, -P, -F or -R flags but no SYN
- Actually: when the firewall is reloaded or its state table is flushed, packets of connections that were already open arrive without matching state and are blocked and logged once.
- Tell-tale signs: no -S packets; a burst lasting seconds right after maintenance; the connections are between known servers on their usual ports.
- Would be real if: SYNs appear, or the burst involves unknown sources.
