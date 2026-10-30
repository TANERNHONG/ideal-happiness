# Attack patterns: Solaris authentication logs

Patterns an attacker leaves in sshd, su, login, gdm and PAM messages. IDs
marked † were not re-checked against ATT&CK v19.2 (see README). Stage 2
signals are columns of `authlog_authentication_sessions.csv`,
`authlog_host_windows_5min.csv` and `authlog_host_behavior_1d.csv`.

### AUTH-01 · SSH password guessing (brute force)
- Techniques: T1110.001 Password Guessing (Credential Access)
- Event types: SSH_LOGIN_FAILED, SSH_MAX_AUTHENTICATION_ATTEMPTS_EXCEEDED, SSH_DISCONNECTING_AUTH_FAILURES, SSH_PAM_MAX_ATTEMPTS_EXCEEDED, SSH_AUTHENTICATION_POSTPONED
- Stage 2 signals: failure_count, events_per_minute, authentication_failed, close_reason, unique_source_ports
- Signs: many "Failed password|keyboard-interactive" lines for the same account from one source; attempts seconds apart or faster; each connection (new source port) ends in "Too many authentication failures" or a reset; "Failed none" first (a tool listing allowed methods); privileged or default names (root, admin, oracle).
- Stronger if: the source is external or never seen before; it continues after lockouts; the same source appears in PF logs hitting port 22 (PF-05); it ends in SSH_LOGIN_SUCCESS (see AUTH-05).
- Weaker if: the source is an internal automation or management host, the attempts recur on a fixed schedule, and they stop after a credential fix (RH-AUTH-01).
- Cases: CASE-KINSING, CASE-RAPPERBOT, CASE-FRITZFROG

### AUTH-02 · Username enumeration with invalid accounts
- Techniques: T1110.001 Password Guessing; T1595.003 Wordlist Scanning (Reconnaissance)
- Event types: SSH_INVALID_USER, SSH_INVALID_USER_CONNECTION_CLOSED, SSH_INVALID_USER_CONNECTION_RESET, SSH_PAM_NO_ACCOUNT_PRESENT, SSH_LOGIN_FAILED with "invalid user"
- Stage 2 signals: invalid_user_count, unique_usernames, username_entropy, dominant_username
- Signs: "Invalid user X from IP" for many different names in a short time, typically from a wordlist (admin, test, user, guest, oracle, postgres, ubuntu, pi, git, ftp); each attempt closed pre-authentication.
- Stronger if: many names are tried per source; names match real staff or service accounts (targeted); valid-account failures follow.
- Weaker if: a single mistyped name from an internal host followed by a success with the correct name (RH-AUTH-05).
- Cases: CASE-RAPPERBOT, CASE-MIRAI

### AUTH-03 · Password spraying (low and slow)
- Techniques: T1110.003 Password Spraying (Credential Access)
- Event types: SSH_LOGIN_FAILED, SSH_PAM_CONVERSATION_FAILURE, error: PAM: Authentication failed (SSH_LOGIN_FAILED)
- Stage 2 signals: host_behavior_1d unique_usernames and unique_source_ips high, failure_count moderate, few failures per account; new_usernames, new_source_ips
- Signs: one or two failures per account across many valid accounts, spread over hours or days, often from several source addresses; no single account reaches its lockout threshold.
- Stronger if: the accounts share a pattern (all service accounts, alphabetical order); sources are external or residential; a single success appears for an account that rarely logs in.
- Weaker if: one shared jump host or VPN address accounts for all users and most logins succeed (RH-AUTH-09).
- Cases: CASE-MIDNIGHT-BLIZZARD

### AUTH-04 · Credential stuffing
- Techniques: T1110.004 Credential Stuffing (Credential Access)
- Event types: SSH_LOGIN_FAILED, SSH_LOGIN_SUCCESS
- Stage 2 signals: unique_usernames, unique_source_ips, success_count and failure_count together
- Signs: many real usernames, each tried once or twice with a different password, often from many addresses; a few succeed immediately with no prior failures because the reused password was correct.
- Stronger if: the successful accounts are ones whose owners reuse passwords elsewhere, or logins arrive from networks the users have never used.
- Weaker if: the usernames are the normal daily population from the usual sources.
- Cases: none cited; see CASE-MIDNIGHT-BLIZZARD for the related spraying behaviour.

### AUTH-05 · Successful login after guessing, or with a dormant or default account
- Techniques: T1078.003 Local Accounts; T1078.001 Default Accounts (Stealth, Persistence); T1133 External Remote Services
- Event types: SSH_LOGIN_SUCCESS preceded by SSH_LOGIN_FAILED or SSH_INVALID_USER; LOGIN_ROOT_CONSOLE
- Stage 2 signals: authentication_succeeded with failure_count > 0 in the same session; new_source_ips, new_usernames in host_behavior_1d
- Signs: "Accepted password for USER from IP" from the same source that just failed repeatedly; a first-ever login for a service, default or long-unused account; a login at an hour the account never uses.
- Stronger if: the source is external; the account is privileged (root, oracle, admin); su to root or an SFTP subsystem request follows within minutes (AUTH-10, AUTH-13).
- Weaker if: a named user's own workstation, a few typos then success during working hours (RH-AUTH-05).
- Cases: CASE-FRITZFROG, CASE-RAPPERBOT, CASE-COLONIAL, CASE-MIRAI

### AUTH-06 · Persistence through SSH authorized keys
- Techniques: T1098.004 SSH Authorized Keys (Persistence)
- Event types: SSH_LOGIN_SUCCESS (method publickey, with key_type and fingerprint), SSH_LOGIN_FAILED (method publickey), SSH_AUTHORIZED_KEYS_PERMISSIONS_INVALID
- Stage 2 signals: authentication_method_sequence, unique_authentication_methods, new_authentication_methods
- Signs: an account that always used passwords starts logging in with "Accepted publickey" shortly after a suspicious password login; a new key fingerprint for an account; "Authentication refused: bad ownership or modes for file …/authorized_keys" (the file was rewritten); legitimate users suddenly failing publickey because their keys were replaced.
- Stronger if: the first publickey login comes from the address that brute-forced the account, or from a new external address.
- Weaker if: the user or an administrator deployed keys during a documented change; permission errors after a home-directory migration.
- Cases: CASE-RAPPERBOT, CASE-FRITZFROG

### AUTH-07 · Tampering with PAM (authentication backdoor)
- Techniques: T1556.003 Pluggable Authentication Modules (Defense Impairment, Persistence)
- Event types: PAM_MODULE_STAT_FAILED, PAM_MODULE_LOAD_FAILED, SSH_PAM_CONVERSATION_FAILURE, PAM_AUTHENTICATION_TOKEN_MANIPULATION_ERROR
- Stage 2 signals: pam_error_count, unknown_event_count
- Signs: "open_module[N:/etc/pam.conf]: stat(/usr/lib/security/…) failed" or "can not open module" for a module path that is unusual, new, or outside /usr/lib/security; PAM errors appearing suddenly on a host that had none; a successful login for an account whose failures continue (a hard-coded backdoor password works while the real one does not).
- Stronger if: it coincides with an sshd restart (AUTH-11), agent stops (OSSEC-01) or integrity-baseline resets (OSSEC-03) on the same host.
- Weaker if: the missing module belongs to a package removed during patching and the errors began at a documented upgrade (RH-AUTH-08).
- Cases: CASE-UNC1945, CASE-UNC2891

### AUTH-08 · Pre-authentication exploitation of sshd or PAM
- Techniques: T1190† Exploit Public-Facing Application; T1133 External Remote Services
- Event types: SSH_AUTHENTICATION_POSTPONED (keyboard-interactive/pam), SSH_PAM_CONVERSATION_FAILURE, SSH_BAD_PACKET_LENGTH, SSH_DISPATCH_PROTOCOL_ERROR, SSH_CONNECTION_RESET [preauth], SSH_PROCESS_OUTPUT_BROKEN_PIPE
- Stage 2 signals: protocol_error_count, pam_error_count, connection_reset_count
- Signs: malformed or aborted keyboard-interactive/PAM exchanges from one source with no normal authentication outcome; protocol errors or bad packet lengths from a host that also sends valid SSH; activity as root or a new process soon after, without an "Accepted" line.
- Stronger if: the host is an unpatched Solaris 9-11 system exposed to the network (CVE-2020-14871 was exploited this way); followed by PAM changes (AUTH-07) or monitoring gaps (OSSEC-01).
- Weaker if: the errors come from a known scanner, an old client, or network equipment corrupting packets (RH-AUTH-03, RH-AUTH-04). The authentication logs alone rarely prove exploitation: treat as needs_review unless follow-on activity is visible.
- Cases: CASE-UNC1945

### AUTH-09 · SSH service scanning and fingerprinting
- Techniques: T1595.002 Vulnerability Scanning; T1595.001 Scanning IP Blocks (Reconnaissance)
- Event types: SSH_KEX_INVALID_BANNER, SSH_KEX_INVALID_PROTOCOL_IDENTIFIER, SSH_PROTOCOL_VERSION_MISMATCH, SSH_KEX_CONNECTION_CLOSED, SSH_KEX_CONNECTION_RESET, SSH_CONNECTION_CLOSED [preauth]
- Stage 2 signals: protocol_error_count, connection_close_count, unique_source_ips
- Signs: connections that send a non-SSH banner (HTTP requests, random bytes) or close immediately after the key exchange, with no authentication attempt; many external sources, or one source repeating every few seconds.
- Stronger if: the same sources then attempt logins (AUTH-01/02) or appear scanning other ports in PF (PF-01).
- Weaker if: the sources are internal monitoring or load-balancer health checks on a fixed interval (RH-AUTH-03), or an authorised scanner (RH-AUTH-04). Internet scanning that goes no further is routine: malicious intent, low severity.
- Cases: CASE-MIRAI, CASE-RAPPERBOT

### AUTH-10 · Privilege escalation with su or root console
- Techniques: T1078.003 Local Accounts (Stealth, Persistence); T1110.001 Password Guessing (for repeated su failures)
- Event types: SU_SESSION_FAILED, SU_SESSION_SUCCESS, SU_SESSION_INITIATED, LOGIN_ROOT_CONSOLE, LOGIN_REPEATED_CONSOLE_FAILURES
- Stage 2 signals: privilege_failure_count, privilege_success_count, unique_target_usernames, unique_terminal_paths
- Signs: "'su root' failed for USER" several times, then "succeeded"; su by an account that never switches users; su to root minutes after that account logged in from a new source; root console login outside working hours.
- Stronger if: preceded by AUTH-05 on the same host; the su user is a service or application account.
- Weaker if: an administrator switching to root during a change window from their usual terminal (RH-AUTH-07).
- Cases: none directly; see CASE-UNC1945 for post-exploitation root activity on Solaris.

### AUTH-11 · Tampering with sshd configuration or keys
- Techniques: T1556 Modify Authentication Process (sshd options); T1571 Non-Standard Port (Command and Control); T1098.004 SSH Authorized Keys
- Event types: SSH_DAEMON_RESTARTING, SSH_DAEMON_TERMINATING, SSH_DAEMON_EXITING_SIGNAL, SSH_SERVER_LISTENING, SSH_HOST_KEY_LOAD_FAILED, SSH_DEPRECATED_OPTION
- Stage 2 signals: unknown_event_count, event_type_entropy, new_event_types
- Signs: sshd reloaded (SIGHUP) outside maintenance; "Server listening on … port N" with an unexpected port or address (a second, backdoor sshd); host keys that can no longer be loaded (replaced or removed); new deprecated-option warnings showing the configuration was edited.
- Stronger if: it follows a suspicious login or su on the same host; OSSEC reports integrity changes or agent stops around the same time.
- Weaker if: it coincides with OS patching or a documented configuration change across several hosts (RH-AUTH-08).
- Cases: CASE-UNC1945 (sshd-based access on Solaris)

### AUTH-12 · Account lockouts caused by attacks
- Techniques: T1110 Brute Force (the lockout is its side effect); T1531 Account Access Removal (Impact) when lockout is the goal
- Event types: AUTH_ACCOUNT_LOCKED, GDM_ACCOUNT_LOCKED, LOGIN_REPEATED_CONSOLE_FAILURES, CRON_LOCKED_ACCOUNT_VALIDATION
- Stage 2 signals: account_lock_count, failure_count
- Signs: "Excessive (N) login failures for USER: locking account" for privileged or several accounts in a short time, especially from remote sources; lockouts that stop scheduled jobs (cron validating a locked account).
- Stronger if: several accounts lock together; the failures came from an external source (AUTH-01, AUTH-03).
- Weaker if: one user locked out at their own console after a password change (RH-AUTH-05), or a cron job owned by an intentionally disabled account (RH-AUTH-06).
- Cases: CASE-RAPPERBOT (legitimate users locked out after key replacement)

### AUTH-13 · File transfer after suspicious access
- Techniques: T1048† Exfiltration Over Alternative Protocol; T1105 Ingress Tool Transfer (Command and Control)
- Event types: SSH_SUBSYSTEM_REQUEST (sftp), SSH_SUBSYSTEM_NOT_FOUND
- Stage 2 signals: event_type_sequence in authentication_sessions
- Signs: "subsystem request for sftp by user X" in a session that began with guessing or a first-ever login; SFTP by an account that never uses it; requests for subsystems that do not exist (tools probing capabilities).
- Stronger if: the session source is new or external; OSSEC shows file changes afterwards.
- Weaker if: the account is a known file-transfer or backup account on its normal schedule (RH-AUTH-01).
- Cases: CASE-FRITZFROG (payload transfer over SSH)

### AUTH-14 · Access-control rejections that reveal targeting
- Techniques: T1078 Valid Accounts (attempted); T1110.001 Password Guessing
- Event types: SSH_USER_NOT_ALLOWED, SSH_PAM_ACCOUNT_ACCESS_DENIED, SSH_PUBLIC_KEY_TYPE_NOT_ACCEPTED, GDM_EMPTY_PASSWORD_NOT_ALLOWED
- Stage 2 signals: access_denied_count
- Signs: login attempts for real service accounts that are deliberately not allowed to log in (the attacker knows the account names); empty-password attempts; keys of disallowed types from unknown sources.
- Stronger if: combined with AUTH-02 from the same source.
- Weaker if: a misconfigured internal client or application repeatedly trying a service account (RH-AUTH-01). The control worked, so severity is low.
- Cases: none cited
