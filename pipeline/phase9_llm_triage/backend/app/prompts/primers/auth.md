Authentication logs from Solaris hosts, in syslog format:

    Apr  3 14:02:11 hostname sshd[2481]: [ID 800047 auth.info] Accepted publickey for alice from 10.0.0.7 port 51234 ssh2

Fields: timestamp (no year), host, process and PID, a Solaris message ID and facility, then the message. Lines with the same PID and host usually belong to one connection or login.

Common messages and what they usually mean:
- "Accepted password|publickey|keyboard-interactive for USER from IP port P": successful SSH login.
- "Failed password|publickey|none for [invalid user] USER from IP": failed SSH authentication. "none" is often a client probing which methods are allowed.
- "Invalid user|Illegal user USER from IP": a login attempt for an account that does not exist. Many different names from one address suggests username guessing.
- "Postponed keyboard-interactive/pam for USER": an intermediate step of a normal login, not a failure.
- "error: PAM: Authentication failed|Maximum number of attempts exceeded|Conversation failure for USER": PAM-level failures.
- "Disconnecting ... Too many authentication failures" and "maximum authentication attempts exceeded": the client exhausted its attempts in one connection.
- "Connection closed|reset by IP port P [preauth]": the client left before authenticating. Common for scanners, health checks and banner grabbers.
- "Received disconnect from IP ... disconnected by user": a normal logout.
- "kex_exchange_identification: ...", "Bad packet length", "Protocol major versions differ", "dispatch_protocol_error": malformed or non-SSH clients; typical of scanners or broken tools.
- "'su USER' succeeded|failed for USER on /dev/pts/N": a local user switching accounts. su to root deserves attention when it follows failures or comes from an unexpected user.
- "ROOT LOGIN /dev/console" and "REPEATED LOGIN FAILURES ON /dev/...": console access.
- "Excessive (N) login failures for USER: locking account": an account lock after repeated failures.
- "User USER not allowed because not listed in AllowUsers", "Access denied ... by PAM account configuration": access control working as intended.
- "last message repeated N times": the previous line repeated N times; count it as N events.

Patterns that usually matter: many failures followed by a success from the same source; many usernames from one source; successful logins from addresses never seen before; root or privileged logins at unusual times; su chains to root; account locks on privileged accounts.

Patterns that are usually benign: single failures followed by success (typing mistakes); preauth closes from monitoring or load-balancer addresses; publickey "Failed" lines immediately followed by "Accepted" (the client tried several keys); normal logout sequences.
