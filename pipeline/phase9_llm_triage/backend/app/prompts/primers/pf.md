PF firewall packet logs (OpenBSD/FreeBSD pf via tcpdump), one packet per line:

    2026-04-22 19:16:08.151748 rule 5/0(match): block in on em0: 203.0.113.6.63088 > 10.0.1.5.3389: flags [S], seq 526820593, win 1024, length 0

Fields:
- Timestamp with microseconds.
- "rule N/S(reason)": the firewall rule that matched.
- Action: "pass" (allowed), "block" (dropped) or "match" (logged without a final decision).
- Direction: "in" (arriving on the interface), "out" (leaving it).
- Interface, for example em0.
- "SRC_IP.SRC_PORT > DST_IP.DST_PORT": the last dot-separated number is the port. Lines without ports (ICMP) show only addresses.
- Protocol details. TCP flags: [S] SYN (connection start), [S.] SYN-ACK (reply), [.] ACK, [P.] data, [F.] FIN (close), [R] or [R.] RST (reset). "win" is the TCP window, "length" the payload size. UDP shows "udp, length N". ICMP shows "icmp echo request|reply" and similar. "domain [...] (invalid)" is a malformed DNS packet.

One packet per line, so a single connection can appear as several lines. Client source ports are usually high, random numbers; service ports are well known (22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80/443 HTTP(S), 123 NTP, 135/139/445 Windows RPC/SMB, 161 SNMP, 389/636 LDAP, 1433 MSSQL, 1521 Oracle, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 5900 VNC, 6379 Redis, 9200 Elasticsearch, 27017 MongoDB).

Patterns that usually matter:
- One source sending SYNs to many ports on one host (vertical scan) or to one port on many hosts (horizontal sweep), especially to administrative or database ports.
- Several external sources probing the same internal host in a short time.
- Traffic that was passed (not blocked) to sensitive ports from external addresses.
- Internal hosts initiating connections to unusual external ports, many destinations, or at unusual times, which can indicate malware or data transfer.
- Malformed packets, odd flag combinations (for example FIN, NULL or XMAS scans) and very small window sizes (for example win 1024) typical of scanning tools.

Patterns that are usually benign:
- Internal clients reaching internal services on their normal ports (DNS, HTTPS, NTP, ICMP echo to gateways).
- A single blocked packet with no follow-up, especially a lone RST or late reply; stray and backscatter packets are common internet noise.
- Background scanning from the internet that was entirely blocked is hostile in intent but routine. It is usually malicious with low severity, not an incident.

Always note whether the packets were blocked or passed, whether any reply came back, and whether the sources and destinations are internal or external (use the site context for internal ranges; RFC 1918 addresses such as 10.x, 172.16-31.x and 192.168.x are private).
