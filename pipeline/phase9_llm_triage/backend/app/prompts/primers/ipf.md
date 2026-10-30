IPFilter firewall logs from Solaris (written by ipmon), one packet per line:

    /var/log/ipflog.22:Nov 30 03:13:03 mm06moc ipmon[172]: [ID 702911 local0.warning] 03:13:03.560605 e1000g0 @0:1 b 172.16.10.29,40781 -> 172.16.10.26,9711 PR tcp len 20 60 -S IN

Fields:
- An optional collection prefix (the rotated log file the line came from, e.g. /var/log/ipflog.22), then the syslog date and time, the host, ipmon[pid] and the message ID.
- Packet time with microseconds, then an optional repeat count: "2x" means two identical packets were folded into this one line.
- Interface (e1000g0), then "@group:rule": the rule that matched (@0:1 is rule 1 of group 0).
- Action: b = blocked, p = passed, L = logged only, S = short packet, n = no rule matched.
- "SRC_IP,SRC_PORT -> DST_IP,DST_PORT": addresses with the port after a comma. ICMP lines have no ports.
- "PR tcp|udp|icmp", then "len" with the IP header length and the total packet length.
- TCP flags: -S SYN (request to open a connection), -SEC SYN offering ECN congestion signalling (the first try of a modern client), -A ACK, -P PSH (data), -F FIN (close), -R RST (reset, giving up). ICMP shows the type/code instead. The last word is the direction, IN or OUT.

THIS LOG IS EMPTY IN NORMAL OPERATION. Eleven of the twelve monthly files collected for this server contain no lines at all, and the server was up throughout (its OSSEC agent logged every day). So:
- Every line is unusual by policy. "Unusual" says nothing about intent; the question is what the traffic was and whether it was expected.
- For alerts found in the "presence" file, the unusualness figure is the alert's rank among this log's alerts by how unlike the rest of the activity it is (1.0 = least like the rest), not a rank among all observations.
- A TCP client that cannot connect retries on a fixed schedule: one -SEC, several -S retries with growing gaps, then -R after about a minute, and the cycle repeats. Thousands of lines at a steady interval from one source to one port is one stuck client, not thousands of attacks.
- Check whether anything was passed (p). If every packet was blocked, nothing got through.
- Use the change windows and site context: activity during a recorded change (for example a migration) on the flows that change involves is expected; activity outside it, or on other flows, is not explained by it.
- Private addresses (RFC 1918: 10.x, 172.16-31.x, 192.168.x) are internal. Broadcasts end in .255.
