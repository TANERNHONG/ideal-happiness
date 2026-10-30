# Attack patterns: PF firewall logs

One line per packet. Event types come from `pipeline/phase1_classify/pf.py`:
`PF_<PASS|BLOCK|MATCH>_<PROTOCOL>` for TCP, UDP, ICMP, ICMP6, RIP, ISAKMP, DHCP,
SNMP and TFTP, plus `PF_<ACTION>_DNS_MALFORMED` for invalid DNS. Stage 2
signals are columns of `pflog_events_all_months.csv` (individual packets),
`pflog_entity_windows_*.csv` (per IP or IP pair), `pflog_implied_flow_sessions.csv`
and `pflog_behavior_windows_*.csv` (per source IP). IDs marked † were not
re-checked against ATT&CK v19.2.

Stage 2's sensitive ports (`SENSITIVE_PORTS`): 21, 22, 23, 25, 69, 110, 135,
137-139, 143, 161, 389, 445, 636, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
5985, 5986, 6379, 9200, 11211, 27017.

### PF-01 · Vertical port scan of one host
- Techniques: T1046† Network Service Discovery; T1595.001 Scanning IP Blocks (Reconnaissance)
- Event types: PF_BLOCK_TCP, PF_PASS_TCP, PF_BLOCK_UDP
- Stage 2 signals: unique_destination_ports, syn_count, sensitive_port_block_count, destination_port_entropy (behavior windows), entity_type=source_ip
- Signs: one source sends TCP SYN ([S]) packets to many different destination ports on the same host within seconds or minutes; small fixed window sizes (win 1024 is typical of scanner tools); no follow-up data packets; administrative and database ports prominent.
- Stronger if: the same source later hits a port that is passed, or logs in over SSH (AUTH-01, AUTH-05); the source is internal (an infected host exploring the network).
- Weaker if: the source is an authorised scanner or asset-discovery tool on its schedule (RH-PF-03). An external scan that was entirely blocked is routine: malicious intent, low severity (RH-PF-01).
- Cases: CASE-MIRAI, CASE-RAPPERBOT

### PF-02 · Horizontal sweep of one port across many hosts
- Techniques: T1595.001 Scanning IP Blocks; T1210† Exploitation of Remote Services (for worms)
- Event types: PF_BLOCK_TCP, PF_PASS_TCP
- Stage 2 signals: unique_destination_ips, new_destination_ips (behavior windows), syn_count, sensitive_port_block_count
- Signs: one source sends SYNs to the same port (445, 22, 23, 3389, 6379 …) on many addresses in sequence or at random.
- Stronger if: the source is an **internal** host sweeping internal ranges: a worm or an intruder moving laterally. That is serious regardless of how many packets were blocked.
- Weaker if: an internal monitoring, backup or inventory server contacting its fleet on its usual port and schedule (RH-PF-03, RH-PF-08).
- Cases: CASE-WANNACRY, CASE-MIRAI

### PF-03 · Coordinated scanning from many sources
- Techniques: T1595.001 Scanning IP Blocks; T1090 Proxy (distributed infrastructure)
- Event types: PF_BLOCK_TCP
- Stage 2 signals: entity_type=destination_ip windows with high unique_source_ips and sensitive_port_block_count
- Signs: several external sources probe the same internal host and ports within a short window; each source sends only a few packets, keeping every one below per-source thresholds.
- Stronger if: the targets are a small set of important hosts, not random addresses; the ports match a known vulnerable service on those hosts.
- Weaker if: the sources and ports look like random internet background noise spread across all public addresses (RH-PF-01).
- Cases: CASE-RAPPERBOT (thousands of scanning IPs), CASE-MIDNIGHT-BLIZZARD (distributed residential proxies)

### PF-04 · Stealth scans and firewall mapping with odd TCP flags
- Techniques: T1046† Network Service Discovery; T1590.006 Gather Victim Network Information: Network Security Appliances (Reconnaissance)
- Event types: PF_BLOCK_TCP
- Stage 2 signals: rst_count, fin_count, syn_count, session_syn_without_response, session_data_without_syn (sessions)
- Signs: packets with FIN only, no flags, or FIN+PSH+URG (XMAS) to many ports; bare ACK packets to many ports (mapping which ports the firewall filters); many RSTs from one source to closed ports.
- Stronger if: many ports or hosts are covered in a short time from one source, in a regular pattern.
- Weaker if: a single late FIN, RST or ACK belonging to a connection whose firewall state already expired (RH-PF-04), or backscatter (RH-PF-02).
- Cases: none cited

### PF-05 · Brute force seen at the network level
- Techniques: T1110 Brute Force (Credential Access); T1133 External Remote Services
- Event types: PF_PASS_TCP, PF_BLOCK_TCP to ports 22, 23, 21, 3389, 5900, 1433, 3306, 5432
- Stage 2 signals: sessions with high connection_count (many initiator ports to one service port), packet_count, duration_seconds; entity windows with high events_per_second to one port
- Signs: one source opens many short connections to the same login service, each from a new source port, repeatedly for minutes or hours. PF cannot see passwords, but this is the network shape of password guessing.
- Stronger if: the connections are passed (the service is reachable); the authentication logs show failures from the same source at the same time (AUTH-01).
- Weaker if: an internal monitoring system polling the service, or a user with a flaky connection reconnecting (RH-PF-08).
- Cases: CASE-RAPPERBOT, CASE-SAMSAM, CASE-KINSING, CASE-MIRAI (Telnet 23/2323)

### PF-06 · Access to exposed sensitive services
- Techniques: T1133 External Remote Services (Persistence); T1190† Exploit Public-Facing Application
- Event types: PF_PASS_TCP, PF_PASS_UDP to sensitive ports from external sources
- Stage 2 signals: pass_count with sensitive destination ports; sessions with reverse_packet_count > 0 (the service answered)
- Signs: external addresses reaching database (3306, 5432, 1433, 1521, 6379, 9200, 27017), remote-desktop (3389, 5900) or file-sharing (445, 2049) ports with traffic passed and replies returned.
- Stronger if: the service should never be internet-facing; long sessions or large replies follow (data leaving); the source is new.
- Weaker if: the site context documents the service as intentionally exposed to that partner or address range.
- Cases: CASE-MEOW, CASE-SAMSAM, CASE-COLONIAL

### PF-07 · Command and control from an internal host
- Techniques: T1571 Non-Standard Port; T1095 Non-Application Layer Protocol; T1071 Application Layer Protocol (Command and Control)
- Event types: PF_PASS_TCP, PF_PASS_UDP, PF_PASS_ICMP (direction out, internal source, external destination)
- Stage 2 signals: behavior windows new_destination_ips and new_destination_ports; sessions with regular mean_inter_event_seconds (low variation), long duration_seconds
- Signs: an internal host, especially a server that normally only answers requests, starts connecting out to an unfamiliar external address, often on an unusual port, at regular intervals (beaconing); ICMP to external hosts with unusual sizes.
- Stronger if: the host shows other alerts (suspicious logins, OSSEC gaps); the destination is contacted by only this host; connections continue around the clock.
- Weaker if: the destination is a known update, time, cloud or monitoring service contacted on a schedule by many hosts (RH-PF-08).
- Cases: CASE-FRITZFROG (peer-to-peer channel between infected hosts)

### PF-08 · DNS abuse and malformed DNS
- Techniques: T1071.004 DNS (Command and Control); T1572 Protocol Tunneling
- Event types: PF_PASS_UDP to port 53, PF_BLOCK_DNS_MALFORMED, PF_PASS_DNS_MALFORMED
- Stage 2 signals: dns_count, malformed_count, malformed_packet, total_packet_bytes and mean_packet_length for port-53 traffic
- Signs: one internal host sending unusually many or unusually large DNS packets to an external resolver instead of the internal one; malformed DNS from external addresses to internal hosts.
- Stronger if: the host bypasses the organisation's resolvers; volume is steady around the clock; the host has other alerts.
- Weaker if: large DNSSEC/EDNS responses parsed as "invalid", or many hosts affected equally (RH-PF-09).
- Cases: none cited

### PF-09 · Denial of service and reflection amplification
- Techniques: T1498.001 Direct Network Flood; T1498.002 Reflection Amplification (Impact)
- Event types: PF_BLOCK_UDP, PF_PASS_UDP, PF_BLOCK_TCP (SYN floods), PF_BLOCK_ICMP
- Stage 2 signals: entity windows with very high events_per_second, total_packet_bytes and unique_source_ips toward one destination; source ports 53, 123, 1900, 11211 on inbound UDP
- Signs: a burst of packets toward one host from many sources; large inbound UDP from well-known amplifier ports (DNS 53, NTP 123, SSDP 1900, memcached 11211); or an internal host sending small UDP requests to many external amplifiers (your host is being used to attack someone).
- Stronger if: the volume is orders of magnitude above normal; services on the target degrade.
- Weaker if: lone replies to requests you never sent, spread thinly across time: backscatter from attacks on others (RH-PF-02).
- Cases: CASE-MEMCACHED, CASE-MIRAI (Dyn DDoS)

### PF-10 · Port knocking before a hidden service opens
- Techniques: T1205.001 Port Knocking (Stealth, Persistence, Command and Control)
- Event types: PF_BLOCK_TCP, PF_BLOCK_UDP followed by PF_PASS_TCP
- Stage 2 signals: individual packets in order; sessions with session_key_type and close_reason
- Signs: one source sends a short, exact sequence of blocked packets to closed ports, then immediately succeeds in connecting to a port that is normally blocked for it. The same sequence recurs before each access.
- Stronger if: the sequence is identical each time and the opened service is unusual (a high port, or a second SSH).
- Weaker if: a scanner happens to hit closed ports before an open one without any repeated order (PF-01).
- Cases: none cited

### PF-11 · Firewall rules changed to let traffic through
- Techniques: T1686 Disable or Modify System Firewall (Defense Impairment)
- Event types: PF_PASS_TCP, PF_PASS_UDP on a rule number never seen before, or passes for traffic previously blocked
- Stage 2 signals: unique_rules, rule_number (individual), sudden change in pass_count/block_count ratio for the same source and port
- Signs: traffic that yesterday matched a block rule now matches a pass rule; a new rule number appears carrying external traffic to a sensitive port; PF logging from a rule stops abruptly.
- Stronger if: no change ticket exists; the newly passed traffic comes from an address involved in other alerts.
- Weaker if: the site context records a firewall change at that time.
- Cases: none cited

### PF-12 · Tool transfer and legacy protocols
- Techniques: T1105 Ingress Tool Transfer (Command and Control); T1071.002 File Transfer Protocols
- Event types: PF_PASS_TFTP, PF_BLOCK_TFTP, PF_PASS_SNMP, PF_BLOCK_SNMP, PF_PASS_UDP to port 69 or 161
- Stage 2 signals: tftp_count, snmp_count, sensitive_port_block
- Signs: TFTP between an internal host and the internet (IoT and Unix malware often fetches payloads by TFTP after a successful break-in); SNMP queries from external addresses (device reconnaissance or configuration theft).
- Stronger if: it immediately follows a successful login from the same external address (AUTH-05) or a brute-force session (PF-05).
- Weaker if: network devices downloading firmware or configuration from an internal TFTP server, or internal monitoring polling SNMP (RH-PF-05).
- Cases: CASE-MIRAI (IoT loaders commonly fetch payloads after default-credential logins)
