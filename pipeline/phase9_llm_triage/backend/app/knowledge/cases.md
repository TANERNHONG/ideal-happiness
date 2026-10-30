# Past attack cases

Real incidents cited by the attack patterns. Each shows how a technique looked
in practice. **An alert resembling a case is not proof that it is that
campaign.**

Cases marked **Verified** were checked against the listed sources in September
2026. Cases marked **Not re-checked** are widely reported but were not
re-verified when this file was written; confirm them before quoting them in a
report.

### CASE-UNC1945 · Solaris PAM zero-day and SLAPSTICK backdoor (2018-2020)
- Status: Verified
- What happened: Threat actor UNC1945 compromised Oracle Solaris servers for
  over two years. In late 2018 it installed **SLAPSTICK**, a backdoor built as
  a Pluggable Authentication Module that logs credentials and grants access
  with a hard-coded password. In mid-2020 it used **EVILSUN**, a remote root
  exploit for **CVE-2020-14871**, a pre-authentication flaw in Solaris PAM
  reachable over SSH. Oracle patched it in the October 2020 Critical Patch
  Update.
- Why it matters here: our authentication logs come from Solaris hosts running
  sshd with PAM. PAM module errors and anomalous keyboard-interactive/PAM
  exchanges deserve attention (AUTH-07, AUTH-08).
- Techniques: T1556.003 Pluggable Authentication Modules; T1190† Exploit
  Public-Facing Application.
- Sources: Mandiant, "Live off the Land? How About Bringing Your Own Island?
  An Overview of UNC1945", November 2020,
  https://cloud.google.com/blog/topics/threat-intelligence/live-off-the-land-an-overview-of-unc1945/ ;
  SecurityWeek, "Sophisticated Threat Actor Exploited Oracle Solaris Zero-Day",
  https://www.securityweek.com/sophisticated-threat-actor-exploited-oracle-solaris-zero-day/

### CASE-UNC2891 · CAKETAP Solaris rootkit on ATM switching servers (2022)
- Status: Verified
- What happened: UNC2891 (also called LightBasin) deployed **CAKETAP**, a
  kernel-module rootkit for Oracle Solaris that hides network connections,
  processes and files. It intercepted messages to payment hardware security
  modules to approve fraudulent cards for ATM withdrawals. The group made
  extensive use of the **SLAPSTICK** PAM backdoor, and its toolset included
  log cleaners and wipers (Miglogcleaner, Wiperight).
- Why it matters here: rootkits hide from normal tools, so file-integrity and
  rootcheck anomalies and gaps in monitoring matter (OSSEC-03, OSSEC-06),
  alongside PAM tampering (AUTH-07).
- Techniques: T1014 Rootkit; T1547.006 Kernel Modules and Extensions;
  T1556.003 Pluggable Authentication Modules; T1685.006 Clear Linux or Mac
  System Logs.
- Sources: The Hacker News, "Hackers Target Bank Networks with new Rootkit to
  Steal Money from ATM Machines", March 2022,
  https://thehackernews.com/2022/03/hackers-target-bank-networks-with-new.html ;
  Malwarebytes, "A new rootkit comes to an ATM near you",
  https://www.malwarebytes.com/blog/news/2022/03/a-new-rootkit-comes-to-an-atm-near-you

### CASE-FRITZFROG · Peer-to-peer SSH brute-force botnet (2020)
- Status: Verified
- What happened: Guardicore found FritzFrog breaching SSH servers from January
  2020, including government, education and finance targets; around 500
  servers were compromised. It spreads by brute-forcing SSH credentials, runs
  filelessly, and keeps access by adding its own public key to
  `authorized_keys`.
- Why it matters here: the sequence brute force, then successful login, then
  later public-key logins for the same account (AUTH-01, AUTH-05, AUTH-06).
- Techniques: T1110.001 Password Guessing; T1098.004 SSH Authorized Keys.
- Sources: Akamai (formerly Guardicore), "FritzFrog: A New Generation of
  Peer-to-Peer Botnets", https://www.akamai.com/blog/security/fritzfrog-a-new-generation-of-peer-to-peer-botnets

### CASE-RAPPERBOT · Mirai-derived SSH brute-forcing botnet (2022)
- Status: Verified
- What happened: FortiGuard Labs found RapperBot, based on Mirai code, which
  brute-forces **SSH** rather than Telnet. From mid-July 2022 it replaced
  victims' `~/.ssh/authorized_keys` with the attackers' key (comment
  "helloworld"), keeping access after passwords changed and locking out
  legitimate key users. Over 3,500 unique IP addresses were seen scanning and
  brute-forcing.
- Why it matters here: many-source SSH brute force (AUTH-01, PF-05) and
  key-based persistence (AUTH-06). Legitimate users suddenly failing key
  authentication can follow a key replacement.
- Techniques: T1110.001 Password Guessing; T1098.004 SSH Authorized Keys.
- Sources: FortiGuard Labs, "So RapperBot, What Ya Bruting For?", August 2022,
  https://www.fortinet.com/blog/threat-research/rapperbot-malware-discovery

### CASE-MIDNIGHT-BLIZZARD · Low-and-slow password spray against Microsoft (2023-2024)
- Status: Verified
- What happened: From late November 2023, Midnight Blizzard (NOBELIUM) used a
  password spray to compromise a legacy, non-production test account without
  multi-factor authentication, then accessed corporate email. The spray
  targeted a limited number of accounts with a low number of attempts to avoid
  detection and lockouts, from distributed residential proxy addresses.
- Why it matters here: spraying looks like scattered single failures from many
  sources, not a burst (AUTH-03). Low volume is not evidence of innocence.
- Techniques: T1110.003 Password Spraying; T1078 Valid Accounts; T1090 Proxy.
- Sources: Microsoft Security, "Midnight Blizzard: Guidance for responders on
  nation-state attack", 25 January 2024,
  https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/ ;
  MSRC, "Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard",
  https://www.microsoft.com/en-us/msrc/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard

### CASE-TEAMTNT · Cloud cryptojacking group disabling monitoring agents
- Status: Verified
- What happened: TeamTNT (ATT&CK G0139), active since at least October 2019,
  targets cloud and container environments to deploy cryptocurrency miners. It
  has disabled and uninstalled security tools such as Alibaba, Tencent and BMC
  cloud monitoring agents.
- Why it matters here: attackers stop host agents to blind defenders
  (OSSEC-01).
- Techniques: T1685 Disable or Modify Tools; T1496 Resource Hijacking.
- Sources: MITRE ATT&CK, TeamTNT (G0139), https://attack.mitre.org/groups/G0139/ ;
  MITRE ATT&CK, Disable or Modify Tools (T1685), https://attack.mitre.org/techniques/T1685/

### CASE-ROCKE · Mining group uninstalling security software
- Status: Verified
- What happened: Rocke (ATT&CK G0106) used scripts that detected and
  uninstalled antivirus software, and evolved its malware to evade cloud
  security detection.
- Why it matters here: the same pattern as CASE-TEAMTNT (OSSEC-01).
- Techniques: T1685 Disable or Modify Tools.
- Sources: MITRE ATT&CK, Disable or Modify Tools (T1685), procedure example
  G0106, https://attack.mitre.org/techniques/T1685/

### CASE-KINSING · Linux malware brute-forcing SSH
- Status: Verified
- What happened: ATT&CK records that Kinsing (S0599) has attempted to brute
  force hosts over SSH, and Chaos (S0220) conducts brute-force attacks against
  SSH to gain initial access.
- Why it matters here: SSH brute force is a standard entry point for Linux
  and Unix malware (AUTH-01, PF-05).
- Techniques: T1110 Brute Force.
- Sources: MITRE ATT&CK, Brute Force (T1110), https://attack.mitre.org/techniques/T1110/

### CASE-MIRAI · Telnet default-credential botnet and the Dyn DDoS (2016)
- Status: Not re-checked
- What happened: Mirai scanned the internet for Telnet on ports 23 and 2323 and
  logged in to IoT devices with factory-default credentials. The botnet
  launched very large DDoS attacks in 2016, including the October 2016 attack
  on DNS provider Dyn. Its source code was published and is the basis of many
  later botnets (including CASE-RAPPERBOT).
- Why it matters here: horizontal sweeps of 23/2323 (PF-02) and default-account
  logins (AUTH-05).
- Techniques: T1595.001 Scanning IP Blocks; T1078.001 Default Accounts;
  T1498 Network Denial of Service.

### CASE-WANNACRY · SMB worm (May 2017)
- Status: Not re-checked
- What happened: WannaCry ransomware spread as a worm by scanning for SMB on
  TCP 445 and exploiting the EternalBlue vulnerability (MS17-010), across
  internal networks and the internet.
- Why it matters here: one infected internal host sweeping port 445 across many
  addresses (PF-02). Outbound sweeps from inside are far more serious than
  inbound ones.
- Techniques: T1210† Exploitation of Remote Services; T1046† Network Service
  Discovery.

### CASE-SAMSAM · RDP brute force leading to ransomware (2015-2018)
- Status: Not re-checked
- What happened: The SamSam operators gained access largely by brute-forcing
  or buying Remote Desktop credentials, then deployed ransomware manually. Two
  Iranian nationals were indicted by the US Department of Justice in November
  2018.
- Why it matters here: repeated connections to TCP 3389 from one external
  source (PF-05, PF-06).
- Techniques: T1110 Brute Force; T1133 External Remote Services.

### CASE-COLONIAL · Unused VPN account without MFA (2021)
- Status: Not re-checked
- What happened: Attackers entered Colonial Pipeline's network in 2021 using
  the password of a legacy VPN account that lacked multi-factor
  authentication. The resulting ransomware incident caused a pipeline
  shutdown.
- Why it matters here: a single successful login to a dormant account from a
  new source can be the whole intrusion (AUTH-05).
- Techniques: T1078 Valid Accounts; T1133 External Remote Services.

### CASE-MEMCACHED · Reflection amplification DDoS against GitHub (2018)
- Status: Not re-checked
- What happened: In February 2018 GitHub received a DDoS peaking around
  1.35 Tbps, amplified through exposed memcached servers (UDP 11211) using
  spoofed source addresses.
- Why it matters here: floods of UDP from source ports such as 11211, 123, 53
  or 1900 toward one host (PF-09). The spoofed victim of such attacks sees
  **backscatter** (RH-PF-02).
- Techniques: T1498.002 Reflection Amplification.

### CASE-MEOW · Wiping of exposed databases (2020)
- Status: Not re-checked
- What happened: In mid-2020, automated "Meow" attacks deleted data from
  thousands of internet-exposed, unauthenticated Elasticsearch and MongoDB
  databases.
- Why it matters here: inbound traffic **passed** to database ports (9200,
  27017) from external sources (PF-06).
- Techniques: T1485 Data Destruction; T1133 External Remote Services.
