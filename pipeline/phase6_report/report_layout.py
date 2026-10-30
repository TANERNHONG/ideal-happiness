"""Phase 6, shared by all three reports: IEEE-style structure, plain-language chapter
introductions, references and a glossary of security and data-science terms.

Each report builds its existing sections (charts, tables, findings) and hands them
to document(), which arranges them into numbered chapters:

    Abstract, Index Terms
    I. Introduction          purpose, how to read, summary at a glance
    II. Data                 the log source in plain words, pipeline health
    III. Methodology         how detection works, feature relevance, model selection
    IV. Results              detector results, model behaviour, model zoo, consensus
    V. Evidence and Analysis evidence integrity, patterns, entities, top alerts
    VI. Discussion           what an alert means, limitations
    VII. Recommendations     the analyst review plan
    VIII. Conclusion
    References, Appendix A (general glossary), Appendix B (terms for this log type)
"""
from __future__ import annotations

import html
import re

ROMAN = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X")
LETTERS = "ABCDEFGHIJKLMNOP"

SOURCE = {
    "auth": {
        "name": "authentication logs",
        "keywords": "authentication logs, SSH, anomaly detection, Isolation Forest, explainable security analytics",
        "data": (
            "Authentication logs record every attempt to sign in to a server: remote logins over SSH, local "
            "switches to the administrator account with <code>su</code>, and the failures of both. Each of the 15 "
            "servers writes its own log, and the pipeline reads the monthly archives supplied by operations. One "
            "line records one step, for example <code>Accepted publickey for backup from 10.0.0.7</code>. Attacks "
            "rarely show in a single line. They show as patterns across lines: many failed passwords from one "
            "address, a login from an address never seen before, or an ordinary account becoming the "
            "administrator. The observations analysed are single events, 5-minute windows per server, SSH "
            "sessions and daily behaviour per server (Appendix A, <i>view</i>)."
        ),
    },
    "ossec": {
        "name": "OSSEC agent logs",
        "keywords": "OSSEC, host-based intrusion detection, agent health, anomaly detection, explainable security analytics",
        "data": (
            "OSSEC is a security agent installed on each server. It checks important files for unexpected "
            "changes (<i>syscheck</i>), scans for rootkits (<i>rootcheck</i>) and reports to a central manager. "
            "This report analyses the agent's <b>own operational log, not its security alerts</b>: lines record the "
            "agent starting, connecting to its manager, and starting or finishing scans. What matters is the "
            "agent's health. An agent that stops, loses its manager or never finishes a scan means monitoring was "
            "interrupted, whether by maintenance, a fault or an intruder. The observations analysed are single "
            "events, 5-minute windows per server, agent episodes (a scan, an outage, a restart) and daily "
            "behaviour per server."
        ),
    },
    "pf": {
        "name": "PF firewall logs",
        "keywords": "firewall logs, PF, empty baseline, presence detection, explainable security analytics",
        "data": (
            "PF (Packet Filter) is the firewall on each server. It logs every network packet a logging rule blocked, "
            "with the sender and receiver addresses and ports. <b>In the study period this log is nearly empty</b>: "
            "on most server-days nothing is blocked, and activity falls on a small number of days. (Two leftover "
            "capture files from 2022–24, outside the study period, are left out.) The pipeline therefore treats "
            "the silence as the data, as it does for the IPFilter log: it analyses every five minutes, hour and day "
            "of the study period, empty or not, and only counts an empty period as quiet when other logs show the "
            "server was up (Appendix B, <i>certified day</i>)."
        ),
    },
    "ipf": {
        "name": "IPFilter firewall logs",
        "keywords": "firewall logs, IPFilter, ipmon, empty baseline, presence detection, explainable security analytics",
        "data": (
            "IPFilter is the firewall on mm06moc, the one server that runs it instead of PF. Its monitor, "
            "<code>ipmon</code>, writes a line for every packet a logging rule matched, with the sender and "
            "receiver addresses and ports, the rule number and the TCP flags. <b>In normal operation this log is "
            "empty</b>: no traffic is expected to reach a logging rule, so a month with no lines is the healthy "
            "state, and any line at all is worth an analyst's attention. The pipeline therefore treats the silence "
            "itself as the data. It analyses every five minutes, hour and day of the study period, empty or not, "
            "and only counts an empty period as quiet when other logs show the server was up (Appendix B, "
            "<i>certified day</i>)."
        ),
    },
}

INTRO = (
    "<p>This report summarises what the automated log-analysis pipeline (Project Huh) found in the {name}. "
    "The pipeline looks for activity that is <b>unusual compared with the servers' own history</b>, and traces "
    "every flagged item back to the original log lines so that an analyst can decide what it means. It does "
    "not, by itself, establish that any activity is an attack; Section VI explains why.</p>"
)
HOW_TO_READ = (
    "<p>Section II describes the data and whether it was processed completely. Section III explains how "
    "detection works. Section IV presents the results, including checks that the models behave sensibly, and "
    "Section V the evidence behind the alerts. Section VI discusses what the results can and cannot show, and "
    "Section VII lists what an analyst should do next. <b>Security and data-science terms are explained in "
    "Appendix A</b>, and terms specific to {name} in Appendix B. Numbers in square brackets, such as [1], refer "
    "to the References.</p>"
)
APPROACH = (
    "<p><b>Observations.</b> Log lines are first turned into typed events (for example <i>failed login</i>). "
    "The same events are then grouped several ways, called <i>views</i>: single events, fixed time windows, "
    "sessions and whole days per server. Unusual activity often shows only in a group, such as ten failures in "
    "one session.</p>"
    "<p><b>Features.</b> Each observation becomes a row of numbers: counts, rates and durations, the time of "
    "day, and hashed tokens for categories, message words and the order of events [2]. The data are split by "
    "time: the first 70% trains the models, the next 15% (validation) sets the thresholds, and the last 15% "
    "(test) is where alerts come from. Nothing from the test period is used to tune anything.</p>"
    "<p><b>Detectors.</b> Three unsupervised detectors score every observation: <i>robust deviation</i> "
    "(a normally stable count far from its usual level), <i>Isolation Forest</i> [1] (an unusual combination of "
    "features) and <i>novelty</i> (values or words rarely or never seen in training). A <i>model zoo</i> of 13 "
    "further unsupervised models [1], [3]–[6] is compared, pruned to a small ensemble, and rows flagged by three "
    "or more members become <i>consensus alerts</i>.</p>"
    "<p><b>Thresholds.</b> With no labelled attacks, there is no natural cut-off. Each threshold is set on the "
    "validation period so that it would have produced an agreed number of alerts per day (the <i>alert "
    "budget</i>), which keeps the review workload bounded. Every alert keeps its <i>lineage</i>: the list of "
    "original log lines it came from.</p>"
    "<p><b>Clusters.</b> Each view's model-zoo observations are drawn on a two-dimensional map [7]. The islands on "
    "that map become <i>behavioural clusters</i>, and every test observation is assigned to one, so analysts can "
    "review a kind of activity at a time (Section IV).</p>"
)
MEANING = (
    "<p><b>Unusual is not malicious.</b> An alert means the activity was rare compared with the rest of the "
    "data. Planned maintenance, a new script or a misconfigured device are rare too. Equally, an attacker who "
    "behaves like a normal user may never be rare. The <code>probability</code> shown with alerts is a "
    "percentile rank: 0.999 means more unusual than 99.9% of observations, not a 99.9% chance of an attack. "
    "Because alerts are the top sliver of rows by design, this value is almost always above 0.99.</p>"
    "<p><b>Rare events and false alarms.</b> Attacks are rare among millions of routine lines, so even a very "
    "accurate detector produces many false alarms in absolute terms. This is why thresholds are set by workload "
    "and why every alert needs human review.</p>"
    "<p><b>No measured accuracy yet.</b> No log lines have been labelled as attack or normal, so precision and "
    "recall cannot be measured. Figures called <i>detection rate</i> use a <i>proxy label</i> (for example, "
    "contains a failed login), which measures agreement with known-risky event types, not true detection.</p>"
)
RECOMMEND_DEFAULT = (
    "<ol><li>Review consensus alerts first, highest model agreement first.</li>"
    "<li>For each alert, read the original log lines in Section V before deciding anything.</li>"
    "<li>Record a triage category for each reviewed alert (security relevant, operationally interesting, "
    "expected behavior, insufficient context) so the pipeline's accuracy can be measured.</li>"
    "<li>Share approved automation addresses and maintenance windows with the pipeline owners.</li></ol>"
)
CONCLUSION = (
    "<p>The pipeline reduces the {name} to a bounded set of unusual observations, each traceable to its "
    "original lines, and Section IV shows that the detectors separate a thin tail of unusual activity from the "
    "bulk rather than flagging everything. Whether any of that activity is hostile can only be settled by "
    "analyst review. Labelling the reviewed alerts is the next step, because it turns the pipeline's rarity "
    "scores into measured detection performance.</p>"
)

REFERENCES = [
    "F. T. Liu, K. M. Ting, and Z.-H. Zhou, “Isolation forest,” in <i>Proc. IEEE Int. Conf. Data Mining (ICDM)</i>, 2008, pp. 413–422.",
    "K. Weinberger, A. Dasgupta, J. Langford, A. Smola, and J. Attenberg, “Feature hashing for large scale multitask learning,” in <i>Proc. Int. Conf. Machine Learning (ICML)</i>, 2009, pp. 1113–1120.",
    "M. M. Breunig, H.-P. Kriegel, R. T. Ng, and J. Sander, “LOF: Identifying density-based local outliers,” in <i>Proc. ACM SIGMOD Int. Conf. Management of Data</i>, 2000, pp. 93–104.",
    "M. Goldstein and A. Dengel, “Histogram-based outlier score (HBOS): A fast unsupervised anomaly detection algorithm,” in <i>KI-2012: Poster and Demo Track</i>, 2012, pp. 59–63.",
    "Z. Li, Y. Zhao, X. Hu, N. Botta, C. Ionescu, and G. H. Chen, “ECOD: Unsupervised outlier detection using empirical cumulative distribution functions,” <i>IEEE Trans. Knowl. Data Eng.</i>, vol. 35, no. 12, pp. 12181–12193, 2023.",
    "B. Schölkopf, J. C. Platt, J. Shawe-Taylor, A. J. Smola, and R. C. Williamson, “Estimating the support of a high-dimensional distribution,” <i>Neural Computation</i>, vol. 13, no. 7, pp. 1443–1471, 2001.",
    "L. van der Maaten and G. Hinton, “Visualizing data using t-SNE,” <i>J. Mach. Learn. Res.</i>, vol. 9, pp. 2579–2605, 2008.",
    "The MITRE Corporation, “MITRE ATT&amp;CK Enterprise Matrix.” [Online]. Available: https://attack.mitre.org",
]

# (term, applies to: "all" or a set of sources, plain-language definition)
GLOSSARY_GENERAL = [
    ("Alert", "An observation the pipeline flags for human review because it is unusual. It is a reason to look, not proof of an attack."),
    ("Alert budget", "The agreed number of alerts per day a detector may raise. Thresholds are set on past data so that roughly this many alerts appear, keeping the review workload bounded."),
    ("Anomaly", "Something rare or different from normal behaviour. Anomalies include attacks, but also maintenance, new software and faults."),
    ("Approved administrative automation", "Scripts and tools (backups, monitoring, configuration management) that the security team has approved to log in or connect routinely. Their addresses are listed so that their normal activity is not mistaken for an attack."),
    ("Attack (or intrusion)", "Deliberate activity to gain access, cause damage or steal information without permission."),
    ("Backdoor", "A hidden way into a system left by an attacker, for example a changed login module or an extra key."),
    ("Base-rate problem", "When real attacks are extremely rare, even a very accurate detector raises more false alarms than true alerts, simply because there are so many normal events."),
    ("Brute force", "Guessing passwords by trying many of them, usually automatically."),
    ("CIDR range", "A compact way to write a block of IP addresses, for example 10.0.6.0/28 for 16 addresses."),
    ("Consensus alert", "An observation flagged by at least three members of the model-zoo ensemble. Agreement between different methods makes it more worth reviewing, not more likely to be malicious."),
    ("Credential", "Something that proves identity to a system: a password, a key or a token."),
    ("Defence evasion", "Attacker actions that hide activity or disable monitoring, such as stopping a security agent or deleting logs."),
    ("Drift", "A change over time in what normal looks like. Detectors tuned on older data then raise more or fewer alerts than intended."),
    ("False positive / false negative", "A false positive is harmless activity that was flagged. A false negative is real hostile activity that was missed."),
    ("Firewall", "Software or a device that allows or blocks network traffic according to rules."),
    ("Host / server", "One computer in the monitored environment. The environment has 15 servers."),
    ("Indicator of compromise", "Evidence that a system has been breached, such as a login from a known attacker address."),
    ("IP address", "The numeric network address of a computer, for example 172.16.10.41."),
    ("Lateral movement", "An attacker using one compromised server to reach others."),
    ("Lineage", "The recorded link from an alert back to the exact original log lines (file and line number) it came from."),
    ("Log", "A file in which a system records events, one line per event, with a timestamp."),
    ("MITRE ATT&amp;CK", "A public catalogue of attacker techniques [8], each with an ID such as T1110 (Brute Force). Used as a shared vocabulary."),
    ("Port", "A number that identifies a network service on a computer, for example 22 for SSH or 443 for HTTPS."),
    ("Port scan", "Probing many ports on a computer to find which services are running, usually a first step before an attack."),
    ("Private (internal) address", "IP addresses reserved for internal networks: 10.0.0.0/8, 172.16.0.0/12 (172.16.0.0 to 172.31.255.255) and 192.168.0.0/16. An address outside these ranges, such as 173.16.x.x, is a public internet address."),
    ("Privilege escalation", "Gaining higher access than intended, for example an ordinary account becoming the administrator (root)."),
    ("Reconnaissance", "An attacker gathering information before acting, for example scanning ports or guessing usernames."),
    ("Red herring", "Harmless activity that looks like an attack, for example a script retrying an old password."),
    ("Review priority score", "A 0–100 heuristic shown in Section I. It combines the share of unrecognised log lines, the highest alert rate, failure-type records in the evidence and the number of alerts. It measures how much review work there is, not how threatened the systems are."),
    ("Rootkit", "Malicious software that hides itself and an attacker's activity from the operating system."),
    ("SIEM", "Security Information and Event Management: a central system that collects logs and raises alerts from rules."),
    ("SOC", "Security Operations Centre: the team that monitors alerts and investigates incidents."),
    ("Triage", "Deciding quickly what an alert is and how urgently it needs attention. The four triage categories used here are security relevant, operationally interesting, expected behavior and insufficient context."),
]
GLOSSARY_METHOD = [
    ("Consensus / ensemble", "An ensemble is a small group of models whose votes are combined. See also consensus alert."),
    ("Detection rate (proxy)", "The share of proxy-positive rows caught within the alert budget. It measures agreement with known-risky event types, not true detection."),
    ("Feature", "One number describing an observation, for example the number of failed logins in a session."),
    ("Feature hashing", "Turning words or categories into a fixed number of columns by hashing them [2]. It needs no vocabulary and handles words never seen before, at the cost of occasional collisions."),
    ("Isolation Forest", "A detector that scores how easily an observation can be separated from the rest by random splits; unusual observations separate quickly [1]."),
    ("Model zoo", "The set of 13 unsupervised detectors compared on the same features, such as LOF [3], HBOS [4], ECOD [5], one-class SVM [6] and an autoencoder."),
    ("Novelty (rarity)", "A detector that flags values, words or event orders that were rare or absent in the training period."),
    ("Observation / view", "One row analysed by the detectors. A view is one way of grouping events: a single event, a time window, a session, or one day per server or address."),
    ("Percentile (the probability column)", "The share of observations in the same run that scored lower. 0.999 means more unusual than 99.9% of them; it is not the probability of an attack."),
    ("Precision and recall", "Precision is the share of alerts that are truly hostile; recall is the share of hostile activity that raised an alert. Both need labelled data."),
    ("Proxy label", "A rule-based stand-in for a real label, for example contains a failed login. Useful for comparing models, but partly circular."),
    ("Robust deviation", "How far a normally stable count is from its usual level, measured with the median and the median absolute deviation so that a few extreme values do not distort the baseline."),
    ("Threshold", "The score above which an observation becomes an alert."),
    ("Train / validation / test", "The three consecutive time periods the data are split into: train (models learn normal behaviour), validation (thresholds are set) and test (alerts are reported)."),
    ("t-SNE map", "A two-dimensional picture of high-dimensional data in which similar observations sit close together [7]. Distances between clusters and cluster sizes are not meaningful."),
    ("Unsupervised", "Learning without labelled examples: the models learn what is typical and flag what is not."),
    ("Base rate (proxy)", "The share of all rows that the proxy label marks as security-relevant. A detection rate is only meaningful compared with it: flagging rows at random would catch roughly the base rate."),
    ("Calibration", "Setting a detector's threshold so that its alert volume matches the budget on past data."),
    ("Disposition", "The analyst's final decision about an alert, for example security relevant or expected behavior."),
    ("Entity", "The thing an observation is about: a server, a user account, an IP address or a pair of addresses."),
    ("Evidence (complete / partial / missing)", "Whether every original log line behind an alert was found. Partial or missing evidence should be fixed before anyone decides what the alert means."),
    ("Greedy selection", "Building the ensemble one model at a time, each time adding the model that improves it most, and stopping when more models stop helping."),
    ("Lineage contract", "The rule that every observation must list the IDs of the original events it came from, so any alert can be traced back."),
    ("Message chain", "The original log lines behind one alert, in time order."),
    ("Permutation importance", "How much a detector's scores change when one feature's values are shuffled; a large change means the feature drives the scores. It shows what makes rows look unusual, not what is dangerous."),
    ("Pruning (degenerate, redundant, unstable)", "Removing models from the ensemble before selection: degenerate models give nearly the same score to everything, redundant ones duplicate another model, and unstable ones change behaviour within the validation period."),
    ("Review queue", "The list of alerts prepared for an analyst, with empty columns for their decision."),
    ("Behavioural cluster", "A group of observations that look alike to the models, numbered per view (for example authentication_sessions#72). Phase 7b finds them as islands on the t-SNE map and assigns every other observation to the island of its nearest mapped neighbours. A grouping aid for review, not a verdict."),
    ("HDBSCAN", "A clustering method that finds dense groups of points and leaves scattered points unassigned; used here to find the islands on each map."),
    ("Isolated (cluster #0)", "Observations on no island of the map: unusual one-offs rather than a repeated kind of activity."),
    ("Lift", "How many times more often a cluster is flagged than its view as a whole. A lift of 50 means alerts are 50 times more common in that cluster."),
    ("Neighbour check", "A test of the cluster assignment: each mapped point's own cluster is hidden and predicted from its nearest neighbours. A high match means the assignment of unmapped observations can be trusted."),
]
GLOSSARY_MODELS = [
    ("autoencoder", "A small neural network trained to reproduce normal rows; rows it reproduces badly are unusual."),
    ("ecod", "Empirical cumulative distribution outlier detection: flags values in the extreme tails of each feature [5]."),
    ("elliptic_envelope", "Fits an ellipse-shaped boundary around typical rows; rows far outside it are unusual."),
    ("gaussian_mixture", "Models the data as a mix of bell-shaped clusters; rows unlikely under every cluster are unusual."),
    ("hbos", "Histogram-based outlier score: rows whose values fall in rarely filled histogram bins are unusual [4]."),
    ("isolation_forest", "The Isolation Forest detector [1], also used as a Phase 4 detector."),
    ("kmeans_distance", "Groups rows into clusters; the distance to the nearest cluster centre is the score."),
    ("knn_distance", "Distance to the nearest similar rows (k-nearest neighbours); isolated rows are unusual."),
    ("lof", "Local outlier factor: compares a row's local density with its neighbours' [3]."),
    ("pca_reconstruction / svd_reconstruction", "Compress rows to their main patterns and rebuild them; rows that rebuild badly do not follow the usual patterns."),
    ("rbf_ocsvm / sgd_ocsvm", "One-class support vector machines [6]: learn a boundary around normal rows; rows outside are unusual. The two differ in how they are fitted."),
]
PRESENCE_TERMS = [
        ("Attempt", "One try to open a connection: the first SYN, its automatic retries and the reset that ends it. A client that cannot connect repeats this on a schedule."),
        ("Certified day", "A day on which the server's monthly file for this log exists and other logs show the server was up. Only on certified days does an empty log prove that nothing happened."),
        ("Empty (nil) baseline", "The normal state of this log is no lines, or almost none. Models cannot learn normal from lines that do not exist, so they learn it from the empty time periods instead."),
        ("Flow episode", "A run of attempts on the same flow (same source, destination, port and protocol) with no pause longer than 30 minutes."),
        ("Presence alert", "An alert raised because there was any activity at all, which is the rule for a log whose baseline is empty."),
        ("Within-activity rank", "The order of the active rows by how unlike the rest of the activity they are. With an empty baseline every active row is already an alert, so the rank, not the alert, tells the analyst where to start."),
        ("Zero tolerance", "The threshold rule used here instead of an alert budget: any observation scoring above the highest score of the quiet validation period alerts."),
]

GLOSSARY_SOURCE = {
    "auth": [
        ("Account lockout", "A server blocking an account after too many failed logins."),
        ("Console login", "Logging in at the server's own keyboard or management console rather than over the network."),
        ("Invalid user", "A login attempt for an account that does not exist. Many different invalid names from one address suggests username guessing."),
        ("Jump host", "A server administrators log in to first and then use to reach other servers. Many logins through one jump host are normal."),
        ("PAM", "Pluggable Authentication Modules: the part of Unix that checks passwords and rules at login. Unexpected PAM errors can mean tampering."),
        ("Password spraying", "Trying one or two common passwords against many accounts, slowly, to avoid lockouts."),
        ("Preauth", "Short for pre-authentication: a connection that closed before the user proved their identity, typical of scanners and health checks."),
        ("Public-key authentication", "Logging in with a cryptographic key instead of a password; typical of automation and administrators."),
        ("root", "The Unix administrator account, which can do anything on the server."),
        ("Session (SSH)", "One connection from a client to a server, from connecting to disconnecting."),
        ("Solaris", "The Unix operating system these servers run; its log lines carry message IDs such as [ID 800047 auth.info]."),
        ("SSH", "Secure Shell: the standard encrypted way to log in to a Unix server remotely, usually on port 22."),
        ("sshd", "The SSH server program that accepts logins and writes most authentication log lines."),
        ("su", "Switch user: a command to become another account, usually root. Unexpected su to root is worth attention."),
        ("syslog", "The standard Unix logging format: timestamp, host, program and message."),
    ],
    "ossec": [
        ("Active response", "An OSSEC feature that runs an action, such as blocking an address, when a rule fires."),
        ("Agent / manager", "The OSSEC agent runs on each server and reports to a central manager (here per1kco and per2kco, port 1514)."),
        ("Agent restart", "The agent stopping and starting again, for example during patching. An unexplained restart can mean someone switched monitoring off."),
        ("Episode", "A group of OSSEC lines describing one activity: a scan, an outage or a restart."),
        ("Integrity baseline", "The recorded fingerprints of monitored files that syscheck compares against. A reset means changes are no longer detected until a new baseline exists."),
        ("OSSEC", "An open-source host-based intrusion detection system (HIDS): security software that watches one computer from the inside."),
        ("rootcheck", "OSSEC's scan for rootkits and suspicious system settings."),
        ("syscheck", "OSSEC's file-integrity monitoring: it detects changes to important files."),
    ],
    "pf": [
        ("Backscatter", "Replies from other networks to attacks that forged this network's addresses; harmless noise here."),
        ("Block / pass", "The two firewall actions: drop the packet, or let it through. These logs contain blocked packets."),
        ("Broadcast", "A packet sent to every device on the local network (for example to 255.255.255.255)."),
        ("DHCP, DNS, NTP, SNMP, TFTP", "Common infrastructure services: address assignment, name lookup, time synchronisation, device monitoring and simple file transfer."),
        ("Ephemeral port", "A temporary high-numbered port a client uses for one connection; it carries no meaning on its own."),
        ("Flood / denial of service", "Sending so much traffic that a service slows or stops."),
        ("ICMP", "Network control messages, such as the ones the ping command uses."),
        ("Interface", "A network connection on the server (for example net2); traffic is logged per interface."),
        ("ISAKMP / IPsec", "The protocol that sets up encrypted VPN tunnels (UDP port 500)."),
        ("PF", "Packet Filter: the firewall built into OpenBSD and Solaris."),
        ("pflog", "PF's log of packets that matched a logging rule, written in tcpdump format."),
        ("RIP", "Routing Information Protocol: routers announcing routes to each other every 30 seconds (UDP port 520). Blocked RIP is usually harmless noise from network equipment."),
        ("Rule", "A firewall instruction such as block incoming traffic to port 22 except from these addresses."),
        ("Service port", "The well-known port of a service (22 SSH, 21 FTP, 443 HTTPS), as opposed to an ephemeral port."),
        ("TCP flags (S, R, F, P, .)", "Markers on TCP packets: S (SYN) starts a connection, R (RST) resets it, F (FIN) closes it, P (PSH) pushes data, and . (ACK) acknowledges. Many SYNs to different ports is a scan."),
        ("TCP / UDP", "The two main ways of sending data: TCP sets up a connection first; UDP sends single packets without one."),
    ],
    "ipf": [
        ("@group:rule", "The IPFilter rule that matched the packet, e.g. @0:1 is rule 1 of group 0. Different rules usually mean different kinds of traffic."),
        ("b / p", "IPFilter's action letters: b blocked the packet, p passed it. Every line in this log is a block."),
        ("Broadcast", "A packet addressed to every device on the local network, e.g. 172.16.10.255."),
        ("IPFilter / ipmon", "IPFilter is a firewall for Solaris and other Unix systems; ipmon is its program that writes the packet log."),
        ("Repeat count (2x)", "ipmon writes identical consecutive packets once with a count, e.g. '2x', so a line can stand for several packets."),
        ("SNMP", "Simple Network Management Protocol (UDP port 161): monitoring tools use it to query devices. A broadcast to port 161 asks every device on the network to answer, which is typical of network discovery."),
        ("SYN, -SEC, RST", "TCP flags in ipmon lines: -S is a SYN (a request to open a connection), -SEC a SYN that also offers congestion signalling (ECN), and -R a reset that gives up on the connection."),
    ],
}

for _source in ("ipf", "pf"):
    GLOSSARY_SOURCE[_source] = sorted(GLOSSARY_SOURCE[_source] + PRESENCE_TERMS, key=lambda item: item[0].lower())

CSS = """
body{font-family:'Times New Roman',Times,Georgia,serif;background:#fff;color:#111;line-height:1.55}
.paper{max-width:1180px;margin:0 auto;padding:36px 28px 60px}
.paper-title{text-align:center;font-size:2.1rem;font-weight:normal;margin:10px 0 6px;line-height:1.2}
.paper-authors{text-align:center;font-style:italic;color:#333;margin-bottom:4px}
.paper-meta{text-align:center;color:#555;font-size:.9rem;margin-bottom:22px}
.abstract{font-size:1rem;margin:0 auto 10px;max-width:980px;text-align:justify}
.abstract b.label,.keywords b.label{font-style:italic}
.keywords{max-width:980px;margin:0 auto 22px;font-size:.95rem;text-align:justify}
.toc{max-width:980px;margin:0 auto 26px;border-top:1px solid #999;border-bottom:1px solid #999;padding:10px 0;columns:2;font-size:.95rem}
.toc a{color:#1a3d7c;text-decoration:none}.toc div{margin:2px 0}
.chapter{margin:34px 0 10px}
.chapter>h2{text-align:center;font-variant:small-caps;letter-spacing:.06em;font-size:1.35rem;font-weight:normal;border-bottom:1px solid #bbb;padding-bottom:6px;margin:0 0 14px}
.chapter-intro{text-align:justify;max-width:1080px}
.chapter section{margin:18px 0 26px}
h3.sub{font-style:italic;font-weight:normal;font-size:1.15rem;margin:22px 0 8px;border:none}
.chapter .lead{color:#333;font-style:normal}
.chapter .panel,.chapter .table-wrap,.chapter .metric-card{box-shadow:none;border-color:#ccc;border-radius:4px}
.chapter th{background:#eef0f4}
.references ol{padding-left:28px}.references li{margin:5px 0;text-align:justify}
dl.glossary{display:grid;grid-template-columns:minmax(200px,26%) 1fr;gap:6px 18px;margin:8px 0 18px}
dl.glossary dt{font-weight:bold}dl.glossary dd{margin:0;text-align:justify}
.paper .footer{text-align:center;color:#666;font-size:.85rem;margin-top:30px;border-top:1px solid #ddd;padding-top:10px}
@media(max-width:800px){.toc{columns:1}dl.glossary{grid-template-columns:1fr}}
@media print{.paper{padding:0}.chapter{break-before:auto}.toc{display:none}}
"""

# Dashboard styles (tables, charts, badges, findings) used inside the chapters of the
# presence-method reports; the auth and OSSEC reports carry their own copy.
DASHBOARD_CSS = """:root{--bg:#f3f6fb;--panel:#fff;--ink:#172033;--muted:#5f6b7d;--line:#dce3ed;--shadow:0 8px 25px #1f293714}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif;line-height:1.5}.hero{background:linear-gradient(135deg,#111827,#1d4ed8 62%,#0891b2);color:white;padding:40px 24px}.hero-inner,.shell{max-width:1500px;margin:auto}.hero h1{font-size:clamp(2rem,4vw,3.3rem);margin:5px 0}.hero p{color:#dbeafe}.meta{display:flex;gap:9px;flex-wrap:wrap}.meta span{background:#ffffff20;border:1px solid #ffffff35;border-radius:99px;padding:6px 10px}.shell{padding:0 24px 50px}.nav{position:sticky;top:0;z-index:4;display:flex;gap:7px;overflow:auto;background:#f3f6fbef;padding:10px 0}.nav a{background:white;border:1px solid var(--line);border-radius:99px;padding:6px 10px;text-decoration:none;color:#334155;white-space:nowrap}section{margin:28px 0;scroll-margin-top:65px}h2{font-size:1.75rem;margin-bottom:5px}.lead{color:var(--muted);max-width:1100px}.panel,.table-wrap{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.panel{padding:18px}.two{display:grid;grid-template-columns:1fr 1fr;gap:17px;margin:12px 0}.chart{width:100%;height:auto}.ct{font-size:17px;font-weight:800;fill:#172033}.axis{font-size:11px;fill:#5f6b7d}.val{font-size:11px;font-weight:700;fill:#172033}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.85rem}th{text-align:left;background:#eaf0f9;padding:10px;white-space:nowrap}td{padding:9px 10px;border-top:1px solid #edf1f5;vertical-align:top}.empty{padding:20px;text-align:center;color:var(--muted);border:1px dashed #cbd5e1;border-radius:10px}details summary{cursor:pointer;color:#2563eb;font-weight:700}pre{white-space:pre-wrap;word-break:break-word;background:#111827;color:#e5e7eb;padding:10px;border-radius:7px;max-width:700px;max-height:280px;overflow:auto;font-size:.76rem}code{font-size:.76rem}.badge{display:inline-block;padding:3px 8px;border-radius:99px;font-size:.74rem;font-weight:800;white-space:nowrap}.badge.success{background:#dcfce7;color:#166534}.badge.warning{background:#fef3c7;color:#92400e}.badge.danger{background:#fee2e2;color:#991b1b}.badge.neutral{background:#e2e8f0;color:#334155}.finding{border-left:4px solid #94a3b8;background:#f8fafc;border-radius:10px;padding:11px 13px;margin:9px 0}.finding p{margin:3px 0;color:var(--muted)}.finding.danger{border-color:#dc2626;background:#fff5f5}.finding.warning{border-color:#f59e0b;background:#fffbeb}.finding.success{border-color:#16a34a;background:#f0fdf4}.footer{text-align:center;color:var(--muted);font-size:.8rem;padding:20px}@media(max-width:1000px){.two{grid-template-columns:1fr}}@media print{body{background:white}.nav{display:none}.panel,.table-wrap{box-shadow:none}}"""

# Labels in the older report sections that assume security or pipeline vocabulary.
PLAIN = [
    (re.compile(r"\bStages 1-5\b"), "Phases 1–5"), (re.compile(r"\bStage (\d[a-z]?(?:\.\d)?)\b"), r"Phase \1"),
    (re.compile(r"\bStage\b"), "Phase"), (re.compile(r"\bRepresentations\b"), "Views"),
    (re.compile(r"\brepresentations\b"), "views"), (re.compile(r"\bRepresentation\b"), "View"),
    (re.compile(r"\brepresentation\b"), "view"), (re.compile(r"Union anomaly candidates"), "Alerts from any detector"),
    (re.compile(r"Threat review score"), "Review priority score"), (re.compile(r"\bUnion alerts\b"), "Alerts from any detector"),
    (re.compile(r"\bUnion alert rate\b"), "Any-detector alert rate"), (re.compile(r"\bUnion\b"), "Any detector"),
]


def plain_language(fragment):
    """Rewrite jargon in text only, never inside tags (ids, classes, attributes stay as they are)."""
    parts = re.split(r"(<[^>]+>)", fragment)
    for index in range(0, len(parts), 2):
        for pattern, replacement in PLAIN:
            parts[index] = pattern.sub(replacement, parts[index])
    return "".join(parts)


def subsection(section_html, letter):
    """The section's own <h2> becomes an IEEE subsection heading, e.g. 'A. Detection results'."""
    return re.sub(r"<h2>(.*?)</h2>", lambda m: f'<h3 class="sub">{letter}. {m.group(1)}</h3>', section_html, count=1)


def text_section(identifier, title, body):
    return f'<section id="{identifier}"><h2>{html.escape(title)}</h2>{body}</section>'


def heading_case(name):
    """Title case that keeps acronyms and brand capitals (OSSEC, PF, IPFilter) as written."""
    return " ".join(word if any(ch.isupper() for ch in word) else word.capitalize() for word in name.split())


def glossary_html(source):
    def block(entries):
        return '<dl class="glossary">' + "".join(f"<dt>{term}</dt><dd>{text}</dd>" for term, text in entries) + "</dl>"
    general = sorted(GLOSSARY_GENERAL + GLOSSARY_METHOD, key=lambda entry: entry[0].lower())
    models = sorted(GLOSSARY_MODELS, key=lambda entry: entry[0])
    specific = sorted(GLOSSARY_SOURCE.get(source, []), key=lambda entry: entry[0].lower())
    name = SOURCE[source]["name"]
    return (f'<div class="chapter" id="appendix-a"><h2>Appendix A: Glossary</h2><p class="chapter-intro">Security, '
            f'data-science and pipeline terms used in this report, in plain language.</p>{block(general)}'
            f'<h3 class="sub">Model-zoo members (as named in the tables)</h3>{block(models)}</div>'
            f'<div class="chapter" id="appendix-b"><h2>Appendix B: Terms Specific to {heading_case(name)}</h2>'
            f'{block(specific)}</div>')


def references_html():
    return ('<div class="chapter references" id="references"><h2>References</h2><ol>'
            + "".join(f"<li>{item}</li>" for item in REFERENCES) + "</ol></div>")


def document(*, title, source, generated, abstract, base_css, chapters, footer):
    """Assemble the report. chapters = [(title, intro_html, [section_html, ...]), ...] in order."""
    name = SOURCE[source]["name"]
    body, toc = [], []
    for index, (chapter_title, intro, sections) in enumerate(chapters):
        number = ROMAN[index]
        anchor = f"chapter-{index + 1}"
        toc.append(f'<div><a href="#{anchor}">{number}. {html.escape(chapter_title)}</a></div>')
        letter = 0
        parts = [f'<div class="chapter" id="{anchor}"><h2>{number}. {html.escape(chapter_title)}</h2>']
        if intro:
            parts.append(f'<div class="chapter-intro">{intro.format(name=name)}</div>')
        for section in sections:
            if not section:
                continue
            parts.append(subsection(plain_language(section), LETTERS[letter]))
            letter += 1
        parts.append("</div>")
        body.append("".join(parts))
    toc += ['<div><a href="#references">References</a></div>', '<div><a href="#appendix-a">Appendix A: Glossary</a></div>',
            f'<div><a href="#appendix-b">Appendix B: {html.escape(heading_case(name))} terms</a></div>']
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>'
            f'<style>{base_css}{CSS}</style></head><body><main class="paper">'
            f'<h1 class="paper-title">{html.escape(title)}</h1>'
            f'<div class="paper-authors">Project Huh log-analysis pipeline, Phase 6</div>'
            f'<div class="paper-meta">Generated {html.escape(generated)} · offline self-contained report</div>'
            f'<p class="abstract"><b class="label">Abstract</b>—{abstract}</p>'
            f'<p class="keywords"><b class="label">Index Terms</b>—{SOURCE[source]["keywords"]}.</p>'
            f'<nav class="toc">{"".join(toc)}</nav>{"".join(body)}{references_html()}{glossary_html(source)}'
            f'<div class="footer">{footer}</div></main></body></html>')


def abstract_text(source, *, lines=None, months=None, alerts=None, traced=None, consensus=None, scored=None):
    """One paragraph summarising the report, from whichever facts the report has."""
    name = SOURCE[source]["name"]
    parts = [f"This report presents the results of unsupervised anomaly detection on {name} from 15 servers"]
    if lines:
        parts[0] += f", covering {lines:,} log lines" + (f" over {months} months" if months else "")
    parts[0] += "."
    if scored:
        parts.append(f"Detectors scored {scored:,} observations in the validation and test periods.")
    if alerts is not None:
        parts.append(f"In the test period, {alerts:,} observations were flagged by at least one of three detectors"
                     + (f", of which {traced:,} Isolation Forest alerts were traced back to their original lines" if traced else "")
                     + ".")
    if consensus:
        parts.append(f"A model zoo of 13 detectors produced {consensus:,} consensus alerts.")
    parts.append("Model-behaviour checks show that alerts come from a thin tail of the score distribution rather "
                 "than from the bulk of the data. Because no activity has yet been labelled as hostile or normal, "
                 "the alerts indicate rarity rather than confirmed attacks, and the report closes with an analyst "
                 "review plan and a glossary of terms.")
    return " ".join(parts)
