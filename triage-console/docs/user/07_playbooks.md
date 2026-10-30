# Playbooks: what to check next

One section per kind of alert. Review's **Playbook** button opens the section for the item in front of you. Each
section says what the alert looks like, what to check in the console, when it is usually harmless, when to
escalate, and which label to give. The checks use only what the console already shows; nothing here asks you to
log on to a server.

## Before you start

Do these for every item, in this order:

1. **Read the lines.** In Review, open the item and use *Lines around* (10 minutes either side). Note the server,
   the account and the source address, and whether the lines are one burst or spread out.
2. **Check the entity's normal.** Open the account, address or server in **Profiles**: is today far from its
   usual weekday (median, P10–P90)? Is it new?
3. **Check what is planned.** Look for an approved change window or approved automation covering the time and the
   server. A planned change explains a lot; an unplanned one at the same time explains nothing.
4. **Check the context.** Who owns the server (`assets.csv`: zone, role, criticality)? An alert on a high-criticality
   OT server outranks the same alert on a test box.
5. **Decide and write it down.** Give a label and a note that says what you checked. *Security relevant* and
   *Suspicious* need a note; so does *Insufficient evidence* (say what is missing).

## Password guessing

**Looks like:** many failed logins for one account (often `root`) from one source address in minutes.

**Check:**
1. Did any login from that address **succeed** afterwards, on any server? If so, go to *Login after failures*.
2. Is the address internal (a known jump host, a monitoring system) or not? Check its Profile and `assets.csv`.
3. Is it a known script with an expired password (the same account, the same interval, every day)?

**Usually harmless when:** a scheduled job or monitoring probe uses an old password; the pattern repeats daily at
the same time from the same internal host.

**Escalate when:** the address is unknown or external, the account is privileged, or any login from it succeeded.

**Label:** *Security relevant* if hostile; *Operationally interesting* for a broken job (ask the owner to fix it);
*Expected behaviour* only for an approved test.

## Password spraying

**Looks like:** one source address trying **many accounts**, one or two attempts each, often slowly.

**Check:**
1. How many accounts, and do they exist? Real account names mean someone knows the site.
2. Did any of them log in successfully from that address?
3. Did the same address touch other servers (Profiles: its partners)?

**Usually harmless when:** an inventory or vulnerability scanner that is approved and announced.

**Escalate when:** the scanner is not approved, any login succeeded, or real account names were tried.

**Label:** *Security relevant* unless an approved scan explains it.

## Account enumeration

**Looks like:** many *invalid user* lines: names that do not exist on the server, from one address.

**Check:**
1. Are the names generic (`admin`, `test`, `oracle`) or site-specific? Site-specific names suggest inside knowledge.
2. Did the address go on to try real accounts, or log in?

**Usually harmless when:** a misconfigured tool cycling through a list of service names.

**Escalate when:** the names are site-specific, or enumeration is followed by attempts on real accounts.

**Label:** *Suspicious* with a note on the names seen; *Security relevant* if followed by real attempts.

## Login after failures

**Looks like:** failed logins for an account, then a **successful** one from the same address.

**Check:**
1. How many failures, over how long? One typo then success is ordinary; many failures then success is not.
2. Is the address the account's usual one (Profiles: its partners on training days)?
3. What happened after the login: a switch to root, new servers, unusual hours?

**Usually harmless when:** a person mistyped a password a few times from their usual workstation.

**Escalate when:** the address is new for the account, the failures look automated, or the session went on to switch
to root or reach other servers. Treat the account as possibly compromised: escalate before contacting its owner.

**Label:** *Security relevant* when compromise is possible; *Expected behaviour* for a confirmed typo.

## Switch to root

**Looks like:** `su` to root (or `sudo`, `pfexec`), or a root console login.

**Check:**
1. Who switched, from which session, at what time? Is it within their usual hours?
2. Is the account expected to administer this server? A whitelisted account still shows here unless its entry
   includes *su*.
3. Is there a change window or ticket covering it?

**Usually harmless when:** an administrator under a change window.

**Escalate when:** the account does not administer this server, the switch is outside hours without a change, or the
session started with failures or from a new address.

**Label:** *Expected behaviour* with the change reference; otherwise *Suspicious* or *Security relevant*.

## New source, server or account

**Looks like:** an account logging in from an address it has never used, to a server it has never used, or an
account that did not exist in the training period. A whitelisted account still raises this.

**Check:**
1. Is there a known reason: a new workstation, a migration, a new staff member?
2. Ask the account owner's team, not the account owner, if compromise is possible.

**Usually harmless when:** a recorded change (new PC, re-addressing, new joiner).

**Escalate when:** no change explains it and the account is privileged or the server is high criticality.

**Label:** *Operationally interesting* for an explained change (record it); *Suspicious* if unexplained.

## Unusual amount or timing

**Looks like:** an activity alert: far more (or, for an entity with its own level, far fewer) lines than this
server, account or address usually has at this time on this weekday. **Explain** shows why, in pictures.

**Check:**
1. Open **Explain**: which window (5, 30, 120 or 720 minutes), how far from usual, and against which weekday's
   training days?
2. Is it a public holiday, a maintenance window, a month end or a recorded change?
3. Read the lines at the peak: one job repeating, or many different things?

**Usually harmless when:** a routine that recurs at the same clock time on several days (the incident is marked as a
routine), or a planned job that ran long.

**Escalate when:** it coincides with failures, new partners or a switch to root, or it touches a high-criticality
server out of hours.

**Label:** *Expected behaviour* for an explained routine; *Operationally interesting* for a fault; otherwise
*Suspicious*.

## Unusual order of events

**Looks like:** a session or episode whose events came in an order rarely or never seen in training (frequent
subsequences). Review shows the usual routine beside it.

**Check:**
1. Which step was rare? A missing step (no logout, no session close) or an extra one (a switch to root mid-session)?
2. Does a software update or new client version explain a different order?

**Usually harmless when:** a client or server update changed the messages.

**Escalate when:** the rare step is a privilege change or an authentication step being skipped.

**Label:** *Operationally interesting* for an update; *Suspicious* otherwise.

## Monitoring went quiet

**Looks like:** an OSSEC agent stopping or going silent, or a server logging nothing for days while other logs show
it was up.

**Check:**
1. Did the agent stop cleanly (a shutdown) or just go quiet? At what time, and was a change window open?
2. Did the server keep working (other logs, Profiles)? Monitoring switched off on a working server is the
   concern.
3. Is the log file missing from the collection (a collection gap) rather than empty?

**Usually harmless when:** a planned maintenance or a collection problem affecting many servers at once (a holiday
collection gap).

**Escalate when:** one server's monitoring stopped without a change while the server stayed in use. Turning off
monitoring is a step attackers take.

**Label:** *Operationally interesting* for a collection fault (tell the log owner); *Security relevant* if
unexplained on a working server.

## Firewall: blocked traffic

**Looks like:** PF or IPFilter lines on a firewall that is normally silent: blocked connection attempts, a port scan
(many ports on one host), a sweep (one port on many hosts), or industrial protocol traffic (IEC-104).

**Check:**
1. Source and destination: both internal? Which zones (`assets.csv`)? Crossing from IT to OT is the serious case.
2. One flow retrying (a misconfigured application) or many ports or hosts (scanning)?
3. Any IEC-104 or other control protocol where it should not be? Treat control traffic in an unexpected place as
   high priority.

**Usually harmless when:** an application retrying a peer after a migration (one flow, a steady interval).

**Escalate when:** scanning, IT-to-OT crossings, or control-protocol traffic from an unexpected source.

**Label:** *Operationally interesting* for a misconfiguration (tell the network owner); *Security relevant* for
scanning or unexpected control traffic.

## Sigma rule match

**Looks like:** a known attack pattern matched by a Sigma rule; the badge names the rule and its ATT&CK technique.

**Check:**
1. Open the rule on the **Sigma** page: what exactly does it match, and how many events?
2. Then follow the section for that kind of activity above (guessing, spraying, switch to root and so on).

**Usually harmless when:** the rule's threshold is lower than this site's normal (note it so the rule can be tuned).

**Escalate when:** the section for the activity says so.

**Label:** as that section says; note the rule title.

## Escalation and hand-off

When a section says escalate:

1. **Label** the item *Security relevant* or *Suspicious*, with a note of what you checked.
2. **Start a report** from the item (Reports): it gets an IR number, the lines with their SHA-256 fingerprints, and
   the activity log's latest hash in its footer.
3. **Open the organisation's incident ticket** following its incident procedure, quote the IR number in it, and
   enter the ticket number in the report's *Ticket no.*
4. **Do not contact the account owner** when the account may be compromised; go through the procedure's first
   contact.
5. **Do not change anything on the server** yourself; containment belongs to the incident procedure.
