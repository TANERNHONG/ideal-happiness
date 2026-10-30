APPROVED ADMINISTRATIVE AUTOMATION (provided by the security team; trusted)

The following IP addresses and ranges are approved administrative automation: scheduled jobs, backups, configuration management and monitoring that log in to or contact these servers as part of normal operation.

{{approved_automation_list}}

How to use this list:
- Routine activity from these addresses is expected behavior: scheduled logins with keys, health checks, file transfers and polling on their usual pattern.
- Being on the list does not clear activity by itself. Automation credentials are a common target. If an approved address does something automation does not normally do, such as logging in as a new or privileged user, switching to root, failing authentication repeatedly, opening an interactive session or appearing on a server it does not usually reach, judge it on the behaviour and say that the address is approved.
- An address that is not on the list is not suspicious for that reason alone.
- The alert details state which approved addresses, if any, appear in the log lines. Rely on that statement rather than matching addresses yourself.
