APPROVED CHANGE WINDOWS (provided by the change-management team; trusted)

The following changes were planned and approved. During each window, the listed hosts and flows are expected to produce unusual traffic, for example a migration that moves a service from one server to another.

{{approved_change_windows}}

How to use these windows:
- Activity inside a window, on the hosts and flow the window names, is explained by the change. Usually that is expected behavior. If the change left something broken, for example a service the change needed is still blocked, it is operationally interesting.
- A window does not cover anything else: other sources, other ports, other servers, or the same flow before the window opens or after it closes. Judge those on their own.
- A window never makes hostile behavior acceptable, such as a scan of many ports, logins as unexpected users or traffic that got through when it should have been blocked.
- The alert details state how many lines fall inside each window and match its flow. Rely on that statement rather than comparing times yourself.
