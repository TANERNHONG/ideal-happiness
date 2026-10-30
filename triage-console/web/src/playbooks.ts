// Which section of docs/user/07_playbooks.md an item opens (Review's Playbook button): its Sigma rules first, then its
// kind, then its group's main events. The anchors are the document's headings as the Docs page slugs them.

const PLAYBOOKS = "#/docs/app/07_playbooks";

export function playbookFor(item: any, source: string): string {
  const top = item.top ?? {};
  const text = [...(item.sigma ?? []).map((s: any) => s.title), top.event_type, top.first_event_type, top.episode_family, top.process_name]
    .filter(Boolean).join(" ").toLowerCase();
  const at = /spray/.test(text) ? "password-spraying"
    : /invalid user|enumerat|ssh_invalid_user/.test(text) ? "account-enumeration"
    : /after guessing|login after/.test(text) ? "login-after-failures"
    : /guess|ssh_login_failed|max_authentication/.test(text) ? "password-guessing"
    : /\bsu\b|su_session|sudo|pfexec|root_console/.test(text) ? "switch-to-root"
    : /agent stopped|agent_stopped|signal_received_exiting|silen/.test(text) ? "monitoring-went-quiet"
    : item.kind === "activity_alert" ? "unusual-amount-or-timing"
    : item.kind === "presence_alert" || source === "pf" || source === "ipf" || /scan|sweep/.test(text) ? "firewall-blocked-traffic"
    : item.sigma?.length ? "sigma-rule-match"
    : item.sequence || /subsequence/.test(text) ? "unusual-order-of-events"
    : "before-you-start";
  return `${PLAYBOOKS}?at=${at}`;
}
