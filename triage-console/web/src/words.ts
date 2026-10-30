// Plain words for what the pipeline produces, for people who run the servers rather than the models
// (US-34): event types as readable names, each view's unit as a noun, how rare something is as
// "1 in N", and short date spans.

const ACRONYMS = new Set(["SSH", "PAM", "SU", "SUDO", "OSSEC", "IP", "TCP", "UDP", "ICMP", "DNS", "NTP", "SNMP", "SFTP", "TTY", "UID",
  "GID", "ID", "PF", "IPF", "USB", "CPU", "RAM", "HTTP", "HTTPS", "TLS", "SSL", "X11", "RSA", "DSA", "ECDSA", "AD", "LDAP", "SMB", "NFS"]);

/** SSH_LOGIN_SUCCESS → "SSH login success"; names people gave stay as they are. */
export function eventName(type: string): string {
  if (!/^[A-Z0-9_]+$/.test(type)) return type;
  const words = type.split("_").filter(Boolean).map((w) => (ACRONYMS.has(w) ? w : w.toLowerCase()));
  const text = words.join(" ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** A group's name made of event types ("A + B (+3)"), each made readable. */
export function groupName(name: string): string {
  return name.replace(/[A-Z0-9]+(?:_[A-Z0-9]+)+|\b[A-Z]{4,}\b/g, (t) => eventName(t));
}

const UNITS: Record<string, [string, string]> = {
  individual: ["line", "lines"], authentication_sessions: ["session", "sessions"], episodes: ["episode", "episodes"],
  attempts: ["attempt", "attempts"], flow_episodes: ["flow", "flows"], host_5min: ["5-minute window", "5-minute windows"],
  slots_5min: ["5-minute window", "5-minute windows"], slots_1h: ["hour", "hours"], host_behavior_1d: ["day", "days"], slots_1d: ["day", "days"],
};
/** "954 sessions", "1 line". */
export function count(view: string, n: number): string {
  const [one, many] = UNITS[view] ?? ["event", "events"];
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** How rare against the reference period: "1 in 1,000"; above everything in it, "rarest". */
export function rarity(p: number | null | undefined): { text: string; title: string; fill: number } {
  if (p === null || p === undefined) return { text: "—", title: "", fill: 0 };
  if (p >= 1) return { text: "rarest", title: "As rare as the rarest in the reference period, or rarer", fill: 1 };
  const n = 1 / (1 - p);
  if (n < 2) return { text: "common", title: "", fill: 0 };
  const nice = n >= 10000 ? Math.round(n / 1000) * 1000 : n >= 1000 ? Math.round(n / 100) * 100 : n >= 100 ? Math.round(n / 10) * 10 : Math.round(n);
  return { text: `1 in ${nice.toLocaleString()}`, title: `Rarer than ${(p * 100).toFixed(2)}% of the reference period`, fill: Math.min(1, Math.log10(n) / 5) };
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** "2026-06-08", "2026-07-30" → "8 Jun – 30 Jul 2026". */
export function dateSpan(a: string, b: string): string {
  const d = (s: string) => { const [y, m, day] = s.slice(0, 10).split("-").map(Number); return { y, m, day }; };
  if (!a) return "";
  const x = d(a), y = d(b || a);
  if (a.slice(0, 10) === (b || a).slice(0, 10)) return `${x.day} ${MONTHS[x.m - 1]} ${x.y}`;
  return `${x.day} ${MONTHS[x.m - 1]}${x.y === y.y ? "" : ` ${x.y}`} – ${y.day} ${MONTHS[y.m - 1]} ${y.y}`;
}

/** "mm04kco (83%); mm03kco (13%)" → [["mm04kco", "83%"], ["mm03kco", "13%"]]. */
export function topValues(text: string | undefined, limit = 3): [string, string][] {
  if (!text) return [];
  return text.split(";").map((part) => {
    const m = /^\s*(.*?)\s*\((\d+%)\)\s*$/.exec(part);
    return (m ? [m[1], m[2]] : [part.trim(), ""]) as [string, string];
  }).filter(([v]) => v).slice(0, limit);
}
