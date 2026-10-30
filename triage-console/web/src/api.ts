// The local service's JSON API (service/server.py). It answers only requests carrying X-Console-Request, which an
// address typed into the browser cannot.

export async function api<T = any>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? (options.body === undefined ? "GET" : "POST"),
    headers: { "X-Console-Request": "1", ...(options.body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  let data: any = null;
  try {
    data = await response.json();
  } catch {
    throw new Error(`The local service answered ${response.status} without JSON. Is it running (python -m service)?`);
  }
  if (!response.ok) throw Object.assign(new Error(data?.error ?? `Request failed (${response.status})`), { code: data?.code as string | undefined });
  return data as T;
}

export function qs(params: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface Settings {
  language: string;
  theme: "light" | "dark" | "system";
  font_family: "inter" | "roboto" | "helvetica" | "system" | "serif" | "mono" | "readable" | "installed";
  font_installed: string;
  font_scale: number;
  display_name: string;
  llm_endpoint: string;
  llm_model: string;
  feature_set: "selected" | "full";
  animations: "all" | "no-arrival" | "none";
  animation_pack: "transit" | "desk" | "commuter";
  console_mode: "simple" | "advanced";
  dashboard_layout: DashboardLayout | null;
  review_filter_seconds: number;        // Settings → Review: a filter is stopped after this long (10 to 3,600)
  retention_months: number;             // Settings → Retention: copies of log lines kept this long (3, 6, 12, 24 or 36)
}

/** Settings → Dashboard: the cards shown, in order, each with its width in columns of 12; the hidden ones; the person's
 * own SQL tables and tiles; and whether it is packed tightly (service/config.py checks the form). */
export interface DashboardLayout {
  cards: { id: string; span: number }[]; hidden: string[]; widgets?: Record<string, DashboardWidget>; tiles?: Record<string, DashboardTile>;
  packed?: boolean;              // Pack tightly: short cards fill the gaps beside tall ones (dashboard.ts pack)
}
/** One of the Dashboard's tiles: an icon, a heading (in one of three sizes) and text, a colour, an alignment, a console
 * page it opens ("" for none), and its height in pixels. */
export interface DashboardTile {
  icon: string; link: string; heading: string; text: string; size: "s" | "m" | "l";
  tone: "" | "red" | "amber" | "green" | "blue" | "grey"; align: "left" | "center"; height: number;
}
/** One of the Dashboard's own SQL tables: its title, a description (behind its info icon), its query, and its height
 * in pixels. */
export interface DashboardWidget { title: string; description: string; query: string; height: number }

export interface ViewInfo {
  id: string; label: string; unit: string; needs: string;
  available: boolean; used: boolean; why: string;
}
/** A view Review lists without models of its own: Phase 4g activity alerts (auth, OSSEC). */
export interface ReviewView { id: string; label: string; unit: string }
export interface SourceInfo { label: string; prefix: string; method: "baseline" | "presence"; views: ViewInfo[]; review_views?: ReviewView[] }
export interface Catalog { sources: Record<string, SourceInfo> }
