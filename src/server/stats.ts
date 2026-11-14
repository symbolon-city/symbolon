// Honest public counters for the register: anonymous daily counts only.
// No IP addresses, no user agents and no fingerprints are stored: just
// (day, kind) -> count, where kind = "<read|write>:<client class>".

import type { D1Like } from "./stores.js";

export type ClientClass = "ai_agent" | "program" | "browser";

const AI = /claude|anthropic|gptbot|chatgpt|openai|oai-searchbot|perplexity|gemini|google-extended|googleother|bard|copilot|mistral|cohere|meta-externalagent|bytespider|amazonbot|applebot-extended|ccbot|youbot|duckassist|mcp|agent/i;
const PROGRAM = /^$|curl|wget|python|node|undici|axios|go-http|java|okhttp|ruby|php|libwww|httpie|postman|deno|bun|cloudflare-workers/i;

/** Rough, transparent classification from the User-Agent header. */
export function classifyClient(userAgent: string | null): ClientClass {
  const ua = userAgent ?? "";
  if (AI.test(ua)) return "ai_agent";
  if (PROGRAM.test(ua) || !/mozilla/i.test(ua)) return "program";
  return "browser";
}

export interface DayStats {
  day: string;
  counts: Record<string, number>;
}

export interface StatsStore {
  count(kind: string, now?: Date): Promise<void>;
  recent(days: number, now?: Date): Promise<DayStats[]>;
}

const dayOf = (d: Date) => d.toISOString().slice(0, 10);

function lastDays(days: number, now: Date): string[] {
  return Array.from({ length: days }, (_, i) => dayOf(new Date(now.getTime() - (days - 1 - i) * 86_400_000)));
}

export class MemoryStats implements StatsStore {
  private rows = new Map<string, number>();
  async count(kind: string, now = new Date()) {
    const k = `${dayOf(now)}|${kind}`;
    this.rows.set(k, (this.rows.get(k) ?? 0) + 1);
  }
  async recent(days: number, now = new Date()) {
    return lastDays(days, now).map((day) => {
      const counts: Record<string, number> = {};
      for (const [k, n] of this.rows) if (k.startsWith(day + "|")) counts[k.slice(11)] = n;
      return { day, counts };
    });
  }
}


export class D1Stats implements StatsStore {
  constructor(private readonly db: D1Like) {}
  async count(kind: string, now = new Date()) {
    await this.db
      .prepare("INSERT INTO daily_stats (day, kind, n) VALUES (?, ?, 1) ON CONFLICT(day, kind) DO UPDATE SET n = n + 1")
      .bind(dayOf(now), kind)
      .run();
  }
  async recent(days: number, now = new Date()) {
    const span = lastDays(days, now);
    const r = await this.db
      .prepare("SELECT day, kind, n FROM daily_stats WHERE day >= ? ORDER BY day")
      .bind(span[0])
      .all<{ day: string; kind: string; n: number }>();
    return span.map((day) => ({
      day,
      counts: Object.fromEntries(r.results.filter((x) => x.day === day).map((x) => [x.kind, x.n])),
    }));
  }
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

/** Self-contained public page (no scripts, no external resources). */
export function statsPage(s: {
  days: DayStats[];
  registerSize: number;
  latestAnchor: { size: number; state: string; time: string } | null;
  generatedAt: string;
}): string {
  const sum = (d: DayStats, prefix: string) => Object.entries(d.counts).filter(([k]) => k.startsWith(prefix)).reduce((a, [, n]) => a + n, 0);
  const total = (prefix: string) => s.days.reduce((a, d) => a + sum(d, prefix), 0);
  const max = Math.max(1, ...s.days.map((d) => sum(d, "")));
  const rows = s.days
    .slice()
    .reverse()
    .map((d) => {
      const all = sum(d, "");
      return `<tr><td>${esc(d.day)}</td><td>${sum(d, "read:ai_agent") + sum(d, "write:ai_agent")}</td><td>${sum(d, "read:program") + sum(d, "write:program")}</td><td>${sum(d, "read:browser") + sum(d, "write:browser")}</td><td>${sum(d, "write:")}</td><td class="bar"><span style="width:${Math.round((all / max) * 100)}%"></span></td></tr>`;
    })
    .join("\n");
  const anchor = s.latestAnchor
    ? `${s.latestAnchor.state === "confirmed" ? "confirmed in Bitcoin" : "waiting for Bitcoin"} · covers ${s.latestAnchor.size} entries · ${esc(s.latestAnchor.time)}`
    : "none yet (first anchor every night at 03:17 UTC)";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register stats</title>
<style>
:root{--bg:#fbfaf7;--fg:#1d1b18;--muted:#6b665e;--line:#e4e0d8;--accent:#2f5d50}
@media (prefers-color-scheme:dark){:root{--bg:#151412;--fg:#ece8e1;--muted:#a39d93;--line:#2d2a26;--accent:#7fb8a6}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:760px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}p{margin:0 0 16px;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
.tile{border:1px solid var(--line);border-radius:10px;padding:12px 14px}.tile b{display:block;font-size:1.6rem;font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:.85rem}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums;font-size:.92rem}
th,td{text-align:right;padding:6px 8px;border-bottom:1px solid var(--line)}th:first-child,td:first-child{text-align:left}
th{color:var(--muted);font-weight:500}.bar{width:30%}.bar span{display:block;height:8px;border-radius:4px;background:var(--accent)}
.note{font-size:.85rem;margin-top:20px}
</style></head><body><main>
<h1>Register stats</h1>
<p>Honest public counters of this prototype register. Anonymous daily counts only: no addresses, no identities, no contents are stored. Last 30 days, UTC.</p>
<div class="tiles">
<div class="tile"><b>${s.registerSize}</b><span>entries in the register</span></div>
<div class="tile"><b>${total("read:ai_agent") + total("write:ai_agent")}</b><span>requests from AI agents</span></div>
<div class="tile"><b>${total("write:")}</b><span>entries sealed</span></div>
<div class="tile"><b>${total("")}</b><span>requests in total</span></div>
</div>
<p><strong>Bitcoin anchor:</strong> ${anchor}</p>
<table><thead><tr><th>Day</th><th>AI agents</th><th>Programs</th><th>Browsers</th><th>Sealed</th><th></th></tr></thead><tbody>
${rows}
</tbody></table>
<p class="note">"AI agents", "programs" and "browsers" are guessed from the User-Agent header and can be wrong. A seal comes from whoever holds a fingerprint: this register cannot tell who is behind it, by design. Counting started on 12 November 2026. Updated ${esc(s.generatedAt)}. Data: <a href="/v1/stats">/v1/stats</a>.</p>
</main></body></html>`;
}
