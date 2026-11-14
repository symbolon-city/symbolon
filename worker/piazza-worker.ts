// Cloudflare Worker of the piazza (separate from the notary register).
// Bindings: DB (D1), REGISTER_URL (notary register), DEMO_OWNER_KEY (optional: owner key of the
// declared demonstration agents, published at this piazza's own /.well-known/symbolon.json, also served at the earlier accord.json path),
// ENVELOPE_LIMIT (rate limiter per client).

import { httpOwnerResolver, type OwnerResolver } from "../src/wellknown.js";
import { handlePiazza } from "../src/piazza/app.js";
import { D1PiazzaStore, PIAZZA_SCHEMA } from "../src/piazza/stores.js";
import { claudeAskModel } from "../src/piazza/guide-claude.js";
import type { D1Like } from "../src/server/stores.js";

interface Env {
  DB: D1Like & { exec(sql: string): Promise<unknown> };
  REGISTER_URL: string;
  /** Service binding to the register worker (same account: direct workers.dev calls are blocked). */
  REGISTER?: { fetch(req: Request): Promise<Response> };
  DEMO_OWNER_KEY?: string;
  ENVELOPE_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  /** Secret: API key of the Guide (its own key, with a spending limit on the Anthropic side too). Absent: prepared answers only. */
  GUIDE_ANTHROPIC_API_KEY?: string;
  /** Daily spending cap of the Guide in millionths of a dollar (default in guide.ts). */
  GUIDE_DAILY_BUDGET_MICRO_USD?: string;
}

let schemaReady = false;
const cache = new Map<string, { keys: string[] | null; at: number }>();

function resolver(env: Env, host: string): OwnerResolver {
  const http = httpOwnerResolver();
  return async (domain) => {
    if (domain === host) return env.DEMO_OWNER_KEY ? [env.DEMO_OWNER_KEY] : null;
    const hit = cache.get(domain);
    if (hit && Date.now() - hit.at < 5 * 60_000) return hit.keys;
    const keys = await http(domain);
    cache.set(domain, { keys, at: Date.now() });
    return keys;
  };
}

export default {
  async fetch(req: Request, env: Env, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/.well-known/symbolon.json" || url.pathname === "/.well-known/accord.json") {
      if (!env.DEMO_OWNER_KEY) return new Response("Not found", { status: 404 });
      return Response.json({ symbolon: 1, accord: 1, domain: url.host, keys: [env.DEMO_OWNER_KEY], note: "demonstration agents of the piazza, declared as such" });
    }
    if (req.method === "POST" && env.ENVELOPE_LIMIT) {
      const ok = (await env.ENVELOPE_LIMIT.limit({ key: req.headers.get("cf-connecting-ip") ?? "unknown" })).success;
      if (!ok) return Response.json({ error: "too many requests, retry in a minute" }, { status: 429 });
    }
    if (!schemaReady) {
      await env.DB.exec(PIAZZA_SCHEMA.trim());
      schemaReady = true;
    }
    return handlePiazza(req, {
      store: new D1PiazzaStore(env.DB),
      ownerResolver: resolver(env, url.host),
      origin: url.origin,
      demoDomain: url.host,
      seal: async (fingerprint) => {
        const req2 = new Request(env.REGISTER_URL.replace(/\/+$/, "") + "/v1/entries", {
          method: "POST",
          headers: { "content-type": "application/json", "user-agent": "symbolon-piazza" },
          body: JSON.stringify({ entry: fingerprint }),
        });
        const res = env.REGISTER ? await env.REGISTER.fetch(req2) : await fetch(req2);
        if (!res.ok) throw new Error(`register: HTTP ${res.status}`);
        return ((await res.json()) as { index: number }).index;
      },
      defer: (p) => ctx.waitUntil(p),
      guide: {
        askModel: env.GUIDE_ANTHROPIC_API_KEY ? claudeAskModel(env.GUIDE_ANTHROPIC_API_KEY) : undefined,
        budgetMicroUsd: env.GUIDE_DAILY_BUDGET_MICRO_USD ? Number(env.GUIDE_DAILY_BUDGET_MICRO_USD) : undefined,
      },
      clientKey: (r) => r.headers.get("cf-connecting-ip") ?? "unknown",
    });
  },
};
