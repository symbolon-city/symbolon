// Cloudflare Worker entry point for the register.
// Bindings: DB (D1 database), REGISTER_SECRET_KEY (secret, 32-byte hex),
// WRITE_LIMIT (Cloudflare rate limiter, per client), DAILY_WRITE_CAP (optional, default 5000).
// Cron: anchors the latest head in Bitcoin once a day and upgrades pending anchors hourly.

import { keyPairFromSecret } from "../src/keys.js";
import { Register } from "../src/register.js";
import { anchorLatest, handle, upgradePending, type AppDeps } from "../src/server/app.js";
import { D1Store, SCHEMA, countDailyWrite, type D1Like } from "../src/server/stores.js";
import { D1Stats } from "../src/server/stats.js";

interface Env {
  DB: D1Like & { exec(sql: string): Promise<unknown> };
  REGISTER_SECRET_KEY: string;
  BASE_URL?: string;
  WRITE_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  DAILY_WRITE_CAP?: string;
}

/** Anti-spam: per-client rate limit (Cloudflare binding) + total cap per UTC day. */
function writeGate(env: Env) {
  const cap = Number(env.DAILY_WRITE_CAP ?? 5000);
  return async (req: Request): Promise<string | null> => {
    const client = req.headers.get("cf-connecting-ip") ?? "unknown";
    if (env.WRITE_LIMIT && !(await env.WRITE_LIMIT.limit({ key: client })).success) return "too many writes from this client, retry in a minute";
    if ((await countDailyWrite(env.DB)) > cap) return "daily write cap reached, retry tomorrow (UTC)";
    return null;
  };
}

let schemaReady = false;

async function deps(env: Env, origin: string, defer?: (p: Promise<unknown>) => void): Promise<AppDeps> {
  if (!schemaReady) {
    await env.DB.exec(SCHEMA.trim()); // D1 exec: one statement per line
    schemaReady = true;
  }
  const store = new D1Store(env.DB);
  return { register: new Register(keyPairFromSecret(env.REGISTER_SECRET_KEY), store), extras: store, baseUrl: env.BASE_URL ?? origin, allowWrite: writeGate(env), stats: new D1Stats(env.DB), defer };
}

export default {
  async fetch(req: Request, env: Env, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<Response> {
    return handle(req, await deps(env, new URL(req.url).origin, (p) => ctx.waitUntil(p)));
  },
  async scheduled(event: { cron: string }, env: Env): Promise<void> {
    const d = await deps(env, env.BASE_URL ?? "");
    if (event.cron === "17 3 * * *") {
      try {
        await anchorLatest(d);
      } catch (e) {
        console.error("anchor failed, will retry tomorrow:", e);
      }
    }
    await upgradePending(d);
  },
};
