// Cloudflare Worker entry point for the register.
// Bindings: DB (D1 database), REGISTER_SECRET_KEY (secret, 32-byte hex),
// WRITE_LIMIT (Cloudflare rate limiter, per client), DAILY_WRITE_CAP (optional, default 5000: plain entries
// and cosignatures), DAILY_REVOCATION_CAP (optional, default 20000: revocations have their own cap).
// Cron: anchors the latest head in Bitcoin once a day and upgrades pending anchors hourly.

import { keyPairFromSecret } from "../src/keys.js";
import { Register } from "../src/register.js";
import { anchorLatest, handle, upgradePending, type AppDeps } from "../src/server/app.js";
import { writeGate } from "../src/server/gate.js";
import { D1Store, SCHEMA, type D1Like } from "../src/server/stores.js";
import { D1Stats } from "../src/server/stats.js";

interface Env {
  DB: D1Like & { exec(sql: string): Promise<unknown> };
  REGISTER_SECRET_KEY: string;
  BASE_URL?: string;
  WRITE_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  DAILY_WRITE_CAP?: string;
  DAILY_REVOCATION_CAP?: string;
}

let schemaReady = false;

async function deps(env: Env, origin: string, defer?: (p: Promise<unknown>) => void): Promise<AppDeps> {
  if (!schemaReady) {
    await env.DB.exec(SCHEMA.trim()); // D1 exec: one statement per line
    schemaReady = true;
  }
  const store = new D1Store(env.DB);
  return { register: new Register(keyPairFromSecret(env.REGISTER_SECRET_KEY), store), extras: store, baseUrl: env.BASE_URL ?? origin, ...writeGate(env), stats: new D1Stats(env.DB), defer };
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
