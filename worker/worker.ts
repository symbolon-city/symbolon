// Cloudflare Worker entry point for the register.
// Bindings: DB (D1 database), REGISTER_SECRET_KEY (secret, 32-byte hex),
// WRITE_LIMIT (Cloudflare rate limiter, per client: IPv4 address or IPv6 /64), INTERNAL_WRITE_LIMIT (rate
// limiter of the internal lane), INTERNAL_WRITE_SECRET (secret shared with the piazza, sent in the
// x-symbolon-internal header), DAILY_WRITE_CAP (default 5000: plain entries and cosignatures) and the other
// daily limits of src/server/gate.ts (GateEnv), all optional.
// Cron: anchors the latest head in Bitcoin once a day, upgrades pending anchors and prunes old daily counters hourly.

import { keyPairFromSecret } from "../src/keys.js";
import { Register } from "../src/register.js";
import { anchorLatest, handle, upgradePending, type AppDeps } from "../src/server/app.js";
import { writeGate, type GateEnv } from "../src/server/gate.js";
import { D1Store, SCHEMA, pruneDailyWrites, type D1Like } from "../src/server/stores.js";
import { D1Stats } from "../src/server/stats.js";

interface Env extends GateEnv {
  DB: D1Like & { exec(sql: string): Promise<unknown> };
  REGISTER_SECRET_KEY: string;
  BASE_URL?: string;
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
    try {
      await pruneDailyWrites(env.DB);
    } catch (e) {
      console.error("pruning daily counters failed:", e);
    }
    await upgradePending(d);
  },
};
