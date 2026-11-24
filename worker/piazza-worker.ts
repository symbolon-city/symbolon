// Cloudflare Worker of the piazza (separate from the public register).
// Bindings: DB (D1), REGISTER_URL (public register), REGISTER (service binding to it), ENVELOPE_LIMIT (rate limiter per client),
// DEMO_OWNER_KEY (optional, comma-separated: earlier owner keys of the declared demonstration agents),
// DEMO_OWNER_SECRET (secret, optional: owner key of the demonstration city; its public key is published too),
// PIAZZA_URL (public address, used by the scheduled demonstration run).
// The demo owner keys are published at this piazza's own /.well-known/symbolon.json (also at the earlier accord.json path).
// INTERNAL_WRITE_SECRET (secret, optional): sent as x-symbolon-internal on calls to the register, which gives the
// piazza's own seals their reserved lane there instead of the shared bucket of clients without an address.
// CLIENT_HASH_SECRET (secret, optional): key of the daily one-way fingerprint of visitors (see PiazzaDeps.clientHashSecret).
// Cron: upkeep (failed seals sealed again, old sealed forms, nonces, counters and Guide answers deleted:
// maintainPiazza in src/piazza/app.ts), then the demonstration agents keep one example post each on the board (src/piazza/demo.ts).

import { keyPairFromSecret } from "../src/keys.js";
import { httpOwnerResolver, type OwnerResolver } from "../src/wellknown.js";
import { handlePiazza, maintainPiazza, type PiazzaDeps } from "../src/piazza/app.js";
import { clientKeyOfRequest } from "../src/client-key.js";
import { OwnerKeyCache, cachedOwnerResolver } from "../src/visitor/owner-cache.js";
import { demoPartnerOwner, runDemoAgreement, runDemoCity } from "../src/piazza/demo.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { D1PiazzaStore, PIAZZA_MIGRATIONS, PIAZZA_SCHEMA } from "../src/piazza/stores.js";
import { claudeAskModel, claudeDemoWriter } from "../src/piazza/guide-claude.js";
import type { D1Like } from "../src/server/stores.js";
import { fetchAllRevocations, type RegisteredRevocation } from "../src/revocation.js";

interface Env {
  DB: D1Like & { exec(sql: string): Promise<unknown> };
  REGISTER_URL: string;
  /** Service binding to the register worker (same account: direct workers.dev calls are blocked). */
  REGISTER?: { fetch(req: Request): Promise<Response> };
  DEMO_OWNER_KEY?: string;
  DEMO_OWNER_SECRET?: string;
  PIAZZA_URL?: string;
  ENVELOPE_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  /** Secret: API key of the Guide (its own key, with a spending limit on the Anthropic side too). Absent: prepared answers only. */
  GUIDE_ANTHROPIC_API_KEY?: string;
  /** Daily spending cap of the Guide in millionths of a dollar (default in guide.ts). */
  GUIDE_DAILY_BUDGET_MICRO_USD?: string;
  /** Model calls per day for demo posts (default 6). */
  DEMO_DAILY_WRITES?: string;
  /** Domain of the second demonstration owner (its key is served by the door at /.well-known/symbolon.json). */
  DEMO_PARTNER_DOMAIN?: string;
  /** Secret shared with the register: its reserved lane for the piazza's own seals. */
  INTERNAL_WRITE_SECRET?: string;
  /** Secret of the visitors' daily one-way fingerprint. */
  CLIENT_HASH_SECRET?: string;
}

let schemaReady = false;
const cache = new OwnerKeyCache();

function demoKeys(env: Env): string[] {
  const keys = (env.DEMO_OWNER_KEY ?? "").split(",").map((k) => k.trim()).filter(Boolean);
  if (env.DEMO_OWNER_SECRET) keys.push(keyPairFromSecret(env.DEMO_OWNER_SECRET).publicKey);
  return [...new Set(keys)];
}

function resolver(env: Env, host: string): OwnerResolver {
  // A board page checks the owners of up to 50 posts: room for one lookup per post (cache misses only).
  const http = cachedOwnerResolver(cache, httpOwnerResolver(), 50);
  return async (domain) => {
    if (env.DEMO_OWNER_SECRET && domain === env.DEMO_PARTNER_DOMAIN) return [demoPartnerOwner(env.DEMO_OWNER_SECRET).publicKey];
    if (domain === host) {
      const keys = demoKeys(env);
      return keys.length ? keys : null;
    }
    return http(domain);
  };
}

async function ready(env: Env) {
  if (schemaReady) return;
  await env.DB.exec(PIAZZA_SCHEMA.trim());
  for (const sql of PIAZZA_MIGRATIONS) await env.DB.exec(sql).catch(() => {}); // already applied
  schemaReady = true;
}

function registerCall(env: Env, path: string, init?: RequestInit): Promise<Response> {
  const req = new Request(env.REGISTER_URL.replace(/\/+$/, "") + path, {
    ...init,
    headers: {
      ...(init?.headers as Record<string, string> | undefined),
      "user-agent": "symbolon-piazza",
      ...(env.INTERNAL_WRITE_SECRET ? { "x-symbolon-internal": env.INTERNAL_WRITE_SECRET } : {}),
    },
  });
  return env.REGISTER ? env.REGISTER.fetch(req) : fetch(req);
}

function deps(env: Env, origin: string, defer?: (p: Promise<unknown>) => void): PiazzaDeps {
  return {
    store: new D1PiazzaStore(env.DB),
    ownerResolver: resolver(env, new URL(origin).host),
    origin,
    demoDomain: new URL(origin).host,
    revocations: (subjects, signers) =>
      fetchAllRevocations(
        async (path) => {
          const res = await registerCall(env, path);
          if (!res.ok) throw new Error(`register: HTTP ${res.status}`);
          return (await res.json()) as { revocations: RegisteredRevocation[]; next?: number };
        },
        subjects,
        signers,
      ),
    seal: async (fingerprint) => {
      const res = await registerCall(env, "/v1/entries", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ entry: fingerprint }) });
      if (!res.ok) throw new Error(`register: HTTP ${res.status}`);
      return ((await res.json()) as { index: number }).index;
    },
    defer,
    guide: {
      askModel: env.GUIDE_ANTHROPIC_API_KEY ? claudeAskModel(env.GUIDE_ANTHROPIC_API_KEY) : undefined,
      budgetMicroUsd: env.GUIDE_DAILY_BUDGET_MICRO_USD ? Number(env.GUIDE_DAILY_BUDGET_MICRO_USD) : undefined,
    },
    clientKey: clientKeyOfRequest,
    clientHashSecret: env.CLIENT_HASH_SECRET,
  };
}

export default {
  async fetch(req: Request, env: Env, ctx: { waitUntil(p: Promise<unknown>): void }): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/.well-known/symbolon.json" || url.pathname === "/.well-known/accord.json") {
      const keys = demoKeys(env);
      if (!keys.length) return new Response("Not found", { status: 404 });
      return Response.json({ symbolon: 1, accord: 1, domain: url.host, keys, note: "demonstration agents of the piazza, declared as such" });
    }
    if (url.pathname === "/v1/demo/partner") {
      if (!env.DEMO_OWNER_SECRET || !env.DEMO_PARTNER_DOMAIN) return Response.json({ error: "not found" }, { status: 404 });
      return Response.json({ symbolon: 1, domain: env.DEMO_PARTNER_DOMAIN, keys: [demoPartnerOwner(env.DEMO_OWNER_SECRET).publicKey], note: "second demonstration owner of the city, declared as such" });
    }
    if (req.method === "POST" && env.ENVELOPE_LIMIT) {
      const ok = (await env.ENVELOPE_LIMIT.limit({ key: clientKeyOfRequest(req) })).success;
      if (!ok) return Response.json({ error: "too many requests, retry in a minute" }, { status: 429 });
    }
    await ready(env);
    return handlePiazza(req, deps(env, url.origin, (p) => ctx.waitUntil(p)));
  },

  async scheduled(_event: { cron: string }, env: Env): Promise<void> {
    await ready(env);
    const origin = (env.PIAZZA_URL ?? "https://piazza.invalid").replace(/\/+$/, "");
    const upkeep = await maintainPiazza(deps(env, origin)).catch((e) => ({ error: String(e) }));
    console.log("upkeep:", JSON.stringify(upkeep));
    if (!env.DEMO_OWNER_SECRET || !env.PIAZZA_URL) return;
    const result = await runDemoCity({
      deps: deps(env, env.PIAZZA_URL.replace(/\/+$/, "")),
      ownerSecret: env.DEMO_OWNER_SECRET,
      writer: env.GUIDE_ANTHROPIC_API_KEY ? claudeDemoWriter(env.GUIDE_ANTHROPIC_API_KEY) : undefined,
      maxWrites: env.DEMO_DAILY_WRITES ? Number(env.DEMO_DAILY_WRITES) : undefined,
    });
    console.log("demo city:", JSON.stringify(result));
    if (env.DEMO_PARTNER_DOMAIN) {
      const d = deps(env, env.PIAZZA_URL.replace(/\/+$/, ""));
      const register = new HttpRegisterClient(env.REGISTER_URL.replace(/\/+$/, ""), (input, init) => registerCall(env, new URL(String(input)).pathname + new URL(String(input)).search, init));
      const agreement = await runDemoAgreement({ deps: d, ownerSecret: env.DEMO_OWNER_SECRET, partnerDomain: env.DEMO_PARTNER_DOMAIN, register }).catch((e) => ({ error: String(e) }));
      console.log("demo agreement:", JSON.stringify(agreement));
    }
  },
};
