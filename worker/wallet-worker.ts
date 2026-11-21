// Cloudflare Worker of the hosted wallet ("the connector", src/hosted/app.ts). Not online yet: publishing it
// needs Andrea's go and the full attack test first (start_here.md, "Cose aperte").
// Everything runs in one Durable Object (strongly consistent storage, one wallet operation at a time per owner);
// it can be split by owner later. Bindings: WALLET (the Durable Object), REGISTER (service binding to the
// register worker), REGISTER_URL, ORIGIN (this service's public address), WALLET_SECRET (secret, base64url,
// 32 bytes or more: `wrangler secret put WALLET_SECRET`), WALLET_LIMIT (rate limiter per client),
// PIAZZA / PIAZZA_URL (optional).

import { HttpRegisterClient } from "../src/agent/client.js";
import { esploraProvider } from "../src/anchor.js";
import { fromBase64url } from "../src/bytes.js";
import { httpOwnerResolver, type OwnerResolver } from "../src/wellknown.js";
import { clientKeyOfRequest } from "../src/client-key.js";
import { handleHosted, sweepHosted } from "../src/hosted/app.js";
import type { KeyValue } from "../src/hosted/store.js";

interface Service {
  fetch(req: Request): Promise<Response>;
}
interface DurableStorage {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
  list(o: { prefix: string; limit: number; startAfter?: string }): Promise<Map<string, unknown>>;
  getAlarm(): Promise<number | null>;
  setAlarm(at: number): Promise<void>;
}
interface DurableNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): Service;
}
interface Env {
  WALLET: DurableNamespace;
  REGISTER: Service;
  REGISTER_URL: string;
  ORIGIN: string;
  WALLET_SECRET: string;
  PIAZZA?: Service;
  PIAZZA_URL?: string;
  WALLET_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
}

/** Calls a sibling worker through its binding, passing on the visitor's address for its own limits. */
function via(service: Service, client: string): typeof fetch {
  return async (input, init) => {
    const req = new Request(String(input), init);
    const headers = new Headers(req.headers);
    headers.set("cf-connecting-ip", client);
    headers.set("user-agent", "symbolon-wallet");
    return service.fetch(new Request(req, { headers }));
  };
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    // Every request counts (GET too: the pages and the connection requests), per client (IPv6 by /64).
    if (req.method !== "OPTIONS" && env.WALLET_LIMIT && !(await env.WALLET_LIMIT.limit({ key: clientKeyOfRequest(req) })).success)
      return Response.json({ error: "too many requests, retry in a minute" }, { status: 429 });
    return env.WALLET.get(env.WALLET.idFromName("wallet")).fetch(req);
  },
};

const ownerCache = new Map<string, { keys: string[] | null; at: number }>();

const SWEEP_EVERY = 60 * 60_000;
const SWEEP_CURSOR = "sweep-cursor";

export class WalletHome {
  private readonly kv: KeyValue;
  private readonly storage: DurableStorage;
  private alarmChecked = false;
  constructor(
    state: { storage: DurableStorage },
    private readonly env: Env,
  ) {
    const s = state.storage;
    this.storage = s;
    this.kv = { get: (k) => s.get(k), put: (k, v) => s.put(k, v), delete: async (k) => void (await s.delete(k)), list: (o) => s.list(o) };
  }

  /** Collects expired records (challenges, codes, tokens, links, unused assistants...) a slice at a time, every hour. */
  async alarm(): Promise<void> {
    const from = await this.storage.get<{ prefix: string; after?: string }>(SWEEP_CURSOR);
    const r = await sweepHosted(this.kv, Date.now(), { budget: 5000, ...(from ? { from } : {}) });
    if (r.next) await this.storage.put(SWEEP_CURSOR, r.next);
    else if (from) await this.storage.delete(SWEEP_CURSOR);
    await this.storage.setAlarm(Date.now() + (r.next ? 60_000 : SWEEP_EVERY));
  }

  async fetch(req: Request): Promise<Response> {
    const env = this.env;
    if (!this.alarmChecked) {
      this.alarmChecked = true;
      if ((await this.storage.getAlarm()) === null) await this.storage.setAlarm(Date.now() + SWEEP_EVERY);
    }
    const client = req.headers.get("cf-connecting-ip") ?? "unknown";
    const registerUrl = env.REGISTER_URL.replace(/\/+$/, "");
    const http = httpOwnerResolver();
    const ownerResolver: OwnerResolver = async (domain) => {
      const hit = ownerCache.get(domain);
      if (hit && Date.now() - hit.at < 5 * 60_000) return hit.keys;
      const keys = await http(domain);
      ownerCache.set(domain, { keys, at: Date.now() });
      return keys;
    };
    const piazzaUrl = env.PIAZZA_URL?.replace(/\/+$/, "");
    return handleHosted(req, {
      kv: this.kv,
      secret: fromBase64url(env.WALLET_SECRET),
      origin: env.ORIGIN,
      register: new HttpRegisterClient(registerUrl, via(env.REGISTER, client)),
      ownerResolver,
      bitcoin: esploraProvider(),
      ...(env.PIAZZA && piazzaUrl ? { piazzaUrl, piazzaFetch: via(env.PIAZZA, client) } : {}),
    });
  }
}
