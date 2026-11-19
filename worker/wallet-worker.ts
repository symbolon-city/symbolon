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
import { handleHosted } from "../src/hosted/app.js";
import type { KeyValue } from "../src/hosted/store.js";

interface Service {
  fetch(req: Request): Promise<Response>;
}
interface DurableStorage {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
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
    const client = req.headers.get("cf-connecting-ip") ?? "unknown";
    if (req.method === "POST" && env.WALLET_LIMIT && !(await env.WALLET_LIMIT.limit({ key: client })).success)
      return Response.json({ error: "too many requests, retry in a minute" }, { status: 429 });
    return env.WALLET.get(env.WALLET.idFromName("wallet")).fetch(req);
  },
};

const ownerCache = new Map<string, { keys: string[] | null; at: number }>();

export class WalletHome {
  private readonly kv: KeyValue;
  constructor(
    state: { storage: DurableStorage },
    private readonly env: Env,
  ) {
    const s = state.storage;
    this.kv = { get: (k) => s.get(k), put: (k, v) => s.put(k, v), delete: async (k) => void (await s.delete(k)) };
  }

  async fetch(req: Request): Promise<Response> {
    const env = this.env;
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
