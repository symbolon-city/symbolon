// Cloudflare Worker of the visitors' door: MCP over streamable HTTP at /mcp.
// Bindings: REGISTER and PIAZZA (service bindings to the register and piazza workers of the
// same account: direct workers.dev calls between them are blocked), REGISTER_URL and PIAZZA_URL
// (their public addresses), DOOR_LIMIT (rate limiter per client).

import { HttpRegisterClient } from "../src/agent/client.js";
import { esploraProvider } from "../src/anchor.js";
import { httpOwnerResolver, type OwnerResolver } from "../src/wellknown.js";
import { handleDoor } from "../src/visitor/door.js";
import { clientKeyOfRequest } from "../src/client-key.js";
import { OwnerKeyCache, cachedOwnerResolver } from "../src/visitor/owner-cache.js";

interface Service {
  fetch(req: Request): Promise<Response>;
}

interface Env {
  REGISTER: Service;
  PIAZZA?: Service;
  REGISTER_URL: string;
  PIAZZA_URL?: string;
  DOOR_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  /** Domain of the second demonstration owner: its key is published here, as given by the piazza. */
  DEMO_PARTNER_DOMAIN?: string;
  /** Public address of the change book's pages. Absent: the book tool is not offered. */
  BOOK_URL?: string;
  /** R2 bucket of the change book: the door writes reading requests under requests/. Absent: no requests. */
  BOOK_REQUESTS?: { head(key: string): Promise<unknown | null>; put(key: string, value: string): Promise<unknown> };
}

/** Owner keys of other sites, shared by all requests of this isolate: bounded, least recently used go first. */
const cache = new OwnerKeyCache();

/**
 * Calls a sibling worker through its binding, passing on the visitor's address for its own limits (they key it
 * by /64 for IPv6, src/client-key.ts). Never adds the internal header: visitors' calls use the visitors' lanes.
 */
function via(service: Service, client: string): typeof fetch {
  return async (input, init) => {
    const req = new Request(String(input), init);
    const headers = new Headers(req.headers);
    headers.set("cf-connecting-ip", client);
    headers.set("user-agent", "symbolon-door");
    return service.fetch(new Request(req, { headers }));
  };
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const client = req.headers.get("cf-connecting-ip") ?? "unknown";
    const url = new URL(req.url);
    if (env.DEMO_PARTNER_DOMAIN && url.host === env.DEMO_PARTNER_DOMAIN && env.PIAZZA && env.PIAZZA_URL) {
      if (url.pathname !== "/.well-known/symbolon.json") return Response.json({ about: "Second demonstration owner of Symbolon City: its agents make example agreements only.", see: "https://symboloncity.com/llms.txt" });
      const res = await via(env.PIAZZA, client)(env.PIAZZA_URL.replace(/\/+$/, "") + "/v1/demo/partner");
      return new Response(res.body, { status: res.status, headers: { "content-type": "application/json", "access-control-allow-origin": "*" } });
    }
    if (req.method === "POST" && env.DOOR_LIMIT && !(await env.DOOR_LIMIT.limit({ key: clientKeyOfRequest(req) })).success)
      return Response.json({ jsonrpc: "2.0", error: { code: -32000, message: "too many requests, retry in a minute" }, id: null }, { status: 429 });

    const registerUrl = env.REGISTER_URL.replace(/\/+$/, "");
    const piazzaUrl = env.PIAZZA_URL?.replace(/\/+$/, "");
    const registerFetch = via(env.REGISTER, client);
    const piazzaFetch = env.PIAZZA ? via(env.PIAZZA, client) : undefined;

    // Owner keys: siblings through their bindings, everyone else over the internet (cached 5 minutes, at most
    // a few new lookups per request).
    const http = cachedOwnerResolver(cache, httpOwnerResolver());
    const siblings = httpOwnerResolver(async (input, init) => {
      const host = new URL(String(input)).host;
      if (piazzaFetch && piazzaUrl && host === new URL(piazzaUrl).host) return piazzaFetch(input, init);
      return registerFetch(input, init);
    });
    const ownerResolver: OwnerResolver = async (domain) => {
      if (piazzaFetch && piazzaUrl && domain === env.DEMO_PARTNER_DOMAIN) {
        const r = await piazzaFetch(piazzaUrl + "/v1/demo/partner").catch(() => null);
        return r?.ok ? ((await r.json()) as { keys: string[] }).keys : null;
      }
      const isSibling = [registerUrl, piazzaUrl].some((u) => u && new URL(u).host === domain);
      if (isSibling) return siblings(domain);
      return http(domain);
    };

    return handleDoor(req, {
      register: new HttpRegisterClient(registerUrl, registerFetch),
      registerUrl,
      piazza: piazzaFetch && piazzaUrl ? (path, init) => piazzaFetch(piazzaUrl + path, init) : undefined,
      piazzaUrl,
      ownerResolver,
      bitcoin: esploraProvider(),
      ...(env.BOOK_URL
        ? { bookUrl: env.BOOK_URL, book: (path: string) => fetch(env.BOOK_URL!.replace(/\/+$/, "") + "/" + path, { headers: { "user-agent": "symbolon-door" } }) }
        : {}),
      ...(env.BOOK_URL && env.BOOK_REQUESTS
        ? { bookRequests: { head: (k: string) => env.BOOK_REQUESTS!.head("dati/" + k), put: (k: string, v: string) => env.BOOK_REQUESTS!.put("dati/" + k, v) } }
        : {}),
    });
  },
};
