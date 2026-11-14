// Cloudflare Worker of the visitors' door: MCP over streamable HTTP at /mcp.
// Bindings: REGISTER and PIAZZA (service bindings to the register and piazza workers of the
// same account: direct workers.dev calls between them are blocked), REGISTER_URL and PIAZZA_URL
// (their public addresses), DOOR_LIMIT (rate limiter per client).

import { HttpRegisterClient } from "../src/agent/client.js";
import { esploraProvider } from "../src/anchor.js";
import { httpOwnerResolver, type OwnerResolver } from "../src/wellknown.js";
import { handleDoor } from "../src/visitor/door.js";

interface Service {
  fetch(req: Request): Promise<Response>;
}

interface Env {
  REGISTER: Service;
  PIAZZA?: Service;
  REGISTER_URL: string;
  PIAZZA_URL?: string;
  DOOR_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
}

const cache = new Map<string, { keys: string[] | null; at: number }>();

/** Calls a sibling worker through its binding, passing on the visitor's address for its own limits. */
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
    if (req.method === "POST" && env.DOOR_LIMIT && !(await env.DOOR_LIMIT.limit({ key: client })).success)
      return Response.json({ jsonrpc: "2.0", error: { code: -32000, message: "too many requests, retry in a minute" }, id: null }, { status: 429 });

    const registerUrl = env.REGISTER_URL.replace(/\/+$/, "");
    const piazzaUrl = env.PIAZZA_URL?.replace(/\/+$/, "");
    const registerFetch = via(env.REGISTER, client);
    const piazzaFetch = env.PIAZZA ? via(env.PIAZZA, client) : undefined;

    // Owner keys: siblings through their bindings, everyone else over the internet (cached 5 minutes).
    const http = httpOwnerResolver();
    const siblings = httpOwnerResolver(async (input, init) => {
      const host = new URL(String(input)).host;
      if (piazzaFetch && piazzaUrl && host === new URL(piazzaUrl).host) return piazzaFetch(input, init);
      return registerFetch(input, init);
    });
    const ownerResolver: OwnerResolver = async (domain) => {
      const isSibling = [registerUrl, piazzaUrl].some((u) => u && new URL(u).host === domain);
      if (isSibling) return siblings(domain);
      const hit = cache.get(domain);
      if (hit && Date.now() - hit.at < 5 * 60_000) return hit.keys;
      const keys = await http(domain);
      cache.set(domain, { keys, at: Date.now() });
      return keys;
    };

    return handleDoor(req, {
      register: new HttpRegisterClient(registerUrl, registerFetch),
      registerUrl,
      piazza: piazzaFetch && piazzaUrl ? (path, init) => piazzaFetch(piazzaUrl + path, init) : undefined,
      piazzaUrl,
      ownerResolver,
      bitcoin: esploraProvider(),
    });
  },
};
