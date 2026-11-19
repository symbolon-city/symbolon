// The hosted wallet ("the connector"): the agent's notary wallet kept on a server for its owner, so that a
// person like Marta adds Symbolon to the assistant she already uses with one click and Face ID, and never
// installs anything. Platform-neutral (Web standard Request/Response): Cloudflare runs it in a Durable Object
// (worker/wallet-worker.ts), tests run it in memory. Anyone can run their own: the code is the same.
//
//   OAuth 2.1 for MCP clients (dynamic registration, PKCE S256, public clients): the assistant asks to connect,
//   the owner signs in on this site with a passkey (Face ID, Touch ID, Windows Hello).
//   /mcp      the wallet's MCP tools (src/agent/mcp.ts) for the connected assistant, one wallet per owner.
//   /owner    the owner's page: requests to sign (a mandate, the approval of one agreement), the agent's
//             mandate and commitments, and "Block everything".
//
// The owner's identity is the passkey (identity level "key"); mandates and approvals are signed by it, on this
// page, over the exact text shown. The agent's key is kept here, encrypted: see src/hosted/store.ts.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { sha256 } from "@noble/hashes/sha2";
import type { BlockProvider } from "../anchor.js";
import { canonical } from "../canonical.js";
import { randomBytes, toBase64url, utf8, toHex } from "../bytes.js";
import { passkeyChallenge, type PublicKey } from "../keys.js";
import { mandateBody, signedMandate, type Amount, type MandateBody } from "../mandate.js";
import { revocationBody, signedRevocation, type RevocationBody } from "../revocation.js";
import type { OwnerResolver } from "../wellknown.js";
import type { RegisterClient } from "../agent/client.js";
import { buildMcpServer, type HostedOwner } from "../agent/mcp.js";
import { Wallet } from "../agent/wallet.js";
import { HostedWalletStorage, KeyedLock, getExpiring, putExpiring, takeExpiring, type KeyValue } from "./store.js";
import { loginProblem, registrationProblem, type LoginChallenge, type Site } from "./webauthn.js";
import { hostedPage } from "./pages.js";

export const HOSTED_VERSION = "0.1.0";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
export const TTL = {
  challenge: 5 * MIN,
  authorizeRequest: 15 * MIN,
  code: 5 * MIN,
  access: HOUR,
  refresh: 30 * DAY,
  session: 30 * MIN,
  mandateRequest: 7 * DAY,
} as const;
const MAX_BODY = 64 * 1024;
const MAX_LINKS = 50;

export interface HostedDeps {
  kv: KeyValue;
  /** The operator's secret (at least 32 bytes) that encrypts the owners' wallets. */
  secret: Uint8Array;
  /** This service's public origin, e.g. https://wallet.symboloncity.com (passkeys are bound to its host). */
  origin: string;
  register: RegisterClient;
  ownerResolver?: OwnerResolver;
  bitcoin?: BlockProvider;
  piazzaUrl?: string;
  piazzaFetch?: typeof fetch;
  charter?: string;
  now?: () => Date;
  lock?: KeyedLock;
}

interface Account {
  publicKey: PublicKey;
  credentialId: string;
  createdAt: string;
  /** Raised by "Block everything": every token and session issued before stops working. */
  epoch: number;
  /** Which agent of this owner is in use: after "Block everything" a new one starts (the old wallet is kept). */
  agentGen: number;
}

interface Client {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  createdAt: string;
}

interface AuthorizeRequest {
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge: string;
}

interface Grant {
  owner: string;
  client_id: string;
  epoch: number;
}

type Link = { owner: string; kind: "approval"; root: string } | { owner: string; kind: "mandate"; body: MandateBody };

const defaultLock = new KeyedLock();

const sha = (s: string) => toHex(sha256(utf8(s)));
const newSecret = () => toBase64url(randomBytes(32));
const ownerIdOf = (pk: PublicKey) => sha(pk).slice(0, 32);

const json = (data: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
const oauthError = (error: string, description: string, status = 400) => json({ error, error_description: description }, status, CORS);

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, accept, mcp-session-id, mcp-protocol-version, last-event-id",
  "access-control-expose-headers": "mcp-session-id, www-authenticate",
};

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "request too large");
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
}

/**
 * Where an assistant may be sent back after the owner signs in: https addresses, the device itself
 * (http://localhost, 127.0.0.1, [::1], for assistants on a computer) and apps' own schemes. Never with a fragment.
 */
export function redirectUriProblem(uri: unknown): string | null {
  if (typeof uri !== "string" || uri.length > 512) return "invalid redirect_uri";
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return "invalid redirect_uri";
  }
  if (u.hash) return "a redirect_uri cannot have a fragment";
  if (u.username || u.password) return "a redirect_uri cannot carry credentials";
  if (u.protocol === "https:") return null;
  if (u.protocol === "http:") return ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname) ? null : "http is allowed only for localhost";
  if (["javascript:", "data:", "file:", "blob:", "about:", "vbscript:", "ftp:", "ws:", "wss:"].includes(u.protocol)) return "this redirect_uri scheme is not allowed";
  return /^[a-z][a-z0-9+.-]*:$/.test(u.protocol) ? null : "invalid redirect_uri";
}

export async function handleHosted(req: Request, deps: HostedDeps): Promise<Response> {
  try {
    return await route(req, deps);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    return json({ error: (e as Error).message ?? "error" }, 400);
  }
}

async function route(req: Request, deps: HostedDeps): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const now = (deps.now ?? (() => new Date()))().getTime();
  const site: Site = { origin: deps.origin.replace(/\/+$/, ""), rpId: new URL(deps.origin).hostname };
  const kv = deps.kv;
  const lock = deps.lock ?? defaultLock;
  const mcpUrl = site.origin + "/mcp";

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  // ---------- OAuth discovery ----------
  if (req.method === "GET" && (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp"))
    return json({ resource: mcpUrl, authorization_servers: [site.origin], bearer_methods_supported: ["header"], resource_name: "Symbolon wallet" }, 200, CORS);
  if (req.method === "GET" && (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration"))
    return json(
      {
        issuer: site.origin,
        authorization_endpoint: site.origin + "/authorize",
        token_endpoint: site.origin + "/token",
        registration_endpoint: site.origin + "/register",
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        authorization_response_iss_parameter_supported: true,
        service_documentation: "https://github.com/symbolon-city/symbolon",
      },
      200,
      CORS,
    );

  // ---------- dynamic client registration (RFC 7591) ----------
  if (req.method === "POST" && path === "/register") {
    const body = await readJson(req).catch(() => null);
    if (!body) return oauthError("invalid_client_metadata", "invalid JSON");
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || uris.length < 1 || uris.length > 5) return oauthError("invalid_redirect_uri", "give 1 to 5 redirect_uris");
    for (const u of uris) {
      const p = redirectUriProblem(u);
      if (p) return oauthError("invalid_redirect_uri", p);
    }
    const method = body.token_endpoint_auth_method ?? "none";
    if (method !== "none") return oauthError("invalid_client_metadata", "only public clients (token_endpoint_auth_method none, with PKCE)");
    const name = typeof body.client_name === "string" ? body.client_name.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, 80) : "";
    const client: Client = { client_id: "c_" + newSecret(), client_name: name || "An assistant", redirect_uris: uris as string[], createdAt: new Date(now).toISOString() };
    await kv.put(`client:${client.client_id}`, client);
    return json(
      {
        client_id: client.client_id,
        client_id_issued_at: Math.floor(now / 1000),
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
      201,
      CORS,
    );
  }

  // ---------- authorization: the owner signs in with a passkey ----------
  if (req.method === "GET" && path === "/authorize") {
    const q = url.searchParams;
    const client = await kv.get<Client>(`client:${q.get("client_id") ?? ""}`);
    const redirect = q.get("redirect_uri") ?? "";
    if (!client || !client.redirect_uris.includes(redirect))
      return hostedPage({ view: "error", origin: site.origin, message: "This connection request is not valid (unknown assistant or return address). Start again from your assistant." }, 400);
    const back = (error: string, description: string) => {
      const u = new URL(redirect);
      u.searchParams.set("error", error);
      u.searchParams.set("error_description", description);
      if (q.get("state")) u.searchParams.set("state", q.get("state")!);
      u.searchParams.set("iss", site.origin);
      return Response.redirect(u.toString(), 302);
    };
    if (q.get("response_type") !== "code") return back("unsupported_response_type", "only response_type=code");
    const challenge = q.get("code_challenge") ?? "";
    if (q.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return back("invalid_request", "PKCE with S256 is required");
    const resource = q.get("resource");
    if (resource && resource.replace(/\/+$/, "") !== mcpUrl && resource.replace(/\/+$/, "") !== site.origin) return back("invalid_target", "unknown resource");
    const state = q.get("state") ?? undefined;
    if (state && state.length > 512) return back("invalid_request", "state too long");
    const id = newSecret();
    await putExpiring(kv, `areq:${id}`, { client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, ...(state ? { state } : {}) } satisfies AuthorizeRequest, now + TTL.authorizeRequest);
    return hostedPage({ view: "authorize", origin: site.origin, request: id, client: client.client_name, redirectHost: new URL(redirect).host || new URL(redirect).protocol });
  }

  // ---------- passkeys: challenge, sign in, first passkey ----------
  if (req.method === "POST" && path.startsWith("/auth/")) {
    sameOrigin(req, site);
    const body = await readJson(req);
    if (path === "/auth/challenge") {
      const purpose = body.purpose;
      if (typeof purpose !== "string" || !(purpose === "owner" || /^authorize:[A-Za-z0-9_-]{43}$/.test(purpose))) throw new HttpError(400, "invalid purpose");
      const challenge: LoginChallenge = { type: "symbolon-hosted/login", origin: site.origin, purpose, nonce: newSecret() };
      await putExpiring(kv, `chal:${challenge.nonce}`, challenge, now + TTL.challenge);
      return json({ nonce: challenge.nonce, challenge: toBase64url(passkeyChallenge(challenge)), rpId: site.rpId });
    }
    if (path === "/auth/signin" || path === "/auth/signup") {
      const challenge = typeof body.nonce === "string" ? await takeExpiring<LoginChallenge>(kv, `chal:${body.nonce}`, now) : undefined;
      if (!challenge) throw new HttpError(400, "the sign-in expired: try again");
      let owner: string;
      if (path === "/auth/signin") {
        if (typeof body.credentialId !== "string" || body.credentialId.length > 1023) throw new HttpError(400, "invalid credential");
        const found = await kv.get<string>(`cred:${body.credentialId}`);
        const account = found ? await kv.get<Account>(`acct:${found}`) : undefined;
        if (!found || !account) throw new HttpError(404, "this passkey has no Symbolon wallet here: create one");
        const problem = loginProblem(challenge, String(body.signature ?? ""), account.publicKey, site);
        if (problem) throw new HttpError(401, problem);
        owner = found;
      } else {
        const r = registrationProblem(challenge, body as never, site);
        if ("problem" in r) throw new HttpError(400, r.problem);
        if (await kv.get(`cred:${r.passkey.credentialId}`)) throw new HttpError(409, "this passkey is already registered: sign in");
        owner = ownerIdOf(r.passkey.publicKey);
        if (await kv.get(`acct:${owner}`)) throw new HttpError(409, "this key is already registered: sign in");
        const account: Account = { publicKey: r.passkey.publicKey, credentialId: r.passkey.credentialId, createdAt: new Date(now).toISOString(), epoch: 0, agentGen: 0 };
        await kv.put(`acct:${owner}`, account);
        await kv.put(`cred:${r.passkey.credentialId}`, owner);
      }
      const account = (await kv.get<Account>(`acct:${owner}`))!;
      if (challenge.purpose === "owner") {
        const session = "s_" + newSecret();
        await putExpiring(kv, `sess:${sha(session)}`, { owner, client_id: "", epoch: account.epoch } satisfies Grant, now + TTL.session);
        return json({ session, expires_in: TTL.session / 1000 });
      }
      const areq = await takeExpiring<AuthorizeRequest>(kv, `areq:${challenge.purpose.slice("authorize:".length)}`, now);
      if (!areq) throw new HttpError(400, "the connection request expired: start again from your assistant");
      const code = "a_" + newSecret();
      await putExpiring(kv, `code:${sha(code)}`, { ...areq, owner, epoch: account.epoch }, now + TTL.code);
      const u = new URL(areq.redirect_uri);
      u.searchParams.set("code", code);
      if (areq.state) u.searchParams.set("state", areq.state);
      u.searchParams.set("iss", site.origin);
      return json({ redirect: u.toString() });
    }
    throw new HttpError(404, "not found");
  }

  // ---------- token endpoint ----------
  if (req.method === "POST" && path === "/token") {
    const text = await req.text();
    if (text.length > MAX_BODY) return oauthError("invalid_request", "request too large");
    const f = new URLSearchParams(text);
    const clientId = f.get("client_id") ?? "";
    const issue = async (g: Grant) => {
      const access = "t_" + newSecret();
      const refresh = "r_" + newSecret();
      await putExpiring(kv, `at:${sha(access)}`, g, now + TTL.access);
      await putExpiring(kv, `rt:${sha(refresh)}`, g, now + TTL.refresh);
      return json({ access_token: access, token_type: "Bearer", expires_in: TTL.access / 1000, refresh_token: refresh }, 200, CORS);
    };
    if (f.get("grant_type") === "authorization_code") {
      const code = await takeExpiring<AuthorizeRequest & { owner: string; epoch: number }>(kv, `code:${sha(f.get("code") ?? "")}`, now);
      if (!code) return oauthError("invalid_grant", "unknown, used or expired code");
      if (code.client_id !== clientId) return oauthError("invalid_grant", "the code was issued to another client");
      if (code.redirect_uri !== f.get("redirect_uri")) return oauthError("invalid_grant", "redirect_uri differs from the authorization request");
      const verifier = f.get("code_verifier") ?? "";
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || toBase64url(sha256(utf8(verifier))) !== code.code_challenge) return oauthError("invalid_grant", "PKCE check failed");
      const account = await kv.get<Account>(`acct:${code.owner}`);
      if (!account || account.epoch !== code.epoch) return oauthError("invalid_grant", "access was blocked by the owner");
      return issue({ owner: code.owner, client_id: clientId, epoch: account.epoch });
    }
    if (f.get("grant_type") === "refresh_token") {
      const g = await takeExpiring<Grant>(kv, `rt:${sha(f.get("refresh_token") ?? "")}`, now);
      if (!g || g.client_id !== clientId) return oauthError("invalid_grant", "unknown, used or expired refresh token");
      const account = await kv.get<Account>(`acct:${g.owner}`);
      if (!account || account.epoch !== g.epoch) return oauthError("invalid_grant", "access was blocked by the owner");
      return issue(g);
    }
    return oauthError("unsupported_grant_type", "authorization_code or refresh_token");
  }

  // ---------- the wallet's MCP tools, for the connected assistant ----------
  if (path === "/mcp") {
    const unauthorized = () =>
      new Response(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "sign in to your Symbolon wallet first" }, id: null }), {
        status: 401,
        headers: { ...CORS, "content-type": "application/json", "www-authenticate": `Bearer resource_metadata="${site.origin}/.well-known/oauth-protected-resource"` },
      });
    const token = /^Bearer ([A-Za-z0-9_-]{10,200})$/.exec(req.headers.get("authorization") ?? "")?.[1];
    const g = token ? await getExpiring<Grant>(kv, `at:${sha(token)}`, now) : undefined;
    const account = g ? await kv.get<Account>(`acct:${g.owner}`) : undefined;
    if (!g || !account || account.epoch !== g.epoch) return unauthorized();
    if (req.method !== "POST")
      return json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed: this server is stateless, use POST" }, id: null }, 405, { ...CORS, allow: "POST" });
    // Stateless: what the assistant can do (open a page for its user) is remembered from its initialize request.
    const capsKey = `caps:${g.owner}:${g.client_id}`;
    let message: unknown;
    try {
      message = JSON.parse(await req.clone().text());
    } catch {
      message = null;
    }
    const init = (Array.isArray(message) ? message : [message]).find((m) => m && typeof m === "object" && (m as { method?: unknown }).method === "initialize") as
      | { params?: { capabilities?: { elicitation?: { url?: unknown } } } }
      | undefined;
    if (init) await putExpiring(kv, capsKey, { url: !!init.params?.capabilities?.elicitation?.url }, now + TTL.refresh);
    const caps = await getExpiring<{ url: boolean }>(kv, capsKey, now);
    return lock.run(g.owner, async () => {
      const wallet = await openWallet(deps, g.owner, account);
      const server: McpServer = buildMcpServer(wallet, {
        hosted: hostedOwner(deps, site, g.owner, account, wallet, now, !!caps?.url),
        ...(deps.piazzaUrl ? { piazzaUrl: deps.piazzaUrl, fetchImpl: deps.piazzaFetch } : {}),
      });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      try {
        const res = await transport.handleRequest(req);
        const h = new Headers(res.headers);
        for (const [k, v] of Object.entries(CORS)) h.set(k, v);
        return new Response(res.body, { status: res.status, headers: h });
      } finally {
        void server.close();
      }
    });
  }

  // ---------- the owner's page ----------
  if (req.method === "GET" && (path === "/owner" || /^\/owner\/r\/[A-Za-z0-9_-]{43}$/.test(path)))
    return hostedPage({ view: "owner", origin: site.origin, request: path.startsWith("/owner/r/") ? path.slice("/owner/r/".length) : undefined });

  // A request to sign, opened from the link the agent gave: readable with the link, valid only with the owner's passkey.
  const reqMatch = /^\/owner\/api\/request\/([A-Za-z0-9_-]{43})$/.exec(path);
  if (reqMatch) {
    const id = reqMatch[1]!;
    const link = await getExpiring<Link>(kv, `link:${id}`, now);
    if (!link) throw new HttpError(404, "this request was already answered or has expired");
    const account = await kv.get<Account>(`acct:${link.owner}`);
    if (!account) throw new HttpError(404, "unknown owner");
    if (req.method === "GET") {
      if (link.kind === "mandate")
        return json({ kind: "mandate", body: link.body, challenge: toBase64url(passkeyChallenge(link.body)), credential_id: account.credentialId });
      return lock.run(link.owner, async () => {
        const wallet = await openWallet(deps, link.owner, account);
        const a = wallet.pendingApprovals().find((x) => x.clauses_root === link.root);
        if (!a) throw new HttpError(404, "this request was already answered or has expired");
        return json({ kind: "approval", ...a, challenge: toBase64url(passkeyChallenge(a.approval_body)), credential_id: account.credentialId });
      });
    }
    if (req.method === "POST") {
      sameOrigin(req, site);
      const body = await readJson(req);
      const signature = typeof body.signature === "string" ? body.signature : "";
      return lock.run(link.owner, async () => {
        const wallet = await openWallet(deps, link.owner, account);
        if (link.kind === "mandate") {
          if (link.body.agent !== wallet.agentKey) throw new HttpError(409, "this request was for an agent that was blocked");
          let m;
          try {
            m = signedMandate(link.body, signature);
          } catch (e) {
            throw new HttpError(401, (e as Error).message);
          }
          const check = await wallet.installMandate(m);
          await kv.delete(`link:${id}`);
          return json({ ok: true, installed: { scope: m.body.scope, maxAmount: m.body.maxAmount ?? null, validUntil: m.body.notAfter }, level: check.level });
        }
        await wallet.recordOwnerApproval(link.root, signature);
        await kv.delete(`link:${id}`);
        return json({ ok: true });
      });
    }
  }

  if (path.startsWith("/owner/api/")) {
    const token = /^Bearer (s_[A-Za-z0-9_-]{43})$/.exec(req.headers.get("authorization") ?? "")?.[1];
    const g = token ? await getExpiring<Grant>(kv, `sess:${sha(token)}`, now) : undefined;
    const account = g ? await kv.get<Account>(`acct:${g.owner}`) : undefined;
    if (!g || !account || account.epoch !== g.epoch) throw new HttpError(401, "sign in again");
    const owner = g.owner;
    if (req.method === "GET" && path === "/owner/api/state")
      return lock.run(owner, async () => {
        const wallet = await openWallet(deps, owner, account);
        const ids = (await kv.get<string[]>(`links:${owner}`)) ?? [];
        const requests: Array<{ id: string; kind: string }> = [];
        for (const id of ids) {
          const l = await getExpiring<Link>(kv, `link:${id}`, now);
          if (l) requests.push({ id, kind: l.kind });
        }
        if (requests.length !== ids.length) await kv.put(`links:${owner}`, requests.map((r) => r.id));
        return json({
          owner_key: account.publicKey,
          agent: wallet.agentKey,
          mandate: wallet.whoami().mandate,
          requests,
          approvals_waiting: wallet.pendingApprovals().filter((a) => !a.signed).length,
          commitments: wallet.commitments(),
        });
      });
    if (path === "/owner/api/block") {
      const wallet = await openWallet(deps, owner, account);
      const expected = (createdAt: string) =>
        revocationBody(account.publicKey, { target: { kind: "agent", key: wallet.agentKey }, reason: "blocked by its owner", createdAt });
      if (req.method === "GET") {
        const body = expected(new Date(now).toISOString());
        return json({ body, challenge: toBase64url(passkeyChallenge(body)), credential_id: account.credentialId });
      }
      if (req.method === "POST") {
        sameOrigin(req, site);
        const b = await readJson(req);
        const rb = b.body as RevocationBody | undefined;
        if (!rb || typeof rb.createdAt !== "string" || canonical(rb) !== canonical(expected(rb.createdAt)) || Math.abs(Date.parse(rb.createdAt) - now) > 10 * MIN)
          throw new HttpError(400, "this is not the block of your agent");
        let r;
        try {
          r = signedRevocation(rb, String(b.signature ?? ""));
        } catch (e) {
          throw new HttpError(401, (e as Error).message);
        }
        const sealed = await deps.register.revoke(r);
        // Every connection and session ends; the next connection gets a new agent, with no mandate.
        await kv.put(`acct:${owner}`, { ...account, epoch: account.epoch + 1, agentGen: account.agentGen + 1 } satisfies Account);
        return json({ ok: true, revoked: { id: sealed.id, at: sealed.time } });
      }
    }
  }

  if (req.method === "GET" && path === "/")
    return json({
      name: "Symbolon wallet",
      about: "The notary wallet of Symbolon City, hosted for its owner: add it to your assistant as a connector (MCP, sign in with a passkey).",
      mcp: mcpUrl,
      owner_page: site.origin + "/owner",
      version: HOSTED_VERSION,
      source: "https://github.com/symbolon-city/symbolon",
    }, 200, CORS);

  return json({ error: "not found" }, 404, CORS);
}

/** Refuses a browser request sent by another site (the passkey already binds the site; this closes the rest). */
function sameOrigin(req: Request, site: Site) {
  const o = req.headers.get("origin");
  if (o !== null && o !== site.origin) throw new HttpError(403, "cross-site request refused");
}

function openWallet(deps: HostedDeps, owner: string, account: Account) {
  return Wallet.open(new HostedWalletStorage(deps.kv, deps.secret, `${owner}:${account.agentGen}`), deps.register, {
    ...(deps.ownerResolver ? { ownerResolver: deps.ownerResolver } : {}),
    ...(deps.bitcoin ? { bitcoin: deps.bitcoin } : {}),
    ...(deps.charter ? { charter: deps.charter } : {}),
    ...(deps.now ? { now: deps.now } : {}),
  });
}

function hostedOwner(deps: HostedDeps, site: Site, owner: string, account: Account, wallet: Wallet, now: number, urlElicitation: boolean): HostedOwner {
  const pageOf = (id: string) => `${site.origin}/owner/r/${id}`;
  const addLink = async (link: Link, expiresAt: number) => {
    const id = newSecret();
    await putExpiring(deps.kv, `link:${id}`, link, expiresAt);
    const ids = (await deps.kv.get<string[]>(`links:${owner}`)) ?? [];
    await deps.kv.put(`links:${owner}`, [...ids, id].slice(-MAX_LINKS));
    return id;
  };
  /** The newest link still waiting, of this kind (and for this agreement). */
  const findLink = async (match: (l: Link) => boolean) => {
    const ids = (await deps.kv.get<string[]>(`links:${owner}`)) ?? [];
    for (const id of [...ids].reverse()) {
      const l = await getExpiring<Link>(deps.kv, `link:${id}`, now);
      if (l && match(l)) return id;
    }
    return null;
  };
  return {
    ownerKey: account.publicKey,
    urlElicitation,
    async approvalLink(root, validUntil) {
      const found = await findLink((l) => l.kind === "approval" && l.root === root);
      return pageOf(found ?? (await addLink({ owner, kind: "approval", root }, Math.min(Date.parse(validUntil), now + TTL.mandateRequest))));
    },
    async pendingMandateLink() {
      const found = await findLink((l) => l.kind === "mandate" && l.body.agent === wallet.agentKey);
      return found ? pageOf(found) : null;
    },
    async askMandate(p) {
      const from = now - MIN;
      const body = mandateBody(account.publicKey, {
        agent: wallet.agentKey,
        scope: p.scope,
        ...(p.maxAmount ? { maxAmount: { value: String((p.maxAmount as Amount).value), currency: String((p.maxAmount as Amount).currency) } } : {}),
        notBefore: new Date(from).toISOString(),
        notAfter: new Date(from + p.days * DAY).toISOString(),
        charter: deps.charter ?? "accord-charter/0.1",
      });
      const page = pageOf(await addLink({ owner, kind: "mandate", body }, now + TTL.mandateRequest));
      const limit = body.maxAmount ? `up to ${body.maxAmount.value} ${body.maxAmount.currency} per agreement` : "with no amount limit";
      return {
        owner_page: page,
        for_the_owner: {
          text: `Your agent asks you to sign this mandate: "${body.scope}", ${limit}, until ${body.notAfter.slice(0, 10)}. Open the link and confirm with Face ID if it is what you want.`,
          scope: body.scope,
          max_amount: body.maxAmount ?? null,
          valid_until: body.notAfter,
        },
      };
    },
  };
}
