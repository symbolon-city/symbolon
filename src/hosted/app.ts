// The hosted wallet ("the connector"): the agent's wallet kept on a server for its owner, so that a
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
import { hmac } from "@noble/hashes/hmac";
import type { BlockProvider } from "../anchor.js";
import { canonical } from "../canonical.js";
import { equalBytes, fromBase64url, randomBytes, toBase64url, utf8, toHex } from "../bytes.js";
import { clientKeyOfRequest } from "../client-key.js";
import { passkeyChallenge, type PublicKey } from "../keys.js";
import { mandateBody, mandateId, ownerName, signedMandate, verifyMandateSignature, type Amount, type Mandate, type MandateBody } from "../mandate.js";
import { revocationBody, signedRevocation, type RevocationBody } from "../revocation.js";
import type { OwnerResolver } from "../wellknown.js";
import type { RegisterClient } from "../agent/client.js";
import { buildMcpServer, type HostedOwner } from "../agent/mcp.js";
import { Wallet } from "../agent/wallet.js";
import { HostedWalletStorage, KeyedLock, getExpiring, getSealed, putExpiring, putSealed, sweepExpired, takeExpiring, type KeyValue } from "./store.js";
import { loginProblem, registrationProblem, type LoginChallenge, type NewPasskey, type Site } from "./webauthn.js";
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
  /** A registered assistant that never completes a connection is forgotten after this (each connection extends it). */
  client: 30 * DAY,
  /** Between creating a passkey and proving it with a first signature. */
  signup: 5 * MIN,
} as const;
const MAX_BODY = 64 * 1024;
/** The largest MCP request read (a tool call is a few KB; the SDK's own limit, 4 MB, applies only after reading). */
export const MAX_MCP_BODY = 1024 * 1024;
const MAX_LINKS = 50;
/** Connected assistants kept per owner: connecting one more disconnects the oldest. */
const MAX_GRANTS = 20;
/** Assistants that one client (IP address, IPv6 /64) may register per day. */
export const MAX_REGISTRATIONS_PER_DAY = 30;
/** Mandates replaced on the page, remembered (to offer their public revocation) while still within their dates. */
const MAX_PREVIOUS_MANDATES = 20;
/** Return addresses of well-known assistants, matched exactly: the consent page warns for any other web address. */
export const KNOWN_RETURN_HOSTS: readonly string[] = ["claude.ai", "claude.com", "chatgpt.com"];
/** The prefixes of records that end (putExpiring): collected by sweepHosted. */
const EXPIRING_PREFIXES = ["chal:", "signup:", "areq-used:", "code:", "at:", "rt:", "rtused:", "grant:", "sess:", "link:", "caps:", "client:", "regs:"] as const;
/** Agents blocked before the current one, shown on the owner's page and in the export. */
const MAX_PREVIOUS_AGENTS = 10;

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
  /** Return hosts the consent page shows without a warning (default KNOWN_RETURN_HOSTS); localhost never warns. */
  knownReturnHosts?: readonly string[];
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
  /** The connection (one assistant, one sign-in) the token belongs to: the owner can end it on the page. Not for page sessions. */
  gid?: string;
}

/** One connected assistant, as the owner's page lists it. */
interface GrantRecord {
  gid: string;
  client_id: string;
  client_name: string;
  return_host: string;
  connected_at: string;
  refreshed_at?: string;
  /** Fingerprints of the current access and refresh tokens (deleted when the owner disconnects it). */
  at?: string;
  rt?: string;
}

/** Mandates the owner signed on this page for one agent: only the current one may be installed. */
interface MandateRecord {
  current: string | null;
  previous: Array<{ id: string; scope: string; maxAmount?: Amount; notAfter: string; revoked?: boolean }>;
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

/** Reads a request body, refusing it (413) as soon as it is longer than max bytes: never the whole of a huge body. */
export async function readBounded(req: Request, max: number): Promise<string> {
  const declared = Number(req.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > max) throw new HttpError(413, "request too large");
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      void reader.cancel().catch(() => undefined);
      throw new HttpError(413, "request too large");
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
  const text = await readBounded(req, MAX_BODY);
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

/**
 * The name an assistant gives itself, made safe to show: no invisible or direction-changing characters (Unicode
 * format and control characters, fillers that render blank), no stacks of combining marks, spaces collapsed.
 * It stays self-declared: the consent page says so and puts the return address first.
 */
export function cleanClientName(v: unknown): string {
  if (typeof v !== "string") return "";
  return v
    .normalize("NFKC")
    .replace(/[\t\n\v\f\r\p{Zs}]+/gu, " ")
    .replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\u115F\u1160\u3164\uFFA0\u2800\u034F\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu, "")
    .replace(/(\p{M})\p{M}+/gu, "$1")
    .replace(/ {2,}/g, " ")
    .trim()
    .slice(0, 60);
}

/** Where the consent page says the owner will be sent back, and whether that address deserves a warning. */
export function returnAddress(uri: string, known: readonly string[] = KNOWN_RETURN_HOSTS): { host: string; kind: "device" | "known" | "app" | "web" } {
  const u = new URL(uri);
  if (u.protocol === "http:") return { host: u.host, kind: "device" };
  if (u.protocol === "https:") return { host: u.host, kind: known.includes(u.hostname.toLowerCase()) && !u.port ? "known" : "web" };
  return { host: u.protocol + (u.host ? "//" + u.host : ""), kind: "app" };
}

/** Deletes the records whose end has passed (challenges, codes, tokens, links, unused assistants...): run it regularly. */
export function sweepHosted(kv: KeyValue, now: number, o: { budget?: number; from?: { prefix: string; after?: string } } = {}) {
  return sweepExpired(kv, now, EXPIRING_PREFIXES, o);
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
    // Anyone may register (that is how MCP clients connect), but not without end: a few per day per client.
    const regsKey = `regs:${clientKeyOfRequest(req)}:${Math.floor(now / DAY)}`;
    const regs = (await getExpiring<number>(kv, regsKey, now)) ?? 0;
    if (regs >= MAX_REGISTRATIONS_PER_DAY) return oauthError("invalid_client_metadata", "too many assistants registered from here today: try again tomorrow", 429);
    await putExpiring(kv, regsKey, regs + 1, (Math.floor(now / DAY) + 1) * DAY);
    const name = cleanClientName(body.client_name);
    const client: Client = { client_id: "c_" + newSecret(), client_name: name || "An assistant", redirect_uris: uris as string[], createdAt: new Date(now).toISOString() };
    await putExpiring(kv, `client:${client.client_id}`, client, now + TTL.client);
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
  // Nothing is stored here: the request travels in a ticket signed by the server (the page's "request"), and is
  // remembered only after the owner's passkey, so that anonymous page loads cannot fill the storage.
  if (req.method === "GET" && path === "/authorize") {
    const q = url.searchParams;
    const client = await getExpiring<Client>(kv, `client:${q.get("client_id") ?? ""}`, now);
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
    const ticket = makeTicket(deps.secret, { client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, ...(state ? { state } : {}) }, now + TTL.authorizeRequest);
    const ret = returnAddress(redirect, deps.knownReturnHosts);
    return hostedPage({ view: "authorize", origin: site.origin, request: ticket, client: client.client_name, redirectHost: ret.host, returnKind: ret.kind });
  }

  // ---------- passkeys: challenge, sign in, first passkey ----------
  if (req.method === "POST" && path.startsWith("/auth/")) {
    sameOrigin(req, site);
    const body = await readJson(req);
    if (path === "/auth/challenge") {
      const purpose = body.purpose;
      if (typeof purpose !== "string" || !(purpose === "owner" || (purpose.startsWith("authorize:") && openTicket(deps.secret, purpose.slice("authorize:".length), now))))
        throw new HttpError(400, "invalid purpose (or the connection request expired: start again from your assistant)");
      const challenge: LoginChallenge = { type: "symbolon-hosted/login", origin: site.origin, purpose, nonce: newSecret() };
      await putExpiring(kv, `chal:${challenge.nonce}`, challenge, now + TTL.challenge);
      return json({ nonce: challenge.nonce, challenge: toBase64url(passkeyChallenge(challenge)), rpId: site.rpId });
    }
    /** After the passkey: a session for the owner's page, or the code for the assistant that asked to connect. */
    const finish = async (owner: string, purpose: string) => {
      const account = (await kv.get<Account>(`acct:${owner}`))!;
      if (purpose === "owner") {
        const session = "s_" + newSecret();
        await putExpiring(kv, `sess:${sha(session)}`, { owner, client_id: "", epoch: account.epoch } satisfies Grant, now + TTL.session);
        return json({ session, expires_in: TTL.session / 1000 });
      }
      const ticket = purpose.slice("authorize:".length);
      const areq = openTicket(deps.secret, ticket, now);
      if (!areq) throw new HttpError(400, "the connection request expired: start again from your assistant");
      // A request is answered once.
      const used = `areq-used:${sha(ticket)}`;
      if (await getExpiring(kv, used, now)) throw new HttpError(400, "this connection request was already used: start again from your assistant");
      await putExpiring(kv, used, true, areq.exp);
      if (!(await getExpiring<Client>(kv, `client:${areq.client_id}`, now))) throw new HttpError(400, "unknown assistant: start again from your assistant");
      const code = "a_" + newSecret();
      const { exp: _exp, n: _n, ...request } = areq;
      await putExpiring(kv, `code:${sha(code)}`, { ...request, owner, epoch: account.epoch }, now + TTL.code);
      const u = new URL(areq.redirect_uri);
      u.searchParams.set("code", code);
      if (areq.state) u.searchParams.set("state", areq.state);
      u.searchParams.set("iss", site.origin);
      return json({ redirect: u.toString() });
    };
    if (path === "/auth/signin") {
      const challenge = typeof body.nonce === "string" ? await takeExpiring<LoginChallenge>(kv, `chal:${body.nonce}`, now) : undefined;
      if (!challenge) throw new HttpError(400, "the sign-in expired: try again");
      if (typeof body.credentialId !== "string" || body.credentialId.length > 1023) throw new HttpError(400, "invalid credential");
      const found = await kv.get<string>(`cred:${body.credentialId}`);
      const account = found ? await kv.get<Account>(`acct:${found}`) : undefined;
      if (!found || !account) throw new HttpError(404, "this passkey has no Symbolon wallet here: create one");
      const problem = loginProblem(challenge, String(body.signature ?? ""), account.publicKey, site);
      if (problem) throw new HttpError(401, problem);
      return finish(found, challenge.purpose);
    }
    // A new passkey: first its registration, then a signature made with it over a new challenge, which proves the
    // device holds it. Only then the account exists (no account for a public key someone merely copied).
    if (path === "/auth/signup") {
      const challenge = typeof body.nonce === "string" ? await takeExpiring<LoginChallenge>(kv, `chal:${body.nonce}`, now) : undefined;
      if (!challenge) throw new HttpError(400, "the sign-in expired: try again");
      const r = registrationProblem(challenge, body as never, site);
      if ("problem" in r) throw new HttpError(400, r.problem);
      if (await kv.get(`cred:${r.passkey.credentialId}`)) throw new HttpError(409, "this passkey is already registered: sign in");
      if (await kv.get(`acct:${ownerIdOf(r.passkey.publicKey)}`)) throw new HttpError(409, "this key is already registered: sign in");
      const confirm: LoginChallenge = { type: "symbolon-hosted/login", origin: site.origin, purpose: challenge.purpose, nonce: newSecret() };
      await putExpiring(kv, `signup:${confirm.nonce}`, { challenge: confirm, passkey: r.passkey }, now + TTL.signup);
      return json({ confirm: { nonce: confirm.nonce, challenge: toBase64url(passkeyChallenge(confirm)), rpId: site.rpId, credential_id: r.passkey.credentialId } });
    }
    if (path === "/auth/signup/confirm") {
      const pending = typeof body.nonce === "string" ? await takeExpiring<{ challenge: LoginChallenge; passkey: NewPasskey }>(kv, `signup:${body.nonce}`, now) : undefined;
      if (!pending) throw new HttpError(400, "the sign-up expired: try again");
      const problem = loginProblem(pending.challenge, String(body.signature ?? ""), pending.passkey.publicKey, site);
      if (problem) throw new HttpError(401, `the new passkey did not sign: ${problem}`);
      const owner = ownerIdOf(pending.passkey.publicKey);
      if ((await kv.get(`cred:${pending.passkey.credentialId}`)) || (await kv.get(`acct:${owner}`))) throw new HttpError(409, "this passkey is already registered: sign in");
      const account: Account = { publicKey: pending.passkey.publicKey, credentialId: pending.passkey.credentialId, createdAt: new Date(now).toISOString(), epoch: 0, agentGen: 0 };
      await kv.put(`acct:${owner}`, account);
      await kv.put(`cred:${pending.passkey.credentialId}`, owner);
      return finish(owner, pending.challenge.purpose);
    }
    throw new HttpError(404, "not found");
  }

  // ---------- token endpoint ----------
  if (req.method === "POST" && path === "/token") {
    let text: string;
    try {
      text = await readBounded(req, MAX_BODY);
    } catch {
      return oauthError("invalid_request", "request too large");
    }
    const f = new URLSearchParams(text);
    const clientId = f.get("client_id") ?? "";
    const issue = async (g: Grant & { gid: string }) => {
      const rec = await getExpiring<GrantRecord>(kv, grantKey(g.owner, g.gid), now);
      if (!rec) return oauthError("invalid_grant", "this assistant was disconnected by the owner");
      const access = "t_" + newSecret();
      const refresh = "r_" + newSecret();
      await putExpiring(kv, `at:${sha(access)}`, g, now + TTL.access);
      await putExpiring(kv, `rt:${sha(refresh)}`, g, now + TTL.refresh);
      if (rec.at) await kv.delete(`at:${rec.at}`);
      await putExpiring(kv, grantKey(g.owner, g.gid), { ...rec, at: sha(access), rt: sha(refresh), refreshed_at: new Date(now).toISOString() } satisfies GrantRecord, now + TTL.refresh);
      // An assistant in use is kept; one never connected is forgotten after TTL.client.
      const client = await getExpiring<Client>(kv, `client:${g.client_id}`, now);
      if (client) await putExpiring(kv, `client:${g.client_id}`, client, now + TTL.refresh);
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
      const client = await getExpiring<Client>(kv, `client:${clientId}`, now);
      if (!client) return oauthError("invalid_grant", "unknown client");
      const gid = "g_" + newSecret();
      await putExpiring(
        kv,
        grantKey(code.owner, gid),
        { gid, client_id: clientId, client_name: client.client_name, return_host: returnAddress(code.redirect_uri).host, connected_at: new Date(now).toISOString() } satisfies GrantRecord,
        now + TTL.refresh,
      );
      const ids = [...((await kv.get<string[]>(`grants:${code.owner}`)) ?? []), gid];
      for (const old of ids.slice(0, Math.max(0, ids.length - MAX_GRANTS))) await endGrant(kv, code.owner, old);
      await kv.put(`grants:${code.owner}`, ids.slice(-MAX_GRANTS));
      return issue({ owner: code.owner, client_id: clientId, epoch: account.epoch, gid });
    }
    if (f.get("grant_type") === "refresh_token") {
      const h = sha(f.get("refresh_token") ?? "");
      const g = await takeExpiring<Grant>(kv, `rt:${h}`, now);
      if (!g) {
        // A refresh token used twice was copied (OAuth 2.1, public clients): the whole connection ends.
        const reused = await getExpiring<{ owner: string; gid: string }>(kv, `rtused:${h}`, now);
        if (reused) await endGrant(kv, reused.owner, reused.gid);
        return oauthError("invalid_grant", "unknown, used or expired refresh token");
      }
      if (g.gid) await putExpiring(kv, `rtused:${h}`, { owner: g.owner, gid: g.gid }, now + TTL.refresh);
      if (g.client_id !== clientId || !g.gid) return oauthError("invalid_grant", "unknown, used or expired refresh token");
      const account = await kv.get<Account>(`acct:${g.owner}`);
      if (!account || account.epoch !== g.epoch) return oauthError("invalid_grant", "access was blocked by the owner");
      return issue({ ...g, gid: g.gid });
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
    if (!g || !account || account.epoch !== g.epoch || !g.gid || !(await getExpiring<GrantRecord>(kv, grantKey(g.owner, g.gid), now))) return unauthorized();
    if (req.method !== "POST")
      return json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed: this server is stateless, use POST" }, id: null }, 405, { ...CORS, allow: "POST" });
    // Read at most MAX_MCP_BODY, once; the SDK gets the same bytes (never a second, unbounded read).
    let text: string;
    try {
      text = await readBounded(req, MAX_MCP_BODY);
    } catch {
      return json({ jsonrpc: "2.0", error: { code: -32000, message: `request too large (at most ${MAX_MCP_BODY} bytes)` }, id: null }, 413, CORS);
    }
    let message: unknown;
    try {
      message = JSON.parse(text);
    } catch {
      message = undefined;
    }
    // Stateless: what the assistant can do (open a page for its user) is remembered from its initialize request.
    const capsKey = `caps:${g.owner}:${g.client_id}`;
    const init = (Array.isArray(message) ? message : [message]).find((m) => m && typeof m === "object" && (m as { method?: unknown }).method === "initialize") as
      | { params?: { capabilities?: { elicitation?: { url?: unknown } } } }
      | undefined;
    if (init) await putExpiring(kv, capsKey, { url: !!init.params?.capabilities?.elicitation?.url }, now + TTL.refresh);
    const caps = await getExpiring<{ url: boolean }>(kv, capsKey, now);
    return lock.run(g.owner, async () => {
      const wallet = await openWallet(deps, g.owner, account);
      // The assistant may install only the mandate the owner signed last on the page: never an older one it kept.
      const signedHere = await getSealed<MandateRecord>(kv, deps.secret, mandatesKey(g.owner, account.agentGen));
      const install = wallet.installMandate.bind(wallet);
      wallet.installMandate = async (m: Mandate) => {
        let id: string | null = null;
        try {
          id = mandateId(m);
        } catch {
          /* malformed: refused below */
        }
        if (!signedHere?.current || id !== signedHere.current)
          throw new Error(
            "on a hosted wallet the only mandate that can be installed is the one your owner signed last on the wallet's page (older, replaced or revoked mandates are refused): ask with symbolon_ask_owner_for_mandate",
          );
        return install(m);
      };
      const server: McpServer = buildMcpServer(wallet, {
        hosted: hostedOwner(deps, site, g.owner, account, wallet, now, !!caps?.url),
        ...(deps.piazzaUrl ? { piazzaUrl: deps.piazzaUrl, fetchImpl: deps.piazzaFetch } : {}),
      });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(transport);
      try {
        const again = new Request(req.url, { method: "POST", headers: req.headers, body: text });
        const res = await transport.handleRequest(again, message !== undefined ? { parsedBody: message } : undefined);
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
        // How sure we are of who the other side is: checked here, from its mandate (never taken from the assistant).
        const theirs = wallet.exportForOwner().approvals[link.root]?.counterparty as Mandate | undefined;
        const fromWallet = (a as { ownerLevel?: unknown }).ownerLevel;
        const level = theirs ? await levelOf(deps, theirs, now) : typeof fromWallet === "string" ? fromWallet : "unknown";
        return json({
          kind: "approval",
          ...a,
          counterparty: { ...a.counterparty, level },
          challenge: toBase64url(passkeyChallenge(a.approval_body)),
          credential_id: account.credentialId,
        });
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
          const before = wallet.exportForOwner().mandate as Mandate | null;
          const check = await wallet.installMandate(m);
          await kv.delete(`link:${id}`);
          // The new mandate replaces the previous one: from now on the wallet refuses the old one (an assistant that
          // kept a copy cannot put it back). Publicly, the old one ends only with the owner's revocation: offered here.
          const key = mandatesKey(link.owner, account.agentGen);
          const rec: MandateRecord = (await getSealed<MandateRecord>(kv, deps.secret, key)) ?? { current: null, previous: [] };
          const newId = mandateId(m);
          const replaced = before && mandateId(before) !== newId ? before : null;
          if (replaced && !rec.previous.some((p) => p.id === mandateId(replaced)))
            rec.previous.push({ id: mandateId(replaced), scope: replaced.body.scope, ...(replaced.body.maxAmount ? { maxAmount: replaced.body.maxAmount } : {}), notAfter: replaced.body.notAfter });
          rec.current = newId;
          rec.previous = rec.previous.filter((p) => p.id !== newId && Date.parse(p.notAfter) > now).slice(-MAX_PREVIOUS_MANDATES);
          await putSealed(kv, deps.secret, key, rec);
          const revoke = replaced ? mandateRevocation(account, mandateId(replaced), now) : null;
          return json({
            ok: true,
            installed: { scope: m.body.scope, maxAmount: m.body.maxAmount ?? null, validUntil: m.body.notAfter },
            level: check.level,
            ...(replaced && revoke
              ? {
                  replaced: {
                    scope: replaced.body.scope,
                    max_amount: replaced.body.maxAmount ?? null,
                    valid_until: replaced.body.notAfter,
                    revoke: { body: revoke, challenge: toBase64url(passkeyChallenge(revoke)), credential_id: account.credentialId },
                  },
                }
              : {}),
          });
        }
        await wallet.recordOwnerApproval(link.root, signature);
        await kv.delete(`link:${id}`);
        return json({ ok: true });
      });
    }
  }

  // The public revocation of one mandate the owner signed here (the current one, or one it replaced). Valid only
  // with the owner's passkey signature over the exact body the server prepared: that signature is the authorization.
  if (req.method === "POST" && path === "/owner/api/revoke-mandate") {
    sameOrigin(req, site);
    const b = await readJson(req);
    const rb = b.body as RevocationBody | undefined;
    if (!rb || typeof rb !== "object" || typeof rb.by !== "string" || rb.target?.kind !== "mandate" || typeof rb.target.id !== "string" || typeof rb.createdAt !== "string")
      throw new HttpError(400, "this is not the revocation of one of your mandates");
    const owner = ownerIdOf(rb.by);
    const account = await kv.get<Account>(`acct:${owner}`);
    if (!account) throw new HttpError(404, "unknown owner");
    const targetId = rb.target.id;
    if (canonical(rb) !== canonical(mandateRevocation(account, targetId, Date.parse(rb.createdAt))) || Math.abs(Date.parse(rb.createdAt) - now) > 10 * MIN)
      throw new HttpError(400, "this is not the revocation of one of your mandates");
    let r;
    try {
      r = signedRevocation(rb, String(b.signature ?? ""));
    } catch (e) {
      throw new HttpError(401, (e as Error).message);
    }
    return lock.run(owner, async () => {
      const key = mandatesKey(owner, account.agentGen);
      const rec = await getSealed<MandateRecord>(kv, deps.secret, key);
      if (!rec || (rec.current !== targetId && !rec.previous.some((p) => p.id === targetId))) throw new HttpError(404, "not a mandate of your current agent");
      const sealed = await deps.register.revoke(r);
      if (rec.current === targetId) rec.current = null;
      for (const p of rec.previous) if (p.id === targetId) p.revoked = true;
      await putSealed(kv, deps.secret, key, rec);
      return json({ ok: true, revoked: { id: sealed.id, at: sealed.time } });
    });
  }

  if (path.startsWith("/owner/api/")) {
    const token = /^Bearer (s_[A-Za-z0-9_-]{43})$/.exec(req.headers.get("authorization") ?? "")?.[1];
    const g = token ? await getExpiring<Grant>(kv, `sess:${sha(token)}`, now) : undefined;
    const account = g ? await kv.get<Account>(`acct:${g.owner}`) : undefined;
    if (!g || !account || account.epoch !== g.epoch) throw new HttpError(401, "sign in again");
    const owner = g.owner;
    const previous = async () => {
      const out = [];
      for (let gen = Math.max(0, account.agentGen - MAX_PREVIOUS_AGENTS); gen < account.agentGen; gen++) {
        const stored = await deps.kv.get(`wallet:${owner}:${gen}`);
        if (stored) out.push({ gen, wallet: await openWallet(deps, owner, account, gen) });
      }
      return out;
    };
    const proofMatch = /^\/owner\/api\/proof\/(\d{1,4})\/([0-9a-f]{64})$/.exec(path);
    if (req.method === "GET" && proofMatch) {
      const gen = Number(proofMatch[1]);
      if (gen > account.agentGen) throw new HttpError(404, "unknown agent");
      return lock.run(owner, async () => {
        const wallet = await openWallet(deps, owner, account, gen);
        const r = wallet.exportForOwner().records.find((x) => x.entry === proofMatch[2]);
        if (!r) throw new HttpError(404, "unknown record");
        // For the owner: every clause revealed. To show a third party only some, the agent makes a narrower proof.
        return json(await wallet.createProof(r.entry, r.opened.clauses.map((c) => c.name)), 200, { "content-disposition": `attachment; filename="symbolon-proof-${r.entry.slice(0, 12)}.json"` });
      });
    }
    if (req.method === "GET" && path === "/owner/api/export")
      return lock.run(owner, async () => {
        const agents = [...(await previous()).map((p) => ({ gen: p.gen, ...p.wallet.exportForOwner() }))];
        agents.push({ gen: account.agentGen, ...(await openWallet(deps, owner, account)).exportForOwner() });
        return json(
          { type: "symbolon/owner-export-all", v: 1, owner_key: account.publicKey, exported_at: new Date(now).toISOString(), from: site.origin, agents },
          200,
          { "content-disposition": `attachment; filename="symbolon-wallet-export.json"` },
        );
      });
    if (req.method === "GET" && path === "/owner/api/state")
      return lock.run(owner, async () => {
        const wallet = await openWallet(deps, owner, account);
        const exported = wallet.exportForOwner();
        const mine = exported.mandate;
        let revoked: unknown = null;
        if (mine) revoked = (await wallet.checkCounterparty(mine).catch(() => null))?.revoked ?? null;
        // Who the other side is, with how sure we are (checked here from their mandate): "domain" (its website publishes
        // the key), "key" (no website: known only by its key) or "unverified" (claims a website that does not confirm it).
        const level = (m: Mandate | undefined) => (m ? levelOf(deps, m, now) : Promise.resolve("unknown"));
        const history = async (w: Wallet) => {
          const out = [];
          for (const r of w.exportForOwner().records.filter((x) => x.receipt)) {
            const parties = [];
            for (const p of r.record.body.parties.filter((p) => p.agent !== w.agentKey)) {
              const m = r.mandates.find((x) => x.body.agent === p.agent);
              parties.push({ owner: m ? ownerName(m.body.owner) : "unknown", level: await level(m) });
            }
            out.push({ entry: r.entry, kind: r.kind, sealed_at: r.receipt!.head.time, with: parties.map((p) => p.owner), parties, closed: r.closed ?? null });
          }
          return out.sort((a, b) => b.sealed_at.localeCompare(a.sealed_at));
        };
        // The commitments, each other side with its identity level.
        type Party = { agent: string; owner: string; level?: string };
        const commitments = wallet.commitments() as ReturnType<Wallet["commitments"]> & Record<string, unknown>;
        const withLevels = async (list: Party[] | undefined, mandates: Mandate[] | undefined) => {
          for (const p of list ?? []) p.level = await level(mandates?.find((x) => x.body.agent === p.agent));
        };
        for (const c of commitments.open) await withLevels(c.with as Party[], exported.records.find((r) => r.entry === c.entry)?.mandates);
        for (const c of commitments.waiting)
          await withLevels(c.to as Party[], (exported.offers as Record<string, { mandates?: Mandate[] }>)[c.offer]?.mandates);
        for (const c of (commitments.waiting_for_owner ?? []) as Array<{ clauses_root: string; with: Party[] }>)
          await withLevels(c.with, [exported.approvals[c.clauses_root]?.counterparty as Mandate].filter(Boolean));
        for (const c of commitments.closed) await withLevels(c.with as Party[], exported.records.find((r) => r.entry === c.entry)?.mandates);
        const ids = (await kv.get<string[]>(`links:${owner}`)) ?? [];
        const requests: Array<{ id: string; kind: string }> = [];
        for (const id of ids) {
          const l = await getExpiring<Link>(kv, `link:${id}`, now);
          if (l) requests.push({ id, kind: l.kind });
        }
        if (requests.length !== ids.length) await kv.put(`links:${owner}`, requests.map((r) => r.id));
        const signedHere = await getSealed<MandateRecord>(kv, deps.secret, mandatesKey(owner, account.agentGen));
        return json({
          owner_key: account.publicKey,
          agent: wallet.agentKey,
          mandate: wallet.whoami().mandate,
          mandate_id: mine ? mandateId(mine) : null,
          /** The current mandate can be revoked from the page (it was signed here and is not revoked yet). */
          mandate_revocable: !!(mine && signedHere?.current === mandateId(mine) && !revoked),
          replaced_mandates: (signedHere?.previous ?? [])
            .filter((p) => !p.revoked && Date.parse(p.notAfter) > now)
            .map((p) => ({ id: p.id, scope: p.scope, max_amount: p.maxAmount ?? null, valid_until: p.notAfter })),
          requests,
          approvals_waiting: wallet.pendingApprovals().filter((a) => !a.signed).length,
          mandate_revoked: revoked,
          agent_gen: account.agentGen,
          commitments,
          history: await history(wallet),
          assistants: await grantsOf(kv, owner, now),
          previous_agents: await Promise.all(
            (await previous()).map(async (p) => ({ gen: p.gen, agent: p.wallet.agentKey, mandate: p.wallet.whoami().mandate, history: await history(p.wallet) })),
          ),
        });
      });
    // Disconnect one assistant: its tokens are deleted and it must ask to connect again.
    if (req.method === "POST" && path === "/owner/api/disconnect") {
      sameOrigin(req, site);
      const b = await readJson(req);
      if (typeof b.id !== "string" || !/^g_[A-Za-z0-9_-]{43}$/.test(b.id)) throw new HttpError(400, "unknown assistant");
      if (!(await getExpiring<GrantRecord>(kv, grantKey(owner, b.id), now))) throw new HttpError(404, "unknown assistant");
      await endGrant(kv, owner, b.id);
      return json({ ok: true });
    }
    if (req.method === "GET" && path === "/owner/api/revoke-mandate")
      return lock.run(owner, async () => {
        const id = url.searchParams.get("id") ?? "";
        const rec = await getSealed<MandateRecord>(kv, deps.secret, mandatesKey(owner, account.agentGen));
        if (!rec || !/^[0-9a-f]{64}$/.test(id) || (rec.current !== id && !rec.previous.some((p) => p.id === id && !p.revoked)))
          throw new HttpError(404, "not a mandate of your current agent");
        const body = mandateRevocation(account, id, now);
        return json({ body, challenge: toBase64url(passkeyChallenge(body)), credential_id: account.credentialId });
      });
    if (path === "/owner/api/block")
      // Inside the owner's lock: the wallet opened here (and the agent key it may create) is the one every other call sees.
      return lock.run(owner, async () => {
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
          const fresh = (await kv.get<Account>(`acct:${owner}`)) ?? account;
          await kv.put(`acct:${owner}`, { ...fresh, epoch: fresh.epoch + 1, agentGen: fresh.agentGen + 1 } satisfies Account);
          for (const gid of (await kv.get<string[]>(`grants:${owner}`)) ?? []) await endGrant(kv, owner, gid);
          return json({ ok: true, revoked: { id: sealed.id, at: sealed.time } });
        }
        throw new HttpError(405, "method not allowed");
      });
  }

  if (req.method === "GET" && path === "/")
    return json({
      name: "Symbolon wallet",
      about: "The agent wallet of Symbolon City, hosted for its owner: add it to your assistant as a connector (MCP, sign in with a passkey).",
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

// ---------- the connection request, carried by the page instead of stored ----------

type Ticket = AuthorizeRequest & { exp: number; n: string };
const ticketKey = (secret: Uint8Array) => hmac(sha256, secret, utf8("symbolon-hosted/authorize-ticket/1"));

function makeTicket(secret: Uint8Array, areq: AuthorizeRequest, exp: number): string {
  // n: each page load is its own request (answered once), even for the same parameters.
  const payload = toBase64url(utf8(JSON.stringify({ ...areq, exp, n: toBase64url(randomBytes(9)) } satisfies Ticket)));
  return payload + "." + toBase64url(hmac(sha256, ticketKey(secret), utf8(payload)));
}

/** The connection request in a ticket made by makeTicket, if it is genuine and not expired. */
function openTicket(secret: Uint8Array, ticket: string, now: number): Ticket | undefined {
  const m = /^([A-Za-z0-9_-]{20,3000})\.([A-Za-z0-9_-]{43})$/.exec(ticket);
  if (!m) return undefined;
  try {
    if (!equalBytes(fromBase64url(m[2]!), hmac(sha256, ticketKey(secret), utf8(m[1]!)))) return undefined;
    const t = JSON.parse(new TextDecoder().decode(fromBase64url(m[1]!))) as Ticket;
    return typeof t.exp === "number" && t.exp > now ? t : undefined;
  } catch {
    return undefined;
  }
}

// ---------- connected assistants ----------

const grantKey = (owner: string, gid: string) => `grant:${owner}:${gid}`;

/** Ends one connection: its tokens are deleted, its record and its place in the owner's list too. */
async function endGrant(kv: KeyValue, owner: string, gid: string) {
  const rec = await kv.get<{ v: GrantRecord }>(grantKey(owner, gid));
  if (rec?.v?.at) await kv.delete(`at:${rec.v.at}`);
  if (rec?.v?.rt) await kv.delete(`rt:${rec.v.rt}`);
  await kv.delete(grantKey(owner, gid));
  const ids = (await kv.get<string[]>(`grants:${owner}`)) ?? [];
  if (ids.includes(gid)) await kv.put(`grants:${owner}`, ids.filter((x) => x !== gid));
}

async function grantsOf(kv: KeyValue, owner: string, now: number) {
  const ids = (await kv.get<string[]>(`grants:${owner}`)) ?? [];
  const out: Array<{ id: string; name: string; return_host: string; connected_at: string; last_used?: string }> = [];
  const alive: string[] = [];
  for (const id of ids) {
    const g = await getExpiring<GrantRecord>(kv, grantKey(owner, id), now);
    if (!g) continue;
    alive.push(id);
    out.push({ id, name: g.client_name, return_host: g.return_host, connected_at: g.connected_at, ...(g.refreshed_at ? { last_used: g.refreshed_at } : {}) });
  }
  if (alive.length !== ids.length) await kv.put(`grants:${owner}`, alive);
  return out;
}

// ---------- mandates signed on the page ----------

const mandatesKey = (owner: string, gen: number) => `mandates:${owner}:${gen}`;

/** The owner's revocation of one of its mandates, as the page asks the owner to sign it. */
function mandateRevocation(account: Account, id: string, at: number): RevocationBody {
  return revocationBody(account.publicKey, { target: { kind: "mandate", id }, reason: "withdrawn by its owner", createdAt: new Date(at).toISOString() });
}

/** How sure the wallet is of who answers for this mandate: "domain", "key", or "unverified" (claims a website that does not confirm it). */
async function levelOf(deps: HostedDeps, m: Mandate, _now: number): Promise<"domain" | "key" | "unverified"> {
  try {
    if (!verifyMandateSignature(m)) return "unverified";
    const domain = m.body.owner.domain;
    if (domain === undefined) return "key";
    const keys = deps.ownerResolver ? await deps.ownerResolver(domain) : null;
    return keys?.includes(m.body.owner.key) ? "domain" : "unverified";
  } catch {
    return "unverified";
  }
}

function openWallet(deps: HostedDeps, owner: string, account: Account, gen = account.agentGen) {
  return Wallet.open(new HostedWalletStorage(deps.kv, deps.secret, `${owner}:${gen}`), deps.register, {
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
    const ids = [...((await deps.kv.get<string[]>(`links:${owner}`)) ?? []), id];
    // At most MAX_LINKS per owner: the oldest requests are deleted, not just forgotten by the index.
    for (const old of ids.slice(0, Math.max(0, ids.length - MAX_LINKS))) await deps.kv.delete(`link:${old}`);
    await deps.kv.put(`links:${owner}`, ids.slice(-MAX_LINKS));
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
