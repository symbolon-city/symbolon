// Helpers for the tests of the hosted wallet (the same steps as test/hosted.test.ts, exported): an in-memory city
// with a register and the museum's agent, the "connect your assistant" dance, soft passkeys.

import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { HttpRegisterClient } from "../src/agent/client.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { MemoryStore, Register, createMandate, generateKeyPair, staticOwnerResolver, type KeyPair } from "../src/index.js";
import { concat, fromBase64url, toBase64url, utf8 } from "../src/bytes.js";
import { handle } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { handleHosted, type HostedDeps } from "../src/hosted/app.js";
import { MemoryKeyValue } from "../src/hosted/store.js";
import { SoftPasskey } from "./softpasskey.js";

export const ORIGIN = "https://wallet.example";
export const RP = "wallet.example";
export const DAY = 86_400_000;
export const REDIRECT = "https://assistant.example/callback";

/** What a browser returns from navigator.credentials.create() for this soft device. */
export function registration(device: Device, challenge: string, o: { origin?: string; flags?: number } = {}) {
  const point = p256.getPublicKey(device.secret, false);
  const x = point.slice(1, 33), y = point.slice(33, 65);
  const credId = fromBase64url(device.credentialId);
  const cose = concat(new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x, new Uint8Array([0x22, 0x58, 0x20]), y);
  const authData = concat(sha256(utf8(device.rpId)), new Uint8Array([o.flags ?? 0x45, 0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, credId.length]), credId, cose);
  const spki = concat(Uint8Array.from(Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex")), point);
  const clientData = utf8(JSON.stringify({ type: "webauthn.create", challenge, origin: o.origin ?? device.origin }));
  return { credentialId: toBase64url(credId), publicKey: toBase64url(spki), clientDataJSON: toBase64url(clientData), authenticatorData: toBase64url(authData) };
}

export async function city(extra: Partial<HostedDeps> = {}) {
  let now = Date.now();
  const clock = () => new Date(now);
  const regDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const register = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), regDeps));
  const museumOwner = generateKeyPair();
  const ownerResolver = staticOwnerResolver({ "museo.example": [museumOwner.publicKey] });
  const kv = new MemoryKeyValue();
  const deps: HostedDeps = { kv, secret: crypto.getRandomValues(new Uint8Array(32)), origin: ORIGIN, register, ownerResolver, now: clock, ...extra };
  const app = (input: string | URL | Request, init?: RequestInit) => handleHosted(new Request(input instanceof Request ? input : new URL(String(input), ORIGIN), init), deps);

  // The museum's agent, with a classic local wallet.
  const museumWallet = await Wallet.open(new MemoryWalletStorage(), register, { ownerResolver, now: clock });
  const validity = { notBefore: new Date(now - DAY).toISOString(), notAfter: new Date(now + 90 * DAY).toISOString(), charter: "accord-charter/0.1" };
  await museumWallet.installMandate(
    createMandate(museumOwner as KeyPair, { ownerDomain: "museo.example", agent: museumWallet.agentKey, scope: "restauri", maxAmount: { value: "10000.00", currency: "EUR" }, ...validity }),
  );
  const museum = await mcpOver(InMemoryTransport.createLinkedPair(), museumWallet);
  return { app, kv, deps, museum, museumWallet, museumOwner, register, ownerResolver, clock, advance: (ms: number) => (now += ms), now: () => now };
}

async function mcpOver([a, b]: [InMemoryTransport, InMemoryTransport], wallet: Wallet) {
  await buildMcpServer(wallet).connect(a);
  const c = new Client({ name: "museum", version: "0" });
  await c.connect(b);
  return caller(c);
}

export function caller(c: Client) {
  return async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await c.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
    if (r.isError) throw new Error(r.content[0]!.text);
    return JSON.parse(r.content[0]!.text);
  };
}

export type App = Awaited<ReturnType<typeof city>>["app"];

export const postJson = (app: App, path: string, body: unknown, headers: Record<string, string> = {}) =>
  app(path, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, ...headers }, body: JSON.stringify(body) });

/** The whole "connect your assistant" dance, as an MCP client and the owner's browser do it. */
export async function connect(app: App, device: Device, o: { create: boolean; opensPages?: boolean }) {
  const reg = await (await app("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "Assistente di Marta" }) })).json();
  const verifier = toBase64url(crypto.getRandomValues(new Uint8Array(48)));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: toBase64url(sha256(utf8(verifier))), code_challenge_method: "S256", state: "xyz", resource: ORIGIN + "/mcp" });
  const page = await app("/authorize?" + q);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Assistente di Marta/);
  const request = /"request":"([A-Za-z0-9_.-]+)"/.exec(html)![1]!;
  const ch = await (await postJson(app, "/auth/challenge", { purpose: "authorize:" + request })).json();
  const answer = o.create
    ? await (async () => {
        const first = await postJson(app, "/auth/signup", { nonce: ch.nonce, ...registration(device, ch.challenge) });
        const { confirm } = await first.json();
        return postJson(app, "/auth/signup/confirm", { nonce: confirm.nonce, signature: device.sign(null, { challenge: fromBase64url(confirm.challenge) }) });
      })()
    : await postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch.challenge) }) });
  const back = await answer.json();
  assert.equal(answer.status, 200, JSON.stringify(back));
  const redirect = new URL(back.redirect);
  assert.equal(redirect.origin + redirect.pathname, REDIRECT);
  assert.equal(redirect.searchParams.get("state"), "xyz");
  assert.equal(redirect.searchParams.get("iss"), ORIGIN);
  const code = redirect.searchParams.get("code")!;
  const tokenReq = (params: Record<string, string>) =>
    app("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params).toString() });
  const tok = await (await tokenReq({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: REDIRECT })).json();
  assert.ok(tok.access_token, JSON.stringify(tok));
  const mcp = new Client({ name: "assistant", version: "0" }, o.opensPages ? { capabilities: { elicitation: { url: {} } } } : {});
  await mcp.connect(new StreamableHTTPClientTransport(new URL(ORIGIN + "/mcp"), { fetch: (u, i) => app(String(u), i), requestInit: { headers: { authorization: "Bearer " + tok.access_token } } }));
  return { call: caller(mcp), mcp, client_id: reg.client_id, tok, code, verifier, tokenReq };
}

/** A soft device that also remembers the id of the passkey it made, as a phone does. */
export class Device extends SoftPasskey {
  readonly credentialId = toBase64url(crypto.getRandomValues(new Uint8Array(32)));
}
export const newDevice = (origin = ORIGIN, rpId = RP) => new Device(rpId, origin);

export async function signRequest(app: App, link: string, device: SoftPasskey) {
  const path = new URL(link).pathname.replace("/owner/r/", "/owner/api/request/");
  const r = await (await app(path)).json();
  const signature = device.sign(null, { challenge: fromBase64url(r.challenge) });
  const res = await postJson(app, path, { signature });
  return { shown: r, res, body: await res.json() };
}

/** Signs in to the owner's page with this passkey: the authorization header of the session. */
export async function signIn(app: App, device: Device) {
  const ch = await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json();
  const r = await (await postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch.challenge) }) })).json();
  return { authorization: "Bearer " + r.session };
}

export const registerClient = (app: App, body: Record<string, unknown>, headers: Record<string, string> = {}) =>
  app("/register", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

export const keysOf = (kv: MemoryKeyValue, prefix: string) => [...kv.map.keys()].filter((k) => k.startsWith(prefix));
