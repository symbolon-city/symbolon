// The hosted wallet ("the connector"): Marta adds Symbolon to her assistant, signs in with Face ID, signs her
// mandate on the wallet's page, approves one agreement above her limit, and can block everything.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
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

const ORIGIN = "https://wallet.example";
const RP = "wallet.example";
const DAY = 86_400_000;
const REDIRECT = "https://assistant.example/callback";

/** What a browser returns from navigator.credentials.create() for this soft device. */
function registration(device: Device, challenge: string, o: { origin?: string; flags?: number } = {}) {
  const point = p256.getPublicKey(device.secret, false);
  const x = point.slice(1, 33), y = point.slice(33, 65);
  const credId = fromBase64url(device.credentialId);
  const cose = concat(new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x, new Uint8Array([0x22, 0x58, 0x20]), y);
  const authData = concat(sha256(utf8(device.rpId)), new Uint8Array([o.flags ?? 0x45, 0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, credId.length]), credId, cose);
  const spki = concat(Uint8Array.from(Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex")), point);
  const clientData = utf8(JSON.stringify({ type: "webauthn.create", challenge, origin: o.origin ?? device.origin }));
  return { credentialId: toBase64url(credId), publicKey: toBase64url(spki), clientDataJSON: toBase64url(clientData), authenticatorData: toBase64url(authData) };
}

async function city() {
  let now = Date.now();
  const clock = () => new Date(now);
  const regDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const register = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), regDeps));
  const museumOwner = generateKeyPair();
  const ownerResolver = staticOwnerResolver({ "museo.example": [museumOwner.publicKey] });
  const kv = new MemoryKeyValue();
  const deps: HostedDeps = { kv, secret: crypto.getRandomValues(new Uint8Array(32)), origin: ORIGIN, register, ownerResolver, now: clock };
  const app = (input: string | URL | Request, init?: RequestInit) => handleHosted(new Request(input instanceof Request ? input : new URL(String(input), ORIGIN), init), deps);

  // The museum's agent, with a classic local wallet.
  const museumWallet = await Wallet.open(new MemoryWalletStorage(), register, { ownerResolver, now: clock });
  const validity = { notBefore: new Date(now - DAY).toISOString(), notAfter: new Date(now + 90 * DAY).toISOString(), charter: "accord-charter/0.1" };
  await museumWallet.installMandate(
    createMandate(museumOwner as KeyPair, { ownerDomain: "museo.example", agent: museumWallet.agentKey, scope: "restauri", maxAmount: { value: "10000.00", currency: "EUR" }, ...validity }),
  );
  const museum = await mcpOver(InMemoryTransport.createLinkedPair(), museumWallet);
  return { app, kv, deps, museum, museumWallet, advance: (ms: number) => (now += ms) };
}

async function mcpOver([a, b]: [InMemoryTransport, InMemoryTransport], wallet: Wallet) {
  await buildMcpServer(wallet).connect(a);
  const c = new Client({ name: "museum", version: "0" });
  await c.connect(b);
  return caller(c);
}

function caller(c: Client) {
  return async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await c.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
    if (r.isError) throw new Error(r.content[0]!.text);
    return JSON.parse(r.content[0]!.text);
  };
}

type App = Awaited<ReturnType<typeof city>>["app"];

const postJson = (app: App, path: string, body: unknown, headers: Record<string, string> = {}) =>
  app(path, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, ...headers }, body: JSON.stringify(body) });

/** The whole "connect your assistant" dance, as an MCP client and the owner's browser do it. */
async function connect(app: App, device: Device, o: { create: boolean; opensPages?: boolean }) {
  const reg = await (await app("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "Assistente di Marta" }) })).json();
  const verifier = toBase64url(crypto.getRandomValues(new Uint8Array(48)));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: toBase64url(sha256(utf8(verifier))), code_challenge_method: "S256", state: "xyz", resource: ORIGIN + "/mcp" });
  const page = await app("/authorize?" + q);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Assistente di Marta/);
  const request = /"request":"([A-Za-z0-9_-]{43})"/.exec(html)![1]!;
  const ch = await (await postJson(app, "/auth/challenge", { purpose: "authorize:" + request })).json();
  const answer = o.create
    ? await postJson(app, "/auth/signup", { nonce: ch.nonce, ...registration(device, ch.challenge) })
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
class Device extends SoftPasskey {
  readonly credentialId = toBase64url(crypto.getRandomValues(new Uint8Array(32)));
}
const newDevice = (origin = ORIGIN, rpId = RP) => new Device(rpId, origin);

async function signRequest(app: App, link: string, device: SoftPasskey) {
  const path = new URL(link).pathname.replace("/owner/r/", "/owner/api/request/");
  const r = await (await app(path)).json();
  const signature = device.sign(null, { challenge: fromBase64url(r.challenge) });
  const res = await postJson(app, path, { signature });
  return { shown: r, res, body: await res.json() };
}

test("hosted: Marta connects her assistant with Face ID, signs her mandate on the page, approves one agreement, the museum accepts", async () => {
  const { app, museum } = await city();
  const device = newDevice();
  const first = await connect(app, device, { create: true });
  const who = await first.call("symbolon_whoami");
  assert.equal(who.mandate, null);

  // "Da oggi puoi accettare lavori di restauro fino a 2.000 €, per tre mesi."
  const ask = await first.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
  assert.match(ask.owner_page, /^https:\/\/wallet\.example\/owner\/r\/[A-Za-z0-9_-]{43}$/);
  assert.match(ask.for_the_owner.text, /lavori di restauro.*2000\.00 EUR/);
  // Nothing is valid before Marta signs.
  assert.equal((await first.call("symbolon_whoami")).mandate, null);
  const page = await app(new URL(ask.owner_page).pathname);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy")!, /default-src 'none'/);
  const signed = await signRequest(app, ask.owner_page, device);
  assert.equal(signed.res.status, 200, JSON.stringify(signed.body));
  assert.equal(signed.shown.body.scope, "lavori di restauro");
  assert.equal(signed.body.level, "key");
  const mine = await first.call("symbolon_whoami");
  assert.equal(mine.mandate.scope, "lavori di restauro");
  // The link works once.
  assert.equal((await app(new URL(ask.owner_page).pathname.replace("/owner/r/", "/owner/api/request/"))).status, 404);

  // The museum offers 2,400 EUR: above the limit. Marta's agent asks her to approve just this one.
  const museumMandate = await museum("symbolon_my_mandate");
  const deal = { object: "restauro della cornice dorata", amount: { value: "2400.00", currency: "EUR" }, delivery: "2026-12-20" };
  const req = await first.call("symbolon_request_owner_approval", { counterparty_mandate: museumMandate, clauses: deal });
  assert.ok(req.owner_page && req.clauses_root);
  assert.equal(req.approval_body, undefined, "on a hosted wallet the agent gets a link, not something to sign");
  await assert.rejects(first.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root }), /has not approved this agreement yet/);
  const approved = await signRequest(app, req.owner_page, device);
  assert.equal(approved.res.status, 200, JSON.stringify(approved.body));
  // The page showed the real clauses, recomputed from the fingerprint, and the general limit.
  assert.deepEqual(approved.shown.clauses, deal);
  assert.equal(approved.shown.general_limit.value, "2000.00");
  assert.equal(approved.shown.counterparty.owner, "museo.example");

  const offer = await first.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root });
  const accepted = await museum("symbolon_accept_agreement", { offer });
  assert.equal(accepted.counterparty.level, "key");
  await first.call("symbolon_confirm_agreement", { confirmation: accepted.confirmation });
  const proof = await first.call("symbolon_create_proof", { entry: accepted.entry, reveal: ["object", "amount"] });
  const report = await museum("symbolon_verify_proof", { proof });
  assert.equal(report.valid, true);

  // Marta's page: sign in with Face ID, see the agent, its mandate and the commitment.
  const ch = await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json();
  const sess = await (await postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch.challenge) }) })).json();
  const state = await (await app("/owner/api/state", { headers: { authorization: "Bearer " + sess.session } })).json();
  assert.equal(state.mandate.scope, "lavori di restauro");
  assert.equal(state.commitments.open.length, 1);
  assert.equal(state.commitments.open[0].with[0].owner, "museo.example");
  assert.equal(state.mandate_revoked, null);
  assert.equal(state.history[0].with[0], "museo.example");
  // The proof of the agreement, downloaded from her page, holds up for anyone (all clauses revealed: it is hers).
  const auth = { authorization: "Bearer " + sess.session };
  const dl = await app(`/owner/api/proof/0/${accepted.entry}`, { headers: auth });
  assert.match(dl.headers.get("content-disposition")!, /attachment/);
  const herProof = await dl.json();
  const check = await museum("symbolon_verify_proof", { proof: herProof });
  assert.equal(check.valid, true);
  assert.equal(herProof.disclosures.length, 3);
  assert.equal((await app(`/owner/api/proof/0/${accepted.entry}`)).status, 401, "only with her session");
  // Everything she may take away: mandates, agreements with their clauses and receipts, never the agent's secret.
  const exported = await (await app("/owner/api/export", { headers: auth })).json();
  assert.equal(exported.agents.length, 1);
  assert.equal(exported.agents[0].records.find((r: { entry: string }) => r.entry === accepted.entry).opened.clauses.length, 3);
  const text = JSON.stringify(exported);
  assert.ok(!/agentSecret|secretKey|"box"/.test(text), "no secrets in the export");

  // The same Marta, from another assistant (or again later): signs in with the same passkey, same wallet.
  const again = await connect(app, device, { create: false });
  assert.equal((await again.call("symbolon_whoami")).agent, mine.agent);
});


test("hosted: the connection refuses unknown assistants, foreign return addresses, missing PKCE, wrong verifiers, reused codes and refresh tokens", async () => {
  const { app } = await city();
  const device = newDevice();
  const c = await connect(app, device, { create: true });
  // A code works once, and only with its verifier, client and return address.
  const again = await (await c.tokenReq({ grant_type: "authorization_code", code: c.code, code_verifier: c.verifier, client_id: c.client_id, redirect_uri: REDIRECT })).json();
  assert.equal(again.error, "invalid_grant");
  // Refresh tokens rotate: the old one stops working.
  const r1 = await (await c.tokenReq({ grant_type: "refresh_token", refresh_token: c.tok.refresh_token, client_id: c.client_id })).json();
  assert.ok(r1.access_token);
  assert.equal((await (await c.tokenReq({ grant_type: "refresh_token", refresh_token: c.tok.refresh_token, client_id: c.client_id })).json()).error, "invalid_grant");
  assert.equal((await (await c.tokenReq({ grant_type: "refresh_token", refresh_token: r1.refresh_token, client_id: "c_other" })).json()).error, "invalid_grant");

  const reg = await (await app("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [REDIRECT] }) })).json();
  const base = { response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: toBase64url(sha256(utf8("v".repeat(43)))), code_challenge_method: "S256" };
  assert.equal((await app("/authorize?" + new URLSearchParams({ ...base, client_id: "c_unknown" }))).status, 400);
  assert.equal((await app("/authorize?" + new URLSearchParams({ ...base, redirect_uri: "https://evil.example/cb" }))).status, 400);
  const noPkce = await app("/authorize?" + new URLSearchParams({ ...base, code_challenge_method: "plain" }));
  assert.equal(noPkce.status, 302);
  assert.equal(new URL(noPkce.headers.get("location")!).searchParams.get("error"), "invalid_request");
  const otherResource = await app("/authorize?" + new URLSearchParams({ ...base, resource: "https://other.example/mcp" }));
  assert.equal(new URL(otherResource.headers.get("location")!).searchParams.get("error"), "invalid_target");

  // A wrong verifier, or a code taken to another assistant, gets nothing.
  const newCode = async () => {
    const html = await (await app("/authorize?" + new URLSearchParams(base))).text();
    const request = /"request":"([A-Za-z0-9_-]{43})"/.exec(html)![1]!;
    const ch = await (await postJson(app, "/auth/challenge", { purpose: "authorize:" + request })).json();
    const back = await (await postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch.challenge) }) })).json();
    return new URL(back.redirect).searchParams.get("code")!;
  };
  const good = { grant_type: "authorization_code", code_verifier: "v".repeat(43), client_id: reg.client_id, redirect_uri: REDIRECT };
  assert.equal((await (await c.tokenReq({ ...good, code: await newCode(), code_verifier: "w".repeat(43) })).json()).error, "invalid_grant");
  assert.equal((await (await c.tokenReq({ ...good, code: await newCode(), redirect_uri: "https://assistant.example/other" })).json()).error, "invalid_grant");
  assert.equal((await (await c.tokenReq({ ...good, code: await newCode(), client_id: c.client_id })).json()).error, "invalid_grant");
  assert.ok((await (await c.tokenReq({ ...good, code: await newCode() })).json()).access_token, "and with everything right it works");

  // Registration only for safe return addresses; only public clients.
  const bad = async (redirect_uris: unknown, extra = {}) =>
    (await app("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris, ...extra }) })).status;
  assert.equal(await bad(["http://evil.example/cb"]), 400);
  assert.equal(await bad(["javascript:alert(1)"]), 400);
  assert.equal(await bad(["https://a.example/cb#x"]), 400);
  assert.equal(await bad([]), 400);
  assert.equal(await bad([REDIRECT], { token_endpoint_auth_method: "client_secret_basic" }), 400);
  assert.equal(await bad(["http://127.0.0.1:33418/callback"]), 201);
  assert.equal(await bad(["cursor://anysphere.cursor-mcp/oauth/callback"]), 201);

  // Without a token the wallet answers 401 and says where to sign in.
  const anon = await app("/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
  assert.equal(anon.status, 401);
  assert.match(anon.headers.get("www-authenticate")!, /resource_metadata="https:\/\/wallet\.example\/\.well-known\/oauth-protected-resource"/);
  const meta = await (await app("/.well-known/oauth-protected-resource")).json();
  assert.equal(meta.resource, ORIGIN + "/mcp");
  const as = await (await app("/.well-known/oauth-authorization-server")).json();
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
});

test("hosted: signing in needs this site's passkey, a fresh challenge, and the person verified", async () => {
  const { app } = await city();
  const device = newDevice();
  await connect(app, device, { create: true });
  const challenge = async () => (await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json()) as { nonce: string; challenge: string };
  const signin = (ch: { nonce: string; challenge: string }, d: Device, o: { flags?: number } = {}) =>
    postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: d.sign(null, { challenge: fromBase64url(ch.challenge), ...o }) });
  // A look-alike site cannot pass on what the owner signed there.
  const phishing = Object.assign(new Device(RP, "https://wallet-example.evil"), { secret: device.secret, publicKey: device.publicKey });
  assert.equal((await signin(await challenge(), phishing)).status, 401);
  const otherRp = Object.assign(new Device("evil.example", ORIGIN), { secret: device.secret, publicKey: device.publicKey });
  assert.equal((await signin(await challenge(), otherRp)).status, 401);
  assert.equal((await signin(await challenge(), device, { flags: 0x01 })).status, 401, "the person must be verified (Face ID, PIN)");
  // Another device's key, claiming Marta's passkey id.
  assert.equal((await signin(await challenge(), newDevice())).status, 401);
  // A challenge works once.
  const ch = await challenge();
  assert.equal((await signin(ch, device)).status, 200);
  assert.equal((await signin(ch, device)).status, 400);
  // Unknown passkey; cross-site request.
  const unknown = newDevice();
  const ch2 = await challenge();
  assert.equal((await postJson(app, "/auth/signin", { nonce: ch2.nonce, credentialId: unknown.credentialId, signature: unknown.sign(null, { challenge: fromBase64url(ch2.challenge) }) })).status, 404);
  assert.equal((await postJson(app, "/auth/challenge", { purpose: "owner" }, { origin: "https://evil.example" })).status, 403);
  // Creating a wallet: on this site, with the person verified, once per passkey.
  const fresh = newDevice();
  const ch3 = await challenge();
  assert.equal((await postJson(app, "/auth/signup", { nonce: ch3.nonce, ...registration(fresh, ch3.challenge, { origin: "https://evil.example" }) })).status, 400);
  const ch4 = await challenge();
  assert.equal((await postJson(app, "/auth/signup", { nonce: ch4.nonce, ...registration(fresh, ch4.challenge, { flags: 0x41 }) })).status, 400);
  const ch5 = await challenge();
  const swapped = { ...registration(fresh, ch5.challenge), publicKey: registration(newDevice(), ch5.challenge).publicKey };
  assert.equal((await postJson(app, "/auth/signup", { nonce: ch5.nonce, ...swapped })).status, 400, "the key must be the one in the registration");
  const ch6 = await challenge();
  assert.equal((await postJson(app, "/auth/signup", { nonce: ch6.nonce, ...registration(device, ch6.challenge) })).status, 409);
});

test("hosted: only the owner's passkey signs a request, over exactly what the page shows", async () => {
  const { app } = await city();
  const device = newDevice();
  const c = await connect(app, device, { create: true });
  const ask = await c.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
  const path = new URL(ask.owner_page).pathname.replace("/owner/r/", "/owner/api/request/");
  const shown = await (await app(path)).json();
  // Someone else's Face ID, or Marta's signature of something else, is refused and installs nothing.
  const intruder = newDevice();
  assert.equal((await postJson(app, path, { signature: intruder.sign(null, { challenge: fromBase64url(shown.challenge) }) })).status, 401);
  const wider = { ...shown.body, maxAmount: { value: "20000.00", currency: "EUR" } };
  assert.equal((await postJson(app, path, { signature: device.sign(wider) })).status, 401);
  assert.equal((await postJson(app, path, { signature: device.sign(null, { challenge: fromBase64url(shown.challenge) }) }, { origin: "https://evil.example" })).status, 403);
  assert.equal((await c.call("symbolon_whoami")).mandate, null);
  // A mandate signed by someone else (sent by a message, a web page...) cannot make Marta's agent act for another owner.
  const stranger = generateKeyPair();
  const agent = (await c.call("symbolon_whoami")).agent;
  const foreign = createMandate(stranger as KeyPair, { agent, scope: "anything", notBefore: new Date(Date.now() - DAY).toISOString(), notAfter: new Date(Date.now() + DAY).toISOString(), charter: "accord-charter/0.1" });
  // On a hosted wallet the assistant cannot install mandates at all: only the owner's page does (security-d, A1).
  await assert.rejects(c.call("symbolon_install_mandate", { mandate: foreign }), /symbolon_install_mandate not found/);
  assert.equal((await c.call("symbolon_whoami")).mandate, null);
  // The agent cannot ask for more than a valid mandate allows (dates, amount format).
  await assert.rejects(c.call("symbolon_ask_owner_for_mandate", { scope: "x", max_amount: { value: "lots", currency: "EUR" }, days: 10 }));
  await assert.rejects(c.call("symbolon_ask_owner_for_mandate", { scope: "lavori", days: 400 }));
  // Unknown or malformed links.
  assert.equal((await app("/owner/api/request/" + "A".repeat(43))).status, 404);
  assert.equal((await app("/owner/r/../../token")).status, 404);
});

test("hosted: Block everything revokes the agent in the register, disconnects every assistant, and a new connection starts a new agent", async () => {
  const { app, museum, kv, deps } = await city();
  const device = newDevice();
  const c = await connect(app, device, { create: true });
  const ask = await c.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
  await signRequest(app, ask.owner_page, device);
  const oldMandate = await c.call("symbolon_my_mandate");
  assert.equal((await museum("symbolon_check_counterparty", { mandate: oldMandate })).revoked, undefined);

  const ch = await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json();
  const { session } = await (await postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch.challenge) }) })).json();
  const auth = { authorization: "Bearer " + session };
  const b = await (await app("/owner/api/block", { headers: auth })).json();
  // Only the block of this very agent is accepted.
  const other = { ...b.body, target: { kind: "agent", key: generateKeyPair().publicKey } };
  assert.equal((await postJson(app, "/owner/api/block", { body: other, signature: device.sign(other) }, auth)).status, 400);
  assert.equal((await postJson(app, "/owner/api/block", { body: b.body, signature: newDevice().sign(b.body) }, auth)).status, 401);
  const done = await postJson(app, "/owner/api/block", { body: b.body, signature: device.sign(null, { challenge: fromBase64url(b.challenge) }) }, auth);
  assert.equal(done.status, 200, await done.clone().text());

  // Everywhere: the museum's wallet now sees the old mandate revoked.
  const check = await museum("symbolon_check_counterparty", { mandate: oldMandate });
  assert.ok(check.revoked, JSON.stringify(check));
  // The connected assistant, its refresh token and the page session stop working.
  await assert.rejects(c.call("symbolon_whoami"));
  assert.equal((await (await c.tokenReq({ grant_type: "refresh_token", refresh_token: c.tok.refresh_token, client_id: c.client_id })).json()).error, "invalid_grant");
  assert.equal((await app("/owner/api/state", { headers: auth })).status, 401);
  // Connecting again gives a new agent, with no mandate; the old wallet is kept (its proofs stay valid).
  const fresh = await connect(app, device, { create: false });
  const who = await fresh.call("symbolon_whoami");
  assert.equal(who.mandate, null);
  assert.notEqual(who.agent, oldMandate.body.agent);
  assert.ok([...kv.map.keys()].filter((k) => k.startsWith("wallet:")).length === 2);
  // Her page shows the new agent, and the blocked one with its mandate.
  const ch2 = await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json();
  const s2 = await (await postJson(app, "/auth/signin", { nonce: ch2.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch2.challenge) }) })).json();
  const st = await (await app("/owner/api/state", { headers: { authorization: "Bearer " + s2.session } })).json();
  assert.equal(st.agent, who.agent);
  assert.equal(st.previous_agents.length, 1);
  assert.equal(st.previous_agents[0].agent, oldMandate.body.agent);
  assert.equal((await (await app("/owner/api/export", { headers: { authorization: "Bearer " + s2.session } })).json()).agents.length, 2);
  assert.equal((await app("/owner/api/proof/7/" + "a".repeat(64), { headers: { authorization: "Bearer " + s2.session } })).status, 404);
  void deps;
});

test("hosted: the wallets are stored encrypted, bound to their owner", async () => {
  const { app, kv, deps } = await city();
  const device = newDevice();
  const c = await connect(app, device, { create: true });
  const who = await c.call("symbolon_whoami");
  const [key, stored] = [...kv.map.entries()].find(([k]) => k.startsWith("wallet:"))!;
  const text = JSON.stringify(stored);
  assert.ok(!text.includes("agentSecret") && !text.includes(who.agent.slice(8)), "nothing readable in the storage");
  const { HostedWalletStorage } = await import("../src/hosted/store.js");
  const owner = key.slice("wallet:".length);
  assert.equal((await new HostedWalletStorage(kv, deps.secret, owner).load())!.v, 1);
  await assert.rejects(new HostedWalletStorage(kv, crypto.getRandomValues(new Uint8Array(32)), owner).load(), "another operator secret cannot read it");
  // Copied under another owner's name, it does not open.
  kv.map.set("wallet:someone:0", stored);
  await assert.rejects(new HostedWalletStorage(kv, deps.secret, "someone:0").load());
});

test("hosted: an assistant that can open pages shows its user the page to sign (URL elicitation), and calls again", async () => {
  const { app, museum } = await city();
  const device = newDevice();
  const c = await connect(app, device, { create: true, opensPages: true });
  const asked = async (p: Promise<unknown>) => {
    const e = (await p.then(() => assert.fail("expected the page to open"), (x) => x)) as McpError;
    assert.ok(e instanceof McpError, String(e));
    assert.equal(e.code, ErrorCode.UrlElicitationRequired);
    const [el] = (e.data as { elicitations: Array<{ mode: string; url: string; message: string; elicitationId: string }> }).elicitations;
    assert.equal(el!.mode, "url");
    return el!;
  };
  const ask = await c.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
  // Anything that needs the mandate opens the page where Marta signs it.
  const museumMandate = await museum("symbolon_my_mandate");
  const deal = { object: "restauro della cornice dorata", amount: { value: "2400.00", currency: "EUR" }, delivery: "2026-12-20" };
  const m = await asked(c.mcp.callTool({ name: "symbolon_request_owner_approval", arguments: { counterparty_mandate: museumMandate, clauses: deal } }));
  assert.equal(m.url, ask.owner_page);
  assert.match(m.message, /has not signed your mandate yet/);
  await signRequest(app, m.url, device);

  const req = await c.call("symbolon_request_owner_approval", { counterparty_mandate: museumMandate, clauses: deal });
  const a = await asked(c.mcp.callTool({ name: "symbolon_propose_approved_agreement", arguments: { clauses_root: req.clauses_root } }));
  assert.equal(a.url, req.owner_page, "the same page, not a new request each time");
  assert.match(a.message, /has not approved this agreement yet/);
  await signRequest(app, a.url, device);
  const offer = await c.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root });
  const accepted = await museum("symbolon_accept_agreement", { offer });
  assert.ok(accepted.entry);
});

test("hosted: an assistant that cannot open pages gets the link in the answer, for the agent to pass on", async () => {
  const { app, museum } = await city();
  const device = newDevice();
  const c = await connect(app, device, { create: true });
  await assert.rejects(c.call("symbolon_my_mandate"), /no mandate yet: ask your owner .* symbolon_ask_owner_for_mandate/);
  const ask = await c.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
  await assert.rejects(c.call("symbolon_my_mandate"), (e: Error) => e.message.includes(ask.owner_page) && /Give your owner this link/.test(e.message));
  await signRequest(app, ask.owner_page, device);
  const museumMandate = await museum("symbolon_my_mandate");
  const req = await c.call("symbolon_request_owner_approval", { counterparty_mandate: museumMandate, clauses: { object: "x", amount: { value: "2400.00", currency: "EUR" } } });
  await assert.rejects(c.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root }), (e: Error) => e.message.includes(req.owner_page));
});
