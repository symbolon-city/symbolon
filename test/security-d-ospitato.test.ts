// Security of the hosted wallet ("the connector"), after the attack test of 21/11: a replaced mandate cannot come
// back, an impostor is shown as NOT VERIFIED, the consent page and the owner's page against consent phishing,
// storage that anonymous requests cannot grow, bounded MCP bodies, signup with proof of the new passkey, and
// every wallet opened inside the owner's lock.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { sha256 } from "@noble/hashes/sha2";
import { buildMcpServer } from "../src/agent/mcp.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { createMandate, generateKeyPair, staticOwnerResolver, type KeyPair } from "../src/index.js";
import { fromBase64url, toBase64url, utf8 } from "../src/bytes.js";
import { MAX_MCP_BODY, MAX_REGISTRATIONS_PER_DAY, cleanClientName, returnAddress, sweepHosted } from "../src/hosted/app.js";
import { HostedWalletStorage, KeyedLock, MemoryKeyValue, putExpiring } from "../src/hosted/store.js";
import { DAY, ORIGIN, REDIRECT, caller, city, connect, keysOf, newDevice, postJson, registerClient, registration, signIn, signRequest, type App } from "./hosted-helpers.js";

const tokenReq = (app: App, params: Record<string, string>) =>
  app("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params).toString() });

/** The MODEL the server writes into a page. */
const modelOf = async (res: Response) => JSON.parse(/const MODEL = (\{.*?\});\n/.exec(await res.text())![1]!);

/** An assistant that registers itself with this name and return address, and is connected by the owner's passkey. */
async function connectAs(app: App, device: ReturnType<typeof newDevice>, name: string, redirect: string) {
  const reg = await (await registerClient(app, { redirect_uris: [redirect], client_name: name })).json();
  const verifier = toBase64url(crypto.getRandomValues(new Uint8Array(48)));
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirect, code_challenge: toBase64url(sha256(utf8(verifier))), code_challenge_method: "S256" });
  const model = await modelOf(await app("/authorize?" + q));
  const ch = await (await postJson(app, "/auth/challenge", { purpose: "authorize:" + model.request })).json();
  const back = await (await postJson(app, "/auth/signin", { nonce: ch.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch.challenge) }) })).json();
  const code = new URL(back.redirect).searchParams.get("code")!;
  const tok = await (await tokenReq(app, { grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: redirect })).json();
  return { model, tok, client_id: reg.client_id };
}

const mcpPost = (app: App, token: string, body: BodyInit, headers: Record<string, string> = {}) =>
  app(ORIGIN + "/mcp", { method: "POST", headers: { authorization: "Bearer " + token, "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body });
const whoamiOk = async (app: App, token: string) =>
  (await mcpPost(app, token, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "symbolon_whoami", arguments: {} } }))).status === 200;

// ---------- A1 ----------

test("hosted security A1: a replaced mandate cannot be put back by the assistant; the owner can revoke it, and the current one, publicly", async () => {
  const { app, museum } = await city();
  const marta = newDevice();
  const a = await connect(app, marta, { create: true });
  const wide = await a.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "10000.00", currency: "EUR" }, days: 365 });
  const first = await signRequest(app, wide.owner_page, marta);
  assert.equal(first.body.replaced, undefined, "nothing replaced the first time");
  const wideMandate = await a.call("symbolon_my_mandate");
  const narrow = await a.call("symbolon_ask_owner_for_mandate", { scope: "piccoli lavori", max_amount: { value: "100.00", currency: "EUR" }, days: 7 });
  const s = await signRequest(app, narrow.owner_page, marta);
  assert.equal(s.res.status, 200);
  assert.equal((await a.call("symbolon_whoami")).mandate.maxAmount.value, "100.00");

  // The assistant tries to put back the wide one it kept: refused (by the hosted wallet, or the tool is gone).
  await assert.rejects(a.call("symbolon_install_mandate", { mandate: wideMandate }), /only mandate that can be installed|not found|unknown tool|older|superseded|replaced/i);
  assert.equal((await a.call("symbolon_whoami")).mandate.maxAmount.value, "100.00");

  // The page offered, right after signing, the public revocation of the replaced mandate.
  const replaced = s.body.replaced;
  assert.equal(replaced.max_amount.value, "10000.00");
  assert.equal(replaced.revoke.body.target.kind, "mandate");
  // Someone else's signature, or a revocation of a mandate that is not hers here, is refused.
  assert.equal((await postJson(app, "/owner/api/revoke-mandate", { body: replaced.revoke.body, signature: newDevice().sign(null, { challenge: fromBase64url(replaced.revoke.challenge) }) })).status, 401);
  const other = { ...replaced.revoke.body, target: { kind: "mandate", id: "f".repeat(64) } };
  assert.equal((await postJson(app, "/owner/api/revoke-mandate", { body: other, signature: marta.sign(other) })).status, 404);
  const rv = await postJson(app, "/owner/api/revoke-mandate", { body: replaced.revoke.body, signature: marta.sign(null, { challenge: fromBase64url(replaced.revoke.challenge) }) });
  assert.equal(rv.status, 200, await rv.clone().text());
  // Everywhere: the museum sees the wide mandate revoked.
  assert.ok((await museum("symbolon_check_counterparty", { mandate: wideMandate })).revoked);

  // On her page: "Revoke this mandate" for the current one.
  const auth = await signIn(app, marta);
  let st = await (await app("/owner/api/state", { headers: auth })).json();
  assert.equal(st.mandate_revocable, true);
  assert.deepEqual(st.replaced_mandates, [], "the replaced one is revoked: no longer offered");
  const prep = await (await app("/owner/api/revoke-mandate?id=" + st.mandate_id, { headers: auth })).json();
  assert.equal(prep.body.target.id, st.mandate_id);
  assert.equal((await app("/owner/api/revoke-mandate?id=" + "e".repeat(64), { headers: auth })).status, 404);
  const done = await postJson(app, "/owner/api/revoke-mandate", { body: prep.body, signature: marta.sign(null, { challenge: fromBase64url(prep.challenge) }) }, auth);
  assert.equal(done.status, 200);
  st = await (await app("/owner/api/state", { headers: auth })).json();
  assert.ok(st.mandate_revoked);
  assert.equal(st.mandate_revocable, false);
  // The agent cannot act on it any more.
  await assert.rejects(a.call("symbolon_propose_agreement", { counterparty_mandate: await museum("symbolon_my_mandate"), clauses: { object: "x", amount: { value: "50.00", currency: "EUR" } } }), /revoked/);
  // And the page script has the buttons.
  const html = await (await app("/owner")).text();
  assert.match(html, /Revoke this mandate with Face ID/);
  assert.match(html, /Revoke the previous mandate with Face ID/);
});

// ---------- A2 ----------

test("hosted security A2: an impostor claiming a website is shown to the owner as NOT VERIFIED, on the request and on her page", async () => {
  const { app, kv, deps, museum, clock } = await city();
  const marta = newDevice();
  const a = await connect(app, marta, { create: true });
  const ask = await a.call("symbolon_ask_owner_for_mandate", { scope: "lavori di restauro", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
  await signRequest(app, ask.owner_page, marta);

  // The impostor's agent: its own key, claiming museo.example (which publishes another key).
  const impostor = generateKeyPair();
  const impWallet = await Wallet.open(new MemoryWalletStorage(), deps.register, { ownerResolver: staticOwnerResolver({}), now: clock });
  const now = clock().getTime();
  await impWallet.installMandate(
    createMandate(impostor as KeyPair, { ownerDomain: "museo.example", agent: impWallet.agentKey, scope: "restauri", maxAmount: { value: "100000.00", currency: "EUR" }, notBefore: new Date(now - DAY).toISOString(), notAfter: new Date(now + 90 * DAY).toISOString(), charter: "accord-charter/0.1" }),
  );
  const [x, y] = InMemoryTransport.createLinkedPair();
  await buildMcpServer(impWallet).connect(x);
  const cl = new Client({ name: "imp", version: "0" });
  await cl.connect(y);
  const imp = caller(cl);
  const impMandate = await imp("symbolon_my_mandate");

  // However the approval request came to exist (an older wallet, or the flag set by someone), the page checks the
  // identity itself. Prepared here directly in Marta's wallet, as the wallet's own code does.
  const owner = keysOf(kv, "acct:")[0]!.slice("acct:".length);
  const wallet = await Wallet.open(new HostedWalletStorage(kv, deps.secret, `${owner}:0`), deps.register, { ownerResolver: deps.ownerResolver!, now: clock });
  const req = await wallet.requestApproval({ counterparty: impMandate, clauses: { object: "restauro cornice", amount: { value: "2400.00", currency: "EUR" } }, allowUnverifiedOwner: true });
  const linkId = toBase64url(crypto.getRandomValues(new Uint8Array(32)));
  await putExpiring(kv, `link:${linkId}`, { owner, kind: "approval", root: req.clauses_root }, now + DAY);
  const shown = await (await app("/owner/api/request/" + linkId)).json();
  assert.equal(shown.counterparty.owner, "museo.example");
  assert.equal(shown.counterparty.level, "unverified");

  // The real museum is "domain".
  const real = await a.call("symbolon_request_owner_approval", { counterparty_mandate: await museum("symbolon_my_mandate"), clauses: { object: "y", amount: { value: "2400.00", currency: "EUR" } } });
  const realShown = await (await app(new URL(real.owner_page).pathname.replace("/owner/r/", "/owner/api/request/"))).json();
  assert.equal(realShown.counterparty.level, "domain");

  // Signed anyway (she may have checked by phone): the commitment and the history keep saying NOT VERIFIED.
  assert.equal((await postJson(app, "/owner/api/request/" + linkId, { signature: marta.sign(null, { challenge: fromBase64url(shown.challenge) }) })).status, 200);
  const w2 = await Wallet.open(new HostedWalletStorage(kv, deps.secret, `${owner}:0`), deps.register, { ownerResolver: deps.ownerResolver!, now: clock });
  const offer = await w2.proposeApproved({ clausesRoot: req.clauses_root });
  const acc = await impWallet.accept(offer);
  await w2.confirm(acc.confirmation);
  const st = await (await app("/owner/api/state", { headers: await signIn(app, marta) })).json();
  assert.equal(st.commitments.open[0].with[0].owner, "museo.example");
  assert.equal(st.commitments.open[0].with[0].level, "unverified");
  assert.deepEqual(st.history[0].parties, [{ owner: "museo.example", level: "unverified" }]);
  assert.equal(st.commitments.waiting_for_owner[0].with[0].level, "domain");
  // The page shows it prominently (English and Italian).
  const html = await (await app("/owner")).text();
  assert.match(html, /notVerified: "NOT VERIFIED", notChecked: "IDENTITY NOT CHECKED", claims: "claims"/);
  assert.match(html, /notVerified: "NON VERIFICATO"/);
  assert.match(html, /el\("dd", \{ class: "big" \}, party\(r\.counterparty\)\)/);
});

// ---------- A3 ----------

test("hosted security A3: the consent page leads with the return address, the name is cleaned and marked self-declared, unknown addresses are warned", async () => {
  assert.equal(cleanClientName("Claude\u200b (Anthropic) \u2013 official\u202e"), "Claude (Anthropic) \u2013 official");
  assert.equal(cleanClientName("A\u2066B\u2069C\u00adD\ufeffE\u3164F\u0000"), "ABCDEF");
  assert.equal(cleanClientName("e\u0301\u0301\u0301\u0301x"), "\u00e9\u0301x", "no stacks of combining marks (one at most)");
  assert.equal(cleanClientName("Assistente   di\nMarta"), "Assistente di Marta");
  assert.equal(returnAddress("https://claude.ai/api/mcp/auth_callback").kind, "known");
  assert.equal(returnAddress("https://claude.ai.connect-callback.example/cb").kind, "web");
  assert.equal(returnAddress("http://127.0.0.1:33418/callback").kind, "device");
  assert.equal(returnAddress("cursor://anysphere.cursor-mcp/oauth/callback").kind, "app");

  const { app } = await city();
  const marta = newDevice();
  await connect(app, marta, { create: true });
  const evil = "https://claude.ai.connect-callback.example/cb";
  const reg = await (await registerClient(app, { redirect_uris: [evil], client_name: "Claude\u200b (Anthropic) \u2013 official\u202e" })).json();
  assert.equal(reg.client_name, "Claude (Anthropic) \u2013 official");
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: evil, code_challenge: toBase64url(new Uint8Array(32)), code_challenge_method: "S256" });
  const page = await app("/authorize?" + q);
  const html = await page.clone().text();
  const model = await modelOf(page);
  assert.equal(model.redirectHost, "claude.ai.connect-callback.example");
  assert.equal(model.returnKind, "web");
  assert.ok(!/[\u200b\u202e]/.test(model.client));
  assert.match(html, /not a well-known assistant/);
  assert.match(html, /name chosen by the requester, not verified/);
  assert.match(html, /T\.sentBackTo\), el\("p", \{ class: "big" \}, MODEL\.redirectHost\)/, "the return address is the headline");
});

test("hosted security A3: the owner sees her connected assistants and disconnects one; a reused refresh token ends its connection", async () => {
  const { app } = await city();
  const marta = newDevice();
  const first = await connect(app, marta, { create: true });
  const other = await connectAs(app, marta, "Another\u200b assistant", "https://other.example/cb");
  const auth = await signIn(app, marta);
  let st = await (await app("/owner/api/state", { headers: auth })).json();
  assert.deepEqual(st.assistants.map((x: { name: string; return_host: string }) => [x.name, x.return_host]), [["Assistente di Marta", "assistant.example"], ["Another assistant", "other.example"]]);

  // Disconnect the second: its access and refresh tokens stop at once; the first keeps working.
  const id = st.assistants[1].id;
  assert.equal((await postJson(app, "/owner/api/disconnect", { id }, auth)).status, 200);
  assert.equal(await whoamiOk(app, other.tok.access_token), false);
  assert.equal((await (await tokenReq(app, { grant_type: "refresh_token", refresh_token: other.tok.refresh_token, client_id: other.client_id })).json()).error, "invalid_grant");
  assert.ok((await first.call("symbolon_whoami")).agent);
  st = await (await app("/owner/api/state", { headers: auth })).json();
  assert.equal(st.assistants.length, 1);
  assert.equal((await postJson(app, "/owner/api/disconnect", { id }, auth)).status, 404);
  assert.equal((await postJson(app, "/owner/api/disconnect", { id: st.assistants[0].id })).status, 401, "only with her session");

  // A refresh token used twice was copied: the whole connection ends (the tokens issued from it too).
  const r1 = await (await first.tokenReq({ grant_type: "refresh_token", refresh_token: first.tok.refresh_token, client_id: first.client_id })).json();
  assert.ok(r1.access_token);
  assert.equal(await whoamiOk(app, r1.access_token), true);
  assert.equal((await (await first.tokenReq({ grant_type: "refresh_token", refresh_token: first.tok.refresh_token, client_id: first.client_id })).json()).error, "invalid_grant");
  assert.equal(await whoamiOk(app, r1.access_token), false, "the thief's copy and the rightful one both end");
  assert.equal((await (await first.tokenReq({ grant_type: "refresh_token", refresh_token: r1.refresh_token, client_id: first.client_id })).json()).error, "invalid_grant");
  assert.equal((await (await app("/owner/api/state", { headers: auth })).json()).assistants.length, 0);
});

// ---------- A4 ----------

test("hosted security A4: connection pages store nothing, registrations are capped per client, expired records and unused assistants are collected", async () => {
  const { app, kv, advance, now } = await city();
  const reg = await (await registerClient(app, { redirect_uris: [REDIRECT], client_name: "x" })).json();
  const before = kv.map.size;
  for (let i = 0; i < 50; i++) {
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: toBase64url(new Uint8Array(32)), code_challenge_method: "S256", state: "s".repeat(512) });
    assert.equal((await app("/authorize?" + q)).status, 200);
  }
  assert.equal(kv.map.size, before, "GET /authorize writes nothing");

  // A forged or altered ticket is refused.
  const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: toBase64url(new Uint8Array(32)), code_challenge_method: "S256" });
  const ticket: string = (await modelOf(await app("/authorize?" + q))).request;
  const [payload, mac] = ticket.split(".");
  const evil = toBase64url(utf8(JSON.stringify({ ...JSON.parse(new TextDecoder().decode(fromBase64url(payload!))), redirect_uri: "https://evil.example/cb" })));
  assert.equal((await postJson(app, "/auth/challenge", { purpose: "authorize:" + evil + "." + mac })).status, 400);
  // A ticket is answered once.
  const device = newDevice();
  const ch1 = await (await postJson(app, "/auth/challenge", { purpose: "authorize:" + ticket })).json();
  const first = await postJson(app, "/auth/signup", { nonce: ch1.nonce, ...registration(device, ch1.challenge) });
  const { confirm } = await first.json();
  assert.equal((await postJson(app, "/auth/signup/confirm", { nonce: confirm.nonce, signature: device.sign(null, { challenge: fromBase64url(confirm.challenge) }) })).status, 200);
  const ch2 = await (await postJson(app, "/auth/challenge", { purpose: "authorize:" + ticket })).json();
  const again = await postJson(app, "/auth/signin", { nonce: ch2.nonce, credentialId: device.credentialId, signature: device.sign(null, { challenge: fromBase64url(ch2.challenge) }) });
  assert.equal(again.status, 400);
  // Expired tickets are refused.
  advance(16 * 60_000);
  assert.equal((await postJson(app, "/auth/challenge", { purpose: "authorize:" + ticket })).status, 400);

  // Registrations: at most MAX_REGISTRATIONS_PER_DAY per client per day (an IPv6 /64 is one client).
  const ip = (i: number) => ({ "cf-connecting-ip": `2001:db8:1:2::${(i + 1).toString(16)}` });
  for (let i = 0; i < MAX_REGISTRATIONS_PER_DAY; i++) assert.equal((await registerClient(app, { redirect_uris: [REDIRECT] }, ip(i))).status, 201);
  assert.equal((await registerClient(app, { redirect_uris: [REDIRECT] }, ip(99))).status, 429);
  assert.equal((await registerClient(app, { redirect_uris: [REDIRECT] }, { "cf-connecting-ip": "2001:db8:1:3::1" })).status, 201, "another client is not affected");
  advance(DAY);
  assert.equal((await registerClient(app, { redirect_uris: [REDIRECT] }, ip(0))).status, 201, "a new day");

  // Challenges never answered, unused assistants: collected once expired.
  for (let i = 0; i < 20; i++) await postJson(app, "/auth/challenge", { purpose: "owner" });
  assert.ok(keysOf(kv, "chal:").length >= 20);
  advance(31 * DAY);
  // An assistant registered and never connected is forgotten after 30 days.
  assert.equal((await app("/authorize?" + q)).status, 400);
  const swept = await sweepHosted(kv, now());
  assert.ok(swept.deleted > 50);
  for (const p of ["chal:", "client:", "regs:", "areq-used:", "code:", "signup:"]) assert.equal(keysOf(kv, p).length, 0, p);
  assert.ok(keysOf(kv, "acct:").length === 1, "accounts are kept");
  // The sweep works in slices and resumes where it stopped.
  for (let i = 0; i < 30; i++) await postJson(app, "/auth/challenge", { purpose: "owner" });
  advance(DAY);
  let r = await sweepHosted(kv, now(), { budget: 10 });
  assert.ok(r.next);
  while (r.next) r = await sweepHosted(kv, now(), { budget: 10, from: r.next });
  assert.equal(keysOf(kv, "chal:").length, 0);
});

test("hosted security A4: the worker rate-limits every method per client key (IPv6 by /64), and the Durable Object sweeps on an alarm", async () => {
  const { default: worker, WalletHome } = await import("../worker/wallet-worker.js");
  const keys: string[] = [];
  const env = {
    WALLET: { idFromName: () => "x", get: () => ({ fetch: async () => new Response("ok") }) },
    WALLET_LIMIT: { limit: async (o: { key: string }) => (keys.push(o.key), { success: keys.length <= 2 }) },
  } as never;
  assert.equal((await worker.fetch(new Request(ORIGIN + "/authorize?x", { headers: { "cf-connecting-ip": "2001:db8:aa:bb:1:2:3:4" } }), env)).status, 200);
  assert.equal((await worker.fetch(new Request(ORIGIN + "/register", { method: "POST", headers: { "cf-connecting-ip": "2001:db8:aa:bb::9" } }), env)).status, 200);
  assert.equal((await worker.fetch(new Request(ORIGIN + "/authorize?y", { headers: { "cf-connecting-ip": "2001:db8:aa:bb::10" } }), env)).status, 429, "GET is limited too");
  assert.deepEqual(keys, ["v6:2001:0db8:00aa:00bb", "v6:2001:0db8:00aa:00bb", "v6:2001:0db8:00aa:00bb"]);

  const mem = new MemoryKeyValue();
  let alarm: number | null = null;
  const storage = {
    get: (k: string) => mem.get(k),
    put: (k: string, v: unknown) => mem.put(k, v),
    delete: async (k: string) => (await mem.delete(k), true),
    list: (o: { prefix: string; limit: number; startAfter?: string }) => mem.list(o),
    getAlarm: async () => alarm,
    setAlarm: async (t: number) => void (alarm = t),
  };
  await putExpiring(mem, "chal:old", { x: 1 }, Date.now() - 1);
  await putExpiring(mem, "chal:new", { x: 1 }, Date.now() + 60_000);
  await mem.put("acct:someone", { x: 1 });
  const home = new WalletHome({ storage: storage as never }, { WALLET_SECRET: toBase64url(new Uint8Array(32)), REGISTER_URL: "https://reg.example", ORIGIN, REGISTER: { fetch: async () => new Response("{}") } } as never);
  await home.fetch(new Request(ORIGIN + "/"));
  assert.ok(alarm && alarm > Date.now(), "the first request arms the sweep");
  await home.alarm();
  assert.deepEqual([...mem.map.keys()].sort(), ["acct:someone", "chal:new"]);
  assert.ok(alarm! > Date.now() + 30 * 60_000, "and it re-arms itself");
});

// ---------- A5 ----------

test("hosted security A5: an MCP body over 1 MB is refused before it is read in full or acted on", async () => {
  const { app, kv } = await city();
  const c = await connect(app, newDevice(), { create: true });
  const capsKey = keysOf(kv, "caps:")[0]!;
  const caps = () => (kv.map.get(capsKey) as { v: { url: boolean } }).v.url;
  assert.equal(caps(), false);
  const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: { elicitation: { url: {} } }, clientInfo: { name: "x", version: "0" } } };
  const big = JSON.stringify([init, { jsonrpc: "2.0", method: "notifications/x", params: { pad: "A".repeat(MAX_MCP_BODY) } }]);
  // Declared too large: refused without reading.
  const declared = await mcpPost(app, c.tok.access_token, big, { "content-length": String(big.length) });
  assert.equal(declared.status, 413);
  // Not declared (streamed): reading stops past the limit.
  let pulled = 0;
  const chunk = utf8(big.slice(0, 64 * 1024));
  const stream = new ReadableStream<Uint8Array>({
    pull(ctl) {
      pulled += chunk.length;
      if (pulled > 20 * MAX_MCP_BODY) ctl.close();
      else ctl.enqueue(chunk);
    },
  });
  const streamed = await app(ORIGIN + "/mcp", { method: "POST", headers: { authorization: "Bearer " + c.tok.access_token, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: stream, duplex: "half" } as RequestInit);
  assert.equal(streamed.status, 413);
  assert.ok(pulled < 2 * MAX_MCP_BODY, `read ${pulled} bytes`);
  assert.equal(caps(), false, "nothing of the oversized body was acted on");
  // A normal request still works, and the SDK gets the same body.
  assert.ok((await c.call("symbolon_whoami")).agent);
  // Other JSON endpoints are bounded too.
  assert.equal((await postJson(app, "/auth/challenge", { purpose: "owner", pad: "x".repeat(100_000) })).status, 413);
});

// ---------- A6 ----------

test("hosted security A6: request links are deleted when they leave the owner's list or expire, never only forgotten", async () => {
  const { app, kv, advance, now } = await city();
  const a = await connect(app, newDevice(), { create: true });
  for (let i = 0; i < 70; i++) await a.call("symbolon_ask_owner_for_mandate", { scope: "lavori " + i, days: 1 });
  assert.equal(keysOf(kv, "link:").length, 50);
  advance(8 * DAY);
  await sweepHosted(kv, now());
  assert.equal(keysOf(kv, "link:").length, 0);
});

// ---------- A7 ----------

test("hosted security A7: a wallet is created only after the new passkey signs: copying someone's public key opens nothing", async () => {
  const { app, kv } = await city();
  const victim = newDevice();
  const attacker = newDevice();
  const ch = await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json();
  // The attacker sends a registration carrying the victim's public key (it is public: in every mandate).
  const reg = registration(victim, ch.challenge);
  const first = await postJson(app, "/auth/signup", { nonce: ch.nonce, ...reg });
  assert.equal(first.status, 200);
  const { confirm } = await first.json();
  assert.equal(keysOf(kv, "acct:").length, 0, "no account before the proof");
  // It cannot sign with the victim's key.
  const bad = await postJson(app, "/auth/signup/confirm", { nonce: confirm.nonce, signature: attacker.sign(null, { challenge: fromBase64url(confirm.challenge) }) });
  assert.equal(bad.status, 401);
  assert.equal(keysOf(kv, "acct:").length, 0);
  assert.equal(keysOf(kv, "cred:").length, 0);
  // The proof works once and only for its challenge.
  assert.equal((await postJson(app, "/auth/signup/confirm", { nonce: confirm.nonce, signature: victim.sign(null, { challenge: fromBase64url(confirm.challenge) }) })).status, 400);
  // The real owner: registration, then her passkey signs, then the wallet exists.
  const ch2 = await (await postJson(app, "/auth/challenge", { purpose: "owner" })).json();
  const ok1 = await (await postJson(app, "/auth/signup", { nonce: ch2.nonce, ...registration(victim, ch2.challenge) })).json();
  const ok2 = await postJson(app, "/auth/signup/confirm", { nonce: ok1.confirm.nonce, signature: victim.sign(null, { challenge: fromBase64url(ok1.confirm.challenge) }) });
  assert.equal(ok2.status, 200);
  assert.ok((await ok2.json()).session);
  assert.equal(keysOf(kv, "acct:").length, 1);
  // The page script makes the second step.
  assert.match(await (await app("/owner")).text(), /\/auth\/signup\/confirm/);
});

// ---------- A8 ----------

test("hosted security A8: every wallet (Block everything too) is opened inside the owner's lock", async () => {
  class WatchedLock extends KeyedLock {
    readonly active = new Set<string>();
    override async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
      return super.run(key, async () => {
        this.active.add(key);
        try {
          return await fn();
        } finally {
          this.active.delete(key);
        }
      });
    }
  }
  const lock = new WatchedLock();
  const outside: string[] = [];
  const kv = new MemoryKeyValue();
  const get = kv.get.bind(kv);
  kv.get = async <T>(k: string) => {
    if (k.startsWith("wallet:") && !lock.active.has(k.split(":")[1]!)) outside.push(k);
    return get<T>(k);
  };
  const { app } = await city({ kv, lock });
  const marta = newDevice();
  const c = await connect(app, marta, { create: true });
  await c.call("symbolon_whoami");
  const auth = await signIn(app, marta);
  await app("/owner/api/state", { headers: auth });
  await app("/owner/api/export", { headers: auth });
  const b = await (await app("/owner/api/block", { headers: auth })).json();
  assert.equal((await postJson(app, "/owner/api/block", { body: b.body, signature: marta.sign(null, { challenge: fromBase64url(b.challenge) }) }, auth)).status, 200);
  assert.deepEqual(outside, []);

  // The race of the attack test: the block page and the assistant's first call on a new, empty agent slot see one agent.
  const again = await connect(app, marta, { create: false });
  for (const k of keysOf(kv, "wallet:")) if (k.endsWith(":1")) kv.map.delete(k);
  const auth2 = await signIn(app, marta);
  const [page, who] = await Promise.all([app("/owner/api/block", { headers: auth2 }).then((r) => r.json()), again.call("symbolon_whoami")]);
  const st = await (await app("/owner/api/state", { headers: auth2 })).json();
  assert.equal(page.body.target.key, st.agent);
  assert.equal(who.agent, st.agent);
});
