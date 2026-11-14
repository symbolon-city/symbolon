import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import {
  MemoryStore,
  Register,
  buildProof,
  checkMandate,
  commitClauses,
  createMandate,
  createRecord,
  createRevocation,
  entryHash,
  generateKeyPair,
  mandateId,
  revokes,
  signRecord,
  staticOwnerResolver,
  verifyProof,
  type KeyPair,
  type Mandate,
} from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { handlePiazza } from "../src/piazza/app.js";
import { signEnvelope } from "../src/piazza/messages.js";
import { MemoryPiazzaStore } from "../src/piazza/stores.js";

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

function mandateFor(owner: KeyPair, agent: string, domain = "alfa.example"): Mandate {
  return createMandate(owner, { ownerDomain: domain, agent, scope: "support", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" });
}

function registerSetup() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const f: typeof fetch = async (input, init) => handle(new Request(String(input), init), deps);
  return { deps, client: new HttpRegisterClient("https://reg.example", f), f };
}

test("who may revoke what", () => {
  const owner = generateKeyPair();
  const second = generateKeyPair(); // another key published by the same owner domain
  const agent = generateKeyPair();
  const stranger = generateKeyPair();
  const m = mandateFor(owner, agent.publicKey);
  const published = [owner.publicKey, second.publicKey];
  const byMandate = (k: KeyPair) => createRevocation(k, { target: { kind: "mandate", id: mandateId(m) } });

  assert.equal(revokes(byMandate(owner), m), true, "the owner key withdraws its mandate");
  assert.equal(revokes(byMandate(agent), m), true, "the agent gives up its mandate");
  assert.equal(revokes(byMandate(stranger), m), false, "a stranger cannot");
  assert.equal(revokes(byMandate(second), m), false, "another key counts only if published by the owner");
  assert.equal(revokes(byMandate(second), m, published), true);
  assert.equal(revokes(createRevocation(second, { target: { kind: "mandate", id: mandateId(m) }, ownerDomain: "beta.example" }), m, published), false);

  assert.equal(revokes(createRevocation(owner, { target: { kind: "agent", key: agent.publicKey } }), m), true, "the owner stops an agent key");
  assert.equal(revokes(createRevocation(agent, { target: { kind: "agent", key: agent.publicKey } }), m), true, "the agent declares its own key stolen");
  assert.equal(revokes(createRevocation(stranger, { target: { kind: "agent", key: agent.publicKey } }), m), false);

  assert.equal(revokes(createRevocation(owner, { target: { kind: "owner-key", key: owner.publicKey } }), m), true, "the owner key revokes itself");
  assert.equal(revokes(createRevocation(second, { target: { kind: "owner-key", key: owner.publicKey } }), m, published), true);
  assert.equal(revokes(createRevocation(agent, { target: { kind: "owner-key", key: owner.publicKey } }), m), false, "an agent cannot revoke its owner's key");

  const forged = byMandate(owner);
  forged.body.reason = "changed after signing";
  assert.equal(revokes(forged, m), false);
  assert.throws(() => createRevocation(owner, { target: { kind: "mandate", id: "nope" } }));
  assert.throws(() => createRevocation(owner, { target: { kind: "agent", key: agent.publicKey }, reason: "x".repeat(201) }));
});

test("the register seals revocations, finds them by subject, and refuses bad ones", async () => {
  const { client, f } = registerSetup();
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const m = mandateFor(owner, agent.publicKey);
  await client.append("ab".repeat(32));
  const r = createRevocation(owner, { target: { kind: "mandate", id: mandateId(m) }, reason: "contract ended" });
  const sealed = await client.revoke(r);
  assert.equal(sealed.index, 1);
  assert.equal((await client.revoke(r)).index, 1, "sending it again changes nothing");
  assert.equal((await client.receipt(sealed.id))?.index, 1, "its fingerprint is in the register");
  const found = await client.revocations([mandateId(m), agent.publicKey]);
  assert.equal(found.length, 1);
  assert.deepEqual(found[0].revocation, r);
  assert.deepEqual(await client.revocations([generateKeyPair().publicKey]), []);

  const tampered = { ...r, body: { ...r.body, reason: "other" } };
  await assert.rejects(client.revoke(tampered), /signature is invalid/);
  const future = createRevocation(owner, { target: { kind: "agent", key: agent.publicKey }, createdAt: later(1) });
  await assert.rejects(client.revoke(future), /future/);
  assert.equal((await f("https://reg.example/v1/revocations?subject=bad")).status, 400);
  const one = (await (await f(`https://reg.example/v1/revocations/${sealed.id}`)).json()) as any;
  assert.equal(one.receipt.index, 1);
});

test("a revoked mandate fails the counterparty check, with when and why", async () => {
  const { client } = registerSetup();
  const owner = generateKeyPair();
  const m = mandateFor(owner, generateKeyPair().publicKey);
  const opts = { ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey] }), revocations: (s: string[]) => client.revocations(s) };
  const before = await checkMandate(m, opts);
  assert.equal(before.ok, true);
  assert.equal(before.revocations, "checked");
  await client.revoke(createRevocation(owner, { target: { kind: "owner-key", key: owner.publicKey }, reason: "key stolen" }));
  const after = await checkMandate(m, opts);
  assert.equal(after.ok, false);
  assert.equal(after.revoked?.reason, "key stolen");
  assert.match(after.problems.join(), /revoked/);
  const offline = await checkMandate(m, { ...opts, revocations: async () => Promise.reject(new Error("down")) });
  assert.equal(offline.ok, false);
  assert.equal(offline.revocations, "not checked");
});

test("records sealed before a revocation stay valid; after it the wallet refuses and proofs fail", async () => {
  const { client } = registerSetup();
  const owner = generateKeyPair();
  const ownerResolver = staticOwnerResolver({ "alfa.example": [owner.publicKey] });
  const wallet = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver });
  const m = mandateFor(owner, wallet.agentKey);
  await wallet.installMandate(m);
  const early = await wallet.sealAction({ instruction: "refund order 7", action: "refunded 12.00 EUR" });

  await client.revoke(createRevocation(owner, { target: { kind: "mandate", id: mandateId(m) }, reason: "agent replaced" }));

  const report = await wallet.verify(await wallet.createProof(early.entry, ["action"]));
  assert.equal(report.valid, true, JSON.stringify(report.checks.filter((c) => !c.ok)));
  assert.match(report.checks.find((c) => c.name.includes("not revoked"))!.detail!, /revoked later/);

  await assert.rejects(wallet.sealAction({ instruction: "refund order 8", action: "refunded 9.00 EUR" }), /revoked/);
  await assert.rejects(wallet.installMandate(m), /revoked/);

  // An agent that ignores the revocation (no wallet) and seals anyway: the proof shows it.
  const rogue = generateKeyPair();
  const rm = mandateFor(owner, rogue.publicKey);
  await client.revoke(createRevocation(owner, { target: { kind: "agent", key: rogue.publicKey } }));
  const opened = commitClauses([{ name: "action", value: "paid 500.00 EUR" }]);
  const record = signRecord(
    createRecord({ type: "accord/action", clausesRoot: opened.root, clauseCount: opened.count, parties: [{ agent: rogue.publicKey, mandate: mandateId(rm) }], charter: "accord-charter/0.1", createdAt: new Date().toISOString() }),
    rogue,
  );
  const receipt = await client.append(entryHash(record));
  const info = await client.info();
  const bad = await verifyProof(buildProof({ record, mandates: [rm], disclosures: [], receipt, cosignatures: [] }), {
    trustedLogs: [info.register_key],
    ownerResolver,
    revocations: (s) => client.revocations(s),
  });
  assert.equal(bad.valid, false);
  assert.match(bad.checks.find((c) => c.name.includes("not revoked"))!.detail!, /revoked on/);
});

test("the piazza refuses envelopes signed under a revoked mandate", async () => {
  const { client } = registerSetup();
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const m = mandateFor(owner, agent.publicKey);
  const deps = {
    store: new MemoryPiazzaStore(),
    ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey] }),
    origin: "https://piazza.example",
    revocations: (s: string[]) => client.revocations(s),
  };
  const post = { kind: "offer", category: "translation", title: "Italian to English", text: "Short technical translations within two days.", expiresAt: later(7) };
  const send = () =>
    handlePiazza(new Request("https://piazza.example/v1/envelopes", { method: "POST", body: JSON.stringify(signEnvelope(agent, m, "https://piazza.example", { op: "post", post } as any)) }), deps);
  const created = (await (await send()).json()) as any;
  const id = created.post.id;
  const get = async (path: string, d: typeof deps = deps) => (await (await handlePiazza(new Request("https://piazza.example" + path), d)).json()) as any;
  assert.equal((await get("/v1/posts")).posts.length, 1);

  await client.revoke(createRevocation(agent, { target: { kind: "agent", key: agent.publicKey }, reason: "my key leaked" }));
  const refused = await send();
  assert.equal(refused.status, 403);
  assert.match(((await refused.json()) as any).error, /revoked/);

  // Its earlier post leaves the board too (checked again after the cache time).
  assert.equal((await get("/v1/posts")).posts.length, 1, "still cached as clean");
  const fresh = { ...deps, revocationCacheMs: 0 };
  assert.equal((await get("/v1/posts", fresh)).posts.length, 0);
  assert.equal((await get(`/v1/posts/${id}`, fresh)).status, "revoked");
  assert.equal((await get("/v1/summary", fresh)).activePosts, 0);

  // A reader cannot reply to it any more.
  const other = generateKeyPair();
  const otherOwner = generateKeyPair();
  const om = createMandate(otherOwner, { ownerDomain: "beta.example", agent: other.publicKey, scope: "piazza", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" });
  const reply = await handlePiazza(
    new Request("https://piazza.example/v1/envelopes", { method: "POST", body: JSON.stringify(signEnvelope(other, om, "https://piazza.example", { op: "contact", postId: id, reply: "interested" } as any)) }),
    { ...fresh, ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey], "beta.example": [otherOwner.publicKey] }) },
  );
  assert.equal(reply.status, 404);
});

test("the piazza keeps showing posts when the register cannot be reached", async () => {
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const m = mandateFor(owner, agent.publicKey);
  let down = false;
  const { client } = registerSetup();
  const deps = {
    store: new MemoryPiazzaStore(),
    ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey] }),
    origin: "https://piazza.example",
    revocations: (s: string[]) => (down ? Promise.reject(new Error("down")) : client.revocations(s)),
    revocationCacheMs: 0,
  };
  const post = { kind: "seek", category: "translation", title: "English to Italian", text: "One page, technical, within a week.", expiresAt: later(7) };
  const res = await handlePiazza(new Request("https://piazza.example/v1/envelopes", { method: "POST", body: JSON.stringify(signEnvelope(agent, m, "https://piazza.example", { op: "post", post } as any)) }), deps);
  assert.equal(res.status, 201);
  down = true;
  const list = (await (await handlePiazza(new Request("https://piazza.example/v1/posts"), deps)).json()) as any;
  assert.equal(list.posts.length, 1);
});
