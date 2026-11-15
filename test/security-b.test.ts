// Security review of 14/11/2026, group B (proofs and wallet): each test replays an attack that worked before the fix.

import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MemoryWalletStorage, Wallet, type Offer } from "../src/agent/wallet.js";
import { toHex, utf8 } from "../src/bytes.js";
import { canonical } from "../src/canonical.js";
import { leafHash } from "../src/hash.js";
import {
  MemoryStore,
  Register,
  buildProof,
  commitClauses,
  createMandate,
  createRecord,
  disclose,
  entryHash,
  generateKeyPair,
  isUsablePublicKey,
  mandateId,
  signRecord,
  staticOwnerResolver,
  treeRoot,
  verifyOpened,
  verifyProof,
  verifyValue,
  type KeyPair,
  type Mandate,
  type OpenedClauses,
} from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { scenario } from "./helpers.js";

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
const failed = (r: { checks: { name: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.name);

function mandateFor(owner: KeyPair, agent: string, domain: string, max?: string): Mandate {
  return createMandate(owner, {
    ownerDomain: domain,
    agent,
    scope: "office supplies",
    ...(max ? { maxAmount: { value: max, currency: "EUR" } } : {}),
    notBefore: later(-1),
    notAfter: later(30),
    charter: "accord-charter/0.1",
  });
}

/** Opened clauses built by hand, as an attacker would, bypassing commitClauses' checks. */
function handOpened(clauses: Array<{ name: string; value: unknown }>): OpenedClauses {
  const salted = clauses.map((c) => ({ ...c, salt: "ab".repeat(32) })) as OpenedClauses["clauses"];
  const leaves = salted.map((c) => leafHash(utf8(canonical({ n: c.name, s: c.salt, v: c.value }))));
  return { root: toHex(treeRoot(leaves)), count: salted.length, clauses: salted };
}

function registerSetup() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const f: typeof fetch = async (input, init) => handle(new Request(String(input), init), deps);
  return { deps, client: new HttpRegisterClient("https://reg.example", f) };
}

/** A victim wallet whose owner is verified, and an attacker with keys in hand (no wallet checks on its side). */
async function victimAndAttacker(attackerPublished: boolean) {
  const { deps, client } = registerSetup();
  const victimOwner = generateKeyPair();
  const attackerOwner = generateKeyPair();
  const attacker = generateKeyPair();
  const table: Record<string, string[]> = { "victim.example": [victimOwner.publicKey] };
  if (attackerPublished) table["attacker.example"] = [attackerOwner.publicKey];
  const victim = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver: staticOwnerResolver(table) });
  await victim.installMandate(mandateFor(victimOwner, victim.agentKey, "victim.example", "1000.00"));
  const attackerMandate = mandateFor(attackerOwner, attacker.publicKey, "attacker.example");
  const offer = (clauses: Array<{ name: string; value: unknown }>, extraParties: Array<{ agent: string; mandate: string }> = []): Offer => {
    const opened = handOpened(clauses);
    const record = signRecord(
      createRecord({
        type: "accord/agreement",
        clausesRoot: opened.root,
        clauseCount: opened.count,
        parties: [
          { agent: attacker.publicKey, mandate: mandateId(attackerMandate) },
          { agent: victim.agentKey, mandate: mandateId(victim.myMandate()) },
          ...extraParties,
        ],
        charter: "accord-charter/0.1",
        createdAt: new Date().toISOString(),
      }),
      attacker,
    );
    return { type: "accord/offer", record, opened, mandates: [attackerMandate] };
  };
  return { deps, victim, attacker, attackerOwner, attackerMandate, offer };
}

// B1 -----------------------------------------------------------------------------------------------

test("B1: an offer with two 'amount' clauses (1,000,000 and 1 EUR) is refused before signing", async () => {
  const { deps, victim, offer } = await victimAndAttacker(true);
  const evil = offer([
    { name: "amount", value: { value: "1000000.00", currency: "EUR" } },
    { name: "amount", value: { value: "1.00", currency: "EUR" } },
  ]);
  assert.equal(verifyOpened(evil.opened), false);
  await assert.rejects(victim.accept(evil), /clauses do not match|repeated/);
  assert.equal(await deps.register.store.size(), 0, "nothing sealed");
});

test("B1: a '__proto__' clause is refused, and cannot hide the amount from the limit check", async () => {
  const { victim, offer } = await victimAndAttacker(true);
  const evil = offer([
    { name: "__proto__", value: { amount: { value: "1.00", currency: "EUR" } } },
    { name: "amount", value: { value: "999999.00", currency: "EUR" } },
  ]);
  await assert.rejects(victim.accept(evil));
  assert.throws(() => commitClauses([{ name: "__proto__", value: 1 }]), /cannot be used/);
});

test("B1: a proof that discloses the same clause twice, or a reserved name, is not valid", async () => {
  const s = await scenario();
  const amount = disclose(s.opened, "amount");
  const twice = await verifyProof(s.proof([amount, { ...amount }]), s.verifyOpts);
  assert.equal(twice.verdict, "invalid");
  assert.ok(failed(twice).some((n) => n.includes("disclosed only once")));

  const proto = await verifyProof(s.proof([amount, { ...disclose(s.opened, "delivery"), name: "__proto__" }]), s.verifyOpts);
  assert.equal(proto.verdict, "invalid");
  assert.equal(Object.getPrototypeOf(proto.disclosed), Object.prototype, "the report's object is ordinary, nothing polluted");
});

// B2 -----------------------------------------------------------------------------------------------

test("B2: amount hidden while a mandate has a limit is 'incomplete', with the reason", async () => {
  const s = await scenario();
  const r = await verifyProof(s.proof([disclose(s.opened, "delivery")]), s.verifyOpts);
  assert.equal(r.valid, false);
  assert.equal(r.verdict, "incomplete");
  assert.match(r.gaps.join(" "), /limit .* could not be checked/);
});

// B3 -----------------------------------------------------------------------------------------------

test("B3: a receipt asked for later carries the sealing time, and a later head is flagged", async () => {
  let clock = new Date("2026-06-01T10:00:00Z");
  const register = new Register(generateKeyPair(), new MemoryStore(), () => clock);
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  // The mandate expires on 2 June; the action is sealed on 1 June, while it was valid.
  const m = createMandate(owner, {
    ownerDomain: "alfa.example", agent: agent.publicKey, scope: "support",
    notBefore: "2026-05-01T00:00:00Z", notAfter: "2026-06-02T00:00:00Z", charter: "accord-charter/0.1",
  });
  const opened = commitClauses([{ name: "action", value: "refund 10 EUR" }]);
  const rec = signRecord(
    createRecord({ type: "accord/action", clausesRoot: opened.root, clauseCount: 1, parties: [{ agent: agent.publicKey, mandate: mandateId(m) }], charter: "accord-charter/0.1", createdAt: clock.toISOString() }),
    agent,
  );
  const entry = entryHash(rec);
  await register.append(entry);
  clock = new Date("2026-07-01T10:00:00Z"); // a month later, after the mandate expired
  for (let i = 0; i < 3; i++) await register.append(String(i).repeat(64));

  const receipt = await register.receipt(entry);
  assert.equal(receipt.head.size, receipt.index + 1);
  assert.equal(receipt.head.time, "2026-06-01T10:00:00.000Z");
  const opts = { trustedLogs: [register.publicKey], ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey] }), revocations: async () => [] };
  const good = await verifyProof(buildProof({ record: rec, mandates: [m], disclosures: [], receipt, cosignatures: [] }), opts);
  assert.equal(good.valid, true, JSON.stringify([good.gaps, failed(good)]));

  // Before the fix the receipt used the latest head: the honest action looked sealed after expiry.
  const latest = (await register.latestHead())!;
  const lateReceipt = { ...receipt, head: latest, path: await register.inclusion(receipt.index, latest.size) };
  const bad = await verifyProof(buildProof({ record: rec, mandates: [m], disclosures: [], receipt: lateReceipt, cosignatures: [] }), opts);
  assert.ok(failed(bad).includes("receipt is from the moment of sealing"));
});

// B5 -----------------------------------------------------------------------------------------------

test("B5: an offer from an owner whose key is not published is refused BEFORE signing and sealing", async () => {
  const { deps, victim, offer } = await victimAndAttacker(false);
  const o = offer([{ name: "object", value: "paper" }, { name: "amount", value: { value: "10.00", currency: "EUR" } }]);
  await assert.rejects(victim.accept(o), /counterparty not accepted: owner key not published by attacker\.example/);
  assert.equal(await deps.register.store.size(), 0, "nothing was signed or sealed");
  // Only an explicit choice of the owner lets it through.
  const ok = await victim.accept(o, { allowUnverifiedOwner: true });
  assert.equal(ok.counterparty.level, "unverified");
  assert.equal(await deps.register.store.size(), 1);
});

test("B5: every other party is checked, not only the first", async () => {
  const { deps, victim, offer } = await victimAndAttacker(true);
  const ghost = generateKeyPair();
  const ghostMandate = mandateFor(generateKeyPair(), ghost.publicKey, "ghost.example");
  const o = offer([{ name: "object", value: "paper" }], [{ agent: ghost.publicKey, mandate: mandateId(ghostMandate) }]);
  o.mandates.push(ghostMandate);
  await assert.rejects(victim.accept(o), /signature of agent .* missing or invalid/);
  assert.equal(await deps.register.store.size(), 0);
});

test("B5: an 'offer' that is really an action record is refused", async () => {
  const { victim } = await victimAndAttacker(true);
  const opened = commitClauses([{ name: "action", value: "x" }]);
  const record = createRecord({ type: "accord/action", clausesRoot: opened.root, clauseCount: 1, parties: [{ agent: victim.agentKey, mandate: mandateId(victim.myMandate()) }], charter: "accord-charter/0.1", createdAt: new Date().toISOString() });
  await assert.rejects(victim.accept({ type: "accord/offer", record, opened, mandates: [] }), /not an agreement/);
});

test("B5: proposing to an unverified owner is refused too, unless the owner allows it", async () => {
  const { victim, attackerMandate } = await victimAndAttacker(false);
  const clauses = { object: "paper", amount: { value: "10.00", currency: "EUR" } };
  await assert.rejects(victim.propose({ counterparty: attackerMandate, clauses }), /owner key not published/);
  const offer = await victim.propose({ counterparty: attackerMandate, clauses, allowUnverifiedOwner: true });
  assert.equal(offer.type, "accord/offer");
});

// B6 -----------------------------------------------------------------------------------------------

test("B6: a record with no parties and no signatures is not valid", async () => {
  const s = await scenario();
  const empty = { body: { ...s.record.body, parties: [] }, signatures: [] };
  const receipt = await s.register.append(entryHash(empty));
  const r = await verifyProof(buildProof({ record: empty, mandates: [], disclosures: [], receipt, cosignatures: [] }), { ...s.verifyOpts, minWitnesses: 0 });
  assert.equal(r.verdict, "invalid");
  assert.deepEqual(failed(r), ["proof file is well formed"]);
});

test("B6: a malformed proof file gives 'invalid' instead of crashing", async () => {
  const s = await scenario();
  for (const junk of [null, {}, { record: 1 }, { ...s.proof(), receipt: null }, { ...s.proof(), disclosures: [null] }]) {
    const r = await verifyProof(junk as never, s.verifyOpts);
    assert.equal(r.verdict, "invalid");
  }
});

// B7 -----------------------------------------------------------------------------------------------

test("B7: a small-order public key no longer 'verifies' a signature nobody made", () => {
  const identity = "ed25519:01" + "00".repeat(31);
  const forged = "01" + "00".repeat(31) + "00".repeat(32); // R = identity point, S = 0
  assert.equal(isUsablePublicKey(identity), false);
  assert.equal(verifyValue({ anything: "at all" }, forged, identity), false);
  assert.equal(isUsablePublicKey(generateKeyPair().publicKey), true);
});

// B8 -----------------------------------------------------------------------------------------------

test("B8: without an owner lookup the check says 'claims', and the proof is only 'incomplete'", async () => {
  const s = await scenario();
  const { ownerResolver: _, ...noOwner } = s.verifyOpts;
  const r = await verifyProof(s.proof([disclose(s.opened, "amount")]), noOwner);
  assert.equal(r.verdict, "incomplete");
  assert.ok(r.checks.some((c) => c.name.includes("signed by the owner key it names (claims alfa.example)")));
  assert.ok(!r.checks.some((c) => /signed by owner alfa\.example$/.test(c.name)));
  assert.match(r.gaps.join(" "), /owner of agent .* not checked/);
});
