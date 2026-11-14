import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ForkDetected,
  Register,
  Witness,
  buildProof,
  commitClauses,
  createMandate,
  createRecord,
  disclose,
  entryHash,
  generateKeyPair,
  mandateId,
  signRecord,
  verifyProof,
} from "../src/index.js";
import { scenario } from "./helpers.js";

const failed = (r: { checks: { name: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.name);

test("a correctly sealed agreement verifies, revealing only the delivery date", async () => {
  const s = await scenario();
  const r = await verifyProof(s.proof([disclose(s.opened, "delivery")]), s.verifyOpts);
  assert.deepEqual(failed(r), []);
  assert.ok(r.valid);
  assert.deepEqual(r.disclosed, { delivery: "2026-12-10" });
  assert.equal(Object.values(r.levels).every((l) => l === "domain"), true);
});

test("the register receives nothing readable", async () => {
  const s = await scenario();
  assert.match(s.receipt.entry, /^[0-9a-f]{64}$/);
  const raw = JSON.stringify(s.record);
  for (const word of ["A4", "42000", "2026-12-10"]) assert.equal(raw.includes(word), false);
});

test("a changed clause is rejected", async () => {
  const s = await scenario();
  const d = { ...disclose(s.opened, "delivery"), value: "2027-03-01" };
  const r = await verifyProof(s.proof([d]), s.verifyOpts);
  assert.equal(r.valid, false);
  assert.deepEqual(failed(r), ['clause "delivery" belongs to the agreement']);
});

test("amount within the buyer's mandate passes, amount above fails", async () => {
  const s = await scenario();
  const ok = await verifyProof(s.proof([disclose(s.opened, "amount")]), s.verifyOpts);
  assert.ok(ok.valid);

  // Same parties, new agreement above the €50,000 limit.
  const opened = commitClauses([{ name: "amount", value: { value: "60000.00", currency: "EUR" } }]);
  let rec = createRecord({ ...s.record.body, clausesRoot: opened.root, clauseCount: opened.count, type: "accord/agreement" });
  rec = signRecord(signRecord(rec, s.buyer), s.seller);
  const receipt = await s.register.append(entryHash(rec));
  const prev = s.witnesses[0].lastSeen(receipt.head.log)!;
  const proofFromPrev = await s.register.consistency(prev.size, receipt.head.size);
  const cos = s.witnesses.map((w) => w.observe(receipt.head, proofFromPrev));
  const bad = await verifyProof(
    buildProof({ record: rec, mandates: [s.buyerMandate, s.sellerMandate], disclosures: [disclose(opened, "amount")], receipt, cosignatures: cos }),
    s.verifyOpts,
  );
  assert.equal(bad.valid, false);
  assert.equal(failed(bad).length, 1);
  assert.match(failed(bad)[0], /^amount within mandate/);
});

test("an agent without a mandate cannot bind anyone", async () => {
  const s = await scenario();
  const r = await verifyProof({ ...s.proof(), mandates: [s.sellerMandate] }, s.verifyOpts);
  assert.equal(r.valid, false);
  assert.ok(failed(r).some((n) => n.startsWith("mandate of agent")));
});

test("a mandate signed by someone other than the owner is rejected", async () => {
  const s = await scenario();
  const impostor = generateKeyPair();
  const fake = createMandate(impostor, {
    ownerDomain: "alfa.example",
    agent: s.buyer.publicKey,
    scope: "anything",
    ...s.validity,
  });
  let rec = createRecord({
    ...s.record.body,
    parties: [
      { agent: s.buyer.publicKey, mandate: mandateId(fake) },
      { agent: s.seller.publicKey, mandate: mandateId(s.sellerMandate) },
    ],
  });
  rec = signRecord(signRecord(rec, s.buyer), s.seller);
  const receipt = await s.register.append(entryHash(rec));
  const r = await verifyProof(
    buildProof({ record: rec, mandates: [fake, s.sellerMandate], disclosures: [], receipt, cosignatures: [] }),
    { ...s.verifyOpts, minWitnesses: 0 },
  );
  assert.deepEqual(failed(r), ["owner key published by alfa.example"]);
  assert.equal(r.levels[s.buyer.publicKey], "unverified");
});

test("an expired mandate is rejected", async () => {
  const s = await scenario();
  const late = new Register(generateKeyPair(), undefined, () => new Date("2028-06-01T00:00:00Z"));
  const receipt = await late.append(entryHash(s.record));
  const r = await verifyProof({ ...s.proof(), receipt, cosignatures: [] }, { ...s.verifyOpts, trustedLogs: [late.publicKey], minWitnesses: 0 });
  assert.equal(r.valid, false);
  assert.ok(failed(r).every((n) => n.includes("valid when sealed")));
});

test("a missing signature is rejected", async () => {
  const s = await scenario();
  const r = await verifyProof({ ...s.proof(), record: { ...s.record, signatures: s.record.signatures.slice(0, 1) } }, s.verifyOpts);
  assert.equal(r.valid, false);
});

test("an untrusted register or too few witnesses are rejected", async () => {
  const s = await scenario();
  const r1 = await verifyProof(s.proof(), { ...s.verifyOpts, trustedLogs: [] });
  assert.deepEqual(failed(r1), ["register is trusted"]);
  const r2 = await verifyProof(s.proof(), { ...s.verifyOpts, minWitnesses: 3 });
  assert.deepEqual(failed(r2), ["at least 3 independent witness(es)"]);
});

test("witnesses catch an operator rewriting history", async () => {
  const s = await scenario();
  for (let i = 0; i < 5; i++) {
    const head = (await s.register.append(String(i).repeat(64))).head;
    const prev = s.witnesses[0].lastSeen(head.log)!;
    s.witnesses[0].observe(head, await s.register.consistency(prev.size, head.size));
  }
  s.store.overwriteForTest(0, "cd".repeat(32));
  const head = await s.register.publishHead();
  const prev = s.witnesses[0].lastSeen(head.log)!;
  const p = await s.register.consistency(prev.size, head.size);
  assert.throws(() => s.witnesses[0].observe(head, p), ForkDetected);
});

test("a single agent can seal its own action", async () => {
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const register = new Register(generateKeyPair());
  const m = createMandate(owner, {
    ownerDomain: "spray.example",
    agent: agent.publicKey,
    scope: "customer support",
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2027-12-31T23:59:59Z",
    charter: "accord-charter/0.1",
  });
  const opened = commitClauses([
    { name: "instruction", value: "Refund order 1043 if the parcel is lost" },
    { name: "action", value: "Refunded 39.90 EUR on order 1043" },
  ]);
  let rec = createRecord({
    type: "accord/action",
    clausesRoot: opened.root,
    clauseCount: opened.count,
    parties: [{ agent: agent.publicKey, mandate: mandateId(m) }],
    charter: "accord-charter/0.1",
    createdAt: new Date().toISOString(),
  });
  rec = signRecord(rec, agent);
  const receipt = await register.append(entryHash(rec));
  const r = await verifyProof(
    buildProof({ record: rec, mandates: [m], disclosures: [disclose(opened, "action")], receipt, cosignatures: [] }),
    { trustedLogs: [register.publicKey] },
  );
  assert.deepEqual(failed(r), []);
  assert.equal(r.disclosed.action, "Refunded 39.90 EUR on order 1043");
});

test("records reject the wrong number of parties", () => {
  const base = { clausesRoot: "00".repeat(32), clauseCount: 1, charter: "c", createdAt: new Date().toISOString() };
  const p = { agent: generateKeyPair().publicKey, mandate: "x" };
  assert.throws(() => createRecord({ ...base, type: "accord/agreement", parties: [p] }));
  assert.throws(() => createRecord({ ...base, type: "accord/action", parties: [p, p] }));
});

test("a witness rejects a head with a bad signature", async () => {
  const reg = new Register(generateKeyPair());
  const head = (await reg.append("ef".repeat(32))).head;
  assert.throws(() => new Witness(generateKeyPair()).observe({ ...head, root: "00".repeat(32) }, []));
});
