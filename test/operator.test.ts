// Automatic mode: the operator joins once, each request of a person becomes a task mandate, and chains of
// sub-mandates can never give more than they received.

import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import {
  MemoryStore,
  Operator,
  Register,
  checkMandate,
  createMandate,
  createRevocation,
  createSubMandate,
  generateKeyPair,
  keyPairFromSecret,
  mandateId,
  revokeIssuing,
  setupOperator,
  signValue,
  staticOwnerResolver,
  taskMatches,
  verifyMandateSignature,
  type Mandate,
  type SubMandateBody,
  type Task,
} from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

const EUR = (value: string) => ({ value, currency: "EUR" });
const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

async function city() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const client = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), deps));
  const setup = setupOperator({ domain: "assistant.example", capPerAgreement: EUR("500.00") });
  const table: Record<string, string[]> = { "assistant.example": setup.ownerFile.keys };
  // A translation agency with an ordinary owner mandate.
  const agencyOwner = generateKeyPair();
  table["agency.example"] = [agencyOwner.publicKey];
  const resolver = staticOwnerResolver(table);
  const agency = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver: resolver });
  await agency.installMandate(
    createMandate(agencyOwner, { ownerDomain: "agency.example", agent: agency.agentKey, scope: "translations", maxAmount: EUR("2000.00"), notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" }),
  );
  const operator = new Operator({ issuerSecretHex: setup.issuerSecretHex, issuingMandate: setup.issuingMandate, confirmAbove: EUR("300.00"), capPerTask: EUR("1000.00") });
  const taskWallet = async (t: Task) => {
    const storage = new MemoryWalletStorage();
    await storage.save({ v: 1, agentSecret: t.agentSecretHex, records: {}, offers: {} });
    const tw = await Wallet.open(storage, client, { ownerResolver: resolver });
    await tw.installMandate(t.mandate);
    return tw;
  };
  return { deps, client, setup, operator, agency, resolver, taskWallet, table };
}

const asTask = (x: ReturnType<Operator["newTask"]>): Task => {
  if ("needsConfirmation" in x) throw new Error("unexpected confirmation request");
  return x;
};

test("a person's request becomes a task mandate; the agent closes a deal; the proof is valid and private", async () => {
  const c = await city();
  const instruction = "Find someone to translate my 10-page contract into Spanish, at most 50 euros";
  const task = asTask(c.operator.newTask({ instruction, principalId: "customer-8812", scope: "translation of a document", total: EUR("50.00") }));
  assert.equal(task.mandate.body.type, "symbolon/submandate");
  assert.ok(!JSON.stringify(task.mandate).includes("customer-8812") && !JSON.stringify(task.mandate).includes("contract"), "nothing personal in the mandate");
  assert.ok(verifyMandateSignature(task.mandate));

  const agent = await c.taskWallet(task);
  const seen = await c.agency.checkCounterparty(task.mandate);
  assert.equal(seen.ok, true, seen.problems.join("; "));
  assert.equal(seen.level, "domain");
  assert.equal(seen.owner, "assistant.example");
  assert.deepEqual(seen.via, { links: 2, task: true });

  const offer = await agent.propose({ counterparty: c.agency.myMandate(), clauses: { service: "translation EN to ES, 10 pages", amount: EUR("45.00") } });
  const { entry, confirmation } = await c.agency.accept(offer);
  await agent.confirm(confirmation);
  const report = await c.agency.verify(await agent.createProof(entry, ["service", "amount"]));
  assert.equal(report.verdict, "valid", JSON.stringify([report.gaps, report.checks.filter((x) => !x.ok)]));

  // In a dispute the operator proves which instruction and customer, with the salt it kept.
  assert.ok(taskMatches(task.mandate, instruction, "customer-8812", task.salt));
  assert.ok(!taskMatches(task.mandate, instruction.replace("50", "500"), "customer-8812", task.salt));
});

test("the task total holds across several agreements", async () => {
  const c = await city();
  const agent = await c.taskWallet(asTask(c.operator.newTask({ instruction: "x", principalId: "p", total: EUR("50.00") })));
  const deal = async (v: string) => {
    const offer = await agent.propose({ counterparty: c.agency.myMandate(), clauses: { service: "part", amount: EUR(v) } });
    const { confirmation } = await c.agency.accept(offer);
    await agent.confirm(confirmation);
  };
  await deal("30.00");
  await assert.rejects(deal("30.00"), /at most 50\.00 EUR in total/);
  await deal("20.00");
  await assert.rejects(agent.propose({ counterparty: c.agency.myMandate(), clauses: { service: "more", amount: EUR("0.01") } }), /in total/);
});

test("the operator's fixed rules, not the AI, decide: caps, confirmation above a threshold", async () => {
  const c = await city();
  assert.throws(() => c.operator.newTask({ instruction: "spend 5000", principalId: "p", total: EUR("5000.00") }), /at most 1000\.00 EUR per task/);
  const ask = c.operator.newTask({ instruction: "up to 400", principalId: "p", total: EUR("400.00") });
  assert.ok("needsConfirmation" in ask && ask.question === "Confirm up to 400.00 EUR?");
  const ok = asTask(c.operator.newTask({ instruction: "up to 400", principalId: "p", total: EUR("400.00"), confirmed: true }));
  // Per agreement it can never exceed the issuing mandate's cap of 500.
  assert.deepEqual(ok.mandate.body.maxAmount, EUR("400.00"));
});

test("a sub-mandate can never give more than it received", async () => {
  const c = await city();
  const issuer = keyPairFromSecret(c.setup.issuerSecretHex);
  const base = { agent: generateKeyPair().publicKey, scope: "x", notBefore: new Date().toISOString(), notAfter: later(1) };
  assert.throws(() => createSubMandate(issuer, c.setup.issuingMandate, { ...base, maxAmount: EUR("600.00") }), /bigger amount/);
  assert.throws(() => createSubMandate(issuer, c.setup.issuingMandate, { ...base }), /bigger amount/, "a capped parent needs a capped child");
  assert.throws(() => createSubMandate(issuer, c.setup.issuingMandate, { ...base, maxAmount: EUR("10.00"), notAfter: later(365) }), /outside the dates/);
  assert.throws(() => createSubMandate(issuer, c.setup.issuingMandate, { ...base, maxAmount: { value: "10.00", currency: "USD" } }), /bigger amount/);
  assert.throws(() => createSubMandate(generateKeyPair(), c.setup.issuingMandate, { ...base, maxAmount: EUR("10.00") }), /only the agent/);
});

test("forged chains are refused: changed limits, another owner, a wrong parent, a missing link, too many links", async () => {
  const c = await city();
  const task = asTask(c.operator.newTask({ instruction: "x", principalId: "p", total: EUR("50.00") }));
  const issuerKey = keyPairFromSecret(c.setup.issuerSecretHex);
  const resign = (body: SubMandateBody, key = issuerKey): Mandate => ({ body, signature: signValue(body, key), chain: task.mandate.chain });
  const b = task.mandate.body as SubMandateBody;

  // Raising the limit after signing breaks the signature; re-signing with the right key is caught by the chain rule.
  assert.equal(verifyMandateSignature({ ...task.mandate, body: { ...b, total: EUR("5000.00") } }), false);
  assert.equal(verifyMandateSignature(resign({ ...b, total: EUR("5000.00"), maxAmount: EUR("5000.00") })), false);
  // Claiming a bigger owner.
  assert.equal(verifyMandateSignature(resign({ ...b, owner: { domain: "bigbank.example", key: b.owner.key } })), false);
  // Signed by a stranger who writes the issuer's key as issuer.
  const stranger = generateKeyPair();
  assert.equal(verifyMandateSignature(resign(b, stranger)), false);
  // A stranger making its own issuing mandate under the operator's name (not signed by the owner key).
  const fakeTop = createMandate(stranger, { ownerDomain: "assistant.example", agent: issuerKey.publicKey, scope: "x", maxAmount: EUR("500.00"), notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" });
  const onFake = createSubMandate(issuerKey, fakeTop, { agent: generateKeyPair().publicKey, scope: "x", maxAmount: EUR("10.00"), notBefore: new Date().toISOString(), notAfter: later(1) });
  assert.equal(verifyMandateSignature(onFake), true, "the chain itself is consistent...");
  const seen = await checkMandate(onFake, { ownerResolver: c.resolver });
  assert.equal(seen.ok, false, "...but the owner key at the top is not the one published by assistant.example");
  assert.equal(seen.level, "unverified");
  // Wrong parent id, missing chain, chain with an extra field.
  assert.equal(verifyMandateSignature(resign({ ...b, parent: "00".repeat(32) })), false);
  assert.equal(verifyMandateSignature({ body: b, signature: task.mandate.signature }), false);
  // Too many links: owner → issuer → A → B → C (5 links).
  const kA = generateKeyPair(), kB = generateKeyPair(), kC = generateKeyPair();
  const start = new Date().toISOString(), end = later(0.9);
  const mk = (k: { publicKey: string }, parentKey: typeof issuerKey, parent: Mandate) =>
    createSubMandate(parentKey, parent, { agent: k.publicKey, scope: "x", maxAmount: EUR("10.00"), notBefore: start, notAfter: end });
  const mA = mk(kA, issuerKey, c.setup.issuingMandate);
  const mB = mk(kB, kA, mA);
  const mC = mk(kC, kB, mB);
  assert.equal(mC.chain?.length, 3);
  assert.throws(() => mk(generateKeyPair(), kC, mC), /1 to 3 mandates above/);
});

test("subcontracting: a task agent hands part of the job to another agent, with a smaller limit", async () => {
  const c = await city();
  const agent = await c.taskWallet(asTask(c.operator.newTask({ instruction: "x", principalId: "p", total: EUR("50.00") })));
  const helperKey = generateKeyPair();
  const sub = await agent.delegate({ agent: helperKey.publicKey, scope: "proofreading of the translation", total: EUR("15.00"), hours: 2 });
  assert.equal((sub.chain ?? []).length, 2);
  await assert.rejects(agent.delegate({ agent: helperKey.publicKey, scope: "x", total: EUR("60.00"), hours: 2 }), /bigger total/);
  const storage = new MemoryWalletStorage();
  await storage.save({ v: 1, agentSecret: Buffer.from(helperKey.secretKey).toString("hex"), records: {}, offers: {} });
  const helper = await Wallet.open(storage, c.client, { ownerResolver: c.resolver });
  await helper.installMandate(sub);
  const seen = await c.agency.checkCounterparty(sub);
  assert.equal(seen.ok, true, seen.problems.join("; "));
  assert.deepEqual(seen.via, { links: 3, task: false });
  await assert.rejects(helper.propose({ counterparty: c.agency.myMandate(), clauses: { service: "proofreading", amount: EUR("20.00") } }), /exceeds|in total/);
  const offer = await helper.propose({ counterparty: c.agency.myMandate(), clauses: { service: "proofreading", amount: EUR("12.00") } });
  const { entry } = await c.agency.accept(offer);
  assert.match(entry, /^[0-9a-f]{64}$/);
});

test("revocations: cancel one task; the issuer stops its sub-agent; the owner stops everything at once", async () => {
  const c = await city();
  const t1 = asTask(c.operator.newTask({ instruction: "a", principalId: "p1", total: EUR("50.00") }));
  const t2 = asTask(c.operator.newTask({ instruction: "b", principalId: "p2", total: EUR("50.00") }));
  const a1 = await c.taskWallet(t1);
  const a2 = await c.taskWallet(t2);
  const clauses = { service: "s", amount: EUR("10.00") };

  await c.client.revoke(c.operator.cancelTask(t1.mandate));
  await assert.rejects(a1.propose({ counterparty: c.agency.myMandate(), clauses }), /revoked/);
  assert.equal((await c.agency.checkCounterparty(t1.mandate)).ok, false, "the counterparty sees it too");
  assert.equal((await c.agency.checkCounterparty(t2.mandate)).ok, true, "the other task is untouched");

  // A stranger cannot revoke a task.
  const stranger = generateKeyPair();
  await c.client.revoke(createRevocation(stranger, { target: { kind: "mandate", id: mandateId(t2.mandate) } }));
  assert.equal((await c.agency.checkCounterparty(t2.mandate)).ok, true);

  // Emergency: the owner withdraws the issuing mandate; every task below stops.
  await c.client.revoke(revokeIssuing(c.setup.ownerSecretHex, c.setup.issuingMandate));
  const after = await c.agency.checkCounterparty(t2.mandate);
  assert.equal(after.ok, false);
  assert.ok(after.revoked);
  await assert.rejects(a2.propose({ counterparty: c.agency.myMandate(), clauses }), /revoked/);
});
