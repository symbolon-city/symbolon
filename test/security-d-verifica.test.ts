// Attack test of 21/11/2026, verification and register limits: amounts with extra keys, prices hidden in
// undisclosed clauses, approvals reused or moved to another owner or outliving their general mandate, dates
// read in the verifier's time zone, a witness countersigning a backdated head, the register's daily caps
// filled from one IPv6 /64 or with junk revocations, and an approval list growing without end.
// Each correction has its check here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MAX_PENDING_APPROVALS, MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import {
  MemoryStore,
  Register,
  Witness,
  amountShapeProblem,
  buildProof,
  checkMandate,
  commitClauses,
  createMandate,
  createRecord,
  createRevocation,
  disclose,
  entryHash,
  generateKeyPair,
  mandateId,
  mandateProblem,
  parseTime,
  signRecord,
  signValue,
  staticOwnerResolver,
  verifyProof,
  type Clause,
  type KeyPair,
  type Mandate,
} from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { writeGate, type GateEnv } from "../src/server/gate.js";
import { MemoryExtras, SCHEMA } from "../src/server/stores.js";
import { sqliteD1 } from "./helpers.js";

const DAY = 86_400_000;
const iso = (t: number) => new Date(t).toISOString();
const NOW = Date.now();
const V = { notBefore: iso(NOW - DAY), notAfter: iso(NOW + 30 * DAY), charter: "accord-charter/0.1" };

/** Seals a record of these parties in a fresh register and verifies its proof with everything checked. */
async function sealAndVerify(o: {
  parties: Array<{ key: KeyPair; mandate: Mandate }>;
  clauses: Clause[];
  reveal?: string[];
  mandates?: Mandate[];
  nonce?: string;
  createdAt?: string;
  resolver: Record<string, string[]>;
}) {
  const opened = commitClauses(o.clauses);
  const base = createRecord({
    type: o.parties.length === 1 ? "accord/action" : "accord/agreement",
    clausesRoot: opened.root,
    clauseCount: opened.count,
    parties: o.parties.map((p) => ({ agent: p.key.publicKey, mandate: mandateId(p.mandate) })),
    charter: "accord-charter/0.1",
    createdAt: o.createdAt ?? new Date().toISOString(),
  });
  let record = o.nonce ? { ...base, body: { ...base.body, nonce: o.nonce } } : base;
  for (const p of o.parties) record = signRecord(record, p.key);
  const register = new Register(generateKeyPair(), new MemoryStore());
  const receipt = await register.append(entryHash(record));
  const names = o.reveal ?? o.clauses.map((c) => c.name);
  const proof = buildProof({ record, mandates: o.mandates ?? o.parties.map((p) => p.mandate), disclosures: names.map((n) => disclose(opened, n)), receipt, cosignatures: [] });
  const report = await verifyProof(proof, { trustedLogs: [register.publicKey], ownerResolver: staticOwnerResolver(o.resolver), revocations: async () => [] });
  return { report, record, opened };
}
const failedChecks = (r: { checks: Array<{ name: string; ok: boolean; detail?: string }> }) => r.checks.filter((c) => !c.ok);

/** Alfa (limit 1000 EUR) and beta (no limit). */
function twoParties() {
  const ownerA = generateKeyPair(), ownerB = generateKeyPair(), agentA = generateKeyPair(), agentB = generateKeyPair();
  const mA = createMandate(ownerA, { ownerDomain: "alfa.example", agent: agentA.publicKey, scope: "small purchases", maxAmount: { value: "1000.00", currency: "EUR" }, ...V });
  const mB = createMandate(ownerB, { ownerDomain: "beta.example", agent: agentB.publicKey, scope: "sales", ...V });
  const resolver = { "alfa.example": [ownerA.publicKey], "beta.example": [ownerB.publicKey] };
  return { ownerA, ownerB, agentA, agentB, mA, mB, resolver, parties: [{ key: agentA, mandate: mA }, { key: agentB, mandate: mB }] };
}

// ---------- B1: the amount is exactly {value, currency} ----------

test("B1: an amount with a quantity, a period or a nested total makes the proof invalid", async () => {
  assert.equal(amountShapeProblem({ value: "12.50", currency: "EUR" }), null);
  for (const bad of [
    { value: "1000.00", currency: "EUR", quantity: 1000 },
    { value: "1.00", currency: "EUR", total: { value: "1000000.00", currency: "EUR" } },
    { value: "999.00", currency: "EUR", per: "day", days: 3650 },
    { value: "1.00" },
    { value: 1, currency: "EUR" },
    { value: "1.00", currency: "eur" },
    ["1.00", "EUR"],
    "1.00 EUR",
  ])
    assert.ok(amountShapeProblem(bad), JSON.stringify(bad));
  const { parties, resolver } = twoParties();
  const nested = await sealAndVerify({ parties, resolver, clauses: [{ name: "object", value: "services" }, { name: "amount", value: { value: "1.00", currency: "EUR", total: { value: "1000000.00", currency: "EUR" } } }] });
  assert.equal(nested.report.verdict, "invalid");
  assert.ok(failedChecks(nested.report).some((c) => /exactly \{value, currency\}/.test(c.name)));
  const plain = await sealAndVerify({ parties, resolver, clauses: [{ name: "object", value: "services" }, { name: "amount", value: { value: "900.00", currency: "EUR" } }] });
  assert.equal(plain.report.verdict, "valid", JSON.stringify([plain.report.gaps, failedChecks(plain.report)]));
});

// ---------- B7: under a limit, every clause disclosed ----------

test("B7: under a spending limit a proof that hides a clause is incomplete; the hidden price, once shown, is invalid", async () => {
  const { parties, resolver, agentA, agentB, mB, ownerB } = twoParties();
  const clauses = [{ name: "amount", value: { value: "900.00", currency: "EUR" } }, { name: "setup fee", value: { value: "250000.00", currency: "EUR" } }];
  const hidden = await sealAndVerify({ parties, resolver, clauses, reveal: ["amount"] });
  assert.equal(hidden.report.verdict, "incomplete");
  assert.match(hidden.report.gaps.join(" "), /1 of 2 clauses are not disclosed/);
  const shown = await sealAndVerify({ parties, resolver, clauses });
  assert.equal(shown.report.verdict, "invalid");
  // Without any limit, showing only some clauses stays valid (selective disclosure).
  const mB2 = createMandate(ownerB, { ownerDomain: "beta.example", agent: agentA.publicKey, scope: "x", ...V });
  const free = await sealAndVerify({ parties: [{ key: agentA, mandate: mB2 }, { key: agentB, mandate: mB }], resolver, clauses: [{ name: "object", value: "x" }, { name: "secret", value: "y" }], reveal: ["object"] });
  assert.equal(free.report.verdict, "valid", JSON.stringify([free.report.gaps, failedChecks(free.report)]));
});

// ---------- B3, B4, B5: approvals bound to one record, one counterparty mandate, a live general mandate ----------

function approvalSetup(o: { generalValidity?: { notBefore: string; notAfter: string } } = {}) {
  const t = twoParties();
  const general = createMandate(t.ownerA, { ownerDomain: "alfa.example", agent: t.agentA.publicKey, scope: "purchases", maxAmount: { value: "1000.00", currency: "EUR" }, ...V, ...(o.generalValidity ?? {}) });
  const clauses = [{ name: "object", value: "one machine" }, { name: "amount", value: { value: "5000.00", currency: "EUR" } }];
  const nonce = "a1".repeat(16);
  const approve = (clausesRoot: string, over: Record<string, unknown> = {}) =>
    createMandate(t.ownerA, {
      ownerDomain: "alfa.example", agent: t.agentA.publicKey, scope: "one agreement only", maxAmount: { value: "5000.00", currency: "EUR" },
      notBefore: iso(NOW - 60_000), notAfter: iso(NOW + 2 * DAY), charter: "accord-charter/0.1",
      agreement: { clausesRoot, with: [t.agentB.publicKey], withMandates: [mandateId(t.mB)], nonce, under: mandateId(general), ...over },
    });
  return { ...t, general, clauses, nonce, approve };
}

/** Seals one agreement under an approval, with the record's clauses committed first so the approval binds their root. */
async function sealApproved(s: ReturnType<typeof approvalSetup>, o: { nonce?: string; counterparty?: { key: KeyPair; mandate: Mandate }; mandates?: (approval: Mandate) => Mandate[]; approvalOver?: Record<string, unknown> } = {}) {
  const opened = commitClauses(s.clauses);
  const approval = s.approve(opened.root, o.approvalOver);
  const cp = o.counterparty ?? { key: s.agentB, mandate: s.mB };
  const base = createRecord({
    type: "accord/agreement", clausesRoot: opened.root, clauseCount: opened.count,
    parties: [{ agent: s.agentA.publicKey, mandate: mandateId(approval) }, { agent: cp.key.publicKey, mandate: mandateId(cp.mandate) }],
    charter: "accord-charter/0.1", createdAt: new Date().toISOString(),
  });
  const record = signRecord(signRecord({ ...base, body: { ...base.body, nonce: o.nonce ?? s.nonce } }, s.agentA), cp.key);
  const register = new Register(generateKeyPair(), new MemoryStore());
  const receipt = await register.append(entryHash(record));
  const mandates = o.mandates ? o.mandates(approval) : [approval, cp.mandate, s.general];
  const proof = buildProof({ record, mandates, disclosures: s.clauses.map((c) => disclose(opened, c.name)), receipt, cosignatures: [] });
  return verifyProof(proof, { trustedLogs: [register.publicKey], ownerResolver: staticOwnerResolver(s.resolver), revocations: async () => [] });
}
const approvalCheck = (r: Awaited<ReturnType<typeof verifyProof>>) => r.checks.find((c) => /approval of agent .* is for this very agreement/.test(c.name));

test("B3: an approval allows the one record whose nonce it carries, never a second agreement", async () => {
  const s = approvalSetup();
  const ok = await sealApproved(s);
  assert.equal(ok.verdict, "valid", JSON.stringify([ok.gaps, failedChecks(ok)]));
  const again = await sealApproved(s, { nonce: "b2".repeat(16) });
  assert.equal(again.verdict, "invalid");
  assert.match(String(approvalCheck(again)?.detail), /another record/);
  // The format before 21/11 (no nonce, no withMandates) allows nothing.
  const old = await sealApproved(s, { approvalOver: { nonce: undefined, withMandates: undefined } });
  assert.equal(old.verdict, "invalid");
  assert.match(String(approvalCheck(old)?.detail), /older format/);
});

test("B4: the same counterparty agent key under another owner's mandate is another party", async () => {
  const s = approvalSetup();
  const shady = createMandate(generateKeyPair(), { agent: s.agentB.publicKey, scope: "anything", ...V });
  const r = await sealApproved(s, { counterparty: { key: s.agentB, mandate: shady } });
  assert.equal(r.verdict, "invalid");
  assert.match(String(approvalCheck(r)?.detail), /another mandate/);
});

test("B5: an approval ends with its general mandate: expired, missing, or of another agent", async () => {
  const expired = approvalSetup({ generalValidity: { notBefore: iso(NOW - 30 * DAY), notAfter: iso(NOW - DAY) } });
  const r1 = await sealApproved(expired);
  assert.equal(r1.verdict, "invalid");
  assert.match(String(approvalCheck(r1)?.detail), /not valid at/);

  const s = approvalSetup();
  const r2 = await sealApproved(s, { mandates: (a) => [a, s.mB] });
  assert.equal(r2.verdict, "invalid");
  assert.match(String(approvalCheck(r2)?.detail), /missing/);

  const otherAgent = createMandate(s.ownerA, { ownerDomain: "alfa.example", agent: generateKeyPair().publicKey, scope: "x", ...V });
  const r3 = await sealApproved(s, { approvalOver: { under: mandateId(otherAgent) }, mandates: (a) => [a, s.mB, otherAgent] });
  assert.equal(r3.verdict, "invalid");
  assert.match(String(approvalCheck(r3)?.detail), /another agent/);

  const otherOwner = createMandate(generateKeyPair(), { ownerDomain: "alfa.example", agent: s.agentA.publicKey, scope: "x", ...V });
  const r4 = await sealApproved(s, { approvalOver: { under: mandateId(otherOwner) }, mandates: (a) => [a, s.mB, otherOwner] });
  assert.equal(r4.verdict, "invalid");
  assert.match(String(approvalCheck(r4)?.detail), /another owner/);
});

test("B3-B5 through the wallets: the approval names the record's nonce and the counterparty's mandate, the offer carries the general mandate", async () => {
  let now = Date.now();
  const clock = () => new Date(now);
  const regDeps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const client = new HttpRegisterClient("https://reg.example", (async (i, init) => handle(new Request(String(i), init), regDeps)) as typeof fetch);
  const ownerA = generateKeyPair(), ownerB = generateKeyPair();
  const table = { "alfa.example": [ownerA.publicKey], "beta.example": [ownerB.publicKey] };
  const ownerResolver = staticOwnerResolver(table);
  const wA = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver, now: clock });
  const wB = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver, now: clock });
  const mA = createMandate(ownerA, { ownerDomain: "alfa.example", agent: wA.agentKey, scope: "purchases", maxAmount: { value: "1000.00", currency: "EUR" }, ...V });
  const mB = createMandate(ownerB, { ownerDomain: "beta.example", agent: wB.agentKey, scope: "sales", ...V });
  await wA.installMandate(mA);
  await wB.installMandate(mB);
  const deal = { object: "a press", amount: { value: "5000.00", currency: "EUR" } };

  const req = await wA.requestApproval({ counterparty: mB, clauses: deal, hours: 1 });
  const binding = req.approval_body.agreement!;
  assert.deepEqual(binding.withMandates, [mandateId(mB)]);
  assert.match(String(binding.nonce), /^[0-9a-f]{32}$/);
  const pending = wA.pendingApprovals();
  assert.equal(pending[0].ownerLevel, "domain", "the owner's page can warn when the counterparty is not verified");

  const offer = await wA.proposeApproved({ clausesRoot: req.clauses_root, signature: signValue(req.approval_body, ownerA) });
  assert.equal(offer.record.body.nonce, binding.nonce);
  assert.ok(offer.mandates.some((m) => mandateId(m) === mandateId(mA)), "the general mandate travels with the offer");
  const accepted = await wB.accept(offer);
  await wA.confirm(accepted.confirmation);
  const proof = await wA.createProof(accepted.entry, Object.keys(deal));
  const report = await wA.verify(proof);
  assert.equal(report.verdict, "valid", JSON.stringify([report.gaps, failedChecks(report)]));
  // The counterparty's own proof also carries the general mandate behind the approval, so it verifies too.
  const proofB = await wB.createProof(accepted.entry, Object.keys(deal));
  assert.ok(proofB.mandates.some((m) => mandateId(m) === mandateId(mA)), "the accepting wallet keeps the general mandate");
  const reportB = await wB.verify(proofB);
  assert.equal(reportB.verdict, "valid", JSON.stringify([reportB.gaps, failedChecks(reportB)]));

  // A6: expired requests are dropped, and at most MAX_PENDING_APPROVALS wait at once.
  for (let i = 0; i < MAX_PENDING_APPROVALS; i++) await wA.requestApproval({ counterparty: mB, clauses: { ...deal, object: `press ${i}` }, hours: 1 });
  await assert.rejects(wA.requestApproval({ counterparty: mB, clauses: { ...deal, object: "one more" }, hours: 1 }), /already waiting/);
  assert.equal(wA.pendingApprovals().length, MAX_PENDING_APPROVALS);
  now += 2 * 3_600_000;
  await wA.requestApproval({ counterparty: mB, clauses: { ...deal, object: "after a while" }, hours: 1 });
  assert.equal(wA.pendingApprovals().length, 1, "the expired requests were dropped");
});

// ---------- B6: times in UTC only ----------

test("B6: mandate, approval and record times are read as UTC only, the same in every time zone", async () => {
  assert.equal(parseTime("2026-11-21T10:00:00Z"), Date.UTC(2026, 10, 21, 10));
  assert.equal(parseTime("2026-11-21T10:00:00.5Z"), Date.UTC(2026, 10, 21, 10, 0, 0, 500));
  assert.equal(parseTime(new Date(NOW).toISOString()), NOW);
  for (const bad of ["2026-11-21T10:00:00", "2026-11-21T10:00:00+01:00", "2026-11-21", "Sat, 21 Nov 2026 10:00:00 GMT", "2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z", "+002026-01-01T00:00:00Z", 12])
    assert.ok(Number.isNaN(parseTime(bad)), String(bad));
  const owner = generateKeyPair(), agent = generateKeyPair();
  assert.throws(() => createMandate(owner, { agent: agent.publicKey, scope: "x", notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-12-31T00:00:00", charter: "c" }), /UTC/);
  const forged = createMandate(owner, { agent: agent.publicKey, scope: "x", ...V });
  forged.body.notAfter = forged.body.notAfter.replace("Z", "");
  assert.match(String(mandateProblem(forged)), /UTC/);
  assert.equal((await checkMandate(forged)).ok, false);
  // A record dated without a zone fails the "not dated after sealing" check.
  const t = twoParties();
  const r = await sealAndVerify({ parties: t.parties, resolver: t.resolver, clauses: [{ name: "amount", value: { value: "1.00", currency: "EUR" } }], createdAt: new Date().toISOString().slice(0, 19) });
  assert.equal(r.report.verdict, "invalid");
  assert.ok(failedChecks(r.report).some((c) => /not dated after sealing/.test(c.name)));
});

// ---------- C7: the witness checks the head's time ----------

test("C7: a witness refuses a head dated before the last one it saw, or far from its own clock", async () => {
  let clock = new Date();
  const register = new Register(generateKeyPair(), new MemoryStore(), () => clock);
  const witness = new Witness(generateKeyPair());
  const r0 = await register.append("11".repeat(32));
  witness.observe(r0.head, []);
  // A head dated a year ago.
  clock = new Date(Date.now() - 365 * DAY);
  const r1 = await register.append("22".repeat(32));
  assert.throws(() => witness.observe(r1.head, []), /from this witness's clock/);
  // A head dated just before the last one seen, within the clock tolerance.
  clock = new Date(Date.parse(r0.head.time) - 60_000);
  const r2 = await register.append("33".repeat(32));
  const c2 = await register.consistency(r0.head.size, r2.head.size);
  assert.throws(() => witness.observe(r2.head, c2), /before the last head seen/);
  // Time moving forward is fine.
  clock = new Date(Date.parse(r0.head.time) + 1000);
  const r3 = await register.append("44".repeat(32));
  assert.equal(witness.observe(r3.head, await register.consistency(r0.head.size, r3.head.size)).size, r3.head.size);
});

// ---------- D6 and B2: the register's daily limits ----------

function gated(env: Omit<GateEnv, "DB">) {
  const sqlite = new DatabaseSync(":memory:");
  const DB = sqliteD1(sqlite);
  for (const line of SCHEMA.trim().split("\n")) sqlite.exec(line);
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg", ...writeGate({ DB, ...env }) };
  const post = (path: string, body: unknown, ip: string, headers: Record<string, string> = {}) =>
    handle(new Request(`https://reg${path}`, { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip, ...headers }, body: JSON.stringify(body) }), deps);
  return { post, deps };
}
const fp = (i: number | string) => createHash("sha256").update(String(i)).digest("hex");
const noLimit = { limit: async () => ({ success: true }) };

test("D6: one IPv6 /64 is one client: its per-minute limit and its daily share do not stop anyone else", async () => {
  // Per-minute limit keyed by client: 2^64 addresses of one /64 share one bucket.
  const keys = new Set<string>();
  const counted = gated({ WRITE_LIMIT: { limit: async ({ key }) => (keys.add(key), { success: true }) } });
  for (let i = 0; i < 5; i++) await counted.post("/v1/entries", { entry: fp(i) }, `2001:db8:0:1::${i.toString(16)}`);
  assert.deepEqual([...keys], ["v6:2001:0db8:0000:0001"]);

  // Daily share: even with the per-minute limit out of the way, one client takes at most DAILY_CLIENT_WRITE_CAP.
  const { post } = gated({ WRITE_LIMIT: noLimit, DAILY_WRITE_CAP: "50", DAILY_CLIENT_WRITE_CAP: "10", DAILY_INTERNAL_RESERVE: "10" });
  let ok = 0;
  for (let i = 0; i < 30; i++) if ((await post("/v1/entries", { entry: fp(`a${i}`) }, `2001:db8:0:1:${i.toString(16)}::1`)).status === 201) ok++;
  assert.equal(ok, 10);
  assert.equal((await post("/v1/entries", { entry: fp("honest") }, "192.0.2.50")).status, 201, "another client still seals");
});

test("D6: the internal lane has its own limit and a reserved part of the daily cap; a wrong secret is an ordinary client", async () => {
  const internalKeys: string[] = [];
  const { post } = gated({
    WRITE_LIMIT: noLimit,
    INTERNAL_WRITE_LIMIT: { limit: async ({ key }) => (internalKeys.push(key), { success: true }) },
    INTERNAL_WRITE_SECRET: "piazza-secret",
    DAILY_WRITE_CAP: "20",
    DAILY_INTERNAL_RESERVE: "5",
    DAILY_CLIENT_WRITE_CAP: "100",
  });
  let pub = 0;
  for (let i = 0; i < 30; i++) if ((await post("/v1/entries", { entry: fp(`p${i}`) }, `198.51.100.${i}`)).status === 201) pub++;
  assert.equal(pub, 15, "the public stops at the cap minus the reserve");
  const wrong = await post("/v1/entries", { entry: fp("w") }, "198.51.100.200", { "x-symbolon-internal": "guess" });
  assert.equal(wrong.status, 429);
  let internal = 0;
  for (let i = 0; i < 10; i++) if ((await post("/v1/entries", { entry: fp(`i${i}`) }, "203.0.113.9", { "x-symbolon-internal": "piazza-secret" })).status === 201) internal++;
  assert.equal(internal, 5, "the internal lane uses the reserve, up to the whole cap");
  assert.ok(internalKeys.length > 0 && internalKeys.every((k) => k === "internal"));
});

test("B2: junk revocations from throwaway keys and many addresses never block a real owner's revocation", async () => {
  const { post } = gated({ WRITE_LIMIT: noLimit, DAILY_REVOCATION_CAP: "60", DAILY_CLIENT_REVOCATION_CAP: "30", DAILY_CLIENT_NEW_SIGNERS: "3", DAILY_SIGNER_REVOCATION_CAP: "5" });
  // An attacker with 4 addresses and a fresh key for every revocation fills the day's cap.
  let junk = 0;
  for (let i = 0; i < 200; i++) {
    const r = createRevocation(generateKeyPair(), { target: { kind: "mandate", id: fp(`junk${i}`) }, reason: "junk" });
    if ((await post("/v1/revocations", r, `198.51.100.${i % 4}`)).status === 201) junk++;
  }
  assert.ok(junk >= 60 && junk <= 4 * 30, `junk bounded by the cap plus the per-client new-key quota (${junk})`);
  // The owner revokes from its own network: its key's first revocation of the day passes the full cap.
  const owner = generateKeyPair();
  const m = createMandate(owner, { ownerDomain: "alfa.example", agent: generateKeyPair().publicKey, scope: "x", ...V });
  const res = await post("/v1/revocations", createRevocation(owner, { target: { kind: "mandate", id: mandateId(m) }, reason: "agent key stolen" }), "203.0.113.7");
  assert.equal(res.status, 201, await res.text());
  // One key cannot flood on its own either.
  const spammer = generateKeyPair();
  const { post: post2 } = gated({ WRITE_LIMIT: noLimit, DAILY_SIGNER_REVOCATION_CAP: "5" });
  let same = 0;
  for (let i = 0; i < 10; i++) if ((await post2("/v1/revocations", createRevocation(spammer, { target: { kind: "mandate", id: fp(`s${i}`) } }), `192.0.2.${i}`)).status === 201) same++;
  assert.equal(same, 5);
});

// ---------- SSRF: owner domains that lead to internal hosts ----------

test("SSRF: owner domains of internal hosts or with an IPv4 address inside are refused", async () => {
  const { ownerDomainProblem, amountLeq } = await import("../src/mandate.js");
  for (const bad of [
    "127.0.0.1.nip.io", "169.254.169.254.nip.io", "10.0.0.1.nip.io", "10-0-0-1.sslip.io", "app.192-168-1-1.sslip.io",
    "metadata.google.internal", "router.localhost", "printer.lan", "nas.local", "box.home.arpa",
  ])
    assert.ok(ownerDomainProblem(bad), bad);
  for (const ok of ["example.com", "alfa.example", "demo.symboloncity.com", "museo.example", "a1.b2.example.org", "web3-2024.example.com", "localhost-tools.com"])
    assert.equal(ownerDomainProblem(ok), null, ok);
  // Errors never quote attacker data.
  assert.throws(() => amountLeq("<script>", "1"), (e: Error) => !e.message.includes("<script>"));
});
