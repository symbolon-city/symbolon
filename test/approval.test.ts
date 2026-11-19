// "Approve just this one": the owner approves one agreement above the agent's limit, with Face ID,
// without raising the limit. Marta (limit 2,000 EUR, no website) and a museum that offers 2,400 EUR.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import {
  MemoryStore,
  Register,
  approvalProblem,
  buildProof,
  commitClauses,
  createMandate,
  createRecord,
  createRevocation,
  createSubMandate,
  entryHash,
  generateKeyPair,
  mandateBody,
  mandateId,
  mandateProblem,
  revocationBody,
  revokes,
  signRecord,
  signedMandate,
  signedRevocation,
  staticOwnerResolver,
  verifyProof,
  type KeyPair,
  type Mandate,
} from "../src/index.js";
import { clausesObject, verifyOpened } from "../src/clauses.js";
import { handle } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { SoftPasskey } from "./softpasskey.js";

const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

/** Marta's wallet (passkey, no website, limit 2000 EUR) and a museum's (domain, limit 10000 EUR), on one register. */
async function city(o: { museumStrict?: boolean } = {}) {
  let now = Date.now();
  const clock = () => new Date(now);
  const regDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const client = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), regDeps));
  const museumOwner = generateKeyPair();
  const resolver = staticOwnerResolver({ "museo.example": [museumOwner.publicKey] });
  const open = async (mandateFor: (agent: string) => Mandate) => {
    const wallet = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver: resolver, now: clock });
    const mcp = new Client({ name: "agent", version: "0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await buildMcpServer(wallet).connect(a);
    await mcp.connect(b);
    const call = async (name: string, args: Record<string, unknown> = {}) => {
      const r = (await mcp.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
      if (r.isError) throw new Error(r.content[0].text);
      return JSON.parse(r.content[0].text);
    };
    const mandate = mandateFor(wallet.agentKey);
    await call("symbolon_install_mandate", { mandate });
    return { wallet, call, mandate };
  };
  const device = new SoftPasskey();
  const validity = { notBefore: iso(now - DAY), notAfter: iso(now + 90 * DAY), charter: "accord-charter/0.1" };
  const marta = await open((agent) => {
    const body = mandateBody(device.publicKey, { agent, scope: "lavori di restauro", maxAmount: { value: "2000.00", currency: "EUR" }, ...validity });
    return signedMandate(body, device.sign(body));
  });
  const museum = await open((agent) =>
    createMandate(museumOwner as KeyPair, { ownerDomain: "museo.example", agent, scope: "restauri", maxAmount: { value: "10000.00", currency: "EUR" }, ...validity }),
  );
  const deal = { object: "restauro della cornice dorata", amount: { value: "2400.00", currency: "EUR" }, delivery: "2026-12-20" };
  return { marta, museum, device, deal, regDeps, client, advance: (ms: number) => (now += ms) };
}

test("approval: Marta approves only the 2,400 EUR agreement with Face ID, the museum accepts, the proof is valid", async () => {
  const { marta, museum, device, deal } = await city();
  // The museum cannot propose 2,400 to Marta: above her limit. Its wallet says what she can do.
  await assert.rejects(museum.call("symbolon_propose_agreement", { counterparty_mandate: marta.mandate, clauses: deal }), /ask its owner to approve just this agreement/);
  // Marta's own wallet, asked to propose it, points to the approval.
  await assert.rejects(marta.call("symbolon_propose_agreement", { counterparty_mandate: museum.mandate, clauses: deal }), /symbolon_request_owner_approval/);

  const req = await marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: deal });
  assert.match(req.for_the_owner.text, /Approve only this agreement: 2400\.00 EUR with the agent of museo\.example \(identity level domain\)\. Your general limit stays 2000\.00 EUR/);
  assert.equal(req.approval_body.agreement.with[0], museum.mandate.body.agent);
  assert.equal(req.approval_body.agreement.under, mandateId(marta.mandate));
  // Marta's page can check that the clauses it shows are the very ones bound by the approval.
  assert.equal(req.clauses_opened.root, req.approval_body.agreement.clausesRoot);
  assert.ok(verifyOpened(req.clauses_opened));
  assert.equal(JSON.stringify(clausesObject(req.clauses_opened)), JSON.stringify(deal));
  const commitments = await marta.call("symbolon_my_commitments");
  assert.equal(commitments.waiting_for_owner.length, 1);

  // Marta taps Face ID on exactly what she was shown.
  const offer = await marta.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root, signature: device.sign(req.approval_body) });
  const accepted = await museum.call("symbolon_accept_agreement", { offer });
  assert.equal(accepted.counterparty.level, "key");
  assert.equal(accepted.counterparty.approval.clausesRoot, req.clauses_root);
  await marta.call("symbolon_confirm_agreement", { confirmation: accepted.confirmation });
  assert.equal((await marta.call("symbolon_my_commitments")).waiting_for_owner, undefined);

  const proof = await marta.call("symbolon_create_proof", { entry: accepted.entry, reveal: ["object", "amount", "delivery"] });
  const report = await museum.call("symbolon_verify_proof", { proof });
  assert.equal(report.valid, true, JSON.stringify([report.gaps, report.checks.filter((c: { ok: boolean }) => !c.ok)]));
  assert.ok(report.checks.some((c: { name: string; ok: boolean }) => /approval of agent .* is for this very agreement/.test(c.name) && c.ok));

  // The general limit has not changed: a second 2,400 EUR deal still needs a new approval.
  assert.equal((await marta.call("symbolon_my_mandate")).body.maxAmount.value, "2000.00");
  await assert.rejects(marta.call("symbolon_propose_agreement", { counterparty_mandate: museum.mandate, clauses: { ...deal, object: "seconda cornice" } }), /exceeds the mandate/);
});

test("approval: within the limit there is nothing to approve; above it the counterparty's own limit still applies", async () => {
  const { marta, museum } = await city();
  await assert.rejects(
    marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: { amount: { value: "1500.00", currency: "EUR" } } }),
    /within your mandate/,
  );
  await assert.rejects(
    marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: { amount: { value: "15000.00", currency: "EUR" } } }),
    /exceeds the mandate of museo\.example/,
  );
  await assert.rejects(marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: { object: "senza prezzo" } }), /needs an 'amount' clause/);
  await assert.rejects(
    marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: { amount: { value: "2400.00", currency: "EUR" } }, hours: 169 }),
  );
});

test("approval: the agent cannot change, reuse or sign the approval itself", async () => {
  const { marta, museum, device, deal } = await city();
  const req = await marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: deal });
  // A signature of something else.
  const other = { ...req.approval_body, maxAmount: { value: "24000.00", currency: "EUR" } };
  await assert.rejects(marta.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root, signature: device.sign(other) }), /not signed by my owner/);
  // A changed approval, even correctly signed by the owner: not what was shown.
  await assert.rejects(marta.call("symbolon_propose_approved_agreement", { approval: { body: other, signature: device.sign(other) } }), /differs from what was shown/);
  // Signed by the agent's own key (or anyone else's).
  await assert.rejects(marta.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root, signature: "00".repeat(64) }), /not signed by my owner/);
  // An approval is not a general mandate.
  const signed = { body: req.approval_body, signature: device.sign(req.approval_body) };
  await assert.rejects(marta.call("symbolon_install_mandate", { mandate: signed }), /approval of one agreement, not a mandate/);
  // The museum cannot propose other terms "under" Marta's approval.
  await assert.rejects(museum.call("symbolon_propose_agreement", { counterparty_mandate: signed, clauses: deal }), /already prepared/);
  // Used once, gone.
  await marta.call("symbolon_propose_approved_agreement", { approval: signed });
  await assert.rejects(marta.call("symbolon_propose_approved_agreement", { approval: signed }), /no approval request of mine matches/);
});

test("approval: an expired approval is refused", async () => {
  const { marta, museum, device, deal, advance } = await city();
  const req = await marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: deal, hours: 2 });
  advance(3 * 3_600_000);
  await assert.rejects(marta.call("symbolon_propose_approved_agreement", { clauses_root: req.clauses_root, signature: device.sign(req.approval_body) }), /expired/);
});

test("approval: revoking Marta's general mandate revokes the approvals given under it", async () => {
  const { marta, museum, device, deal, client } = await city();
  const req = await marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: deal });
  const approval: Mandate = { body: req.approval_body, signature: device.sign(req.approval_body) };
  const req2 = await marta.call("symbolon_request_owner_approval", { counterparty_mandate: museum.mandate, clauses: { ...deal, object: "altra cornice" } });
  // The first offer is already on its way to the museum when Marta blocks her general mandate.
  const offer = await marta.call("symbolon_propose_approved_agreement", { approval });
  const rb = revocationBody(device.publicKey, { target: { kind: "mandate", id: mandateId(marta.mandate) }, reason: "basta" });
  const revocation = signedRevocation(rb, device.sign(rb));
  assert.ok(revokes(revocation, approval));
  await client.revoke(revocation);
  // The museum's wallet finds the revocation through the general mandate's id, and refuses.
  await assert.rejects(museum.call("symbolon_accept_agreement", { offer }), /revoked/);
  // Marta's wallet refuses to use the other approval.
  await assert.rejects(marta.call("symbolon_propose_approved_agreement", { clauses_root: req2.clauses_root, signature: device.sign(req2.approval_body) }), /revoked/);
  // A stranger cannot revoke it through the general mandate's id.
  assert.equal(revokes(createRevocation(generateKeyPair(), { target: { kind: "mandate", id: mandateId(marta.mandate) } }), approval), false);
});

test("approval: the format binds it to one agreement, for a few days, and it cannot be passed on", () => {
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const other = generateKeyPair();
  const now = Date.now();
  const base = { ownerDomain: "alfa.example", agent: agent.publicKey, scope: "one agreement", maxAmount: { value: "2400.00", currency: "EUR" }, charter: "accord-charter/0.1", notBefore: iso(now), notAfter: iso(now + 2 * DAY) };
  const agreement = { clausesRoot: "ab".repeat(32), with: [other.publicKey], under: "cd".repeat(32) };
  const ok = createMandate(owner, { ...base, agreement });
  assert.equal(mandateProblem(ok), null);
  for (const bad of [
    { ...agreement, with: [] },
    { ...agreement, with: [agent.publicKey] },
    { ...agreement, with: [other.publicKey, other.publicKey] },
    { ...agreement, clausesRoot: "x" },
    { ...agreement, extra: 1 },
  ])
    assert.throws(() => createMandate(owner, { ...base, agreement: bad as typeof agreement }));
  assert.throws(() => createMandate(owner, { ...base, notAfter: iso(now + 8 * DAY), agreement }), /at most 7 days/);
  // Not passed on to another agent.
  assert.throws(() => createSubMandate(agent, ok, { agent: generateKeyPair().publicKey, scope: "x", notBefore: base.notBefore, notAfter: base.notAfter }), /cannot be passed on/);
  // Bound to its clauses and its parties.
  assert.equal(approvalProblem(ok, { clausesRoot: agreement.clausesRoot, parties: [{ agent: agent.publicKey }, { agent: other.publicKey }] }), null);
  assert.match(String(approvalProblem(ok, { clausesRoot: "ef".repeat(32), parties: [{ agent: agent.publicKey }, { agent: other.publicKey }] })), /other clauses/);
  assert.match(String(approvalProblem(ok, { clausesRoot: agreement.clausesRoot, parties: [{ agent: agent.publicKey }, { agent: generateKeyPair().publicKey }] })), /other parties/);
  assert.match(
    String(approvalProblem(ok, { clausesRoot: agreement.clausesRoot, parties: [{ agent: agent.publicKey }, { agent: other.publicKey }, { agent: generateKeyPair().publicKey }] })),
    /other parties/,
  );
});

test("approval: a proof that uses an approval for another agreement is invalid", async () => {
  const owner = generateKeyPair();
  const agentA = generateKeyPair();
  const agentB = generateKeyPair();
  const ownerB = generateKeyPair();
  const now = Date.now();
  const v = { notBefore: iso(now - DAY), notAfter: iso(now + DAY), charter: "accord-charter/0.1" };
  const approved = commitClauses([{ name: "amount", value: { value: "2400.00", currency: "EUR" } }]);
  const other = commitClauses([{ name: "amount", value: { value: "2400.00", currency: "EUR" } }, { name: "object", value: "something else" }]);
  const approval = createMandate(owner, { agent: agentA.publicKey, scope: "one", maxAmount: { value: "2400.00", currency: "EUR" }, ...v, agreement: { clausesRoot: approved.root, with: [agentB.publicKey], under: "cd".repeat(32) } });
  const mB = createMandate(ownerB, { ownerDomain: "beta.example", agent: agentB.publicKey, scope: "x", ...v });
  let record = createRecord({
    type: "accord/agreement",
    clausesRoot: other.root,
    clauseCount: other.count,
    parties: [{ agent: agentA.publicKey, mandate: mandateId(approval) }, { agent: agentB.publicKey, mandate: mandateId(mB) }],
    charter: "accord-charter/0.1",
    createdAt: iso(now),
  });
  record = signRecord(signRecord(record, agentA), agentB);
  const register = new Register(generateKeyPair(), new MemoryStore());
  const receipt = await register.append(entryHash(record));
  const report = await verifyProof(buildProof({ record, mandates: [approval, mB], disclosures: [], receipt, cosignatures: [] }), {
    trustedLogs: [register.publicKey],
    ownerResolver: staticOwnerResolver({ "beta.example": [ownerB.publicKey] }),
    revocations: async () => [],
  });
  assert.equal(report.verdict, "invalid");
  assert.ok(report.checks.some((c) => /is for this very agreement/.test(c.name) && !c.ok && /other clauses/.test(String(c.detail))));
});
