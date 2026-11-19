// Identity level "key": an owner without a website, known only by its key (typically a passkey on its phone).
// Marta, a restorer with no site, gives her agent a mandate with Face ID and makes an agreement with a museum.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { archiveKeyProblem, newArchiveKey } from "../src/archive.js";
import {
  MemoryStore,
  Register,
  chainProblem,
  checkMandate,
  createMandate,
  createRevocation,
  createSubMandate,
  generateKeyPair,
  mandateBody,
  mandateId,
  mandateProblem,
  ownerName,
  revocationBody,
  revokes,
  signValue,
  signedMandate,
  signedRevocation,
  staticOwnerResolver,
  verifyMandateSignature,
  type KeyPair,
  type Mandate,
} from "../src/index.js";
import { handlePiazza } from "../src/piazza/app.js";
import { signEnvelope } from "../src/piazza/messages.js";
import { MemoryPiazzaStore } from "../src/piazza/stores.js";
import { handle } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { SoftPasskey } from "./softpasskey.js";

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
const validity = () => ({ notBefore: later(-1), notAfter: later(90), charter: "accord-charter/0.1" });

/** Marta's mandate, signed with her passkey, with no domain. */
function martaMandate(agent: string, device = new SoftPasskey()) {
  const body = mandateBody(device.publicKey, { agent, scope: "lavori di restauro", maxAmount: { value: "2000.00", currency: "EUR" }, ...validity() });
  return { device, body, mandate: signedMandate(body, device.sign(body)) };
}

/** A resolver that fails the test if anyone asks it anything. */
const noLookups = async (d: string): Promise<string[] | null> => {
  throw new Error(`no domain should be looked up, asked for ${d}`);
};

test("level key: a mandate without a domain is well formed, signed, and has no domain field at all", () => {
  const { device, mandate } = martaMandate(generateKeyPair().publicKey);
  assert.equal(mandateProblem(mandate), null);
  assert.ok(verifyMandateSignature(mandate));
  assert.deepEqual(Object.keys(mandate.body.owner), ["key"]);
  assert.equal(ownerName(mandate.body.owner), device.publicKey);
  // Same with an ordinary (non-passkey) owner key.
  const plain = createMandate(generateKeyPair(), { agent: generateKeyPair().publicKey, scope: "x", ...validity() });
  assert.ok(verifyMandateSignature(plain));
  assert.deepEqual(Object.keys(plain.body.owner), ["key"]);
});

test("level key: a domain field that is present must be a real domain (no empty, null or undefined spellings)", () => {
  const owner = generateKeyPair();
  const sign = (domain: unknown) => {
    const body = { ...mandateBody(owner.publicKey, { agent: generateKeyPair().publicKey, scope: "x", ...validity() }), owner: { domain, key: owner.publicKey } };
    return { body, signature: signValue(body, owner) } as unknown as Mandate;
  };
  for (const d of ["", null, undefined, 0, "localhost", "EXAMPLE.com"]) assert.ok(mandateProblem(sign(d)), `domain ${JSON.stringify(d)} accepted`);
  assert.throws(() => mandateBody(owner.publicKey, { ownerDomain: "", agent: generateKeyPair().publicKey, scope: "x", ...validity() }));
});

test("level key: removing the domain from a signed mandate breaks its signature (no downgrade)", () => {
  const owner = generateKeyPair();
  const m = createMandate(owner, { ownerDomain: "alfa.example", agent: generateKeyPair().publicKey, scope: "x", ...validity() });
  const stripped: Mandate = { body: { ...m.body, owner: { key: m.body.owner.key } }, signature: m.signature };
  assert.equal(mandateProblem(stripped), null);
  assert.equal(verifyMandateSignature(stripped), false);
  const added: Mandate = { body: { ...m.body, owner: { domain: "beta.example", key: m.body.owner.key } }, signature: m.signature };
  assert.equal(verifyMandateSignature(added), false);
});

test("level key: a counterparty sees level key, the owner's key as its name, and no domain is looked up", async () => {
  const { device, mandate } = martaMandate(generateKeyPair().publicKey);
  const check = await checkMandate(mandate, { ownerResolver: noLookups, revocations: async () => [] });
  assert.deepEqual(check.problems, []);
  assert.equal(check.ok, true);
  assert.equal(check.level, "key");
  assert.equal(check.owner, device.publicKey);
  assert.deepEqual(check.limit, { value: "2000.00", currency: "EUR" });
  // A mandate that names a domain still needs it to publish the key.
  const owner = generateKeyPair();
  const claimed = createMandate(owner, { ownerDomain: "alfa.example", agent: generateKeyPair().publicKey, scope: "x", ...validity() });
  const c2 = await checkMandate(claimed, { ownerResolver: staticOwnerResolver({}), revocations: async () => [] });
  assert.equal(c2.level, "unverified");
  assert.equal(c2.ok, false);
});

test("level key: a chain keeps the owner exactly, so no link can add or remove a domain", () => {
  const issuer = generateKeyPair();
  const { mandate: top } = martaMandate(issuer.publicKey);
  const sub = createSubMandate(issuer, top, { agent: generateKeyPair().publicKey, scope: "one job", maxAmount: { value: "500.00", currency: "EUR" }, notBefore: top.body.notBefore, notAfter: top.body.notAfter });
  assert.equal(chainProblem(sub), null);
  assert.deepEqual(Object.keys(sub.body.owner), ["key"]);
  const forge = (owner: object, parent: Mandate): Mandate => {
    const body = { ...sub.body, parent: mandateId(parent), owner };
    return { body: body as Mandate["body"], signature: signValue(body, issuer), chain: [parent] };
  };
  // The agent adds a domain to its sub-mandate.
  assert.match(String(chainProblem(forge({ domain: "evil.example", key: top.body.owner.key }, top))), /another owner/);
  // The other way round: a domain owner's agent drops the domain.
  const owner = generateKeyPair();
  const domTop = createMandate(owner, { ownerDomain: "alfa.example", agent: issuer.publicKey, scope: "x", ...validity() });
  assert.match(String(chainProblem(forge({ key: owner.publicKey }, domTop))), /another owner/);
});

test("level key: only the owner's own key revokes as owner, even if someone passes other keys", () => {
  const agent = generateKeyPair();
  const { device, mandate } = martaMandate(agent.publicKey);
  const rb = revocationBody(device.publicKey, { target: { kind: "mandate", id: mandateId(mandate) }, reason: "stop" });
  assert.ok(revokes(signedRevocation(rb, device.sign(rb)), mandate));
  const stranger = generateKeyPair();
  const byStranger = createRevocation(stranger, { target: { kind: "mandate", id: mandateId(mandate) } });
  assert.equal(revokes(byStranger, mandate, [stranger.publicKey]), false);
  const claiming = createRevocation(stranger, { target: { kind: "owner-key", key: device.publicKey }, ownerDomain: "evil.example" });
  assert.equal(revokes(claiming, mandate, [stranger.publicKey]), false);
  // The agent can still revoke itself.
  assert.ok(revokes(createRevocation(agent, { target: { kind: "agent", key: agent.publicKey } }), mandate));
});

test("level key: the owner's archive key has no domain either, and must match the mandate exactly", async () => {
  const owner = generateKeyPair();
  const m = createMandate(owner, { agent: generateKeyPair().publicKey, scope: "x", ...validity() });
  const { claim } = await newArchiveKey(owner, undefined);
  assert.equal(archiveKeyProblem(claim, m), null);
  const { claim: withDomain } = await newArchiveKey(owner, "alfa.example");
  assert.match(String(archiveKeyProblem(withDomain, m)), /not from this agent's owner/);
  const domMandate = createMandate(owner, { ownerDomain: "alfa.example", agent: generateKeyPair().publicKey, scope: "x", ...validity() });
  assert.match(String(archiveKeyProblem(claim, domMandate)), /not from this agent's owner/);
});

test("level key: the piazza is for owners with a domain; an owner known only by its key gets a clear refusal", async () => {
  const agent = generateKeyPair();
  const { mandate } = martaMandate(agent.publicKey);
  const deps = { store: new MemoryPiazzaStore(), ownerResolver: noLookups, origin: "https://piazza.example", seal: async () => 0 };
  const env = signEnvelope(agent, mandate, deps.origin, { op: "inbox" });
  const res = await handlePiazza(new Request(deps.origin + "/v1/envelopes", { method: "POST", body: JSON.stringify(env) }), deps);
  assert.equal(res.status, 403);
  assert.match(((await res.json()) as { error: string }).error, /only owners with a domain/);
});

test("level key: Marta (no website, Face ID) and a museum agree through MCP, and the proof is valid with her level shown", async () => {
  const regDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const client = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), regDeps));
  const museumOwner = generateKeyPair();
  const resolver = staticOwnerResolver({ "museo.example": [museumOwner.publicKey] });
  const open = async (mandateFor: (agent: string) => Mandate, requireOwnerDomain = false) => {
    const wallet = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver: resolver, requireOwnerDomain });
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
    return { call, mandate };
  };
  const device = new SoftPasskey();
  const marta = await open((agent) => martaMandate(agent, device).mandate);
  const museum = await open((agent: string) =>
    createMandate(museumOwner as KeyPair, { ownerDomain: "museo.example", agent, scope: "restauri", maxAmount: { value: "10000.00", currency: "EUR" }, ...validity() }),
  );

  const seen = await museum.call("symbolon_check_counterparty", { mandate: marta.mandate });
  assert.equal(seen.ok, true);
  assert.equal(seen.level, "key");
  assert.equal(seen.owner, device.publicKey);

  // Within Marta's 2,000 EUR: fine. Above it, her own wallet refuses (asking her is the next piece of work).
  await assert.rejects(museum.call("symbolon_propose_agreement", { counterparty_mandate: marta.mandate, clauses: { amount: { value: "2400.00", currency: "EUR" } } }), /exceeds the mandate/);
  const offer = await museum.call("symbolon_propose_agreement", {
    counterparty_mandate: marta.mandate,
    clauses: { object: "restauro di una cornice", amount: { value: "1800.00", currency: "EUR" } },
  });
  const accepted = await marta.call("symbolon_accept_agreement", { offer });
  assert.equal(accepted.counterparty.owner, "museo.example");
  await museum.call("symbolon_confirm_agreement", { confirmation: accepted.confirmation });

  const proof = await museum.call("symbolon_create_proof", { entry: accepted.entry, reveal: ["object", "amount"] });
  const report = await marta.call("symbolon_verify_proof", { proof });
  assert.equal(report.valid, true, JSON.stringify([report.gaps, report.checks.filter((c: { ok: boolean }) => !c.ok)]));
  const agents = Object.keys(report.levels);
  assert.equal(agents.length, 2);
  assert.deepEqual(new Set(Object.values(report.levels)), new Set(["key", "domain"]), JSON.stringify(report.levels));
  assert.ok(report.checks.some((c: { name: string; detail?: string }) => /has no domain/.test(c.name) && /identity level key/.test(String(c.detail))));

  // A museum whose owner wants only counterparties with a domain refuses Marta, saying why.
  const strict = await open(
    (agent: string) => createMandate(museumOwner as KeyPair, { ownerDomain: "museo.example", agent, scope: "restauri", ...validity() }),
    true,
  );
  await assert.rejects(
    strict.call("symbolon_propose_agreement", { counterparty_mandate: marta.mandate, clauses: { amount: { value: "100.00", currency: "EUR" } } }),
    /has no domain, and this wallet accepts only owners with a domain/,
  );
});
