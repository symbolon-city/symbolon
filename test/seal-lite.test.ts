import { test } from "node:test";
import assert from "node:assert/strict";
import { toHex } from "../src/bytes.js";
import { MemoryStore, Register, createMandate, generateKeyPair, staticOwnerResolver, verifyProof } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { proofFromPackage, sealAction } from "../src/seal-lite.js";

function setup() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://r.example" };
  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => handle(new Request(input, init), deps)) as typeof fetch;
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const mandate = createMandate(owner, {
    ownerDomain: "chat.example",
    agent: agent.publicKey,
    scope: "seal quotes",
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2027-12-31T23:59:59Z",
    charter: "accord-charter/0.1",
  });
  return { deps, fetchImpl, owner, agent, mandate };
}

test("seal-lite: a server-side seal verifies with the normal verifier, revealing only chosen clauses", async () => {
  const { deps, fetchImpl, owner, agent, mandate } = setup();
  const pkg = await sealAction({
    registerUrl: "https://r.example",
    agentSecretHex: toHex(agent.secretKey),
    mandate,
    clauses: { what: "quote", zone: "Roma Nord", price: "300 EUR + IVA" },
    fetchImpl,
  });
  assert.equal(await deps.register.store.size(), 1);
  const proof = proofFromPackage(JSON.parse(JSON.stringify(pkg)), ["price"]);
  assert.equal(proof.disclosures.length, 1);
  const report = await verifyProof(proof, {
    trustedLogs: [deps.register.publicKey],
    ownerResolver: staticOwnerResolver({ "chat.example": [owner.publicKey] }),
    revocations: async () => [],
  });
  assert.ok(report.valid, JSON.stringify(report.checks.filter((c) => !c.ok)));
});

test("seal-lite: refuses a mandate for another agent and sends nothing", async () => {
  const { deps, fetchImpl, mandate } = setup();
  await assert.rejects(
    sealAction({ registerUrl: "https://r.example", agentSecretHex: toHex(generateKeyPair().secretKey), mandate, clauses: { a: "b" }, fetchImpl }),
    /does not name this agent/,
  );
  assert.equal(await deps.register.store.size(), 0);
});
