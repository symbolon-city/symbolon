import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { MemoryArchiveStore, handleArchive, makeSnapshot, newArchiveKey, ownerView, type Snapshot } from "../src/archive.js";
import { MemoryStore, Register, createMandate, generateKeyPair, staticOwnerResolver, type KeyPair } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

const later = (h: number) => new Date(Date.now() + h * 3_600_000).toISOString();

async function setup() {
  const regDeps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const register = new HttpRegisterClient("https://reg.example", (async (i, init) => handle(new Request(String(i), init), regDeps)) as typeof fetch);
  const table: Record<string, string[]> = {};
  const ownerResolver = staticOwnerResolver(table);
  const company = generateKeyPair();
  table["company.example"] = [company.publicKey];
  const archive = await newArchiveKey(company, "company.example");
  const store = new MemoryArchiveStore();
  let up = true;
  const archiveFetch = (async (i, init) => {
    if (!up) throw new Error("archive unreachable");
    return handleArchive(new Request(String(i), init), { store, ownerKey: company.publicKey });
  }) as typeof fetch;
  const agentOf = async (owner: KeyPair, domain: string, scope: string, withArchive = true) => {
    table[domain] ??= [owner.publicKey];
    const wallet = await Wallet.open(new MemoryWalletStorage(), register, {
      ownerResolver,
      ...(withArchive ? { archive: { url: "https://archive.company.example", claim: archive.claim, fetchImpl: archiveFetch } } : {}),
    });
    await wallet.installMandate(
      createMandate(owner, { ownerDomain: domain, agent: wallet.agentKey, scope, maxAmount: { value: "1000.00", currency: "EUR" }, notBefore: later(-24), notAfter: later(24 * 30), charter: "accord-charter/0.1" }),
    );
    return wallet;
  };
  return { company, archive, store, archiveFetch, agentOf, setUp: (v: boolean) => (up = v) };
}

test("the owner sees the commitments of all its agents; the archive server keeps them sealed", async () => {
  const { company, archive, store, agentOf } = await setup();
  const buyer = await agentOf(company, "company.example", "purchasing");
  const maintenance = await agentOf(company, "company.example", "maintenance");
  const supplier = await agentOf(generateKeyPair(), "supplier.example", "office supplies", false);
  const plumber = await agentOf(generateKeyPair(), "plumber.example", "plumbing", false);

  // Two agents of the same company make two different agreements.
  const o1 = await buyer.propose({ counterparty: supplier.myMandate(), clauses: { object: "toner", amount: { value: "300.00", currency: "EUR" }, delivery: later(48).slice(0, 10) } });
  await buyer.confirm((await supplier.accept(o1)).confirmation);
  await maintenance.propose({ counterparty: plumber.myMandate(), clauses: { service: "boiler check", amount: { value: "90.00", currency: "EUR" } } });

  // The archive keeps one sealed snapshot per agent, and cannot read them.
  const kept = await store.all();
  assert.equal(kept.length, 2);
  assert.doesNotMatch(JSON.stringify(kept), /toner|boiler/);

  // The owner opens them all with its archive key.
  const view = await ownerView(kept, archive.secret, company.publicKey);
  const byScope = Object.fromEntries(view.agents.map((a) => [(a as { scope: string }).scope, a as { commitments: { open: unknown[]; waiting: unknown[] } }]));
  assert.equal(byScope.purchasing.commitments.open.length, 1);
  assert.equal(byScope.maintenance.commitments.waiting.length, 1);
  assert.match(JSON.stringify(view), /toner/);
  assert.match(JSON.stringify(view), /boiler check/);

  // Each agent's own view says when it last saved.
  assert.ok(buyer.commitments().owner_archive?.last_saved_at);
});

test("the archive refuses agents of other owners, forged and replayed snapshots; a lost archive never blocks the agent", async () => {
  const { company, archive, store, archiveFetch, agentOf, setUp } = await setup();
  const buyer = await agentOf(company, "company.example", "purchasing");
  const supplier = await agentOf(generateKeyPair(), "supplier.example", "office supplies", false);
  await buyer.propose({ counterparty: supplier.myMandate(), clauses: { object: "toner", amount: { value: "300.00", currency: "EUR" } } });
  const put = (s: unknown) => archiveFetch("https://archive.company.example/v1/snapshots", { method: "PUT", body: JSON.stringify(s) });

  // An agent of another owner, even using this owner's archive key, is refused.
  const outsiderOwner = generateKeyPair();
  const outsider = generateKeyPair();
  const outsiderMandate = createMandate(outsiderOwner, { ownerDomain: "other.example", agent: outsider.publicKey, scope: "x", notBefore: later(-1), notAfter: later(24), charter: "accord-charter/0.1" });
  const foreign = await makeSnapshot(outsider, outsiderMandate, archive.claim, 1, { open: [] });
  assert.equal((await put(foreign)).status, 400);

  // A snapshot changed after signing, or an older one sent again, is refused.
  const latest = (await store.all())[0] as Snapshot;
  const forged = structuredClone(latest);
  forged.body.at = "2020-01-01T00:00:00.000Z";
  assert.match(((await (await put(forged)).json()) as { error: string }).error, /not signed by the agent/);
  assert.equal((await put(latest)).status, 409, "same or older sequence: refused");

  // The archive is down: the agent keeps working; its commitments say the last save failed.
  setUp(false);
  const o = await buyer.propose({ counterparty: supplier.myMandate(), clauses: { object: "paper", amount: { value: "50.00", currency: "EUR" } } });
  assert.ok(o.record);
  assert.match(buyer.commitments().owner_archive?.last_error ?? "", /unreachable/);
  setUp(true);
  assert.deepEqual(await buyer.saveToOwnerArchive(), { saved: true });
  assert.equal(buyer.commitments().owner_archive?.last_error, undefined);

  // An archive key not signed by this agent's owner is never used.
  const fake = await newArchiveKey(generateKeyPair(), "company.example");
  const w = await Wallet.open(new MemoryWalletStorage(), (buyer as unknown as { register: HttpRegisterClient }).register, {
    archive: { url: "https://archive.company.example", claim: fake.claim, fetchImpl: archiveFetch },
  });
  await w.installMandate(createMandate(company, { ownerDomain: "company.example", agent: w.agentKey, scope: "y", notBefore: later(-1), notAfter: later(24), charter: "accord-charter/0.1" }));
  assert.match((await w.saveToOwnerArchive())?.error ?? "", /not from this agent's owner/);
});
