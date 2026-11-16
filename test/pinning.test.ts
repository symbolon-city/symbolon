import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { KNOWN_REGISTERS, MemoryStore, Register, createMandate, generateKeyPair, pinnedRegisterKey, staticOwnerResolver, type KeyPair } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

function registerWith(key: KeyPair) {
  const deps: AppDeps = { register: new Register(key, new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  return (async (input, init) => handle(new Request(String(input), init), deps)) as typeof fetch;
}

test("the test register's key is fixed in the code, found whatever the spelling of its address", () => {
  const known = KNOWN_REGISTERS.find((r) => r.url.includes("registro-prova"))!;
  assert.match(known.key, /^ed25519:[0-9a-f]{64}$/);
  assert.equal(pinnedRegisterKey("https://registro-prova.symbolon-city.workers.dev"), known.key);
  assert.equal(pinnedRegisterKey("https://REGISTRO-PROVA.symbolon-city.workers.dev/"), known.key);
  assert.equal(pinnedRegisterKey("https://registro-prova.symbolon-city.workers.dev.evil.example"), undefined);
  assert.equal(pinnedRegisterKey("http://registro-prova.symbolon-city.workers.dev"), undefined, "plain http is another address");
  assert.equal(new HttpRegisterClient("https://registro-prova.symbolon-city.workers.dev", fetch).pinnedKey, known.key);
});

test("an impostor register (other key at the same address) is refused before anything is sealed", async () => {
  const real = generateKeyPair();
  const impostor = generateKeyPair();
  const client = new HttpRegisterClient("https://reg.example", registerWith(impostor), { key: real.publicKey });
  await assert.rejects(client.info(), /register key mismatch/);
  await assert.rejects(client.append("ab".repeat(32)), /not signed by its pinned key/);
  await assert.rejects(client.head(), /not signed by its pinned key/);

  // A wallet on the impostor cannot seal: the receipt is refused.
  const owner = generateKeyPair();
  const wallet = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey] }) });
  await wallet.installMandate(createMandate(owner, { ownerDomain: "alfa.example", agent: wallet.agentKey, scope: "support", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" }));
  await assert.rejects(wallet.sealAction({ instruction: "refund order 7", action: "refunded 12.00 EUR" }), /pinned key/);
});

test("with the right pinned key everything works, and verification trusts only that key", async () => {
  const real = generateKeyPair();
  const client = new HttpRegisterClient("https://reg.example", registerWith(real), { key: real.publicKey });
  assert.equal((await client.info()).register_key, real.publicKey);
  const receipt = await client.append("cd".repeat(32));
  assert.equal(receipt.head.log, real.publicKey);
  assert.equal((await client.receipt("cd".repeat(32)))?.index, 0);
  assert.equal((await client.head())?.size, 1);
});

test("an unknown register without a pinned key still works (taken at its word), as before", async () => {
  const client = new HttpRegisterClient("https://reg.example", registerWith(generateKeyPair()));
  assert.equal(client.pinnedKey, undefined);
  assert.match((await client.info()).register_key, /^ed25519:/);
  assert.equal((await client.append("ef".repeat(32))).index, 0);
});
