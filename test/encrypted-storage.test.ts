import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EncryptedWalletStorage,
  dpapiProvider,
  keychainProvider,
  passphraseProvider,
  providerFromEnv,
  type Runner,
} from "../src/agent/encrypted-storage.js";
import type { WalletState } from "../src/agent/wallet.js";

const FAST = { N: 1 << 12, r: 8, p: 1 }; // light scrypt for tests only
const state = (): WalletState => ({
  v: 1,
  agentSecret: "ab".repeat(32),
  records: { x: { kind: "action", record: {} as any, opened: { root: "r", count: 1, clauses: [{ name: "action", value: "SECRET-REFUND-1043", salt: "s" }] }, mandates: [] } },
  offers: {},
});
const dir = () => mkdtemp(join(tmpdir(), "wallet-"));

test("the wallet file contains nothing readable", async () => {
  const p = join(await dir(), "wallet.json");
  await new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).save(state());
  const raw = await readFile(p, "utf8");
  assert.equal(raw.includes("SECRET-REFUND-1043"), false);
  assert.equal(raw.includes("ab".repeat(32)), false);
  assert.match(raw, /"format": "symbolon-wallet"/);
});

test("the right password opens it, a wrong one does not", async () => {
  const p = join(await dir(), "wallet.json");
  await new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).save(state());
  assert.deepEqual(await new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).load(), state());
  await assert.rejects(new EncryptedWalletStorage(p, passphraseProvider("wrong horse battery!", FAST)).load(), /wrong password/);
});

test("a modified file is refused, including its header", async () => {
  const p = join(await dir(), "wallet.json");
  await new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).save(state());
  const f = JSON.parse(await readFile(p, "utf8"));
  const data = Buffer.from(f.data, "base64");
  data[5] ^= 1;
  await writeFile(p, JSON.stringify({ ...f, data: data.toString("base64") }));
  await assert.rejects(new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).load(), /modified/);
  await writeFile(p, JSON.stringify({ ...f, key: { ...f.key, N: f.key.N * 2 } }));
  await assert.rejects(new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).load());
});

test("every save uses a fresh nonce", async () => {
  const p = join(await dir(), "wallet.json");
  const s = new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST));
  await s.save(state());
  const n1 = JSON.parse(await readFile(p, "utf8")).nonce;
  await s.save(state());
  assert.notEqual(JSON.parse(await readFile(p, "utf8")).nonce, n1);
});

test("a wallet left in clear by the old version is encrypted on first open", async () => {
  const p = join(await dir(), "wallet.json");
  await writeFile(p, JSON.stringify(state()));
  const loaded = await new EncryptedWalletStorage(p, passphraseProvider("correct horse battery", FAST)).load();
  assert.deepEqual(loaded, state());
  assert.equal((await readFile(p, "utf8")).includes("SECRET-REFUND-1043"), false);
});

test("short passwords are refused", () => {
  assert.throws(() => passphraseProvider("short"), /at least 12/);
});

test("macOS Keychain: the key is created once and reused", async () => {
  const vault = new Map<string, string>();
  const calls: string[] = [];
  const run: Runner = async (cmd, args) => {
    calls.push(args[0]);
    const id = args[args.indexOf("-s") + 1] + "|" + args[args.indexOf("-a") + 1];
    if (args[0] === "find-generic-password") {
      if (!vault.has(id)) throw new Error("not found");
      return vault.get(id)! + "\n";
    }
    vault.set(id, args[args.indexOf("-w") + 1]);
    return "";
  };
  const p = join(await dir(), "wallet.json");
  await new EncryptedWalletStorage(p, keychainProvider(p, run)).save(state());
  assert.deepEqual(await new EncryptedWalletStorage(p, keychainProvider(p, run)).load(), state());
  assert.equal(calls.filter((c) => c === "add-generic-password").length, 1);
  vault.clear();
  await assert.rejects(new EncryptedWalletStorage(p, keychainProvider(p, run)).load(), /not in the Keychain/);
});

test("Windows DPAPI: the key is stored protected next to the wallet", async () => {
  // Fake DPAPI: wraps the key; a real one ties it to the Windows user.
  const run: Runner = async (_cmd, args, input) => {
    const script = args[args.length - 1];
    const b = Buffer.from(input!.trim(), "base64");
    return script.includes("::Unprotect(") ? Buffer.from(b.subarray(4)).toString("base64") : Buffer.concat([Buffer.from("DPAP"), b]).toString("base64");
  };
  const p = join(await dir(), "wallet.json");
  await new EncryptedWalletStorage(p, dpapiProvider(p + ".key", run)).save(state());
  const blob = await readFile(p + ".key", "utf8");
  assert.ok(Buffer.from(blob, "base64").subarray(0, 4).equals(Buffer.from("DPAP")));
  assert.deepEqual(await new EncryptedWalletStorage(p, dpapiProvider(p + ".key", run)).load(), state());
});

test("the provider is chosen by system and never falls back to clear", () => {
  const run: Runner = async () => "";
  assert.doesNotThrow(() => providerFromEnv("/w", {}, "darwin", run));
  assert.doesNotThrow(() => providerFromEnv("/w", {}, "win32", run));
  assert.throws(() => providerFromEnv("/w", {}, "linux", run), /SYMBOLON_WALLET_PASSWORD/);
  assert.throws(() => providerFromEnv("/w", { SYMBOLON_WALLET_KEY: "none" }, "linux", run), /unknown/);
});
