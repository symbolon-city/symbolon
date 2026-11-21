// What survives the launch: proofs of the test register stay verifiable after the launch register replaces it,
// and every check says they were tests, never binding commitments.

import { test } from "node:test";
import assert from "node:assert/strict";
import { KNOWN_REGISTERS, knownRegisterKeys, type KnownRegister } from "../src/known-registers.js";
import { disclose, verifyProof } from "../src/index.js";
import { scenario } from "./helpers.js";

/** Runs fn with an extra known register (the real ones cannot sign in a test: their keys are not here). */
async function withKnown(r: KnownRegister, fn: () => Promise<void>) {
  const list = KNOWN_REGISTERS as KnownRegister[];
  list.push(r);
  try {
    await fn();
  } finally {
    list.splice(list.indexOf(r), 1);
  }
}

test("launch: the test register is a known register, marked as a test", () => {
  const t = KNOWN_REGISTERS.find((r) => r.url === "https://registro-prova.symbolon-city.workers.dev");
  assert.equal(t?.test, true);
  assert.ok(knownRegisterKeys().includes(t!.key));
});

test("launch: a proof of a test register stays valid and is labelled a test; a launch register is not", async () => {
  const s = await scenario();
  await withKnown({ url: "https://old.example", key: s.register.publicKey, name: "Old test register", since: "2026-11-14", test: true }, async () => {
    const report = await verifyProof(s.proof(s.opened.clauses.map((c) => disclose(s.opened, c.name))), s.verifyOpts);
    assert.equal(report.valid, true);
    assert.deepEqual(report.register, { key: s.register.publicKey, name: "Old test register", test: true });
    const label = report.checks.find((c) => c.name === "register is a test register");
    assert.ok(label?.ok && /never binding commitments/.test(label.detail ?? ""));
  });
  await withKnown({ url: "https://launch.example", key: s.register.publicKey, name: "Launch register", since: "2027-01-01" }, async () => {
    const report = await verifyProof(s.proof(s.opened.clauses.map((c) => disclose(s.opened, c.name))), s.verifyOpts);
    assert.deepEqual(report.register, { key: s.register.publicKey, name: "Launch register" });
    assert.equal(report.checks.some((c) => c.name === "register is a test register"), false);
  });
  // A register nobody fixed in the code is not named at all.
  assert.equal((await verifyProof(s.proof(s.opened.clauses.map((c) => disclose(s.opened, c.name))), s.verifyOpts)).register, undefined);
});

test("launch: wallets and the door trust every known register, so old proofs verify against a new register", async () => {
  const s = await scenario();
  await withKnown({ url: "https://old.example", key: s.register.publicKey, name: "Old test register", since: "2026-11-14", test: true }, async () => {
    // A verifier connected to another register (the launch one) still accepts the old register's proof.
    const report = await verifyProof(s.proof(s.opened.clauses.map((c) => disclose(s.opened, c.name))), { ...s.verifyOpts, trustedLogs: ["ed25519:" + "1".repeat(64), ...knownRegisterKeys()] });
    assert.equal(report.valid, true);
    assert.equal(report.register?.test, true);
  });
  // Without it being known, the same proof is refused by that verifier.
  const report = await verifyProof(s.proof(s.opened.clauses.map((c) => disclose(s.opened, c.name))), { ...s.verifyOpts, trustedLogs: ["ed25519:" + "1".repeat(64)] });
  assert.equal(report.valid, false);
});
