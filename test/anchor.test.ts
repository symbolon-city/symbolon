import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fromBase64, fromHex, toBase64, toHex } from "../src/bytes.js";
import {
  allAttestations,
  applyOp,
  fromOtsFile,
  headDigest,
  newTimestamp,
  parseTimestamp,
  serializeTimestamp,
  stamp,
  toOtsFile,
  upgradeAnchor,
  verifyAnchor,
  verifyProof,
  verifyTimestamp,
  type Anchor,
  type BlockProvider,
  type Op,
  type Timestamp,
} from "../src/index.js";
import { scenario } from "./helpers.js";

const fx = JSON.parse(readFileSync(new URL("./fixtures/calendar-responses.json", import.meta.url), "utf8")) as Record<string, string>;
const digest = fromHex(fx.digest);
const calendars = Object.keys(fx).filter((k) => k.startsWith("https://"));

/** A fake fetch answering like the real calendars did. */
const fakeCalendars: typeof fetch = async (input) => {
  const url = String(input);
  const base = calendars.find((c) => url.startsWith(c));
  return base ? new Response(fromHex(fx[base]) as unknown as BodyInit) : new Response("no", { status: 404 });
};

/** Builds a timestamp whose final value is in a (fake) Bitcoin block. */
function confirmed(msg: Uint8Array, height: number): { ts: Timestamp; blocks: BlockProvider } {
  const ts = newTimestamp(msg);
  const op: Op = { tag: "sha256" };
  const inBlock = applyOp(op, msg);
  ts.ops.push({ op, stamp: { msg: inBlock, attestations: [{ kind: "bitcoin", height }], ops: [] } });
  const merkleRoot = toHex(inBlock.slice().reverse());
  return { ts, blocks: async (h) => (h === height ? { merkleRoot, time: 1_800_000_000 } : Promise.reject(new Error("no block"))) };
}

test("real calendar answers are read and written back byte for byte", () => {
  for (const c of calendars) {
    const ts = parseTimestamp(fromHex(fx[c]), digest);
    assert.equal(toHex(serializeTimestamp(ts)), fx[c]);
    const pending = allAttestations(ts).filter((a) => a.attestation.kind === "pending");
    assert.equal(pending.length, 1);
  }
});

test("stamp merges several calendars into one standard .ots file", async () => {
  const ts = await stamp(digest, { calendars, fetchImpl: fakeCalendars });
  const file = toOtsFile(ts);
  const back = fromOtsFile(file);
  assert.equal(toHex(back.msg), fx.digest);
  assert.equal(toHex(toOtsFile(back)), toHex(file));
  assert.equal(allAttestations(back).filter((a) => a.attestation.kind === "pending").length, calendars.length);
});

test("stamp fails if too few calendars answer", async () => {
  await assert.rejects(stamp(digest, { calendars: [calendars[0], "https://down.example"], fetchImpl: fakeCalendars, minCalendars: 2 }));
});

test("a pending timestamp is reported as pending", async () => {
  const ts = await stamp(digest, { calendars, fetchImpl: fakeCalendars });
  const r = await verifyTimestamp(ts, async () => Promise.reject(new Error("unused")));
  assert.equal(r.status, "pending");
});

test("a Bitcoin attestation is checked against the block's merkle root", async () => {
  const { ts, blocks } = confirmed(digest, 900_000);
  assert.deepEqual(await verifyTimestamp(ts, blocks), {
    status: "confirmed",
    height: 900_000,
    blockTime: new Date(1_800_000_000_000).toISOString(),
  });
  const wrong: BlockProvider = async () => ({ merkleRoot: "00".repeat(32), time: 0 });
  assert.equal((await verifyTimestamp(ts, wrong)).status, "invalid");
});

test("upgrade replaces a pending attestation with the Bitcoin one", async () => {
  const s = await scenario();
  const head = (await s.register.latestHead())!;
  const ts = newTimestamp(headDigest(head));
  ts.attestations.push({ kind: "pending", uri: "https://cal.example" });
  const anchor: Anchor = { head, ots: toBase64(toOtsFile(ts)) };
  const { ts: done } = confirmed(headDigest(head), 900_001);
  const answer = serializeTimestamp(done);
  const f: typeof fetch = async (u) =>
    String(u) === `https://cal.example/timestamp/${toHex(headDigest(head))}` ? new Response(answer as unknown as BodyInit) : new Response("", { status: 404 });
  const { anchor: up, upgraded } = await upgradeAnchor(anchor, f);
  assert.equal(upgraded, 1);
  const kinds = allAttestations(fromOtsFile(fromBase64(up.ots))).map((a) => a.attestation.kind);
  assert.deepEqual(kinds, ["bitcoin"]);
});

test("a proof can carry a Bitcoin anchor of a later tree head", async () => {
  const s = await scenario();
  for (let i = 0; i < 6; i++) await s.register.append(toHex(new Uint8Array(32).fill(i)));
  const later = (await s.register.latestHead())!;
  const { ts, blocks } = confirmed(headDigest(later), 900_002);
  const anchor = { anchor: { head: later, ots: toBase64(toOtsFile(ts)) }, consistency: await s.register.consistency(s.receipt.head.size, later.size) };

  const ok = await verifyProof({ ...s.proof(), anchor }, { ...s.verifyOpts, bitcoin: blocks });
  assert.ok(ok.valid, JSON.stringify(ok.checks.filter((c) => !c.ok)));
  assert.equal(ok.bitcoin.status, "confirmed");

  const notChecked = await verifyProof({ ...s.proof(), anchor }, s.verifyOpts);
  assert.equal(notChecked.bitcoin.status, "not checked");

  const forged = { ...anchor, consistency: anchor.consistency.map(() => "00".repeat(32)) };
  const bad = await verifyProof({ ...s.proof(), anchor: forged }, { ...s.verifyOpts, bitcoin: blocks });
  assert.equal(bad.valid, false);
});

test("an .ots file for a different head is rejected", async () => {
  const s = await scenario();
  const head = (await s.register.latestHead())!;
  const { ts, blocks } = confirmed(digest, 900_003);
  const r = await verifyAnchor({ head, ots: toBase64(toOtsFile(ts)) }, blocks);
  assert.equal(r.status, "invalid");
});

test("malformed .ots files are rejected, not crashed on", () => {
  assert.throws(() => fromOtsFile(new Uint8Array([1, 2, 3])));
  assert.throws(() => parseTimestamp(fromHex("f0ff"), digest));
});

test("the official OpenTimestamps example (hello-world.txt, 2015) verifies", async () => {
  // Block 358391 as published by any Bitcoin explorer.
  const blocks: BlockProvider = async (h) =>
    h === 358391 ? { merkleRoot: "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00", time: 1432827678 } : Promise.reject(new Error("no block"));
  const ts = fromOtsFile(new Uint8Array(readFileSync(new URL("./fixtures/hello-world.txt.ots", import.meta.url))));
  assert.equal(toHex(ts.msg), "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"); // sha256("Hello World!\n")
  assert.deepEqual(await verifyTimestamp(ts, blocks), { status: "confirmed", height: 358391, blockTime: "2015-05-28T15:41:18.000Z" });
});
