import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fromHex } from "../src/bytes.js";
import { MemoryStore, Register, Witness, generateKeyPair, verifyHeadSignature, verifyInclusion, verifyConsistency, entryLeaf, type Receipt, type SignedTreeHead } from "../src/index.js";
import { anchorLatest, handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

const fx = JSON.parse(readFileSync(new URL("./fixtures/calendar-responses.json", import.meta.url), "utf8")) as Record<string, string>;

function app() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://register.example" };
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await handle(
      new Request("https://register.example" + path, { method, body: body === undefined ? undefined : JSON.stringify(body) }),
      deps,
    );
    return { status: res.status, body: (await res.json()) as any };
  };
  return { deps, call };
}

const entry = (i: number) => i.toString(16).padStart(64, "0");

test("entries get a signed receipt with a valid inclusion path", async () => {
  const { call } = app();
  for (let i = 0; i < 5; i++) await call("POST", "/v1/entries", { entry: entry(i) });
  const r = await call("GET", `/v1/entries/${entry(2)}`);
  assert.equal(r.status, 200);
  const rec = r.body as Receipt;
  assert.ok(verifyHeadSignature(rec.head));
  assert.ok(verifyInclusion(entryLeaf(rec.entry), rec.index, rec.head.size, rec.path.map(fromHex), fromHex(rec.head.root)));
});

test("the same entry twice keeps its first position", async () => {
  const { call } = app();
  const a = await call("POST", "/v1/entries", { entry: entry(7) });
  await call("POST", "/v1/entries", { entry: entry(8) });
  const b = await call("POST", "/v1/entries", { entry: entry(7) });
  assert.equal(a.body.index, 0);
  assert.equal(b.body.index, 0);
});

test("consistency proofs served by the API verify", async () => {
  const { call } = app();
  for (let i = 0; i < 9; i++) await call("POST", "/v1/entries", { entry: entry(i) });
  const h3 = (await call("GET", "/v1/heads/3")).body as SignedTreeHead;
  const h9 = (await call("GET", "/v1/head")).body as SignedTreeHead;
  const p = (await call("GET", "/v1/consistency?from=3&to=9")).body.proof as string[];
  assert.ok(verifyConsistency(3, 9, fromHex(h3.root), fromHex(h9.root), p.map(fromHex)));
});

test("bad input is refused", async () => {
  const { call } = app();
  assert.equal((await call("POST", "/v1/entries", { entry: "hello" })).status, 400);
  assert.equal((await call("GET", "/v1/consistency?from=0&to=1")).status, 400);
  assert.equal((await call("GET", "/v1/head")).status, 404);
  assert.equal((await call("GET", "/nope")).status, 404);
});

test("witnesses can publish countersignatures; forged ones are refused", async () => {
  const { call } = app();
  await call("POST", "/v1/entries", { entry: entry(1) });
  const head = (await call("GET", "/v1/head")).body as SignedTreeHead;
  const w = new Witness(generateKeyPair());
  const c = w.observe(head, []);
  assert.equal((await call("POST", "/v1/cosignatures", c)).status, 201);
  assert.equal((await call("POST", "/v1/cosignatures", { ...c, root: "00".repeat(32) })).status, 400);
  assert.equal((await call("GET", "/v1/cosignatures/1")).body.length, 1);
});

test("the daily job anchors the latest head once", async () => {
  const { deps, call } = app();
  await call("POST", "/v1/entries", { entry: entry(1) });
  const calendars = Object.keys(fx).filter((k) => k.startsWith("https://"));
  // Fake calendars: each answers with a bare pending attestation pointing to itself.
  const fake: typeof fetch = async (u) => {
    const base = calendars.find((c) => String(u).startsWith(c));
    if (!base) return new Response("", { status: 404 });
    const uri = new TextEncoder().encode(base);
    const payload = [uri.length, ...uri];
    const bytes = new Uint8Array([0x00, ...fromHex("83dfe30d2ef90c8e"), payload.length, ...payload]);
    return new Response(bytes as unknown as BodyInit);
  };
  assert.ok(await anchorLatest(deps, fake));
  assert.equal(await anchorLatest(deps, fake), null, "nothing new to anchor");
  assert.equal((await call("GET", "/v1/anchors/latest")).body.state, "pending");
});

test("writes refused by the anti-spam gate get HTTP 429 and change nothing", async () => {
  const { deps, call } = app();
  let allowed = 2;
  deps.allowWrite = async () => (allowed-- > 0 ? null : "too many writes");
  assert.equal((await call("POST", "/v1/entries", { entry: entry(1) })).status, 201);
  assert.equal((await call("POST", "/v1/entries", { entry: entry(2) })).status, 201);
  const r = await call("POST", "/v1/entries", { entry: entry(3) });
  assert.equal(r.status, 429);
  assert.equal(await deps.register.store.size(), 2);
  assert.equal((await call("GET", "/v1/head")).status, 200); // reads are never limited
});
