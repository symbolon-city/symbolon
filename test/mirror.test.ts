import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryStore, Register, copyRegister, generateKeyPair, rewrittenSince } from "../src/index.js";
import { ENTRIES_PAGE, handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { sha256Hex } from "../src/hash.js";
import { utf8 } from "../src/bytes.js";

const fp = (i: number) => sha256Hex(utf8(`entry ${i}`));

function setup() {
  const key = generateKeyPair();
  const store = new MemoryStore();
  const register = new Register(key, store);
  const deps: AppDeps = { register, extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const f = (async (input, init) => handle(new Request(String(input), init), deps)) as typeof fetch;
  return { key, store, register, f };
}

test("the public list gives every entry in order, in pages, with the signed head", async () => {
  const { register, f } = setup();
  for (let i = 0; i < 5; i++) await register.append(fp(i));
  const all = (await (await f("https://reg.example/v1/entries")).json()) as any;
  assert.deepEqual(all.entries, [0, 1, 2, 3, 4].map(fp));
  assert.equal(all.size, 5);
  assert.equal(all.head.size, 5);
  assert.equal(all.next, undefined);
  const page = (await (await f("https://reg.example/v1/entries?from=1&limit=2")).json()) as any;
  assert.deepEqual(page.entries, [fp(1), fp(2)]);
  assert.equal(page.next, 3);
  assert.deepEqual(((await (await f("https://reg.example/v1/entries?from=9")).json()) as any).entries, []);
  assert.equal((await f("https://reg.example/v1/entries?from=-1")).status, 400);
  const capped = (await (await f(`https://reg.example/v1/entries?limit=${ENTRIES_PAGE * 5}`)).json()) as any;
  assert.equal(capped.entries.length, 5);
});

test("anyone can keep a checked copy, across several pages", async () => {
  const { key, register, f } = setup();
  const n = ENTRIES_PAGE + 3;
  for (let i = 0; i < n; i++) await register.append(fp(i));
  const { copy, problems } = await copyRegister("https://reg.example", { key: key.publicKey, fetchImpl: f });
  assert.deepEqual(problems, []);
  assert.equal(copy.entries.length, n);
  assert.equal(copy.entries[n - 1], fp(n - 1));
});

test("a copy refuses a register signed by another key, and needs a key from outside", async () => {
  const { register, f } = setup();
  await register.append(fp(0));
  const { problems } = await copyRegister("https://reg.example", { key: generateKeyPair().publicKey, fetchImpl: f });
  assert.match(problems.join(), /not by the register's key/);
  await assert.rejects(copyRegister("https://reg.example", { fetchImpl: f }), /not known/);
});

test("a dishonest operator rewriting an old entry is caught, by the signed root and by an older copy", async () => {
  const { key, store, register, f } = setup();
  for (let i = 0; i < 4; i++) await register.append(fp(i));
  const before = (await copyRegister("https://reg.example", { key: key.publicKey, fetchImpl: f })).copy;

  // The operator quietly replaces entry 1 and keeps serving the old signed head.
  store.overwriteForTest(1, fp(99));
  const after = await copyRegister("https://reg.example", { key: key.publicKey, fetchImpl: f });
  assert.match(after.problems.join(), /do not give the head's root/);
  assert.match(rewrittenSince(before, after.copy)!, /entry 1 was rewritten/);

  // Comparing with an honest later copy: nothing rewritten, only appended.
  const honest = setup();
  for (let i = 0; i < 2; i++) await honest.register.append(fp(i));
  const c1 = (await copyRegister("https://reg.example", { key: honest.key.publicKey, fetchImpl: honest.f })).copy;
  await honest.register.append(fp(2));
  const c2 = (await copyRegister("https://reg.example", { key: honest.key.publicKey, fetchImpl: honest.f })).copy;
  assert.equal(rewrittenSince(c1, c2), null);
  assert.match(rewrittenSince(c2, c1)!, /shrank/);
});
