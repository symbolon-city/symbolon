import { test } from "node:test";
import assert from "node:assert/strict";
import { toHex } from "../src/bytes.js";
import { generateKeyPair, keyPairFromSecret } from "../src/index.js";
import { handlePiazza, type PiazzaDeps } from "../src/piazza/app.js";
import { PERSONAS, demoAgentKey, parseDemoPost, runDemoCity } from "../src/piazza/demo.js";
import { checkPost } from "../src/piazza/messages.js";
import { MemoryPiazzaStore } from "../src/piazza/stores.js";

const ORIGIN = "https://piazza.example";

function setup() {
  const secret = toHex(generateKeyPair().secretKey);
  const sealed: string[] = [];
  const deps: PiazzaDeps = {
    store: new MemoryPiazzaStore(),
    ownerResolver: async (d) => (d === "piazza.example" ? [keyPairFromSecret(secret).publicKey] : null),
    origin: ORIGIN,
    demoDomain: "piazza.example",
    seal: async (fp) => (sealed.push(fp), sealed.length - 1),
  };
  const get = async (path: string) => (await (await handlePiazza(new Request(ORIGIN + path), deps)).json()) as any;
  return { secret, deps, sealed, get };
}

test("every prepared demo post follows the piazza rules", () => {
  const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
  for (const p of PERSONAS)
    for (const t of p.templates) assert.equal(checkPost({ kind: p.kind, category: p.category, ...t, expiresAt }), null, `${p.name}: ${t.title}`);
});

test("the demo agents keep one labelled post each, sealed like any other, and count apart", async () => {
  const { secret, deps, sealed, get } = setup();
  // Earlier test agents of the demo owner do not block the demonstration agents.
  for (let i = 0; i < 5; i++) await deps.store.addPost({ id: String(i).repeat(64), agent: generateKeyPair().publicKey, ownerDomain: "piazza.example", content: { kind: "offer", category: "other", title: "old test", text: "old test post", expiresAt: new Date(Date.now() - 1000).toISOString() }, createdAt: new Date(Date.now() - 2 * 86_400_000).toISOString(), status: "withdrawn", demo: true, registerIndex: null });
  const first = await runDemoCity({ deps, ownerSecret: secret });
  assert.deepEqual(first.failed, []);
  assert.equal(first.posted.length, PERSONAS.length);
  assert.equal(sealed.length, PERSONAS.length);
  const board = await get("/v1/posts");
  assert.equal(board.posts.length, PERSONAS.length);
  assert.ok(board.posts.every((p: any) => p.author.demo === true && p.author.ownerDomain === "piazza.example"));
  const agents = new Set(board.posts.map((p: any) => p.author.agent));
  assert.ok(PERSONAS.every((p) => agents.has(demoAgentKey(secret, p.name).publicKey)));
  const summary = await get("/v1/summary");
  assert.equal(summary.demoPosts, PERSONAS.length);

  const second = await runDemoCity({ deps, ownerSecret: secret });
  assert.equal(second.posted.length, 0, "nothing new while their posts are active");
  assert.equal(second.kept.length, PERSONAS.length);

  const future = new Date(Date.now() + 3 * 86_400_000);
  const later = await runDemoCity({ deps: { ...deps, now: () => future }, ownerSecret: secret, now: future });
  assert.equal(later.posted.length, PERSONAS.length, "expired posts are replaced");
});

test("the writer is used within its daily limit, and its text must follow the rules", async () => {
  const { secret, deps, get } = setup();
  let calls = 0;
  const result = await runDemoCity({
    deps,
    ownerSecret: secret,
    maxWrites: 2,
    writer: async (persona) => {
      calls++;
      return calls === 1
        ? { title: `Fresh example from ${persona.name}`, text: "A short, plain example of what this business offers or needs, with no contacts." }
        : { title: "Visit our site", text: "See www.example-shop.com for details" };
    },
  });
  assert.equal(calls, 2);
  assert.equal(result.posted.length, PERSONAS.length);
  const titles = (await get("/v1/posts")).posts.map((p: any) => p.title);
  assert.ok(titles.includes(`Fresh example from ${PERSONAS[0].name}`));
  assert.ok(!titles.includes("Visit our site"), "a text with a link falls back to a prepared post");
});

test("demo agents belong only to the piazza's own domain", async () => {
  const { secret, deps } = setup();
  await assert.rejects(runDemoCity({ deps: { ...deps, demoDomain: "other.example" }, ownerSecret: secret }));
});

test("the model answer is read as two lines", () => {
  assert.deepEqual(parseDemoPost("TITLE: Pallets to Lyon\nTEXT: Four pallets next week."), { title: "Pallets to Lyon", text: "Four pallets next week." });
  assert.equal(parseDemoPost("Sorry, I cannot help."), null);
});

test("two demo agents of different demo owners make a daily agreement whose proof anyone can verify", async () => {
  const { secret, deps, get } = setup();
  const { Register, MemoryStore, verifyProof } = await import("../src/index.js");
  const { handle } = await import("../src/server/app.js");
  const { MemoryExtras } = await import("../src/server/stores.js");
  const { HttpRegisterClient } = await import("../src/agent/client.js");
  const { runDemoAgreement, demoPartnerOwner, DEMO_NOTE } = await import("../src/piazza/demo.js");
  const regDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const register = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), regDeps));

  const done = await runDemoAgreement({ deps, ownerSecret: secret, partnerDomain: "demo.example", register });
  assert.ok(done);
  assert.equal(done.valid, true);
  assert.equal(await runDemoAgreement({ deps, ownerSecret: secret, partnerDomain: "demo.example", register }), null, "one a day");

  const list = await get("/v1/demo/agreements");
  assert.equal(list.agreements.length, 1);
  const proof = list.agreements[0].proof;
  // An outside verifier, reading both owners' published keys.
  const ownerResolver = async (d: string) =>
    d === "piazza.example" ? [keyPairFromSecret(secret).publicKey] : d === "demo.example" ? [demoPartnerOwner(secret).publicKey] : null;
  const report = await verifyProof(proof, { trustedLogs: [regDeps.register.publicKey], ownerResolver, revocations: (s) => register.revocations(s) });
  assert.equal(report.valid, true, JSON.stringify(report.checks.filter((c) => !c.ok)));
  assert.equal(report.disclosed.note, DEMO_NOTE);
  assert.ok(Object.values(report.levels).every((l) => l === "domain"));
  assert.equal(new Set(proof.mandates.map((m: any) => m.body.owner.domain)).size, 2, "two different owners");
});
