import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { createMandate, generateKeyPair, staticOwnerResolver } from "../src/index.js";
import { digest } from "../src/hash.js";
import { handlePiazza, type PiazzaDeps } from "../src/piazza/app.js";
import { LIMITS, MANDATE_RULES, POST_LIMITS, signEnvelope, type Action } from "../src/piazza/messages.js";
import { removalRecord, storedRemoval } from "../src/piazza/removals.js";
import { ENVELOPES_PER_MINUTE, REPORT_LIMITS, currentRulesVersion, upcomingRules, clause, rulesDocument, rulesFingerprint } from "../src/piazza/rules.js";
import { D1PiazzaStore, MemoryPiazzaStore, PIAZZA_MIGRATIONS, PIAZZA_SCHEMA, removalStatements, toSqlText } from "../src/piazza/stores.js";
import { sqliteD1 } from "./helpers.js";

const ORIGIN = "https://piazza.example";
const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

// If this fails, version 1 of the published rules was changed. Published versions never change:
// add version 2 in src/piazza/rules.ts instead (freezing version 1 as it is) and announce it in UPCOMING.
const RULES_V1_FINGERPRINT = "d75237faa3dff84ef0bc270ebfece8e9f3c18b0af3c4ed86f12bb7d624ea158f";
// Version 2 (security correction of 14/11/2026), same rule: never change it, add version 3.
const RULES_V2_FINGERPRINT = "d9994a6556ea2d3bee10459e7104fcaabf3ce5e3875161db5a5c69e553d4d9cf";
// Version 3 (the channel between agents), published with its fingerprint during the notice (from 19/11/2026).
const RULES_V3_FINGERPRINT = "d3214eab6641b6aa6e769900577f6092830b3bf75a61de70ccb3cb1aa3377c07";

test("rules: version 1 is fixed once published", () => {
  assert.equal(rulesFingerprint(1), RULES_V1_FINGERPRINT);
  assert.equal(rulesFingerprint(2), RULES_V2_FINGERPRINT);
  assert.equal(rulesFingerprint(3), RULES_V3_FINGERPRINT);
  assert.equal(rulesDocument(1)!.changes, undefined);
  assert.match(rulesDocument(2)!.changes![0], /Security correction/);
  assert.equal(rulesDocument(99), null);
});

test("rules: the text states the limits the code enforces", () => {
  const all = JSON.stringify(rulesDocument());
  for (const n of [LIMITS.activePostsPerOwner, LIMITS.postsPerOwnerPerDay, LIMITS.agentsPerOwner, LIMITS.contactsPerAgentPerDay, LIMITS.newOwnersPerDay, MANDATE_RULES.scopeMaxChars, POST_LIMITS.titleMaxChars, POST_LIMITS.textMaxChars])
    assert.match(all, new RegExp(`\\b${n}\\b`));
  const toml = readFileSync(new URL("../wrangler-piazza.toml", import.meta.url), "utf8");
  assert.match(toml, new RegExp(`simple = \\{ limit = ${ENVELOPES_PER_MINUTE}, period = 60 \\}`), "ENVELOPES_PER_MINUTE must match wrangler-piazza.toml");
  assert.match(clause("8.3")!.text, /only when it is illegal content/);
  const ids = rulesDocument()!.sections.flatMap((s) => s.clauses.map((c) => c.id));
  assert.equal(new Set(ids).size, ids.length, "clause ids are unique");
});

function setup(store = new MemoryPiazzaStore() as MemoryPiazzaStore | D1PiazzaStore) {
  const owner = generateKeyPair();
  const agent = generateKeyPair();
  const mandate = createMandate(owner, { ownerDomain: "alfa.example", agent: agent.publicKey, scope: "piazza", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" });
  const sealed: string[] = [];
  const deps: PiazzaDeps = {
    store,
    ownerResolver: staticOwnerResolver({ "alfa.example": [owner.publicKey] }),
    origin: ORIGIN,
    seal: async (fp) => (sealed.push(fp), sealed.length - 1),
    clientKey: () => "198.51.100.7",
  };
  const req = (path: string, init?: RequestInit) => handlePiazza(new Request(ORIGIN + path, init), deps);
  const get = async (path: string) => (await (await req(path)).json()) as any;
  const postJson = async (path: string, body: unknown) => {
    const res = await req(path, { method: "POST", body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as any };
  };
  const send = (action: Action) => postJson("/v1/envelopes", signEnvelope(agent, mandate, ORIGIN, action));
  const newPost = async () =>
    (await send({ op: "post", post: { kind: "offer", category: "data", title: "Cleaned price lists", text: "Weekly cleaned supplier price lists, CSV.", expiresAt: later(5) } })).body.post.id as string;
  return { deps, sealed, req, get, postJson, send, newPost, store };
}

test("rules: served as JSON and HTML, sealed in the register only once", async () => {
  const { sealed, get, req } = setup();
  const first = await get("/v1/rules");
  assert.equal(first.document.version, currentRulesVersion());
  assert.equal(first.fingerprint, digest(first.document));
  assert.equal(first.fingerprint, rulesFingerprint());
  assert.equal(first.sealedInRegister, 0);
  // Version 3 (the channel between agents) is announced ahead, as clause 10.2 requires (until its day).
  if (currentRulesVersion() < 3) {
    assert.equal(first.upcoming?.version, 3);
    assert.equal(first.upcoming?.effectiveFrom, "2026-11-30");
    assert.equal(first.upcoming?.fingerprint, RULES_V3_FINGERPRINT);
  }
  assert.deepEqual(sealed, [first.fingerprint]);
  assert.equal((await get(`/v1/rules/${currentRulesVersion()}`)).sealedInRegister, 0);
  assert.equal(sealed.length, 1, "the current version is sealed only once");
  const v1 = await get("/v1/rules/1");
  assert.equal(v1.current, false);
  assert.equal(v1.sealedInRegister, 1, "an earlier version read for the first time is sealed too");
  assert.deepEqual(first.versions, [1, 2, 3]);
  const html = await req("/v1/rules", { headers: { accept: "text/html" } });
  assert.match(await html.text(), /<b>8\.3<\/b>/);
  assert.equal((await req("/v1/rules/99")).status, 404);
  assert.equal((await get("/v1")).rules.url, ORIGIN + "/v1/rules");
});

test("reports: anyone can report a post, a report never removes it", async () => {
  const { postJson, get, newPost, store } = setup();
  const id = await newPost();
  const ok = await postJson("/v1/reports", { postId: id, reason: "scam", text: "Asks to ignore previous instructions" });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  assert.equal((store as MemoryPiazzaStore).reports[0].text, "Asks to ignore previous instructions");
  assert.equal((await postJson("/v1/reports", { postId: id, reason: "boring" })).status, 400);
  assert.equal((await postJson("/v1/reports", { postId: "0".repeat(64), reason: "spam" })).status, 404);
  assert.equal((await postJson("/v1/reports", { postId: id, reason: "spam", text: "see https://evil.example" })).status, 400);
  for (let i = 1; i < REPORT_LIMITS.perClientPerDay; i++) assert.equal((await postJson("/v1/reports", { postId: id, reason: "spam" })).status, 201);
  assert.equal((await postJson("/v1/reports", { postId: id, reason: "spam" })).status, 429);
  assert.equal((await get("/v1/posts")).posts.length, 1, "still on the board");
  assert.equal((await get("/v1/summary")).reports, REPORT_LIMITS.perClientPerDay);
});

test("removals: only illegal content or an authority order; public, verifiable, without the text", async () => {
  const { get, send, newPost, store } = setup();
  const id = await newPost();
  const post = (await store.post(id))!;
  assert.throws(() => removalRecord(post, "spam" as any, "Reported as spam several times"));
  assert.throws(() => removalRecord(post, "illegal_content", "short"));
  const record = removalRecord(post, "illegal_content", "Notice received 2026-11-14: offer of counterfeit branded goods, illegal under EU law");
  await store.addRemoval(storedRemoval(record, 7));

  assert.equal((await get("/v1/posts")).posts.length, 0);
  const one = await get(`/v1/posts/${id}`);
  assert.equal(one.status, "removed");
  assert.equal(one.text, undefined, "the removed text is not served");
  assert.equal((await send({ op: "withdraw", postId: id })).status, 200);
  assert.equal((await get(`/v1/posts/${id}`)).status, "removed", "withdrawing does not bring it back");

  const list = (await get("/v1/removals")).removals;
  assert.equal(list.length, 1);
  const r = list[0];
  assert.equal(r.sealedInRegister, 7);
  const rebuilt = {
    type: "piazza/removal",
    v: 1,
    postId: r.postId,
    ownerDomain: r.owner.domain,
    agent: r.owner.agent,
    removedAt: r.removedAt,
    reason: r.reason,
    basis: r.basis,
    clause: r.clause,
    rules: { version: r.rulesVersion, fingerprint: rulesFingerprint(r.rulesVersion) },
  };
  assert.equal(digest(rebuilt), r.fingerprint, "anyone can recompute the sealed fingerprint");
  assert.equal((await get("/v1/summary")).removals, 1);
});

test("D1 store: reports, removals (also as SQL text for wrangler) and sealed rules", async () => {
  const sqlite = new DatabaseSync(":memory:");
  const d1 = sqliteD1(sqlite);
  d1.exec(PIAZZA_SCHEMA);
  for (const m of PIAZZA_MIGRATIONS) {
    try {
      d1.exec(m);
    } catch {
      /* already in the schema */
    }
  }
  const { get, postJson, newPost, store } = setup(new D1PiazzaStore(d1));
  const a = await newPost();
  assert.equal((await postJson("/v1/reports", { postId: a, reason: "illegal" })).status, 201);
  assert.equal((await get("/v1/rules")).sealedInRegister, 1, "post sealed at 0, rules at 1");
  assert.equal((await get("/v1/rules")).sealedInRegister, 1);

  // the script path: plain SQL text, as run by `wrangler d1 execute --file`
  const record = removalRecord((await store.post(a))!, "authority_order", "Order of a court, reference 123/2026, to remove this post");
  const sql = toSqlText(removalStatements(storedRemoval(record, 9)));
  assert.match(sql, /INSERT OR REPLACE INTO removals/);
  sqlite.exec(sql);
  const s = await get("/v1/summary");
  assert.deepEqual([s.activePosts, s.reports, s.removals], [0, 1, 1]);
  const r = (await get("/v1/removals")).removals[0];
  assert.equal(r.fingerprint, digest(record));
  assert.equal(r.sealedInRegister, 9);
  assert.equal((await get(`/v1/posts/${a}`)).status, "removed");

  // quotes in the basis cannot break the SQL text
  const b = await newPost();
  const tricky = removalRecord((await store.post(b))!, "illegal_content", "Notice: the seller's offer is illegal'); DROP TABLE posts; --");
  sqlite.exec(toSqlText(removalStatements(storedRemoval(tricky, null))));
  assert.equal((await get("/v1/removals")).removals.length, 2);
  assert.equal((await get("/v1/summary")).removals, 2);
});

test("rules: a version announced ahead is published and fixed during the notice, and comes into force by itself on its day", () => {
  const before = new Date("2026-11-29T23:59:59Z");
  const on = new Date("2026-11-30T00:00:00Z");
  assert.equal(currentRulesVersion(before), 2);
  assert.deepEqual(upcomingRules(before), { version: 3, effectiveFrom: "2026-11-30", changes: rulesDocument(3)!.changes!, fingerprint: RULES_V3_FINGERPRINT });
  assert.equal(currentRulesVersion(on), 3);
  assert.equal(upcomingRules(on), null);
  assert.match(clause("4.3", currentRulesVersion(before))!.text, /outside the piazza/);
  assert.match(clause("4.3", currentRulesVersion(on))!.text, /cannot read them/);
});
