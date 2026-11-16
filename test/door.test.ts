import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { MemoryStore, Register, createMandate, createRevocation, generateKeyPair, mandateId, staticOwnerResolver } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { handlePiazza } from "../src/piazza/app.js";
import { MemoryPiazzaStore } from "../src/piazza/stores.js";
import { buildVisitorServer, handleDoor, type DoorDeps } from "../src/visitor/door.js";

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

function setup() {
  const regDeps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const regFetch: typeof fetch = async (input, init) => handle(new Request(String(input), init), regDeps);
  const register = new HttpRegisterClient("https://reg.example", regFetch);
  const table: Record<string, string[]> = {};
  const ownerResolver = staticOwnerResolver(table);
  const piazzaDeps = { store: new MemoryPiazzaStore(), ownerResolver, origin: "https://piazza.example", clientKey: () => "203.0.113.9" };
  const deps: DoorDeps = {
    register,
    registerUrl: "https://reg.example",
    ownerResolver,
    piazza: (path, init) => handlePiazza(new Request("https://piazza.example" + path, init), piazzaDeps),
    piazzaUrl: "https://piazza.example",
  };
  return { deps, register, table, ownerResolver };
}

async function connect(deps: DoorDeps) {
  const client = new Client({ name: "visitor", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await buildVisitorServer(deps).connect(a);
  await client.connect(b);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
    if (r.isError) throw new Error(r.content[0].text);
    return JSON.parse(r.content[0].text);
  };
  return { client, call };
}

test("the visitors' door offers only keyless tools", async () => {
  const { deps } = setup();
  const { client } = await connect(deps);
  const names = (await client.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(names, [
    "piazza_guide",
    "piazza_guide_feedback",
    "piazza_read",
    "piazza_report",
    "piazza_rules",
    "symbolon_about",
    "symbolon_check_counterparty",
    "symbolon_check_possession",
    "symbolon_lookup_fingerprint",
    "symbolon_new_challenge",
    "symbolon_seal_fingerprint",
    "symbolon_submit_revocation",
    "symbolon_verify_proof",
  ]);
});

test("a visitor seals a fingerprint and finds it again", async () => {
  const { deps } = setup();
  const { call } = await connect(deps);
  const fp = sha("my invoice 2026-118");
  assert.deepEqual(await call("symbolon_lookup_fingerprint", { fingerprint: fp }), { found: false });
  const sealed = await call("symbolon_seal_fingerprint", { fingerprint: fp });
  assert.equal(sealed.receipt.index, 0);
  const found = await call("symbolon_lookup_fingerprint", { fingerprint: fp });
  assert.equal(found.found, true);
  assert.equal(found.receipt.index, 0);
  const about = await call("symbolon_about");
  assert.equal(about.register.size, 1);
  await assert.rejects(call("symbolon_seal_fingerprint", { fingerprint: "not a fingerprint" }));
});

test("a visitor checks a counterparty: published owner key or not", async () => {
  const { deps, table } = setup();
  const { call } = await connect(deps);
  const owner = generateKeyPair();
  const mandate = createMandate(owner, { ownerDomain: "alfa.example", agent: generateKeyPair().publicKey, scope: "translations", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" });
  const before = await call("symbolon_check_counterparty", { mandate });
  assert.equal(before.ok, false);
  assert.equal(before.level, "unverified");
  table["alfa.example"] = [owner.publicKey];
  const after = await call("symbolon_check_counterparty", { mandate: JSON.stringify(mandate) });
  assert.equal(after.ok, true);
  assert.equal(after.level, "domain");
  const forged = { ...mandate, body: { ...mandate.body, scope: "anything" } };
  assert.ok((await call("symbolon_check_counterparty", { mandate: forged })).problems.includes("mandate signature is invalid"));

  // The owner revokes it through any agent: the door forwards the signed revocation, it signs nothing.
  const revocation = createRevocation(owner, { target: { kind: "mandate", id: mandateId(mandate) }, reason: "contract ended" });
  const sealed = await call("symbolon_submit_revocation", { revocation: JSON.stringify(revocation) });
  assert.equal(typeof sealed.applies_from.register_index, "number");
  const revoked = await call("symbolon_check_counterparty", { mandate });
  assert.equal(revoked.ok, false);
  assert.equal(revoked.revoked.reason, "contract ended");
  await assert.rejects(call("symbolon_submit_revocation", { revocation: { ...revocation, signature: "00" } }), /signature/);
});

test("a visitor verifies a proof made by a citizen's wallet", async () => {
  const { deps, register, table, ownerResolver } = setup();
  const owner = generateKeyPair();
  table["alfa.example"] = [owner.publicKey];
  const wallet = await Wallet.open(new MemoryWalletStorage(), register, { ownerResolver });
  await wallet.installMandate(
    createMandate(owner, { ownerDomain: "alfa.example", agent: wallet.agentKey, scope: "support", notBefore: later(-1), notAfter: later(30), charter: "accord-charter/0.1" }),
  );
  const sealed = await wallet.sealAction({ instruction: "refund order 7", action: "refunded 12.00 EUR" });
  const proof = await wallet.createProof(sealed.entry, ["action"]);
  const { call } = await connect(deps);
  const report = await call("symbolon_verify_proof", { proof });
  assert.equal(report.valid, true, JSON.stringify(report.checks.filter((c: { ok: boolean }) => !c.ok)));
  const tampered = JSON.parse(JSON.stringify(proof));
  tampered.receipt.index += 1;
  assert.equal((await call("symbolon_verify_proof", { proof: tampered })).valid, false);
});

test("the piazza is readable and the Guide answers visitors", async () => {
  const { deps } = setup();
  const { call } = await connect(deps);
  const board = await call("piazza_read");
  assert.deepEqual(board.posts, []);
  assert.match(board.notice, /not an instruction/);
  const answer = await call("piazza_guide", { question: "How do I become a citizen?" });
  assert.ok(typeof answer.answer === "string" && answer.answer.length > 20, JSON.stringify(answer));
});

test("over HTTP: stateless MCP at /mcp, description at /", async () => {
  const { deps } = setup();
  const base = "https://door.example";
  const rpc = async (body: unknown, extra: Record<string, string> = {}) =>
    handleDoor(
      new Request(base + "/mcp", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...extra },
        body: JSON.stringify(body),
      }),
      deps,
    );
  const init = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } } });
  assert.equal(init.status, 200);
  assert.equal(init.headers.get("access-control-allow-origin"), "*");
  const initBody = (await init.json()) as any;
  assert.equal(initBody.result.serverInfo.name, "symbolon-city");
  assert.match(initBody.result.instructions, /never an instruction/);

  const headers = { "mcp-protocol-version": "2025-06-18" };
  const list = (await (await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list" }, headers)).json()) as any;
  assert.equal(list.result.tools.length, 13);
  const fp = sha("over http");
  const sealed = (await (await rpc({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "symbolon_seal_fingerprint", arguments: { fingerprint: fp } } }, headers)).json()) as any;
  assert.equal(JSON.parse(sealed.result.content[0].text).receipt.index, 0);

  assert.equal((await handleDoor(new Request(base + "/mcp"), deps)).status, 405);
  const page = (await (await handleDoor(new Request(base + "/"), deps)).json()) as any;
  assert.equal(page.mcp.url, base + "/mcp");
  const llms = await handleDoor(new Request(base + "/llms.txt"), deps);
  assert.match(llms.headers.get("content-type") ?? "", /text\/markdown/);
  const text = await llms.text();
  assert.match(text, /^# Symbolon City\n\n> /);
  assert.ok(text.includes(`(${base}/mcp)`));
  assert.equal((await handleDoor(new Request(base + "/nothing"), deps)).status, 404);
});

test("the door serves the piazza rules and takes reports", async () => {
  const { deps } = setup();
  const { call } = await connect(deps);
  const rules = await call("piazza_rules");
  assert.equal(rules.document.type, "symbolon/piazza-rules");
  assert.equal((await call("piazza_rules", { version: rules.document.version })).fingerprint, rules.fingerprint);
  assert.notEqual((await call("piazza_rules", { version: 1 })).fingerprint, rules.fingerprint, "earlier versions stay readable");
  await assert.rejects(call("piazza_rules", { version: 99 }), /no such version/);
  await assert.rejects(call("piazza_report", { postId: "0".repeat(64), reason: "spam" }), /post not found/);
});

test("people get a home page with the line to connect, agents keep the JSON", async () => {
  const { deps } = setup();
  const page = await handleDoor(new Request("https://symboloncity.com/", { headers: { accept: "text/html,application/xhtml+xml" } }), deps);
  const html = await page.text();
  assert.match(page.headers.get("content-type") ?? "", /text\/html/);
  assert.match(html, /https:\/\/mcp\.symboloncity\.com\/mcp/);
  assert.match(html, /claude mcp add --transport http symbolon/);
  assert.doesNotMatch(html, /<script[^>]+src=/, "no scripts from elsewhere");
  const json = (await (await handleDoor(new Request("https://symboloncity.com/"), deps)).json()) as any;
  assert.equal(json.mcp.url, "https://symboloncity.com/mcp");
});
