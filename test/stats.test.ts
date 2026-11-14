import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryStore, Register, generateKeyPair } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { MemoryStats, classifyClient } from "../src/server/stats.js";

test("client classes are guessed from the User-Agent", () => {
  assert.equal(classifyClient("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"), "ai_agent");
  assert.equal(classifyClient("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0)"), "ai_agent");
  assert.equal(classifyClient("curl/8.4.0"), "program");
  assert.equal(classifyClient("node"), "program");
  assert.equal(classifyClient(null), "program");
  assert.equal(classifyClient("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"), "browser");
});

test("/stats counts reads and writes anonymously and does not count itself", async () => {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://r.example", stats: new MemoryStats() };
  const req = (method: string, path: string, ua: string, body?: unknown) =>
    handle(new Request("https://r.example" + path, { method, headers: { "user-agent": ua }, body: body === undefined ? undefined : JSON.stringify(body) }), deps);
  await req("POST", "/v1/entries", "ClaudeBot/1.0", { entry: "a".repeat(64) });
  await req("GET", "/v1/head", "curl/8");
  await req("GET", "/", "Mozilla/5.0 Safari");
  await req("GET", "/stats", "Mozilla/5.0 Safari");
  const r = await req("GET", "/v1/stats", "curl/8");
  const body = (await r.json()) as { registerSize: number; days: { counts: Record<string, number> }[] };
  assert.equal(body.registerSize, 1);
  assert.deepEqual(body.days.at(-1)!.counts, { "write:ai_agent": 1, "read:program": 1, "read:browser": 1 });
  const page = await (await req("GET", "/stats", "x")).text();
  assert.match(page, /Register stats/);
  assert.doesNotMatch(page, /aaaaaaaa/); // fingerprints never shown
});
