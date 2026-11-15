import { test } from "node:test";
import assert from "node:assert/strict";
import { httpOwnerResolver, ownerFile } from "../src/index.js";

function site(files: Record<string, unknown>): typeof fetch {
  return async (input) => {
    const u = new URL(String(input));
    const body = files[u.host + u.pathname];
    return body === undefined ? new Response("not found", { status: 404 }) : Response.json(body);
  };
}

test("owner keys are read from symbolon.json, and still from the earlier accord.json", async () => {
  const resolve = httpOwnerResolver(
    site({
      "new.example/.well-known/symbolon.json": ownerFile("new.example", ["ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]),
      "old.example/.well-known/accord.json": { accord: 1, domain: "old.example", keys: ["ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] },
      "both.example/.well-known/symbolon.json": ownerFile("both.example", ["ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]),
      "both.example/.well-known/accord.json": { accord: 1, domain: "both.example", keys: ["ed25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"] },
      "liar.example/.well-known/symbolon.json": ownerFile("someone-else.example", ["ed25519:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]),
    }),
  );
  assert.deepEqual(await resolve("new.example"), ["ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
  assert.deepEqual(await resolve("old.example"), ["ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]);
  assert.deepEqual(await resolve("both.example"), ["ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]);
  assert.equal(await resolve("liar.example"), null);
  assert.equal(await resolve("nobody.example"), null);
  assert.equal(await resolve("bad domain/../x"), null);
});

test("owner key lookups do not follow redirects, and do not ask for redirect 'error' (unsupported on Cloudflare Workers)", async () => {
  const seen: Array<string | undefined> = [];
  const resolve = httpOwnerResolver(async (input, init) => {
    seen.push(init?.redirect);
    if (init?.redirect === "error") throw new TypeError("unsupported redirect mode");
    return new Response(null, { status: 301, headers: { location: "https://elsewhere.example/.well-known/symbolon.json" } });
  });
  assert.equal(await resolve("moved.example"), null);
  assert.ok(seen.every((r) => r === "manual"));
});
