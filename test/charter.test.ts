// The charter accord-charter/0.1: one text, served by the door, fingerprint fixed (a published version never changes).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CHARTER_NAME, CHARTER_TEXT, charterFingerprint } from "../src/charter.js";
import { handleDoor } from "../src/visitor/door.js";

test("the charter in the code is the same text as docs/CHARTER-0.1.md, and its fingerprint never changes", () => {
  assert.equal(readFileSync(new URL("../docs/CHARTER-0.1.md", import.meta.url), "utf8"), CHARTER_TEXT);
  assert.equal(CHARTER_NAME, "accord-charter/0.1");
  // Sealed in the register at publication: changing the text means a new version, never an edit of this one.
  assert.equal(charterFingerprint().fingerprint, "5a16275112df1aafa9bc44c826cc7d017d5f3bdd9f13b6021468df43bf3f0482");
});

test("the door serves the charter as Markdown and as JSON, with its fingerprint, and links it", async () => {
  const deps = { registerUrl: "https://reg.example" } as Parameters<typeof handleDoor>[1];
  const md = await handleDoor(new Request("https://door.example/charter"), deps);
  assert.equal(md.status, 200);
  assert.equal(await md.text(), CHARTER_TEXT);
  assert.equal(md.headers.get("x-symbolon-fingerprint"), charterFingerprint().fingerprint);
  const js = await handleDoor(new Request("https://door.example/charter/0.1", { headers: { accept: "application/json" } }), deps);
  const body = (await js.json()) as { name: string; fingerprint: string; text: string };
  assert.equal(body.name, CHARTER_NAME);
  assert.equal(body.fingerprint, charterFingerprint().fingerprint);
  assert.equal(body.text, CHARTER_TEXT);
  const llms = await (await handleDoor(new Request("https://door.example/llms.txt"), deps)).text();
  assert.match(llms, /https:\/\/door\.example\/charter/);
  const about = (await (await handleDoor(new Request("https://door.example/"), deps)).json()) as { charter: { fingerprint: string } };
  assert.equal(about.charter.fingerprint, charterFingerprint().fingerprint);
});
