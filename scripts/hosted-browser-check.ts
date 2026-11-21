// Checks the hosted wallet's pages in a real browser (Chromium with a simulated Face ID): Marta connects an
// assistant creating her passkey, signs the mandate her agent asked for, signs in to her page and blocks
// everything. Everything runs locally, in memory (a local register too): nothing goes online.
//   npm run hosted:check     (needs Playwright where it runs: `npm i playwright && npx playwright install chromium`,
//                             or NODE_PATH pointing to a folder where it is installed)
import { createServer } from "node:http";
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import { sha256 } from "@noble/hashes/sha2";
import { HttpRegisterClient } from "../src/agent/client.js";
import { toBase64url, utf8 } from "../src/bytes.js";
import { MemoryStore, Register, generateKeyPair } from "../src/index.js";
import { handle } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";
import { handleHosted } from "../src/hosted/app.js";
import { MemoryKeyValue } from "../src/hosted/store.js";

type Page = {
  goto(url: string): Promise<unknown>;
  getByRole(role: string, o: { name: RegExp }): { click(): Promise<void> };
  getByText(t: RegExp): { waitFor(): Promise<void> };
  waitForURL(u: RegExp): Promise<void>;
  url(): string;
  on(e: string, f: (m: { text(): string }) => void): void;
  context(): { newCDPSession(p: Page): Promise<{ send(m: string, p?: object): Promise<unknown> }> };
};

async function main() {
  const require = createRequire(import.meta.url);
  const { chromium } = require("playwright") as { chromium: { launch(): Promise<{ newPage(): Promise<Page>; close(): Promise<void> }> } };
  const regDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const register = new HttpRegisterClient("https://reg.example", async (input, init) => handle(new Request(String(input), init), regDeps));
  let origin = "";
  const deps = () => ({ kv, secret, origin, register });
  const kv = new MemoryKeyValue();
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const r = await handleHosted(
      new Request(origin + req.url, { method: req.method, headers: req.headers as Record<string, string>, ...(chunks.length ? { body: Buffer.concat(chunks) } : {}) }),
      deps(),
    );
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  origin = `http://localhost:${(server.address() as { port: number }).port}`;
  const app = (path: string, init?: RequestInit) => fetch(origin + path, init);

  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    page.on("console", (m) => console.log("  [page]", m.text()));
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });

    // 1. The assistant asks to connect; Marta creates her wallet with Face ID.
    const redirect = origin + "/assistant-callback";
    const reg = await (await app("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [redirect], client_name: "Marta's assistant" }) })).json();
    const verifier = toBase64url(crypto.getRandomValues(new Uint8Array(48)));
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirect, code_challenge: toBase64url(sha256(utf8(verifier))), code_challenge_method: "S256", state: "s1" });
    await page.goto(origin + "/authorize?" + q);
    await page.getByRole("button", { name: /First time/ }).click();
    // The new passkey then proves itself with a first signature (a second tap).
    await page.getByRole("button", { name: /Confirm the new passkey/ }).click();
    await page.waitForURL(/assistant-callback\?code=/);
    const code = new URL(page.url()).searchParams.get("code")!;
    const tok = await (await app("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: redirect }).toString() })).json();
    assert.ok(tok.access_token, JSON.stringify(tok));
    console.log("ok  connected with a new passkey (Face ID)");

    const call = async (name: string, args: object = {}) => {
      const r = await app("/mcp", { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer " + tok.access_token }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) });
      const j = await r.json();
      if (j.result?.isError) throw new Error(j.result.content[0].text);
      return JSON.parse(j.result.content[0].text);
    };

    // 2. "Accept restoration jobs up to 2000 EUR for three months": she signs the mandate on the page.
    const ask = await call("symbolon_ask_owner_for_mandate", { scope: "restoration jobs", max_amount: { value: "2000.00", currency: "EUR" }, days: 90 });
    await page.goto(ask.owner_page);
    await page.getByText(/restoration jobs/).waitFor();
    await page.getByRole("button", { name: /Sign with Face ID/ }).click();
    await page.getByText(/^Signed/).waitFor();
    const who = await call("symbolon_whoami");
    assert.equal(who.mandate?.scope, "restoration jobs");
    console.log("ok  mandate signed on the page and installed in the wallet");
    await call("symbolon_seal_action", { instruction: "photograph the frame before work", action: "photos taken" });

    // 3. Her page: sign in, see the agent, block everything.
    await page.goto(origin + "/owner");
    await page.getByRole("button", { name: /Sign in with Face ID/ }).click();
    await page.getByText(/restoration jobs/).waitFor();
    await page.getByText(/^Action/).waitFor();
    await page.getByRole("button", { name: /Download everything/ }).click();
    await page.getByRole("button", { name: /Download the proof/ }).click();
    console.log("ok  owner page: mandate, history with the sealed action, downloads");
    await page.getByRole("button", { name: /Block with Face ID/ }).click();
    await page.getByText(/^Blocked/).waitFor();
    await assert.rejects(call("symbolon_whoami"));
    console.log("ok  owner page signed in, Block everything sealed, the assistant disconnected");
  } finally {
    await browser.close();
    server.close();
  }
}

main().then(
  () => console.log("hosted:check passed"),
  (e) => {
    console.error("hosted:check FAILED:", e);
    process.exit(1);
  },
);
