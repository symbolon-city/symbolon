// Checks passkey signatures with a real browser: Chromium creates a passkey on a virtual authenticator
// (with user verification, like Face ID), signs a mandate and a revocation through navigator.credentials,
// and the city's own code must accept them, and refuse them once changed.
//
//   npm run passkey:check        (needs Playwright with Chromium installed)

import { createServer } from "node:http";
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import { fromBase64url, toBase64url } from "../src/bytes.js";
import { passkeyChallenge, passkeyKeyFromRaw, passkeySignature, verifyValue } from "../src/keys.js";
import { checkMandate, generateKeyPair, mandateBody, mandateId, revocationBody, revokes, signedMandate, signedRevocation, verifyMandateSignature } from "../src/index.js";

const PAGE = `<!doctype html><meta charset="utf-8"><title>passkey</title><script>
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
window.makePasskey = async () => {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: "Symbolon", id: "localhost" },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "marta", displayName: "Marta" },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  } });
  return { id: cred.id, spki: b64u(cred.response.getPublicKey()) };
};
window.signWithPasskey = async (id, challenge) => {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: fromB64u(challenge), rpId: "localhost", userVerification: "required",
    allowCredentials: [{ type: "public-key", id: fromB64u(id) }],
  } });
  return { authenticatorData: b64u(a.response.authenticatorData), clientDataJSON: b64u(a.response.clientDataJSON), signature: b64u(a.response.signature) };
};
</script>`;

async function main() {
  const require = createRequire(import.meta.url);
  // Playwright is not a dependency of the city: it is used only by this check, where it is installed.
  type Page = { evaluate(js: string): Promise<unknown>; goto(url: string): Promise<unknown>; context(): { newCDPSession(p: Page): Promise<{ send(m: string, p?: object): Promise<unknown> }> } };
  const { chromium } = require("playwright") as { chromium: { launch(): Promise<{ newPage(): Promise<Page>; close(): Promise<void> }> } };
  const server = createServer((_, res) => res.writeHead(200, { "content-type": "text/html" }).end(PAGE));
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const port = (server.address() as { port: number }).port;
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });
    await page.goto(`http://localhost:${port}/`);

    const made = (await page.evaluate("makePasskey()")) as { id: string; spki: string };
    const spki = fromBase64url(made.spki);
    const ownerKey = passkeyKeyFromRaw(spki.slice(spki.length - 65)); // SPKI for P-256 ends with the 65-byte point
    const sign = async (value: unknown) => {
      const a = (await page.evaluate(`signWithPasskey(${JSON.stringify(made.id)}, ${JSON.stringify(toBase64url(passkeyChallenge(value)))})`)) as Record<string, string>;
      return passkeySignature({
        authenticatorData: fromBase64url(a.authenticatorData),
        clientDataJSON: fromBase64url(a.clientDataJSON),
        signature: fromBase64url(a.signature),
      });
    };

    const agent = generateKeyPair();
    const now = Date.now();
    const body = mandateBody(ownerKey, {
      ownerDomain: "restauri-marta.example",
      agent: agent.publicKey,
      scope: "lavori di restauro",
      maxAmount: { value: "2000.00", currency: "EUR" },
      notBefore: new Date(now - 60_000).toISOString(),
      notAfter: new Date(now + 90 * 86_400_000).toISOString(),
      charter: "accord-charter/0.1",
    });
    const mandate = signedMandate(body, await sign(body));
    assert.ok(verifyMandateSignature(mandate), "mandate signed in the browser is valid");
    assert.ok(!verifyValue({ ...body, maxAmount: { value: "20000.00", currency: "EUR" } }, mandate.signature, ownerKey), "changed mandate is refused");
    console.log(`ok  mandate signed by a browser passkey (${ownerKey.slice(0, 20)}…, signature ${mandate.signature.length} characters)`);

    const rb = revocationBody(ownerKey, { target: { kind: "mandate", id: mandateId(mandate) }, reason: "telefono perso" });
    const revocation = signedRevocation(rb, await sign(rb));
    assert.ok(revokes(revocation, mandate), "revocation signed in the browser blocks the mandate");
    console.log("ok  revocation signed by the same passkey blocks the mandate");

    // The same owner without a website (identity level "key"): no domain in the mandate, nothing to publish.
    const bodyNoSite = mandateBody(ownerKey, { agent: body.agent, scope: body.scope, maxAmount: body.maxAmount, notBefore: body.notBefore, notAfter: body.notAfter, charter: body.charter });
    assert.deepEqual(Object.keys(bodyNoSite.owner), ["key"]);
    const mandateNoSite = signedMandate(bodyNoSite, await sign(bodyNoSite));
    const seen = await checkMandate(mandateNoSite, { revocations: async () => [] });
    assert.equal(seen.level, "key");
    assert.deepEqual(seen.problems, []);
    console.log("ok  mandate without a website signed by the same passkey: level key");
  } finally {
    await browser.close();
    server.close();
  }
}

main().catch((e) => {
  console.error("FAILED:", e instanceof Error ? e.message : e);
  process.exit(1);
});
