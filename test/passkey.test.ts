// Owners who sign with a passkey (Face ID, Touch ID, Windows Hello, security key) through WebAuthn.
// A software authenticator stands in for the device here; test/passkey-browser.ts checks the same with a real browser.

import { test } from "node:test";
import assert from "node:assert/strict";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { concat, toBase64url, utf8 } from "../src/bytes.js";
import {
  checkMandate,
  createSubMandate,
  generateKeyPair,
  mandateBody,
  mandateId,
  revocationBody,
  revokes,
  signedMandate,
  signedRevocation,
  staticOwnerResolver,
  verifyMandateSignature,
  type Mandate,
} from "../src/index.js";
import { MAX_PASSKEY_SIGNATURE, isUsablePublicKey, passkeyChallenge, passkeyKeyFromRaw, passkeyProblem, passkeySignature, verifyValue } from "../src/keys.js";
import { archiveKeyProblem, type ArchiveKeyClaim } from "../src/archive.js";

/** A device with one passkey for one site. `flags` and `tamper` let a test make the assertions it should refuse. */
class SoftPasskey {
  readonly secret = p256.utils.randomPrivateKey();
  readonly publicKey = passkeyKeyFromRaw(p256.getPublicKey(this.secret, false));
  constructor(readonly rpId = "symboloncity.com", readonly origin = "https://symboloncity.com") {}

  sign(
    value: unknown,
    o: { flags?: number; type?: string; challenge?: Uint8Array; crossOrigin?: boolean; extraAuthData?: Uint8Array; lowS?: boolean } = {},
  ): string {
    const authData = concat(sha256(utf8(this.rpId)), new Uint8Array([o.flags ?? 0x05]), new Uint8Array([0, 0, 0, 7]), o.extraAuthData ?? new Uint8Array());
    const clientData = utf8(
      JSON.stringify({
        type: o.type ?? "webauthn.get",
        challenge: toBase64url(o.challenge ?? passkeyChallenge(value)),
        origin: this.origin,
        ...(o.crossOrigin === undefined ? {} : { crossOrigin: o.crossOrigin }),
      }),
    );
    let sig: { r: bigint; s: bigint; toDERRawBytes(): Uint8Array } = p256.sign(sha256(concat(authData, sha256(clientData))), this.secret, { prehash: false, lowS: true });
    // lowS: false gives the other valid encoding of the same signature (S replaced by n - S), as many devices produce.
    if (o.lowS === false) sig = new p256.Signature(sig.r, p256.CURVE.n - sig.s);
    return passkeySignature({ authenticatorData: authData, clientDataJSON: clientData, signature: sig.toDERRawBytes() });
  }
}

const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

function marta() {
  const device = new SoftPasskey();
  const agent = generateKeyPair();
  const body = mandateBody(device.publicKey, {
    ownerDomain: "restauri-marta.example",
    agent: agent.publicKey,
    scope: "lavori di restauro",
    maxAmount: { value: "2000.00", currency: "EUR" },
    notBefore: later(-1),
    notAfter: later(90),
    charter: "accord-charter/0.1",
  });
  return { device, agent, body, mandate: signedMandate(body, device.sign(body)) };
}

test("passkey: a mandate signed with Face ID is a valid mandate", async () => {
  const { device, mandate } = marta();
  assert.match(device.publicKey, /^p256:0[23][0-9a-f]{64}$/);
  assert.ok(verifyMandateSignature(mandate));
  const check = await checkMandate(mandate, { ownerResolver: staticOwnerResolver({ "restauri-marta.example": [device.publicKey] }), revocations: async () => [] });
  assert.deepEqual(check.problems, []);
  assert.equal(check.level, "domain");
  assert.deepEqual(check.limit, { value: "2000.00", currency: "EUR" });
});

test("passkey: the signature covers exactly the mandate shown to the owner", () => {
  const { device, body, mandate } = marta();
  const bigger = { ...body, maxAmount: { value: "20000.00", currency: "EUR" } };
  assert.ok(!verifyMandateSignature({ body: bigger, signature: mandate.signature }));
  assert.throws(() => signedMandate(bigger, mandate.signature), /not the owner's signature/);
  // Another device's passkey cannot sign for Marta's key.
  assert.throws(() => signedMandate(body, new SoftPasskey().sign(body)), /not the owner's signature/);
  // A signature of this mandate does not sign another one.
  assert.equal(passkeyProblem(bigger, device.sign(body), device.publicKey), "the passkey signed something else");
});

test("passkey: refuses assertions without user verification or of the wrong kind", () => {
  const { device, body } = marta();
  const k = device.publicKey;
  assert.equal(passkeyProblem(body, device.sign(body), k), null);
  assert.equal(passkeyProblem(body, device.sign(body, { flags: 0x01 }), k), "the owner was not verified on the device"); // present, not verified
  assert.equal(passkeyProblem(body, device.sign(body, { flags: 0x04 }), k), "the owner was not verified on the device"); // verified, not present
  assert.equal(passkeyProblem(body, device.sign(body, { type: "webauthn.create" }), k), "not a WebAuthn assertion");
  assert.equal(passkeyProblem(body, device.sign(body, { crossOrigin: true }), k), "invalid origin");
  assert.equal(passkeyProblem(body, device.sign(body, { flags: 0x85, extraAuthData: new Uint8Array([0xa0]) }), k), "unexpected authenticator data");
  assert.equal(passkeyProblem(body, device.sign(body, { challenge: sha256(utf8("something else")) }), k), "the passkey signed something else");
  // Both encodings of the same ECDSA signature are fine (browsers do not normalise S); the mandate id does not depend on it.
  assert.equal(passkeyProblem(body, device.sign(body, { lowS: false }), k), null);
});

test("passkey: malformed signatures and keys are refused without throwing", () => {
  const { device, body } = marta();
  const good = device.sign(body);
  const parts = good.split(".");
  for (const bad of [
    "",
    "webauthn",
    good.replace("webauthn.", "webauthm."),
    good + ".x",
    [parts[0], parts[1] + "=", parts[2], parts[3]].join("."), // padding is not canonical
    [parts[0], parts[1], parts[2], parts[3].slice(0, -4)].join("."),
    [parts[0], parts[1], toBase64url(utf8("not json")), parts[3]].join("."),
    "webauthn." + "A".repeat(MAX_PASSKEY_SIGNATURE),
  ])
    assert.ok(!verifyValue(body, bad, device.publicKey), bad.slice(0, 40));
  assert.ok(!isUsablePublicKey("p256:02" + "ff".repeat(32))); // x outside the field
  assert.ok(!isUsablePublicKey("p256:04" + "11".repeat(32)));
  // An Ed25519 signature is not accepted for a passkey key, nor a passkey signature for an Ed25519 key.
  const ed = generateKeyPair();
  assert.ok(!verifyValue(body, good, ed.publicKey));
});

test("passkey: agents keep Ed25519 keys; only owners sign with passkeys", () => {
  const { device, body } = marta();
  assert.throws(() => mandateBody(device.publicKey, { ...body, ownerDomain: body.owner.domain, agent: device.publicKey }), /invalid key in mandate/);
});

test("passkey: sub-mandates under a passkey mandate work as usual", () => {
  const { agent, mandate } = marta();
  const helper = generateKeyPair();
  const sub = createSubMandate(agent, mandate, {
    agent: helper.publicKey,
    scope: "trasporto della pala",
    maxAmount: { value: "300.00", currency: "EUR" },
    notBefore: later(-1),
    notAfter: later(10),
  });
  assert.ok(verifyMandateSignature(sub));
  // The top of the chain is the passkey mandate: changing it breaks the chain.
  const forged: Mandate = { ...sub, chain: [{ body: { ...mandate.body, maxAmount: { value: "9000.00", currency: "EUR" } }, signature: mandate.signature }] };
  assert.ok(!verifyMandateSignature(forged));
});

test("passkey: the owner blocks a mandate with Face ID", () => {
  const { device, mandate } = marta();
  const body = revocationBody(device.publicKey, { target: { kind: "mandate", id: mandateId(mandate) }, reason: "telefono perso" });
  const r = signedRevocation(body, device.sign(body));
  assert.ok(revokes(r, mandate));
  // Someone else's passkey cannot block Marta's mandate.
  const other = new SoftPasskey();
  const b2 = revocationBody(other.publicKey, { target: { kind: "mandate", id: mandateId(mandate) } });
  assert.ok(!revokes(signedRevocation(b2, other.sign(b2)), mandate));
  // A passkey key can be blocked as an owner key, but it is never an agent key.
  const b3 = revocationBody(device.publicKey, { target: { kind: "owner-key", key: device.publicKey } });
  assert.ok(revokes(signedRevocation(b3, device.sign(b3)), mandate));
  assert.throws(() => revocationBody(device.publicKey, { target: { kind: "agent", key: device.publicKey } }), /invalid target key/);
  assert.throws(() => signedRevocation(body, other.sign(body)), /signature is invalid/);
});

test("passkey: the owner's archive key can be signed with a passkey", () => {
  const { device, mandate } = marta();
  const body = { type: "symbolon/archive-key" as const, v: 1 as const, owner: { ...mandate.body.owner }, key: "x25519:" + "ab".repeat(32), createdAt: new Date().toISOString() };
  const claim: ArchiveKeyClaim = { body, signature: device.sign(body) };
  assert.equal(archiveKeyProblem(claim, mandate), null);
  assert.equal(archiveKeyProblem({ ...claim, signature: new SoftPasskey().sign(body) }, mandate), "the archive key is not signed by the owner");
});
