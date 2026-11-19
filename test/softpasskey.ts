// A software stand-in for a device with a passkey (Face ID, Touch ID, Windows Hello), used by the tests.
// scripts/passkey-browser-check.ts checks the same with a real browser.

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { concat, toBase64url, utf8 } from "../src/bytes.js";
import { passkeyChallenge, passkeyKeyFromRaw, passkeySignature } from "../src/keys.js";

/** A device with one passkey for one site. `flags` and `tamper` let a test make the assertions it should refuse. */
export class SoftPasskey {
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
