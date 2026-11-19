// Passkeys on the hosted wallet's own site: creating the owner's passkey, and signing in with it.
//
// Signing a mandate or an approval with a passkey is checked by src/keys.ts (passkeyProblem) and is valid
// wherever it was made. Signing in is different: it must have happened on this site, so here the origin and
// the site (rpId) of the assertion are checked too.

import { sha256 } from "@noble/hashes/sha2";
import { equalBytes, fromBase64url, fromHex, toBase64url, utf8 } from "../bytes.js";
import { passkeyChallenge, passkeyKeyFromRaw, passkeyProblem, type PublicKey } from "../keys.js";

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

/** SubjectPublicKeyInfo prefix of an uncompressed P-256 key (id-ecPublicKey, prime256v1): 65 key bytes follow. */
const P256_SPKI = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export interface Site {
  /** The site's origin, e.g. https://wallet.symboloncity.com */
  origin: string;
  /** The WebAuthn relying party id: the host of the origin. */
  rpId: string;
}

/** What the server asks the device to sign: random, for this site and this purpose, usable once. */
export interface LoginChallenge {
  type: "symbolon-hosted/login";
  origin: string;
  purpose: string;
  nonce: string;
}

export const MAX_CREDENTIAL_ID = 1023;

function clientDataOf(b64: string): { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown } | null {
  try {
    const cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64url(b64)));
    return cd && typeof cd === "object" ? cd : null;
  } catch {
    return null;
  }
}

/** Why this sign-in assertion is not valid for this challenge, key and site, or null if it is. */
export function loginProblem(challenge: LoginChallenge, signature: string, pk: PublicKey, site: Site): string | null {
  const problem = passkeyProblem(challenge, signature, pk);
  if (problem) return problem;
  const [, authData, clientData] = signature.split(".");
  const cd = clientDataOf(clientData!);
  if (!cd || cd.origin !== site.origin) return "signed on another site";
  if (!equalBytes(fromBase64url(authData!).slice(0, 32), sha256(utf8(site.rpId)))) return "signed for another site";
  return null;
}

export interface NewPasskey {
  credentialId: string; // base64url
  publicKey: PublicKey; // p256:...
}

/**
 * Checks the answer of navigator.credentials.create(): made on this site, for this challenge, with the person
 * verified, and gives back the new passkey. The browser's attestation is not used ("none"): a forged answer
 * can only open a new, empty account for the key of whoever forged it.
 */
export function registrationProblem(
  challenge: LoginChallenge,
  a: { credentialId: unknown; publicKey: unknown; clientDataJSON: unknown; authenticatorData: unknown },
  site: Site,
): { problem: string } | { passkey: NewPasskey } {
  if (typeof a.credentialId !== "string" || !/^[A-Za-z0-9_-]{16,1023}$/.test(a.credentialId)) return { problem: "invalid credential id" };
  if (typeof a.clientDataJSON !== "string" || typeof a.authenticatorData !== "string" || typeof a.publicKey !== "string" || a.clientDataJSON.length > 4096 || a.authenticatorData.length > 4096)
    return { problem: "invalid registration" };
  const cd = clientDataOf(a.clientDataJSON);
  if (!cd || cd.type !== "webauthn.create") return { problem: "not a passkey registration" };
  if (cd.challenge !== toBase64url(passkeyChallenge(challenge))) return { problem: "the registration is for another challenge" };
  if (cd.origin !== site.origin || cd.crossOrigin === true) return { problem: "registered on another site" };
  let authData: Uint8Array, spki: Uint8Array, credId: Uint8Array;
  try {
    authData = fromBase64url(a.authenticatorData);
    spki = fromBase64url(a.publicKey);
    credId = fromBase64url(a.credentialId);
  } catch {
    return { problem: "invalid registration" };
  }
  if (authData.length < 55 || !equalBytes(authData.slice(0, 32), sha256(utf8(site.rpId)))) return { problem: "registered for another site" };
  const flags = authData[32]!;
  if (!(flags & UP) || !(flags & UV)) return { problem: "the owner was not verified on the device" };
  if (!(flags & AT)) return { problem: "no new passkey in the registration" };
  // Attested credential data: aaguid (16), id length (2), id, then the COSE key.
  const idLen = (authData[53]! << 8) | authData[54]!;
  if (!equalBytes(authData.slice(55, 55 + idLen), credId)) return { problem: "the credential id does not match the registration" };
  if (spki.length !== P256_SPKI.length + 65 || !equalBytes(spki.slice(0, P256_SPKI.length), P256_SPKI)) return { problem: "the passkey must use P-256 (ES256)" };
  const point = spki.slice(P256_SPKI.length);
  // The COSE key of the registration holds x and y: they must be this very key.
  const cose = authData.slice(55 + idLen);
  if (!contains(cose, point.slice(1, 33)) || !contains(cose, point.slice(33, 65))) return { problem: "the public key does not match the registration" };
  try {
    return { passkey: { credentialId: a.credentialId, publicKey: passkeyKeyFromRaw(point) } };
  } catch {
    return { problem: "invalid public key" };
  }
}

function contains(hay: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}
