// Keys and signatures over canonical JSON.
//
// Two kinds of key:
// - "ed25519:<64 hex>": agents, registers, witnesses, and owners who sign with software (the mandate page, the CLI).
// - "p256:<66 hex>" (compressed P-256 point): an owner's passkey. The owner signs with Face ID, Touch ID,
//   Windows Hello or a security key, through WebAuthn: the private key never leaves the device.
//   Only owners use passkeys; an agent signs on its own, without a person, so it always has an Ed25519 key.

import * as ed from "@noble/ed25519";
import { p256 } from "@noble/curves/p256";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { concat, fromBase64url, fromHex, toBase64url, toHex, utf8 } from "./bytes.js";
import { canonical } from "./canonical.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/** Public keys are written as "ed25519:<hex>" or, for an owner's passkey, "p256:<hex>". */
export type PublicKey = string;

/** An agent key (and any key that signs without a person): Ed25519 only. */
export const AGENT_KEY = /^ed25519:[0-9a-f]{64}$/;
/** A key that can sign for an owner: Ed25519, or a passkey (compressed P-256 point). */
export const OWNER_KEY = /^(?:ed25519:[0-9a-f]{64}|p256:0[23][0-9a-f]{64})$/;

export interface KeyPair {
  publicKey: PublicKey;
  secretKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const secretKey = ed.utils.randomPrivateKey();
  return { secretKey, publicKey: "ed25519:" + toHex(ed.getPublicKey(secretKey)) };
}

/** True for an owner's passkey key ("p256:..."). */
export function isPasskeyKey(pk: PublicKey): boolean {
  return typeof pk === "string" && pk.startsWith("p256:");
}

function rawPublic(pk: PublicKey): Uint8Array {
  if (typeof pk !== "string" || !pk.startsWith("ed25519:")) throw new Error("unsupported key type");
  return fromHex(pk.slice(8));
}

/**
 * True for a usable public key: canonical encoding of a point that is not of small order.
 * A small-order key "verifies" signatures nobody made, so a party could later say anyone could have signed.
 */
export function isUsablePublicKey(pk: PublicKey): boolean {
  try {
    if (isPasskeyKey(pk)) {
      if (!OWNER_KEY.test(pk)) return false;
      p256.ProjectivePoint.fromHex(pk.slice(5)).assertValidity();
      return true;
    }
    const raw = rawPublic(pk);
    return raw.length === 32 && !ed.ExtendedPoint.fromHex(raw, false).isSmallOrder();
  } catch {
    return false;
  }
}

export function signValue(value: unknown, key: KeyPair): string {
  return toHex(ed.sign(utf8(canonical(value)), key.secretKey));
}

/** Strict verification (RFC 8032, no ZIP-215 leniency), and never with a small-order key. A passkey key is checked as a WebAuthn assertion. */
export function verifyValue(value: unknown, signature: string, pk: PublicKey): boolean {
  try {
    if (!isUsablePublicKey(pk)) return false;
    if (isPasskeyKey(pk)) return verifyPasskey(value, signature, pk);
    return ed.verify(fromHex(signature), utf8(canonical(value)), rawPublic(pk), { zip215: false });
  } catch {
    return false;
  }
}

/** Rebuilds a key pair from a stored 32-byte secret (hex). */
export function keyPairFromSecret(secretHex: string): KeyPair {
  const secretKey = fromHex(secretHex);
  if (secretKey.length !== 32) throw new Error("secret key must be 32 bytes");
  return { secretKey, publicKey: "ed25519:" + toHex(ed.getPublicKey(secretKey)) };
}

// ---------- passkeys (WebAuthn) ----------
//
// The owner's device signs a WebAuthn assertion whose challenge is the fingerprint of the value (SHA-256 of its
// canonical JSON, the same fingerprint the register uses). The signature is written as
//   "webauthn.<authenticatorData>.<clientDataJSON>.<DER signature>"  (each part base64url, no padding).
// Checked: the assertion is for "webauthn.get", its challenge is this value's fingerprint, the person was present
// and verified (Face ID, PIN), it is not embedded in another site, and the P-256 signature over
// authenticatorData || SHA-256(clientDataJSON) is valid for the key.

/** Longest passkey signature accepted (base64url text): a real one is about 600 characters. */
export const MAX_PASSKEY_SIGNATURE = 2048;
const UP = 0x01; // user present
const UV = 0x04; // user verified (biometrics or PIN)

/** The WebAuthn challenge for a value: the SHA-256 of its canonical JSON. Pass it to navigator.credentials.get(). */
export function passkeyChallenge(value: unknown): Uint8Array {
  return sha256(utf8(canonical(value)));
}

/** Writes an assertion as a signature string. Parts as returned by navigator.credentials.get(). */
export function passkeySignature(a: { authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array }): string {
  return ["webauthn", toBase64url(a.authenticatorData), toBase64url(a.clientDataJSON), toBase64url(a.signature)].join(".");
}

/** Why a passkey signature does not sign this value for this key, or null if it does. */
export function passkeyProblem(value: unknown, signature: string, pk: PublicKey): string | null {
  if (!isPasskeyKey(pk) || !isUsablePublicKey(pk)) return "not a passkey key";
  if (typeof signature !== "string" || signature.length > MAX_PASSKEY_SIGNATURE) return "invalid passkey signature";
  const parts = signature.split(".");
  if (parts.length !== 4 || parts[0] !== "webauthn") return "invalid passkey signature";
  let authData: Uint8Array, clientData: Uint8Array, der: Uint8Array;
  try {
    [authData, clientData, der] = parts.slice(1).map(fromBase64url) as [Uint8Array, Uint8Array, Uint8Array];
  } catch {
    return "invalid passkey signature";
  }
  // rpIdHash (32) + flags (1) + counter (4): no attested credential data, no extensions.
  if (authData.length !== 37) return "unexpected authenticator data";
  const flags = authData[32];
  if (!(flags & UP) || !(flags & UV)) return "the owner was not verified on the device";
  let cd: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    cd = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(clientData));
  } catch {
    return "invalid client data";
  }
  if (!cd || typeof cd !== "object" || cd.type !== "webauthn.get") return "not a WebAuthn assertion";
  if (cd.challenge !== toBase64url(passkeyChallenge(value))) return "the passkey signed something else";
  if (typeof cd.origin !== "string" || cd.crossOrigin === true) return "invalid origin";
  try {
    const hash = sha256(concat(authData, sha256(clientData)));
    if (!p256.verify(der, hash, fromHex(pk.slice(5)), { lowS: false, prehash: false, format: "der" })) return "the passkey signature is invalid";
  } catch {
    return "the passkey signature is invalid";
  }
  return null;
}

function verifyPasskey(value: unknown, signature: string, pk: PublicKey): boolean {
  return passkeyProblem(value, signature, pk) === null;
}

/** A passkey key as written in mandates, from the COSE or raw public key the browser returns at registration. */
export function passkeyKeyFromRaw(raw: Uint8Array): PublicKey {
  return "p256:" + p256.ProjectivePoint.fromHex(raw).toHex(true);
}
