// Ed25519 keys and signatures over canonical JSON.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { fromHex, toHex, utf8 } from "./bytes.js";
import { canonical } from "./canonical.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/** Public keys are written as "ed25519:<hex>". */
export type PublicKey = string;

export interface KeyPair {
  publicKey: PublicKey;
  secretKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const secretKey = ed.utils.randomPrivateKey();
  return { secretKey, publicKey: "ed25519:" + toHex(ed.getPublicKey(secretKey)) };
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
    const raw = rawPublic(pk);
    return raw.length === 32 && !ed.ExtendedPoint.fromHex(raw, false).isSmallOrder();
  } catch {
    return false;
  }
}

export function signValue(value: unknown, key: KeyPair): string {
  return toHex(ed.sign(utf8(canonical(value)), key.secretKey));
}

/** Strict verification (RFC 8032, no ZIP-215 leniency), and never with a small-order key. */
export function verifyValue(value: unknown, signature: string, pk: PublicKey): boolean {
  try {
    if (!isUsablePublicKey(pk)) return false;
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
