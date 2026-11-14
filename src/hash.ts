import { sha256 } from "@noble/hashes/sha2";
import { concat, toHex, utf8 } from "./bytes.js";
import { canonical } from "./canonical.js";

// Domain separation as in RFC 6962 / RFC 9162 (Certificate Transparency):
// leaves and inner nodes are hashed with different prefixes, so a leaf
// can never be passed off as an inner node.
const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

export function sha256Hex(data: Uint8Array): string {
  return toHex(sha256(data));
}

export function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concat(LEAF, data));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(NODE, left, right));
}

export function emptyRoot(): Uint8Array {
  return sha256(new Uint8Array());
}

/** Fingerprint of any JSON value, over its canonical form. */
export function digest(value: unknown): string {
  return sha256Hex(utf8(canonical(value)));
}
