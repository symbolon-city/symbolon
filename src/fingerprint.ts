// Fingerprints of content, computed the same way everywhere (spec: docs/FORMAT.md).
// Plain text: SHA-256 of its UTF-8 bytes, exactly as given. JSON: SHA-256 of its canonical form
// (RFC 8785 JCS, restricted to safe integers: amounts are decimal strings). One byte of
// difference gives a different fingerprint, so both sides must use the same method.

import { utf8 } from "./bytes.js";
import { canonical } from "./canonical.js";
import { sha256Hex } from "./hash.js";

export type FingerprintMethod = "sha256-utf8" | "sha256-jcs";

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Throws on text that has no exact UTF-8 form (a lone surrogate), anywhere inside the value. */
function requireWellFormed(v: unknown): void {
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new Error("text contains an unpaired surrogate: it has no exact UTF-8 form");
  } else if (Array.isArray(v)) v.forEach(requireWellFormed);
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) (requireWellFormed(k), requireWellFormed(x));
}

export function fingerprintText(text: string): { fingerprint: string; method: FingerprintMethod; bytes: number } {
  requireWellFormed(text);
  const b = utf8(text);
  return { fingerprint: sha256Hex(b), method: "sha256-utf8", bytes: b.length };
}

export function fingerprintJson(value: unknown): { fingerprint: string; method: FingerprintMethod; canonical: string } {
  requireWellFormed(value);
  const c = canonical(value);
  return { fingerprint: sha256Hex(utf8(c)), method: "sha256-jcs", canonical: c };
}
