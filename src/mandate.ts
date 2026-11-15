// A mandate is the owner's signed permission for an agent to act on its behalf.
// Without a valid mandate an agreement binds nobody.

import { digest } from "./hash.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";

export interface Amount {
  value: string; // decimal string, e.g. "50000.00"
  currency: string; // ISO 4217, e.g. "EUR"
}

export interface MandateBody {
  type: "accord/mandate";
  v: 1;
  owner: { domain: string; key: PublicKey };
  agent: PublicKey;
  scope: string;
  maxAmount?: Amount;
  notBefore: string; // ISO 8601
  notAfter: string;
  charter: string;
}

export interface Mandate {
  body: MandateBody;
  signature: string;
}

export function createMandate(
  owner: KeyPair,
  params: Omit<MandateBody, "type" | "v" | "owner"> & { ownerDomain: string },
): Mandate {
  const { ownerDomain, ...rest } = params;
  const body: MandateBody = { type: "accord/mandate", v: 1, owner: { domain: ownerDomain, key: owner.publicKey }, ...rest };
  const m = { body, signature: signValue(body, owner) };
  const problem = mandateProblem(m);
  if (problem) throw new Error(problem);
  return m;
}

/**
 * The mandate's id: the fingerprint of its signed body only. Anything outside the body (extra fields,
 * the signature's encoding) cannot change it, so a revocation by id always finds the mandate.
 */
export function mandateId(m: Mandate): string {
  return digest(m.body);
}

const KEY = /^ed25519:[0-9a-f]{64}$/;
const BODY_FIELDS = ["type", "v", "owner", "agent", "scope", "maxAmount", "notBefore", "notAfter", "charter"];
/** Size limits of a mandate's free fields (checked everywhere a mandate is accepted). */
export const MANDATE_LIMITS = { scopeMaxChars: 500, charterMaxChars: 64 } as const;

/**
 * An owner domain as the city accepts it: lowercase letters, digits and hyphens, at least two labels,
 * no trailing dot, a top-level label that starts with a letter (so no IP addresses, no "localhost").
 * One spelling per domain, so limits and lookups cannot be dodged with "EXAMPLE.com" or "example.com.".
 */
export function ownerDomainProblem(d: unknown): string | null {
  if (typeof d !== "string" || d.length > 253) return "owner domain is not a domain name";
  const labels = d.split(".");
  if (labels.length < 2 || labels.some((l) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) || !/^[a-z]/.test(labels[labels.length - 1]))
    return "owner domain must be a lowercase domain name like example.com (no trailing dot, no IP address)";
  return null;
}

/** Shape check: only known fields, right types, a canonical owner domain. Null if well formed. */
export function mandateProblem(m: unknown): string | null {
  const x = m as Mandate;
  if (!x || typeof x !== "object" || !x.body || typeof x.body !== "object") return "not a mandate";
  if (Object.keys(x).some((k) => k !== "body" && k !== "signature")) return "unexpected fields in mandate";
  const b = x.body;
  if (Object.keys(b).some((k) => !BODY_FIELDS.includes(k))) return "unexpected fields in mandate body";
  if (b.type !== "accord/mandate" || b.v !== 1) return "not a mandate";
  if (!b.owner || typeof b.owner !== "object" || Object.keys(b.owner).some((k) => k !== "domain" && k !== "key")) return "invalid mandate owner";
  const bad = ownerDomainProblem(b.owner.domain);
  if (bad) return bad;
  if (typeof b.owner.key !== "string" || !KEY.test(b.owner.key) || typeof b.agent !== "string" || !KEY.test(b.agent)) return "invalid key in mandate";
  if (typeof b.scope !== "string" || b.scope.length > MANDATE_LIMITS.scopeMaxChars) return `mandate scope must be a text of at most ${MANDATE_LIMITS.scopeMaxChars} characters`;
  if (typeof b.charter !== "string" || b.charter.length > MANDATE_LIMITS.charterMaxChars) return "invalid mandate charter";
  if (typeof b.notBefore !== "string" || typeof b.notAfter !== "string" || Number.isNaN(Date.parse(b.notBefore)) || Number.isNaN(Date.parse(b.notAfter)))
    return "invalid mandate dates";
  if (b.maxAmount !== undefined) {
    const a = b.maxAmount;
    if (
      !a || typeof a !== "object" || Object.keys(a).some((k) => k !== "value" && k !== "currency") ||
      typeof a.value !== "string" || !/^\d{1,18}(?:\.\d{1,6})?$/.test(a.value) || typeof a.currency !== "string" || !/^[A-Z]{3}$/.test(a.currency)
    )
      return "invalid mandate maxAmount";
  }
  if (typeof x.signature !== "string") return "mandate signature missing";
  return null;
}

/** True if the mandate is well formed (mandateProblem) and signed by the owner key it names. */
export function verifyMandateSignature(m: Mandate): boolean {
  return !mandateProblem(m) && verifyValue(m.body, m.signature, m.body.owner.key);
}

export function withinValidity(m: Mandate, isoTime: string): boolean {
  const t = Date.parse(isoTime);
  return t >= Date.parse(m.body.notBefore) && t <= Date.parse(m.body.notAfter);
}

/** Compares two decimal strings exactly (up to 6 decimals). */
export function amountLeq(a: string, b: string): boolean {
  const scale = (s: string) => {
    const m = /^(\d+)(?:\.(\d{1,6}))?$/.exec(s);
    if (!m) throw new Error(`invalid amount ${s}`);
    return BigInt(m[1]) * 1_000_000n + BigInt((m[2] ?? "").padEnd(6, "0"));
  };
  return scale(a) <= scale(b);
}

/** True if a clause value is, or contains at any depth, an object shaped like an amount ({value, currency} or {amount, currency}). */
export function looksLikeAmount(v: unknown, depth = 0): boolean {
  if (depth > 20 || v === null || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some((x) => looksLikeAmount(x, depth + 1));
  const o = v as Record<string, unknown>;
  if ("currency" in o && ("value" in o || "amount" in o)) return true;
  return Object.values(o).some((x) => looksLikeAmount(x, depth + 1));
}
