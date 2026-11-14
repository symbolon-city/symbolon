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
  return { body, signature: signValue(body, owner) };
}

export function mandateId(m: Mandate): string {
  return digest(m);
}

export function verifyMandateSignature(m: Mandate): boolean {
  return m.body.type === "accord/mandate" && verifyValue(m.body, m.signature, m.body.owner.key);
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
