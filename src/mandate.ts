// A mandate is the owner's signed permission for an agent to act on its behalf.
// Without a valid mandate an agreement binds nobody. A sub-mandate passes part of a mandate on to
// another agent, never more than was received; the owner at the top answers for the whole chain.

import { randomBytes, toHex } from "./bytes.js";
import { digest } from "./hash.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";

export interface Amount {
  value: string; // decimal string, e.g. "50000.00"
  currency: string; // ISO 4217, e.g. "EUR"
}

/** A mandate signed by the owner itself (the top of every chain). */
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

/**
 * A sub-mandate: given by an agent (the "issuer", the agent of the mandate above) to another agent, with
 * limits that can only be equal or smaller. Used by operators for each task of a person ("automatic mode")
 * and by agents that hand part of a job to other agents. `owner` is copied from the top of the chain: the
 * owner answers for every link. The links above travel with it in `chain` (outside the signed body).
 */
export interface SubMandateBody {
  type: "symbolon/submandate";
  v: 1;
  /** mandateId of the mandate above. */
  parent: string;
  /** The agent key of the mandate above: it signs this one. */
  issuer: PublicKey;
  owner: { domain: string; key: PublicKey };
  agent: PublicKey;
  scope: string;
  /** Limit per agreement. */
  maxAmount?: Amount;
  /** Limit for everything done under this mandate (kept by the agent's wallet and the issuer's software). */
  total?: Amount;
  notBefore: string;
  notAfter: string;
  charter: string;
  /** Salted fingerprints of the person's original instruction and of who the person is (no personal data in clear). */
  task?: { instruction: string; principal: string };
}

export interface Mandate {
  body: MandateBody | SubMandateBody;
  signature: string;
  /** For a sub-mandate: the mandates above it, top first. Not signed: each link carries its own signature. */
  chain?: Mandate[];
}

/** At most this many links in a chain, top included (keeps checks and revocation lookups small). */
export const MAX_CHAIN_LINKS = 4;

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

/** The mandate without the links above it: what a chain stores for each link. */
function bare(m: Mandate): Mandate {
  return { body: m.body, signature: m.signature };
}

/** Every link of a mandate, top first, the mandate itself last. */
export function linksOf(m: Mandate): Mandate[] {
  return [...(m.chain ?? []).map(bare), bare(m)];
}

/**
 * Gives part of a mandate to another agent. `issuer` must be the agent of `parent`. Limits and dates are
 * checked against every link above: a sub-mandate can never give more than it received.
 */
export function createSubMandate(
  issuer: KeyPair,
  parent: Mandate,
  params: { agent: PublicKey; scope: string; maxAmount?: Amount; total?: Amount; notBefore: string; notAfter: string; charter?: string; task?: { instruction: string; principal: string } },
): Mandate {
  if (issuer.publicKey !== parent.body.agent) throw new Error("only the agent of the mandate above can give a sub-mandate");
  const body: SubMandateBody = {
    type: "symbolon/submandate",
    v: 1,
    parent: mandateId(parent),
    issuer: issuer.publicKey,
    owner: { ...parent.body.owner },
    agent: params.agent,
    scope: params.scope,
    ...(params.maxAmount ? { maxAmount: params.maxAmount } : {}),
    ...(params.total ? { total: params.total } : {}),
    notBefore: params.notBefore,
    notAfter: params.notAfter,
    charter: params.charter ?? parent.body.charter,
    ...(params.task ? { task: params.task } : {}),
  };
  const m: Mandate = { body, signature: signValue(body, issuer), chain: linksOf(parent) };
  const problem = mandateProblem(m) ?? chainProblem(m);
  if (problem) throw new Error(problem);
  return m;
}

/**
 * The mandate's id: the fingerprint of its signed body only. Anything outside the body (extra fields,
 * the signature's encoding, the links above) cannot change it, so a revocation by id always finds it.
 */
export function mandateId(m: Mandate): string {
  return digest(m.body);
}

const KEY = /^ed25519:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const BODY_FIELDS = ["type", "v", "owner", "agent", "scope", "maxAmount", "notBefore", "notAfter", "charter"];
const SUB_FIELDS = ["type", "v", "parent", "issuer", "owner", "agent", "scope", "maxAmount", "total", "notBefore", "notAfter", "charter", "task"];
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

function amountProblem(a: unknown, name: string): string | null {
  const x = a as Amount;
  if (
    !x || typeof x !== "object" || Object.keys(x).some((k) => k !== "value" && k !== "currency") ||
    typeof x.value !== "string" || !/^\d{1,18}(?:\.\d{1,6})?$/.test(x.value) || typeof x.currency !== "string" || !/^[A-Z]{3}$/.test(x.currency)
  )
    return `invalid mandate ${name}`;
  return null;
}

/** Shape of one mandate body and signature, without the chain. */
function oneProblem(x: Mandate, allowChain: boolean): string | null {
  if (!x || typeof x !== "object" || !x.body || typeof x.body !== "object") return "not a mandate";
  if (Object.keys(x).some((k) => k !== "body" && k !== "signature" && !(allowChain && k === "chain"))) return "unexpected fields in mandate";
  const b = x.body;
  const sub = b.type === "symbolon/submandate";
  if (Object.keys(b).some((k) => !(sub ? SUB_FIELDS : BODY_FIELDS).includes(k))) return "unexpected fields in mandate body";
  if ((b.type !== "accord/mandate" && !sub) || b.v !== 1) return "not a mandate";
  if (!b.owner || typeof b.owner !== "object" || Object.keys(b.owner).some((k) => k !== "domain" && k !== "key")) return "invalid mandate owner";
  const bad = ownerDomainProblem(b.owner.domain);
  if (bad) return bad;
  if (typeof b.owner.key !== "string" || !KEY.test(b.owner.key) || typeof b.agent !== "string" || !KEY.test(b.agent)) return "invalid key in mandate";
  if (typeof b.scope !== "string" || b.scope.length > MANDATE_LIMITS.scopeMaxChars) return `mandate scope must be a text of at most ${MANDATE_LIMITS.scopeMaxChars} characters`;
  if (typeof b.charter !== "string" || b.charter.length > MANDATE_LIMITS.charterMaxChars) return "invalid mandate charter";
  if (typeof b.notBefore !== "string" || typeof b.notAfter !== "string" || Number.isNaN(Date.parse(b.notBefore)) || Number.isNaN(Date.parse(b.notAfter)))
    return "invalid mandate dates";
  if (b.maxAmount !== undefined && amountProblem(b.maxAmount, "maxAmount")) return "invalid mandate maxAmount";
  if (sub) {
    const s = b as SubMandateBody;
    if (typeof s.parent !== "string" || !HEX64.test(s.parent)) return "invalid parent mandate id";
    if (typeof s.issuer !== "string" || !KEY.test(s.issuer)) return "invalid issuer key";
    if (s.total !== undefined && amountProblem(s.total, "total")) return "invalid mandate total";
    if (s.task !== undefined) {
      const t = s.task;
      if (!t || typeof t !== "object" || Object.keys(t).some((k) => k !== "instruction" && k !== "principal") || !HEX64.test(String(t.instruction)) || !HEX64.test(String(t.principal)))
        return "invalid mandate task";
    }
  }
  if (typeof x.signature !== "string") return "mandate signature missing";
  return null;
}

/** Shape check: only known fields, right types, a canonical owner domain; for a sub-mandate, its chain too. Null if well formed. */
export function mandateProblem(m: unknown): string | null {
  const x = m as Mandate;
  const p = oneProblem(x, true);
  if (p) return p;
  const sub = x.body.type === "symbolon/submandate";
  if (!sub) return x.chain === undefined ? null : "a mandate signed by its owner has no chain";
  if (!Array.isArray(x.chain) || x.chain.length < 1 || x.chain.length > MAX_CHAIN_LINKS - 1) return `a sub-mandate carries 1 to ${MAX_CHAIN_LINKS - 1} mandates above it`;
  for (const c of x.chain) {
    const q = oneProblem(c, false);
    if (q) return `mandate above: ${q}`;
  }
  return null;
}

function atMost(child: Amount | undefined, parent: Amount | undefined): boolean {
  if (!parent) return true;
  if (!child || child.currency !== parent.currency) return false;
  try {
    return amountLeq(child.value, parent.value);
  } catch {
    return false;
  }
}

/**
 * Why a sub-mandate's chain is not acceptable, or null: the top is signed by the owner key it names,
 * each link is signed by the agent of the link above, names it as parent, keeps the same owner, and
 * never gives more (limits, dates) than the link above.
 */
export function chainProblem(m: Mandate): string | null {
  const shape = mandateProblem(m);
  if (shape) return shape;
  const links = linksOf(m);
  if (links.length > MAX_CHAIN_LINKS) return "chain too long";
  const top = links[0];
  if (top.body.type !== "accord/mandate") return "the top of the chain must be a mandate signed by its owner";
  if (!verifyValue(top.body, top.signature, top.body.owner.key)) return "the owner's signature at the top of the chain is invalid";
  for (let i = 1; i < links.length; i++) {
    const above = links[i - 1];
    const l = links[i];
    if (l.body.type !== "symbolon/submandate") return "only the top of a chain can be signed by the owner";
    const b = l.body;
    if (b.parent !== mandateId(above)) return "a link does not point to the mandate above it";
    if (b.issuer !== above.body.agent) return "a link is not given by the agent of the mandate above it";
    if (b.owner.domain !== top.body.owner.domain || b.owner.key !== top.body.owner.key) return "a link names another owner than the top of the chain";
    if (b.agent === above.body.agent) return "a link gives the mandate back to the same agent";
    if (!verifyValue(b, l.signature, b.issuer)) return "a link's signature is invalid";
    if (Date.parse(b.notBefore) < Date.parse(above.body.notBefore) || Date.parse(b.notAfter) > Date.parse(above.body.notAfter))
      return "a link is valid outside the dates of the mandate above it";
    if (!atMost(b.maxAmount, above.body.maxAmount)) return "a link allows a bigger amount per agreement than the mandate above it";
    const aboveTotal = above.body.type === "symbolon/submandate" ? above.body.total : undefined;
    if (!atMost(b.total, aboveTotal)) return "a link allows a bigger total than the mandate above it";
  }
  return null;
}

/** True if the mandate is well formed and correctly signed: by the owner key it names, or, for a sub-mandate, along its whole chain. */
export function verifyMandateSignature(m: Mandate): boolean {
  if (mandateProblem(m)) return false;
  if (m.body.type === "symbolon/submandate") return chainProblem(m) === null;
  return verifyValue(m.body, m.signature, m.body.owner.key);
}

/**
 * Salted fingerprints for a task: of the person's instruction and of who the person is. The operator
 * keeps `salt`; revealing it later (in a dispute) proves which instruction and which customer, while
 * nothing readable ever leaves the operator.
 */
export function taskCommitments(instruction: string, principalId: string, salt = toHex(randomBytes(32))) {
  return {
    task: { instruction: digest({ salt, instruction }), principal: digest({ salt, principal: principalId }) },
    salt,
  };
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

/** The spending limit that applies to one agreement under this mandate: per agreement, or else the total of a sub-mandate. */
export function spendingLimit(m: Mandate): Amount | undefined {
  return m.body.maxAmount ?? (m.body.type === "symbolon/submandate" ? m.body.total : undefined);
}

/** True if a clause value is, or contains at any depth, an object shaped like an amount ({value, currency} or {amount, currency}). */
export function looksLikeAmount(v: unknown, depth = 0): boolean {
  if (depth > 20 || v === null || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some((x) => looksLikeAmount(x, depth + 1));
  const o = v as Record<string, unknown>;
  if ("currency" in o && ("value" in o || "amount" in o)) return true;
  return Object.values(o).some((x) => looksLikeAmount(x, depth + 1));
}
