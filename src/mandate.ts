// A mandate is the owner's signed permission for an agent to act on its behalf.
// Without a valid mandate an agreement binds nobody. A sub-mandate passes part of a mandate on to
// another agent, never more than was received; the owner at the top answers for the whole chain.

import { randomBytes, toHex } from "./bytes.js";
import { digest } from "./hash.js";
import { AGENT_KEY, OWNER_KEY, signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";

/**
 * Who answers for an agent. With `domain` (identity level "domain"): the key must be published at
 * https://<domain>/.well-known/symbolon.json. Without it (level "key"): the owner is known only by its key,
 * typically a passkey on the owner's phone. Always the same owner, but who it is is not verified: the
 * counterparty sees the level and decides.
 */
export interface Owner {
  domain?: string;
  key: PublicKey;
}

/** How an owner is shown: its domain, or its key when it has no domain. Keys contain ":", domains cannot, so the two never collide. */
export function ownerName(o: Owner): string {
  return o.domain ?? o.key;
}

export interface Amount {
  value: string; // decimal string, e.g. "50000.00"
  currency: string; // ISO 4217, e.g. "EUR"
}

/**
 * An owner's approval of one agreement only ("approve just this one" with Face ID): a mandate whose
 * `agreement` binds it to the exact clauses (their root), the other parties (agent keys and the mandates they
 * sign under) and the one record (its nonce), given under the agent's general mandate (`under`, its id). It
 * lets the agent go above its general limit for that agreement and nothing else; it ends with the general
 * mandate (expired, revoked, or not shown). It lasts at most APPROVAL_MAX_DAYS and cannot be passed on.
 */
export interface AgreementBinding {
  clausesRoot: string;
  /** The agent keys of the other parties, in any order. */
  with: PublicKey[];
  /**
   * The mandate id each of those agents signs under, in the same order as `with` (since 21/11/2026): the same
   * agent key under another owner's mandate is another party. Required for the approval to be usable.
   */
  withMandates?: string[];
  /**
   * The nonce of the one record this approval allows (since 21/11/2026, chosen when the approval is asked):
   * the record's identity, so the approval cannot be used for a second agreement. Required to be usable.
   */
  nonce?: string;
  /** Id of the agent's general mandate this approval extends. */
  under: string;
}

export const APPROVAL_MAX_DAYS = 7;

/** A mandate signed by the owner itself (the top of every chain). */
export interface MandateBody {
  type: "accord/mandate";
  v: 1;
  owner: Owner;
  agent: PublicKey;
  scope: string;
  maxAmount?: Amount;
  notBefore: string; // ISO 8601
  notAfter: string;
  charter: string;
  /** Present only in an approval of one agreement (see AgreementBinding). */
  agreement?: AgreementBinding;
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
  owner: Owner;
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

/**
 * Strict time parser for mandates, approvals and records: only `YYYY-MM-DDTHH:MM:SS(.sss)Z` (UTC, as written by
 * toISOString), with real calendar values. NaN for anything else, so a time never depends on the verifier's
 * time zone ("2026-11-27T00:00:00" without a zone is refused, not read as local time).
 */
export function parseTime(s: unknown): number {
  if (typeof s !== "string") return NaN;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(s);
  if (!m) return NaN;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  const t = Date.UTC(y, mo - 1, d, h, mi, se, m[7] ? Number(m[7].padEnd(3, "0")) : 0);
  const x = new Date(t);
  if (x.getUTCFullYear() !== y || x.getUTCMonth() !== mo - 1 || x.getUTCDate() !== d || x.getUTCHours() !== h || x.getUTCMinutes() !== mi || x.getUTCSeconds() !== se)
    return NaN;
  return t;
}

export interface Mandate {
  body: MandateBody | SubMandateBody;
  signature: string;
  /** For a sub-mandate: the mandates above it, top first. Not signed: each link carries its own signature. */
  chain?: Mandate[];
}

/** At most this many links in a chain, top included (keeps checks and revocation lookups small). */
export const MAX_CHAIN_LINKS = 4;

/** `ownerDomain` omitted: an owner without a website (identity level "key"). */
export function createMandate(
  owner: KeyPair,
  params: Omit<MandateBody, "type" | "v" | "owner"> & { ownerDomain?: string },
): Mandate {
  const body = mandateBody(owner.publicKey, params);
  return { body, signature: signValue(body, owner) };
}

/**
 * The body of a mandate, checked, ready to be signed. For an owner who signs with a passkey: the page shows
 * the body, the device signs passkeyChallenge(body), and signedMandate() puts the two together.
 */
export function mandateBody(ownerKey: PublicKey, params: Omit<MandateBody, "type" | "v" | "owner"> & { ownerDomain?: string }): MandateBody {
  const { ownerDomain, ...rest } = params;
  const owner: Owner = ownerDomain === undefined ? { key: ownerKey } : { domain: ownerDomain, key: ownerKey };
  const body: MandateBody = { type: "accord/mandate", v: 1, owner, ...rest };
  const problem = mandateProblem({ body, signature: "" });
  if (problem) throw new Error(problem);
  return body;
}

/** A mandate from a body and a signature made elsewhere (a passkey on the owner's device). Throws if the signature does not match. */
export function signedMandate(body: MandateBody, signature: string): Mandate {
  const m: Mandate = { body, signature };
  const problem = mandateProblem(m);
  if (problem) throw new Error(problem);
  if (!verifyValue(body, signature, body.owner.key)) throw new Error("the signature is not the owner's signature of this mandate");
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

const HEX64 = /^[0-9a-f]{64}$/;
const BODY_FIELDS = ["type", "v", "owner", "agent", "scope", "maxAmount", "notBefore", "notAfter", "charter", "agreement"];
const SUB_FIELDS = ["type", "v", "parent", "issuer", "owner", "agent", "scope", "maxAmount", "total", "notBefore", "notAfter", "charter", "task"];
/** Size limits of a mandate's free fields (checked everywhere a mandate is accepted). */
export const MANDATE_LIMITS = { scopeMaxChars: 500, charterMaxChars: 64 } as const;

/**
 * An owner domain as the city accepts it: lowercase letters, digits and hyphens, at least two labels,
 * no trailing dot, a top-level label that starts with a letter (so no IP addresses, no "localhost").
 * One spelling per domain, so limits and lookups cannot be dodged with "EXAMPLE.com" or "example.com.".
 */
/** Suffixes of names that are never public owner domains. */
const INTERNAL_SUFFIXES = ["localhost", "internal", "local", "lan", "home.arpa", "intranet", "corp", "localdomain"];

export function ownerDomainProblem(d: unknown): string | null {
  if (typeof d !== "string" || d.length > 253) return "owner domain is not a domain name";
  const labels = d.split(".");
  if (labels.length < 2 || labels.some((l) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) || !/^[a-z]/.test(labels[labels.length - 1]))
    return "owner domain must be a lowercase domain name like example.com (no trailing dot, no IP address)";
  // Names that lead to internal hosts: the city fetches https://<domain>/.well-known/symbolon.json.
  if (INTERNAL_SUFFIXES.some((x) => d === x || d.endsWith(`.${x}`))) return "owner domain must be a public domain name (not a local or internal one)";
  // An IPv4 address written inside the name (nip.io / sslip.io style: 10.0.0.1.nip.io, 10-0-0-1.sslip.io).
  const octet = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
  if (new RegExp(`(?:^|[.-])${octet}([.-])${octet}\\1${octet}\\1${octet}(?:$|[.-])`).test(d))
    return "owner domain must not contain an IP address";
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
  // No domain: an owner known only by its key. A domain written as anything but a valid domain is refused,
  // including a "domain" field present but empty or undefined: one spelling per owner.
  if ("domain" in b.owner) {
    const bad = ownerDomainProblem(b.owner.domain);
    if (bad) return bad;
  }
  if (typeof b.owner.key !== "string" || !OWNER_KEY.test(b.owner.key) || typeof b.agent !== "string" || !AGENT_KEY.test(b.agent)) return "invalid key in mandate";
  if (typeof b.scope !== "string" || b.scope.length > MANDATE_LIMITS.scopeMaxChars) return `mandate scope must be a text of at most ${MANDATE_LIMITS.scopeMaxChars} characters`;
  if (typeof b.charter !== "string" || b.charter.length > MANDATE_LIMITS.charterMaxChars) return "invalid mandate charter";
  if (Number.isNaN(parseTime(b.notBefore)) || Number.isNaN(parseTime(b.notAfter)))
    return "invalid mandate dates: times are YYYY-MM-DDTHH:MM:SS(.sss)Z, in UTC";
  if (b.maxAmount !== undefined && amountProblem(b.maxAmount, "maxAmount")) return "invalid mandate maxAmount";
  if (!sub && (b as MandateBody).agreement !== undefined) {
    const bad = bindingProblem(b as MandateBody);
    if (bad) return bad;
  }
  if (sub) {
    const s = b as SubMandateBody;
    if (typeof s.parent !== "string" || !HEX64.test(s.parent)) return "invalid parent mandate id";
    if (typeof s.issuer !== "string" || !AGENT_KEY.test(s.issuer)) return "invalid issuer key";
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

const BINDING_FIELDS = ["clausesRoot", "with", "withMandates", "nonce", "under"];
/** The nonce of a record bound by an approval: 16 to 32 random bytes in hex (createRecord writes 16). */
const APPROVAL_NONCE = /^[0-9a-f]{32,64}$/;

/** Shape of an approval's binding to one agreement. */
function bindingProblem(b: MandateBody): string | null {
  const a = b.agreement as AgreementBinding;
  if (!a || typeof a !== "object" || Array.isArray(a) || Object.keys(a).some((k) => !BINDING_FIELDS.includes(k)))
    return "invalid approval: agreement must be {clausesRoot, with, withMandates, nonce, under}";
  if (typeof a.clausesRoot !== "string" || !HEX64.test(a.clausesRoot) || typeof a.under !== "string" || !HEX64.test(a.under)) return "invalid approval: clausesRoot and under must be fingerprints";
  if (!Array.isArray(a.with) || a.with.length < 1 || a.with.length > 9 || a.with.some((k) => typeof k !== "string" || !AGENT_KEY.test(k)) || new Set(a.with).size !== a.with.length || a.with.includes(b.agent))
    return "invalid approval: with must list 1 to 9 other agents' keys, once each";
  if (a.withMandates !== undefined && (!Array.isArray(a.withMandates) || a.withMandates.length !== a.with.length || a.withMandates.some((x) => typeof x !== "string" || !HEX64.test(x))))
    return "invalid approval: withMandates must give the mandate id of each agent in with, in the same order";
  if (a.nonce !== undefined && (typeof a.nonce !== "string" || !APPROVAL_NONCE.test(a.nonce))) return "invalid approval: nonce must be 32 to 64 hex characters";
  const from = parseTime(b.notBefore);
  const to = parseTime(b.notAfter);
  if (!(to > from) || to - from > APPROVAL_MAX_DAYS * 86_400_000) return `invalid approval: it lasts at most ${APPROVAL_MAX_DAYS} days`;
  return null;
}

/**
 * Null if this mandate may be used for this agreement: always for an ordinary mandate; for an approval, only
 * if the record has exactly its clauses root, its nonce, and exactly its other parties, each under exactly the
 * mandate the owner saw. An approval without `nonce` or `withMandates` (format before 21/11/2026) allows nothing.
 *
 * With `general`, also checks the general mandate the approval extends (`under`): the mandates of the proof or
 * offer, among which it must be, and `at` (the sealing time, or now): it must be an owner-signed mandate of the
 * same owner and agent, itself no approval, valid at that time. Without it that check is left to the caller.
 */
export function approvalProblem(
  m: Mandate,
  record: { clausesRoot: string; nonce?: string; parties: Array<{ agent: PublicKey; mandate?: string }> },
  general?: { mandates: Mandate[]; at: string },
): string | null {
  const a = m.body.type === "accord/mandate" ? m.body.agreement : undefined;
  if (!a) return null;
  if (record.clausesRoot !== a.clausesRoot) return "the owner's approval is for other clauses";
  if (a.nonce === undefined || a.withMandates === undefined)
    return "the owner's approval is of an older format, not bound to one record and to the other parties' mandates: ask the owner again";
  if (record.nonce !== a.nonce) return "the owner's approval is for another record (another nonce): one approval allows one agreement only";
  const others = record.parties.filter((p) => p.agent !== m.body.agent);
  if (others.length !== a.with.length || new Set(others.map((p) => p.agent)).size !== others.length || others.some((p) => !a.with.includes(p.agent)))
    return "the owner's approval is for other parties";
  if (others.some((p) => p.mandate !== a.withMandates![a.with.indexOf(p.agent)]))
    return "the owner's approval is for other parties: an agent signs under another mandate (another owner?) than the one the owner approved";
  if (general) return generalProblem(m, a.under, general.mandates, general.at);
  return null;
}

/** Why the general mandate an approval extends does not hold it up (see approvalProblem), or null. */
function generalProblem(approval: Mandate, under: string, mandates: Mandate[], at: string): string | null {
  const g = mandates.find((x) => !mandateProblem(x) && mandateId(x) === under);
  if (!g) return "the general mandate the owner's approval extends is missing: an approval ends with its general mandate";
  const gb = g.body;
  const ab = approval.body;
  if (gb.type !== "accord/mandate" || gb.agreement) return "the owner's approval extends something that is not a general mandate signed by the owner";
  if (gb.agent !== ab.agent) return "the owner's approval extends the general mandate of another agent";
  if (gb.owner.key !== ab.owner.key || gb.owner.domain !== ab.owner.domain || "domain" in gb.owner !== "domain" in ab.owner)
    return "the owner's approval extends the general mandate of another owner";
  if (!verifyMandateSignature(g)) return "the general mandate the owner's approval extends is not signed by its owner";
  if (!withinValidity(g, at)) return `the general mandate the owner's approval extends was not valid at ${at}: an approval ends with its general mandate`;
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
  if (top.body.agreement) return "an approval for one agreement cannot be passed on to another agent";
  if (!verifyValue(top.body, top.signature, top.body.owner.key)) return "the owner's signature at the top of the chain is invalid";
  for (let i = 1; i < links.length; i++) {
    const above = links[i - 1];
    const l = links[i];
    if (l.body.type !== "symbolon/submandate") return "only the top of a chain can be signed by the owner";
    const b = l.body;
    if (b.parent !== mandateId(above)) return "a link does not point to the mandate above it";
    if (b.issuer !== above.body.agent) return "a link is not given by the agent of the mandate above it";
    if ("domain" in b.owner !== "domain" in top.body.owner || b.owner.domain !== top.body.owner.domain || b.owner.key !== top.body.owner.key)
      return "a link names another owner than the top of the chain";
    if (b.agent === above.body.agent) return "a link gives the mandate back to the same agent";
    if (!verifyValue(b, l.signature, b.issuer)) return "a link's signature is invalid";
    if (parseTime(b.notBefore) < parseTime(above.body.notBefore) || parseTime(b.notAfter) > parseTime(above.body.notAfter))
      return "a link is valid outside the dates of the mandate above it";
    if (!atMost(b.maxAmount, above.body.maxAmount)) return "a link allows a bigger amount per agreement than the mandate above it";
    const aboveTotal = above.body.type === "symbolon/submandate" ? above.body.total : undefined;
    if (!atMost(b.total, aboveTotal)) return "a link allows a bigger total than the mandate above it";
    // Per agreement never above a total: neither the link's own, nor the one of the link above.
    if (b.maxAmount && !atMost(b.maxAmount, aboveTotal)) return "a link allows a bigger amount per agreement than the total of the mandate above it";
    if (b.maxAmount && b.total && !atMost(b.maxAmount, b.total)) return "a link allows a bigger amount per agreement than its own total";
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

/** True if the mandate is valid at this time (both read with parseTime: a time in another form is never within). */
export function withinValidity(m: Mandate, isoTime: string): boolean {
  const t = parseTime(isoTime);
  return t >= parseTime(m.body.notBefore) && t <= parseTime(m.body.notAfter);
}

/** Compares two decimal strings exactly (up to 6 decimals). */
export function amountLeq(a: string, b: string): boolean {
  const scale = (s: string) => {
    const m = /^(\d+)(?:\.(\d{1,6}))?$/.exec(s);
    if (!m) throw new Error("invalid amount: a decimal string with up to 6 decimals is expected");
    return BigInt(m[1]) * 1_000_000n + BigInt((m[2] ?? "").padEnd(6, "0"));
  };
  return scale(a) <= scale(b);
}

/**
 * The spending limit that really applies to one agreement under this mandate: the smallest limit
 * (per agreement or total) of any link of its chain, so a counterparty sees what the agent can actually
 * commit to. If two limits are in different currencies the mandate allows nothing ("0" in the first one).
 *
 * The total is a promise kept by whoever issues the mandate (the operator's software, the agent's wallet):
 * the city checks that each link stays within the link above, but it does not add up what several
 * sub-mandates of the same parent spend together. One agreement never exceeds this limit; the sum of many
 * agreements is the issuer's responsibility.
 */
export function spendingLimit(m: Mandate): Amount | undefined {
  let min: Amount | undefined;
  for (const l of linksOf(m)) {
    for (const a of [l.body.maxAmount, l.body.type === "symbolon/submandate" ? l.body.total : undefined]) {
      if (!a) continue;
      if (!min) min = a;
      else if (a.currency !== min.currency) return { value: "0", currency: min.currency };
      else {
        try {
          if (amountLeq(a.value, min.value)) min = a;
        } catch {
          return { value: "0", currency: min.currency };
        }
      }
    }
  }
  return min;
}

/** True if a clause value is, or contains at any depth, an object shaped like an amount ({value, currency} or {amount, currency}). */
export function looksLikeAmount(v: unknown, depth = 0): boolean {
  if (depth > 20 || v === null || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some((x) => looksLikeAmount(x, depth + 1));
  const o = v as Record<string, unknown>;
  if ("currency" in o && ("value" in o || "amount" in o)) return true;
  return Object.values(o).some((x) => looksLikeAmount(x, depth + 1));
}
