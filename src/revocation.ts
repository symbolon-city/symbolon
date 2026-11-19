// Revocation: the city's "block card". An owner withdraws a mandate, stops an agent key, or
// declares one of its own keys stolen; an agent can give up its own mandate or declare its own
// key stolen. A revocation is a signed statement whose fingerprint is sealed in the register:
// its position in the register says, for everyone, from when it applies. Records sealed before
// it stay valid; anything sealed after it, or any mandate checked now, is refused.
//
// Who may revoke what (checked by whoever applies the revocation, never trusted from the register):
// - the mandate's owner key, or any key published at the owner's domain: anything about that owner's mandates;
// - the agent named in a mandate: that mandate ("I give it up") and its own key ("my key was stolen");
// - for a sub-mandate, also its issuer (the agent that gave it): that sub-mandate and that agent key.
// A revocation of any link of a chain stops every sub-mandate below it.
// A thief holding a stolen key can revoke it too, but cannot undo a revocation: there is no "unrevoke".

import { digest } from "./hash.js";
import { AGENT_KEY, OWNER_KEY, signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { linksOf, mandateId, ownerDomainProblem, type Mandate } from "./mandate.js";

const HEX64 = /^[0-9a-f]{64}$/;
export const MAX_REASON = 200;

export type RevocationTarget =
  /** One mandate, by its id (mandateId). */
  | { kind: "mandate"; id: string }
  /** Every mandate given to this agent key. */
  | { kind: "agent"; key: PublicKey }
  /** Every mandate signed with this owner key (the owner's key was stolen or retired). */
  | { kind: "owner-key"; key: PublicKey };

export interface RevocationBody {
  type: "symbolon/revocation";
  v: 1;
  /** The key that signs the revocation. */
  by: PublicKey;
  /** The owner domain the revocation speaks for (needed when signed with another published key of that domain). */
  ownerDomain?: string;
  target: RevocationTarget;
  /** Short plain reason, public. Never personal data. */
  reason?: string;
  createdAt: string;
}

export interface Revocation {
  body: RevocationBody;
  signature: string;
}

/** A revocation as the register holds it: its position and time in the register decide from when it applies. */
export interface RegisteredRevocation {
  revocation: Revocation;
  index: number;
  time: string;
}

export function createRevocation(
  signer: KeyPair,
  p: { target: RevocationTarget; ownerDomain?: string; reason?: string; createdAt?: string },
): Revocation {
  const body = revocationBody(signer.publicKey, p);
  return { body, signature: signValue(body, signer) };
}

/** A revocation from a body and a signature made elsewhere (an owner's passkey). Throws if it does not hold. */
export function signedRevocation(body: RevocationBody, signature: string): Revocation {
  const r = { body, signature };
  const problem = revocationProblem(r);
  if (problem) throw new Error(problem);
  return r;
}

/** The body of a revocation, checked, ready to be signed (by software or by a passkey: passkeyChallenge(body)). */
export function revocationBody(by: PublicKey, p: { target: RevocationTarget; ownerDomain?: string; reason?: string; createdAt?: string }): RevocationBody {
  const body: RevocationBody = {
    type: "symbolon/revocation",
    v: 1,
    by,
    ...(p.ownerDomain ? { ownerDomain: p.ownerDomain } : {}),
    target: p.target,
    ...(p.reason ? { reason: p.reason } : {}),
    createdAt: p.createdAt ?? new Date().toISOString(),
  };
  const problem = revocationProblem({ body, signature: "" }, { skipSignature: true });
  if (problem) throw new Error(problem);
  return body;
}

/** The fingerprint sealed in the register: of the signed body only, so nothing outside it can make a second id. */
export function revocationId(r: Revocation): string {
  return digest(r.body);
}

/** What the revocation is about: a mandate id or a key. Used to look revocations up. */
export function revocationSubject(r: Revocation): string {
  return r.body.target.kind === "mandate" ? r.body.target.id : r.body.target.key;
}

/** The subjects to look up for a mandate: the id and agent key of every link of its chain, and the owner key. */
export function subjectsOf(m: Mandate): string[] {
  const links = linksOf(m);
  // An approval of one agreement is also found by the id of the general mandate it extends.
  const under = links.flatMap((l) => (l.body.type === "accord/mandate" && l.body.agreement ? [l.body.agreement.under] : []));
  return [...new Set([...links.map(mandateId), ...under, ...links.map((l) => l.body.agent), m.body.owner.key])];
}

/**
 * The keys whose revocations can apply to this mandate: its owner key, its agent key and the other keys
 * published at the owner's domain (when known). Lookups ask the register for these signers only, so
 * revocations written by unrelated keys cannot crowd out the real one.
 */
export function signersOf(m: Mandate, ownerKeys: PublicKey[] | null = null): PublicKey[] {
  // An owner without a domain has no other keys: only its own key speaks for it.
  const others = m.body.owner.domain === undefined ? [] : (ownerKeys ?? []);
  return [...new Set([m.body.owner.key, ...linksOf(m).map((l) => l.body.agent), ...others])];
}

/** Structural and signature check. Returns a problem, or null if well formed and signed by `by`. */
export function revocationProblem(r: Revocation, opts: { skipSignature?: boolean; now?: Date } = {}): string | null {
  const b = r?.body;
  if (!b || typeof b !== "object") return "not a revocation";
  if (Object.keys(r).some((k) => k !== "body" && k !== "signature")) return "unexpected fields in revocation";
  if (b.type !== "symbolon/revocation" || b.v !== 1) return "not a revocation";
  if (typeof b.by !== "string" || !OWNER_KEY.test(b.by)) return "invalid signer key";
  if (b.ownerDomain !== undefined && ownerDomainProblem(b.ownerDomain)) return "invalid owner domain";
  const t = b.target;
  if (!t || typeof t !== "object") return "invalid target";
  if (Object.keys(t).some((k) => k !== "kind" && k !== (t.kind === "mandate" ? "id" : "key"))) return "unexpected fields in revocation target";
  if (t.kind === "mandate") {
    if (typeof t.id !== "string" || !HEX64.test(t.id)) return "invalid mandate id";
  } else if (t.kind === "agent" || t.kind === "owner-key") {
    if (typeof t.key !== "string" || !(t.kind === "agent" ? AGENT_KEY : OWNER_KEY).test(t.key)) return "invalid target key";
  } else return "invalid target";
  if (b.reason !== undefined && (typeof b.reason !== "string" || b.reason.length > MAX_REASON)) return `reason must be at most ${MAX_REASON} characters`;
  if (typeof b.createdAt !== "string" || Number.isNaN(Date.parse(b.createdAt))) return "invalid createdAt";
  if (opts.now && Date.parse(b.createdAt) > opts.now.getTime() + 5 * 60_000) return "createdAt is in the future";
  const keys = Object.keys(b).filter((k) => !["type", "v", "by", "ownerDomain", "target", "reason", "createdAt"].includes(k));
  if (keys.length) return "unexpected fields in revocation";
  if (!opts.skipSignature && (typeof r.signature !== "string" || !verifyValue(b, r.signature, b.by))) return "revocation signature is invalid";
  return null;
}

/**
 * Does this revocation apply to this mandate? `ownerKeys` are the keys currently published at the
 * mandate owner's domain (null if unknown): they let an owner revoke with another of its keys.
 */
export function revokes(r: Revocation, m: Mandate, ownerKeys: PublicKey[] | null = null): boolean {
  if (revocationProblem(r)) return false;
  const { by, target, ownerDomain } = r.body;
  const owner = m.body.owner;
  // Another key of the owner counts only for an owner with a domain that publishes it; an owner without a
  // domain (identity level "key") is its key, so only that key can revoke as owner.
  const byOwner = by === owner.key || (owner.domain !== undefined && !!ownerKeys?.includes(by) && (ownerDomain ?? owner.domain) === owner.domain);
  if (target.kind === "owner-key") return target.key === owner.key && byOwner;
  // Any link revoked stops the whole chain below it.
  return linksOf(m).some((l) => {
    const byAgent = by === l.body.agent;
    const byIssuer = l.body.type === "symbolon/submandate" && by === l.body.issuer;
    // Revoking the general mandate also revokes the approvals of single agreements given under it.
    const under = l.body.type === "accord/mandate" ? l.body.agreement?.under : undefined;
    if (target.kind === "mandate") return (target.id === mandateId(l) || target.id === under) && (byOwner || byAgent || byIssuer);
    return target.key === l.body.agent && (byOwner || (byAgent && by === target.key) || byIssuer);
  });
}

/** The revocations, among those found, that apply to the mandate (earliest first). */
export function revocationsOf(m: Mandate, found: RegisteredRevocation[], ownerKeys: PublicKey[] | null = null): RegisteredRevocation[] {
  return found.filter((x) => revokes(x.revocation, m, ownerKeys)).sort((a, b) => a.index - b.index);
}

/**
 * Looks up revocations by subject (mandate ids and keys), e.g. from the register. `signers`, when given,
 * limits the answer to revocations signed by those keys (see signersOf). A source must return every match
 * or throw: never a silently shortened list.
 */
export type RevocationSource = (subjects: string[], signers?: PublicKey[]) => Promise<RegisteredRevocation[]>;

/** Pages read at most by fetchAllRevocations (100 each): more than that is treated as "cannot check". */
export const MAX_REVOCATION_PAGES = 20;

/**
 * Reads every page of GET /v1/revocations for these subjects and signers. `get` fetches one path and
 * returns the parsed answer. Throws if the register does not answer or there are too many pages, so a
 * caller never mistakes a partial list for a complete one.
 */
export async function fetchAllRevocations(
  get: (path: string) => Promise<{ revocations: RegisteredRevocation[]; next?: number } | null>,
  subjects: string[],
  signers?: PublicKey[],
): Promise<RegisteredRevocation[]> {
  const out: RegisteredRevocation[] = [];
  let after: number | undefined;
  for (let page = 0; page < MAX_REVOCATION_PAGES; page++) {
    const q = new URLSearchParams([...subjects.map((s) => ["subject", s]), ...(signers ?? []).map((k) => ["signer", k]), ...(after === undefined ? [] : [["after", String(after)]])]);
    const r = await get(`/v1/revocations?${q}`);
    if (!r || !Array.isArray(r.revocations)) throw new Error("this register does not support revocations");
    out.push(...r.revocations);
    if (typeof r.next !== "number") return out;
    if (after !== undefined && r.next <= after) throw new Error("register returned a bad revocation page");
    after = r.next;
  }
  throw new Error("too many revocations for these subjects: cannot check them");
}
