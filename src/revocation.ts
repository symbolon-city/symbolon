// Revocation: the city's "block card". An owner withdraws a mandate, stops an agent key, or
// declares one of its own keys stolen; an agent can give up its own mandate or declare its own
// key stolen. A revocation is a signed statement whose fingerprint is sealed in the register:
// its position in the register says, for everyone, from when it applies. Records sealed before
// it stay valid; anything sealed after it, or any mandate checked now, is refused.
//
// Who may revoke what (checked by whoever applies the revocation, never trusted from the register):
// - the mandate's owner key, or any key published at the owner's domain: anything about that owner's mandates;
// - the agent named in a mandate: that mandate ("I give it up") and its own key ("my key was stolen").
// A thief holding a stolen key can revoke it too, but cannot undo a revocation: there is no "unrevoke".

import { digest } from "./hash.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { mandateId, type Mandate } from "./mandate.js";

const HEX64 = /^[0-9a-f]{64}$/;
const KEY = /^ed25519:[0-9a-f]{64}$/;
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
  const body: RevocationBody = {
    type: "symbolon/revocation",
    v: 1,
    by: signer.publicKey,
    ...(p.ownerDomain ? { ownerDomain: p.ownerDomain } : {}),
    target: p.target,
    ...(p.reason ? { reason: p.reason } : {}),
    createdAt: p.createdAt ?? new Date().toISOString(),
  };
  const problem = revocationProblem({ body, signature: "" }, { skipSignature: true });
  if (problem) throw new Error(problem);
  return { body, signature: signValue(body, signer) };
}

/** The fingerprint sealed in the register. */
export function revocationId(r: Revocation): string {
  return digest(r);
}

/** What the revocation is about: a mandate id or a key. Used to look revocations up. */
export function revocationSubject(r: Revocation): string {
  return r.body.target.kind === "mandate" ? r.body.target.id : r.body.target.key;
}

/** The subjects to look up for a mandate: its id, its agent key, its owner key. */
export function subjectsOf(m: Mandate): string[] {
  return [mandateId(m), m.body.agent, m.body.owner.key];
}

/** Structural and signature check. Returns a problem, or null if well formed and signed by `by`. */
export function revocationProblem(r: Revocation, opts: { skipSignature?: boolean; now?: Date } = {}): string | null {
  const b = r?.body;
  if (!b || typeof b !== "object") return "not a revocation";
  if (b.type !== "symbolon/revocation" || b.v !== 1) return "not a revocation";
  if (typeof b.by !== "string" || !KEY.test(b.by)) return "invalid signer key";
  if (b.ownerDomain !== undefined && (typeof b.ownerDomain !== "string" || !/^[a-z0-9.-]{1,253}$/i.test(b.ownerDomain))) return "invalid owner domain";
  const t = b.target;
  if (!t || typeof t !== "object") return "invalid target";
  if (t.kind === "mandate") {
    if (typeof t.id !== "string" || !HEX64.test(t.id)) return "invalid mandate id";
  } else if (t.kind === "agent" || t.kind === "owner-key") {
    if (typeof t.key !== "string" || !KEY.test(t.key)) return "invalid target key";
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
  const byOwner = by === owner.key || (!!ownerKeys?.includes(by) && (ownerDomain ?? owner.domain) === owner.domain);
  const byAgent = by === m.body.agent;
  switch (target.kind) {
    case "mandate":
      return target.id === mandateId(m) && (byOwner || byAgent);
    case "agent":
      return target.key === m.body.agent && (byOwner || (byAgent && by === target.key));
    case "owner-key":
      return target.key === owner.key && byOwner;
  }
}

/** The revocations, among those found, that apply to the mandate (earliest first). */
export function revocationsOf(m: Mandate, found: RegisteredRevocation[], ownerKeys: PublicKey[] | null = null): RegisteredRevocation[] {
  return found.filter((x) => revokes(x.revocation, m, ownerKeys)).sort((a, b) => a.index - b.index);
}

/** Looks up revocations by subject (mandate ids and keys), e.g. from the register. */
export type RevocationSource = (subjects: string[]) => Promise<RegisteredRevocation[]>;
