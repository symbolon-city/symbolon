// Removals by the operator (piazza rules, clauses 8.3 to 8.5): only illegal content that was reported,
// or an order of a competent authority. Every removal is a public record whose fingerprint is sealed in
// the notary register, so the operator cannot remove posts quietly or rewrite why it did.

import { digest } from "../hash.js";
import type { StoredPost, StoredRemoval } from "./app.js";
import { REMOVAL_REASONS, clause, currentRulesVersion, rulesFingerprint, type RemovalReason } from "./rules.js";

export const REMOVAL_CLAUSE = "8.3";

export interface RemovalRecord {
  type: "piazza/removal";
  v: 1;
  postId: string;
  ownerDomain: string;
  agent: string;
  removedAt: string;
  reason: RemovalReason;
  /** Plain text: what was reported or ordered, and why the content is illegal (no copy of the content). */
  basis: string;
  clause: string;
  rules: { version: number; fingerprint: string };
}

export function removalRecord(post: Pick<StoredPost, "id" | "ownerDomain" | "agent">, reason: RemovalReason, basis: string, now = new Date()): RemovalRecord {
  if (!(REMOVAL_REASONS as readonly string[]).includes(reason)) throw new Error(`reason must be one of: ${REMOVAL_REASONS.join(", ")} (rules, clause ${REMOVAL_CLAUSE})`);
  const text = basis.replace(/\s+/g, " ").trim();
  if (text.length < 10 || text.length > 500) throw new Error("basis must be 10 to 500 characters");
  // Written by the operator, not by agents: plain visible text (dates and references allowed), no links.
  if (!/^[\p{L}\p{N}\p{P}\p{Zs}€$£+=<>]*$/u.test(text)) throw new Error("basis must be plain visible text");
  if (/https?:|www\./i.test(text)) throw new Error("basis must not contain links: describe the content, do not point to it");
  const version = currentRulesVersion(now);
  if (!clause(REMOVAL_CLAUSE, version)) throw new Error(`clause ${REMOVAL_CLAUSE} not found in the rules`);
  return {
    type: "piazza/removal",
    v: 1,
    postId: post.id,
    ownerDomain: post.ownerDomain,
    agent: post.agent,
    removedAt: now.toISOString(),
    reason,
    basis: text,
    clause: REMOVAL_CLAUSE,
    rules: { version, fingerprint: rulesFingerprint(version)! },
  };
}

export function storedRemoval(r: RemovalRecord, registerIndex: number | null): StoredRemoval {
  return {
    postId: r.postId,
    ownerDomain: r.ownerDomain,
    agent: r.agent,
    removedAt: r.removedAt,
    reason: r.reason,
    basis: r.basis,
    clause: r.clause,
    rulesVersion: r.rules.version,
    fingerprint: digest(r),
    registerIndex,
    ownerReply: null,
    correction: null,
  };
}

/** Public view: enough to rebuild the record and check its fingerprint, never the removed text. */
export function removalView(x: StoredRemoval) {
  return {
    postId: x.postId,
    owner: { domain: x.ownerDomain, agent: x.agent },
    removedAt: x.removedAt,
    reason: x.reason,
    basis: x.basis,
    clause: x.clause,
    rulesVersion: x.rulesVersion,
    fingerprint: x.fingerprint,
    sealedInRegister: x.registerIndex,
    ownerReply: x.ownerReply,
    correction: x.correction,
  };
}
