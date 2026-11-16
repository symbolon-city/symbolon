// Checking another agent's mandate: signed by its owner, valid now, the owner's key
// published on the owner's website (level "domain"), and not revoked. Used by the agent wallet
// and by the visitors' door, which has no wallet.

import { spendingLimit, verifyMandateSignature, withinValidity, type Amount, type Mandate } from "./mandate.js";
import { revocationsOf, signersOf, subjectsOf, type RevocationSource } from "./revocation.js";
import type { OwnerResolver } from "./wellknown.js";

export interface CounterpartyCheck {
  ok: boolean;
  owner: string;
  level: "unverified" | "domain";
  scope: string;
  maxAmount?: Amount;
  /** For a task or sub-mandate: the limit for everything done under it. */
  total?: Amount;
  /** The most one agreement with this agent can be worth: the smallest limit along its whole chain. */
  limit?: Amount;
  validUntil: string;
  /** How the agent holds its mandate: directly from the owner, or through a chain (operator task, subcontracting). */
  via: { links: number; task: boolean };
  /** Present when the mandate was revoked: from when (register time and position), by whom, why. */
  revoked?: { at: string; registerIndex: number; by: string; target: string; reason?: string };
  /** "checked" when revocations were looked up, "not checked" otherwise (e.g. register unreachable). */
  revocations: "checked" | "not checked";
  problems: string[];
}

export async function checkMandate(
  m: Mandate,
  opts: { ownerResolver?: OwnerResolver; revocations?: RevocationSource; now?: Date } = {},
): Promise<CounterpartyCheck> {
  if (!m || typeof m !== "object" || !m.body || typeof m.body !== "object" || !m.body.owner) throw new Error("not a mandate");
  const problems: string[] = [];
  if (!verifyMandateSignature(m)) problems.push("mandate signature is invalid");
  if (!withinValidity(m, (opts.now ?? new Date()).toISOString())) problems.push("mandate is not valid now");
  let level: CounterpartyCheck["level"] = "unverified";
  let ownerKeys: string[] | null = null;
  if (opts.ownerResolver) {
    ownerKeys = await opts.ownerResolver(m.body.owner.domain);
    if (ownerKeys?.includes(m.body.owner.key)) level = "domain";
    else problems.push(`owner key not published by ${m.body.owner.domain}`);
  }
  let revoked: CounterpartyCheck["revoked"];
  let status: CounterpartyCheck["revocations"] = "not checked";
  if (opts.revocations) {
    try {
      const hit = revocationsOf(m, await opts.revocations(subjectsOf(m), signersOf(m, ownerKeys)), ownerKeys)[0];
      status = "checked";
      if (hit) {
        const b = hit.revocation.body;
        revoked = { at: hit.time, registerIndex: hit.index, by: b.by, target: b.target.kind, ...(b.reason ? { reason: b.reason } : {}) };
        problems.push(`mandate revoked on ${hit.time} (${b.target.kind}${b.reason ? `: ${b.reason}` : ""})`);
      }
    } catch {
      problems.push("could not check revocations: treat as not verified");
    }
  }
  return {
    ok: problems.length === 0,
    owner: m.body.owner.domain,
    level,
    scope: m.body.scope,
    maxAmount: m.body.maxAmount,
    ...(m.body.type === "symbolon/submandate" && m.body.total ? { total: m.body.total } : {}),
    ...(spendingLimit(m) ? { limit: spendingLimit(m) } : {}),
    validUntil: m.body.notAfter,
    via: { links: (m.chain?.length ?? 0) + 1, task: m.body.type === "symbolon/submandate" && !!m.body.task },
    ...(revoked ? { revoked } : {}),
    revocations: status,
    problems,
  };
}
