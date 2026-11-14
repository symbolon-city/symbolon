// Checking another agent's mandate: signed by its owner, valid now, and the owner's key
// published on the owner's website (level "domain"). Used by the agent wallet and by the
// visitors' door, which has no wallet.

import { verifyMandateSignature, withinValidity, type Amount, type Mandate } from "./mandate.js";
import type { OwnerResolver } from "./wellknown.js";

export interface CounterpartyCheck {
  ok: boolean;
  owner: string;
  level: "unverified" | "domain";
  scope: string;
  maxAmount?: Amount;
  validUntil: string;
  problems: string[];
}

export async function checkMandate(m: Mandate, opts: { ownerResolver?: OwnerResolver; now?: Date } = {}): Promise<CounterpartyCheck> {
  if (!m || typeof m !== "object" || !m.body || typeof m.body !== "object" || !m.body.owner) throw new Error("not a mandate");
  const problems: string[] = [];
  if (!verifyMandateSignature(m)) problems.push("mandate signature is invalid");
  if (!withinValidity(m, (opts.now ?? new Date()).toISOString())) problems.push("mandate is not valid now");
  let level: CounterpartyCheck["level"] = "unverified";
  if (opts.ownerResolver) {
    const keys = await opts.ownerResolver(m.body.owner.domain);
    if (keys?.includes(m.body.owner.key)) level = "domain";
    else problems.push(`owner key not published by ${m.body.owner.domain}`);
  }
  return {
    ok: problems.length === 0,
    owner: m.body.owner.domain,
    level,
    scope: m.body.scope,
    maxAmount: m.body.maxAmount,
    validUntil: m.body.notAfter,
    problems,
  };
}
