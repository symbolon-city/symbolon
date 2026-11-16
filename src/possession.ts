// Proof of possession. Mandates are public: anyone can copy one and show it. Checking a mandate proves
// that its owner gave it to some agent key, not that the agent in front of you holds that key. So the
// checker picks a fresh random word (the challenge), the other agent signs it with its key, and the
// checker verifies the signature against the key named in the mandate.
//
//   checker:  const c = newChallenge()                      -> send c.challenge to the other agent
//   agent:    const answer = answerChallenge(key, mandate, c.challenge, { for: checkerKey })
//   checker:  possessionProblem(mandate, answer, c.challenge) -> null if the agent holds the key
//
// Limit (as in every challenge-response without a secure channel): a middleman who talks to the real
// agent at the same time can pass the challenge on and bring back its answer. Naming the checker in
// the answer (`for`) lets an honest agent refuse to answer for someone it is not talking to, and lets
// the checker refuse answers meant for someone else.

import { randomBytes, toHex } from "./bytes.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { mandateId, type Mandate } from "./mandate.js";

export interface PossessionBody {
  type: "symbolon/possession";
  v: 1;
  /** The checker's random word, 64 hex characters. */
  challenge: string;
  /** The agent key that signs: must be the agent named in the mandate. */
  agent: PublicKey;
  /** mandateId of the mandate this answer is for. */
  mandate: string;
  /** Who asked, when known (the checker's agent key). */
  for?: PublicKey;
  /** When the agent answered (ISO 8601). */
  at: string;
}

export interface PossessionAnswer {
  body: PossessionBody;
  signature: string;
}

const HEX64 = /^[0-9a-f]{64}$/;
const KEY = /^ed25519:[0-9a-f]{64}$/;
/** How old an answer can be, and how far in the future its clock can be (default 5 minutes). */
export const POSSESSION_MAX_AGE_MS = 5 * 60_000;

/** A fresh random challenge for the other agent to sign. Keep it until the answer comes back. */
export function newChallenge(now = new Date()): { challenge: string; issuedAt: string; expiresAt: string } {
  return {
    challenge: toHex(randomBytes(32)),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + POSSESSION_MAX_AGE_MS).toISOString(),
  };
}

/** The agent signs the checker's challenge with its own key, for the mandate it shows. */
export function answerChallenge(key: KeyPair, mandate: Mandate, challenge: string, o: { for?: PublicKey; now?: Date } = {}): PossessionAnswer {
  if (typeof challenge !== "string" || !HEX64.test(challenge)) throw new Error("the challenge must be 64 lowercase hex characters");
  if (mandate.body.agent !== key.publicKey) throw new Error("this mandate is for another agent key");
  if (o.for !== undefined && (typeof o.for !== "string" || !KEY.test(o.for))) throw new Error("invalid checker key");
  const body: PossessionBody = {
    type: "symbolon/possession",
    v: 1,
    challenge,
    agent: key.publicKey,
    mandate: mandateId(mandate),
    ...(o.for ? { for: o.for } : {}),
    at: (o.now ?? new Date()).toISOString(),
  };
  return { body, signature: signValue(body, key) };
}

/**
 * Null if the answer proves that whoever answered holds the key named in the mandate, for this very
 * challenge, recently; otherwise why not. It does not check the mandate itself (use checkMandate for that).
 */
export function possessionProblem(
  mandate: Mandate,
  answer: unknown,
  challenge: string,
  o: { for?: PublicKey; now?: Date; maxAgeMs?: number } = {},
): string | null {
  const a = answer as PossessionAnswer;
  if (!a || typeof a !== "object" || !a.body || typeof a.body !== "object" || typeof a.signature !== "string") return "not a possession answer";
  if (Object.keys(a).some((k) => k !== "body" && k !== "signature")) return "unexpected fields in possession answer";
  const b = a.body;
  if (Object.keys(b).some((k) => !["type", "v", "challenge", "agent", "mandate", "for", "at"].includes(k))) return "unexpected fields in possession answer";
  if (b.type !== "symbolon/possession" || b.v !== 1) return "not a possession answer";
  if (typeof challenge !== "string" || !HEX64.test(challenge)) return "the challenge must be 64 lowercase hex characters";
  if (b.challenge !== challenge) return "the answer is for another challenge";
  if (!mandate || !mandate.body || b.agent !== mandate.body.agent) return "the answer is signed for another agent than the one named in the mandate";
  if (b.mandate !== mandateId(mandate)) return "the answer is for another mandate";
  if (o.for !== undefined && b.for !== o.for) return "the answer was given to someone else";
  const t = typeof b.at === "string" ? Date.parse(b.at) : NaN;
  const now = (o.now ?? new Date()).getTime();
  const max = o.maxAgeMs ?? POSSESSION_MAX_AGE_MS;
  if (Number.isNaN(t) || t < now - max || t > now + max) return "the answer is too old or dated in the future";
  if (!verifyValue(b, a.signature, b.agent)) return "the signature does not match the agent key in the mandate";
  return null;
}
