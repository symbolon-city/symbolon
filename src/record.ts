// A record is what the agents sign: an agreement between two or more agents,
// or an action sealed by a single agent ("what I was asked, what I did").
// It contains only the clause root, never the clauses themselves.

import { randomBytes, toHex } from "./bytes.js";
import { digest } from "./hash.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";

export type RecordType = "accord/agreement" | "accord/action";

export interface RecordBody {
  type: RecordType;
  v: 1;
  clausesRoot: string;
  clauseCount: number;
  parties: Array<{ agent: PublicKey; mandate: string }>;
  charter: string;
  createdAt: string;
  nonce: string;
}

export interface SignedRecord {
  body: RecordBody;
  signatures: Array<{ agent: PublicKey; signature: string }>;
}

export function createRecord(params: Omit<RecordBody, "v" | "nonce">): SignedRecord {
  if (params.type === "accord/agreement" && params.parties.length < 2)
    throw new Error("an agreement needs at least two parties");
  if (params.type === "accord/action" && params.parties.length !== 1)
    throw new Error("an action has exactly one party");
  return { body: { ...params, v: 1, nonce: toHex(randomBytes(16)) }, signatures: [] };
}

const HEX64 = /^[0-9a-f]{64}$/;
const KEY = /^ed25519:[0-9a-f]{64}$/;
const BODY_FIELDS = ["type", "v", "clausesRoot", "clauseCount", "parties", "charter", "createdAt", "nonce"];

/**
 * Shape check of a signed record: known type and fields only, the right number of distinct parties,
 * one signature entry per party at most. Null if well formed. Signatures themselves are checked elsewhere.
 */
export function recordProblem(r: unknown): string | null {
  const x = r as SignedRecord;
  if (!x || typeof x !== "object" || !x.body || typeof x.body !== "object" || !Array.isArray(x.signatures)) return "not a record";
  if (Object.keys(x).some((k) => k !== "body" && k !== "signatures")) return "unexpected fields in record";
  const b = x.body;
  if (Object.keys(b).some((k) => !BODY_FIELDS.includes(k))) return "unexpected fields in record body";
  if ((b.type !== "accord/agreement" && b.type !== "accord/action") || b.v !== 1) return "unknown record type";
  if (typeof b.clausesRoot !== "string" || !HEX64.test(b.clausesRoot)) return "invalid clause root";
  if (!Number.isInteger(b.clauseCount) || b.clauseCount < 1 || b.clauseCount > 10_000) return "invalid clause count";
  if (typeof b.charter !== "string" || b.charter.length > 64) return "invalid charter";
  if (typeof b.createdAt !== "string" || Number.isNaN(Date.parse(b.createdAt))) return "invalid creation date";
  if (typeof b.nonce !== "string" || b.nonce.length > 64) return "invalid nonce";
  if (!Array.isArray(b.parties)) return "invalid parties";
  if (b.type === "accord/agreement" && (b.parties.length < 2 || b.parties.length > 10)) return "an agreement needs 2 to 10 parties";
  if (b.type === "accord/action" && b.parties.length !== 1) return "an action has exactly one party";
  for (const p of b.parties) {
    if (!p || typeof p !== "object" || Object.keys(p).some((k) => k !== "agent" && k !== "mandate")) return "invalid party";
    if (typeof p.agent !== "string" || !KEY.test(p.agent) || typeof p.mandate !== "string" || !HEX64.test(p.mandate)) return "invalid party";
  }
  if (new Set(b.parties.map((p) => p.agent)).size !== b.parties.length) return "the same agent appears twice among the parties";
  for (const s of x.signatures) {
    if (!s || typeof s !== "object" || Object.keys(s).some((k) => k !== "agent" && k !== "signature")) return "invalid signature entry";
    if (typeof s.agent !== "string" || typeof s.signature !== "string") return "invalid signature entry";
  }
  if (new Set(x.signatures.map((s) => s.agent)).size !== x.signatures.length) return "two signature entries for the same agent";
  return null;
}

export function signRecord(rec: SignedRecord, agent: KeyPair): SignedRecord {
  if (!rec.body.parties.some((p) => p.agent === agent.publicKey)) throw new Error("signer is not a party");
  const others = rec.signatures.filter((s) => s.agent !== agent.publicKey);
  return { ...rec, signatures: [...others, { agent: agent.publicKey, signature: signValue(rec.body, agent) }] };
}

export function isFullySigned(rec: SignedRecord): boolean {
  return rec.body.parties.every((p) =>
    rec.signatures.some((s) => s.agent === p.agent && verifyValue(rec.body, s.signature, p.agent)),
  );
}

/**
 * The fingerprint sent to the register. Reveals nothing: the clause root is salted.
 * Computed over the body and the parties' signatures in party order, and nothing else, so the same
 * agreement always has the same fingerprint (extra fields or reordered signatures cannot make a second one).
 */
export function entryHash(rec: SignedRecord): string {
  const signatures = rec.body.parties.flatMap((p) => {
    const s = rec.signatures.find((x) => x.agent === p.agent);
    return s ? [{ agent: s.agent, signature: s.signature }] : [];
  });
  return digest({ body: rec.body, signatures });
}
