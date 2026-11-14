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

/** The fingerprint sent to the register. Reveals nothing: the clause root is salted. */
export function entryHash(rec: SignedRecord): string {
  return digest(rec);
}
