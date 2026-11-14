// A witness is an independent party that countersigns tree heads, but only
// after checking that each new head extends the last one it saw. If the
// operator ever rewrites history, the witness refuses and the fork is exposed.

import { fromHex } from "./bytes.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { verifyConsistency } from "./merkle.js";
import { verifyHeadSignature, type SignedTreeHead } from "./register.js";

export interface Cosignature {
  witness: PublicKey;
  log: PublicKey;
  size: number;
  root: string;
  time: string;
  signature: string;
}

function cosignBody(h: { log: string; size: number; root: string; time: string }) {
  return { type: "accord/cosign", log: h.log, size: h.size, root: h.root, time: h.time };
}

export class ForkDetected extends Error {}

export class Witness {
  private seen = new Map<PublicKey, { size: number; root: string }>();

  constructor(private readonly key: KeyPair) {}

  get publicKey(): PublicKey {
    return this.key.publicKey;
  }

  /** Last head this witness accepted for a log, if any. */
  lastSeen(log: PublicKey) {
    return this.seen.get(log);
  }

  observe(head: SignedTreeHead, proofFromLastSeen: string[]): Cosignature {
    if (!verifyHeadSignature(head)) throw new Error("invalid tree head signature");
    const prev = this.seen.get(head.log);
    if (prev) {
      const ok = verifyConsistency(
        prev.size,
        head.size,
        fromHex(prev.root),
        fromHex(head.root),
        proofFromLastSeen.map(fromHex),
      );
      if (!ok) throw new ForkDetected(`log ${head.log} is not consistent with size ${prev.size}`);
    }
    this.seen.set(head.log, { size: head.size, root: head.root });
    return { witness: this.key.publicKey, ...cosignBody(head), signature: signValue(cosignBody(head), this.key) } as Cosignature;
  }
}

export function verifyCosignature(c: Cosignature, head: SignedTreeHead): boolean {
  if (c.log !== head.log || c.size !== head.size || c.root !== head.root || c.time !== head.time) return false;
  return verifyValue(cosignBody(c), c.signature, c.witness);
}
