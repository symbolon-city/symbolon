// A witness is an independent party that countersigns tree heads, but only
// after checking that each new head extends the last one it saw. If the
// operator ever rewrites history, the witness refuses and the fork is exposed.
// It also checks the head's time: never before the last head it saw, and close to its own clock, so a
// register cannot get a countersigned head that backdates (or postdates) what it sealed.

import { fromHex } from "./bytes.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { verifyConsistency } from "./merkle.js";
import { verifyHeadSignature, type SignedTreeHead } from "./register.js";
import { parseTime } from "./mandate.js";

/** How far a head's time may be from the witness's own clock (default 5 minutes). */
export const WITNESS_MAX_SKEW_MS = 5 * 60_000;

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
  private seen = new Map<PublicKey, { size: number; root: string; time?: string }>();
  private readonly now: () => Date;
  private readonly maxSkewMs: number;

  constructor(
    private readonly key: KeyPair,
    opts: { now?: () => Date; maxSkewMs?: number } = {},
  ) {
    this.now = opts.now ?? (() => new Date());
    this.maxSkewMs = opts.maxSkewMs ?? WITNESS_MAX_SKEW_MS;
  }

  get publicKey(): PublicKey {
    return this.key.publicKey;
  }

  /** Last head this witness accepted for a log, if any. */
  lastSeen(log: PublicKey) {
    return this.seen.get(log);
  }

  observe(head: SignedTreeHead, proofFromLastSeen: string[]): Cosignature {
    if (!verifyHeadSignature(head)) throw new Error("invalid tree head signature");
    const t = parseTime(head.time);
    if (Number.isNaN(t)) throw new Error("the head's time is not a UTC time YYYY-MM-DDTHH:MM:SS(.sss)Z");
    const now = this.now().getTime();
    if (Math.abs(t - now) > this.maxSkewMs)
      throw new Error(`the head is dated ${head.time}, more than ${Math.round(this.maxSkewMs / 60_000)} minutes from this witness's clock (${new Date(now).toISOString()})`);
    const prev = this.seen.get(head.log);
    if (prev?.time !== undefined && t < parseTime(prev.time))
      throw new Error(`the head is dated ${head.time}, before the last head seen (${prev.time}): a register's time never goes back`);
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
    this.seen.set(head.log, { size: head.size, root: head.root, time: head.time });
    return { witness: this.key.publicKey, ...cosignBody(head), signature: signValue(cosignBody(head), this.key) } as Cosignature;
  }
}

export function verifyCosignature(c: Cosignature, head: SignedTreeHead): boolean {
  if (c.log !== head.log || c.size !== head.size || c.root !== head.root || c.time !== head.time) return false;
  return verifyValue(cosignBody(c), c.signature, c.witness);
}
