// Anti-spam gate of the register's writes: a per-client rate limit (Cloudflare binding) and caps per
// UTC day on successful writes, one for plain entries and cosignatures and a separate one for
// revocations, so that filling the register with fingerprints can never stop an owner from revoking.
// Refused or invalid requests never count towards the caps.

import type { WriteKind } from "./app.js";
import { countDailyWrite, dailyWrites, type CapBucket, type D1Like } from "./stores.js";

export interface GateEnv {
  DB: D1Like;
  WRITE_LIMIT?: { limit(o: { key: string }): Promise<{ success: boolean }> };
  /** Default 5000: plain entries and cosignatures. */
  DAILY_WRITE_CAP?: string;
  /** Default 20000: revocations. */
  DAILY_REVOCATION_CAP?: string;
}

export const bucketOf = (kind: WriteKind): CapBucket => (kind === "revocation" ? "revocations" : "entries");

export function writeGate(env: GateEnv, now: () => Date = () => new Date()) {
  const caps: Record<CapBucket, number> = { entries: Number(env.DAILY_WRITE_CAP ?? 5000), revocations: Number(env.DAILY_REVOCATION_CAP ?? 20000) };
  return {
    allowWrite: async (req: Request, kind: WriteKind): Promise<string | null> => {
      const client = req.headers.get("cf-connecting-ip") ?? "unknown";
      if (env.WRITE_LIMIT && !(await env.WRITE_LIMIT.limit({ key: client })).success) return "too many writes from this client, retry in a minute";
      const bucket = bucketOf(kind);
      if ((await dailyWrites(env.DB, bucket, now())) >= caps[bucket]) return `daily ${bucket === "revocations" ? "revocation" : "write"} cap reached, retry tomorrow (UTC)`;
      return null;
    },
    countWrite: (kind: WriteKind) => countDailyWrite(env.DB, bucketOf(kind), now()),
  };
}
