// Anti-spam gate of the register's writes. Refused or invalid requests never count towards any limit.
//
// Plain entries and cosignatures:
// - a per-minute rate limit per client (Cloudflare binding), a client being an IPv4 address or an IPv6 /64
//   (src/client-key.ts), since one person easily holds a whole /64;
// - a daily share per client: no client can take more than a small part of the day's writes;
// - a daily cap for everyone, minus a reserve that only the city's own services can use (the "internal lane":
//   the piazza sends INTERNAL_WRITE_SECRET in the x-symbolon-internal header), so a flood from outside cannot
//   stop the piazza from sealing.
//
// Revocations have their own counters, so that filling the register with fingerprints never stops an owner
// from revoking, and junk revocations (anyone can sign one with a throwaway key: the register cannot tell who
// may revoke what, it only sees fingerprints) cannot either:
// - a daily limit per signing key and a daily share per client;
// - the global daily cap never refuses the first revocation of the day of a signing key, for the first few
//   new signing keys of each client: a real owner, revoking from its own network, always gets through, even
//   when someone has filled the cap with junk; the junk itself is bounded per client.

import type { WriteKind } from "./app.js";
import { clientKeyOfRequest } from "../client-key.js";
import { OWNER_KEY } from "../keys.js";
import { countDailyKeys, dailyCount, dailyKey, type CapBucket, type D1Like } from "./stores.js";

type RateLimiter = { limit(o: { key: string }): Promise<{ success: boolean }> };

export interface GateEnv {
  DB: D1Like;
  /** Per-minute limit per public client (key: clientKeyOfRequest). */
  WRITE_LIMIT?: RateLimiter;
  /** Per-minute limit of the internal lane (key "internal"); absent = only the daily caps apply. */
  INTERNAL_WRITE_LIMIT?: RateLimiter;
  /** Secret shared with the city's own services (piazza); the x-symbolon-internal header must equal it. */
  INTERNAL_WRITE_SECRET?: string;
  /** Default 5000: plain entries and cosignatures, everyone together. */
  DAILY_WRITE_CAP?: string;
  /** Default DAILY_WRITE_CAP / 5: the part of the daily cap only the internal lane can use. */
  DAILY_INTERNAL_RESERVE?: string;
  /** Default max(100, DAILY_WRITE_CAP / 50): entries and cosignatures per public client per day. */
  DAILY_CLIENT_WRITE_CAP?: string;
  /** Default 20000: revocations, everyone together (never refuses a signer's first revocation of the day). */
  DAILY_REVOCATION_CAP?: string;
  /** Default max(200, DAILY_REVOCATION_CAP / 100): revocations per public client per day. */
  DAILY_CLIENT_REVOCATION_CAP?: string;
  /** Default 20: revocations signed by one key per day. */
  DAILY_SIGNER_REVOCATION_CAP?: string;
  /** Default 5: new signing keys per client per day whose first revocation passes even a full global cap. */
  DAILY_CLIENT_NEW_SIGNERS?: string;
}

export const bucketOf = (kind: WriteKind): CapBucket => (kind === "revocation" ? "revocations" : "entries");

/** The header the city's own services send with INTERNAL_WRITE_SECRET. */
export const INTERNAL_HEADER = "x-symbolon-internal";
/** The client key of the internal lane. */
export const INTERNAL_CLIENT = "internal";

const num = (v: string | undefined, fallback: number) => {
  const n = Number(v);
  return v !== undefined && v !== "" && Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
};

/** Constant-time comparison of two secrets (their SHA-256, so lengths do not show either). */
async function sameSecret(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const u = new Uint8Array(x);
  const v = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < u.length; i++) diff |= u[i] ^ v[i];
  return diff === 0;
}

/** What allowWrite learned about a request, for countWrite once it succeeded. */
interface Seen {
  client: string;
  internal: boolean;
  signer?: string;
  /** First revocation of the day by this signer, within the client's quota of new signers. */
  newSigner?: boolean;
}

/** The signing key of a revocation in a request body, read from a copy (the app reads the original). */
async function signerOf(req: Request): Promise<string | undefined> {
  try {
    const text = await req.clone().text();
    if (text.length > 8192) return undefined;
    const by = (JSON.parse(text) as { body?: { by?: unknown } })?.body?.by;
    return typeof by === "string" && OWNER_KEY.test(by) ? by : undefined;
  } catch {
    return undefined;
  }
}

export function writeGate(env: GateEnv, now: () => Date = () => new Date()) {
  const cap = num(env.DAILY_WRITE_CAP, 5000);
  const reserve = Math.min(cap, num(env.DAILY_INTERNAL_RESERVE, Math.floor(cap / 5)));
  const clientCap = num(env.DAILY_CLIENT_WRITE_CAP, Math.max(100, Math.floor(cap / 50)));
  const revCap = num(env.DAILY_REVOCATION_CAP, 20000);
  const clientRevCap = num(env.DAILY_CLIENT_REVOCATION_CAP, Math.max(200, Math.floor(revCap / 100)));
  const signerCap = num(env.DAILY_SIGNER_REVOCATION_CAP, 20);
  const newSigners = num(env.DAILY_CLIENT_NEW_SIGNERS, 5);
  const seen = new WeakMap<Request, Seen>();

  const isInternal = async (req: Request) => {
    const given = req.headers.get(INTERNAL_HEADER);
    return !!env.INTERNAL_WRITE_SECRET && given !== null && (await sameSecret(given, env.INTERNAL_WRITE_SECRET));
  };

  return {
    allowWrite: async (req: Request, kind: WriteKind): Promise<string | null> => {
      const internal = await isInternal(req);
      const client = internal ? INTERNAL_CLIENT : clientKeyOfRequest(req);
      const limiter = internal ? env.INTERNAL_WRITE_LIMIT : env.WRITE_LIMIT;
      if (limiter && !(await limiter.limit({ key: client })).success) return "too many writes from this client, retry in a minute";
      const day = now();
      const s: Seen = { client, internal };

      if (kind !== "revocation") {
        const total = await dailyCount(env.DB, dailyKey(day, "entries"));
        if (total >= (internal ? cap : cap - reserve)) return "daily write cap reached, retry tomorrow (UTC)";
        if (!internal && (await dailyCount(env.DB, dailyKey(day, "entries", "client", client))) >= clientCap)
          return "this client's daily share of writes is used up, retry tomorrow (UTC)";
        seen.set(req, s);
        return null;
      }

      if (!internal && (await dailyCount(env.DB, dailyKey(day, "revocations", "client", client))) >= clientRevCap)
        return "this client's daily share of revocations is used up, retry tomorrow (UTC)";
      const signer = await signerOf(req);
      // A body without a readable signer is refused by the app (400) and never counted.
      if (signer) {
        s.signer = signer;
        const bySigner = await dailyCount(env.DB, dailyKey(day, "revocations", "signer", signer));
        if (bySigner >= signerCap) return `this key has signed ${signerCap} revocations today, retry tomorrow (UTC)`;
        s.newSigner =
          bySigner === 0 && (internal || (await dailyCount(env.DB, dailyKey(day, "revocations", "newsigners", client))) < newSigners);
      }
      // The global cap never refuses a key's first revocation of the day (within its client's quota of new keys).
      if (!s.newSigner && (await dailyCount(env.DB, dailyKey(day, "revocations"))) >= revCap) return "daily revocation cap reached, retry tomorrow (UTC)";
      seen.set(req, s);
      return null;
    },

    /** Counts a write that succeeded: in the day's total and in the counters of its client (and signer). */
    countWrite: async (kind: WriteKind, req?: Request) => {
      const day = now();
      const bucket = bucketOf(kind);
      const s = req ? seen.get(req) : undefined;
      const keys = [dailyKey(day, bucket)];
      if (s && !s.internal) keys.push(dailyKey(day, bucket, "client", s.client));
      if (s?.signer) keys.push(dailyKey(day, bucket, "signer", s.signer));
      if (s?.newSigner && !s.internal) keys.push(dailyKey(day, bucket, "newsigners", s.client));
      await countDailyKeys(env.DB, keys);
    },
  };
}
