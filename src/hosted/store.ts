// Storage of the hosted wallet: a small key-value interface (a Durable Object's storage on Cloudflare, a Map in
// tests), and the wallets of the owners kept in it encrypted with a key of the operator.
//
// Honest limit: the operator of a hosted wallet holds the agents' keys (it must, to sign while the owner is
// away). Encryption protects a copy of the storage (backup, leak), not against the operator itself. What limits
// the damage is the mandate: the agent can never do more than its owner signed, and "Block everything" (a
// revocation signed by the owner's passkey, sealed in the register) stops it everywhere.

import type { WalletState, WalletStorage } from "../agent/wallet.js";
import { fromBase64url, toBase64url, utf8 } from "../bytes.js";

export interface KeyValue {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  /** Keys with this prefix in key order, after `startAfter`, at most `limit` (for collecting expired records). */
  list?(o: { prefix: string; limit: number; startAfter?: string }): Promise<Map<string, unknown>>;
}

export class MemoryKeyValue implements KeyValue {
  readonly map = new Map<string, unknown>();
  async get<T>(key: string) {
    const v = this.map.get(key);
    return v === undefined ? undefined : (structuredClone(v) as T);
  }
  async put(key: string, value: unknown) {
    this.map.set(key, structuredClone(value));
  }
  async delete(key: string) {
    this.map.delete(key);
  }
  async list(o: { prefix: string; limit: number; startAfter?: string }) {
    const keys = [...this.map.keys()].filter((k) => k.startsWith(o.prefix) && (o.startAfter === undefined || k > o.startAfter)).sort().slice(0, o.limit);
    return new Map(keys.map((k) => [k, structuredClone(this.map.get(k))]));
  }
}

interface Expiring<T> {
  v: T;
  exp: number;
}

/** Values with an end: read back only before it (and deleted when found expired). */
export async function putExpiring(kv: KeyValue, key: string, value: unknown, expiresAt: number) {
  await kv.put(key, { v: value, exp: expiresAt } satisfies Expiring<unknown>);
}

export async function getExpiring<T>(kv: KeyValue, key: string, now: number): Promise<T | undefined> {
  const e = await kv.get<Expiring<T>>(key);
  if (!e) return undefined;
  if (!(e.exp > now)) {
    await kv.delete(key);
    return undefined;
  }
  return e.v;
}

/** Reads and deletes in one step: for things usable once (authorization codes, challenges). */
export async function takeExpiring<T>(kv: KeyValue, key: string, now: number): Promise<T | undefined> {
  const v = await getExpiring<T>(kv, key, now);
  if (v !== undefined) await kv.delete(key);
  return v;
}

/**
 * Deletes the expiring records (putExpiring) of these prefixes whose end has passed: run regularly (a Durable
 * Object alarm), so that records nobody reads again do not stay forever. Looks at most `budget` keys per call
 * and says where to continue. Without kv.list it does nothing.
 */
export async function sweepExpired(
  kv: KeyValue,
  now: number,
  prefixes: readonly string[],
  o: { budget?: number; from?: { prefix: string; after?: string } } = {},
): Promise<{ deleted: number; next?: { prefix: string; after?: string } }> {
  if (!kv.list) return { deleted: 0 };
  let budget = o.budget ?? 2000;
  let deleted = 0;
  const start = o.from ? Math.max(0, prefixes.indexOf(o.from.prefix)) : 0;
  let after = o.from?.after;
  for (let i = start; i < prefixes.length; i++, after = undefined) {
    const prefix = prefixes[i]!;
    for (;;) {
      if (budget <= 0) return { deleted, next: { prefix, ...(after !== undefined ? { after } : {}) } };
      const page = await kv.list({ prefix, limit: Math.min(budget, 200), ...(after !== undefined ? { startAfter: after } : {}) });
      if (!page.size) break;
      for (const [k, v] of page) {
        budget--;
        after = k;
        const exp = (v as Partial<Expiring<unknown>> | null)?.exp;
        if (typeof exp === "number" && !(exp > now)) {
          await kv.delete(k);
          deleted++;
        }
      }
    }
  }
  return { deleted };
}

/** AES-GCM key for one owner's wallet, derived from the operator's secret (HKDF-SHA256, the owner id as info). */
async function walletKey(secret: Uint8Array, ownerId: string, salt = "symbolon-hosted-wallet/1"): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", secret as BufferSource, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8(salt) as BufferSource, info: utf8(ownerId) as BufferSource },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** One owner's wallet in the key-value storage, encrypted (the owner id is bound to the ciphertext). */
export class HostedWalletStorage implements WalletStorage {
  constructor(
    private readonly kv: KeyValue,
    private readonly secret: Uint8Array,
    private readonly ownerId: string,
  ) {
    if (secret.length < 32) throw new Error("the wallet secret must be at least 32 bytes");
  }
  private get key() {
    return `wallet:${this.ownerId}`;
  }
  async load(): Promise<WalletState | null> {
    const box = await this.kv.get<{ iv: string; ct: string }>(this.key);
    if (!box) return null;
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64url(box.iv) as BufferSource, additionalData: utf8(this.key) as BufferSource },
      await walletKey(this.secret, this.ownerId),
      fromBase64url(box.ct) as BufferSource,
    );
    return JSON.parse(new TextDecoder().decode(plain)) as WalletState;
  }
  async save(state: WalletState): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: utf8(this.key) as BufferSource },
      await walletKey(this.secret, this.ownerId),
      utf8(JSON.stringify(state)) as BufferSource,
    );
    await this.kv.put(this.key, { iv: toBase64url(iv), ct: toBase64url(new Uint8Array(ct)) });
  }
}

/** A small record kept encrypted under the operator's secret, bound to its storage key (like the wallets). */
export async function getSealed<T>(kv: KeyValue, secret: Uint8Array, key: string): Promise<T | undefined> {
  const box = await kv.get<{ iv: string; ct: string }>(key);
  if (!box) return undefined;
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64url(box.iv) as BufferSource, additionalData: utf8(key) as BufferSource },
    await walletKey(secret, key, "symbolon-hosted-record/1"),
    fromBase64url(box.ct) as BufferSource,
  );
  return JSON.parse(new TextDecoder().decode(plain)) as T;
}

export async function putSealed(kv: KeyValue, secret: Uint8Array, key: string, value: unknown): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource, additionalData: utf8(key) as BufferSource },
    await walletKey(secret, key, "symbolon-hosted-record/1"),
    utf8(JSON.stringify(value)) as BufferSource,
  );
  await kv.put(key, { iv: toBase64url(iv), ct: toBase64url(new Uint8Array(ct)) });
}

/** Runs one task at a time per key (one owner's wallet), within this process or Durable Object. */
export class KeyedLock {
  private tails = new Map<string, Promise<unknown>>();
  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    const next = prev.catch(() => undefined).then(fn);
    this.tails.set(key, next);
    try {
      return await next;
    } finally {
      if (this.tails.get(key) === next) this.tails.delete(key);
    }
  }
}
