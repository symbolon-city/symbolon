// Owner keys fetched from owners' websites, kept a few minutes by the workers (door, piazza). The cache has a
// fixed size (least recently used entries go first), so made-up domains cannot make it grow without end, and
// each request may cause only a few new lookups, so one request cannot become many outbound fetches.

import type { OwnerResolver } from "../wellknown.js";

export const OWNER_CACHE = { ttlMs: 5 * 60_000, maxEntries: 1_000, lookupsPerRequest: 4 };

export class OwnerKeyCache {
  private entries = new Map<string, { keys: string[] | null; at: number }>();
  constructor(
    readonly maxEntries = OWNER_CACHE.maxEntries,
    readonly ttlMs = OWNER_CACHE.ttlMs,
  ) {}
  get size() {
    return this.entries.size;
  }
  /** The keys kept for this domain, if still fresh (undefined: not kept). */
  get(domain: string, now = Date.now()): string[] | null | undefined {
    const hit = this.entries.get(domain);
    if (!hit) return undefined;
    this.entries.delete(domain);
    if (now - hit.at >= this.ttlMs) return undefined;
    this.entries.set(domain, hit); // most recently used last
    return hit.keys;
  }
  set(domain: string, keys: string[] | null, now = Date.now()) {
    this.entries.delete(domain);
    this.entries.set(domain, { keys, at: now });
    while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value!);
  }
}

/**
 * A resolver for one request: answers from the cache, and makes at most `lookupsPerRequest` new lookups
 * (after that it answers null, "not checked"). Create one per request around a cache shared by all requests.
 */
export function cachedOwnerResolver(cache: OwnerKeyCache, resolve: OwnerResolver, lookupsPerRequest = OWNER_CACHE.lookupsPerRequest): OwnerResolver {
  let lookups = 0;
  return async (domain) => {
    const hit = cache.get(domain);
    if (hit !== undefined) return hit;
    if (lookups >= lookupsPerRequest) return null;
    lookups++;
    const keys = await resolve(domain);
    cache.set(domain, keys);
    return keys;
  };
}
