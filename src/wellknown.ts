// Identity level 1 ("domain"): the owner publishes its public keys at
// https://<domain>/.well-known/symbolon.json
// The earlier name of the file (/.well-known/accord.json, field "accord": 1) is still read,
// so owners who published it before the rename keep working.

import { OWNER_KEY, type PublicKey } from "./keys.js";
import { ownerDomainProblem } from "./mandate.js";

export const WELL_KNOWN_PATH = "/.well-known/symbolon.json";
export const LEGACY_WELL_KNOWN_PATH = "/.well-known/accord.json";

export interface OwnerFile {
  symbolon: 1;
  domain: string;
  keys: PublicKey[];
}

/** The file an owner publishes at WELL_KNOWN_PATH. */
export function ownerFile(domain: string, keys: PublicKey[]): OwnerFile {
  return { symbolon: 1, domain, keys };
}

/** Returns the keys an owner domain publishes, or null if none. */
export type OwnerResolver = (domain: string) => Promise<PublicKey[] | null>;

/** Limits of an owner file: anything bigger, slower or with more keys is refused (a hostile site must not stall the city). */
export const OWNER_FILE_LIMITS: { maxBytes: number; timeoutMs: number; maxKeys: number } = { maxBytes: 16 * 1024, timeoutMs: 5_000, maxKeys: 10 };

/** Reads at most maxBytes of a response body; null if it is longer. */
async function readCapped(res: Response, maxBytes: number): Promise<string | null> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

export function httpOwnerResolver(fetchImpl: typeof fetch = fetch, limits: Partial<typeof OWNER_FILE_LIMITS> = {}): OwnerResolver {
  const lim = { ...OWNER_FILE_LIMITS, ...limits };
  const read = async (domain: string, path: string): Promise<PublicKey[] | null> => {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), lim.timeoutMs);
    try {
      // Redirects are not followed (the file must be served by the domain itself). "manual", not "error":
      // Cloudflare Workers reject redirect "error", which made every lookup fail there.
      const res = await fetchImpl(`https://${domain}${path}`, { redirect: "manual", signal: abort.signal });
      if (res.status !== 200) return null;
      const text = await readCapped(res, lim.maxBytes);
      if (text === null) return null;
      const file = JSON.parse(text) as { symbolon?: unknown; accord?: unknown; domain?: unknown; keys?: unknown };
      if (!file || typeof file !== "object") return null;
      if ((file.symbolon !== 1 && file.accord !== 1) || file.domain !== domain || !Array.isArray(file.keys)) return null;
      // A handful of keys in the one accepted format, nothing else.
      if (file.keys.length === 0 || file.keys.length > lim.maxKeys || file.keys.some((k) => typeof k !== "string" || !OWNER_KEY.test(k))) return null;
      return [...new Set(file.keys as PublicKey[])];
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };
  return async (domain) => {
    if (ownerDomainProblem(domain)) return null; // one lowercase spelling, no IP addresses, no "localhost"
    return (await read(domain, WELL_KNOWN_PATH)) ?? (await read(domain, LEGACY_WELL_KNOWN_PATH));
  };
}

export function staticOwnerResolver(table: Record<string, PublicKey[]>): OwnerResolver {
  return async (domain) => table[domain] ?? null;
}
