// Identity level 1 ("domain"): the owner publishes its public keys at
// https://<domain>/.well-known/symbolon.json
// The earlier name of the file (/.well-known/accord.json, field "accord": 1) is still read,
// so owners who published it before the rename keep working.

import type { PublicKey } from "./keys.js";
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

export function httpOwnerResolver(fetchImpl: typeof fetch = fetch): OwnerResolver {
  const read = async (domain: string, path: string): Promise<PublicKey[] | null> => {
    try {
      // Redirects are not followed (the file must be served by the domain itself). "manual", not "error":
      // Cloudflare Workers reject redirect "error", which made every lookup fail there.
      const res = await fetchImpl(`https://${domain}${path}`, { redirect: "manual" });
      if (res.status !== 200) return null;
      const file = (await res.json()) as { symbolon?: unknown; accord?: unknown; domain?: unknown; keys?: unknown };
      if ((file.symbolon !== 1 && file.accord !== 1) || file.domain !== domain || !Array.isArray(file.keys)) return null;
      return file.keys as PublicKey[];
    } catch {
      return null;
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
