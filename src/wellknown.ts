// Identity level 1 ("domain"): the owner publishes its public keys at
// https://<domain>/.well-known/accord.json

import type { PublicKey } from "./keys.js";

export const WELL_KNOWN_PATH = "/.well-known/accord.json";

export interface OwnerFile {
  accord: 1;
  domain: string;
  keys: PublicKey[];
}

/** Returns the keys an owner domain publishes, or null if none. */
export type OwnerResolver = (domain: string) => Promise<PublicKey[] | null>;

export function httpOwnerResolver(fetchImpl: typeof fetch = fetch): OwnerResolver {
  return async (domain) => {
    if (!/^[a-z0-9.-]+$/i.test(domain)) return null;
    try {
      const res = await fetchImpl(`https://${domain}${WELL_KNOWN_PATH}`, { redirect: "error" });
      if (!res.ok) return null;
      const file = (await res.json()) as OwnerFile;
      if (file.accord !== 1 || file.domain !== domain || !Array.isArray(file.keys)) return null;
      return file.keys;
    } catch {
      return null;
    }
  };
}

export function staticOwnerResolver(table: Record<string, PublicKey[]>): OwnerResolver {
  return async (domain) => table[domain] ?? null;
}
