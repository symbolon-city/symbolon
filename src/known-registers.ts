// Registers whose public key is fixed here, outside the register itself. A register that answers with a
// different key is refused: otherwise whoever controls the address (or the connection) could present a
// register of its own and every check would pass against its key. This list travels in the code and in
// the npm package (built by GitHub with provenance), an independent channel from the register's own answers.
//
// Cross-check of the key below (16/11/2026): the same key signs the current heads, the Bitcoin-anchored head
// of 16/11/2026 (size 70, confirmed) and the daily demonstration agreements.

import type { PublicKey } from "./keys.js";

export interface KnownRegister {
  url: string;
  key: PublicKey;
  name: string;
  since: string;
}

export const KNOWN_REGISTERS: readonly KnownRegister[] = [
  {
    url: "https://registro-prova.symbolon-city.workers.dev",
    key: "ed25519:0b26c53a5dbc29498b786b0d0f308717350d48cdb234d6381e7c9473a0e26f96",
    name: "Symbolon City test register (will be reset at launch)",
    since: "2026-11-14",
  },
];

function normalise(url: string): string {
  try {
    const u = new URL(url);
    return (u.protocol + "//" + u.host.toLowerCase() + u.pathname.replace(/\/+$/, "")).toLowerCase();
  } catch {
    return url.replace(/\/+$/, "").toLowerCase();
  }
}

/** The fixed key of a known register, or undefined for any other address. */
export function pinnedRegisterKey(url: string): PublicKey | undefined {
  const n = normalise(url);
  return KNOWN_REGISTERS.find((r) => normalise(r.url) === n)?.key;
}
