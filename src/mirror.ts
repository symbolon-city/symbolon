// A full copy of a register that anyone can keep and check, without trusting the operator:
// every entry in order (GET /v1/entries), checked against a head signed by the register's pinned key.
// Kept over time, copies also show whether the history was ever rewritten: an older copy must be the
// beginning of a newer one.

import { toHex } from "./bytes.js";
import type { PublicKey } from "./keys.js";
import { pinnedRegisterKey } from "./known-registers.js";
import { treeRoot } from "./merkle.js";
import { entryLeaf, verifyHeadSignature, type SignedTreeHead } from "./register.js";

export interface RegisterCopy {
  register: string;
  key: PublicKey;
  head: SignedTreeHead;
  entries: string[];
  copiedAt: string;
}

/** Problems of a copy (empty when sound): head signed by the key, entries giving exactly the head's root. */
export function copyProblems(c: RegisterCopy): string[] {
  const p: string[] = [];
  if (c.head.log !== c.key) p.push(`the head is signed by ${c.head.log}, not by the register's key ${c.key}`);
  else if (!verifyHeadSignature(c.head)) p.push("the head's signature is invalid");
  if (c.entries.length !== c.head.size) p.push(`the copy has ${c.entries.length} entries, the head says ${c.head.size}`);
  else {
    try {
      if (toHex(treeRoot(c.entries.map(entryLeaf))) !== c.head.root) p.push("the entries do not give the head's root: the list differs from what the register signed");
    } catch (e) {
      p.push(`invalid entry: ${(e as Error).message}`);
    }
  }
  return p;
}

/** Where an older copy and a newer one disagree: the older must be exactly the start of the newer. */
export function rewrittenSince(older: RegisterCopy, newer: RegisterCopy): string | null {
  if (older.key !== newer.key) return `the register's key changed (${older.key} → ${newer.key})`;
  if (newer.entries.length < older.entries.length) return `the register shrank from ${older.entries.length} to ${newer.entries.length} entries`;
  const i = older.entries.findIndex((e, k) => newer.entries[k] !== e);
  return i < 0 ? null : `entry ${i} was rewritten (${older.entries[i]} → ${newer.entries[i]})`;
}

/** Downloads every entry of a register and checks the copy against its signed head. */
export async function copyRegister(
  baseUrl: string,
  opts: { key?: PublicKey; fetchImpl?: typeof fetch; now?: Date } = {},
): Promise<{ copy: RegisterCopy; problems: string[] }> {
  const f = opts.fetchImpl ?? fetch;
  const base = baseUrl.replace(/\/+$/, "");
  const key = opts.key ?? pinnedRegisterKey(base);
  if (!key) throw new Error(`the key of ${base} is not known: give it (it must come from the operator, not from the register itself)`);
  const entries: string[] = [];
  let head: SignedTreeHead | null = null;
  let from = 0;
  for (;;) {
    const res = await f(`${base}/v1/entries?from=${from}`);
    if (!res.ok) throw new Error(`register: HTTP ${res.status} on /v1/entries`);
    const page = (await res.json()) as { entries: string[]; head: SignedTreeHead | null; next?: number };
    head ??= page.head; // the head of the first page: later entries beyond it are ignored
    if (!head) throw new Error("the register is empty");
    entries.push(...page.entries);
    if (page.next === undefined || entries.length >= head.size) break;
    if (page.next !== entries.length) throw new Error("the register's pages do not follow each other");
    from = page.next;
  }
  const copy: RegisterCopy = { register: base, key, head: head!, entries: entries.slice(0, head!.size), copiedAt: (opts.now ?? new Date()).toISOString() };
  return { copy, problems: copyProblems(copy) };
}
