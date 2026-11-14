// Agreements are split into clauses. Each clause is salted and hashed;
// the clause hashes form a Merkle tree whose root is the only thing that
// leaves the parties. Later, any single clause can be revealed and proven
// to belong to the agreement without revealing the others.

import { fromHex, randomBytes, toHex, utf8 } from "./bytes.js";
import { canonical, type Json } from "./canonical.js";
import { leafHash } from "./hash.js";
import { inclusionProof, treeRoot, verifyInclusion } from "./merkle.js";

export interface Clause {
  name: string;
  value: Json;
}

/** The private, full agreement kept by the parties. Never sent to the register. */
export interface OpenedClauses {
  root: string;
  count: number;
  clauses: Array<Clause & { salt: string }>;
}

/** One clause revealed to a third party, with the path to the agreement root. */
export interface Disclosure {
  index: number;
  name: string;
  value: Json;
  salt: string;
  path: string[];
}

function clauseLeaf(c: Clause & { salt: string }): Uint8Array {
  return leafHash(utf8(canonical({ n: c.name, s: c.salt, v: c.value })));
}

export function commitClauses(clauses: Clause[]): OpenedClauses {
  if (clauses.length === 0) throw new Error("an agreement needs at least one clause");
  const names = new Set(clauses.map((c) => c.name));
  if (names.size !== clauses.length) throw new Error("clause names must be unique");
  const salted = clauses.map((c) => ({ ...c, salt: toHex(randomBytes(32)) }));
  return { root: toHex(treeRoot(salted.map(clauseLeaf))), count: salted.length, clauses: salted };
}

export function disclose(opened: OpenedClauses, name: string): Disclosure {
  const index = opened.clauses.findIndex((c) => c.name === name);
  if (index < 0) throw new Error(`no clause named ${name}`);
  const c = opened.clauses[index];
  const path = inclusionProof(opened.clauses.map(clauseLeaf), index).map(toHex);
  return { index, name: c.name, value: c.value, salt: c.salt, path };
}

export function verifyDisclosure(d: Disclosure, root: string, count: number): boolean {
  try {
    return verifyInclusion(clauseLeaf(d), d.index, count, d.path.map(fromHex), fromHex(root));
  } catch {
    return false;
  }
}

/** Checks that a full set of opened clauses really produces the stated root. */
export function verifyOpened(opened: OpenedClauses): boolean {
  try {
    return opened.clauses.length === opened.count && toHex(treeRoot(opened.clauses.map(clauseLeaf))) === opened.root;
  } catch {
    return false;
  }
}
