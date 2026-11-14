// Merkle tree over leaf hashes, following RFC 9162 (Certificate Transparency v2):
// tree root, inclusion proofs ("this entry is in the tree") and consistency
// proofs ("the new tree contains the old one unchanged").

import { equalBytes } from "./bytes.js";
import { emptyRoot, nodeHash } from "./hash.js";

/** Largest power of two strictly smaller than n (n >= 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function treeRoot(leaves: Uint8Array[]): Uint8Array {
  const n = leaves.length;
  if (n === 0) return emptyRoot();
  if (n === 1) return leaves[0];
  const k = split(n);
  return nodeHash(treeRoot(leaves.slice(0, k)), treeRoot(leaves.slice(k)));
}

export function inclusionProof(leaves: Uint8Array[], index: number): Uint8Array[] {
  const n = leaves.length;
  if (index < 0 || index >= n) throw new Error("index out of range");
  if (n === 1) return [];
  const k = split(n);
  return index < k
    ? [...inclusionProof(leaves.slice(0, k), index), treeRoot(leaves.slice(k))]
    : [...inclusionProof(leaves.slice(k), index - k), treeRoot(leaves.slice(0, k))];
}

function subproof(m: number, leaves: Uint8Array[], complete: boolean): Uint8Array[] {
  const n = leaves.length;
  if (m === n) return complete ? [] : [treeRoot(leaves)];
  const k = split(n);
  return m <= k
    ? [...subproof(m, leaves.slice(0, k), complete), treeRoot(leaves.slice(k))]
    : [...subproof(m - k, leaves.slice(k), false), treeRoot(leaves.slice(0, k))];
}

/** Proof that the tree of the first `m` leaves is a prefix of the tree of all leaves. */
export function consistencyProof(leaves: Uint8Array[], m: number): Uint8Array[] {
  if (m < 1 || m > leaves.length) throw new Error("bad sizes");
  if (m === leaves.length) return [];
  return subproof(m, leaves, true);
}

const odd = (x: number) => x % 2 === 1;
const half = (x: number) => Math.floor(x / 2);

export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  size: number,
  path: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!odd(fn)) {
        while (!odd(fn) && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equalBytes(r, root);
}

export function verifyConsistency(
  size1: number,
  size2: number,
  root1: Uint8Array,
  root2: Uint8Array,
  proof: Uint8Array[],
): boolean {
  if (size1 < 1 || size1 > size2) return false;
  if (size1 === size2) return proof.length === 0 && equalBytes(root1, root2);
  if (proof.length === 0) return false;
  const path = (size1 & (size1 - 1)) === 0 ? [root1, ...proof] : [...proof];
  let fn = size1 - 1;
  let sn = size2 - 1;
  while (odd(fn)) {
    fn = half(fn);
    sn = half(sn);
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!odd(fn)) {
        while (!odd(fn) && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equalBytes(fr, root1) && equalBytes(sr, root2);
}
