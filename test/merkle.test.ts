import { test } from "node:test";
import assert from "node:assert/strict";
import { utf8 } from "../src/bytes.js";
import { leafHash } from "../src/hash.js";
import { consistencyProof, inclusionProof, treeRoot, verifyConsistency, verifyInclusion } from "../src/merkle.js";

const leaves = (n: number) => Array.from({ length: n }, (_, i) => leafHash(utf8(`entry ${i}`)));

test("inclusion proofs verify for every leaf of trees of size 1..40", () => {
  for (let n = 1; n <= 40; n++) {
    const ls = leaves(n);
    const root = treeRoot(ls);
    for (let i = 0; i < n; i++) {
      assert.ok(verifyInclusion(ls[i], i, n, inclusionProof(ls, i), root), `n=${n} i=${i}`);
    }
  }
});

test("inclusion proof fails for wrong leaf, index or root", () => {
  const ls = leaves(13);
  const root = treeRoot(ls);
  const p = inclusionProof(ls, 5);
  assert.equal(verifyInclusion(ls[6], 5, 13, p, root), false);
  assert.equal(verifyInclusion(ls[5], 4, 13, p, root), false);
  assert.equal(verifyInclusion(ls[5], 5, 13, p, treeRoot(leaves(12))), false);
});

test("consistency proofs verify for all size pairs up to 33", () => {
  for (let n = 1; n <= 33; n++) {
    const ls = leaves(n);
    for (let m = 1; m <= n; m++) {
      const ok = verifyConsistency(m, n, treeRoot(ls.slice(0, m)), treeRoot(ls), consistencyProof(ls, m));
      assert.ok(ok, `m=${m} n=${n}`);
    }
  }
});

test("consistency proof fails if an old entry was rewritten", () => {
  const ls = leaves(20);
  const oldRoot = treeRoot(ls.slice(0, 11));
  const forged = [...ls];
  forged[3] = leafHash(utf8("forged"));
  assert.equal(verifyConsistency(11, 20, oldRoot, treeRoot(forged), consistencyProof(forged, 11)), false);
});
