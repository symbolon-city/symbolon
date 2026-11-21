// Test vectors for docs/FORMAT.md: fixed keys, salts and nonces, so that an implementation in any
// language can check it computes exactly the same bytes. `npm run format:vectors` rewrites
// docs/format-vectors.json; test/format.test.ts fails if the code and the file ever disagree.

import { writeFileSync } from "node:fs";
import { toHex, utf8 } from "../src/bytes.js";
import { canonical } from "../src/canonical.js";
import { leafHash, sha256Hex } from "../src/hash.js";
import { keyPairFromSecret, signValue } from "../src/keys.js";
import { createMandate, mandateId } from "../src/mandate.js";
import { treeRoot } from "../src/merkle.js";
import { entryHash, signRecord, type SignedRecord } from "../src/record.js";
import { entryLeaf } from "../src/register.js";
import { fingerprintJson, fingerprintText } from "../src/fingerprint.js";

const secret = (label: string) => sha256Hex(utf8("symbolon format vectors: " + label));

export function buildVectors() {
  const owner = keyPairFromSecret(secret("owner"));
  const agentA = keyPairFromSecret(secret("agent A"));
  const agentB = keyPairFromSecret(secret("agent B"));

  const text = "Boiler repair: tomorrow 8-10, call-out 60.00 EUR. Caffè incluso.\n";
  const json = { "é": { z: 0, y: -3 }, b: [1, "x", true, null], a: "12.50", "a b": "quote \" backslash \\ newline \n tab \t ctrl \u0001 euro €" };

  const clauses = [
    { name: "service", value: "boiler repair", salt: "11".repeat(32) },
    { name: "price", value: { value: "60.00", currency: "EUR" }, salt: "22".repeat(32) },
    { name: "window", value: "2026-11-17T08:00:00Z/2026-11-17T10:00:00Z", salt: "33".repeat(32) },
  ];
  const clauseLeaves = clauses.map((c) => leafHash(utf8(canonical({ n: c.name, s: c.salt, v: c.value }))));
  const clausesRoot = toHex(treeRoot(clauseLeaves));

  const mandateA = createMandate(owner, {
    ownerDomain: "owner.example", agent: agentA.publicKey, scope: "home repairs", maxAmount: { value: "150.00", currency: "EUR" },
    notBefore: "2026-11-16T00:00:00Z", notAfter: "2026-12-16T00:00:00Z", charter: "accord-charter/0.1",
  });
  const mandateB = createMandate(owner, {
    ownerDomain: "owner.example", agent: agentB.publicKey, scope: "plumbing services",
    notBefore: "2026-11-16T00:00:00Z", notAfter: "2026-12-16T00:00:00Z", charter: "accord-charter/0.1",
  });

  // An owner without a domain (identity level "key"): the owner object has the key only.
  const keyOwner = keyPairFromSecret(secret("owner without domain"));
  const mandateNoDomain = createMandate(keyOwner, {
    agent: agentA.publicKey, scope: "picture-frame restoration", maxAmount: { value: "2000.00", currency: "EUR" },
    notBefore: "2026-11-19T00:00:00Z", notAfter: "2027-02-19T00:00:00Z", charter: "accord-charter/0.1",
  });

  // The owner's approval of one agreement above agent A's limit: bound to the clauses root, to agent B and its
  // mandate, and to the nonce of the one record it allows.
  const approval = createMandate(owner, {
    ownerDomain: "owner.example", agent: agentA.publicKey, scope: "one agreement only, of 240.00 EUR, with the agent of owner.example",
    maxAmount: { value: "240.00", currency: "EUR" }, notBefore: "2026-11-19T10:00:00Z", notAfter: "2026-11-21T10:00:00Z", charter: "accord-charter/0.1",
    agreement: { clausesRoot, with: [agentB.publicKey], withMandates: [mandateId(mandateB)], nonce: "00112233445566778899aabbccddeeff", under: mandateId(mandateA) },
  });

  let record: SignedRecord = {
    body: {
      type: "accord/agreement", v: 1, clausesRoot, clauseCount: clauses.length,
      parties: [{ agent: agentA.publicKey, mandate: mandateId(mandateA) }, { agent: agentB.publicKey, mandate: mandateId(mandateB) }],
      charter: "accord-charter/0.1", createdAt: "2026-11-16T18:00:00.000Z", nonce: "00112233445566778899aabbccddeeff",
    },
    signatures: [],
  };
  record = signRecord(signRecord(record, agentB), agentA);
  const entry = entryHash(record);

  const entries = [entry, sha256Hex(utf8("second entry")), sha256Hex(utf8("third entry"))];
  const leaves = entries.map(entryLeaf);

  return {
    spec: "docs/FORMAT.md",
    version: 1,
    note: "All hex is lowercase. Secret keys are given only so that signatures can be reproduced; never reuse them.",
    text_fingerprint: { text, utf8_hex: toHex(utf8(text)), ...fingerprintText(text) },
    json_fingerprint: { json, ...fingerprintJson(json) },
    signature: {
      secret_key: secret("agent A"),
      public_key: agentA.publicKey,
      value: { hello: "world", n: 42 },
      canonical: canonical({ hello: "world", n: 42 }),
      signature: signValue({ hello: "world", n: 42 }, agentA),
    },
    clauses: {
      clauses,
      leaf_preimages: clauses.map((c) => canonical({ n: c.name, s: c.salt, v: c.value })),
      leaves: clauseLeaves.map(toHex),
      root: clausesRoot,
    },
    mandate: { owner_secret_key: secret("owner"), mandate: mandateA, canonical_body: canonical(mandateA.body), id: mandateId(mandateA) },
    mandate_approval: {
      note: "Approval of one agreement: valid only for clausesRoot (the clauses vector's root), with agent B under mandate B (withMandates), for the one record with this nonce, under mandate A.",
      owner_secret_key: secret("owner"),
      mandate: approval,
      canonical_body: canonical(approval.body),
      id: mandateId(approval),
    },
    mandate_without_domain: {
      note: "Identity level key: no domain field at all; the owner is known only by its key.",
      owner_secret_key: secret("owner without domain"),
      mandate: mandateNoDomain,
      canonical_body: canonical(mandateNoDomain.body),
      id: mandateId(mandateNoDomain),
    },
    record: {
      agent_secret_keys: { A: secret("agent A"), B: secret("agent B") },
      mandate_B: mandateB,
      record,
      entry_preimage: canonical({ body: record.body, signatures: record.body.parties.map((p) => record.signatures.find((s) => s.agent === p.agent)) }),
      entry,
    },
    register: {
      entries,
      leaves: leaves.map(toHex),
      roots: { "1": toHex(treeRoot(leaves.slice(0, 1))), "2": toHex(treeRoot(leaves.slice(0, 2))), "3": toHex(treeRoot(leaves)) },
    },
  };
}

if (/format-vectors\.ts$/.test(process.argv[1] ?? "")) {
  writeFileSync(new URL("../docs/format-vectors.json", import.meta.url), JSON.stringify(buildVectors(), null, 2) + "\n");
  console.log("docs/format-vectors.json written");
}
