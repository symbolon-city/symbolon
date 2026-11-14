// Minimal sealing for agents that run on a server (e.g. a Cloudflare Worker) instead of
// a local wallet: seal one action, keep the returned package, build a proof later.
// Same formats as the wallet, so proofs verify with the normal verifier.
// Bundled into a single file with `npm run build:seal-lite` for other projects.

import { commitClauses, disclose, type OpenedClauses } from "./clauses.js";
import type { Json } from "./canonical.js";
import { keyPairFromSecret } from "./keys.js";
import { mandateId, verifyMandateSignature, withinValidity, type Mandate } from "./mandate.js";
import { buildProof, type ProofBundle } from "./proof.js";
import { createRecord, entryHash, signRecord, type SignedRecord } from "./record.js";
import type { Receipt } from "./register.js";

export interface SealedPackage {
  entry: string;
  record: SignedRecord;
  opened: OpenedClauses;
  mandate: Mandate;
  receipt: Receipt;
}

export interface SealOptions {
  registerUrl: string;
  agentSecretHex: string;
  mandate: Mandate;
  clauses: Record<string, Json>;
  fetchImpl?: typeof fetch;
  now?: Date;
}

/** Seals an action: signs it with the agent key and puts only its fingerprint in the register. */
export async function sealAction(o: SealOptions): Promise<SealedPackage> {
  const key = keyPairFromSecret(o.agentSecretHex);
  const now = (o.now ?? new Date()).toISOString();
  if (o.mandate.body.agent !== key.publicKey) throw new Error("mandate does not name this agent");
  if (!verifyMandateSignature(o.mandate)) throw new Error("mandate signature is invalid");
  if (!withinValidity(o.mandate, now)) throw new Error("mandate is not valid now");
  const opened = commitClauses(Object.entries(o.clauses).map(([name, value]) => ({ name, value })));
  const record = signRecord(
    createRecord({
      type: "accord/action",
      clausesRoot: opened.root,
      clauseCount: opened.count,
      parties: [{ agent: key.publicKey, mandate: mandateId(o.mandate) }],
      charter: o.mandate.body.charter,
      createdAt: now,
    }),
    key,
  );
  const entry = entryHash(record);
  const res = await (o.fetchImpl ?? fetch)(o.registerUrl.replace(/\/+$/, "") + "/v1/entries", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ entry }),
  });
  if (!res.ok) throw new Error(`register: HTTP ${res.status}`);
  const receipt = (await res.json()) as Receipt;
  if (receipt.entry !== entry) throw new Error("register returned a receipt for another entry");
  return { entry, record, opened, mandate: o.mandate, receipt };
}

/** Builds a proof file from a stored package, revealing only the named clauses. */
export function proofFromPackage(p: SealedPackage, reveal: string[]): ProofBundle {
  return buildProof({
    record: p.record,
    mandates: [p.mandate],
    disclosures: reveal.map((n) => disclose(p.opened, n)),
    receipt: p.receipt,
    cosignatures: [],
  });
}

export { createMandate, type Mandate } from "./mandate.js";
export { generateKeyPair, keyPairFromSecret } from "./keys.js";
export { verifyProof, type ProofBundle } from "./proof.js";
