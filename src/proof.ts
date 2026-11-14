// The proof file: everything a third party (counterparty, insurer, arbitrator,
// court) needs to check an agreement without trusting the register operator.

import { verifyAnchor, type Anchor, type AnchorStatus, type BlockProvider } from "./anchor.js";
import { fromHex } from "./bytes.js";
import { verifyDisclosure, type Disclosure } from "./clauses.js";
import { verifyValue, type PublicKey } from "./keys.js";
import { amountLeq, mandateId, verifyMandateSignature, withinValidity, type Amount, type Mandate } from "./mandate.js";
import { verifyConsistency, verifyInclusion } from "./merkle.js";
import { entryHash, type SignedRecord } from "./record.js";
import { entryLeaf, verifyHeadSignature, type Receipt } from "./register.js";
import { revocationsOf, signersOf, subjectsOf, type RevocationSource } from "./revocation.js";
import type { OwnerResolver } from "./wellknown.js";
import { verifyCosignature, type Cosignature } from "./witness.js";

export interface ProofBundle {
  type: "accord/proof";
  v: 1;
  record: SignedRecord;
  mandates: Mandate[];
  disclosures: Disclosure[];
  receipt: Receipt;
  cosignatures: Cosignature[];
  /** Optional: a later tree head anchored in Bitcoin, and the proof it extends the receipt's head. */
  anchor?: { anchor: Anchor; consistency: string[] };
}

export function buildProof(p: Omit<ProofBundle, "type" | "v">): ProofBundle {
  return { type: "accord/proof", v: 1, ...p };
}

export interface VerifyOptions {
  trustedLogs: PublicKey[];
  trustedWitnesses?: PublicKey[];
  minWitnesses?: number;
  ownerResolver?: OwnerResolver;
  /** Tolerated difference between the agents' clock and the register's clock. */
  clockSkewMs?: number;
  /** Where to read Bitcoin block headers; without it the Bitcoin anchor is not checked. */
  bitcoin?: BlockProvider;
  /** Revocations of the same register; without it revocations are not checked. */
  revocations?: RevocationSource;
}

export type Level = "unverified" | "domain";

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface Report {
  valid: boolean;
  checks: Check[];
  levels: Record<PublicKey, Level>;
  sealedAt?: string;
  disclosed: Record<string, unknown>;
  bitcoin: AnchorStatus | { status: "absent" | "not checked" };
}

export async function verifyProof(b: ProofBundle, opts: VerifyOptions): Promise<Report> {
  const checks: Check[] = [];
  const levels: Record<PublicKey, Level> = {};
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });
  const rec = b.record;
  const head = b.receipt.head;

  // 1. Signatures of the agents.
  for (const p of rec.body.parties) {
    const sig = rec.signatures.find((s) => s.agent === p.agent);
    add(`signature of agent ${short(p.agent)}`, !!sig && verifyValue(rec.body, sig.signature, p.agent));
  }
  const strangers = rec.signatures.filter((s) => !rec.body.parties.some((p) => p.agent === s.agent));
  add("no signatures from non-parties", strangers.length === 0);

  // 2. Mandates: each agent acted for an owner, within the validity period.
  const clockSkew = opts.clockSkewMs ?? 5 * 60_000;
  for (const p of rec.body.parties) {
    const m = b.mandates.find((x) => mandateId(x) === p.mandate);
    const who = short(p.agent);
    if (!m) {
      add(`mandate of agent ${who}`, false, "missing");
      levels[p.agent] = "unverified";
      continue;
    }
    add(`mandate of agent ${who} signed by owner ${m.body.owner.domain}`, verifyMandateSignature(m));
    add(`mandate of agent ${who} names this agent`, m.body.agent === p.agent);
    add(`mandate of agent ${who} valid when sealed`, withinValidity(m, head.time), `sealed ${head.time}`);
    add(
      `record of agent ${who} not dated after sealing`,
      Date.parse(rec.body.createdAt) <= Date.parse(head.time) + clockSkew,
    );
    levels[p.agent] = "unverified";
    let keys: PublicKey[] | null = null;
    if (opts.ownerResolver) {
      keys = await opts.ownerResolver(m.body.owner.domain);
      const ok = !!keys && keys.includes(m.body.owner.key);
      if (ok) levels[p.agent] = "domain";
      add(`owner key published by ${m.body.owner.domain}`, ok);
    }
    if (opts.revocations) {
      // A revocation applies from its position in the register: records sealed before it stay valid.
      try {
        const found = revocationsOf(m, await opts.revocations(subjectsOf(m), signersOf(m, keys)), keys);
        const before = found.find((r) => r.index < b.receipt.index);
        const after = found.find((r) => r.index > b.receipt.index);
        add(
          `mandate of agent ${who} not revoked before sealing`,
          !before,
          before ? `revoked on ${before.time} (register position ${before.index})` : after ? `revoked later, on ${after.time}: does not affect this record` : "no revocation",
        );
      } catch {
        add(`mandate of agent ${who} not revoked before sealing`, false, "could not check revocations");
      }
    }
  }

  // 3. The register: the record existed at the stated time and is unchanged.
  add("register is trusted", opts.trustedLogs.includes(head.log));
  add("register head signature", verifyHeadSignature(head));
  add("receipt is for this record", b.receipt.entry === entryHash(rec));
  let included = false;
  try {
    included = verifyInclusion(
      entryLeaf(b.receipt.entry),
      b.receipt.index,
      head.size,
      b.receipt.path.map(fromHex),
      fromHex(head.root),
    );
  } catch {
    included = false;
  }
  add("record is in the register", included);

  // 4. Independent witnesses.
  const trusted = new Set(opts.trustedWitnesses ?? []);
  const good = new Set(
    b.cosignatures.filter((c) => trusted.has(c.witness) && verifyCosignature(c, head)).map((c) => c.witness),
  );
  const need = opts.minWitnesses ?? 0;
  add(`at least ${need} independent witness(es)`, good.size >= need, `${good.size} valid`);

  // 5. Disclosed clauses belong to the signed agreement.
  const disclosed: Record<string, unknown> = {};
  for (const d of b.disclosures) {
    const ok = verifyDisclosure(d, rec.body.clausesRoot, rec.body.clauseCount);
    add(`clause "${d.name}" belongs to the agreement`, ok);
    if (ok) disclosed[d.name] = d.value;
  }

  // 6. Amount within each mandate's limit (only if the amount was disclosed).
  const amount = disclosed["amount"] as Amount | undefined;
  if (amount) {
    for (const p of rec.body.parties) {
      const m = b.mandates.find((x) => mandateId(x) === p.mandate);
      const max = m?.body.maxAmount;
      if (!max) continue;
      let ok = false;
      try {
        ok = max.currency === amount.currency && amountLeq(amount.value, max.value);
      } catch {
        ok = false;
      }
      add(`amount within mandate of agent ${short(p.agent)}`, ok, `${amount.value} ${amount.currency} ≤ ${max.value} ${max.currency}`);
    }
  }

  // 7. Bitcoin anchor: the record existed before a given Bitcoin block.
  let bitcoin: Report["bitcoin"] = { status: "absent" };
  if (b.anchor) {
    const ah = b.anchor.anchor.head;
    add("anchored head is from the same register", ah.log === head.log);
    add("anchored head signature", verifyHeadSignature(ah));
    let consistent = false;
    try {
      consistent = verifyConsistency(
        head.size,
        ah.size,
        fromHex(head.root),
        fromHex(ah.root),
        b.anchor.consistency.map(fromHex),
      );
    } catch {
      consistent = false;
    }
    add("anchored head contains this record's head", consistent);
    if (opts.bitcoin) {
      bitcoin = await verifyAnchor(b.anchor.anchor, opts.bitcoin);
      add("Bitcoin anchor", bitcoin.status !== "invalid", bitcoin.status === "invalid" ? bitcoin.reason : bitcoin.status);
    } else {
      bitcoin = { status: "not checked" };
    }
  }

  return { valid: checks.every((c) => c.ok), checks, levels, sealedAt: head.time, disclosed, bitcoin };
}

function short(pk: PublicKey): string {
  return pk.slice(8, 16);
}
