// The proof file: everything a third party (counterparty, insurer, arbitrator,
// court) needs to check an agreement without trusting the register operator.

import { verifyAnchor, type Anchor, type AnchorStatus, type BlockProvider } from "./anchor.js";
import { fromHex } from "./bytes.js";
import { clauseNamesProblem, verifyDisclosure, type Disclosure } from "./clauses.js";
import { verifyValue, type PublicKey } from "./keys.js";
import { amountLeq, looksLikeAmount, mandateId, mandateProblem, spendingLimit, verifyMandateSignature, withinValidity, type Amount, type Mandate } from "./mandate.js";
import { verifyConsistency, verifyInclusion } from "./merkle.js";
import { entryHash, recordProblem, type SignedRecord } from "./record.js";
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
  /**
   * True only when every check passed AND nothing that matters was left unverified (see `gaps`).
   * A proof that passes every check but has gaps is "incomplete", not valid.
   */
  valid: boolean;
  /** "valid": all checked, all fine. "incomplete": nothing failed, but `gaps` lists what could not be checked. "invalid": a check failed. */
  verdict: "valid" | "incomplete" | "invalid";
  /** What this verification could not establish, in plain words. */
  gaps: string[];
  checks: Check[];
  levels: Record<PublicKey, Level>;
  /** The time the register signed when it added the record. */
  sealedAt?: string;
  disclosed: Record<string, unknown>;
  bitcoin: AnchorStatus | { status: "absent" | "not checked" };
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Shape of the parts of a proof file the verifier reads, so a malformed file gives "invalid", not an error. */
function bundleProblem(b: ProofBundle): string | null {
  if (!b || typeof b !== "object") return "not a proof file";
  const rp = recordProblem(b.record);
  if (rp) return rp;
  if (!Array.isArray(b.mandates) || !Array.isArray(b.disclosures) || !Array.isArray(b.cosignatures)) return "missing mandates, disclosures or cosignatures";
  const r = b.receipt;
  if (!r || typeof r !== "object" || typeof r.entry !== "string" || !Number.isInteger(r.index) || r.index < 0 || !Array.isArray(r.path)) return "invalid receipt";
  const h = r.head;
  if (!h || typeof h !== "object" || typeof h.log !== "string" || !Number.isInteger(h.size) || typeof h.root !== "string" || !HEX64.test(h.root) || typeof h.time !== "string" || Number.isNaN(Date.parse(h.time)))
    return "invalid register head";
  for (const d of b.disclosures) if (!d || typeof d !== "object" || typeof d.name !== "string" || !Number.isInteger(d.index) || !Array.isArray(d.path)) return "invalid disclosure";
  if (b.anchor !== undefined) {
    const a = b.anchor;
    if (!a || typeof a !== "object" || !a.anchor || typeof a.anchor !== "object" || !a.anchor.head || !Array.isArray(a.consistency)) return "invalid anchor";
  }
  return null;
}

export async function verifyProof(b: ProofBundle, opts: VerifyOptions): Promise<Report> {
  const checks: Check[] = [];
  const gaps: string[] = [];
  const levels: Record<PublicKey, Level> = {};
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });

  const malformed = bundleProblem(b);
  if (malformed) {
    add("proof file is well formed", false, malformed);
    return { valid: false, verdict: "invalid", gaps, checks, levels, disclosed: {}, bitcoin: { status: "absent" } };
  }
  const rec = b.record;
  const head = b.receipt.head;

  // 0. The receipt's head must be the one signed when the record was added: only then is its time the
  // sealing time. A later head would make expired mandates look valid then, or valid ones look expired.
  const atSealing = head.size === b.receipt.index + 1;
  add(
    "receipt is from the moment of sealing",
    atSealing,
    atSealing
      ? `sealed ${head.time}`
      : `the receipt is against a later head (size ${head.size}, record at position ${b.receipt.index}): ask the register for a fresh receipt`,
  );

  // 1. Signatures of the agents.
  for (const p of rec.body.parties) {
    const sig = rec.signatures.find((s) => s.agent === p.agent);
    add(`signature of agent ${short(p.agent)}`, !!sig && verifyValue(rec.body, sig.signature, p.agent));
  }
  const strangers = rec.signatures.filter((s) => !rec.body.parties.some((p) => p.agent === s.agent));
  add("no signatures from non-parties", strangers.length === 0);

  // 2. Mandates: each agent acted for an owner, within the validity period.
  const clockSkew = opts.clockSkewMs ?? 5 * 60_000;
  const mandateOf = (id: string) => b.mandates.find((x) => !mandateProblem(x) && mandateId(x) === id);
  for (const p of rec.body.parties) {
    const m = mandateOf(p.mandate);
    const who = short(p.agent);
    if (!m) {
      add(`mandate of agent ${who}`, false, "missing");
      levels[p.agent] = "unverified";
      continue;
    }
    const domain = m.body.owner.domain;
    // The mandate is signed by the key written in it; that this key belongs to the domain is a separate check.
    add(`mandate of agent ${who} signed by the owner key it names (claims ${domain})`, verifyMandateSignature(m));
    add(`mandate of agent ${who} names this agent`, m.body.agent === p.agent);
    add(`mandate of agent ${who} valid when sealed`, withinValidity(m, head.time), `sealed ${head.time}`);
    add(
      `record of agent ${who} not dated after sealing`,
      Date.parse(rec.body.createdAt) <= Date.parse(head.time) + clockSkew,
    );
    levels[p.agent] = "unverified";
    let keys: PublicKey[] | null = null;
    if (opts.ownerResolver) {
      keys = await opts.ownerResolver(domain);
      const ok = !!keys && keys.includes(m.body.owner.key);
      if (ok) levels[p.agent] = "domain";
      add(`owner key published by ${domain}`, ok);
    } else {
      gaps.push(`owner of agent ${who} not checked: the mandate claims ${domain}, but nobody looked at the keys published by ${domain}, and anyone can write any domain`);
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
    } else {
      gaps.push(`revocations of the mandate of agent ${who} not checked`);
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

  // 5. Disclosed clauses belong to the signed agreement. Each name and each position at most once,
  // and no reserved names: a second "amount" (or a "__proto__") must not hide or replace the first.
  const disclosed = Object.create(null) as Record<string, unknown>;
  const names = new Set<string>();
  const positions = new Set<number>();
  for (const d of b.disclosures) {
    if (names.has(d.name) || positions.has(d.index)) {
      add(`clause "${d.name}" disclosed only once`, false, "the same clause name or position appears twice in this proof");
      continue;
    }
    names.add(d.name);
    positions.add(d.index);
    const ok = clauseNamesProblem([d.name]) === null && verifyDisclosure(d, rec.body.clausesRoot, rec.body.clauseCount);
    add(`clause "${d.name}" belongs to the agreement`, ok);
    if (ok) disclosed[d.name] = d.value;
  }

  // 6. Amount within each mandate's limit. If a mandate has a limit and the amount is not shown,
  // the limit could not be checked: that is a gap, never a pass.
  const amount = disclosed["amount"] as Amount | undefined;
  const limited = rec.body.parties.some((p) => { const m = mandateOf(p.mandate); return !!m && !!spendingLimit(m); });
  if (limited)
    for (const [name, value] of Object.entries(disclosed))
      if (name !== "amount" && looksLikeAmount(value))
        add(`clause "${name}" holds no hidden price`, false, "a mandate has a spending limit: the price may appear only in the \"amount\" clause");
  for (const p of rec.body.parties) {
    const lm = mandateOf(p.mandate);
    const max = lm ? spendingLimit(lm) : undefined;
    if (!max) continue;
    if (amount === undefined) {
      gaps.push(`amount not disclosed: the limit of the mandate of agent ${short(p.agent)} (${max.value} ${max.currency}) could not be checked`);
      continue;
    }
    let ok = false;
    try {
      ok = !!amount && typeof amount === "object" && max.currency === amount.currency && amountLeq(amount.value, max.value);
    } catch {
      ok = false;
    }
    add(`amount within mandate of agent ${short(p.agent)}`, ok, `${amount?.value} ${amount?.currency} ≤ ${max.value} ${max.currency}`);
  }

  // 7. Bitcoin anchor: the record existed before a given Bitcoin block. Only "confirmed" counts as passed.
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
      try {
        bitcoin = await verifyAnchor(b.anchor.anchor, opts.bitcoin);
      } catch (e) {
        bitcoin = { status: "invalid", reason: e instanceof Error ? e.message : "unreadable anchor" };
      }
      if (bitcoin.status === "confirmed") add("Bitcoin anchor confirmed", true, `block ${bitcoin.height}, ${bitcoin.blockTime}`);
      else if (bitcoin.status === "invalid") add("Bitcoin anchor", false, bitcoin.reason);
      else gaps.push("Bitcoin anchor still pending: not yet in a Bitcoin block, so for now the time rests on the register's signature");
    } else {
      bitcoin = { status: "not checked" };
      gaps.push("Bitcoin anchor present but not checked against Bitcoin");
    }
  }

  const verdict: Report["verdict"] = checks.some((c) => !c.ok) ? "invalid" : gaps.length ? "incomplete" : "valid";
  return { valid: verdict === "valid", verdict, gaps, checks, levels, sealedAt: head.time, disclosed: { ...disclosed }, bitcoin };
}

function short(pk: PublicKey): string {
  return pk.slice(8, 16);
}
