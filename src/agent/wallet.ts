// The agent's notary wallet. Runs next to the agent and keeps everything
// private: its key, its owner's mandate, the full text of every agreement.
// Only fingerprints ever go to the register.

import type { BlockProvider } from "../anchor.js";
import { canonical, type Json } from "../canonical.js";
import { clauseNamesProblem, clausesObject, commitClauses, disclose, verifyOpened, type OpenedClauses } from "../clauses.js";
import { generateKeyPair, keyPairFromSecret, passkeyChallenge, verifyValue, type KeyPair, type PublicKey } from "../keys.js";
import { toBase64url, toHex } from "../bytes.js";
import { digest } from "../hash.js";
import {
  APPROVAL_MAX_DAYS,
  amountLeq,
  approvalProblem,
  createSubMandate,
  looksLikeAmount,
  mandateBody,
  ownerName,
  spendingLimit,
  mandateId,
  mandateProblem,
  verifyMandateSignature,
  withinValidity,
  type Amount,
  type Mandate,
  type MandateBody,
} from "../mandate.js";
import { buildProof, verifyProof, type ProofBundle, type Report } from "../proof.js";
import { createRecord, entryHash, isFullySigned, recordProblem, signRecord, type SignedRecord } from "../record.js";
import type { Receipt } from "../register.js";
import type { OwnerResolver } from "../wellknown.js";
import type { RegisterClient } from "./client.js";
import { checkMandate, type CounterpartyCheck } from "../counterparty.js";
import { answerChallenge, newChallenge, possessionProblem, type PossessionAnswer } from "../possession.js";
import { revocationsOf, signersOf, subjectsOf } from "../revocation.js";
import { checkStoredEnvelope, signEnvelope, type Action, type Envelope } from "../piazza/messages.js";
import { archiveKeyProblem, makeSnapshot, type ArchiveKeyClaim } from "../archive.js";
import { FORM_MEANING, WITHDRAWAL_REASONS, boxKeyClaim, boxKeyClaimProblem, formProblem, newBoxSecret, openBox, sealBox, type BoxKeyClaim, type BoxSecret, type Form } from "../channel.js";

export interface StoredRecord {
  kind: "action" | "agreement";
  record: SignedRecord;
  opened: OpenedClauses;
  mandates: Mandate[];
  receipt?: Receipt;
  /** For an agreement this agent has closed: how it ended, and the sealed action that says so. */
  closed?: { outcome: CommitmentOutcome | "withdrawn"; at: string; entry: string; by?: "me" | "counterparty" };
}

/** How a commitment ended. The closing is itself sealed, so it can be proven like the agreement. */
export const COMMITMENT_OUTCOMES = ["fulfilled", "cancelled_by_agreement", "not_fulfilled"] as const;
export type CommitmentOutcome = (typeof COMMITMENT_OUTCOMES)[number];
/** The clause that gives both parties a right of withdrawal until the time it states (ISO 8601). */
export const WITHDRAWAL_CLAUSE = "withdrawal_until";

/** Dates written in clause values (2026-11-17, or full ISO times, also inside intervals "a/b"), found anywhere inside. */
function datesIn(value: Json, out: string[] = []): string[] {
  if (typeof value === "string") {
    for (const m of value.matchAll(/\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)?\b/g))
      if (!Number.isNaN(Date.parse(m[0]))) out.push(m[0]);
  } else if (Array.isArray(value)) value.forEach((v) => datesIn(v, out));
  else if (value && typeof value === "object") Object.values(value).forEach((v) => datesIn(v as Json, out));
  return out;
}

export interface WalletState {
  v: 1;
  agentSecret: string;
  mandate?: Mandate;
  records: Record<string, StoredRecord>; // by entry hash
  offers: Record<string, StoredRecord>; // by clause root, waiting for the counterparty
  /** X25519 key for sealed forms from other agents (src/channel.ts), created on first use. */
  box?: BoxSecret;
  /** Piazzas (by origin) where this wallet's box key is published. */
  boxPublished?: string[];
  /** The owner's archive of commitments: last snapshot number, and how the last save went. */
  archive?: { seq: number; savedAt?: string; error?: string };
  /** Agreements prepared above the mandate's limit, waiting for the owner's approval (by clause root). */
  approvals?: Record<string, PendingApproval>;
}

/** An agreement prepared by this agent, shown to its owner for approval and not yet proposed. */
export interface PendingApproval {
  opened: OpenedClauses;
  counterparty: Mandate;
  /** Exactly what the owner is asked to sign. */
  body: MandateBody;
  allowUnverifiedOwner?: boolean;
  /** The owner's signature of body, when the owner signed it on a page of the wallet (hosted wallet). */
  signature?: string;
}

/** True if this mandate is the owner's approval of one agreement only. */
const isApproval = (m: Mandate | undefined) => !!m && m.body?.type === "accord/mandate" && !!m.body.agreement;

export interface WalletStorage {
  load(): Promise<WalletState | null>;
  save(state: WalletState): Promise<void>;
}

export class MemoryWalletStorage implements WalletStorage {
  private state: WalletState | null = null;
  async load() {
    return this.state ? structuredClone(this.state) : null;
  }
  async save(s: WalletState) {
    this.state = structuredClone(s);
  }
}

/** What one agent sends to the other to propose an agreement. */
export interface Offer {
  type: "accord/offer";
  record: SignedRecord;
  opened: OpenedClauses;
  mandates: Mandate[];
}

/** What the accepting agent sends back once the agreement is sealed. */
export interface Confirmation {
  type: "accord/confirmation";
  record: SignedRecord;
  receipt: Receipt;
}

export type { CounterpartyCheck } from "../counterparty.js";

export interface WalletOptions {
  ownerResolver?: OwnerResolver;
  bitcoin?: BlockProvider;
  now?: () => Date;
  charter?: string;
  /**
   * The owner's archive of commitments (src/archive.ts): after every change, the wallet sends there a snapshot
   * sealed with the owner's archive key. A failed save never blocks the agent; it is shown in my commitments.
   */
  archive?: { url: string; claim: ArchiveKeyClaim; fetchImpl?: typeof fetch };
  /**
   * Counterparties whose owner has no domain (identity level "key": always the same owner, but who it is is
   * not verified) are accepted by default, and their level is shown. An owner who wants only counterparties
   * with a domain sets this to true.
   */
  requireOwnerDomain?: boolean;
}

export class Wallet {
  private constructor(
    private state: WalletState,
    private readonly key: KeyPair,
    private readonly storage: WalletStorage,
    private readonly register: RegisterClient,
    private readonly opts: WalletOptions,
  ) {}

  static async open(storage: WalletStorage, register: RegisterClient, opts: WalletOptions = {}): Promise<Wallet> {
    let state = await storage.load();
    if (!state) {
      state = { v: 1, agentSecret: toHex(generateKeyPair().secretKey), records: {}, offers: {} };
      await storage.save(state);
    }
    return new Wallet(state, keyPairFromSecret(state.agentSecret), storage, register, opts);
  }

  private now() {
    return (this.opts.now ?? (() => new Date()))();
  }
  private get charter() {
    return this.opts.charter ?? "accord-charter/0.1";
  }
  private async persist() {
    await this.storage.save(this.state);
  }

  /**
   * Sends the owner's archive a sealed snapshot of this agent's commitments (see WalletOptions.archive).
   * Best effort: the outcome is kept and shown, the agent's work goes on either way.
   */
  async saveToOwnerArchive(): Promise<{ saved: boolean; error?: string } | null> {
    const a = this.opts.archive;
    const m = this.state.mandate;
    if (!a || !m) return null;
    const seq = (this.state.archive?.seq ?? 0) + 1;
    let error: string | undefined;
    try {
      const bad = archiveKeyProblem(a.claim, m);
      if (bad) throw new Error(bad);
      const { as_of: _ignored, ...commitments } = this.commitments();
      const snap = await makeSnapshot(this.key, m, a.claim, seq, commitments as unknown as Json, this.now());
      const res = await (a.fetchImpl ?? fetch)(a.url.replace(/\/+$/, "") + "/v1/snapshots", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(snap), signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`archive: HTTP ${res.status} ${((await res.json().catch(() => ({}))) as { error?: string }).error ?? ""}`.trim());
    } catch (e) {
      error = (e as Error).message;
    }
    // The number always moves on, so a save that arrived but whose answer was lost does not block the next ones.
    const savedAt = error ? this.state.archive?.savedAt : this.now().toISOString();
    this.state.archive = { seq, ...(savedAt ? { savedAt } : {}), ...(error ? { error } : {}) };
    await this.persist();
    return error ? { saved: false, error } : { saved: true };
  }

  get agentKey(): PublicKey {
    return this.key.publicKey;
  }

  whoami() {
    const m = this.state.mandate;
    return {
      agent: this.key.publicKey,
      mandate: m
        ? { owner: ownerName(m.body.owner), scope: m.body.scope, maxAmount: m.body.maxAmount ?? null, validUntil: m.body.notAfter }
        : null,
      records: Object.keys(this.state.records).length,
    };
  }

  /** The mandate to show counterparties. */
  myMandate(): Mandate {
    if (!this.state.mandate) throw new Error("no mandate installed: ask your owner for one (see `npm run owner`)");
    return this.state.mandate;
  }

  /** Signs a piazza envelope with this agent's key and mandate. The key never leaves the wallet. */
  signPiazzaEnvelope(audience: string, action: Action): Envelope {
    return signEnvelope(this.key, this.myMandate(), audience, action, this.now());
  }

  // ---------- the channel between agents (sealed forms) ----------

  private async boxSecret(): Promise<BoxSecret> {
    if (!this.state.box) {
      this.state.box = await newBoxSecret();
      await this.persist();
    }
    return this.state.box;
  }

  /** This wallet's box key, signed by the agent key, to publish once in a piazza. */
  async myBoxKeyClaim(): Promise<BoxKeyClaim> {
    return boxKeyClaim(this.key, await this.boxSecret(), this.now());
  }
  boxKeyPublishedAt(piazza: string): boolean {
    return (this.state.boxPublished ?? []).includes(piazza);
  }
  async markBoxKeyPublished(piazza: string) {
    this.state.boxPublished = [...new Set([...(this.state.boxPublished ?? []), piazza])];
    await this.persist();
  }

  /**
   * Seals a form for another agent. Only fixed forms travel (src/channel.ts); the recipient's box key must be
   * signed by that very agent. An offer sent this way is one this wallet made (symbolon_propose_agreement).
   */
  async sealForm(p: { to: PublicKey; toBoxKey: unknown; postId: string; form: Form }) {
    const bad = boxKeyClaimProblem(p.toBoxKey, p.to) ?? formProblem(p.form, this.now());
    if (bad) throw new Error(bad);
    if (p.form.form === "offer") {
      const root = (p.form.offer as unknown as Offer)?.record?.body?.clausesRoot;
      if (!root || !this.state.offers[root]) throw new Error("send only offers made by this wallet (symbolon_propose_agreement)");
    }
    return sealBox(p.form as unknown as Json, (p.toBoxKey as BoxKeyClaim).body.key, { from: this.key.publicKey, to: p.to, postId: p.postId });
  }

  /**
   * Opens a sealed form received through a piazza: the envelope must be signed by the sender named in its
   * mandate, addressed to this agent, and the box must open and hold exactly one of the fixed forms.
   * The sender's mandate is checked like any counterparty's (owner key, revocations).
   */
  async openForm(envelope: Envelope, piazza: string) {
    const bad = checkStoredEnvelope(envelope, piazza);
    if (bad) throw new Error(bad);
    const a = envelope.body.action;
    if (a.op !== "send") throw new Error("not a sealed form");
    if (a.to !== this.key.publicKey) throw new Error("this form is addressed to another agent");
    const from = envelope.mandate.body.agent;
    const form = await openBox(a.box, await this.boxSecret(), { from, to: this.key.publicKey, postId: a.postId });
    const problem = formProblem(form, new Date(Date.parse(envelope.body.createdAt)));
    if (problem) throw new Error(`the box holds something that is not a valid form (${problem}): ignored`);
    const sender = await this.checkCounterparty(envelope.mandate);
    const f = form as Form;
    return {
      from: { agent: from, owner: sender.owner, level: sender.level, ok: sender.ok, problems: sender.problems },
      postId: a.postId,
      sentAt: envelope.body.createdAt,
      form: f,
      meaning: FORM_MEANING[f.form],
    };
  }

  async installMandate(m: Mandate): Promise<CounterpartyCheck> {
    if (m.body.agent !== this.key.publicKey) throw new Error("this mandate is for a different agent key");
    if (isApproval(m)) throw new Error("this is your owner's approval of one agreement, not a mandate: use it with symbolon_propose_approved_agreement");
    if (!verifyMandateSignature(m)) throw new Error("mandate signature is invalid");
    if (!withinValidity(m, this.now().toISOString())) throw new Error("mandate is not valid now");
    const check = await this.checkCounterparty(m);
    if (check.revoked) throw new Error(`this mandate was revoked on ${check.revoked.at}`);
    this.state.mandate = m;
    await this.persist();
    return check;
  }

  checkCounterparty(m: Mandate): Promise<CounterpartyCheck> {
    return checkMandate(m, { ownerResolver: this.opts.ownerResolver, revocations: (s, k) => this.register.revocations(s, k), now: this.now() });
  }

  /**
   * Refuses to act on a revoked mandate. Fails closed: if the revocation list cannot be read (register
   * down, or someone blocking just that lookup), the wallet does not act, exactly as for a counterparty.
   */
  private async refuseIfRevoked(m: Mandate, whose: string) {
    const domain = m.body.owner.domain;
    const keys = this.opts.ownerResolver && domain !== undefined ? await this.opts.ownerResolver(domain) : null;
    let r: Awaited<ReturnType<RegisterClient["revocations"]>>;
    try {
      r = await this.register.revocations(subjectsOf(m), signersOf(m, keys));
    } catch {
      throw new Error(`could not check whether ${whose} mandate was revoked (revocation list unreachable): not acting until it can be checked`);
    }
    const hit = revocationsOf(m, r, keys)[0];
    if (hit) throw new Error(`${whose} mandate was revoked on ${hit.time}${hit.revocation.body.reason ? ` (${hit.revocation.body.reason})` : ""}`);
  }

  /**
   * Proof of possession, step 1 (checker): a fresh random challenge to send to the other agent, together
   * with this agent's key so the answer can name who asked.
   */
  newChallenge(): { challenge: string; expiresAt: string; for: PublicKey } {
    const c = newChallenge(this.now());
    return { challenge: c.challenge, expiresAt: c.expiresAt, for: this.key.publicKey };
  }

  /** Proof of possession, step 2 (the other agent): signs the checker's challenge with this agent's key. */
  answerChallenge(challenge: string, forKey?: PublicKey): PossessionAnswer {
    return answerChallenge(this.key, this.myMandate(), challenge, { ...(forKey ? { for: forKey } : {}), now: this.now() });
  }

  /**
   * Proof of possession, step 3 (checker): does the agent in front of me hold the key of the mandate it
   * showed? The answer must be addressed to this agent (its `for`), so it cannot be borrowed from a
   * conversation with someone else.
   */
  checkPossession(mandate: Mandate, answer: unknown, challenge: string): { ok: boolean; problem?: string } {
    const problem = possessionProblem(mandate, answer, challenge, { for: this.key.publicKey, now: this.now() });
    return problem ? { ok: false, problem } : { ok: true };
  }

  /**
   * Gives part of this agent's mandate to another agent (a sub-mandate: subcontracting, or an operator's
   * task agent handing on a piece of work). Never more than this agent has: limits and dates are capped
   * by every mandate above, and the owner at the top answers for the whole chain.
   */
  async delegate(p: { agent: PublicKey; scope: string; maxAmount?: Amount; total?: Amount; hours: number; task?: { instruction: string; principal: string } }): Promise<Mandate> {
    const mine = this.myMandate();
    await this.refuseIfRevoked(mine, "my");
    if (p.agent === this.key.publicKey) throw new Error("cannot give a sub-mandate to yourself");
    if (!(p.hours > 0)) throw new Error("hours must be a positive number");
    const now = this.now().getTime();
    const notBefore = new Date(Math.max(now - 60_000, Date.parse(mine.body.notBefore))).toISOString();
    const notAfter = new Date(Math.min(now + p.hours * 3_600_000, Date.parse(mine.body.notAfter))).toISOString();
    const mineTotal = mine.body.type === "symbolon/submandate" ? mine.body.total : undefined;
    const total = p.total ?? mineTotal;
    let maxAmount = p.maxAmount ?? mine.body.maxAmount;
    // An inherited limit per agreement never goes above the sub-mandate's own total.
    if (!p.maxAmount && maxAmount && total && maxAmount.currency === total.currency && !amountLeq(maxAmount.value, total.value)) maxAmount = total;
    return createSubMandate(this.key, mine, {
      agent: p.agent, scope: p.scope, notBefore, notAfter, charter: mine.body.charter,
      ...(maxAmount ? { maxAmount } : {}), ...(total ? { total } : {}), ...(p.task ? { task: p.task } : {}),
    });
  }

  /** Seals what this agent was asked and what it did. */
  async sealAction(p: { instruction: string; action: string; details?: Json }): Promise<{ entry: string; index: number; sealedAt: string }> {
    const mandate = this.myMandate();
    await this.refuseIfRevoked(mandate, "my");
    const clauses = [
      { name: "instruction", value: p.instruction },
      { name: "action", value: p.action },
      ...(p.details === undefined ? [] : [{ name: "details", value: p.details }]),
    ];
    const opened = commitClauses(clauses);
    const record = signRecord(
      createRecord({
        type: "accord/action",
        clausesRoot: opened.root,
        clauseCount: opened.count,
        parties: [{ agent: this.key.publicKey, mandate: mandateId(mandate) }],
        charter: this.charter,
        createdAt: this.now().toISOString(),
      }),
      this.key,
    );
    const entry = entryHash(record);
    const receipt = await this.register.append(entry);
    this.state.records[entry] = { kind: "action", record, opened, mandates: [mandate], receipt };
    await this.persist();
    return { entry, index: receipt.index, sealedAt: receipt.head.time };
  }

  /**
   * Refuses a counterparty whose check is not clean: bad signature, expired, revoked, revocations
   * unreachable, or an owner key not published at the owner's domain. The last one alone can be
   * waived with allowUnverifiedOwner (the owner must say so: anyone can write any domain in a mandate).
   * An owner without a domain claims nothing false: accepted at level "key" unless requireOwnerDomain.
   */
  private async requireCounterparty(m: Mandate, allowUnverifiedOwner = false): Promise<CounterpartyCheck> {
    if (mandateProblem(m)) throw new Error(`the counterparty's mandate is malformed: ${mandateProblem(m)}`);
    const check = await this.checkCounterparty(m);
    if (check.revoked) throw new Error(`the counterparty's mandate was revoked on ${check.revoked.at}`);
    const ownerOnly = (x: string) => x.startsWith("owner key not published by");
    const blocking = check.problems.filter((x) => !(allowUnverifiedOwner && ownerOnly(x)));
    if (check.level === "key") {
      if (this.opts.requireOwnerDomain) blocking.push(`owner ${check.owner} has no domain, and this wallet accepts only owners with a domain`);
    } else if (!allowUnverifiedOwner && check.level !== "domain" && !blocking.some(ownerOnly))
      blocking.push(`owner ${check.owner} not verified (no owner lookup configured)`);
    if (blocking.length) throw new Error(`counterparty not accepted: ${blocking.join("; ")}`);
    return check;
  }

  /** Prepares and signs an agreement; the result goes to the counterparty. */
  async propose(p: { counterparty: Mandate; clauses: Record<string, Json>; allowUnverifiedOwner?: boolean }): Promise<Offer> {
    const mine = this.myMandate();
    if (p.counterparty?.body?.agent === this.key.publicKey) throw new Error("cannot make an agreement with yourself");
    if (isApproval(p.counterparty))
      throw new Error("this is the owner's approval of one agreement that the other agent has already prepared: wait for its offer and accept it");
    await this.requireCounterparty(p.counterparty, p.allowUnverifiedOwner);
    await this.refuseIfRevoked(mine, "my");
    const problem = clauseNamesProblem(Object.keys(p.clauses));
    if (problem) throw new Error(problem);
    this.checkAmount(p.clauses, mine, true);
    this.checkAmount(p.clauses, p.counterparty);
    this.checkTotal(p.clauses, mine);
    const opened = commitClauses(Object.entries(p.clauses).map(([name, value]) => ({ name, value })));
    const record = signRecord(
      createRecord({
        type: "accord/agreement",
        clausesRoot: opened.root,
        clauseCount: opened.count,
        parties: [
          { agent: this.key.publicKey, mandate: mandateId(mine) },
          { agent: p.counterparty.body.agent, mandate: mandateId(p.counterparty) },
        ],
        charter: this.charter,
        createdAt: this.now().toISOString(),
      }),
      this.key,
    );
    const mandates = [mine, p.counterparty];
    this.state.offers[opened.root] = { kind: "agreement", record, opened, mandates };
    await this.persist();
    await this.saveToOwnerArchive();
    return { type: "accord/offer", record, opened, mandates };
  }

  /** Checks an offer received from another agent, signs it and seals it in the register. */
  /**
   * Checks an offer received from another agent, signs it and seals it in the register.
   * Every other party is checked (signature, mandate, owner, revocations, amount) before anything is signed.
   */
  async accept(
    offer: Offer,
    opts: { allowUnverifiedOwner?: boolean } = {},
  ): Promise<{ entry: string; confirmation: Confirmation; counterparty: CounterpartyCheck; counterparties: CounterpartyCheck[] }> {
    const mine = this.myMandate();
    if (!offer || typeof offer !== "object") throw new Error("not an offer");
    const { record, opened, mandates } = offer;
    const shape = recordProblem(record);
    if (shape) throw new Error(`the offer is malformed: ${shape}`);
    if (record.body.type !== "accord/agreement") throw new Error("the offer is not an agreement");
    if (!Array.isArray(mandates)) throw new Error("the offer has no mandates");
    const me = record.body.parties.find((p) => p.agent === this.key.publicKey);
    if (!me) throw new Error("this offer is not addressed to me");
    if (me.mandate !== mandateId(mine)) throw new Error("the offer refers to a different mandate of mine");
    if (!opened || !verifyOpened(opened) || opened.root !== record.body.clausesRoot || opened.count !== record.body.clauseCount)
      throw new Error("the clauses do not match the signed agreement (or a clause name is repeated or not allowed)");

    const others = record.body.parties.filter((p) => p.agent !== this.key.publicKey);
    const theirMandates: Mandate[] = [];
    const counterparties: CounterpartyCheck[] = [];
    for (const p of others) {
      const who = p.agent.slice(8, 16);
      const sig = record.signatures.find((s) => s.agent === p.agent);
      if (!sig || !verifyValue(record.body, sig.signature, p.agent)) throw new Error(`the signature of agent ${who} is missing or invalid`);
      const m = mandates.find((x) => !mandateProblem(x) && mandateId(x) === p.mandate);
      if (!m || m.body.agent !== p.agent) throw new Error(`agent ${who} has no valid mandate in the offer`);
      const notThis = approvalProblem(m, record.body);
      if (notThis) throw new Error(`agent ${who}: ${notThis}`);
      counterparties.push(await this.requireCounterparty(m, opts.allowUnverifiedOwner));
      theirMandates.push(m);
    }
    await this.refuseIfRevoked(mine, "my");
    const clauses = clausesObject(opened);
    this.checkAmount(clauses, mine, true);
    for (const m of theirMandates) this.checkAmount(clauses, m);
    this.checkTotal(clauses, mine);

    const signed = signRecord(record, this.key);
    const entry = entryHash(signed);
    const receipt = await this.register.append(entry);
    this.state.records[entry] = { kind: "agreement", record: signed, opened, mandates: [...theirMandates, mine], receipt };
    await this.persist();
    await this.saveToOwnerArchive();
    return { entry, confirmation: { type: "accord/confirmation", record: signed, receipt }, counterparty: counterparties[0], counterparties };
  }

  /**
   * "Approve just this one": prepares an agreement above this agent's limit and returns what its owner must
   * sign (with Face ID, a passkey, or the owner key) to approve that agreement only. The general limit does
   * not change. Once signed, proposeApproved() sends it to the counterparty.
   */
  async requestApproval(p: { counterparty: Mandate; clauses: Record<string, Json>; hours?: number; allowUnverifiedOwner?: boolean }) {
    const mine = this.myMandate();
    if (mine.body.type !== "accord/mandate") throw new Error("only an agent with a mandate signed directly by its owner can ask it to approve one agreement");
    if (p.counterparty?.body?.agent === this.key.publicKey) throw new Error("cannot make an agreement with yourself");
    if (isApproval(p.counterparty)) throw new Error("the counterparty's mandate is an approval of another agreement: use its general mandate");
    const check = await this.requireCounterparty(p.counterparty, p.allowUnverifiedOwner);
    await this.refuseIfRevoked(mine, "my");
    const problem = clauseNamesProblem(Object.keys(p.clauses));
    if (problem) throw new Error(problem);
    const amount = (Object.prototype.hasOwnProperty.call(p.clauses, "amount") ? p.clauses["amount"] : undefined) as unknown as Amount | undefined;
    if (!amount || typeof amount !== "object" || typeof amount.value !== "string" || typeof amount.currency !== "string")
      throw new Error("an approval is for an amount: the agreement needs an 'amount' clause {value: '123.45', currency: 'EUR'}");
    const limit = spendingLimit(mine);
    let within = false;
    try {
      within = !limit || (limit.currency === amount.currency && amountLeq(amount.value, limit.value));
    } catch {
      throw new Error(`invalid amount ${amount.value}`);
    }
    if (within) throw new Error("this agreement is within your mandate: propose it directly with symbolon_propose_agreement");
    this.checkAmount(p.clauses, p.counterparty);
    const hours = p.hours ?? 48;
    if (!Number.isFinite(hours) || hours <= 0 || hours > APPROVAL_MAX_DAYS * 24) throw new Error(`an approval lasts from a few minutes to ${APPROVAL_MAX_DAYS * 24} hours`);
    const opened = commitClauses(Object.entries(p.clauses).map(([name, value]) => ({ name, value })));
    const from = this.now().getTime() - 60_000;
    const owner = mine.body.owner;
    const body = mandateBody(owner.key, {
      ...(owner.domain !== undefined ? { ownerDomain: owner.domain } : {}),
      agent: this.key.publicKey,
      scope: `one agreement only, of ${amount.value} ${amount.currency}, with the agent of ${check.owner}`,
      maxAmount: { value: amount.value, currency: amount.currency },
      notBefore: new Date(from).toISOString(),
      notAfter: new Date(from + hours * 3_600_000).toISOString(),
      charter: mine.body.charter,
      agreement: { clausesRoot: opened.root, with: [p.counterparty.body.agent], under: mandateId(mine) },
    });
    this.checkAmount(p.clauses, { body, signature: "" });
    (this.state.approvals ??= {})[opened.root] = { opened, counterparty: p.counterparty, body, ...(p.allowUnverifiedOwner ? { allowUnverifiedOwner: true } : {}) };
    await this.persist();
    const general = limit ? `${limit.value} ${limit.currency}` : "none";
    return {
      clauses_root: opened.root,
      approval_body: body,
      fingerprint: digest(body),
      passkey_challenge: toBase64url(passkeyChallenge(body)),
      /**
       * The clauses with their salts: whoever shows the request to the owner (a page, the owner tool) recomputes
       * their root and must find approval_body.agreement.clausesRoot, so the owner reads the very clauses signed,
       * not only this agent's description of them.
       */
      clauses_opened: opened,
      for_the_owner: {
        text:
          `Approve only this agreement: ${amount.value} ${amount.currency} with the agent of ${check.owner} (identity level ${check.level}). ` +
          `Your general limit stays ${general}. This approval is valid until ${body.notAfter} and for these clauses only.`,
        clauses: p.clauses,
        counterparty: { owner: check.owner, level: check.level },
        general_limit: limit ?? null,
        valid_until: body.notAfter,
      },
      next:
        "Show for_the_owner to your owner as the thing to approve, and give the owner's page or tool the whole answer: it checks clauses_opened against approval_body. The owner signs approval_body with the owner key " +
        "(a passkey signs passkey_challenge; an owner key signs the canonical approval_body). Then call symbolon_propose_approved_agreement " +
        "with clauses_root and the signature (or the signed approval), and send the offer to the counterparty.",
    };
  }

  /** Agreements waiting for the owner's approval: what a page shows the owner (clauses recomputed from their root). */
  pendingApprovals() {
    return Object.entries(this.state.approvals ?? {}).map(([root, a]) => {
      if (!verifyOpened(a.opened) || a.opened.root !== root || a.body.agreement?.clausesRoot !== root)
        throw new Error("a stored approval request does not match its clauses");
      return {
        clauses_root: root,
        approval_body: a.body,
        clauses: clausesObject(a.opened),
        counterparty: { agent: a.counterparty.body.agent, owner: ownerName(a.counterparty.body.owner), scope: a.counterparty.body.scope },
        general_limit: this.state.mandate ? (spendingLimit(this.state.mandate) ?? null) : null,
        signed: !!a.signature,
      };
    });
  }

  /**
   * Files the owner's signature of a pending approval (signed on the wallet's own page), so that the agent can
   * then propose it with the clause root only. Checked now: signed by my owner's key, exactly this body.
   */
  async recordOwnerApproval(root: string, signature: string) {
    const pending = this.state.approvals?.[root];
    if (!pending) throw new Error("no approval request of mine matches");
    const approval: Mandate = { body: pending.body, signature };
    const shape = mandateProblem(approval);
    if (shape) throw new Error(`the approval is malformed: ${shape}`);
    if (approval.body.owner.key !== this.myMandate().body.owner.key) throw new Error("the approval must be signed by the owner of my mandate");
    if (!verifyMandateSignature(approval)) throw new Error("the approval is not signed by my owner's key (or it was changed)");
    pending.signature = signature;
    await this.persist();
  }

  /** Proposes an agreement prepared with requestApproval(), once the owner has signed the approval. */
  async proposeApproved(p: { approval?: Mandate; clausesRoot?: string; signature?: string }): Promise<Offer> {
    const root = p.approval?.body?.type === "accord/mandate" ? p.approval.body.agreement?.clausesRoot : p.clausesRoot;
    const pending = root ? this.state.approvals?.[root] : undefined;
    if (!pending || !root) throw new Error("no approval request of mine matches: first ask with symbolon_request_owner_approval");
    const signature = p.signature ?? pending.signature;
    if (!p.approval && !signature) throw new Error("your owner has not approved this agreement yet");
    const approval: Mandate = p.approval ? { body: p.approval.body, signature: p.approval.signature } : { body: pending.body, signature: signature ?? "" };
    const shape = mandateProblem(approval);
    if (shape) throw new Error(`the approval is malformed: ${shape}`);
    if (canonical(approval.body) !== canonical(pending.body)) throw new Error("the approval differs from what was shown to the owner");
    if (!verifyMandateSignature(approval)) throw new Error("the approval is not signed by my owner's key (or it was changed)");
    const mine = this.myMandate();
    if (pending.body.agreement!.under !== mandateId(mine)) throw new Error("my mandate changed since the owner was asked: ask again");
    if (!withinValidity(approval, this.now().toISOString())) throw new Error("the approval has expired: ask the owner again");
    await this.requireCounterparty(pending.counterparty, pending.allowUnverifiedOwner);
    await this.refuseIfRevoked(mine, "my");
    await this.refuseIfRevoked(approval, "the approval of my");
    const clauses = clausesObject(pending.opened);
    this.checkAmount(clauses, approval);
    this.checkAmount(clauses, pending.counterparty);
    const record = signRecord(
      createRecord({
        type: "accord/agreement",
        clausesRoot: pending.opened.root,
        clauseCount: pending.opened.count,
        parties: [
          { agent: this.key.publicKey, mandate: mandateId(approval) },
          { agent: pending.counterparty.body.agent, mandate: mandateId(pending.counterparty) },
        ],
        charter: this.charter,
        createdAt: this.now().toISOString(),
      }),
      this.key,
    );
    const bad = approvalProblem(approval, record.body);
    if (bad) throw new Error(bad);
    const mandates = [approval, pending.counterparty];
    this.state.offers[root] = { kind: "agreement", record, opened: pending.opened, mandates };
    delete this.state.approvals![root];
    await this.persist();
    await this.saveToOwnerArchive();
    return { type: "accord/offer", record, opened: pending.opened, mandates };
  }

  /** The proposer files the counterparty's confirmation. */
  async confirm(c: Confirmation): Promise<{ entry: string }> {
    const pending = this.state.offers[c.record.body.clausesRoot];
    if (!pending) throw new Error("no offer of mine matches this confirmation");
    // Compared in canonical form: the same agreement may come back with its fields in another order (e.g. through a sealed form).
    if (!c?.record?.body || canonical(pending.record.body) !== canonical(c.record.body)) throw new Error("the confirmed agreement differs from my offer");
    if (!isFullySigned(c.record)) throw new Error("the agreement is not signed by all parties");
    const entry = entryHash(c.record);
    const receipt = (await this.register.receipt(entry)) ?? undefined;
    if (!receipt) throw new Error("the agreement is not in the register");
    this.state.records[entry] = { ...pending, record: c.record, receipt };
    delete this.state.offers[c.record.body.clausesRoot];
    await this.persist();
    await this.saveToOwnerArchive();
    return { entry };
  }

  /**
   * "My commitments": what this agent has promised and not yet closed, so that it can pick up its work
   * after a conversation ends and it forgets. Open agreements (with every date found in their clauses,
   * overdue ones first), offers it sent that are still waiting for the other side, and the last closed ones.
   */
  commitments() {
    const now = this.now();
    const nowMs = now.getTime();
    const counterparties = (r: StoredRecord) =>
      r.record.body.parties
        .filter((p) => p.agent !== this.key.publicKey)
        .map((p) => {
          const m = r.mandates.find((x) => mandateId(x) === p.mandate);
          return { agent: p.agent, owner: m ? ownerName(m.body.owner) : "unknown", scope: m?.body.scope };
        });
    const open = Object.entries(this.state.records)
      .filter(([, r]) => r.kind === "agreement" && !r.closed)
      .map(([entry, r]) => {
        const clauses = clausesObject(r.opened);
        const dates = Object.entries(clauses)
          .flatMap(([name, v]) => datesIn(v).map((date) => ({ clause: name, date })))
          .sort((a, b) => Date.parse(a.date) - Date.parse(b.date));
        const last = dates.length ? Date.parse(dates[dates.length - 1].date.split("/").pop()!) : NaN;
        const next = dates.find((d) => Date.parse(d.date) >= nowMs);
        return {
          entry,
          sealed_at: r.receipt?.head.time,
          with: counterparties(r),
          clauses,
          dates,
          ...(next ? { next_date: next } : {}),
          ...((u) => (u !== null && u > nowMs ? { can_withdraw_until: new Date(u).toISOString() } : {}))(this.withdrawalUntil(r)),
          overdue: Number.isFinite(last) && last < nowMs,
        };
      })
      .sort((a, b) => Number(b.overdue) - Number(a.overdue) || (Date.parse(a.next_date?.date ?? "9999") - Date.parse(b.next_date?.date ?? "9999")));
    const waiting = Object.entries(this.state.offers).map(([root, r]) => ({
      offer: root,
      to: counterparties(r),
      clauses: clausesObject(r.opened),
      offered_at: r.record.body.createdAt,
      note: "Sent, not yet sealed: the other agent has not accepted (or you have not filed its confirmation with symbolon_confirm_agreement).",
    }));
    const waitingForOwner = Object.entries(this.state.approvals ?? {}).map(([root, a]) => ({
      clauses_root: root,
      with: [{ agent: a.counterparty.body.agent, owner: ownerName(a.counterparty.body.owner) }],
      clauses: clausesObject(a.opened),
      ask_until: a.body.notAfter,
      note: "Prepared above your limit and waiting for your owner's approval (then symbolon_propose_approved_agreement).",
    }));
    const closed = Object.entries(this.state.records)
      .filter(([, r]) => r.closed)
      .map(([entry, r]) => ({ entry, with: counterparties(r), outcome: r.closed!.outcome, at: r.closed!.at, closing_entry: r.closed!.entry, ...(r.closed!.by ? { by: r.closed!.by } : {}) }))
      .sort((a, b) => b.at.localeCompare(a.at))
      .slice(0, 20);
    const m = this.state.mandate;
    return {
      as_of: now.toISOString(),
      my_mandate: m
        ? { owner: ownerName(m.body.owner), scope: m.body.scope, valid_until: m.body.notAfter, days_left: Math.floor((Date.parse(m.body.notAfter) - nowMs) / 86_400_000) }
        : null,
      open,
      waiting,
      ...(waitingForOwner.length ? { waiting_for_owner: waitingForOwner } : {}),
      closed,
      ...(this.opts.archive
        ? { owner_archive: { url: this.opts.archive.url, last_saved_at: this.state.archive?.savedAt ?? null, ...(this.state.archive?.error ? { last_error: this.state.archive.error } : {}) } }
        : {}),
      how_to_use:
        "These are the promises this agent made on behalf of its owner, kept in its wallet. Read them when you resume work. " +
        "When one is done (or cancelled by both sides, or not kept), close it with symbolon_close_commitment: the closing is sealed too.",
    };
  }

  /** Closes an open agreement with its outcome, sealing an action that names it: the ending can be proven too. */
  async closeCommitment(p: { entry: string; outcome: CommitmentOutcome; note?: string }) {
    const r = this.state.records[p.entry];
    if (!r || r.kind !== "agreement") throw new Error("no sealed agreement of mine with this fingerprint (see symbolon_my_commitments)");
    if (r.closed) throw new Error(`already closed on ${r.closed.at} as ${r.closed.outcome}`);
    if (!(COMMITMENT_OUTCOMES as readonly string[]).includes(p.outcome)) throw new Error(`outcome must be one of ${COMMITMENT_OUTCOMES.join(", ")}`);
    if (p.note !== undefined && (typeof p.note !== "string" || p.note.length > 500)) throw new Error("note: plain text of at most 500 characters");
    const sealed = await this.sealAction({
      instruction: `close commitment ${p.entry}`,
      action: p.outcome,
      details: { closes: p.entry, outcome: p.outcome, ...(p.note ? { note: p.note } : {}) },
    });
    r.closed = { outcome: p.outcome, at: sealed.sealedAt, entry: sealed.entry };
    await this.persist();
    await this.saveToOwnerArchive();
    return { closed: p.entry, outcome: p.outcome, closing_entry: sealed.entry, sealed_at: sealed.sealedAt };
  }

  /** The end of the withdrawal period of an agreement, or null if it has none. */
  private withdrawalUntil(r: StoredRecord): number | null {
    const v = clausesObject(r.opened)[WITHDRAWAL_CLAUSE];
    const t = typeof v === "string" ? Date.parse(v) : NaN;
    return Number.isFinite(t) ? t : null;
  }

  /**
   * Right of withdrawal: within the period stated in the agreement (clause withdrawal_until), either party can
   * withdraw. The withdrawal is sealed; the result includes a sealed form, with its proof, to send to the other side.
   */
  async withdraw(p: { entry: string; reason: (typeof WITHDRAWAL_REASONS)[number] }) {
    const r = this.state.records[p.entry];
    if (!r || r.kind !== "agreement") throw new Error("no sealed agreement of mine with this fingerprint (see symbolon_my_commitments)");
    if (r.closed) throw new Error(`already closed on ${r.closed.at} as ${r.closed.outcome}`);
    if (!(WITHDRAWAL_REASONS as readonly string[]).includes(p.reason)) throw new Error(`reason must be one of: ${WITHDRAWAL_REASONS.join(", ")}`);
    const until = this.withdrawalUntil(r);
    if (until === null) throw new Error(`this agreement gives no right of withdrawal (no clause ${WITHDRAWAL_CLAUSE})`);
    if (this.now().getTime() >= until) throw new Error(`the withdrawal period ended on ${new Date(until).toISOString()}`);
    const sealed = await this.sealAction({
      instruction: `withdraw agreement ${p.entry}`,
      action: "withdrawn",
      details: { closes: p.entry, outcome: "withdrawn", reason: p.reason },
    });
    if (Date.parse(sealed.sealedAt) > until) throw new Error(`sealed at ${sealed.sealedAt}, after the end of the withdrawal period: the agreement stands`);
    r.closed = { outcome: "withdrawn", at: sealed.sealedAt, entry: sealed.entry, by: "me" };
    await this.persist();
    await this.saveToOwnerArchive();
    const proof = await this.createProof(sealed.entry, ["details"]);
    return {
      withdrawn: p.entry,
      closing_entry: sealed.entry,
      sealed_at: sealed.sealedAt,
      form: { form: "withdrawal" as const, about: p.entry, reason: p.reason, proof: proof as unknown as Json },
      next: "Send the form to the other agent (piazza_send_form), or give it the proof by any other channel.",
    };
  }

  /**
   * Records a withdrawal made by the other party, only after checking it: the proof must be sound, be signed by
   * a party of this agreement other than me, say it withdraws this very agreement, and be sealed in time.
   */
  async recordWithdrawal(form: { about: string; proof: unknown }) {
    const r = this.state.records[form?.about];
    if (!r || r.kind !== "agreement") throw new Error("no sealed agreement of mine with this fingerprint");
    if (r.closed) throw new Error(`already closed on ${r.closed.at} as ${r.closed.outcome}`);
    const until = this.withdrawalUntil(r);
    if (until === null) throw new Error(`this agreement gives no right of withdrawal (no clause ${WITHDRAWAL_CLAUSE})`);
    const proof = form.proof as ProofBundle;
    const report = await this.verify(proof);
    const failed = report.checks.filter((c) => !c.ok);
    // Under a mandate with a spending limit a withdrawal (no amount) is "incomplete" for that reason only: acceptable.
    const otherGaps = report.gaps.filter((g) => !/amount not disclosed/.test(g));
    if (failed.length || otherGaps.length) throw new Error(`the withdrawal proof does not hold: ${[...failed.map((c) => c.name), ...otherGaps].join("; ")}`);
    const by = proof.record.body.parties[0]?.agent;
    if (by === this.key.publicKey || !r.record.body.parties.some((x) => x.agent === by)) throw new Error("the withdrawal is not signed by the other party of this agreement");
    const d = report.disclosed["details"] as { closes?: string; outcome?: string } | undefined;
    if (d?.closes !== form.about || d?.outcome !== "withdrawn") throw new Error("the proof does not withdraw this agreement");
    if (!report.sealedAt || Date.parse(report.sealedAt) > until) throw new Error(`withdrawn too late: sealed at ${report.sealedAt}, period ended ${new Date(until).toISOString()}`);
    r.closed = { outcome: "withdrawn", at: report.sealedAt, entry: entryHash(proof.record), by: "counterparty" };
    await this.persist();
    await this.saveToOwnerArchive();
    return { recorded: form.about, outcome: "withdrawn", by, sealed_at: report.sealedAt };
  }

  /**
   * Everything the owner may take away (to another wallet, a lawyer, an archive): mandates, every sealed record
   * with its full clauses and receipt (enough for anyone to rebuild and check a proof), offers and approvals
   * waiting. Never the agent's secret keys.
   */
  exportForOwner() {
    const records = Object.entries(this.state.records).map(([entry, r]) => ({ entry, ...structuredClone(r) }));
    return {
      type: "symbolon/owner-export",
      v: 1,
      agent: this.key.publicKey,
      mandate: this.state.mandate ?? null,
      records,
      offers: structuredClone(this.state.offers),
      approvals: Object.fromEntries(Object.entries(this.state.approvals ?? {}).map(([root, a]) => [root, { opened: a.opened, counterparty: a.counterparty, body: a.body, signed: !!a.signature }])),
    };
  }

  list() {
    return Object.entries(this.state.records).map(([entry, r]) => ({
      entry,
      kind: r.kind,
      sealedAt: r.receipt?.head.time,
      clauses: r.opened.clauses.map((c) => c.name),
    }));
  }

  /** Builds a proof file revealing only the chosen clauses. */
  async createProof(entry: string, revealClauses: string[]): Promise<ProofBundle> {
    const r = this.state.records[entry];
    if (!r?.receipt) throw new Error("unknown or unsealed record");
    const bundle = buildProof({
      record: r.record,
      mandates: r.mandates,
      disclosures: revealClauses.map((n) => disclose(r.opened, n)),
      receipt: r.receipt,
      cosignatures: [],
    });
    const latest = await this.register.latestAnchor().catch(() => null);
    if (latest && latest.anchor.head.size >= r.receipt.head.size && latest.anchor.head.log === r.receipt.head.log) {
      const consistency = await this.register.consistency(r.receipt.head.size, latest.anchor.head.size);
      bundle.anchor = { anchor: latest.anchor, consistency };
    }
    return bundle;
  }

  async verify(bundle: ProofBundle, extraTrustedLogs: PublicKey[] = []): Promise<Report> {
    const info = await this.register.info();
    return verifyProof(bundle, {
      trustedLogs: [info.register_key, ...extraTrustedLogs],
      ownerResolver: this.opts.ownerResolver,
      bitcoin: this.opts.bitcoin,
      revocations: (s, k) => this.register.revocations(s, k),
    });
  }

  /**
   * The total of a sub-mandate ("at most 50 EUR for this task"): what this wallet already agreed under it,
   * sealed or still offered, plus this agreement, must stay within it.
   */
  private checkTotal(clauses: Record<string, Json>, mine: Mandate) {
    const total = mine.body.type === "symbolon/submandate" ? mine.body.total : undefined;
    if (!total) return;
    const id = mandateId(mine);
    const amountOf = (c: Record<string, Json>): Amount | null => {
      const a = (Object.prototype.hasOwnProperty.call(c, "amount") ? c["amount"] : null) as unknown as Amount | null;
      return a && typeof a === "object" && typeof a.value === "string" ? a : null;
    };
    const scale = (v: string) => {
      const [i, f = ""] = v.split(".");
      return BigInt(i) * 1_000_000n + BigInt(f.padEnd(6, "0").slice(0, 6));
    };
    let used = 0n;
    for (const r of [...Object.values(this.state.records), ...Object.values(this.state.offers)]) {
      if (r.kind !== "agreement" || !r.record.body.parties.some((p) => p.agent === this.key.publicKey && p.mandate === id)) continue;
      const a = amountOf(clausesObject(r.opened));
      if (a && a.currency === total.currency) used += scale(a.value);
    }
    const now = amountOf(clauses);
    if (!now) return;
    if (now.currency !== total.currency) throw new Error(`this task's total is in ${total.currency}, the amount is in ${now.currency}`);
    if (used + scale(now.value) > scale(total.value))
      throw new Error(`this task allows at most ${total.value} ${total.currency} in total, and ${(Number(used) / 1e6).toFixed(2)} are already agreed`);
  }

  /**
   * The mandate limit is checked on the "amount" clause, so under a mandate with a limit the agreement must
   * state its price there, and nowhere else: a 999,999 EUR "price" next to (or instead of) a small "amount"
   * would dodge the limit. Strings like "999999 EUR" inside free text cannot be told apart from prose: the
   * full fix (amount as a field of the signed record, the only price that binds) comes with the launch register.
   */
  private checkAmount(clauses: Record<string, Json>, m: Mandate, mine = false) {
    const has = Object.prototype.hasOwnProperty.call(clauses, "amount");
    const amount = (has ? clauses["amount"] : undefined) as unknown as Amount | undefined;
    const max = spendingLimit(m);
    if (!max) return;
    for (const [name, value] of Object.entries(clauses))
      if (name !== "amount" && looksLikeAmount(value))
        throw new Error(`clause "${name}" contains an amount: under a mandate with a spending limit the price goes only in the "amount" clause`);
    if (amount === undefined)
      throw new Error(`the mandate of ${ownerName(m.body.owner)} has a spending limit (${max.value} ${max.currency}): the agreement needs an "amount" clause {value, currency}`);
    if (!amount || typeof amount !== "object" || typeof amount.value !== "string" || typeof amount.currency !== "string")
      throw new Error("the amount clause must be {value: '123.45', currency: 'EUR'}");
    let within = false;
    try {
      within = amount.currency === max.currency && amountLeq(amount.value, max.value);
    } catch {
      throw new Error(`invalid amount ${amount.value}`);
    }
    if (!within)
      throw new Error(
        mine
          ? `amount ${amount.value} ${amount.currency} exceeds the mandate of ${ownerName(m.body.owner)} (${max.value} ${max.currency}): instead of dropping the deal, ask your owner to approve just this agreement (symbolon_request_owner_approval), then propose it yourself (symbolon_propose_approved_agreement)`
          : `amount ${amount.value} ${amount.currency} exceeds the mandate of ${ownerName(m.body.owner)} (${max.value} ${max.currency}): instead of dropping the deal, that agent can pause, ask its owner to approve just this agreement, and propose it itself (sealed form ask_owner)`,
      );
  }
}

