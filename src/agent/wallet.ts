// The agent's notary wallet. Runs next to the agent and keeps everything
// private: its key, its owner's mandate, the full text of every agreement.
// Only fingerprints ever go to the register.

import type { BlockProvider } from "../anchor.js";
import type { Json } from "../canonical.js";
import { clauseNamesProblem, clausesObject, commitClauses, disclose, verifyOpened, type OpenedClauses } from "../clauses.js";
import { generateKeyPair, keyPairFromSecret, verifyValue, type KeyPair, type PublicKey } from "../keys.js";
import { toHex } from "../bytes.js";
import { amountLeq, createSubMandate, looksLikeAmount, spendingLimit, mandateId, mandateProblem, verifyMandateSignature, withinValidity, type Amount, type Mandate } from "../mandate.js";
import { buildProof, verifyProof, type ProofBundle, type Report } from "../proof.js";
import { createRecord, entryHash, isFullySigned, recordProblem, signRecord, type SignedRecord } from "../record.js";
import type { Receipt } from "../register.js";
import type { OwnerResolver } from "../wellknown.js";
import type { RegisterClient } from "./client.js";
import { checkMandate, type CounterpartyCheck } from "../counterparty.js";
import { revocationsOf, signersOf, subjectsOf } from "../revocation.js";
import { signEnvelope, type Action, type Envelope } from "../piazza/messages.js";

export interface StoredRecord {
  kind: "action" | "agreement";
  record: SignedRecord;
  opened: OpenedClauses;
  mandates: Mandate[];
  receipt?: Receipt;
}

export interface WalletState {
  v: 1;
  agentSecret: string;
  mandate?: Mandate;
  records: Record<string, StoredRecord>; // by entry hash
  offers: Record<string, StoredRecord>; // by clause root, waiting for the counterparty
}

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

  get agentKey(): PublicKey {
    return this.key.publicKey;
  }

  whoami() {
    const m = this.state.mandate;
    return {
      agent: this.key.publicKey,
      mandate: m
        ? { owner: m.body.owner.domain, scope: m.body.scope, maxAmount: m.body.maxAmount ?? null, validUntil: m.body.notAfter }
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

  async installMandate(m: Mandate): Promise<CounterpartyCheck> {
    if (m.body.agent !== this.key.publicKey) throw new Error("this mandate is for a different agent key");
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

  /** Refuses to act on a revoked mandate (own or counterparty's). Unreachable revocation list: not blocking. */
  private async refuseIfRevoked(m: Mandate, whose: string) {
    const keys = this.opts.ownerResolver ? await this.opts.ownerResolver(m.body.owner.domain) : null;
    const r = await this.register.revocations(subjectsOf(m), signersOf(m, keys)).catch(() => []);
    const hit = revocationsOf(m, r, keys)[0];
    if (hit) throw new Error(`${whose} mandate was revoked on ${hit.time}${hit.revocation.body.reason ? ` (${hit.revocation.body.reason})` : ""}`);
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
    const maxAmount = p.maxAmount ?? mine.body.maxAmount;
    const mineTotal = mine.body.type === "symbolon/submandate" ? mine.body.total : undefined;
    const total = p.total ?? mineTotal;
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
   */
  private async requireCounterparty(m: Mandate, allowUnverifiedOwner = false): Promise<CounterpartyCheck> {
    if (mandateProblem(m)) throw new Error(`the counterparty's mandate is malformed: ${mandateProblem(m)}`);
    const check = await this.checkCounterparty(m);
    if (check.revoked) throw new Error(`the counterparty's mandate was revoked on ${check.revoked.at}`);
    const ownerOnly = (x: string) => x.startsWith("owner key not published by");
    const blocking = check.problems.filter((x) => !(allowUnverifiedOwner && ownerOnly(x)));
    if (!allowUnverifiedOwner && check.level !== "domain" && !blocking.some(ownerOnly))
      blocking.push(`owner ${check.owner} not verified (no owner lookup configured)`);
    if (blocking.length) throw new Error(`counterparty not accepted: ${blocking.join("; ")}`);
    return check;
  }

  /** Prepares and signs an agreement; the result goes to the counterparty. */
  async propose(p: { counterparty: Mandate; clauses: Record<string, Json>; allowUnverifiedOwner?: boolean }): Promise<Offer> {
    const mine = this.myMandate();
    if (p.counterparty?.body?.agent === this.key.publicKey) throw new Error("cannot make an agreement with yourself");
    await this.requireCounterparty(p.counterparty, p.allowUnverifiedOwner);
    await this.refuseIfRevoked(mine, "my");
    const problem = clauseNamesProblem(Object.keys(p.clauses));
    if (problem) throw new Error(problem);
    this.checkAmount(p.clauses, mine);
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
      counterparties.push(await this.requireCounterparty(m, opts.allowUnverifiedOwner));
      theirMandates.push(m);
    }
    await this.refuseIfRevoked(mine, "my");
    const clauses = clausesObject(opened);
    this.checkAmount(clauses, mine);
    for (const m of theirMandates) this.checkAmount(clauses, m);
    this.checkTotal(clauses, mine);

    const signed = signRecord(record, this.key);
    const entry = entryHash(signed);
    const receipt = await this.register.append(entry);
    this.state.records[entry] = { kind: "agreement", record: signed, opened, mandates: [...theirMandates, mine], receipt };
    await this.persist();
    return { entry, confirmation: { type: "accord/confirmation", record: signed, receipt }, counterparty: counterparties[0], counterparties };
  }

  /** The proposer files the counterparty's confirmation. */
  async confirm(c: Confirmation): Promise<{ entry: string }> {
    const pending = this.state.offers[c.record.body.clausesRoot];
    if (!pending) throw new Error("no offer of mine matches this confirmation");
    if (JSON.stringify(pending.record.body) !== JSON.stringify(c.record.body)) throw new Error("the confirmed agreement differs from my offer");
    if (!isFullySigned(c.record)) throw new Error("the agreement is not signed by all parties");
    const entry = entryHash(c.record);
    const receipt = (await this.register.receipt(entry)) ?? undefined;
    if (!receipt) throw new Error("the agreement is not in the register");
    this.state.records[entry] = { ...pending, record: c.record, receipt };
    delete this.state.offers[c.record.body.clausesRoot];
    await this.persist();
    return { entry };
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
  private checkAmount(clauses: Record<string, Json>, m: Mandate) {
    const has = Object.prototype.hasOwnProperty.call(clauses, "amount");
    const amount = (has ? clauses["amount"] : undefined) as unknown as Amount | undefined;
    const max = spendingLimit(m);
    if (!max) return;
    for (const [name, value] of Object.entries(clauses))
      if (name !== "amount" && looksLikeAmount(value))
        throw new Error(`clause "${name}" contains an amount: under a mandate with a spending limit the price goes only in the "amount" clause`);
    if (amount === undefined)
      throw new Error(`the mandate of ${m.body.owner.domain} has a spending limit (${max.value} ${max.currency}): the agreement needs an "amount" clause {value, currency}`);
    if (!amount || typeof amount !== "object" || typeof amount.value !== "string" || typeof amount.currency !== "string")
      throw new Error("the amount clause must be {value: '123.45', currency: 'EUR'}");
    let within = false;
    try {
      within = amount.currency === max.currency && amountLeq(amount.value, max.value);
    } catch {
      throw new Error(`invalid amount ${amount.value}`);
    }
    if (!within)
      throw new Error(`amount ${amount.value} ${amount.currency} exceeds the mandate of ${m.body.owner.domain} (${max.value} ${max.currency})`);
  }
}

