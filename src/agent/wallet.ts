// The agent's notary wallet. Runs next to the agent and keeps everything
// private: its key, its owner's mandate, the full text of every agreement.
// Only fingerprints ever go to the register.

import type { BlockProvider } from "../anchor.js";
import type { Json } from "../canonical.js";
import { commitClauses, disclose, verifyOpened, type OpenedClauses } from "../clauses.js";
import { generateKeyPair, keyPairFromSecret, verifyValue, type KeyPair, type PublicKey } from "../keys.js";
import { toHex } from "../bytes.js";
import { amountLeq, mandateId, verifyMandateSignature, withinValidity, type Amount, type Mandate } from "../mandate.js";
import { buildProof, verifyProof, type ProofBundle, type Report } from "../proof.js";
import { createRecord, entryHash, isFullySigned, signRecord, type SignedRecord } from "../record.js";
import type { Receipt } from "../register.js";
import type { OwnerResolver } from "../wellknown.js";
import type { RegisterClient } from "./client.js";
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

export interface CounterpartyCheck {
  ok: boolean;
  owner: string;
  level: "unverified" | "domain";
  scope: string;
  maxAmount?: Amount;
  validUntil: string;
  problems: string[];
}

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
    this.state.mandate = m;
    await this.persist();
    return check;
  }

  async checkCounterparty(m: Mandate): Promise<CounterpartyCheck> {
    const problems: string[] = [];
    if (!verifyMandateSignature(m)) problems.push("mandate signature is invalid");
    if (!withinValidity(m, this.now().toISOString())) problems.push("mandate is not valid now");
    let level: CounterpartyCheck["level"] = "unverified";
    if (this.opts.ownerResolver) {
      const keys = await this.opts.ownerResolver(m.body.owner.domain);
      if (keys?.includes(m.body.owner.key)) level = "domain";
      else problems.push(`owner key not published by ${m.body.owner.domain}`);
    }
    return {
      ok: problems.length === 0,
      owner: m.body.owner.domain,
      level,
      scope: m.body.scope,
      maxAmount: m.body.maxAmount,
      validUntil: m.body.notAfter,
      problems,
    };
  }

  /** Seals what this agent was asked and what it did. */
  async sealAction(p: { instruction: string; action: string; details?: Json }): Promise<{ entry: string; index: number; sealedAt: string }> {
    const mandate = this.myMandate();
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

  /** Prepares and signs an agreement; the result goes to the counterparty. */
  async propose(p: { counterparty: Mandate; clauses: Record<string, Json> }): Promise<Offer> {
    const mine = this.myMandate();
    if (!verifyMandateSignature(p.counterparty)) throw new Error("counterparty mandate signature is invalid");
    if (!withinValidity(p.counterparty, this.now().toISOString())) throw new Error("counterparty mandate is not valid now");
    if (p.counterparty.body.agent === this.key.publicKey) throw new Error("cannot make an agreement with yourself");
    this.checkAmount(p.clauses, mine);
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
  async accept(offer: Offer): Promise<{ entry: string; confirmation: Confirmation; counterparty: CounterpartyCheck }> {
    const mine = this.myMandate();
    const { record, opened, mandates } = offer;
    const me = record.body.parties.find((p) => p.agent === this.key.publicKey);
    if (!me) throw new Error("this offer is not addressed to me");
    if (me.mandate !== mandateId(mine)) throw new Error("the offer refers to a different mandate of mine");
    if (!verifyOpened(opened) || opened.root !== record.body.clausesRoot || opened.count !== record.body.clauseCount)
      throw new Error("the clauses do not match the signed agreement");
    const proposer = record.body.parties.find((p) => p.agent !== this.key.publicKey)!;
    const sig = record.signatures.find((s) => s.agent === proposer.agent);
    if (!sig || !verifyValue(record.body, sig.signature, proposer.agent)) throw new Error("the proposer's signature is invalid");
    const theirMandate = mandates.find((m) => mandateId(m) === proposer.mandate);
    if (!theirMandate || theirMandate.body.agent !== proposer.agent) throw new Error("the proposer has no valid mandate");
    const counterparty = await this.checkCounterparty(theirMandate);
    if (!verifyMandateSignature(theirMandate) || !withinValidity(theirMandate, this.now().toISOString()))
      throw new Error("the proposer's mandate is invalid or expired");
    const clauses = Object.fromEntries(opened.clauses.map((c) => [c.name, c.value]));
    this.checkAmount(clauses, mine);
    this.checkAmount(clauses, theirMandate);

    const signed = signRecord(record, this.key);
    const entry = entryHash(signed);
    const receipt = await this.register.append(entry);
    this.state.records[entry] = { kind: "agreement", record: signed, opened, mandates: [theirMandate, mine], receipt };
    await this.persist();
    return { entry, confirmation: { type: "accord/confirmation", record: signed, receipt }, counterparty };
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
    });
  }

  private checkAmount(clauses: Record<string, Json>, m: Mandate) {
    const amount = clauses["amount"] as unknown as Amount | undefined;
    const max = m.body.maxAmount;
    if (!amount || !max) return;
    if (amount.currency !== max.currency || !amountLeq(amount.value, max.value))
      throw new Error(`amount ${amount.value} ${amount.currency} exceeds the mandate of ${m.body.owner.domain} (${max.value} ${max.currency})`);
  }
}
