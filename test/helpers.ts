import { DatabaseSync } from "node:sqlite";
import type { D1Like } from "../src/server/stores.js";
import {
  MemoryStore,
  Register,
  Witness,
  buildProof,
  commitClauses,
  createMandate,
  createRecord,
  entryHash,
  generateKeyPair,
  mandateId,
  signRecord,
  staticOwnerResolver,
} from "../src/index.js";

/** Two companies, two agents, one register, two witnesses, one sealed agreement. */
export async function scenario() {
  const alfaOwner = generateKeyPair();
  const betaOwner = generateKeyPair();
  const buyer = generateKeyPair();
  const seller = generateKeyPair();
  const store = new MemoryStore();
  const register = new Register(generateKeyPair(), store);
  const witnesses = [new Witness(generateKeyPair()), new Witness(generateKeyPair())];

  const validity = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-12-31T23:59:59Z", charter: "accord-charter/0.1" };
  const buyerMandate = createMandate(alfaOwner, {
    ownerDomain: "alfa.example",
    agent: buyer.publicKey,
    scope: "purchase of office supplies",
    maxAmount: { value: "50000.00", currency: "EUR" },
    ...validity,
  });
  const sellerMandate = createMandate(betaOwner, {
    ownerDomain: "beta.example",
    agent: seller.publicKey,
    scope: "sale of office supplies",
    ...validity,
  });

  const opened = commitClauses([
    { name: "object", value: "10000 boxes of A4 paper" },
    { name: "amount", value: { value: "42000.00", currency: "EUR" } },
    { name: "delivery", value: "2026-12-10" },
    { name: "penalty", value: "0.5% per day of delay" },
  ]);

  let record = createRecord({
    type: "accord/agreement",
    clausesRoot: opened.root,
    clauseCount: opened.count,
    parties: [
      { agent: buyer.publicKey, mandate: mandateId(buyerMandate) },
      { agent: seller.publicKey, mandate: mandateId(sellerMandate) },
    ],
    charter: "accord-charter/0.1",
    createdAt: new Date().toISOString(),
  });
  record = signRecord(record, buyer);
  record = signRecord(record, seller);

  const receipt = await register.append(entryHash(record));
  const cosignatures = witnesses.map((w) => w.observe(receipt.head, []));

  const resolver = staticOwnerResolver({
    "alfa.example": [alfaOwner.publicKey],
    "beta.example": [betaOwner.publicKey],
  });
  const verifyOpts = {
    trustedLogs: [register.publicKey],
    trustedWitnesses: witnesses.map((w) => w.publicKey),
    minWitnesses: 2,
    ownerResolver: resolver,
    // No revocations exist in this scenario; checking them is part of a complete verification.
    revocations: async () => [],
  };

  const proof = (disclosures: ReturnType<typeof import("../src/index.js").disclose>[] = []) =>
    buildProof({ record, mandates: [buyerMandate, sellerMandate], disclosures, receipt, cosignatures });

  return {
    alfaOwner, betaOwner, buyer, seller, register, store, witnesses,
    buyerMandate, sellerMandate, opened, record, receipt, cosignatures, verifyOpts, proof, validity,
  };
}

// A D1 stand-in over node:sqlite, to check the SQL that runs in production.
export function sqliteD1(db: DatabaseSync): D1Like & { exec(sql: string): void } {
  const stmt = (sql: string, values: unknown[] = []) => ({
    bind: (...v: unknown[]) => stmt(sql, v),
    first: async <T>() => (db.prepare(sql).get(...(values as never[])) as T) ?? null,
    all: async <T>() => ({ results: db.prepare(sql).all(...(values as never[])) as T[] }),
    run: async () => db.prepare(sql).run(...(values as never[])),
    sql,
    values,
  });
  return {
    prepare: (sql) => stmt(sql),
    batch: async (stmts) => {
      for (const s of stmts) await s.run();
      return [];
    },
    exec: (sql) => db.exec(sql),
  };
}
