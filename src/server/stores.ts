// Storage for the register server: leaves and heads (LogStore), plus anchors
// and witness cosignatures. Memory version for tests, D1 version for Cloudflare.

import type { Anchor } from "../anchor.js";
import type { LogStore, SignedTreeHead } from "../register.js";
import type { RegisteredRevocation } from "../revocation.js";
import type { Cosignature } from "../witness.js";

export type AnchorState = "pending" | "confirmed";

export interface ExtrasStore {
  putAnchor(size: number, anchor: Anchor, state: AnchorState): Promise<void>;
  anchor(size: number): Promise<{ anchor: Anchor; state: AnchorState } | null>;
  latestAnchor(): Promise<{ anchor: Anchor; state: AnchorState } | null>;
  pendingAnchors(): Promise<Anchor[]>;
  addCosignature(c: Cosignature): Promise<void>;
  cosignatures(size: number): Promise<Cosignature[]>;
  /** Stores a sealed revocation under its id and subject. False if that id is already stored. */
  addRevocation(id: string, subject: string, r: RegisteredRevocation): Promise<boolean>;
  revocation(id: string): Promise<RegisteredRevocation | null>;
  /**
   * Revocations about these subjects, by register position, after `after` (default: from the start),
   * at most `limit` (default: all), only those signed by `signers` when given.
   */
  revocationsFor(subjects: string[], opts?: RevocationQuery): Promise<RegisteredRevocation[]>;
}

export interface RevocationQuery {
  signers?: string[];
  after?: number;
  limit?: number;
}

export class MemoryExtras implements ExtrasStore {
  private anchors = new Map<number, { anchor: Anchor; state: AnchorState }>();
  private cosigs = new Map<number, Cosignature[]>();

  async putAnchor(size: number, anchor: Anchor, state: AnchorState) {
    this.anchors.set(size, { anchor, state });
  }
  async anchor(size: number) {
    return this.anchors.get(size) ?? null;
  }
  async latestAnchor() {
    const sizes = [...this.anchors.keys()].sort((a, b) => b - a);
    return sizes.length ? this.anchors.get(sizes[0])! : null;
  }
  async pendingAnchors() {
    return [...this.anchors.values()].filter((a) => a.state === "pending").map((a) => a.anchor);
  }
  async addCosignature(c: Cosignature) {
    const list = this.cosigs.get(c.size) ?? [];
    if (!list.some((x) => x.witness === c.witness)) list.push(c);
    this.cosigs.set(c.size, list);
  }
  async cosignatures(size: number) {
    return this.cosigs.get(size) ?? [];
  }
  private revs = new Map<string, { subject: string; r: RegisteredRevocation }>();
  async addRevocation(id: string, subject: string, r: RegisteredRevocation) {
    if (this.revs.has(id)) return false;
    this.revs.set(id, { subject, r });
    return true;
  }
  async revocation(id: string) {
    return this.revs.get(id)?.r ?? null;
  }
  async revocationsFor(subjects: string[], q: RevocationQuery = {}) {
    return [...this.revs.values()]
      .filter((x) => subjects.includes(x.subject) && (!q.signers || q.signers.includes(x.r.revocation.body.by)) && x.r.index > (q.after ?? -1))
      .map((x) => x.r)
      .sort((a, b) => a.index - b.index)
      .slice(0, q.limit ?? Infinity);
  }
}

// ---------- Cloudflare D1 ----------

/** The part of Cloudflare's D1 API used here. */
export interface D1Like {
  prepare(sql: string): D1Stmt;
  batch(stmts: D1Stmt[]): Promise<unknown>;
}
interface D1Stmt {
  bind(...values: unknown[]): D1Stmt;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  run(): Promise<unknown>;
}

export const SCHEMA = `
CREATE TABLE IF NOT EXISTS leaves (idx INTEGER PRIMARY KEY, entry TEXT NOT NULL, leaf TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS leaves_entry ON leaves(entry);
CREATE TABLE IF NOT EXISTS heads (size INTEGER PRIMARY KEY, head TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS anchors (size INTEGER PRIMARY KEY, anchor TEXT NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cosignatures (size INTEGER NOT NULL, witness TEXT NOT NULL, cosig TEXT NOT NULL, PRIMARY KEY (size, witness));
CREATE TABLE IF NOT EXISTS daily_writes (day TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS revocations (id TEXT PRIMARY KEY, subject TEXT NOT NULL, idx INTEGER NOT NULL, time TEXT NOT NULL, revocation TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS revocations_subject ON revocations(subject);
CREATE TABLE IF NOT EXISTS daily_stats (day TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, kind));
`;

/**
 * Daily caps (UTC day): plain entries and cosignatures share one counter, revocations have their own,
 * so that filling the register with fingerprints can never stop an owner from revoking.
 */
export type CapBucket = "entries" | "revocations";
const capKey = (bucket: CapBucket, now: Date) => {
  const day = now.toISOString().slice(0, 10);
  return bucket === "entries" ? day : `${day}:${bucket}`;
};

/**
 * The key of one daily counter: the bucket's total for the day, or, with `parts`, a counter inside it (for
 * example "client", <client key> or "signer", <key>). Every key starts with the UTC day, so old counters are
 * removed by date (pruneDailyWrites).
 */
export function dailyKey(now: Date, bucket: CapBucket, ...parts: string[]): string {
  const base = capKey(bucket, now);
  return parts.length ? `${now.toISOString().slice(0, 10)}:${bucket}:${parts.join(":")}` : base;
}

/** The value of one daily counter (0 if never counted). */
export async function dailyCount(db: D1Like, key: string): Promise<number> {
  const r = await db.prepare("SELECT n FROM daily_writes WHERE day = ?").bind(key).first<{ n: number }>();
  return r?.n ?? 0;
}

/** Adds one to each of these daily counters. */
export async function countDailyKeys(db: D1Like, keys: string[]): Promise<void> {
  if (!keys.length) return;
  await db.batch(keys.map((k) => db.prepare("INSERT INTO daily_writes (day, n) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET n = n + 1").bind(k)));
}

/** Removes the counters of days before yesterday (UTC): per-client and per-key counters are many. */
export async function pruneDailyWrites(db: D1Like, now = new Date()): Promise<void> {
  const yesterday = new Date(now.getTime() - 86_400_000).toISOString().slice(0, 10);
  await db.prepare("DELETE FROM daily_writes WHERE day < ?").bind(yesterday).run();
}

/** Today's count of successful writes in this bucket. */
export async function dailyWrites(db: D1Like, bucket: CapBucket, now = new Date()): Promise<number> {
  return dailyCount(db, capKey(bucket, now));
}

/** Counts one successful write in this bucket. */
export async function countDailyWrite(db: D1Like, bucket: CapBucket, now = new Date()): Promise<void> {
  await countDailyKeys(db, [capKey(bucket, now)]);
}

const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));
const bytesToHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

export class D1Store implements LogStore, ExtrasStore {
  constructor(private readonly db: D1Like) {}

  async size() {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM leaves").first<{ n: number }>();
    return r?.n ?? 0;
  }
  async leaves(count: number) {
    const r = await this.db.prepare("SELECT leaf FROM leaves WHERE idx < ? ORDER BY idx").bind(count).all<{ leaf: string }>();
    return r.results.map((x) => hexToBytes(x.leaf));
  }
  async appendLeaf(index: number, entry: string, leaf: Uint8Array, head: SignedTreeHead) {
    try {
      await this.db.batch([
        this.db.prepare("INSERT INTO leaves (idx, entry, leaf) VALUES (?, ?, ?)").bind(index, entry, bytesToHex(leaf)),
        this.db.prepare("INSERT OR REPLACE INTO heads (size, head) VALUES (?, ?)").bind(head.size, JSON.stringify(head)),
      ]);
      return true;
    } catch (e) {
      if (/UNIQUE|PRIMARY KEY|constraint/i.test(String(e))) return false;
      throw e;
    }
  }
  async putHead(head: SignedTreeHead) {
    await this.db.prepare("INSERT OR REPLACE INTO heads (size, head) VALUES (?, ?)").bind(head.size, JSON.stringify(head)).run();
  }
  async head(size: number) {
    const r = await this.db.prepare("SELECT head FROM heads WHERE size = ?").bind(size).first<{ head: string }>();
    return r ? (JSON.parse(r.head) as SignedTreeHead) : null;
  }
  async indexOf(entry: string) {
    const r = await this.db.prepare("SELECT idx FROM leaves WHERE entry = ? ORDER BY idx LIMIT 1").bind(entry).first<{ idx: number }>();
    return r ? r.idx : null;
  }
  async entries(from: number, limit: number) {
    const r = await this.db.prepare("SELECT entry FROM leaves WHERE idx >= ? ORDER BY idx LIMIT ?").bind(from, limit).all<{ entry: string }>();
    return r.results.map((x) => x.entry);
  }

  async putAnchor(size: number, anchor: Anchor, state: AnchorState) {
    await this.db
      .prepare("INSERT OR REPLACE INTO anchors (size, anchor, state) VALUES (?, ?, ?)")
      .bind(size, JSON.stringify(anchor), state)
      .run();
  }
  async anchor(size: number) {
    const r = await this.db.prepare("SELECT anchor, state FROM anchors WHERE size = ?").bind(size).first<{ anchor: string; state: AnchorState }>();
    return r ? { anchor: JSON.parse(r.anchor) as Anchor, state: r.state } : null;
  }
  async latestAnchor() {
    const r = await this.db.prepare("SELECT anchor, state FROM anchors ORDER BY size DESC LIMIT 1").first<{ anchor: string; state: AnchorState }>();
    return r ? { anchor: JSON.parse(r.anchor) as Anchor, state: r.state } : null;
  }
  async pendingAnchors() {
    const r = await this.db.prepare("SELECT anchor FROM anchors WHERE state = 'pending'").all<{ anchor: string }>();
    return r.results.map((x) => JSON.parse(x.anchor) as Anchor);
  }
  async addCosignature(c: Cosignature) {
    await this.db
      .prepare("INSERT OR IGNORE INTO cosignatures (size, witness, cosig) VALUES (?, ?, ?)")
      .bind(c.size, c.witness, JSON.stringify(c))
      .run();
  }
  async cosignatures(size: number) {
    const r = await this.db.prepare("SELECT cosig FROM cosignatures WHERE size = ?").bind(size).all<{ cosig: string }>();
    return r.results.map((x) => JSON.parse(x.cosig) as Cosignature);
  }
  async addRevocation(id: string, subject: string, r: RegisteredRevocation) {
    try {
      await this.db
        .prepare("INSERT INTO revocations (id, subject, idx, time, revocation) VALUES (?, ?, ?, ?, ?)")
        .bind(id, subject, r.index, r.time, JSON.stringify(r.revocation))
        .run();
      return true;
    } catch (e) {
      if (/UNIQUE|PRIMARY KEY|constraint/i.test(String(e))) return false;
      throw e;
    }
  }
  async revocation(id: string) {
    const r = await this.db.prepare("SELECT idx, time, revocation FROM revocations WHERE id = ?").bind(id).first<RevRow>();
    return r ? fromRevRow(r) : null;
  }
  async revocationsFor(subjects: string[], q: RevocationQuery = {}) {
    if (!subjects.length) return [];
    const marks = (xs: string[]) => xs.map(() => "?").join(", ");
    const bySigner = q.signers?.length ? ` AND json_extract(revocation, '$.body.by') IN (${marks(q.signers)})` : "";
    const limit = q.limit === undefined ? "" : " LIMIT ?";
    const r = await this.db
      .prepare(`SELECT idx, time, revocation FROM revocations WHERE subject IN (${marks(subjects)})${bySigner} AND idx > ? ORDER BY idx${limit}`)
      .bind(...subjects, ...(q.signers?.length ? q.signers : []), q.after ?? -1, ...(q.limit === undefined ? [] : [q.limit]))
      .all<RevRow>();
    return r.results.map(fromRevRow);
  }
}

interface RevRow {
  idx: number;
  time: string;
  revocation: string;
}
const fromRevRow = (r: RevRow): RegisteredRevocation => ({ revocation: JSON.parse(r.revocation), index: r.idx, time: r.time });
