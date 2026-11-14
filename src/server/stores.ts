// Storage for the register server: leaves and heads (LogStore), plus anchors
// and witness cosignatures. Memory version for tests, D1 version for Cloudflare.

import type { Anchor } from "../anchor.js";
import type { LogStore, SignedTreeHead } from "../register.js";
import type { Cosignature } from "../witness.js";

export type AnchorState = "pending" | "confirmed";

export interface ExtrasStore {
  putAnchor(size: number, anchor: Anchor, state: AnchorState): Promise<void>;
  anchor(size: number): Promise<{ anchor: Anchor; state: AnchorState } | null>;
  latestAnchor(): Promise<{ anchor: Anchor; state: AnchorState } | null>;
  pendingAnchors(): Promise<Anchor[]>;
  addCosignature(c: Cosignature): Promise<void>;
  cosignatures(size: number): Promise<Cosignature[]>;
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
CREATE TABLE IF NOT EXISTS daily_stats (day TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, kind));
`;

/** Counts today's writes (UTC day) and returns the new total. Used by the daily cap. */
export async function countDailyWrite(db: D1Like, now = new Date()): Promise<number> {
  const day = now.toISOString().slice(0, 10);
  await db.prepare("INSERT INTO daily_writes (day, n) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET n = n + 1").bind(day).run();
  const r = await db.prepare("SELECT n FROM daily_writes WHERE day = ?").bind(day).first<{ n: number }>();
  return r?.n ?? 0;
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
}
