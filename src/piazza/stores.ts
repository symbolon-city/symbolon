// Storage of the piazza: in memory for tests, Cloudflare D1 in production.

import type { D1Like } from "../server/stores.js";
import type { PiazzaStore, PiazzaSummary, StoredContact, StoredPost, StoredRemoval, StoredReport } from "./app.js";
import type { Tier } from "./guide.js";

export class MemoryPiazzaStore implements PiazzaStore {
  private nonces = new Set<string>();
  private postsById = new Map<string, StoredPost>();
  private contacts: StoredContact[] = [];
  private answers = new Map<string, string>();
  private counters = new Map<string, number>();
  readonly feedback: Array<{ at: string; tier: Tier; stage: string | null; text: string }> = [];

  async cachedAnswer(key: string) {
    return this.answers.get(key) ?? null;
  }
  async saveAnswer(key: string, _q: string, answer: string) {
    this.answers.set(key, answer);
  }
  async bump(day: string, name: string, by = 1) {
    const k = day + "|" + name;
    const n = (this.counters.get(k) ?? 0) + by;
    this.counters.set(k, n);
    return n;
  }
  async counter(day: string, name: string) {
    return this.counters.get(day + "|" + name) ?? 0;
  }
  async addFeedback(f: { at: string; tier: Tier; stage: string | null; text: string }) {
    this.feedback.push(f);
  }

  async useNonce(nonce: string) {
    if (this.nonces.has(nonce)) return false;
    this.nonces.add(nonce);
    return true;
  }
  async addPost(p: StoredPost) {
    this.postsById.set(p.id, { ...p });
  }
  async setRegisterIndex(id: string, index: number) {
    const p = this.postsById.get(id);
    if (p) p.registerIndex = index;
  }
  async post(id: string) {
    return this.postsById.get(id) ?? null;
  }
  async posts(f: { kind?: string; category?: string; now: string; limit: number }) {
    return [...this.postsById.values()]
      .filter((p) => p.status === "active" && p.content.expiresAt > f.now && (!f.kind || p.content.kind === f.kind) && (!f.category || p.content.category === f.category))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, f.limit);
  }
  async withdraw(id: string) {
    const p = this.postsById.get(id);
    if (p && p.status === "active") p.status = "withdrawn";
  }
  private proofs: Array<{ entry: string; at: string; proof: unknown }> = [];
  async addDemoProof(entry: string, at: string, proof: unknown) {
    if (!this.proofs.some((x) => x.entry === entry)) this.proofs.unshift({ entry, at, proof });
  }
  async demoProofs(limit: number) {
    return this.proofs.slice(0, limit);
  }
  async markRevoked(id: string) {
    const p = this.postsById.get(id);
    if (p && p.status === "active") p.status = "revoked";
  }
  async countPostsByOwner(owner: string, since: string) {
    return [...this.postsById.values()].filter((p) => p.ownerDomain === owner && p.createdAt >= since).length;
  }
  async countActiveByOwner(owner: string, now: string) {
    return [...this.postsById.values()].filter((p) => p.ownerDomain === owner && p.status === "active" && p.content.expiresAt > now).length;
  }
  async agentsOfOwner(owner: string) {
    const fromPosts = [...this.postsById.values()].filter((p) => p.ownerDomain === owner).map((p) => p.agent);
    const fromContacts = this.contacts.filter((c) => c.fromOwner === owner).map((c) => c.fromAgent);
    return [...new Set([...fromPosts, ...fromContacts])];
  }
  async addContact(c: StoredContact) {
    if (this.contacts.some((x) => x.postId === c.postId && x.fromAgent === c.fromAgent)) return false;
    this.contacts.push(c);
    return true;
  }
  async countContactsByAgent(agent: string, since: string) {
    return this.contacts.filter((c) => c.fromAgent === agent && c.createdAt >= since).length;
  }
  async inbox(agent: string) {
    return this.contacts
      .filter((c) => this.postsById.get(c.postId)?.agent === agent)
      .map((c) => ({ ...c, postTitle: this.postsById.get(c.postId)!.content.title }));
  }
  readonly reports: StoredReport[] = [];
  private removalsList: StoredRemoval[] = [];
  private sealedDocs = new Map<string, number>();
  async addReport(r: StoredReport) {
    this.reports.push({ ...r });
  }
  async addRemoval(r: StoredRemoval) {
    this.removalsList = [{ ...r }, ...this.removalsList.filter((x) => x.postId !== r.postId)];
    const p = this.postsById.get(r.postId);
    if (p) p.status = "removed";
  }
  async removals(limit: number) {
    return [...this.removalsList].sort((a, b) => b.removedAt.localeCompare(a.removedAt)).slice(0, limit);
  }
  async sealedDoc(fp: string) {
    return this.sealedDocs.get(fp) ?? null;
  }
  async setSealedDoc(fp: string, index: number) {
    if (!this.sealedDocs.has(fp)) this.sealedDocs.set(fp, index);
  }
  async summary(now: string): Promise<PiazzaSummary> {
    const active = await this.posts({ now, limit: 1e9 });
    return {
      activePosts: active.length,
      demoPosts: active.filter((p) => p.demo).length,
      owners: new Set(active.map((p) => p.ownerDomain)).size,
      agents: new Set(active.map((p) => p.agent)).size,
      contacts: this.contacts.length,
      reports: this.reports.length,
      removals: this.removalsList.length,
    };
  }
}

export const PIAZZA_SCHEMA = `
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, agent TEXT NOT NULL, owner TEXT NOT NULL, kind TEXT NOT NULL, category TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL, demo INTEGER NOT NULL, register_index INTEGER, mandate TEXT);
CREATE INDEX IF NOT EXISTS posts_owner ON posts(owner, created_at);
CREATE TABLE IF NOT EXISTS contacts (post_id TEXT NOT NULL, from_agent TEXT NOT NULL, from_owner TEXT NOT NULL, mandate TEXT NOT NULL, reply TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (post_id, from_agent));
CREATE TABLE IF NOT EXISTS daily_stats (day TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, kind));
CREATE TABLE IF NOT EXISTS guide_answers (key TEXT PRIMARY KEY, question TEXT NOT NULL, answer TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS guide_counters (day TEXT NOT NULL, name TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, name));
CREATE TABLE IF NOT EXISTS demo_proofs (entry TEXT PRIMARY KEY, at TEXT NOT NULL, proof TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS guide_feedback (at TEXT NOT NULL, tier TEXT NOT NULL, stage TEXT, text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (post_id TEXT NOT NULL, reason TEXT NOT NULL, text TEXT, tier TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS removals (post_id TEXT PRIMARY KEY, owner TEXT NOT NULL, agent TEXT NOT NULL, removed_at TEXT NOT NULL, reason TEXT NOT NULL, basis TEXT NOT NULL, clause TEXT NOT NULL, rules_version INTEGER NOT NULL, fingerprint TEXT NOT NULL, register_index INTEGER, owner_reply TEXT, correction TEXT);
CREATE TABLE IF NOT EXISTS sealed_docs (fingerprint TEXT PRIMARY KEY, register_index INTEGER NOT NULL, at TEXT NOT NULL);
`;

/** Changes to tables created before them; each may fail harmlessly if already applied. */
export const PIAZZA_MIGRATIONS = ["ALTER TABLE posts ADD COLUMN mandate TEXT"];

type PostRow = { id: string; agent: string; owner: string; content: string; created_at: string; status: string; demo: number; register_index: number | null; mandate?: string | null };
const toPost = (r: PostRow): StoredPost => ({
  id: r.id,
  agent: r.agent,
  ownerDomain: r.owner,
  content: JSON.parse(r.content),
  createdAt: r.created_at,
  status: r.status as StoredPost["status"],
  demo: r.demo === 1,
  registerIndex: r.register_index,
  mandate: r.mandate ? JSON.parse(r.mandate) : null,
});

export class D1PiazzaStore implements PiazzaStore {
  constructor(private readonly db: D1Like) {}
  async cachedAnswer(key: string) {
    const r = await this.db.prepare("SELECT answer FROM guide_answers WHERE key = ?").bind(key).first<{ answer: string }>();
    return r?.answer ?? null;
  }
  async saveAnswer(key: string, question: string, answer: string, at: string) {
    await this.db.prepare("INSERT OR REPLACE INTO guide_answers (key, question, answer, at) VALUES (?, ?, ?, ?)").bind(key, question, answer, at).run();
  }
  async bump(day: string, name: string, by = 1) {
    const r = await this.db
      .prepare("INSERT INTO guide_counters (day, name, n) VALUES (?, ?, ?) ON CONFLICT (day, name) DO UPDATE SET n = n + excluded.n RETURNING n")
      .bind(day, name, by)
      .first<{ n: number }>();
    return r?.n ?? by;
  }
  async counter(day: string, name: string) {
    const r = await this.db.prepare("SELECT n FROM guide_counters WHERE day = ? AND name = ?").bind(day, name).first<{ n: number }>();
    return r?.n ?? 0;
  }
  async addFeedback(f: { at: string; tier: Tier; stage: string | null; text: string }) {
    await this.db.prepare("INSERT INTO guide_feedback (at, tier, stage, text) VALUES (?, ?, ?, ?)").bind(f.at, f.tier, f.stage, f.text).run();
  }
  async useNonce(nonce: string, at: string) {
    try {
      await this.db.prepare("INSERT INTO nonces (nonce, at) VALUES (?, ?)").bind(nonce, at).run();
      return true;
    } catch {
      return false;
    }
  }
  async addPost(p: StoredPost) {
    await this.db
      .prepare("INSERT INTO posts (id, agent, owner, kind, category, content, created_at, expires_at, status, demo, register_index, mandate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(p.id, p.agent, p.ownerDomain, p.content.kind, p.content.category, JSON.stringify(p.content), p.createdAt, p.content.expiresAt, p.status, p.demo ? 1 : 0, p.registerIndex, p.mandate ? JSON.stringify(p.mandate) : null)
      .run();
  }
  async setRegisterIndex(id: string, index: number) {
    await this.db.prepare("UPDATE posts SET register_index = ? WHERE id = ?").bind(index, id).run();
  }
  async post(id: string) {
    const r = await this.db.prepare("SELECT * FROM posts WHERE id = ?").bind(id).first<PostRow>();
    return r ? toPost(r) : null;
  }
  async posts(f: { kind?: string; category?: string; now: string; limit: number }) {
    const r = await this.db
      .prepare("SELECT * FROM posts WHERE status = 'active' AND expires_at > ? AND (? IS NULL OR kind = ?) AND (? IS NULL OR category = ?) ORDER BY created_at DESC LIMIT ?")
      .bind(f.now, f.kind ?? null, f.kind ?? null, f.category ?? null, f.category ?? null, f.limit)
      .all<PostRow>();
    return r.results.map(toPost);
  }
  async withdraw(id: string) {
    await this.db.prepare("UPDATE posts SET status = 'withdrawn' WHERE id = ? AND status = 'active'").bind(id).run();
  }
  async addDemoProof(entry: string, at: string, proof: unknown) {
    await this.db.prepare("INSERT OR IGNORE INTO demo_proofs (entry, at, proof) VALUES (?, ?, ?)").bind(entry, at, JSON.stringify(proof)).run();
  }
  async demoProofs(limit: number) {
    const r = await this.db.prepare("SELECT entry, at, proof FROM demo_proofs ORDER BY at DESC LIMIT ?").bind(limit).all<{ entry: string; at: string; proof: string }>();
    return r.results.map((x) => ({ entry: x.entry, at: x.at, proof: JSON.parse(x.proof) as unknown }));
  }
  async markRevoked(id: string) {
    await this.db.prepare("UPDATE posts SET status = 'revoked' WHERE id = ? AND status = 'active'").bind(id).run();
  }
  async countPostsByOwner(owner: string, since: string) {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM posts WHERE owner = ? AND created_at >= ?").bind(owner, since).first<{ n: number }>();
    return r?.n ?? 0;
  }
  async countActiveByOwner(owner: string, now: string) {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM posts WHERE owner = ? AND status = 'active' AND expires_at > ?").bind(owner, now).first<{ n: number }>();
    return r?.n ?? 0;
  }
  async agentsOfOwner(owner: string) {
    const r = await this.db
      .prepare("SELECT agent FROM posts WHERE owner = ? UNION SELECT from_agent AS agent FROM contacts WHERE from_owner = ?")
      .bind(owner, owner)
      .all<{ agent: string }>();
    return r.results.map((x) => x.agent);
  }
  async addContact(c: StoredContact) {
    try {
      await this.db
        .prepare("INSERT INTO contacts (post_id, from_agent, from_owner, mandate, reply, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(c.postId, c.fromAgent, c.fromOwner, JSON.stringify(c.fromMandate), c.reply, c.createdAt)
        .run();
      return true;
    } catch {
      return false;
    }
  }
  async countContactsByAgent(agent: string, since: string) {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM contacts WHERE from_agent = ? AND created_at >= ?").bind(agent, since).first<{ n: number }>();
    return r?.n ?? 0;
  }
  async inbox(agent: string) {
    const r = await this.db
      .prepare("SELECT c.*, p.content AS post_content FROM contacts c JOIN posts p ON p.id = c.post_id WHERE p.agent = ? ORDER BY c.created_at DESC LIMIT 200")
      .bind(agent)
      .all<{ post_id: string; from_agent: string; from_owner: string; mandate: string; reply: string; created_at: string; post_content: string }>();
    return r.results.map((x) => ({
      postId: x.post_id,
      fromAgent: x.from_agent,
      fromOwner: x.from_owner,
      fromMandate: JSON.parse(x.mandate),
      reply: x.reply as StoredContact["reply"],
      createdAt: x.created_at,
      postTitle: JSON.parse(x.post_content).title,
    }));
  }
  async summary(now: string): Promise<PiazzaSummary> {
    const r = await this.db
      .prepare(
        "SELECT COUNT(*) AS posts, COALESCE(SUM(demo), 0) AS demo, COUNT(DISTINCT owner) AS owners, COUNT(DISTINCT agent) AS agents, " +
          "(SELECT COUNT(*) FROM contacts) AS contacts, (SELECT COUNT(*) FROM reports) AS reports, (SELECT COUNT(*) FROM removals) AS removals " +
          "FROM posts WHERE status = 'active' AND expires_at > ?",
      )
      .bind(now)
      .first<{ posts: number; demo: number; owners: number; agents: number; contacts: number; reports: number; removals: number }>();
    return {
      activePosts: r?.posts ?? 0,
      demoPosts: r?.demo ?? 0,
      owners: r?.owners ?? 0,
      agents: r?.agents ?? 0,
      contacts: r?.contacts ?? 0,
      reports: r?.reports ?? 0,
      removals: r?.removals ?? 0,
    };
  }
  async addReport(r: StoredReport) {
    await this.db.prepare("INSERT INTO reports (post_id, reason, text, tier, at) VALUES (?, ?, ?, ?, ?)").bind(r.postId, r.reason, r.text, r.tier, r.at).run();
  }
  async addRemoval(r: StoredRemoval) {
    await this.db.batch(removalStatements(r).map(([sql, ...values]) => this.db.prepare(sql as string).bind(...values)));
  }
  async removals(limit: number) {
    const r = await this.db.prepare("SELECT * FROM removals ORDER BY removed_at DESC LIMIT ?").bind(limit).all<RemovalRow>();
    return r.results.map((x) => ({
      postId: x.post_id,
      ownerDomain: x.owner,
      agent: x.agent,
      removedAt: x.removed_at,
      reason: x.reason as StoredRemoval["reason"],
      basis: x.basis,
      clause: x.clause,
      rulesVersion: x.rules_version,
      fingerprint: x.fingerprint,
      registerIndex: x.register_index,
      ownerReply: x.owner_reply,
      correction: x.correction,
    }));
  }
  async sealedDoc(fp: string) {
    const r = await this.db.prepare("SELECT register_index FROM sealed_docs WHERE fingerprint = ?").bind(fp).first<{ register_index: number }>();
    return r?.register_index ?? null;
  }
  async setSealedDoc(fp: string, index: number, at: string) {
    await this.db.prepare("INSERT OR IGNORE INTO sealed_docs (fingerprint, register_index, at) VALUES (?, ?, ?)").bind(fp, index, at).run();
  }
}

type RemovalRow = {
  post_id: string;
  owner: string;
  agent: string;
  removed_at: string;
  reason: string;
  basis: string;
  clause: string;
  rules_version: number;
  fingerprint: string;
  register_index: number | null;
  owner_reply: string | null;
  correction: string | null;
};

/** The statements that record a removal and take the post off the board, as [sql, ...values]. */
export function removalStatements(r: StoredRemoval): unknown[][] {
  return [
    [
      "INSERT OR REPLACE INTO removals (post_id, owner, agent, removed_at, reason, basis, clause, rules_version, fingerprint, register_index, owner_reply, correction) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      r.postId, r.ownerDomain, r.agent, r.removedAt, r.reason, r.basis, r.clause, r.rulesVersion, r.fingerprint, r.registerIndex, r.ownerReply, r.correction,
    ],
    ["UPDATE posts SET status = 'removed' WHERE id = ?", r.postId],
  ];
}

/** The same statements as plain SQL text, for `wrangler d1 execute --file` (scripts/piazza-remove.ts). */
export function toSqlText(statements: unknown[][]): string {
  const lit = (v: unknown) =>
    v === null || v === undefined ? "NULL" : typeof v === "number" && Number.isSafeInteger(v) ? String(v) : "'" + String(v).replace(/'/g, "''") + "'";
  return (
    statements
      .map(([sql, ...values]) => {
        let i = 0;
        return (sql as string).replace(/\?/g, () => lit(values[i++])) + ";";
      })
      .join("\n") + "\n"
  );
}
