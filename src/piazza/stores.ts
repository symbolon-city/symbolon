// Storage of the piazza: in memory for tests, Cloudflare D1 in production.

import type { D1Like } from "../server/stores.js";
import type { PiazzaStore, PiazzaSummary, StoredContact, StoredMessage, StoredPost, StoredRemoval, StoredReport } from "./app.js";
import type { BoxKeyClaim } from "../channel.js";
import type { Tier } from "./guide.js";
import { inSite } from "./site.js";

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
  async posts(f: { kind?: string; category?: string; now: string; limit: number; offset?: number }) {
    return [...this.postsById.values()]
      .filter((p) => p.status === "active" && p.content.expiresAt > f.now && (!f.kind || p.content.kind === f.kind) && (!f.category || p.content.category === f.category))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(f.offset ?? 0, (f.offset ?? 0) + f.limit);
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
  async countPostsByOwner(site: string, since: string) {
    return [...this.postsById.values()].filter((p) => inSite(p.ownerDomain, site) && p.createdAt >= since).length;
  }
  async countActiveByOwner(site: string, now: string) {
    return [...this.postsById.values()].filter((p) => inSite(p.ownerDomain, site) && p.status === "active" && p.content.expiresAt > now).length;
  }
  async agentsOfOwner(site: string) {
    const fromPosts = [...this.postsById.values()].filter((p) => inSite(p.ownerDomain, site)).map((p) => p.agent);
    const fromContacts = this.contacts.filter((c) => inSite(c.fromOwner, site)).map((c) => c.fromAgent);
    return [...new Set([...fromPosts, ...fromContacts])];
  }
  async newOwnerDomains(since: string) {
    const first = new Map<string, string>();
    for (const [d, at] of [...[...this.postsById.values()].map((p) => [p.ownerDomain, p.createdAt]), ...this.contacts.map((c) => [c.fromOwner, c.createdAt])])
      if (!first.has(d) || at < first.get(d)!) first.set(d, at);
    return [...first].filter(([, at]) => at >= since).map(([d]) => d);
  }
  async addContact(c: StoredContact) {
    if (this.contacts.some((x) => x.postId === c.postId && x.fromAgent === c.fromAgent)) return false;
    this.contacts.push(c);
    return true;
  }
  async countContactsByAgent(agent: string, since: string) {
    return this.contacts.filter((c) => c.fromAgent === agent && c.createdAt >= since).length;
  }
  async inbox(agent: string, before?: string) {
    return this.contacts
      .filter((c) => this.postsById.get(c.postId)?.agent === agent && (!before || c.createdAt < before))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, 200)
      .map((c) => ({ ...c, postTitle: this.postsById.get(c.postId)!.content.title }));
  }
  async hasContact(postId: string, agent: string) {
    return this.contacts.some((c) => c.postId === postId && c.fromAgent === agent && c.reply !== "not_for_us");
  }
  private boxKeys = new Map<string, BoxKeyClaim>();
  private messages: StoredMessage[] = [];
  async putBoxKey(agent: string, claim: BoxKeyClaim) {
    this.boxKeys.set(agent, claim);
  }
  async boxKey(agent: string) {
    return this.boxKeys.get(agent) ?? null;
  }
  async addMessage(m: StoredMessage) {
    this.messages.push(m);
  }
  async countMessagesByAgent(agent: string, since: string) {
    return this.messages.filter((m) => m.fromAgent === agent && m.createdAt >= since).length;
  }
  async messagesFor(agent: string, after: { at: string; id: string }, notBefore: string, limit: number) {
    return this.messages
      .filter((m) => m.toAgent === agent && (m.createdAt > after.at || (m.createdAt === after.at && m.id > after.id)) && m.createdAt >= notBefore)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id))
      .slice(0, limit);
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
  async summary(now: string, siteOf: (d: string) => string = (d) => d): Promise<PiazzaSummary> {
    const active = await this.posts({ now, limit: 1e9 });
    return {
      activePosts: active.length,
      demoPosts: active.filter((p) => p.demo).length,
      owners: new Set(active.map((p) => siteOf(p.ownerDomain))).size,
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
CREATE TABLE IF NOT EXISTS box_keys (agent TEXT PRIMARY KEY, claim TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, to_agent TEXT NOT NULL, from_agent TEXT NOT NULL, from_owner TEXT NOT NULL, post_id TEXT NOT NULL, envelope TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS messages_to ON messages (to_agent, created_at);
CREATE INDEX IF NOT EXISTS messages_from ON messages (from_agent, created_at);
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
    } catch {
      return false;
    }
    // Now and then, forget nonces older than an hour: envelopes older than a few minutes are refused anyway.
    if (Math.random() < 0.01)
      await this.db.prepare("DELETE FROM nonces WHERE at < ?").bind(new Date(Date.parse(at) - 3_600_000).toISOString()).run().catch(() => {});
    return true;
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
  async posts(f: { kind?: string; category?: string; now: string; limit: number; offset?: number }) {
    const r = await this.db
      .prepare("SELECT * FROM posts WHERE status = 'active' AND expires_at > ? AND (? IS NULL OR kind = ?) AND (? IS NULL OR category = ?) ORDER BY created_at DESC LIMIT ? OFFSET ?")
      .bind(f.now, f.kind ?? null, f.kind ?? null, f.category ?? null, f.category ?? null, f.limit, f.offset ?? 0)
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
  // A site matches its own domain and every subdomain (domains are checked lowercase letters, digits,
  // hyphens and dots, so they hold no LIKE wildcards).
  async countPostsByOwner(site: string, since: string) {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM posts WHERE (owner = ? OR owner LIKE ?) AND created_at >= ?").bind(site, "%." + site, since).first<{ n: number }>();
    return r?.n ?? 0;
  }
  async countActiveByOwner(site: string, now: string) {
    const r = await this.db
      .prepare("SELECT COUNT(*) AS n FROM posts WHERE (owner = ? OR owner LIKE ?) AND status = 'active' AND expires_at > ?")
      .bind(site, "%." + site, now)
      .first<{ n: number }>();
    return r?.n ?? 0;
  }
  async agentsOfOwner(site: string) {
    const r = await this.db
      .prepare("SELECT agent FROM posts WHERE owner = ? OR owner LIKE ? UNION SELECT from_agent AS agent FROM contacts WHERE from_owner = ? OR from_owner LIKE ?")
      .bind(site, "%." + site, site, "%." + site)
      .all<{ agent: string }>();
    return r.results.map((x) => x.agent);
  }
  async newOwnerDomains(since: string) {
    const r = await this.db
      .prepare(
        "SELECT owner FROM (SELECT owner, created_at FROM posts UNION ALL SELECT from_owner AS owner, created_at FROM contacts) GROUP BY owner HAVING MIN(created_at) >= ? LIMIT 2000",
      )
      .bind(since)
      .all<{ owner: string }>();
    return r.results.map((x) => x.owner);
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
  async inbox(agent: string, before?: string) {
    const r = await this.db
      .prepare("SELECT c.*, p.content AS post_content FROM contacts c JOIN posts p ON p.id = c.post_id WHERE p.agent = ? AND (? IS NULL OR c.created_at < ?) ORDER BY c.created_at DESC LIMIT 200")
      .bind(agent, before ?? null, before ?? null)
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
  async hasContact(postId: string, agent: string) {
    return !!(await this.db.prepare("SELECT 1 AS x FROM contacts WHERE post_id = ? AND from_agent = ? AND reply != 'not_for_us'").bind(postId, agent).first<{ x: number }>());
  }
  async putBoxKey(agent: string, claim: BoxKeyClaim, at: string) {
    await this.db.prepare("INSERT OR REPLACE INTO box_keys (agent, claim, updated_at) VALUES (?, ?, ?)").bind(agent, JSON.stringify(claim), at).run();
  }
  async boxKey(agent: string) {
    const r = await this.db.prepare("SELECT claim FROM box_keys WHERE agent = ?").bind(agent).first<{ claim: string }>();
    return r ? (JSON.parse(r.claim) as BoxKeyClaim) : null;
  }
  async addMessage(m: StoredMessage) {
    await this.db
      .prepare("INSERT OR IGNORE INTO messages (id, to_agent, from_agent, from_owner, post_id, envelope, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(m.id, m.toAgent, m.fromAgent, m.fromOwner, m.postId, JSON.stringify(m.envelope), m.createdAt)
      .run();
  }
  async countMessagesByAgent(agent: string, since: string) {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM messages WHERE from_agent = ? AND created_at >= ?").bind(agent, since).first<{ n: number }>();
    return r?.n ?? 0;
  }
  async messagesFor(agent: string, after: { at: string; id: string }, notBefore: string, limit: number) {
    const r = await this.db
      .prepare("SELECT * FROM messages WHERE to_agent = ? AND (created_at > ? OR (created_at = ? AND id > ?)) AND created_at >= ? ORDER BY created_at, id LIMIT ?")
      .bind(agent, after.at, after.at, after.id, notBefore, limit)
      .all<{ id: string; to_agent: string; from_agent: string; from_owner: string; post_id: string; envelope: string; created_at: string }>();
    return r.results.map((x) => ({
      id: x.id,
      toAgent: x.to_agent,
      fromAgent: x.from_agent,
      fromOwner: x.from_owner,
      postId: x.post_id,
      envelope: JSON.parse(x.envelope),
      createdAt: x.created_at,
    }));
  }
  async summary(now: string, siteOf?: (d: string) => string): Promise<PiazzaSummary> {
    const sites = siteOf
      ? new Set(
          (await this.db.prepare("SELECT DISTINCT owner FROM posts WHERE status = 'active' AND expires_at > ?").bind(now).all<{ owner: string }>()).results.map((x) => siteOf(x.owner)),
        ).size
      : null;
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
      owners: sites ?? r?.owners ?? 0,
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
