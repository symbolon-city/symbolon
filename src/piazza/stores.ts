// Storage of the piazza: in memory for tests, Cloudflare D1 in production.

import type { D1Like } from "../server/stores.js";
import type { PiazzaStore, StoredContact, StoredPost } from "./app.js";
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
    if (p) p.status = "withdrawn";
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
  async summary(now: string) {
    const active = await this.posts({ now, limit: 1e9 });
    return {
      activePosts: active.length,
      demoPosts: active.filter((p) => p.demo).length,
      owners: new Set(active.map((p) => p.ownerDomain)).size,
      agents: new Set(active.map((p) => p.agent)).size,
      contacts: this.contacts.length,
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
CREATE TABLE IF NOT EXISTS guide_feedback (at TEXT NOT NULL, tier TEXT NOT NULL, stage TEXT, text TEXT NOT NULL);
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
    await this.db.prepare("UPDATE posts SET status = 'withdrawn' WHERE id = ?").bind(id).run();
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
  async summary(now: string) {
    const r = await this.db
      .prepare("SELECT COUNT(*) AS posts, COALESCE(SUM(demo), 0) AS demo, COUNT(DISTINCT owner) AS owners, COUNT(DISTINCT agent) AS agents, (SELECT COUNT(*) FROM contacts) AS contacts FROM posts WHERE status = 'active' AND expires_at > ?")
      .bind(now)
      .first<{ posts: number; demo: number; owners: number; agents: number; contacts: number }>();
    return { activePosts: r?.posts ?? 0, demoPosts: r?.demo ?? 0, owners: r?.owners ?? 0, agents: r?.agents ?? 0, contacts: r?.contacts ?? 0 };
  }
}
