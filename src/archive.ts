// The owner's archive of commitments: every agent of an owner sends, after each change, a sealed snapshot
// of its commitments to a server the owner chooses (its own, or a provider's). The snapshot is signed by the
// agent and sealed with the owner's archive key, so the server checks who sent it but cannot read it; only
// the owner opens it, and sees the commitments of all its agents together. Nothing is kept by Symbolon.

import type { Json } from "./canonical.js";
import { boxProblem, newBoxSecret, openBox, sealBox, type Box, type BoxSecret } from "./channel.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { ownerName, verifyMandateSignature, type Mandate, type Owner } from "./mandate.js";

const BOX_KEY = /^x25519:[0-9a-f]{64}$/;
/** What a snapshot box is bound to, besides sender and owner. */
const CONTEXT = "symbolon/commitments-archive/1";

// ---------- the owner's archive key ----------

export interface ArchiveKeyClaim {
  body: { type: "symbolon/archive-key"; v: 1; owner: Owner; key: string; createdAt: string };
  signature: string;
}

/** `domain` undefined: an owner without a domain (identity level "key"). */
export async function newArchiveKey(owner: KeyPair, domain: string | undefined, now = new Date()): Promise<{ secret: BoxSecret; claim: ArchiveKeyClaim }> {
  const secret = await newBoxSecret();
  const who: Owner = domain === undefined ? { key: owner.publicKey } : { domain, key: owner.publicKey };
  const body = { type: "symbolon/archive-key" as const, v: 1 as const, owner: who, key: "x25519:" + secret.x, createdAt: now.toISOString() };
  return { secret, claim: { body, signature: signValue(body, owner) } };
}

/** Problem with an archive key for this mandate, or null: signed by the mandate's owner key, for its domain. */
export function archiveKeyProblem(c: unknown, mandate: Mandate): string | null {
  const x = c as ArchiveKeyClaim;
  if (!x?.body || typeof x.signature !== "string" || x.body.type !== "symbolon/archive-key" || x.body.v !== 1) return "not an archive key";
  if (typeof x.body.key !== "string" || !BOX_KEY.test(x.body.key)) return "invalid archive key";
  if (!x.body.owner || typeof x.body.owner !== "object" || x.body.owner.key !== mandate.body.owner.key || x.body.owner.domain !== mandate.body.owner.domain || "domain" in x.body.owner !== "domain" in mandate.body.owner)
    return "the archive key is not from this agent's owner";
  if (!verifyValue(x.body, x.signature, x.body.owner.key)) return "the archive key is not signed by the owner";
  return null;
}

// ---------- snapshots ----------

export interface Snapshot {
  body: { type: "symbolon/commitments-snapshot"; v: 1; agent: PublicKey; owner: string; seq: number; at: string; box: Box };
  /** The agent's mandate, so the archive can check that the agent belongs to its owner. */
  mandate: Mandate;
  signature: string;
}

const ctxOf = (agent: PublicKey, ownerKey: PublicKey) => ({ from: agent, to: ownerKey, postId: CONTEXT });

export async function makeSnapshot(agent: KeyPair, mandate: Mandate, claim: ArchiveKeyClaim, seq: number, commitments: Json, now = new Date()): Promise<Snapshot> {
  const box = await sealBox(commitments, claim.body.key, ctxOf(agent.publicKey, mandate.body.owner.key));
  const body = { type: "symbolon/commitments-snapshot" as const, v: 1 as const, agent: agent.publicKey, owner: ownerName(mandate.body.owner), seq, at: now.toISOString(), box };
  return { body, mandate, signature: signValue(body, agent) };
}

/** What the archive server checks: signed by the agent, whose mandate comes from this owner key. */
export function snapshotProblem(s: unknown, ownerKey: PublicKey): string | null {
  const x = s as Snapshot;
  if (!x?.body || !x.mandate || typeof x.signature !== "string" || x.body.type !== "symbolon/commitments-snapshot" || x.body.v !== 1) return "not a snapshot";
  if (!Number.isSafeInteger(x.body.seq) || x.body.seq < 1) return "invalid sequence number";
  const bad = boxProblem(x.body.box);
  if (bad) return bad;
  if (x.mandate.body?.agent !== x.body.agent) return "the mandate is for another agent";
  if (x.mandate.body.owner?.key !== ownerKey) return "the agent's mandate is not from this archive's owner";
  if (!verifyMandateSignature(x.mandate)) return "the mandate signature is invalid";
  if (!verifyValue(x.body, x.signature, x.body.agent)) return "the snapshot is not signed by the agent";
  return null;
}

/** The owner opens a snapshot with the archive secret. */
export async function openSnapshot(s: Snapshot, secret: BoxSecret): Promise<unknown> {
  return openBox(s.body.box, secret, ctxOf(s.body.agent, s.mandate.body.owner.key));
}

// ---------- a minimal archive server (anyone can run it: the owner, an operator, a provider) ----------

export interface ArchiveStore {
  /** Keeps the snapshot if its seq is higher than the one kept for that agent; false otherwise. */
  put(agent: PublicKey, seq: number, snapshot: Snapshot): Promise<boolean>;
  all(): Promise<Snapshot[]>;
}

export class MemoryArchiveStore implements ArchiveStore {
  private byAgent = new Map<string, Snapshot>();
  async put(agent: PublicKey, seq: number, s: Snapshot) {
    const old = this.byAgent.get(agent);
    if (old && old.body.seq >= seq) return false;
    this.byAgent.set(agent, s);
    return true;
  }
  async all() {
    return [...this.byAgent.values()];
  }
}

/**
 * PUT /v1/snapshots (a snapshot) keeps the latest one of each agent of this owner; GET /v1/snapshots lists them.
 * Snapshots are sealed: listing them reveals only which agents exist and when they last changed.
 */
export async function handleArchive(req: Request, deps: { store: ArchiveStore; ownerKey: PublicKey; maxBytes?: number }): Promise<Response> {
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  const json = (data: unknown, status = 200) => new Response(JSON.stringify(data) + "\n", { status, headers: { "content-type": "application/json" } });
  if (path !== "/v1/snapshots") return json({ error: "not found" }, 404);
  if (req.method === "GET") return json({ owner_key: deps.ownerKey, snapshots: await deps.store.all() });
  if (req.method !== "PUT") return json({ error: "use GET or PUT" }, 405);
  const text = await req.text();
  if (text.length > (deps.maxBytes ?? 200_000)) return json({ error: "snapshot too large" }, 413);
  let s: Snapshot;
  try {
    s = JSON.parse(text);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const bad = snapshotProblem(s, deps.ownerKey);
  if (bad) return json({ error: bad }, 400);
  const kept = await deps.store.put(s.body.agent, s.body.seq, s);
  return kept ? json({ ok: true, seq: s.body.seq }, 201) : json({ error: "an equal or newer snapshot of this agent is already kept" }, 409);
}

/** The owner's view: every agent's commitments, opened with the archive secret. */
export async function ownerView(snapshots: Snapshot[], secret: BoxSecret, ownerKey: PublicKey) {
  const agents = [];
  for (const s of snapshots) {
    const bad = snapshotProblem(s, ownerKey);
    if (bad) {
      agents.push({ agent: s?.body?.agent, ignored: bad });
      continue;
    }
    try {
      agents.push({ agent: s.body.agent, scope: s.mandate.body.scope, saved_at: s.body.at, commitments: await openSnapshot(s, secret) });
    } catch (e) {
      agents.push({ agent: s.body.agent, ignored: (e as Error).message });
    }
  }
  return { agents, note: "Commitments of all your agents, as each wallet last saved them." };
}

