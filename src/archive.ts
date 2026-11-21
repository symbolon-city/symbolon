// The owner's archive of commitments: every agent of an owner sends, after each change, a sealed snapshot
// of its commitments to a server the owner chooses (its own, or a provider's). The snapshot is signed by the
// agent and sealed with the owner's archive key, so the server checks who sent it but cannot read it; only
// the owner opens it, and sees the commitments of all its agents together. Nothing is kept by Symbolon.

import type { Json } from "./canonical.js";
import { boxProblem, newBoxSecret, openBox, sealBox, type Box, type BoxSecret } from "./channel.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { ownerName, verifyMandateSignature, withinValidity, type Mandate, type Owner } from "./mandate.js";

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

/**
 * Largest snapshot box (base64 characters of the ciphertext). Far above the piazza's boxes: a snapshot holds all
 * open commitments of an agent, each up to the wallet's clause limits, and one long agreement must never stop
 * the owner's copy from being updated.
 */
export const SNAPSHOT_BOX_MAX_CHARS = 12_000_000;
/** Largest snapshot request the archive server reads (the box plus the agent's mandate and signature). */
export const SNAPSHOT_MAX_BYTES = SNAPSHOT_BOX_MAX_CHARS + 200_000;
/** How far in the future a snapshot's time may be (clocks differ a little). */
const FUTURE_SKEW_MS = 10 * 60_000;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

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
  if (typeof x.body.at !== "string" || !ISO_TIME.test(x.body.at) || !Number.isFinite(Date.parse(x.body.at))) return "invalid snapshot time";
  const bad = boxProblem(x.body.box, SNAPSHOT_BOX_MAX_CHARS);
  if (bad) return bad;
  if (x.mandate.body?.agent !== x.body.agent) return "the mandate is for another agent";
  if (x.mandate.body.owner?.key !== ownerKey) return "the agent's mandate is not from this archive's owner";
  if (!verifyMandateSignature(x.mandate)) return "the mandate signature is invalid";
  if (!verifyValue(x.body, x.signature, x.body.agent)) return "the snapshot is not signed by the agent";
  // An agent speaks for its owner only while its mandate is valid: a snapshot dated outside it is not the owner's agent talking.
  if (!withinValidity(x.mandate, x.body.at)) return "the agent's mandate was not valid at the snapshot's time";
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
export async function handleArchive(req: Request, deps: { store: ArchiveStore; ownerKey: PublicKey; maxBytes?: number; now?: () => Date }): Promise<Response> {
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  const json = (data: unknown, status = 200) => new Response(JSON.stringify(data) + "\n", { status, headers: { "content-type": "application/json" } });
  if (path !== "/v1/snapshots") return json({ error: "not found" }, 404);
  if (req.method === "GET") return json({ owner_key: deps.ownerKey, snapshots: await deps.store.all() });
  if (req.method !== "PUT") return json({ error: "use GET or PUT" }, 405);
  const text = await req.text();
  if (text.length > (deps.maxBytes ?? SNAPSHOT_MAX_BYTES)) return json({ error: "snapshot too large" }, 413);
  let s: Snapshot;
  try {
    s = JSON.parse(text);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const bad = snapshotProblem(s, deps.ownerKey);
  if (bad) return json({ error: bad }, 400);
  const now = (deps.now ?? (() => new Date()))().getTime();
  if (Date.parse(s.body.at) > now + FUTURE_SKEW_MS) return json({ error: "the snapshot is dated in the future" }, 400);
  if (!withinValidity(s.mandate, new Date(now).toISOString())) return json({ error: "the agent's mandate is not valid now" }, 400);
  const kept = await deps.store.put(s.body.agent, s.body.seq, s);
  return kept ? json({ ok: true, seq: s.body.seq }, 201) : json({ error: "an equal or newer snapshot of this agent is already kept" }, 409);
}

/**
 * What the owner's tool remembers between two looks at the archive, kept on the owner's side (never on the
 * archive server): the highest snapshot number and time seen for each agent. With it, an archive that serves an
 * older snapshot (rollback) or hides an agent is noticed.
 */
export type ArchiveSeen = Record<PublicKey, { seq: number; at: string }>;

/**
 * The owner's view: every agent's commitments, opened with the archive secret.
 * opts.seen: what the owner's tool saw last time (updated in place with what it sees now; keep it, e.g. in a file).
 * opts.revoked: says whether an agent's mandate was revoked (e.g. from the register), and since when.
 */
export async function ownerView(
  snapshots: Snapshot[],
  secret: BoxSecret,
  ownerKey: PublicKey,
  opts: { seen?: ArchiveSeen; now?: Date; revoked?: (m: Mandate) => Promise<string | null> } = {},
) {
  const agents = [];
  const warnings: string[] = [];
  const seen = opts.seen;
  const nowMs = (opts.now ?? new Date()).getTime();
  const present = new Set<string>();
  for (const s of snapshots) {
    const bad = snapshotProblem(s, ownerKey);
    if (bad) {
      agents.push({ agent: s?.body?.agent, ignored: bad });
      continue;
    }
    const agent = s.body.agent;
    present.add(agent);
    const before = seen?.[agent];
    let rolledBack: string | undefined;
    if (before && (s.body.seq < before.seq || Date.parse(s.body.at) < Date.parse(before.at))) {
      rolledBack = `the archive shows an older snapshot of this agent (number ${s.body.seq} of ${s.body.at}) than one already seen (number ${before.seq} of ${before.at}): it may hide later commitments`;
      warnings.push(`agent ${agent}: ${rolledBack}`);
    } else if (seen) seen[agent] = { seq: s.body.seq, at: s.body.at };
    const flags = {
      ...(rolledBack ? { rolled_back: rolledBack } : {}),
      ...(Date.parse(s.mandate.body.notAfter) < nowMs ? { mandate_expired: s.mandate.body.notAfter } : {}),
    };
    if (opts.revoked) {
      try {
        const r = await opts.revoked(s.mandate);
        if (r) Object.assign(flags, { revoked: r });
      } catch {
        Object.assign(flags, { revoked: "could not be checked" });
      }
    }
    try {
      agents.push({ agent, scope: s.mandate.body.scope, saved_at: s.body.at, seq: s.body.seq, ...flags, commitments: await openSnapshot(s, secret) });
    } catch (e) {
      agents.push({ agent, ignored: (e as Error).message, ...flags });
    }
  }
  for (const [agent, last] of Object.entries(seen ?? {}))
    if (!present.has(agent)) warnings.push(`agent ${agent}: missing from the archive (last seen: snapshot number ${last.seq} of ${last.at})`);
  return { agents, ...(warnings.length ? { warnings } : {}), note: "Commitments of all your agents, as each wallet last saved them." };
}

