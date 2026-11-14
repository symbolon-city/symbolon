// Anchoring to Bitcoin through OpenTimestamps.
// Once a day the register's signed tree head is reduced to one fingerprint
// and sent to public OpenTimestamps calendars (free). A few hours later the
// calendars have written it into a Bitcoin block; from then on, the tree head
// provably existed before that block.

import { equalBytes, fromBase64, fromHex, toBase64, toHex } from "./bytes.js";
import { digest } from "./hash.js";
import {
  allAttestations,
  fromOtsFile,
  mergeTimestamp,
  newTimestamp,
  parseTimestamp,
  toOtsFile,
  type Timestamp,
} from "./ots.js";
import type { SignedTreeHead, TreeHead } from "./register.js";

export const DEFAULT_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
];

const ACCEPT = { Accept: "application/vnd.opentimestamps.v1" };

/** The fingerprint of a tree head that gets anchored. */
export function headDigest(h: TreeHead): Uint8Array {
  return fromHex(digest({ type: "accord/anchor", log: h.log, size: h.size, root: h.root, time: h.time }));
}

export interface Anchor {
  head: SignedTreeHead;
  /** Standard .ots file, base64. Verifiable with the official `ots` client too. */
  ots: string;
}

/** Sends the digest to several calendars. Needs at least `minCalendars` answers. */
export async function stamp(
  digest32: Uint8Array,
  opts: { calendars?: string[]; minCalendars?: number; fetchImpl?: typeof fetch } = {},
): Promise<Timestamp> {
  const calendars = opts.calendars ?? DEFAULT_CALENDARS;
  const f = opts.fetchImpl ?? fetch;
  const ts = newTimestamp(digest32);
  const results = await Promise.allSettled(
    calendars.map(async (url) => {
      const res = await f(`${url}/digest`, { method: "POST", body: new Uint8Array(digest32) as unknown as BodyInit, headers: ACCEPT });
      if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
      return parseTimestamp(new Uint8Array(await res.arrayBuffer()), digest32);
    }),
  );
  let ok = 0;
  for (const r of results) {
    if (r.status === "fulfilled") {
      mergeTimestamp(ts, r.value);
      ok++;
    }
  }
  if (ok < (opts.minCalendars ?? 2)) throw new Error(`only ${ok} calendar(s) answered`);
  return ts;
}

export async function anchorHead(head: SignedTreeHead, opts?: Parameters<typeof stamp>[1]): Promise<Anchor> {
  const ts = await stamp(headDigest(head), opts);
  return { head, ots: toBase64(toOtsFile(ts)) };
}

/**
 * Asks each calendar whether its pending commitment is now in Bitcoin.
 * Returns how many pending attestations were upgraded.
 */
export async function upgrade(ts: Timestamp, fetchImpl: typeof fetch = fetch): Promise<number> {
  let upgraded = 0;
  for (const { msg, attestation, node } of allAttestations(ts)) {
    if (attestation.kind !== "pending") continue;
    const res = await fetchImpl(`${attestation.uri}/timestamp/${toHex(msg)}`, { headers: ACCEPT });
    if (!res.ok) continue; // still waiting for Bitcoin
    const more = parseTimestamp(new Uint8Array(await res.arrayBuffer()), msg);
    if (!allAttestations(more).some((a) => a.attestation.kind === "bitcoin")) continue;
    mergeTimestamp(node, more);
    node.attestations = node.attestations.filter((a) => a !== attestation);
    upgraded++;
  }
  return upgraded;
}

export async function upgradeAnchor(a: Anchor, fetchImpl?: typeof fetch): Promise<{ anchor: Anchor; upgraded: number }> {
  const ts = fromOtsFile(fromBase64(a.ots));
  const upgraded = await upgrade(ts, fetchImpl);
  return { anchor: { ...a, ots: toBase64(toOtsFile(ts)) }, upgraded };
}

// ---------- verification against Bitcoin ----------

export interface BlockInfo {
  merkleRoot: string; // as shown by block explorers (big-endian hex)
  time: number; // unix seconds
}

export type BlockProvider = (height: number) => Promise<BlockInfo>;

/** Reads block headers from an Esplora explorer (blockstream.info, mempool.space). */
export function esploraProvider(base = "https://blockstream.info/api", fetchImpl: typeof fetch = fetch): BlockProvider {
  return async (height) => {
    const h = await fetchImpl(`${base}/block-height/${height}`);
    if (!h.ok) throw new Error(`block ${height} not found`);
    const hash = (await h.text()).trim();
    const b = await fetchImpl(`${base}/block/${hash}`);
    if (!b.ok) throw new Error(`block ${hash} not found`);
    const j = (await b.json()) as { merkle_root: string; timestamp: number; height: number };
    if (j.height !== height) throw new Error("explorer returned the wrong block");
    return { merkleRoot: j.merkle_root, time: j.timestamp };
  };
}

export type AnchorStatus =
  | { status: "confirmed"; height: number; blockTime: string }
  | { status: "pending"; calendars: string[] }
  | { status: "invalid"; reason: string };

/** Checks a timestamp tree against Bitcoin. */
export async function verifyTimestamp(ts: Timestamp, blocks: BlockProvider): Promise<AnchorStatus> {
  const all = allAttestations(ts);
  let best: { height: number; time: number } | undefined;
  for (const { msg, attestation } of all) {
    if (attestation.kind !== "bitcoin") continue;
    if (msg.length !== 32) return { status: "invalid", reason: "bitcoin attestation on a non-32-byte value" };
    let block: BlockInfo;
    try {
      block = await blocks(attestation.height);
    } catch (e) {
      return { status: "invalid", reason: (e as Error).message };
    }
    // Explorers show merkle roots byte-reversed.
    const shown = toHex(msg.slice().reverse());
    if (shown !== block.merkleRoot) return { status: "invalid", reason: `does not match block ${attestation.height}` };
    if (!best || attestation.height < best.height) best = { height: attestation.height, time: block.time };
  }
  if (best) return { status: "confirmed", height: best.height, blockTime: new Date(best.time * 1000).toISOString() };
  const pending = all.flatMap((x) => (x.attestation.kind === "pending" ? [x.attestation.uri] : []));
  if (pending.length) return { status: "pending", calendars: pending };
  return { status: "invalid", reason: "no attestation" };
}

/** Checks that the anchor's .ots file really belongs to its head and is in Bitcoin. */
export async function verifyAnchor(a: Anchor, blocks: BlockProvider): Promise<AnchorStatus> {
  let ts: Timestamp;
  try {
    ts = fromOtsFile(fromBase64(a.ots));
  } catch (e) {
    return { status: "invalid", reason: `unreadable .ots: ${(e as Error).message}` };
  }
  if (!equalBytes(ts.msg, headDigest(a.head))) return { status: "invalid", reason: ".ots is for a different head" };
  return verifyTimestamp(ts, blocks);
}
