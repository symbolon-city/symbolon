// The change book's own anchor: each day's summary is bound to Bitcoin with OpenTimestamps,
// directly, without a register and without a key to keep. Anyone can check a day with the
// summary file, its .ots file and a Bitcoin block explorer (or the official `ots` client):
//
//   snapshot of a server or skill --(recompute its fingerprint)--> item of the day
//   item --(leaf)--> Merkle root of the day (RFC 9162) --(day digest)--> .ots --> Bitcoin block
//
// leaf       = leafHash(JCS({v:"symbolon-book/leaf/1", date, kind, id, fingerprint}))   for every ok item, in order
// day digest = SHA-256("symbolon-book/day/1" || 0x00 || JCS({date, root, leaves}))
// The .ots proves the day existed by the time of its Bitcoin block: never earlier than it was written.

import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { concat, toHex, utf8 } from "../bytes.js";
import { canonicalRfc8785 } from "../canonical.js";
import { leafHash } from "../hash.js";
import { treeRoot } from "../merkle.js";
import { stamp, upgrade, verifyTimestamp, type AnchorStatus, type BlockProvider } from "../anchor.js";
import { fromOtsFile, toOtsFile } from "../ots.js";
import { fingerprintRfc8785 } from "../fingerprint.js";
import { mcpFingerprints, type McpObservation } from "./mcp-reader.js";
import type { SkillObservation } from "./skills-reader.js";

export const LEAF_VERSION = "symbolon-book/leaf/1";
export const DAY_VERSION = "symbolon-book/day/1";

export interface DayItemLike {
  kind: string;
  id: string;
  status: string;
  fingerprint?: string;
}
export interface DayLike {
  date: string;
  items: DayItemLike[];
  root: string;
  leaves: number;
}

export function bookLeaf(date: string, item: DayItemLike): Uint8Array {
  return leafHash(utf8(canonicalRfc8785({ v: LEAF_VERSION, date, kind: item.kind, id: item.id, fingerprint: item.fingerprint ?? null })));
}

/** The items that make the day's tree: every ok item with a fingerprint, in the summary's order. */
export function dayLeaves(date: string, items: DayItemLike[]): Uint8Array[] {
  return items.filter((i) => i.status === "ok" && i.fingerprint).map((i) => bookLeaf(date, i));
}

export function dayRoot(date: string, items: DayItemLike[]): { root: string; leaves: number } {
  const leaves = dayLeaves(date, items);
  return { root: toHex(treeRoot(leaves)), leaves: leaves.length };
}

export function dayDigest(d: Pick<DayLike, "date" | "root" | "leaves">): Uint8Array {
  return sha256(concat(utf8(DAY_VERSION), new Uint8Array([0]), utf8(canonicalRfc8785({ date: d.date, root: d.root, leaves: d.leaves }))));
}

type CalendarOptions = { calendars?: string[]; minCalendars?: number; fetchImpl?: typeof fetch };

/** Stamps a day (sends only its 32-byte digest to the calendars) and writes days/<date>.ots. */
export async function stampDay(dataDir: string, day: DayLike, opts: CalendarOptions = {}): Promise<string> {
  const ts = await stamp(dayDigest(day), opts);
  const path = join(dataDir, "days", `${day.date}.ots`);
  await writeFile(path, toOtsFile(ts));
  return path;
}

/** Asks the calendars whether pending days are in Bitcoin now; rewrites the .ots files that moved. */
export async function upgradeDays(dataDir: string, fetchImpl: typeof fetch = fetch): Promise<{ checked: number; upgraded: string[] }> {
  const dir = join(dataDir, "days");
  const upgraded: string[] = [];
  let checked = 0;
  for (const f of (await readdir(dir)).filter((x) => x.endsWith(".ots")).sort()) {
    const date = f.slice(0, -4);
    const day = JSON.parse(await readFile(join(dir, `${date}.json`), "utf8")) as DayLike;
    const ts = fromOtsFile(new Uint8Array(await readFile(join(dir, f))), dayDigest(day));
    checked++;
    if ((await upgrade(ts, fetchImpl)) > 0) {
      await writeFile(join(dir, f), toOtsFile(ts));
      upgraded.push(date);
    }
  }
  return { checked, upgraded };
}

export interface DayCheck {
  date: string;
  /** The root written in the summary is the one its items give. */
  rootMatches: boolean;
  anchor: AnchorStatus | { status: "missing" };
}

/** Checks a day: its root from its own items, then its .ots against Bitcoin. */
export async function verifyDay(dataDir: string, date: string, blocks: BlockProvider): Promise<DayCheck> {
  const day = JSON.parse(await readFile(join(dataDir, "days", `${date}.json`), "utf8")) as DayLike;
  const again = dayRoot(day.date, day.items);
  const rootMatches = again.root === day.root && again.leaves === day.leaves;
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await readFile(join(dataDir, "days", `${date}.ots`)));
  } catch {
    return { date, rootMatches, anchor: { status: "missing" } };
  }
  let anchor: AnchorStatus;
  try {
    anchor = await verifyTimestamp(fromOtsFile(bytes, dayDigest(day)), blocks);
  } catch (e) {
    anchor = { status: "invalid", reason: `.ots does not belong to this day: ${(e as Error).message}` };
  }
  return { date, rootMatches, anchor };
}


/** Recomputes a kept snapshot's fingerprint from its content (never trusting the stored value). */
export function snapshotFingerprint(o: McpObservation | SkillObservation): string {
  return o.kind === "mcp-server" ? mcpFingerprints(o).manifest : fingerprintRfc8785({ files: o.files ?? {} }).fingerprint;
}

/**
 * Stamps every day that has no .ots yet (a day whose calendars were down, or days written before
 * anchoring existed). A day without .ots was never anchored, so its root may still be recomputed
 * from its items; a day with an .ots is never rewritten.
 */
export async function stampMissing(dataDir: string, opts: CalendarOptions = {}): Promise<{ stamped: string[]; failed: string[] }> {
  const dir = join(dataDir, "days");
  const files = await readdir(dir);
  const stamped: string[] = [];
  const failed: string[] = [];
  for (const f of files.filter((x) => x.endsWith(".json")).sort()) {
    const date = f.slice(0, -5);
    if (files.includes(`${date}.ots`)) continue;
    const day = JSON.parse(await readFile(join(dir, f), "utf8")) as DayLike & Record<string, unknown>;
    const again = dayRoot(day.date, day.items);
    if (again.root !== day.root || again.leaves !== day.leaves) {
      Object.assign(day, again);
      await writeFile(join(dir, f), JSON.stringify(day, null, 2) + "\n", "utf8");
    }
    try {
      await stampDay(dataDir, day, opts);
      stamped.push(date);
    } catch {
      failed.push(date);
    }
  }
  return { stamped, failed };
}
