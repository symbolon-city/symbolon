// One day of the change book: read every server and skill on the list, compare with the last
// good observation, keep a copy when something changed, and write the day's summary with the
// Merkle root of the day's fingerprints (RFC 9162, src/merkle.ts), which day-anchor.ts binds to
// Bitcoin with OpenTimestamps. No register and no key are involved.
//
// Data folder layout:
//   lists.json                     the fixed lists and how they were chosen
//   latest/<file>.json             last good observation of each item
//   history/<file>/<date>.json     every good observation that differed from the one before
//   status.json                    last status of each item
//   days/<date>.json               the day's summary

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { utf8 } from "../bytes.js";
import { sha256Hex } from "../hash.js";
import { dayRoot } from "./day-anchor.js";
import { compareMcp, compareSkill, type Change } from "./classify.js";
import { READER_VERSION, readMcpServer, type McpObservation, type McpTarget, type ObservationStatus } from "./mcp-reader.js";
import { readSkill, type SkillObservation, type SkillTarget } from "./skills-reader.js";

export interface Lists {
  createdAt: string;
  mcp: McpTarget[];
  skills: SkillTarget[];
  criteria: Record<string, unknown>;
}

export interface DayItem {
  kind: "mcp-server" | "skill";
  id: string;
  observedAt: string;
  status: ObservationStatus;
  previousStatus?: ObservationStatus;
  /** manifest (servers) or folder fingerprint (skills); only when status is ok */
  fingerprint?: string;
  first?: boolean;
  changes: Change[];
  error?: string;
  counts?: { tools?: number; prompts?: number; resourceTemplates?: number; files?: number };
}

export interface DaySummary {
  date: string;
  reader: string;
  startedAt: string;
  finishedAt: string;
  items: DayItem[];
  /** Merkle root (hex) over the day's leaves (day-anchor.ts: one per ok item with a fingerprint, in item order) */
  root: string;
  leaves: number;
}

export function fileName(id: string): string {
  return id.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 80) + "-" + sha256Hex(utf8(id)).slice(0, 8);
}

async function readJson<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch {
    return undefined;
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, JSON.stringify(value, null, 2) + "\n", "utf8");
}

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    }),
  );
  return out;
}

export interface DayOptions {
  dataDir: string;
  now?: () => Date;
  githubToken?: string;
  concurrency?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  readMcp?: typeof readMcpServer;
  readSkillFn?: typeof readSkill;
}

export async function runDay(lists: Lists, o: DayOptions): Promise<DaySummary> {
  const now = o.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const date = startedAt.slice(0, 10);
  for (const d of ["latest", "history", "days"]) await mkdir(join(o.dataDir, d), { recursive: true });
  const statusPath = join(o.dataDir, "status.json");
  const status = (await readJson<Record<string, ObservationStatus>>(statusPath)) ?? {};

  const keep = async (id: string, obs: McpObservation | SkillObservation, changed: boolean) => {
    const f = fileName(id);
    await writeJson(join(o.dataDir, "latest", f + ".json"), obs);
    if (changed) {
      await mkdir(join(o.dataDir, "history", f), { recursive: true });
      await writeJson(join(o.dataDir, "history", f, date + ".json"), obs);
    }
  };

  const readMcp = o.readMcp ?? readMcpServer;
  const mcpItems = await pool(lists.mcp, o.concurrency ?? 6, async (t): Promise<[DayItem, McpObservation]> => {
    const obs = await readMcp(t, { now, timeoutMs: o.timeoutMs, fetchImpl: o.fetchImpl });
    const prev = await readJson<McpObservation>(join(o.dataDir, "latest", fileName(t.id) + ".json"));
    const item: DayItem = { kind: "mcp-server", id: t.id, observedAt: obs.observedAt, status: obs.status, previousStatus: status[t.id], changes: [] };
    if (obs.error) item.error = obs.error;
    if (obs.status === "ok") {
      item.fingerprint = obs.fingerprints?.manifest;
      item.counts = { tools: obs.tools?.length, prompts: obs.prompts?.length, resourceTemplates: obs.resourceTemplates?.length };
      item.first = !prev;
      item.changes = prev ? compareMcp(prev, obs) : [];
      const changed = !prev || prev.fingerprints?.manifest !== obs.fingerprints?.manifest;
      await keep(t.id, obs, changed);
    }
    if (status[t.id] && status[t.id] !== obs.status) item.changes.push({ kind: "status", item: "server", detail: `${status[t.id]} -> ${obs.status}` });
    return [item, obs];
  });

  const readSkillFn = o.readSkillFn ?? readSkill;
  const skillItems: [DayItem, SkillObservation][] = [];
  for (const t of lists.skills) {
    const prev = await readJson<SkillObservation>(join(o.dataDir, "latest", fileName(t.id) + ".json"));
    const obs = await readSkillFn(t, { now, githubToken: o.githubToken, previous: prev, fetchImpl: o.fetchImpl });
    const item: DayItem = { kind: "skill", id: t.id, observedAt: obs.observedAt, status: obs.status, previousStatus: status[t.id], changes: [] };
    if (obs.error) item.error = obs.error;
    if (obs.status === "ok") {
      item.fingerprint = obs.fingerprint;
      item.counts = { files: Object.keys(obs.files ?? {}).length };
      item.first = !prev;
      item.changes = prev ? compareSkill(prev, obs) : [];
      await keep(t.id, obs, !prev || prev.fingerprint !== obs.fingerprint);
    }
    if (status[t.id] && status[t.id] !== obs.status) item.changes.push({ kind: "status", item: "skill", detail: `${status[t.id]} -> ${obs.status}` });
    skillItems.push([item, obs]);
  }

  const all = [...mcpItems, ...skillItems];
  for (const [item] of all) status[item.id] = item.status;
  await writeJson(statusPath, status);
  const items = all.map(([i]) => i);
  const { root, leaves } = dayRoot(date, items);
  const summary: DaySummary = {
    date,
    reader: `SymbolonBook/${READER_VERSION}`,
    startedAt,
    finishedAt: now().toISOString(),
    items,
    root,
    leaves,
  };
  await writeJson(join(o.dataDir, "days", date + ".json"), summary);
  return summary;
}
