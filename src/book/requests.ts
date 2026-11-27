// Reading on request: when someone asks the door about a server or skill that is not on the book's
// shelves, the door writes down the request (only the name, never who asked). At its next daily
// reading the book checks each request by the same criteria as its lists (an open remote server in
// the official MCP registry, or a skill on GitHub that has a SKILL.md) and, if it passes, puts it on
// the shelf: from then on it is read every day like the others. Nothing is read at the moment of the
// question, so asking never makes Symbolon contact a third party on someone's behalf.
//
// Shared by the door (Workers) and the reader (Node): no Node imports here.

import { fileName } from "./names.js";
import { OFFICIAL_REGISTRY, openRemote } from "./lists.js";
import type { McpTarget } from "./mcp-reader.js";
import type { SkillTarget } from "./skills-reader.js";

/** Official MCP registry names are "reverse-dns/name"; skills are "owner/repo/skill" as on skills.sh. */
const MCP_NAME = /^[A-Za-z0-9][A-Za-z0-9.-]{0,120}\/[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/;
const SKILL_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._:-]{1,100}$/;

export type RequestKind = "mcp-server" | "skill";

/** The kind of item a name can be, or undefined if it cannot be a registry name or a skill id. */
export function requestKind(name: string): RequestKind | undefined {
  if (MCP_NAME.test(name)) return "mcp-server";
  if (SKILL_NAME.test(name)) return "skill";
  return undefined;
}

export interface BookRequest {
  name: string;
  kind: RequestKind;
  /** First time it was asked; later questions do not change it. */
  askedAt: string;
}

/** Where the door keeps requests: requests/<file>.json, the same folder the reader takes them from. */
export function requestPath(name: string): string {
  return `requests/${fileName(name)}.json`;
}

/** Minimal storage the door needs (an R2 bucket fits it). */
export interface RequestStore {
  head(key: string): Promise<unknown | null>;
  put(key: string, value: string): Promise<unknown>;
}

/** Records a request once. Returns "new", "already" (asked before), or "invalid" (not a possible name). */
export async function recordRequest(store: RequestStore, name: string, now: Date = new Date()): Promise<"new" | "already" | "invalid"> {
  const kind = requestKind(name);
  if (!kind) return "invalid";
  const key = requestPath(name);
  if (await store.head(key)) return "already";
  const r: BookRequest = { name, kind, askedAt: now.toISOString() };
  await store.put(key, JSON.stringify(r));
  return "new";
}

export type RequestOutcome = "added" | "already-on-shelf" | "not-in-registry" | "not-open" | "not-a-skill" | "invalid";

/**
 * Looks a server up in the official registry by its exact name and applies the lists' criterion.
 * Returns the target to read, or why not.
 */
export async function registryLookup(
  name: string,
  fetchImpl: typeof fetch = fetch,
  userAgent = "SymbolonBook/0.1",
): Promise<McpTarget | "not-in-registry" | "not-open"> {
  const u = new URL("/v0/servers", OFFICIAL_REGISTRY);
  u.searchParams.set("search", name);
  u.searchParams.set("version", "latest");
  u.searchParams.set("limit", "100");
  const res = await fetchImpl(u, { headers: { "User-Agent": userAgent, Accept: "application/json" } });
  if (!res.ok) throw new Error(`registry: HTTP ${res.status}`);
  const body = (await res.json()) as { servers?: Parameters<typeof openRemote>[0][] };
  const exact = (body.servers ?? []).filter((e) => e.server?.name === name);
  if (!exact.length) return "not-in-registry";
  for (const e of exact) {
    const t = openRemote(e);
    if (t) return t;
  }
  return "not-open";
}

export interface ShelfChoice {
  mcp: McpTarget[];
  skills: SkillTarget[];
  outcomes: { name: string; askedAt: string; outcome: RequestOutcome }[];
  /** Requests left for another day (over the daily cap). */
  waiting: number;
}

/**
 * Decides which requests go on the shelf, oldest first, at most `cap` checks a day. `done` holds the
 * names already decided, so a request is checked only once (asking again does not re-queue it).
 */
export async function chooseRequested(
  requests: BookRequest[],
  o: {
    onShelf: Set<string>;
    done: Set<string>;
    cap: number;
    lookup: (name: string) => Promise<McpTarget | "not-in-registry" | "not-open">;
    isSkill: (id: string) => Promise<boolean>;
  },
): Promise<ShelfChoice> {
  const pending = requests
    .filter((r) => !o.done.has(r.name))
    .sort((a, b) => (a.askedAt < b.askedAt ? -1 : a.askedAt > b.askedAt ? 1 : a.name < b.name ? -1 : 1));
  const out: ShelfChoice = { mcp: [], skills: [], outcomes: [], waiting: Math.max(0, pending.length - o.cap) };
  for (const r of pending.slice(0, o.cap)) {
    const note = (outcome: RequestOutcome) => out.outcomes.push({ name: r.name, askedAt: r.askedAt, outcome });
    if (requestKind(r.name) !== r.kind) note("invalid");
    else if (o.onShelf.has(r.name)) note("already-on-shelf");
    else {
      // A failed check (registry or GitHub down) decides nothing: the request is tried again next time.
      try {
        if (r.kind === "mcp-server") {
          const t = await o.lookup(r.name);
          if (typeof t === "string") note(t);
          else (out.mcp.push(t), note("added"));
        } else if (await o.isSkill(r.name)) (out.skills.push({ id: r.name }), note("added"));
        else note("not-a-skill");
      } catch {
        out.waiting++;
      }
    }
  }
  return out;
}
