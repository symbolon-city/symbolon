// Which servers and skills the book reads. The choice is written down with its criterion,
// so anyone can see why something is (or is not) on the shelf.

import { sha256Hex } from "../hash.js";
import { utf8 } from "../bytes.js";
import type { McpTarget } from "./mcp-reader.js";
import type { SkillTarget } from "./skills-reader.js";

export const OFFICIAL_REGISTRY = "https://registry.modelcontextprotocol.io";

interface RegistryRemote {
  type?: string;
  url?: string;
  headers?: { isRequired?: boolean }[];
  variables?: Record<string, unknown>;
}
interface RegistryEntry {
  server?: { name?: string; remotes?: RegistryRemote[] };
  _meta?: Record<string, { status?: string }>;
}

export interface McpListStats {
  registryEntries: number;
  withRemote: number;
  withoutRequiredHeaders: number;
}

/** Remote servers in the official registry that do not declare a required header or a URL variable. */
export function openRemote(e: RegistryEntry): McpTarget | undefined {
  const name = e.server?.name;
  const status = e._meta?.["io.modelcontextprotocol.registry/official"]?.status;
  if (!name || (status && status !== "active")) return undefined;
  for (const r of e.server?.remotes ?? []) {
    if (!r.url || !/^https:\/\//.test(r.url) || r.url.includes("{")) continue;
    if ((r.headers ?? []).some((h) => h.isRequired)) continue;
    if (r.variables && Object.keys(r.variables).length) continue;
    if (r.type === "streamable-http" || r.type === "sse") return { id: name, url: r.url, transport: r.type };
  }
  return undefined;
}

export async function registryCandidates(
  fetchImpl: typeof fetch = fetch,
  maxPages = 2000,
  userAgent = "SymbolonBook/0.1",
): Promise<{ targets: McpTarget[]; stats: McpListStats }> {
  const targets = new Map<string, McpTarget>();
  let entries = 0;
  let withRemote = 0;
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const u = new URL("/v0/servers", OFFICIAL_REGISTRY);
    u.searchParams.set("limit", "100");
    u.searchParams.set("version", "latest");
    if (cursor) u.searchParams.set("cursor", cursor);
    const res = await fetchImpl(u, { headers: { "User-Agent": userAgent, Accept: "application/json" } });
    if (!res.ok) throw new Error(`registry: HTTP ${res.status}`);
    const body = (await res.json()) as { servers?: RegistryEntry[]; metadata?: { nextCursor?: string } };
    for (const e of body.servers ?? []) {
      entries++;
      if (e.server?.remotes?.length) withRemote++;
      const t = openRemote(e);
      if (t) targets.set(t.id, t);
    }
    const next = body.metadata?.nextCursor;
    if (!next || next === cursor) break;
    cursor = next;
  }
  return { targets: [...targets.values()], stats: { registryEntries: entries, withRemote, withoutRequiredHeaders: targets.size } };
}

/** A fixed sample nobody picks by hand: order by SHA-256 of the name, take the first n. */
export function sampleByHash<T extends { id: string }>(items: T[], n: number): T[] {
  return [...items].sort((a, b) => (sha256Hex(utf8(a.id)) < sha256Hex(utf8(b.id)) ? -1 : 1)).slice(0, n);
}

// "site/<domain>/<skill>" entries are hosted outside GitHub: not read in the prototype.
const NOT_SKILLS = new Set(["site", "docs", "api", "about", "blog", "search", "login", "_next", "static", "settings", "audits", "trending", "hot"]);

/** Skills in the order the skills.sh home page lists them (its all-time ranking). */
export function skillsFromHomePage(html: string, n: number): SkillTarget[] {
  const seen = new Set<string>();
  const out: SkillTarget[] = [];
  for (const m of html.matchAll(/href="\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.:-]+)"/g)) {
    if (NOT_SKILLS.has(m[1].toLowerCase())) continue;
    const id = `${m[1]}/${m[2]}/${m[3]}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ id });
    if (out.length >= n) break;
  }
  return out;
}
