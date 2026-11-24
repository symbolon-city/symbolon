// One-off census of A2A agent cards: how many sites publish one at /.well-known/agent-card.json
// (or the pre-0.3 /.well-known/agent.json), and how many of those cards are signed.
//   npm run a2a:census -- --tranco <top-1m.csv> --top 10000 --out <file.json> [--mcp-hosts]
// One polite GET per path and host, identified, short timeouts, no retries. Reads public files only.

import { readFile, writeFile } from "node:fs/promises";
import { registryCandidates } from "../src/book/lists.js";

const UA = "SymbolonCensus/0.1 (one-off count of public A2A agent cards; +https://github.com/symbolon-city/symbolon)";
const PATHS = ["/.well-known/agent-card.json", "/.well-known/agent.json"];
const MAX_BYTES = 256 * 1024;
const TIMEOUT = 8000;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

export interface CardFound {
  host: string;
  group: string;
  path: string;
  name: string;
  protocolVersion?: string;
  organization?: string;
  skills: number;
  signed: boolean;
  signatures: number;
  securitySchemes: string[];
  urlHost?: string;
}

async function getJson(url: string): Promise<unknown | undefined> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT);
  try {
    const res = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/json" }, signal: ctl.signal, redirect: "follow" });
    if (!res.ok) return undefined;
    const len = Number(res.headers.get("content-length") ?? 0);
    if (len > MAX_BYTES) return undefined;
    const text = await res.text();
    if (text.length > MAX_BYTES) return undefined;
    return JSON.parse(text);
  } catch {
    return undefined;
  } finally {
    clearTimeout(t);
  }
}

/** A card is a JSON object with a name and either skills or a service URL (soft-404 pages are not). */
export function asCard(host: string, group: string, path: string, v: unknown): CardFound | undefined {
  if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
  const c = v as Record<string, unknown>;
  if (typeof c.name !== "string" || !c.name) return undefined;
  if (!Array.isArray(c.skills) && typeof c.url !== "string" && !Array.isArray(c.supportedInterfaces)) return undefined;
  const sigs = Array.isArray(c.signatures) ? c.signatures.length : 0;
  let urlHost: string | undefined;
  try {
    urlHost = typeof c.url === "string" ? new URL(c.url).host : undefined;
  } catch {}
  const provider = c.provider as { organization?: unknown } | undefined;
  return {
    host,
    group,
    path,
    name: c.name.slice(0, 120),
    ...(typeof c.protocolVersion === "string" ? { protocolVersion: c.protocolVersion } : {}),
    ...(typeof provider?.organization === "string" ? { organization: provider.organization.slice(0, 120) } : {}),
    skills: Array.isArray(c.skills) ? c.skills.length : 0,
    signed: sigs > 0,
    signatures: sigs,
    securitySchemes: c.securitySchemes && typeof c.securitySchemes === "object" ? Object.keys(c.securitySchemes as object).slice(0, 10) : [],
    ...(urlHost ? { urlHost } : {}),
  };
}

async function probe(host: string, group: string): Promise<CardFound | undefined> {
  for (const p of PATHS) {
    const card = asCard(host, group, p, await getJson(`https://${host}${p}`));
    if (card) return card;
  }
  return undefined;
}

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>, every = 1000): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  let done = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
        if (++done % every === 0) console.log(`  ${done}/${items.length}`);
      }
    }),
  );
  return out;
}

if (process.argv[1]?.endsWith("a2a-census.ts")) {
  const top = Number(arg("top") ?? 10000);
  const groups: { name: string; hosts: string[] }[] = [];
  const tranco = arg("tranco");
  if (tranco) {
    const lines = (await readFile(tranco, "utf8")).split(/\r?\n/).filter(Boolean).slice(0, top);
    groups.push({ name: `tranco-top-${top}`, hosts: lines.map((l) => l.split(",")[1]?.trim()).filter((h): h is string => !!h && /^[a-z0-9.-]+$/i.test(h)) });
  }
  if (process.argv.includes("--mcp-hosts")) {
    const { targets } = await registryCandidates(fetch, 2000, UA);
    const all = new Set<string>();
    for (const t of targets) all.add(new URL(t.url).host);
    groups.push({ name: "mcp-remote-hosts", hosts: [...all].sort() });
  }
  const results: { group: string; probed: number; found: number; signed: number; cards: CardFound[] }[] = [];
  for (const g of groups) {
    console.log(`${g.name}: ${g.hosts.length} hosts`);
    const cards = (await pool(g.hosts, 64, (h) => probe(h, g.name))).filter((c): c is CardFound => !!c);
    results.push({ group: g.name, probed: g.hosts.length, found: cards.length, signed: cards.filter((c) => c.signed).length, cards });
    console.log(`  found ${cards.length}, signed ${cards.filter((c) => c.signed).length}`);
  }
  await writeFile(arg("out") ?? "a2a-census.json", JSON.stringify({ at: new Date().toISOString(), paths: PATHS, userAgent: UA, results }, null, 2) + "\n");
}
