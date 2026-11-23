// The change book, shelf 1: reads what a public MCP server offers, without ever using it.
// Only list methods are sent (initialize, tools/list, prompts/list, resources/templates/list):
// never tools/call, prompts/get or resources/read. What comes back is kept exactly as received,
// and fingerprinted with full RFC 8785 (docs/FORMAT.md, section 2).

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { z } from "zod";
import type { Json } from "../canonical.js";
import { fingerprintRfc8785 } from "../fingerprint.js";
import { DigestReject, digestToolList, type ToolListDigest } from "./mcp-digest.js";

export const READER_NAME = "SymbolonBook";
export const READER_VERSION = "0.1";
export const READER_USER_AGENT = `${READER_NAME}/${READER_VERSION} (read-only listing, never calls tools; +https://github.com/symbolon-city/symbolon)`;

/** The only methods the reader may send. Checked before every request. */
export const ALLOWED_METHODS = ["tools/list", "prompts/list", "resources/templates/list"] as const;
type ListMethod = (typeof ALLOWED_METHODS)[number];

const MAX_PAGES = 20;
const MAX_ITEMS = 2000;

export type ObservationStatus = "ok" | "auth-required" | "unreachable" | "error";

export interface McpTarget {
  id: string;
  url: string;
  transport: "streamable-http" | "sse";
}

export interface McpFingerprints {
  manifest: string;
  instructions: string | null;
  tools: Record<string, string>;
  prompts: Record<string, string>;
  resourceTemplates: Record<string, string>;
  /** The tools as mcp-tool-digest/v1-draft "full" would digest them (what an MCP client would pin), or why it refuses. */
  mcpToolDigest?: ToolListDigest | { reject: string };
}

export interface McpObservation {
  kind: "mcp-server";
  id: string;
  url: string;
  observedAt: string;
  status: ObservationStatus;
  error?: string;
  server?: Json;
  instructions?: string | null;
  tools?: Json[];
  prompts?: Json[];
  resourceTemplates?: Json[];
  listErrors?: string[];
  fingerprints?: McpFingerprints;
}

export interface ReadOptions {
  timeoutMs?: number;
  now?: () => Date;
  /** For tests: supplies the transport instead of connecting over HTTP. */
  makeTransport?: (t: McpTarget) => Transport;
  fetchImpl?: typeof fetch;
}

const AUTH = /\b(401|403)\b|unauthori[sz]ed|forbidden|oauth|authenticat/i;
const NETWORK = /ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|certificate|fetch failed|timed? ?out|aborted|socket/i;

export function classifyError(message: string): ObservationStatus {
  if (AUTH.test(message)) return "auth-required";
  if (NETWORK.test(message)) return "unreachable";
  return "error";
}

function key(item: Json, field: string, i: number, seen: Set<string>): string {
  const v = item && typeof item === "object" && !Array.isArray(item) ? (item as Record<string, Json>)[field] : undefined;
  let k = typeof v === "string" && v ? v : `#${i}`;
  while (seen.has(k)) k += "#dup";
  seen.add(k);
  return k;
}

function fingerprintMap(items: Json[], field: string): Record<string, string> {
  const out: Record<string, string> = {};
  const seen = new Set<string>();
  items.forEach((it, i) => (out[key(it, field, i, seen)] = fingerprintRfc8785(it).fingerprint));
  return out;
}

export function mcpFingerprints(o: Pick<McpObservation, "instructions" | "tools" | "prompts" | "resourceTemplates">): McpFingerprints {
  const instructions = typeof o.instructions === "string" ? fingerprintRfc8785(o.instructions).fingerprint : null;
  const tools = fingerprintMap(o.tools ?? [], "name");
  const prompts = fingerprintMap(o.prompts ?? [], "name");
  const resourceTemplates = fingerprintMap(o.resourceTemplates ?? [], "uriTemplate");
  const manifest = fingerprintRfc8785({ instructions, tools, prompts, resourceTemplates }).fingerprint;
  let mcpToolDigest: ToolListDigest | { reject: string };
  try {
    mcpToolDigest = digestToolList({ tools: o.tools ?? [] }, "full");
  } catch (e) {
    if (!(e instanceof DigestReject)) throw e;
    mcpToolDigest = { reject: e.code };
  }
  return { manifest, instructions, tools, prompts, resourceTemplates, mcpToolDigest };
}

const AnyResult = z.object({}).passthrough();

async function listAll(client: Client, method: ListMethod, field: string, timeout: number): Promise<Json[]> {
  if (!ALLOWED_METHODS.includes(method)) throw new Error(`method not allowed: ${method}`);
  const items: Json[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = (await client.request({ method, params: cursor ? { cursor } : {} }, AnyResult, { timeout })) as Record<string, unknown>;
    const list = res[field];
    if (Array.isArray(list)) items.push(...(list as Json[]));
    if (items.length >= MAX_ITEMS) break;
    const next = res.nextCursor;
    if (typeof next !== "string" || !next || next === cursor) break;
    cursor = next;
  }
  return items.slice(0, MAX_ITEMS);
}

function defaultTransport(t: McpTarget, fetchImpl?: typeof fetch): Transport {
  const requestInit = { headers: { "User-Agent": READER_USER_AGENT } };
  const url = new URL(t.url);
  return t.transport === "sse"
    ? new SSEClientTransport(url, { requestInit, ...(fetchImpl ? { fetch: fetchImpl } : {}) })
    : new StreamableHTTPClientTransport(url, { requestInit, ...(fetchImpl ? { fetch: fetchImpl } : {}) });
}

function short(e: unknown): string {
  const code = (e as { code?: unknown } | null)?.code;
  const m = (e instanceof Error ? `${e.name}: ${e.message}` : String(e)) + (typeof code === "number" && code >= 100 && code < 600 ? ` (HTTP ${code})` : "");
  return m.replace(/\s+/g, " ").slice(0, 300);
}

/** Reads one server's listings. Never throws: failures come back as a status. */
export async function readMcpServer(t: McpTarget, o: ReadOptions = {}): Promise<McpObservation> {
  const timeout = o.timeoutMs ?? 20_000;
  const observedAt = (o.now ?? (() => new Date()))().toISOString();
  const base: McpObservation = { kind: "mcp-server", id: t.id, url: t.url, observedAt, status: "error" };
  const client = new Client({ name: READER_NAME, version: READER_VERSION }, { capabilities: {} });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const work = (async (): Promise<McpObservation> => {
    const transport = o.makeTransport ? o.makeTransport(t) : defaultTransport(t, o.fetchImpl);
    await client.connect(transport, { timeout });
    const caps = client.getServerCapabilities() ?? {};
    const listErrors: string[] = [];
    const tryList = async (method: ListMethod, field: string, offered: boolean): Promise<Json[] | undefined> => {
      if (!offered) return undefined;
      try {
        return await listAll(client, method, field, timeout);
      } catch (e) {
        listErrors.push(`${method}: ${short(e)}`);
        return undefined;
      }
    };
    const tools = await tryList("tools/list", "tools", !!caps.tools);
    const prompts = await tryList("prompts/list", "prompts", !!caps.prompts);
    const resourceTemplates = await tryList("resources/templates/list", "resourceTemplates", !!caps.resources);
    const obs: McpObservation = {
      ...base,
      status: "ok",
      server: (client.getServerVersion() ?? null) as Json,
      instructions: client.getInstructions() ?? null,
      tools: tools ?? [],
      prompts: prompts ?? [],
      resourceTemplates: resourceTemplates ?? [],
    };
    if (listErrors.length) {
      obs.listErrors = listErrors;
      if (caps.tools && !tools) return { ...base, status: classifyError(listErrors.join(" ")), error: listErrors.join("; ") };
    }
    obs.fingerprints = mcpFingerprints(obs);
    return obs;
  })();
  const deadline = new Promise<McpObservation>((resolve) => {
    timer = setTimeout(() => resolve({ ...base, status: "unreachable", error: `timed out after ${timeout * 3} ms` }), timeout * 3);
  });
  try {
    return await Promise.race([work.catch((e) => ({ ...base, status: classifyError(short(e)), error: short(e) })), deadline]);
  } finally {
    if (timer) clearTimeout(timer);
    await client.close().catch(() => {});
  }
}
