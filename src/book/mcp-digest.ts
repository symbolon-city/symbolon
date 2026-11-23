// mcp-tool-digest/v1-draft: the tool-definition digest drafted for the MCP SEP-3452 discussion
// (https://github.com/purysho/mcp-digest-vectors, SPEC.md). The change book stores it next to its
// own fingerprints, so that what the book records is the same digest an MCP client would compute.
//   tool digest = "sha256:" + hex(SHA-256("mcp-tool-digest/v1-draft/<profile>/tool" || 0x00 || JCS(tool)))
//   set digest  = the same with ".../set" over the JCS array of the selected tools sorted by name
// Checked against every vector of that repository (test/fixtures/mcp-digest-vectors).

import { sha256 } from "@noble/hashes/sha2";
import { concat, toHex, utf8 } from "../bytes.js";
import { canonicalRfc8785, type Json } from "../canonical.js";

export const MCP_DIGEST_VERSION = "mcp-tool-digest/v1-draft";
export type DigestProfile = "desc" | "four-field" | "full";

const PROFILE_FIELDS: Record<DigestProfile, string[] | null> = {
  desc: ["name", "description"],
  "four-field": ["name", "description", "inputSchema", "annotations"],
  full: null,
};

export class DigestReject extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(`${code}: ${message}`);
  }
}

export interface ToolListDigest {
  version: string;
  profile: DigestProfile;
  set: string;
  tools: Record<string, string>;
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Rejects values two parsers could read differently, or that have no RFC 8785 form. */
function checkValue(v: unknown): void {
  if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new DigestReject("lone-surrogate", "a string has an unpaired surrogate");
  } else if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new DigestReject("number-out-of-range", "a number is not finite");
  } else if (Array.isArray(v)) v.forEach(checkValue);
  else if (v && typeof v === "object")
    for (const [k, x] of Object.entries(v)) {
      checkValue(k);
      checkValue(x);
    }
}

/** Duplicate member names at any depth (JSON.parse silently keeps the last one). */
function checkDuplicateKeys(text: string): void {
  const stack: { obj: boolean; keys: Set<string>; wantKey: boolean }[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top?.obj && top.wantKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) throw new DigestReject("duplicate-key", `member ${JSON.stringify(key)} appears twice`);
        top.keys.add(key);
        top.wantKey = false;
      }
      i = j;
    } else if (c === "{") stack.push({ obj: true, keys: new Set(), wantKey: true });
    else if (c === "[") stack.push({ obj: false, keys: new Set(), wantKey: false });
    else if (c === "}" || c === "]") stack.pop();
    else if (c === ",") {
      const top = stack[stack.length - 1];
      if (top?.obj) top.wantKey = true;
    }
  }
}

/** Strict parse of the raw bytes of a tools/list result (SPEC.md section 2). */
export function parseStrict(raw: Uint8Array | string): unknown {
  let text: string;
  if (typeof raw === "string") text = raw;
  else
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
    } catch {
      throw new DigestReject("invalid-utf8", "the bytes are not valid UTF-8");
    }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new DigestReject("invalid-json", "not a single JSON value");
  }
  checkDuplicateKeys(text);
  checkValue(value);
  return value;
}

function hash(profile: DigestProfile, kind: "tool" | "set", canonical: string): string {
  return "sha256:" + toHex(sha256(concat(utf8(`${MCP_DIGEST_VERSION}/${profile}/${kind}`), new Uint8Array([0]), utf8(canonical))));
}

function select(tool: Record<string, Json>, profile: DigestProfile): Record<string, Json> {
  const fields = PROFILE_FIELDS[profile];
  if (!fields) return { ...tool };
  const out: Record<string, Json> = {};
  for (const f of fields) if (f in tool) out[f] = tool[f];
  return out;
}

/** Digest of an already parsed tools/list result (or a plain array of tools). */
export function digestToolList(result: unknown, profile: DigestProfile = "full"): ToolListDigest {
  checkValue(result);
  const tools = Array.isArray(result) ? result : (result as { tools?: unknown } | null)?.tools;
  if (!Array.isArray(tools)) throw new DigestReject("not-a-tool-list", "expected an object with a 'tools' array");
  const seen = new Set<string>();
  for (const t of tools) {
    if (!t || typeof t !== "object" || Array.isArray(t)) throw new DigestReject("not-a-tool-list", "every tool must be an object");
    const name = (t as Record<string, unknown>).name;
    if (typeof name !== "string" || !name) throw new DigestReject("bad-tool-name", "tool name must be a non-empty string");
    if (seen.has(name)) throw new DigestReject("duplicate-tool-name", `tool name ${JSON.stringify(name)} appears twice`);
    seen.add(name);
  }
  const sorted = [...(tools as Record<string, Json>[])].sort((a, b) => ((a.name as string) < (b.name as string) ? -1 : 1));
  const selected = sorted.map((t) => select(t, profile));
  const out: Record<string, string> = {};
  sorted.forEach((t, i) => (out[t.name as string] = hash(profile, "tool", canonicalRfc8785(selected[i]))));
  return { version: MCP_DIGEST_VERSION, profile, set: hash(profile, "set", canonicalRfc8785(selected)), tools: out };
}

/** Digest of the raw bytes of a tools/list result, rejecting what SPEC.md says to reject. */
export function digestToolListRaw(raw: Uint8Array | string, profile: DigestProfile = "full"): ToolListDigest {
  return digestToolList(parseStrict(raw), profile);
}
