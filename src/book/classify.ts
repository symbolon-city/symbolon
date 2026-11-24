// What kind of change happened between two observations of the same server or skill.
// The book always says "changed", never "dangerous". The kind that matters most is
// "model-text": the words an agent reads as instructions (descriptions, titles, server
// instructions, prompt texts, SKILL.md), where hidden orders go. When those words changed only
// in their numbers (a counter, a version: "7,631 tools" -> "7,656 tools"), the change is
// "numbers" instead, so that real wording changes stand out.

import type { Json } from "../canonical.js";
import { canonicalRfc8785 } from "../canonical.js";
import type { McpObservation } from "./mcp-reader.js";
import type { SkillObservation } from "./skills-reader.js";

export type ChangeKind = "model-text" | "numbers" | "shape" | "added" | "removed" | "status";

export interface Change {
  kind: ChangeKind;
  /** e.g. "tool:search", "prompt:summary", "instructions", "file:SKILL.md", "server" */
  item: string;
  detail?: string;
}

const TEXT_KEYS = new Set(["description", "title"]);

/** The text with every number (digits, with . or , inside) replaced by one mark. */
export function withoutNumbers(text: string): string {
  return text.replace(/\d+(?:[.,]\d+)*/g, "#");
}

/** "model-text", or "numbers" when the two texts differ only in their numbers. */
function textKind(before: string, after: string): ChangeKind {
  return withoutNumbers(before) === withoutNumbers(after) ? "numbers" : "model-text";
}

/** Every description/title string inside a definition, with its path: what the model reads. */
export function modelText(value: Json, path = ""): string {
  const out: [string, string][] = [];
  const walk = (v: Json, p: string) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${p}[${i}]`));
    else if (v && typeof v === "object")
      for (const [k, x] of Object.entries(v)) {
        if (TEXT_KEYS.has(k) && typeof x === "string") out.push([`${p}.${k}`, x]);
        else walk(x, `${p}.${k}`);
      }
  };
  walk(value, path);
  return canonicalRfc8785(out);
}

function byKey(items: Json[] | undefined, field: string): Map<string, Json> {
  const m = new Map<string, Json>();
  (items ?? []).forEach((it, i) => {
    const v = it && typeof it === "object" && !Array.isArray(it) ? (it as Record<string, Json>)[field] : undefined;
    let k = typeof v === "string" && v ? v : `#${i}`;
    while (m.has(k)) k += "#dup";
    m.set(k, it);
  });
  return m;
}

function compareLists(prefix: string, a: Map<string, Json>, b: Map<string, Json>): Change[] {
  const out: Change[] = [];
  for (const [k, v] of b) {
    const old = a.get(k);
    if (old === undefined) out.push({ kind: "added", item: `${prefix}:${k}` });
    else if (canonicalRfc8785(old) !== canonicalRfc8785(v))
      out.push({ kind: modelText(old) !== modelText(v) ? textKind(modelText(old), modelText(v)) : "shape", item: `${prefix}:${k}` });
  }
  for (const k of a.keys()) if (!b.has(k)) out.push({ kind: "removed", item: `${prefix}:${k}` });
  return out;
}

/** Changes from the last good observation to the new one. Status changes are reported separately. */
export function compareMcp(prev: McpObservation, cur: McpObservation): Change[] {
  if (prev.status !== "ok" || cur.status !== "ok") return [];
  if (prev.fingerprints?.manifest && prev.fingerprints.manifest === cur.fingerprints?.manifest) return [];
  const out: Change[] = [];
  if ((prev.instructions ?? null) !== (cur.instructions ?? null))
    out.push({
      kind: (prev.instructions ?? null) === null ? "added" : (cur.instructions ?? null) === null ? "removed" : textKind(prev.instructions!, cur.instructions!),
      item: "instructions",
    });
  out.push(...compareLists("tool", byKey(prev.tools, "name"), byKey(cur.tools, "name")));
  out.push(...compareLists("prompt", byKey(prev.prompts, "name"), byKey(cur.prompts, "name")));
  out.push(...compareLists("resource-template", byKey(prev.resourceTemplates, "uriTemplate"), byKey(cur.resourceTemplates, "uriTemplate")));
  return out;
}

const INSTRUCTION_FILE = /\.(md|mdx|txt)$/i;

export function compareSkill(prev: SkillObservation, cur: SkillObservation): Change[] {
  if (prev.status !== "ok" || cur.status !== "ok") return [];
  if (prev.fingerprint && prev.fingerprint === cur.fingerprint) return [];
  const out: Change[] = [];
  if (prev.dir !== cur.dir) out.push({ kind: "shape", item: "folder", detail: `${prev.dir} -> ${cur.dir}` });
  const a = prev.files ?? {};
  const b = cur.files ?? {};
  for (const [p, h] of Object.entries(b)) {
    if (!(p in a)) out.push({ kind: "added", item: `file:${p}` });
    else if (a[p] !== h) {
      const ta = prev.texts?.[p];
      const tb = cur.texts?.[p];
      const kind: ChangeKind = !INSTRUCTION_FILE.test(p) ? "shape" : ta !== undefined && tb !== undefined ? textKind(ta, tb) : "model-text";
      out.push({ kind, item: `file:${p}` });
    }
  }
  for (const p of Object.keys(a)) if (!(p in b)) out.push({ kind: "removed", item: `file:${p}` });
  return out;
}
