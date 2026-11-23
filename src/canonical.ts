// Canonical JSON: the same value always produces the same bytes,
// so that signatures and fingerprints are reproducible by anyone.
// Rules: object keys sorted, no whitespace, only integers as numbers
// (amounts are written as decimal strings, e.g. "4.20").

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function canonical(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) throw new Error("only safe integers allowed; use strings for amounts");
      return String(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
    }
    default:
      throw new Error(`cannot canonicalise ${typeof value}`);
  }
}

/**
 * Full RFC 8785 (JCS) canonical form, for JSON written by others (e.g. MCP tool definitions),
 * where decimal numbers are common. Numbers follow RFC 8785 section 3.2.2.3, which is the
 * ECMAScript number-to-string rule, so JSON.stringify gives exactly the right bytes; strings use
 * the JSON.stringify escaping RFC 8785 requires; keys are sorted by UTF-16 code units.
 * Mandates and accords keep using canonical() above (integers only).
 */
export function canonicalRfc8785(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error("RFC 8785 has no form for NaN or Infinity");
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return "[" + value.map(canonicalRfc8785).join(",") + "]";
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalRfc8785(obj[k])).join(",") + "}";
    }
    default:
      throw new Error(`cannot canonicalise ${typeof value}`);
  }
}
