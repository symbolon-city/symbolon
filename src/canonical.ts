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
