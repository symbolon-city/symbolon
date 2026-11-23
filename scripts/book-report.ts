// The change book, local prototype: summary of all days read so far.
//   npm run book:report -- --data <folder>

import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { DaySummary } from "../src/book/crawl.js";

const i = process.argv.indexOf("--data");
const dataDir = resolve(i > 0 ? process.argv[i + 1] : "book-data");
const files = (await readdir(join(dataDir, "days"))).filter((f) => f.endsWith(".json")).sort();
const days = await Promise.all(files.map(async (f) => JSON.parse(await readFile(join(dataDir, "days", f), "utf8")) as DaySummary));

console.log(`${days.length} days read, from ${days[0]?.date} to ${days.at(-1)?.date}\n`);
for (const kind of ["mcp-server", "skill"] as const) {
  console.log(kind === "mcp-server" ? "MCP servers" : "Skills");
  for (const d of days) {
    const items = d.items.filter((x) => x.kind === kind);
    const by = (s: string) => items.filter((x) => x.status === s).length;
    const ch = items.flatMap((x) => x.changes);
    const changedItems = items.filter((x) => x.changes.some((c) => c.kind !== "status")).length;
    console.log(
      `  ${d.date}  ok ${by("ok")}/${items.length}  auth ${by("auth-required")}  down ${by("unreachable")}  error ${by("error")}  ` +
        `changed ${changedItems}  (model-text ${ch.filter((c) => c.kind === "model-text").length}, shape ${ch.filter((c) => c.kind === "shape").length}, ` +
        `added ${ch.filter((c) => c.kind === "added").length}, removed ${ch.filter((c) => c.kind === "removed").length}, status ${ch.filter((c) => c.kind === "status").length})`,
    );
  }
  const ever = new Set(days.flatMap((d) => d.items.filter((x) => x.kind === kind && x.changes.some((c) => c.kind !== "status")).map((x) => x.id)));
  const text = new Set(days.flatMap((d) => d.items.filter((x) => x.kind === kind && x.changes.some((c) => c.kind === "model-text")).map((x) => x.id)));
  console.log(`  items that changed at least once: ${ever.size}; with model-text changes: ${text.size}`);
  for (const id of text) console.log(`    model-text: ${id}`);
  console.log("");
}
