// The change book: check a day the way anyone could, from the files alone and Bitcoin.
//   npm run book:verify -- --data <folder> [--date YYYY-MM-DD] [--id <server or skill>]
// Without --date: every day. With --id: also recomputes that item's fingerprint from its kept
// snapshot (history/) and checks it is the one in the day, so the snapshot is tied to Bitcoin.

import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { esploraProvider } from "../src/anchor.js";
import { fileName, type DaySummary } from "../src/book/crawl.js";
import { snapshotFingerprint, verifyDay } from "../src/book/day-anchor.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}
const dataDir = resolve(arg("data") ?? "book-data");
const id = arg("id");
const dates = arg("date") ? [arg("date")!] : (await readdir(join(dataDir, "days"))).filter((f) => f.endsWith(".json")).map((f) => f.slice(0, -5)).sort();
const blocks = esploraProvider();
let bad = 0;
for (const date of dates) {
  const r = await verifyDay(dataDir, date, blocks);
  const a = r.anchor;
  const anchor = a.status === "confirmed" ? `in Bitcoin, block ${a.height} (${a.blockTime})` : a.status === "pending" ? "waiting for Bitcoin (a few hours)" : a.status === "missing" ? "not anchored" : `INVALID: ${a.reason}`;
  if (!r.rootMatches || a.status === "invalid") bad++;
  console.log(`${date}: root ${r.rootMatches ? "matches its items" : "DOES NOT MATCH its items"}; ${anchor}`);
  if (id) {
    const day = JSON.parse(await readFile(join(dataDir, "days", `${date}.json`), "utf8")) as DaySummary;
    const item = day.items.find((i) => i.id === id);
    if (!item?.fingerprint) {
      console.log(`  ${id}: not read that day`);
      continue;
    }
    const dir = join(dataDir, "history", fileName(id));
    const kept = (await readdir(dir)).filter((f) => f.endsWith(".json") && f.slice(0, 10) <= date).sort();
    const snap = kept.length ? JSON.parse(await readFile(join(dir, kept[kept.length - 1]), "utf8")) : undefined;
    const fp = snap ? snapshotFingerprint(snap) : undefined;
    if (fp !== item.fingerprint) bad++;
    console.log(`  ${id}: snapshot ${kept.at(-1) ?? "(none)"} gives ${fp === item.fingerprint ? "the fingerprint of the day" : "ANOTHER fingerprint"} (${item.fingerprint.slice(0, 16)}...)`);
  }
}
process.exitCode = bad ? 1 : 0;
