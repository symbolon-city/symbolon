// The change book: builds the public pages from the data folder (writes files only, publishes nothing).
//   npm run book:site -- --data <folder> --out <folder>

import { resolve } from "node:path";
import { buildSite } from "../src/book/site.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}
const r = await buildSite(resolve(arg("data") ?? "book-data"), resolve(arg("out") ?? "book-site"));
console.log(`built ${r.items} item pages over ${r.days} day(s), ${r.changes} change(s) shown`);
