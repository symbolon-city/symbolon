// Keeps a full, checked copy of a Symbolon register, and tells if its history was ever rewritten.
//   npm run register:copy -- [register url] [copy file] [--key ed25519:<hex>]
// Defaults: the public test register, ./register-copy.json. Run it again later with the same file:
// the old copy must be the beginning of the new one.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { copyRegister, rewrittenSince, type RegisterCopy } from "../src/mirror.js";

const args = process.argv.slice(2);
const keyAt = args.indexOf("--key");
const key = keyAt >= 0 ? args.splice(keyAt, 2)[1] : undefined;
const url = args[0] ?? "https://registro-prova.symbolon-city.workers.dev";
const file = args[1] ?? "register-copy.json";

const { copy, problems } = await copyRegister(url, key ? { key } : {});
console.log(`${copy.register}: ${copy.entries.length} entries, head of ${copy.head.time}, key ${copy.key}`);
if (problems.length) {
  console.error("COPY DOES NOT MATCH THE SIGNED HEAD:\n- " + problems.join("\n- "));
  process.exit(1);
}
console.log("OK: every entry matches the head signed by the register's key.");
if (existsSync(file)) {
  const older = JSON.parse(readFileSync(file, "utf8")) as RegisterCopy;
  const rewritten = rewrittenSince(older, copy);
  if (rewritten) {
    console.error(`HISTORY REWRITTEN since the copy of ${older.copiedAt}: ${rewritten}. The old copy is kept in ${file}.`);
    process.exit(2);
  }
  console.log(`OK: the copy of ${older.copiedAt} (${older.entries.length} entries) is the beginning of this one: nothing was rewritten.`);
}
writeFileSync(file, JSON.stringify(copy, null, 1) + "\n");
console.log(`Saved to ${file}.`);
