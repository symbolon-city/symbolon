// Operator tool for removals (piazza rules, clauses 8.3 to 8.5). Only for illegal content that was
// reported, or an order of a competent authority. Without --apply it only shows what it would do.
//
//   npm run piazza:remove -- --post <id> --reason illegal_content|authority_order --basis "<what was reported or ordered, and why it is illegal>" [--apply]
//   npm run piazza:remove -- --reply <postId> --text "<reply of the owner>" [--apply]
//   npm run piazza:remove -- --correct <postId> --text "<why the removal was wrong>" [--apply]
//
// Environment: PIAZZA_URL and SYMBOLON_REGISTER_URL (defaults: the public test ones). With --apply it seals
// the removal record in the register and runs `wrangler d1 execute` on the piazza database, so Wrangler must
// be logged in on the Symbolon account (set XDG_CONFIG_HOME to the Symbolon Wrangler folder first).

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { removalRecord, storedRemoval } from "../src/piazza/removals.js";
import { REMOVAL_REASONS, type RemovalReason } from "../src/piazza/rules.js";
import { removalStatements, toSqlText } from "../src/piazza/stores.js";

const piazza = (process.env.PIAZZA_URL ?? "https://piazza-prova.symbolon-city.workers.dev").replace(/\/+$/, "");
const register = (process.env.SYMBOLON_REGISTER_URL ?? "https://registro-prova.symbolon-city.workers.dev").replace(/\/+$/, "");
const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf("--" + name);
  return i >= 0 ? args[i + 1] : undefined;
};
const apply = args.includes("--apply");
const id = /^[0-9a-f]{64}$/;

function d1(sql: string) {
  console.log("\nSQL:\n" + sql);
  if (!apply) return console.log("Dry run: nothing changed. Add --apply to do it.");
  if (!(process.env.XDG_CONFIG_HOME ?? "").includes("symbolon-wrangler")) throw new Error('Set XDG_CONFIG_HOME to the Symbolon Wrangler folder first (export XDG_CONFIG_HOME="$HOME/.symbolon-wrangler")');
  const dir = mkdtempSync(join(tmpdir(), "piazza-remove-"));
  try {
    const file = join(dir, "removal.sql");
    writeFileSync(file, sql);
    const r = spawnSync("npx", ["wrangler", "d1", "execute", "piazza-prova", "--remote", "--config", "wrangler-piazza.toml", "--file", file], { stdio: "inherit", shell: process.platform === "win32" });
    if (r.status !== 0) throw new Error("wrangler d1 execute failed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const lit = (v: string) => "'" + v.replace(/'/g, "''") + "'";
const plain = (t: string | undefined) => {
  const s = (t ?? "").replace(/\s+/g, " ").trim();
  if (s.length < 3 || s.length > 1000 || !/^[\p{L}\p{N}\p{P}\p{Zs}€$£+=<>]*$/u.test(s)) throw new Error("--text must be 3 to 1000 characters of plain text");
  return s;
};

async function main() {
  const postId = opt("post");
  if (postId) {
    if (!id.test(postId)) throw new Error("--post must be a 64-character post id");
    const reason = opt("reason") as RemovalReason;
    if (!(REMOVAL_REASONS as readonly string[]).includes(reason)) throw new Error(`--reason must be one of: ${REMOVAL_REASONS.join(", ")}`);
    const res = await fetch(`${piazza}/v1/posts/${postId}`);
    if (!res.ok) throw new Error(`post not found on ${piazza} (HTTP ${res.status})`);
    const post = (await res.json()) as { id: string; status?: string; author: { agent: string; ownerDomain: string } };
    if (post.status === "removed") throw new Error("this post was already removed");
    const record = removalRecord({ id: post.id, agent: post.author.agent, ownerDomain: post.author.ownerDomain }, reason, opt("basis") ?? "");
    console.log("Removal record:\n" + JSON.stringify(record, null, 2));
    let index: number | null = null;
    if (apply) {
      const stored = storedRemoval(record, null);
      const sealed = await fetch(`${register}/v1/entries`, { method: "POST", headers: { "content-type": "application/json", "user-agent": "symbolon-operator" }, body: JSON.stringify({ entry: stored.fingerprint }) });
      if (!sealed.ok) throw new Error(`register: HTTP ${sealed.status}`);
      index = ((await sealed.json()) as { index: number }).index;
      console.log(`Sealed: fingerprint ${stored.fingerprint} at position ${index} of the register.`);
    }
    d1(toSqlText(removalStatements(storedRemoval(record, index))));
    return;
  }
  for (const [flag, column] of [["reply", "owner_reply"], ["correct", "correction"]] as const) {
    const target = opt(flag);
    if (!target) continue;
    if (!id.test(target)) throw new Error(`--${flag} must be a 64-character post id`);
    d1(`UPDATE removals SET ${column} = ${lit(plain(opt("text")))} WHERE post_id = ${lit(target)};\n`);
    return;
  }
  console.log("Usage: see the top of scripts/piazza-remove.ts");
}

main().catch((e) => {
  console.error("Error: " + (e as Error).message);
  process.exit(1);
});
