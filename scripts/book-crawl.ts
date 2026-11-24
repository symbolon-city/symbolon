// The change book, local prototype: one reading a day.
//   npm run book:crawl -- --data <folder> [--mcp 50] [--skills 50] [--new-lists] [--grow] [--lists-only]
// The first run chooses the lists (official MCP registry: open remote servers, a fixed sample by
// hash of the name; skills.sh: the first skills of its ranking) and writes them to lists.json.
// Later runs reuse them. --grow keeps the items already on the lists and adds the next ones by the
// same criteria up to --mcp / --skills, so the day-by-day comparison of the first ones goes on. Nothing is published and nothing is sent to a register: each day's
// digest (32 bytes) goes to the OpenTimestamps calendars, which put it in Bitcoin (--no-anchor: skip).

import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { runDay, type Lists } from "../src/book/crawl.js";
import { stampMissing, upgradeDays } from "../src/book/day-anchor.js";
import { READER_USER_AGENT } from "../src/book/mcp-reader.js";
import { registryCandidates, sampleByHash, skillsFromHomePage } from "../src/book/lists.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const dataDir = resolve(arg("data") ?? "book-data");
const nMcp = Number(arg("mcp") ?? 50);
const nSkills = Number(arg("skills") ?? 50);

function githubToken(): string | undefined {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  try {
    return execFileSync("gh", ["auth", "token"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || undefined;
  } catch {
    return undefined;
  }
}

async function loadOrChooseLists(): Promise<Lists> {
  const path = join(dataDir, "lists.json");
  let old: Lists | undefined;
  try {
    old = JSON.parse(await readFile(path, "utf8")) as Lists;
  } catch {}
  const grow = process.argv.includes("--grow");
  if (old && !grow && !process.argv.includes("--new-lists")) return old;
  console.log("choosing lists: reading the official MCP registry...");
  const { targets, stats } = await registryCandidates(fetch, 2000, READER_USER_AGENT);
  const html = await (await fetch("https://skills.sh/", { headers: { "User-Agent": READER_USER_AGENT } })).text();
  let mcp = sampleByHash(targets, nMcp);
  let skills = skillsFromHomePage(html, nSkills);
  if (grow && old) {
    // Keep every item already read (even if it left the registry or the ranking), then fill up in the same order.
    const haveM = new Set(old.mcp.map((t) => t.id));
    mcp = [...old.mcp, ...sampleByHash(targets, targets.length).filter((t) => !haveM.has(t.id))].slice(0, Math.max(nMcp, old.mcp.length));
    const haveS = new Set(old.skills.map((t) => t.id));
    skills = [...old.skills, ...skillsFromHomePage(html, 10_000).filter((t) => !haveS.has(t.id))].slice(0, Math.max(nSkills, old.skills.length));
  }
  const lists: Lists = {
    createdAt: grow && old ? old.createdAt : new Date().toISOString(),
    mcp,
    skills,
    criteria: {
      mcp: "official MCP registry (latest versions, active), remote https servers without required headers or URL variables; first N by SHA-256 of the name",
      skills: "skills.sh home page ranking, first N hosted on GitHub",
      registry: stats,
      sampleSize: { mcp: mcp.length, skills: skills.length },
      ...(grow && old ? { grown: [...(((old.criteria as { grown?: unknown[] }).grown) ?? []), { at: new Date().toISOString(), from: { mcp: old.mcp.length, skills: old.skills.length }, to: { mcp: mcp.length, skills: skills.length } }] } : {}),
    },
  };
  await mkdir(dataDir, { recursive: true });
  await writeFile(path, JSON.stringify(lists, null, 2) + "\n", "utf8");
  console.log(`registry: ${stats.registryEntries} entries, ${stats.withRemote} remote, ${stats.withoutRequiredHeaders} open candidates`);
  return lists;
}

const lists = await loadOrChooseLists();
if (process.argv.includes("--lists-only")) {
  console.log(`lists: ${lists.mcp.length} servers, ${lists.skills.length} skills (not read now)`);
  process.exit(0);
}
console.log(`reading ${lists.mcp.length} servers and ${lists.skills.length} skills into ${dataDir}`);
const day = await runDay(lists, { dataDir, githubToken: githubToken() });
const count = (k: string) => day.items.filter((i) => i.status === k).length;
const changes = day.items.flatMap((i) => i.changes.map((c) => ({ id: i.id, ...c })));
console.log(`${day.date}: ok ${count("ok")}, auth-required ${count("auth-required")}, unreachable ${count("unreachable")}, error ${count("error")}`);
console.log(`changes: ${changes.length} (model-text ${changes.filter((c) => c.kind === "model-text").length}); root ${day.root} over ${day.leaves} observations`);
for (const c of changes.slice(0, 30)) console.log(`  ${c.kind.padEnd(10)} ${c.id}  ${c.item}${c.detail ? "  " + c.detail : ""}`);

if (!process.argv.includes("--no-anchor")) {
  const s = await stampMissing(dataDir);
  console.log(`anchor: stamped ${s.stamped.join(", ") || "none"}${s.failed.length ? `; calendars failed for ${s.failed.join(", ")} (retried next run)` : ""}`);
  const u = await upgradeDays(dataDir);
  console.log(`anchor: ${u.checked} day(s) checked, now in Bitcoin: ${u.upgraded.join(", ") || "none new"}`);
}
