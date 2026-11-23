// The change book, local prototype: one reading a day.
//   npm run book:crawl -- --data <folder> [--mcp 50] [--skills 50] [--new-lists]
// The first run chooses the lists (official MCP registry: open remote servers, a fixed sample by
// hash of the name; skills.sh: the first skills of its ranking) and writes them to lists.json.
// Later runs reuse them. Nothing is published and nothing is sent to a register.

import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { runDay, type Lists } from "../src/book/crawl.js";
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
  if (!process.argv.includes("--new-lists")) {
    try {
      return JSON.parse(await readFile(path, "utf8")) as Lists;
    } catch {}
  }
  console.log("choosing lists: reading the official MCP registry...");
  const { targets, stats } = await registryCandidates(fetch, 2000, READER_USER_AGENT);
  const mcp = sampleByHash(targets, nMcp);
  const html = await (await fetch("https://skills.sh/", { headers: { "User-Agent": READER_USER_AGENT } })).text();
  const skills = skillsFromHomePage(html, nSkills);
  const lists: Lists = {
    createdAt: new Date().toISOString(),
    mcp,
    skills,
    criteria: {
      mcp: "official MCP registry (latest versions, active), remote https servers without required headers or URL variables; first N by SHA-256 of the name",
      skills: "skills.sh home page ranking, first N hosted on GitHub",
      registry: stats,
      sampleSize: { mcp: mcp.length, skills: skills.length },
    },
  };
  await mkdir(dataDir, { recursive: true });
  await writeFile(path, JSON.stringify(lists, null, 2) + "\n", "utf8");
  console.log(`registry: ${stats.registryEntries} entries, ${stats.withRemote} remote, ${stats.withoutRequiredHeaders} open candidates`);
  return lists;
}

const lists = await loadOrChooseLists();
console.log(`reading ${lists.mcp.length} servers and ${lists.skills.length} skills into ${dataDir}`);
const day = await runDay(lists, { dataDir, githubToken: githubToken() });
const count = (k: string) => day.items.filter((i) => i.status === k).length;
const changes = day.items.flatMap((i) => i.changes.map((c) => ({ id: i.id, ...c })));
console.log(`${day.date}: ok ${count("ok")}, auth-required ${count("auth-required")}, unreachable ${count("unreachable")}, error ${count("error")}`);
console.log(`changes: ${changes.length} (model-text ${changes.filter((c) => c.kind === "model-text").length}); root ${day.root} over ${day.leaves} observations`);
for (const c of changes.slice(0, 30)) console.log(`  ${c.kind.padEnd(10)} ${c.id}  ${c.item}${c.detail ? "  " + c.detail : ""}`);
