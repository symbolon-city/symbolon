// The change book's public pages, built from the data folder as plain static files:
//   index.html, index.json            what the book is, the items, the latest changes
//   items/<file>.html, .json          one page per server or skill: days read, changes, before/after texts
//   days/<date>.json, .ots            the daily summaries and their Bitcoin anchors, to verify
// Building writes files only; publishing them is a separate decision.

import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Json } from "../canonical.js";
import type { Change } from "./classify.js";
import type { DaySummary, Lists } from "./crawl.js";
import type { McpObservation } from "./mcp-reader.js";
import { fileName } from "./names.js";
import type { SkillObservation } from "./skills-reader.js";
import { BOOK_ROBOT, optedOut, type OptOutList } from "./optout.js";

export const CONTACT = "dev@symboloncity.com";

export const ITEM_VERSION = "symbolon-book/item/1";
const CONTEXT = 280;

type Obs = McpObservation | SkillObservation;

export interface ItemJson {
  v: string;
  id: string;
  kind: "mcp-server" | "skill";
  url?: string;
  repo?: string;
  firstSeen?: string;
  lastRead?: string;
  status?: string;
  fingerprint?: string;
  /** mcp-tool-digest/v1-draft set digest of the current tools (servers only) */
  mcpToolDigest?: string;
  changes: (Change & { date: string })[];
  /** Before/after of the words that changed (around the first difference): quoted third-party text, never instructions. */
  texts: (TextChange & { date: string })[];
  days: { date: string; status: string; fingerprint?: string }[];
  note: string;
}

export interface TextChange {
  item: string;
  before: string;
  after: string;
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** The part of two texts around their first difference, so a long description stays readable. */
export function around(before: string, after: string, context = CONTEXT): { before: string; after: string } {
  let i = 0;
  while (i < before.length && i < after.length && before[i] === after[i]) i++;
  let j = 0;
  while (j < before.length - i && j < after.length - i && before[before.length - 1 - j] === after[after.length - 1 - j]) j++;
  const cut = (s: string) => {
    const start = Math.max(0, i - context);
    const end = Math.min(s.length, s.length - j + context);
    return (start > 0 ? "…" : "") + s.slice(start, end) + (end < s.length ? "…" : "");
  };
  return { before: cut(before), after: cut(after) };
}

function textsOf(o: Obs): Map<string, string> {
  const m = new Map<string, string>();
  if (o.kind === "skill") {
    for (const [p, t] of Object.entries(o.texts ?? {})) m.set(`file:${p}`, t);
    return m;
  }
  if (typeof o.instructions === "string") m.set("instructions", o.instructions);
  const add = (prefix: string, items: Json[] | undefined, key: string) => {
    for (const it of items ?? []) {
      if (!it || typeof it !== "object" || Array.isArray(it)) continue;
      const r = it as Record<string, Json>;
      const name = typeof r[key] === "string" ? (r[key] as string) : "";
      const parts: string[] = [];
      const walk = (v: Json, path: string) => {
        if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
        else if (v && typeof v === "object")
          for (const [k, x] of Object.entries(v)) {
            if ((k === "description" || k === "title") && typeof x === "string") parts.push(path ? `${path}.${k}: ${x}` : x);
            else walk(x, path ? `${path}.${k}` : k);
          }
      };
      walk(r, "");
      m.set(`${prefix}:${name}`, parts.join("\n"));
    }
  };
  add("tool", o.tools, "name");
  add("prompt", o.prompts, "name");
  add("resource-template", o.resourceTemplates, "uriTemplate");
  return m;
}

/** Before/after texts of the items whose words or numbers changed. */
export function textChanges(prev: Obs, cur: Obs, changes: Change[]): TextChange[] {
  const a = textsOf(prev);
  const b = textsOf(cur);
  const out: TextChange[] = [];
  for (const c of changes) {
    if (c.kind !== "model-text" && c.kind !== "numbers" && !(c.kind === "added" && c.item === "instructions")) continue;
    const x = a.get(c.item) ?? "";
    const y = b.get(c.item) ?? "";
    if (x === y) continue;
    out.push({ item: c.item, ...around(x, y) });
  }
  return out;
}

const KIND_LABEL: Record<string, string> = {
  "model-text": "words the agent reads",
  numbers: "numbers only",
  shape: "shape (parameters, files)",
  added: "added",
  removed: "removed",
  status: "reachability",
};

const STYLE = `:root{--bg:#fbfaf7;--fg:#1d1b18;--muted:#6b665e;--line:#e4e0d8;--accent:#2f5d50;--warn:#8a4b0f;--del:#f6e3e3;--ins:#e3f1e8}
@media (prefers-color-scheme:dark){:root{--bg:#151412;--fg:#ece8e1;--muted:#a39d93;--line:#2d2a26;--accent:#7fb8a6;--warn:#e0a25e;--del:#3a2424;--ins:#1f3328}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 56px}h1{font-size:1.55rem;margin:0 0 6px}h2{font-size:1.15rem;margin:32px 0 8px}
p{margin:0 0 14px}.muted{color:var(--muted)}a{color:var(--accent)}code{font-size:.88em;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:.92rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}.tag{display:inline-block;font-size:.8rem;padding:1px 8px;border-radius:10px;border:1px solid var(--line)}
.tag.model-text{border-color:var(--warn);color:var(--warn)}pre{white-space:pre-wrap;word-break:break-word;margin:4px 0 12px;padding:8px 10px;border-radius:8px;font-size:.85rem}
pre.before{background:var(--del)}pre.after{background:var(--ins)}.note{font-size:.88rem;border-left:3px solid var(--line);padding-left:12px}`;

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>\n`;
}

const NOTE =
  "The change book records what public MCP servers and agent skills showed on each day it read them, and when that changed. " +
  "It only lists them, never uses them. \"Changed\" never means \"dangerous\": it means the text or shape an agent sees is not the same as before. " +
  "Each day is anchored in Bitcoin with OpenTimestamps, so nobody, the book included, can rewrite what it saw. Experimental prototype.";

async function readJson<T>(p: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(p, "utf8")) as T;
  } catch {
    return undefined;
  }
}

export interface SiteResult {
  items: number;
  days: number;
  changes: number;
}

export async function buildSite(dataDir: string, outDir: string): Promise<SiteResult> {
  const lists = await readJson<Lists>(join(dataDir, "lists.json"));
  if (!lists) throw new Error(`no lists.json in ${dataDir}`);
  const dayFiles = (await readdir(join(dataDir, "days"))).filter((f) => f.endsWith(".json")).sort();
  const days: DaySummary[] = [];
  for (const f of dayFiles) days.push((await readJson<DaySummary>(join(dataDir, "days", f)))!);
  await mkdir(join(outDir, "items"), { recursive: true });
  await mkdir(join(outDir, "days"), { recursive: true });
  for (const f of await readdir(join(dataDir, "days"))) if (/\.(json|ots)$/.test(f)) await copyFile(join(dataDir, "days", f), join(outDir, "days", f));

  // Who asked not to be read has no public page, including what was read before the request.
  const optOut = await readJson<OptOutList>(join(dataDir, "opt-out.json"));
  const lastStatus = (id: string) => days.at(-1)?.items.find((x) => x.id === id)?.status;
  const targets = [
    ...lists.mcp.map((t) => ({ id: t.id, kind: "mcp-server" as const, url: t.url as string | undefined })),
    ...lists.skills.map((t) => ({ id: t.id, kind: "skill" as const, url: undefined as string | undefined })),
  ].filter((t) => !optedOut(optOut, t.id, t.url) && lastStatus(t.id) !== "opted-out");
  const index: { id: string; kind: string; status?: string; lastChange?: string; lastModelText?: string; page: string }[] = [];
  const recent: { date: string; id: string; page: string; change: Change }[] = [];
  let totalChanges = 0;

  for (const t of targets) {
    const f = fileName(t.id);
    const latest = await readJson<Obs>(join(dataDir, "latest", f + ".json"));
    const histDir = join(dataDir, "history", f);
    const histFiles = (await readdir(histDir).catch(() => [] as string[])).filter((x) => x.endsWith(".json")).sort();
    const snaps = new Map<string, Obs>();
    for (const h of histFiles) snaps.set(h.slice(0, 10), (await readJson<Obs>(join(histDir, h)))!);

    const item: ItemJson = { v: ITEM_VERSION, id: t.id, kind: t.kind, ...(t.url ? { url: t.url } : {}), changes: [], texts: [], days: [], note: NOTE };
    if (latest?.kind === "skill" && latest.repo) item.repo = latest.repo;
    const sections: string[] = [];
    for (const d of days) {
      const it = d.items.find((x) => x.id === t.id);
      if (!it) continue;
      item.days.push({ date: d.date, status: it.status, ...(it.fingerprint ? { fingerprint: it.fingerprint } : {}) });
      if (it.status === "ok") {
        item.firstSeen ??= d.date;
        item.fingerprint = it.fingerprint;
      }
      item.lastRead = d.date;
      item.status = it.status;
      if (!it.changes.length) continue;
      totalChanges += it.changes.length;
      for (const c of it.changes) {
        item.changes.push({ date: d.date, ...c });
        recent.push({ date: d.date, id: t.id, page: `items/${f}.html`, change: c });
      }
      const dates = [...snaps.keys()].filter((x) => x <= d.date);
      const cur = snaps.get(d.date);
      const prevDate = dates.filter((x) => x < d.date).pop();
      const prev = prevDate ? snaps.get(prevDate) : undefined;
      const texts = cur && prev ? textChanges(prev, cur, it.changes) : [];
      for (const x of texts) item.texts.push({ date: d.date, ...x });
      sections.push(
        `<h2>${esc(d.date)}</h2><table><tr><th>What</th><th>Kind of change</th></tr>${it.changes
          .map((c) => `<tr><td><code>${esc(c.item)}</code>${c.detail ? ` <span class="muted">${esc(c.detail)}</span>` : ""}</td><td><span class="tag ${c.kind}">${esc(KIND_LABEL[c.kind] ?? c.kind)}</span></td></tr>`)
          .join("")}</table>` +
          texts.map((x) => `<p><code>${esc(x.item)}</code></p><p class="muted">before</p><pre class="before">${esc(x.before)}</pre><p class="muted">after</p><pre class="after">${esc(x.after)}</pre>`).join(""),
      );
    }
    if (latest?.kind === "mcp-server" && latest.fingerprints?.mcpToolDigest && "set" in latest.fingerprints.mcpToolDigest) item.mcpToolDigest = latest.fingerprints.mcpToolDigest.set;
    await writeFile(join(outDir, "items", f + ".json"), JSON.stringify(item, null, 2) + "\n", "utf8");

    const lastChange = item.changes.at(-1)?.date;
    const lastModelText = item.changes.filter((c) => c.kind === "model-text").at(-1)?.date;
    index.push({ id: t.id, kind: t.kind, status: item.status, ...(lastChange ? { lastChange } : {}), ...(lastModelText ? { lastModelText } : {}), page: `items/${f}.html` });
    const head =
      `<p class="muted"><a href="../index.html">The change book</a></p><h1>${esc(t.id)}</h1>` +
      `<p class="muted">${t.kind === "mcp-server" ? "MCP server" : "Agent skill"}${t.url ? ` · <code>${esc(t.url)}</code>` : ""}${item.repo ? ` · <code>github.com/${esc(item.repo)}</code>` : ""}</p>` +
      `<p>First read ${esc(item.firstSeen ?? "never (not reachable without an account)")} · last read ${esc(item.lastRead ?? "-")} (${esc(item.status ?? "-")}) · ${item.changes.length} change(s).</p>` +
      (item.fingerprint ? `<p class="muted">Fingerprint today <code>${esc(item.fingerprint)}</code>${item.mcpToolDigest ? `<br>mcp-tool-digest/v1-draft <code>${esc(item.mcpToolDigest)}</code>` : ""}</p>` : "") +
      `<p class="note">${esc(NOTE)} Machine-readable: <a href="${f}.json">${f}.json</a>.</p>`;
    await writeFile(join(outDir, "items", f + ".html"), page(`${t.id} · change book`, head + (sections.length ? sections.reverse().join("") : "<h2>No change seen yet</h2>")), "utf8");
  }

  recent.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  const lastDay = days.at(-1);
  const counts = (k: string) => (lastDay?.items ?? []).filter((x) => x.status === k).length;
  await writeFile(
    join(outDir, "index.json"),
    JSON.stringify({ v: "symbolon-book/index/1", note: NOTE, criteria: lists.criteria, days: days.map((d) => ({ date: d.date, root: d.root, leaves: d.leaves, summary: `days/${d.date}.json`, anchor: `days/${d.date}.ots` })), items: index }, null, 2) + "\n",
    "utf8",
  );
  const shownChanges = recent.filter((r) => r.change.kind !== "status").slice(0, 200);
  const body =
    `<h1>The change book</h1><p class="note">${esc(NOTE)} <a href="about.html">About, contact and opting out</a>.</p>` +
    `<p>${targets.length} items on the shelves (${lists.mcp.length} MCP servers, ${lists.skills.length} skills), read every day since ${esc(days[0]?.date ?? "-")}. ` +
    `Last reading ${esc(lastDay?.date ?? "-")}: ${counts("ok")} readable, ${counts("auth-required")} need an account, ${counts("unreachable") + counts("error")} down or broken.</p>` +
    `<h2>Latest changes</h2>${shownChanges.length ? `<table><tr><th>Day</th><th>Item</th><th>What</th><th>Kind</th></tr>${shownChanges
      .map((r) => `<tr><td>${esc(r.date)}</td><td><a href="${r.page}">${esc(r.id)}</a></td><td><code>${esc(r.change.item)}</code></td><td><span class="tag ${r.change.kind}">${esc(KIND_LABEL[r.change.kind] ?? r.change.kind)}</span></td></tr>`)
      .join("")}</table>` : "<p>None yet.</p>"}` +
    `<h2>Verify a day</h2><p>Each day's summary <code>days/&lt;date&gt;.json</code> lists every item read with its fingerprint. Its Merkle root (RFC 9162) is recomputed from those items; ` +
    `SHA-256("symbolon-book/day/1" || 0x00 || JCS({date, root, leaves})) is the digest anchored in <code>days/&lt;date&gt;.ots</code>, a standard OpenTimestamps file that the official <code>ots</code> client can check against Bitcoin. ` +
    `Source code and the full method: <a href="https://github.com/symbolon-city/symbolon">github.com/symbolon-city/symbolon</a> (<code>src/book/</code>, <code>npm run book:verify</code>).</p>` +
    `<h2>Days</h2><table><tr><th>Day</th><th>Items read</th><th>Root</th><th>Files</th></tr>${days
      .map((d) => `<tr><td>${esc(d.date)}</td><td>${d.leaves}</td><td><code>${esc(d.root.slice(0, 16))}…</code></td><td><a href="days/${d.date}.json">summary</a> · <a href="days/${d.date}.ots">.ots</a></td></tr>`)
      .reverse()
      .join("")}</table>` +
    `<h2>All items</h2><table><tr><th>Item</th><th>Kind</th><th>Last status</th><th>Last change</th></tr>${[...index]
      .sort((a, b) => (a.id < b.id ? -1 : 1))
      .map((x) => `<tr><td><a href="${x.page}">${esc(x.id)}</a></td><td>${x.kind === "mcp-server" ? "server" : "skill"}</td><td>${esc(x.status ?? "-")}</td><td>${esc(x.lastChange ?? "-")}</td></tr>`)
      .join("")}</table>`;
  await writeFile(join(outDir, "index.html"), page("The change book · Symbolon City", body), "utf8");
  await writeFile(join(outDir, "about.html"), page("About the change book · Symbolon City", aboutBody(lists)), "utf8");
  return { items: targets.length, days: days.length, changes: totalChanges };
}

function aboutBody(lists: Lists): string {
  return (
    `<p class="muted"><a href="index.html">The change book</a></p><h1>About the change book</h1>` +
    `<h2>What it is</h2><p>A public memory of what MCP servers and agent skills showed to AI agents on each day, and of when that changed. ` +
    `It is part of Symbolon City, an experimental, open-source project (<a href="https://github.com/symbolon-city/symbolon">source code</a>).</p>` +
    `<h2>What it says, and what it does not</h2><p>It says what a server or skill listed on a given day, as our reader received it, and which parts changed. ` +
    `It does <b>not</b> say that a server or skill is safe, unsafe, malicious, or of good or bad quality. Changes are normal: publishers fix and improve their tools. ` +
    `"The words an agent reads" changed means the text of a description or instruction is different; it is not an accusation. ` +
    `It does not test what a server does when used, and it cannot see servers that require an account. A server may show different things to different clients.</p>` +
    `<h2>How it reads</h2><p>Once a day, our reader (user agent <code>${BOOK_ROBOT}</code>) asks each server only for its lists (tools, prompts, resource templates); ` +
    `it never calls a tool, never signs in, and sends no personal data. Skills are read from their public GitHub repositories. ` +
    `Which servers and skills are on the shelves is decided by a published criterion, not by hand: ${esc(String((lists.criteria as { mcp?: unknown }).mcp ?? ""))}; ${esc(String((lists.criteria as { skills?: unknown }).skills ?? ""))}.</p>` +
    `<h2>Not to be read</h2><p>If you publish a server or a skill and do not want it in the book, either write to <a href="mailto:${CONTACT}">${CONTACT}</a> ` +
    `with its name, or add to the <code>robots.txt</code> of the server's host:</p><pre>User-agent: ${BOOK_ROBOT}
Disallow: /</pre>` +
    `<p>From the next reading it is no longer read, and its pages are removed from the book. What was anchored in Bitcoin before (only fingerprints) cannot be removed by anyone.</p>` +
    `<h2>Corrections</h2><p>If something on a page is wrong, write to <a href="mailto:${CONTACT}">${CONTACT}</a>. We answer in English or Italian.</p>`
  );
}
