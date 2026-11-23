// The change book, shelf 2: reads a public agent skill (a folder with SKILL.md) from its GitHub
// repository at the current commit of the default branch, and fingerprints every file in it.
// Git keeps its own history, but it can be rewritten (force pushes, moved tags) and names nobody
// who answers for a version: the book keeps an outside memory of what was there and when.

import { fingerprintRfc8785 } from "../fingerprint.js";
import { sha256 } from "@noble/hashes/sha2";
import { toHex } from "../bytes.js";
import { classifyError, type ObservationStatus } from "./mcp-reader.js";

const MAX_FILES = 100;
const MAX_FILE_BYTES = 512 * 1024;
/** Text the agent reads as instructions: kept in full so changes can be shown. */
const KEEP_TEXT = /\.(md|mdx|txt)$/i;
const MAX_KEPT_TEXT = 64 * 1024;

export interface SkillTarget {
  /** "owner/repo/skill", as listed on skills.sh. */
  id: string;
}

export interface SkillObservation {
  kind: "skill";
  id: string;
  observedAt: string;
  status: ObservationStatus;
  error?: string;
  repo?: string;
  commit?: string;
  dir?: string;
  /** path inside the skill folder -> sha256 of the bytes, or "skipped:<reason>" */
  files?: Record<string, string>;
  /** Instruction text files (SKILL.md and other .md), in full. */
  texts?: Record<string, string>;
  fingerprint?: string;
}

export interface SkillReadOptions {
  fetchImpl?: typeof fetch;
  githubToken?: string;
  now?: () => Date;
  /** Last good observation: if the commit has not changed, its files are reused (same commit, same bytes). */
  previous?: SkillObservation;
  userAgent?: string;
}

interface TreeEntry {
  path: string;
  type: string;
  size?: number;
}

function enc(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

function frontmatterName(md: string): string | undefined {
  const m = /^---\s*\n([\s\S]*?)\n---/.exec(md.replace(/^﻿/, ""));
  const n = m && /^name:\s*["']?([^"'\n]+?)["']?\s*$/m.exec(m[1]);
  return n ? n[1].trim() : undefined;
}

export async function readSkill(t: SkillTarget, o: SkillReadOptions = {}): Promise<SkillObservation> {
  const f = o.fetchImpl ?? fetch;
  const observedAt = (o.now ?? (() => new Date()))().toISOString();
  const base: SkillObservation = { kind: "skill", id: t.id, observedAt, status: "error" };
  const parts = t.id.split("/");
  if (parts.length !== 3 || parts.some((p) => !p)) return { ...base, error: "id must be owner/repo/skill" };
  const [owner, repo, skill] = parts;
  const headers: Record<string, string> = { "User-Agent": o.userAgent ?? "SymbolonBook/0.1", Accept: "application/vnd.github+json" };
  if (o.githubToken) headers.Authorization = `Bearer ${o.githubToken}`;
  const api = async (path: string, accept?: string): Promise<Response> => {
    const res = await f(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}${path}`, {
      headers: accept ? { ...headers, Accept: accept } : headers,
    });
    if (!res.ok) throw new Error(`GitHub ${path || "/"}: HTTP ${res.status}`);
    return res;
  };
  const raw = async (commit: string, path: string): Promise<Uint8Array> => {
    const res = await f(`https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${commit}/${enc(path)}`, {
      headers: { "User-Agent": headers["User-Agent"] },
    });
    if (!res.ok) throw new Error(`raw ${path}: HTTP ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  };
  try {
    const info = (await (await api("")).json()) as { default_branch?: string };
    const branch = info.default_branch ?? "main";
    const commit = (await (await api(`/commits/${encodeURIComponent(branch)}`, "application/vnd.github.sha")).text()).trim();
    if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("unexpected commit id");
    const prev = o.previous;
    if (prev && prev.status === "ok" && prev.commit === commit && prev.files && prev.fingerprint) {
      return { ...prev, observedAt };
    }
    const tree = (await (await api(`/git/trees/${commit}?recursive=1`)).json()) as { tree?: TreeEntry[]; truncated?: boolean };
    const blobs = (tree.tree ?? []).filter((e) => e.type === "blob");
    const skillFiles = blobs.filter((e) => /(^|\/)SKILL\.md$/i.test(e.path));
    if (!skillFiles.length) return { ...base, status: "error", repo: `${owner}/${repo}`, commit, error: "no SKILL.md in repository" };
    const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
    const baseName = (d: string) => d.slice(d.lastIndexOf("/") + 1).toLowerCase();
    let chosen = skillFiles.filter((e) => baseName(dirOf(e.path)) === skill.toLowerCase());
    if (chosen.length !== 1) {
      const candidates = (chosen.length ? chosen : skillFiles).slice(0, 60);
      chosen = [];
      for (const c of candidates) {
        const name = frontmatterName(new TextDecoder().decode(await raw(commit, c.path)));
        if (name && name.toLowerCase() === skill.toLowerCase()) chosen.push(c);
      }
      if (!chosen.length && skillFiles.length === 1) chosen = skillFiles;
    }
    if (!chosen.length) return { ...base, repo: `${owner}/${repo}`, commit, error: `cannot tell which SKILL.md is "${skill}"` };
    // Several copies (e.g. the same skill packaged twice): take the shortest path, then the first by name.
    chosen.sort((a, b) => a.path.length - b.path.length || (a.path < b.path ? -1 : 1));
    const dir = dirOf(chosen[0].path);
    const inside = blobs.filter((e) => (dir ? e.path.startsWith(dir + "/") : true)).sort((a, b) => (a.path < b.path ? -1 : 1));
    const files: Record<string, string> = {};
    const texts: Record<string, string> = {};
    for (const [i, e] of inside.entries()) {
      const rel = dir ? e.path.slice(dir.length + 1) : e.path;
      if (i >= MAX_FILES) {
        files[rel] = "skipped:too-many-files";
        continue;
      }
      if ((e.size ?? 0) > MAX_FILE_BYTES) {
        files[rel] = `skipped:size-${e.size}`;
        continue;
      }
      const bytes = await raw(commit, e.path);
      files[rel] = toHex(sha256(bytes));
      if (KEEP_TEXT.test(rel) && bytes.length <= MAX_KEPT_TEXT) texts[rel] = new TextDecoder().decode(bytes);
    }
    if (tree.truncated) files["(tree)"] = "skipped:github-tree-truncated";
    return {
      ...base,
      status: "ok",
      repo: `${owner}/${repo}`,
      commit,
      dir,
      files,
      texts,
      fingerprint: fingerprintRfc8785({ files }).fingerprint,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const status: ObservationStatus = /HTTP 404/.test(msg) ? "unreachable" : classifyError(msg);
    return { ...base, status, error: msg.slice(0, 300) };
  }
}
