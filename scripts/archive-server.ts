// A minimal archive of commitments for one owner, to run on a machine the owner controls.
//   npm run archive:serve [-- --port 8790] [--file archive-store.json]
// It reads the owner's key from ./owner-archive.json (made by `npm run owner -- archive-key`), accepts
// sealed snapshots only from agents whose mandate comes from that owner, keeps the latest of each agent in a
// file, and lists them. It cannot read them: only the owner opens them (`npm run owner -- commitments`).
// Put it behind HTTPS (a reverse proxy, a tunnel) before giving its address to the wallets.

import { createServer } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { handleArchive, type ArchiveStore, type Snapshot } from "../src/archive.js";

const args = process.argv.slice(2);
const opt = (name: string, dflt: string) => (args.includes(`--${name}`) ? args[args.indexOf(`--${name}`) + 1] : dflt);
const port = Number(opt("port", "8790"));
const file = opt("file", "archive-store.json");
const ownerKey = (JSON.parse(readFileSync(process.env.SYMBOLON_ARCHIVE_FILE ?? "owner-archive.json", "utf8")) as { claim: { body: { owner: { key: string } } } }).claim.body.owner.key;

class FileArchiveStore implements ArchiveStore {
  private data: Record<string, Snapshot> = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
  async put(agent: string, seq: number, s: Snapshot) {
    if (this.data[agent] && this.data[agent].body.seq >= seq) return false;
    this.data[agent] = s;
    writeFileSync(file, JSON.stringify(this.data));
    return true;
  }
  async all() {
    return Object.values(this.data);
  }
}
const store = new FileArchiveStore();

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const r = await handleArchive(
    new Request(`http://localhost${req.url}`, { method: req.method, headers: { "content-type": "application/json" }, ...(req.method === "PUT" ? { body: Buffer.concat(chunks) } : {}) }),
    { store, ownerKey },
  );
  res.writeHead(r.status, { "content-type": "application/json" });
  res.end(await r.text());
}).listen(port, () => console.log(`Archive of commitments for owner key ${ownerKey} on http://localhost:${port} (file ${file})`));
