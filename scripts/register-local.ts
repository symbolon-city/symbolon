// A register on this computer, in memory, for trying things out.
//   npm run register:local   →  http://127.0.0.1:8788
import { createServer } from "node:http";
import { generateKeyPair, MemoryStore, Register } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

const port = Number(process.env.PORT ?? 8788);
const base = `http://127.0.0.1:${port}`;
const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: base };

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const body = chunks.length ? Buffer.concat(chunks) : undefined;
  const r = await handle(new Request(base + req.url, { method: req.method, headers: req.headers as HeadersInit, body }), deps);
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, "127.0.0.1", () => console.log(`Register (in memory) on ${base}, key ${deps.register.publicKey}`));
