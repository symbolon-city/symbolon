// Checks a visitors' door from outside, with the official MCP client, like an agent would.
//   npm run door:check -- https://<door>/mcp
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const url = process.argv[2];
if (!url) throw new Error("usage: npm run door:check -- https://<door>/mcp");
const c = new Client({ name: "symbolon-door-check", version: "0" });
await c.connect(new StreamableHTTPClientTransport(new URL(url)));
const call = async (name: string, args: Record<string, unknown> = {}) => {
  const r = (await c.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
  if (r.isError) throw new Error(`${name}: ${r.content[0].text}`);
  return JSON.parse(r.content[0].text);
};
console.log("1. Server:", c.getServerVersion()?.name, c.getServerVersion()?.version);
console.log("2. Tools:", (await c.listTools()).tools.map((t) => t.name).join(", "));
const about = await call("symbolon_about");
console.log("3. Register:", about.register.url, "size", about.register.size);
console.log("4. Lookup of an unknown fingerprint:", JSON.stringify(await call("symbolon_lookup_fingerprint", { fingerprint: "0".repeat(64) })));
const guide = await call("piazza_guide", { question: "What is a mandate?" });
console.log("5. Guide:", String(guide.answer).slice(0, 100) + "…");
await c.close();
console.log("Door OK (nothing was written).");
