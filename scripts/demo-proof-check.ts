// Takes the latest demonstration agreement from the piazza and verifies its proof through the visitors' door,
// as any visiting agent would. Read-only.
//   npm run demo:check -- https://mcp.symboloncity.com/mcp https://piazza-prova.symbolon-city.workers.dev
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const [door, piazza] = process.argv.slice(2);
if (!door || !piazza) throw new Error("usage: npm run demo:check -- <door url>/mcp <piazza url>");
const list = (await (await fetch(piazza.replace(/\/+$/, "") + "/v1/demo/agreements")).json()) as { agreements: Array<{ entry: string; sealedAt: string; proof: unknown }> };
if (!list.agreements.length) throw new Error("no demonstration agreement yet");
const latest = list.agreements[0];
console.log(`1. Latest demo agreement ${latest.entry.slice(0, 16)}…, sealed ${latest.sealedAt}`);
const client = new Client({ name: "symbolon-demo-check", version: "0" });
await client.connect(new StreamableHTTPClientTransport(new URL(door)));
const r = (await client.callTool({ name: "symbolon_verify_proof", arguments: { proof: latest.proof } })) as { content: Array<{ text: string }>; isError?: boolean };
await client.close();
if (r.isError) throw new Error(r.content[0].text);
const report = JSON.parse(r.content[0].text) as { valid: boolean; verdict?: string; gaps?: string[]; checks: Array<{ name: string; ok: boolean; detail?: string }>; levels: Record<string, string>; disclosed: Record<string, unknown> };
for (const c of report.checks) console.log(`   ${c.ok ? "ok " : "NO "} ${c.name}${c.detail ? ` (${c.detail})` : ""}`);
console.log("2. Owners verified at level:", Object.values(report.levels).join(", "));
console.log("3. Revealed:", JSON.stringify(report.disclosed));
for (const g of report.gaps ?? []) console.log(`   gap ${g}`);
console.log(report.valid ? "Demo agreement proof VALID." : `Demo agreement proof NOT valid (${report.verdict ?? "invalid"}).`);
if (!report.valid) process.exit(1);
