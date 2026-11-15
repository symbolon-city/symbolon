// End-to-end check of the MCP door against a live register, as a real agent would use it.
//   SYMBOLON_REGISTER_URL=https://... npm run mcp:check
// Uses a throw-away wallet (temporary folder, random password) and a throw-away owner key.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createMandate, generateKeyPair } from "../src/index.js";

const url = process.env.SYMBOLON_REGISTER_URL;
if (!url) throw new Error("Set SYMBOLON_REGISTER_URL");
const home = mkdtempSync(join(tmpdir(), "symbolon-check-"));

const transport = new StdioClientTransport({
  command: "npx",
  args: ["tsx", "scripts/symbolon-mcp.ts"],
  env: {
    ...(process.env as Record<string, string>),
    SYMBOLON_REGISTER_URL: url,
    SYMBOLON_HOME: home,
    SYMBOLON_WALLET_KEY: "passphrase",
    SYMBOLON_WALLET_PASSWORD: randomBytes(24).toString("hex"),
  },
  stderr: "ignore",
});
const client = new Client({ name: "mcp-live-check", version: "0.1.0" });

async function call(name: string, args: Record<string, unknown> = {}) {
  const r = (await client.callTool({ name, arguments: args })) as { content: { text: string }[]; isError?: boolean };
  const text = r.content.map((c) => c.text).join("\n");
  if (r.isError) throw new Error(`${name}: ${text}`);
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

try {
  await client.connect(transport);
  const tools = (await client.listTools()).tools.map((t) => t.name);
  console.log(`1. Porta MCP aperta: ${tools.length} strumenti (${tools.join(", ")})`);

  const who = await call("symbolon_whoami");
  const agentKey: string = who.agentKey ?? who.agent_key ?? who.key ?? JSON.stringify(who).match(/ed25519:[0-9a-f]{64}/)?.[0];
  console.log(`2. Chiave dell'agente: ${agentKey}`);

  const owner = generateKeyPair();
  const now = new Date();
  const mandate = createMandate(owner, {
    ownerDomain: "prova.example",
    agent: agentKey,
    scope: "prova tecnica del notaio online",
    notBefore: now.toISOString(),
    notAfter: new Date(now.getTime() + 86_400_000).toISOString(),
    charter: "accord-charter/0.1",
  });
  await call("symbolon_install_mandate", { mandate });
  console.log("3. Delega del padrone (di prova) installata");

  const sealed = await call("symbolon_seal_action", {
    instruction: "Prova: sigilla la prima azione sul notaio online",
    action: "Azione di prova sigillata dalla porta MCP",
  });
  const entry: string = sealed.entry ?? JSON.stringify(sealed).match(/[0-9a-f]{64}/)?.[0];
  console.log(`4. Azione sigillata sul registro online. Impronta ${entry}, posizione ${sealed.index ?? sealed.receipt?.index ?? "?"}`);

  const proof = await call("symbolon_create_proof", { entry, reveal: [] });
  console.log("5. Fascicolo di prova creato");

  const check = await call("symbolon_verify_proof", { proof });
  console.log("6. Verifica del fascicolo:", check.verdict ?? check.valid, ...(check.gaps?.length ? ["\n   lacune: " + check.gaps.join("; ")] : []), "\n" + check.checks.map((c: { ok: boolean; name: string }) => `   ${c.ok ? "ok " : "NO "} ${c.name}`).join("\n"));
} finally {
  await client.close().catch(() => {});
  rmSync(home, { recursive: true, force: true });
}
