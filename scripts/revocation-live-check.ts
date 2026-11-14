// Live check of revocations through a visitors' door: signs a throwaway mandate and a revocation
// with throwaway keys, submits the revocation, and checks that the door reports the mandate revoked.
// It writes one revocation (and its fingerprint) to the register: use it on test registers.
//   npm run revocation:check -- https://mcp.symboloncity.com/mcp
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createMandate, createRevocation, generateKeyPair, mandateId } from "../src/index.js";

const url = process.argv[2];
if (!url) throw new Error("usage: npm run revocation:check -- <door url>/mcp");
const client = new Client({ name: "symbolon-revocation-check", version: "0" });
await client.connect(new StreamableHTTPClientTransport(new URL(url)));
const call = async (name: string, args: Record<string, unknown>) => {
  const r = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
  if (r.isError) throw new Error(r.content[0].text);
  return JSON.parse(r.content[0].text);
};

const owner = generateKeyPair();
const now = Date.now();
const mandate = createMandate(owner, {
  ownerDomain: "revocation-check.example",
  agent: generateKeyPair().publicKey,
  scope: "live check of revocations (throwaway keys)",
  notBefore: new Date(now - 60_000).toISOString(),
  notAfter: new Date(now + 3_600_000).toISOString(),
  charter: "accord-charter/0.1",
});
const before = await call("symbolon_check_counterparty", { mandate });
console.log("1. Before:", before.revoked ? "revoked" : "not revoked", "| revocations", before.revocations);
const sealed = await call("symbolon_submit_revocation", {
  revocation: createRevocation(owner, { target: { kind: "mandate", id: mandateId(mandate) }, reason: "live check" }),
});
console.log("2. Revocation sealed at register position", sealed.applies_from.register_index, sealed.applies_from.time);
const after = await call("symbolon_check_counterparty", { mandate });
console.log("3. After:", after.revoked ? `revoked on ${after.revoked.at} (${after.revoked.reason})` : "NOT revoked");
await client.close();
if (before.revoked || !after.revoked || after.revocations !== "checked") {
  console.error("Revocations NOT working.");
  process.exit(1);
}
console.log("Revocations OK.");
