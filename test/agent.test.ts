import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { MemoryStore, Register, createMandate, generateKeyPair, staticOwnerResolver, type Mandate } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

/** A register reachable through a fake fetch, like a real one over HTTP. */
function registerClient() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const f: typeof fetch = async (input, init) => handle(new Request(String(input), init), deps);
  return new HttpRegisterClient("https://reg.example", f);
}

async function agentWithOwner(domain: string, client: HttpRegisterClient, resolverTable: Record<string, string[]>, maxAmount?: string) {
  const owner = generateKeyPair();
  resolverTable[domain] = [owner.publicKey];
  const wallet = await Wallet.open(new MemoryWalletStorage(), client, { ownerResolver: staticOwnerResolver(resolverTable) });
  const mandate = createMandate(owner, {
    ownerDomain: domain,
    agent: wallet.agentKey,
    scope: "office supplies",
    ...(maxAmount ? { maxAmount: { value: maxAmount, currency: "EUR" } } : {}),
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2027-12-31T23:59:59Z",
    charter: "accord-charter/0.1",
  });
  const mcp = new Client({ name: `agent-${domain}`, version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await buildMcpServer(wallet).connect(a);
  await mcp.connect(b);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = (await mcp.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
    const text = r.content[0].text;
    if (r.isError) throw new Error(text);
    return JSON.parse(text);
  };
  return { wallet, mandate, call };
}

test("two agents agree through MCP, and a third party verifies the proof", async () => {
  const client = registerClient();
  const table: Record<string, string[]> = {};
  const buyer = await agentWithOwner("alfa.example", client, table, "50000.00");
  const seller = await agentWithOwner("beta.example", client, table);

  const tools = (await (async () => {
    const c = new Client({ name: "probe", version: "0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await buildMcpServer(buyer.wallet).connect(a);
    await c.connect(b);
    return c.listTools();
  })()).tools.map((t) => t.name);
  assert.ok(tools.includes("symbolon_propose_agreement") && tools.includes("symbolon_verify_proof"));

  await buyer.call("symbolon_install_mandate", { mandate: buyer.mandate });
  await seller.call("symbolon_install_mandate", { mandate: JSON.stringify(seller.mandate) }); // strings accepted too

  const sellerMandate = (await seller.call("symbolon_my_mandate")) as Mandate;
  const check = await buyer.call("symbolon_check_counterparty", { mandate: sellerMandate });
  assert.equal(check.ok, true);
  assert.equal(check.level, "domain");

  const offer = await buyer.call("symbolon_propose_agreement", {
    counterparty_mandate: sellerMandate,
    clauses: { object: "10000 boxes of A4 paper", amount: { value: "42000.00", currency: "EUR" }, delivery: "2026-12-10" },
  });
  const accepted = await seller.call("symbolon_accept_agreement", { offer });
  assert.equal(accepted.counterparty.owner, "alfa.example");
  const confirmed = await buyer.call("symbolon_confirm_agreement", { confirmation: accepted.confirmation });
  assert.equal(confirmed.entry, accepted.entry);

  const proof = await buyer.call("symbolon_create_proof", { entry: accepted.entry, reveal: ["delivery"] });
  assert.equal(proof.disclosures.length, 1);
  const report = await seller.call("symbolon_verify_proof", { proof });
  // Only the delivery date is shown, but the buyer's mandate has a limit: nothing failed, yet it is not complete.
  assert.deepEqual(report.checks.filter((c: { ok: boolean }) => !c.ok), []);
  assert.equal(report.verdict, "incomplete");
  assert.deepEqual(report.disclosed, { delivery: "2026-12-10" });
  const full = await buyer.call("symbolon_create_proof", { entry: accepted.entry, reveal: ["delivery", "amount", "object"] });
  const fullReport = await seller.call("symbolon_verify_proof", { proof: full });
  assert.equal(fullReport.valid, true, JSON.stringify([fullReport.gaps, fullReport.checks.filter((c: { ok: boolean }) => !c.ok)]));
});

test("an offer above the buyer's limit is refused by the buyer's own wallet", async () => {
  const client = registerClient();
  const table: Record<string, string[]> = {};
  const buyer = await agentWithOwner("alfa.example", client, table, "1000.00");
  const seller = await agentWithOwner("beta.example", client, table);
  await buyer.call("symbolon_install_mandate", { mandate: buyer.mandate });
  await seller.call("symbolon_install_mandate", { mandate: seller.mandate });
  await assert.rejects(
    buyer.call("symbolon_propose_agreement", { counterparty_mandate: seller.mandate, clauses: { amount: { value: "5000.00", currency: "EUR" } } }),
    /exceeds the mandate/,
  );
});

test("a tampered offer is refused by the accepting agent", async () => {
  const client = registerClient();
  const table: Record<string, string[]> = {};
  const buyer = await agentWithOwner("alfa.example", client, table);
  const seller = await agentWithOwner("beta.example", client, table);
  await buyer.call("symbolon_install_mandate", { mandate: buyer.mandate });
  await seller.call("symbolon_install_mandate", { mandate: seller.mandate });
  const offer = await buyer.call("symbolon_propose_agreement", { counterparty_mandate: seller.mandate, clauses: { price: "10", delivery: "tomorrow" } });
  offer.opened.clauses[0].value = "1";
  await assert.rejects(seller.call("symbolon_accept_agreement", { offer }), /clauses do not match/);
});

test("an agent seals its own action and proves it later", async () => {
  const client = registerClient();
  const agent = await agentWithOwner("spray.example", client, {});
  await assert.rejects(agent.call("symbolon_seal_action", { instruction: "x", action: "y" }), /no mandate/);
  await agent.call("symbolon_install_mandate", { mandate: agent.mandate });
  const sealed = await agent.call("symbolon_seal_action", {
    instruction: "Refund order 1043 if the parcel is lost",
    action: "Refunded 39.90 EUR on order 1043",
  });
  const list = await agent.call("symbolon_list_records");
  assert.equal(list[0].entry, sealed.entry);
  const proof = await agent.call("symbolon_create_proof", { entry: sealed.entry, reveal: ["action"] });
  const report = await agent.call("symbolon_verify_proof", { proof });
  assert.equal(report.valid, true);
});

test("a mandate for another agent cannot be installed", async () => {
  const client = registerClient();
  const a = await agentWithOwner("a.example", client, {});
  const b = await agentWithOwner("b.example", client, {});
  await assert.rejects(a.call("symbolon_install_mandate", { mandate: b.mandate }), /different agent/);
});
