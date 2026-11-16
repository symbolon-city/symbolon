import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { MemoryWalletStorage, Wallet } from "../src/agent/wallet.js";
import { MemoryStore, Register, createMandate, generateKeyPair, staticOwnerResolver } from "../src/index.js";
import { handle, type AppDeps } from "../src/server/app.js";
import { MemoryExtras } from "../src/server/stores.js";

// Dates relative to the real clock: the register stamps real time, and a record dated after its seal is refused.
const NOW = new Date(Math.floor(Date.now() / 3_600_000) * 3_600_000 + 3_600_000 - 60_000); // just before the next full hour
const at = (hours: number) => new Date(NOW.getTime() + hours * 3_600_000).toISOString().replace(".000", "");

async function setup() {
  const deps: AppDeps = { register: new Register(generateKeyPair(), new MemoryStore()), extras: new MemoryExtras(), baseUrl: "https://reg.example" };
  const f: typeof fetch = async (input, init) => handle(new Request(String(input), init), deps);
  const client = new HttpRegisterClient("https://reg.example", f);
  const table: Record<string, string[]> = {};
  const ownerResolver = staticOwnerResolver(table);
  const agent = async (domain: string, scope: string, storage = new MemoryWalletStorage()) => {
    const owner = generateKeyPair();
    table[domain] = [owner.publicKey];
    const wallet = await Wallet.open(storage, client, { ownerResolver });
    await wallet.installMandate(
      createMandate(owner, { ownerDomain: domain, agent: wallet.agentKey, scope, maxAmount: { value: "150.00", currency: "EUR" }, notBefore: at(-24 * 15), notAfter: at(24 * 30), charter: "accord-charter/0.1" }),
    );
    return { wallet, storage };
  };
  return { client, ownerResolver, agent };
}

test("my commitments: open agreements with their dates, offers still waiting, then closing one", async () => {
  const { client, ownerResolver, agent } = await setup();
  const home = await agent("home.example", "home repairs");
  const plumber = await agent("plumber.example", "plumbing services");

  // The home's agent agrees a boiler repair for tomorrow morning.
  const offer = await home.wallet.propose({
    counterparty: plumber.wallet.myMandate(),
    clauses: { service: "boiler repair", amount: { value: "60.00", currency: "EUR" }, window: `${at(14)}/${at(16)}` },
  });
  const { confirmation, entry } = await plumber.wallet.accept(offer);
  await home.wallet.confirm(confirmation);
  // A second offer is sent and not answered yet.
  await home.wallet.propose({ counterparty: plumber.wallet.myMandate(), clauses: { service: "yearly boiler check", amount: { value: "90.00", currency: "EUR" }, due: at(24 * 60).slice(0, 10) } });

  // A new conversation: the agent has forgotten everything, the wallet has not (same storage).
  const again = await Wallet.open(home.storage, client, { ownerResolver });
  const c = again.commitments();
  assert.equal(c.open.length, 1);
  assert.equal(c.open[0].entry, entry);
  assert.equal(c.open[0].with[0].owner, "plumber.example");
  assert.deepEqual(c.open[0].dates.map((d) => d.date), [at(14), at(16)]);
  assert.equal(c.open[0].next_date?.clause, "window");
  assert.equal(c.open[0].overdue, false);
  assert.equal(c.waiting.length, 1);
  assert.equal(c.waiting[0].clauses.service, "yearly boiler check");
  assert.ok(c.my_mandate!.days_left >= 29 && c.my_mandate!.days_left <= 30);
  // The plumber's wallet remembers the same agreement from its side.
  assert.equal(plumber.wallet.commitments().open[0].with[0].owner, "home.example");

  // Two days later the window has passed: the commitment shows as overdue until it is closed.
  const twoDaysLater = await Wallet.open(home.storage, client, { ownerResolver, now: () => new Date(NOW.getTime() + 48 * 3_600_000) });
  assert.equal(twoDaysLater.commitments().open[0].overdue, true);
  const later = await Wallet.open(home.storage, client, { ownerResolver });
  const closed = await later.closeCommitment({ entry, outcome: "fulfilled", note: "boiler repaired on 17 November" });
  assert.equal(closed.closed, entry);
  const after = later.commitments();
  assert.equal(after.open.length, 0);
  assert.equal(after.closed[0].outcome, "fulfilled");

  // The closing is itself sealed: it can be proven, with the agreement it names.
  const proof = await later.createProof(closed.closing_entry, ["details"]);
  const report = await later.verify(proof);
  // Nothing fails. Under a mandate with a spending limit, a closing (which carries no amount) is reported
  // "incomplete" rather than "valid": the verifier cannot check the limit, and says so.
  assert.deepEqual(report.checks.filter((x) => !x.ok), []);
  assert.equal(report.verdict, "incomplete");
  assert.match(report.gaps.join(), /amount not disclosed/);
  assert.deepEqual((proof.disclosures[0].value as { closes: string }).closes, entry);

  await assert.rejects(later.closeCommitment({ entry, outcome: "not_fulfilled" }), /already closed/);
  await assert.rejects(later.closeCommitment({ entry: "ab".repeat(32), outcome: "fulfilled" }), /no sealed agreement/);
  await assert.rejects(later.closeCommitment({ entry: closed.closing_entry, outcome: "fulfilled" }), /no sealed agreement/, "an action is not a commitment");
});

test("the wallet's MCP server offers the commitments tools and tells agents to read them first", async () => {
  const { agent } = await setup();
  const a = await agent("home.example", "home repairs");
  const c = new Client({ name: "probe", version: "0" });
  const [x, y] = InMemoryTransport.createLinkedPair();
  await buildMcpServer(a.wallet).connect(x);
  await c.connect(y);
  assert.match(c.getInstructions() ?? "", /symbolon_my_commitments/);
  const names = (await c.listTools()).tools.map((t) => t.name);
  assert.ok(names.includes("symbolon_my_commitments") && names.includes("symbolon_close_commitment"));
  const r = (await c.callTool({ name: "symbolon_my_commitments", arguments: {} })) as { content: Array<{ text: string }> };
  const body = JSON.parse(r.content[0].text);
  assert.deepEqual(body.open, []);
  assert.match(body.how_to_use, /resume work/);
});
