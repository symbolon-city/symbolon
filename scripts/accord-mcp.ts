// The agent's notary wallet as an MCP server over stdio.
//   ACCORD_REGISTER_URL  register to use (required)
//   PIAZZA_URL           piazza to use (optional: without it the piazza tools are not offered)
//   ACCORD_HOME          where the wallet is kept (default ~/.accord)
//   SYMBOLON_WALLET_KEY  keychain (Mac, default) | dpapi (Windows, default) | passphrase (default elsewhere)
//   SYMBOLON_WALLET_PASSWORD  the password, when SYMBOLON_WALLET_KEY=passphrase
import { homedir } from "node:os";
import { join } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { EncryptedWalletStorage, providerFromEnv } from "../src/agent/encrypted-storage.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { Wallet } from "../src/agent/wallet.js";
import { esploraProvider, httpOwnerResolver } from "../src/index.js";

const url = process.env.ACCORD_REGISTER_URL;
if (!url) {
  console.error("Set ACCORD_REGISTER_URL to the register address.");
  process.exit(1);
}
const home = process.env.ACCORD_HOME ?? join(homedir(), ".accord");
const walletPath = join(home, "wallet.json");
let storage: EncryptedWalletStorage;
try {
  storage = new EncryptedWalletStorage(walletPath, providerFromEnv(walletPath));
} catch (e) {
  console.error((e as Error).message);
  process.exit(1);
}
let wallet: Wallet;
try {
  wallet = await Wallet.open(storage, new HttpRegisterClient(url.replace(/\/+$/, "")), {
    ownerResolver: httpOwnerResolver(),
    bitcoin: esploraProvider(),
  });
} catch (e) {
  console.error((e as Error).message);
  process.exit(1);
}
await buildMcpServer(wallet, { piazzaUrl: process.env.PIAZZA_URL }).connect(new StdioServerTransport());
console.error(`Accord wallet ready. Agent key: ${wallet.agentKey}`);
