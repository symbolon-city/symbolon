// The agent's notary wallet as an MCP server over stdio.
//   SYMBOLON_REGISTER_URL  register to use (required)
//   PIAZZA_URL           piazza to use (optional: without it the piazza tools are not offered)
//   SYMBOLON_HOME          where the wallet is kept (default ~/.symbolon; an existing ~/.accord is still used)
//   SYMBOLON_WALLET_KEY  keychain (Mac, default) | dpapi (Windows, default) | passphrase (default elsewhere)
//   SYMBOLON_WALLET_PASSWORD  the password, when SYMBOLON_WALLET_KEY=passphrase
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { EncryptedWalletStorage, providerFromEnv } from "../src/agent/encrypted-storage.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { Wallet } from "../src/agent/wallet.js";
import { esploraProvider, httpOwnerResolver } from "../src/index.js";

const url = process.env.SYMBOLON_REGISTER_URL ?? process.env.ACCORD_REGISTER_URL; // earlier name still accepted
if (!url) {
  console.error("Set SYMBOLON_REGISTER_URL to the register address.");
  process.exit(1);
}
const legacyHome = join(homedir(), ".accord");
const home =
  process.env.SYMBOLON_HOME ??
  process.env.ACCORD_HOME ??
  (!existsSync(join(homedir(), ".symbolon")) && existsSync(join(legacyHome, "wallet.json")) ? legacyHome : join(homedir(), ".symbolon"));
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
console.error(`Symbolon wallet ready. Agent key: ${wallet.agentKey}`);
