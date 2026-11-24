// The agent's wallet as an MCP server over stdio (also published as the npm package @symbolon-city/wallet).
//   SYMBOLON_REGISTER_URL  register to use (default: the public test register of Symbolon City)
//   SYMBOLON_REGISTER_KEY  the register's public key, fixed by you (known registers have it built in; any other
//                          register without it is taken at its own word, and a warning is printed)
//   SYMBOLON_PIAZZA_URL    piazza to use (default: the public test piazza; "none" turns the piazza tools off). PIAZZA_URL is still read.
//   SYMBOLON_ARCHIVE_URL   your owner's archive of commitments (optional); with SYMBOLON_ARCHIVE_KEY, the archive key claim
//                          (JSON, or a file containing it) printed by `npm run owner -- archive-key`
//   SYMBOLON_HOME          where the wallet is kept (default ~/.symbolon; an existing ~/.accord is still used)
//   SYMBOLON_WALLET_KEY    keychain (Mac, default) | dpapi (Windows, default) | passphrase (default elsewhere)
//   SYMBOLON_WALLET_PASSWORD  the password, when SYMBOLON_WALLET_KEY=passphrase
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { EncryptedWalletStorage, providerFromEnv } from "../src/agent/encrypted-storage.js";
import { buildMcpServer } from "../src/agent/mcp.js";
import { Wallet } from "../src/agent/wallet.js";
import { esploraProvider, httpOwnerResolver } from "../src/index.js";

export const DEFAULT_REGISTER_URL = "https://registro-prova.symbolon-city.workers.dev";
export const DEFAULT_PIAZZA_URL = "https://piazza-prova.symbolon-city.workers.dev";

const url = process.env.SYMBOLON_REGISTER_URL ?? process.env.ACCORD_REGISTER_URL ?? DEFAULT_REGISTER_URL; // earlier name still accepted
const piazzaSetting = process.env.SYMBOLON_PIAZZA_URL ?? process.env.PIAZZA_URL ?? DEFAULT_PIAZZA_URL;
const piazzaUrl = piazzaSetting === "none" ? undefined : piazzaSetting;
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
const registerKey = process.env.SYMBOLON_REGISTER_KEY;
const register = new HttpRegisterClient(url.replace(/\/+$/, ""), fetch, registerKey ? { key: registerKey } : {});
if (!register.pinnedKey)
  console.error(`Warning: the key of register ${url} is not fixed; set SYMBOLON_REGISTER_KEY to the key published by its operator.`);
/** The owner's archive of commitments, when both settings are given. */
function archiveSetting() {
  const url = process.env.SYMBOLON_ARCHIVE_URL;
  const key = process.env.SYMBOLON_ARCHIVE_KEY;
  if (!url || !key) return {};
  const claim = JSON.parse(key.trim().startsWith("{") ? key : readFileSync(key, "utf8"));
  return { archive: { url, claim } };
}
let wallet: Wallet;
try {
  wallet = await Wallet.open(storage, register, {
    ownerResolver: httpOwnerResolver(),
    bitcoin: esploraProvider(),
    ...archiveSetting(),
  });
} catch (e) {
  console.error((e as Error).message);
  process.exit(1);
}
await buildMcpServer(wallet, { piazzaUrl }).connect(new StdioServerTransport());
console.error(`Symbolon wallet ready. Agent key: ${wallet.agentKey}. Register: ${url}${piazzaUrl ? `, piazza: ${piazzaUrl}` : ""}`);
