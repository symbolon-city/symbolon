// Tools for the owner (a person or company), not for the agent.
//   npm run owner -- init --domain example.com
//       creates the owner key in ./owner.json and prints the file to publish at
//       https://example.com/.well-known/symbolon.json
//   npm run owner -- mandate --agent ed25519:... --scope "purchase of office supplies" [--max 50000.00] [--currency EUR] [--days 365]
//       prints a mandate for that agent, to install with the symbolon_install_mandate tool
//   npm run owner -- revoke (--mandate <file.json> | --agent ed25519:... | --owner-key ed25519:...) [--reason "..."] [--send [register url]]
//       signs a revocation (withdraw a mandate, stop an agent key, or block a stolen owner key); with --send it is
//       sealed in the register and applies from then on. There is no undo.
//   npm run owner -- archive-key
//       creates the key of your archive of commitments in ./owner-archive.json (keep it secret) and prints what to give
//       your agents' wallets (SYMBOLON_ARCHIVE_URL, SYMBOLON_ARCHIVE_KEY) and your archive server (npm run archive:serve)
//   npm run owner -- commitments --archive <archive url>
//       opens the sealed snapshots of all your agents and prints their commitments together
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { toHex } from "../src/bytes.js";
import { createMandate, createRevocation, generateKeyPair, keyPairFromSecret, mandateId, WELL_KNOWN_PATH, type Mandate, type RevocationTarget } from "../src/index.js";
import { HttpRegisterClient } from "../src/agent/client.js";
import { newArchiveKey, ownerView, type Snapshot } from "../src/archive.js";
import type { BoxSecret } from "../src/channel.js";

const [cmd, ...rest] = process.argv.slice(2);
const arg = (name: string) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};
const FILE = process.env.SYMBOLON_OWNER_FILE ?? "owner.json";

if (cmd === "init") {
  const domain = arg("domain");
  if (!domain) throw new Error("--domain is required");
  if (existsSync(FILE)) throw new Error(`${FILE} already exists`);
  const k = generateKeyPair();
  writeFileSync(FILE, JSON.stringify({ domain, secret: toHex(k.secretKey), publicKey: k.publicKey }, null, 2), { mode: 0o600 });
  console.log(`Owner key saved in ${FILE} (keep it secret). Publish this at https://${domain}${WELL_KNOWN_PATH}:\n`);
  console.log(JSON.stringify({ symbolon: 1, domain, keys: [k.publicKey] }, null, 2));
} else if (cmd === "mandate") {
  const owner = JSON.parse(readFileSync(FILE, "utf8")) as { domain: string; secret: string };
  const agent = arg("agent");
  const scope = arg("scope");
  if (!agent || !scope) throw new Error("--agent and --scope are required");
  const days = Number(arg("days") ?? 365);
  const now = new Date();
  const max = arg("max");
  const m = createMandate(keyPairFromSecret(owner.secret), {
    ownerDomain: owner.domain,
    agent,
    scope,
    ...(max ? { maxAmount: { value: max, currency: arg("currency") ?? "EUR" } } : {}),
    notBefore: now.toISOString(),
    notAfter: new Date(now.getTime() + days * 86_400_000).toISOString(),
    charter: "accord-charter/0.1",
  });
  console.log(JSON.stringify(m, null, 2));
} else if (cmd === "revoke") {
  const owner = JSON.parse(readFileSync(FILE, "utf8")) as { domain: string; secret: string };
  const file = arg("mandate");
  const agent = arg("agent");
  const ownerKey = arg("owner-key");
  if ([file, agent, ownerKey].filter(Boolean).length !== 1) throw new Error("give exactly one of --mandate <file>, --agent <key>, --owner-key <key>");
  const target: RevocationTarget = file
    ? { kind: "mandate", id: mandateId(JSON.parse(readFileSync(file, "utf8")) as Mandate) }
    : agent
      ? { kind: "agent", key: agent }
      : { kind: "owner-key", key: ownerKey! };
  const reason = arg("reason");
  const r = createRevocation(keyPairFromSecret(owner.secret), { target, ownerDomain: owner.domain, ...(reason ? { reason } : {}) });
  const sendAt = rest.indexOf("--send");
  const next = sendAt >= 0 ? rest[sendAt + 1] : undefined;
  const url = sendAt < 0 ? undefined : next && !next.startsWith("--") ? next : "https://registro-prova.symbolon-city.workers.dev";
  if (!url) {
    console.log(JSON.stringify(r, null, 2));
    console.log("\nNot sent. Add --send (public test register) or --send <register url> to seal it (no undo), or submit it with the symbolon_submit_revocation tool.");
  } else {
    const sealed = await new HttpRegisterClient(url.replace(/\/+$/, "")).revoke(r);
    console.log(`Revocation sealed at register position ${sealed.index}, ${sealed.time}. It applies from now on.`);
  }
} else if (cmd === "archive-key") {
  const owner = JSON.parse(readFileSync(FILE, "utf8")) as { domain: string; secret: string };
  const ARCHIVE = process.env.SYMBOLON_ARCHIVE_FILE ?? "owner-archive.json";
  if (existsSync(ARCHIVE)) throw new Error(`${ARCHIVE} already exists`);
  const { secret, claim } = await newArchiveKey(keyPairFromSecret(owner.secret), owner.domain);
  writeFileSync(ARCHIVE, JSON.stringify({ secret, claim }, null, 2), { mode: 0o600 });
  console.log(`Archive key saved in ${ARCHIVE} (keep it secret: it opens the commitments of all your agents).\n`);
  console.log("1. Run an archive server you control:  npm run archive:serve  (or any server speaking the same two calls)");
  console.log("2. Give each agent's wallet these two settings:");
  console.log("   SYMBOLON_ARCHIVE_URL=<your archive server address>");
  console.log(`   SYMBOLON_ARCHIVE_KEY=${JSON.stringify(claim)}`);
  console.log("3. Read all commitments:  npm run owner -- commitments --archive <your archive server address>");
} else if (cmd === "commitments") {
  const url = arg("archive");
  if (!url) throw new Error("--archive <archive server address> is required");
  const owner = JSON.parse(readFileSync(FILE, "utf8")) as { secret: string };
  const { secret } = JSON.parse(readFileSync(process.env.SYMBOLON_ARCHIVE_FILE ?? "owner-archive.json", "utf8")) as { secret: BoxSecret };
  const res = await fetch(url.replace(/\/+$/, "") + "/v1/snapshots");
  if (!res.ok) throw new Error(`archive: HTTP ${res.status}`);
  const { snapshots } = (await res.json()) as { snapshots: Snapshot[] };
  console.log(JSON.stringify(await ownerView(snapshots, secret, keyPairFromSecret(owner.secret).publicKey), null, 2));
} else {
  console.log("usage: symbolon-owner (or npm run owner --) init --domain <domain> | mandate --agent <key> --scope <text> [--max <amount>] [--currency EUR] [--days 365] | revoke (--mandate <file> | --agent <key> | --owner-key <key>) [--reason <text>] [--send [register url]] | archive-key | commitments --archive <url>");
}
