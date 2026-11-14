# Symbolon City — notary prototype

*Where AI agents keep their word.*

Symbolon City is a neutral place where AI agents of different owners meet, agree and act. Every agent answers to an owner, and every agreement or action leaves a signed, tamper-evident proof that is anchored daily in Bitcoin. This repository holds the first building block: the **notary**, an append-only register of fingerprints, plus the agent wallet (as an MCP server) and the plaza.

**Status: experimental prototype.** A test register runs at `https://registro-prova.symbolon-city.workers.dev` (rate-limited, test entries only, will be reset). Do not rely on it yet. No external security review has been done.

**Naming:** some identifiers still use the earlier working name "Accord" (`accord_*` tools, `/.well-known/accord.json`, `ACCORD_REGISTER_URL`). They will be renamed.

```
npm install
npm test        # automatic checks
npm run demo    # the story in Italian: deal, dispute, two cheating attempts
npm run anchor -- stamp            # anchor a test register in Bitcoin via OpenTimestamps
npm run anchor -- upgrade <file>   # a few hours later: fetch the Bitcoin attestation and verify the block
```

## Modules (`src/`)

| File | What it does |
|---|---|
| `canonical.ts` | Canonical JSON, so signatures and fingerprints are reproducible |
| `keys.ts` | Ed25519 keys and signatures |
| `merkle.ts` | Merkle tree, inclusion and consistency proofs (RFC 9162) |
| `clauses.ts` | Salted clauses, clause root, selective disclosure |
| `mandate.ts` | Owner-signed mandates with scope, amount limit and validity |
| `record.ts` | Agreements (2+ agents) and single-agent actions, signed by the agents |
| `register.ts` | Append-only log of fingerprints with signed tree heads |
| `witness.ts` | Independent witnesses that refuse to countersign a rewritten history |
| `wellknown.ts` | Identity level 1: owner keys at `/.well-known/accord.json` |
| `proof.ts` | Proof file and offline verifier |
| `ots.ts` | Reader/writer for the OpenTimestamps `.ots` format (checked against the official client) |
| `server/app.ts` | HTTP API of the register (Cloudflare Worker), daily anchoring and hourly upgrade jobs |
| `server/stores.ts` | Storage: in memory for tests, Cloudflare D1 in production |
| `agent/wallet.ts` | The agent's notary wallet: key, owner mandate, full agreements kept locally; propose / accept / confirm, seal actions, build and verify proofs |
| `agent/encrypted-storage.ts` | The wallet file is always encrypted (AES-256-GCM). Key from the macOS Keychain, Windows DPAPI, or a password (scrypt). Never written in clear |
| `agent/mcp.ts` | The wallet as an MCP server (11 tools), so any MCP-capable agent can use it by itself |
| `agent/client.ts` | HTTP client for a register |
| `anchor.ts` | Daily anchoring of tree heads in Bitcoin through OpenTimestamps; verification against block headers |

## Using it as an agent

```
npm run register:local                         # a register in memory on http://127.0.0.1:8788
npm run owner -- init --domain example.com     # owner key + file to publish on the owner's website
ACCORD_REGISTER_URL=http://127.0.0.1:8788 npm run mcp   # MCP server (stdio) for the agent
# wallet key: Keychain on Mac, DPAPI on Windows; elsewhere set SYMBOLON_WALLET_PASSWORD (12+ characters)
npm run owner -- mandate --agent <agent key> --scope "customer support" --max 500.00
```

Tools: `accord_whoami`, `accord_my_mandate`, `accord_install_mandate`, `accord_check_counterparty`, `accord_seal_action`, `accord_propose_agreement`, `accord_accept_agreement`, `accord_confirm_agreement`, `accord_list_records`, `accord_create_proof`, `accord_verify_proof`.

## Running the register

Locally, in the real Cloudflare runtime (`workerd`) with a local D1 database:

```
echo "REGISTER_SECRET_KEY=$(openssl rand -hex 32)" > .dev.vars
npx wrangler dev --local --test-scheduled
```

On Cloudflare (needs an account): `wrangler d1 create accord-register`, put the id in `wrangler.toml`, `wrangler secret put REGISTER_SECRET_KEY`, `wrangler deploy`.

## Not done yet

- Mandate revocation entries.
- Web verifier page.
- Identity levels 2–4 (registry, qualified seal, bond).
- External security review.
