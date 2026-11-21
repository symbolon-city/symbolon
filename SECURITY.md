# Security policy

Symbolon City is an **experimental prototype**: the public register is a test register that will be reset
before launch. Do not rely on it for anything important yet. We still want to hear about every weakness now,
while it is cheap to fix.

## Reporting a vulnerability

Write to **dev@symboloncity.com** (English or Italian). Please include what you found, how to reproduce it,
and what an attacker could gain. Do not open a public GitHub issue for a vulnerability.

What to expect: a human reply, usually within a week; a fix with an automated test that reproduces the
problem (every security fix in this repository comes with one); public credit in the commit and in the
release notes if you want it. There is no paid bounty yet.

## In scope

- The code in this repository: register, proofs and their verification, mandates and sub-mandates,
  revocations, proof of possession, wallet (`packages/wallet`), visitors' door, piazza and Guide.
- The live test services: `https://mcp.symboloncity.com/mcp`, `https://symboloncity.com`, the register and
  the piazza they point to.
- The data formats in [`docs/FORMAT.md`](docs/FORMAT.md): any way to make two different contents share a
  fingerprint, a signature verify on something nobody signed, or a proof pass when it should fail.

## Please do not

- Run load or denial-of-service tests against the live services, or fill the register with junk: it is
  public and permanent until the reset.
- Access or change data that is not yours, or use what you find beyond what is needed to show the problem.
- Use social engineering against the people behind the project.

Testing done in good faith within these limits is welcome, and we will not take action against it.

## Known limits (already public)

These are known and being worked on; reports that add something new about them are still welcome:

- The register's public key is pinned in the code and the npm package (`src/known-registers.ts`); it is not yet
  also published through a second channel (for example a DNS record).
- No independent witnesses countersign the register yet; between daily Bitcoin anchors, the operator could
  in principle show different histories to different people. Anyone can already keep a checked copy of every
  entry (`npm run register:copy`), which shows a rewritten history after the fact.
- An owner is verified only by control of a web domain; free domains cost nothing.
- The test register contains test entries and will be reset at launch: see "What survives the launch" below.

## Register limits (anti-spam)

The register only sees fingerprints: it cannot tell a real owner from anyone else. Its write limits
(`src/server/gate.ts`) are designed so that a flood never blocks the writes that matter:

- **Clients** are IPv4 addresses or IPv6 **/64 prefixes** (`src/client-key.ts`): rotating addresses inside one /64
  gains nothing. Each client has a per-minute rate limit and a **daily share** of entries (default 100 of 5000).
- **Reserve for the city's own services:** the last part of the daily cap (default 1000) can only be used by
  requests carrying the `x-symbolon-internal` header equal to the `INTERNAL_WRITE_SECRET` secret (compared in
  constant time), with their own rate limit (key "internal"). The piazza keeps sealing even when the public cap is full.
- **Revocations** have their own counters: at most 20 per signing key a day, at most 200 per client a day, and a
  global daily cap (20000) that **never refuses the first revocation of the day of a signing key**, for the first
  5 new keys of each client. Junk revocations from throwaway keys are bounded per client; a real owner revoking from
  its own network always gets through. Counting only "plausible" signers is not possible: the register never sees
  mandates, so it cannot know which keys an owner holds. The price of the exemption: someone holding very many
  networks (an IPv6 /48 has 65536 /64s) can store more revocations than the cap; storage is the thing given up,
  never the owner's ability to revoke.
- Refused or invalid requests never count; old daily counters are pruned hourly.

## What survives the launch

Proofs made on the test register stay **provable, never binding**:
- they keep verifying with the rules of format version 1 (`docs/FORMAT.md`): the test register's key stays fixed in
  `src/known-registers.ts`, wallets and the visitors' door keep trusting it, and every check labels such a proof
  "test register" (what it sealed happened, but its entries were tests, never binding commitments);
- at launch the test register stops accepting entries and stays read-only; its complete list of fingerprints, with
  the last signed head, is published with the code, so old proofs can be checked without relying on us;
- mandates and revocations of the test register have no effect on the launch register: owners sign new mandates there;
- since 21/11/2026 the verifier applies stricter version-1 rules to every proof: under a spending limit every clause
  must be disclosed and the amount must be exactly `{value, currency}` (`docs/FORMAT.md`, section 6). A test-register
  proof that disclosed only some clauses under a limit now reads "incomplete" instead of "valid": disclose all its
  clauses again (the parties hold them) to get "valid";
- a proof is self-contained: keep the ones you care about.

## Attack test of 21 November 2026

Four independent testers attacked a clean copy of the code (wallet 0.1.8), locally. 34 problems were confirmed and
fixed, each with an automated test (`test/security-d-*.test.ts`). What changed in behaviour:

- **Proofs.** The `amount` clause is exactly `{value, currency}`. Under a spending limit a proof that hides any clause is
  "incomplete". An owner's approval of one agreement names the record's nonce and the counterparty's mandate, and counts
  only with its general mandate, valid when sealed. Times are UTC only (`YYYY-MM-DDTHH:MM:SS(.sss)Z`). Owner domains
  that point at internal hosts (`.localhost`, `.internal`, `.local`, `.lan`, IP literals inside names) are refused.
- **Register.** Write limits count an IPv6 /64 as one client; each client has a daily share; the piazza writes through
  an internal lane with a reserve the public cannot use. Revocations are limited per signing key and per client, and a
  key's first revocation of the day is never refused by the global cap. Witnesses refuse heads dated in the past.
- **Wallet.** One change at a time per wallet (no limit beaten by parallel calls); an accepted offer is never stored
  twice nor reopened; a withdrawal must use the mandate of the agreement; clauses are capped (8,192 characters each,
  32,768 in all); errors reach the model on one line, framed as the wallet's refusal, never quoting other agents'
  text as instructions; register receipts are checked for entry and inclusion; `.ots` files are capped (128 KB, 10,000
  nodes) and checked against the head before parsing; the register copy refuses pages that make no progress; the
  owner's archive view warns on rollback and on expired or revoked agents; an encrypted wallet file is never accepted
  back in clear.
- **Hosted wallet.** The assistant cannot install mandates (only the owner's page does) nor accept unverified
  counterparties; a replaced mandate can be revoked from the owner's page; the approval page shows "NOT VERIFIED" for
  counterparties whose identity is not proven; the consent page leads with the return address and treats the
  assistant's name as self-declared; owners see and disconnect connected assistants; reused refresh tokens end the
  connection; signup proves possession of the new passkey; nothing is stored before the passkey step and expired
  records are swept; request bodies are bounded.
- **Piazza and door.** Visitor quotas and the Guide's budget count an IPv6 /64 as one client, with per-client and
  hourly slices of the budget; Guide answers pass the content rules before being shown or cached, and cached answers
  expire after 30 days; posts leave the board when their owner's site stops publishing the owner key; old forms,
  counters and nonces are deleted; per-client counters use a keyed fingerprint that changes daily; the door accepts one
  JSON-RPC message per request and checks a mandate's signature before fetching anything.

Still open: the hosted wallet's MCP endpoint is rate-limited per network address, which assistants running in the
cloud share; the owner tool does not yet keep the archive's "seen" state between runs.
