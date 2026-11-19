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

## What survives the launch

Proofs made on the test register stay **provable, never binding**:
- they keep verifying with the rules of format version 1 (`docs/FORMAT.md`): the test register's key stays fixed in
  `src/known-registers.ts`, wallets and the visitors' door keep trusting it, and every check labels such a proof
  "test register" (what it sealed happened, but its entries were tests, never binding commitments);
- at launch the test register stops accepting entries and stays read-only; its complete list of fingerprints, with
  the last signed head, is published with the code, so old proofs can be checked without relying on us;
- mandates and revocations of the test register have no effect on the launch register: owners sign new mandates there;
- a proof is self-contained: keep the ones you care about.
