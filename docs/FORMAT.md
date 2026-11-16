# Symbolon data formats, version 1

This document says exactly which bytes Symbolon hashes and signs, so that anyone can compute and verify
fingerprints, signatures and proofs **without our code**. One byte of difference gives a different
fingerprint: follow it to the letter.

- **Test vectors:** [`format-vectors.json`](format-vectors.json) (fixed keys, salts and nonces). Our test
  suite fails if the code ever disagrees with them.
- **Independent check:** [`scripts/verify-format-vectors.py`](../scripts/verify-format-vectors.py), written
  from this document only, recomputes every vector with the Python standard library (plus `cryptography`
  for Ed25519).
- **Status:** version 1 is used by the current **test register**, which will be reset at launch. The launch
  register will bring format changes all at once (record types renamed from `accord/*` to `symbolon/*`, clause
  names and amounts inside the signed record, alignment with IETF SCITT/COSE); they will be a version 2 of this
  document, with its own vectors. Proofs made under version 1 stay verifiable with version 1 rules.

Conventions: all hex is lowercase. Times are ISO 8601 UTC strings. "Fingerprint" always means SHA-256,
written as 64 hex characters.

## 1. Canonical JSON

Every JSON value that is hashed or signed is first written in canonical form:
**RFC 8785 (JSON Canonicalization Scheme), restricted to integers.**

- Object keys sorted by their UTF-16 code units (as RFC 8785 says; this is not the same as code-point order
  for characters outside the Basic Multilingual Plane).
- No whitespace anywhere.
- Strings escaped as RFC 8785 / ECMAScript `JSON.stringify`: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`;
  other control characters as `\u00xx` (lowercase hex); everything else, including non-ASCII, as UTF-8.
  Strings with unpaired surrogates are refused.
- **Numbers: only integers between -(2^53 - 1) and 2^53 - 1.** Amounts and anything with decimals are
  strings: `{"value": "60.00", "currency": "EUR"}`. Under this restriction the output is identical to RFC 8785.
- `true`, `false`, `null` as written.

Example: `{"b":[1,"x",true,null],"a":"12.50"}` (keys `a` before `b`). See `json_fingerprint` in the vectors.

## 2. Fingerprints of content

What a visitor seals is up to them; to make it reproducible Symbolon offers two methods (also as the door
tool `symbolon_fingerprint`):

| method | fingerprint of | use for |
|---|---|---|
| `sha256-utf8` | the exact UTF-8 bytes of a text | documents, messages: every space and line break counts |
| `sha256-jcs` | the canonical form (section 1) of a JSON value | structured data: key order and spacing do not matter |

Keep the content exactly as fingerprinted (for JSON, keep the canonical text too).
**Only the fingerprint goes to the register, never the content.**

## 3. Keys and signatures

- Keys are Ed25519 (RFC 8032). A public key is written `ed25519:` followed by its 32 bytes in hex.
- **Signing a JSON value** = Ed25519 signature over the UTF-8 bytes of its canonical form. Signatures are
  64 bytes in hex.
- Verification is strict RFC 8032 (no ZIP-215 leniency) and refuses small-order public keys.

## 4. Clauses (what the parties agreed)

An agreement or an action is a list of clauses `{name, value}` with unique names (1-100 characters; not
`__proto__`, `constructor` or `prototype`). The clauses never leave the parties; only their root does.

- Each clause gets a random 32-byte salt (hex), so that a clause cannot be guessed from its hash.
- Clause leaf = `SHA-256(0x00 || UTF-8(canonical({"n": name, "s": salt, "v": value})))`.
- Clauses root = Merkle tree root (section 7) of the leaves, in clause order. `clauseCount` = number of clauses.
- A single clause can later be revealed with its salt and its inclusion path to the root, without revealing
  the others.

## 5. Mandates (the owner's authority)

A mandate is `{"body": ..., "signature": ...}`, signed by the owner key over the canonical `body`:

```
{ "type": "accord/mandate", "v": 1,
  "owner": { "domain": "<owner domain>", "key": "ed25519:<hex>" },
  "agent": "ed25519:<hex>", "scope": "<text>",
  "maxAmount": { "value": "<decimal>", "currency": "<ISO 4217>" },   (optional)
  "notBefore": "<time>", "notAfter": "<time>", "charter": "accord-charter/0.1" }
```

- **Mandate id** = fingerprint of the canonical `body` only (`SHA-256(UTF-8(canonical(body)))`). The
  signature and anything outside the body do not change it.
- The owner key is valid at level "domain" only if it is listed at `https://<owner domain>/.well-known/symbolon.json`.
- Sub-mandates (`"type": "symbolon/submandate"`) are signed by the agent of the mandate above (`issuer`),
  name it by id (`parent`), copy the `owner`, may add `total` and a salted `task`, and carry the links above
  in `chain` (outside the signed body). Limits and dates can never exceed those above. Details: `src/mandate.ts`.

## 6. Records and the register entry

A record is what agents sign:

```
{ "body": { "type": "accord/agreement" | "accord/action", "v": 1,
            "clausesRoot": "<hex>", "clauseCount": <int>,
            "parties": [ { "agent": "ed25519:<hex>", "mandate": "<mandate id>" }, ... ],
            "charter": "accord-charter/0.1", "createdAt": "<time>", "nonce": "<hex>" },
  "signatures": [ { "agent": "ed25519:<hex>", "signature": "<hex>" }, ... ] }
```

- Each party signs the canonical `body`. An agreement has 2-10 parties; an action exactly one.
- **Entry** (the only thing sent to the register) =
  `fingerprint(canonical({"body": body, "signatures": [ the signature of each party, in party order ]}))`,
  each signature written as `{"agent", "signature"}` and nothing else. Extra fields or reordered signatures
  cannot produce a second entry for the same record.

## 7. The register

An append-only Merkle log (RFC 9162, Certificate Transparency v2) that sees only fingerprints.

- Register leaf = `SHA-256(0x00 || UTF-8("accord-entry/1:" + entry))`.
- Inner node = `SHA-256(0x01 || left || right)`. Root of n leaves: n = 0 → `SHA-256("")`; n = 1 → the leaf;
  otherwise split at k = the largest power of two smaller than n, root = node(root(first k), root(rest)).
  Inclusion and consistency proofs as in RFC 9162.
- **Signed tree head** = `{"log", "size", "root", "time"}` signed by the register key (section 3);
  `log` is the register's public key. A receipt is `{entry, index, head, path}`.
- Each day the latest head is anchored in Bitcoin through OpenTimestamps.
- **Public list of entries:** `GET /v1/entries?from=<index>` returns every entry in order (1000 per page, `next`
  for the following page) with the latest signed head. Anyone can keep a full copy: the leaves of the first
  `head.size` entries must give `head.root`, and an older copy must be the beginning of a newer one
  (`npm run register:copy` does both checks).
- Revocation id = fingerprint of the canonical revocation `body`.

> **Pin the register's key.** Never take it from the register's own answer alone: whoever controls the address
> or the connection could present a register of its own. Known registers and their keys are listed in
> [`src/known-registers.ts`](../src/known-registers.ts) (also inside the npm package, built by GitHub with
> provenance); the test register is `ed25519:0b26c53a5dbc29498b786b0d0f308717350d48cdb234d6381e7c9473a0e26f96`.

## 8. Test vectors

[`format-vectors.json`](format-vectors.json) contains, for fixed inputs: a text fingerprint (with its UTF-8
bytes), a JSON fingerprint (with its canonical form), an Ed25519 signature over canonical JSON (with the
secret key), three salted clauses (leaf preimages, leaves, root), a mandate (canonical body, id), a signed
two-party record (entry preimage, entry) and a three-entry register (leaves and roots for sizes 1-3).
The secret keys there are public test keys: never use them for anything else.
