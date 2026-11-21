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
  document, with its own vectors. Proofs made under version 1 stay verifiable with version 1 rules; those of the test
  register are labelled as tests, never binding commitments (see "What survives the launch" in `SECURITY.md`).

Conventions: all hex is lowercase. Times are UTC strings of exactly the form `YYYY-MM-DDTHH:MM:SS(.sss)Z`
(what `toISOString` writes, milliseconds optional) with real calendar values; mandate, approval, record and tree
head times in any other form (no zone, an offset, a date only) are refused, so a time never depends on the
verifier's time zone. "Fingerprint" always means SHA-256, written as 64 hex characters.

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

### 3.1 Owner passkeys (WebAuthn), prototype

An **owner** may sign with a passkey instead (Face ID, Touch ID, Windows Hello, a security key), so that the
private key never leaves the person's device. Only owner keys can be passkeys: a mandate's `owner.key`, a
revocation's `by` and an `owner-key` target, an archive key's `owner.key`, the keys of an owner file. Agent,
issuer, register and witness keys stay Ed25519, because they sign without a person.

- Key: `p256:` followed by the **compressed** P-256 point (33 bytes, first byte `02` or `03`) in hex.
- **Signing a JSON value** = a WebAuthn assertion (`navigator.credentials.get`) whose `challenge` is the
  SHA-256 of the value's canonical form (the same 32 bytes as its fingerprint), with `userVerification: "required"`.
- Signature text: `webauthn.` + base64url(authenticatorData) + `.` + base64url(clientDataJSON) + `.` +
  base64url(DER ECDSA signature), base64url without padding (RFC 4648 section 5), at most 2048 characters.
- Verification: authenticatorData is exactly 37 bytes (no attested data, no extensions) with flags UP (`0x01`)
  and UV (`0x04`) set; clientDataJSON is UTF-8 JSON with `type` `"webauthn.get"`, `challenge` equal to the
  base64url of the value's SHA-256, a string `origin`, and `crossOrigin` not `true`; the ECDSA P-256 signature
  over authenticatorData ‖ SHA-256(clientDataJSON) is valid for the key. Both encodings of S are accepted.
- Ids never depend on a signature: a mandate's or a revocation's id is the fingerprint of its body only.
- Status: accepted by the current code next to Ed25519 owner keys; it becomes part of format version 2 with the
  launch register. No test vector yet (an assertion is not deterministic): `test/passkey.test.ts` and
  `npm run passkey:check` (a real browser with a virtual authenticator) check it.

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
- **Identity levels.** With `owner.domain`, the owner key is valid at level "domain" only if it is listed at
  `https://<owner domain>/.well-known/symbolon.json`. **Without a domain** the owner object is
  `{ "key": "<owner key>" }` and nothing else (no `domain` field at all: an empty, `null` or non-canonical
  domain is refused): level "key", an owner known only by its key, typically a passkey (section 3.1). Always the
  same owner, but who it is is not verified; verifiers report the level and the counterparty decides. Nothing
  is looked up, so a proof is not incomplete for that. Only that key revokes as owner. The piazza is for owners
  with a domain (its limits count owners per site). Test vector: `mandate_without_domain`.
- **Approval of one agreement** ("approve just this one"): an owner-signed mandate with one more field,
  `"agreement": { "clausesRoot": "<hex>", "with": ["<agent key of each other party>", ...], "withMandates": ["<mandate id of each of them, same order>", ...], "nonce": "<hex>", "under": "<id of the agent's general mandate>" }`.
  It is valid only for **one record**: the record whose `nonce` is exactly `nonce` (32-64 hex characters, chosen
  when the approval is asked), whose `clausesRoot` is exactly that one, and whose other parties are exactly
  `with` (1-9 keys, once each, never the agent itself), each signing under exactly the mandate id at the same
  position of `withMandates` (the same agent key under another owner's mandate is another party). The nonce is the
  agreement's identity: a record with another nonce is another agreement and the approval does not cover it.
  It lasts at most 7 days (`notAfter - notBefore`); it cannot be the top of a chain (no sub-mandates under it).
  It lets the agent go above its general limit for that agreement only: its `maxAmount` is the approved amount.
  **It ends with its general mandate:** a proof must also carry the `under` mandate, signed by the same owner (key
  and domain) for the same agent, itself no approval, and valid at sealing time; a revocation of the `under`
  mandate revokes the approval too, so lookups also ask for that id. The agent prepares it
  (`symbolon_request_owner_approval`), the owner signs it (passkey or owner key), the agent proposes the agreement
  with it, in a record carrying that nonce, and sends the general mandate with the offer.
  `withMandates` and `nonce` exist since 21/11/2026: an approval without them is still well formed but allows no
  record (none was in use). Test vector: `mandate_approval` (still in the earlier shape, to be regenerated).
- Sub-mandates (`"type": "symbolon/submandate"`) are signed by the agent of the mandate above (`issuer`),
  name it by id (`parent`), copy the `owner` exactly (with or without `domain`), may add `total` and a salted `task`, and carry the links above
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
- **Amounts and limits.** When a party's mandate has a spending limit (`maxAmount`, or `total` in its chain), the
  price is the `amount` clause and must be exactly `{"value": "<decimal>", "currency": "<ISO 4217>"}` with no other
  key (a quantity, a period or a nested total would change what the price means): otherwise the proof is invalid.
  A proof is complete only if it discloses **every** clause (`clauseCount` of them): a price could hide in an
  undisclosed one. Disclosing only some clauses gives "incomplete", never "valid". Without any limit, selective
  disclosure stays complete.
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
- A witness countersigns a head only if it extends the last head it saw, its `time` is not before that head's
  time, and its `time` is within 5 minutes of the witness's own clock.
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
