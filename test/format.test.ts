import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildVectors } from "../scripts/format-vectors.js";
import { canonical, entryHash, fingerprintJson, fingerprintText, isFullySigned, mandateId, verifyMandateSignature, verifyOpened, verifyValue } from "../src/index.js";

const file = JSON.parse(readFileSync(new URL("../docs/format-vectors.json", import.meta.url), "utf8"));

test("the published test vectors match the code exactly", () => {
  assert.deepEqual(buildVectors(), file, "code and docs/format-vectors.json disagree: a format change? run `npm run format:vectors` only if intended");
});

test("the test vectors are consistent with the library's own checks", () => {
  assert.ok(verifyOpened({ root: file.clauses.root, count: file.clauses.clauses.length, clauses: file.clauses.clauses }));
  assert.ok(verifyMandateSignature(file.mandate.mandate));
  assert.equal(mandateId(file.mandate.mandate), file.mandate.id);
  assert.ok(isFullySigned(file.record.record));
  assert.equal(entryHash(file.record.record), file.record.entry);
  assert.ok(verifyValue(file.signature.value, file.signature.signature, file.signature.public_key));
});

test("fingerprints: exact bytes for text, canonical JSON (RFC 8785 subset) for JSON", () => {
  assert.equal(fingerprintText("abc").fingerprint, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.notEqual(fingerprintText("abc").fingerprint, fingerprintText("abc\n").fingerprint, "every byte counts");
  // Same value, different spacing and key order: same fingerprint.
  assert.equal(fingerprintJson(JSON.parse('{ "b": 1, "a": [true, null] }')).fingerprint, fingerprintJson({ a: [true, null], b: 1 }).fingerprint);
  assert.equal(canonical({ b: 1, a: "x" }), '{"a":"x","b":1}');
  // RFC 8785 key order is by UTF-16 code units: "é" (U+00E9) after "z", "\u{1F600}" (surrogates) before "ﬀ" (U+FB00).
  assert.equal(canonical({ "é": 1, z: 2 }), '{"z":2,"é":1}');
  assert.equal(canonical({ "ﬀ": 1, "\u{1F600}": 2 }), '{"\u{1F600}":2,"ﬀ":1}');
  assert.throws(() => fingerprintJson({ amount: 12.5 }), /integers/);
  assert.throws(() => fingerprintText("bad \uD800 text"), /surrogate/);
  assert.throws(() => fingerprintJson({ "\uDC00": 1 }), /surrogate/);
});
