// Reader and writer for the OpenTimestamps proof format (.ots).
// A timestamp is a tree of operations (append, prepend, hash) that turns
// our fingerprint into a value written in a Bitcoin block, plus
// "attestations" saying where that value can be found.

import { sha1, ripemd160 } from "@noble/hashes/legacy";
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { concat, equalBytes, fromHex, toHex } from "./bytes.js";

export type Op =
  | { tag: "append"; arg: Uint8Array }
  | { tag: "prepend"; arg: Uint8Array }
  | { tag: "sha256" | "sha1" | "ripemd160" | "keccak256" };

export type Attestation =
  | { kind: "pending"; uri: string }
  | { kind: "bitcoin"; height: number }
  | { kind: "unknown"; tag: string; payload: Uint8Array };

export interface Timestamp {
  msg: Uint8Array;
  attestations: Attestation[];
  ops: Array<{ op: Op; stamp: Timestamp }>;
}

const UNARY: Record<number, Op["tag"]> = { 0x08: "sha256", 0x02: "sha1", 0x03: "ripemd160", 0x67: "keccak256" };
const BINARY: Record<number, "append" | "prepend"> = { 0xf0: "append", 0xf1: "prepend" };
const TAG_OF: Record<Op["tag"], number> = { sha256: 0x08, sha1: 0x02, ripemd160: 0x03, keccak256: 0x67, append: 0xf0, prepend: 0xf1 };

const PENDING = "83dfe30d2ef90c8e";
const BITCOIN = "0588960d73d71901";

const MAGIC = fromHex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294");
const MAX_MSG = 4096;
const MAX_DEPTH = 256;
/** Largest .ots file or calendar answer read (real ones are a few KB). */
export const MAX_OTS_BYTES = 128 * 1024;
/** Most nodes in a timestamp tree, and most message bytes kept in all of them together. */
const MAX_NODES = 10_000;
const MAX_TREE_BYTES = 4 * 1024 * 1024;

/** What one parse may still use: every node keeps its own message, so a small file could otherwise fill memory. */
interface Budget {
  nodes: number;
  bytes: number;
}
const newBudget = (): Budget => ({ nodes: MAX_NODES, bytes: MAX_TREE_BYTES });

export function applyOp(op: Op, msg: Uint8Array): Uint8Array {
  switch (op.tag) {
    case "append":
      return concat(msg, op.arg);
    case "prepend":
      return concat(op.arg, msg);
    case "sha256":
      return sha256(msg);
    case "sha1":
      return sha1(msg);
    case "ripemd160":
      return ripemd160(msg);
    case "keccak256":
      return keccak_256(msg);
  }
}

export function newTimestamp(msg: Uint8Array): Timestamp {
  return { msg, attestations: [], ops: [] };
}

// ---------- reading ----------

class Reader {
  pos = 0;
  constructor(private readonly buf: Uint8Array) {}
  byte(): number {
    if (this.pos >= this.buf.length) throw new Error("truncated timestamp");
    return this.buf[this.pos++];
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error("truncated timestamp");
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
      if (shift > 49) throw new Error("varuint too large");
    }
  }
  varbytes(max = MAX_MSG): Uint8Array {
    const n = this.varuint();
    if (n > max) throw new Error("field too large");
    return this.bytes(n);
  }
  done(): boolean {
    return this.pos === this.buf.length;
  }
}

function readAttestation(r: Reader): Attestation {
  const tag = toHex(r.bytes(8));
  const payload = r.varbytes(8192);
  const pr = new Reader(payload);
  if (tag === PENDING) {
    const uri = new TextDecoder().decode(pr.varbytes(1000));
    if (!/^https:\/\/[A-Za-z0-9.\-:/]+$/.test(uri)) throw new Error("invalid calendar uri");
    return { kind: "pending", uri };
  }
  if (tag === BITCOIN) return { kind: "bitcoin", height: pr.varuint() };
  return { kind: "unknown", tag, payload };
}

function readTimestamp(r: Reader, msg: Uint8Array, depth: number, budget: Budget): Timestamp {
  if (depth > MAX_DEPTH) throw new Error("timestamp too deep");
  if (--budget.nodes < 0) throw new Error("timestamp has too many operations");
  budget.bytes -= msg.length;
  if (budget.bytes < 0) throw new Error("timestamp too large");
  const ts = newTimestamp(msg);
  const item = (tag: number) => {
    if (tag === 0x00) {
      ts.attestations.push(readAttestation(r));
    } else if (tag in UNARY) {
      const op = { tag: UNARY[tag] } as Op;
      ts.ops.push({ op, stamp: readTimestamp(r, applyOp(op, msg), depth + 1, budget) });
    } else if (tag in BINARY) {
      const op: Op = { tag: BINARY[tag], arg: r.varbytes() };
      const next = applyOp(op, msg);
      if (next.length > MAX_MSG) throw new Error("message too long");
      ts.ops.push({ op, stamp: readTimestamp(r, next, depth + 1, budget) });
    } else {
      throw new Error(`unknown op tag 0x${tag.toString(16)}`);
    }
  };
  let tag = r.byte();
  while (tag === 0xff) {
    item(r.byte());
    tag = r.byte();
  }
  item(tag);
  return ts;
}

/** Parses a timestamp (as returned by a calendar) for the given starting message. */
export function parseTimestamp(bytes: Uint8Array, msg: Uint8Array): Timestamp {
  if (bytes.length > MAX_OTS_BYTES) throw new Error("timestamp too large");
  const r = new Reader(bytes);
  const ts = readTimestamp(r, msg, 0, newBudget());
  if (!r.done()) throw new Error("trailing bytes after timestamp");
  return ts;
}

// ---------- writing ----------

function varuint(n: number): Uint8Array {
  const out: number[] = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return new Uint8Array(out);
}

const varbytes = (b: Uint8Array) => concat(varuint(b.length), b);

function writeAttestation(a: Attestation): Uint8Array {
  switch (a.kind) {
    case "pending":
      return concat(fromHex(PENDING), varbytes(varbytes(new TextEncoder().encode(a.uri))));
    case "bitcoin":
      return concat(fromHex(BITCOIN), varbytes(varuint(a.height)));
    case "unknown":
      return concat(fromHex(a.tag), varbytes(a.payload));
  }
}

function writeOp(op: Op): Uint8Array {
  const tag = new Uint8Array([TAG_OF[op.tag]]);
  return op.tag === "append" || op.tag === "prepend" ? concat(tag, varbytes(op.arg)) : tag;
}

export function serializeTimestamp(ts: Timestamp): Uint8Array {
  const items: Uint8Array[] = [
    ...ts.attestations.map((a) => concat(new Uint8Array([0x00]), writeAttestation(a))),
    ...ts.ops.map(({ op, stamp }) => concat(writeOp(op), serializeTimestamp(stamp))),
  ];
  if (items.length === 0) throw new Error("empty timestamp");
  const parts: Uint8Array[] = [];
  items.forEach((it, i) => {
    if (i < items.length - 1) parts.push(new Uint8Array([0xff]));
    parts.push(it);
  });
  return concat(...parts);
}

/** Standard detached .ots file for a SHA-256 digest, readable by the official `ots` client. */
export function toOtsFile(ts: Timestamp): Uint8Array {
  if (ts.msg.length !== 32) throw new Error("expected a sha256 digest");
  return concat(MAGIC, varuint(1), new Uint8Array([0x08]), ts.msg, serializeTimestamp(ts));
}

/**
 * Reads a detached .ots file. With `expectedDigest`, a file for another digest is refused before its tree is
 * read (so a file that is not about what is being checked costs nothing to look at).
 */
export function fromOtsFile(bytes: Uint8Array, expectedDigest?: Uint8Array): Timestamp {
  if (bytes.length > MAX_OTS_BYTES) throw new Error(`.ots file too large (at most ${MAX_OTS_BYTES} bytes)`);
  const r = new Reader(bytes);
  if (!equalBytes(r.bytes(MAGIC.length), MAGIC)) throw new Error("not an OpenTimestamps file");
  if (r.varuint() !== 1) throw new Error("unsupported .ots version");
  if (r.byte() !== 0x08) throw new Error("only sha256 file digests are supported");
  const digest = r.bytes(32);
  if (expectedDigest && !equalBytes(digest, expectedDigest)) throw new Error(".ots is for a different digest");
  const ts = readTimestamp(r, digest, 0, newBudget());
  if (!r.done()) throw new Error("trailing bytes in .ots file");
  return ts;
}

// ---------- tree helpers ----------

/** Merges `other` (a timestamp for the same message) into `ts`. */
export function mergeTimestamp(ts: Timestamp, other: Timestamp): void {
  if (!equalBytes(ts.msg, other.msg)) throw new Error("cannot merge timestamps of different messages");
  for (const a of other.attestations) {
    if (!ts.attestations.some((b) => sameAttestation(a, b))) ts.attestations.push(a);
  }
  for (const o of other.ops) {
    const mine = ts.ops.find((x) => sameOp(x.op, o.op));
    if (mine) mergeTimestamp(mine.stamp, o.stamp);
    else ts.ops.push(o);
  }
}

function sameOp(a: Op, b: Op): boolean {
  if (a.tag !== b.tag) return false;
  return !("arg" in a) || equalBytes(a.arg, (b as { arg: Uint8Array }).arg);
}

function sameAttestation(a: Attestation, b: Attestation): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "pending") return a.uri === (b as typeof a).uri;
  if (a.kind === "bitcoin") return a.height === (b as typeof a).height;
  return a.tag === (b as typeof a).tag && equalBytes(a.payload, (b as typeof a).payload);
}

/** Every attestation in the tree, with the message it attests. */
export function allAttestations(ts: Timestamp): Array<{ msg: Uint8Array; attestation: Attestation; node: Timestamp }> {
  const out: Array<{ msg: Uint8Array; attestation: Attestation; node: Timestamp }> = [];
  const walk = (t: Timestamp) => {
    for (const a of t.attestations) out.push({ msg: t.msg, attestation: a, node: t });
    for (const o of t.ops) walk(o.stamp);
  };
  walk(ts);
  return out;
}
