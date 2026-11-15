// The register: an append-only Merkle log that only ever sees fingerprints.
// After each append it publishes a signed tree head; anyone can check that
// every new head extends the previous one (consistency proof).
//
// Storage is pluggable: MemoryStore for tests, D1Store on Cloudflare.
// Prototype note: the tree is recomputed from the stored leaves on each
// request. A production version stores inner nodes as well.

import { toHex, utf8 } from "./bytes.js";
import { leafHash } from "./hash.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";
import { consistencyProof, inclusionProof, treeRoot } from "./merkle.js";

export interface TreeHead {
  log: PublicKey;
  size: number;
  root: string;
  time: string;
}

export interface SignedTreeHead extends TreeHead {
  signature: string;
}

export interface Receipt {
  entry: string;
  index: number;
  head: SignedTreeHead;
  path: string[];
}

export function entryLeaf(entry: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(entry)) throw new Error("entry must be a sha256 hex fingerprint");
  return leafHash(utf8("accord-entry/1:" + entry));
}

function headBody(h: TreeHead): TreeHead {
  return { log: h.log, size: h.size, root: h.root, time: h.time };
}

export function verifyHeadSignature(h: SignedTreeHead): boolean {
  return verifyValue(headBody(h), h.signature, h.log);
}

export interface LogStore {
  size(): Promise<number>;
  /** The first `count` leaf hashes, in order. */
  leaves(count: number): Promise<Uint8Array[]>;
  /** Stores leaf `index` and the head for size index+1 atomically. False if the index is already taken. */
  appendLeaf(index: number, entry: string, leaf: Uint8Array, head: SignedTreeHead): Promise<boolean>;
  putHead(head: SignedTreeHead): Promise<void>;
  head(size: number): Promise<SignedTreeHead | null>;
  indexOf(entry: string): Promise<number | null>;
}

export class MemoryStore implements LogStore {
  private items: Array<{ entry: string; leaf: Uint8Array }> = [];
  private heads = new Map<number, SignedTreeHead>();

  async size() {
    return this.items.length;
  }
  async leaves(count: number) {
    return this.items.slice(0, count).map((i) => i.leaf);
  }
  async appendLeaf(index: number, entry: string, leaf: Uint8Array, head: SignedTreeHead) {
    if (index !== this.items.length) return false;
    this.items.push({ entry, leaf });
    this.heads.set(head.size, head);
    return true;
  }
  async putHead(head: SignedTreeHead) {
    this.heads.set(head.size, head);
  }
  async head(size: number) {
    return this.heads.get(size) ?? null;
  }
  async indexOf(entry: string) {
    const i = this.items.findIndex((x) => x.entry === entry);
    return i < 0 ? null : i;
  }
  /** For tests only: a dishonest operator rewriting an old entry. */
  overwriteForTest(index: number, entry: string) {
    this.items[index] = { entry, leaf: entryLeaf(entry) };
  }
}

export class Register {
  constructor(
    private readonly key: KeyPair,
    readonly store: LogStore = new MemoryStore(),
    private readonly now: () => Date = () => new Date(),
  ) {}

  get publicKey(): PublicKey {
    return this.key.publicKey;
  }

  private signHead(leaves: Uint8Array[]): SignedTreeHead {
    const body: TreeHead = {
      log: this.key.publicKey,
      size: leaves.length,
      root: toHex(treeRoot(leaves)),
      time: this.now().toISOString(),
    };
    return { ...body, signature: signValue(body, this.key) };
  }

  /** Adds a fingerprint. If it is already there, returns a receipt for the existing entry. */
  async append(entry: string): Promise<Receipt> {
    const leaf = entryLeaf(entry);
    for (let attempt = 0; attempt < 8; attempt++) {
      const existing = await this.store.indexOf(entry);
      if (existing !== null) return this.receipt(entry, existing);
      const size = await this.store.size();
      const leaves = [...(await this.store.leaves(size)), leaf];
      const head = this.signHead(leaves);
      if (await this.store.appendLeaf(size, entry, leaf, head)) {
        return { entry, index: size, head, path: toHexList(inclusionProof(leaves, size)) };
      }
    }
    throw new Error("register busy, try again");
  }

  /**
   * Receipt for an existing entry, against the head signed when it was added (size index+1), so the
   * receipt's time is the sealing time. Later heads only say "sealed no later than"; a Bitcoin anchor
   * or a consistency proof links this head to any later one.
   */
  async receipt(entry: string, index?: number): Promise<Receipt> {
    const i = index ?? (await this.store.indexOf(entry));
    if (i === null) throw new Error("entry not found");
    const head = (await this.store.head(i + 1)) ?? (await this.latestHead());
    if (!head) throw new Error("empty register");
    return { entry, index: i, head, path: await this.inclusion(i, head.size) };
  }

  /** Signs and stores a head for the current content (used after tampering in tests). */
  async publishHead(): Promise<SignedTreeHead> {
    const head = this.signHead(await this.store.leaves(await this.store.size()));
    await this.store.putHead(head);
    return head;
  }

  async latestHead(): Promise<SignedTreeHead | null> {
    const size = await this.store.size();
    return size === 0 ? null : this.store.head(size);
  }

  async headAt(size: number): Promise<SignedTreeHead | null> {
    return this.store.head(size);
  }

  async inclusion(index: number, size: number): Promise<string[]> {
    return toHexList(inclusionProof(await this.store.leaves(size), index));
  }

  async consistency(oldSize: number, newSize: number): Promise<string[]> {
    const leaves = await this.store.leaves(newSize);
    if (leaves.length !== newSize) throw new Error("size beyond the register");
    return toHexList(consistencyProof(leaves, oldSize));
  }
}

function toHexList(xs: Uint8Array[]): string[] {
  return xs.map(toHex);
}
