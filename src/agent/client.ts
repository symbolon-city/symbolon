// Client for a remote register (the HTTP API in src/server/app.ts).

import type { Anchor } from "../anchor.js";
import type { PublicKey } from "../keys.js";
import { pinnedRegisterKey } from "../known-registers.js";
import { fromHex } from "../bytes.js";
import { verifyInclusion } from "../merkle.js";
import { entryLeaf, verifyHeadSignature, type Receipt, type SignedTreeHead } from "../register.js";
import { fetchAllRevocations, type RegisteredRevocation, type Revocation } from "../revocation.js";

/**
 * Problem with a receipt the register gave for `entry`, or null: about that very entry, with a head signed by the
 * key it names, and a path that proves the entry is in that head's tree. A receipt of another entry (replayed by a
 * cache, a proxy or a register that dropped the entry) never makes the wallet believe something is sealed.
 */
export function receiptProblem(r: unknown, entry: string): string | null {
  const x = r as Receipt;
  if (!x || typeof x !== "object" || !x.head || typeof x.head !== "object") return "not a receipt";
  if (x.entry !== entry) return "the receipt is for another entry";
  if (!Number.isSafeInteger(x.index) || x.index < 0 || !Number.isSafeInteger(x.head.size) || x.index >= x.head.size) return "the receipt's position is invalid";
  if (!Array.isArray(x.path) || x.path.length > 64 || x.path.some((p) => typeof p !== "string" || !/^[0-9a-f]{64}$/.test(p))) return "the receipt's path is invalid";
  if (typeof x.head.root !== "string" || !/^[0-9a-f]{64}$/.test(x.head.root)) return "the receipt's head is invalid";
  if (!verifyHeadSignature(x.head)) return "the receipt's head is not signed by the register";
  if (!verifyInclusion(entryLeaf(entry), x.index, x.head.size, x.path.map(fromHex), fromHex(x.head.root))) return "the receipt does not prove that the entry is in the register";
  return null;
}

export interface RegisterClient {
  info(): Promise<{ register_key: PublicKey }>;
  append(entry: string): Promise<Receipt>;
  receipt(entry: string): Promise<Receipt | null>;
  head(): Promise<SignedTreeHead | null>;
  consistency(from: number, to: number): Promise<string[]>;
  latestAnchor(): Promise<{ anchor: Anchor; state: string } | null>;
  /** Seals a signed revocation; returns its id, position and time in the register. */
  revoke(r: Revocation): Promise<RegisteredRevocation & { id: string; receipt: Receipt }>;
  /** Every revocation about these subjects (mandate ids or keys), only by these signers when given. */
  revocations(subjects: string[], signers?: PublicKey[]): Promise<RegisteredRevocation[]>;
}

export class HttpRegisterClient implements RegisterClient {
  /**
   * The register's key fixed outside the register: given in `opts.key`, or taken from the list of known
   * registers (src/known-registers.ts). When set, a different key announced by the register, or a head
   * signed by another key, is refused. Undefined for an unknown register given without a key.
   */
  readonly pinnedKey: PublicKey | undefined;

  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
    opts: { key?: PublicKey } = {},
  ) {
    this.pinnedKey = opts.key ?? pinnedRegisterKey(baseUrl);
  }

  private async get<T>(path: string): Promise<T | null> {
    const res = await this.fetchImpl(this.baseUrl + path);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`register: HTTP ${res.status} on ${path}`);
    return (await res.json()) as T;
  }

  /** Refuses a head that is not signed by the pinned key (no-op without a pinned key). */
  private checkHead<H extends SignedTreeHead | null | undefined>(head: H): H {
    if (!this.pinnedKey || !head) return head;
    if (head.log !== this.pinnedKey || !verifyHeadSignature(head))
      throw new Error(`the register's answer is not signed by its pinned key (${this.pinnedKey}): refusing it`);
    return head;
  }

  async info() {
    const r =
      (await this.get<{ register_key: PublicKey }>("/.well-known/symbolon-register.json")) ??
      (await this.get<{ register_key: PublicKey }>("/.well-known/accord-register.json")); // earlier name
    if (!r) throw new Error("not a Symbolon register");
    if (this.pinnedKey && r.register_key !== this.pinnedKey)
      throw new Error(
        `register key mismatch: ${this.baseUrl} announces ${r.register_key}, but its pinned key is ${this.pinnedKey}. ` +
          "Refusing it: it may be an impostor, or the register was replaced (then update to a wallet version that knows the new key).",
      );
    return { register_key: this.pinnedKey ?? r.register_key };
  }
  async append(entry: string) {
    const res = await this.fetchImpl(this.baseUrl + "/v1/entries", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ entry }),
    });
    if (!res.ok) throw new Error(`register refused the entry: HTTP ${res.status}`);
    const receipt = (await res.json()) as Receipt;
    this.checkHead(receipt?.head);
    const bad = receiptProblem(receipt, entry);
    if (bad) throw new Error(`the register's answer does not hold: ${bad}`);
    return receipt;
  }
  async receipt(entry: string) {
    const r = await this.get<Receipt>(`/v1/entries/${entry}`);
    if (!r) return r;
    this.checkHead(r.head);
    const bad = receiptProblem(r, entry);
    if (bad) throw new Error(`the register's answer does not hold: ${bad}`);
    return r;
  }
  async head() {
    return this.checkHead(await this.get<SignedTreeHead>("/v1/head"));
  }
  async consistency(from: number, to: number) {
    const r = await this.get<{ proof: string[] }>(`/v1/consistency?from=${from}&to=${to}`);
    if (!r) throw new Error("consistency proof not available");
    return r.proof;
  }
  latestAnchor() {
    return this.get<{ anchor: Anchor; state: string }>("/v1/anchors/latest");
  }
  async revoke(r: Revocation) {
    const res = await this.fetchImpl(this.baseUrl + "/v1/revocations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(r),
    });
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) throw new Error(`register refused the revocation: ${body.error ?? `HTTP ${res.status}`}`);
    return body as RegisteredRevocation & { id: string; receipt: Receipt };
  }
  revocations(subjects: string[], signers?: PublicKey[]) {
    return fetchAllRevocations((path) => this.get(path), subjects, signers);
  }
}
