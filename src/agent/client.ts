// Client for a remote register (the HTTP API in src/server/app.ts).

import type { Anchor } from "../anchor.js";
import type { PublicKey } from "../keys.js";
import type { Receipt, SignedTreeHead } from "../register.js";

export interface RegisterClient {
  info(): Promise<{ register_key: PublicKey }>;
  append(entry: string): Promise<Receipt>;
  receipt(entry: string): Promise<Receipt | null>;
  head(): Promise<SignedTreeHead | null>;
  consistency(from: number, to: number): Promise<string[]>;
  latestAnchor(): Promise<{ anchor: Anchor; state: string } | null>;
}

export class HttpRegisterClient implements RegisterClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async get<T>(path: string): Promise<T | null> {
    const res = await this.fetchImpl(this.baseUrl + path);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`register: HTTP ${res.status} on ${path}`);
    return (await res.json()) as T;
  }

  async info() {
    const r = await this.get<{ register_key: PublicKey }>("/.well-known/accord-register.json");
    if (!r) throw new Error("not an Accord register");
    return r;
  }
  async append(entry: string) {
    const res = await this.fetchImpl(this.baseUrl + "/v1/entries", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ entry }),
    });
    if (!res.ok) throw new Error(`register refused the entry: HTTP ${res.status}`);
    return (await res.json()) as Receipt;
  }
  receipt(entry: string) {
    return this.get<Receipt>(`/v1/entries/${entry}`);
  }
  head() {
    return this.get<SignedTreeHead>("/v1/head");
  }
  async consistency(from: number, to: number) {
    const r = await this.get<{ proof: string[] }>(`/v1/consistency?from=${from}&to=${to}`);
    if (!r) throw new Error("consistency proof not available");
    return r.proof;
  }
  latestAnchor() {
    return this.get<{ anchor: Anchor; state: string }>("/v1/anchors/latest");
  }
}
