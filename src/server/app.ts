// HTTP interface of the register. Plain fetch handler: runs on Cloudflare
// Workers and in tests. It only ever receives fingerprints.

import { anchorHead, upgradeAnchor, type Anchor } from "../anchor.js";
import { allAttestations, fromOtsFile } from "../ots.js";
import { fromBase64 } from "../bytes.js";
import type { Register } from "../register.js";
import { revocationId, revocationProblem, revocationSubject, type RegisteredRevocation, type Revocation } from "../revocation.js";
import { verifyCosignature, type Cosignature } from "../witness.js";
import type { ExtrasStore } from "./stores.js";
import { classifyClient, statsPage, type StatsStore } from "./stats.js";

export interface AppDeps {
  register: Register;
  extras: ExtrasStore;
  /** Public base URL, used in the self-description. */
  baseUrl: string;
  /**
   * Anti-spam gate for writes (new entries, cosignatures). Returns null to allow,
   * or a short reason to refuse with HTTP 429. Absent = no limit (tests, local use).
   */
  allowWrite?: (req: Request) => Promise<string | null>;
  /** Anonymous public counters (/stats). Absent = not counted. */
  stats?: StatsStore;
  /** Runs work after the response (Cloudflare ctx.waitUntil); absent = awaited inline. */
  defer?: (p: Promise<unknown>) => void;
}

const HEX64 = /^[0-9a-f]{64}$/;
const MAX_BODY = 8192;

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2) + "\n", {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...CORS },
  });
}

const error = (status: number, message: string) => json({ error: message }, status);

async function readJson(req: Request): Promise<unknown> {
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "body too large");
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function intParam(v: string | null, name: string): number {
  const n = Number(v);
  if (!v || !Number.isSafeInteger(n) || n < 0) throw new HttpError(400, `invalid ${name}`);
  return n;
}

export function describe(deps: AppDeps) {
  return {
    service: "Symbolon register (prototype)",
    about:
      "A neutral, append-only register of fingerprints of agreements between AI agents and of actions sealed by a single agent. " +
      "It never receives the content of an agreement, only a SHA-256 fingerprint computed by the parties. " +
      "Every tree head is signed, can be countersigned by independent witnesses, and is anchored daily in Bitcoin via OpenTimestamps. " +
      "Using it is free and binds no one: an agreement binds its owners only if their agents carry a valid owner mandate.",
    source: "https://github.com/symbolon-city/symbolon",
    register_key: deps.register.publicKey,
    endpoints: {
      "POST /v1/entries": "body {entry: <sha256 hex>} → receipt with index, signed tree head and inclusion path",
      "GET /v1/entries/{entry}": "receipt for an existing entry, against the latest head",
      "GET /v1/head": "latest signed tree head",
      "GET /v1/heads/{size}": "signed tree head at a given size",
      "GET /v1/consistency?from={m}&to={n}": "proof that head n extends head m",
      "GET /v1/anchors/latest": "latest Bitcoin anchor (.ots, base64)",
      "GET /v1/anchors/{size}": "Bitcoin anchor of the head at that size",
      "POST /v1/cosignatures": "witnesses publish their countersignature of a head",
      "GET /v1/cosignatures/{size}": "countersignatures of the head at that size",
      "POST /v1/revocations": "body: a signed revocation (mandate, agent key or owner key) → sealed in the register; applies from its register position",
      "GET /v1/revocations?subject={mandate id or key}": "revocations about these subjects (repeat subject, at most 10); apply them only if signed by an authorized key",
      "GET /v1/revocations/{id}": "one revocation, with its receipt",
      "GET /stats": "public page with anonymous daily usage counters (JSON at /v1/stats)",
    },
    limits: "writes are rate-limited per client and capped per day; HTTP 429 means try again later",
    base_url: deps.baseUrl,
  };
}

export async function handle(req: Request, deps: AppDeps): Promise<Response> {
  const res = await route(req, deps);
  const path = new URL(req.url).pathname;
  if (deps.stats && req.method !== "OPTIONS" && !path.startsWith("/stats") && path !== "/v1/stats" && path !== "/favicon.ico") {
    const kind = `${req.method === "POST" && res.status === 201 ? "write" : "read"}:${classifyClient(req.headers.get("user-agent"))}`;
    const p = deps.stats.count(kind).catch(() => {});
    if (deps.defer) deps.defer(p);
    else await p;
  }
  return res;
}

async function route(req: Request, deps: AppDeps): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const { register, extras } = deps;
  try {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    if (req.method === "GET" && (path === "/" || path === "/.well-known/symbolon-register.json" || path === "/.well-known/accord-register.json")) return json(describe(deps));

    if (req.method === "GET" && (path === "/stats" || path === "/v1/stats")) {
      if (!deps.stats) return error(404, "stats not enabled");
      const days = await deps.stats.recent(30);
      const latest = await extras.latestAnchor();
      const summary = {
        registerSize: await register.store.size(),
        latestAnchor: latest ? { size: latest.anchor.head.size, state: latest.state, time: latest.anchor.head.time } : null,
        generatedAt: new Date().toISOString(),
      };
      if (path === "/v1/stats") return json({ ...summary, days, note: "anonymous daily counts; client class guessed from User-Agent" });
      return new Response(statsPage({ ...summary, days }), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=60" } });
    }

    if (req.method === "POST" && (path === "/v1/entries" || path === "/v1/cosignatures" || path === "/v1/revocations") && deps.allowWrite) {
      const refused = await deps.allowWrite(req);
      if (refused) return error(429, refused);
    }

    if (req.method === "POST" && path === "/v1/entries") {
      const body = (await readJson(req)) as { entry?: unknown };
      if (typeof body?.entry !== "string" || !HEX64.test(body.entry)) return error(400, "entry must be a sha256 hex fingerprint");
      return json(await register.append(body.entry), 201);
    }

    if (req.method === "POST" && path === "/v1/revocations") {
      const r = (await readJson(req)) as Revocation;
      const problem = revocationProblem(r, { now: new Date() });
      if (problem) return error(400, problem);
      const id = revocationId(r);
      const known = await extras.revocation(id);
      if (known) return json({ id, ...known, receipt: await register.receipt(id, known.index) });
      const receipt = await register.append(id);
      const at = await register.headAt(receipt.index + 1);
      const sealed: RegisteredRevocation = { revocation: r, index: receipt.index, time: at?.time ?? receipt.head.time };
      await extras.addRevocation(id, revocationSubject(r), sealed);
      return json({ id, ...sealed, receipt }, 201);
    }

    if (req.method === "GET" && path === "/v1/revocations") {
      const subjects = [...new Set(url.searchParams.getAll("subject"))];
      if (!subjects.length || subjects.length > 10) return error(400, "give 1 to 10 subject parameters");
      if (subjects.some((x) => !HEX64.test(x) && !/^ed25519:[0-9a-f]{64}$/.test(x))) return error(400, "a subject is a mandate id (64 hex) or a key (ed25519:<64 hex>)");
      return json({
        revocations: await extras.revocationsFor(subjects),
        note: "Apply a revocation only if it is signed by the mandate's owner key, a key published at the owner's domain, or (for its own mandate or key) the agent. It applies from its register position.",
      });
    }

    let m: RegExpMatchArray | null;
    if (req.method === "GET" && (m = path.match(/^\/v1\/revocations\/([0-9a-f]{64})$/))) {
      const r = await extras.revocation(m[1]);
      return r ? json({ id: m[1], ...r, receipt: await register.receipt(m[1], r.index) }) : error(404, "revocation not found");
    }
    if (req.method === "GET" && (m = path.match(/^\/v1\/entries\/([0-9a-f]{64})$/))) {
      const index = await register.store.indexOf(m[1]);
      return index === null ? error(404, "entry not found") : json(await register.receipt(m[1], index));
    }

    if (req.method === "GET" && path === "/v1/head") {
      const head = await register.latestHead();
      return head ? json(head) : error(404, "empty register");
    }

    if (req.method === "GET" && (m = path.match(/^\/v1\/heads\/(\d+)$/))) {
      const head = await register.headAt(Number(m[1]));
      return head ? json(head) : error(404, "no head at that size");
    }

    if (req.method === "GET" && path === "/v1/consistency") {
      const from = intParam(url.searchParams.get("from"), "from");
      const to = intParam(url.searchParams.get("to"), "to");
      if (from < 1 || from > to) return error(400, "need 1 <= from <= to");
      if (to > (await register.store.size())) return error(404, "size beyond the register");
      return json({ from, to, proof: await register.consistency(from, to) });
    }

    if (req.method === "GET" && path === "/v1/anchors/latest") {
      const a = await extras.latestAnchor();
      return a ? json(a) : error(404, "no anchor yet");
    }

    if (req.method === "GET" && (m = path.match(/^\/v1\/anchors\/(\d+)$/))) {
      const a = await extras.anchor(Number(m[1]));
      return a ? json(a) : error(404, "no anchor at that size");
    }

    if (req.method === "POST" && path === "/v1/cosignatures") {
      const c = (await readJson(req)) as Cosignature;
      const head = typeof c?.size === "number" ? await register.headAt(c.size) : null;
      if (!head || !verifyCosignature(c, head)) return error(400, "cosignature does not match a head of this register");
      await extras.addCosignature(c);
      return json({ ok: true }, 201);
    }

    if (req.method === "GET" && (m = path.match(/^\/v1\/cosignatures\/(\d+)$/))) {
      return json(await extras.cosignatures(Number(m[1])));
    }

    return error(404, "not found");
  } catch (e) {
    if (e instanceof HttpError) return error(e.status, e.message);
    return error(500, "internal error");
  }
}

// ---------- scheduled jobs ----------

/** Anchors the latest head in Bitcoin if it is newer than the last anchored one. */
export async function anchorLatest(deps: AppDeps, fetchImpl?: typeof fetch): Promise<Anchor | null> {
  const head = await deps.register.latestHead();
  if (!head) return null;
  const last = await deps.extras.latestAnchor();
  if (last && last.anchor.head.size >= head.size) return null;
  const anchor = await anchorHead(head, { fetchImpl });
  await deps.extras.putAnchor(head.size, anchor, "pending");
  return anchor;
}

/** Asks the calendars for the Bitcoin attestation of each pending anchor. */
export async function upgradePending(deps: AppDeps, fetchImpl?: typeof fetch): Promise<number> {
  let confirmed = 0;
  for (const a of await deps.extras.pendingAnchors()) {
    const { anchor, upgraded } = await upgradeAnchor(a, fetchImpl);
    if (!upgraded) continue;
    const hasBitcoin = allAttestations(fromOtsFile(fromBase64(anchor.ots))).some((x) => x.attestation.kind === "bitcoin");
    await deps.extras.putAnchor(anchor.head.size, anchor, hasBitcoin ? "confirmed" : "pending");
    if (hasBitcoin) confirmed++;
  }
  return confirmed;
}
