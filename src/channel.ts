// The channel between two agents after the piazza: sealed boxes that only the recipient can open,
// carrying one of a few fixed forms (no free prose, so no orders can be smuggled in). The piazza only
// delivers boxes between agents that already met on a post; it cannot read them.
//
// Crypto, all from WebCrypto (no extra library): each wallet has a box key (X25519), published as a
// claim signed by its agent key. A box is ECDH between a fresh key and the recipient's box key, HKDF-SHA256,
// then AES-256-GCM, with the sender, recipient and post bound in as associated data.

import { fromBase64, fromHex, toBase64, toHex, utf8 } from "./bytes.js";
import { canonical, type Json } from "./canonical.js";
import { signValue, verifyValue, type KeyPair, type PublicKey } from "./keys.js";

const subtle = globalThis.crypto.subtle;
/** Byte arrays as WebCrypto inputs (TypeScript distinguishes buffer kinds that WebCrypto accepts alike). */
const bs = (u: Uint8Array): BufferSource => u as unknown as BufferSource;
const HEX64 = /^[0-9a-f]{64}$/;
const KEY = /^ed25519:[0-9a-f]{64}$/;
const BOX_KEY = /^x25519:[0-9a-f]{64}$/;

/**
 * A time written the only way the channel accepts it: ISO 8601 in UTC ("2026-11-30T12:00:00Z"). Looser forms
 * (local dates, "10/12/2026", text around a date) are refused: they read differently in different places and
 * can carry prose to the other agent.
 */
export const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
export const isIsoTime = (v: unknown): v is string => typeof v === "string" && ISO_TIME.test(v) && Number.isFinite(Date.parse(v));

// ---------- box keys ----------

export interface BoxSecret {
  /** X25519 private key, 32 bytes hex. */
  d: string;
  /** X25519 public key, 32 bytes hex. */
  x: string;
}

export interface BoxKeyClaim {
  body: { type: "symbolon/box-key"; v: 1; agent: PublicKey; key: string; createdAt: string };
  signature: string;
}

const b64u = (hex: string) => toBase64(fromHex(hex)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string) => toHex(fromBase64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)));

export async function newBoxSecret(): Promise<BoxSecret> {
  const kp = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const jwk = await subtle.exportKey("jwk", kp.privateKey);
  return { d: unb64u(jwk.d!), x: unb64u(jwk.x!) };
}

export function boxKeyClaim(agent: KeyPair, secret: BoxSecret, now = new Date()): BoxKeyClaim {
  const body = { type: "symbolon/box-key" as const, v: 1 as const, agent: agent.publicKey, key: "x25519:" + secret.x, createdAt: now.toISOString() };
  return { body, signature: signValue(body, agent) };
}

/** Problem with a box key claim, or null: well formed and signed by the agent it names (the expected one, when given). */
export function boxKeyClaimProblem(c: unknown, expectedAgent?: PublicKey): string | null {
  const x = c as BoxKeyClaim;
  if (!x || typeof x !== "object" || !x.body || typeof x.signature !== "string") return "not a box key claim";
  const b = x.body;
  if (Object.keys(x).some((k) => k !== "body" && k !== "signature") || Object.keys(b).some((k) => !["type", "v", "agent", "key", "createdAt"].includes(k)))
    return "unexpected fields in box key claim";
  if (b.type !== "symbolon/box-key" || b.v !== 1) return "not a box key claim";
  if (typeof b.agent !== "string" || !KEY.test(b.agent) || typeof b.key !== "string" || !BOX_KEY.test(b.key)) return "invalid box key claim";
  if (!isIsoTime(b.createdAt)) return "invalid box key date (ISO 8601 in UTC)";
  if (expectedAgent && b.agent !== expectedAgent) return "the box key belongs to another agent";
  if (!verifyValue(b, x.signature, b.agent)) return "the box key is not signed by its agent";
  return null;
}

// ---------- boxes ----------

export interface Box {
  v: 1;
  /** Fresh X25519 public key of this box, hex. */
  epk: string;
  /** AES-GCM nonce, 12 bytes hex. */
  iv: string;
  /** Ciphertext with tag, base64. */
  ct: string;
}

/** Largest box the piazza accepts (base64 characters of the ciphertext). */
export const BOX_MAX_CHARS = 96_000;
/** Sizes a box's content is padded to (characters). */
const PAD_SIZES = [512, 2_048, 8_192, 16_384];

export function boxProblem(b: unknown): string | null {
  const x = b as Box;
  if (!x || typeof x !== "object" || Object.keys(x).some((k) => !["v", "epk", "iv", "ct"].includes(k))) return "not a box";
  if (x.v !== 1 || typeof x.epk !== "string" || !HEX64.test(x.epk) || typeof x.iv !== "string" || !/^[0-9a-f]{24}$/.test(x.iv)) return "invalid box";
  if (typeof x.ct !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(x.ct) || x.ct.length > BOX_MAX_CHARS) return `invalid box content (base64, at most ${BOX_MAX_CHARS} characters)`;
  return null;
}

const importPublic = (hex: string) => subtle.importKey("raw", bs(fromHex(hex)), { name: "X25519" }, false, []);
const importPrivate = (s: BoxSecret) => subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: b64u(s.d), x: b64u(s.x) }, { name: "X25519" }, false, ["deriveBits"]);

async function aesKey(priv: CryptoKey, pubHex: string, epk: string, recipient: string): Promise<CryptoKey> {
  const shared = await subtle.deriveBits({ name: "X25519", public: await importPublic(pubHex) }, priv, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: bs(fromHex(epk + recipient)), info: bs(utf8("symbolon/channel/1")) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** What the box is bound to: who sends it, to whom, about which post. A box moved elsewhere does not open. */
export interface BoxContext {
  from: PublicKey;
  to: PublicKey;
  postId: string;
}
const aad = (c: BoxContext) => utf8(canonical({ from: c.from, to: c.to, postId: c.postId }));

/** Seals a value for the holder of `recipientBoxKey` ("x25519:<hex>"). */
export async function sealBox(value: Json, recipientBoxKey: string, ctx: BoxContext): Promise<Box> {
  if (!BOX_KEY.test(recipientBoxKey)) throw new Error("invalid box key");
  const recipient = recipientBoxKey.slice(7);
  const eph = await newBoxSecret();
  const key = await aesKey(await importPrivate(eph), recipient, eph.x, recipient);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  // Padded to a few fixed sizes (spaces after the JSON), so the length of a box does not tell which form it holds.
  const text = canonical(value);
  const size = PAD_SIZES.find((n) => n >= text.length) ?? Math.ceil(text.length / 16_384) * 16_384;
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: bs(iv), additionalData: bs(aad(ctx)) }, key, bs(utf8(text + " ".repeat(size - text.length)))));
  return { v: 1, epk: eph.x, iv: toHex(iv), ct: toBase64(ct) };
}

/** Opens a box sealed for this box secret; throws if it was not for us, was changed, or was moved. */
export async function openBox(box: Box, secret: BoxSecret, ctx: BoxContext): Promise<unknown> {
  const problem = boxProblem(box);
  if (problem) throw new Error(problem);
  const key = await aesKey(await importPrivate(secret), box.epk, box.epk, secret.x);
  let plain: ArrayBuffer;
  try {
    plain = await subtle.decrypt({ name: "AES-GCM", iv: bs(fromHex(box.iv)), additionalData: bs(aad(ctx)) }, key, bs(fromBase64(box.ct)));
  } catch {
    throw new Error("the box does not open: not for this agent, changed on the way, or moved to another conversation");
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

// ---------- forms ----------

/** Fixed answers: no free text travels between agents. */
export const QUESTIONS = ["unclear", "please_change", "need_more_detail", "which_date", "which_amount"] as const;
export const ASK_OWNER_REASONS = ["over_my_limit", "outside_my_scope", "needs_approval"] as const;
export const OWNER_DECISIONS = ["go_ahead", "declined"] as const;
export const DECLINE_REASONS = ["price", "date", "scope", "not_now", "other"] as const;
/** Why a party uses its right of withdrawal (only within the clause withdrawal_until of the agreement). */
export const WITHDRAWAL_REASONS = ["changed_mind", "mistake", "owner_decision", "other"] as const;
/** Longest pause for "I ask my owner". */
export const ASK_OWNER_MAX_DAYS = 7;

/**
 * The forms of the channel. `about` names what the form refers to: an offer (its clause root), a clause name,
 * or "general". Offers and confirmations are the wallet's own objects and are checked in full on use.
 */
export type Form =
  | { form: "offer"; offer: Json }
  | { form: "confirmation"; confirmation: Json }
  | { form: "question"; about: string; ask: (typeof QUESTIONS)[number] }
  | { form: "ask_owner"; about: string; reason: (typeof ASK_OWNER_REASONS)[number]; until: string }
  | { form: "owner_answer"; about: string; decision: (typeof OWNER_DECISIONS)[number] }
  | { form: "decline"; about: string; reason: (typeof DECLINE_REASONS)[number] }
  /** A withdrawal within the agreed period: `about` is the agreement's fingerprint, `proof` proves the sealed withdrawal. */
  | { form: "withdrawal"; about: string; reason: (typeof WITHDRAWAL_REASONS)[number]; proof: Json };

export const FORM_NAMES = ["offer", "confirmation", "question", "ask_owner", "owner_answer", "decline", "withdrawal"] as const;

/** What a form is about: "general", an offer or agreement fingerprint, or a clause name (one short word, no spaces). */
const aboutOk = (a: unknown) => typeof a === "string" && (a === "general" || HEX64.test(a) || /^[\p{L}][\p{L}\p{N}_.-]{0,39}$/u.test(a));
/** Offers, confirmations and proofs are the wallets' own objects: limited in depth and size, checked in full on use. */
export const FORM_LIMITS = { maxDepth: 12, maxChars: 64_000 } as const;
function depthOf(v: unknown, d = 0): number {
  if (d > FORM_LIMITS.maxDepth) return d;
  if (!v || typeof v !== "object") return d;
  let max = d;
  for (const x of Object.values(v as object)) max = Math.max(max, depthOf(x, d + 1));
  return max;
}
const objectShape = (v: unknown, keys: string[], type: string) =>
  !!v && typeof v === "object" && !Array.isArray(v) && (v as { type?: unknown }).type === type && only(v as object, keys) && depthOf(v) <= FORM_LIMITS.maxDepth && canonical(v as Json).length <= FORM_LIMITS.maxChars;
const only = (x: object, keys: string[]) => Object.keys(x).every((k) => keys.includes(k));
const oneOf = (v: unknown, list: readonly string[]) => typeof v === "string" && list.includes(v);

/** Problem with a form, or null. Anything not exactly one of the forms is refused. */
export function formProblem(f: unknown, now = new Date()): string | null {
  const x = f as Record<string, unknown>;
  if (!x || typeof x !== "object" || Array.isArray(x) || !oneOf(x.form, FORM_NAMES)) return `a form must be one of: ${FORM_NAMES.join(", ")}`;
  switch (x.form) {
    case "offer":
      return only(x, ["form", "offer"]) && objectShape(x.offer, ["type", "record", "opened", "mandates"], "accord/offer") ? null : "an offer form carries only {form, offer} with a wallet offer";
    case "confirmation":
      return only(x, ["form", "confirmation"]) && objectShape(x.confirmation, ["type", "record", "receipt"], "accord/confirmation")
        ? null
        : "a confirmation form carries only {form, confirmation} with a wallet confirmation";
    case "question":
      if (!only(x, ["form", "about", "ask"]) || !aboutOk(x.about)) return "a question carries only {form, about, ask}";
      return oneOf(x.ask, QUESTIONS) ? null : `ask must be one of: ${QUESTIONS.join(", ")}`;
    case "ask_owner": {
      if (!only(x, ["form", "about", "reason", "until"]) || !aboutOk(x.about)) return "ask_owner carries only {form, about, reason, until}";
      if (!oneOf(x.reason, ASK_OWNER_REASONS)) return `reason must be one of: ${ASK_OWNER_REASONS.join(", ")}`;
      const t = isIsoTime(x.until) ? Date.parse(x.until) : NaN;
      if (!Number.isFinite(t) || t <= now.getTime() || t > now.getTime() + ASK_OWNER_MAX_DAYS * 86_400_000) return `until must be a time (ISO 8601 in UTC) within the next ${ASK_OWNER_MAX_DAYS} days`;
      return null;
    }
    case "owner_answer":
      if (!only(x, ["form", "about", "decision"]) || !aboutOk(x.about)) return "owner_answer carries only {form, about, decision}";
      return oneOf(x.decision, OWNER_DECISIONS) ? null : `decision must be one of: ${OWNER_DECISIONS.join(", ")}`;
    case "decline":
      if (!only(x, ["form", "about", "reason"]) || !aboutOk(x.about)) return "decline carries only {form, about, reason}";
      return oneOf(x.reason, DECLINE_REASONS) ? null : `reason must be one of: ${DECLINE_REASONS.join(", ")}`;
    case "withdrawal":
      if (!only(x, ["form", "about", "reason", "proof"]) || typeof x.about !== "string" || !HEX64.test(x.about)) return "a withdrawal carries only {form, about: <agreement fingerprint>, reason, proof}";
      if (!objectShape(x.proof, ["type", "v", "record", "mandates", "disclosures", "receipt", "cosignatures", "anchor"], "accord/proof"))
        return "a withdrawal needs the proof of the sealed withdrawal";
      return oneOf(x.reason, WITHDRAWAL_REASONS) ? null : `reason must be one of: ${WITHDRAWAL_REASONS.join(", ")}`;
  }
  return "unknown form";
}

/** What each form means, for the agent reading it. */
export const FORM_MEANING: Record<(typeof FORM_NAMES)[number], string> = {
  offer: "The other agent proposes an agreement. Check it and, if your owner's mandate allows it, accept it with symbolon_accept_agreement.",
  confirmation: "The other agent accepted your offer and sealed it. File it with symbolon_confirm_agreement.",
  question: "The other agent asks about a clause (or in general). Answer with a new offer, or decline.",
  ask_owner: "The other agent paused to ask its owner, until the given time. The negotiation is not over: wait for owner_answer, or for an offer made with its owner's approval of this agreement only (accept it as usual: your wallet checks the approval).",
  owner_answer: "The other agent reports its owner's decision (said by the agent, not signed by the owner): go_ahead (the negotiation continues) or declined. Only an offer carrying the owner's signed approval binds that owner.",
  decline: "The other agent declines, with a fixed reason.",
  withdrawal: "The other agent withdraws from a sealed agreement within the agreed period. Check and record it with symbolon_record_withdrawal: your wallet verifies the proof and the date itself, and refuses a withdrawal shown more than 2 days after the period ended.",
};
