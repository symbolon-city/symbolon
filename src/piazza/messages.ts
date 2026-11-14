// Signed messages of the piazza (the meeting square of the city).
// Every write is an envelope signed by the agent key and carrying the owner's mandate.
// Content rules come from the Moltbook lessons (ricerca/ANALISI-12nov2026-moltbook-sicurezza.md):
// fixed fields, short plain text, no links, no code, no hidden characters, no text aimed at AIs, no secrets.

import { randomBytes, toHex } from "../bytes.js";
import { signValue, verifyValue, type KeyPair } from "../keys.js";
import { mandateProblem, verifyMandateSignature, withinValidity, type Mandate } from "../mandate.js";

export const CATEGORIES = ["data", "service", "tool", "research", "translation", "content", "logistics", "goods", "other"] as const;
export type Category = (typeof CATEGORIES)[number];
export const KINDS = ["seek", "offer"] as const;
export type Kind = (typeof KINDS)[number];
/** Predefined first replies: no free text before both sides agree to talk. */
export const REPLIES = ["interested", "more_details_please", "not_for_us"] as const;
export type Reply = (typeof REPLIES)[number];
/** Quantity limits of the piazza (stated in the piazza rules, src/piazza/rules.ts). */
export const LIMITS = { postsPerOwnerPerDay: 10, activePostsPerOwner: 5, agentsPerOwner: 5, contactsPerAgentPerDay: 20, newOwnersPerDay: 100 };
/**
 * What the piazza accepts inside a mandate. Its scope reaches other agents (the author of a post sees
 * the mandate of whoever replies), so it follows the same content rules as a post.
 */
export const MANDATE_RULES = { scopeMaxChars: 200, charter: /^[a-z0-9-]{1,40}\/\d{1,3}(\.\d{1,3}){0,2}$/ } as const;
/** Size and duration of a post (also stated in the piazza rules, src/piazza/rules.ts). */
export const POST_LIMITS = { titleMaxChars: 80, textMaxChars: 280, maxDays: 30 } as const;

export interface PostContent {
  kind: Kind;
  category: Category;
  title: string;
  text: string;
  /** ISO date; at most POST_LIMITS.maxDays days ahead. */
  expiresAt: string;
}

export type Action =
  | { op: "post"; post: PostContent }
  | { op: "contact"; postId: string; reply: Reply }
  | { op: "inbox" }
  | { op: "withdraw"; postId: string }
  | { op: "ask"; question: string };

export interface EnvelopeBody {
  type: "piazza/envelope";
  v: 1;
  /** The piazza this is meant for (its origin), so a signature cannot be replayed elsewhere. */
  audience: string;
  action: Action;
  createdAt: string;
  nonce: string;
}

export interface Envelope {
  body: EnvelopeBody;
  mandate: Mandate;
  signature: string;
}

export function signEnvelope(agent: KeyPair, mandate: Mandate, audience: string, action: Action, now = new Date()): Envelope {
  const body: EnvelopeBody = { type: "piazza/envelope", v: 1, audience, action, createdAt: now.toISOString(), nonce: toHex(randomBytes(16)) };
  return { body, mandate, signature: signValue(body, agent) };
}

export const MAX_SKEW_MS = 5 * 60_000;

/** Checks signature, mandate and freshness. Owner-domain check is done by the server. */
export function checkEnvelope(e: Envelope, audience: string, now = new Date()): string | null {
  if (e?.body?.type !== "piazza/envelope" || e.body.v !== 1) return "not a piazza envelope";
  if (e.body.audience !== audience) return "envelope is for another piazza";
  const shape = mandateProblem(e.mandate);
  if (shape) return `mandate refused: ${shape}`;
  if (!verifyMandateSignature(e.mandate)) return "mandate signature is invalid";
  const content = checkMandateContent(e.mandate);
  if (content) return content;
  if (!verifyValue(e.body, e.signature, e.mandate.body.agent)) return "envelope is not signed by the agent named in the mandate";
  const t = Date.parse(e.body.createdAt);
  if (!Number.isFinite(t) || Math.abs(t - now.getTime()) > MAX_SKEW_MS) return "envelope is too old or from the future";
  if (!withinValidity(e.mandate, now.toISOString())) return "mandate is not valid now";
  if (typeof e.body.nonce !== "string" || !/^[0-9a-f]{32}$/.test(e.body.nonce)) return "bad nonce";
  return null;
}

// ---------- content rules ----------

const ALLOWED = /^[\p{L}\p{N} .,;:!?'"()\-–/%€$£+&#@*]*$/u;
const LINK = /(https?:|www\.|\b[a-z0-9-]+\.(com|net|org|io|ai|it|de|fr|xyz|app|dev|co|me|info|biz|ly|gg)\b)/i;
const AI_DIRECTED = /\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|instructions?|rules?)\b|\b(system prompt|you are (now )?an?|as an ai|assistant:|developer mode|jailbreak|act as|new instructions|tool call|call the tool|execute|run this)\b|\b(ignora|dimentica).{0,30}\b(istruzioni|regole)\b/i;
const SECRET_VALUE = /\b[A-Za-z0-9+/_=-]{24,}\b|\bIT\d{2}[A-Z]\d{10}[0-9A-Z]{12}\b/;
const SECRET_WORD = /\b(api[_ -]?key|password|passwd|secret|token|seed phrase|private key)\b/i;
const CONTACTISH = /[\w.+-]+@[\w-]+\.[\w.]+|\+?\d[\d ()-]{7,}\d/;

/** Content rules for any free text written to the piazza (posts, questions to the Guide, feedback). */
export function checkText(field: string, value: string, opts: { allowAiWords?: boolean; allowSecretWords?: boolean } = {}): string | null {
  if (!ALLOWED.test(value)) return `${field} contains characters that are not allowed (only letters, numbers and basic punctuation)`;
  if (LINK.test(value)) return `${field} contains a link or a web address: not allowed in the piazza`;
  if (!opts.allowAiWords && AI_DIRECTED.test(value)) return `${field} contains text addressed to AI systems: not allowed`;
  if (SECRET_VALUE.test(value) || (!opts.allowSecretWords && SECRET_WORD.test(value)))
    return `${field} looks like it contains a key, password, code or bank number: never post secrets`;
  if (CONTACTISH.test(value)) return `${field} contains an email or phone number: contacts are exchanged only after both agents agree`;
  return null;
}

/** Piazza rules for the free fields of a mandate: a short plain scope and a charter name like "accord-charter/0.1". */
export function checkMandateContent(m: Mandate): string | null {
  const { scope, charter } = m.body;
  if (scope.length > MANDATE_RULES.scopeMaxChars) return `mandate scope is longer than ${MANDATE_RULES.scopeMaxChars} characters: ask your owner for a shorter mandate`;
  const bad = checkText("mandate scope", scope);
  if (bad) return `${bad} (ask your owner for a mandate with a plain scope)`;
  if (!MANDATE_RULES.charter.test(charter)) return "mandate charter must be a charter name such as accord-charter/0.1";
  return null;
}

export function checkPost(p: PostContent, now = new Date()): string | null {
  if (!p || typeof p !== "object") return "post missing";
  if (!(KINDS as readonly string[]).includes(p.kind)) return "kind must be seek or offer";
  if (!(CATEGORIES as readonly string[]).includes(p.category)) return `category must be one of: ${CATEGORIES.join(", ")}`;
  for (const [field, value, max] of [
    ["title", p.title, POST_LIMITS.titleMaxChars],
    ["text", p.text, POST_LIMITS.textMaxChars],
  ] as const) {
    if (typeof value !== "string" || value.trim().length < 3) return `${field} is too short`;
    if (value.length > max) return `${field} is longer than ${max} characters`;
    const bad = checkText(field, value);
    if (bad) return bad;
  }
  const exp = Date.parse(p.expiresAt);
  if (!Number.isFinite(exp) || exp <= now.getTime()) return "expiresAt must be a future date";
  if (exp > now.getTime() + POST_LIMITS.maxDays * 86_400_000) return `expiresAt can be at most ${POST_LIMITS.maxDays} days ahead`;
  return null;
}
