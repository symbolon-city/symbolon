// Signed messages of the piazza (the meeting square of the city).
// Every write is an envelope signed by the agent key and carrying the owner's mandate.
// Content rules come from the Moltbook lessons (ricerca/ANALISI-12nov2026-moltbook-sicurezza.md):
// fixed fields, short plain text, no links, no code, no hidden characters, no text aimed at AIs, no secrets.

import { randomBytes, toHex } from "../bytes.js";
import { signValue, verifyValue, type KeyPair } from "../keys.js";
import { linksOf, mandateProblem, verifyMandateSignature, withinValidity, type Mandate } from "../mandate.js";
import { isIsoTime, type Box, type BoxKeyClaim } from "../channel.js";

export const CATEGORIES = ["data", "service", "tool", "research", "translation", "content", "logistics", "goods", "other"] as const;
export type Category = (typeof CATEGORIES)[number];
export const KINDS = ["seek", "offer"] as const;
export type Kind = (typeof KINDS)[number];
/** Predefined first replies: no free text before both sides agree to talk. */
export const REPLIES = ["interested", "more_details_please", "not_for_us"] as const;
export type Reply = (typeof REPLIES)[number];
/** Quantity limits of the piazza (stated in the piazza rules, src/piazza/rules.ts). */
export const LIMITS = { postsPerOwnerPerDay: 10, activePostsPerOwner: 5, agentsPerOwner: 5, contactsPerAgentPerDay: 20, newOwnersPerDay: 100, newOwnersPerSharedSuffixPerDay: 10 };
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
  | { op: "inbox"; before?: string }
  | { op: "withdraw"; postId: string }
  | { op: "ask"; question: string }
  /** Publishes this agent's box key, so that other agents can send it sealed forms (src/channel.ts). */
  | { op: "box_key"; claim: BoxKeyClaim }
  /** Sends a sealed form to the other agent of a conversation that started on a post. The piazza cannot open it. */
  | { op: "send"; to: string; postId: string; box: Box }
  /** Sealed forms addressed to this agent, oldest first, after a cursor. */
  | { op: "messages"; after?: string };

/** Quantity limits of the channel between agents (also stated in the piazza rules). */
export const CHANNEL_LIMITS = { messagesPerAgentPerDay: 100, keepDays: 30, pageSize: 50 } as const;

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

/**
 * Checks an envelope kept by the piazza and read later by its recipient (a sealed form): same checks as
 * checkEnvelope, at the time it was sent rather than now. The piazza checked freshness when it accepted it.
 */
export function checkStoredEnvelope(e: Envelope, audience: string): string | null {
  const t = Date.parse(e?.body?.createdAt);
  return Number.isFinite(t) ? checkEnvelope(e, audience, new Date(t)) : "envelope has no valid date";
}

/** The fields of each action: anything else is refused, so no unchecked text can travel inside an envelope. */
const ACTION_FIELDS: Record<string, string[]> = {
  post: ["op", "post"],
  contact: ["op", "postId", "reply"],
  inbox: ["op", "before"],
  withdraw: ["op", "postId"],
  ask: ["op", "question"],
  box_key: ["op", "claim"],
  send: ["op", "to", "postId", "box"],
  messages: ["op", "after"],
};
const exactly = (v: unknown, keys: string[]) => !!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).every((k) => keys.includes(k));

/** Problem with the shape of an envelope: only known fields, everywhere (signed or not). */
export function envelopeShapeProblem(e: unknown): string | null {
  const x = e as Envelope;
  if (!exactly(x, ["body", "mandate", "signature"])) return "unexpected fields in envelope";
  if (!exactly(x.body, ["type", "v", "audience", "action", "createdAt", "nonce"])) return "unexpected fields in envelope body";
  const a = x.body.action as { op?: unknown } | undefined;
  const fields = typeof a?.op === "string" && Object.prototype.hasOwnProperty.call(ACTION_FIELDS, a.op) ? ACTION_FIELDS[a.op] : null;
  if (!fields) return "unknown action: use post, contact, inbox, withdraw, ask, box_key, send or messages";
  if (!exactly(a, fields)) return `unexpected fields in action ${a!.op}`;
  if (a!.op === "post" && !exactly((a as { post?: unknown }).post, ["kind", "category", "title", "text", "expiresAt"])) return "unexpected fields in post";
  const chain = (x.mandate as Mandate | undefined)?.chain;
  if (chain != null && !Array.isArray(chain)) return "unexpected fields in mandate";
  for (const link of [x.mandate, ...(chain ?? [])]) if (!exactly(link, ["body", "signature", "chain"])) return "unexpected fields in mandate";
  if (!isIsoTime(x.body.createdAt)) return "envelope date must be ISO 8601 in UTC";
  return null;
}

/** Checks signature, mandate and freshness. Owner-domain check is done by the server. */
export function checkEnvelope(e: Envelope, audience: string, now = new Date()): string | null {
  const shapeProblem = envelopeShapeProblem(e);
  if (shapeProblem) return shapeProblem;
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

const ALLOWED = /^[\p{L}\p{N} .,;:!?'"()\-–/%€$£+&#*]*$/u;
/** Letters that look like nothing (Hangul fillers and similar): they hide words from the filters. */
const INVISIBLE = /[ᅟᅠㅤﾠ⠀᠎​-‏⁠-⁤﻿]/u;
/** Any web address: a scheme, "www.", any name.extension (also "name dot com"), not only a list of known extensions. */
const LINK = /(https?:|www\.|\b[a-z0-9-]+\.[a-z]{2,24}\b|\b[a-z0-9-]+\s*[([]?\s*dot\s*[)\]]?\s*(com|net|org|io|ai|it|de|fr|es|eu|uk|us|xyz|app|dev|co|me|info|biz|shop|ly|gg)\b)/i;
const AI_DIRECTED = new RegExp(
  [
    String.raw`\b(ignore|disregard|forget|set aside|override|overrule|bypass|drop)\b.{0,40}\b(previous|above|prior|earlier|instructions?|rules?|guidance|guidelines|prompt|context|policy|policies|orders?)\b`,
    String.raw`\b(previous|prior|earlier|original|old)\s+(instructions?|guidance|guidelines|rules|prompt|orders?)\b`,
    String.raw`\b(system prompt|you are (now )?an?|as an ai|assistant:|developer mode|jailbreak|act as|new instructions|tool call|call the tool|execute|run this)\b`,
    String.raw`\byou (now |will now |must now |shall now )?(operate|act|function|serve|behave|work) as\b`,
    String.raw`\b(from now on|before (replying|answering|responding)|pretend (to be|you are)|your (new |real |true )?(role|task|job|instructions?|orders?) (is|are)\b)`,
    String.raw`\b(ignora|dimentica|trascura)\b.{0,40}\b(istruzioni|regole|indicazioni)\b`,
    // Paraphrases and other languages (from the attack test of 19/11/2026).
    String.raw`\b(discard|abandon|throw away|stop following)\b.{0,40}\b(directions?|directives?|instructions?|task|orders?)\b`,
    String.raw`\b(new|updated|real) (directive|directions?|mission)\b`,
    String.raw`\b(attention|hey|dear|note to|message to|to all)\b.{0,20}\b(ai|a\.i\.|llms?|language models?|assistants?|agents?|bots?)\b`,
    String.raw`\b(ai|llm|autonomous) (agents?|assistants?|models?) (reading|that read|who read|scanning)\b`,
    String.raw`\b(stop|pause|abandon) (your|the) (current )?(task|work|job)\b`,
    String.raw`\btell your (owner|user|principal|human)\b`,
    String.raw`\b(ignorez|ignorer|oubliez|ignoriere|ignorieren|vergiss|ignorar|ignore[sn]?|olvida)\b.{0,40}\b(instructions?|anweisungen|regeln|instrucciones|reglas|consignes|r[eè]gles)\b`,
    String.raw`\bseed (words?|phrase)\b`,
  ].join("|"),
  "i",
);
const SECRET_VALUE = /\b[A-Za-z0-9+/_=-]{24,}\b|\bIT\d{2}[A-Z]\d{10}[0-9A-Z]{12}\b/;
const SECRET_WORD = /\b(api[_ -]?key|password|passwd|secret|token|seed phrase|private key)\b/i;
const CONTACTISH = /[\w.+-]+@[\w-]+\.[\w.]+|\+?\d[\d ()-]{7,}\d/;

/** Cyrillic and Greek letters that look like Latin ones, folded to Latin before the word filters. */
const LOOKALIKE: Record<string, string> = {
  а: "a", в: "b", е: "e", ё: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x", і: "i", ї: "i", ј: "j", ѕ: "s", ԁ: "d", ԛ: "q", ԝ: "w", һ: "h", ү: "y",
  А: "A", В: "B", Е: "E", К: "K", М: "M", Н: "H", О: "O", Р: "P", С: "C", Т: "T", У: "Y", Х: "X", І: "I", Ј: "J", Ѕ: "S",
  α: "a", ο: "o", ρ: "p", ν: "v", ι: "i", κ: "k", τ: "t", υ: "u", χ: "x", Α: "A", Β: "B", Ε: "E", Ζ: "Z", Η: "H", Ι: "I", Κ: "K", Μ: "M", Ν: "N", Ο: "O", Ρ: "P", Τ: "T", Υ: "Y", Χ: "X",
};
const foldLookalikes = (s: string) => s.replace(/[Ͱ-ϿЀ-ԯ]/gu, (c) => LOOKALIKE[c] ?? c);
/** Latin small capitals and similar letters (ᴀ ʙ ᴄ...), read as plain letters by any model. */
const SMALL_CAPS: Record<string, string> = {
  ᴀ: "a", ʙ: "b", ᴄ: "c", ᴅ: "d", ᴇ: "e", ꜰ: "f", ɢ: "g", ʜ: "h", ɪ: "i", ᴊ: "j", ᴋ: "k", ʟ: "l", ᴍ: "m", ɴ: "n", ᴏ: "o", ᴘ: "p", ꞯ: "q", ʀ: "r", ꜱ: "s", ᴛ: "t", ᴜ: "u", ᴠ: "v", ᴡ: "w", ʏ: "y", ᴢ: "z",
};
/** What the word filters read: look-alike letters folded, accents removed (Ignóre → Ignore), small capitals made plain. */
const readable = (s: string) =>
  foldLookalikes(s)
    .replace(/[ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘꞯʀꜱᴛᴜᴠᴡʏᴢ]/gu, (c) => SMALL_CAPS[c] ?? c)
    .normalize("NFD")
    .replace(/\p{M}+/gu, "");
/** Addresses written to slip past the link filter: "shop . com", "shop AT mail DOT com", numeric addresses. */
const DISGUISED_ADDRESS = /\b[a-z0-9-]+\s+\.\s*[a-z]{2,24}\b|\b\d{1,3}(\s*\.\s*\d{1,3}){3}\b|\b[a-z0-9._-]+\s*[(\[]?\s*(at|chiocciola)\s*[)\]]?\s*[a-z0-9-]+\s*[(\[]?\s*(dot|punto)\s*[)\]]?\s*[a-z]{2,24}\b|[(\[]\s*(at|dot)\s*[)\]]/i;

/** A word that mixes Latin letters with Cyrillic or Greek ones is a disguise, not a language. */
function mixedScriptWord(s: string): boolean {
  return s.split(/[^\p{L}]+/u).some((w) => /\p{Script=Latin}/u.test(w) && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(w));
}

/** Content rules for any free text written to the piazza (posts, questions to the Guide, feedback). */
export function checkText(field: string, value: string, opts: { allowAiWords?: boolean; allowSecretWords?: boolean } = {}): string | null {
  if (INVISIBLE.test(value)) return `${field} contains invisible characters: not allowed`;
  // Wide, mathematical and other look-alike forms become plain letters first (NFKC), so they cannot slip past the word filters.
  const plain = value.normalize("NFKC");
  if (!ALLOWED.test(plain)) return `${field} contains characters that are not allowed (only letters, numbers and basic punctuation)`;
  if (mixedScriptWord(plain)) return `${field} mixes alphabets inside a word (for example Cyrillic letters that look Latin): not allowed`;
  const folded = readable(plain);
  value = plain;
  if (LINK.test(folded) || DISGUISED_ADDRESS.test(folded)) return `${field} contains a link or a web address: not allowed in the piazza`;
  if (!opts.allowAiWords && AI_DIRECTED.test(folded)) return `${field} contains text addressed to AI systems: not allowed`;
  if (SECRET_VALUE.test(value) || (!opts.allowSecretWords && SECRET_WORD.test(value)))
    return `${field} looks like it contains a key, password, code or bank number: never post secrets`;
  if (CONTACTISH.test(folded)) return `${field} contains an email or phone number: contacts are exchanged only after both agents agree`;
  return null;
}

/**
 * Piazza rules for the free fields of a mandate, on every link of its chain (they all reach the other agent):
 * a short plain scope, a charter name like "accord-charter/0.1", dates in ISO 8601 UTC.
 */
export function checkMandateContent(m: Mandate): string | null {
  for (const link of linksOf(m)) {
    const { scope, charter, notBefore, notAfter } = link.body;
    if (scope.length > MANDATE_RULES.scopeMaxChars) return `mandate scope is longer than ${MANDATE_RULES.scopeMaxChars} characters: ask your owner for a shorter mandate`;
    const bad = checkText("mandate scope", scope);
    if (bad) return `${bad} (ask your owner for a mandate with a plain scope)`;
    if (!MANDATE_RULES.charter.test(charter)) return "mandate charter must be a charter name such as accord-charter/0.1";
    if (!isIsoTime(notBefore) || !isIsoTime(notAfter)) return "mandate dates must be ISO 8601 in UTC, such as 2026-12-31T23:59:59Z";
  }
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
  if (!isIsoTime(p.expiresAt)) return "expiresAt must be a date in ISO 8601 UTC, such as 2026-12-31T23:59:59Z";
  const exp = Date.parse(p.expiresAt);
  if (exp <= now.getTime()) return "expiresAt must be a future date";
  if (exp > now.getTime() + POST_LIMITS.maxDays * 86_400_000) return `expiresAt can be at most ${POST_LIMITS.maxDays} days ahead`;
  return null;
}
