// The pages of the hosted wallet: "connect your assistant" (sign in with a passkey) and the owner's page
// (sign a request, see the agent, Block everything). One small page, no external resources, every value
// from the server written as text (never as HTML). English, or Italian when the browser asks for it.

import { randomBytes, toBase64url } from "../bytes.js";

export type PageModel =
  | { view: "authorize"; origin: string; request: string; client: string; redirectHost: string }
  | { view: "owner"; origin: string; request?: string }
  | { view: "error"; origin: string; message: string };

/** JSON safe inside a <script> element. */
const scriptJson = (v: unknown) => JSON.stringify(v).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");

export function hostedPage(model: PageModel, status = 200): Response {
  const nonce = toBase64url(randomBytes(16));
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Symbolon wallet</title>
<style>
:root{--bg:#f7f5f0;--card:#fff;--ink:#1d1d1b;--muted:#6b6862;--line:#e3dfd6;--accent:#1f5f4a;--warn:#9a3b1c}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--ink:#efece6;--muted:#a19d95;--line:#33322f;--accent:#6fc2a3;--warn:#f08a64}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:560px;margin:0 auto;padding:28px 16px 48px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:24px 0 8px}
.muted{color:var(--muted);font-size:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:14px 0}
button{font:inherit;font-weight:600;border:0;border-radius:10px;padding:13px 18px;width:100%;margin-top:10px;background:var(--accent);color:#fff;cursor:pointer}
@media (prefers-color-scheme:dark){button{color:#10201a}}
button.secondary{background:transparent;color:var(--accent);border:1px solid var(--line)}button.danger{background:var(--warn)}
button:disabled{opacity:.5}dl{margin:0}dt{color:var(--muted);font-size:13px;margin-top:10px}dd{margin:2px 0 0;word-break:break-word}
.big{font-size:20px;font-weight:700}.err{color:var(--warn)}.ok{color:var(--accent);font-weight:600}code{font-size:12px;word-break:break-all}
.brand{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:18px}
</style></head><body><main><div class="brand">Symbolon City · wallet</div><div id="app"></div></main>
<script nonce="${nonce}">
const MODEL = ${scriptJson(model)};
${CLIENT_SCRIPT}
</script></body></html>`;
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'`,
    },
  });
}

// Runs in the browser. Kept free of template placeholders on purpose.
const CLIENT_SCRIPT = String.raw`
const IT = (navigator.language || "").toLowerCase().startsWith("it");
const T = IT ? {
  connectTitle: "Collega il tuo assistente", connectWho: "chiede di usare il tuo portafoglio Symbolon", returnTo: "Tornerai a",
  connectWhat: "Potrà preparare accordi a tuo nome. Niente vale senza la tua firma: una delega o un'approvazione che leggi qui e confermi con Face ID.",
  signIn: "Continua con Face ID", firstTime: "È la prima volta? Crea il tuo portafoglio", noPasskey: "Nessun portafoglio con questa chiave: creane uno.",
  ownerTitle: "Il tuo portafoglio", signInOwner: "Entra con Face ID", agent: "Il tuo agente", noMandate: "Nessuna delega: il tuo agente non può fare accordi a tuo nome.",
  mandate: "Delega", scope: "Cosa può fare", limit: "Fino a", noLimit: "nessun limite d'importo", until: "Valida fino al",
  requests: "Da firmare", noRequests: "Niente da firmare.", open: "Apri", commitments: "Impegni presi", noCommitments: "Nessun impegno aperto.",
  block: "Blocca tutto", blockWhat: "Il tuo agente si ferma subito, ovunque: la revoca viene sigillata nel registro pubblico. Gli assistenti collegati vengono scollegati. Gli accordi già fatti restano.",
  blockConfirm: "Blocca con Face ID", blocked: "Bloccato. Il tuo agente non può più agire. Ricollega l'assistente per ripartire con un agente nuovo.",
  reqMandate: "Il tuo agente ti chiede questa delega", reqApproval: "Approva solo questo accordo", sign: "Firma con Face ID",
  notSign: "Se non è quello che vuoi, chiudi la pagina: la richiesta scade da sola.", signed: "Firmato. Puoi tornare al tuo assistente.",
  counterparty: "Con", generalLimit: "Il tuo limite generale resta", clauses: "Clausole (quelle vere, ricalcolate dall'impronta)", validUntil: "Valida fino al",
  identity: "La tua chiave", amount: "Importo",
  proof: "Scarica la prova", agreement: "Accordo", action: "Azione", sealed: "Sigillato il", revoked: "Questa delega è stata revocata: il tuo agente non può agire.",
  overdue: "Scaduto: controlla se è stato fatto", nextDate: "Prossima data", withdrawUntil: "Puoi ripensarci fino al",
  waiting: "In attesa", waitingYou: "Aspetta la tua approvazione", waitingThem: "Inviato, aspetta l'altra parte",
  history: "Storico", previousAgent: "Agente precedente (bloccato)", yours: "I tuoi dati",
  exportWhat: "Scarica deleghe, accordi e prove in un file: sono tuoi e puoi portarli altrove. Le chiavi segrete dell'agente non ci sono.", exportAll: "Scarica tutto",
  outcomes: { fulfilled: "eseguito", cancelled_by_agreement: "annullato d'accordo", not_fulfilled: "non eseguito", withdrawn: "ripensamento" }, error: "Errore", again: "Riprova",
} : {
  connectTitle: "Connect your assistant", connectWho: "asks to use your Symbolon wallet", returnTo: "You will return to",
  connectWhat: "It will be able to prepare agreements on your behalf. Nothing is valid without your signature: a mandate or an approval you read here and confirm with Face ID.",
  signIn: "Continue with Face ID", firstTime: "First time? Create your wallet", noPasskey: "No wallet for this passkey: create one.",
  ownerTitle: "Your wallet", signInOwner: "Sign in with Face ID", agent: "Your agent", noMandate: "No mandate: your agent cannot make agreements on your behalf.",
  mandate: "Mandate", scope: "What it may do", limit: "Up to", noLimit: "no amount limit", until: "Valid until",
  requests: "To sign", noRequests: "Nothing to sign.", open: "Open", commitments: "Commitments", noCommitments: "No open commitments.",
  block: "Block everything", blockWhat: "Your agent stops at once, everywhere: the revocation is sealed in the public register. Connected assistants are disconnected. Agreements already made stay.",
  blockConfirm: "Block with Face ID", blocked: "Blocked. Your agent can no longer act. Connect your assistant again to start with a new agent.",
  reqMandate: "Your agent asks you for this mandate", reqApproval: "Approve only this agreement", sign: "Sign with Face ID",
  notSign: "If this is not what you want, close the page: the request expires by itself.", signed: "Signed. You can go back to your assistant.",
  counterparty: "With", generalLimit: "Your general limit stays", clauses: "Clauses (the real ones, recomputed from the fingerprint)", validUntil: "Valid until",
  identity: "Your key", amount: "Amount",
  proof: "Download the proof", agreement: "Agreement", action: "Action", sealed: "Sealed on", revoked: "This mandate was revoked: your agent cannot act.",
  overdue: "Past due: check whether it was done", nextDate: "Next date", withdrawUntil: "You can withdraw until",
  waiting: "Waiting", waitingYou: "Waiting for your approval", waitingThem: "Sent, waiting for the other side",
  history: "History", previousAgent: "Previous agent (blocked)", yours: "Your data",
  exportWhat: "Download mandates, agreements and proofs in one file: they are yours and you can take them elsewhere. The agent's secret keys are not in it.", exportAll: "Download everything",
  outcomes: { fulfilled: "fulfilled", cancelled_by_agreement: "cancelled by agreement", not_fulfilled: "not fulfilled", withdrawn: "withdrawn" }, error: "Error", again: "Try again",
};
document.documentElement.lang = IT ? "it" : "en";
const app = document.getElementById("app");
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) if (k === "onclick") e.onclick = v; else e.setAttribute(k, v);
  for (const k of kids) if (k !== null && k !== undefined) e.append(k instanceof Node ? k : String(k));
  return e;
}
function show(...nodes) { app.replaceChildren(...nodes); }
function fail(e) { const p = el("p", { class: "err" }, T.error + ": " + (e && e.message ? e.message : e)); app.append(p); }
async function api(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.error_description || res.status);
  return data;
}
const post = (path, body, session) => api(path, { method: "POST", headers: { "content-type": "application/json", ...(session ? { authorization: "Bearer " + session } : {}) }, body: JSON.stringify(body) });
const money = (a) => a ? a.value + " " + a.currency : T.noLimit;
const day = (iso) => iso ? new Date(iso).toLocaleDateString(IT ? "it-IT" : undefined, { day: "numeric", month: "long", year: "numeric" }) : "";

/** Signs in with a passkey of this site (or creates one) for a purpose; returns the server's answer. */
async function passkeyLogin(purpose, create) {
  const c = await post("/auth/challenge", { purpose });
  if (!create) {
    const cred = await navigator.credentials.get({ publicKey: { challenge: unb64u(c.challenge), rpId: c.rpId, userVerification: "required", timeout: 120000 } });
    const r = cred.response;
    return post("/auth/signin", { nonce: c.nonce, credentialId: b64u(cred.rawId), signature: ["webauthn", b64u(r.authenticatorData), b64u(r.clientDataJSON), b64u(r.signature)].join(".") });
  }
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: unb64u(c.challenge), rp: { id: c.rpId, name: "Symbolon" },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "Symbolon", displayName: "Symbolon wallet" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], attestation: "none", timeout: 120000,
    authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
  } });
  const r = cred.response;
  return post("/auth/signup", { nonce: c.nonce, credentialId: b64u(cred.rawId), publicKey: b64u(r.getPublicKey()), clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.getAuthenticatorData()) });
}

/** Signs a value prepared by the server (its challenge is the fingerprint of the exact text shown) with the owner's passkey. */
async function passkeySign(challenge, credentialId) {
  const cred = await navigator.credentials.get({ publicKey: { challenge: unb64u(challenge), allowCredentials: [{ type: "public-key", id: unb64u(credentialId) }], userVerification: "required", timeout: 120000 } });
  const r = cred.response;
  return ["webauthn", b64u(r.authenticatorData), b64u(r.clientDataJSON), b64u(r.signature)].join(".");
}

function busy(button, fn) {
  return async () => { button.disabled = true; try { await fn(); } catch (e) { fail(e); } finally { button.disabled = false; } };
}

function authorizeView() {
  const go = async (create) => {
    try { const r = await passkeyLogin("authorize:" + MODEL.request, create); location.assign(r.redirect); }
    catch (e) { if (!create && /no Symbolon wallet/.test(e.message)) fail(new Error(T.noPasskey)); else fail(e); }
  };
  const a = el("button", {}, T.signIn), b = el("button", { class: "secondary" }, T.firstTime);
  a.onclick = busy(a, () => go(false)); b.onclick = busy(b, () => go(true));
  show(el("h1", {}, T.connectTitle), el("div", { class: "card" }, el("p", { class: "big" }, MODEL.client), el("p", {}, T.connectWho),
    el("p", { class: "muted" }, T.returnTo + " " + MODEL.redirectHost), el("p", {}, T.connectWhat)), a, b);
}

async function requestView(id) {
  const r = await api("/owner/api/request/" + id);
  const card = el("div", { class: "card" });
  const dl = el("dl");
  if (r.kind === "mandate") {
    card.append(el("h1", {}, T.reqMandate));
    dl.append(el("dt", {}, T.scope), el("dd", { class: "big" }, r.body.scope), el("dt", {}, T.limit), el("dd", {}, money(r.body.maxAmount)), el("dt", {}, T.until), el("dd", {}, day(r.body.notAfter)));
  } else {
    card.append(el("h1", {}, T.reqApproval));
    const amount = r.clauses.amount;
    dl.append(el("dt", {}, T.counterparty), el("dd", { class: "big" }, r.counterparty.owner), el("dt", {}, T.amount), el("dd", { class: "big" }, money(amount)),
      el("dt", {}, T.generalLimit), el("dd", {}, money(r.general_limit)), el("dt", {}, T.validUntil), el("dd", {}, day(r.approval_body.notAfter)), el("dt", {}, T.clauses));
    for (const [k, v] of Object.entries(r.clauses)) dl.append(el("dd", {}, el("b", {}, k + ": "), typeof v === "string" ? v : JSON.stringify(v)));
  }
  card.append(dl);
  const b = el("button", {}, T.sign);
  b.onclick = busy(b, async () => {
    const signature = await passkeySign(r.challenge, r.credential_id);
    await post("/owner/api/request/" + id, { signature });
    show(el("h1", {}, T.signed));
  });
  show(card, b, el("p", { class: "muted" }, T.notSign));
}

async function download(path, session, name) {
  const res = await fetch(path, { headers: { authorization: "Bearer " + session } });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.status);
  const url = URL.createObjectURL(await res.blob());
  const a = el("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000);
}
const clauseText = (c) => Object.entries(c || {}).map(([k, v]) => k + ": " + (typeof v === "string" ? v : v && v.value && v.currency ? v.value + " " + v.currency : JSON.stringify(v))).join(" · ");
const outcomeText = (o) => (T.outcomes[o] || o);

function historyList(items, gen, session) {
  const nodes = [];
  for (const h of items) {
    const b = el("button", { class: "secondary" }, T.proof);
    b.onclick = busy(b, () => download("/owner/api/proof/" + gen + "/" + h.entry, session, "symbolon-proof-" + h.entry.slice(0, 12) + ".json"));
    nodes.push(el("div", { class: "card" },
      el("b", {}, (h.kind === "agreement" ? T.agreement : T.action) + (h.with.length ? " · " + h.with.join(", ") : "")),
      el("p", { class: "muted" }, T.sealed + " " + day(h.sealed_at) + (h.closed ? " · " + outcomeText(h.closed.outcome) : "")), b));
  }
  return nodes;
}

async function ownerView(session) {
  const s = await api("/owner/api/state", { headers: { authorization: "Bearer " + session } });
  const c = s.commitments || {};
  const nodes = [el("h1", {}, T.ownerTitle)];
  const m = s.mandate;
  nodes.push(el("h2", {}, T.agent), el("div", { class: "card" }, m
    ? el("dl", {}, el("dt", {}, T.scope), el("dd", { class: "big" }, m.scope), el("dt", {}, T.limit), el("dd", {}, money(m.maxAmount)), el("dt", {}, T.until), el("dd", {}, day(m.validUntil)))
    : el("p", {}, T.noMandate),
    s.mandate_revoked ? el("p", { class: "err" }, T.revoked) : null,
    el("p", { class: "muted" }, el("code", {}, s.agent))));

  nodes.push(el("h2", {}, T.requests));
  if (!s.requests.length) nodes.push(el("p", { class: "muted" }, T.noRequests));
  for (const q of s.requests) { const b = el("button", { class: "secondary" }, T.open + " · " + (q.kind === "mandate" ? T.mandate : T.reqApproval)); b.onclick = () => location.assign("/owner/r/" + q.id); nodes.push(b); }

  nodes.push(el("h2", {}, T.commitments));
  const open = c.open || [];
  if (!open.length) nodes.push(el("p", { class: "muted" }, T.noCommitments));
  for (const x of open) {
    const b = el("button", { class: "secondary" }, T.proof);
    b.onclick = busy(b, () => download("/owner/api/proof/" + s.agent_gen + "/" + x.entry, session, "symbolon-proof-" + x.entry.slice(0, 12) + ".json"));
    nodes.push(el("div", { class: "card" },
      el("b", {}, (x.with || []).map((w) => w.owner).join(", ")),
      x.overdue ? el("p", { class: "err" }, T.overdue) : null,
      x.next_date ? el("p", {}, T.nextDate + ": " + day(x.next_date.date) + " (" + x.next_date.clause + ")") : null,
      x.can_withdraw_until ? el("p", { class: "muted" }, T.withdrawUntil + " " + day(x.can_withdraw_until)) : null,
      el("p", { class: "muted" }, clauseText(x.clauses)), b));
  }
  const waiting = (c.waiting || []).concat(c.waiting_for_owner || []);
  if (waiting.length) {
    nodes.push(el("h2", {}, T.waiting));
    for (const w of waiting) nodes.push(el("div", { class: "card" }, el("b", {}, ((w.to || w.with) || []).map((p) => p.owner).join(", ")),
      el("p", { class: "muted" }, (w.ask_until ? T.waitingYou : T.waitingThem) + " · " + clauseText(w.clauses))));
  }

  const closed = (s.history || []).filter((h) => h.closed || h.kind === "action");
  if (closed.length) nodes.push(el("h2", {}, T.history), ...historyList(closed, s.agent_gen, session));
  for (const p of s.previous_agents || []) {
    if (!p.history.length) continue;
    nodes.push(el("h2", {}, T.previousAgent), el("p", { class: "muted" }, el("code", {}, p.agent)), ...historyList(p.history, p.gen, session));
  }

  const exp = el("button", { class: "secondary" }, T.exportAll);
  exp.onclick = busy(exp, () => download("/owner/api/export", session, "symbolon-wallet-export.json"));
  nodes.push(el("h2", {}, T.yours), el("p", { class: "muted" }, T.exportWhat), exp);

  const block = el("button", { class: "danger" }, T.blockConfirm);
  block.onclick = busy(block, async () => {
    const r = await api("/owner/api/block", { headers: { authorization: "Bearer " + session } });
    const signature = await passkeySign(r.challenge, r.credential_id);
    await post("/owner/api/block", { body: r.body, signature }, session);
    show(el("h1", {}, T.blocked));
  });
  nodes.push(el("h2", {}, T.block), el("p", { class: "muted" }, T.blockWhat), block, el("p", { class: "muted" }, T.identity + ": ", el("code", {}, s.owner_key)));
  show(...nodes);
}

function ownerSignIn() {
  const b = el("button", {}, T.signInOwner);
  b.onclick = busy(b, async () => { const r = await passkeyLogin("owner", false); await ownerView(r.session); });
  show(el("h1", {}, T.ownerTitle), b);
}

(async () => {
  try {
    if (MODEL.view === "error") show(el("h1", {}, T.error), el("p", {}, MODEL.message));
    else if (MODEL.view === "authorize") authorizeView();
    else if (MODEL.request) await requestView(MODEL.request);
    else ownerSignIn();
  } catch (e) { fail(e); }
})();
`;
