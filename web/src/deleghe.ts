// Browser logic of the mandate page. Bundled into web/deleghe.html.
import { generateKeyPair, keyPairFromSecret, type KeyPair } from "../../src/keys.js";
import { createMandate, mandateId, verifyMandateSignature, withinValidity, type Mandate } from "../../src/mandate.js";
import { toHex } from "../../src/bytes.js";

const STORE = "symbolon-owner-v1";
interface Owner { domain: string; secret: string; publicKey: string }

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function load(): Owner | null {
  try {
    const raw = localStorage.getItem(STORE);
    return raw ? (JSON.parse(raw) as Owner) : null;
  } catch {
    return null;
  }
}
function save(o: Owner | null) {
  try {
    if (o) localStorage.setItem(STORE, JSON.stringify(o));
    else localStorage.removeItem(STORE);
  } catch {
    /* storage unavailable: the key lives only in this tab */
  }
}

let owner: Owner | null = load();

async function copy(text: string, btn: HTMLButtonElement, area?: HTMLTextAreaElement) {
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent;
    btn.textContent = "Copiato";
    setTimeout(() => (btn.textContent = old), 1600);
  } catch {
    if (area) {
      area.focus();
      area.select();
    }
  }
}

function wellKnown(o: Owner) {
  return JSON.stringify({ symbolon: 1, domain: o.domain, keys: [o.publicKey] }, null, 2);
}

function render() {
  const has = !!owner;
  $("no-owner").hidden = has;
  $("has-owner").hidden = !has;
  $("mandate-form").toggleAttribute("inert", !has);
  $("mandate-card").classList.toggle("locked", !has);
  if (owner) {
    $("owner-domain").textContent = owner.domain;
    $("owner-key").textContent = owner.publicKey;
    $<HTMLTextAreaElement>("wellknown").value = wellKnown(owner);
    $("wellknown-url").textContent = `https://${owner.domain}/.well-known/symbolon.json`;
  }
}

$("create-owner").addEventListener("submit", (e) => {
  e.preventDefault();
  const domain = $<HTMLInputElement>("domain").value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const err = $("domain-error");
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) {
    err.textContent = "Scrivi solo il dominio del sito, per esempio example.com";
    err.hidden = false;
    return;
  }
  err.hidden = true;
  const k: KeyPair = generateKeyPair();
  owner = { domain, secret: toHex(k.secretKey), publicKey: k.publicKey };
  save(owner);
  render();
});

$("copy-wellknown").addEventListener("click", (e) =>
  copy($<HTMLTextAreaElement>("wellknown").value, e.currentTarget as HTMLButtonElement, $<HTMLTextAreaElement>("wellknown")),
);

$("show-backup").addEventListener("click", () => {
  if (!owner) return;
  const box = $("backup-box");
  box.hidden = !box.hidden;
  $<HTMLTextAreaElement>("backup").value = JSON.stringify(owner);
});
$("copy-backup").addEventListener("click", (e) =>
  copy($<HTMLTextAreaElement>("backup").value, e.currentTarget as HTMLButtonElement, $<HTMLTextAreaElement>("backup")),
);

$("restore-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const err = $("restore-error");
  try {
    const o = JSON.parse($<HTMLTextAreaElement>("restore").value) as Owner;
    const k = keyPairFromSecret(o.secret);
    if (k.publicKey !== o.publicKey || !o.domain) throw new Error();
    owner = o;
    save(owner);
    err.hidden = true;
    render();
  } catch {
    err.textContent = "Copia di sicurezza non valida: incolla il testo esatto che avevi salvato.";
    err.hidden = false;
  }
});

$("forget").addEventListener("click", () => {
  const c = $("forget-confirm");
  c.hidden = false;
});
$("forget-no").addEventListener("click", () => ($("forget-confirm").hidden = true));
$("forget-yes").addEventListener("click", () => {
  owner = null;
  save(null);
  $("forget-confirm").hidden = true;
  $("result").hidden = true;
  render();
});

$("mandate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!owner) return;
  const err = $("mandate-error");
  const agent = $<HTMLInputElement>("agent").value.trim();
  const scope = $<HTMLInputElement>("scope").value.trim();
  const max = $<HTMLInputElement>("max").value.trim().replace(",", ".");
  const currency = $<HTMLSelectElement>("currency").value;
  const days = Number($<HTMLSelectElement>("days").value);
  const problems: string[] = [];
  if (!/^ed25519:[0-9a-f]{64}$/.test(agent)) problems.push("Il codice dell'agente deve iniziare con ed25519: seguito da 64 caratteri (lo mostra l'agente con symbolon_whoami).");
  if (!scope) problems.push("Scrivi cosa può fare l'agente.");
  if (max && !/^\d+(\.\d{1,2})?$/.test(max)) problems.push("Il limite di spesa deve essere un numero, per esempio 500 oppure 1250.50.");
  if (problems.length) {
    err.textContent = problems.join(" ");
    err.hidden = false;
    return;
  }
  err.hidden = true;
  const now = new Date();
  const m: Mandate = createMandate(keyPairFromSecret(owner.secret), {
    ownerDomain: owner.domain,
    agent,
    scope,
    ...(max ? { maxAmount: { value: Number(max).toFixed(2), currency } } : {}),
    notBefore: now.toISOString(),
    notAfter: new Date(now.getTime() + days * 86_400_000).toISOString(),
    charter: "accord-charter/0.1",
  });
  const json = JSON.stringify(m, null, 2);
  $<HTMLTextAreaElement>("mandate-out").value = json;
  $("summary").textContent =
    `${owner.domain} autorizza l'agente ${agent.slice(8, 16)}… a: ${scope}` +
    (max ? `, fino a ${Number(max).toFixed(2)} ${currency}` : ", senza limite di spesa") +
    `, fino al ${new Date(m.body.notAfter).toLocaleDateString("it-IT")}.`;
  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
});

$("copy-mandate").addEventListener("click", (e) =>
  copy($<HTMLTextAreaElement>("mandate-out").value, e.currentTarget as HTMLButtonElement, $<HTMLTextAreaElement>("mandate-out")),
);

$("verify-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const out = $("verify-out");
  out.hidden = false;
  out.className = "verdict";
  try {
    const m = JSON.parse($<HTMLTextAreaElement>("verify-in").value) as Mandate;
    const sigOk = verifyMandateSignature(m);
    const timeOk = withinValidity(m, new Date().toISOString());
    const b = m.body;
    out.classList.add(sigOk && timeOk ? "good" : "bad");
    out.innerHTML = "";
    const lines = [
      sigOk ? "✔ Timbro valido: la delega non è stata modificata." : "✘ Timbro non valido: la delega è stata modificata o è falsa.",
      timeOk ? "✔ In corso di validità." : "✘ Scaduta o non ancora valida.",
      `Padrone: ${b.owner.domain}`,
      `Agente: ${b.agent.slice(0, 24)}…`,
      `Può: ${b.scope}`,
      `Limite: ${b.maxAmount ? `${b.maxAmount.value} ${b.maxAmount.currency}` : "nessuno"}`,
      `Valida fino al ${new Date(b.notAfter).toLocaleDateString("it-IT")}`,
      `Codice della delega: ${mandateId(m).slice(0, 16)}…`,
      `Resta da controllare che la chiave del padrone sia pubblicata su https://${b.owner.domain}/.well-known/symbolon.json`,
    ];
    for (const l of lines) {
      const p = document.createElement("p");
      p.textContent = l;
      out.appendChild(p);
    }
  } catch {
    out.classList.add("bad");
    out.textContent = "Testo non riconosciuto: incolla la delega intera, dalla prima { all'ultima }.";
  }
});

render();
