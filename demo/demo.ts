// Storia dimostrativa: due aziende, due agenti, un accordo sigillato,
// una prova mostrata a un arbitro, due tentativi di imbroglio scoperti.
// Avvio: npm run demo

import {
  ForkDetected,
  MemoryStore,
  Register,
  Witness,
  buildProof,
  commitClauses,
  createMandate,
  createRecord,
  disclose,
  entryHash,
  generateKeyPair,
  mandateId,
  signRecord,
  staticOwnerResolver,
  verifyProof,
  type Report,
} from "../src/index.js";

const say = (s = "") => console.log(s);
const verdict = (r: Report) => {
  for (const c of r.checks) say(`   ${c.ok ? "✔" : "✘"} ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  say(`   → ${r.valid ? "PROVA VALIDA" : "PROVA NON VALIDA"}`);
};

say("1. Due aziende danno una delega ai loro agenti");
const alfa = generateKeyPair();
const beta = generateKeyPair();
const buyer = generateKeyPair();
const seller = generateKeyPair();
const validity = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-12-31T23:59:59Z", charter: "accord-charter/0.1" };
const mBuyer = createMandate(alfa, {
  ownerDomain: "alfa.example",
  agent: buyer.publicKey,
  scope: "acquisto di cancelleria",
  maxAmount: { value: "50000.00", currency: "EUR" },
  ...validity,
});
const mSeller = createMandate(beta, { ownerDomain: "beta.example", agent: seller.publicKey, scope: "vendita di cancelleria", ...validity });
say("   Alfa: il suo agente può comprare cancelleria fino a 50.000 €");
say("   Beta: il suo agente può vendere cancelleria");

say("\n2. Gli agenti si accordano; l'accordo resta a loro, diviso in clausole");
const opened = commitClauses([
  { name: "oggetto", value: "10.000 risme di carta A4" },
  { name: "amount", value: { value: "42000.00", currency: "EUR" } },
  { name: "consegna", value: "2026-12-10" },
  { name: "penale", value: "0,5% al giorno di ritardo" },
]);
let record = createRecord({
  type: "accord/agreement",
  clausesRoot: opened.root,
  clauseCount: opened.count,
  parties: [
    { agent: buyer.publicKey, mandate: mandateId(mBuyer) },
    { agent: seller.publicKey, mandate: mandateId(mSeller) },
  ],
  charter: "accord-charter/0.1",
  createdAt: new Date().toISOString(),
});
record = signRecord(signRecord(record, buyer), seller);
say("   Firmato da entrambi gli agenti.");

say("\n3. Al registro va solo l'impronta");
const store = new MemoryStore();
const register = new Register(generateKeyPair(), store);
const receipt = await register.append(entryHash(record));
say(`   Impronta: ${receipt.entry}`);
say(`   Ricevuta: voce n. ${receipt.index}, ora ${receipt.head.time}`);

say("\n4. Due testimoni indipendenti controfirmano il registro");
const witnesses = [new Witness(generateKeyPair()), new Witness(generateKeyPair())];
const cosignatures = witnesses.map((w) => w.observe(receipt.head, []));
say("   Fatto.");

const opts = {
  trustedLogs: [register.publicKey],
  trustedWitnesses: witnesses.map((w) => w.publicKey),
  minWitnesses: 2,
  ownerResolver: staticOwnerResolver({ "alfa.example": [alfa.publicKey], "beta.example": [beta.publicKey] }),
};
const proof = (disclosures: ReturnType<typeof disclose>[]) =>
  buildProof({ record, mandates: [mBuyer, mSeller], disclosures, receipt, cosignatures });

say("\n5. Lite sul ritardo: Alfa mostra all'arbitro solo la data di consegna e l'importo");
verdict(await verifyProof(proof([disclose(opened, "consegna"), disclose(opened, "amount")]), opts));
say("   (l'arbitro non vede oggetto né penale)");

say("\n6. Beta prova a sostenere che la consegna era a marzo 2027");
const fake = { ...disclose(opened, "consegna"), value: "2027-03-01" };
verdict(await verifyProof(proof([fake]), opts));

say("\n7. Il gestore del registro prova a riscrivere la storia");
store.overwriteForTest(0, "00".repeat(32));
const head = await register.publishHead();
const proofFromOld = await register.consistency(1, head.size);
try {
  witnesses[0].observe(head, proofFromOld);
  say("   ✘ non scoperto");
} catch (e) {
  say(`   ✔ ${e instanceof ForkDetected ? "Il testimone rifiuta di controfirmare: imbroglio scoperto" : String(e)}`);
}
