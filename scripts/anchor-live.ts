// Ancora reale su Bitcoin tramite OpenTimestamps.
//   npm run anchor -- stamp            crea un registro di prova, ancora la sua testa, salva in ancore/
//   npm run anchor -- upgrade <file>   chiede ai calendari se è già in Bitcoin e verifica il blocco
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fromBase64 } from "../src/bytes.js";
import {
  Register,
  anchorHead,
  esploraProvider,
  generateKeyPair,
  toOtsFile,
  fromOtsFile,
  upgradeAnchor,
  verifyAnchor,
  type Anchor,
} from "../src/index.js";

const [cmd, file] = process.argv.slice(2);
const blocks = esploraProvider();

if (cmd === "stamp") {
  const register = new Register(generateKeyPair());
  for (const word of ["prima", "seconda", "terza"]) {
    const { createHash } = await import("node:crypto");
    await register.append(createHash("sha256").update(`voce di prova ${word}`).digest("hex"));
  }
  const anchor = await anchorHead((await register.latestHead())!);
  const status = await verifyAnchor(anchor, blocks);
  mkdirSync("ancore", { recursive: true });
  const out = `ancore/${anchor.head.time.slice(0, 10)}-prova.json`;
  writeFileSync(out, JSON.stringify(anchor, null, 2) + "\n");
  writeFileSync(out.replace(".json", ".ots"), toOtsFile(fromOtsFile(fromBase64(anchor.ots))));
  console.log(`Salvata ${out}`);
  console.log("Stato:", JSON.stringify(status));
} else if (cmd === "upgrade" && file) {
  const anchor = JSON.parse(readFileSync(file, "utf8")) as Anchor;
  const { anchor: up, upgraded } = await upgradeAnchor(anchor);
  if (upgraded) {
    writeFileSync(file, JSON.stringify(up, null, 2) + "\n");
    writeFileSync(file.replace(".json", ".ots"), fromBase64(up.ots));
  }
  console.log(`Attestazioni aggiornate: ${upgraded}`);
  console.log("Stato:", JSON.stringify(await verifyAnchor(up, blocks)));
} else {
  console.log("uso: npm run anchor -- stamp | upgrade <file.json>");
}
