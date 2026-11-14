// Verifica contro Bitcoin vero la prova d'esempio ufficiale di OpenTimestamps (hello-world.txt, 2015).
import { readFileSync } from "node:fs";
import { toHex } from "../src/bytes.js";
import { esploraProvider, fromOtsFile, verifyTimestamp } from "../src/index.js";

const ts = fromOtsFile(new Uint8Array(readFileSync("test/fixtures/hello-world.txt.ots")));
console.log("impronta:", toHex(ts.msg));
console.log(JSON.stringify(await verifyTimestamp(ts, esploraProvider())));
