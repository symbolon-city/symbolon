// Builds web/deleghe.html: the template with the bundled browser script inlined.
import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";

const out = await build({ entryPoints: ["web/src/deleghe.ts"], bundle: true, minify: true, format: "iife", target: "es2020", write: false });
const js = out.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const html = readFileSync("web/deleghe.template.html", "utf8").replace("/*SCRIPT*/", () => js);
writeFileSync("web/deleghe.html", html);
console.log(`web/deleghe.html: ${(html.length / 1024).toFixed(1)} KB`);
