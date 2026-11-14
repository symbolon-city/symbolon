// Builds the npm package @symbolon-city/wallet in packages/wallet: the wallet MCP server and the owner tool,
// bundled into two files; the dependencies stay external (installed by npm).
//   npm run build:wallet && cd packages/wallet && npm pack
import { build } from "esbuild";
import { copyFileSync, readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("packages/wallet/package.json", "utf8")) as { version: string; dependencies: Record<string, string> };
for (const [entry, out] of [
  ["scripts/symbolon-mcp.ts", "packages/wallet/dist/wallet.js"],
  ["scripts/owner.ts", "packages/wallet/dist/owner.js"],
]) {
  await build({
    entryPoints: [entry],
    outfile: out,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    external: Object.keys(pkg.dependencies).flatMap((d) => [d, `${d}/*`]),
    banner: { js: "#!/usr/bin/env node" },
    legalComments: "none",
  });
}
copyFileSync("LICENSE", "packages/wallet/LICENSE");
console.log(`packages/wallet built (version ${pkg.version})`);
