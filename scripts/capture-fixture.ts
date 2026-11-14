// Records real calendar answers for a fixed digest, used by the offline tests.
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const d = createHash("sha256").update("accord test").digest();
const out: Record<string, string> = { digest: d.toString("hex") };
for (const u of ["https://a.pool.opentimestamps.org", "https://finney.calendar.eternitywall.com"]) {
  const r = await fetch(u + "/digest", { method: "POST", body: d, headers: { Accept: "application/vnd.opentimestamps.v1" } });
  out[u] = Buffer.from(await r.arrayBuffer()).toString("hex");
}
writeFileSync("test/fixtures/calendar-responses.json", JSON.stringify(out, null, 2) + "\n");
console.log(Object.keys(out));
