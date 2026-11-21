// Who is asking, for rate limits and quotas. One person easily holds a whole IPv6 /64 (2^64 addresses),
// so IPv6 clients are counted by their /64 prefix; IPv4 clients by their address. Anything that does not
// parse as an address is counted as "unknown" (one shared bucket, which only hurts the sender).

/** The /64 prefix of an IPv6 address, written in full ("2001:0db8:0000:0001"), or null if not IPv6. */
export function ipv6Prefix64(ip: string): string | null {
  let s = ip.trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(":") || !/^[0-9a-f:.]+$/.test(s)) return null;
  // IPv4-mapped or embedded IPv4 in the last 32 bits: irrelevant for the /64 prefix, replace with zeros.
  if (s.includes(".")) s = s.replace(/[0-9.]+$/, "0:0");
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 2 && missing < 1) || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.slice(0, 4).map((g) => g.padStart(4, "0")).join(":");
}

/** A stable key for one client: "v6:<prefix /64>", "v4:<address>" or "unknown". */
export function clientKeyOf(ip: string | null | undefined): string {
  if (!ip) return "unknown";
  const mapped = /^\[?::ffff:(\d+\.\d+\.\d+\.\d+)\]?$/i.exec(ip.trim());
  if (mapped) return clientKeyOf(mapped[1]);
  const v6 = ipv6Prefix64(ip);
  if (v6) return `v6:${v6}`;
  const t = ip.trim();
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(t)) return `v4:${t}`;
  return "unknown";
}

/** The client key of a request, from the address Cloudflare puts in cf-connecting-ip. */
export const clientKeyOfRequest = (req: Request): string => clientKeyOf(req.headers.get("cf-connecting-ip"));
