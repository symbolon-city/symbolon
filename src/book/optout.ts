// Who does not want to be read by the change book, and is respected:
// - opt-out.json in the data folder: names (server names, skill ids) and hosts, added on request
//   (write to the contact address); an item matched there is not read and has no public page;
// - robots.txt of a server's host: a group naming our user agent ("SymbolonBook") that disallows the
//   server's path. Generic "*" groups are not applied: the servers are published in a public registry
//   precisely so that programs connect to them, and the book only lists them, once a day.

export const BOOK_ROBOT = "SymbolonBook";

export interface OptOutEntry {
  /** A server name, a skill id ("owner/repo/skill"), or "host:<hostname>" for every server on a host. */
  value: string;
  since: string;
  note?: string;
}
export interface OptOutList {
  entries: OptOutEntry[];
}

export function optedOut(list: OptOutList | undefined, id: string, url?: string): OptOutEntry | undefined {
  if (!list) return undefined;
  let host: string | undefined;
  try {
    host = url ? new URL(url).host.toLowerCase() : undefined;
  } catch {}
  return list.entries.find((e) => e.value === id || (host !== undefined && e.value.toLowerCase() === `host:${host}`));
}

/** True when robots.txt has a group for our user agent that disallows this path (longest match wins, Allow beats Disallow on ties). */
export function robotsDisallow(robots: string, path: string, agent = BOOK_ROBOT): boolean {
  const rules: { allow: boolean; prefix: string }[] = [];
  let inGroup = false;
  let lastWasAgent = false;
  for (const raw of robots.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const field = m[1].toLowerCase();
    const value = m[2].trim();
    if (field === "user-agent") {
      const mine = value.toLowerCase() === agent.toLowerCase();
      inGroup = lastWasAgent ? inGroup || mine : mine;
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (!inGroup) continue;
    if (field === "disallow" && value) rules.push({ allow: false, prefix: value });
    if (field === "allow" && value) rules.push({ allow: true, prefix: value });
  }
  let best: { allow: boolean; prefix: string } | undefined;
  for (const r of rules)
    if (path.startsWith(r.prefix) && (!best || r.prefix.length > best.prefix.length || (r.prefix.length === best.prefix.length && r.allow))) best = r;
  return !!best && !best.allow;
}

/** Fetches robots.txt once per host per run; any failure means "no rule for us". */
export function robotsChecker(fetchImpl: typeof fetch = fetch, userAgent = BOOK_ROBOT) {
  const cache = new Map<string, Promise<string>>();
  return async (url: string): Promise<boolean> => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return false;
    }
    if (!cache.has(u.host))
      cache.set(
        u.host,
        (async () => {
          try {
            const res = await fetchImpl(`${u.protocol}//${u.host}/robots.txt`, { headers: { "User-Agent": userAgent }, signal: AbortSignal.timeout(5000) });
            return res.ok ? (await res.text()).slice(0, 100_000) : "";
          } catch {
            return "";
          }
        })(),
      );
    return robotsDisallow(await cache.get(u.host)!, u.pathname || "/");
  };
}
