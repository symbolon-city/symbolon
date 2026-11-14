// The "site" of an owner: its registrable domain (the part bought from a registrar), found with the
// Public Suffix List, private suffixes included. s1.example.com, s2.example.com and example.com are one
// site; alice.github.io and bob.github.io are two. The piazza's limits per owner count per site, so a
// single owner cannot multiply its limits with subdomains.

import { getDomain } from "tldts";

export function siteOf(domain: string): string {
  return getDomain(domain, { allowPrivateDomains: true }) ?? domain;
}

/** True if `domain` is `site` or one of its subdomains. */
export function inSite(domain: string, site: string): boolean {
  return domain === site || domain.endsWith("." + site);
}
