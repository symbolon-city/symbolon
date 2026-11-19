// The "site" of an owner: its registrable domain (the part bought from a registrar), found with the
// Public Suffix List, private suffixes included. s1.example.com, s2.example.com and example.com are one
// site; alice.github.io and bob.github.io are two. The piazza's limits per owner count per site, so a
// single owner cannot multiply its limits with subdomains.

import { getDomain, parse } from "tldts";

export function siteOf(domain: string): string {
  return getDomain(domain, { allowPrivateDomains: true }) ?? domain;
}

/** True if `domain` is `site` or one of its subdomains. */
export function inSite(domain: string, site: string): boolean {
  return domain === site || domain.endsWith("." + site);
}

/**
 * The shared suffix of a free hosting service (pages.dev, github.io, workers.dev...) when the domain sits under
 * one: anyone can get unlimited names there for nothing. Null for a domain bought from a registrar.
 */
export function sharedSuffixOf(domain: string): string | null {
  const p = parse(domain, { allowPrivateDomains: true });
  return p.isPrivate && p.publicSuffix ? p.publicSuffix : null;
}
