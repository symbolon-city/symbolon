// Serves the change book's public pages (built by site.ts) from a bucket, read-only.
// Only GET and HEAD, only files under the site prefix, no listing, no query handling.
// Shared by the book's worker (Cloudflare) and the tests: no Node imports here.

export interface BookObject {
  body: ReadableStream | null;
  size: number;
  httpEtag?: string;
}

export interface BookBucket {
  get(key: string): Promise<BookObject | null>;
}

const TYPES: Record<string, string> = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  ots: "application/octet-stream",
  txt: "text/plain; charset=utf-8",
};

/** The bucket key for a request path, or undefined if the path is not a page of the book. */
export function bookKey(pathname: string, prefix: string): string | undefined {
  let p: string;
  try {
    p = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
  if (p === "/" || p === "") p = "/index.html";
  if (p.endsWith("/")) p += "index.html";
  if (p.length > 300 || !/^\/[A-Za-z0-9._\/-]+$/.test(p) || p.split("/").some((s) => s === ".." || s === ".")) return undefined;
  const ext = p.slice(p.lastIndexOf(".") + 1);
  if (!TYPES[ext]) return undefined;
  return prefix + p.slice(1);
}

const SECURITY = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

export async function serveBook(req: Request, bucket: BookBucket, prefix = "sito/"): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/robots.txt")
    return new Response("User-agent: *\nAllow: /\n", { headers: { "content-type": TYPES.txt, ...SECURITY } });
  if (req.method !== "GET" && req.method !== "HEAD")
    return new Response("Method not allowed", { status: 405, headers: { allow: "GET, HEAD", ...SECURITY } });
  const key = bookKey(url.pathname, prefix);
  const obj = key ? await bucket.get(key) : null;
  if (!key || !obj) return new Response("Not found in the change book.", { status: 404, headers: { "content-type": TYPES.txt, ...SECURITY } });
  const ext = key.slice(key.lastIndexOf(".") + 1);
  const headers: Record<string, string> = {
    "content-type": TYPES[ext],
    "cache-control": "public, max-age=300",
    // the JSON files are for programs and agents of any origin
    ...(ext === "json" || ext === "ots" ? { "access-control-allow-origin": "*" } : {}),
    ...(obj.httpEtag ? { etag: obj.httpEtag } : {}),
    ...SECURITY,
  };
  return new Response(req.method === "HEAD" ? null : obj.body, { headers });
}
