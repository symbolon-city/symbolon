// Cloudflare Worker of the change book's public pages: serves, read-only, the files that the daily
// reading builds (src/book/site.ts) and uploads to the R2 bucket under sito/. Nothing else.

import { serveBook, type BookBucket } from "../src/book/serve.js";

interface Env {
  BOOK: BookBucket;
}

export default {
  fetch(req: Request, env: Env): Promise<Response> {
    return serveBook(req, env.BOOK, "sito/");
  },
};
