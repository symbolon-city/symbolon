// File names of the change book, shared by the reader (Node) and the visitors' door (Workers).

import { utf8 } from "../bytes.js";
import { sha256Hex } from "../hash.js";

/** Readable and collision-free file name for a server name or a skill id. */
export function fileName(id: string): string {
  return id.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 80) + "-" + sha256Hex(utf8(id)).slice(0, 8);
}
