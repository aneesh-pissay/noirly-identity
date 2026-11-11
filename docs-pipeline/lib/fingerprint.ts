import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

/** Every file under a path (or the path itself), sorted, skipping tests. */
export function filesUnder(source: string): string[] {
  if (!existsSync(source)) return [];
  if (statSync(source).isFile()) return [source];
  return readdirSync(source, { withFileTypes: true })
    .flatMap((entry) => filesUnder(path.join(source, entry.name)))
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort();
}

/**
 * A short hash of the files an article describes. Line endings are normalised
 * so a checkout on another OS gives the same answer. Missing sources hash as
 * "missing" so a deleted file reads as a change.
 */
export function fingerprint(sources: string[]): string {
  const hash = createHash("sha256");
  for (const source of [...sources].sort()) {
    const files = filesUnder(source);
    if (!files.length) hash.update(`${source}\0missing\0`);
    for (const file of files) {
      hash.update(`${file.replace(/\\/g, "/")}\0`);
      hash.update(readFileSync(file, "utf8").replace(/\r\n/g, "\n"));
      hash.update("\0");
    }
  }
  return hash.digest("hex").slice(0, 16);
}
