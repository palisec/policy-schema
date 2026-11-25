import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

/** SHA-256 over the engine's sources (Cargo.toml, Cargo.lock, src/**), line endings normalized. */
export function sourceHash(dir) {
  const files = ["Cargo.toml", "Cargo.lock"];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".rs")) files.push(relative(dir, p).split("\\").join("/"));
    }
  };
  walk(join(dir, "src"));
  const h = createHash("sha256");
  for (const f of files.sort()) {
    h.update(`${f}\n`);
    h.update(readFileSync(join(dir, f), "utf8").replace(/\r\n/g, "\n"));
    h.update("\n");
  }
  return h.digest("hex");
}
