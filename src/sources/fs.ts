import { promises as fs } from "node:fs";
import path from "node:path";
import type { ScanFile } from "../core/types.js";

const SKIP_DIRS = new Set([".git", "node_modules", ".next", "dist", "build", ".venv"]);
const MAX_BYTES = 5_000_000;

/** Walk a working tree and yield files. Never follows symlinks, never executes anything. */
export async function* walk(root: string, rel = ""): AsyncGenerator<ScanFile> {
  const entries = await fs.readdir(path.join(root, rel), { withFileTypes: true });
  for (const e of entries) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(root, r);
    } else if (e.isFile()) {
      const full = path.join(root, r);
      const st = await fs.stat(full);
      if (st.size > MAX_BYTES) continue;
      yield { path: r, content: await fs.readFile(full) };
    }
  }
}
