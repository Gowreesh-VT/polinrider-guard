import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

const run = promisify(execFile);

/**
 * Everything the host checks may touch. Read-only by construction: there is no write or
 * delete here, and nothing that runs files found on disk. Tests swap in a fake.
 */
export interface Sys {
  platform: NodeJS.Platform;
  home: string;
  tmp: string;
  /** run a trusted system tool (ps, lsof, crontab, reg, ...) and return stdout, "" on failure */
  exec(cmd: string, args: string[]): Promise<string>;
  readText(p: string, maxBytes?: number): Promise<string | undefined>;
  exists(p: string): Promise<boolean>;
  list(dir: string): Promise<{ name: string; dir: boolean }[]>;
  env(name: string): string | undefined;
}

export function realSys(home = os.homedir()): Sys {
  return {
    platform: process.platform,
    home,
    tmp: os.tmpdir(),
    async exec(cmd, args) {
      try {
        const { stdout } = await run(cmd, args, { maxBuffer: 64 * 1024 * 1024, timeout: 30_000 });
        return stdout;
      } catch (e) {
        return (e as { stdout?: string }).stdout ?? "";
      }
    },
    async readText(p, maxBytes = 1_000_000) {
      try {
        const fh = await fs.open(p, "r");
        try {
          const buf = Buffer.alloc(maxBytes);
          const { bytesRead } = await fh.read(buf, 0, maxBytes, 0);
          return buf.subarray(0, bytesRead).toString("utf8");
        } finally { await fh.close(); }
      } catch { return undefined; }
    },
    async exists(p) { try { await fs.lstat(p); return true; } catch { return false; } },
    async list(dir) {
      try {
        return (await fs.readdir(dir, { withFileTypes: true })).map((e) => ({ name: e.name, dir: e.isDirectory() }));
      } catch { return []; }
    },
    env: (n) => process.env[n],
  };
}

export const join = (...p: string[]) => path.join(...p);
