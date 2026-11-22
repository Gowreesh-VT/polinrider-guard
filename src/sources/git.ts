import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding, ScanFile } from "../core/types.js";
import { scanFile, VENDOR_RULES } from "../core/scan.js";

const run = promisify(execFile);
/** Repositories we read may be hostile: never run commands named in their config. */
const SAFE_GIT = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat", "-c", "protocol.ext.allow=never"];
const MAX_TEXT = 1_500_000;
const MAX_MEDIA = 5_000_000;
const BATCH_BYTES = 100_000_000;
const VENDORED = /(^|\/)(node_modules|vendor|third_party|site-packages|\.venv)\//;
// media and fonts are checked for code hidden inside; large video/audio/archives are not worth reading
const MEDIA = /\.(png|jpe?g|gif|webp|ico|bmp|woff2?|ttf|otf|eot|orc)$/i;
const SKIP_EXT = /\.(mp4|mov|mp3|wav|webm|ogg|flac|m4a|mkv|avi|pdf|zip|gz|tgz|7z|tar|jar|lock|map|svg|svgz|psd|ai|pyc|class|exe|dll|so|dylib|wasm|onnx|pb|bin|dat|node|glb|gltf|obj|fbx)$/i;
const VENDOR_TEXT = /\.(c?js|mjs|json|sh|bat|ts)$/i;

async function git(repo: string, args: string[]): Promise<string> {
  const { stdout } = await run("git", [...SAFE_GIT, "-C", repo, ...args], { maxBuffer: 512 * 1024 * 1024 });
  return stdout;
}

export async function listBranches(repo: string): Promise<string[]> {
  const out = await git(repo, ["for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes"]);
  return out.split("\n").filter((r) => r && !r.endsWith("/HEAD"));
}

export interface TreeEntry { path: string; sha: string; size: number }

export async function listTree(repo: string, ref: string): Promise<TreeEntry[]> {
  const out = await git(repo, ["ls-tree", "-r", "-l", "-z", ref]);
  const entries: TreeEntry[] = [];
  for (const rec of out.split("\0")) {
    const m = /^\d+ blob ([0-9a-f]+)\s+(\d+)\t(.*)$/s.exec(rec);
    if (!m) continue;
    const [, sha, size, path] = m;
    if (!sha || !size || !path) continue;
    const n = Number(size);
    if (VENDORED.test(path)) { if (!VENDOR_TEXT.test(path) || n > MAX_TEXT) continue; }
    else if (MEDIA.test(path)) { if (n > MAX_MEDIA) continue; }
    else if (SKIP_EXT.test(path) || n > MAX_TEXT) continue;
    entries.push({ path, sha, size: Number(size) });
  }
  return entries;
}

/** Read many blobs with one `git cat-file --batch` process. */
export function readBlobs(repo: string, shas: string[]): Promise<Map<string, Buffer>> {
  return new Promise((resolve, reject) => {
    const p = spawn("git", [...SAFE_GIT, "-C", repo, "cat-file", "--batch"]);
    const chunks: Buffer[] = [];
    p.stdout.on("data", (c: Buffer) => chunks.push(c));
    p.on("error", reject);
    p.on("close", () => {
      const buf = Buffer.concat(chunks);
      const out = new Map<string, Buffer>();
      let i = 0;
      while (i < buf.length) {
        const nl = buf.indexOf(10, i);
        if (nl < 0) break;
        const [sha, type, size] = buf.toString("utf8", i, nl).split(" ");
        if (!sha || type === "missing" || !size) { i = nl + 1; continue; }
        const n = Number(size);
        out.set(sha, buf.subarray(nl + 1, nl + 1 + n));
        i = nl + 1 + n + 1;
      }
      resolve(out);
    });
    p.stdin.end(shas.join("\n") + "\n");
  });
}

export interface RepoFinding extends Finding {
  blob: string;
  /** branches whose tip contains this exact blob at this path */
  branches: string[];
}

/**
 * Scan every branch tip. Each unique (path, blob) is scanned once, so a payload
 * present on 50 branches costs one scan, and is reported once with all branches.
 */
export async function scanRepoBranches(repo: string): Promise<RepoFinding[]> {
  const refs = await listBranches(repo);
  const seen = new Map<string, { entry: TreeEntry; branches: string[] }>();
  for (const ref of refs) {
    for (const e of await listTree(repo, ref)) {
      const key = `${e.sha}\0${e.path}`;
      const s = seen.get(key);
      if (s) s.branches.push(short(ref)); else seen.set(key, { entry: e, branches: [short(ref)] });
    }
  }
  const results: RepoFinding[] = [];
  const all = [...seen.values()];
  // one entry per blob, with its size, grouped into batches by total bytes
  const sizes = new Map<string, number>();
  for (const a of all) sizes.set(a.entry.sha, a.entry.size);
  const shas = [...sizes.keys()];
  const batches: string[][] = [];
  let cur: string[] = [], bytes = 0;
  for (const sha of shas) {
    const sz = sizes.get(sha) ?? 0;
    if (cur.length && bytes + sz > BATCH_BYTES) { batches.push(cur); cur = []; bytes = 0; }
    cur.push(sha); bytes += sz;
  }
  if (cur.length) batches.push(cur);
  for (const batch of batches) {
    const blobs = await readBlobs(repo, batch);
    const inBatch = new Set(batch);
    for (const a of all) {
      if (!inBatch.has(a.entry.sha)) continue;
      const content = blobs.get(a.entry.sha);
      if (!content) continue;
      const file: ScanFile = { path: a.entry.path, content };
      const found = scanFile(file, VENDORED.test(a.entry.path) ? VENDOR_RULES : undefined);
      for (const f of found) results.push({ ...f, blob: a.entry.sha, branches: a.branches });
    }
  }
  return results;
}

const short = (ref: string) => ref.replace(/^refs\/(heads|remotes)\//, "");

export interface Introduction { commit: string; author: string; date: string; subject: string }

/**
 * Oldest commit where this exact blob appears on the NEW side of a change, i.e. the
 * commit that put it into the tree. A later commit that removes it is not an introduction.
 */
export async function firstIntroduction(repo: string, blob: string): Promise<Introduction | undefined> {
  const out = await git(repo, [
    "log", "--all", `--find-object=${blob}`, "--raw", "--no-abbrev", "--no-renames", "--reverse",
    "--format=%x01%H%x09%an%x09%aI%x09%s",
  ]);
  for (const block of out.split("\u0001").filter(Boolean)) {
    const [head, ...raw] = block.split("\n");
    const added = raw.some((l) => new RegExp(`^:\\d+ \\d+ [0-9a-f]+ ${blob} `).test(l));
    if (!added || !head) continue;
    const [commit, author, date, ...subject] = head.split("\t");
    if (commit && author && date) return { commit, author, date, subject: subject.join("\t") };
  }
  return undefined;
}

export async function revParse(repo: string, ref: string): Promise<string | undefined> {
  try { return (await git(repo, ["rev-parse", "--verify", "-q", ref])).trim() || undefined; } catch { return undefined; }
}

/** Mode and blob of a path at a ref, e.g. "100755". Undefined when the path does not exist there. */
export async function entryAt(repo: string, ref: string, path: string): Promise<{ mode: string; sha: string } | undefined> {
  try {
    const out = await git(repo, ["ls-tree", ref, "--", path]);
    const m = /^(\d+) blob ([0-9a-f]+)\t/.exec(out);
    return m ? { mode: m[1]!, sha: m[2]! } : undefined;
  } catch { return undefined; }
}
