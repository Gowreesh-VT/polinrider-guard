import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Introduction } from "./git.js";

const run = promisify(execFile);

/** Strings that only the malware (or its cleanup) put into a repository. Written in pieces so this repo scans clean. */
export const HISTORY_PATTERNS: { label: string; needle: string }[] = [
  { label: "padded payload marker", needle: "rmcej" + "%otb%" },
  { label: "payload marker", needle: "Cot%3t" + "=shtP" },
  { label: "payload marker", needle: "global['" + "!']" },
  { label: "payload marker", needle: "global['" + "_V']" },
  { label: "payload marker", needle: "_$_1e" + "42" },
  { label: "env-variable loader", needle: "ev" + "al(proxyInfo)" },
  { label: "loader key", needle: "AUTH_API_KEY" },
  { label: "dropper script", needle: "temp_auto_" + "push" },
  { label: "init hook in package.json", needle: "node init &&" },
  { label: "folder-open autorun task", needle: "folderOpen" },
  { label: "automatic tasks enabled", needle: "allowAutomaticTasks" },
];

export interface HistoryHit {
  label: string;
  needle: string;
  commits: number;
  first: Introduction;
  last: Introduction;
}

const parse = (line: string): Introduction | undefined => {
  const [commit, author, date, ...subject] = line.split("\t");
  return commit && author && date ? { commit, author, date, subject: subject.join("\t") } : undefined;
};

/**
 * Commits anywhere in history that added or removed one of the malware's strings. A hit here with a clean
 * tip means the repo was infected earlier. Removing it needs a history rewrite, which this tool never does.
 */
export async function scanHistory(repo: string): Promise<HistoryHit[]> {
  const hits: HistoryHit[] = [];
  for (const p of HISTORY_PATTERNS) {
    let out = "";
    try {
      out = (await run("git", ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo, "log", "--all", "-S", p.needle, "--format=%H%x09%an%x09%aI%x09%s"], { maxBuffer: 64 * 1024 * 1024, timeout: 300_000 })).stdout;
    } catch { continue; }
    const lines = out.split("\n").filter(Boolean);
    if (!lines.length) continue;
    const newest = parse(lines[0]!), oldest = parse(lines[lines.length - 1]!);
    if (newest && oldest) hits.push({ label: p.label, needle: p.needle, commits: lines.length, first: oldest, last: newest });
  }
  return hits;
}
