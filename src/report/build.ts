import { GitHub } from "../github/client.js";
import { explainForcePush, fetchForcePushes, type AmendEvidence } from "../github/forcepush.js";
import { ensureMirror, withShallowClone } from "../sync.js";
import { firstIntroduction, scanRepoBranches } from "../sources/git.js";
import { scanHistory } from "../sources/history.js";
import { mapPool } from "../pool.js";
import type { Target } from "../targets.js";
import { attributeIntroductions, statusOf, summarizeActors, type RepoReport, type Report } from "./model.js";

export interface BuildOptions {
  targets: Target[];
  accounts: string[];
  /** logins whose force-pushes are not suspicious (normally your own accounts) */
  ignoreActors: string[];
  forcePushDays?: number;
  /** look through old commits for the malware's strings (slower); default on */
  history?: boolean;
  /** newest commit of each branch only, no cache: fast, but no history scan or "first added" */
  quick?: boolean;
  concurrency?: number;
  onProgress?: (done: number, total: number, repo: string) => void;
}

const LOW_BUDGET = 150;

export async function buildRepoReport(t: Target, opts: BuildOptions, gh: GitHub, cache: Map<string, AmendEvidence | undefined>): Promise<RepoReport> {
  const notes: string[] = [];
  const quick = opts.quick === true;
  const scanned = async (dir: string) => {
    const findings = await scanRepoBranches(dir);
    const out = [];
    for (const f of findings) out.push({ ...f, introduced: quick ? undefined : await firstIntroduction(dir, f.blob) });
    return { out, history: quick || opts.history === false ? undefined : await scanHistory(dir) };
  };
  const { out: views, history } = quick
    ? await withShallowClone(t.repo, t.token, scanned)
    : await scanned(await ensureMirror(t.repo, t.token));
  if (quick) notes.push("Quick scan: only the newest commit of each branch was checked, so old history and \"first added\" are not covered.");

  let forcePushes: RepoReport["forcePushes"] = [];
  if (!t.token) {
    notes.push("Force-push history needs a signed-in account; skipped for public-only scans.");
  } else {
    try {
      forcePushes = await fetchForcePushes(gh, t.repo, opts.forcePushDays ?? 90);
      for (const fp of forcePushes) {
        if (opts.ignoreActors.includes(fp.actor) || fp.actor.endsWith("[bot]")) continue;
        if (gh.remaining !== undefined && gh.remaining < LOW_BUDGET) {
          notes.push(`GitHub API budget nearly used up (${gh.remaining} left); some force-pushes were not inspected for amend patterns.`);
          break;
        }
        const key = `${t.repo}@${fp.before}@${fp.after}`;
        if (!cache.has(key)) cache.set(key, await explainForcePush(gh, t.repo, fp));
        fp.amend = cache.get(key);
      }
    } catch (e) {
      notes.push(`Force-push history unavailable: ${(e as Error).message}.`);
    }
  }
  attributeIntroductions(views, forcePushes);
  return {
    repo: t.repo, status: statusOf(views), findings: views, forcePushes, notes, history,
    visibility: t.info ? (t.info.private ? "private" : "public") : undefined,
    canPush: t.info?.canPush,
  };
}

export async function buildReport(opts: BuildOptions): Promise<Report> {
  const clients = new Map<string, GitHub>();
  const clientFor = (token?: string) => {
    const k = token ?? "";
    if (!clients.has(k)) clients.set(k, new GitHub(token));
    return clients.get(k)!;
  };
  const cache = new Map<string, AmendEvidence | undefined>();
  let done = 0;
  const repos = await mapPool(opts.targets, opts.concurrency ?? 4, async (t) => {
    let r: RepoReport;
    try {
      r = await buildRepoReport(t, opts, clientFor(t.token), cache);
    } catch (e) {
      r = { repo: t.repo, status: "unknown", findings: [], forcePushes: [], notes: [`Could not scan: ${(e as Error).message}`] };
    }
    opts.onProgress?.(++done, opts.targets.length, t.repo);
    return r;
  });
  return {
    generatedAt: new Date().toISOString(),
    accounts: opts.accounts,
    repos,
    actors: summarizeActors(repos, opts.ignoreActors),
  };
}
