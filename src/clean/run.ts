import { GitHub } from "../github/client.js";
import { GitHubWriteApi } from "../github/write.js";
import { ensureMirror } from "../sync.js";
import { mapPool } from "../pool.js";
import type { Target } from "../targets.js";
import { planRepo, type BranchPlan } from "./plan.js";
import { applyBranchPlan, type ApplyResult } from "./apply.js";
import { safe } from "../safe.js";

export interface CleanRepoResult {
  repo: string;
  plans: BranchPlan[];
  results: ApplyResult[];
  note?: string;
}

export async function cleanRepos(targets: Target[], opts: { apply: boolean; pr: boolean; concurrency?: number; onProgress?: (done: number, total: number, repo: string) => void }): Promise<CleanRepoResult[]> {
  let done = 0;
  return mapPool(targets, opts.concurrency ?? 2, async (t) => {
    const out: CleanRepoResult = { repo: t.repo, plans: [], results: [] };
    try {
      const mirror = await ensureMirror(t.repo, t.token);
      out.plans = await planRepo(t.repo, mirror);
      // only worth mentioning when there is something to fix
      if (out.plans.length) {
        if (t.info?.archived) out.note = "archived: unarchive it first, then run again";
        else if (t.info && !t.info.canPush) out.note = "no write access: report only, ask the owner to run this";
      }
      if (opts.apply && out.plans.length && !out.note && t.token) {
        const api = new GitHubWriteApi(new GitHub(t.token));
        for (const p of out.plans) out.results.push(await applyBranchPlan(api, p, { pr: opts.pr }));
      } else if (opts.apply && out.plans.length && !out.note && !t.token) {
        out.note = "no signed-in account for this repo; cannot write";
      }
    } catch (e) {
      out.note = `error: ${(e as Error).message}`;
    }
    opts.onProgress?.(++done, targets.length, t.repo);
    return out;
  });
}

export function formatClean(results: CleanRepoResult[], applied: boolean): string {
  const L: string[] = [];
  let branches = 0, files = 0, manual = 0;
  for (const r of results) {
    if (!r.plans.length && !r.note) continue;
    L.push(`${safe(r.repo)}${r.note ? `  (${safe(r.note)})` : ""}`);
    for (const p of r.plans) {
      branches++; files += p.changes.length; manual += p.manual.length;
      L.push(`  ${safe(p.branch)}`);
      for (const c of p.changes) L.push(`    ${c.kind === "delete" ? "delete" : "clean "} ${safe(c.path)}${c.kind === "edit" ? ` (${c.before} -> ${c.after} bytes)` : ""}  [${c.rules.join(", ")}]`);
      for (const m of p.manual) L.push(`    MANUAL ${safe(m.path)}: ${safe(m.why)}`);
      const res = r.results.find((x) => x.branch === p.branch);
      if (res) L.push(`    => ${res.status}${res.commit ? ` ${res.commit.slice(0, 8)}` : ""}${res.url ? ` ${safe(res.url)}` : ""}${res.verified === false ? " (NOT verified)" : res.verified ? " (verified)" : ""}${res.note ? ` - ${safe(res.note)}` : ""}`);
    }
  }
  L.push("", `${files} file change(s) on ${branches} branch(es) in ${results.filter((r) => r.plans.length).length} repo(s); ${manual} item(s) need a human.`);
  if (!applied) L.push("Dry run: nothing was changed. Run again with --apply to commit these fixes.");
  return L.join("\n");
}
