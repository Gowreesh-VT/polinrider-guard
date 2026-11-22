import { GitHubError } from "../github/client.js";
import type { TreeEntry, WriteApi } from "../github/write.js";
import type { BranchPlan } from "./plan.js";
import { record } from "./undo.js";

export interface ApplyResult {
  branch: string;
  status: "committed" | "pull-request" | "skipped" | "failed";
  commit?: string;
  url?: string;
  note?: string;
  verified?: boolean;
}

export function commitMessage(plan: BranchPlan): string {
  const rules = [...new Set(plan.changes.flatMap((c) => c.rules))].filter((r) => !r.startsWith("task target"));
  const files = plan.changes.map((c) => `- ${c.kind === "delete" ? "remove" : "clean"} ${c.path}`).join("\n");
  return `security: remove PolinRider malware (${rules.join(", ") || "task targets"})\n\n${files}\n\nApplied by gitward.`;
}

const safeBranch = (b: string) => b.replace(/[^A-Za-z0-9._/-]/g, "-");
const isProtected = (e: unknown) =>
  e instanceof GitHubError && [403, 409, 422].includes(e.status) && /protect|pull request|required|review|status check/i.test(e.message);

/**
 * One commit per branch, fast-forward only (never a force-push). If the branch is protected, the same
 * commit goes to a new branch and a pull request is opened instead. Changes are read back afterwards.
 */
export async function applyBranchPlan(api: WriteApi, plan: BranchPlan, opts: { pr: boolean }): Promise<ApplyResult> {
  const { repo, branch } = plan;
  if (!plan.changes.length) return { branch, status: "skipped", note: "nothing to change automatically" };
  try {
    const tip = await api.getBranchSha(repo, branch);
    if (!tip) return { branch, status: "skipped", note: "branch no longer exists" };
    if (tip !== plan.tip) return { branch, status: "skipped", note: "branch changed since the scan; run again" };

    const entries: TreeEntry[] = plan.changes.map((c) =>
      c.kind === "delete"
        ? { path: c.path, mode: c.mode, type: "blob", sha: null }
        : { path: c.path, mode: c.mode, type: "blob", content: c.text! });
    const tree = await api.createTree(repo, await api.getCommitTree(repo, tip), entries);
    const commit = await api.createCommit(repo, commitMessage(plan), tree, tip);

    let ref = branch, status: ApplyResult["status"] = "committed", url: string | undefined;
    try {
      await api.updateBranch(repo, branch, commit);
    } catch (e) {
      if (!opts.pr || !isProtected(e)) throw e;
      ref = `gitward/clean-${safeBranch(branch)}-${commit.slice(0, 7)}`;
      await api.createBranch(repo, ref, commit);
      url = await api.createPull(repo, ref, branch, "security: remove PolinRider malware",
        `Removes the malware files and hooks found on \`${branch}\`.\n\n${plan.changes.map((c) => `- ${c.kind} \`${c.path}\``).join("\n")}\n\nOpened by gitward because \`${branch}\` is protected.`);
      status = "pull-request";
    }

    if (status === "committed") { try { record({ repo, branch, commit, parent: tip, time: new Date().toISOString() }); } catch { /* journal is best effort */ } }
    let verified = true;
    for (const c of plan.changes) {
      const now = await api.getFileText(repo, c.path, ref);
      if (c.kind === "delete" ? now !== undefined : now !== c.text) verified = false;
    }
    return { branch, status, commit, url, verified, note: verified ? undefined : "read-back did not match; check this branch" };
  } catch (e) {
    return { branch, status: "failed", note: (e as Error).message };
  }
}
