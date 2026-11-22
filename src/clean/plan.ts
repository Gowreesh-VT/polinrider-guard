import { entryAt, readBlobs, revParse, scanRepoBranches } from "../sources/git.js";
import { posix } from "node:path";
import { fixFile } from "./fixers.js";
import { scanFile } from "../core/scan.js";

export interface Change {
  path: string;
  kind: "edit" | "delete";
  rules: string[];
  before: number;
  after: number;
  mode: string;
  text?: string;
}
export interface Manual { path: string; rule: string; why: string }
export interface BranchPlan { repo: string; branch: string; tip: string; changes: Change[]; manual: Manual[] }

// delete wins; otherwise edits are applied in this order
const ORDER = ["init-file", "fake-binary", "dropper-file", "vscode-autorun", "padded-payload", "package-hook", "package-scripts", "gitignore-config-bat", "env-loader", "decode-exec", "known-bad-package", "known-signature", "media-trailing-code"];

const rank = (r: string) => (ORDER.includes(r) ? ORDER.indexOf(r) : 99);

/** Work out, per branch, exactly what the cleaner would change. Reads only the local mirror. */
export async function planRepo(repo: string, mirror: string): Promise<BranchPlan[]> {
  const findings = await scanRepoBranches(mirror);
  const byBranch = new Map<string, Map<string, { rules: Set<string>; blob: string }>>();
  for (const f of findings) {
    for (const raw of f.branches) {
      const branch = raw.replace(/^origin\//, "");
      const files = byBranch.get(branch) ?? new Map();
      const e = files.get(f.path) ?? { rules: new Set<string>(), blob: f.blob };
      e.rules.add(f.rule);
      files.set(f.path, e);
      byBranch.set(branch, files);
    }
  }
  const blobs = await readBlobs(mirror, [...new Set(findings.map((f) => f.blob))]);
  const plans: BranchPlan[] = [];

  for (const [branch, files] of byBranch) {
    const tip = await revParse(mirror, `refs/heads/${branch}`);
    if (!tip) continue; // a remote-tracking duplicate, or a branch that no longer exists
    const plan: BranchPlan = { repo, branch, tip, changes: [], manual: [] };
    const deletes = new Map<string, Change>();
    const edits: Change[] = [];

    for (const [p, { rules, blob }] of files) {
      const original = (blobs.get(blob) ?? Buffer.alloc(0)).toString("utf8");
      let text = original, deleted = false, edited = false;
      const used: string[] = [];
      for (const rule of [...rules].sort((a, b) => rank(a) - rank(b))) {
        // an earlier fix on this file may already have removed this pattern
        if (edited && !scanFile({ path: p, content: Buffer.from(text) }).some((x) => x.rule === rule)) continue;
        const fix = fixFile(rule, p, text);
        if (fix.kind === "manual") { plan.manual.push({ path: p, rule, why: fix.why }); continue; }
        used.push(rule);
        if (fix.kind === "delete") {
          deleted = true;
          for (const t of fix.also ?? []) {
            if (deletes.has(t) || files.has(t)) continue;
            // a hostile tasks.json could name any file; only delete what is itself a fake font, and stay inside the repo
            const norm = posix.normalize(t);
            if (norm.startsWith("..") || norm.startsWith("/")) { plan.manual.push({ path: t, rule: "vscode-autorun", why: "task target is outside the repository; left alone" }); continue; }
            const ent = await entryAt(mirror, `refs/heads/${branch}`, norm);
            if (!ent) continue;
            const content = (await readBlobs(mirror, [ent.sha])).get(ent.sha) ?? Buffer.alloc(0);
            if (!scanFile({ path: norm, content }).some((x) => x.rule === "fake-binary")) {
              plan.manual.push({ path: norm, rule: "vscode-autorun", why: "named by a folder-open task but is a real file, not a fake font; left alone" });
              continue;
            }
            deletes.set(norm, { path: norm, kind: "delete", rules: [`task target of ${p}`], before: 0, after: 0, mode: ent.mode });
          }
          break;
        }
        text = fix.text; edited = true;
      }
      const ent = await entryAt(mirror, `refs/heads/${branch}`, p);
      const mode = ent?.mode ?? "100644";
      if (deleted) deletes.set(p, { path: p, kind: "delete", rules: used, before: original.length, after: 0, mode });
      else if (edited && text !== original) edits.push({ path: p, kind: "edit", rules: used, before: original.length, after: text.length, mode, text });
    }
    plan.changes = [...deletes.values(), ...edits].sort((a, b) => a.path.localeCompare(b.path));
    if (plan.changes.length || plan.manual.length) plans.push(plan);
  }
  return plans;
}
