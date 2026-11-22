import fs from "node:fs";
import path from "node:path";
import { cacheDir } from "../sync.js";
import type { WriteApi } from "../github/write.js";
import { safe } from "../safe.js";

/** Every commit the cleaner makes is recorded here so it can be reverted later. */
export interface JournalEntry { repo: string; branch: string; commit: string; parent: string; time: string; undone?: boolean }

export const journalPath = () => process.env.POLINRIDER_GUARD_JOURNAL ?? path.join(path.dirname(cacheDir()), "journal.jsonl");

export function readJournal(file = journalPath()): JournalEntry[] {
  try {
    return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).flatMap((l) => { try { return [JSON.parse(l) as JournalEntry]; } catch { return []; } });
  } catch { return []; }
}

export function record(e: JournalEntry, file = journalPath()): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.appendFileSync(file, JSON.stringify(e) + "\n", { mode: 0o600 });
}

function markUndone(commit: string, file: string): void {
  const all = readJournal(file).map((e) => (e.commit === commit ? { ...e, undone: true } : e));
  fs.writeFileSync(file, all.map((e) => JSON.stringify(e)).join("\n") + "\n", { mode: 0o600 });
}

export interface UndoResult { repo: string; branch: string; commit: string; status: "reverted" | "skipped" | "failed"; note?: string }

/**
 * Put the branch back to the tree it had before the cleaner's commit, as a NEW commit on top (never a force-push).
 * Only safe while the cleaner's commit is still the branch tip; otherwise later work would be lost, so it is skipped.
 */
export async function undoEntries(api: WriteApi, entries: JournalEntry[], opts: { apply: boolean; file?: string }): Promise<UndoResult[]> {
  const out: UndoResult[] = [];
  for (const e of entries.filter((x) => !x.undone)) {
    const base = { repo: e.repo, branch: e.branch, commit: e.commit };
    try {
      const tip = await api.getBranchSha(e.repo, e.branch);
      if (!tip) { out.push({ ...base, status: "skipped", note: "branch no longer exists" }); continue; }
      if (tip !== e.commit) { out.push({ ...base, status: "skipped", note: "branch has newer commits; revert by hand (git revert " + e.commit.slice(0, 8) + ")" }); continue; }
      if (!opts.apply) { out.push({ ...base, status: "skipped", note: "dry run" }); continue; }
      const tree = await api.getCommitTree(e.repo, e.parent);
      const rev = await api.createCommit(e.repo, `Revert polinrider-guard cleanup ${e.commit.slice(0, 8)}\n\nRestores the files exactly as they were before the cleanup commit.`, tree, tip);
      await api.updateBranch(e.repo, e.branch, rev);
      markUndone(e.commit, opts.file ?? journalPath());
      out.push({ ...base, status: "reverted", note: `new commit ${rev.slice(0, 8)}` });
    } catch (err) {
      out.push({ ...base, status: "failed", note: (err as Error).message });
    }
  }
  return out;
}

export function formatUndo(rs: UndoResult[], apply: boolean): string {
  if (!rs.length) return "Nothing to undo: no cleanup commits recorded on this machine.";
  const L = rs.map((r) => `${safe(r.repo)} ${safe(r.branch)} ${r.commit.slice(0, 8)}: ${r.status}${r.note ? ` (${safe(r.note)})` : ""}`);
  if (!apply) L.push("", "Dry run: nothing was changed. Run again with --apply to revert.");
  return L.join("\n");
}
