import type { RepoFinding, Introduction } from "../sources/git.js";
import type { ForcePush } from "../github/forcepush.js";
import type { HostResult } from "../host/types.js";
import type { HistoryHit } from "../sources/history.js";

export interface FindingView extends RepoFinding {
  introduced?: Introduction;
  /** the force-push that created the introducing commit, if there is one: then the commit's
   * author is only the preserved original author, not the person who added the payload */
  createdByForcePush?: { actor: string; timestamp: string; ref: string };
}

export function attributeIntroductions(findings: FindingView[], pushes: ForcePush[]): void {
  for (const f of findings) {
    const c = f.introduced?.commit;
    if (!c) continue;
    const fp = pushes.find((p) => p.after === c);
    if (fp) f.createdByForcePush = { actor: fp.actor, timestamp: fp.timestamp, ref: fp.ref };
  }
}

export interface RepoReport {
  repo: string;
  status: "infected" | "suspicious" | "clean" | "unknown";
  findings: FindingView[];
  forcePushes: ForcePush[];
  notes: string[];
  /** the malware's strings found in old commits (the current files may be clean) */
  history?: HistoryHit[];
  visibility?: "public" | "private";
  /** whether the signed-in account can write here (decides if cleaning is possible) */
  canPush?: boolean;
}

export interface ActorSummary {
  actor: string;
  forcePushes: number;
  amended: number;
  repos: string[];
  infectedRepos: string[];
}

export interface Report {
  generatedAt: string;
  accounts: string[];
  repos: RepoReport[];
  actors: ActorSummary[];
  host?: HostResult;
}

export const CAVEAT =
  "A force-push shows which account's credentials were used, not who was at the keyboard or whether " +
  "that person's computer is infected. 'Consistent with' means the pattern matches this malware; " +
  "confirm on the machine itself.";

/** Informational (low) findings are listed but never make a repo suspicious on their own. */
export function statusOf(findings: { severity: string }[]): RepoReport["status"] {
  if (findings.some((f) => f.severity === "high")) return "infected";
  return findings.some((f) => f.severity === "medium") ? "suspicious" : "clean";
}

export function summarizeActors(repos: RepoReport[], ignore: string[] = []): ActorSummary[] {
  const by = new Map<string, ActorSummary>();
  for (const r of repos) {
    for (const fp of r.forcePushes) {
      if (ignore.includes(fp.actor) || fp.actor.endsWith("[bot]")) continue;
      const a = by.get(fp.actor) ?? { actor: fp.actor, forcePushes: 0, amended: 0, repos: [], infectedRepos: [] };
      a.forcePushes++;
      if (fp.amend?.likelyAmend) a.amended++;
      if (!a.repos.includes(r.repo)) a.repos.push(r.repo);
      if (r.status === "infected" && !a.infectedRepos.includes(r.repo)) a.infectedRepos.push(r.repo);
      by.set(fp.actor, a);
    }
  }
  return [...by.values()].sort((x, y) => y.amended - x.amended || y.forcePushes - x.forcePushes);
}
