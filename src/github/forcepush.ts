import { GitHub, GitHubError } from "./client.js";

export interface ForcePush {
  ref: string;
  actor: string;
  timestamp: string;
  before: string;
  after: string;
  amend?: AmendEvidence;
}

export interface AmendEvidence {
  /** same author, same author date and same subject, but a different commit */
  likelyAmend: boolean;
  author: string;
  subject: string;
  bodyLost: boolean;
  committerBefore?: string;
  committerAfter?: string;
}

interface ActivityItem {
  ref: string; before: string; after: string; timestamp: string;
  actor: { login: string } | null;
}

interface CommitInfo {
  commit: {
    author: { name: string; date: string };
    committer: { name: string; date: string };
    message: string;
  };
}

export async function fetchForcePushes(gh: GitHub, repo: string, days = 90): Promise<ForcePush[]> {
  const items = await gh.paginate<ActivityItem>(
    `/repos/${repo}/activity?activity_type=force_push&time_period=${days > 30 ? "quarter" : days > 7 ? "month" : "week"}&per_page=100`,
  );
  return items.map((i) => ({
    ref: i.ref.replace(/^refs\/heads\//, ""),
    actor: i.actor?.login ?? "unknown",
    timestamp: i.timestamp,
    before: i.before,
    after: i.after,
  }));
}

const subjectOf = (m: string) => m.split("\n")[0] ?? "";

export function compareCommits(before: CommitInfo, after: CommitInfo): AmendEvidence {
  const b = before.commit, a = after.commit;
  const sameAuthor = a.author.name === b.author.name && a.author.date === b.author.date;
  const sameSubject = subjectOf(a.message) === subjectOf(b.message);
  return {
    likelyAmend: sameAuthor && sameSubject,
    author: b.author.name,
    subject: subjectOf(b.message),
    bodyLost: b.message.trim().length > a.message.trim().length,
    committerBefore: `${b.committer.name} ${b.committer.date}`,
    committerAfter: `${a.committer.name} ${a.committer.date}`,
  };
}

/** Look at the commits on both sides of a force-push. Old commits may be gone; then undefined. */
export async function explainForcePush(gh: GitHub, repo: string, fp: ForcePush): Promise<AmendEvidence | undefined> {
  try {
    const [b, a] = await Promise.all([
      gh.get<CommitInfo>(`/repos/${repo}/commits/${fp.before}`),
      gh.get<CommitInfo>(`/repos/${repo}/commits/${fp.after}`),
    ]);
    return compareCommits(b.data, a.data);
  } catch (e) {
    if (e instanceof GitHubError && (e.status === 404 || e.status === 422)) return undefined;
    throw e;
  }
}
