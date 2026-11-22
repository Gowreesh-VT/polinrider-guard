import { GitHub } from "./client.js";

export interface RepoInfo {
  fullName: string;
  private: boolean;
  archived: boolean;
  fork: boolean;
  canPush: boolean;
  pushedAt: string | null;
}

interface ApiRepo {
  full_name: string; private: boolean; archived: boolean; fork: boolean;
  permissions?: { push?: boolean; admin?: boolean }; pushed_at: string | null;
}

const toInfo = (r: ApiRepo): RepoInfo => ({
  fullName: r.full_name, private: r.private, archived: r.archived, fork: r.fork,
  canPush: Boolean(r.permissions?.push || r.permissions?.admin), pushedAt: r.pushed_at,
});

/** Every repo the signed-in account can see: owned, collaborator, and via organizations. */
export async function listMyRepos(gh: GitHub): Promise<RepoInfo[]> {
  const rows = await gh.paginate<ApiRepo>(
    "/user/repos?affiliation=owner,collaborator,organization_member&per_page=100&sort=pushed", 100);
  return rows.map(toInfo);
}

/** Public repos of any username or organization. Works without signing in. */
export async function listPublicRepos(gh: GitHub, name: string): Promise<RepoInfo[]> {
  const kind = await gh.get<{ type: string }>(`/users/${encodeURIComponent(name)}`);
  const base = kind.data.type === "Organization" ? "orgs" : "users";
  const rows = await gh.paginate<ApiRepo>(`/${base}/${encodeURIComponent(name)}/repos?type=public&per_page=100`, 100);
  return rows.map(toInfo);
}
