import { GitHub } from "./github/client.js";
import { listMyRepos, listPublicRepos, type RepoInfo } from "./github/repos.js";
import { ghAccounts } from "./accounts.js";
import { tokenFor } from "./auth.js";
import { parseLogin, parseRepo } from "./validate.js";

export interface Target {
  repo: string;
  token?: string;
  account?: string;
  info?: RepoInfo;
}

export interface TargetOptions {
  accounts: string[];
  allAccounts: boolean;
  users: string[];
  repos: string[];
  exclude: string[];
  skipForks: boolean;
}

export const isExcluded = (repo: string, exclude: string[]) =>
  exclude.some((e) => repo.toLowerCase().startsWith(e.toLowerCase()));

export interface Resolved { targets: Target[]; accounts: string[]; warnings: string[] }

export async function resolveTargets(raw: TargetOptions): Promise<Resolved> {
  const o: TargetOptions = { ...raw, accounts: raw.accounts.map(parseLogin), users: raw.users.map(parseLogin), repos: raw.repos.map(parseRepo) };
  const accounts = o.allAccounts ? await ghAccounts() : [...o.accounts];
  const targets = new Map<string, Target>();
  const warnings: string[] = [];
  const add = (t: Target) => {
    const key = t.repo.toLowerCase();
    const have = targets.get(key);
    // prefer a login that can push, so cleaning and force-push history work
    if (!have || (!have.info?.canPush && t.info?.canPush)) targets.set(key, t);
  };

  // explicit --repo means exactly those repos; --account then only picks which login to use
  const listAccounts = !o.repos.length;
  for (const account of listAccounts ? accounts : []) {
    try {
      const token = await tokenFor(account);
      for (const info of await listMyRepos(new GitHub(token))) {
        if (o.skipForks && info.fork) continue;
        add({ repo: info.fullName, token, account, info });
      }
    } catch (e) {
      warnings.push(`Account ${account}: ${(e as Error).message}`);
    }
  }
  for (const user of o.users) {
    try {
      // a token, if one is set, only raises the API rate limit for listing; repos are still read as public
      for (const info of await listPublicRepos(new GitHub(await tokenFor()), user)) {
        if (o.skipForks && info.fork) continue;
        add({ repo: info.fullName, info });
      }
    } catch (e) {
      warnings.push(`User ${user}: ${(e as Error).message}`);
    }
  }
  const fallback = accounts.length ? await tokenFor(accounts[0]).catch(() => undefined) : await tokenFor();
  const tokens = new Map<string, string | undefined>();
  // for explicit repos, any signed-in account may be the one with access
  for (const a of o.repos.length ? (accounts.length ? accounts : await ghAccounts().catch(() => [])) : []) tokens.set(a, await tokenFor(a).catch(() => undefined));
  for (const repo of o.repos) {
    // ask each signed-in account whether it can see the repo; prefer one that can push
    let best: Target | undefined;
    for (const [account, token] of tokens) {
      try {
        const info = (await new GitHub(token).get<{ full_name: string; fork: boolean; private: boolean; archived: boolean; pushed_at: string | null; permissions?: { push?: boolean } }>(`/repos/${repo}`)).data;
        const cand: Target = { repo, token, account, info: { fullName: info.full_name, fork: info.fork, private: info.private, archived: info.archived, canPush: !!info.permissions?.push, pushedAt: info.pushed_at } };
        if (!best || (!best.info?.canPush && cand.info?.canPush)) best = cand;
      } catch { /* this account cannot see it */ }
    }
    add(best ?? { repo, token: fallback, account: accounts[0] });
  }

  return {
    targets: [...targets.values()].filter((t) => !isExcluded(t.repo, o.exclude)),
    accounts,
    warnings,
  };
}
