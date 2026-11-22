import { GitHub, GitHubError } from "./client.js";

export interface TreeEntry { path: string; mode: string; type: "blob"; content?: string; sha?: string | null }

/** The few write operations the cleaner needs. An interface so tests can fake it. */
export interface WriteApi {
  getBranchSha(repo: string, branch: string): Promise<string | undefined>;
  getCommitTree(repo: string, commit: string): Promise<string>;
  createTree(repo: string, baseTree: string, entries: TreeEntry[]): Promise<string>;
  createCommit(repo: string, message: string, tree: string, parent: string): Promise<string>;
  /** fast-forward only; throws GitHubError when protected or not a fast-forward */
  updateBranch(repo: string, branch: string, commit: string): Promise<void>;
  createBranch(repo: string, branch: string, commit: string): Promise<void>;
  createPull(repo: string, head: string, base: string, title: string, body: string): Promise<string>;
  getFileText(repo: string, path: string, ref: string): Promise<string | undefined>;
}

const enc = (s: string) => s.split("/").map(encodeURIComponent).join("/");

export class GitHubWriteApi implements WriteApi {
  constructor(private gh: GitHub) {}

  async getBranchSha(repo: string, branch: string) {
    try {
      return (await this.gh.get<{ object: { sha: string } }>(`/repos/${repo}/git/ref/heads/${enc(branch)}`)).data.object.sha;
    } catch (e) {
      if (e instanceof GitHubError && e.status === 404) return undefined;
      throw e;
    }
  }
  async getCommitTree(repo: string, commit: string) {
    return (await this.gh.get<{ tree: { sha: string } }>(`/repos/${repo}/git/commits/${commit}`)).data.tree.sha;
  }
  async createTree(repo: string, baseTree: string, entries: TreeEntry[]) {
    return (await this.gh.send<{ sha: string }>("POST", `/repos/${repo}/git/trees`, { base_tree: baseTree, tree: entries })).sha;
  }
  async createCommit(repo: string, message: string, tree: string, parent: string) {
    return (await this.gh.send<{ sha: string }>("POST", `/repos/${repo}/git/commits`, { message, tree, parents: [parent] })).sha;
  }
  async updateBranch(repo: string, branch: string, commit: string) {
    await this.gh.send("PATCH", `/repos/${repo}/git/refs/heads/${enc(branch)}`, { sha: commit, force: false });
  }
  async createBranch(repo: string, branch: string, commit: string) {
    await this.gh.send("POST", `/repos/${repo}/git/refs`, { ref: `refs/heads/${branch}`, sha: commit });
  }
  async createPull(repo: string, head: string, base: string, title: string, body: string) {
    return (await this.gh.send<{ html_url: string }>("POST", `/repos/${repo}/pulls`, { title, head, base, body })).html_url;
  }
  async getFileText(repo: string, path: string, ref: string) {
    try {
      const r = await this.gh.get<{ content?: string; encoding?: string }>(`/repos/${repo}/contents/${enc(path)}?ref=${encodeURIComponent(ref)}`);
      return r.data.content ? Buffer.from(r.data.content, "base64").toString("utf8") : "";
    } catch (e) {
      if (e instanceof GitHubError && e.status === 404) return undefined;
      throw e;
    }
  }
}
