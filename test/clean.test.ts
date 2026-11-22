import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { cleanPadded, fixFile, removeAutoTasks, removeEnvLoader, taskTargets } from "../src/clean/fixers.js";
import { planRepo, type BranchPlan } from "../src/clean/plan.js";
import { applyBranchPlan } from "../src/clean/apply.js";
import { GitHubError } from "../src/github/client.js";
import type { WriteApi } from "../src/github/write.js";

const A = "at" + "ob", E = "ev" + "al", P = "process.env.";
const padded = (code: string) => "export default {};" + " ".repeat(300) + code;

describe("fixers", () => {
  it("cuts hidden code after padding and keeps the real config", () => {
    const out = cleanPadded("import x from 'y';\n" + padded("(function(){var a=1;})();") + "\nexport const k = 1;\n");
    expect(out).toBe("import x from 'y';\nexport default {};\nexport const k = 1;\n");
  });
  it("keeps deeply indented code (not padding)", () => {
    const src = "const a = (\n" + " ".repeat(120) + "<b/>\n);\n";
    expect(cleanPadded(src)).toBe(src);
  });
  it("removes the createRequire header the payload relies on", () => {
    expect(cleanPadded("import { createRequire } from 'module';\nconst require = createRequire(import.meta.url);\nexport default {};\n")).toBe("export default {};\n");
  });
  it("removes the init hook but keeps the rest of package.json valid", () => {
    const f = fixFile("package-hook", "package.json", '{"scripts":{"dev":"node init && next dev","build":"node ./init && next build"}}');
    expect(f).toMatchObject({ kind: "edit" });
    expect(JSON.parse((f as { text: string }).text).scripts).toEqual({ dev: "next dev", build: "next build" });
  });
  it("removes only the config.bat line from .gitignore", () => {
    const f = fixFile("gitignore-config-bat", ".gitignore", "node_modules\nconfig.bat\n.env\n");
    expect(f).toEqual({ kind: "edit", text: "node_modules\n.env\n" });
  });
  it("deletes a tasks.json only when it runs a fake font; otherwise asks a human", () => {
    const bad = '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"node","args":["public/fonts/fa.woff2"]}]}';
    expect(fixFile("vscode-autorun", "app/.vscode/tasks.json", bad)).toEqual({ kind: "delete", also: ["app/public/fonts/fa.woff2"] });
    const legit = '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"node","args":["scripts/dev.js"]}]}';
    expect(fixFile("vscode-autorun", ".vscode/tasks.json", legit).kind).toBe("manual");
    expect(taskTargets(".vscode/tasks.json", bad)).toEqual(["public/fonts/fa.woff2"]);
  });
  it("strips automatic-task settings and keeps other settings", () => {
    const f = removeAutoTasks('{\n  "editor.tabSize": 2,\n  "task.allowAutomaticTasks": "on",\n  "files.eol": "\\n"\n}\n');
    expect(JSON.parse(f!)).toEqual({ "editor.tabSize": 2, "files.eol": "\n" });
  });
  it("removes an env-variable loader but not surrounding code", () => {
    const src = `import a from "a";\n(async () => {\n  const s = ${A}(${P}AUTH_API_KEY);\n  ${E}(s);\n})();\nexport const x = 1;\n`;
    const out = removeEnvLoader(src)!;
    expect(out).toContain('import a from "a";');
    expect(out).toContain("export const x = 1;");
    expect(out).not.toContain(P);
    expect(fixFile("env-loader", "a.ts", src).kind).toBe("edit");
  });
  it("sends unknown or risky cases to a human", () => {
    expect(fixFile("known-bad-package", "package.json", "{}").kind).toBe("manual");
    expect(fixFile("decode-exec", "a.js", "no loader here").kind).toBe("manual");
  });
});

let repo = "";
const g = (...a: string[]) => execFileSync("git", ["-C", repo, "-c", "user.name=Dev", "-c", "user.email=d@example.com", ...a], { encoding: "utf8" });

beforeAll(() => {
  repo = mkdtempSync(path.join(tmpdir(), "pgc-"));
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  writeFileSync(path.join(repo, "postcss.config.mjs"), "export default {};\n");
  writeFileSync(path.join(repo, "package.json"), '{"scripts":{"dev":"next dev"}}\n');
  g("add", "-A"); g("commit", "-q", "-m", "initial");
  g("checkout", "-q", "-b", "feature");
  mkdirSync(path.join(repo, ".vscode")); mkdirSync(path.join(repo, "public"));
  writeFileSync(path.join(repo, "postcss.config.mjs"), padded("(function(){var a=1;})();") + "\n");
  writeFileSync(path.join(repo, "package.json"), '{"scripts":{"dev":"node init && next dev"}}\n');
  writeFileSync(path.join(repo, "init"), "var a=1;".repeat(600) + "\n");
  writeFileSync(path.join(repo, ".vscode/tasks.json"), '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"node","args":["public/a.woff2"]}]}');
  writeFileSync(path.join(repo, "public/a.woff2"), "function a(){return 1}");
  g("add", "-A"); g("commit", "-q", "-m", "infect");
  g("checkout", "-q", "main");
});

describe("plan", () => {
  it("plans fixes only for the infected branch, including task targets", async () => {
    const plans = await planRepo("o/r", repo);
    expect(plans.map((p) => p.branch)).toEqual(["feature"]);
    const byPath = Object.fromEntries(plans[0]!.changes.map((c) => [c.path, c.kind]));
    expect(byPath).toEqual({
      ".vscode/tasks.json": "delete", "public/a.woff2": "delete", init: "delete",
      "package.json": "edit", "postcss.config.mjs": "edit",
    });
    const pkg = plans[0]!.changes.find((c) => c.path === "package.json")!;
    expect(JSON.parse(pkg.text!).scripts.dev).toBe("next dev");
  });
});

class FakeApi implements WriteApi {
  files = new Map<string, string>();
  calls: string[] = [];
  constructor(public tip: string, public opts: { protectedBranch?: boolean; failWith?: number; corrupt?: boolean } = {}) {}
  async getBranchSha() { return this.tip; }
  async getCommitTree() { return "tree0"; }
  async createTree(_r: string, _b: string, entries: { path: string; content?: string; sha?: string | null }[]) {
    for (const e of entries) { if (e.sha === null) this.files.set(e.path, "\0deleted"); else this.files.set(e.path, e.content!); }
    return "tree1";
  }
  async createCommit() { return "c0ffee1234567"; }
  async updateBranch() {
    this.calls.push("update");
    if (this.opts.protectedBranch) throw new GitHubError(409, "PATCH -> 409 Changes must be made through a pull request");
    if (this.opts.failWith) throw new GitHubError(this.opts.failWith, "PATCH -> boom");
  }
  async createBranch(_r: string, b: string) { this.calls.push("branch:" + b); }
  async createPull() { this.calls.push("pull"); return "https://github.com/o/r/pull/1"; }
  async getFileText(_r: string, p: string) {
    const v = this.files.get(p);
    if (v === "\0deleted" || v === undefined) return undefined;
    return this.opts.corrupt ? v + "x" : v;
  }
}

const plan = (): BranchPlan => ({
  repo: "o/r", branch: "feature", tip: "abc",
  changes: [
    { path: "init", kind: "delete", rules: ["init-file"], before: 10, after: 0, mode: "100644" },
    { path: "package.json", kind: "edit", rules: ["package-hook"], before: 50, after: 30, mode: "100644", text: '{"scripts":{"dev":"next dev"}}\n' },
  ], manual: [],
});

describe("apply", () => {
  it("commits with a fast-forward and verifies by reading back", async () => {
    const api = new FakeApi("abc");
    const r = await applyBranchPlan(api, plan(), { pr: true });
    expect(r).toMatchObject({ status: "committed", verified: true });
    expect(api.calls).toEqual(["update"]);
  });
  it("opens a pull request when the branch is protected", async () => {
    const api = new FakeApi("abc", { protectedBranch: true });
    const r = await applyBranchPlan(api, plan(), { pr: true });
    expect(r.status).toBe("pull-request");
    expect(r.url).toContain("/pull/1");
    expect(api.calls.some((c) => c.startsWith("branch:polinrider-guard/clean-feature-"))).toBe(true);
  });
  it("does not open a PR when --no-pr", async () => {
    const r = await applyBranchPlan(new FakeApi("abc", { protectedBranch: true }), plan(), { pr: false });
    expect(r.status).toBe("failed");
  });
  it("skips a branch that moved since the scan instead of overwriting it", async () => {
    const api = new FakeApi("different");
    const r = await applyBranchPlan(api, plan(), { pr: true });
    expect(r.status).toBe("skipped");
    expect(api.calls).toEqual([]);
  });
  it("reports failures and unverified read-backs", async () => {
    expect((await applyBranchPlan(new FakeApi("abc", { failWith: 500 }), plan(), { pr: true })).status).toBe("failed");
    expect((await applyBranchPlan(new FakeApi("abc", { corrupt: true }), plan(), { pr: true })).verified).toBe(false);
  });
});

describe("plan: overlapping rules on one file", () => {
  it("does not ask for a manual fix when the padding fix already removed the loader", async () => {
    const r = mkdtempSync(path.join(tmpdir(), "pgo-"));
    execFileSync("git", ["init", "-q", "-b", "main", r]);
    const loader = `(async()=>{let d=(t)=>${A}(t);${E}(d("aA=="));fetch("https://x.example")})();`;
    writeFileSync(path.join(r, "vite.config.ts"), padded(loader) + "\n");
    execFileSync("git", ["-C", r, "add", "-A"]);
    execFileSync("git", ["-C", r, "-c", "user.name=D", "-c", "user.email=d@e.x", "commit", "-q", "-m", "x"]);
    const plans = await planRepo("o/r", r);
    expect(plans[0]!.manual).toEqual([]);
    expect(plans[0]!.changes[0]).toMatchObject({ path: "vite.config.ts", kind: "edit" });
    expect(plans[0]!.changes[0]!.text).not.toContain("fetch");
  });
});
