import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseLogin, parseRepo } from "../src/validate.js";
import { md, redact, safe } from "../src/safe.js";
import { GitHub } from "../src/github/client.js";
import { readJournal, record, undoEntries } from "../src/clean/undo.js";
import type { WriteApi } from "../src/github/write.js";

describe("input validation", () => {
  it("accepts normal names", () => { expect(parseRepo("octo/hello-world.js")).toBe("octo/hello-world.js"); expect(parseLogin("a-b1")).toBe("a-b1"); });
  it("rejects hostile names", () => {
    for (const bad of ["a/b/c", "a", "-x/y", "a/..", "a/-flag", "a/b;rm -rf", "a/b c", "../x/y", "a/b\n", ""]) expect(() => parseRepo(bad)).toThrow();
    for (const bad of ["", "-a", "a b", "a/b", "x".repeat(40)]) expect(() => parseLogin(bad)).toThrow();
  });
});

describe("untrusted text", () => {
  it("strips terminal escapes, newlines and bidi overrides", () => {
    const out = safe("a\u001b[31mred\u001b]0;title\u0007\nb‮evil");
    expect(out).not.toMatch(/[\u0000-\u0008\u000b-\u001f‮]/);
    expect(out).not.toContain("\n");
  });
  it("md neutralises backticks and table pipes", () => { expect(md("a`b|c")).toBe("a'b\\|c"); });
  it("redacts credentials", () => {
    const t = "node x --token abc123 https://u:pw@host ghp_" + "a".repeat(30) + " Bearer " + "z".repeat(20);
    const r = redact(t);
    expect(r).not.toContain("abc123"); expect(r).not.toContain("pw@"); expect(r).not.toMatch(/ghp_a/); expect(r).not.toContain("zzzzzzzzzz");
  });
});

describe("github client", () => {
  it("never sends the token to another host", async () => {
    await expect(new GitHub("secret").get("https://evil.example/x")).rejects.toThrow(/refusing/);
  });
});

class Fake implements WriteApi {
  tips = new Map<string, string>(); made: string[] = [];
  async getBranchSha(_r: string, b: string) { return this.tips.get(b); }
  async getCommitTree(_r: string, c: string) { return "tree-of-" + c; }
  async createTree(): Promise<string> { throw new Error("n/a"); }
  async createCommit(_r: string, _m: string, tree: string) { this.made.push(tree); return "rev" + this.made.length + "0000000"; }
  async updateBranch(_r: string, b: string, c: string) { this.tips.set(b, c); }
  async createBranch() {}
  async createPull() { return ""; }
  async getFileText() { return undefined; }
}

describe("undo", () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "guard-j-")), "j.jsonl");
  const e = { repo: "o/r", branch: "main", commit: "c".repeat(40), parent: "p".repeat(40), time: "t" };
  it("reverts only when the cleanup is still the tip, as a new commit", async () => {
    record(e, file); record({ ...e, branch: "dev", commit: "d".repeat(40) }, file);
    const api = new Fake(); api.tips.set("main", e.commit); api.tips.set("dev", "newer");
    const rs = await undoEntries(api, readJournal(file), { apply: true, file });
    expect(rs.find((r) => r.branch === "main")?.status).toBe("reverted");
    expect(api.made).toEqual(["tree-of-" + e.parent]);
    expect(rs.find((r) => r.branch === "dev")?.status).toBe("skipped");
    expect(readJournal(file).find((x) => x.branch === "main")?.undone).toBe(true);
  });
  it("dry run changes nothing", async () => {
    const api = new Fake(); api.tips.set("dev", "d".repeat(40));
    const rs = await undoEntries(api, [{ ...e, branch: "dev", commit: "d".repeat(40) }], { apply: false, file });
    expect(rs[0]!.status).toBe("skipped"); expect(api.made).toEqual([]);
  });
});
