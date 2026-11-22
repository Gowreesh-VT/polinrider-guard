import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { scanRepoBranches, firstIntroduction } from "../src/sources/git.js";

let repo = "";
const g = (...a: string[]) =>
  execFileSync("git", ["-C", repo, "-c", "user.name=Dev One", "-c", "user.email=dev@example.com", ...a], { encoding: "utf8" });

beforeAll(() => {
  repo = mkdtempSync(path.join(tmpdir(), "pg-"));
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  writeFileSync(path.join(repo, "postcss.config.mjs"), "export default {};\n");
  writeFileSync(path.join(repo, "package.json"), '{"scripts":{"dev":"next dev"}}\n');
  g("add", "-A"); g("commit", "-q", "-m", "initial");
  g("checkout", "-q", "-b", "feature");
  // defanged infection: padded code after a normal line, plus the init hook
  writeFileSync(path.join(repo, "postcss.config.mjs"), "export default {};" + " ".repeat(300) + "(function(){var a=1;})();\n");
  writeFileSync(path.join(repo, "package.json"), '{"scripts":{"dev":"node init && next dev"}}\n');
  g("add", "-A"); g("commit", "-q", "-m", "update config");
  // a later cleanup commit removes the payload; it must not count as the introduction
  writeFileSync(path.join(repo, "postcss.config.mjs"), "export default {};\n");
  g("add", "-A"); g("commit", "-q", "-m", "security: remove payload");
  g("checkout", "-q", "-b", "infected-tip", "HEAD~1");
  g("checkout", "-q", "main");
});

describe("git source", () => {
  it("finds infection on a non-checked-out branch and reports the branch", async () => {
    const findings = await scanRepoBranches(repo);
    const padded = findings.find((f) => f.rule === "padded-payload");
    expect(padded?.branches).toEqual(["infected-tip"]);
    expect(findings.some((f) => f.rule === "package-hook")).toBe(true);
  });
  it("does not flag the clean branch", async () => {
    const findings = await scanRepoBranches(repo);
    expect(findings.every((f) => !f.branches.includes("main"))).toBe(true);
  });
  it("finds the commit that introduced the payload", async () => {
    const f = (await scanRepoBranches(repo)).find((x) => x.rule === "padded-payload")!;
    const intro = await firstIntroduction(repo, f.blob);
    expect(intro?.subject).toBe("update config");
    expect(intro?.author).toBe("Dev One");
  });
});
