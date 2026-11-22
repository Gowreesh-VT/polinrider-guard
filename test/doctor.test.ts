import { describe, it, expect } from "vitest";
import { formatDoctor, installGhHelp, parseScopes, type Check } from "../src/doctor.js";

describe("doctor", () => {
  it("gives the right install command per platform", () => {
    expect(installGhHelp("darwin")).toContain("brew install gh");
    expect(installGhHelp("win32")).toContain("winget install --id GitHub.cli");
    expect(installGhHelp("linux")).toContain("github.com/cli/cli");
  });
  it("parses the scopes header", () => {
    expect(parseScopes("repo, workflow, gist")).toEqual(["repo", "workflow", "gist"]);
    expect(parseScopes(null)).toEqual([]);
    expect(parseScopes("")).toEqual([]);
  });
  it("shows a fix for each failing check and a ready message when all pass", () => {
    const bad: Check[] = [{ name: "gh", ok: false, detail: "not found", fix: "install it" }, { name: "git", ok: true, detail: "v2" }];
    const text = formatDoctor(bad);
    expect(text).toContain("FIX  gh");
    expect(text).toContain("-> install it");
    expect(text).toContain("1 thing(s) to fix");
    expect(formatDoctor([{ name: "git", ok: true, detail: "v2" }])).toContain("Ready.");
  });
});
