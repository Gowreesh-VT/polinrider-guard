import { describe, it, expect } from "vitest";
import { compareCommits } from "../src/github/forcepush.js";
import { summarizeActors, statusOf, type RepoReport, type Report } from "../src/report/model.js";
import { toHtml, toMarkdown, esc } from "../src/report/render.js";

const commit = (name: string, date: string, msg: string, committer = "Dev " + date) =>
  ({ commit: { author: { name, date }, committer: { name: committer, date }, message: msg } });

describe("amend detection", () => {
  it("flags same author/date/subject with a lost message body", () => {
    const e = compareCommits(
      commit("Ann", "2026-07-30T18:57:45Z", "Fix thing\n\nlong explanation"),
      commit("Ann", "2026-07-30T18:57:45Z", "Fix thing"));
    expect(e.likelyAmend).toBe(true);
    expect(e.bodyLost).toBe(true);
  });
  it("does not flag a genuinely different commit", () => {
    expect(compareCommits(commit("Ann", "2026-07-30T18:57:45Z", "A"), commit("Bob", "2026-08-01T00:00:00Z", "B")).likelyAmend).toBe(false);
  });
});

const repo = (name: string, status: RepoReport["status"], fps: RepoReport["forcePushes"]): RepoReport =>
  ({ repo: name, status, findings: [], forcePushes: fps, notes: [] });
const fp = (actor: string, amended: boolean) => ({
  ref: "main", actor, timestamp: "2026-11-17T22:51:10Z", before: "a".repeat(40), after: "b".repeat(40),
  amend: { likelyAmend: amended, author: "x", subject: "s", bodyLost: false },
});

describe("report model", () => {
  it("summarizes accounts, ignoring bots and listed accounts", () => {
    const actors = summarizeActors([
      repo("o/a", "infected", [fp("mallory", true), fp("mallory", true), fp("dependabot[bot]", false), fp("me", true)]),
      repo("o/b", "clean", [fp("mallory", false)]),
    ], ["me"]);
    expect(actors).toHaveLength(1);
    expect(actors[0]).toMatchObject({ actor: "mallory", forcePushes: 3, amended: 2, infectedRepos: ["o/a"] });
  });
  it("derives status from severity", () => {
    expect(statusOf([])).toBe("clean");
    expect(statusOf([{ severity: "medium" }])).toBe("suspicious");
    expect(statusOf([{ severity: "high" }])).toBe("infected");
  });
});

describe("rendering", () => {
  const report: Report = {
    generatedAt: "2026-11-21T00:00:00Z", accounts: ["me"], actors: [],
    repos: [{ repo: "o/<img src=x onerror=alert(1)>", status: "infected", notes: ["<script>x</script>"], forcePushes: [],
      findings: [{ rule: "r", severity: "high", path: "a\"><b>.js", evidence: "<script>alert(1)</script>", blob: "0", branches: ["m"] }] }],
  };
  it("escapes attacker-controlled text in HTML", () => {
    const html = toHtml(report);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
  });
  it("renders markdown with the caveat when there are force-pushes", () => {
    const md = toMarkdown({ ...report, actors: summarizeActors([repo("o/a", "infected", [fp("mallory", true)])]) });
    expect(md).toContain("mallory");
    expect(md).toContain("not who was at the keyboard");
  });
  it("esc handles all five characters", () => { expect(esc(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#39;"); });
});

import { attributeIntroductions } from "../src/report/model.js";
describe("attribution", () => {
  it("credits the force-push when the introducing commit is a force-push result", () => {
    const f: any = { rule: "r", severity: "high", path: "p", evidence: "", blob: "0", branches: ["main"],
      introduced: { commit: "b".repeat(40), author: "Original Author", date: "2026-07-30T00:00:00Z", subject: "s" } };
    attributeIntroductions([f], [fp("mallory", true)]);
    expect(f.createdByForcePush?.actor).toBe("mallory");
  });
  it("leaves ordinary commits unattributed", () => {
    const f: any = { introduced: { commit: "c".repeat(40) } };
    attributeIntroductions([f], [fp("mallory", true)]);
    expect(f.createdByForcePush).toBeUndefined();
  });
});
