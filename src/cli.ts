#!/usr/bin/env node
import { existsSync } from "node:fs";
import path from "node:path";
import { scan } from "./core/scan.js";
import { walk } from "./sources/fs.js";
import { firstIntroduction, scanRepoBranches } from "./sources/git.js";
import { safe } from "./safe.js";

process.stdout.on("error", (e: NodeJS.ErrnoException) => { if (e.code === "EPIPE") process.exit(0); });
const args = process.argv.slice(2);
const cmd = args[0];
if (cmd === "--version" || cmd === "-v") {
  const { readFileSync } = await import("node:fs");
  console.log(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
  process.exit(0);
}

function opt(name: string): string[] {
  const out: string[] = [];
  args.forEach((a, i) => { if (a === `--${name}` && args[i + 1]) out.push(args[i + 1]!); });
  return out;
}

if (cmd === "doctor") {
  const { doctor, formatDoctor } = await import("./doctor.js");
  const checks = await doctor();
  console.log(formatDoctor(checks));
  process.exit(checks.every((c) => c.ok) ? 0 : 1);
}

if (cmd === "host") {
  const { realSys } = await import("./host/sys.js");
  const { runHostCheck, formatHost } = await import("./host/index.js");
  const home = opt("home")[0];
  const res = await runHostCheck(realSys(home), { paths: opt("path"), maxFiles: Number(opt("max-files")[0] ?? 200_000) },
    (l) => process.stderr.write(`\r${l.slice(0, 60).padEnd(60)}`));
  process.stderr.write("\r".padEnd(62) + "\r");
  if (args.includes("--json")) console.log(JSON.stringify(res, null, 2)); else console.log(formatHost(res));
  process.exit(res.verdict === "likely-infected" ? 1 : 0);
}

if (cmd === "clean" && args.includes("--undo")) {
  const { readJournal, undoEntries, formatUndo } = await import("./clean/undo.js");
  const { GitHub } = await import("./github/client.js");
  const { GitHubWriteApi } = await import("./github/write.js");
  const { tokenFor } = await import("./auth.js");
  const apply = args.includes("--apply");
  const only = opt("repo");
  const entries = readJournal().filter((e) => !only.length || only.includes(e.repo));
  const results = [];
  for (const owner of [...new Set(entries.map((e) => e.repo.split("/")[0]!))]) {
    const token = await tokenFor(owner);
    if (!token) { console.error(`warning: not signed in as ${owner}; skipping its repos`); continue; }
    results.push(...await undoEntries(new GitHubWriteApi(new GitHub(token)), entries.filter((e) => e.repo.startsWith(owner + "/")), { apply }));
  }
  console.log(formatUndo(results, apply));
  process.exit(results.some((r) => r.status === "failed") ? 1 : 0);
}

if (cmd === "clean") {
  const { resolveTargets } = await import("./targets.js");
  const { cleanRepos, formatClean } = await import("./clean/run.js");
  const resolved = await resolveTargets({
    accounts: opt("account"), allAccounts: args.includes("--all-accounts"),
    users: [], repos: opt("repo"), exclude: opt("exclude"), skipForks: args.includes("--skip-forks"),
  });
  for (const w of resolved.warnings) console.error(`warning: ${w}`);
  if (!resolved.targets.length) {
    console.error("usage: gitward clean [--account LOGIN ... | --all-accounts] [--repo owner/name ...] [--exclude owner/ ...] [--apply] [--no-pr]\n" +
      "       dry run by default; --apply commits the fixes (one commit per branch, never a force-push)");
    process.exit(2);
  }
  const apply = args.includes("--apply");
  console.error(`${apply ? "Cleaning" : "Planning (dry run) for"} ${resolved.targets.length} repo(s)...`);
  const results = await cleanRepos(resolved.targets, {
    apply, pr: !args.includes("--no-pr"),
    onProgress: (d, n, r) => process.stderr.write(`\r[${d}/${n}] ${r.slice(0, 60).padEnd(60)}`),
  });
  process.stderr.write("\n");
  console.log(formatClean(results, apply));
  const failed = results.some((r) => r.results.some((x) => x.status === "failed" || x.verified === false));
  process.exit(failed ? 1 : 0);
}

if (cmd === "report") {
  const { resolveTargets } = await import("./targets.js");
  const { buildReport } = await import("./report/build.js");
  const { toHtml, toMarkdown } = await import("./report/render.js");
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const resolved = await resolveTargets({
    accounts: opt("account"), allAccounts: args.includes("--all-accounts"),
    users: opt("user"), repos: opt("repo"), exclude: opt("exclude"), skipForks: args.includes("--skip-forks"),
  });
  for (const w of resolved.warnings) console.error(`warning: ${w}`);
  if (!resolved.targets.length && !resolved.accounts.length && !opt("user").length && !opt("repo").length) {
    console.error("No GitHub account found. Run `gitward doctor` for setup steps (install gh, then gh auth login).");
    process.exit(2);
  }
  if (!resolved.targets.length) {
    console.error("usage: gitward report [--account LOGIN ... | --all-accounts] [--user NAME ...] [--repo owner/name ...]\n" +
      "                    [--exclude owner/ ...] [--ignore LOGIN ...] [--skip-forks] [--quick] [--concurrency N] [--out DIR]");
    process.exit(2);
  }
  console.error(`Scanning ${resolved.targets.length} repo(s)...`);
  const hostResult = args.includes("--host")
    ? await (async () => { const { realSys } = await import("./host/sys.js"); const { runHostCheck } = await import("./host/index.js"); return runHostCheck(realSys(), { paths: opt("path") }); })()
    : undefined;
  const report = await buildReport({
    targets: resolved.targets, accounts: resolved.accounts,
    ignoreActors: [...resolved.accounts, ...opt("ignore")],
    concurrency: Number(opt("concurrency")[0] ?? 4),
    history: !args.includes("--no-history"),
    quick: args.includes("--quick"),
    onProgress: (d, n, r) => process.stderr.write(`\r[${d}/${n}] ${r.slice(0, 60).padEnd(60)}`),
  });
  process.stderr.write("\n");
  if (hostResult) report.host = hostResult;
  const out = opt("out")[0] ?? "reports";
  mkdirSync(out, { recursive: true });
  writeFileSync(`${out}/report.json`, JSON.stringify(report, null, 2));
  writeFileSync(`${out}/report.md`, toMarkdown(report));
  writeFileSync(`${out}/report.html`, toHtml(report));
  const count = (s: string) => report.repos.filter((r) => r.status === s).length;
  console.log(`${report.repos.length} repo(s): ${count("infected")} infected, ${count("suspicious")} suspicious, ${count("unknown")} not scanned.`);
  console.log(`Wrote ${out}/report.html, report.md, report.json`);
  process.exit(count("infected") ? 1 : 0);
}

const worktreeOnly = args.includes("--worktree");
const target = args.slice(1).find((a) => !a.startsWith("--")) ?? ".";

if (cmd !== "scan") {
  console.log("usage: gitward scan <directory-or-repo> [--worktree]\n       gitward report [--account LOGIN | --all-accounts] [--user NAME] [--repo owner/name] [--host]\n       gitward doctor                      check setup (git, gh, sign-in) and say what to fix\n       gitward host [--path DIR ...]\n       gitward clean [--account LOGIN | --all-accounts] [--repo owner/name] [--apply]\n       gitward clean --undo [--repo owner/name] [--apply]   revert earlier cleanups (dry run without --apply)\n" +
    "  git repos are scanned across every branch (and history lookup); --worktree scans files only");
  process.exit(cmd ? 2 : 0);
}

const isGit = existsSync(path.join(target, ".git")) || existsSync(path.join(target, "HEAD"));
let high = false;

if (isGit && !worktreeOnly) {
  const findings = await scanRepoBranches(target);
  for (const f of findings) {
    if (f.severity === "high") high = true;
    const intro = await firstIntroduction(target, f.blob);
    console.log(`[${f.severity.toUpperCase()}] ${f.rule}  ${safe(f.path)}`);
    console.log(`         ${safe(f.evidence)}`);
    console.log(`         on ${f.branches.length} branch(es): ${f.branches.slice(0, 6).map((b) => safe(b, 60)).join(", ")}${f.branches.length > 6 ? ", ..." : ""}`);
    if (intro) console.log(`         first added: ${intro.commit.slice(0, 10)} by ${safe(intro.author, 60)} on ${intro.date.slice(0, 10)} "${safe(intro.subject, 60)}"`);
  }
  console.log(findings.length ? `\n${findings.length} finding(s).` : "No findings.");
} else {
  const findings = await scan(walk(target));
  for (const f of findings) {
    if (f.severity === "high") high = true;
    console.log(`[${f.severity.toUpperCase()}] ${f.rule}  ${safe(f.path)}\n         ${safe(f.evidence)}`);
  }
  console.log(findings.length ? `\n${findings.length} finding(s).` : "No findings.");
}
process.exit(high ? 1 : 0);
