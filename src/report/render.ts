import type { Report } from "./model.js";
import { CAVEAT } from "./model.js";
import { md, safe } from "../safe.js";
import type { HostResult } from "../host/types.js";

const VERDICT = { "likely-infected": "LIKELY INFECTED", suspicious: "SUSPICIOUS", clear: "CLEAR (nothing found now)" } as const;

function hostMd(h: HostResult): string[] {
  const L = [`## This computer (${h.platform}): ${VERDICT[h.verdict]}`, ``];
  for (const f of h.findings) L.push(`- **${f.severity.toUpperCase()}** ${f.check}: ${md(f.detail)}${f.where ? ` (\`${md(f.where)}\`)` : ""}`);
  if (h.exposure.length) { L.push(``, `Credentials a stealer could read if the machine was infected:`, ...h.exposure.map((e) => `- ${md(e.detail)}${e.where ? ` (\`${md(e.where)}\`)` : ""}`)); }
  L.push(``, `What to do:`, ...h.advice.map((a) => `- ${a}`), ``);
  return L;
}

function hostHtml(h: HostResult): string {
  const li = (x: { detail: string; where?: string; severity?: string; check?: string }) =>
    `<li>${x.severity ? `<b>${esc(x.severity.toUpperCase())}</b> ` : ""}${x.check ? `${esc(x.check)}: ` : ""}${esc(x.detail)}${x.where ? ` <code>${esc(x.where)}</code>` : ""}</li>`;
  return `<section><h2>This computer (${esc(h.platform)}): ${esc(VERDICT[h.verdict])}</h2><ul>${h.findings.map(li).join("")}</ul>` +
    (h.exposure.length ? `<p class="m">Credentials a stealer could read if the machine was infected:</p><ul>${h.exposure.map(li).join("")}</ul>` : "") +
    `<p><b>What to do</b></p><ul>${h.advice.map((a) => `<li>${esc(a)}</li>`).join("")}</ul></section>`;
}

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const hist = (h: NonNullable<import("./model.js").RepoReport["history"]>) =>
  h.map((x) => `${x.label} (\`${x.needle}\`): ${x.commits} commit(s), first ${x.first.commit.slice(0, 10)} by ${x.first.author} on ${x.first.date.slice(0, 10)}, last ${x.last.commit.slice(0, 10)} on ${x.last.date.slice(0, 10)}`);

const day = (iso: string) => iso.slice(0, 16).replace("T", " ") + "Z";

export function toMarkdown(r: Report): string {
  const L: string[] = [];
  const infected = r.repos.filter((x) => x.status === "infected");
  L.push(`# PolinRider report`, ``, `Generated ${r.generatedAt}. Accounts: ${r.accounts.join(", ") || "n/a"}.`, ``);
  L.push(`**${r.repos.length}** repos scanned, **${infected.length}** infected, ` +
    `**${r.repos.filter((x) => x.status === "suspicious").length}** suspicious, ` +
    `**${r.repos.filter((x) => x.status === "unknown").length}** could not be scanned, ` +
    `**${r.repos.filter((x) => x.status === "clean" && x.history?.length).length}** clean now but with the malware in old commits.`, ``);
  if (r.host) L.push(...hostMd(r.host));
  if (r.actors.length) {
    L.push(`## Accounts that force-pushed`, ``, `> ${CAVEAT}`, ``,
      `| Account | Force-pushes | Look like amended commits | Repos | Infected repos |`, `|---|---|---|---|---|`);
    for (const a of r.actors)
      L.push(`| ${md(a.actor, 60)} | ${a.forcePushes} | ${a.amended} | ${a.repos.length} | ${a.infectedRepos.length} |`);
    L.push(``);
  }
  for (const repo of r.repos) {
    if (repo.status === "clean" && !repo.forcePushes.length && !repo.findings.length && !repo.history?.length) continue;
    L.push(`## ${md(repo.repo, 120)} (${repo.status}${repo.visibility ? `, ${repo.visibility}` : ""}${repo.canPush === false ? ", read-only for you" : ""})`, ``);
    for (const f of repo.findings) {
      L.push(`- **${f.severity.toUpperCase()}** \`${f.rule}\` in \`${md(f.path)}\` - ${md(f.evidence)}`);
      L.push(`  - branches: ${f.branches.map((b) => md(b, 80)).join(", ")}`);
      if (f.introduced)
        L.push(`  - first added in \`${f.introduced.commit.slice(0, 10)}\` (author shown: ${md(f.introduced.author, 80)}, ${f.introduced.date.slice(0, 10)}): "${md(f.introduced.subject, 120)}"`);
      if (f.createdByForcePush)
        L.push(`  - that commit was created by a force-push from **${md(f.createdByForcePush.actor, 60)}** to ${md(f.createdByForcePush.ref, 80)} at ${day(f.createdByForcePush.timestamp)}; the author above is the original author carried over, not necessarily who added the payload`);
    }
    if (repo.forcePushes.length) {
      L.push(``, `Force-pushes:`, ``, `| When | Branch | Account | Before | After | Pattern |`, `|---|---|---|---|---|---|`);
      for (const fp of repo.forcePushes)
        L.push(`| ${day(fp.timestamp)} | ${md(fp.ref, 80)} | ${md(fp.actor, 60)} | \`${fp.before.slice(0, 8)}\` | \`${fp.after.slice(0, 8)}\` | ${
          fp.amend ? (fp.amend.likelyAmend ? "consistent with amend-and-force-push" : "different commit") : "n/a"} |`);
    }
    if (repo.history?.length) L.push(``, `In old commits (removing this needs a history rewrite, which this tool never does):`, ...hist(repo.history).map((x) => `- ${x}`));
    for (const n of repo.notes) L.push(``, `_${n}_`);
    L.push(``);
  }
  return L.join("\n");
}

export function toHtml(r: Report): string {
  const badge = (s: string) => `<span class="b ${esc(s)}">${esc(s)}</span>`;
  const rows = r.repos.filter((x) => x.status !== "clean" || x.forcePushes.length || x.findings.length || x.history?.length).map((repo) => `
<section><h2>${esc(repo.repo)} ${badge(repo.status)}${repo.visibility ? ` <span class="m">${esc(repo.visibility)}${repo.canPush === false ? ", read-only for you" : ""}</span>` : ""}</h2>
${repo.findings.map((f) => `<div class="f"><b>${esc(f.severity.toUpperCase())}</b> <code>${esc(f.rule)}</code> in <code>${esc(f.path)}</code><br>
<span class="m">${esc(f.evidence)}</span><br>
<span class="m">branches: ${esc(f.branches.join(", "))}</span>${f.introduced ? `<br><span class="m">first added in <code>${esc(f.introduced.commit.slice(0, 10))}</code> (author shown: ${esc(f.introduced.author)}, ${esc(f.introduced.date.slice(0, 10))}): &ldquo;${esc(f.introduced.subject)}&rdquo;</span>` : ""}${f.createdByForcePush ? `<br><span class="m"><b>That commit was created by a force-push from ${esc(f.createdByForcePush.actor)}</b> to ${esc(f.createdByForcePush.ref)} at ${esc(day(f.createdByForcePush.timestamp))}; the author above is the original author carried over, not necessarily who added the payload.</span>` : ""}</div>`).join("")}
${repo.forcePushes.length ? `<table><tr><th>When</th><th>Branch</th><th>Account</th><th>Before</th><th>After</th><th>Pattern</th></tr>${repo.forcePushes.map((fp) =>
  `<tr><td>${esc(day(fp.timestamp))}</td><td>${esc(fp.ref)}</td><td>${esc(fp.actor)}</td><td><code>${esc(fp.before.slice(0, 8))}</code></td><td><code>${esc(fp.after.slice(0, 8))}</code></td><td>${
    fp.amend ? (fp.amend.likelyAmend ? "consistent with amend-and-force-push" : "different commit") : "n/a"}</td></tr>`).join("")}</table>` : ""}
${repo.history?.length ? `<p class="m">In old commits (removing this needs a history rewrite, which this tool never does):</p><ul>${hist(repo.history).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
${repo.notes.map((n) => `<p class="m"><i>${esc(n)}</i></p>`).join("")}</section>`).join("");
  const actors = r.actors.length ? `<section><h2>Accounts that force-pushed</h2><p class="m">${esc(CAVEAT)}</p><table>
<tr><th>Account</th><th>Force-pushes</th><th>Look like amended commits</th><th>Repos</th><th>Infected repos</th></tr>${r.actors.map((a) =>
  `<tr><td>${esc(a.actor)}</td><td>${a.forcePushes}</td><td>${a.amended}</td><td>${a.repos.length}</td><td>${a.infectedRepos.length}</td></tr>`).join("")}</table></section>` : "";
  const infected = r.repos.filter((x) => x.status === "infected").length;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PolinRider report</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mu:#666;--bd:#ddd;--hi:#c0392b;--me:#b9770e;--ok:#1e8449}
@media(prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--mu:#999;--bd:#333;--hi:#ff6b5b;--me:#e5a53a;--ok:#4cc38a}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:0 auto;padding:16px}
section{border-top:1px solid var(--bd);padding:12px 0}.m{color:var(--mu);font-size:13px}code{font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;display:block;overflow-x:auto}td,th{border:1px solid var(--bd);padding:4px 8px;text-align:left}
.b{font-size:12px;padding:1px 8px;border-radius:10px;border:1px solid currentColor}.infected{color:var(--hi)}.suspicious{color:var(--me)}.clean{color:var(--ok)}.unknown{color:var(--mu)}
.f{margin:8px 0;padding-left:8px;border-left:3px solid var(--bd)}
</style></head><body><h1>PolinRider report</h1>
<p class="m">Generated ${esc(r.generatedAt)}. Accounts: ${esc(r.accounts.join(", ") || "n/a")}.</p>
<p><b>${r.repos.length}</b> repos scanned, <b>${infected}</b> infected, <b>${r.repos.filter((x) => x.status === "suspicious").length}</b> suspicious, <b>${r.repos.filter((x) => x.status === "unknown").length}</b> could not be scanned, <b>${r.repos.filter((x) => x.status === "clean" && x.history?.length).length}</b> clean now but with the malware in old commits.</p>
${r.host ? hostHtml(r.host) : ""}${actors}${rows}</body></html>`;
}
