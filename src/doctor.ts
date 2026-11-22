import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { ghAccounts } from "./accounts.js";
import { tokenFor } from "./auth.js";

const run = promisify(execFile);

export interface Check { name: string; ok: boolean; detail: string; fix?: string }

export function installGhHelp(platform: NodeJS.Platform): string {
  switch (platform) {
    case "darwin": return "Install the GitHub CLI:  brew install gh   (or download from https://cli.github.com)";
    case "win32": return "Install the GitHub CLI:  winget install --id GitHub.cli   (or download from https://cli.github.com)";
    default: return "Install the GitHub CLI from https://github.com/cli/cli#installation (for Debian/Ubuntu: sudo apt install gh)";
  }
}

export const LOGIN_HELP = "Sign in:  gh auth login   (choose GitHub.com, HTTPS, and log in with the browser). Run it again to add another account.";

export function parseScopes(header: string | null): string[] {
  return (header ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

async function tool(cmd: string, args: string[]): Promise<string | undefined> {
  try { return (await run(cmd, args)).stdout.trim(); } catch { return undefined; }
}

async function scopesFor(token: string): Promise<string[] | undefined> {
  try {
    const res = await fetch("https://api.github.com/user", { headers: { authorization: `Bearer ${token}`, "user-agent": "polinrider-guard" } });
    return res.ok ? parseScopes(res.headers.get("x-oauth-scopes")) : undefined;
  } catch { return undefined; }
}

/** Checks everything the tool needs and says exactly what to do about whatever is missing. */
export async function doctor(platform: NodeJS.Platform = process.platform): Promise<Check[]> {
  const out: Check[] = [];
  const major = Number(process.versions.node.split(".")[0]);
  out.push({ name: "Node.js 20 or newer", ok: major >= 20, detail: `found ${process.versions.node}`, fix: major >= 20 ? undefined : "Install Node.js 20+ from https://nodejs.org" });

  const git = await tool("git", ["--version"]);
  out.push({ name: "git", ok: !!git, detail: git ?? "not found", fix: git ? undefined : "Install git from https://git-scm.com" });

  const gh = await tool("gh", ["--version"]);
  out.push({ name: "GitHub CLI (gh)", ok: !!gh, detail: gh?.split("\n")[0] ?? "not found", fix: gh ? undefined : installGhHelp(platform) });
  if (!gh) return out;

  const accounts = await ghAccounts();
  out.push({ name: "Signed in to GitHub", ok: accounts.length > 0, detail: accounts.length ? accounts.join(", ") : "no accounts", fix: accounts.length ? undefined : LOGIN_HELP });
  for (const a of accounts) {
    const token = await tokenFor(a).catch(() => undefined);
    const scopes = token ? await scopesFor(token) : undefined;
    // classic tokens list scopes; fine-grained or app tokens do not, so only warn when we can see the list
    const ok = !scopes || scopes.length === 0 || scopes.includes("repo");
    out.push({
      name: `Permissions for ${a}`, ok,
      detail: scopes?.length ? scopes.join(", ") : "scopes not reported (fine-grained token)",
      fix: ok ? undefined : `Grant repo access:  gh auth refresh -h github.com -s repo   (log in as ${a} first)`,
    });
  }
  return out;
}

export function formatDoctor(checks: Check[]): string {
  const L = checks.map((c) => `${c.ok ? "OK  " : "FIX "} ${c.name}: ${c.detail}${c.fix ? `\n       -> ${c.fix}` : ""}`);
  const bad = checks.filter((c) => !c.ok).length;
  L.push("", bad ? `${bad} thing(s) to fix before scanning your repos.` : "Ready. Try:  polinrider-guard report --all-accounts   or   polinrider-guard host");
  return L.join("\n");
}
