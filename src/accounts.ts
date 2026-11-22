import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

/** Logins that `gh` is signed in to (gh prints its status on stderr or stdout depending on version). */
export async function ghAccounts(): Promise<string[]> {
  try {
    const { stdout, stderr } = await run("gh", ["auth", "status"]);
    return parseAccounts(stdout + "\n" + stderr);
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    return parseAccounts((err.stdout ?? "") + "\n" + (err.stderr ?? ""));
  }
}

export function parseAccounts(text: string): string[] {
  return [...new Set([...text.matchAll(/Logged in to \S+ account (\S+)/g)].map((m) => m[1]!))];
}
