import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { parseLogin } from "./validate.js";

const run = promisify(execFile);

/** Token for a signed-in `gh` account, or GH_TOKEN/GITHUB_TOKEN, or none (public data only). */
export async function tokenFor(account?: string): Promise<string | undefined> {
  if (!account) return process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
  try {
    const { stdout } = await run("gh", ["auth", "token", "--user", parseLogin(account)]);
    return stdout.trim() || undefined;
  } catch {
    throw new Error(`No gh login for "${account}". Run: gh auth login`);
  }
}
