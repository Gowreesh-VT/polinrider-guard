import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseRepo } from "./validate.js";

const run = promisify(execFile);

export const cacheDir = () =>
  process.env.GITWARD_CACHE ?? path.join(os.homedir(), ".cache", "gitward", "repos");

/**
 * Keep a bare mirror of owner/name up to date. The token is handed to git through
 * environment variables for that one call, so it is never written to the clone's config
 * and does not appear in the process list.
 */
export async function ensureMirror(rawRepo: string, token?: string): Promise<string> {
  const repo = parseRepo(rawRepo);
  const dir = path.join(cacheDir(), repo.replace("/", "__") + ".git");
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: "https", GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "credential.helper", GIT_CONFIG_VALUE_0: "" };
  if (token) {
    env.GIT_CONFIG_COUNT = "2";
    env.GIT_CONFIG_KEY_1 = "http.extraHeader";
    env.GIT_CONFIG_VALUE_1 = `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}`;
  }
  const url = `https://github.com/${repo}.git`;
  if (existsSync(dir)) {
    await run("git", ["-C", dir, "fetch", "-q", "--prune", "--force", "origin", "+refs/heads/*:refs/heads/*"], { env, maxBuffer: 64 * 1024 * 1024 });
  } else {
    mkdirSync(path.dirname(dir), { recursive: true, mode: 0o700 });
    await run("git", ["clone", "-q", "--bare", url, dir], { env, maxBuffer: 64 * 1024 * 1024 });
  }
  return dir;
}
