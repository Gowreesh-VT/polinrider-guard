import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
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
function gitEnv(token?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ALLOW_PROTOCOL: "https", GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "credential.helper", GIT_CONFIG_VALUE_0: "" };
  if (token) {
    env.GIT_CONFIG_COUNT = "2";
    env.GIT_CONFIG_KEY_1 = "http.extraHeader";
    env.GIT_CONFIG_VALUE_1 = `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}`;
  }
  return env;
}

/**
 * Quick scan: only the newest commit of every branch, in a temporary folder that is deleted afterwards.
 * Much smaller and faster than a full mirror, but has no history (so no history scan or "first added").
 */
export async function withShallowClone<T>(rawRepo: string, token: string | undefined, fn: (dir: string) => Promise<T>): Promise<T> {
  const repo = parseRepo(rawRepo);
  const tmp = mkdtempSync(path.join(os.tmpdir(), "gitward-"));
  const dir = path.join(tmp, "repo.git");
  try {
    await run("git", ["clone", "-q", "--bare", "--depth", "1", "--no-single-branch", `https://github.com/${repo}.git`, dir], { env: gitEnv(token), maxBuffer: 64 * 1024 * 1024 });
    return await fn(dir);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export async function ensureMirror(rawRepo: string, token?: string): Promise<string> {
  const repo = parseRepo(rawRepo);
  const dir = path.join(cacheDir(), repo.replace("/", "__") + ".git");
  const env = gitEnv(token);
  const url = `https://github.com/${repo}.git`;
  if (existsSync(dir)) {
    await run("git", ["-C", dir, "fetch", "-q", "--prune", "--force", "origin", "+refs/heads/*:refs/heads/*"], { env, maxBuffer: 64 * 1024 * 1024 });
  } else {
    mkdirSync(path.dirname(dir), { recursive: true, mode: 0o700 });
    await run("git", ["clone", "-q", "--bare", url, dir], { env, maxBuffer: 64 * 1024 * 1024 });
  }
  return dir;
}
