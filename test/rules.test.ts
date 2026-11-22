import { describe, it, expect } from "vitest";
import { scanFile } from "../src/core/scan.js";

// Built from pieces so scanning this repo does not flag its own test fixtures.
const A = "at" + "ob", E = "ev" + "al", F = "fe" + "tch", H = "http" + "s://";
const f = (path: string, text: string | Buffer) => ({
  path, content: Buffer.isBuffer(text) ? text : Buffer.from(text),
});
const rules = (path: string, text: string | Buffer) =>
  scanFile(f(path, text)).map((x) => x.rule);

// Fixtures are defanged: same shape as real samples, harmless contents.
const padded = (code: string) =>
  "module.exports = {};" + " ".repeat(300) + code;

describe("rules", () => {
  it("flags code hidden after padding in a config file", () => {
    expect(rules("postcss.config.mjs", padded("(function(){var a=1;})();"))).toContain("padded-payload");
  });
  it("ignores a normal config file", () => {
    expect(rules("vite.config.ts", "export default { server: { port: 3000 } };\n")).toEqual([]);
  });
  it("flags the init loader and its package.json hook", () => {
    expect(rules("init", "x".repeat(10) + "\n" + "var a=1;".repeat(600))).toContain("init-file");
    expect(rules("package.json", '{"scripts":{"dev":"node init && next dev"}}')).toContain("package-hook");
  });
  it("does not flag a normal dev script", () => {
    expect(rules("package.json", '{"scripts":{"dev":"next dev"}}')).toEqual([]);
  });
  it("flags folder-open tasks and automatic task settings", () => {
    expect(rules(".vscode/tasks.json", '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"node x.woff2"}]}')).toContain("vscode-autorun");
    expect(rules(".vscode/settings.json", '{"task.allowAutomaticTasks": "on"}')).toContain("vscode-autorun");
  });
  it("flags env loader and decode-fetch-eval", () => {
    expect(rules("src/constants.ts", `(async()=>{const s=${A}(` + "process.env." + `AUTH_API_KEY);${E}(s)})();`)).toContain("env-loader");
    expect(rules("a.js", `const u=${A}("aA==");${F}(u).then(r=>r.text()).then(t=>${E}(t));`)).toContain("decode-exec");
  });
  it("does not flag atob without eval", () => {
    expect(rules("a.js", `const x = ${A}("aGk="); console.log(x);`)).toEqual([]);
  });
  it("flags a font that is really javascript, not a real font", () => {
    expect(rules("fonts/a.ttf", "function a(){return 1}")).toContain("fake-binary");
    expect(rules("fonts/a.ttf", Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x0a]))).toEqual([]);
  });
  it("flags config.bat in .gitignore and dropper files", () => {
    expect(rules(".gitignore", "node_modules\nconfig.bat\n")).toContain("gitignore-config-bat");
    expect(rules("temp_auto_" + "push.bat", "@echo off")).toContain("dropper-file");
  });
});

describe("noise control", () => {
  it("ignores long lines in minified bundles and build output", () => {
    const longLine = "var a=function(){return 1};".repeat(400);
    expect(rules("dist/app.js", longLine)).toEqual([]);
    expect(rules("assets/index-D1ze5r62.js", longLine)).toEqual([]);
    expect(rules("lib/vendor.min.js", longLine)).toEqual([]);
  });
});

describe("false positives seen on real repos", () => {
  it("ignores deeply indented JSX", () => {
    const jsx = " ".repeat(90) + '<span className="text-[9px] font-bold uppercase tracking-wider">label</span>' + "\n";
    expect(rules("src/app/preferences/page.tsx", jsx.repeat(3))).toEqual([]);
  });
  it("ignores long lines in vendored libs and data files", () => {
    const long = "var a=function(){return 1};".repeat(400);
    expect(rules("libs/Three.js", long)).toEqual([]);
    expect(rules("src/mediaMap.ts", long)).toEqual([]);
    expect(rules("public/sw-main.js", long)).toEqual([]);
  });
  it("still flags a huge line inside a config-style file", () => {
    expect(rules("postcss.config.mjs", "var a=function(){return 1};".repeat(400))).toContain("padded-payload");
  });
  it("ignores decode/fetch/eval in a minified vendor worker", () => {
    expect(rules("public/tesseract/worker.min.js", `${A}("x");${F}("${H}a.b");${E}("1")`)).toEqual([]);
  });
  it("still catches a padded loader inside a vite config", () => {
    expect(rules("lumina/vite.config.ts", "export default {};" + " ".repeat(250) + `(async()=>{let d=(t:any)=>${A}(t);${E}(d("aA=="));${F}("${H}x.y")})();`)).toContain("padded-payload");
  });
});
