import type { Rule } from "../types.js";
import { asText, base, snippet } from "../text.js";

/** Hidden extensionless `init` payload and the package.json hook that runs it. */
export const initFile: Rule = {
  id: "init-file",
  severity: "high",
  check(file) {
    if (base(file.path) !== "init") return [];
    const text = asText(file);
    if (!text || text.length < 3000) return [];
    const longest = Math.max(...text.split("\n").map((l) => l.length));
    return longest > 3000
      ? [{ rule: this.id, severity: this.severity, path: file.path,
           evidence: `extensionless init file with a ${longest}-char line` }]
      : [];
  },
};

const HOOK = /node\s+(\.\/)?([\w./-]*\/)?init\s*&&/;
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "prepublish"];

export const packageHook: Rule = {
  id: "package-hook",
  severity: "high",
  check(file) {
    if (base(file.path) !== "package.json") return [];
    const text = asText(file);
    if (!text) return [];
    const out = [];
    const m = HOOK.exec(text);
    if (m) out.push({ rule: this.id, severity: this.severity, path: file.path,
      evidence: `script runs init loader: ${snippet(m[0])}` });
    try {
      const scripts = (JSON.parse(text) as { scripts?: Record<string, string> }).scripts ?? {};
      for (const k of LIFECYCLE) {
        const v = scripts[k];
        if (v && /\b(node|sh|bash|curl|wget)\b[^&|;]*\.(woff2?|ttf|orc|bat)\b/.test(v))
          out.push({ rule: this.id, severity: "high" as const, path: file.path,
            evidence: `${k} hook runs a font/bat file: ${snippet(v)}` });
      }
    } catch { /* invalid JSON: ignore */ }
    return out;
  },
};
