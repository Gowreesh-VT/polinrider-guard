import type { Rule } from "../types.js";
import { asText, base, snippet, BUNDLE } from "../text.js";

/** atob/base64 -> network fetch -> eval/new Function, the common loader shape. */
export const decodeExec: Rule = {
  id: "decode-exec",
  severity: "high",
  check(file) {
    if (!/\.(c?js|mjs|ts|tsx|jsx)$/.test(file.path)) return [];
    const text = asText(file);
    if (!text) return [];
    const decode = /\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]/.test(text);
    const exec = /\beval\s*\(|new\s+Function\s*\(|\(0\s*,\s*eval\)/.test(text);
    const net = /\bfetch\s*\(|node-fetch|https?:\/\/|XMLHttpRequest|require\(['"]https?['"]\)/.test(text);
    const envKey = /atob\s*\(\s*process\.env\.\w+/.test(text);
    if (BUNDLE.test(file.path) && !envKey) return [];
    if (envKey && exec)
      return [{ rule: "env-loader", severity: "high", path: file.path,
        evidence: "decodes an environment variable and evaluates it" }];
    if (decode && exec && net)
      return [{ rule: this.id, severity: this.severity, path: file.path,
        evidence: "decodes data, fetches from the network and evaluates the result" }];
    return [];
  },
};

export const gitignoreDropper: Rule = {
  id: "gitignore-config-bat",
  severity: "medium",
  check(file) {
    if (base(file.path) !== ".gitignore") return [];
    const text = asText(file);
    return text && /^(?:config\.bat|temp_auto_[p]ush\.bat)\s*$/m.test(text)
      ? [{ rule: this.id, severity: this.severity, path: file.path,
           evidence: "ignores a dropper file name (config.bat / the auto-push script)" }]
      : [];
  },
};

export const dropperFile: Rule = {
  id: "dropper-file",
  severity: "high",
  check(file) {
    const b = base(file.path);
    return b === "temp_auto_" + "push.bat" || b === "config.bat"
      ? [{ rule: this.id, severity: this.severity, path: file.path,
           evidence: `${b} present` }]
      : [];
  },
};
