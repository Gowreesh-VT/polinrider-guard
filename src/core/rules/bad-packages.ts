import type { Rule } from "../types.js";
import { asText, base } from "../text.js";
import { BAD_PACKAGES } from "../../host/ioc.js";

/** package.json / lockfiles that depend on a package reported as a malware carrier. */
export const knownBadPackage: Rule = {
  id: "known-bad-package",
  severity: "high",
  check(file) {
    const b = base(file.path);
    if (b !== "package.json" && b !== "package-lock.json" && b !== "pnpm-lock.yaml" && b !== "yarn.lock") return [];
    const text = asText(file);
    if (!text) return [];
    const hit = BAD_PACKAGES.find((p) => new RegExp(`["'/ ]${p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'@: ]`).test(text));
    return hit
      ? [{ rule: this.id, severity: this.severity, path: file.path, evidence: `depends on reported malicious package ${hit}` }]
      : [];
  },
};
