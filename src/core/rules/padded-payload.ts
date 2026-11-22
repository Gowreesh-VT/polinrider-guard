import type { Rule } from "../types.js";
import { asText, snippet, BUNDLE } from "../text.js";

const CODE_FILE = /\.(c?js|mjs|ts|tsx|jsx)$/;
const CONFIG_NAME = /(^|\/)(\.?eslintrc|[\w-]+\.config)\.[a-z]+$/;
const LONG = 3000;
// padding must follow real content on the same line; deep indentation alone is normal
const PADDING = /\S[ \t]{80,}\S/;

/**
 * Payload hidden after a long run of spaces on a normal-looking line, or a
 * single enormous line in a source/config file.
 */
export const paddedPayload: Rule = {
  id: "padded-payload",
  severity: "high",
  check(file) {
    if (!CODE_FILE.test(file.path) && !CONFIG_NAME.test(file.path) && file.path.includes("."))
      return [];
    if (BUNDLE.test(file.path)) return [];
    const text = asText(file);
    if (!text) return [];
    for (const line of text.split("\n")) {
      const m = PADDING.exec(line);
      if (m && line.length > 150) {
        const after = line.slice(m.index + m[0].length - 1);
        const run = m[0].length - 2;
        if (/[(){};=]/.test(after.slice(0, 200)))
          return [{
            rule: this.id, severity: this.severity, path: file.path,
            evidence: `code after ${run}+ spaces: ${snippet(after, 60)}`,
          }];
      }
      if (CONFIG_NAME.test(file.path) && line.length > LONG && /\b(function|var|let|const|eval|global)\b/.test(line.slice(0, 500)))
        return [{
          rule: this.id, severity: "medium", path: file.path,
          evidence: `single line of ${line.length} chars containing code`,
        }];
    }
    return [];
  },
};
