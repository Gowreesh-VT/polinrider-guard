import type { Rule } from "../types.js";
import { asText, snippet } from "../text.js";

export const vscodeAutorun: Rule = {
  id: "vscode-autorun",
  severity: "high",
  check(file) {
    const text = asText(file);
    if (!text) return [];
    if (file.path.endsWith(".vscode/tasks.json") && /"runOn"\s*:\s*"folderOpen"/.test(text) && /\bnode\b/.test(text))
      return [{ rule: this.id, severity: this.severity, path: file.path,
        evidence: "task runs node when the folder is opened" }];
    if (file.path.endsWith(".vscode/settings.json")) {
      if (/"task\.allowAutomaticTasks"\s*:\s*(true|"on")/.test(text))
        return [{ rule: this.id, severity: "high", path: file.path,
          evidence: "automatic tasks switched on in workspace settings" }];
      if (/folderOpen/.test(text))
        return [{ rule: this.id, severity: "medium", path: file.path,
          evidence: `folderOpen in settings: ${snippet(text.slice(text.indexOf("folderOpen") - 40), 80)}` }];
    }
    return [];
  },
};
