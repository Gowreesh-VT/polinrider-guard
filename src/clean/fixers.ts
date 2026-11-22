import { scanFile } from "../core/scan.js";
import { base } from "../core/text.js";

export type Fix =
  | { kind: "edit"; text: string }
  | { kind: "delete"; also?: string[] }
  | { kind: "manual"; why: string };

const FONT = /\.(woff2?|ttf|otf|orc)$/i;
const HOOK = /node\s+(\.\/)?([\w./-]*\/)?init\s*&&\s*/g;

const validJson = (s: string) => { try { JSON.parse(s); return true; } catch { return false; } };

/** Cut hidden code off a padded line; drop lines that are one giant blob. Everything else is kept. */
export function cleanPadded(text: string): string {
  const out: string[] = [];
  for (const raw of text.split("\n")) {
    let line = raw.replace(/\r$/, "");
    const pad = /(?<=\S)[ \t]{40,}/.exec(line);
    if (pad && /\S[ \t]{80,}\S/.test(line)) {
      line = line.slice(0, pad.index);
      if (!line.trim()) continue;
    } else if (line.length > 3000) {
      continue;
    }
    out.push(line);
  }
  let t = out.join("\n");
  t = t.replace(/^import \{ createRequire \} from 'module';[ \t]*\n/m, "")
       .replace(/^(const|var) require = createRequire\(import\.meta\.url\);[ \t]*\n/m, "")
       .replace(/^var module = \{ exports: \{\} \};[ \t]*\n/m, "")
       .replace(/\n{3,}/g, "\n\n").replace(/^\n+/, "");
  return t.replace(/\s+$/, "") + "\n";
}

/** Remove `(async () => { ... atob(process.env.X) ... })();` by balancing parentheses. */
export function removeEnvLoader(text: string): string | undefined {
  const at = text.search(/atob\s*\(\s*process\.env\.\w+/);
  if (at < 0) return undefined;
  const start = text.lastIndexOf("(async", at);
  if (start < 0) return undefined;
  let depth = 0, i = start;
  for (; i < text.length; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) { i++; break; }
  }
  if (depth !== 0) return undefined;
  while (text[i] === " ") i++;
  if (text[i] === "(" && text[i + 1] === ")") i += 2;
  if (text[i] === ";") i++;
  return (text.slice(0, start) + text.slice(i)).replace(/\n{3,}/g, "\n\n");
}

/** Remove the `"tasks": { ... "folderOpen" ... }` block by scanning, not by regex (regexes went quadratic on hostile input). */
function removeTasksBlock(text: string): string {
  const key = text.indexOf('"tasks"');
  if (key < 0) return text;
  let i = key + 7;
  while (i < text.length && /\s/.test(text[i]!)) i++;
  if (text[i] !== ":") return text;
  i++;
  while (i < text.length && /\s/.test(text[i]!)) i++;
  if (text[i] !== "{") return text;
  let depth = 0, end = -1, inStr = false;
  for (let k = i; k < text.length; k++) {
    const c = text[k]!;
    if (inStr) { if (c === "\\") k++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) { end = k + 1; break; }
  }
  if (end < 0 || !text.slice(i, end).includes("folderOpen")) return text;
  let start = key;
  while (start > 0 && /\s/.test(text[start - 1]!)) start--;
  if (text[start - 1] === ",") start--;
  return text.slice(0, start) + text.slice(end);
}

export function removeAutoTasks(text: string): string | undefined {
  if (text.length > 1_000_000) return undefined;
  let t = removeTasksBlock(text);
  t = t.replace(/^[ \t]{0,200}"task\.allowAutomaticTasks"\s{0,20}:\s{0,20}[^,\r\n]{1,20},?[ \t]*\r?\n/m, "").replace(/,(\s{0,200}\})/g, "$1");
  return /allowAutomaticTasks|folderOpen/.test(t) ? undefined : t;
}

/** Files a malicious tasks.json runs (relative to the folder that holds .vscode). */
export function taskTargets(tasksPath: string, text: string): string[] {
  const root = tasksPath.replace(/(^|\/)\.vscode\/tasks\.json$/, "");
  const found = new Set<string>();
  for (const m of text.matchAll(/node\s+(\.?\/?[^\s"')]+)/g)) found.add(m[1]!);
  for (const m of text.matchAll(/"args"\s*:\s*\[\s*"([^"]+)"/g)) found.add(m[1]!);
  return [...found]
    .filter((t) => FONT.test(t))
    .map((t) => [root, t.replace(/^\.\//, "")].filter(Boolean).join("/"));
}

/**
 * Decide what to do with one flagged file. `rule` is the rule id that flagged it.
 * Edits are re-scanned, and JSON files must still parse, otherwise the fix is refused.
 */
export function fixFile(rule: string, path: string, text: string): Fix {
  const b = base(path);
  const verify = (fix: Fix): Fix => {
    if (fix.kind !== "edit") return fix;
    if (b.endsWith(".json") && validJson(text) && !validJson(fix.text)) return { kind: "manual", why: "edit would break the JSON; fix by hand" };
    const still = scanFile({ path, content: Buffer.from(fix.text) }).some((f) => f.rule === rule);
    return still ? { kind: "manual", why: `could not remove the ${rule} pattern safely; fix by hand` } : fix;
  };
  switch (rule) {
    case "init-file":
    case "fake-binary":
    case "dropper-file":

      return { kind: "delete" };
    case "padded-payload":
      return b === "init" ? { kind: "delete" } : verify({ kind: "edit", text: cleanPadded(text) });
    case "package-hook":
      return verify({ kind: "edit", text: text.replace(HOOK, "") });
    case "env-loader-key": {
      const kept = text.split(/(?<=\n)/).filter((l) => !/^AUTH_API_KEY\s*=/.test(l));
      return kept.join("").trim() ? verify({ kind: "edit", text: kept.join("") }) : { kind: "delete" };
    }
    case "gitignore-config-bat":
      return verify({ kind: "edit", text: text.split(/(?<=\n)/).filter((l) => !/^(?:config\.bat|temp_auto_[p]ush\.bat)$/.test(l.trim())).join("") });
    case "vscode-autorun":
      if (path.endsWith("tasks.json")) {
        // a folder-open task running node is only auto-removed when it runs a fake font file
        const targets = taskTargets(path, text);
        return targets.length
          ? { kind: "delete", also: targets }
          : { kind: "manual", why: "folder-open task runs node but not a font file; review it before deleting" };
      }
      { const t = removeAutoTasks(text); return t === undefined ? { kind: "manual", why: "could not edit settings.json cleanly" } : verify({ kind: "edit", text: t }); }
    case "env-loader":
    case "decode-exec": {
      const t = removeEnvLoader(text);
      return t === undefined ? { kind: "manual", why: "loader is embedded in code; review and remove by hand" } : verify({ kind: "edit", text: t });
    }
    case "known-bad-package":
      return { kind: "manual", why: "remove the dependency and reinstall; the right replacement depends on your project" };
    default:
      return { kind: "manual", why: `no automatic fix for ${rule}` };
  }
}
