import type { Rule } from "../types.js";
import { asText, base, snippet, BUNDLE } from "../text.js";

const CODE_FILE = /\.(c?js|mjs|ts|tsx|jsx|mts|cts|vue|svelte)$/i;
const CONFIG_FILE = /(^|\/)(vite|vitest|webpack|rollup|postcss|tailwind|eslint|next|nuxt|babel|jest|astro|svelte|gulpfile|tsup|esbuild|craco|gatsby-\w+|metro|app\.config|prettier|stylelint|playwright|cypress|karma|remix|vue|snowpack|parcel|hardhat|truffle)[\w.-]*\.(c|m)?(js|ts)$/i;
// documentation and notes quote indicators on purpose
const PROSE = /\.(md|mdx|txt|rst|adoc)$/i;
const SHELLISH = /\.(sh|bash|bat|cmd|ps1|ya?ml|py|mk)$|(^|\/)(Makefile|Dockerfile)$|(^|\/)\.husky\/|^\.githooks\//i;

// Markers taken from known samples. Strong: legitimate code does not contain these.
const MARKERS = new RegExp([
  "rmcej" + "%otb%", "Cot%3t" + "=shtP", "_\\$_1e" + "42", "global\\['" + "!'\\]", "global\\['" + "_V'\\]", "global\\[.r.\\]\\s*=\\s*require",
  "TMfKQEd7TJJa5xNZJZ2" + "Lep838vrzrs7mAP", "TXfxHUet9pJVU1BgVkBAbrES4" + "YUc1nGzcG", "e9b53a7c-2342-" + "4b15-b02d",
  "var z = '-" + "2914-2'", "eval\\(proxyInfo\\)", "temp_auto_" + "push",
  // April 2026 variant
  "function M" + "Dy\\(f\\)", "2\\[gWfGj;<:" + "-93Z\\^C", "m6:tTh\\^D" + "\\)cBz\\?NM\\]",
  "260120\\.vercel\\.app", "default-configuration\\.vercel\\.app", "vscode-settings-(?:bootstrap|config)\\.vercel\\.app",
].join("|"));

// Hosts the malware used, but that also have legitimate uses (file upload, crypto apps): informational.
const WEAK_ENDPOINT = /catbox\.moe|api\.trongrid\.io|fullnode\.mainnet\.aptoslabs\.com|bsc-dataseed[\w.-]*\.binance\.org/;

export const EVAL = /(?<![\w$.])eval\s*\(\s*[A-Za-z_$][\w$.[\]'"]{0,80}\s*\)|new\s+Function\s*\(|(?<![\w$.])Function\s*\(\s*['"`]|vm\.(?:runIn\w+|Script)\s*\(|\.constructor\(\s*['"`]return/;
export const NET = /\bfetch\s*\(|https?\.(?:get|request)\s*\(|axios|XMLHttpRequest|node-fetch|\bgot\s*\(|\bcurl\b|\bwget\b|require\(['"](?:https?|net|dns|dgram)['"]\)|from\s+['"](?:https?|node:https?|net)['"]|WebSocket\s*\(|import\(\s*[^)'"`]/;
export const DECODE = /\batob\s*\(|Buffer\.from\([^)]{0,200}['"]base64['"]\)|b64decode|FromBase64String/;
const CHILD = /child_process|\bexecSync\s*\(|\bspawnSync?\s*\(|\bexecFileSync?\s*\(|subprocess\.(?:run|Popen|call)|os\.system\s*\(/;
const CRED = /\.ssh\/(?:id_|known_hosts)|\.aws\/credentials|Login[ ]Data|Local[ ]State|wallet\.dat|\.git-credential[s]|JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys)\(\s*process\.env\s*\)[^\n]{0,80}(?:fetch|post|send)|os\.homedir\(\)[^\n]{0,120}(?:readFile|createReadStream)/;
const EXFIL = /discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|pastebin\.com\/raw|transfer\.sh|ngrok(?:-free)?\.(?:io|app|dev)|webhook\.site|requestbin|interact\.sh|burpcollaborator|0x0\.st|anonfiles|gofile\.io/;
// strong: encoded commands, decode-and-run, living-off-the-land downloaders, download piped to iex
const SHELL_STRONG = /powershell(?:\.exe)?\s+[^\n]{0,200}-(?:enc|encodedcommand)\b|base64\s+(?:-d|--decode)[^\n]{0,200}\|\s*(?:ba)?sh|certutil\s+-urlcache|mshta\s+https?:|(?:iwr|Invoke-WebRequest|DownloadString)[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)/i;
// installer-style `curl | sh` is everywhere (rustup, nodesource); worth knowing about, not alarming
const SHELL_INSTALLER = /(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/;
const OBF1 = /_0x[0-9a-f]{4,6}\b/g;
const OBF2 = /while\s*\(\s*!!\s*\[\s*\]\s*\)|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){12,}|String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){12,}/;

export const knownSignature: Rule = {
  id: "known-signature",
  severity: "high",
  check(file) {
    if (PROSE.test(file.path) || base(file.path) === ".gitignore") return [];
    const text = asText(file);
    if (!text) return [];
    const m = MARKERS.exec(text);
    if (m) return [{ rule: this.id, severity: this.severity, path: file.path, evidence: `known marker: ${snippet(m[0], 50)}` }];
    if (/(^|\/)\.env[\w.-]*$/.test(file.path) && /^AUTH_API_KEY\s*=/m.test(text))
      return [{ rule: "env-loader-key", severity: "high", path: file.path, evidence: "committed AUTH_API_KEY used by the env-variable loader" }];
    return [];
  },
};

export const suspiciousEndpoint: Rule = {
  id: "suspicious-endpoint",
  severity: "low",
  check(file) {
    if (BUNDLE.test(file.path) || !CODE_FILE.test(file.path) && !/\.(json|env|ya?ml)$/.test(file.path)) return [];
    const text = asText(file);
    const m = text ? WEAK_ENDPOINT.exec(text) : null;
    const x = text ? EXFIL.exec(text) : null;
    const hit = m ?? x;
    return hit ? [{ rule: this.id, severity: this.severity, path: file.path, evidence: `contacts ${hit[0]} (also used legitimately; check the context)` }] : [];
  },
};

export const evalNetwork: Rule = {
  id: "eval-network",
  severity: "medium",
  check(file) {
    if (!CODE_FILE.test(file.path) || BUNDLE.test(file.path)) return [];
    const text = asText(file);
    if (!text) return [];
    const ev = EVAL.exec(text);
    if (!ev || !NET.test(text)) return [];
    const strong = DECODE.test(text) || CONFIG_FILE.test(file.path);
    return [{ rule: this.id, severity: strong ? "high" : "low", path: file.path, evidence: `${snippet(ev[0], 40)} next to network access${strong ? " in a config file or with decoding" : ""}` }];
  },
};

export const obfuscated: Rule = {
  id: "obfuscated",
  severity: "medium",
  check(file) {
    if (!CODE_FILE.test(file.path) || BUNDLE.test(file.path)) return [];
    const text = asText(file);
    if (!text || text.length > 2_000_000) return [];
    const n = (text.match(OBF1) ?? []).length;
    if (n >= 40 || (n >= 15 && CONFIG_FILE.test(file.path)) || (OBF2.test(text) && CONFIG_FILE.test(file.path)))
      return [{ rule: this.id, severity: n >= 40 ? "high" : "medium", path: file.path, evidence: `obfuscated code (${n} hex-named identifiers)` }];
    return [];
  },
};

export const credentialAccess: Rule = {
  id: "credential-access",
  severity: "high",
  check(file) {
    if (!CODE_FILE.test(file.path) || BUNDLE.test(file.path)) return [];
    const text = asText(file);
    if (!text) return [];
    const c = CRED.exec(text);
    if (!c || !(NET.test(text) || CHILD.test(text))) return [];
    // plenty of legitimate tools read these paths; it is only alarming together with hiding techniques
    const hidden = DECODE.test(text) || EVAL.test(text) || CONFIG_FILE.test(file.path);
    return [{ rule: this.id, severity: hidden ? "high" : "low", path: file.path, evidence: `reads ${snippet(c[0], 40)} and can send data out${hidden ? " (with decoding, eval or in a config file)" : ""}` }];
  },
};

export const shellDownloadExec: Rule = {
  id: "shell-download-exec",
  severity: "high",
  check(file) {
    if (!SHELLISH.test(file.path) || BUNDLE.test(file.path)) return [];
    const text = asText(file);
    if (!text) return [];
    const strong = SHELL_STRONG.exec(text);
    if (strong) return [{ rule: this.id, severity: "high", path: file.path, evidence: `encoded or hidden download-and-run: ${snippet(strong[0], 60)}` }];
    const m = SHELL_INSTALLER.exec(text);
    return m ? [{ rule: this.id, severity: "low", path: file.path, evidence: `pipes a download into a shell: ${snippet(m[0], 60)}` }] : [];
  },
};

/** The way the malware spreads: amend the last commit and force-push it. */
export const gitAmendPush: Rule = {
  id: "git-amend-force-push",
  severity: "high",
  check(file) {
    if (!SHELLISH.test(file.path) && !CODE_FILE.test(file.path) || file.path.startsWith(".github/workflows/")) return [];
    const text = asText(file);
    if (!text) return [];
    // the dropper keeps the old date by reading it from LAST_COMMIT_DATE/TIME
    const amend = /commit\s+[^\n]{0,60}--amend/.test(text), push = /push\s+[^\n]{0,60}(?:--force|-f\b|--force-with-lease)/.test(text);
    const dated = /LAST_COMMIT_(?:DATE|TIME)/.test(text);
    return (amend && push) || (dated && (amend || push))
      ? [{ rule: this.id, severity: SHELLISH.test(file.path) ? "high" : "low", path: file.path, evidence: "amends the last commit and force-pushes (how the malware spreads)" }]
      : [];
  },
};

export const devcontainerHook: Rule = {
  id: "devcontainer-hook",
  severity: "low",
  check(file) {
    if (!file.path.endsWith("devcontainer.json")) return [];
    const text = asText(file);
    return text && /(?:postCreate|postStart|postAttach|onCreate|updateContent|initialize)Command["']?\s*:\s*["'[][^\n]{0,300}(?:curl|wget|node |bash|sh |powershell|http)/.test(text)
      ? [{ rule: this.id, severity: this.severity, path: file.path, evidence: "devcontainer runs a download or script automatically" }]
      : [];
  },
};

export const workflowRisk: Rule = {
  id: "workflow-pr-target",
  severity: "low",
  check(file) {
    if (!file.path.startsWith(".github/workflows/")) return [];
    const text = asText(file);
    return text && /pull_request_target/.test(text) && /secrets\.|github\.event\.pull_request\.head/.test(text) && /(?:curl|wget|run:)/.test(text)
      ? [{ rule: this.id, severity: this.severity, path: file.path, evidence: "pull_request_target with secrets or the PR head checked out" }]
      : [];
  },
};

const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack", "postpack"];
const LOCAL_SCRIPT = /^(?:node|tsx|ts-node|bun)\s+(?:\.\/)?(?!init\b)[\w./-]+\.(?:mjs|cjs|js|ts)(?:\s+[\w./=:-]+)*$/;
const SAFE_LIFE = /^(?:husky(?: install)?|npx husky(?: install)?|prisma generate|npx prisma generate|patch-package|npx patch-package|npm run build|tsc|ngcc|node-gyp rebuild|electron-builder install-app-deps|lefthook install|simple-git-hooks|panda codegen|npx panda codegen|node scripts\/[\w./-]+|npm run [\w:-]+|pnpm [\w:-]+|yarn [\w:-]+|npm test|npm run [\w:-]+(?: --?[\w-]+)*|tsc(?: -[\w-]+)*|true|exit 0|echo .*|)$/;
const LOADER_SCRIPT = /node\s+(?:\.\/)?[\w./-]*?(?:init|\.woff2?|\.orc|\.ttf|\.otf)\b|(?:curl|wget)[^&|]{0,200}\|\s*(?:ba)?sh/;
const REVIEW_SCRIPT = /powershell|Invoke-|\beval\b|base64/;
const safeLifecycle = (v: string) => v.split(/\s*&&\s*/).every((seg) => SAFE_LIFE.test(seg.trim()) || LOCAL_SCRIPT.test(seg.trim()));

export const packageScripts: Rule = {
  id: "package-scripts",
  severity: "high",
  check(file) {
    if (base(file.path) !== "package.json") return [];
    const text = asText(file);
    if (!text) return [];
    let pj: { scripts?: Record<string, unknown>; dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> };
    try { pj = JSON.parse(text); } catch { return []; }
    const out = [];
    for (const [k, v] of Object.entries(pj.scripts ?? {})) {
      if (typeof v !== "string") continue;
      if (LOADER_SCRIPT.test(v))
        out.push({ rule: this.id, severity: "high" as const, path: file.path, evidence: `${k} script looks like a loader: ${snippet(v, 70)}` });
      else if (LIFECYCLE.includes(k) && !safeLifecycle(v.trim()) && /node|curl|wget|sh |powershell|python|http/.test(v))
        out.push({ rule: this.id, severity: "low" as const, path: file.path, evidence: `${k} hook runs: ${snippet(v, 70)}; review` });
      else if (REVIEW_SCRIPT.test(v))
        out.push({ rule: this.id, severity: "low" as const, path: file.path, evidence: `${k} script uses ${snippet(REVIEW_SCRIPT.exec(v)![0], 20)}; review` });
    }
    for (const group of [pj.dependencies, pj.devDependencies])
      for (const [name, ver] of Object.entries(group ?? {}))
        if (typeof ver === "string" && /^(?:https?:|git\+|git:|file:|ssh:)/.test(ver))
          out.push({ rule: "dep-from-url", severity: "low" as const, path: file.path, evidence: `${name} installed from ${snippet(ver, 50)}` });
    return out;
  },
};

// Lines the malware adds to the top of ES-module configs so its hidden code can call require().
const PRELUDE = new Set([
  "import { create" + "Require } from 'module';", 'import { create' + 'Require } from "module";',
  "const require = create" + "Require(import.meta.url);", "var require = create" + "Require(import.meta.url);",
  "var module = { exp" + "orts: {} };",
]);

/** The header alone is common in real configs, so it only counts next to something else suspicious. */
export const injectedPrelude: Rule = {
  id: "injected-require-prelude",
  severity: "medium",
  check(file) {
    if (!CONFIG_FILE.test(file.path) || BUNDLE.test(file.path)) return [];
    const text = asText(file);
    if (!text || !text.split(/\r?\n/).some((l) => PRELUDE.has(l.trim()))) return [];
    const longest = text.split("\n").reduce((m, l) => Math.max(m, l.length), 0);
    if (longest < 1500 && !(EVAL.test(text) && NET.test(text))) return [];
    return [{ rule: this.id, severity: "medium", path: file.path, evidence: "config starts with a require() header and also holds a huge line or eval of fetched code" }];
  },
};
