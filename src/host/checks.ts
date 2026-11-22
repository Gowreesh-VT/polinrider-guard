import type { Sys } from "./sys.js";
import { join } from "./sys.js";
import type { HostFinding } from "./types.js";
import { DROPPER_DIRS, DROPPER_FILES, HISTORY_TERMS, IOC_IPS, SECRET_FILE_NAME } from "./ioc.js";
import { scan } from "../core/scan.js";
import { redact } from "../safe.js";
import type { ScanFile } from "../core/types.js";
import { BUNDLE } from "../core/text.js";

export interface CheckResult { findings: HostFinding[]; exposure?: HostFinding[]; skipped?: string }
export interface Check { id: string; label: string; run(sys: Sys, opts: HostOptions): Promise<CheckResult> }
export interface HostOptions { paths: string[]; maxFiles: number }

// command lines can contain tokens; mask them before anything is shown or written
const f = (check: string, severity: HostFinding["severity"], detail: string, where?: string): HostFinding =>
  ({ check, severity, detail: redact(detail), where: where === undefined ? undefined : redact(where) });

// ---- hidden module folder reported for the newer variant ------------------------------
export const hiddenNodeModules: Check = {
  id: "hidden-node-modules",
  label: "Hidden ~/.node_modules folder",
  async run(sys) {
    const out: HostFinding[] = [];
    for (const rel of [".node_modules", "AppData/Roaming/.node_modules", ".config/.node_modules"]) {
      const p = join(sys.home, rel);
      if (await sys.exists(p)) out.push(f(this.id, "high", "hidden node_modules folder in the home directory (reported marker of the in-memory variant)", p));
    }
    return { findings: out };
  },
};

// ---- processes ------------------------------------------------------------------------
export interface Proc { pid: number; cmd: string }

export function parseProcs(platform: NodeJS.Platform, text: string): Proc[] {
  if (platform === "win32") {
    try {
      const j = JSON.parse(text) as { ProcessId: number; CommandLine: string | null }[] | { ProcessId: number; CommandLine: string | null };
      return (Array.isArray(j) ? j : [j]).filter((x) => x.CommandLine).map((x) => ({ pid: x.ProcessId, cmd: x.CommandLine! }));
    } catch { return []; }
  }
  return text.split("\n").slice(1).flatMap((l) => {
    const m = /^\s*(\d+)\s+(.*)$/.exec(l);
    return m ? [{ pid: Number(m[1]), cmd: m[2]! }] : [];
  });
}

/** First word of a command line, honouring quotes (Windows paths contain spaces). */
export function argv0(cmd: string): { exe: string; rest: string } {
  const m = /^\s*(?:"([^"]+)"|'([^']+)'|(\S+))\s*(.*)$/s.exec(cmd);
  return { exe: (m?.[1] ?? m?.[2] ?? m?.[3] ?? "").replace(/^.*[\\/]/, ""), rest: m?.[4] ?? "" };
}

export function suspiciousProc(cmd: string): string | undefined {
  // only when the program being run is node itself, not a shell whose text mentions it
  const { exe, rest } = argv0(cmd);
  if (!/^(node|nodejs)(\.exe)?$/i.test(exe)) return undefined;
  const line = `${exe} ${rest}`;
  if (/\.(woff2?|ttf|otf|orc)\b/i.test(rest)) return "node is running a font file";
  if (/\.node_modules/.test(rest)) return "node is running code from a hidden node_modules folder";
  if (/^(\.[\\/])?init(\s|$)/i.test(rest.replace(/^(--?\S+\s+)+/, ""))) return "node is running a file named init";
  if (/(^|\s)(-e|--eval)\s+\S{300,}/.test(rest)) return "node is running a very long inline script";
  if (/[\\/](tmp|temp)[\\/][^\s]*\.js\b/i.test(rest) && !/node_modules|\.cache/.test(line)) return "node is running a script from a temp folder";
  return undefined;
}

export const processes: Check = {
  id: "processes",
  label: "Running processes",
  async run(sys) {
    const text = sys.platform === "win32"
      ? await sys.exec("powershell", ["-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"])
      : await sys.exec("ps", ["-axo", "pid,command"]);
    const out: HostFinding[] = [];
    for (const p of parseProcs(sys.platform, text)) {
      if (p.pid === process.pid) continue;
      const why = suspiciousProc(p.cmd);
      if (why) out.push(f(this.id, "high", `${why} (pid ${p.pid})`, p.cmd.slice(0, 160)));
    }
    return { findings: out };
  },
};

// ---- network --------------------------------------------------------------------------
export const network: Check = {
  id: "network",
  label: "Connections to known malicious addresses",
  async run(sys) {
    const text = sys.platform === "win32"
      ? await sys.exec("netstat", ["-ano"])
      : sys.platform === "linux" ? await sys.exec("ss", ["-tunap"]) : await sys.exec("lsof", ["-nP", "-i"]);
    const out: HostFinding[] = [];
    for (const ip of IOC_IPS) {
      const line = text.split("\n").find((l) => l.includes(ip));
      if (line) out.push(f(this.id, "medium", `connection involving ${ip}, an address one victim reported (unverified; supporting evidence only)`, line.trim().slice(0, 160)));
    }
    return { findings: out };
  },
};

// ---- persistence ----------------------------------------------------------------------
const INTERP = /\b(node|bash|sh|zsh|python3?|osascript|curl|wget|powershell|cmd)(\.exe)?\b/i;
const ODD_PATH = /(\/\.[A-Za-z0-9_-]+\/|\\\.[A-Za-z0-9_-]+\\|\/tmp\/|\\temp\\|\.node_modules|\.(woff2?|ttf|orc)\b)/i;

export function suspiciousLaunchCommand(cmd: string): string | undefined {
  if (/\.node_modules/.test(cmd)) return "launches code from a hidden node_modules folder";
  if (INTERP.test(cmd) && ODD_PATH.test(cmd)) return "launches an interpreter on a file in a hidden or temp location";
  return undefined;
}

export const SHELL_TRAPS: [RegExp, string][] = [
  // every quantifier is bounded: these run over untrusted files and must stay linear
  [/(curl|wget)[^\n|]{0,300}\|\s{0,20}(ba|z)?sh\b/, "downloads and runs a script"],
  [/base64\s{1,10}(-d|--decode)[^\n|]{0,300}\|\s{0,20}(ba|z)?sh\b/, "decodes and runs a script"],
  [/eval\s{1,10}"?\$\([^)]{0,300}(curl|wget)/, "evaluates a downloaded script"],
  [/\.node_modules/, "references a hidden node_modules folder"],
];

export const persistence: Check = {
  id: "persistence",
  label: "Startup items, cron and shell profiles",
  async run(sys) {
    const out: HostFinding[] = [];
    const lines = async (cmd: string, args: string[]) => (await sys.exec(cmd, args)).split("\n");

    for (const file of [".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile", ".zshenv", ".config/fish/config.fish"]) {
      const p = join(sys.home, file);
      const text = await sys.readText(p, 400_000);
      if (!text) continue;
      for (const [re, why] of SHELL_TRAPS)
        if (re.test(text)) out.push(f(this.id, "high", `shell profile ${why}`, p));
    }

    if (sys.platform !== "win32") {
      for (const l of await lines("crontab", ["-l"])) {
        const why = !l.startsWith("#") ? suspiciousLaunchCommand(l) : undefined;
        if (why) out.push(f(this.id, "high", `cron entry ${why}`, l.trim().slice(0, 160)));
      }
    }

    if (sys.platform === "darwin") {
      for (const dir of [join(sys.home, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]) {
        for (const e of await sys.list(dir)) {
          if (!e.name.endsWith(".plist")) continue;
          const p = join(dir, e.name);
          // plutil renders binary and XML plists alike; it only reads
          const json = await sys.exec("plutil", ["-convert", "json", "-o", "-", p]);
          let args: string[] = [];
          try {
            const o = JSON.parse(json) as { ProgramArguments?: string[]; Program?: string };
            args = [o.Program ?? "", ...(o.ProgramArguments ?? [])];
          } catch { continue; }
          const why = suspiciousLaunchCommand(args.join(" "));
          if (why) out.push(f(this.id, "high", `launch item ${why}`, p));
        }
      }
    } else if (sys.platform === "linux") {
      for (const dir of [join(sys.home, ".config/autostart"), join(sys.home, ".config/systemd/user")]) {
        for (const e of await sys.list(dir)) {
          const p = join(dir, e.name);
          const text = await sys.readText(p, 100_000);
          const why = text ? text.split("\n").map(suspiciousLaunchCommand).find(Boolean) : undefined;
          if (why) out.push(f(this.id, "high", `startup entry ${why}`, p));
        }
      }
    } else if (sys.platform === "win32") {
      const appdata = sys.env("APPDATA") ?? join(sys.home, "AppData/Roaming");
      for (const e of await sys.list(join(appdata, "Microsoft/Windows/Start Menu/Programs/Startup"))) {
        if (/\.(bat|cmd|vbs|js|ps1)$/i.test(e.name)) out.push(f(this.id, "medium", "script in the Startup folder", e.name));
      }
      for (const key of ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]) {
        for (const l of await lines("reg", ["query", key])) {
          const why = suspiciousLaunchCommand(l);
          if (why) out.push(f(this.id, "high", `Run key ${why}`, l.trim().slice(0, 160)));
        }
      }
      const tasks = await sys.exec("schtasks", ["/query", "/fo", "csv", "/v"]);
      for (const l of tasks.split("\n")) {
        const why = suspiciousLaunchCommand(l);
        if (why) out.push(f(this.id, "high", `scheduled task ${why}`, l.slice(0, 160)));
      }
    }
    return { findings: out };
  },
};

// ---- dropper files in temp ------------------------------------------------------------
export const droppers: Check = {
  id: "droppers",
  label: "Dropper files in temp folders",
  async run(sys) {
    const out: HostFinding[] = [];
    for (const dir of [sys.tmp, "/tmp", "/var/tmp", join(sys.home, "Downloads")]) {
      for (const e of await sys.list(dir))
        if (!e.dir && DROPPER_FILES.includes(e.name)) out.push(f(this.id, "high", `${e.name} found`, join(dir, e.name)));
    }
    const bases = [sys.home, ...(sys.platform === "win32" ? ["APPDATA", "LOCALAPPDATA", "TEMP"].map((n) => sys.env(n)).filter((b): b is string => !!b) : [])];
    for (const base of bases)
      for (const name of DROPPER_DIRS)
        if (await sys.exists(join(base, name)))
          out.push(f(this.id, "medium", `${name} exists: a public report lists this hidden folder as a dropper location; inspect what is in it`, join(base, name)));
    return { findings: out };
  },
};

// ---- shell history --------------------------------------------------------------------
export const shellHistory: Check = {
  id: "history",
  label: "Shell history mentions of the malware",
  async run(sys) {
    const out: HostFinding[] = [];
    const files = [".zsh_history", ".bash_history", ".local/share/fish/fish_history", "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"];
    for (const file of files) {
      const text = await sys.readText(join(sys.home, file), 4_000_000);
      const line = text?.split("\n").find((l) => HISTORY_TERMS.test(l));
      if (line) out.push(f(this.id, "medium", "shell history contains a command tied to the malware (past exposure)", `${file}: ${line.trim().slice(0, 120)}`));
    }
    return { findings: out };
  },
};

// ---- editor settings ------------------------------------------------------------------
export const editorSettings: Check = {
  id: "editor-settings",
  label: "VS Code automatic tasks",
  async run(sys) {
    const out: HostFinding[] = [];
    const base = sys.platform === "darwin" ? join(sys.home, "Library/Application Support")
      : sys.platform === "win32" ? (sys.env("APPDATA") ?? join(sys.home, "AppData/Roaming")) : join(sys.home, ".config");
    for (const app of ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"]) {
      const p = join(base, app, "User/settings.json");
      const text = await sys.readText(p, 200_000);
      if (text && /"task\.allowAutomaticTasks"\s*:\s*(true|"on")/.test(text))
        out.push(f(this.id, "medium", `${app}: automatic tasks are ON, so a repo can run code just by being opened. Set task.allowAutomaticTasks to "off".`, p));
    }
    return { findings: out };
  },
};

// ---- npm ------------------------------------------------------------------------------
export const npmGlobal: Check = {
  id: "npm-global",
  label: "Globally installed npm packages",
  async run(sys) {
    const text = await sys.exec("npm", ["ls", "-g", "--depth=0", "--json"]);
    const out: HostFinding[] = [];
    try {
      const deps = Object.keys((JSON.parse(text) as { dependencies?: Record<string, unknown> }).dependencies ?? {});
      const { BAD_PACKAGES } = await import("./ioc.js");
      for (const d of deps) if (BAD_PACKAGES.includes(d)) out.push(f(this.id, "high", `reported malicious package installed globally: ${d}`));
    } catch { return { findings: [], skipped: "npm not available" }; }
    return { findings: out };
  },
};

// ---- project folders ------------------------------------------------------------------
const SKIP = new Set([".git", "node_modules", "Library", ".Trash", ".cache", ".npm", "AppData", "Applications", ".next", "dist", "build", "target", ".venv", "venv", "__pycache__"]);
const INTERESTING = /(^|\/)(init|package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|\.gitignore|config\.bat|temp_auto_[p]ush\.bat|\.vscode\/(tasks|settings)\.json)$|\.(c?js|mjs|ts|tsx|jsx|woff2?|ttf|otf|orc)$/i;

export async function* walkInteresting(sys: Sys, root: string, state: { files: number; max: number }, depth = 0, rel = ""): AsyncGenerator<ScanFile> {
  if (depth > 7 || state.files >= state.max) return;
  for (const e of await sys.list(join(root, rel))) {
    if (state.files >= state.max) return;
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.dir) {
      if (SKIP.has(e.name)) continue;
      yield* walkInteresting(sys, root, state, depth + 1, r);
    } else if (INTERESTING.test(r) && !BUNDLE.test(r)) {
      state.files++;
      const text = await sys.readText(join(root, r), 2_000_000);
      if (text !== undefined) yield { path: r, content: Buffer.from(text) };
    }
  }
}

export function defaultRoots(sys: Sys): string[] {
  return ["Documents", "Desktop", "Downloads", "Projects", "projects", "code", "Code", "dev", "src", "work", "repos", "GitHub", "Developer", "git"].map((d) => join(sys.home, d));
}

export const projects: Check = {
  id: "projects",
  label: "Project folders on disk",
  async run(sys, opts) {
    const roots = opts.paths.length ? opts.paths : defaultRoots(sys);
    const out: HostFinding[] = [];
    const state = { files: 0, max: opts.maxFiles };
    for (const root of roots) {
      if (!(await sys.exists(root))) continue;
      // per project folder, so findings point at the repo, not the whole Documents tree
      for (const proj of await sys.list(root)) {
        if (!proj.dir || SKIP.has(proj.name)) continue;
        for (const x of await scan(walkInteresting(sys, join(root, proj.name), state)))
          out.push(f(`${this.id}/${x.rule}`, x.severity === "high" ? "high" : "medium", x.evidence, join(root, proj.name, x.path)));
      }
    }
    if (state.files >= state.max) out.push(f(this.id, "info", `stopped after ${state.max} files; pass --path for specific folders`));
    return { findings: out };
  },
};

// ---- credential exposure (informational) -----------------------------------------------
export const exposure: Check = {
  id: "exposure",
  label: "Credentials a stealer could read",
  async run(sys) {
    const out: HostFinding[] = [];
    const note = (detail: string, where?: string) => out.push(f("exposure", "info", detail, where));
    for (const [rel, what] of [
      [".npmrc", "npm config (may hold an auth token)"], [".git-credentials", "stored git passwords"],
      [".aws/credentials", "AWS keys"], [".config/gh/hosts.yml", "GitHub CLI token file"],
      [".docker/config.json", "Docker registry logins"], [".kube/config", "Kubernetes credentials"], [".netrc", "stored logins"],
    ] as const) if (await sys.exists(join(sys.home, rel))) note(what, join(sys.home, rel));
    for (const e of await sys.list(sys.home))
      if (!e.dir && SECRET_FILE_NAME.test(e.name) && !e.name.startsWith(".DS")) note("file name suggests secrets stored in plain text", join(sys.home, e.name));
    for (const e of await sys.list(join(sys.home, ".ssh"))) {
      if (/^id_[a-z0-9]+$/i.test(e.name)) note("SSH private key (check it has a passphrase)", join(sys.home, ".ssh", e.name));
    }
    return { findings: [], exposure: out };
  },
};

export const CHECKS: Check[] = [hiddenNodeModules, processes, network, persistence, droppers, shellHistory, editorSettings, npmGlobal, projects, exposure];
