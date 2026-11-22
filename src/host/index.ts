import type { Sys } from "./sys.js";
import { CHECKS, type HostOptions } from "./checks.js";
import type { HostFinding, HostResult, Verdict } from "./types.js";
import { safe } from "../safe.js";

/** Host-level indicators mean the machine itself may be compromised; project hits mean files to clean. */
const isProject = (f: HostFinding) => f.check.startsWith("projects");

export function decide(findings: HostFinding[]): Verdict {
  if (findings.some((f) => f.severity === "high" && !isProject(f))) return "likely-infected";
  if (findings.some((f) => f.severity !== "info")) return "suspicious";
  return "clear";
}

export function adviceFor(verdict: Verdict, findings: HostFinding[], exposure: HostFinding[]): string[] {
  const a: string[] = [];
  if (verdict === "likely-infected") {
    a.push("Treat this computer as compromised. From a DIFFERENT, clean device: change your GitHub password, revoke all sessions, authorized OAuth apps and personal access tokens, regenerate recovery codes, and remove unknown SSH keys.");
    a.push("Rotate every secret that was on this machine: .env files, npm tokens, cloud and database keys, and saved browser passwords.");
    a.push("Do not just delete the files you found: the malware may have set up a startup item. Back up your own files, then reinstall the operating system.");
  }
  if (findings.some(isProject)) a.push("Projects on disk contain the malware. Do not open them in VS Code until cleaned; run `gitward report` on their repos, or delete the folders and re-clone from a cleaned remote.");
  if (findings.some((f) => f.check === "editor-settings")) a.push('Set "task.allowAutomaticTasks": "off" in your VS Code user settings.');
  if (exposure.length) a.push("If any of the credentials listed under exposure were on this machine while it may have been infected, rotate them.");
  a.push("A clear result only means nothing was found right now. This malware can run once, steal what it can and remove itself, so if you opened an infected project, rotate your credentials anyway.");
  return a;
}

export async function runHostCheck(sys: Sys, opts: Partial<HostOptions> = {}, onStep?: (label: string) => void): Promise<HostResult> {
  const o: HostOptions = { paths: opts.paths ?? [], maxFiles: opts.maxFiles ?? 200_000 };
  const findings: HostFinding[] = [], exposure: HostFinding[] = [], checked: string[] = [], skipped: string[] = [];
  for (const c of CHECKS) {
    onStep?.(c.label);
    try {
      const r = await c.run(sys, o);
      findings.push(...r.findings);
      exposure.push(...(r.exposure ?? []));
      if (r.skipped) skipped.push(`${c.label}: ${r.skipped}`); else checked.push(c.label);
    } catch (e) {
      skipped.push(`${c.label}: ${(e as Error).message}`);
    }
  }
  const verdict = decide(findings);
  return { generatedAt: new Date().toISOString(), platform: sys.platform, verdict, findings, exposure, checked, skipped, advice: adviceFor(verdict, findings, exposure) };
}

export function formatHost(r: HostResult): string {
  const L: string[] = [];
  const label = { "likely-infected": "LIKELY INFECTED", suspicious: "SUSPICIOUS", clear: "CLEAR (nothing found)" }[r.verdict];
  L.push(`Computer check (${r.platform}): ${label}`, "");
  for (const f of r.findings) L.push(`[${f.severity.toUpperCase()}] ${f.check}: ${safe(f.detail)}${f.where ? `\n         ${safe(f.where)}` : ""}`);
  if (r.exposure.length) {
    L.push("", "Credentials a stealer could read if this machine was infected:");
    for (const e of r.exposure) L.push(`  - ${safe(e.detail)}${e.where ? `  ${safe(e.where)}` : ""}`);
  }
  L.push("", `Checked: ${r.checked.join("; ")}.`);
  if (r.skipped.length) L.push(`Skipped: ${r.skipped.join("; ")}.`);
  L.push("", "What to do:", ...r.advice.map((x) => `  - ${x}`));
  return L.join("\n");
}
