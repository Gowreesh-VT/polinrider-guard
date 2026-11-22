import type { Finding, Rule, ScanFile } from "./types.js";
import { paddedPayload } from "./rules/padded-payload.js";
import { initFile, packageHook } from "./rules/init-loader.js";
import { vscodeAutorun } from "./rules/vscode.js";
import { knownBadPackage } from "./rules/bad-packages.js";
import { decodeExec, gitignoreDropper, dropperFile } from "./rules/loaders.js";
import { knownSignature, suspiciousEndpoint, evalNetwork, obfuscated, credentialAccess, shellDownloadExec, gitAmendPush, devcontainerHook, workflowRisk, packageScripts, injectedPrelude } from "./rules/behavior.js";
import { mediaChecks } from "./rules/binary.js";

export const RULES: Rule[] = [
  paddedPayload, initFile, packageHook, vscodeAutorun,
  decodeExec, gitignoreDropper, dropperFile, knownBadPackage,
  knownSignature, suspiciousEndpoint, evalNetwork, obfuscated, credentialAccess, shellDownloadExec,
  gitAmendPush, devcontainerHook, workflowRisk, packageScripts, injectedPrelude, mediaChecks,
];

/** Inside node_modules/vendor folders only the strongest evidence counts; everything else is noise. */
export const VENDOR_RULES: Rule[] = [knownSignature];

// Test fixtures, examples and docs often contain malware-shaped samples on purpose (security tools especially).
const FIXTURE_DIR = /(^|\/)(tests?|__tests__|spec|fixtures?|examples?|samples?|docs?)\//i;
const CAPPED = new Set(["package-scripts", "shell-download-exec", "credential-access", "git-amend-force-push", "eval-network", "obfuscated"]);

export function scanFile(file: ScanFile, rules: Rule[] = RULES): Finding[] {
  const found = rules.flatMap((r) => r.check(file));
  if (!FIXTURE_DIR.test(file.path)) return found;
  return found.map((f) => (CAPPED.has(f.rule) && f.severity !== "low" ? { ...f, severity: "low" as const, evidence: `${f.evidence} (in a test/example folder)` } : f));
}

export async function scan(
  files: AsyncIterable<ScanFile> | Iterable<ScanFile>,
  rules: Rule[] = RULES,
): Promise<Finding[]> {
  const out: Finding[] = [];
  for await (const f of files) out.push(...scanFile(f, rules));
  return out;
}
