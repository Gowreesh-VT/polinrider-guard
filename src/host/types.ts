export type HostSeverity = "high" | "medium" | "info";

export interface HostFinding {
  check: string;
  severity: HostSeverity;
  detail: string;
  /** file, process or address involved, when there is one */
  where?: string;
}

export type Verdict = "likely-infected" | "suspicious" | "clear";

export interface HostResult {
  generatedAt: string;
  platform: string;
  verdict: Verdict;
  findings: HostFinding[];
  /** credentials a stealer could have read; informational, never changes the verdict */
  exposure: HostFinding[];
  checked: string[];
  skipped: string[];
  advice: string[];
}
