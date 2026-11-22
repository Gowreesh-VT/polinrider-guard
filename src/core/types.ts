export type Severity = "high" | "medium" | "low";

export interface ScanFile {
  /** path relative to the scanned root, forward slashes */
  path: string;
  /** raw bytes; rules must treat as untrusted data and never execute it */
  content: Buffer;
}

export interface Finding {
  rule: string;
  severity: Severity;
  path: string;
  /** short human-readable proof, never the full payload */
  evidence: string;
}

export interface Rule {
  id: string;
  severity: Severity;
  check(file: ScanFile): Finding[];
}
