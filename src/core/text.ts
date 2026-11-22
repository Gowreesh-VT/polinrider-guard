import type { ScanFile } from "./types.js";

const MAX_TEXT = 2_000_000;

/** Returns utf8 text for plausible text files, otherwise undefined. */
export function asText(file: ScanFile): string | undefined {
  if (file.content.length > MAX_TEXT) return undefined;
  const head = file.content.subarray(0, 4096);
  if (head.includes(0)) return undefined;
  return file.content.toString("utf8");
}

export const base = (p: string) => p.slice(p.lastIndexOf("/") + 1);
export const snippet = (s: string, n = 80) =>
  s.replace(/\s+/g, " ").trim().slice(0, n);

/** Build output, minified bundles and vendored libraries legitimately have enormous lines. */
export const BUNDLE =
  /(^|\/)(dist|build|out|\.next|assets|vendor|vendors|third[-_]party|libs?)\/|\.min\.|-[A-Za-z0-9_-]{8}\.(c?js|mjs)$/;
