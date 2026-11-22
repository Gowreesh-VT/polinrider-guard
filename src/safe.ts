/** Text from repositories and processes is untrusted. Never let it drive the terminal or the report format. */

// C0/C1 control characters (including ESC, used by terminal escape sequences), except tab and newline
const CONTROL = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]", "g");

/** One printable line: no escape codes, no newlines, no bidirectional-override tricks. */
export function safe(s: string, max = 300): string {
  const t = s.replace(/[\r\n\t]+/g, " ").replace(CONTROL, "?");
  return t.length > max ? t.slice(0, max) + "..." : t;
}

/** Safe inside Markdown inline code and table cells. */
export function md(s: string, max = 300): string {
  return safe(s, max).replace(/`/g, "'").replace(/\|/g, "\\|");
}

const SECRETS: [RegExp, string][] = [
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[token]"], [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[token]"],
  [/\bsk-[A-Za-z0-9_-]{20,}/g, "[key]"], [/\bAKIA[0-9A-Z]{16}\b/g, "[key]"], [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, "[token]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{10,}/gi, "Bearer [token]"],
  [/(--?(?:token|password|passwd|secret|api[-_]?key|auth)[=\s]+)\S+/gi, "$1[redacted]"],
  [/(:\/\/[^\s:@/]+:)[^\s@/]+@/g, "$1[redacted]@"],
];

/** Mask credentials that appear in command lines before they are shown or written to a report. */
export function redact(s: string): string {
  return SECRETS.reduce((t, [re, to]) => t.replace(re, to), s);
}
