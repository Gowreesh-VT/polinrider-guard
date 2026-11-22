/**
 * Indicators, with how well each is established. Behavior checks matter more than any list here.
 */

/**
 * VERIFIED 2026-11-21 against the live npm registry: each of these is now an npm "security holding"
 * package (0.0.1-security, no maintainers) or was unpublished, which is how npm replaces packages it removes
 * as malicious. Legitimately named neighbours such as tailwindcss-animate and tailwindcss-typography are real
 * packages with maintainers and are deliberately NOT listed.
 */
export const BAD_PACKAGES = [
  "tailwind-mainanimation",
  "tailwindcss-style-animate",
  "tailwind-autoanimation",
  "tailwind-animationbased",
  "tailwindcss-typography-style",
  "tailwindcss-style-modify",
  "tailwindcss-animate-style",
];

/**
 * UNVERIFIED: reported by one victim (hosted in Paris, ISP Ukrtelecom) as the address the in-memory variant fetched
 * its code from, and the server location reportedly changes between victims. Supporting evidence only: a hit raises
 * a warning but never decides a verdict.
 */
export const IOC_IPS = ["95.135.181.84"];

/** Files the malware drops or runs. */
export const DROPPER_FILES = ["temp_auto_" + "push.bat", "config.bat"];

/**
 * Hidden folders a public report lists as dropper locations in the home folder (and, on Windows, in
 * APPDATA, LOCALAPPDATA and TEMP). Unverified here: names like these can be legitimate, so a hit only
 * raises a warning to inspect the folder.
 */
export const DROPPER_DIRS = [".n2", ".npl", ".pyp", ".sysinfo", ".nlp"];

/** Terms that should never appear in a shell history unless someone ran or pasted the malware's commands. */
export const HISTORY_TERMS = new RegExp(
  ["vercel\\.app/settings", "default-" + "configuration", "260120\\.vercel", "api\\.trongrid", "aptoslabs",
   "temp_auto_" + "push", "node init\\b"].join("|"));

export const SECRET_FILE_NAME = /(secret|credential|passwd|password|token|apikey|api[-_]key|private[-_]key)/i;
