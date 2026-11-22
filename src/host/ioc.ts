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

export const SECRET_FILE_NAME = /(secret|credential|passwd|password|token|apikey|api[-_]key|private[-_]key)/i;
