import type { Finding, Rule, ScanFile } from "../types.js";
import { snippet } from "../text.js";

const MAGIC: Record<string, Buffer[]> = {
  ".woff2": [Buffer.from("wOF2")], ".woff": [Buffer.from("wOFF")],
  ".ttf": [Buffer.from([0, 1, 0, 0]), Buffer.from("true"), Buffer.from("ttcf")], ".otf": [Buffer.from("OTTO")],
  ".png": [Buffer.from([0x89, 0x50, 0x4e, 0x47])], ".jpg": [Buffer.from([0xff, 0xd8])], ".jpeg": [Buffer.from([0xff, 0xd8])],
  ".gif": [Buffer.from("GIF8")], ".webp": [Buffer.from("RIFF")],
};
const FONT = /\.(woff2?|ttf|otf|eot|orc)$/i;
const MEDIA = /\.(png|jpe?g|gif|webp|ico|bmp|woff2?|ttf|otf|eot|orc)$/i;
const CODE = /eval\s*\(|new\s+Function\s*\(|global\[|require\s*\(\s*['"]|\batob\s*\(|process\.env|child_process|String\.fromCharCode\s*\(|<script|powershell|\/bin\/(?:ba)?sh\b|\bcurl\s+-|\bwget\s+|module\.exports|\(function\s*\(/;
const KNOWN = new RegExp("rmcej" + "%otb%|_\\$_1e42|global\\['!'\\]|global\\['_V'\\]|AUTH_API_KEY|eval\\(proxyInfo\\)|temp_auto_" + "push");

const ext = (p: string) => (/\.[A-Za-z0-9]+$/.exec(p)?.[0] ?? "").toLowerCase();

function printable(b: Buffer): boolean {
  if (!b.length) return false;
  let ok = 0;
  for (const c of b) if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++;
  return ok / b.length > 0.97;
}

/** Bytes after the point where a valid file of this type should end, or undefined if unknown. */
export function trailingBytes(e: string, d: Buffer): number | undefined {
  const n = d.length;
  try {
    if (e === ".png") { const i = d.lastIndexOf(Buffer.from([0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82])); return i >= 0 ? n - (i + 8) : undefined; }
    if (e === ".jpg" || e === ".jpeg") { const i = d.lastIndexOf(Buffer.from([0xff, 0xd9])); return i >= 0 ? n - (i + 2) : undefined; }
    if (e === ".gif" && d.subarray(0, 3).toString() === "GIF") return n - (d.lastIndexOf(0x3b) + 1);
    if ((e === ".woff" || e === ".woff2") && ["wOFF", "wOF2"].includes(d.subarray(0, 4).toString())) return n - d.readUInt32BE(8);
    if ((e === ".ttf" || e === ".otf") && (d.readUInt32BE(0) === 0x00010000 || ["OTTO", "true"].includes(d.subarray(0, 4).toString()))) {
      let end = 0;
      for (let i = 0, nt = d.readUInt16BE(4); i < nt; i++) end = Math.max(end, d.readUInt32BE(12 + 16 * i + 8) + d.readUInt32BE(12 + 16 * i + 12));
      return n - Math.ceil(end / 4) * 4;
    }
    if (e === ".webp" && d.subarray(0, 4).toString() === "RIFF") return n - (d.readUInt32LE(4) + 8);
  } catch { return undefined; }
  return undefined;
}

export const mediaChecks: Rule = {
  id: "media-check",
  severity: "high",
  check(file: ScanFile): Finding[] {
    const e = ext(file.path);
    if (!MEDIA.test(file.path)) return [];
    const d = file.content;
    const out: Finding[] = [];
    const head = d.subarray(0, 600);

    // a "font" or "image" that is really text: the malware's fake font files
    const magics = MAGIC[e];
    const notReal = magics ? !magics.some((m) => d.subarray(0, m.length).equals(m)) : FONT.test(file.path) && e === ".orc";
    if (printable(head) && (notReal || FONT.test(file.path)) && /require\(|\bfunction[\s(]|\beval\(|global\[|\bconst |\bvar |\bimport |module\.exports|process\.|#!\//.test(head.toString("latin1")))
      out.push({ rule: "fake-binary", severity: "high", path: file.path, evidence: `${e.slice(1)} file is JavaScript text: ${snippet(head.toString("latin1"), 50)}` });

    const t = trailingBytes(e, d);
    if (t !== undefined && t > 32) {
      const tail = d.subarray(d.length - t).toString("latin1");
      const c = CODE.exec(tail);
      if (c) out.push({ rule: "media-trailing-code", severity: "high", path: file.path, evidence: `${t} extra bytes after the end of the file, containing ${snippet(c[0], 30)}` });
    }
    if (!out.length) {
      const text = d.toString("latin1");
      const k = KNOWN.exec(text);
      if (k) out.push({ rule: "media-trailing-code", severity: "high", path: file.path, evidence: `known marker hidden inside the file: ${snippet(k[0], 30)}` });
    }
    return out;
  },
};
