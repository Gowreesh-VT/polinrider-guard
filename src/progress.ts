import { safe } from "./safe.js";

export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}h${String(m).padStart(2, "0")}m` : m ? `${m}m${String(sec).padStart(2, "0")}s` : `${sec}s`;
}

export function renderBar(done: number, total: number, startedAt: number, now: number, repo: string, columns: number): string {
  const frac = total ? Math.min(1, done / total) : 1;
  const elapsed = now - startedAt;
  const eta = done > 0 && done < total ? ` ETA ~${fmtDuration((elapsed / done) * (total - done))}` : "";
  const tail = ` ${String(done).padStart(String(total).length)}/${total} ${String(Math.floor(frac * 100)).padStart(3)}%  ${fmtDuration(elapsed)}${eta}`;
  const barW = Math.max(10, Math.min(30, columns - tail.length - 4));
  const filled = Math.round(frac * barW);
  const head = `[${"█".repeat(filled)}${"░".repeat(barW - filled)}]${tail}`;
  const room = columns - head.length - 3;
  const name = room > 8 && repo ? `  ${safe(repo).slice(0, room)}` : "";
  return (head + name).slice(0, Math.max(20, columns - 1));
}

/** Progress reporter: a live bar on a terminal, a line every ~10% when output is piped. */
export function makeProgress(label: string, stream: NodeJS.WriteStream = process.stderr) {
  const startedAt = Date.now();
  const tty = !!stream.isTTY;
  let lastPct = -1;
  const update = (done: number, total: number, repo: string) => {
    if (tty) {
      stream.write(`\r\x1b[2K${renderBar(done, total, startedAt, Date.now(), repo, stream.columns || 80)}`);
    } else {
      const pct = total ? Math.floor((done / total) * 10) : 10;
      if (pct !== lastPct || done === total) { lastPct = pct; stream.write(`${label}: ${done}/${total} (${Math.floor((done / Math.max(1, total)) * 100)}%)\n`); }
    }
  };
  const finish = () => { if (tty) stream.write("\n"); };
  return { update, finish };
}
