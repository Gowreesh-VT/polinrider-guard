import os from "node:os";
import path from "node:path";
import { defineConfig } from "vitest/config";

// tests must never touch the real undo journal
process.env.GITWARD_JOURNAL = path.join(os.tmpdir(), `guard-test-journal-${process.pid}.jsonl`);
export default defineConfig({});
