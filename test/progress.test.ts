import { describe, it, expect } from "vitest";
import { renderBar, fmtDuration } from "../src/progress.js";

describe("progress bar", () => {
  it("shows fill, count, percent and ETA", () => {
    const l = renderBar(50, 200, 0, 60_000, "me/repo", 100);
    expect(l).toContain("50/200"); expect(l).toContain("25%"); expect(l).toContain("ETA ~3m00s"); expect(l).toContain("me/repo");
    expect(l.length).toBeLessThan(100);
  });
  it("is full at the end with no ETA, and fits narrow terminals", () => {
    const l = renderBar(10, 10, 0, 5000, "a/b", 40);
    expect(l).toContain("100%"); expect(l).not.toContain("ETA"); expect(l.length).toBeLessThan(40);
  });
  it("strips control characters from repo names", () => {
    expect(renderBar(1, 2, 0, 1000, "x\x1b[31m/y", 100)).not.toContain("\x1b");
  });
  it("formats durations", () => { expect(fmtDuration(65_000)).toBe("1m05s"); expect(fmtDuration(3_700_000)).toBe("1h01m"); });
});
