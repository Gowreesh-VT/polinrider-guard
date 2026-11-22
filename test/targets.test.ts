import { describe, it, expect } from "vitest";
import { isExcluded } from "../src/targets.js";
import { parseAccounts } from "../src/accounts.js";
import { mapPool } from "../src/pool.js";

describe("targets", () => {
  it("excludes by owner prefix, case-insensitively", () => {
    expect(isExcluded("AWS-Cloud-Club-VITC/frontier", ["aws-cloud-club-vitc/"])).toBe(true);
    expect(isExcluded("me/frontier", ["aws-cloud-club-vitc/"])).toBe(false);
  });
  it("parses gh auth status output for every account", () => {
    const text = "github.com\n  ✓ Logged in to github.com account Gowreesh-VT (keyring)\n  - Active account: true\n  ✓ Logged in to github.com account srisaidhakshini (keyring)\n";
    expect(parseAccounts(text)).toEqual(["Gowreesh-VT", "srisaidhakshini"]);
  });
  it("mapPool keeps order and respects the limit", async () => {
    let live = 0, peak = 0;
    const out = await mapPool([1, 2, 3, 4, 5, 6], 2, async (n) => {
      live++; peak = Math.max(peak, live);
      await new Promise((r) => setTimeout(r, 5)); live--; return n * 2;
    });
    expect(out).toEqual([2, 4, 6, 8, 10, 12]);
    expect(peak).toBeLessThanOrEqual(2);
  });
});
