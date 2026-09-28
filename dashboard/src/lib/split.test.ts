import { describe, expect, it } from "vitest";
import { fmtAddressCount, parsePrefixList, treeSubnetCount } from "./split";

describe("parsePrefixList", () => {
  it("parses comma-separated prefixes, tolerating spaces and slashes", () => {
    expect(parsePrefixList("26, 28,/28")).toEqual([26, 28, 28]);
  });

  it("rejects empty input", () => {
    expect(() => parsePrefixList(" ")).toThrow(/at least one prefix/);
  });

  it("rejects non-numeric and empty entries", () => {
    expect(() => parsePrefixList("26,,28")).toThrow(/Invalid prefix length/);
    expect(() => parsePrefixList("26,abc")).toThrow(/Invalid prefix length: abc/);
  });

  it("rejects out-of-range prefixes", () => {
    expect(() => parsePrefixList("129")).toThrow(/Invalid prefix length: 129/);
  });
});

describe("treeSubnetCount", () => {
  it("sums the subnets generated at each level", () => {
    // /18 -> 16 x /22 -> 64 x /24
    expect(treeSubnetCount(18, [22, 24])).toBe(16 + 64);
  });

  it("grows past the dashboard limit for large trees", () => {
    // /8 -> 256 x /16 -> 65536 x /24
    expect(treeSubnetCount(8, [16, 24])).toBe(256 + 65536);
  });

  it("returns 0 when no steps are given", () => {
    expect(treeSubnetCount(24, [])).toBe(0);
  });
});

describe("fmtAddressCount", () => {
  it("uses the compact K/M/B form for IPv4-scale counts", () => {
    expect(fmtAddressCount("96")).toBe("96");
    expect(fmtAddressCount("16777216")).toBe("16.8M");
  });

  it("uses scientific notation for IPv6-scale decimal strings", () => {
    expect(fmtAddressCount("80280230208783968632832")).toBe("8.03e+22");
  });

  it("passes through non-numeric values", () => {
    expect(fmtAddressCount("2^76")).toBe("2^76");
  });
});
