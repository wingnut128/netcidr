/** Helpers for the Splitter page's VLSM and hierarchical (steps) modes. */

import { fmtSize } from "./format";

/**
 * Largest split tree the dashboard will request. The API allows up to
 * 1,000,000 subnets, which is far more rows than a browser table can render
 * usefully; larger trees belong in the CLI or API.
 */
export const MAX_TREE_SUBNETS = 4096;

/**
 * Parse a comma-separated list of prefix lengths ("26, 28,/28").
 * Ordering rules (descending for VLSM, strictly increasing for steps) are
 * left to the API, which reports them precisely.
 */
export function parsePrefixList(input: string): number[] {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Enter at least one prefix length");
  }
  return trimmed.split(",").map((raw) => {
    const part = raw.trim().replace(/^\//, "");
    const n = Number(part);
    if (!/^\d+$/.test(part) || n > 128) {
      throw new Error(`Invalid prefix length: ${part || "(empty)"}`);
    }
    return n;
  });
}

/** Total subnets a hierarchical split generates across all levels (root excluded). */
export function treeSubnetCount(parentPrefix: number, steps: number[]): number {
  return steps.reduce((sum, step) => sum + 2 ** (step - parentPrefix), 0);
}

/**
 * Format an address count sent as a decimal string. IPv6 counts overflow
 * fmtSize's K/M/B scale (e.g. "80280230208783.0B"), so switch to scientific
 * notation past a trillion.
 */
export function fmtAddressCount(value: string): string {
  const n = Number(value);
  if (!Number.isFinite(n)) return value;
  return n >= 1e12 ? n.toExponential(2) : fmtSize(n);
}
