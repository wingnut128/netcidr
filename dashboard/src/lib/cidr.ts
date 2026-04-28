/**
 * Client-side CIDR helpers for the IPAM Visualizer.
 *
 * IPv4 only for now — `start`/`end` are stored as 32-bit unsigned ints in
 * regular `number` (JS numbers are safe up to 2^53). IPv6 visualizer support
 * would need BigInt and is out of scope.
 */

export interface ParsedCidr {
  cidr: string;
  prefix: number;
  start: number; // network address as u32
  end: number; // broadcast address as u32 (inclusive)
  size: number; // 2^(32-prefix)
}

const IPV4 = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;

function ipToInt(ip: string): number | null {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return null;
  for (const p of parts) {
    if (!Number.isInteger(p) || p < 0 || p > 255) return null;
  }
  const [a, b, c, d] = parts as [number, number, number, number];
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

export function parseCidr(input: string): ParsedCidr | null {
  const m = input.trim().match(IPV4);
  if (!m || !m[1] || !m[2]) return null;
  const ip = ipToInt(m[1]);
  const prefix = Number(m[2]);
  if (ip === null || prefix < 0 || prefix > 32) return null;
  // Network address: zero out host bits.
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (ip & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  const end = (start + size - 1) >>> 0;
  return { cidr: `${intToIp(start)}/${prefix}`, prefix, start, end, size };
}

export function intToIp(n: number): string {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join(".");
}

/** Return value indicates how `candidate` relates to `existing`. */
export type Overlap = "disjoint" | "contained" | "contains" | "overlap";

export function relate(candidate: ParsedCidr, existing: ParsedCidr): Overlap {
  if (candidate.end < existing.start || candidate.start > existing.end) {
    return "disjoint";
  }
  if (candidate.start >= existing.start && candidate.end <= existing.end) {
    return "contained";
  }
  if (candidate.start <= existing.start && candidate.end >= existing.end) {
    return "contains";
  }
  return "overlap";
}

export type FitVerdict =
  | { kind: "fits"; reason: string }
  | { kind: "conflict"; with: ParsedCidr; reason: string }
  | { kind: "outside"; reason: string }
  | { kind: "invalid"; reason: string };

/**
 * Decide whether `candidate` could be allocated cleanly within `supernet`
 * given `taken` (active+reserved allocations). The block must:
 *   - be a valid IPv4 CIDR
 *   - sit entirely inside `supernet`
 *   - not overlap any taken allocation
 */
export function checkFit(
  raw: string,
  supernet: ParsedCidr,
  taken: ParsedCidr[],
): FitVerdict {
  const candidate = parseCidr(raw);
  if (!candidate) {
    return { kind: "invalid", reason: "Not a valid IPv4 CIDR" };
  }
  if (relate(candidate, supernet) !== "contained") {
    return {
      kind: "outside",
      reason: `${candidate.cidr} is not contained within ${supernet.cidr}`,
    };
  }
  for (const t of taken) {
    const r = relate(candidate, t);
    if (r !== "disjoint") {
      return {
        kind: "conflict",
        with: t,
        reason:
          r === "contained"
            ? `Already inside existing allocation ${t.cidr}`
            : r === "contains"
              ? `Overlaps existing allocation ${t.cidr}`
              : `Partial overlap with existing allocation ${t.cidr}`,
      };
    }
  }
  return { kind: "fits", reason: "No conflicts" };
}
