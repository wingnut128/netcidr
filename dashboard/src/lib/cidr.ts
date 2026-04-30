/**
 * Client-side CIDR helpers for the IPAM Visualizer.
 *
 * Dual-stack: handles IPv4 and IPv6. Address arithmetic uses BigInt
 * because IPv6 spaces don't fit in JS's safe-integer range (2^53).
 * IPv4 addresses round-trip through bigint too — at the cost of a
 * little overhead, all consumers get one uniform type to work with.
 */

export type IpKind = "v4" | "v6";

export interface ParsedCidr {
  cidr: string; // canonical form, network address + prefix
  kind: IpKind;
  bits: 32 | 128; // address width
  prefix: number; // 0..32 (v4) or 0..128 (v6)
  start: bigint; // network address (inclusive)
  end: bigint; // last address in the block (inclusive)
  size: bigint; // 2^(bits - prefix)
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
// Permissive — actual validation happens via Address parsing below.
const IPV6_RE = /^([0-9a-fA-F:]+)\/(\d{1,3})$/;

// ──────────────────────────── IPv4 ──────────────────────────────

function v4ToBigInt(parts: number[]): bigint | null {
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!Number.isInteger(p) || p < 0 || p > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}

export function bigIntToV4(n: bigint): string {
  return [
    Number((n >> 24n) & 0xffn),
    Number((n >> 16n) & 0xffn),
    Number((n >> 8n) & 0xffn),
    Number(n & 0xffn),
  ].join(".");
}

// ──────────────────────────── IPv6 ──────────────────────────────

/**
 * Parse a (possibly compressed) IPv6 address into a 128-bit BigInt.
 * Accepts the standard `::` zero-run shorthand. Rejects scoped (`%`)
 * and IPv4-mapped (`::ffff:1.2.3.4`) forms — IPAM data shouldn't have
 * either, and supporting them adds parsing surface for no benefit.
 */
function v6ToBigInt(addr: string): bigint | null {
  if (addr.includes("%")) return null;
  // Reject embedded IPv4 (mapped/translated) — out of scope here.
  if (addr.includes(".")) return null;

  const doubleColonCount = (addr.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) return null;

  let parts: string[];
  if (doubleColonCount === 1) {
    const [head, tail] = addr.split("::");
    const headParts = head ? head.split(":") : [];
    const tailParts = tail ? tail.split(":") : [];
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    parts = [...headParts, ...Array(missing).fill("0"), ...tailParts];
  } else {
    parts = addr.split(":");
  }

  if (parts.length !== 8) return null;

  let n = 0n;
  for (const p of parts) {
    if (p.length === 0 || p.length > 4 || !/^[0-9a-fA-F]+$/.test(p)) return null;
    n = (n << 16n) | BigInt(parseInt(p, 16));
  }
  return n;
}

/**
 * Render a 128-bit BigInt as a canonical (RFC 5952) IPv6 string.
 * Lowercase hex, longest run of zero hextets compressed to `::`.
 */
export function bigIntToV6(n: bigint): string {
  const hextets: string[] = [];
  for (let i = 7; i >= 0; i--) {
    const v = Number((n >> BigInt(i * 16)) & 0xffffn);
    hextets.push(v.toString(16));
  }

  // Find the longest run of "0" hextets (length ≥ 2). Ties: leftmost.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (hextets[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) return hextets.join(":");

  const left = hextets.slice(0, bestStart).join(":");
  const right = hextets.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

// ──────────────────────────── Common ────────────────────────────

function maskBigInt(bits: 32 | 128, prefix: number): bigint {
  if (prefix === 0) return 0n;
  const total = bits === 32 ? 32n : 128n;
  return ((1n << BigInt(prefix)) - 1n) << (total - BigInt(prefix));
}

export function bigIntToIp(n: bigint, kind: IpKind): string {
  return kind === "v4" ? bigIntToV4(n) : bigIntToV6(n);
}

export function parseCidr(input: string): ParsedCidr | null {
  const trimmed = input.trim();

  const v4 = trimmed.match(IPV4_RE);
  if (v4) {
    const ip = v4ToBigInt([Number(v4[1]), Number(v4[2]), Number(v4[3]), Number(v4[4])]);
    const prefix = Number(v4[5]);
    if (ip === null || prefix < 0 || prefix > 32) return null;
    const mask = maskBigInt(32, prefix);
    const start = ip & mask;
    const size = 1n << BigInt(32 - prefix);
    const end = start + size - 1n;
    return {
      cidr: `${bigIntToV4(start)}/${prefix}`,
      kind: "v4",
      bits: 32,
      prefix,
      start,
      end,
      size,
    };
  }

  const v6 = trimmed.match(IPV6_RE);
  if (v6) {
    const ip = v6ToBigInt(v6[1]!);
    const prefix = Number(v6[2]);
    if (ip === null || prefix < 0 || prefix > 128) return null;
    const mask = maskBigInt(128, prefix);
    const start = ip & mask;
    const size = 1n << BigInt(128 - prefix);
    const end = start + size - 1n;
    return {
      cidr: `${bigIntToV6(start)}/${prefix}`,
      kind: "v6",
      bits: 128,
      prefix,
      start,
      end,
      size,
    };
  }

  return null;
}

/**
 * Backwards-compatible alias used by existing callers that expected a
 * v4-only `intToIp(n: number)`. Now BigInt-only.
 */
export function intToIp(n: bigint): string {
  return bigIntToV4(n);
}

/** Return value indicates how `candidate` relates to `existing`. */
export type Overlap = "disjoint" | "contained" | "contains" | "overlap";

export function relate(candidate: ParsedCidr, existing: ParsedCidr): Overlap {
  if (candidate.kind !== existing.kind) return "disjoint";
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
 *   - parse as a valid CIDR (v4 or v6)
 *   - share an address family with `supernet`
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
    return { kind: "invalid", reason: "Not a valid IPv4 or IPv6 CIDR" };
  }
  if (candidate.kind !== supernet.kind) {
    return {
      kind: "outside",
      reason: `${candidate.cidr} is ${candidate.kind} but supernet is ${supernet.kind}`,
    };
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
