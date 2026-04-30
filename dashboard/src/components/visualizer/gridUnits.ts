/**
 * Address-space cellularization shared by Block and Hilbert views.
 *
 * Both grids walk the supernet at a fixed unit prefix, producing one
 * cell per `2^(unitPrefix - supernetPrefix)` slot. Each cell carries
 * the dominant allocation that touches it (for status-coloring) and
 * a CIDR label for the hover.
 */

import type { Allocation, FreeBlock } from "../../types";
import { bigIntToIp, type ParsedCidr } from "../../lib/cidr";

export type CellStatus = "active" | "reserved" | "released" | "free";

export interface Cell {
  index: number;
  startAddr: bigint;
  endAddr: bigint;
  cidr: string; // canonical CIDR for this cell (or range if it's a partial)
  status: CellStatus;
  allocation?: Allocation;
}

export interface GridLayout {
  unitPrefix: number; // CIDR length of one cell
  cellCount: number; // total cells = 2^(unitPrefix - supernetPrefix)
  cells: Cell[];
  truncatedToMin: boolean; // true when supernet was finer than the unit floor
}

const MAX_CELLS = 1024; // 32×32 — comfortable on a desktop, scrollable on mobile

/**
 * Smallest cell prefix the dashboard will render at. v6 supernets bigger
 * than ~/64 always coarsen — never try to draw individual /128s.
 */
const MIN_UNIT_PREFIX_V4 = 32;
const MIN_UNIT_PREFIX_V6 = 64;

/**
 * Pick the cell granularity.
 *
 *   - We want the smallest unit (largest prefix number) such that
 *     `2^(unitPrefix - supernetPrefix) ≤ MAX_CELLS`.
 *   - But never finer than MIN_UNIT_PREFIX_v* for that family.
 *   - And never coarser than the supernet itself (degenerate single cell).
 */
export function pickUnitPrefix(supernet: ParsedCidr): number {
  const minUnit =
    supernet.kind === "v4" ? MIN_UNIT_PREFIX_V4 : MIN_UNIT_PREFIX_V6;
  const maxBitsBelow = Math.floor(Math.log2(MAX_CELLS)); // 10 for 1024
  let unit = supernet.prefix + maxBitsBelow;
  if (unit > minUnit) unit = minUnit;
  if (unit < supernet.prefix) unit = supernet.prefix;
  return unit;
}

/**
 * Walk the supernet at `unitPrefix` granularity, classify each cell.
 */
export function buildGrid(
  supernet: ParsedCidr,
  allocations: Allocation[],
  freeBlocks: FreeBlock[],
  parseCidr: (s: string) => ParsedCidr | null,
): GridLayout {
  const unitPrefix = pickUnitPrefix(supernet);
  const cellSize = 1n << BigInt(supernet.bits - unitPrefix);
  const cellCountBig = supernet.size / cellSize;
  // Defensive: cellCount should always fit in a JS number given MAX_CELLS=1024.
  const cellCount = Number(cellCountBig);

  // Index allocations + free blocks into the cell grid. We classify each
  // cell by the highest-priority allocation that intersects it. Priority
  // mirrors what users care about most: active > reserved > released > free.
  type ClassRecord = { status: CellStatus; allocation?: Allocation };
  const cellStatus: ClassRecord[] = Array.from({ length: cellCount }, () => ({
    status: "free",
  }));

  const priority: Record<CellStatus, number> = {
    active: 4,
    reserved: 3,
    released: 2,
    free: 1,
  };

  for (const a of allocations) {
    const p = parseCidr(a.cidr);
    if (!p || p.kind !== supernet.kind) continue;
    const firstCell = Number((p.start - supernet.start) / cellSize);
    const lastCell = Number((p.end - supernet.start) / cellSize);
    const status = a.status as CellStatus;
    for (let i = firstCell; i <= lastCell && i < cellCount; i++) {
      if (i < 0) continue;
      if (priority[status] > priority[cellStatus[i]!.status]) {
        cellStatus[i] = { status, allocation: a };
      }
    }
  }

  // Free blocks override leftover "free" cells with a more accurate label
  // (their CIDR), but they don't outrank active/reserved/released.
  // We don't store them anywhere extra here — the cell stays "free" and the
  // tooltip below uses the cell's own CIDR.
  void freeBlocks;

  const cells: Cell[] = Array.from({ length: cellCount }, (_, i) => {
    const startAddr = supernet.start + cellSize * BigInt(i);
    const endAddr = startAddr + cellSize - 1n;
    const cls = cellStatus[i]!;
    return {
      index: i,
      startAddr,
      endAddr,
      cidr: `${bigIntToIp(startAddr, supernet.kind)}/${unitPrefix}`,
      status: cls.status,
      allocation: cls.allocation,
    };
  });

  return {
    unitPrefix,
    cellCount,
    cells,
    truncatedToMin:
      (supernet.kind === "v6" && unitPrefix === MIN_UNIT_PREFIX_V6) ||
      (supernet.kind === "v4" && unitPrefix === MIN_UNIT_PREFIX_V4),
  };
}

/** Tailwind classes for each status. */
export const CELL_FILL: Record<CellStatus, string> = {
  active: "bg-green/70 hover:bg-green",
  reserved: "bg-yellow/70 hover:bg-yellow",
  released: "bg-text-muted/30 hover:bg-text-muted/50",
  free: "bg-surface2 hover:bg-surface3",
};

/** SVG fill utility classes for the Hilbert view (Tailwind 4 `fill-*`). */
export const CELL_FILL_SVG: Record<CellStatus, string> = {
  active: "fill-green/70 hover:fill-green",
  reserved: "fill-yellow/70 hover:fill-yellow",
  released: "fill-text-muted/30 hover:fill-text-muted/50",
  free: "fill-surface2 hover:fill-surface",
};
