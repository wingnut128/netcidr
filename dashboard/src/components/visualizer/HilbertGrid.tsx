import { useState } from "react";
import type { Allocation } from "../../types";
import { type Cell, type GridLayout, CELL_FILL_SVG } from "./gridUnits";

/**
 * Hilbert-curve layout: address-adjacent cells stay screen-adjacent, so
 * any contiguous CIDR allocation forms a rectangular region. Order of
 * cells along the curve = order in address space.
 *
 * The curve only fills a power-of-two square. We pad cellCount up to the
 * next 4^k so the math is clean; the padding cells are not rendered.
 */
export function HilbertGrid({
  layout,
  onAllocationClick,
}: {
  layout: GridLayout;
  onAllocationClick: (a: Allocation) => void;
}) {
  const order = nextPowerOf4Order(layout.cellCount);
  const side = 1 << order; // 2^order
  const totalCells = side * side;
  const tileSize = 100 / side; // svg-coord units (viewBox is 100x100)

  return (
    <svg
      viewBox="0 0 100 100"
      preserveAspectRatio="xMidYMid meet"
      className="w-full max-w-[640px] block mx-auto"
      role="grid"
      aria-label="Hilbert-curve allocation map"
    >
      {Array.from({ length: totalCells }, (_, d) => {
        if (d >= layout.cellCount) return null;
        const [x, y] = hilbertD2XY(side, d);
        return (
          <HilbertCell
            key={d}
            cell={layout.cells[d]!}
            x={x * tileSize}
            y={y * tileSize}
            size={tileSize}
            onAllocationClick={onAllocationClick}
          />
        );
      })}
    </svg>
  );
}

function HilbertCell({
  cell,
  x,
  y,
  size,
  onAllocationClick,
}: {
  cell: Cell;
  x: number;
  y: number;
  size: number;
  onAllocationClick: (a: Allocation) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const tooltip = cell.allocation
    ? `${cell.allocation.cidr}${cell.allocation.name ? ` — ${cell.allocation.name}` : ""} (${cell.allocation.status})`
    : `${cell.cidr} (free)`;
  const interactive = !!cell.allocation;

  return (
    <g
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={() => cell.allocation && onAllocationClick(cell.allocation)}
      style={{ cursor: interactive ? "pointer" : "default" }}
      role={interactive ? "button" : "gridcell"}
    >
      <rect
        x={x}
        y={y}
        width={size}
        height={size}
        className={`${CELL_FILL_SVG[cell.status]} transition-colors`}
      >
        <title>{tooltip}</title>
      </rect>
      {hovered && (
        <rect
          x={x}
          y={y}
          width={size}
          height={size}
          fill="none"
          className="stroke-fg"
          strokeWidth={0.4}
        />
      )}
    </g>
  );
}

// ────────────────────── Hilbert curve ──────────────────────

/**
 * Smallest k such that 4^k ≥ n. Used to pick the smallest curve order
 * that fits the requested cell count.
 */
function nextPowerOf4Order(n: number): number {
  if (n <= 1) return 0;
  let k = 0;
  let v = 1;
  while (v < n) {
    v *= 4;
    k++;
  }
  return k;
}

/**
 * Convert curve-distance `d` (0..side²-1) to grid (x, y) coordinates on
 * an `side`×`side` Hilbert curve. Standard rotation/reflection algorithm
 * — see "Hilbert curve" on Wikipedia.
 */
function hilbertD2XY(side: number, d: number): [number, number] {
  let x = 0;
  let y = 0;
  let t = d;
  for (let s = 1; s < side; s *= 2) {
    const rx = 1 & (t / 2);
    const ry = 1 & (t ^ rx);
    if (ry === 0) {
      if (rx === 1) {
        x = s - 1 - x;
        y = s - 1 - y;
      }
      [x, y] = [y, x];
    }
    x += s * rx;
    y += s * ry;
    t = Math.floor(t / 4);
  }
  return [x, y];
}
