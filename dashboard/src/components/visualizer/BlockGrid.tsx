import { useState } from "react";
import type { Allocation } from "../../types";
import { type GridLayout, CELL_FILL } from "./gridUnits";

/**
 * Equal-size cell grid. Each cell covers `1 / cellCount` of the supernet's
 * address space, indexed in linear order (low → high). Status determines
 * fill; tooltip shows the cell's CIDR and any owning allocation.
 */
export function BlockGrid({
  layout,
  onAllocationClick,
}: {
  layout: GridLayout;
  onAllocationClick: (a: Allocation) => void;
}) {
  // Pick a column count that yields a roughly square grid. cellCount is
  // bounded by gridUnits.MAX_CELLS (1024) so √n is at most 32.
  const cols = Math.max(1, Math.ceil(Math.sqrt(layout.cellCount)));

  return (
    <div
      className="grid gap-0.5"
      style={{
        gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`,
      }}
      role="grid"
    >
      {layout.cells.map((c) => (
        <BlockCell
          key={c.index}
          cidr={c.cidr}
          status={c.status}
          allocation={c.allocation}
          onAllocationClick={onAllocationClick}
        />
      ))}
    </div>
  );
}

function BlockCell({
  cidr,
  status,
  allocation,
  onAllocationClick,
}: {
  cidr: string;
  status: keyof typeof CELL_FILL;
  allocation?: Allocation;
  onAllocationClick: (a: Allocation) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const tooltip = allocation
    ? `${allocation.cidr}${allocation.name ? ` — ${allocation.name}` : ""} (${allocation.status})`
    : `${cidr} (free)`;
  const interactive = !!allocation;

  return (
    <div
      role={interactive ? "button" : "gridcell"}
      tabIndex={interactive ? 0 : -1}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={() => allocation && onAllocationClick(allocation)}
      onKeyDown={(e) => {
        if (allocation && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          onAllocationClick(allocation);
        }
      }}
      title={tooltip}
      className={`relative aspect-square rounded-[2px] transition-colors ${CELL_FILL[status]} ${
        interactive ? "cursor-pointer" : ""
      }`}
    >
      {hovered && (
        <span className="absolute z-10 bottom-full left-1/2 -translate-x-1/2 mb-1 bg-surface border border-border rounded px-2 py-0.5 text-xs whitespace-nowrap shadow pointer-events-none">
          {tooltip}
        </span>
      )}
    </div>
  );
}
