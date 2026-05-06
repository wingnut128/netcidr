import { useEffect, useMemo, useState } from "react";
import type { Allocation, FreeBlock, CidrBlock } from "../../types";
import { bigIntToIp, parseCidr, type ParsedCidr } from "../../lib/cidr";
import { buildGrid } from "./gridUnits";
import { BlockGrid } from "./BlockGrid";
import { HilbertGrid } from "./HilbertGrid";

interface AllocationMapProps {
  cidr_block: CidrBlock;
  allocations: Allocation[];
  freeBlocks: FreeBlock[];
  whatIfFits?: ParsedCidr[];
  whatIfConflicts?: ParsedCidr[];
  onAllocationClick: (a: Allocation) => void;
}

type ViewMode = "block" | "hilbert";
const VIEW_STORAGE_KEY = "netcidr.visualizer.view";

export function AllocationMap({
  cidr_block,
  allocations,
  freeBlocks,
  // whatIfFits/whatIfConflicts are accepted to keep the WhatIfPanel API
  // wiring intact, but neither grid currently paints them as overlays.
  // The verdict badges in WhatIfPanel itself still show fit vs conflict
  // per candidate. Re-adding map overlays is a follow-up.
  whatIfFits: _whatIfFits = [],
  whatIfConflicts: _whatIfConflicts = [],
  onAllocationClick,
}: AllocationMapProps) {

  const parsedCidrBlock = useMemo(
    () => parseCidr(cidr_block.cidr),
    [cidr_block.cidr],
  );

  // Persist toggle across visits — small UX win when comparing CIDR blocks.
  const [view, setView] = useState<ViewMode>(() => {
    if (typeof window === "undefined") return "block";
    const saved = window.localStorage.getItem(VIEW_STORAGE_KEY);
    return saved === "hilbert" ? "hilbert" : "block";
  });
  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(VIEW_STORAGE_KEY, view);
    }
  }, [view]);

  const grid = useMemo(() => {
    if (!parsedCidrBlock) return null;
    return buildGrid(parsedCidrBlock, allocations, freeBlocks, parseCidr);
  }, [parsedCidrBlock, allocations, freeBlocks]);

  if (!parsedCidrBlock) {
    return (
      <div className="text-text-muted text-sm">
        Could not parse CIDR block CIDR <code>{cidr_block.cidr}</code>.
      </div>
    );
  }

  if (!grid) return null;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs text-text-muted">
        <div>
          {grid.cellCount.toLocaleString()} cells, each a /{grid.unitPrefix}
          {grid.truncatedToMin && parsedCidrBlock.kind === "v6" && (
            <span className="ml-2 italic">
              (coarsened to /64 — finer detail not shown)
            </span>
          )}
        </div>
        <ViewToggle view={view} onChange={setView} />
      </div>

      {view === "block" ? (
        <BlockGrid layout={grid} onAllocationClick={onAllocationClick} />
      ) : (
        <HilbertGrid layout={grid} onAllocationClick={onAllocationClick} />
      )}

      <div className="flex justify-between text-xs text-text-muted font-mono pt-1">
        <span>{bigIntToIp(parsedCidrBlock.start, parsedCidrBlock.kind)}</span>
        <span>{bigIntToIp(parsedCidrBlock.end, parsedCidrBlock.kind)}</span>
      </div>
    </div>
  );
}

function ViewToggle({
  view,
  onChange,
}: {
  view: ViewMode;
  onChange: (v: ViewMode) => void;
}) {
  const baseBtn =
    "px-2.5 py-1 text-xs font-medium border border-border first:rounded-l-md last:rounded-r-md -ml-px first:ml-0 transition-colors";
  const activeBtn = "bg-cyan/10 text-cyan border-cyan/40 z-10 relative";
  const idleBtn = "bg-surface text-text-muted hover:bg-surface2";

  return (
    <div role="tablist" aria-label="Visualization style" className="inline-flex">
      <button
        type="button"
        role="tab"
        aria-selected={view === "block"}
        className={`${baseBtn} ${view === "block" ? activeBtn : idleBtn}`}
        onClick={() => onChange("block")}
      >
        Blocks
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={view === "hilbert"}
        className={`${baseBtn} ${view === "hilbert" ? activeBtn : idleBtn}`}
        onClick={() => onChange("hilbert")}
      >
        Hilbert
      </button>
    </div>
  );
}
