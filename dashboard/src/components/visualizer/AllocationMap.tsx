import { useMemo, useState } from "react";
import type { Allocation, FreeBlock, Supernet } from "../../types";
import { intToIp, parseCidr, type ParsedCidr } from "../../lib/cidr";

interface AllocationMapProps {
  supernet: Supernet;
  allocations: Allocation[];
  freeBlocks: FreeBlock[];
  whatIfFits?: ParsedCidr[];
  whatIfConflicts?: ParsedCidr[];
  onAllocationClick: (a: Allocation) => void;
}

interface Segment {
  kind: "alloc" | "free";
  start: number;
  end: number;
  size: number;
  allocation?: Allocation;
  cidr: string;
}

const STATUS_FILL: Record<Allocation["status"], string> = {
  active: "bg-green/70 hover:bg-green",
  reserved: "bg-yellow/70 hover:bg-yellow",
  released: "bg-text-muted/30 hover:bg-text-muted/50",
};

/**
 * Decide how many rows to render. Each row covers a fixed slice of the
 * supernet's address space; smaller supernets get fewer rows so each block
 * stays readable.
 */
function pickRowCount(prefix: number): number {
  // Total IPs in the supernet. We aim for ~4096 IPs per row so an /28 (16
  // IPs) renders at ~0.4% width — still visible at typical container widths.
  const total = 2 ** (32 - prefix);
  if (total <= 4096) return 1;
  if (total <= 65536) return 16;
  return 64;
}

export function AllocationMap({
  supernet,
  allocations,
  freeBlocks,
  whatIfFits = [],
  whatIfConflicts = [],
  onAllocationClick,
}: AllocationMapProps) {
  const parsedSupernet = useMemo(() => parseCidr(supernet.cidr), [supernet.cidr]);

  // Walk the supernet from start → end, emitting alternating allocation
  // and free segments. We sort everything by network address so the strip
  // reads left-to-right just like the address space.
  const segments = useMemo<Segment[]>(() => {
    if (!parsedSupernet) return [];
    const all: Segment[] = [];
    for (const a of allocations) {
      const p = parseCidr(a.cidr);
      if (!p) continue;
      all.push({
        kind: "alloc",
        start: p.start,
        end: p.end,
        size: p.size,
        allocation: a,
        cidr: a.cidr,
      });
    }
    for (const f of freeBlocks) {
      const p = parseCidr(f.cidr);
      if (!p) continue;
      all.push({
        kind: "free",
        start: p.start,
        end: p.end,
        size: p.size,
        cidr: f.cidr,
      });
    }
    all.sort((x, y) => x.start - y.start);
    return all;
  }, [parsedSupernet, allocations, freeBlocks]);

  if (!parsedSupernet) {
    return (
      <div className="text-text-muted text-sm">
        Could not parse supernet CIDR (IPv4 only for now).
      </div>
    );
  }

  const rowCount = pickRowCount(supernet.prefix_length);
  const rowSize = parsedSupernet.size / rowCount;

  return (
    <div className="space-y-1.5">
      {Array.from({ length: rowCount }, (_, rowIdx) => {
        const rowStart = parsedSupernet.start + rowIdx * rowSize;
        const rowEnd = rowStart + rowSize - 1;
        // Only render segments that touch this row.
        const rowSegments = segments
          .map((s) => ({
            ...s,
            visStart: Math.max(s.start, rowStart),
            visEnd: Math.min(s.end, rowEnd),
          }))
          .filter((s) => s.visStart <= s.visEnd);

        return (
          <Row
            key={rowIdx}
            rowStart={rowStart}
            rowEnd={rowEnd}
            rowSize={rowSize}
            segments={rowSegments}
            whatIfFits={whatIfFits}
            whatIfConflicts={whatIfConflicts}
            onAllocationClick={onAllocationClick}
            showLabels={rowCount === 1}
          />
        );
      })}
      <div className="flex justify-between text-xs text-text-muted font-mono pt-1">
        <span>{intToIp(parsedSupernet.start)}</span>
        <span>{intToIp(parsedSupernet.end)}</span>
      </div>
    </div>
  );
}

interface RowProps {
  rowStart: number;
  rowEnd: number;
  rowSize: number;
  segments: (Segment & { visStart: number; visEnd: number })[];
  whatIfFits: ParsedCidr[];
  whatIfConflicts: ParsedCidr[];
  onAllocationClick: (a: Allocation) => void;
  showLabels: boolean;
}

function Row({
  rowStart,
  rowEnd,
  rowSize,
  segments,
  whatIfFits,
  whatIfConflicts,
  onAllocationClick,
  showLabels,
}: RowProps) {
  // Filter what-if overlays that touch this row.
  const fitsOverlays = whatIfFits
    .map((p) => clampToRow(p, rowStart, rowEnd))
    .filter(Boolean) as { start: number; end: number; cidr: string }[];
  const conflictOverlays = whatIfConflicts
    .map((p) => clampToRow(p, rowStart, rowEnd))
    .filter(Boolean) as { start: number; end: number; cidr: string }[];

  return (
    <div className="relative h-7 w-full bg-surface2 rounded-sm overflow-hidden border border-border">
      <div className="flex h-full w-full">
        {segments.map((s, i) => {
          const width = ((s.visEnd - s.visStart + 1) / rowSize) * 100;
          if (s.kind === "alloc" && s.allocation) {
            return (
              <SegmentBlock
                key={i}
                width={width}
                fill={STATUS_FILL[s.allocation.status]}
                title={`${s.allocation.cidr}${s.allocation.name ? " — " + s.allocation.name : ""} (${s.allocation.status})`}
                label={showLabels ? s.allocation.name || s.cidr : undefined}
                onClick={() => onAllocationClick(s.allocation!)}
              />
            );
          }
          return (
            <SegmentBlock
              key={i}
              width={width}
              fill="bg-transparent"
              title={`${s.cidr} (free)`}
              label={showLabels ? "free" : undefined}
              muted
            />
          );
        })}
      </div>
      {/* What-if overlays sit on top, half-transparent, with a dashed
          border so they read as "candidate" rather than committed. */}
      {fitsOverlays.map((o, i) => (
        <Overlay
          key={`fit-${i}`}
          rowStart={rowStart}
          rowSize={rowSize}
          start={o.start}
          end={o.end}
          className="border-2 border-dashed border-cyan bg-cyan/10"
          title={`${o.cidr} — fits`}
        />
      ))}
      {conflictOverlays.map((o, i) => (
        <Overlay
          key={`conflict-${i}`}
          rowStart={rowStart}
          rowSize={rowSize}
          start={o.start}
          end={o.end}
          className="border-2 border-dashed border-red bg-red/10"
          title={`${o.cidr} — conflicts`}
        />
      ))}
    </div>
  );
}

function clampToRow(
  p: ParsedCidr,
  rowStart: number,
  rowEnd: number,
): { start: number; end: number; cidr: string } | null {
  if (p.end < rowStart || p.start > rowEnd) return null;
  return {
    start: Math.max(p.start, rowStart),
    end: Math.min(p.end, rowEnd),
    cidr: p.cidr,
  };
}

function SegmentBlock({
  width,
  fill,
  title,
  label,
  muted,
  onClick,
}: {
  width: number;
  fill: string;
  title: string;
  label?: string;
  muted?: boolean;
  onClick?: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={onClick}
      onKeyDown={(e) => {
        if (onClick && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          onClick();
        }
      }}
      title={title}
      className={`relative h-full ${fill} ${onClick ? "cursor-pointer" : ""} transition-colors flex items-center justify-center text-xs overflow-hidden`}
      style={{ width: `${width}%`, minWidth: width > 0 ? "1px" : 0 }}
    >
      {label && width > 4 && (
        <span
          className={`px-1 truncate ${muted ? "text-text-muted" : "text-bg font-medium"}`}
        >
          {label}
        </span>
      )}
      {hovered && width <= 4 && (
        <span className="absolute z-10 -top-7 left-1/2 -translate-x-1/2 bg-surface border border-border rounded px-2 py-0.5 text-xs whitespace-nowrap shadow">
          {title}
        </span>
      )}
    </div>
  );
}

function Overlay({
  rowStart,
  rowSize,
  start,
  end,
  className,
  title,
}: {
  rowStart: number;
  rowSize: number;
  start: number;
  end: number;
  className: string;
  title: string;
}) {
  const left = ((start - rowStart) / rowSize) * 100;
  const width = ((end - start + 1) / rowSize) * 100;
  return (
    <div
      className={`absolute top-0 bottom-0 pointer-events-none rounded-sm ${className}`}
      style={{ left: `${left}%`, width: `${width}%` }}
      title={title}
    />
  );
}
