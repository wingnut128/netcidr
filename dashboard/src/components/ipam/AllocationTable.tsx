import { Panel } from "../ui/Panel";
import { StatusBadge } from "./StatusBadge";
import type { Allocation, CidrBlock } from "../../types";
import { fmtDate } from "../../lib/format";
import { TABLE_HEADER } from "../../lib/styles";

export interface AllocationFilters {
  cidr_blockId: string;
  status: string;
  owner: string;
  environment: string;
}

interface AllocationTableProps {
  allocations: Allocation[];
  cidr_blocks: CidrBlock[];
  snMap: Record<string, string>;
  filters: AllocationFilters;
  onFiltersChange: (f: AllocationFilters) => void;
  onViewDetail: (a: Allocation) => void;
  onRelease: (id: string) => void;
  onReactivate: (id: string) => void;
  onAllocateSpecificClick: () => void;
  onAutoAllocateClick: () => void;
}

export function AllocationTable({
  allocations,
  cidr_blocks,
  snMap,
  filters,
  onFiltersChange,
  onViewDetail,
  onRelease,
  onReactivate,
  onAllocateSpecificClick,
  onAutoAllocateClick,
}: AllocationTableProps) {
  const set = (patch: Partial<AllocationFilters>) =>
    onFiltersChange({ ...filters, ...patch });

  return (
    <Panel
      title="Allocations"
      collapsible
      actions={
        <div className="flex gap-2">
          <button
            className="text-xs font-medium rounded-md px-3 py-2 md:py-1 min-h-[44px] md:min-h-0 border border-border text-text-muted hover:text-text hover:border-text transition-colors"
            onClick={onAllocateSpecificClick}
          >
            SPECIFIC
          </button>
          <button
            className="text-xs font-medium rounded-md px-3 py-2 md:py-1 min-h-[44px] md:min-h-0 border border-cyan text-cyan hover:bg-cyan hover:text-bg transition-colors"
            onClick={onAutoAllocateClick}
          >
            AUTO
          </button>
        </div>
      }
    >
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-4 sm:flex-wrap">
        <select
          className="w-full sm:flex-1 sm:min-w-[180px] font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
          value={filters.cidr_blockId}
          onChange={(e) => set({ cidr_blockId: e.target.value })}
        >
          <option value="">All CIDR blocks</option>
          {cidr_blocks.map((sn) => (
            <option key={sn.id} value={sn.id}>
              {sn.cidr} {sn.name ? `– ${sn.name}` : ""}
            </option>
          ))}
        </select>
        <select
          className="w-full sm:w-auto sm:min-w-[120px] font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
          value={filters.status}
          onChange={(e) => set({ status: e.target.value })}
        >
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="reserved">Reserved</option>
          <option value="released">Released</option>
        </select>
        <input
          type="text"
          className="w-full sm:w-auto sm:min-w-[100px] font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
          placeholder="Owner"
          value={filters.owner}
          onChange={(e) => set({ owner: e.target.value })}
        />
        <input
          type="text"
          className="w-full sm:w-auto sm:min-w-[100px] font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
          placeholder="Environment"
          value={filters.environment}
          onChange={(e) => set({ environment: e.target.value })}
        />
      </div>

      {/* Table (desktop) / Card list (mobile) */}
      {!filters.cidr_blockId ? (
        <p className="text-center text-text-muted py-6">
          SELECT A SUPERNET TO VIEW ALLOCATIONS
        </p>
      ) : (
        <>
          {/* Mobile: stacked cards */}
          <div className="md:hidden flex flex-col gap-3">
            {allocations.map((a) => (
              <div
                key={a.id}
                className="border border-border rounded-md p-3 bg-bg flex flex-col gap-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="text-cyan font-mono text-sm break-all">
                    {a.cidr}
                  </span>
                  <StatusBadge status={a.status} />
                </div>
                {a.name && (
                  <div className="text-sm text-text">{a.name}</div>
                )}
                <dl className="grid grid-cols-2 gap-y-1 gap-x-3 text-xs">
                  <dt className="text-text-muted">CIDR Block</dt>
                  <dd className="text-text font-mono break-all">
                    {snMap[a.cidr_block_id] ?? "-"}
                  </dd>
                  <dt className="text-text-muted">Owner</dt>
                  <dd className="text-text">{a.owner ?? "-"}</dd>
                  <dt className="text-text-muted">Environment</dt>
                  <dd className="text-text">{a.environment ?? "-"}</dd>
                  <dt className="text-text-muted">Created</dt>
                  <dd className="text-text-muted">{fmtDate(a.created_at)}</dd>
                </dl>
                {a.tags && a.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {a.tags.map((t) => (
                      <span
                        key={t.key + t.value}
                        className="inline-block px-1.5 py-0.5 text-xs border border-border text-text-muted"
                      >
                        {t.key}={t.value}
                      </span>
                    ))}
                  </div>
                )}
                <div className="flex gap-2 flex-wrap pt-1">
                  <button
                    className="text-xs font-medium rounded-md px-3 py-2 min-h-[44px] border border-border text-text-muted hover:text-text hover:border-text transition-colors"
                    onClick={() => onViewDetail(a)}
                  >
                    DETAIL
                  </button>
                  {a.status !== "released" && (
                    <button
                      className="text-xs font-medium rounded-md px-3 py-2 min-h-[44px] border border-red text-red hover:bg-red hover:text-bg transition-colors"
                      onClick={() => onRelease(a.id)}
                    >
                      RELEASE
                    </button>
                  )}
                  {a.status === "released" && (
                    <button
                      className="text-xs font-medium rounded-md px-3 py-2 min-h-[44px] border border-green text-green hover:bg-green hover:text-bg transition-colors"
                      onClick={() => onReactivate(a.id)}
                    >
                      RE-ACTIVATE
                    </button>
                  )}
                </div>
              </div>
            ))}
            {allocations.length === 0 && (
              <p className="text-center text-text-muted py-6 text-sm">
                No allocations found.
              </p>
            )}
          </div>

          {/* Desktop: table */}
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full border-collapse text-xs">
            <thead>
              <tr>
                {[
                  "CIDR",
                  "CIDR Block",
                  "Status",
                  "Name",
                  "Owner",
                  "Environment",
                  "Tags",
                  "Created",
                  "Actions",
                ].map((h) => (
                  <th key={h} className={TABLE_HEADER}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allocations.map((a) => (
                <tr key={a.id} className="hover:bg-cyan/[0.03]">
                  <td className="px-3 py-2 border-b border-border text-cyan">
                    {a.cidr}
                  </td>
                  <td className="px-3 py-2 border-b border-border text-text-muted">
                    {snMap[a.cidr_block_id] ?? "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {a.name ?? "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {a.owner ?? "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {a.environment ?? "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {(a.tags ?? []).map((t) => (
                      <span
                        key={t.key + t.value}
                        className="inline-block px-1.5 py-0.5 text-xs border border-border text-text-muted mr-1"
                      >
                        {t.key}={t.value}
                      </span>
                    ))}
                    {(!a.tags || a.tags.length === 0) && "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border text-text-muted">
                    {fmtDate(a.created_at)}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    <div className="flex gap-1">
                      <button
                        className="text-xs font-medium rounded-md px-2 py-0.5 border border-border text-text-muted hover:text-text hover:border-text transition-colors"
                        onClick={() => onViewDetail(a)}
                      >
                        DETAIL
                      </button>
                      {a.status !== "released" && (
                        <button
                          className="text-xs font-medium rounded-md px-2 py-0.5 border border-red text-red hover:bg-red hover:text-bg transition-colors"
                          onClick={() => onRelease(a.id)}
                        >
                          RELEASE
                        </button>
                      )}
                      {a.status === "released" && (
                        <button
                          className="text-xs font-medium rounded-md px-2 py-0.5 border border-green text-green hover:bg-green hover:text-bg transition-colors"
                          onClick={() => onReactivate(a.id)}
                        >
                          RE-ACTIVATE
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {allocations.length === 0 && (
                <tr>
                  <td
                    colSpan={9}
                    className="px-3 py-6 text-center text-text-muted border-b border-border"
                  >
                    No allocations found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          </div>
        </>
      )}
    </Panel>
  );
}
