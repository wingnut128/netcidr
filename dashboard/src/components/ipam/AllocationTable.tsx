import { Panel } from "../ui/Panel";
import { StatusBadge } from "./StatusBadge";
import type { Allocation, Supernet } from "../../types";
import { fmtDate } from "../../lib/format";
import { TABLE_HEADER } from "../../lib/styles";

export interface AllocationFilters {
  supernetId: string;
  status: string;
  owner: string;
  environment: string;
}

interface AllocationTableProps {
  allocations: Allocation[];
  supernets: Supernet[];
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
  supernets,
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
      actions={
        <div className="flex gap-2">
          <button
            className="font-mono text-[10px] font-bold uppercase tracking-[0.1em] px-3 py-1 border-2 border-border text-text-muted hover:text-text hover:border-text transition-colors"
            onClick={onAllocateSpecificClick}
          >
            SPECIFIC
          </button>
          <button
            className="font-mono text-[10px] font-bold uppercase tracking-[0.1em] px-3 py-1 border-2 border-cyan text-cyan hover:bg-cyan hover:text-bg transition-colors"
            onClick={onAutoAllocateClick}
          >
            AUTO
          </button>
        </div>
      }
    >
      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap">
        <select
          className="flex-1 min-w-[180px] font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
          value={filters.supernetId}
          onChange={(e) => set({ supernetId: e.target.value })}
        >
          <option value="">All Supernets</option>
          {supernets.map((sn) => (
            <option key={sn.id} value={sn.id}>
              {sn.cidr} {sn.name ? `– ${sn.name}` : ""}
            </option>
          ))}
        </select>
        <select
          className="min-w-[120px] font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
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
          className="min-w-[100px] font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
          placeholder="Owner"
          value={filters.owner}
          onChange={(e) => set({ owner: e.target.value })}
        />
        <input
          type="text"
          className="min-w-[100px] font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
          placeholder="Environment"
          value={filters.environment}
          onChange={(e) => set({ environment: e.target.value })}
        />
      </div>

      {/* Table */}
      {!filters.supernetId ? (
        <p className="text-center text-text-muted py-6">
          SELECT A SUPERNET TO VIEW ALLOCATIONS
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr>
                {[
                  "CIDR",
                  "Supernet",
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
                    {snMap[a.supernet_id] ?? "-"}
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
                        className="inline-block px-1.5 py-0.5 text-[10px] border border-border text-text-muted mr-1"
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
                        className="font-mono text-[10px] font-bold uppercase px-2 py-0.5 border border-border text-text-muted hover:text-text hover:border-text transition-colors"
                        onClick={() => onViewDetail(a)}
                      >
                        DETAIL
                      </button>
                      {a.status !== "released" && (
                        <button
                          className="font-mono text-[10px] font-bold uppercase px-2 py-0.5 border border-red text-red hover:bg-red hover:text-bg transition-colors"
                          onClick={() => onRelease(a.id)}
                        >
                          RELEASE
                        </button>
                      )}
                      {a.status === "released" && (
                        <button
                          className="font-mono text-[10px] font-bold uppercase px-2 py-0.5 border border-green text-green hover:bg-green hover:text-bg transition-colors"
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
      )}
    </Panel>
  );
}
