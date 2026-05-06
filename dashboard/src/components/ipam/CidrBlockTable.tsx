import { Panel } from "../ui/Panel";
import type { CidrBlock } from "../../types";
import { fmtNum } from "../../lib/format";
import { TABLE_HEADER } from "../../lib/styles";

interface CidrBlockTableProps {
  cidr_blocks: CidrBlock[];
  utilization: Record<string, { pct: number; count: number }>;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
  onCreateClick: () => void;
}

function utilColor(pct: number): string {
  if (pct >= 80) return "bg-red";
  if (pct >= 50) return "bg-yellow";
  return "bg-green";
}

export function CidrBlockTable({
  cidr_blocks,
  utilization,
  onSelect,
  onDelete,
  onCreateClick,
}: CidrBlockTableProps) {
  return (
    <Panel
      title="CIDR Blocks"
      collapsible
      actions={
        <button
          className="text-xs font-medium rounded-md px-3 py-2 md:py-1 min-h-[44px] md:min-h-0 border border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
          onClick={onCreateClick}
        >
          + CREATE
        </button>
      }
    >
      {/* Mobile: stacked cards */}
      <div className="md:hidden flex flex-col gap-3">
        {cidr_blocks.map((sn) => {
          const u = utilization[sn.id];
          const pct = u?.pct ?? 0;
          return (
            <div
              key={sn.id}
              className="border border-border rounded-md p-3 bg-bg flex flex-col gap-2"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-cyan font-mono text-sm break-all">
                  {sn.cidr}
                </span>
                <span className="text-text-muted text-xs">
                  /{sn.prefix_length}
                </span>
              </div>
              {sn.name && <div className="text-sm text-text">{sn.name}</div>}
              <dl className="grid grid-cols-2 gap-y-1 gap-x-3 text-xs">
                <dt className="text-text-muted">Total hosts</dt>
                <dd className="text-text">{fmtNum(sn.total_hosts)}</dd>
                <dt className="text-text-muted">Utilization</dt>
                <dd className="text-text">{pct.toFixed(1)}%</dd>
              </dl>
              <div className="h-1.5 bg-border rounded-sm overflow-hidden">
                <div
                  className={`h-full ${utilColor(pct)} transition-all`}
                  style={{ width: `${Math.min(pct, 100)}%` }}
                />
              </div>
              <div className="flex gap-2 flex-wrap pt-1">
                <button
                  className="text-xs font-medium rounded-md px-3 py-2 min-h-[44px] border border-border text-text-muted hover:text-cyan hover:border-cyan transition-colors"
                  onClick={() => onSelect(sn.id)}
                >
                  VIEW
                </button>
                <button
                  className="text-xs font-medium rounded-md px-3 py-2 min-h-[44px] border border-border text-text-muted hover:text-red hover:border-red transition-colors"
                  onClick={() => onDelete(sn.id)}
                >
                  DEL
                </button>
              </div>
            </div>
          );
        })}
        {cidr_blocks.length === 0 && (
          <p className="text-center text-text-muted py-6 text-sm">
            No CIDR blocks. Create one to get started.
          </p>
        )}
      </div>

      {/* Desktop: table */}
      <div className="hidden md:block overflow-x-auto">
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr>
              {["CIDR", "Name", "Prefix", "Total Hosts", "Utilization", "Actions"].map(
                (h) => (
                  <th key={h} className={TABLE_HEADER}>
                    {h}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {cidr_blocks.map((sn) => {
              const u = utilization[sn.id];
              const pct = u?.pct ?? 0;
              return (
                <tr key={sn.id} className="hover:bg-cyan/[0.03]">
                  <td className="px-3 py-2 border-b border-border text-cyan">
                    {sn.cidr}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {sn.name ?? "-"}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    /{sn.prefix_length}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    {fmtNum(sn.total_hosts)}
                  </td>
                  <td className="px-3 py-2 border-b border-border w-40">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-border rounded-sm overflow-hidden">
                        <div
                          className={`h-full ${utilColor(pct)} transition-all`}
                          style={{ width: `${Math.min(pct, 100)}%` }}
                        />
                      </div>
                      <span className="text-xs text-text-muted w-10 text-right">
                        {pct.toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    <div className="flex gap-1">
                      <button
                        className="text-xs font-medium rounded-md px-2 py-0.5 border border-border text-text-muted hover:text-cyan hover:border-cyan transition-colors"
                        onClick={() => onSelect(sn.id)}
                      >
                        VIEW
                      </button>
                      <button
                        className="text-xs font-medium rounded-md px-2 py-0.5 border border-border text-text-muted hover:text-red hover:border-red transition-colors"
                        onClick={() => onDelete(sn.id)}
                      >
                        DEL
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {cidr_blocks.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-text-muted border-b border-border"
                >
                  No CIDR blocks. Create one to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
