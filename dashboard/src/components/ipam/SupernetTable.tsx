import { Panel } from "../ui/Panel";
import type { Supernet } from "../../types";
import { fmtNum } from "../../lib/format";
import { TABLE_HEADER } from "../../lib/styles";

interface SupernetTableProps {
  supernets: Supernet[];
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

const ROW_ACTION_VIEW =
  "font-mono text-[10px] font-bold uppercase px-2 min-h-[44px] md:min-h-0 md:py-0.5 border border-border text-text-muted hover:text-cyan hover:border-cyan transition-colors";
const ROW_ACTION_DEL =
  "font-mono text-[10px] font-bold uppercase px-2 min-h-[44px] md:min-h-0 md:py-0.5 border border-border text-text-muted hover:text-red hover:border-red transition-colors";

export function SupernetTable({
  supernets,
  utilization,
  onSelect,
  onDelete,
  onCreateClick,
}: SupernetTableProps) {
  const utilBar = (pct: number) => (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-border rounded-sm overflow-hidden">
        <div
          className={`h-full ${utilColor(pct)} transition-all`}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
      <span className="text-[10px] text-text-muted w-10 text-right">
        {pct.toFixed(1)}%
      </span>
    </div>
  );

  return (
    <Panel
      title="Supernets"
      collapsible
      actions={
        <button
          className="font-mono text-[10px] font-bold uppercase tracking-[0.1em] px-3 min-h-[44px] md:min-h-0 md:py-1 border-2 border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
          onClick={onCreateClick}
        >
          + CREATE
        </button>
      }
    >
      {/* Mobile: card layout */}
      <div className="md:hidden flex flex-col gap-3">
        {supernets.map((sn) => {
          const u = utilization[sn.id];
          const pct = u?.pct ?? 0;
          return (
            <div
              key={sn.id}
              className="bg-bg border border-border p-3 flex flex-col gap-2"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-cyan font-mono text-sm break-all">
                  {sn.cidr}
                </span>
                <span className="text-text-muted text-xs">
                  /{sn.prefix_length}
                </span>
              </div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                {sn.name && (
                  <>
                    <dt className="text-text-muted uppercase text-[10px]">
                      Name
                    </dt>
                    <dd>{sn.name}</dd>
                  </>
                )}
                <dt className="text-text-muted uppercase text-[10px]">Hosts</dt>
                <dd>{fmtNum(sn.total_hosts)}</dd>
              </dl>
              {utilBar(pct)}
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  className={ROW_ACTION_VIEW}
                  onClick={() => onSelect(sn.id)}
                >
                  VIEW
                </button>
                <button
                  className={ROW_ACTION_DEL}
                  onClick={() => onDelete(sn.id)}
                >
                  DEL
                </button>
              </div>
            </div>
          );
        })}
        {supernets.length === 0 && (
          <p className="text-center text-text-muted py-6">
            No supernets. Create one to get started.
          </p>
        )}
      </div>

      {/* Desktop: table layout */}
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
            {supernets.map((sn) => {
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
                    {utilBar(pct)}
                  </td>
                  <td className="px-3 py-2 border-b border-border">
                    <div className="flex gap-1">
                      <button
                        className={ROW_ACTION_VIEW}
                        onClick={() => onSelect(sn.id)}
                      >
                        VIEW
                      </button>
                      <button
                        className={ROW_ACTION_DEL}
                        onClick={() => onDelete(sn.id)}
                      >
                        DEL
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {supernets.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-text-muted border-b border-border"
                >
                  No supernets. Create one to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
