import { useState, useCallback } from "react";
import { get } from "../api";
import type { Ipv4Subnet, FromRangeResult } from "../types";
import { fmtSize } from "../lib/format";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { StatCard } from "../components/ui/StatCard";
import { ErrorBanner } from "../components/ui/ErrorBanner";

export function FromRange() {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [result, setResult] = useState<FromRangeResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const doFromRange = useCallback(async () => {
    const s = start.trim();
    const e = end.trim();
    if (!s || !e) return;
    const isV6 = s.includes(":");
    const ep = isV6 ? "/v6/from-range" : "/v4/from-range";
    try {
      const data = await get<FromRangeResult>(
        `${ep}?start=${encodeURIComponent(s)}&end=${encodeURIComponent(e)}`,
      );
      setResult(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setResult(null);
    }
  }, [start, end]);

  const totalAddresses = result
    ? (result.cidrs ?? []).reduce(
        (acc, c) =>
          acc +
          Number(
            (c as Ipv4Subnet).total_hosts ??
              (c as { total_addresses?: string }).total_addresses ??
              0,
          ),
        0,
      )
    : 0;

  return (
    <div>
      <PageHeader
        title="From Range"
        subtitle="Convert IP address range to CIDRs"
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Input">
        <div className="flex gap-3 items-end flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
              Start IP
            </label>
            <input
              type="text"
              className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 10.0.0.0"
              value={start}
              onChange={(e) => setStart(e.target.value)}
            />
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
              End IP
            </label>
            <input
              type="text"
              className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 10.0.3.255"
              value={end}
              onChange={(e) => setEnd(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doFromRange()}
            />
          </div>
          <button
            className="font-mono text-[11px] font-bold uppercase tracking-[0.1em] px-4 py-2 border-2 border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
            onClick={doFromRange}
          >
            CONVERT
          </button>
        </div>
      </Panel>

      {result && (
        <>
          <div className="grid grid-cols-3 gap-4 mb-5">
            <StatCard
              label="Range"
              value={`${result.start_address} – ${result.end_address}`}
              color="cyan"
              valueSize="16px"
            />
            <StatCard
              label="CIDR Count"
              value={result.cidr_count}
              color="green"
            />
            <StatCard
              label="Total Addresses"
              value={fmtSize(totalAddresses)}
              color="yellow"
            />
          </div>

          <Panel title="CIDRs">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr>
                    <th className="text-left px-3 py-2 font-bold text-[10px] uppercase tracking-[0.1em] text-text-muted bg-surface2 border-b-2 border-border">
                      #
                    </th>
                    <th className="text-left px-3 py-2 font-bold text-[10px] uppercase tracking-[0.1em] text-text-muted bg-surface2 border-b-2 border-border">
                      CIDR
                    </th>
                    <th className="text-left px-3 py-2 font-bold text-[10px] uppercase tracking-[0.1em] text-text-muted bg-surface2 border-b-2 border-border">
                      Network
                    </th>
                    <th className="text-left px-3 py-2 font-bold text-[10px] uppercase tracking-[0.1em] text-text-muted bg-surface2 border-b-2 border-border">
                      Total
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {(result.cidrs ?? []).map((c, i) => (
                    <tr key={i} className="hover:bg-cyan/[0.03]">
                      <td className="px-3 py-2 border-b border-border text-text-muted">
                        {i + 1}
                      </td>
                      <td className="px-3 py-2 border-b border-border text-cyan">
                        {c.input}
                      </td>
                      <td className="px-3 py-2 border-b border-border">
                        {c.network_address}
                      </td>
                      <td className="px-3 py-2 border-b border-border">
                        {fmtSize(
                          (c as Ipv4Subnet).total_hosts ??
                            (c as { total_addresses?: string })
                              .total_addresses ??
                            0,
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}
