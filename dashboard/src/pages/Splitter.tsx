import { useState, useCallback } from "react";
import { get } from "../api";
import type { Ipv4Subnet, SplitResult } from "../types";
import { fmtSize } from "../lib/format";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { StatCard } from "../components/ui/StatCard";
import { ErrorBanner } from "../components/ui/ErrorBanner";

function isV4Subnet(s: unknown): s is Ipv4Subnet {
  return typeof s === "object" && s !== null && "broadcast_address" in s;
}

export function Splitter() {
  const [cidr, setCidr] = useState("");
  const [prefix, setPrefix] = useState("");
  const [count, setCount] = useState("");
  const [max, setMax] = useState(false);
  const [result, setResult] = useState<SplitResult | null>(null);
  const [isV4, setIsV4] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const doSplit = useCallback(async () => {
    const input = cidr.trim();
    if (!input || !prefix) return;
    try {
      const v6 = input.includes(":");
      setIsV4(!v6);
      const ep = v6 ? "/v6/split" : "/v4/split";
      let qs = `cidr=${encodeURIComponent(input)}&prefix=${prefix}`;
      if (max || !count) {
        qs += "&max=true";
      } else {
        qs += `&count=${count}`;
      }
      const data = await get<SplitResult>(`${ep}?${qs}`);
      setResult(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setResult(null);
    }
  }, [cidr, prefix, count, max]);

  return (
    <div>
      <PageHeader
        title="Subnet Splitter"
        subtitle="Split a network into smaller subnets"
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Input">
        <div className="flex gap-3 items-end flex-wrap">
          <div className="flex-[3] min-w-[200px]">
            <label className="block text-xs font-medium text-text-muted mb-1">
              CIDR
            </label>
            <input
              type="text"
              className="w-full font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 10.0.0.0/8"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
            />
          </div>
          <div className="flex-1 min-w-[100px]">
            <label className="block text-xs font-medium text-text-muted mb-1">
              Target Prefix
            </label>
            <input
              type="number"
              className="w-full font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 24"
              min={0}
              max={128}
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
            />
          </div>
          <div className="flex-1 min-w-[100px]">
            <label className="block text-xs font-medium text-text-muted mb-1">
              Count
            </label>
            <input
              type="number"
              className="w-full font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan disabled:opacity-40"
              placeholder="max"
              min={1}
              value={count}
              onChange={(e) => setCount(e.target.value)}
              disabled={max}
            />
          </div>
          <div className="flex items-center gap-3">
            <label className="text-xs text-text-muted whitespace-nowrap flex items-center gap-1 cursor-pointer">
              <input
                type="checkbox"
                checked={max}
                onChange={(e) => setMax(e.target.checked)}
              />
              MAX
            </label>
            <button
              className="text-xs font-medium rounded-md px-4 py-2 min-h-[44px] md:min-h-0 border border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
              onClick={doSplit}
            >
              SPLIT
            </button>
          </div>
        </div>
      </Panel>

      {result && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
            <StatCard
              label="Parent CIDR"
              value={result.supernet?.input ?? cidr}
              color="cyan"
              valueSize="18px"
            />
            <StatCard
              label="Child Subnets"
              value={result.subnets?.length ?? 0}
              color="green"
            />
            <StatCard
              label="New Prefix"
              value={`/${result.new_prefix}`}
              color="yellow"
            />
          </div>

          <Panel
            title="Subnets"
            actions={
              <span className="text-xs text-text-muted">
                {result.subnets?.length ?? 0} results
              </span>
            }
          >
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr>
                    <th className="text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border">
                      #
                    </th>
                    <th className="text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border">
                      CIDR
                    </th>
                    <th className="text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border">
                      Network
                    </th>
                    {isV4 && (
                      <th className="text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border">
                        Broadcast
                      </th>
                    )}
                    <th className="text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border">
                      Total
                    </th>
                    {isV4 && (
                      <th className="text-left px-3 py-2 text-xs font-semibold text-text-muted bg-surface2 border-b-2 border-border">
                        Usable
                      </th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {(result.subnets ?? []).map((s, i) => (
                    <tr
                      key={i}
                      className="hover:bg-cyan/[0.03]"
                    >
                      <td className="px-3 py-2 border-b border-border text-text-muted">
                        {i + 1}
                      </td>
                      <td className="px-3 py-2 border-b border-border text-cyan">
                        {s.input}
                      </td>
                      <td className="px-3 py-2 border-b border-border">
                        {s.network_address}
                      </td>
                      {isV4 && isV4Subnet(s) && (
                        <td className="px-3 py-2 border-b border-border">
                          {s.broadcast_address}
                        </td>
                      )}
                      <td className="px-3 py-2 border-b border-border">
                        {fmtSize(
                          isV4Subnet(s)
                            ? s.total_hosts
                            : (s as { total_addresses?: string }).total_addresses ?? 0,
                        )}
                      </td>
                      {isV4 && isV4Subnet(s) && (
                        <td className="px-3 py-2 border-b border-border">
                          {fmtSize(s.usable_hosts)}
                        </td>
                      )}
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
