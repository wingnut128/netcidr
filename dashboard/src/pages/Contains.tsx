import { useState, useCallback } from "react";
import { get } from "../api";
import type { ContainsResult } from "../types";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { DataRow } from "../components/ui/DataRow";
import { ErrorBanner } from "../components/ui/ErrorBanner";

export function Contains() {
  const [cidr, setCidr] = useState("");
  const [address, setAddress] = useState("");
  const [result, setResult] = useState<ContainsResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const doContains = useCallback(async () => {
    const c = cidr.trim();
    const a = address.trim();
    if (!c || !a) return;
    try {
      const isV6 = c.includes(":");
      const ep = isV6 ? "/v6/contains" : "/v4/contains";
      const data = await get<ContainsResult>(
        `${ep}?cidr=${encodeURIComponent(c)}&address=${encodeURIComponent(a)}`,
      );
      setResult(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setResult(null);
    }
  }, [cidr, address]);

  return (
    <div>
      <PageHeader
        title="Contains Check"
        subtitle="Check if an IP address is within a CIDR range"
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Input">
        <div className="flex flex-col sm:flex-row sm:items-end sm:flex-wrap gap-3">
          <div className="w-full sm:flex-[2] sm:min-w-[200px]">
            <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
              CIDR
            </label>
            <input
              type="text"
              className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 192.168.1.0/24"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
            />
          </div>
          <div className="w-full sm:flex-[2] sm:min-w-[200px]">
            <label className="block text-[10px] font-bold uppercase tracking-[0.1em] text-text-muted mb-1">
              IP Address
            </label>
            <input
              type="text"
              className="w-full font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 192.168.1.100"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doContains()}
            />
          </div>
          <button
            className="w-full sm:w-auto font-mono text-[11px] font-bold uppercase tracking-[0.1em] px-4 min-h-[44px] md:min-h-0 md:py-2 border-2 border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
            onClick={doContains}
          >
            CHECK
          </button>
        </div>
      </Panel>

      {result !== null && (
        <>
          <Panel>
            <div
              className={`py-6 text-center text-[32px] font-bold uppercase tracking-[0.2em] ${
                result.contained
                  ? "bg-green text-bg"
                  : "bg-red text-bg"
              }`}
            >
              {result.contained ? "YES — CONTAINED" : "NO — NOT CONTAINED"}
            </div>
          </Panel>

          <Panel title="Details">
            <DataRow label="CIDR">{result.cidr}</DataRow>
            <DataRow label="Address">{result.address}</DataRow>
            <DataRow label="Network Address">{result.network_address}</DataRow>
            {result.broadcast_address && (
              <DataRow label="Broadcast Address">
                {result.broadcast_address}
              </DataRow>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
