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
        <div className="flex gap-3 items-end flex-wrap">
          <div className="flex-[2] min-w-[200px]">
            <label className="block text-xs font-medium text-text-muted mb-1">
              CIDR
            </label>
            <input
              type="text"
              className="w-full font-mono text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 192.168.1.0/24"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
            />
          </div>
          <div className="flex-[2] min-w-[200px]">
            <label className="block text-xs font-medium text-text-muted mb-1">
              IP Address
            </label>
            <input
              type="text"
              className="w-full font-mono text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
              placeholder="e.g. 192.168.1.100"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doContains()}
            />
          </div>
          <button
            className="text-xs font-medium rounded-md px-4 py-2 border border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
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
              className={`py-6 text-center text-2xl font-semibold rounded-md ${
                result.contained
                  ? "bg-green/10 text-green border border-green/30"
                  : "bg-red/10 text-red border border-red/30"
              }`}
            >
              {result.contained ? "Contained" : "Not contained"}
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
