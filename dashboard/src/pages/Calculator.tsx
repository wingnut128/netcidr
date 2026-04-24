import { useState, useCallback } from "react";
import { get } from "../api";
import type { Ipv6Subnet, CalcResult } from "../types";
import { fmtNum } from "../lib/format";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { DataRow } from "../components/ui/DataRow";
import { BitGrid } from "../components/ui/BitGrid";
import { ErrorBanner } from "../components/ui/ErrorBanner";

function isIpv6(result: CalcResult): result is Ipv6Subnet {
  return "hextets" in result;
}

export function Calculator() {
  const [cidr, setCidr] = useState("");
  const [result, setResult] = useState<CalcResult | null>(null);
  const [bitCount, setBitCount] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const doCalc = useCallback(async () => {
    const input = cidr.trim();
    if (!input) return;
    try {
      const isV6 = input.includes(":");
      const ep = isV6 ? "/v6" : "/v4";
      const data = await get<CalcResult>(
        `${ep}?cidr=${encodeURIComponent(input)}`,
      );
      setResult(data);
      setBitCount(isV6 ? 128 : 32);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setResult(null);
      setBitCount(0);
    }
  }, [cidr]);

  return (
    <div>
      <PageHeader title="Subnet Calculator" subtitle="IPv4 & IPv6 CIDR Analysis" />

      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      {/* Input */}
      <Panel title="Input">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            className="w-full sm:flex-1 font-mono text-[13px] px-3 py-2 bg-bg border-2 border-border text-text outline-none focus:border-cyan"
            placeholder="e.g. 192.168.1.0/24 or 2001:db8::/48"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doCalc()}
          />
          <button
            className="w-full sm:w-auto font-mono text-[11px] font-bold uppercase tracking-[0.1em] px-4 min-h-[44px] md:min-h-0 md:py-2 border-2 border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
            onClick={doCalc}
          >
            CALC
          </button>
        </div>
      </Panel>

      {result && (
        <>
          {/* Bit Visualization */}
          {bitCount > 0 && (
            <Panel
              title="Bit Visualization"
              actions={
                <span className="text-[11px] text-text-muted">
                  <span className="text-cyan">NETWORK</span> /{" "}
                  <span>HOST</span>
                </span>
              }
            >
              <BitGrid
                prefixLength={result.prefix_length}
                totalBits={bitCount}
              />
            </Panel>
          )}

          {/* Two-column results */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Addresses */}
            <Panel title="Addresses">
              <DataRow label="Network">{result.network_address}</DataRow>
              {!isIpv6(result) && (
                <>
                  <DataRow label="Broadcast">
                    {result.broadcast_address}
                  </DataRow>
                  <DataRow label="First Host">{result.first_host}</DataRow>
                  <DataRow label="Last Host">{result.last_host}</DataRow>
                </>
              )}
              {isIpv6(result) && (
                <>
                  <DataRow label="Last Address">
                    {result.last_address}
                  </DataRow>
                  <DataRow label="Full Address">
                    <span className="text-[10px]">
                      {result.network_address_full}
                    </span>
                  </DataRow>
                  <DataRow label="Last Full">
                    <span className="text-[10px]">
                      {result.last_address_full}
                    </span>
                  </DataRow>
                </>
              )}
            </Panel>

            {/* Details */}
            <Panel title="Details">
              <DataRow label="Prefix">/{result.prefix_length}</DataRow>
              {!isIpv6(result) && (
                <>
                  <DataRow label="Subnet Mask">{result.subnet_mask}</DataRow>
                  <DataRow label="Wildcard">{result.wildcard_mask}</DataRow>
                  <DataRow label="Total Hosts">
                    <span className="text-cyan">
                      {fmtNum(result.total_hosts)}
                    </span>
                  </DataRow>
                  <DataRow label="Usable Hosts">
                    <span className="text-green">
                      {fmtNum(result.usable_hosts)}
                    </span>
                  </DataRow>
                  <DataRow label="Class">{result.network_class}</DataRow>
                  <DataRow label="Scope">
                    <span
                      className={`inline-block px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.1em] border-2 ${
                        result.is_private
                          ? "border-green text-green"
                          : "border-yellow text-yellow"
                      }`}
                    >
                      {result.is_private ? "PRIVATE" : "PUBLIC"}
                    </span>
                  </DataRow>
                </>
              )}
              {isIpv6(result) && (
                <>
                  <DataRow label="Total Addresses">
                    <span className="text-cyan">{result.total_addresses}</span>
                  </DataRow>
                  <DataRow label="Type">{result.address_type}</DataRow>
                </>
              )}
              {"address_type" in result && !isIpv6(result) && (
                <DataRow label="Type">{result.address_type}</DataRow>
              )}
            </Panel>
          </div>

          {/* Hextets (IPv6 only) */}
          {isIpv6(result) && result.hextets.length > 0 && (
            <Panel title="Hextets">
              <div className="flex gap-1 flex-wrap">
                {result.hextets.map((h, i) => (
                  <div
                    key={i}
                    className="px-2 py-1 border border-border text-[13px] font-semibold"
                  >
                    {h}
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
