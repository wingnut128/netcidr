import { useState, useCallback, useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { get } from "../api";
import type { CalcResult, Ipv4Subnet } from "../types";
import { fmtSize } from "../lib/format";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { StatCard } from "../components/ui/StatCard";
import { ErrorBanner } from "../components/ui/ErrorBanner";

interface GridCell {
  cls: string;
  label: string;
}

function isV4(r: CalcResult): r is Ipv4Subnet {
  return "total_hosts" in r;
}

export function Visualizer() {
  const [cidr, setCidr] = useState("");
  const [result, setResult] = useState<CalcResult | null>(null);
  const [cells, setCells] = useState<GridCell[]>([]);
  const [gridCols, setGridCols] = useState(16);
  const [error, setError] = useState<string | null>(null);

  const doVisualize = useCallback(async () => {
    const input = cidr.trim();
    if (!input) return;
    try {
      const isV6 = input.includes(":");
      const ep = isV6 ? "/v6" : "/v4";
      const data = await get<CalcResult>(
        `${ep}?cidr=${encodeURIComponent(input)}`,
      );
      setResult(data);

      const prefix = data.prefix_length;
      const totalBits = isV6 ? 128 : 32;
      const hostBits = totalBits - prefix;

      let splitPrefix: number;
      if (hostBits <= 4) {
        splitPrefix = totalBits;
      } else if (hostBits <= 8) {
        splitPrefix = prefix + Math.ceil(hostBits / 2);
      } else {
        splitPrefix = Math.min(prefix + 8, totalBits);
      }

      const cellCount = Math.min(Math.pow(2, splitPrefix - prefix), 1024);
      setGridCols(Math.min(Math.ceil(Math.sqrt(cellCount)), 32));

      const newCells: GridCell[] = [];
      for (let i = 0; i < cellCount; i++) {
        newCells.push({ cls: "viz-free", label: `Block ${i}` });
      }
      setCells(newCells);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setResult(null);
      setCells([]);
    }
  }, [cidr]);

  // Split distribution data (IPv4 only, hostBits >= 4)
  const splitData = useMemo(() => {
    if (!result || !isV4(result)) return null;
    const prefix = result.prefix_length;
    const hostBits = 32 - prefix;
    if (hostBits < 4) return null;
    const data = [];
    for (let p = prefix + 1; p <= Math.min(prefix + 8, 32); p++) {
      data.push({
        prefix: `/${p}`,
        count: Math.pow(2, p - prefix),
      });
    }
    return data;
  }, [result]);

  const totalSize = result
    ? isV4(result)
      ? result.total_hosts
      : (result as { total_addresses?: string }).total_addresses ?? "0"
    : 0;

  return (
    <div>
      <PageHeader
        title="Subnet Visualizer"
        subtitle="Visual address space map"
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Input">
        <div className="flex gap-3">
          <input
            type="text"
            className="flex-1 font-mono text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan"
            placeholder="e.g. 10.0.0.0/16"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doVisualize()}
          />
          <button
            className="text-xs font-medium rounded-md px-4 py-2 border border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
            onClick={doVisualize}
          >
            VISUALIZE
          </button>
        </div>
      </Panel>

      {result && (
        <>
          <div className="grid grid-cols-3 gap-4 mb-5">
            <StatCard
              label="Network"
              value={result.input}
              color="cyan"
              valueSize="16px"
            />
            <StatCard
              label="Total Addresses"
              value={fmtSize(totalSize)}
              color="green"
            />
            <StatCard
              label="Prefix"
              value={`/${result.prefix_length}`}
              color="yellow"
            />
          </div>

          {/* Address Space Grid */}
          <Panel
            title="Address Space Map"
            actions={
              <span className="text-xs text-text-muted">
                <span className="text-cyan">ALLOCATED</span> /{" "}
                <span className="text-yellow">PARTIAL</span> /{" "}
                <span>FREE</span>
              </span>
            }
          >
            <div
              className="grid gap-px bg-border"
              style={{
                gridTemplateColumns: `repeat(${gridCols}, 1fr)`,
              }}
            >
              {cells.map((cell, i) => (
                <div
                  key={i}
                  className={`aspect-square flex items-center justify-center text-[8px] cursor-default min-w-0 ${
                    cell.cls === "viz-alloc"
                      ? "bg-cyan/30"
                      : cell.cls === "viz-partial"
                        ? "bg-yellow/30"
                        : "bg-surface2"
                  }`}
                  title={cell.label}
                />
              ))}
            </div>
          </Panel>

          {/* Split Distribution Chart */}
          {splitData && (
            <Panel title="Subnet Split Distribution">
              <div className="h-[250px] my-4">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={splitData}>
                    <XAxis
                      dataKey="prefix"
                      tick={{ fill: "#777", fontFamily: "monospace", fontSize: 11 }}
                      axisLine={{ stroke: "#333" }}
                      tickLine={{ stroke: "#333" }}
                    />
                    <YAxis
                      scale="log"
                      domain={["auto", "auto"]}
                      allowDataOverflow
                      tick={{ fill: "#777", fontFamily: "monospace", fontSize: 11 }}
                      axisLine={{ stroke: "#333" }}
                      tickLine={{ stroke: "#333" }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#111",
                        border: "1px solid #333",
                        fontFamily: "monospace",
                        fontSize: 12,
                      }}
                      labelStyle={{ color: "#777" }}
                      itemStyle={{ color: "#00ffcc" }}
                    />
                    <Bar
                      dataKey="count"
                      fill="#00ffcc"
                      name="Possible Subnets"
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
