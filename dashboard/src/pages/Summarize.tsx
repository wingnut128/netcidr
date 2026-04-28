import { useState, useCallback } from "react";
import { get } from "../api";
import type { SummarizeResult } from "../types";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { StatCard } from "../components/ui/StatCard";
import { ErrorBanner } from "../components/ui/ErrorBanner";

export function Summarize() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<SummarizeResult | null>(null);
  const [inputList, setInputList] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const doSummarize = useCallback(async () => {
    const raw = input.trim();
    if (!raw) return;
    const cidrs = raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    setInputList(cidrs);

    const isV6 = cidrs.some((c) => c.includes(":"));
    const ep = isV6 ? "/v6/summarize" : "/v4/summarize";
    try {
      const data = await get<SummarizeResult>(
        `${ep}?cidrs=${encodeURIComponent(cidrs.join(","))}`,
      );
      setResult(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setResult(null);
    }
  }, [input]);

  const reduction =
    result && result.input_count > 0
      ? Math.round((1 - result.output_count / result.input_count) * 100) + "%"
      : "0%";

  return (
    <div>
      <PageHeader
        title="Summarize"
        subtitle="Aggregate multiple CIDRs into minimal set"
      />
      <ErrorBanner message={error} onDismiss={() => setError(null)} />

      <Panel title="Input CIDRs">
        <label className="block text-xs font-bold text-text-muted mb-1">
          One CIDR per line (or comma-separated)
        </label>
        <textarea
          className="w-full min-h-[100px] font-mono text-sm px-3 py-2 bg-bg border border-border text-text outline-none focus:border-cyan resize-y"
          placeholder={"192.168.1.0/25\n192.168.1.128/25\n10.0.0.0/24"}
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button
          className="mt-3 text-xs font-medium rounded-md px-4 py-2 border border-cyan text-cyan bg-surface2 cursor-pointer hover:bg-cyan hover:text-bg transition-colors"
          onClick={doSummarize}
        >
          SUMMARIZE
        </button>
      </Panel>

      {result && (
        <>
          <div className="grid grid-cols-3 gap-4 mb-5">
            <StatCard
              label="Input CIDRs"
              value={result.input_count}
              color="yellow"
            />
            <StatCard
              label="Output CIDRs"
              value={result.output_count}
              color="green"
            />
            <StatCard label="Reduction" value={reduction} color="cyan" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <Panel title="Input">
              {inputList.map((c) => (
                <div
                  key={c}
                  className="py-1 border-b border-border text-text"
                >
                  {c}
                </div>
              ))}
            </Panel>
            <Panel title="Summarized">
              {(result.cidrs ?? []).map((s) => (
                <div
                  key={s.input}
                  className="py-1 border-b border-border text-cyan"
                >
                  {s.input}
                </div>
              ))}
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
