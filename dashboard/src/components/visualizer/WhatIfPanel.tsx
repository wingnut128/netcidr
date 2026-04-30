import { useMemo, useState } from "react";
import type { Allocation } from "../../types";
import {
  checkFit,
  parseCidr,
  type FitVerdict,
  type ParsedCidr,
} from "../../lib/cidr";

interface WhatIfPanelProps {
  supernetCidr: string;
  /** Active + reserved allocations only — released ones are reusable. */
  takenCidrs: Allocation[];
  onResultsChange: (fits: ParsedCidr[], conflicts: ParsedCidr[]) => void;
}

interface Row {
  raw: string;
  verdict: FitVerdict;
  parsed: ParsedCidr | null;
}

const VERDICT_BADGE: Record<FitVerdict["kind"], string> = {
  fits: "border-cyan/40 text-cyan bg-cyan/10",
  conflict: "border-red/40 text-red bg-red/10",
  outside: "border-yellow/40 text-yellow bg-yellow/10",
  invalid: "border-text-muted text-text-muted bg-surface2",
};

const VERDICT_LABEL: Record<FitVerdict["kind"], string> = {
  fits: "Fits",
  conflict: "Conflict",
  outside: "Outside",
  invalid: "Invalid",
};

export function WhatIfPanel({
  supernetCidr,
  takenCidrs,
  onResultsChange,
}: WhatIfPanelProps) {
  const [text, setText] = useState("");

  const rows = useMemo<Row[]>(() => {
    const supernet = parseCidr(supernetCidr);
    if (!supernet) return [];
    const taken = takenCidrs
      .filter((a) => a.status !== "released")
      .map((a) => parseCidr(a.cidr))
      .filter((p): p is ParsedCidr => p !== null);
    return text
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((raw) => {
        const verdict = checkFit(raw, supernet, taken);
        const parsed = parseCidr(raw);
        return { raw, verdict, parsed };
      });
  }, [text, supernetCidr, takenCidrs]);

  // Push the parsed CIDRs up to the parent so the AllocationMap can paint
  // them as overlays. Wrapped in a ref-style memo so we don't churn on each
  // render — only when the verdict-set actually changes.
  const fits = useMemo(
    () =>
      rows
        .filter((r) => r.verdict.kind === "fits" && r.parsed)
        .map((r) => r.parsed!),
    [rows],
  );
  const conflicts = useMemo(
    () =>
      rows
        .filter((r) => r.verdict.kind === "conflict" && r.parsed)
        .map((r) => r.parsed!),
    [rows],
  );

  // Notify parent when the result-set changes.
  const fitsKey = fits.map((p) => p.cidr).join(",");
  const conflictsKey = conflicts.map((p) => p.cidr).join(",");
  useMemo(() => {
    onResultsChange(fits, conflicts);
    // We intentionally key off the *content* of the lists so the callback
    // only fires when the candidates actually change, not on every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fitsKey, conflictsKey]);

  return (
    <div>
      <p className="text-sm text-text-muted mb-3">
        Paste candidate CIDRs (one per line) to see whether they would fit
        within {supernetCidr} without colliding with existing allocations.
        Fitting candidates render as outlined cyan overlays on the map;
        conflicts render in red.
      </p>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="10.0.64.0/22&#10;10.0.96.0/24"
        rows={4}
        className="w-full font-mono text-base md:text-sm px-3 py-2 bg-bg border border-border rounded-md text-text outline-none focus:border-cyan focus:ring-2 focus:ring-cyan/20 transition-colors mb-4"
      />
      {rows.length > 0 && (
        <div className="space-y-1.5">
          {rows.map((r, i) => (
            <div key={i} className="flex items-center gap-3 text-sm">
              <span
                className={`inline-block px-2 py-0.5 text-xs font-medium rounded-md border ${VERDICT_BADGE[r.verdict.kind]}`}
              >
                {VERDICT_LABEL[r.verdict.kind]}
              </span>
              <span className="font-mono">{r.raw}</span>
              <span className="text-text-muted">— {r.verdict.reason}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
