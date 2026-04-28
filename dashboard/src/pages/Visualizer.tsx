import { useEffect, useMemo, useState } from "react";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { StatCard } from "../components/ui/StatCard";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { SignInCard } from "../components/auth/SignInCard";
import { AllocationMap } from "../components/visualizer/AllocationMap";
import { WhatIfPanel } from "../components/visualizer/WhatIfPanel";
import { AllocationDetailModal } from "../components/ipam/modals/AllocationDetailModal";
import { useIpam } from "../hooks/useIpam";
import { useAuth } from "../auth/AuthContext";
import { isAuthConfigured } from "../auth/oidc";
import type { Allocation } from "../types";
import type { ParsedCidr } from "../lib/cidr";

export function Visualizer() {
  const auth = useAuth();

  if (auth.status === "loading") {
    return (
      <div className="flex items-center justify-center min-h-[60vh] text-text-muted text-xs">
        Loading…
      </div>
    );
  }
  if (auth.status !== "authenticated") {
    return (
      <SignInCard
        onSignIn={() => void auth.signIn()}
        configured={isAuthConfigured}
      />
    );
  }

  return <VisualizerInner />;
}

function VisualizerInner() {
  const ipam = useIpam();
  const [selectedId, setSelectedId] = useState<string>("");
  const [whatIfFits, setWhatIfFits] = useState<ParsedCidr[]>([]);
  const [whatIfConflicts, setWhatIfConflicts] = useState<ParsedCidr[]>([]);

  // Default-select the first supernet once the list loads.
  useEffect(() => {
    const first = ipam.supernets[0];
    if (!selectedId && first) {
      setSelectedId(first.id);
    }
  }, [ipam.supernets, selectedId]);

  // Drive the IPAM hook's filters → fetches allocations + free blocks.
  useEffect(() => {
    if (selectedId) {
      ipam.setFilters({ supernetId: selectedId, status: "" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  const supernet = useMemo(
    () => ipam.supernets.find((s) => s.id === selectedId),
    [ipam.supernets, selectedId],
  );

  const stats = useMemo(() => {
    if (!supernet) return null;
    const u = ipam.utilization[supernet.id];
    return {
      used: u?.count ?? ipam.allocations.length,
      utilization: u ? `${u.pct.toFixed(1)}%` : "—",
      freeBlocks: ipam.freeBlocks.length,
    };
  }, [supernet, ipam.utilization, ipam.allocations.length, ipam.freeBlocks.length]);

  const handleAllocationClick = (a: Allocation) => {
    ipam.viewAllocation(a);
  };

  return (
    <div>
      <PageHeader
        title="Allocation Map"
        subtitle="Visualize an IPAM supernet's address space"
      />
      <ErrorBanner message={ipam.error} onDismiss={ipam.clearError} />

      {ipam.supernets.length === 0 ? (
        <Panel>
          <p className="text-text-muted text-sm">
            No supernets yet. Create one on the IPAM tab first, then come back
            here to map it.
          </p>
        </Panel>
      ) : (
        <>
          <Panel title="Supernet">
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              className="w-full font-mono text-sm px-3 py-2 bg-bg border border-border rounded-md text-text outline-none focus:border-cyan focus:ring-2 focus:ring-cyan/20 transition-colors"
            >
              {ipam.supernets.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.cidr}
                  {s.name ? ` — ${s.name}` : ""}
                </option>
              ))}
            </select>
          </Panel>

          {supernet && stats && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                <StatCard
                  label="Network"
                  value={supernet.cidr}
                  color="cyan"
                  valueSize="16px"
                />
                <StatCard label="Allocations" value={stats.used} color="green" />
                <StatCard
                  label="Utilization"
                  value={stats.utilization}
                  color="yellow"
                />
                <StatCard
                  label="Free Blocks"
                  value={stats.freeBlocks}
                  color="purple"
                />
              </div>

              <Panel
                title="Address Space"
                actions={
                  <div className="flex items-center gap-3 text-xs">
                    <Legend swatch="bg-green/70" label="Active" />
                    <Legend swatch="bg-yellow/70" label="Reserved" />
                    <Legend swatch="bg-text-muted/30" label="Released" />
                    <Legend swatch="bg-transparent border border-border" label="Free" />
                  </div>
                }
              >
                <AllocationMap
                  supernet={supernet}
                  allocations={ipam.allocations}
                  freeBlocks={ipam.freeBlocks}
                  whatIfFits={whatIfFits}
                  whatIfConflicts={whatIfConflicts}
                  onAllocationClick={handleAllocationClick}
                />
              </Panel>

              <Panel title="What if" collapsible defaultOpen={false}>
                <WhatIfPanel
                  supernetCidr={supernet.cidr}
                  takenCidrs={ipam.allocations}
                  onResultsChange={(fits, conflicts) => {
                    setWhatIfFits(fits);
                    setWhatIfConflicts(conflicts);
                  }}
                />
              </Panel>
            </>
          )}
        </>
      )}

      <AllocationDetailModal
        open={ipam.activeModal === "alloc-detail"}
        onClose={ipam.closeModal}
        allocation={ipam.detailAllocation}
        onAddTag={ipam.addTag}
      />
    </div>
  );
}

function Legend({ swatch, label }: { swatch: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-text-muted">
      <span className={`inline-block h-2.5 w-2.5 rounded-sm ${swatch}`} />
      {label}
    </span>
  );
}
