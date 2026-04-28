import { useIpam } from "../hooks/useIpam";
import { PageHeader } from "../components/ui/PageHeader";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { IpamStats } from "../components/ipam/IpamStats";
import { IpamSearch } from "../components/ipam/IpamSearch";
import { SupernetTable } from "../components/ipam/SupernetTable";
import { AllocationTable } from "../components/ipam/AllocationTable";
import { FreeBlocksList } from "../components/ipam/FreeBlocksList";
import { AuditLog } from "../components/ipam/AuditLog";
import { CreateSupernetModal } from "../components/ipam/modals/CreateSupernetModal";
import { AllocateSpecificModal } from "../components/ipam/modals/AllocateSpecificModal";
import { AutoAllocateModal } from "../components/ipam/modals/AutoAllocateModal";
import { AllocationDetailModal } from "../components/ipam/modals/AllocationDetailModal";
import { useAuth } from "../auth/AuthContext";
import { isAuthConfigured } from "../auth/oidc";
import { SignInCard } from "../components/auth/SignInCard";

export function Ipam() {
  const auth = useAuth();

  if (auth.status === "loading") {
    return (
      <div className="flex items-center justify-center min-h-[60vh] text-text-muted text-xs">
        Loading…
      </div>
    );
  }

  // Show the sign-in card whenever the user isn't authenticated — including
  // the "disabled" state where the build was missing VITE_OAUTH_WEB_CLIENT_ID.
  // SignInCard renders a "not configured" message in that case rather than a
  // working button, which is more honest than letting the dashboard render
  // and 401 on every API call.
  if (auth.status !== "authenticated") {
    return (
      <SignInCard
        onSignIn={() => void auth.signIn()}
        configured={isAuthConfigured}
        error={auth.error}
      />
    );
  }

  return <IpamDashboard />;
}

function IpamDashboard() {
  const ipam = useIpam();

  return (
    <div>
      <PageHeader
        title="IPAM Dashboard"
        subtitle="IP Address Management"
      />

      <ErrorBanner message={ipam.error} onDismiss={ipam.clearError} />

      <IpamStats
        supernetCount={ipam.stats.supernets}
        allocationCount={ipam.stats.allocations}
        avgUtilization={ipam.stats.utilization}
        freeBlockCount={ipam.stats.freeBlocks}
      />

      <IpamSearch
        onFindIp={ipam.findIp}
        onFindResource={ipam.findResource}
        searchResults={ipam.searchResults}
      />

      <SupernetTable
        supernets={ipam.supernets}
        utilization={ipam.utilization}
        onSelect={ipam.selectSupernet}
        onDelete={ipam.deleteSupernet}
        onCreateClick={() => ipam.openModal("create-supernet")}
      />

      <AllocationTable
        allocations={ipam.allocations}
        supernets={ipam.supernets}
        snMap={ipam.snMap}
        filters={ipam.filters}
        onFiltersChange={ipam.setFilters}
        onViewDetail={ipam.viewAllocation}
        onRelease={ipam.releaseAllocation}
        onReactivate={ipam.reactivateAllocation}
        onAllocateSpecificClick={() => ipam.openModal("allocate-specific")}
        onAutoAllocateClick={() => ipam.openModal("auto-allocate")}
      />

      {/* Free blocks + Audit side by side */}
      {ipam.filters.supernetId && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <FreeBlocksList blocks={ipam.freeBlocks} />
          <AuditLog entries={ipam.audit} />
        </div>
      )}

      {/* Modals */}
      <CreateSupernetModal
        open={ipam.activeModal === "create-supernet"}
        onClose={ipam.closeModal}
        onSubmit={ipam.createSupernet}
      />
      <AllocateSpecificModal
        open={ipam.activeModal === "allocate-specific"}
        onClose={ipam.closeModal}
        supernets={ipam.supernets}
        defaultSupernetId={ipam.filters.supernetId || undefined}
        onSubmit={ipam.allocateSpecific}
      />
      <AutoAllocateModal
        open={ipam.activeModal === "auto-allocate"}
        onClose={ipam.closeModal}
        supernets={ipam.supernets}
        defaultSupernetId={ipam.filters.supernetId || undefined}
        onSubmit={ipam.autoAllocate}
      />
      <AllocationDetailModal
        open={ipam.activeModal === "alloc-detail"}
        onClose={ipam.closeModal}
        allocation={ipam.detailAllocation}
        onAddTag={ipam.addTag}
      />
    </div>
  );
}
