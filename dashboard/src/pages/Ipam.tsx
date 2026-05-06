import { useIpam } from "../hooks/useIpam";
import { PageHeader } from "../components/ui/PageHeader";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { IpamStats } from "../components/ipam/IpamStats";
import { IpamSearch } from "../components/ipam/IpamSearch";
import { CidrBlockTable } from "../components/ipam/CidrBlockTable";
import { AllocationTable } from "../components/ipam/AllocationTable";
import { FreeBlocksList } from "../components/ipam/FreeBlocksList";
import { AuditLog } from "../components/ipam/AuditLog";
import { CreateCidrBlockModal } from "../components/ipam/modals/CreateCidrBlockModal";
import { AllocateSpecificModal } from "../components/ipam/modals/AllocateSpecificModal";
import { AutoAllocateModal } from "../components/ipam/modals/AutoAllocateModal";
import { AllocationDetailModal } from "../components/ipam/modals/AllocationDetailModal";
import { AuthGate } from "../components/auth/AuthGate";

export function Ipam() {
  return (
    <AuthGate>
      <IpamDashboard />
    </AuthGate>
  );
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
        cidr_blockCount={ipam.stats.cidr_blocks}
        allocationCount={ipam.stats.allocations}
        avgUtilization={ipam.stats.utilization}
        freeBlockCount={ipam.stats.freeBlocks}
      />

      <IpamSearch
        onFindIp={ipam.findIp}
        onFindResource={ipam.findResource}
        searchResults={ipam.searchResults}
      />

      <CidrBlockTable
        cidr_blocks={ipam.cidr_blocks}
        utilization={ipam.utilization}
        onSelect={ipam.selectCidrBlock}
        onDelete={ipam.deleteCidrBlock}
        onCreateClick={() => ipam.openModal("create-cidr-block")}
      />

      <AllocationTable
        allocations={ipam.allocations}
        cidr_blocks={ipam.cidr_blocks}
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
      {ipam.filters.cidr_blockId && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <FreeBlocksList blocks={ipam.freeBlocks} />
          <AuditLog entries={ipam.audit} />
        </div>
      )}

      {/* Modals */}
      <CreateCidrBlockModal
        open={ipam.activeModal === "create-cidr-block"}
        onClose={ipam.closeModal}
        onSubmit={ipam.createCidrBlock}
      />
      <AllocateSpecificModal
        open={ipam.activeModal === "allocate-specific"}
        onClose={ipam.closeModal}
        cidr_blocks={ipam.cidr_blocks}
        defaultCidrBlockId={ipam.filters.cidr_blockId || undefined}
        onSubmit={ipam.allocateSpecific}
      />
      <AutoAllocateModal
        open={ipam.activeModal === "auto-allocate"}
        onClose={ipam.closeModal}
        cidr_blocks={ipam.cidr_blocks}
        defaultCidrBlockId={ipam.filters.cidr_blockId || undefined}
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
