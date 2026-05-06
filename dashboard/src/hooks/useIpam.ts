import { useState, useCallback, useEffect, useMemo } from "react";
import { get, post, patch, put, del } from "../api";
import type {
  CidrBlock,
  CidrBlockList,
  Allocation,
  AllocationList,
  FreeBlock,
  FreeBlocksReport,
  AuditEntry,
  AuditList,
  UtilizationReport,
} from "../types";
import type { AllocationFilters } from "../components/ipam/AllocationTable";
import { getErrorMessage } from "../lib/errors";

type ModalType =
  | "create-cidr-block"
  | "allocate-specific"
  | "auto-allocate"
  | "alloc-detail"
  | null;

export function useIpam() {
  const [cidr_blocks, setCidrBlocks] = useState<CidrBlock[]>([]);
  const [allocations, setAllocations] = useState<Allocation[]>([]);
  const [freeBlocks, setFreeBlocks] = useState<FreeBlock[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [searchResults, setSearchResults] = useState<Allocation[]>([]);
  const [utilization, setUtilization] = useState<
    Record<string, { pct: number; count: number }>
  >({});
  const [filters, setFiltersState] = useState<AllocationFilters>({
    cidr_blockId: "",
    status: "",
    owner: "",
    environment: "",
  });
  const [activeModal, setActiveModal] = useState<ModalType>(null);
  const [detailAllocation, setDetailAllocation] = useState<Allocation | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  // Derived (memoized to preserve referential identity)
  const snMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const sn of cidr_blocks) {
      map[sn.id] = sn.cidr;
    }
    return map;
  }, [cidr_blocks]);

  // --- Data loading ---

  const loadCidrBlocks = useCallback(async () => {
    try {
      const data = await get<CidrBlockList>("/ipam/cidr-blocks");
      setCidrBlocks(data.cidr_blocks);
      return data.cidr_blocks;
    } catch (e) {
      setError(getErrorMessage(e, "Failed to load CIDR blocks"));
      return [];
    }
  }, []);

  const loadUtilization = useCallback(async (sns: CidrBlock[]) => {
    try {
      const results = await Promise.all(
        sns.map((sn) =>
          get<UtilizationReport>(`/ipam/cidr-blocks/${sn.id}/utilization`).then(
            (u) => ({ id: sn.id, pct: u.utilization_percent, count: u.allocation_count }),
          ),
        ),
      );
      const map: Record<string, { pct: number; count: number }> = {};
      for (const r of results) {
        map[r.id] = { pct: r.pct, count: r.count };
      }
      setUtilization(map);
    } catch {
      // Non-critical, keep going
    }
  }, []);

  const loadAllocations = useCallback(async () => {
    if (!filters.cidr_blockId) {
      setAllocations([]);
      setFreeBlocks([]);
      return;
    }
    try {
      let qs = "";
      if (filters.status) qs += `&status=${filters.status}`;
      if (filters.owner) qs += `&owner=${encodeURIComponent(filters.owner)}`;
      if (filters.environment)
        qs += `&environment=${encodeURIComponent(filters.environment)}`;

      const [allocs, free] = await Promise.all([
        get<AllocationList>(
          `/ipam/cidr-blocks/${filters.cidr_blockId}/allocations?${qs}`,
        ),
        get<FreeBlocksReport>(
          `/ipam/cidr-blocks/${filters.cidr_blockId}/free`,
        ),
      ]);
      setAllocations(allocs.allocations);
      setFreeBlocks(free.blocks);
    } catch (e) {
      setError(getErrorMessage(e, "Failed to load allocations"));
    }
  }, [filters]);

  const loadAudit = useCallback(async () => {
    try {
      const data = await get<AuditList>("/ipam/audit?limit=20");
      setAudit(data.entries);
    } catch {
      // Non-critical
    }
  }, []);

  const loadAll = useCallback(async () => {
    const sns = await loadCidrBlocks();
    await Promise.all([loadUtilization(sns), loadAudit()]);
  }, [loadCidrBlocks, loadUtilization, loadAudit]);

  // Load on mount
  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  // Reload allocations when filters change
  useEffect(() => {
    void loadAllocations();
  }, [loadAllocations]);

  // --- Mutations ---

  const createCidrBlock = useCallback(
    async (form: { cidr: string; name: string; description: string }) => {
      try {
        await post("/ipam/cidr-blocks", {
          cidr: form.cidr,
          name: form.name || undefined,
          description: form.description || undefined,
        });
        setActiveModal(null);
        await loadAll();
      } catch (e) {
        setError(getErrorMessage(e, "Create failed"));
        throw e;
      }
    },
    [loadAll],
  );

  const deleteCidrBlock = useCallback(
    async (id: string) => {
      if (!confirm("Delete this CIDR block?")) return;
      try {
        await del(`/ipam/cidr-blocks/${id}`);
        await loadAll();
        if (filters.cidr_blockId === id) {
          setFiltersState((f) => ({ ...f, cidr_blockId: "" }));
        }
      } catch (e) {
        setError(getErrorMessage(e, "Delete failed"));
      }
    },
    [loadAll, filters.cidr_blockId],
  );

  const allocateSpecific = useCallback(
    async (form: {
      cidr_blockId: string;
      cidr: string;
      name: string;
      environment: string;
      owner: string;
      resourceId: string;
    }) => {
      try {
        await post(`/ipam/cidr-blocks/${form.cidr_blockId}/allocate-specific`, {
          cidr: form.cidr,
          name: form.name || undefined,
          environment: form.environment || undefined,
          owner: form.owner || undefined,
          resource_id: form.resourceId || undefined,
        });
        setActiveModal(null);
        await Promise.all([loadAll(), loadAllocations()]);
      } catch (e) {
        setError(getErrorMessage(e, "Allocation failed"));
        throw e;
      }
    },
    [loadAll, loadAllocations],
  );

  const autoAllocate = useCallback(
    async (form: {
      cidr_blockId: string;
      prefix: number;
      count: number;
      name: string;
      environment: string;
      owner: string;
    }) => {
      try {
        await post(`/ipam/cidr-blocks/${form.cidr_blockId}/allocate`, {
          prefix_length: form.prefix,
          count: form.count,
          name: form.name || undefined,
          environment: form.environment || undefined,
          owner: form.owner || undefined,
        });
        setActiveModal(null);
        await Promise.all([loadAll(), loadAllocations()]);
      } catch (e) {
        setError(getErrorMessage(e, "Auto-allocate failed"));
        throw e;
      }
    },
    [loadAll, loadAllocations],
  );

  const releaseAllocation = useCallback(
    async (id: string) => {
      if (!confirm("Release this allocation?")) return;
      try {
        await post(`/ipam/allocations/${id}/release`);
        await Promise.all([loadAll(), loadAllocations()]);
      } catch (e) {
        setError(getErrorMessage(e, "Release failed"));
      }
    },
    [loadAll, loadAllocations],
  );

  const reactivateAllocation = useCallback(
    async (id: string) => {
      if (!confirm("Re-activate this allocation?")) return;
      try {
        await patch(`/ipam/allocations/${id}`, { status: "active" });
        await Promise.all([loadAll(), loadAllocations()]);
      } catch (e) {
        setError(getErrorMessage(e, "Re-activate failed"));
      }
    },
    [loadAll, loadAllocations],
  );

  const addTag = useCallback(
    async (allocationId: string, key: string, value: string) => {
      try {
        const alloc = allocations.find((a) => a.id === allocationId);
        const existing = alloc?.tags ?? [];
        const tags = [...existing, { key, value }];
        await put(`/ipam/allocations/${allocationId}/tags`, { tags });
        // Refresh detail and allocation list concurrently
        const [updated] = await Promise.all([
          get<Allocation>(`/ipam/allocations/${allocationId}`),
          loadAllocations(),
        ]);
        setDetailAllocation(updated);
      } catch (e) {
        setError(getErrorMessage(e, "Add tag failed"));
      }
    },
    [allocations, loadAllocations],
  );

  const findIp = useCallback(async (address: string) => {
    if (!address) return;
    try {
      const data = await get<AllocationList>(
        `/ipam/find-ip/${encodeURIComponent(address)}`,
      );
      setSearchResults(data.allocations);
    } catch (e) {
      setError(getErrorMessage(e, "Find IP failed"));
      setSearchResults([]);
    }
  }, []);

  const findResource = useCallback(async (resourceId: string) => {
    if (!resourceId) return;
    try {
      const data = await get<AllocationList>(
        `/ipam/find-resource/${encodeURIComponent(resourceId)}`,
      );
      setSearchResults(data.allocations);
    } catch (e) {
      setError(getErrorMessage(e, "Find resource failed"));
      setSearchResults([]);
    }
  }, []);

  // --- Computed stats (memoized) ---

  const stats = useMemo(() => {
    const totalAllocations = Object.values(utilization).reduce(
      (a, u) => a + u.count,
      0,
    );
    const avgUtil =
      cidr_blocks.length > 0
        ? (
            Object.values(utilization).reduce((a, u) => a + u.pct, 0) /
            cidr_blocks.length
          ).toFixed(1) + "%"
        : "0%";
    return {
      cidr_blocks: cidr_blocks.length,
      allocations: totalAllocations,
      utilization: avgUtil,
      freeBlocks: freeBlocks.length,
    };
  }, [utilization, cidr_blocks, freeBlocks.length]);

  // --- Actions ---

  const selectCidrBlock = useCallback((id: string) => {
    setFiltersState((f) => ({ ...f, cidr_blockId: id }));
  }, []);

  const setFilters = useCallback((patch: Partial<AllocationFilters>) => {
    setFiltersState((f) => ({ ...f, ...patch }));
  }, []);

  const viewAllocation = useCallback((a: Allocation) => {
    setDetailAllocation(a);
    setActiveModal("alloc-detail");
  }, []);

  return {
    cidr_blocks,
    allocations,
    freeBlocks,
    audit,
    searchResults,
    utilization,
    snMap,
    filters,
    activeModal,
    detailAllocation,
    error,
    stats,
    // Actions
    loadAll,
    createCidrBlock,
    deleteCidrBlock,
    allocateSpecific,
    autoAllocate,
    releaseAllocation,
    reactivateAllocation,
    addTag,
    findIp,
    findResource,
    selectCidrBlock,
    setFilters,
    viewAllocation,
    openModal: setActiveModal,
    closeModal: () => setActiveModal(null),
    clearError: () => setError(null),
  };
}
