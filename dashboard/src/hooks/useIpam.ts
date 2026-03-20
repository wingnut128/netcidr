import { useState, useCallback, useEffect, useMemo } from "react";
import { get, post, patch, put, del } from "../api";
import type {
  Supernet,
  SupernetList,
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
  | "create-supernet"
  | "allocate-specific"
  | "auto-allocate"
  | "alloc-detail"
  | null;

export function useIpam() {
  const [supernets, setSupernets] = useState<Supernet[]>([]);
  const [allocations, setAllocations] = useState<Allocation[]>([]);
  const [freeBlocks, setFreeBlocks] = useState<FreeBlock[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [searchResults, setSearchResults] = useState<Allocation[]>([]);
  const [utilization, setUtilization] = useState<
    Record<string, { pct: number; count: number }>
  >({});
  const [filters, setFiltersState] = useState<AllocationFilters>({
    supernetId: "",
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
    for (const sn of supernets) {
      map[sn.id] = sn.cidr;
    }
    return map;
  }, [supernets]);

  // --- Data loading ---

  const loadSupernets = useCallback(async () => {
    try {
      const data = await get<SupernetList>("/ipam/supernets");
      setSupernets(data.supernets);
      return data.supernets;
    } catch (e) {
      setError(getErrorMessage(e, "Failed to load supernets"));
      return [];
    }
  }, []);

  const loadUtilization = useCallback(async (sns: Supernet[]) => {
    try {
      const results = await Promise.all(
        sns.map((sn) =>
          get<UtilizationReport>(`/ipam/supernets/${sn.id}/utilization`).then(
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
    if (!filters.supernetId) {
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
          `/ipam/supernets/${filters.supernetId}/allocations?${qs}`,
        ),
        get<FreeBlocksReport>(
          `/ipam/supernets/${filters.supernetId}/free`,
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
    const sns = await loadSupernets();
    await Promise.all([loadUtilization(sns), loadAudit()]);
  }, [loadSupernets, loadUtilization, loadAudit]);

  // Load on mount
  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  // Reload allocations when filters change
  useEffect(() => {
    void loadAllocations();
  }, [loadAllocations]);

  // --- Mutations ---

  const createSupernet = useCallback(
    async (form: { cidr: string; name: string; description: string }) => {
      try {
        await post("/ipam/supernets", {
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

  const deleteSupernet = useCallback(
    async (id: string) => {
      if (!confirm("Delete this supernet?")) return;
      try {
        await del(`/ipam/supernets/${id}`);
        await loadAll();
        if (filters.supernetId === id) {
          setFiltersState((f) => ({ ...f, supernetId: "" }));
        }
      } catch (e) {
        setError(getErrorMessage(e, "Delete failed"));
      }
    },
    [loadAll, filters.supernetId],
  );

  const allocateSpecific = useCallback(
    async (form: {
      supernetId: string;
      cidr: string;
      name: string;
      environment: string;
      owner: string;
      resourceId: string;
    }) => {
      try {
        await post(`/ipam/supernets/${form.supernetId}/allocate-specific`, {
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
      supernetId: string;
      prefix: number;
      count: number;
      name: string;
      environment: string;
      owner: string;
    }) => {
      try {
        await post(`/ipam/supernets/${form.supernetId}/allocate`, {
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
      supernets.length > 0
        ? (
            Object.values(utilization).reduce((a, u) => a + u.pct, 0) /
            supernets.length
          ).toFixed(1) + "%"
        : "0%";
    return {
      supernets: supernets.length,
      allocations: totalAllocations,
      utilization: avgUtil,
      freeBlocks: freeBlocks.length,
    };
  }, [utilization, supernets, freeBlocks.length]);

  // --- Actions ---

  const selectSupernet = useCallback((id: string) => {
    setFiltersState((f) => ({ ...f, supernetId: id }));
  }, []);

  const setFilters = useCallback((patch: Partial<AllocationFilters>) => {
    setFiltersState((f) => ({ ...f, ...patch }));
  }, []);

  const viewAllocation = useCallback((a: Allocation) => {
    setDetailAllocation(a);
    setActiveModal("alloc-detail");
  }, []);

  return {
    supernets,
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
    createSupernet,
    deleteSupernet,
    allocateSpecific,
    autoAllocate,
    releaseAllocation,
    reactivateAllocation,
    addTag,
    findIp,
    findResource,
    selectSupernet,
    setFilters,
    viewAllocation,
    openModal: setActiveModal,
    closeModal: () => setActiveModal(null),
    clearError: () => setError(null),
  };
}
