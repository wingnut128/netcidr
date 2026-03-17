use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use chrono::Utc;

use crate::error::{IpCalcError, Result};
use crate::ipam::models::*;
use crate::ipam::store::IpamStore;
use crate::validation;

/// High-level IPAM operations that sit above the store trait.
/// All conflict detection and free-space logic lives here, keeping
/// the store as a thin persistence boundary.
pub struct IpamOps {
    store: Arc<dyn IpamStore>,
}

impl std::fmt::Debug for IpamOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpamOps").finish_non_exhaustive()
    }
}

impl IpamOps {
    pub fn new(store: Arc<dyn IpamStore>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &dyn IpamStore {
        self.store.as_ref()
    }

    // -----------------------------------------------------------------------
    // Supernet operations
    // -----------------------------------------------------------------------

    pub async fn create_supernet(&self, input: &CreateSupernet) -> Result<Supernet> {
        validation::validate_cidr(&input.cidr)?;
        validation::validate_optional_text(&input.name, 0)?;
        validation::validate_optional_text(&input.description, 0)?;

        let candidate = parse_range(&input.cidr)?;

        // Check for overlap with existing supernets
        let existing = self.store.list_supernets().await?;
        for sn in &existing {
            let existing_range = parse_range(&sn.cidr)?;
            if ranges_overlap(&candidate, &existing_range) {
                return Err(IpCalcError::AllocationConflict {
                    existing: sn.cidr.clone(),
                    candidate: input.cidr.clone(),
                });
            }
        }

        let supernet = self.store.create_supernet(input).await?;
        self.audit(
            "create_supernet",
            "supernet",
            &supernet.id,
            Some(&supernet.cidr),
        )
        .await?;
        Ok(supernet)
    }

    pub async fn get_supernet(&self, id: &str) -> Result<Supernet> {
        validation::validate_identifier(id)?;
        self.store.get_supernet(id).await
    }

    pub async fn list_supernets(&self) -> Result<Vec<Supernet>> {
        self.store.list_supernets().await
    }

    pub async fn delete_supernet(&self, id: &str) -> Result<()> {
        validation::validate_identifier(id)?;
        let sn = self.store.get_supernet(id).await?;
        self.store.delete_supernet(id).await?;
        self.audit("delete_supernet", "supernet", id, Some(&sn.cidr))
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Allocation operations
    // -----------------------------------------------------------------------

    /// Allocate a specific CIDR block within a supernet.
    pub async fn allocate_specific(&self, input: &CreateAllocation) -> Result<Allocation> {
        Self::validate_create_allocation(input)?;

        let supernet = self.store.get_supernet(&input.supernet_id).await?;
        let supernet_range = parse_range(&supernet.cidr)?;
        let candidate_range = parse_range(&input.cidr)?;

        // Verify the candidate falls within the supernet
        if !range_contains(&supernet_range, &candidate_range) {
            return Err(IpCalcError::AllocationConflict {
                existing: supernet.cidr.clone(),
                candidate: format!("{} is outside supernet", input.cidr),
            });
        }

        // Check for parent containment if specified
        if let Some(ref parent_id) = input.parent_allocation_id {
            let parent = self.store.get_allocation(parent_id).await?;
            let parent_range = parse_range(&parent.cidr)?;
            if !range_contains(&parent_range, &candidate_range) {
                return Err(IpCalcError::AllocationConflict {
                    existing: parent.cidr.clone(),
                    candidate: format!("{} does not fit within parent allocation", input.cidr),
                });
            }
        }

        // Check overlap with existing active/reserved allocations
        self.check_overlap(&input.supernet_id, &candidate_range, &input.cidr)
            .await?;

        let alloc = self.store.create_allocation(input).await?;
        self.audit("allocate", "allocation", &alloc.id, Some(&alloc.cidr))
            .await?;
        Ok(alloc)
    }

    /// Auto-allocate the next available block(s) of a given prefix length.
    pub async fn allocate_auto(&self, request: &AutoAllocateRequest) -> Result<Vec<Allocation>> {
        validation::validate_identifier(&request.supernet_id)?;
        validation::validate_optional_text(&request.name, 0)?;
        validation::validate_optional_text(&request.description, 0)?;
        validation::validate_optional_text(&request.owner, 0)?;
        validation::validate_optional_text(&request.environment, 0)?;
        validation::validate_optional_identifier(&request.resource_id)?;
        validation::validate_optional_identifier(&request.parent_allocation_id)?;

        let supernet = self.store.get_supernet(&request.supernet_id).await?;
        let supernet_range = parse_range(&supernet.cidr)?;
        let count = request.count.unwrap_or(1);

        let existing = self
            .store
            .find_allocations_in_supernet(
                &request.supernet_id,
                &[AllocationStatus::Active, AllocationStatus::Reserved],
            )
            .await?;

        let existing_ranges: Vec<IpRange> = existing
            .iter()
            .filter_map(|a| parse_range(&a.cidr).ok())
            .collect();

        let blocks = find_free_blocks(
            &supernet_range,
            &existing_ranges,
            request.prefix_length,
            count,
        )?;

        if blocks.is_empty() {
            return Err(IpCalcError::NoFreeSpace {
                supernet: supernet.cidr.clone(),
                prefix: request.prefix_length,
            });
        }

        let mut allocations = Vec::with_capacity(blocks.len());
        for cidr in blocks {
            let input = CreateAllocation {
                supernet_id: request.supernet_id.clone(),
                cidr,
                status: request.status.clone(),
                resource_id: request.resource_id.clone(),
                resource_type: request.resource_type.clone(),
                name: request.name.clone(),
                description: request.description.clone(),
                environment: request.environment.clone(),
                owner: request.owner.clone(),
                parent_allocation_id: request.parent_allocation_id.clone(),
                tags: request.tags.clone(),
            };
            let alloc = self.store.create_allocation(&input).await?;
            self.audit("allocate", "allocation", &alloc.id, Some(&alloc.cidr))
                .await?;
            allocations.push(alloc);
        }
        Ok(allocations)
    }

    pub async fn get_allocation(&self, id: &str) -> Result<Allocation> {
        validation::validate_identifier(id)?;
        self.store.get_allocation(id).await
    }

    pub async fn list_allocations(&self, filter: &AllocationFilter) -> Result<Vec<Allocation>> {
        validation::validate_optional_identifier(&filter.supernet_id)?;
        validation::validate_optional_identifier(&filter.resource_id)?;
        self.store.list_allocations(filter).await
    }

    pub async fn update_allocation(
        &self,
        id: &str,
        input: &UpdateAllocation,
    ) -> Result<Allocation> {
        validation::validate_identifier(id)?;
        validation::validate_optional_text(&input.name, 0)?;
        validation::validate_optional_text(&input.description, 0)?;
        validation::validate_optional_text(&input.owner, 0)?;
        validation::validate_optional_text(&input.environment, 0)?;
        validation::validate_optional_identifier(&input.resource_id)?;

        let alloc = self.store.update_allocation(id, input).await?;
        self.audit("update", "allocation", id, None).await?;
        Ok(alloc)
    }

    pub async fn release_allocation(&self, id: &str) -> Result<Allocation> {
        validation::validate_identifier(id)?;
        let alloc = self.store.release_allocation(id).await?;
        self.audit("release", "allocation", id, Some(&alloc.cidr))
            .await?;
        Ok(alloc)
    }

    // -----------------------------------------------------------------------
    // Query operations
    // -----------------------------------------------------------------------

    /// Calculate utilization for a supernet with per-status breakdown.
    pub async fn utilization(&self, supernet_id: &str) -> Result<UtilizationReport> {
        validation::validate_identifier(supernet_id)?;
        let supernet = self.store.get_supernet(supernet_id).await?;

        // Fetch active + reserved allocations (these consume space)
        let active_reserved = self
            .store
            .find_allocations_in_supernet(
                supernet_id,
                &[AllocationStatus::Active, AllocationStatus::Reserved],
            )
            .await?;

        // Fetch released allocations for the breakdown
        let released = self
            .store
            .find_allocations_in_supernet(supernet_id, &[AllocationStatus::Released])
            .await?;

        let mut active_addresses: u128 = 0;
        let mut active_count: usize = 0;
        let mut reserved_addresses: u128 = 0;
        let mut reserved_count: usize = 0;

        for alloc in &active_reserved {
            match alloc.status {
                AllocationStatus::Active => {
                    active_addresses += alloc.total_hosts;
                    active_count += 1;
                }
                AllocationStatus::Reserved => {
                    reserved_addresses += alloc.total_hosts;
                    reserved_count += 1;
                }
                AllocationStatus::Released => {}
            }
        }

        let released_addresses: u128 = released.iter().map(|a| a.total_hosts).sum();
        let released_count = released.len();

        let allocated = active_addresses + reserved_addresses;
        let total = supernet.total_hosts;
        let free = total.saturating_sub(allocated);
        let pct = if total > 0 {
            (allocated as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Ok(UtilizationReport {
            supernet_id: supernet_id.to_string(),
            supernet_cidr: supernet.cidr,
            total_addresses: total,
            allocated_addresses: allocated,
            free_addresses: free,
            utilization_percent: pct,
            allocation_count: active_reserved.len(),
            by_status: StatusBreakdown {
                active_addresses,
                active_count,
                reserved_addresses,
                reserved_count,
                released_addresses,
                released_count,
            },
        })
    }

    /// List free blocks in a supernet, optionally filtered by prefix length.
    pub async fn free_blocks(
        &self,
        supernet_id: &str,
        target_prefix: Option<u8>,
    ) -> Result<FreeBlocksReport> {
        validation::validate_identifier(supernet_id)?;
        let supernet = self.store.get_supernet(supernet_id).await?;
        let supernet_range = parse_range(&supernet.cidr)?;

        let active = self
            .store
            .find_allocations_in_supernet(
                supernet_id,
                &[AllocationStatus::Active, AllocationStatus::Reserved],
            )
            .await?;

        let existing_ranges: Vec<IpRange> = active
            .iter()
            .filter_map(|a| parse_range(&a.cidr).ok())
            .collect();

        let gaps = find_gaps(&supernet_range, &existing_ranges);
        let mut blocks = Vec::new();
        let mut total_free: u128 = 0;

        for (start, end) in gaps {
            let cidrs = range_to_cidrs(start, end, supernet_range.is_v4);
            for (cidr_str, size) in cidrs {
                if let Some(tp) = target_prefix {
                    let prefix = cidr_str
                        .split('/')
                        .nth(1)
                        .and_then(|p| p.parse::<u8>().ok())
                        .unwrap_or(0);
                    if prefix > tp {
                        continue; // block is smaller than requested
                    }
                    if prefix < tp {
                        // Split this block into target-prefix-sized blocks
                        let sub_blocks = split_cidr_to_prefix(&cidr_str, tp, supernet_range.is_v4);
                        for sb in sub_blocks {
                            let sb_size = if supernet_range.is_v4 {
                                1u128 << (32 - tp)
                            } else {
                                1u128 << (128 - tp)
                            };
                            total_free += sb_size;
                            blocks.push(FreeBlock {
                                cidr: sb,
                                size: sb_size,
                            });
                        }
                        continue;
                    }
                }
                total_free += size;
                blocks.push(FreeBlock {
                    cidr: cidr_str,
                    size,
                });
            }
        }

        Ok(FreeBlocksReport {
            supernet_id: supernet_id.to_string(),
            supernet_cidr: supernet.cidr,
            blocks,
            total_free,
        })
    }

    /// Find allocations containing a given IP address.
    pub async fn find_by_ip(&self, address: &str) -> Result<Vec<Allocation>> {
        validation::validate_ip_address(address)?;
        let ip = parse_ip(address)?;

        // Search all supernets
        let supernets = self.store.list_supernets().await?;
        let mut results = Vec::new();

        for sn in &supernets {
            let sn_range = parse_range(&sn.cidr)?;
            if ip < sn_range.start || ip > sn_range.end {
                continue;
            }
            let allocs = self
                .store
                .find_allocations_in_supernet(
                    &sn.id,
                    &[AllocationStatus::Active, AllocationStatus::Reserved],
                )
                .await?;
            for alloc in allocs {
                if let Ok(range) = parse_range(&alloc.cidr)
                    && ip >= range.start
                    && ip <= range.end
                {
                    results.push(alloc);
                }
            }
        }
        Ok(results)
    }

    /// Find allocations by resource ID.
    pub async fn find_by_resource(&self, resource_id: &str) -> Result<Vec<Allocation>> {
        validation::validate_identifier(resource_id)?;
        self.store
            .list_allocations(&AllocationFilter {
                resource_id: Some(resource_id.to_string()),
                ..Default::default()
            })
            .await
    }

    /// Query the audit log.
    pub async fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        self.store.query_audit(filter).await
    }

    // -----------------------------------------------------------------------
    // Tags
    // -----------------------------------------------------------------------

    pub async fn set_tags(&self, allocation_id: &str, tags: &[Tag]) -> Result<()> {
        validation::validate_identifier(allocation_id)?;
        for tag in tags {
            validation::validate_text_field(&tag.key, 0)?;
            validation::validate_text_field(&tag.value, 0)?;
        }
        self.store.set_tags(allocation_id, tags).await
    }

    pub async fn get_tags(&self, allocation_id: &str) -> Result<Vec<Tag>> {
        validation::validate_identifier(allocation_id)?;
        self.store.get_tags(allocation_id).await
    }

    // -----------------------------------------------------------------------
    // Validation helpers
    // -----------------------------------------------------------------------

    fn validate_create_allocation(input: &CreateAllocation) -> Result<()> {
        validation::validate_identifier(&input.supernet_id)?;
        validation::validate_cidr(&input.cidr)?;
        validation::validate_optional_text(&input.name, 0)?;
        validation::validate_optional_text(&input.description, 0)?;
        validation::validate_optional_text(&input.owner, 0)?;
        validation::validate_optional_text(&input.environment, 0)?;
        validation::validate_optional_identifier(&input.resource_id)?;
        validation::validate_optional_identifier(&input.parent_allocation_id)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn check_overlap(
        &self,
        supernet_id: &str,
        candidate: &IpRange,
        candidate_cidr: &str,
    ) -> Result<()> {
        let existing = self
            .store
            .find_allocations_in_supernet(
                supernet_id,
                &[AllocationStatus::Active, AllocationStatus::Reserved],
            )
            .await?;

        for alloc in &existing {
            if let Ok(range) = parse_range(&alloc.cidr)
                && ranges_overlap(candidate, &range)
            {
                return Err(IpCalcError::AllocationConflict {
                    existing: alloc.cidr.clone(),
                    candidate: candidate_cidr.to_string(),
                });
            }
        }
        Ok(())
    }

    async fn audit(
        &self,
        action: &str,
        entity_type: &str,
        entity_id: &str,
        details: Option<&str>,
    ) -> Result<()> {
        self.store
            .append_audit(&AuditEntry {
                id: String::new(),
                entity_type: entity_type.to_string(),
                entity_id: entity_id.to_string(),
                action: action.to_string(),
                details: details.map(|s| s.to_string()),
                timestamp: Utc::now().to_rfc3339(),
            })
            .await
    }
}

// ===========================================================================
// IP range arithmetic (backend-agnostic, pure Rust)
// ===========================================================================

#[derive(Debug, Clone)]
pub struct IpRange {
    pub start: u128,
    pub end: u128,
    pub is_v4: bool,
}

fn parse_range(cidr: &str) -> Result<IpRange> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| IpCalcError::InvalidCidr(cidr.to_string()))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| IpCalcError::InvalidCidr(cidr.to_string()))?;

    if let Ok(addr) = addr_str.parse::<Ipv4Addr>() {
        let addr_u32 = u32::from(addr);
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let network = addr_u32 & mask;
        let broadcast = network | !mask;
        Ok(IpRange {
            start: network as u128,
            end: broadcast as u128,
            is_v4: true,
        })
    } else if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
        let addr_u128 = u128::from(addr);
        let mask = if prefix == 0 {
            0u128
        } else {
            !0u128 << (128 - prefix)
        };
        let network = addr_u128 & mask;
        let last = network | !mask;
        Ok(IpRange {
            start: network,
            end: last,
            is_v4: false,
        })
    } else {
        Err(IpCalcError::InvalidCidr(cidr.to_string()))
    }
}

fn parse_ip(address: &str) -> Result<u128> {
    if let Ok(v4) = address.parse::<Ipv4Addr>() {
        Ok(u32::from(v4) as u128)
    } else if let Ok(v6) = address.parse::<Ipv6Addr>() {
        Ok(u128::from(v6))
    } else {
        Err(IpCalcError::InvalidCidr(address.to_string()))
    }
}

fn ranges_overlap(a: &IpRange, b: &IpRange) -> bool {
    a.start <= b.end && b.start <= a.end
}

fn range_contains(outer: &IpRange, inner: &IpRange) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

/// Find gaps (unallocated regions) in a supernet given sorted existing allocations.
fn find_gaps(supernet: &IpRange, allocated: &[IpRange]) -> Vec<(u128, u128)> {
    let mut sorted: Vec<&IpRange> = allocated.iter().collect();
    sorted.sort_by_key(|r| r.start);

    let mut gaps = Vec::new();
    let mut cursor = supernet.start;

    for range in sorted {
        if range.start > cursor {
            gaps.push((cursor, range.start - 1));
        }
        if range.end >= cursor {
            cursor = range.end.saturating_add(1);
        }
    }

    if cursor <= supernet.end {
        gaps.push((cursor, supernet.end));
    }

    gaps
}

/// Find the first N free blocks of a given prefix length.
fn find_free_blocks(
    supernet: &IpRange,
    allocated: &[IpRange],
    prefix: u8,
    count: u32,
) -> Result<Vec<String>> {
    let bits = if supernet.is_v4 { 32 } else { 128 };
    if prefix > bits {
        return Err(IpCalcError::InvalidPrefixLength(prefix));
    }
    let block_size: u128 = 1u128 << (bits - prefix);

    let gaps = find_gaps(supernet, allocated);
    let mut results = Vec::new();

    for (gap_start, gap_end) in gaps {
        // Align to block boundary
        let remainder = if block_size > 1 {
            gap_start % block_size
        } else {
            0
        };
        let aligned_start = if remainder == 0 {
            gap_start
        } else {
            gap_start + (block_size - remainder)
        };

        let mut addr = aligned_start;
        while addr + block_size - 1 <= gap_end && (results.len() as u32) < count {
            let cidr = if supernet.is_v4 {
                format!("{}/{}", Ipv4Addr::from(addr as u32), prefix)
            } else {
                format!("{}/{}", Ipv6Addr::from(addr), prefix)
            };
            results.push(cidr);
            addr += block_size;
        }

        if results.len() as u32 >= count {
            break;
        }
    }

    Ok(results)
}

/// Convert a contiguous IP range into the minimal set of CIDR blocks.
fn range_to_cidrs(start: u128, end: u128, is_v4: bool) -> Vec<(String, u128)> {
    let bits: u8 = if is_v4 { 32 } else { 128 };
    let mut results = Vec::new();
    let mut current = start;

    while current <= end {
        let max_prefix = if current == 0 {
            bits
        } else {
            current.trailing_zeros().min(bits as u32) as u8
        };

        let mut prefix = bits;
        for p in (bits - max_prefix)..=bits {
            let block_size = 1u128 << (bits - p);
            if current + block_size - 1 <= end {
                prefix = p;
                break;
            }
        }

        let block_size = 1u128 << (bits - prefix);
        let cidr = if is_v4 {
            format!("{}/{}", Ipv4Addr::from(current as u32), prefix)
        } else {
            format!("{}/{}", Ipv6Addr::from(current), prefix)
        };
        results.push((cidr, block_size));
        current += block_size;
    }

    results
}

/// Split a CIDR block into sub-blocks of a target prefix length.
fn split_cidr_to_prefix(cidr: &str, target_prefix: u8, is_v4: bool) -> Vec<String> {
    let bits: u8 = if is_v4 { 32 } else { 128 };
    let Ok(range) = parse_range(cidr) else {
        return Vec::new();
    };
    let block_size: u128 = 1u128 << (bits - target_prefix);
    let mut results = Vec::new();
    let mut addr = range.start;

    while addr + block_size - 1 <= range.end {
        let cidr_str = if is_v4 {
            format!("{}/{}", Ipv4Addr::from(addr as u32), target_prefix)
        } else {
            format!("{}/{}", Ipv6Addr::from(addr), target_prefix)
        };
        results.push(cidr_str);
        addr += block_size;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::sqlite::SqliteStore;

    async fn test_ops() -> IpamOps {
        let store = SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        IpamOps::new(Arc::new(store))
    }

    #[tokio::test]
    async fn test_create_supernet_overlap_rejected() {
        let ops = test_ops().await;

        ops.create_supernet(&CreateSupernet {
            cidr: "10.0.0.0/8".to_string(),
            name: None,
            description: None,
        })
        .await
        .unwrap();

        let err = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.128.0.0/9".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, IpCalcError::AllocationConflict { .. }));
    }

    #[tokio::test]
    async fn test_allocate_specific() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        let a1 = ops
            .allocate_specific(&CreateAllocation {
                supernet_id: sn.id.clone(),
                cidr: "10.0.0.0/24".to_string(),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
            })
            .await
            .unwrap();

        assert_eq!(a1.cidr, "10.0.0.0/24");

        // Overlapping allocation should fail
        let err = ops
            .allocate_specific(&CreateAllocation {
                supernet_id: sn.id.clone(),
                cidr: "10.0.0.128/25".to_string(),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(err, IpCalcError::AllocationConflict { .. }));
    }

    #[tokio::test]
    async fn test_auto_allocate() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/16".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        // Allocate first /24
        ops.allocate_specific(&CreateAllocation {
            supernet_id: sn.id.clone(),
            cidr: "10.0.0.0/24".to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
        })
        .await
        .unwrap();

        // Auto-allocate next 3 /24s
        let allocs = ops
            .allocate_auto(&AutoAllocateRequest {
                supernet_id: sn.id.clone(),
                prefix_length: 24,
                count: Some(3),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
            })
            .await
            .unwrap();

        assert_eq!(allocs.len(), 3);
        assert_eq!(allocs[0].cidr, "10.0.1.0/24");
        assert_eq!(allocs[1].cidr, "10.0.2.0/24");
        assert_eq!(allocs[2].cidr, "10.0.3.0/24");
    }

    #[tokio::test]
    async fn test_utilization() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/24".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        ops.allocate_specific(&CreateAllocation {
            supernet_id: sn.id.clone(),
            cidr: "10.0.0.0/25".to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
        })
        .await
        .unwrap();

        let util = ops.utilization(&sn.id).await.unwrap();
        assert_eq!(util.total_addresses, 256);
        assert_eq!(util.allocated_addresses, 128);
        assert_eq!(util.free_addresses, 128);
        assert!((util.utilization_percent - 50.0).abs() < 0.1);
        assert_eq!(util.by_status.active_addresses, 128);
        assert_eq!(util.by_status.active_count, 1);
        assert_eq!(util.by_status.reserved_addresses, 0);
        assert_eq!(util.by_status.reserved_count, 0);
        assert_eq!(util.by_status.released_addresses, 0);
        assert_eq!(util.by_status.released_count, 0);
    }

    #[tokio::test]
    async fn test_free_blocks() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/24".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        ops.allocate_specific(&CreateAllocation {
            supernet_id: sn.id.clone(),
            cidr: "10.0.0.0/25".to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
        })
        .await
        .unwrap();

        let report = ops.free_blocks(&sn.id, None).await.unwrap();
        assert_eq!(report.blocks.len(), 1);
        assert_eq!(report.blocks[0].cidr, "10.0.0.128/25");
        assert_eq!(report.total_free, 128);
    }

    #[tokio::test]
    async fn test_find_by_ip() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/8".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        ops.allocate_specific(&CreateAllocation {
            supernet_id: sn.id.clone(),
            cidr: "10.0.1.0/24".to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
        })
        .await
        .unwrap();

        let found = ops.find_by_ip("10.0.1.50").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].cidr, "10.0.1.0/24");

        let not_found = ops.find_by_ip("10.0.2.50").await.unwrap();
        assert!(not_found.is_empty());
    }

    #[tokio::test]
    async fn test_release_frees_space() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/24".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        let a1 = ops
            .allocate_specific(&CreateAllocation {
                supernet_id: sn.id.clone(),
                cidr: "10.0.0.0/25".to_string(),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
            })
            .await
            .unwrap();

        ops.allocate_specific(&CreateAllocation {
            supernet_id: sn.id.clone(),
            cidr: "10.0.0.128/25".to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
        })
        .await
        .unwrap();

        // Supernet fully allocated
        let util = ops.utilization(&sn.id).await.unwrap();
        assert!((util.utilization_percent - 100.0).abs() < 0.1);

        // Release first block
        ops.release_allocation(&a1.id).await.unwrap();

        // Now auto-allocate should find the freed space
        let allocs = ops
            .allocate_auto(&AutoAllocateRequest {
                supernet_id: sn.id.clone(),
                prefix_length: 25,
                count: Some(1),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
            })
            .await
            .unwrap();

        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].cidr, "10.0.0.0/25");
    }

    #[tokio::test]
    async fn test_utilization_status_breakdown() {
        let ops = test_ops().await;

        let sn = ops
            .create_supernet(&CreateSupernet {
                cidr: "10.0.0.0/24".to_string(),
                name: None,
                description: None,
            })
            .await
            .unwrap();

        // Active allocation
        let a1 = ops
            .allocate_specific(&CreateAllocation {
                supernet_id: sn.id.clone(),
                cidr: "10.0.0.0/26".to_string(),
                status: None,
                resource_id: None,
                resource_type: None,
                name: None,
                description: None,
                environment: None,
                owner: None,
                parent_allocation_id: None,
                tags: None,
            })
            .await
            .unwrap();

        // Reserved allocation
        ops.allocate_specific(&CreateAllocation {
            supernet_id: sn.id.clone(),
            cidr: "10.0.0.64/26".to_string(),
            status: Some(AllocationStatus::Reserved),
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
        })
        .await
        .unwrap();

        // Release the first allocation
        ops.release_allocation(&a1.id).await.unwrap();

        let util = ops.utilization(&sn.id).await.unwrap();
        // Only reserved counts as allocated (active was released)
        assert_eq!(util.allocated_addresses, 64);
        assert_eq!(util.free_addresses, 192);
        assert_eq!(util.by_status.active_addresses, 0);
        assert_eq!(util.by_status.active_count, 0);
        assert_eq!(util.by_status.reserved_addresses, 64);
        assert_eq!(util.by_status.reserved_count, 1);
        assert_eq!(util.by_status.released_addresses, 64);
        assert_eq!(util.by_status.released_count, 1);
    }

    #[test]
    fn test_ranges_overlap() {
        let a = IpRange {
            start: 0,
            end: 255,
            is_v4: true,
        };
        let b = IpRange {
            start: 128,
            end: 383,
            is_v4: true,
        };
        assert!(ranges_overlap(&a, &b));

        let c = IpRange {
            start: 256,
            end: 511,
            is_v4: true,
        };
        assert!(!ranges_overlap(&a, &c));
    }

    #[test]
    fn test_find_gaps() {
        let supernet = IpRange {
            start: 0,
            end: 1023,
            is_v4: true,
        };
        let allocated = vec![
            IpRange {
                start: 0,
                end: 255,
                is_v4: true,
            },
            IpRange {
                start: 512,
                end: 767,
                is_v4: true,
            },
        ];
        let gaps = find_gaps(&supernet, &allocated);
        assert_eq!(gaps, vec![(256, 511), (768, 1023)]);
    }

    #[test]
    fn test_range_to_cidrs() {
        // 10.0.0.128 to 10.0.0.255 should be 10.0.0.128/25
        let start = u32::from(Ipv4Addr::new(10, 0, 0, 128)) as u128;
        let end = u32::from(Ipv4Addr::new(10, 0, 0, 255)) as u128;
        let cidrs = range_to_cidrs(start, end, true);
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].0, "10.0.0.128/25");
    }
}
