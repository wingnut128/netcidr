//! IPAM backend switch: the same operations against a local [`IpamOps`] or a
//! remote `netcidr serve` API via [`HttpIpamClient`].
//!
//! Used by the MCP server.

use std::sync::Arc;

use crate::error::Result;
use crate::ipam::http_client::HttpIpamClient;
use crate::ipam::models::*;
use crate::ipam::operations::IpamOps;
use crate::tenant::Tenant;

// Local backend passes `Tenant::LOCAL`. The remote backend authenticates via
// OIDC, so the API server derives the tenant from the principal there.

#[derive(Debug, Clone)]
pub enum IpamBackend {
    Local(Arc<IpamOps>),
    Remote(HttpIpamClient),
}

impl IpamBackend {
    pub async fn create_cidr_block(&self, input: &CreateCidrBlock) -> Result<CidrBlock> {
        match self {
            Self::Local(ops) => ops.create_cidr_block(Tenant::LOCAL, input).await,
            Self::Remote(client) => client.create_cidr_block(input).await,
        }
    }

    pub async fn list_cidr_blocks(&self) -> Result<Vec<CidrBlock>> {
        match self {
            Self::Local(ops) => ops.list_cidr_blocks(Tenant::LOCAL).await,
            Self::Remote(client) => client.list_cidr_blocks().await,
        }
    }

    pub async fn allocate_auto(&self, request: &AutoAllocateRequest) -> Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.allocate_auto(Tenant::LOCAL, request).await,
            Self::Remote(client) => client.allocate_auto(request).await,
        }
    }

    pub async fn allocate_specific(&self, input: &CreateAllocation) -> Result<Allocation> {
        match self {
            Self::Local(ops) => ops.allocate_specific(Tenant::LOCAL, input).await,
            Self::Remote(client) => client.allocate_specific(input).await,
        }
    }

    pub async fn update_allocation(
        &self,
        id: &str,
        input: &UpdateAllocation,
    ) -> Result<Allocation> {
        match self {
            Self::Local(ops) => ops.update_allocation(Tenant::LOCAL, id, input).await,
            Self::Remote(client) => client.update_allocation(id, input).await,
        }
    }

    pub async fn release_allocation(&self, id: &str) -> Result<Allocation> {
        match self {
            Self::Local(ops) => ops.release_allocation(Tenant::LOCAL, id).await,
            Self::Remote(client) => client.release_allocation(id).await,
        }
    }

    pub async fn list_allocations(&self, filter: &AllocationFilter) -> Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.list_allocations(Tenant::LOCAL, filter).await,
            Self::Remote(client) => client.list_allocations(filter).await,
        }
    }

    pub async fn free_blocks(
        &self,
        cidr_block_id: &str,
        prefix: Option<u8>,
    ) -> Result<FreeBlocksReport> {
        match self {
            Self::Local(ops) => ops.free_blocks(Tenant::LOCAL, cidr_block_id, prefix).await,
            Self::Remote(client) => client.free_blocks(cidr_block_id, prefix).await,
        }
    }

    pub async fn utilization(&self, cidr_block_id: &str) -> Result<UtilizationReport> {
        match self {
            Self::Local(ops) => ops.utilization(Tenant::LOCAL, cidr_block_id).await,
            Self::Remote(client) => client.utilization(cidr_block_id).await,
        }
    }

    pub async fn find_by_ip(&self, address: &str) -> Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.find_by_ip(Tenant::LOCAL, address).await,
            Self::Remote(client) => client.find_by_ip(address).await,
        }
    }

    pub async fn find_by_resource(&self, resource_id: &str) -> Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.find_by_resource(Tenant::LOCAL, resource_id).await,
            Self::Remote(client) => client.find_by_resource(resource_id).await,
        }
    }

    pub async fn batch_allocate(&self, items: &[BatchAllocateItem]) -> Result<BatchAllocateResult> {
        match self {
            Self::Local(ops) => ops.batch_allocate(Tenant::LOCAL, items).await,
            Self::Remote(client) => client.batch_allocate(items).await,
        }
    }

    pub async fn batch_release(&self, request: &BatchReleaseRequest) -> Result<BatchReleaseResult> {
        match self {
            Self::Local(ops) => ops.batch_release(Tenant::LOCAL, request).await,
            Self::Remote(client) => client.batch_release(request).await,
        }
    }

    pub async fn allocation_summary(
        &self,
        cidr_block_id: Option<&str>,
    ) -> Result<AllocationSummary> {
        match self {
            Self::Local(ops) => ops.allocation_summary(Tenant::LOCAL, cidr_block_id).await,
            Self::Remote(client) => client.allocation_summary(cidr_block_id).await,
        }
    }

    pub async fn set_hostname_pointer(
        &self,
        input: &CreateHostnamePointer,
    ) -> Result<HostnamePointer> {
        match self {
            Self::Local(ops) => ops.set_hostname_pointer(Tenant::LOCAL, input).await,
            Self::Remote(client) => client.set_hostname_pointer(input).await,
        }
    }

    pub async fn list_hostname_pointers(
        &self,
        filter: &HostnamePointerFilter,
    ) -> Result<Vec<HostnamePointer>> {
        match self {
            Self::Local(ops) => ops.list_hostname_pointers(Tenant::LOCAL, filter).await,
            Self::Remote(client) => client.list_hostname_pointers(filter).await,
        }
    }

    pub async fn list_hostname_history(
        &self,
        filter: &HostnameHistoryFilter,
    ) -> Result<Vec<HostnamePointerHistoryEntry>> {
        match self {
            Self::Local(ops) => ops.list_hostname_history(Tenant::LOCAL, filter).await,
            Self::Remote(client) => client.list_hostname_history(filter).await,
        }
    }

    pub async fn delete_hostname_pointer(&self, ip: &str, hostname: &str) -> Result<()> {
        match self {
            Self::Local(ops) => {
                ops.delete_hostname_pointer(Tenant::LOCAL, ip, hostname)
                    .await
            }
            Self::Remote(client) => client.delete_hostname_pointer(ip, hostname).await,
        }
    }
}
