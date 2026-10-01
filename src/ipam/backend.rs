//! IPAM backend switch: the same operations against a local [`IpamOps`] or a
//! remote `netcidr serve` API via [`HttpIpamClient`].
//!
//! Shared by the MCP server and `netcidr ipam`.

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
            Self::Remote(client) if filter.cidr_block_id.is_some() => {
                client.list_allocations(filter).await
            }
            // The API only lists allocations per CIDR block, so "every
            // block" means asking each one. Paging applies to the combined
            // result, as it does for the local store.
            Self::Remote(client) => {
                let mut all = Vec::new();
                for block in client.list_cidr_blocks().await? {
                    let per_block = AllocationFilter {
                        cidr_block_id: Some(block.id),
                        limit: None,
                        offset: None,
                        ..filter.clone()
                    };
                    all.extend(client.list_allocations(&per_block).await?);
                }
                let offset = filter.offset.unwrap_or(0) as usize;
                let limit = filter.limit.map_or(usize::MAX, |l| l as usize);
                Ok(all.into_iter().skip(offset).take(limit).collect())
            }
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

    /// Release this tenant's allocations whose TTL has passed.
    pub async fn reap_expired(&self) -> Result<ReapResult> {
        match self {
            Self::Local(ops) => Ok(ReapResult {
                released: ops.reap_expired(Tenant::LOCAL).await?,
            }),
            Self::Remote(client) => client.reap_expired().await,
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

impl IpamBackend {
    pub async fn get_cidr_block(&self, id: &str) -> Result<CidrBlock> {
        match self {
            Self::Local(ops) => ops.get_cidr_block(Tenant::LOCAL, id).await,
            Self::Remote(client) => client.get_cidr_block(id).await,
        }
    }

    pub async fn delete_cidr_block(&self, id: &str) -> Result<()> {
        match self {
            Self::Local(ops) => ops.delete_cidr_block(Tenant::LOCAL, id).await,
            Self::Remote(client) => client.delete_cidr_block(id).await,
        }
    }

    pub async fn get_allocation(&self, id: &str) -> Result<Allocation> {
        match self {
            Self::Local(ops) => ops.get_allocation(Tenant::LOCAL, id).await,
            Self::Remote(client) => client.get_allocation(id).await,
        }
    }

    /// Replace an allocation's tags and return the updated allocation.
    pub async fn set_tags(&self, allocation_id: &str, tags: &[Tag]) -> Result<Allocation> {
        match self {
            Self::Local(ops) => {
                ops.set_tags(Tenant::LOCAL, allocation_id, tags).await?;
                ops.get_allocation(Tenant::LOCAL, allocation_id).await
            }
            Self::Remote(client) => client.set_tags(allocation_id, tags).await,
        }
    }

    pub async fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        match self {
            Self::Local(ops) => ops.query_audit(Tenant::LOCAL, filter).await,
            Self::Remote(client) => client.query_audit(filter).await,
        }
    }

    pub async fn get_hostname_pointers_for_ip(&self, ip: &str) -> Result<Vec<HostnamePointer>> {
        match self {
            Self::Local(ops) => ops.get_hostname_pointers_for_ip(Tenant::LOCAL, ip).await,
            // Same lookup as the local op: pointers filtered by this IP. The
            // server canonicalizes the address before filtering.
            Self::Remote(client) => {
                client
                    .list_hostname_pointers(&HostnamePointerFilter {
                        ip_address: Some(ip.to_string()),
                        ..Default::default()
                    })
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipam::store::IpamStore;

    async fn local_ops() -> Arc<IpamOps> {
        let store = crate::ipam::sqlite::SqliteStore::in_memory().expect("in-memory store");
        store.initialize().await.expect("init");
        store.migrate().await.expect("migrate");
        Arc::new(IpamOps::new(Arc::new(store)))
    }

    /// A real `netcidr serve` router in bearer-token mode on a loopback port,
    /// fronted by the remote backend.
    async fn remote_backend() -> IpamBackend {
        use crate::api::{RouterConfig, create_router};
        use crate::config::{AuthMode, ServerConfig};

        let server = ServerConfig {
            rate_limit_per_second: 0,
            auth_mode: AuthMode::Bearer,
            auth_token: Some("backend-test-token".to_string()),
            ..Default::default()
        };
        // NETCIDR_API_TOKEN in the environment would win over the field, so
        // ask the config which token the server will really accept.
        let token = server.auth_token().expect("bearer token");
        let app = create_router(RouterConfig {
            server,
            ipam_ops: Some(local_ops().await),
            pat_pepper: None,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        IpamBackend::Remote(HttpIpamClient::new(&format!("http://{addr}"), Some(&token)).unwrap())
    }

    fn block(cidr: &str) -> CreateCidrBlock {
        CreateCidrBlock {
            cidr: cidr.to_string(),
            name: None,
            description: None,
        }
    }

    fn alloc(block_id: &str, cidr: &str) -> CreateAllocation {
        CreateAllocation {
            cidr_block_id: block_id.to_string(),
            cidr: cidr.to_string(),
            status: None,
            resource_id: None,
            resource_type: None,
            name: None,
            description: None,
            environment: None,
            owner: None,
            parent_allocation_id: None,
            tags: None,
            ttl_seconds: None,
        }
    }

    /// The operations `netcidr ipam` needs, which must behave the same
    /// whether the backend is local or remote.
    async fn cli_scenario(backend: &IpamBackend) {
        let a = backend
            .create_cidr_block(&block("10.0.0.0/16"))
            .await
            .unwrap();
        let b = backend
            .create_cidr_block(&block("10.1.0.0/16"))
            .await
            .unwrap();
        let empty = backend
            .create_cidr_block(&block("10.2.0.0/16"))
            .await
            .unwrap();
        assert_eq!(
            backend.get_cidr_block(&a.id).await.unwrap().cidr,
            "10.0.0.0/16"
        );

        let in_a = backend
            .allocate_specific(&alloc(&a.id, "10.0.1.0/24"))
            .await
            .unwrap();
        backend
            .allocate_specific(&alloc(&b.id, "10.1.1.0/24"))
            .await
            .unwrap();
        assert_eq!(
            backend.get_allocation(&in_a.id).await.unwrap().cidr,
            "10.0.1.0/24"
        );

        // No CIDR block filter means every block, as with the local store.
        let all = backend
            .list_allocations(&AllocationFilter::default())
            .await
            .unwrap();
        let mut cidrs: Vec<_> = all.iter().map(|a| a.cidr.as_str()).collect();
        cidrs.sort();
        assert_eq!(cidrs, vec!["10.0.1.0/24", "10.1.1.0/24"]);

        let tagged = backend
            .set_tags(
                &in_a.id,
                &[Tag {
                    key: "team".to_string(),
                    value: "platform".to_string(),
                }],
            )
            .await
            .unwrap();
        assert_eq!(tagged.tags.len(), 1);
        assert_eq!(tagged.tags[0].value, "platform");

        backend
            .set_hostname_pointer(&CreateHostnamePointer {
                ip_address: "10.0.1.10".to_string(),
                hostname: "web.example.com".to_string(),
                allocation_id: None,
                notes: None,
            })
            .await
            .unwrap();
        let pointers = backend
            .get_hostname_pointers_for_ip("10.0.1.10")
            .await
            .unwrap();
        assert_eq!(pointers.len(), 1);
        assert_eq!(pointers[0].hostname, "web.example.com");

        let audit = backend
            .query_audit(&AuditFilter {
                entity_id: Some(in_a.id.clone()),
                limit: Some(50),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(audit.iter().any(|e| e.action == "allocate"), "{audit:?}");

        backend.delete_cidr_block(&empty.id).await.unwrap();
        assert!(backend.get_cidr_block(&empty.id).await.is_err());
    }

    #[tokio::test]
    async fn cli_operations_work_on_the_local_backend() {
        cli_scenario(&IpamBackend::Local(local_ops().await)).await;
    }

    #[tokio::test]
    async fn cli_operations_work_on_the_remote_backend() {
        cli_scenario(&remote_backend().await).await;
    }
}
