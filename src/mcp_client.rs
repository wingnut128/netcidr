//! HTTP client that proxies IPAM operations to a remote `netcidr serve` API.
//!
//! Used by the MCP server when started with `--api-url` instead of `--ipam-db`.

use reqwest::Client;

use crate::error::{NetcidrError, Result};
use crate::ipam::models::*;

/// HTTP client for a remote netcidr API server.
#[derive(Debug, Clone)]
pub struct HttpIpamClient {
    client: Client,
    base_url: String,
}

/// Wrapper for JSON error responses from the API.
#[derive(serde::Deserialize)]
struct ApiError {
    error: String,
}

impl HttpIpamClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| NetcidrError::InvalidInput(format!("HTTP client error: {e}")))?;
        Ok(Self { client, base_url })
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}/ipam{}", self.base_url, path)
    }

    /// Map a non-success HTTP response to an `NetcidrError`.
    async fn map_error(resp: reqwest::Response) -> NetcidrError {
        let status = resp.status().as_u16();
        let body = resp
            .json::<ApiError>()
            .await
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("HTTP {status}"));
        match status {
            404 => {
                if body.contains("upernet") {
                    NetcidrError::CidrBlockNotFound(body)
                } else {
                    NetcidrError::AllocationNotFound(body)
                }
            }
            409 => NetcidrError::InvalidInput(body),
            422 => NetcidrError::InvalidInput(body),
            _ => NetcidrError::DatabaseError(body),
        }
    }

    // -----------------------------------------------------------------------
    // CidrBlock operations
    // -----------------------------------------------------------------------

    pub async fn create_cidr_block(&self, input: &CreateCidrBlock) -> Result<CidrBlock> {
        let resp = self
            .client
            .post(self.url("/cidr-blocks"))
            .json(input)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn list_cidr_blocks(&self) -> Result<Vec<CidrBlock>> {
        let resp = self
            .client
            .get(self.url("/cidr-blocks"))
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            let list: CidrBlockList = resp
                .json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            Ok(list.cidr_blocks)
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    // -----------------------------------------------------------------------
    // Allocation operations
    // -----------------------------------------------------------------------

    pub async fn allocate_auto(&self, request: &AutoAllocateRequest) -> Result<Vec<Allocation>> {
        let body = serde_json::json!({
            "prefix_length": request.prefix_length,
            "count": request.count,
            "status": request.status,
            "resource_id": request.resource_id,
            "resource_type": request.resource_type,
            "name": request.name,
            "description": request.description,
            "environment": request.environment,
            "owner": request.owner,
            "parent_allocation_id": request.parent_allocation_id,
            "tags": request.tags,
            "ttl_seconds": request.ttl_seconds,
        });
        let resp = self
            .client
            .post(self.url(&format!("/cidr-blocks/{}/allocate", request.cidr_block_id)))
            .json(&body)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            let list: AllocationList = resp
                .json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            Ok(list.allocations)
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn allocate_specific(&self, input: &CreateAllocation) -> Result<Allocation> {
        let body = serde_json::json!({
            "cidr": input.cidr,
            "status": input.status,
            "resource_id": input.resource_id,
            "resource_type": input.resource_type,
            "name": input.name,
            "description": input.description,
            "environment": input.environment,
            "owner": input.owner,
            "parent_allocation_id": input.parent_allocation_id,
            "tags": input.tags,
            "ttl_seconds": input.ttl_seconds,
        });
        let resp = self
            .client
            .post(self.url(&format!(
                "/cidr-blocks/{}/allocate-specific",
                input.cidr_block_id
            )))
            .json(&body)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn release_allocation(&self, id: &str) -> Result<Allocation> {
        let resp = self
            .client
            .post(self.url(&format!("/allocations/{id}/release")))
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn list_allocations(&self, filter: &AllocationFilter) -> Result<Vec<Allocation>> {
        let cidr_block_id = filter.cidr_block_id.as_deref().unwrap_or("");
        let mut query_params = Vec::new();
        if let Some(ref s) = filter.status {
            query_params.push(("status", s.to_string()));
        }
        if let Some(ref e) = filter.environment {
            query_params.push(("environment", e.clone()));
        }
        if let Some(ref o) = filter.owner {
            query_params.push(("owner", o.clone()));
        }
        if let Some(ref r) = filter.resource_id {
            query_params.push(("resource_id", r.clone()));
        }
        if let Some(ref r) = filter.resource_type {
            query_params.push(("resource_type", r.clone()));
        }
        let resp = self
            .client
            .get(self.url(&format!("/cidr-blocks/{cidr_block_id}/allocations")))
            .query(&query_params)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            let list: AllocationList = resp
                .json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            Ok(list.allocations)
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    // -----------------------------------------------------------------------
    // Free space & utilization
    // -----------------------------------------------------------------------

    pub async fn free_blocks(
        &self,
        cidr_block_id: &str,
        prefix: Option<u8>,
    ) -> Result<FreeBlocksReport> {
        let mut query_params = Vec::new();
        if let Some(p) = prefix {
            query_params.push(("prefix", p.to_string()));
        }
        let resp = self
            .client
            .get(self.url(&format!("/cidr-blocks/{cidr_block_id}/free")))
            .query(&query_params)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn utilization(&self, cidr_block_id: &str) -> Result<UtilizationReport> {
        let resp = self
            .client
            .get(self.url(&format!("/cidr-blocks/{cidr_block_id}/utilization")))
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    // -----------------------------------------------------------------------
    // Search
    // -----------------------------------------------------------------------

    pub async fn find_by_ip(&self, address: &str) -> Result<Vec<Allocation>> {
        let resp = self
            .client
            .get(self.url(&format!("/find-ip/{address}")))
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            let list: AllocationList = resp
                .json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            Ok(list.allocations)
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn batch_allocate(&self, items: &[BatchAllocateItem]) -> Result<BatchAllocateResult> {
        let resp = self
            .client
            .post(self.url("/batch/allocate"))
            .json(items)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn batch_release(&self, request: &BatchReleaseRequest) -> Result<BatchReleaseResult> {
        let resp = self
            .client
            .post(self.url("/batch/release"))
            .json(request)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn allocation_summary(
        &self,
        cidr_block_id: Option<&str>,
    ) -> Result<AllocationSummary> {
        let mut url = self.url("/batch/summary");
        if let Some(id) = cidr_block_id {
            url = format!("{url}?cidr_block_id={id}");
        }
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            resp.json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn find_by_resource(&self, resource_id: &str) -> Result<Vec<Allocation>> {
        let resp = self
            .client
            .get(self.url(&format!("/find-resource/{resource_id}")))
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            let list: AllocationList = resp
                .json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            Ok(list.allocations)
        } else {
            Err(Self::map_error(resp).await)
        }
    }
}
