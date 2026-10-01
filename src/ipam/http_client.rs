//! HTTP client that proxies IPAM operations to a remote `netcidr serve` API.
//!
//! Used by the MCP server when started with `--api-url` instead of `--ipam-db`.

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Url};

use crate::error::{NetcidrError, Result};
use crate::ipam::models::*;

/// Largest page the API serves (`MAX_PAGE_LIMIT` in `ipam_api`).
const PAGE_SIZE: u32 = 1000;
/// Upper bound on pages walked for one list call, so a server that ignores
/// `offset` cannot keep the client looping forever (10M rows).
const MAX_PAGES: u32 = 10_000;

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
    pub fn new(base_url: &str, api_token: Option<&str>) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let mut builder = Client::builder().timeout(std::time::Duration::from_secs(30));

        // Authenticate to the remote API with a bearer token when one is
        // configured. Without it the remote must run unauthenticated, which
        // widens its exposure. The header is marked sensitive so it is
        // redacted from request logs.
        if let Some(token) = api_token.map(str::trim).filter(|t| !t.is_empty()) {
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| NetcidrError::InvalidInput("invalid API token".to_string()))?;
            value.set_sensitive(true);
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }

        let client = builder
            .build()
            .map_err(|e| NetcidrError::InvalidInput(format!("HTTP client error: {e}")))?;
        Ok(Self { client, base_url })
    }

    /// Build a URL for a path that contains no caller-controlled segments.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}/ipam{}", self.base_url, path)
    }

    /// Build a URL by appending caller-controlled path `segments` to the
    /// `/ipam` base, percent-encoding each segment. This prevents a value
    /// containing `/`, `?`, or `#` from injecting extra path segments or a
    /// query string into the request to the remote API.
    fn seg_url(&self, segments: &[&str]) -> Result<Url> {
        let mut url = Url::parse(&format!("{}/ipam", self.base_url))
            .map_err(|e| NetcidrError::InvalidInput(format!("invalid API base URL: {e}")))?;
        url.path_segments_mut()
            .map_err(|_| NetcidrError::InvalidInput("invalid API base URL".to_string()))?
            .extend(segments);
        Ok(url)
    }

    /// Map a non-success HTTP response from the upstream API to a
    /// `NetcidrError::Upstream`. The upstream's `error_presenter`
    /// already scrubbed the body and chose the status, so this side
    /// just forwards both; the MCP presenter then renders the upstream
    /// status to the MCP caller exactly as if the request had been
    /// served locally.
    async fn map_error(resp: reqwest::Response) -> NetcidrError {
        let status = resp.status().as_u16();
        let message = resp
            .json::<ApiError>()
            .await
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("HTTP {status}"));
        NetcidrError::Upstream { status, message }
    }

    /// GET a list endpoint. With an explicit `limit` the caller wants one
    /// page, so it is forwarded as-is. Without one, walk every page: the API
    /// caps each response (default 100 rows), and stopping at the first page
    /// would silently truncate the result.
    async fn get_list<L, T>(
        &self,
        url: Url,
        params: &[(&str, String)],
        limit: Option<u32>,
        offset: Option<u32>,
        items: fn(L) -> Vec<T>,
    ) -> Result<Vec<T>>
    where
        L: serde::de::DeserializeOwned,
    {
        if let Some(limit) = limit {
            return self
                .get_page(url, params, limit, offset.unwrap_or(0), items)
                .await;
        }

        let mut all = Vec::new();
        let mut offset = offset.unwrap_or(0);
        for _ in 0..MAX_PAGES {
            let page = self
                .get_page(url.clone(), params, PAGE_SIZE, offset, items)
                .await?;
            let short = page.len() < PAGE_SIZE as usize;
            all.extend(page);
            if short {
                return Ok(all);
            }
            offset = offset
                .checked_add(PAGE_SIZE)
                .ok_or_else(|| NetcidrError::DatabaseError("list offset overflowed".to_string()))?;
        }
        Err(NetcidrError::DatabaseError(format!(
            "list did not finish within {MAX_PAGES} pages"
        )))
    }

    async fn get_page<L, T>(
        &self,
        url: Url,
        params: &[(&str, String)],
        limit: u32,
        offset: u32,
        items: fn(L) -> Vec<T>,
    ) -> Result<Vec<T>>
    where
        L: serde::de::DeserializeOwned,
    {
        let resp = self
            .client
            .get(url)
            .query(params)
            .query(&[("limit", limit), ("offset", offset)])
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            let list: L = resp
                .json()
                .await
                .map_err(|e| NetcidrError::DatabaseError(e.to_string()))?;
            Ok(items(list))
        } else {
            Err(Self::map_error(resp).await)
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
        let url = self.seg_url(&["cidr-blocks"])?;
        self.get_list(url, &[], None, None, |l: CidrBlockList| l.cidr_blocks)
            .await
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
            .post(self.seg_url(&["cidr-blocks", &request.cidr_block_id, "allocate"])?)
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
            .post(self.seg_url(&["cidr-blocks", &input.cidr_block_id, "allocate-specific"])?)
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

    pub async fn update_allocation(
        &self,
        id: &str,
        input: &UpdateAllocation,
    ) -> Result<Allocation> {
        let body = serde_json::json!({
            "name": input.name,
            "description": input.description,
            "resource_id": input.resource_id,
            "resource_type": input.resource_type,
            "environment": input.environment,
            "owner": input.owner,
            "status": input.status,
        });
        let resp = self
            .client
            .patch(self.seg_url(&["allocations", id])?)
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
            .post(self.seg_url(&["allocations", id, "release"])?)
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
        let mut params = Vec::new();
        if let Some(ref s) = filter.status {
            params.push(("status", s.to_string()));
        }
        if let Some(ref e) = filter.environment {
            params.push(("environment", e.clone()));
        }
        if let Some(ref o) = filter.owner {
            params.push(("owner", o.clone()));
        }
        if let Some(ref r) = filter.resource_id {
            params.push(("resource_id", r.clone()));
        }
        if let Some(ref r) = filter.resource_type {
            params.push(("resource_type", r.clone()));
        }
        let url = self.seg_url(&["cidr-blocks", cidr_block_id, "allocations"])?;
        self.get_list(
            url,
            &params,
            filter.limit,
            filter.offset,
            |l: AllocationList| l.allocations,
        )
        .await
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
            .get(self.seg_url(&["cidr-blocks", cidr_block_id, "free"])?)
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
            .get(self.seg_url(&["cidr-blocks", cidr_block_id, "utilization"])?)
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
            .get(self.seg_url(&["find-ip", address])?)
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
        let query: Vec<(&str, &str)> = cidr_block_id
            .map(|id| vec![("cidr_block_id", id)])
            .unwrap_or_default();
        let resp = self
            .client
            .get(self.url("/batch/summary"))
            .query(&query)
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
            .get(self.seg_url(&["find-resource", resource_id])?)
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
    // Hostname pointer operations
    // -----------------------------------------------------------------------

    pub async fn set_hostname_pointer(
        &self,
        input: &CreateHostnamePointer,
    ) -> Result<HostnamePointer> {
        let resp = self
            .client
            .post(self.url("/hostnames"))
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

    pub async fn list_hostname_pointers(
        &self,
        filter: &HostnamePointerFilter,
    ) -> Result<Vec<HostnamePointer>> {
        let mut params = Vec::new();
        if let Some(ref ip) = filter.ip_address {
            params.push(("ip", ip.clone()));
        }
        if let Some(ref h) = filter.hostname {
            params.push(("hostname", h.clone()));
        }
        if let Some(ref a) = filter.allocation_id {
            params.push(("allocation_id", a.clone()));
        }
        let url = self.seg_url(&["hostnames"])?;
        self.get_list(
            url,
            &params,
            filter.limit,
            filter.offset,
            |l: HostnamePointerList| l.pointers,
        )
        .await
    }

    pub async fn list_hostname_history(
        &self,
        filter: &HostnameHistoryFilter,
    ) -> Result<Vec<HostnamePointerHistoryEntry>> {
        let mut params = Vec::new();
        if let Some(ref ip) = filter.ip_address {
            params.push(("ip", ip.clone()));
        }
        if let Some(ref h) = filter.hostname {
            params.push(("hostname", h.clone()));
        }
        let url = self.seg_url(&["hostnames", "history"])?;
        self.get_list(
            url,
            &params,
            filter.limit,
            filter.offset,
            |l: HostnamePointerHistoryList| l.entries,
        )
        .await
    }

    pub async fn delete_hostname_pointer(&self, ip: &str, hostname: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url("/hostnames"))
            .query(&[("ip", ip), ("hostname", hostname)])
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    // -----------------------------------------------------------------------
    // Lookups and edits used by `netcidr ipam` in remote mode
    // -----------------------------------------------------------------------

    async fn send_json<T: serde::de::DeserializeOwned>(req: reqwest::RequestBuilder) -> Result<T> {
        let resp = req
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

    pub async fn get_cidr_block(&self, id: &str) -> Result<CidrBlock> {
        Self::send_json(self.client.get(self.seg_url(&["cidr-blocks", id])?)).await
    }

    pub async fn delete_cidr_block(&self, id: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.seg_url(&["cidr-blocks", id])?)
            .send()
            .await
            .map_err(|e| NetcidrError::DatabaseError(format!("HTTP request failed: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::map_error(resp).await)
        }
    }

    pub async fn get_allocation(&self, id: &str) -> Result<Allocation> {
        Self::send_json(self.client.get(self.seg_url(&["allocations", id])?)).await
    }

    /// Replace an allocation's tags. The API answers with the updated
    /// allocation, which is what callers display.
    pub async fn set_tags(&self, allocation_id: &str, tags: &[Tag]) -> Result<Allocation> {
        Self::send_json(
            self.client
                .put(self.seg_url(&["allocations", allocation_id, "tags"])?)
                .json(&serde_json::json!({ "tags": tags })),
        )
        .await
    }

    /// Release the caller's tenant's allocations whose TTL has passed.
    pub async fn reap_expired(&self) -> Result<ReapResult> {
        Self::send_json(self.client.post(self.seg_url(&["reap"])?)).await
    }

    /// Query the audit log. The endpoint takes a `limit` but no offset, so
    /// this is always a single request.
    pub async fn query_audit(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>> {
        let mut params: Vec<(&str, String)> = Vec::new();
        for (key, value) in [
            ("entity_type", &filter.entity_type),
            ("entity_id", &filter.entity_id),
            ("action", &filter.action),
            ("caller_email", &filter.caller_email),
            ("pat_id", &filter.pat_id),
        ] {
            if let Some(v) = value {
                params.push((key, v.clone()));
            }
        }
        if let Some(limit) = filter.limit {
            params.push(("limit", limit.to_string()));
        }
        let list: AuditList =
            Self::send_json(self.client.get(self.seg_url(&["audit"])?).query(&params)).await?;
        Ok(list.entries)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn client() -> HttpIpamClient {
        HttpIpamClient::new("http://localhost:8080", None).unwrap()
    }

    #[test]
    fn seg_url_builds_normal_path() {
        let url = client()
            .seg_url(&["allocations", "abc-123", "release"])
            .unwrap();
        assert_eq!(url.path(), "/ipam/allocations/abc-123/release");
        assert!(url.query().is_none());
    }

    #[test]
    fn seg_url_encodes_path_injection() {
        // A value packed with delimiters must stay a single path segment: no
        // extra segments, no injected query string, no fragment.
        let url = client()
            .seg_url(&["find-resource", "evil/../x?y=1#z"])
            .unwrap();

        let segments: Vec<&str> = url.path_segments().unwrap().collect();
        assert_eq!(
            segments,
            vec!["ipam", "find-resource", "evil%2F..%2Fx%3Fy=1%23z"]
        );
        assert!(url.query().is_none(), "query must not be injected: {url}");
        assert!(
            url.fragment().is_none(),
            "fragment must not be injected: {url}"
        );
    }

    #[test]
    fn new_accepts_valid_token() {
        assert!(HttpIpamClient::new("http://localhost:8080", Some("ncdr_pat_abc")).is_ok());
    }

    #[test]
    fn new_treats_blank_token_as_absent() {
        assert!(HttpIpamClient::new("http://localhost:8080", Some("   ")).is_ok());
    }

    #[test]
    fn new_rejects_token_with_control_chars() {
        // A token with a newline can't form a valid header value.
        assert!(HttpIpamClient::new("http://localhost:8080", Some("bad\ntoken")).is_err());
    }

    // -----------------------------------------------------------------------
    // update_allocation against an in-process mock API
    // -----------------------------------------------------------------------

    /// What the mock API saw on its single PATCH route.
    #[derive(Debug, Clone)]
    pub(crate) struct SeenRequest {
        /// Raw (still percent-encoded) request path.
        pub(crate) path: String,
        pub(crate) auth: Option<String>,
        pub(crate) body: serde_json::Value,
    }

    pub(crate) fn sample_allocation() -> serde_json::Value {
        serde_json::json!({
            "id": "alloc-1",
            "tenant_id": "local",
            "cidr_block_id": "block-1",
            "cidr": "10.0.1.0/24",
            "network_address": "10.0.1.0",
            "broadcast_address": "10.0.1.255",
            "prefix_length": 24,
            "total_hosts": 254,
            "status": "active",
            "resource_id": null,
            "resource_type": null,
            "name": "eks_az1",
            "description": null,
            "environment": null,
            "owner": null,
            "parent_allocation_id": null,
            "tags": [],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "released_at": null,
            "expires_at": null,
        })
    }

    /// Serve a mock `PATCH /ipam/allocations/{id}` that records the request
    /// and replies with `status` + `reply`. Returns the base URL and the
    /// recorded request slot.
    pub(crate) async fn mock_update_api(
        status: u16,
        reply: serde_json::Value,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Option<SeenRequest>>>,
    ) {
        use axum::extract::{Json, OriginalUri, State};
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::patch;
        use std::sync::{Arc, Mutex};

        type Seen = Arc<Mutex<Option<SeenRequest>>>;
        let seen: Seen = Arc::new(Mutex::new(None));

        let app = axum::Router::new()
            .route(
                "/ipam/allocations/{id}",
                patch(
                    move |State(seen): State<Seen>,
                          OriginalUri(uri): OriginalUri,
                          headers: HeaderMap,
                          Json(body): Json<serde_json::Value>| {
                        let reply = reply.clone();
                        async move {
                            *seen.lock().unwrap() = Some(SeenRequest {
                                path: uri.path().to_string(),
                                auth: headers
                                    .get(AUTHORIZATION)
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_string),
                                body,
                            });
                            (StatusCode::from_u16(status).unwrap(), Json(reply))
                        }
                    },
                ),
            )
            .with_state(seen.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    fn rename_only(name: &str) -> UpdateAllocation {
        UpdateAllocation {
            name: Some(name.to_string()),
            description: None,
            resource_id: None,
            resource_type: None,
            environment: None,
            owner: None,
            status: None,
        }
    }

    #[tokio::test]
    async fn update_allocation_sends_patch_with_auth_and_returns_allocation() {
        let (base, seen) = mock_update_api(200, sample_allocation()).await;
        let client = HttpIpamClient::new(&base, Some("ncdr_pat_abc")).unwrap();

        let alloc = client
            .update_allocation("alloc-1", &rename_only("eks_az1"))
            .await
            .expect("update should succeed");
        assert_eq!(alloc.id, "alloc-1");
        assert_eq!(alloc.name.as_deref(), Some("eks_az1"));

        let seen = seen.lock().unwrap().clone().expect("mock saw a request");
        assert_eq!(seen.path, "/ipam/allocations/alloc-1");
        assert_eq!(seen.auth.as_deref(), Some("Bearer ncdr_pat_abc"));
        assert_eq!(seen.body["name"], "eks_az1");
        // Fields the caller didn't set must not be sent as values.
        for field in [
            "description",
            "resource_id",
            "resource_type",
            "environment",
            "owner",
            "status",
        ] {
            assert!(
                seen.body.get(field).is_none_or(serde_json::Value::is_null),
                "{field} should be unset, got {}",
                seen.body
            );
        }
    }

    #[tokio::test]
    async fn update_allocation_path_encodes_id() {
        let (base, seen) = mock_update_api(404, serde_json::json!({"error": "not found"})).await;
        let client = HttpIpamClient::new(&base, None).unwrap();

        // A crafted id must stay one segment — it must not reach another route.
        let _ = client
            .update_allocation("x/release?y=1", &rename_only("n"))
            .await;
        let seen = seen.lock().unwrap().clone().expect("mock saw a request");
        assert_eq!(seen.path, "/ipam/allocations/x%2Frelease%3Fy=1");
    }

    #[tokio::test]
    async fn update_allocation_forwards_upstream_errors() {
        for (status, message) in [(403, "Forbidden"), (404, "allocation not found")] {
            let (base, _) = mock_update_api(status, serde_json::json!({ "error": message })).await;
            let client = HttpIpamClient::new(&base, None).unwrap();
            let err = client
                .update_allocation("alloc-1", &rename_only("n"))
                .await
                .expect_err("non-2xx must be an error");
            match err {
                NetcidrError::Upstream {
                    status: s,
                    message: m,
                } => {
                    assert_eq!(s, status);
                    assert_eq!(m, message);
                }
                other => panic!("expected Upstream, got {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Pagination: list endpoints cap a page at 1000 rows (default 100)
    // -----------------------------------------------------------------------

    fn sample_cidr_block(i: usize) -> serde_json::Value {
        serde_json::json!({
            "id": format!("block-{i}"),
            "tenant_id": "t",
            "cidr": format!("10.{}.{}.0/24", i / 256, i % 256),
            "network_address": "10.0.0.0",
            "broadcast_address": "10.0.0.255",
            "prefix_length": 24,
            "total_hosts": 254,
            "name": null,
            "description": null,
            "ip_version": 4,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        })
    }

    /// Serve `total` CIDR blocks from `GET /ipam/cidr-blocks`, paginated the
    /// way the real API is (default 100, clamped to 1000, `offset` skips).
    /// Records every (limit, offset) the client asked for.
    async fn mock_paged_cidr_blocks(
        total: usize,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(u32, u32)>>>) {
        use axum::extract::{Query, State};
        use axum::routing::get;
        use std::sync::{Arc, Mutex};

        #[derive(serde::Deserialize)]
        struct Page {
            limit: Option<u32>,
            offset: Option<u32>,
        }
        type Seen = Arc<Mutex<Vec<(u32, u32)>>>;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));

        let app = axum::Router::new()
            .route(
                "/ipam/cidr-blocks",
                get(
                    move |State(seen): State<Seen>, Query(page): Query<Page>| async move {
                        let limit = page.limit.unwrap_or(100).clamp(1, 1000);
                        let offset = page.offset.unwrap_or(0);
                        seen.lock().unwrap().push((limit, offset));
                        let blocks: Vec<_> = (offset as usize..total)
                            .take(limit as usize)
                            .map(sample_cidr_block)
                            .collect();
                        axum::Json(serde_json::json!({
                            "count": blocks.len(),
                            "cidr_blocks": blocks,
                        }))
                    },
                ),
            )
            .with_state(seen.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    #[tokio::test]
    async fn list_cidr_blocks_fetches_every_page() {
        // 2500 rows: two full 1000-row pages plus a short one.
        let (base, seen) = mock_paged_cidr_blocks(2500).await;
        let client = HttpIpamClient::new(&base, None).unwrap();

        let blocks = client.list_cidr_blocks().await.unwrap();
        assert_eq!(
            blocks.len(),
            2500,
            "must not stop at the server's default page"
        );
        assert_eq!(blocks[0].id, "block-0");
        assert_eq!(blocks[2499].id, "block-2499");
        assert_eq!(
            *seen.lock().unwrap(),
            vec![(1000, 0), (1000, 1000), (1000, 2000)]
        );
    }

    #[tokio::test]
    async fn list_cidr_blocks_stops_after_an_exactly_full_last_page() {
        let (base, seen) = mock_paged_cidr_blocks(1000).await;
        let client = HttpIpamClient::new(&base, None).unwrap();

        assert_eq!(client.list_cidr_blocks().await.unwrap().len(), 1000);
        // One full page, then an empty one that ends the walk.
        assert_eq!(*seen.lock().unwrap(), vec![(1000, 0), (1000, 1000)]);
    }

    // -----------------------------------------------------------------------
    // Endpoints the CLI needs beyond the MCP tool set
    // -----------------------------------------------------------------------

    /// One request as the mock API saw it.
    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        query: String,
        body: serde_json::Value,
    }

    /// Mock API that answers every request with `status` + `reply` and
    /// records what was asked.
    async fn mock_any(
        status: u16,
        reply: serde_json::Value,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Recorded>>>) {
        use axum::body::Bytes;
        use axum::extract::{OriginalUri, State};
        use axum::http::{Method, StatusCode};
        use std::sync::{Arc, Mutex};

        type Seen = Arc<Mutex<Vec<Recorded>>>;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .fallback(
                move |State(seen): State<Seen>,
                      method: Method,
                      OriginalUri(uri): OriginalUri,
                      body: Bytes| {
                    let reply = reply.clone();
                    async move {
                        seen.lock().unwrap().push(Recorded {
                            method: method.to_string(),
                            path: uri.path().to_string(),
                            query: uri.query().unwrap_or("").to_string(),
                            body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
                        });
                        let status = StatusCode::from_u16(status).unwrap();
                        if status == StatusCode::NO_CONTENT {
                            status.into_response()
                        } else {
                            (status, axum::Json(reply)).into_response()
                        }
                    }
                },
            )
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    use axum::response::IntoResponse;

    fn only(seen: &std::sync::Mutex<Vec<Recorded>>) -> Recorded {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "expected one request, got {seen:?}");
        seen[0].clone()
    }

    #[tokio::test]
    async fn get_cidr_block_gets_by_encoded_id() {
        let (base, seen) = mock_any(200, sample_cidr_block(7)).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        let block = client.get_cidr_block("block-7").await.unwrap();
        assert_eq!(block.id, "block-7");
        let req = only(&seen);
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("GET", "/ipam/cidr-blocks/block-7")
        );
    }

    #[tokio::test]
    async fn delete_cidr_block_accepts_no_content() {
        let (base, seen) = mock_any(204, serde_json::Value::Null).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        client.delete_cidr_block("a/b").await.unwrap();
        let req = only(&seen);
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("DELETE", "/ipam/cidr-blocks/a%2Fb")
        );
    }

    #[tokio::test]
    async fn get_allocation_gets_by_id() {
        let (base, seen) = mock_any(200, sample_allocation()).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        assert_eq!(
            client.get_allocation("alloc-1").await.unwrap().id,
            "alloc-1"
        );
        let req = only(&seen);
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("GET", "/ipam/allocations/alloc-1")
        );
    }

    #[tokio::test]
    async fn set_tags_puts_tags_and_returns_allocation() {
        let (base, seen) = mock_any(200, sample_allocation()).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        let tags = vec![Tag {
            key: "team".to_string(),
            value: "platform".to_string(),
        }];
        assert_eq!(
            client.set_tags("alloc-1", &tags).await.unwrap().id,
            "alloc-1"
        );
        let req = only(&seen);
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("PUT", "/ipam/allocations/alloc-1/tags")
        );
        assert_eq!(
            req.body,
            serde_json::json!({"tags": [{"key": "team", "value": "platform"}]})
        );
    }

    #[tokio::test]
    async fn reap_expired_posts_and_returns_the_count() {
        let (base, seen) = mock_any(200, serde_json::json!({"released": 3})).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        assert_eq!(
            client.reap_expired().await.unwrap(),
            ReapResult { released: 3 }
        );
        let req = only(&seen);
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("POST", "/ipam/reap")
        );
    }

    #[tokio::test]
    async fn query_audit_sends_filters_and_limit() {
        let (base, seen) = mock_any(200, serde_json::json!({"entries": [], "count": 0})).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        let entries = client
            .query_audit(&AuditFilter {
                entity_type: Some("allocation".to_string()),
                entity_id: Some("alloc-1".to_string()),
                action: Some("update".to_string()),
                limit: Some(25),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(entries.is_empty());
        let req = only(&seen);
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("GET", "/ipam/audit")
        );
        for part in [
            "entity_type=allocation",
            "entity_id=alloc-1",
            "action=update",
            "limit=25",
        ] {
            assert!(
                req.query.contains(part),
                "query {:?} missing {part}",
                req.query
            );
        }
    }

    #[tokio::test]
    async fn new_endpoints_forward_upstream_errors() {
        let (base, _) = mock_any(403, serde_json::json!({"error": "Forbidden"})).await;
        let client = HttpIpamClient::new(&base, None).unwrap();
        let err = client.delete_cidr_block("block-1").await.unwrap_err();
        assert!(
            matches!(err, NetcidrError::Upstream { status: 403, .. }),
            "got {err:?}"
        );
    }
}
