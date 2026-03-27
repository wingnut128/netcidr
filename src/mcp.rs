use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::ServerCapabilities;
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::contains::{check_ipv4_contains, check_ipv6_contains};
use crate::from_range::{from_range_ipv4, from_range_ipv6};
use crate::ipam::models::*;
use crate::ipam::operations::IpamOps;
use crate::ipv4::Ipv4Subnet;
use crate::ipv6::Ipv6Subnet;
use crate::mcp_client::HttpIpamClient;
use crate::subnet_generator::{count_subnets, generate_ipv4_subnets, generate_ipv6_subnets};
use crate::summarize::{summarize_ipv4, summarize_ipv6};

// ---------------------------------------------------------------------------
// IPAM backend abstraction — local IpamOps or remote HTTP client
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum McpIpamBackend {
    Local(Arc<IpamOps>),
    Remote(HttpIpamClient),
}

impl McpIpamBackend {
    pub async fn create_supernet(&self, input: &CreateSupernet) -> crate::error::Result<Supernet> {
        match self {
            Self::Local(ops) => ops.create_supernet(input).await,
            Self::Remote(client) => client.create_supernet(input).await,
        }
    }

    pub async fn list_supernets(&self) -> crate::error::Result<Vec<Supernet>> {
        match self {
            Self::Local(ops) => ops.list_supernets().await,
            Self::Remote(client) => client.list_supernets().await,
        }
    }

    pub async fn allocate_auto(
        &self,
        request: &AutoAllocateRequest,
    ) -> crate::error::Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.allocate_auto(request).await,
            Self::Remote(client) => client.allocate_auto(request).await,
        }
    }

    pub async fn allocate_specific(
        &self,
        input: &CreateAllocation,
    ) -> crate::error::Result<Allocation> {
        match self {
            Self::Local(ops) => ops.allocate_specific(input).await,
            Self::Remote(client) => client.allocate_specific(input).await,
        }
    }

    pub async fn release_allocation(&self, id: &str) -> crate::error::Result<Allocation> {
        match self {
            Self::Local(ops) => ops.release_allocation(id).await,
            Self::Remote(client) => client.release_allocation(id).await,
        }
    }

    pub async fn list_allocations(
        &self,
        filter: &AllocationFilter,
    ) -> crate::error::Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.list_allocations(filter).await,
            Self::Remote(client) => client.list_allocations(filter).await,
        }
    }

    pub async fn free_blocks(
        &self,
        supernet_id: &str,
        prefix: Option<u8>,
    ) -> crate::error::Result<FreeBlocksReport> {
        match self {
            Self::Local(ops) => ops.free_blocks(supernet_id, prefix).await,
            Self::Remote(client) => client.free_blocks(supernet_id, prefix).await,
        }
    }

    pub async fn utilization(&self, supernet_id: &str) -> crate::error::Result<UtilizationReport> {
        match self {
            Self::Local(ops) => ops.utilization(supernet_id).await,
            Self::Remote(client) => client.utilization(supernet_id).await,
        }
    }

    pub async fn find_by_ip(&self, address: &str) -> crate::error::Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.find_by_ip(address).await,
            Self::Remote(client) => client.find_by_ip(address).await,
        }
    }

    pub async fn find_by_resource(
        &self,
        resource_id: &str,
    ) -> crate::error::Result<Vec<Allocation>> {
        match self {
            Self::Local(ops) => ops.find_by_resource(resource_id).await,
            Self::Remote(client) => client.find_by_resource(resource_id).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Parameter types — calculator tools
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
struct SubnetCalcParams {
    /// IP address in CIDR notation, e.g. 192.168.1.0/24 or 2001:db8::/48
    cidr: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SubnetSplitParams {
    /// Supernet in CIDR notation, e.g. 10.0.0.0/8
    cidr: String,
    /// New prefix length for the generated subnets
    prefix: u8,
    /// Number of subnets to generate (mutually exclusive with max)
    count: Option<u64>,
    /// Generate all possible subnets (mutually exclusive with count)
    max: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ContainsCheckParams {
    /// Network in CIDR notation, e.g. 192.168.1.0/24
    cidr: String,
    /// IP address to check, e.g. 192.168.1.100
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FromRangeParams {
    /// Start IP address, e.g. 192.168.1.10 or 2001:db8::1
    start: String,
    /// End IP address, e.g. 192.168.1.20 or 2001:db8::ff
    end: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SummarizeParams {
    /// CIDR ranges to summarize, e.g. ["192.168.0.0/24", "192.168.1.0/24"]
    cidrs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parameter types — IPAM tools
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamCreateSupernetParams {
    /// CIDR notation for the supernet, e.g. 10.0.0.0/8 or 2001:db8::/32
    cidr: String,
    /// Optional name for the supernet
    name: Option<String>,
    /// Optional description
    description: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamListSupernetsParams {}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamAllocateParams {
    /// Supernet ID to allocate from
    supernet_id: String,
    /// Desired prefix length for the allocation
    prefix_length: u8,
    /// Number of blocks to allocate (default: 1)
    count: Option<u32>,
    /// Human-readable name
    name: Option<String>,
    /// Environment (e.g., production, staging)
    environment: Option<String>,
    /// Owner
    owner: Option<String>,
    /// External resource identifier
    resource_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamAllocateSpecificParams {
    /// Supernet ID to allocate within
    supernet_id: String,
    /// Specific CIDR to allocate, e.g. 10.0.1.0/24
    cidr: String,
    /// Human-readable name
    name: Option<String>,
    /// Environment (e.g., production, staging)
    environment: Option<String>,
    /// Owner
    owner: Option<String>,
    /// External resource identifier
    resource_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamReleaseParams {
    /// Allocation ID to release
    allocation_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamListAllocationsParams {
    /// Supernet ID to list allocations for
    supernet_id: String,
    /// Filter by status (active, reserved, released)
    status: Option<String>,
    /// Filter by environment
    environment: Option<String>,
    /// Filter by owner
    owner: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamFreeBlocksParams {
    /// Supernet ID to check for free space
    supernet_id: String,
    /// Filter by minimum prefix length
    prefix: Option<u8>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamUtilizationParams {
    /// Supernet ID to get utilization for
    supernet_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamFindIpParams {
    /// IP address to look up, e.g. 10.0.1.50 or 2001:db8::1
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IpamFindResourceParams {
    /// Resource ID to look up
    resource_id: String,
}

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NetcidrMcp {
    tool_router: ToolRouter<Self>,
    ipam: Option<McpIpamBackend>,
}

impl NetcidrMcp {
    pub fn new(ipam: Option<McpIpamBackend>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            ipam,
        }
    }
}

fn is_ipv6(s: &str) -> bool {
    s.contains(':')
}

fn result_to_string<T: serde::Serialize>(result: crate::error::Result<T>) -> String {
    match result {
        Ok(val) => serde_json::to_string_pretty(&val).unwrap_or_else(|e| format!("Error: {e}")),
        Err(e) => format!("Error: {e}"),
    }
}

const IPAM_NOT_ENABLED: &str = "Error: IPAM is not enabled. Start the MCP server with --ipam-db <path> or --api-url <url> to enable IPAM tools.";

#[tool_router]
impl NetcidrMcp {
    // -------------------------------------------------------------------
    // Calculator tools
    // -------------------------------------------------------------------

    #[tool(
        name = "subnet_calc",
        description = "Calculate IPv4 or IPv6 subnet details from CIDR notation. Returns network address, broadcast, mask, host range, total/usable hosts, network class (IPv4), address type, and more."
    )]
    async fn subnet_calc(&self, Parameters(params): Parameters<SubnetCalcParams>) -> String {
        if is_ipv6(&params.cidr) {
            result_to_string(Ipv6Subnet::from_cidr(&params.cidr))
        } else {
            result_to_string(Ipv4Subnet::from_cidr(&params.cidr))
        }
    }

    #[tool(
        name = "subnet_split",
        description = "Split a supernet into smaller subnets. Provide either a count or set max=true to generate all possible subnets. Auto-detects IPv4 vs IPv6."
    )]
    async fn subnet_split(&self, Parameters(params): Parameters<SubnetSplitParams>) -> String {
        let max = params.max.unwrap_or(false);
        if !max && params.count.is_none() {
            if let Ok(summary) = count_subnets(&params.cidr, params.prefix) {
                return serde_json::to_string_pretty(&summary)
                    .unwrap_or_else(|e| format!("Error: {e}"));
            }
            return "Error: Either count or max must be specified".to_string();
        }

        let count = if max {
            match count_subnets(&params.cidr, params.prefix) {
                Ok(summary) => summary.available_subnets.parse::<u64>().unwrap_or(u64::MAX),
                Err(e) => return format!("Error: {e}"),
            }
        } else {
            params.count.unwrap_or(1)
        };

        if is_ipv6(&params.cidr) {
            result_to_string(generate_ipv6_subnets(
                &params.cidr,
                params.prefix,
                Some(count),
            ))
        } else {
            result_to_string(generate_ipv4_subnets(
                &params.cidr,
                params.prefix,
                Some(count),
            ))
        }
    }

    #[tool(
        name = "contains_check",
        description = "Check if an IP address is contained within a CIDR range. Auto-detects IPv4 vs IPv6."
    )]
    async fn contains_check(&self, Parameters(params): Parameters<ContainsCheckParams>) -> String {
        if is_ipv6(&params.cidr) {
            result_to_string(check_ipv6_contains(&params.cidr, &params.address))
        } else {
            result_to_string(check_ipv4_contains(&params.cidr, &params.address))
        }
    }

    #[tool(
        name = "from_range",
        description = "Convert an IP address range (start-end) into minimal CIDR blocks. Auto-detects IPv4 vs IPv6."
    )]
    async fn from_range(&self, Parameters(params): Parameters<FromRangeParams>) -> String {
        if is_ipv6(&params.start) {
            result_to_string(from_range_ipv6(&params.start, &params.end))
        } else {
            result_to_string(from_range_ipv4(&params.start, &params.end))
        }
    }

    #[tool(
        name = "summarize",
        description = "Aggregate/summarize a list of CIDRs into the minimal covering set. All CIDRs must be the same address family (all IPv4 or all IPv6)."
    )]
    async fn summarize(&self, Parameters(params): Parameters<SummarizeParams>) -> String {
        if params.cidrs.is_empty() {
            return "Error: At least one CIDR is required".to_string();
        }
        if is_ipv6(&params.cidrs[0]) {
            result_to_string(summarize_ipv6(&params.cidrs))
        } else {
            result_to_string(summarize_ipv4(&params.cidrs))
        }
    }

    // -------------------------------------------------------------------
    // IPAM tools
    // -------------------------------------------------------------------

    #[tool(
        name = "ipam_create_supernet",
        description = "Create a new IPAM supernet (top-level address space). Returns the created supernet with its ID. Rejects overlapping supernets."
    )]
    async fn ipam_create_supernet(
        &self,
        Parameters(params): Parameters<IpamCreateSupernetParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        let input = CreateSupernet {
            cidr: params.cidr,
            name: params.name,
            description: params.description,
        };
        result_to_string(backend.create_supernet(&input).await)
    }

    #[tool(
        name = "ipam_list_supernets",
        description = "List all IPAM supernets. Returns an array of supernets with their IDs, CIDRs, and metadata."
    )]
    async fn ipam_list_supernets(
        &self,
        Parameters(_params): Parameters<IpamListSupernetsParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        result_to_string(backend.list_supernets().await)
    }

    #[tool(
        name = "ipam_allocate",
        description = "Auto-allocate the next available CIDR block(s) from a supernet. Specify the desired prefix length and optional count. Returns the created allocation(s)."
    )]
    async fn ipam_allocate(&self, Parameters(params): Parameters<IpamAllocateParams>) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        let request = AutoAllocateRequest {
            supernet_id: params.supernet_id,
            prefix_length: params.prefix_length,
            count: params.count,
            status: None,
            resource_id: params.resource_id,
            resource_type: None,
            name: params.name,
            description: None,
            environment: params.environment,
            owner: params.owner,
            parent_allocation_id: None,
            tags: None,
            ttl_seconds: None,
        };
        result_to_string(backend.allocate_auto(&request).await)
    }

    #[tool(
        name = "ipam_allocate_specific",
        description = "Allocate a specific CIDR block from a supernet. Rejects if the block overlaps with existing allocations."
    )]
    async fn ipam_allocate_specific(
        &self,
        Parameters(params): Parameters<IpamAllocateSpecificParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        let input = CreateAllocation {
            supernet_id: params.supernet_id,
            cidr: params.cidr,
            status: None,
            resource_id: params.resource_id,
            resource_type: None,
            name: params.name,
            description: None,
            environment: params.environment,
            owner: params.owner,
            parent_allocation_id: None,
            tags: None,
            ttl_seconds: None,
        };
        result_to_string(backend.allocate_specific(&input).await)
    }

    #[tool(
        name = "ipam_release",
        description = "Release an IPAM allocation, marking it as released and freeing the address space for future use."
    )]
    async fn ipam_release(&self, Parameters(params): Parameters<IpamReleaseParams>) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        result_to_string(backend.release_allocation(&params.allocation_id).await)
    }

    #[tool(
        name = "ipam_list_allocations",
        description = "List allocations within a supernet. Optionally filter by status, environment, or owner."
    )]
    async fn ipam_list_allocations(
        &self,
        Parameters(params): Parameters<IpamListAllocationsParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        let status = params.status.and_then(|s| s.parse().ok());
        let filter = AllocationFilter {
            supernet_id: Some(params.supernet_id),
            status,
            resource_id: None,
            resource_type: None,
            environment: params.environment,
            owner: params.owner,
        };
        result_to_string(backend.list_allocations(&filter).await)
    }

    #[tool(
        name = "ipam_free_blocks",
        description = "Find free (unallocated) CIDR blocks within a supernet. Optionally filter by minimum prefix length."
    )]
    async fn ipam_free_blocks(
        &self,
        Parameters(params): Parameters<IpamFreeBlocksParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        result_to_string(
            backend
                .free_blocks(&params.supernet_id, params.prefix)
                .await,
        )
    }

    #[tool(
        name = "ipam_utilization",
        description = "Get utilization statistics for a supernet: total addresses, allocated addresses, free addresses, and utilization percentage."
    )]
    async fn ipam_utilization(
        &self,
        Parameters(params): Parameters<IpamUtilizationParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        result_to_string(backend.utilization(&params.supernet_id).await)
    }

    #[tool(
        name = "ipam_find_ip",
        description = "Find all IPAM allocations that contain a given IP address. Returns matching allocations across all supernets."
    )]
    async fn ipam_find_ip(&self, Parameters(params): Parameters<IpamFindIpParams>) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        result_to_string(backend.find_by_ip(&params.address).await)
    }

    #[tool(
        name = "ipam_find_resource",
        description = "Find all IPAM allocations associated with a given resource ID."
    )]
    async fn ipam_find_resource(
        &self,
        Parameters(params): Parameters<IpamFindResourceParams>,
    ) -> String {
        let Some(backend) = &self.ipam else {
            return IPAM_NOT_ENABLED.to_string();
        };
        result_to_string(backend.find_by_resource(&params.resource_id).await)
    }
}

#[tool_handler]
impl ServerHandler for NetcidrMcp {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new(
                "netcidr",
                env!("CARGO_PKG_VERSION"),
            ))
    }
}

pub struct McpServerConfig<'a> {
    pub transport: crate::cli::McpTransport,
    pub address: &'a str,
    pub port: u16,
    pub daemonize: bool,
    pub pid_file: &'a str,
    pub log_file: Option<&'a str>,
    pub ipam_db: Option<&'a str>,
    pub api_url: Option<&'a str>,
}

pub async fn run_mcp_server(config: McpServerConfig<'_>) -> crate::error::Result<()> {
    let ipam = match (config.ipam_db, config.api_url) {
        (Some(_), Some(_)) => {
            return Err(crate::error::NetcidrError::InvalidInput(
                "--ipam-db and --api-url are mutually exclusive".to_string(),
            ));
        }
        (Some(db), None) => {
            let ipam_config = crate::ipam::config::IpamConfig::default();
            let store = crate::ipam::create_store(&ipam_config, Some(db), None).await?;
            Some(McpIpamBackend::Local(Arc::new(IpamOps::new(store))))
        }
        (None, Some(url)) => {
            let client = HttpIpamClient::new(url)?;
            Some(McpIpamBackend::Remote(client))
        }
        (None, None) => None,
    };

    match config.transport {
        crate::cli::McpTransport::Stdio => {
            if config.daemonize {
                return Err(crate::error::NetcidrError::InvalidInput(
                    "--daemonize is only supported with HTTP transport".to_string(),
                ));
            }
            run_mcp_stdio(ipam).await
        }
        crate::cli::McpTransport::Http => {
            if config.daemonize {
                daemonize_process(config.pid_file, config.log_file)?;
            }
            run_mcp_http(ipam, config.address, config.port).await
        }
    }
}

/// Fork the current process into the background using the `daemonize` crate,
/// write a PID file, and redirect output to a log file (or /dev/null).
fn daemonize_process(pid_file: &str, log_file: Option<&str>) -> crate::error::Result<()> {
    let mut daemon = daemonize::Daemonize::new().pid_file(pid_file);

    if let Some(path) = log_file {
        let stdout = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                crate::error::NetcidrError::InvalidInput(format!(
                    "Failed to open log file {path}: {e}"
                ))
            })?;
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                crate::error::NetcidrError::InvalidInput(format!(
                    "Failed to open log file {path}: {e}"
                ))
            })?;
        daemon = daemon.stdout(stdout).stderr(stderr);
    }

    daemon.start().map_err(|e| {
        crate::error::NetcidrError::InvalidInput(format!("Failed to daemonize: {e}"))
    })?;

    Ok(())
}

async fn run_mcp_stdio(ipam: Option<McpIpamBackend>) -> crate::error::Result<()> {
    let server = NetcidrMcp::new(ipam);
    let transport = rmcp::transport::io::stdio();
    let service = server
        .serve(transport)
        .await
        .map_err(|e| crate::error::NetcidrError::InvalidInput(format!("MCP server error: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| crate::error::NetcidrError::InvalidInput(format!("MCP server error: {e}")))?;
    Ok(())
}

async fn run_mcp_http(
    ipam: Option<McpIpamBackend>,
    address: &str,
    port: u16,
) -> crate::error::Result<()> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    };

    let config = StreamableHttpServerConfig::default();
    let ct = config.cancellation_token.clone();

    let service = StreamableHttpService::new(
        move || Ok(NetcidrMcp::new(ipam.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let bind_addr = format!("{address}:{port}");
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| {
            crate::error::NetcidrError::InvalidInput(format!("Failed to bind {bind_addr}: {e}"))
        })?;

    eprintln!("MCP server listening on http://{bind_addr}/mcp");

    let shutdown_ct = ct.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_ct.cancel();
    });

    axum::serve(listener, router)
        .with_graceful_shutdown(async move { ct.cancelled().await })
        .await
        .map_err(|e| crate::error::NetcidrError::InvalidInput(format!("MCP server error: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calc_server() -> NetcidrMcp {
        NetcidrMcp::new(None)
    }

    async fn ipam_server() -> NetcidrMcp {
        use crate::ipam::store::IpamStore;
        let store = crate::ipam::sqlite::SqliteStore::in_memory().expect("in-memory store");
        store.initialize().await.expect("init");
        store.migrate().await.expect("migrate");
        let ops = Arc::new(IpamOps::new(Arc::new(store)));
        NetcidrMcp::new(Some(McpIpamBackend::Local(ops)))
    }

    // -------------------------------------------------------------------
    // Calculator tool tests
    // -------------------------------------------------------------------

    #[test]
    fn test_is_ipv6() {
        assert!(is_ipv6("2001:db8::/32"));
        assert!(is_ipv6("::1"));
        assert!(!is_ipv6("192.168.1.0/24"));
        assert!(!is_ipv6("10.0.0.1"));
    }

    #[tokio::test]
    async fn test_subnet_calc_ipv4() {
        let server = calc_server();
        let result = server
            .subnet_calc(Parameters(SubnetCalcParams {
                cidr: "192.168.1.0/24".into(),
            }))
            .await;
        assert!(result.contains("192.168.1.0"));
        assert!(result.contains("192.168.1.255"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_subnet_calc_ipv6() {
        let server = calc_server();
        let result = server
            .subnet_calc(Parameters(SubnetCalcParams {
                cidr: "2001:db8::/48".into(),
            }))
            .await;
        assert!(result.contains("2001:db8::"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_subnet_calc_invalid() {
        let server = calc_server();
        let result = server
            .subnet_calc(Parameters(SubnetCalcParams {
                cidr: "not-a-cidr".into(),
            }))
            .await;
        assert!(result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_subnet_split_with_count() {
        let server = calc_server();
        let result = server
            .subnet_split(Parameters(SubnetSplitParams {
                cidr: "10.0.0.0/8".into(),
                prefix: 16,
                count: Some(3),
                max: None,
            }))
            .await;
        assert!(result.contains("10.0.0.0"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_subnet_split_with_max() {
        let server = calc_server();
        let result = server
            .subnet_split(Parameters(SubnetSplitParams {
                cidr: "192.168.0.0/24".into(),
                prefix: 26,
                count: None,
                max: Some(true),
            }))
            .await;
        assert!(result.contains("192.168.0.0"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_subnet_split_no_count_no_max() {
        let server = calc_server();
        let result = server
            .subnet_split(Parameters(SubnetSplitParams {
                cidr: "10.0.0.0/8".into(),
                prefix: 16,
                count: None,
                max: None,
            }))
            .await;
        // Should return count summary, not an error
        assert!(result.contains("available_subnets"));
    }

    #[tokio::test]
    async fn test_contains_check_ipv4_contained() {
        let server = calc_server();
        let result = server
            .contains_check(Parameters(ContainsCheckParams {
                cidr: "192.168.1.0/24".into(),
                address: "192.168.1.100".into(),
            }))
            .await;
        assert!(result.contains("true"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_contains_check_ipv4_not_contained() {
        let server = calc_server();
        let result = server
            .contains_check(Parameters(ContainsCheckParams {
                cidr: "192.168.1.0/24".into(),
                address: "10.0.0.1".into(),
            }))
            .await;
        assert!(result.contains("false"));
    }

    #[tokio::test]
    async fn test_contains_check_ipv6() {
        let server = calc_server();
        let result = server
            .contains_check(Parameters(ContainsCheckParams {
                cidr: "2001:db8::/32".into(),
                address: "2001:db8::1".into(),
            }))
            .await;
        assert!(result.contains("true"));
    }

    #[tokio::test]
    async fn test_from_range_ipv4() {
        let server = calc_server();
        let result = server
            .from_range(Parameters(FromRangeParams {
                start: "192.168.1.0".into(),
                end: "192.168.1.255".into(),
            }))
            .await;
        assert!(result.contains("192.168.1.0/24"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_from_range_ipv6() {
        let server = calc_server();
        let result = server
            .from_range(Parameters(FromRangeParams {
                start: "2001:db8::".into(),
                end: "2001:db8::ff".into(),
            }))
            .await;
        assert!(result.contains("2001:db8::"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_summarize_ipv4() {
        let server = calc_server();
        let result = server
            .summarize(Parameters(SummarizeParams {
                cidrs: vec!["192.168.0.0/24".into(), "192.168.1.0/24".into()],
            }))
            .await;
        assert!(result.contains("192.168.0.0/23"));
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_summarize_ipv6() {
        let server = calc_server();
        let result = server
            .summarize(Parameters(SummarizeParams {
                cidrs: vec!["2001:db8::/48".into(), "2001:db8:1::/48".into()],
            }))
            .await;
        assert!(!result.starts_with("Error"));
    }

    #[tokio::test]
    async fn test_summarize_empty() {
        let server = calc_server();
        let result = server
            .summarize(Parameters(SummarizeParams { cidrs: vec![] }))
            .await;
        assert!(result.starts_with("Error"));
    }

    // -------------------------------------------------------------------
    // IPAM tool tests — disabled
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_ipam_tools_disabled() {
        let server = calc_server(); // no IPAM
        let result = server
            .ipam_list_supernets(Parameters(IpamListSupernetsParams {}))
            .await;
        assert!(result.contains("IPAM is not enabled"));
    }

    // -------------------------------------------------------------------
    // IPAM tool tests — enabled (local backend)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_ipam_create_and_list_supernets() {
        let server = ipam_server().await;
        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "10.0.0.0/8".into(),
                name: Some("Corp".into()),
                description: None,
            }))
            .await;
        assert!(!result.starts_with("Error"), "create failed: {result}");
        assert!(result.contains("10.0.0.0/8"));

        let result = server
            .ipam_list_supernets(Parameters(IpamListSupernetsParams {}))
            .await;
        assert!(!result.starts_with("Error"));
        assert!(result.contains("10.0.0.0/8"));
    }

    #[tokio::test]
    async fn test_ipam_allocate_and_list() {
        let server = ipam_server().await;

        // Create supernet
        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "10.0.0.0/8".into(),
                name: None,
                description: None,
            }))
            .await;
        let supernet: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sn_id = supernet["id"].as_str().unwrap().to_string();

        // Auto-allocate
        let result = server
            .ipam_allocate(Parameters(IpamAllocateParams {
                supernet_id: sn_id.clone(),
                prefix_length: 24,
                count: Some(2),
                name: Some("test".into()),
                environment: None,
                owner: None,
                resource_id: None,
            }))
            .await;
        assert!(!result.starts_with("Error"), "allocate failed: {result}");

        // List allocations
        let result = server
            .ipam_list_allocations(Parameters(IpamListAllocationsParams {
                supernet_id: sn_id,
                status: None,
                environment: None,
                owner: None,
            }))
            .await;
        assert!(!result.starts_with("Error"));
        let allocs: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
        assert_eq!(allocs.len(), 2);
    }

    #[tokio::test]
    async fn test_ipam_allocate_specific_and_release() {
        let server = ipam_server().await;

        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "10.0.0.0/8".into(),
                name: None,
                description: None,
            }))
            .await;
        let supernet: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sn_id = supernet["id"].as_str().unwrap().to_string();

        // Allocate specific
        let result = server
            .ipam_allocate_specific(Parameters(IpamAllocateSpecificParams {
                supernet_id: sn_id,
                cidr: "10.0.1.0/24".into(),
                name: Some("web".into()),
                environment: Some("prod".into()),
                owner: None,
                resource_id: Some("vpc-123".into()),
            }))
            .await;
        assert!(!result.starts_with("Error"), "alloc failed: {result}");
        let alloc: serde_json::Value = serde_json::from_str(&result).unwrap();
        let alloc_id = alloc["id"].as_str().unwrap().to_string();

        // Release
        let result = server
            .ipam_release(Parameters(IpamReleaseParams {
                allocation_id: alloc_id,
            }))
            .await;
        assert!(!result.starts_with("Error"));
        assert!(result.contains("released"));
    }

    #[tokio::test]
    async fn test_ipam_utilization_and_free_blocks() {
        let server = ipam_server().await;

        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "192.168.0.0/24".into(),
                name: None,
                description: None,
            }))
            .await;
        let supernet: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sn_id = supernet["id"].as_str().unwrap().to_string();

        // Allocate half
        server
            .ipam_allocate_specific(Parameters(IpamAllocateSpecificParams {
                supernet_id: sn_id.clone(),
                cidr: "192.168.0.0/25".into(),
                name: None,
                environment: None,
                owner: None,
                resource_id: None,
            }))
            .await;

        // Utilization
        let result = server
            .ipam_utilization(Parameters(IpamUtilizationParams {
                supernet_id: sn_id.clone(),
            }))
            .await;
        assert!(!result.starts_with("Error"));
        assert!(result.contains("utilization_percent"));

        // Free blocks
        let result = server
            .ipam_free_blocks(Parameters(IpamFreeBlocksParams {
                supernet_id: sn_id,
                prefix: None,
            }))
            .await;
        assert!(!result.starts_with("Error"));
        assert!(result.contains("192.168.0.128/25"));
    }

    #[tokio::test]
    async fn test_ipam_find_ip() {
        let server = ipam_server().await;

        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "10.0.0.0/8".into(),
                name: None,
                description: None,
            }))
            .await;
        let supernet: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sn_id = supernet["id"].as_str().unwrap().to_string();

        server
            .ipam_allocate_specific(Parameters(IpamAllocateSpecificParams {
                supernet_id: sn_id,
                cidr: "10.0.1.0/24".into(),
                name: None,
                environment: None,
                owner: None,
                resource_id: None,
            }))
            .await;

        let result = server
            .ipam_find_ip(Parameters(IpamFindIpParams {
                address: "10.0.1.50".into(),
            }))
            .await;
        assert!(!result.starts_with("Error"));
        assert!(result.contains("10.0.1.0/24"));
    }

    #[tokio::test]
    async fn test_ipam_find_resource() {
        let server = ipam_server().await;

        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "10.0.0.0/8".into(),
                name: None,
                description: None,
            }))
            .await;
        let supernet: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sn_id = supernet["id"].as_str().unwrap().to_string();

        server
            .ipam_allocate_specific(Parameters(IpamAllocateSpecificParams {
                supernet_id: sn_id,
                cidr: "10.0.2.0/24".into(),
                name: None,
                environment: None,
                owner: None,
                resource_id: Some("eni-abc123".into()),
            }))
            .await;

        let result = server
            .ipam_find_resource(Parameters(IpamFindResourceParams {
                resource_id: "eni-abc123".into(),
            }))
            .await;
        assert!(!result.starts_with("Error"));
        assert!(result.contains("10.0.2.0/24"));
    }

    #[tokio::test]
    async fn test_ipam_overlap_rejected() {
        let server = ipam_server().await;

        let result = server
            .ipam_create_supernet(Parameters(IpamCreateSupernetParams {
                cidr: "10.0.0.0/8".into(),
                name: None,
                description: None,
            }))
            .await;
        let supernet: serde_json::Value = serde_json::from_str(&result).unwrap();
        let sn_id = supernet["id"].as_str().unwrap().to_string();

        server
            .ipam_allocate_specific(Parameters(IpamAllocateSpecificParams {
                supernet_id: sn_id.clone(),
                cidr: "10.0.0.0/16".into(),
                name: None,
                environment: None,
                owner: None,
                resource_id: None,
            }))
            .await;

        // Overlapping allocation should fail
        let result = server
            .ipam_allocate_specific(Parameters(IpamAllocateSpecificParams {
                supernet_id: sn_id,
                cidr: "10.0.0.0/24".into(),
                name: None,
                environment: None,
                owner: None,
                resource_id: None,
            }))
            .await;
        assert!(result.starts_with("Error"));
    }

    // -------------------------------------------------------------------
    // HttpIpamClient unit tests (construction)
    // -------------------------------------------------------------------

    #[test]
    fn test_http_client_new() {
        let client = HttpIpamClient::new("http://localhost:8080").unwrap();
        assert_eq!(
            client.url("/supernets"),
            "http://localhost:8080/ipam/supernets"
        );
    }

    #[test]
    fn test_http_client_strips_trailing_slash() {
        let client = HttpIpamClient::new("http://localhost:8080/").unwrap();
        assert_eq!(
            client.url("/supernets"),
            "http://localhost:8080/ipam/supernets"
        );
    }

    #[test]
    fn test_mutually_exclusive_options() {
        // run_mcp_server validates this, but we can test the logic directly
        let result = tokio_test::block_on(run_mcp_server(McpServerConfig {
            transport: crate::cli::McpTransport::Stdio,
            address: "127.0.0.1",
            port: 3000,
            daemonize: false,
            pid_file: "/tmp/netcidr-test.pid",
            log_file: None,
            ipam_db: Some("test.db"),
            api_url: Some("http://localhost:8080"),
        }));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"));
    }
}
