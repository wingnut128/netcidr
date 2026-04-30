use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Router,
    extract::Query,
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, instrument, warn};
#[cfg(feature = "swagger")]
use utoipa::{IntoParams, OpenApi, ToSchema};
#[cfg(feature = "swagger")]
use utoipa_swagger_ui::SwaggerUi;

use crate::auth::require_auth;
#[cfg(feature = "swagger")]
use crate::batch::BatchResult;
use crate::batch::process_batch_with_limit;
use crate::config::ServerConfig;
#[cfg(feature = "swagger")]
use crate::contains::ContainsResult;
use crate::contains::{check_ipv4_contains, check_ipv6_contains};
use crate::error::NetcidrError;
#[cfg(feature = "swagger")]
use crate::from_range::{Ipv4FromRangeResult, Ipv6FromRangeResult};
use crate::from_range::{from_range_ipv4_with_limit, from_range_ipv6_with_limit};
use crate::ipv4::Ipv4Subnet;
use crate::ipv6::Ipv6Subnet;
use crate::output::{CsvOutput, OutputFormat, TextOutput};
#[cfg(feature = "swagger")]
use crate::subnet_generator::{Ipv4SubnetList, Ipv6SubnetList, SplitSummary};
use crate::subnet_generator::{count_subnets, generate_ipv4_subnets, generate_ipv6_subnets};
#[cfg(feature = "swagger")]
use crate::summarize::{Ipv4SummaryResult, Ipv6SummaryResult};
use crate::summarize::{summarize_ipv4_with_limit, summarize_ipv6_with_limit};

#[cfg(feature = "swagger")]
use crate::ipam::models::{
    Allocation, AllocationList, AllocationStatus, AuditEntry, AuditList, CreateSupernet, FreeBlock,
    FreeBlocksReport, Supernet, SupernetList, Tag, UpdateAllocation, UtilizationReport,
};
#[cfg(feature = "swagger")]
use crate::ipam_api::{AllocateSpecificRequest, AutoAllocateBody, IpamErrorResponse, TagsBody};

#[cfg(feature = "swagger")]
#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        version,
        calculate_ipv4,
        calculate_ipv6,
        split_ipv4,
        split_ipv6,
        contains_ipv4,
        contains_ipv6,
        summarize_ipv4_handler,
        summarize_ipv6_handler,
        from_range_ipv4_handler,
        from_range_ipv6_handler,
        batch_handler,
        crate::ipam_api::ipam_create_supernet,
        crate::ipam_api::ipam_list_supernets,
        crate::ipam_api::ipam_get_supernet,
        crate::ipam_api::ipam_delete_supernet,
        crate::ipam_api::ipam_allocate_specific,
        crate::ipam_api::ipam_auto_allocate,
        crate::ipam_api::ipam_list_supernet_allocations,
        crate::ipam_api::ipam_free_blocks,
        crate::ipam_api::ipam_utilization,
        crate::ipam_api::ipam_get_allocation,
        crate::ipam_api::ipam_update_allocation,
        crate::ipam_api::ipam_release_allocation,
        crate::ipam_api::ipam_find_ip,
        crate::ipam_api::ipam_find_resource,
        crate::ipam_api::ipam_query_audit,
        crate::ipam_api::ipam_set_tags,
    ),
    components(
        schemas(
            Ipv4Subnet, Ipv6Subnet, Ipv4SubnetList, Ipv6SubnetList, SplitSummary,
            ContainsResult, Ipv4SummaryResult, Ipv6SummaryResult, Ipv4FromRangeResult,
            Ipv6FromRangeResult, SubnetQuery, SplitQuery, ContainsQuery, SummarizeQuery,
            FromRangeQuery, BatchRequest, BatchResult, ErrorResponse, VersionResponse,
            Supernet, SupernetList, CreateSupernet, Allocation, AllocationList,
            AllocationStatus, Tag, UpdateAllocation, AllocateSpecificRequest,
            AutoAllocateBody, TagsBody, AuditEntry, AuditList, UtilizationReport,
            FreeBlock, FreeBlocksReport, IpamErrorResponse,
        )
    ),
    tags(
        (name = "netcidr", description = "IP subnet calculator API"),
        (name = "ipam", description = "IP Address Management API"),
    ),
    info(
        title = "netcidr API",
        version = env!("CARGO_PKG_VERSION"),
        description = "A fast IPv4 and IPv6 subnet calculator API with IP address management",
    )
)]
pub struct ApiDoc;

#[derive(Default)]
pub struct RouterConfig {
    pub server: ServerConfig,
    pub ipam_ops: Option<Arc<crate::ipam::operations::IpamOps>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema, IntoParams))]
pub struct SubnetQuery {
    /// IP address in CIDR notation (e.g., 192.168.1.0/24 or 2001:db8::/48)
    cidr: String,
    /// Pretty print JSON output
    #[serde(default)]
    pretty: bool,
    /// Output format (json, text, csv, yaml)
    #[serde(default)]
    format: ApiOutputFormat,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema, IntoParams))]
pub struct SplitQuery {
    /// Network in CIDR notation
    cidr: String,
    /// New prefix length for subnets
    prefix: u8,
    /// Number of subnets to generate. If not provided and max is true, generates all.
    count: Option<u64>,
    /// Generate maximum number of subnets possible.
    #[serde(default)]
    max: bool,
    /// Show only the number of available subnets (no generation)
    #[serde(default, alias = "count-only")]
    count_only: bool,
    /// Pretty print JSON output
    #[serde(default)]
    pretty: bool,
    /// Output format (json, text, csv, yaml)
    #[serde(default)]
    format: ApiOutputFormat,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema, IntoParams))]
pub struct ContainsQuery {
    /// Network in CIDR notation (e.g., 192.168.1.0/24)
    cidr: String,
    /// IP address to check (e.g., 192.168.1.100)
    address: String,
    /// Pretty print JSON output
    #[serde(default)]
    pretty: bool,
    /// Output format (json, text, csv, yaml)
    #[serde(default)]
    format: ApiOutputFormat,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema, IntoParams))]
pub struct SummarizeQuery {
    /// Comma-separated CIDR ranges to summarize
    cidrs: String,
    /// Pretty print JSON output
    #[serde(default)]
    pretty: bool,
    /// Output format (json, text, csv, yaml)
    #[serde(default)]
    format: ApiOutputFormat,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema, IntoParams))]
pub struct FromRangeQuery {
    /// Start IP address (e.g., 192.168.1.10 or 2001:db8::1)
    start: String,
    /// End IP address (e.g., 192.168.1.20 or 2001:db8::ff)
    end: String,
    /// Pretty print JSON output
    #[serde(default)]
    pretty: bool,
    /// Output format (json, text, csv, yaml)
    #[serde(default)]
    format: ApiOutputFormat,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
pub struct BatchRequest {
    /// List of CIDRs to process (IPv4 and/or IPv6)
    pub cidrs: Vec<String>,
    /// Pretty print JSON output
    #[serde(default)]
    pub pretty: bool,
    /// Output format (json, text, csv, yaml)
    #[serde(default)]
    pub format: ApiOutputFormat,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
struct ErrorResponse {
    /// Error message
    error: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(ToSchema))]
struct VersionResponse {
    /// Application name
    name: &'static str,
    /// Application version
    version: &'static str,
    /// Short git commit SHA the binary was built from (or "unknown")
    commit: &'static str,
    /// Full git commit SHA the binary was built from (or "unknown")
    commit_full: &'static str,
}

#[derive(Deserialize, Default, Clone, Copy)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ApiOutputFormat {
    #[default]
    Json,
    Text,
    Csv,
    Yaml,
}

impl From<ApiOutputFormat> for OutputFormat {
    fn from(f: ApiOutputFormat) -> Self {
        match f {
            ApiOutputFormat::Json => OutputFormat::Json,
            ApiOutputFormat::Text => OutputFormat::Text,
            ApiOutputFormat::Csv => OutputFormat::Csv,
            ApiOutputFormat::Yaml => OutputFormat::Yaml,
        }
    }
}

fn build_response(status: StatusCode, content_type: &str, body: String) -> Response {
    match Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(body.into())
    {
        Ok(resp) => resp,
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .expect("fallback response must be valid"),
    }
}

/// CSV responses use a download disposition so a browser opening the URL
/// directly saves the file instead of rendering it inline. Combined with the
/// global `X-Content-Type-Options: nosniff` and the formula-neutralization
/// in `output.rs::sanitize_csv_cell`, this hardens against both
/// MIME-confusion and spreadsheet formula-injection attacks.
fn build_csv_response(status: StatusCode, body: String) -> Response {
    match Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"netcidr.csv\"",
        )
        .body(body.into())
    {
        Ok(resp) => resp,
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .expect("fallback response must be valid"),
    }
}

fn format_response<T: Serialize + TextOutput + CsvOutput>(
    value: T,
    format: ApiOutputFormat,
    pretty: bool,
    status: StatusCode,
) -> Response {
    match format {
        ApiOutputFormat::Json => {
            let body = if pretty {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            };
            match body {
                Ok(b) => build_response(status, "application/json", b),
                Err(e) => json_response(
                    ErrorResponse {
                        error: e.to_string(),
                    },
                    false,
                    StatusCode::INTERNAL_SERVER_ERROR,
                ),
            }
        }
        ApiOutputFormat::Text => {
            let body = value.to_text();
            build_response(status, "text/plain", body)
        }
        ApiOutputFormat::Csv => match value.to_csv() {
            Ok(body) => build_csv_response(status, body),
            Err(e) => json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                false,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        },
        ApiOutputFormat::Yaml => match serde_saphyr::to_string(&value) {
            Ok(body) => build_response(status, "application/yaml", body),
            Err(e) => json_response(
                ErrorResponse {
                    error: NetcidrError::Yaml(e.to_string()).to_string(),
                },
                false,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        },
    }
}

pub fn create_router(config: RouterConfig) -> Router {
    let config_ext = Arc::new(config.server.clone());
    let auth_config = config.server.auth_config();

    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/v4", get(calculate_ipv4))
        .route("/v6", get(calculate_ipv6))
        .route("/v4/split", get(split_ipv4))
        .route("/v6/split", get(split_ipv6))
        .route("/v4/contains", get(contains_ipv4))
        .route("/v6/contains", get(contains_ipv6))
        .route("/v4/summarize", get(summarize_ipv4_handler))
        .route("/v6/summarize", get(summarize_ipv6_handler))
        .route("/v4/from-range", get(from_range_ipv4_handler))
        .route("/v6/from-range", get(from_range_ipv6_handler))
        .route("/batch", post(batch_handler));

    let ipam_enabled = config.ipam_ops.is_some();

    #[cfg(feature = "dashboard")]
    let router = router
        .route("/dashboard", get(dashboard))
        .route("/", get(dashboard));
    #[cfg(not(feature = "dashboard"))]
    let router = router;

    // Conditionally mount IPAM routes — auth applies only to /ipam/*.
    let router = if let Some(ops) = config.ipam_ops {
        let ipam_auth = auth_config.clone();
        let ipam_router = crate::ipam_api::create_ipam_router()
            .layer(Extension(ops))
            .layer(middleware::from_fn(move |request, next| {
                let auth_config = ipam_auth.clone();
                async move { require_auth(auth_config, request, next).await }
            }));
        router.nest("/ipam", ipam_router)
    } else {
        router
    };

    // Features endpoint
    #[cfg(feature = "swagger")]
    let swagger_enabled = config.server.enable_swagger;
    #[cfg(not(feature = "swagger"))]
    let swagger_enabled = false;

    let features = FeaturesResponse {
        ipam: ipam_enabled,
        swagger: swagger_enabled,
    };
    let router = router.route(
        "/features",
        get(move || async move { Json(features.clone()) }),
    );

    // /me + admin allowlist read endpoint. Both are auth-aware but live
    // outside the /ipam middleware (so an unallowlisted user can hit /me
    // and get a 200 with `is_allowlisted: false` instead of a 403).
    let router = router
        .route("/me", get(me_handler))
        .route("/admin/allowlist", get(allowlist_handler))
        .layer(Extension(auth_config.clone()));

    #[cfg(feature = "swagger")]
    let router = if config.server.enable_swagger {
        router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
    } else {
        router
    };

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(
            Vec::<HeaderValue>::new(),
        ))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    let _ = auth_config; // auth is now scoped to /ipam/* above; non-IPAM routes are public.

    let router = router
        .layer(Extension(config_ext))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(config.server.max_body_size))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.server.timeout_seconds),
        ));

    // Per-IP rate limiting via tower-governor (disabled when rate_limit_per_second == 0).
    // Requires ConnectInfo<SocketAddr> — the server must use
    // `into_make_service_with_connect_info::<SocketAddr>()`.
    let router =
        if let Some(replenish_ms) = 1000u64.checked_div(config.server.rate_limit_per_second) {
            match GovernorConfigBuilder::default()
                .per_millisecond(replenish_ms)
                .burst_size(config.server.rate_limit_burst)
                .finish()
            {
                Some(governor_config) => router.layer(GovernorLayer::new(governor_config)),
                None => {
                    // burst_size = 0 makes the config invalid; disable rate limiting and warn.
                    warn!(
                        rate_limit_per_second = config.server.rate_limit_per_second,
                        rate_limit_burst = config.server.rate_limit_burst,
                        "invalid rate limit config (burst_size must be > 0); rate limiting disabled"
                    );
                    router
                }
            }
        } else {
            router
        };

    router
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy", body = String)
    ),
    tag = "netcidr"
))]
async fn health() -> &'static str {
    "OK"
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/version",
    responses(
        (status = 200, description = "Version information", body = VersionResponse)
    ),
    tag = "netcidr"
))]
async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        commit: env!("GIT_SHA_SHORT"),
        commit_full: env!("GIT_SHA_FULL"),
    })
}

/// Helper function to format JSON responses with optional pretty printing
fn json_response<T: Serialize>(value: T, pretty: bool, status: StatusCode) -> Response {
    let json_string = if pretty {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    };

    match json_string {
        Ok(body) => build_response(status, "application/json", body),
        Err(_) => build_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json",
            r#"{"error":"Internal serialization error"}"#.to_string(),
        ),
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v4",
    params(
        SubnetQuery
    ),
    responses(
        (status = 200, description = "IPv4 subnet information", body = Ipv4Subnet),
        (status = 400, description = "Invalid CIDR notation", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidr = %params.cidr))]
async fn calculate_ipv4(Query(params): Query<SubnetQuery>) -> impl IntoResponse {
    info!("Calculating IPv4 subnet");
    match Ipv4Subnet::from_cidr(&params.cidr) {
        Ok(subnet) => {
            info!(network = %subnet.network, "IPv4 calculation successful");
            format_response(subnet, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv4 calculation failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v6",
    params(
        SubnetQuery
    ),
    responses(
        (status = 200, description = "IPv6 subnet information", body = Ipv6Subnet),
        (status = 400, description = "Invalid CIDR notation", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidr = %params.cidr))]
async fn calculate_ipv6(Query(params): Query<SubnetQuery>) -> impl IntoResponse {
    info!("Calculating IPv6 subnet");
    match Ipv6Subnet::from_cidr(&params.cidr) {
        Ok(subnet) => {
            info!(network = %subnet.network, "IPv6 calculation successful");
            format_response(subnet, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv6 calculation failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v4/split",
    params(
        SplitQuery
    ),
    responses(
        (status = 200, description = "Generated IPv4 subnets", body = Ipv4SubnetList),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidr = %params.cidr, prefix = params.prefix, count = ?params.count, max = params.max))]
async fn split_ipv4(Query(params): Query<SplitQuery>) -> impl IntoResponse {
    info!("Splitting IPv4 supernet");

    if params.count_only {
        return match count_subnets(&params.cidr, params.prefix) {
            Ok(summary) => {
                info!(available = %summary.available_subnets, "IPv4 count-only successful");
                format_response(summary, params.format, params.pretty, StatusCode::OK)
            }
            Err(e) => {
                warn!(error = %e, "IPv4 count-only failed");
                json_response(
                    ErrorResponse {
                        error: e.to_string(),
                    },
                    params.pretty,
                    StatusCode::BAD_REQUEST,
                )
            }
        };
    }

    // Determine the actual count: None means generate max
    let actual_count = if params.max {
        None
    } else {
        match params.count {
            Some(c) => Some(c),
            None => {
                warn!("Neither count nor max specified");
                return json_response(
                    ErrorResponse {
                        error: "Either 'count' or 'max=true' must be specified".to_string(),
                    },
                    params.pretty,
                    StatusCode::BAD_REQUEST,
                );
            }
        }
    };

    match generate_ipv4_subnets(&params.cidr, params.prefix, actual_count) {
        Ok(result) => {
            info!(
                subnets_generated = result.subnets.len(),
                "IPv4 split successful"
            );
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv4 split failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v6/split",
    params(
        SplitQuery
    ),
    responses(
        (status = 200, description = "Generated IPv6 subnets", body = Ipv6SubnetList),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidr = %params.cidr, prefix = params.prefix, count = ?params.count, max = params.max))]
async fn split_ipv6(Query(params): Query<SplitQuery>) -> impl IntoResponse {
    info!("Splitting IPv6 supernet");

    if params.count_only {
        return match count_subnets(&params.cidr, params.prefix) {
            Ok(summary) => {
                info!(available = %summary.available_subnets, "IPv6 count-only successful");
                format_response(summary, params.format, params.pretty, StatusCode::OK)
            }
            Err(e) => {
                warn!(error = %e, "IPv6 count-only failed");
                json_response(
                    ErrorResponse {
                        error: e.to_string(),
                    },
                    params.pretty,
                    StatusCode::BAD_REQUEST,
                )
            }
        };
    }

    // Determine the actual count: None means generate max
    let actual_count = if params.max {
        None
    } else {
        match params.count {
            Some(c) => Some(c),
            None => {
                warn!("Neither count nor max specified");
                return json_response(
                    ErrorResponse {
                        error: "Either 'count' or 'max=true' must be specified".to_string(),
                    },
                    params.pretty,
                    StatusCode::BAD_REQUEST,
                );
            }
        }
    };

    match generate_ipv6_subnets(&params.cidr, params.prefix, actual_count) {
        Ok(result) => {
            info!(
                subnets_generated = result.subnets.len(),
                "IPv6 split successful"
            );
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv6 split failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v4/contains",
    params(
        ContainsQuery
    ),
    responses(
        (status = 200, description = "IPv4 containment check result", body = ContainsResult),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidr = %params.cidr, address = %params.address))]
async fn contains_ipv4(Query(params): Query<ContainsQuery>) -> impl IntoResponse {
    info!("Checking IPv4 address containment");
    match check_ipv4_contains(&params.cidr, &params.address) {
        Ok(result) => {
            info!(
                contained = result.contained,
                "IPv4 containment check successful"
            );
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv4 containment check failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v6/contains",
    params(
        ContainsQuery
    ),
    responses(
        (status = 200, description = "IPv6 containment check result", body = ContainsResult),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidr = %params.cidr, address = %params.address))]
async fn contains_ipv6(Query(params): Query<ContainsQuery>) -> impl IntoResponse {
    info!("Checking IPv6 address containment");
    match check_ipv6_contains(&params.cidr, &params.address) {
        Ok(result) => {
            info!(
                contained = result.contained,
                "IPv6 containment check successful"
            );
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv6 containment check failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v4/summarize",
    params(
        SummarizeQuery
    ),
    responses(
        (status = 200, description = "Summarized IPv4 CIDRs", body = Ipv4SummaryResult),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidrs = %params.cidrs))]
async fn summarize_ipv4_handler(
    Extension(config): Extension<Arc<ServerConfig>>,
    Query(params): Query<SummarizeQuery>,
) -> impl IntoResponse {
    info!("Summarizing IPv4 CIDRs");
    let cidrs: Vec<String> = params
        .cidrs
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    match summarize_ipv4_with_limit(&cidrs, config.max_summarize_inputs) {
        Ok(result) => {
            info!(
                input = result.input_count,
                output = result.output_count,
                "IPv4 summarization successful"
            );
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv4 summarization failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v6/summarize",
    params(
        SummarizeQuery
    ),
    responses(
        (status = 200, description = "Summarized IPv6 CIDRs", body = Ipv6SummaryResult),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(cidrs = %params.cidrs))]
async fn summarize_ipv6_handler(
    Extension(config): Extension<Arc<ServerConfig>>,
    Query(params): Query<SummarizeQuery>,
) -> impl IntoResponse {
    info!("Summarizing IPv6 CIDRs");
    let cidrs: Vec<String> = params
        .cidrs
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    match summarize_ipv6_with_limit(&cidrs, config.max_summarize_inputs) {
        Ok(result) => {
            info!(
                input = result.input_count,
                output = result.output_count,
                "IPv6 summarization successful"
            );
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv6 summarization failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v4/from-range",
    params(
        FromRangeQuery
    ),
    responses(
        (status = 200, description = "CIDR blocks covering the IPv4 range", body = Ipv4FromRangeResult),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(start = %params.start, end = %params.end))]
async fn from_range_ipv4_handler(
    Extension(config): Extension<Arc<ServerConfig>>,
    Query(params): Query<FromRangeQuery>,
) -> impl IntoResponse {
    info!("Converting IPv4 range to CIDRs");
    match from_range_ipv4_with_limit(&params.start, &params.end, config.max_generated_cidrs) {
        Ok(result) => {
            info!(cidr_count = result.cidr_count, "IPv4 from-range successful");
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv4 from-range failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/v6/from-range",
    params(
        FromRangeQuery
    ),
    responses(
        (status = 200, description = "CIDR blocks covering the IPv6 range", body = Ipv6FromRangeResult),
        (status = 400, description = "Invalid parameters", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(start = %params.start, end = %params.end))]
async fn from_range_ipv6_handler(
    Extension(config): Extension<Arc<ServerConfig>>,
    Query(params): Query<FromRangeQuery>,
) -> impl IntoResponse {
    info!("Converting IPv6 range to CIDRs");
    match from_range_ipv6_with_limit(&params.start, &params.end, config.max_generated_cidrs) {
        Ok(result) => {
            info!(cidr_count = result.cidr_count, "IPv6 from-range successful");
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "IPv6 from-range failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/batch",
    request_body = BatchRequest,
    responses(
        (status = 200, description = "Batch CIDR processing results", body = BatchResult),
        (status = 400, description = "Invalid request (e.g., empty CIDR list)", body = ErrorResponse)
    ),
    tag = "netcidr"
))]
#[instrument(skip_all, fields(count = params.cidrs.len()))]
async fn batch_handler(
    Extension(config): Extension<Arc<ServerConfig>>,
    Json(params): Json<BatchRequest>,
) -> impl IntoResponse {
    info!("Processing batch CIDRs");
    match process_batch_with_limit(&params.cidrs, config.max_batch_size) {
        Ok(result) => {
            info!(count = result.count, "Batch processing successful");
            format_response(result, params.format, params.pretty, StatusCode::OK)
        }
        Err(e) => {
            warn!(error = %e, "Batch processing failed");
            json_response(
                ErrorResponse {
                    error: e.to_string(),
                },
                params.pretty,
                StatusCode::BAD_REQUEST,
            )
        }
    }
}

#[derive(Clone, Serialize)]
struct FeaturesResponse {
    ipam: bool,
    swagger: bool,
}

#[derive(Serialize)]
struct MeResponse {
    /// Verified email of the signed-in principal (may be null for bearer tokens).
    email: Option<String>,
    /// Whether the email passes the configured allowlist.
    is_allowlisted: bool,
    /// Whether the email matches the admin allowlist.
    is_admin: bool,
    /// First configured admin email — surfaced so unallowlisted users have
    /// someone to contact for access. Null when no admins are configured.
    admin_contact: Option<String>,
}

#[derive(Serialize)]
struct AllowlistResponse {
    /// Email addresses authorized to call /ipam/*.
    emails: Vec<String>,
    /// Email addresses with administrative access.
    admins: Vec<String>,
    /// How the allowlist is managed. Currently always "env" — sourced from
    /// the NETCIDR_OIDC_ALLOWED_EMAILS environment variable / config file.
    /// To add or remove an email, edit `samconfig.toml.tpl` (or the deploy
    /// equivalent) and redeploy.
    management: &'static str,
}

async fn me_handler(
    Extension(auth_config): Extension<crate::auth::AuthConfig>,
    request: axum::extract::Request,
) -> Response {
    let principal = match auth_config.authenticate(request.headers()).await {
        Some(p) => p,
        None => {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    };
    let email = principal.email.clone();
    let is_allowlisted = auth_config.email_is_allowed(email.as_deref());
    let is_admin = auth_config.is_admin(email.as_deref());
    let admin_contact = auth_config.admin_emails().first().cloned();
    Json(MeResponse {
        email,
        is_allowlisted,
        is_admin,
        admin_contact,
    })
    .into_response()
}

async fn allowlist_handler(
    Extension(auth_config): Extension<crate::auth::AuthConfig>,
    request: axum::extract::Request,
) -> Response {
    let principal = match auth_config.authenticate(request.headers()).await {
        Some(p) => p,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };
    if !auth_config.is_admin(principal.email.as_deref()) {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }
    Json(AllowlistResponse {
        emails: auth_config.allowed_emails().to_vec(),
        admins: auth_config.admin_emails().to_vec(),
        management: "env",
    })
    .into_response()
}

#[cfg(feature = "dashboard")]
async fn dashboard() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html")],
        include_str!("../dashboard/dist/index.html"),
    )
}
