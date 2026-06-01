//! A fast IPv4 and IPv6 subnet calculator.
//!
//! Provides CLI, TUI, and HTTP API interfaces for subnet calculations,
//! including prefix lookups, subnet splitting, address containment checks,
//! range-to-CIDR conversion, route summarization, and IPAM.

// Core calculation modules
pub mod batch;
pub mod contains;
pub mod from_range;
pub mod ipv4;
pub mod ipv6;
pub mod subnet_generator;
pub mod summarize;

// I/O and interface modules
pub mod api;
pub mod audit_context;
pub mod auth;
pub mod authorization;
pub mod cli;
pub mod ipam_api;
pub mod me_api;
pub mod output;
pub mod pat;
pub mod pat_lifecycle;
pub mod tenant;

// IPAM persistence layer
pub mod ipam;

// DNS management layer
pub mod dns;

// Infrastructure
pub mod config;
pub mod daemon;
pub mod error;
pub mod error_presenter;
pub mod logging;
pub mod validation;

#[cfg(feature = "otel")]
pub mod telemetry;

#[cfg(feature = "tui")]
pub mod tui;

#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mcp")]
pub mod mcp_client;

#[cfg(feature = "lambda")]
pub mod s3_sync;

// Public API re-exports
pub use batch::{BatchResult, process_batch, process_batch_with_limit};
pub use contains::ContainsResult;
pub use from_range::{Ipv4FromRangeResult, Ipv6FromRangeResult};
pub use ipv4::Ipv4Subnet;
pub use ipv6::Ipv6Subnet;
pub use logging::{LogConfig, init_logging};
pub use output::{OutputFormat, OutputWriter};
pub use summarize::{Ipv4SummaryResult, Ipv6SummaryResult};
