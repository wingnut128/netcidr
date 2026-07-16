use thiserror::Error;

use crate::auth::Role;

#[derive(Error, Debug)]
pub enum NetcidrError {
    #[error("Invalid IPv4 address: {0}")]
    InvalidIpv4Address(String),

    #[error("Invalid IPv6 address: {0}")]
    InvalidIpv6Address(String),

    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    #[error("Invalid prefix length: {0} (must be 0-32 for IPv4, 0-128 for IPv6)")]
    InvalidPrefixLength(u8),

    #[error(
        "Cannot generate {requested} /{new_prefix} subnets from /{original_prefix} (only {available} available)"
    )]
    InsufficientSubnets {
        requested: u64,
        available: u64,
        new_prefix: u8,
        original_prefix: u8,
    },

    #[error(
        "New prefix length {new_prefix} must be greater than original prefix {original_prefix}"
    )]
    InvalidSubnetSplit { new_prefix: u8, original_prefix: u8 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "Generating {count} subnets exceeds the limit of {limit}. Use --count-only to see the count, or -n to generate a smaller number."
    )]
    SubnetLimitExceeded { count: String, limit: u64 },

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CSV serialization error: {0}")]
    Csv(String),

    #[error("YAML serialization error: {0}")]
    Yaml(String),

    #[error("No CIDRs provided for summarization")]
    EmptyCidrList,

    #[error("Invalid range: start {0} is greater than end {1}")]
    InvalidRange(String, String),

    #[error("Batch size {count} exceeds maximum of {limit}")]
    BatchSizeExceeded { count: usize, limit: usize },

    #[error("Generated CIDR count {count} exceeds maximum of {limit}")]
    FromRangeLimitExceeded { count: usize, limit: usize },

    #[error("Summarize input count {count} exceeds maximum of {limit}")]
    SummarizeInputLimitExceeded { count: usize, limit: usize },

    #[error("Input string exceeds maximum length of {limit} bytes")]
    InputTooLong { length: usize, limit: usize },

    #[error("Configuration parse error: {0}")]
    ConfigParse(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Allocation conflict: {candidate} overlaps with existing {existing}")]
    AllocationConflict { existing: String, candidate: String },

    #[error("CIDR block not found: {0}")]
    CidrBlockNotFound(String),

    #[error("Allocation not found: {0}")]
    AllocationNotFound(String),

    #[error("Hostname pointer not found: {0}")]
    HostnamePointerNotFound(String),

    #[error("Role assignment not found: {0}")]
    RoleAssignmentNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("cannot revoke the last remaining admin")]
    LastAdmin,

    #[error("cannot remove, disable, or demote the last active platform admin")]
    LastPlatformAdmin,

    #[error("CIDR block {0} has active allocations and cannot be deleted")]
    CidrBlockHasActiveAllocations(String),

    #[error("No free space in {cidr_block} for a /{prefix} allocation")]
    NoFreeSpace { cidr_block: String, prefix: u8 },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Personal access token not found: {0}")]
    PatNotFound(String),

    #[error(
        "PAT limit reached: {count} active tokens (max {limit}); revoke a token to create a new one"
    )]
    PatLimitExceeded { count: u32, limit: u32 },

    /// An idempotency key was reused with a different request body for
    /// the same operation scope. The key is bound to the *first* payload
    /// it saw; reusing it for a new payload is almost always a client
    /// bug. Maps to HTTP 409 via the error presenter.
    #[error("idempotency key reused with a different request body")]
    IdempotencyConflict { key: String, scope: String },

    /// A response from an upstream HTTP API (e.g. the MCP server's
    /// remote-API backend, or the `netcidr token` CLI talking to a
    /// remote `netcidr serve`). Carries the status code and a message
    /// the upstream chose to expose; both have already passed through
    /// that upstream's own error presenter.
    #[error("upstream error (HTTP {status}): {message}")]
    Upstream { status: u16, message: String },

    /// Caller is authenticated but lacks the role required by the
    /// requested endpoint. Maps to HTTP 403 via the error presenter
    /// with a fixed-safe `"Forbidden"` message; the `required` and
    /// `actual` values are *not* echoed to the client (they go to the
    /// server log at WARN level for the operator to correlate).
    #[error("Forbidden: required {required:?}, got {actual:?}")]
    Forbidden { required: Role, actual: Role },
}

pub type Result<T> = std::result::Result<T, NetcidrError>;
