use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "netcidr")]
#[command(version)]
#[command(about = "IP subnet calculator for IPv4 and IPv6", long_about = None)]
pub struct Cli {
    /// IP address(es) in CIDR notation (e.g., 192.168.1.0/24 or 2001:db8::/48)
    #[arg(value_name = "CIDR")]
    pub cidr: Vec<String>,

    /// Read CIDRs from standard input (one per line)
    #[arg(long)]
    pub stdin: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Output format (json, text, csv, or yaml)
    #[arg(short, long, default_value = "json", global = true)]
    pub format: OutputFormatArg,

    /// Output file path (prints to stdout if not specified)
    #[arg(short = 'o', long, global = true)]
    pub output: Option<String>,

    /// Launch interactive TUI mode
    #[cfg(feature = "tui")]
    #[arg(long)]
    pub tui: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate subnets from a CIDR block
    Split {
        /// Network in CIDR notation (or prefix notation for IPv6)
        cidr: String,

        /// New prefix length for fixed-size subnets (required unless --vlsm or --steps is used)
        #[arg(short = 'p', long, required_unless_present_any = ["vlsm", "steps"])]
        prefix: Option<u8>,

        /// Number of subnets to generate (mutually exclusive with --max)
        #[arg(short = 'n', long, conflicts_with = "max")]
        count: Option<u64>,

        /// Generate maximum number of subnets possible
        #[arg(short = 'm', long, conflicts_with = "count")]
        max: bool,

        /// Show only the number of available subnets (no generation)
        #[arg(long, conflicts_with_all = ["count", "max"])]
        count_only: bool,

        /// VLSM: comma-separated descending prefix lengths to carve greedily
        /// from the block, largest block first (e.g. --vlsm 26,28,28)
        #[arg(long, value_delimiter = ',', conflicts_with_all = ["prefix", "count", "max", "count_only", "steps"])]
        vlsm: Option<Vec<u8>>,

        /// Hierarchical: comma-separated strictly-increasing prefix lengths
        /// applied recursively to each level, producing a tree (e.g. --steps 22,24)
        #[arg(long, value_delimiter = ',', conflicts_with_all = ["prefix", "count", "max", "count_only", "vlsm"])]
        steps: Option<Vec<u8>>,
    },

    /// Check if an IP address is contained in a subnet
    Contains {
        /// Network in CIDR notation (e.g., 192.168.1.0/24)
        cidr: String,
        /// IP address to check (e.g., 192.168.1.100)
        address: String,
    },

    /// Convert an IP range (start–end) into minimal CIDR blocks
    FromRange {
        /// Start IP address (e.g., 192.168.1.10 or 2001:db8::1)
        start: String,
        /// End IP address (e.g., 192.168.1.20 or 2001:db8::ff)
        end: String,
    },

    /// Summarize/aggregate CIDRs into the minimal covering set
    Summarize {
        /// CIDR ranges to summarize
        #[arg(required = true, num_args = 1..)]
        cidrs: Vec<String>,
    },

    /// IP Address Management — track allocations, CIDR blocks, and free space
    Ipam {
        /// Path to SQLite database (overrides NETCIDR_DB env and config file)
        #[arg(long)]
        db: Option<String>,

        #[command(subcommand)]
        command: IpamCommands,
    },

    /// Start the MCP (Model Context Protocol) server
    #[cfg(feature = "mcp")]
    McpServe {
        /// Transport protocol (http or stdio)
        #[arg(long, default_value = "http")]
        transport: McpTransport,

        /// Address to bind to (HTTP transport only)
        #[arg(short, long, default_value = "127.0.0.1")]
        address: String,

        /// Port to listen on (HTTP transport only)
        #[arg(short, long, default_value = "3000")]
        port: u16,

        /// Run as a background daemon (HTTP transport only)
        #[arg(long)]
        daemonize: bool,

        /// PID file path (used with --daemonize)
        #[arg(long, default_value = "/tmp/netcidr-mcp.pid")]
        pid_file: String,

        /// Log file path (used with --daemonize, stderr otherwise)
        #[arg(long)]
        log_file: Option<String>,

        /// Path to IPAM SQLite database (enables IPAM tools via local store)
        #[arg(long, conflicts_with = "api_url")]
        ipam_db: Option<String>,

        /// URL of a running netcidr API server (enables IPAM tools via HTTP proxy)
        #[arg(long, conflicts_with = "ipam_db")]
        api_url: Option<String>,
    },

    /// Manage personal access tokens against a remote netcidr server
    Token {
        /// API base URL (overrides NETCIDR_API_URL)
        #[arg(long)]
        api_url: Option<String>,

        #[command(subcommand)]
        command: TokenCommands,
    },

    /// Generate shell completions for the given shell
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },

    /// Start the HTTP API server
    Serve {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1")]
        address: String,

        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Run as a background daemon
        #[arg(long)]
        daemonize: bool,

        /// PID file path (used with --daemonize)
        #[arg(long, default_value = "/tmp/netcidr-serve.pid")]
        pid_file: String,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Log to file instead of stdout
        #[arg(long)]
        log_file: Option<String>,

        /// Output logs in JSON format
        #[arg(long)]
        log_json: bool,

        /// Path to config file (TOML)
        #[arg(long)]
        config: Option<String>,

        /// Enable Swagger UI at /swagger-ui
        #[arg(long)]
        enable_swagger: bool,

        /// Maximum CIDRs in a batch request (overrides config file)
        #[arg(long)]
        max_batch_size: Option<usize>,

        /// Maximum CIDRs generated by from-range (overrides config file)
        #[arg(long)]
        max_range_cidrs: Option<usize>,

        /// Maximum input CIDRs for summarize (overrides config file)
        #[arg(long)]
        max_summarize_inputs: Option<usize>,

        /// Maximum request body size in bytes (overrides config file)
        #[arg(long)]
        max_body_size: Option<usize>,

        /// Rate limit: requests per second (overrides config file)
        #[arg(long)]
        rate_limit_per_second: Option<u64>,

        /// Rate limit: burst size (overrides config file)
        #[arg(long)]
        rate_limit_burst: Option<u32>,

        /// Request timeout in seconds (overrides config file)
        #[arg(long)]
        timeout: Option<u64>,

        /// Enable IPAM API routes at /ipam/
        #[arg(long)]
        ipam_enabled: bool,

        /// IPAM storage backend (default: sqlite)
        #[arg(long, default_value = "sqlite")]
        ipam_backend: Option<String>,

        /// IPAM database path (overrides NETCIDR_DB env and config file)
        #[arg(long)]
        ipam_db: Option<String>,

        /// IPAM PostgreSQL connection URL (overrides NETCIDR_IPAM_DB_URL env and config file)
        #[arg(long)]
        ipam_db_url: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IpamCommands {
    /// Manage CIDR blocks (top-level address spaces)
    CidrBlock {
        #[command(subcommand)]
        command: CidrBlockCommands,
    },

    /// Allocate a specific CIDR block within a CIDR block
    Allocate {
        /// CIDR block ID
        cidr_block_id: String,
        /// CIDR to allocate (e.g., 10.0.1.0/24 or 2001:db8:1::/48)
        cidr: String,
        /// Allocation name
        #[arg(long)]
        name: Option<String>,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Resource ID (e.g., vpc-12345)
        #[arg(long)]
        resource_id: Option<String>,
        /// Resource type (e.g., vpc, subnet)
        #[arg(long)]
        resource_type: Option<String>,
        /// Environment (e.g., production, staging)
        #[arg(long)]
        environment: Option<String>,
        /// Owner
        #[arg(long)]
        owner: Option<String>,
        /// Initial status
        #[arg(long)]
        status: Option<String>,
        /// Parent allocation ID for sub-allocations
        #[arg(long)]
        parent_id: Option<String>,
        /// TTL in seconds (reservation expires after this duration)
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Auto-allocate the next available block(s) of a given prefix length
    AutoAllocate {
        /// CIDR block ID
        cidr_block_id: String,
        /// Desired prefix length (e.g., 24 for /24)
        #[arg(short = 'p', long)]
        prefix: u8,
        /// Number of blocks to allocate
        #[arg(short = 'n', long, default_value = "1")]
        count: u32,
        /// Allocation name
        #[arg(long)]
        name: Option<String>,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Resource ID
        #[arg(long)]
        resource_id: Option<String>,
        /// Resource type
        #[arg(long)]
        resource_type: Option<String>,
        /// Environment
        #[arg(long)]
        environment: Option<String>,
        /// Owner
        #[arg(long)]
        owner: Option<String>,
        /// Initial status
        #[arg(long)]
        status: Option<String>,
        /// Parent allocation ID
        #[arg(long)]
        parent_id: Option<String>,
        /// TTL in seconds (reservation expires after this duration)
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Manage allocations (get, list, update)
    Allocation {
        #[command(subcommand)]
        command: AllocationCommands,
    },

    /// Release an allocation (mark as released)
    Release {
        /// Allocation ID to release
        id: String,
    },

    /// Show utilization report for a CIDR block
    Utilization {
        /// CIDR block ID
        cidr_block_id: String,
    },

    /// List free blocks in a CIDR block
    FreeBlocks {
        /// CIDR block ID
        cidr_block_id: String,
        /// Filter by target prefix length
        #[arg(short = 'p', long)]
        prefix: Option<u8>,
    },

    /// Find allocations containing an IP address
    FindIp {
        /// IP address to look up
        address: String,
    },

    /// Find allocations by resource ID
    FindResource {
        /// Resource ID to search for
        resource_id: String,
    },

    /// Query the audit log
    Audit {
        /// Filter by entity type (cidr_block, allocation)
        #[arg(long)]
        entity_type: Option<String>,
        /// Filter by entity ID
        #[arg(long)]
        entity_id: Option<String>,
        /// Filter by action
        #[arg(long)]
        action: Option<String>,
        /// Maximum entries to return
        #[arg(long, default_value = "50")]
        limit: u32,
    },

    /// Manage tags on allocations
    Tags {
        #[command(subcommand)]
        command: TagCommands,
    },

    /// Manage hostname pointers (IP↔hostname mappings with change history)
    Hostname {
        #[command(subcommand)]
        command: HostnameCommands,
    },

    /// Export all IPAM data to JSON
    Dump {
        /// Tenant ID to export (default: "local" for CLI; set to your email for API-written data)
        #[arg(long, default_value = "local")]
        tenant: String,
    },

    /// Import IPAM data from JSON (stdin or file)
    Load {
        /// Path to JSON file (reads from stdin if omitted)
        file: Option<String>,
        /// Tenant ID to import data under (default: "local")
        #[arg(long, default_value = "local")]
        tenant: String,
    },
}

#[derive(Subcommand)]
pub enum HostnameCommands {
    /// Set (create or update) a hostname pointer for an IP
    Set {
        /// IP address (IPv4 or IPv6)
        ip: String,
        /// Fully-qualified hostname (e.g., web-01.example.com)
        hostname: String,
        /// Optional allocation ID to associate with this pointer
        #[arg(long)]
        allocation_id: Option<String>,
        /// Optional free-form notes
        #[arg(long)]
        notes: Option<String>,
    },
    /// Show the current hostnames recorded for an IP
    Get {
        /// IP address
        ip: String,
    },
    /// List hostname pointers, optionally filtered
    List {
        /// Filter by IP address
        #[arg(long)]
        ip: Option<String>,
        /// Filter by hostname
        #[arg(long)]
        hostname: Option<String>,
        /// Filter by allocation ID
        #[arg(long)]
        allocation_id: Option<String>,
    },
    /// Show the append-only change history for an IP or hostname
    History {
        /// An IP address or a hostname; auto-detected
        target: String,
    },
    /// Delete a hostname pointer (the deletion is preserved in history)
    Delete {
        /// IP address
        ip: String,
        /// Hostname
        hostname: String,
    },
}

#[derive(Subcommand)]
pub enum CidrBlockCommands {
    /// Create a new CIDR block
    Create {
        /// CIDR notation (e.g., 10.0.0.0/8 or 2001:db8::/32)
        cidr: String,
        /// CIDR block name
        #[arg(long)]
        name: Option<String>,
        /// Description
        #[arg(long)]
        description: Option<String>,
    },
    /// List all CIDR blocks
    List,
    /// Get details of a CIDR block
    Get {
        /// CIDR block ID
        id: String,
    },
    /// Delete a CIDR block (must have no active allocations)
    Delete {
        /// CIDR block ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum AllocationCommands {
    /// Get details of an allocation
    Get {
        /// Allocation ID
        id: String,
    },
    /// List allocations with optional filters
    List {
        /// Filter by CIDR block ID
        #[arg(long)]
        cidr_block_id: Option<String>,
        /// Filter by status (active, reserved, released)
        #[arg(long)]
        status: Option<String>,
        /// Filter by resource ID
        #[arg(long)]
        resource_id: Option<String>,
        /// Filter by resource type
        #[arg(long)]
        resource_type: Option<String>,
        /// Filter by environment
        #[arg(long)]
        environment: Option<String>,
        /// Filter by owner
        #[arg(long)]
        owner: Option<String>,
    },
    /// Update an allocation's metadata
    Update {
        /// Allocation ID
        id: String,
        /// New name
        #[arg(long)]
        name: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
        /// New resource ID
        #[arg(long)]
        resource_id: Option<String>,
        /// New resource type
        #[arg(long)]
        resource_type: Option<String>,
        /// New environment
        #[arg(long)]
        environment: Option<String>,
        /// New owner
        #[arg(long)]
        owner: Option<String>,
        /// New status
        #[arg(long)]
        status: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TagCommands {
    /// Get tags for an allocation
    Get {
        /// Allocation ID
        allocation_id: String,
    },
    /// Set tags on an allocation (replaces existing tags)
    Set {
        /// Allocation ID
        allocation_id: String,
        /// Tags in key=value format
        #[arg(required = true, num_args = 1..)]
        tags: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum TokenCommands {
    /// List your personal access tokens
    List,
    /// Create a new personal access token (plaintext is shown ONCE)
    Create {
        /// Display name (1-64 chars, no control chars)
        #[arg(long)]
        name: String,
        /// Lifetime as `<N><unit>`: d=days, w=weeks, y=years.
        /// Examples: 1d, 30d, 12w, 1y. Max 1y, default 90d.
        #[arg(long)]
        expires_in: Option<String>,
        /// Role to grant. Defaults to the minting user's resolved role.
        /// A PAT can narrow the user's privileges but never widen them —
        /// e.g. an admin user can mint a `reader` PAT for a CI script, but
        /// an `allocator` user requesting `--role admin` will be clamped
        /// to `allocator` at mint time.
        #[arg(long)]
        role: Option<crate::auth::Role>,
    },
    /// Revoke a personal access token by id
    Revoke {
        /// Token id (returned by `token list`)
        id: String,
    },
}

#[derive(Clone, Copy, ValueEnum, Default)]
pub enum OutputFormatArg {
    #[default]
    Json,
    Text,
    Csv,
    Yaml,
}

#[cfg(feature = "mcp")]
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum McpTransport {
    /// Streamable HTTP server (default)
    #[default]
    Http,
    /// Legacy stdio transport
    Stdio,
}

impl From<OutputFormatArg> for crate::output::OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Json => crate::output::OutputFormat::Json,
            OutputFormatArg::Text => crate::output::OutputFormat::Text,
            OutputFormatArg::Csv => crate::output::OutputFormat::Csv,
            OutputFormatArg::Yaml => crate::output::OutputFormat::Yaml,
        }
    }
}
