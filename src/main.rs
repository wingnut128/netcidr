use clap::{CommandFactory, Parser};
use netcidr::api::{RouterConfig, create_router};
use netcidr::batch::process_batch;
use netcidr::cli::{Cli, Commands};
use netcidr::config::{CliOverrides, ServerConfig};
use netcidr::contains::{check_ipv4_contains, check_ipv6_contains};
use netcidr::from_range::{from_range_ipv4, from_range_ipv6};
use netcidr::ipv4::Ipv4Subnet;
use netcidr::ipv6::Ipv6Subnet;
use netcidr::logging::{LogConfig, init_logging, parse_log_level};
use netcidr::output::{CsvOutput, OutputFormat, OutputWriter, TextOutput};
use netcidr::subnet_generator::{
    count_subnets, generate_ipv4_subnets, generate_ipv6_subnets, hierarchical_split_ipv4,
    hierarchical_split_ipv6, vlsm_split_ipv4, vlsm_split_ipv6,
};
use netcidr::summarize::{summarize_ipv4, summarize_ipv6};
use serde::Serialize;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use tracing::{info, warn};

mod ipam_cli;
mod login_cli;
mod token_cli;

/// Print to stdout, handling broken pipe errors gracefully.
/// When output is piped to commands like `head`, the pipe may close early.
fn print_stdout(s: &str) {
    if let Err(e) = writeln!(io::stdout(), "{}", s) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("Error writing to stdout: {}", e);
        std::process::exit(1);
    }
}

/// Handle a Result from a calculation: write output on success, print error and exit on failure.
fn handle_result<T: Serialize + TextOutput + CsvOutput>(
    writer: &OutputWriter,
    result: netcidr::error::Result<T>,
    output_file: &Option<String>,
) {
    match result {
        Ok(val) => {
            let output = writer.write(&val).expect("Failed to write output");
            if output_file.is_none() {
                print_stdout(&output);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("Shutdown signal received, starting graceful shutdown");
}

fn main() {
    let cli = Cli::parse();

    // Launch TUI mode if requested
    #[cfg(feature = "tui")]
    if cli.tui {
        if let Err(e) = netcidr::tui::run_tui() {
            eprintln!("TUI Error: {}", e);
        }
        return;
    }

    // Daemonize BEFORE creating the tokio runtime so the fork doesn't
    // corrupt kqueue/epoll file descriptors used by the async I/O reactor.
    #[cfg(feature = "mcp")]
    if let Some(Commands::McpServe {
        daemonize: true,
        ref pid_file,
        ref log_file,
        ref transport,
        ref address,
        allow_public_bind,
        ..
    }) = cli.command
    {
        if *transport == netcidr::cli::McpTransport::Stdio {
            eprintln!("Error: --daemonize is only supported with HTTP transport");
            std::process::exit(1);
        }
        // Fail closed before forking so the operator sees the error on the
        // controlling terminal rather than a daemon that silently exits.
        if let Err(e) = netcidr::mcp::check_http_bind_allowed(address, allow_public_bind) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        if let Err(e) = netcidr::mcp::daemonize_process(pid_file, log_file.as_deref()) {
            eprintln!("Failed to daemonize: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(Commands::Serve {
        daemonize: true,
        ref pid_file,
        ref log_file,
        ..
    }) = cli.command
        && let Err(e) = netcidr::daemon::daemonize_process(pid_file, log_file.as_deref())
    {
        eprintln!("Failed to daemonize: {}", e);
        std::process::exit(1);
    }

    // Build the tokio runtime after any fork so file descriptors are valid.
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    runtime.block_on(async_main(cli));
}

async fn async_main(cli: Cli) {
    let format: OutputFormat = cli.format.into();
    let writer = OutputWriter::new(format, cli.output.clone());

    // Collect CIDRs from positional args and/or stdin
    let mut cidrs = cli.cidr;
    if cli.stdin {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let line = line.expect("Failed to read stdin");
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            cidrs.push(trimmed.to_string());
        }
    }

    // Handle direct CIDR input (auto-detect)
    if !cidrs.is_empty() {
        if cidrs.len() == 1 {
            // Single CIDR — preserve flat output for backward compatibility
            let cidr = &cidrs[0];
            if cidr.contains(':') {
                handle_result(&writer, Ipv6Subnet::from_cidr(cidr), &cli.output);
            } else {
                handle_result(&writer, Ipv4Subnet::from_cidr(cidr), &cli.output);
            }
        } else {
            // Multiple CIDRs — batch mode
            handle_result(&writer, process_batch(&cidrs), &cli.output);
        }
        return;
    }

    // Handle subcommands
    match cli.command {
        Some(Commands::Split {
            cidr,
            prefix,
            count,
            max,
            count_only,
            vlsm,
            steps,
        }) => {
            // VLSM mode: carve a variable-length allocation from the block.
            if let Some(prefixes) = vlsm {
                if cidr.contains(':') {
                    handle_result(&writer, vlsm_split_ipv6(&cidr, &prefixes), &cli.output);
                } else {
                    handle_result(&writer, vlsm_split_ipv4(&cidr, &prefixes), &cli.output);
                }
                return;
            }

            // Hierarchical mode: recursively split into a tree.
            if let Some(step_list) = steps {
                if cidr.contains(':') {
                    handle_result(
                        &writer,
                        hierarchical_split_ipv6(&cidr, &step_list),
                        &cli.output,
                    );
                } else {
                    handle_result(
                        &writer,
                        hierarchical_split_ipv4(&cidr, &step_list),
                        &cli.output,
                    );
                }
                return;
            }

            // Fixed-size mode. clap guarantees --prefix is present here
            // (required_unless_present_any = ["vlsm", "steps"]).
            let prefix = prefix.expect("clap enforces --prefix unless --vlsm/--steps is given");

            if count_only {
                handle_result(&writer, count_subnets(&cidr, prefix), &cli.output);
                return;
            }

            // Determine the actual count to use
            let actual_count = if max {
                None // Signal to generate maximum
            } else {
                match count {
                    Some(c) => Some(c),
                    None => {
                        eprintln!("Error: Either --count or --max must be specified");
                        std::process::exit(1);
                    }
                }
            };

            if cidr.contains(':') {
                handle_result(
                    &writer,
                    generate_ipv6_subnets(&cidr, prefix, actual_count),
                    &cli.output,
                );
            } else {
                handle_result(
                    &writer,
                    generate_ipv4_subnets(&cidr, prefix, actual_count),
                    &cli.output,
                );
            }
        }
        Some(Commands::Contains { cidr, address }) => {
            let result = if cidr.contains(':') {
                check_ipv6_contains(&cidr, &address)
            } else {
                check_ipv4_contains(&cidr, &address)
            };
            handle_result(&writer, result, &cli.output);
        }
        Some(Commands::FromRange { start, end }) => {
            if start.contains(':') {
                handle_result(&writer, from_range_ipv6(&start, &end), &cli.output);
            } else {
                handle_result(&writer, from_range_ipv4(&start, &end), &cli.output);
            }
        }
        Some(Commands::Summarize { cidrs }) => {
            if cidrs.iter().any(|c| c.contains(':')) {
                handle_result(&writer, summarize_ipv6(&cidrs), &cli.output);
            } else {
                handle_result(&writer, summarize_ipv4(&cidrs), &cli.output);
            }
        }
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "netcidr", &mut io::stdout());
        }
        Some(Commands::Ipam { db, command }) => {
            if let Err(e) =
                ipam_cli::handle_ipam_command(&writer, &cli.output, db.as_deref(), command).await
            {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Admin { db, command }) => {
            if let Err(e) =
                ipam_cli::handle_admin_command(&writer, &cli.output, db.as_deref(), command).await
            {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Token { api_url, command }) => {
            if let Err(e) =
                token_cli::handle_token_command(&writer, &cli.output, api_url.as_deref(), command)
                    .await
            {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        #[cfg(feature = "mcp")]
        Some(Commands::McpServe {
            transport,
            address,
            port,
            allow_public_bind,
            daemonize: _,
            pid_file,
            log_file,
            ipam_db,
            api_url,
            api_token,
        }) => {
            // Precedence: --api-token, then NETCIDR_API_TOKEN, then a
            // cached `netcidr login` for this server. clap's `env` feature
            // is not enabled, so the env fallback is resolved here.
            //
            // Unlike `netcidr token`, a missing credential is not fatal:
            // a remote server may have auth disabled entirely. A resolver
            // error therefore degrades to "no token" rather than aborting.
            let api_token = match api_token
                .or_else(|| std::env::var("NETCIDR_API_TOKEN").ok())
                .filter(|t| !t.trim().is_empty())
            {
                Some(token) => Some(token),
                None => match api_url.as_deref() {
                    Some(url) => match netcidr::credentials::normalize_api_url(url) {
                        Ok(normalized) => {
                            match netcidr::credentials::resolve_credential(&normalized, None).await
                            {
                                Ok(token) => Some(token),
                                // No account cached for this server — a
                                // legitimate, silent state (never logged
                                // in, or the server has auth disabled).
                                Err(netcidr::error::NetcidrError::NotAuthenticated(_)) => None,
                                // Every other error (corrupt credentials
                                // file, unreachable /features, a dead
                                // refresh token) is a real problem the
                                // user should know about, even though we
                                // still proceed unauthenticated.
                                Err(e) => {
                                    eprintln!("warning: ignoring cached credential: {e}");
                                    None
                                }
                            }
                        }
                        Err(_) => None,
                    },
                    None => None,
                },
            };
            let mcp_config = netcidr::mcp::McpServerConfig {
                transport,
                address: &address,
                port,
                allow_public_bind,
                // Daemonization already happened in main() before the tokio
                // runtime was created, so we never daemonize inside the async
                // context where it would corrupt the I/O reactor.
                daemonize: false,
                pid_file: &pid_file,
                log_file: log_file.as_deref(),
                ipam_db: ipam_db.as_deref(),
                api_url: api_url.as_deref(),
                api_token: api_token.as_deref(),
            };
            if let Err(e) = netcidr::mcp::run_mcp_server(mcp_config).await {
                eprintln!("MCP server error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Serve {
            address,
            port,
            daemonize: _,
            pid_file: _,
            log_level,
            log_file,
            log_json,
            config,
            enable_swagger,
            max_batch_size,
            max_range_cidrs,
            max_summarize_inputs,
            max_body_size,
            rate_limit_per_second,
            rate_limit_burst,
            timeout,
            ipam_enabled,
            ipam_backend,
            ipam_db,
            ipam_db_url,
        }) => {
            // Parse and validate log level
            let level = match parse_log_level(&log_level) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            // Initialize logging
            let log_config = LogConfig::new(level).with_json(log_json);
            let log_config = match log_file {
                Some(path) => log_config.with_file(path),
                None => log_config,
            };

            // Keep the guard alive for the lifetime of the program
            let _guard = init_logging(&log_config);

            // Load server config
            let mut server_config = if let Some(ref path) = config {
                match ServerConfig::load(path) {
                    Ok(c) => {
                        info!("Loaded config from {}", path);
                        c
                    }
                    Err(e) => {
                        eprintln!("Error loading config: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                ServerConfig::default()
            };

            // Apply CLI overrides
            server_config.merge_cli_overrides(&CliOverrides {
                enable_swagger,
                max_batch_size,
                max_range_cidrs,
                max_summarize_inputs,
                max_body_size,
                rate_limit_per_second,
                rate_limit_burst,
                timeout,
                ipam_enabled,
                ipam_backend,
                ipam_db,
                ipam_db_url,
            });

            if let Err(e) = server_config.validate_deployment(&address) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }

            // Bind-address warning
            if address != "127.0.0.1" && address != "::1" {
                warn!(
                    "Binding to non-loopback address '{}'. Use 127.0.0.1 for local-only access.",
                    address
                );
            }

            let addr: SocketAddr = format!("{}:{}", address, port)
                .parse()
                .expect("Invalid address");

            info!("Starting netcidr API server on http://{}", addr);
            info!("Log level: {}", log_level);

            // Print to stdout as well for visibility
            println!("Starting netcidr API server on http://{}", addr);
            println!("Endpoints:");
            println!("  GET /health              - Health check");
            println!("  GET /version             - Version information");
            println!("  GET /v4?cidr=<cidr>      - Calculate IPv4 subnet");
            println!("  GET /v6?cidr=<cidr>      - Calculate IPv6 subnet");
            println!("  GET /v4/split?cidr=<cidr>&prefix=<n>&count=<n> - Split IPv4 cidr_block");
            println!("  GET /v6/split?cidr=<cidr>&prefix=<n>&count=<n> - Split IPv6 cidr_block");
            println!("  GET /v4/contains?cidr=<cidr>&address=<ip>     - Check IPv4 containment");
            println!("  GET /v6/contains?cidr=<cidr>&address=<ip>     - Check IPv6 containment");
            println!("  GET /v4/summarize?cidrs=<cidr,cidr,...>       - Summarize IPv4 CIDRs");
            println!("  GET /v6/summarize?cidrs=<cidr,cidr,...>       - Summarize IPv6 CIDRs");
            println!("  GET /v4/from-range?start=<ip>&end=<ip>       - IPv4 range to CIDRs");
            println!("  GET /v6/from-range?start=<ip>&end=<ip>       - IPv6 range to CIDRs");
            println!("  POST /batch                                  - Batch CIDR processing");
            if server_config.enable_swagger {
                #[cfg(feature = "swagger")]
                {
                    println!("  GET /swagger-ui          - Interactive API documentation");
                    println!("  GET /api-docs/openapi.json - OpenAPI specification");
                }
            }

            // Initialize IPAM if enabled
            let ipam_ops = if server_config.ipam_enabled {
                use netcidr::ipam;
                let mut ipam_config = ipam::config::IpamConfig::default();
                if let Ok(backend) = server_config.ipam_backend.parse::<ipam::config::Backend>() {
                    ipam_config.backend = backend;
                }
                let store = ipam::create_store(
                    &ipam_config,
                    server_config.ipam_db.as_deref(),
                    server_config.ipam_db_url.as_deref(),
                )
                .await
                .expect("Failed to initialize IPAM store");

                // Bootstrap the users directory from the env lists — a
                // one-shot seed (marker-guarded); the DB is the source of
                // truth thereafter. Shared with the Lambda binary.
                netcidr::ipam::bootstrap::seed_users(&store, &server_config).await;

                info!("IPAM enabled, backend: {}", server_config.ipam_backend);
                println!("IPAM endpoints enabled at /ipam/");
                #[cfg(feature = "dashboard")]
                println!("IPAM dashboard at /dashboard");
                Some(std::sync::Arc::new(ipam::operations::IpamOps::new(store)))
            } else {
                None
            };

            // PAT pepper bootstrap. We require NETCIDR_PAT_PEPPER whenever
            // OIDC auth is active (the only mode that mints PATs); refuse
            // to start otherwise so a misconfiguration can't silently
            // disable PAT verification. Bearer-only and unauthenticated
            // modes don't need a pepper.
            let pat_pepper = if matches!(server_config.auth_mode, netcidr::config::AuthMode::Oidc) {
                match netcidr::pat::PatPepper::from_env() {
                    Ok(p) => Some(std::sync::Arc::new(p)),
                    Err(e) => {
                        eprintln!(
                            "Error: NETCIDR_PAT_PEPPER must be set when auth_mode='oidc': {}",
                            e
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                None
            };

            let router_config = RouterConfig {
                server: server_config,
                ipam_ops,
                pat_pepper,
            };
            let router = create_router(router_config);

            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();

            // Flush any buffered OpenTelemetry spans before exit (no-op without
            // the `otel` feature or when OTLP export is not configured). The
            // guard's Drop also shuts the pipeline down.
            _guard.flush();

            info!("Server shut down gracefully");
        }
        None => {
            // Show help when no arguments are provided
            Cli::command().print_help().expect("Failed to print help");
            println!(); // Add a newline for better formatting
            std::process::exit(0);
        }
    }
}
