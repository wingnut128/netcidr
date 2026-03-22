use std::path::Path;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: Level,
    pub file_path: Option<String>,
    pub json_format: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            file_path: None,
            json_format: false,
        }
    }
}

impl LogConfig {
    pub fn new(level: Level) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    pub fn with_file(mut self, path: String) -> Self {
        self.file_path = Some(path);
        self
    }

    pub fn with_json(mut self, json: bool) -> Self {
        self.json_format = json;
        self
    }
}

/// Initialize logging and return a guard that must be held for the lifetime of the program.
/// Dropping the guard will flush any remaining log entries.
pub fn init_logging(config: &LogConfig) -> WorkerGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.level.to_string()));

    let (non_blocking, guard) = match &config.file_path {
        Some(path) => {
            let path = Path::new(path);
            let parent = path.parent().unwrap_or(Path::new("."));
            let filename = path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("netcidr.log");

            let file_appender = tracing_appender::rolling::never(parent, filename);
            tracing_appender::non_blocking(file_appender)
        }
        None => tracing_appender::non_blocking(std::io::stdout()),
    };

    if config.json_format {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .json()
                    .with_writer(non_blocking)
                    .with_span_events(FmtSpan::CLOSE),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_writer(non_blocking)
                    .with_span_events(FmtSpan::CLOSE),
            )
            .init();
    }

    guard
}

pub fn parse_log_level(s: &str) -> Result<Level, String> {
    match s.to_lowercase().as_str() {
        "trace" => Ok(Level::TRACE),
        "debug" => Ok(Level::DEBUG),
        "info" => Ok(Level::INFO),
        "warn" | "warning" => Ok(Level::WARN),
        "error" => Ok(Level::ERROR),
        _ => Err(format!(
            "Invalid log level '{}'. Valid levels: trace, debug, info, warn, error",
            s
        )),
    }
}
