use std::path::Path;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer,
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

/// Guard returned by [`init_logging`]. Holds the non-blocking log writer guard
/// (flushes buffered log lines on drop) and, when built with `--features otel`
/// and OTLP export is configured, the OpenTelemetry provider guard (flushes and
/// shuts down the span pipeline on drop).
pub struct LogGuard {
    _worker: WorkerGuard,
    #[cfg(feature = "otel")]
    otel: Option<crate::telemetry::OtelGuard>,
}

impl LogGuard {
    /// Flush any buffered OpenTelemetry spans immediately. No-op without the
    /// `otel` feature or when export is not configured. Call before a graceful
    /// shutdown so in-flight spans are exported.
    pub fn flush(&self) {
        #[cfg(feature = "otel")]
        if let Some(g) = &self.otel {
            g.force_flush();
        }
    }
}

/// Initialize logging and return a guard that must be held for the lifetime of the program.
/// Dropping the guard will flush any remaining log entries (and shut down the
/// OpenTelemetry pipeline when the `otel` feature is active and configured).
pub fn init_logging(config: &LogConfig) -> LogGuard {
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

    // Single fmt layer (json or plain), type-erased via `.boxed()` so both
    // shapes share one registry type and the OTel layer can attach uniformly.
    let fmt_layer = if config.json_format {
        fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_span_events(FmtSpan::CLOSE)
            .boxed()
    } else {
        fmt::layer()
            .with_writer(non_blocking)
            .with_span_events(FmtSpan::CLOSE)
            .boxed()
    };

    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    #[cfg(feature = "otel")]
    {
        let (otel_layer, otel) = match crate::telemetry::otel_layer() {
            Some((layer, g)) => (Some(layer), Some(g)),
            None => (None, None),
        };
        registry.with(otel_layer).init();
        LogGuard {
            _worker: guard,
            otel,
        }
    }

    #[cfg(not(feature = "otel"))]
    {
        registry.init();
        LogGuard { _worker: guard }
    }
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
