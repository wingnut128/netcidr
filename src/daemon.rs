//! Process daemonization for background server operation.
//!
//! **Must be called before creating a tokio runtime.** Forking after the
//! runtime is alive corrupts the kqueue/epoll file descriptor, causing
//! `TcpListener::bind` to fail with EBADF (os error 9).

/// Fork the current process into the background, write a PID file, and
/// redirect output to a log file (or /dev/null).
pub fn daemonize_process(pid_file: &str, log_file: Option<&str>) -> crate::error::Result<()> {
    let mut daemon = daemonize_me::Daemon::new().pid_file(pid_file, Some(false));

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
