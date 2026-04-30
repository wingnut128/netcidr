//! Per-request audit context, threaded via tokio task-locals.
//!
//! HTTP middleware constructs an [`AuditContext`] from the authenticated
//! principal, the connection's source IP, and a freshly-generated request
//! ID, then runs the rest of the request inside [`scope`]. Anywhere
//! downstream — including [`crate::ipam::operations`] — can call
//! [`current`] to read it without changing call signatures.
//!
//! CLI invocations leave the task-local unset; [`current`] returns a
//! default [`AuditContext`] with all fields `None`.

use std::future::Future;

use tokio::task_local;

#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub caller_sub: Option<String>,
    pub caller_email: Option<String>,
    pub source_ip: Option<String>,
    pub request_id: Option<String>,
}

task_local! {
    static CURRENT: AuditContext;
}

/// Read the current task's [`AuditContext`], or `Default::default()` when
/// running outside a [`scope`] (e.g., CLI invocations, unit tests).
pub fn current() -> AuditContext {
    CURRENT.try_with(|c| c.clone()).unwrap_or_default()
}

/// Run `future` with `ctx` installed as the current task-local
/// [`AuditContext`].
pub async fn scope<F: Future>(ctx: AuditContext, future: F) -> F::Output {
    CURRENT.scope(ctx, future).await
}
