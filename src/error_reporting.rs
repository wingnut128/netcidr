//! Opt-in Sentry error and panic reporting (Cargo feature `sentry`).
//!
//! ## Activation
//!
//! Reporting is active **only** when both are true:
//! 1. the binary was built with `--features sentry`, and
//! 2. `SENTRY_DSN` is set (non-empty) at runtime.
//!
//! With either missing, the SDK is never initialized and no layer is attached
//! — a true no-op, mirroring the `otel` feature.
//!
//! ## Scope: errors and panics only
//!
//! `tracing` events at `ERROR` become Sentry events and panics are captured by
//! the SDK's panic hook. Spans are **not** sent — traces already go to the
//! OTLP backend via the `otel` feature — and lower-level events are not kept
//! as breadcrumbs, so routine log fields never leave the process.
//!
//! ## Initialization order
//!
//! [`init`] must run on the main thread **before** the tokio runtime is built
//! (worker threads inherit the main hub's client) and **after** any
//! daemonize fork (the transport thread does not survive a fork).
//!
//! ## PII
//!
//! `send_default_pii` stays off, no request data is attached, and every event
//! passes through [`scrub_event`], which drops user/request data and removes
//! any field whose key is flagged by [`crate::pii::is_pii_key`] — the same
//! rule the OTLP exporter enforces. Message *text* is not rewritten, so
//! `error!` call sites must keep credentials and emails out of the message.
//!
//! ## Configuration
//!
//! - `SENTRY_DSN`         — project DSN (required to enable).
//! - `SENTRY_ENVIRONMENT` — environment tag (SDK default: `production`).
//! - `SENTRY_RELEASE`     — overrides the default `netcidr@<crate version>`.

use std::borrow::Cow;
use std::time::Duration;

use sentry::ClientInitGuard;
use sentry::integrations::tracing::{EventFilter, SentryLayer};
use sentry::protocol::{Context, Event};
use tracing::{Level, Subscriber};
use tracing_subscriber::registry::LookupSpan;

/// Env var that gates activation. Set it to enable reporting.
const ENABLE_ENV: &str = "SENTRY_DSN";

/// True when `SENTRY_DSN` is set to a non-empty value.
pub fn is_configured() -> bool {
    std::env::var(ENABLE_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Initialize the Sentry client, or return `None` when unconfigured.
///
/// The returned guard must be held for the lifetime of the program; dropping
/// it flushes pending events. See the module docs for ordering constraints.
pub fn init() -> Option<ClientInitGuard> {
    if !is_configured() {
        return None;
    }

    // The DSN and environment are read from SENTRY_DSN / SENTRY_ENVIRONMENT
    // by `apply_defaults`; an invalid DSN leaves the client disabled.
    let release = std::env::var("SENTRY_RELEASE")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(Cow::Owned)
        .unwrap_or(Cow::Borrowed(concat!(
            "netcidr@",
            env!("CARGO_PKG_VERSION")
        )));

    let guard = sentry::init(sentry::ClientOptions {
        release: Some(release),
        send_default_pii: false,
        attach_stacktrace: true,
        before_send: Some(std::sync::Arc::new(|event| Some(scrub_event(event)))),
        ..Default::default()
    });

    guard.is_enabled().then_some(guard)
}

/// `tracing` layer that forwards `ERROR` events to Sentry, or `None` when the
/// client is not active. Call after [`init`].
pub fn layer<S>() -> Option<SentryLayer<S>>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let active = sentry::Hub::current()
        .client()
        .is_some_and(|c| c.is_enabled());
    if !active {
        return None;
    }

    Some(
        sentry::integrations::tracing::layer()
            .event_filter(|md| {
                if *md.level() == Level::ERROR {
                    EventFilter::Event
                } else {
                    EventFilter::Ignore
                }
            })
            .span_filter(|_| false),
    )
}

/// Block until queued events are sent or `timeout` elapses. Used by the
/// Lambda binary, whose execution environment can freeze between invocations.
/// Returns immediately when the client is inactive.
pub fn flush(timeout: Duration) {
    if let Some(client) = sentry::Hub::current().client() {
        client.flush(Some(timeout));
    }
}

/// Strip user/request data and any PII-keyed field from an outgoing event.
pub fn scrub_event(mut event: Event<'static>) -> Event<'static> {
    event.user = None;
    event.request = None;
    event.extra.retain(|k, _| !crate::pii::is_pii_key(k));
    event.tags.retain(|k, _| !crate::pii::is_pii_key(k));
    for ctx in event.contexts.values_mut() {
        if let Context::Other(map) = ctx {
            map.retain(|k, _| !crate::pii::is_pii_key(k));
        }
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry::protocol::{Request, User, Value};
    use std::collections::BTreeMap;

    #[test]
    fn scrub_drops_user_and_request() {
        let event = Event {
            user: Some(User {
                email: Some("a@example.com".into()),
                ..Default::default()
            }),
            request: Some(Request::default()),
            ..Default::default()
        };
        let scrubbed = scrub_event(event);
        assert!(scrubbed.user.is_none());
        assert!(scrubbed.request.is_none());
    }

    #[test]
    fn scrub_removes_pii_keys_everywhere() {
        let mut fields = BTreeMap::new();
        fields.insert("owner_email".to_string(), Value::from("a@example.com"));
        fields.insert("pat_secret".to_string(), Value::from("s3cr3t"));
        fields.insert("cidr".to_string(), Value::from("10.0.0.0/8"));

        let mut event = Event::default();
        event
            .contexts
            .insert("Rust Tracing Fields".into(), Context::Other(fields));
        event
            .extra
            .insert("authorization".into(), Value::from("Bearer x"));
        event.extra.insert("pat_id".into(), Value::from("abc"));
        event.tags.insert("caller_email".into(), "a@b.c".into());
        event.tags.insert("netcidr.role".into(), "admin".into());

        let scrubbed = scrub_event(event);

        let Some(Context::Other(fields)) = scrubbed.contexts.get("Rust Tracing Fields") else {
            panic!("tracing fields context missing");
        };
        assert_eq!(fields.keys().collect::<Vec<_>>(), vec!["cidr"]);
        assert_eq!(scrubbed.extra.keys().collect::<Vec<_>>(), vec!["pat_id"]);
        assert_eq!(
            scrubbed.tags.keys().collect::<Vec<_>>(),
            vec!["netcidr.role"]
        );
    }

    #[test]
    fn unconfigured_is_a_noop() {
        // Guard against a developer shell that exports SENTRY_DSN.
        if is_configured() {
            return;
        }
        assert!(init().is_none());
        assert!(layer::<tracing_subscriber::Registry>().is_none());
    }
}
