//! `netcidr login` / `netcidr logout`.
//!
//! Runs a Google OAuth authorization-code flow with PKCE against a
//! loopback redirect, then caches the credential. The listener binds
//! 127.0.0.1 explicitly, serves exactly one request, and shuts down.

use std::collections::HashMap;
use std::time::Duration;

use netcidr::error::{NetcidrError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Successful authorization callback.
// Consumed by `handle_login` in Task 8; the attribute goes away with it.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Callback {
    pub code: String,
}

// Consumed by `wait_for_callback` once Task 8 calls it from `handle_login`;
// the attribute goes away with that wiring.
#[allow(dead_code)]
const SUCCESS_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>netcidr</title>\
<body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
<h1>Signed in</h1><p>You can close this tab and return to the terminal.</p>";

// Consumed by `wait_for_callback` once Task 8 calls it from `handle_login`;
// the attribute goes away with that wiring.
#[allow(dead_code)]
const FAILURE_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>netcidr</title>\
<body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
<h1>Sign-in failed</h1><p>Return to the terminal for details.</p>";

/// Wait for the browser to hit the loopback redirect, validate `state`,
/// and return the authorization code.
///
/// Reads only the request line, which is all that carries the query
/// string — the flow never needs headers or a body.
// Consumed by `handle_login` in Task 8; the attribute goes away with it.
#[allow(dead_code)]
pub async fn wait_for_callback(
    listener: TcpListener,
    expected_state: String,
    timeout: Duration,
) -> Result<Callback> {
    let start = std::time::Instant::now();

    let accepted = tokio::time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| {
            NetcidrError::Auth(format!(
                "timed out after {}s waiting for the browser callback",
                timeout.as_secs()
            ))
        })?;

    let (mut stream, _peer) =
        accepted.map_err(|e| NetcidrError::Auth(format!("callback connection failed: {e}")))?;

    // Budget the read against what's left of the overall deadline, rather
    // than granting it a fresh `timeout`, so a client that completes the
    // handshake and then sends nothing can't make total wall-clock exceed
    // what the caller asked for.
    let remaining = timeout.saturating_sub(start.elapsed());
    let mut buffer = [0u8; 4096];
    let read = tokio::time::timeout(remaining, stream.read(&mut buffer))
        .await
        .map_err(|_| {
            NetcidrError::Auth(
                "browser connected but sent nothing before the callback timed out".to_string(),
            )
        })?
        .map_err(|e| NetcidrError::Auth(format!("could not read the callback request: {e}")))?;
    let request = String::from_utf8_lossy(&buffer[..read]);

    let outcome = interpret_request(&request, &expected_state);
    let page = if outcome.is_ok() {
        SUCCESS_PAGE
    } else {
        FAILURE_PAGE
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    outcome
}

/// Pull the query string out of the HTTP request line and turn it into a
/// result. Split out from the socket handling so it is directly testable.
// Consumed by `wait_for_callback` once Task 8 calls it from `handle_login`;
// the attribute goes away with that wiring.
#[allow(dead_code)]
fn interpret_request(request: &str, expected_state: &str) -> Result<Callback> {
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line.split_whitespace().nth(1).unwrap_or_default();
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let params = parse_query(query);

    if let Some(error) = params.get("error") {
        return Err(match error.as_str() {
            "access_denied" => NetcidrError::Auth("sign-in was declined".to_string()),
            other => NetcidrError::Auth(format!("authorization failed: {other}")),
        });
    }

    let state = params.get("state").map(String::as_str).unwrap_or_default();
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(NetcidrError::Auth(
            "authorization response failed state validation - aborting".to_string(),
        ));
    }

    let code = params
        .get("code")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| NetcidrError::Auth("authorization response carried no code".to_string()))?;

    Ok(Callback { code: code.clone() })
}

/// Decode the query string. `form_urlencoded` handles both `%XX` escapes
/// and `+` as space, and is already in the dependency tree via axum.
// Consumed by `interpret_request` once Task 8 wires the module in; the
// attribute goes away with that wiring.
#[allow(dead_code)]
fn parse_query(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

/// Length-independent comparison for the `state` check. Mirrors the helper
/// in `auth.rs`: it loops to the longer input's length, treats out-of-range
/// bytes as zero, and folds the length difference into the accumulator
/// unconditionally, so the number of comparisons never depends on whether
/// the lengths matched. Duplicated rather than made public because the bin
/// and lib halves of this crate should not grow a dependency for a dozen
/// lines.
// Consumed by `interpret_request` once Task 8 wires the module in; the
// attribute goes away with that wiring.
#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();

    for i in 0..max_len {
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= (left ^ right) as usize;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    async fn listener_and_url() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, format!("http://{addr}/callback"))
    }

    #[tokio::test]
    async fn accepts_a_matching_state_and_returns_the_code() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        let response = reqwest::get(format!("{url}?code=the-code&state=the-state"))
            .await
            .unwrap();
        assert!(response.status().is_success());

        let callback = task.await.unwrap().unwrap();
        assert_eq!(callback.code, "the-code");
    }

    #[tokio::test]
    async fn rejects_a_tampered_state() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        let _ = reqwest::get(format!("{url}?code=the-code&state=wrong-state")).await;

        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("state validation"), "got: {err}");
    }

    #[tokio::test]
    async fn surfaces_a_declined_sign_in() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        let _ = reqwest::get(format!("{url}?error=access_denied&state=the-state")).await;

        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("declined"), "got: {err}");
    }

    #[tokio::test]
    async fn times_out_when_no_callback_arrives() {
        let (listener, _url) = listener_and_url().await;

        let err = wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("timed out"), "got: {err}");
    }

    #[test]
    fn parses_query_parameters_with_percent_encoding() {
        let params = parse_query("code=a%2Fb&state=x%20y");
        assert_eq!(params.get("code").map(String::as_str), Some("a/b"));
        assert_eq!(params.get("state").map(String::as_str), Some("x y"));
    }

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"the-state", b"the-state"));
        assert!(constant_time_eq(b"", b""));

        // Equal length, differing content.
        assert!(!constant_time_eq(b"the-state", b"the-stat3"));

        // Differing length, one a prefix of the other.
        assert!(!constant_time_eq(b"the-state", b"the-stat"));
        assert!(!constant_time_eq(b"the-stat", b"the-state"));

        // Empty vs. non-empty.
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"x", b""));
    }

    #[tokio::test]
    async fn times_out_when_connected_client_sends_nothing() {
        let (listener, addr) = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            (listener, addr)
        };

        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_millis(300),
        ));

        // Complete the TCP handshake but never write a request line, so
        // the callback hangs past `accept` and into the read.
        let _stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {err}");
    }
}
