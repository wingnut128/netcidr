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
#[derive(Debug)]
pub struct Callback {
    pub code: String,
}

const SUCCESS_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>netcidr</title>\
<body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
<h1>Signed in</h1><p>You can close this tab and return to the terminal.</p>";

const FAILURE_PAGE: &str = "<!doctype html><meta charset=utf-8>\
<title>netcidr</title>\
<body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
<h1>Sign-in failed</h1><p>Return to the terminal for details.</p>";

/// Wait for the browser to hit the loopback redirect, validate `state`,
/// and return the authorization code.
///
/// Reads only the request line, which is all that carries the query
/// string — the flow never needs headers or a body.
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
fn interpret_request(request: &str, expected_state: &str) -> Result<Callback> {
    let request_line = request.lines().next().unwrap_or_default();
    let target = request_line.split_whitespace().nth(1).unwrap_or_default();
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let params = parse_query(query);

    if let Some(error) = params.get("error") {
        return Err(match error.as_str() {
            "access_denied" => NetcidrError::Auth("sign-in was declined".to_string()),
            other => NetcidrError::Auth(format!(
                "authorization failed: {}",
                sanitize_for_display(other)
            )),
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

/// Bound on a sanitized IdP-supplied value echoed back to the terminal.
/// OAuth error codes are short identifiers like `access_denied` or
/// `invalid_scope`; 64 bytes is generous headroom without being unbounded.
const SANITIZED_VALUE_MAX_LEN: usize = 64;

/// Scrub an untrusted, percent-decoded query value before it is
/// interpolated into a message printed to the terminal. The `error` query
/// parameter on the loopback callback is attacker-influenceable — anyone
/// who can get the user to open a crafted URL at the loopback port while
/// `netcidr login` is waiting controls this string — so it must not be
/// allowed to carry ANSI escapes or other control bytes into the terminal.
/// Keeps only printable ASCII (space through `~`) and truncates to
/// `SANITIZED_VALUE_MAX_LEN`, dropping everything else rather than
/// replacing it with a placeholder, so the bound on output length holds
/// regardless of how much junk was stripped.
fn sanitize_for_display(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(SANITIZED_VALUE_MAX_LEN)
        .collect()
}

/// Decode the query string. `form_urlencoded` handles both `%XX` escapes
/// and `+` as space, and is already in the dependency tree via axum.
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

use netcidr::credentials::{Account, CredentialStore, normalize_api_url};
use netcidr::oauth::{self, Pkce};
use serde::Deserialize;

const ENV_API_URL: &str = "NETCIDR_API_URL";

/// Identity echoed back by `GET /me`, used to confirm the server actually
/// accepts the freshly minted token.
#[derive(Deserialize)]
struct Me {
    email: Option<String>,
    #[serde(default)]
    is_allowlisted: bool,
}

fn resolve_api_url(cli_flag: Option<&str>) -> Result<String> {
    let raw = match cli_flag {
        Some(url) => url.to_string(),
        None => std::env::var(ENV_API_URL).map_err(|_| {
            NetcidrError::Auth(format!("no API URL - pass --api-url or set {ENV_API_URL}"))
        })?,
    };
    normalize_api_url(&raw)
}

/// Confirm the server accepts this token, and learn the verified email.
/// Checking against the live server tests the audience list it actually
/// has, rather than the CLI's assumption about it.
async fn verify_with_server(api_url: &str, id_token: &str) -> Result<Me> {
    let response = reqwest::Client::new()
        .get(format!("{api_url}/me"))
        .bearer_auth(id_token)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not reach {api_url}: {e}")))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(NetcidrError::Auth(format!(
            "signed in, but {api_url} will not accept the token \
             (its NETCIDR_OIDC_AUDIENCE likely omits this CLI client)"
        )));
    }
    if !response.status().is_success() {
        return Err(NetcidrError::Auth(format!(
            "{api_url}/me returned HTTP {}",
            response.status().as_u16()
        )));
    }
    response
        .json::<Me>()
        .await
        .map_err(|e| NetcidrError::Auth(format!("unreadable /me response: {e}")))
}

fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // No known way to launch a browser on this target. Report failure
        // rather than pretending success — `handle_login`'s
        // `no_browser || !open_browser(&auth_url)` then falls back to
        // printing the URL, instead of leaving the user stuck waiting with
        // nothing on screen.
        let _ = url;
        return false;
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub async fn handle_login(
    api_url: Option<&str>,
    no_browser: bool,
    timeout_secs: u64,
) -> Result<()> {
    let api_url = resolve_api_url(api_url)?;
    let auth = oauth::fetch_auth_features(&api_url).await?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not bind a loopback port: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| NetcidrError::Auth(format!("could not read the loopback port: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let pkce = Pkce::generate();
    let state = oauth::random_state();
    let auth_url =
        oauth::build_auth_url(&auth.cli_client_id, &redirect_uri, &pkce.challenge, &state);

    if no_browser || !open_browser(&auth_url) {
        println!("Open this URL to sign in:\n\n  {auth_url}\n");
    } else {
        println!("Opening your browser to sign in with Google...");
    }

    let callback = wait_for_callback(listener, state, Duration::from_secs(timeout_secs)).await?;

    let tokens = oauth::exchange_code(
        oauth::TOKEN_ENDPOINT,
        &auth.cli_client_id,
        &auth.cli_client_secret,
        &callback.code,
        &pkce.verifier,
        &redirect_uri,
    )
    .await?;

    let me = verify_with_server(&api_url, &tokens.id_token).await?;
    let email = me.email.unwrap_or_else(|| "(unknown)".to_string());

    // `exchange_code` already rejects a response with no refresh token, but
    // that invariant is enforced there, not here — check it again at the
    // point that relies on it rather than trusting it stayed true. An
    // empty string cached silently would only surface much later as a
    // confusing "session expired".
    let refresh_token = tokens.refresh_token.clone().ok_or_else(|| {
        NetcidrError::Auth(
            "Google returned no refresh token - check the client is of type \"Desktop app\""
                .to_string(),
        )
    })?;

    let mut store = CredentialStore::load()?;
    store.insert(
        &api_url,
        Account {
            email: email.clone(),
            refresh_token,
            id_token: tokens.id_token,
            expires_at: oauth::expiry_from_now(tokens.expires_in),
            client_id: auth.cli_client_id,
        },
    );
    store.save()?;

    println!("Signed in as {email}");
    println!(
        "Credential cached in {}",
        netcidr::credentials::credentials_path()?.display()
    );
    if !me.is_allowlisted {
        println!(
            "\nNote: {email} is not yet admitted by this server's users directory.\n\
             Sign-in worked, but IPAM calls will be refused until an admin adds you."
        );
    }
    Ok(())
}

pub async fn handle_logout(api_url: Option<&str>, all: bool) -> Result<()> {
    let mut store = CredentialStore::load()?;

    if all {
        if store.is_empty() {
            println!("No cached logins.");
            return Ok(());
        }
        store.clear();
        store.save()?;
        println!("Discarded every cached login.");
        return Ok(());
    }

    let api_url = resolve_api_url(api_url)?;
    if store.remove(&api_url) {
        store.save()?;
        println!("Signed out of {api_url}");
    } else {
        println!("Not signed in to {api_url}");
    }
    Ok(())
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

    /// An IdP-controlled `error` value carrying an ANSI escape and raw
    /// control bytes must never reach the terminal unfiltered: anyone who
    /// can get the user to open a crafted URL at the loopback port while
    /// `netcidr login` is waiting controls this string.
    #[tokio::test]
    async fn sanitizes_control_bytes_in_the_error_parameter() {
        let (listener, url) = listener_and_url().await;
        let task = tokio::spawn(wait_for_callback(
            listener,
            "the-state".to_string(),
            Duration::from_secs(5),
        ));

        // \x1b[31m is an ANSI color escape; \x07 is BEL; \x08 is backspace.
        // Percent-encoded so the query string itself stays well-formed.
        let malicious = "weird%1b%5b31mderror%07%08";
        let _ = reqwest::get(format!("{url}?error={malicious}&state=the-state")).await;

        let err = task.await.unwrap().unwrap_err();
        let message = err.to_string();
        assert!(!message.contains('\x1b'), "got: {message:?}");
        assert!(!message.contains('\x07'), "got: {message:?}");
        assert!(!message.contains('\x08'), "got: {message:?}");
        assert!(message.contains("weird"), "got: {message:?}");
    }

    #[test]
    fn sanitize_for_display_strips_control_bytes_and_truncates() {
        let raw = format!("\x1b[31minjected\x07{}", "x".repeat(200));
        let cleaned = sanitize_for_display(&raw);

        assert!(cleaned.chars().all(|c| c.is_ascii_graphic() || c == ' '));
        assert!(cleaned.len() <= SANITIZED_VALUE_MAX_LEN);
        assert!(cleaned.starts_with("[31minjected"));
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

    // `handle_logout` always reads and writes through
    // `CredentialStore::load`/`save`, which resolve to the real
    // `~/.config/netcidr/credentials.json` — there is no way to redirect
    // that path from here, and a test must never touch the real user
    // credential file. So these exercise the same store operations
    // `handle_logout` performs (`remove` for one account, `clear` for
    // `--all`, and the "was nothing removed" case) directly against
    // `CredentialStore` on a `tempfile` path via `save_to`/`load_from`,
    // rather than calling `handle_logout` or going through a CLI
    // subprocess.
    fn sample_account() -> Account {
        Account {
            email: "user@example.com".to_string(),
            refresh_token: "1//0g-refresh".to_string(),
            id_token: "eyJ-id".to_string(),
            expires_at: "2026-08-18T21:04:11Z".to_string(),
            client_id: "desktop-client".to_string(),
        }
    }

    #[test]
    fn logout_removes_one_account_and_leaves_others_intact() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        let mut store = CredentialStore::default();
        store.insert("https://a.example", sample_account());
        store.insert("https://b.example", sample_account());
        store.save_to(&path).unwrap();

        let mut store = CredentialStore::load_from(&path).unwrap();
        assert!(store.remove("https://a.example"));
        store.save_to(&path).unwrap();

        let reloaded = CredentialStore::load_from(&path).unwrap();
        assert!(reloaded.get("https://a.example").is_none());
        assert!(reloaded.get("https://b.example").is_some());
    }

    #[test]
    fn logout_all_clears_every_cached_login() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        let mut store = CredentialStore::default();
        store.insert("https://a.example", sample_account());
        store.insert("https://b.example", sample_account());
        store.save_to(&path).unwrap();

        let mut store = CredentialStore::load_from(&path).unwrap();
        assert!(!store.is_empty());
        store.clear();
        store.save_to(&path).unwrap();

        let reloaded = CredentialStore::load_from(&path).unwrap();
        assert!(reloaded.is_empty());
    }

    #[test]
    fn logout_of_a_url_never_signed_in_to_reports_cleanly() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");

        let mut store = CredentialStore::default();
        store.insert("https://a.example", sample_account());
        store.save_to(&path).unwrap();

        // Mirrors `handle_logout`'s non-`--all` branch: `remove` returning
        // `false` is the "not signed in" case `handle_logout` prints a
        // plain message for, not an error path.
        let mut store = CredentialStore::load_from(&path).unwrap();
        assert!(!store.remove("https://never-signed-in.example"));
        store.save_to(&path).unwrap();

        let reloaded = CredentialStore::load_from(&path).unwrap();
        assert!(reloaded.get("https://a.example").is_some());
    }
}
