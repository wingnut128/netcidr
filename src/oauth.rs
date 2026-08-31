//! Google OAuth mechanics for `netcidr login`.
//!
//! Pure protocol code — PKCE derivation, authorization-URL construction,
//! and the two token-endpoint calls. Nothing here touches the filesystem
//! or the terminal, so it is all directly testable.

use base64::Engine;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{NetcidrError, Result};

pub const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Scopes requested at login. `openid` and `email` are what the server
/// needs to identify the principal; `profile` is what makes Google's
/// consent screen show a human name rather than a bare address.
const SCOPES: &str = "openid email profile";

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A PKCE verifier/challenge pair (RFC 7636). S256 only — `plain` is
/// never offered, because it provides no protection at all.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        // 32 random bytes -> 43 base64url chars, the RFC's minimum length
        // and the value Google's own libraries use.
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = b64url(&bytes);
        let challenge = challenge_for(&verifier);
        Self {
            verifier,
            challenge,
        }
    }
}

/// S256 code challenge: BASE64URL(SHA256(ASCII(verifier))), no padding.
fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    b64url(&digest)
}

/// CSRF token echoed back on the callback. 32 random bytes, compared in
/// constant time when the callback arrives.
pub fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    b64url(&bytes)
}

/// Everything outside RFC 3986's unreserved set gets percent-encoded.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encode a query-parameter value.
fn encode(value: &str) -> String {
    utf8_percent_encode(value, QUERY_VALUE).to_string()
}

/// Build the browser-facing authorization URL.
///
/// `access_type=offline` plus `prompt=consent` is what makes Google
/// reliably return a refresh token. Without `prompt=consent` a user who
/// has already granted this client gets an exchange with no
/// `refresh_token`, and the login silently degrades to a one-hour session.
pub fn build_auth_url(client_id: &str, redirect_uri: &str, challenge: &str, state: &str) -> String {
    format!(
        "{AUTH_ENDPOINT}?client_id={}&redirect_uri={}&response_type=code&scope={}\
         &code_challenge={}&code_challenge_method=S256&state={}&access_type=offline&prompt=consent",
        encode(client_id),
        encode(redirect_uri),
        encode(SCOPES),
        encode(challenge),
        encode(state),
    )
}

/// Successful token-endpoint response. `refresh_token` is present on an
/// authorization-code exchange and absent on a refresh, which is why it is
/// optional here rather than in two separate types.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: u64,
}

/// Google's error body. `error` is the machine-readable code we branch on;
/// `error_description` is human text we fold into the message.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Convert a token response's `expires_in` into an absolute RFC3339
/// instant, matching the timestamp convention used elsewhere in the
/// project.
pub fn expiry_from_now(expires_in: u64) -> String {
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);
    expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

async fn post_token_form(token_endpoint: &str, form: &[(&str, &str)]) -> Result<TokenResponse> {
    let response = reqwest::Client::new()
        .post(token_endpoint)
        .form(form)
        .send()
        .await
        .map_err(|e| NetcidrError::Auth(format!("token request failed: {e}")))?;

    if response.status().is_success() {
        return response
            .json::<TokenResponse>()
            .await
            .map_err(|e| NetcidrError::Auth(format!("unreadable token response: {e}")));
    }

    let status = response.status().as_u16();
    let body = response.json::<TokenErrorResponse>().await.ok();
    match body {
        Some(err) if err.error == "invalid_grant" => Err(NetcidrError::Auth(
            "session expired - run `netcidr login`".to_string(),
        )),
        Some(err) => {
            let detail = err.error_description.unwrap_or_else(|| err.error.clone());
            Err(NetcidrError::Auth(format!(
                "token endpoint rejected the request: {detail}"
            )))
        }
        None => Err(NetcidrError::Auth(format!(
            "token endpoint returned HTTP {status}"
        ))),
    }
}

/// Exchange an authorization code for tokens. A response with no refresh
/// token is treated as a failure: without one the credential dies in an
/// hour, and the usual cause is a client registered as the wrong type.
pub async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse> {
    let response = post_token_form(
        token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
        ],
    )
    .await?;

    if response.refresh_token.is_none() {
        return Err(NetcidrError::Auth(
            "Google returned no refresh token - check the client is of type \"Desktop app\""
                .to_string(),
        ));
    }
    Ok(response)
}

/// Re-mint an ID token from a stored refresh token.
pub async fn refresh_id_token(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    post_token_form(
        token_endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ],
    )
    .await
}

/// The `auth` block of `GET /features` — a deployment's CLI OAuth client.
///
/// Lives here rather than in the CLI binary because both `netcidr login`
/// and the credential resolver need it: the resolver has no other way to
/// learn the client secret when it refreshes a stale ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthFeatures {
    pub mode: String,
    pub cli_client_id: String,
    pub cli_client_secret: String,
}

#[derive(Deserialize)]
struct FeaturesBody {
    #[serde(default)]
    auth: Option<AuthFeatures>,
}

/// Fetch the CLI OAuth client a server advertises. Errors name the exact
/// missing configuration so the operator knows what to set.
pub async fn fetch_auth_features(api_url: &str) -> Result<AuthFeatures> {
    let body: FeaturesBody = reqwest::Client::new()
        .get(format!("{api_url}/features"))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| NetcidrError::Auth(format!("could not reach {api_url}: {e}")))?
        .json()
        .await
        .map_err(|e| NetcidrError::Auth(format!("unreadable /features response: {e}")))?;

    let auth = body.auth.ok_or_else(|| {
        NetcidrError::Auth(format!(
            "server at {api_url} has no CLI OAuth client configured \
             (set NETCIDR_OIDC_CLI_CLIENT_ID)"
        ))
    })?;

    if auth.mode != "oidc" {
        return Err(NetcidrError::Auth(format!(
            "server at {api_url} is not in OIDC mode - use NETCIDR_API_TOKEN instead"
        )));
    }
    Ok(auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B test vector: this exact verifier must produce
    /// this exact S256 challenge. If this fails, the challenge derivation
    /// is wrong and Google will reject every exchange.
    #[test]
    fn s256_challenge_matches_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge_for(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifier_is_within_rfc_length_bounds() {
        let pkce = Pkce::generate();
        assert!(
            (43..=128).contains(&pkce.verifier.len()),
            "verifier length {} out of range",
            pkce.verifier.len()
        );
        assert_eq!(pkce.challenge, challenge_for(&pkce.verifier));
    }

    #[test]
    fn generated_verifiers_are_unique() {
        let a = Pkce::generate();
        let b = Pkce::generate();
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn verifier_uses_only_unreserved_characters() {
        let pkce = Pkce::generate();
        assert!(
            pkce.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')),
            "verifier contains a reserved character: {}",
            pkce.verifier
        );
    }

    #[test]
    fn state_is_unique_and_long_enough() {
        let a = random_state();
        let b = random_state();
        assert_ne!(a, b);
        assert!(a.len() >= 43, "state too short: {}", a.len());
    }

    #[test]
    fn auth_url_carries_every_required_parameter() {
        let url = build_auth_url(
            "desktop-client",
            "http://127.0.0.1:51847/callback",
            "test-challenge",
            "test-state",
        );

        assert!(url.starts_with(AUTH_ENDPOINT));
        assert!(url.contains("client_id=desktop-client"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=test-challenge"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=test-state"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        // Redirect URI and scope must be percent-encoded.
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A51847%2Fcallback"));
        assert!(
            url.contains("scope=openid+email+profile")
                || url.contains("scope=openid%20email%20profile")
        );
    }
}
