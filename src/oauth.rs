//! Google OAuth mechanics for `netcidr login`.
//!
//! Pure protocol code — PKCE derivation, authorization-URL construction,
//! and the two token-endpoint calls. Nothing here touches the filesystem
//! or the terminal, so it is all directly testable.

use base64::Engine;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use sha2::{Digest, Sha256};

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
