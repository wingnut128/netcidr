use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::config::AuthMode;

const IAP_JWT_HEADER: &str = "x-goog-iap-jwt-assertion";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    BearerToken,
    Oidc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub kind: PrincipalKind,
    pub subject: String,
    pub email: Option<String>,
    pub audience: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    mode: AuthMode,
    bearer_token: Option<String>,
    oidc_audience: Option<String>,
}

impl AuthConfig {
    pub fn new(mode: AuthMode, bearer_token: Option<String>, oidc_audience: Option<String>) -> Self {
        Self {
            mode,
            bearer_token,
            oidc_audience,
        }
    }

    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn bearer(token: Option<String>) -> Self {
        Self::new(AuthMode::Bearer, token, None)
    }

    pub fn oidc(audience: Option<String>) -> Self {
        Self::new(AuthMode::Oidc, None, audience)
    }

    pub fn enabled(&self) -> bool {
        !matches!(self.mode, AuthMode::None)
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }
}

pub async fn require_auth(config: AuthConfig, mut request: Request, next: Next) -> Response {
    if is_public_path(request.uri().path()) || !config.enabled() {
        return next.run(request).await;
    }

    let principal = match config.mode {
        AuthMode::None => None,
        AuthMode::Bearer => authenticate_bearer(request.headers(), config.bearer_token.as_deref()),
        AuthMode::Oidc => authenticate_oidc(request.headers(), config.oidc_audience.as_deref()),
    };

    let Some(principal) = principal else {
        return unauthorized(config.mode);
    };

    request.extensions_mut().insert(principal);
    next.run(request).await
}

pub async fn require_bearer_auth(config: AuthConfig, request: Request, next: Next) -> Response {
    require_auth(config, request, next).await
}

fn authenticate_bearer(headers: &HeaderMap, expected_token: Option<&str>) -> Option<AuthenticatedPrincipal> {
    let expected_token = expected_token?;
    let actual_token = bearer_token(headers.get(header::AUTHORIZATION))?;
    if !constant_time_eq(actual_token.as_bytes(), expected_token.as_bytes()) {
        return None;
    }

    Some(AuthenticatedPrincipal {
        kind: PrincipalKind::BearerToken,
        subject: "bearer-token".to_string(),
        email: None,
        audience: None,
    })
}

fn authenticate_oidc(headers: &HeaderMap, expected_audience: Option<&str>) -> Option<AuthenticatedPrincipal> {
    let expected_audience = expected_audience?;
    let jwt = headers.get(IAP_JWT_HEADER).and_then(header_to_str)?;

    // TODO: Validate the signed IAP JWT using Google's public keys before relying on
    // identity claims. This scaffold parses claims and enforces audience so the
    // router, tenant, and authorization paths can be wired next.
    let claims = decode_unverified_jwt_claims(jwt)?;
    if claims.aud != expected_audience {
        return None;
    }

    Some(AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: claims.sub,
        email: claims.email,
        audience: Some(claims.aud),
    })
}

fn is_public_path(path: &str) -> bool {
    matches!(path, "/health" | "/version")
}

fn bearer_token(header_value: Option<&HeaderValue>) -> Option<&str> {
    let value = header_value.and_then(header_to_str)?;
    let token = value.strip_prefix("Bearer ")?;
    if token.trim().is_empty() {
        return None;
    }
    Some(token)
}

fn header_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

fn unauthorized(mode: AuthMode) -> Response {
    let authenticate = match mode {
        AuthMode::Bearer => "Bearer",
        AuthMode::Oidc => "Bearer, error=\"invalid_token\"",
        AuthMode::None => "Bearer",
    };
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, authenticate)], "Unauthorized")
        .into_response()
}

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

#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: String,
    aud: String,
    email: Option<String>,
}

fn decode_unverified_jwt_claims(jwt: &str) -> Option<OidcClaims> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let payload = decode_base64_url(parts[1])?;
    serde_json::from_slice(&payload).ok()
}

fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0;

    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }
        let val = value(byte)? as u32;
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_jwt_with_claims(subject: &str, audience: &str, email: Option<&str>) -> String {
        let email_field = email
            .map(|email| format!(r#", "email":"{email}""#))
            .unwrap_or_default();
        let payload = format!(r#"{{"sub":"{subject}","aud":"{audience}"{email_field}}}"#);
        format!("e30.{}.sig", encode_base64_url(payload.as_bytes()))
    }

    fn encode_base64_url(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[(n & 0x3f) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn public_paths_do_not_require_auth() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/version"));
        assert!(!is_public_path("/features"));
        assert!(!is_public_path("/ipam/supernets"));
    }

    #[test]
    fn bearer_token_parses_valid_header() {
        let value = HeaderValue::from_static("Bearer test-token");
        assert_eq!(bearer_token(Some(&value)), Some("test-token"));
    }

    #[test]
    fn bearer_token_rejects_missing_or_invalid_header() {
        assert_eq!(bearer_token(None), None);

        let wrong_scheme = HeaderValue::from_static("Basic test-token");
        assert_eq!(bearer_token(Some(&wrong_scheme)), None);

        let empty = HeaderValue::from_static("Bearer ");
        assert_eq!(bearer_token(Some(&empty)), None);
    }

    #[test]
    fn token_compare_matches_only_exact_equal_values() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"", b"abc"));
    }

    #[test]
    fn auth_config_reports_modes() {
        assert!(!AuthConfig::disabled().enabled());
        assert_eq!(AuthConfig::bearer(Some("t".to_string())).mode(), AuthMode::Bearer);
        assert_eq!(
            AuthConfig::oidc(Some("aud".to_string())).mode(),
            AuthMode::Oidc
        );
    }

    #[test]
    fn bearer_auth_returns_service_principal() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer test-token"));
        let principal = authenticate_bearer(&headers, Some("test-token")).unwrap();
        assert_eq!(principal.kind, PrincipalKind::BearerToken);
        assert_eq!(principal.subject, "bearer-token");
        assert_eq!(principal.email, None);
    }

    #[test]
    fn oidc_scaffold_checks_expected_audience_and_extracts_identity() {
        let jwt = fake_jwt_with_claims("accounts.google.com:123", "expected-audience", Some("user@example.com"));
        let mut headers = HeaderMap::new();
        headers.insert(IAP_JWT_HEADER, HeaderValue::from_str(&jwt).unwrap());

        let principal = authenticate_oidc(&headers, Some("expected-audience")).unwrap();
        assert_eq!(principal.kind, PrincipalKind::Oidc);
        assert_eq!(principal.subject, "accounts.google.com:123");
        assert_eq!(principal.email.as_deref(), Some("user@example.com"));
        assert_eq!(principal.audience.as_deref(), Some("expected-audience"));

        assert!(authenticate_oidc(&headers, Some("other-audience")).is_none());
    }

    #[test]
    fn unverified_claims_parser_rejects_bad_jwt() {
        assert!(decode_unverified_jwt_claims("not-a-jwt").is_none());
        assert!(decode_unverified_jwt_claims("a.b.c").is_none());
    }
}
