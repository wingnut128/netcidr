use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::config::AuthMode;

const IAP_JWT_HEADER: &str = "x-goog-iap-jwt-assertion";

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

pub async fn require_auth(config: AuthConfig, request: Request, next: Next) -> Response {
    if is_public_path(request.uri().path()) || !config.enabled() {
        return next.run(request).await;
    }

    let authorized = match config.mode {
        AuthMode::None => true,
        AuthMode::Bearer => authorize_bearer(request.headers(), config.bearer_token.as_deref()),
        AuthMode::Oidc => authorize_oidc(request.headers(), config.oidc_audience.as_deref()),
    };

    if !authorized {
        return unauthorized(config.mode);
    }

    next.run(request).await
}

pub async fn require_bearer_auth(config: AuthConfig, request: Request, next: Next) -> Response {
    require_auth(config, request, next).await
}

fn authorize_bearer(headers: &HeaderMap, expected_token: Option<&str>) -> bool {
    let Some(expected_token) = expected_token else {
        return false;
    };
    let Some(actual_token) = bearer_token(headers.get(header::AUTHORIZATION)) else {
        return false;
    };
    constant_time_eq(actual_token.as_bytes(), expected_token.as_bytes())
}

fn authorize_oidc(headers: &HeaderMap, expected_audience: Option<&str>) -> bool {
    let Some(expected_audience) = expected_audience else {
        return false;
    };
    let Some(jwt) = headers.get(IAP_JWT_HEADER).and_then(header_to_str) else {
        return false;
    };

    // TODO: Validate the signed IAP JWT using Google's public keys before relying on
    // identity claims. This initial scaffold validates only JWT shape and expected
    // audience so the config/middleware paths can be wired safely first.
    jwt_has_audience(jwt, expected_audience)
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

fn jwt_has_audience(jwt: &str, expected_audience: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let Some(payload) = decode_base64_url(parts[1]) else {
        return false;
    };
    let Ok(payload) = std::str::from_utf8(&payload) else {
        return false;
    };

    payload.contains(&format!("\"aud\":\"{expected_audience}\""))
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

    fn fake_jwt_with_aud(audience: &str) -> String {
        let payload = format!(r#"{{"aud":"{audience}","email":"user@example.com"}}"#);
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
    fn oidc_scaffold_checks_expected_audience() {
        let jwt = fake_jwt_with_aud("expected-audience");
        assert!(jwt_has_audience(&jwt, "expected-audience"));
        assert!(!jwt_has_audience(&jwt, "other-audience"));
        assert!(!jwt_has_audience("not-a-jwt", "expected-audience"));
    }
}
