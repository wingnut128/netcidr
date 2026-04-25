use axum::{
    extract::Request,
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    token: Option<String>,
}

impl AuthConfig {
    pub fn new(token: Option<String>) -> Self {
        Self { token }
    }

    pub fn enabled(&self) -> bool {
        self.token.is_some()
    }
}

pub async fn require_bearer_auth(config: AuthConfig, request: Request, next: Next) -> Response {
    if is_public_path(request.uri().path()) || !config.enabled() {
        return next.run(request).await;
    }

    let Some(expected_token) = config.token.as_deref() else {
        return next.run(request).await;
    };

    let Some(actual_token) = bearer_token(request.headers().get(header::AUTHORIZATION)) else {
        return unauthorized();
    };

    if !constant_time_eq(actual_token.as_bytes(), expected_token.as_bytes()) {
        return unauthorized();
    }

    next.run(request).await
}

fn is_public_path(path: &str) -> bool {
    matches!(path, "/health" | "/version")
}

fn bearer_token(header_value: Option<&axum::http::HeaderValue>) -> Option<&str> {
    let value = header_value?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    if token.trim().is_empty() {
        return None;
    }
    Some(token)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "Unauthorized",
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_paths_do_not_require_auth() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/version"));
        assert!(!is_public_path("/features"));
        assert!(!is_public_path("/ipam/supernets"));
    }

    #[test]
    fn bearer_token_parses_valid_header() {
        let value = axum::http::HeaderValue::from_static("Bearer test-token");
        assert_eq!(bearer_token(Some(&value)), Some("test-token"));
    }

    #[test]
    fn bearer_token_rejects_missing_or_invalid_header() {
        assert_eq!(bearer_token(None), None);

        let wrong_scheme = axum::http::HeaderValue::from_static("Basic test-token");
        assert_eq!(bearer_token(Some(&wrong_scheme)), None);

        let empty = axum::http::HeaderValue::from_static("Bearer ");
        assert_eq!(bearer_token(Some(&empty)), None);
    }

    #[test]
    fn token_compare_matches_only_exact_equal_values() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"", b"abc"));
    }
}
