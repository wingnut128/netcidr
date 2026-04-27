use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::AuthMode;

const IAP_JWT_HEADER: &str = "x-goog-iap-jwt-assertion";
const IAP_ISSUER: &str = "https://cloud.google.com/iap";
const IAP_PUBLIC_KEYS_URL: &str = "https://www.gstatic.com/iap/verify/public_key";
const DEFAULT_KEY_TTL: Duration = Duration::from_secs(60 * 60);
const MIN_KEY_TTL: Duration = Duration::from_secs(60);
const CLOCK_SKEW_SECONDS: u64 = 60;

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
    pub fn new(
        mode: AuthMode,
        bearer_token: Option<String>,
        oidc_audience: Option<String>,
    ) -> Self {
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
        AuthMode::Oidc => {
            authenticate_oidc(request.headers(), config.oidc_audience.as_deref()).await
        }
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

fn authenticate_bearer(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Option<AuthenticatedPrincipal> {
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

async fn authenticate_oidc(
    headers: &HeaderMap,
    expected_audience: Option<&str>,
) -> Option<AuthenticatedPrincipal> {
    let expected_audience = expected_audience?;
    let jwt = headers.get(IAP_JWT_HEADER).and_then(header_to_str)?;
    let keys = iap_public_keys().await.ok()?;
    let claims = validate_iap_jwt(jwt, expected_audience, &keys)?;

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
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, authenticate)],
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

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OidcClaims {
    sub: String,
    aud: String,
    email: Option<String>,
    exp: usize,
    iat: usize,
    nbf: Option<usize>,
    iss: String,
}

#[derive(Debug, Default)]
struct IapKeyCache {
    keys: HashMap<String, String>,
    expires_at: Option<Instant>,
}

static IAP_KEYS: OnceLock<RwLock<IapKeyCache>> = OnceLock::new();

fn key_cache() -> &'static RwLock<IapKeyCache> {
    IAP_KEYS.get_or_init(|| RwLock::new(IapKeyCache::default()))
}

async fn iap_public_keys() -> Result<HashMap<String, String>, ()> {
    let now = Instant::now();
    {
        let cache = key_cache().read().await;
        if cache.expires_at.is_some_and(|expires_at| expires_at > now) && !cache.keys.is_empty() {
            return Ok(cache.keys.clone());
        }
    }

    let (keys, ttl) = fetch_iap_public_keys().await.map_err(|err| {
        warn!(error = %err, "failed to refresh Google IAP public keys");
    })?;

    let mut cache = key_cache().write().await;
    cache.keys = keys.clone();
    cache.expires_at = Some(Instant::now() + ttl.max(MIN_KEY_TTL));
    Ok(keys)
}

async fn fetch_iap_public_keys() -> Result<(HashMap<String, String>, Duration), reqwest::Error> {
    let response = reqwest::Client::new()
        .get(IAP_PUBLIC_KEYS_URL)
        .send()
        .await?
        .error_for_status()?;
    let ttl = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(cache_control_max_age)
        .unwrap_or(DEFAULT_KEY_TTL);
    let keys = response.json::<HashMap<String, String>>().await?;
    Ok((keys, ttl))
}

fn cache_control_max_age(value: &str) -> Option<Duration> {
    value
        .split(',')
        .map(str::trim)
        .find_map(|directive| directive.strip_prefix("max-age="))
        .and_then(|seconds| seconds.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn validate_iap_jwt(
    jwt: &str,
    expected_audience: &str,
    keys: &HashMap<String, String>,
) -> Option<OidcClaims> {
    let header = decode_header(jwt).ok()?;
    if header.alg != Algorithm::ES256 {
        return None;
    }
    let kid = header.kid.as_deref()?;
    let pem = keys.get(kid)?;
    let decoding_key = DecodingKey::from_ec_pem(pem.as_bytes()).ok()?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[expected_audience]);
    validation.set_issuer(&[IAP_ISSUER]);
    validation.leeway = CLOCK_SKEW_SECONDS;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.required_spec_claims.insert("sub".to_string());

    let token = decode::<OidcClaims>(jwt, &decoding_key, &validation).ok()?;
    if token.claims.sub.trim().is_empty() || issued_in_future(token.claims.iat) {
        return None;
    }
    Some(token.claims)
}

fn issued_in_future(iat: usize) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    iat as u64 > now.saturating_add(CLOCK_SKEW_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde::Serialize;

    const TEST_KEY_ID: &str = "test-key";
    const TEST_PRIVATE_KEY: &str = include_str!("../tests/fixtures/iap-test-private.pem");
    const TEST_PUBLIC_KEY: &str = include_str!("../tests/fixtures/iap-test-public.pem");

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        aud: String,
        email: Option<String>,
        iss: String,
        exp: usize,
        iat: usize,
    }

    fn now_seconds() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
    }

    fn key_map() -> HashMap<String, String> {
        HashMap::from([(TEST_KEY_ID.to_string(), TEST_PUBLIC_KEY.to_string())])
    }

    fn signed_iap_jwt(subject: &str, audience: &str, issuer: &str, exp: usize) -> String {
        signed_iap_jwt_with_iat(subject, audience, issuer, exp, now_seconds())
    }

    fn signed_iap_jwt_with_iat(
        subject: &str,
        audience: &str,
        issuer: &str,
        exp: usize,
        iat: usize,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(TEST_KEY_ID.to_string());
        let claims = TestClaims {
            sub: subject.to_string(),
            aud: audience.to_string(),
            email: Some("user@example.com".to_string()),
            iss: issuer.to_string(),
            exp,
            iat,
        };
        encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
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
        assert_eq!(
            AuthConfig::bearer(Some("t".to_string())).mode(),
            AuthMode::Bearer
        );
        assert_eq!(
            AuthConfig::oidc(Some("aud".to_string())).mode(),
            AuthMode::Oidc
        );
    }

    #[test]
    fn bearer_auth_returns_service_principal() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token"),
        );
        let principal = authenticate_bearer(&headers, Some("test-token")).unwrap();
        assert_eq!(principal.kind, PrincipalKind::BearerToken);
        assert_eq!(principal.subject, "bearer-token");
        assert_eq!(principal.email, None);
    }

    #[test]
    fn iap_jwt_validation_accepts_valid_signed_token() {
        let jwt = signed_iap_jwt(
            "accounts.google.com:123",
            "expected-audience",
            IAP_ISSUER,
            now_seconds() + 3600,
        );
        let claims = validate_iap_jwt(&jwt, "expected-audience", &key_map()).unwrap();
        assert_eq!(claims.sub, "accounts.google.com:123");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.aud, "expected-audience");
    }

    #[tokio::test]
    async fn oidc_auth_extracts_identity_from_valid_iap_jwt() {
        let jwt = signed_iap_jwt(
            "accounts.google.com:123",
            "expected-audience",
            IAP_ISSUER,
            now_seconds() + 3600,
        );
        let mut headers = HeaderMap::new();
        headers.insert(IAP_JWT_HEADER, HeaderValue::from_str(&jwt).unwrap());

        let cache = key_cache();
        {
            let mut cache = cache.write().await;
            cache.keys = key_map();
            cache.expires_at = Some(Instant::now() + DEFAULT_KEY_TTL);
        }

        let principal = authenticate_oidc(&headers, Some("expected-audience"))
            .await
            .unwrap();
        assert_eq!(principal.kind, PrincipalKind::Oidc);
        assert_eq!(principal.subject, "accounts.google.com:123");
        assert_eq!(principal.email.as_deref(), Some("user@example.com"));
        assert_eq!(principal.audience.as_deref(), Some("expected-audience"));
    }

    #[test]
    fn iap_jwt_validation_rejects_bad_audience() {
        let jwt = signed_iap_jwt(
            "accounts.google.com:123",
            "expected-audience",
            IAP_ISSUER,
            now_seconds() + 3600,
        );
        assert!(validate_iap_jwt(&jwt, "other-audience", &key_map()).is_none());
    }

    #[test]
    fn iap_jwt_validation_rejects_bad_issuer() {
        let jwt = signed_iap_jwt(
            "accounts.google.com:123",
            "expected-audience",
            "https://issuer.example.com",
            now_seconds() + 3600,
        );
        assert!(validate_iap_jwt(&jwt, "expected-audience", &key_map()).is_none());
    }

    #[test]
    fn iap_jwt_validation_rejects_unknown_key_id() {
        let jwt = signed_iap_jwt(
            "accounts.google.com:123",
            "expected-audience",
            IAP_ISSUER,
            now_seconds() + 3600,
        );
        assert!(validate_iap_jwt(&jwt, "expected-audience", &HashMap::new()).is_none());
    }

    #[test]
    fn iap_jwt_validation_rejects_expired_token() {
        let jwt = signed_iap_jwt(
            "accounts.google.com:123",
            "expected-audience",
            IAP_ISSUER,
            now_seconds() - 3600,
        );
        assert!(validate_iap_jwt(&jwt, "expected-audience", &key_map()).is_none());
    }

    #[test]
    fn iap_jwt_validation_rejects_future_issued_token() {
        let jwt = signed_iap_jwt_with_iat(
            "accounts.google.com:123",
            "expected-audience",
            IAP_ISSUER,
            now_seconds() + 3600,
            now_seconds() + 3600,
        );
        assert!(validate_iap_jwt(&jwt, "expected-audience", &key_map()).is_none());
    }

    #[tokio::test]
    async fn oidc_auth_rejects_missing_iap_header() {
        let headers = HeaderMap::new();
        assert!(
            authenticate_oidc(&headers, Some("expected-audience"))
                .await
                .is_none()
        );
    }

    #[test]
    fn iap_jwt_validation_rejects_malformed_jwt() {
        assert!(validate_iap_jwt("not-a-jwt", "expected-audience", &key_map()).is_none());
        assert!(validate_iap_jwt("a.b.c", "expected-audience", &key_map()).is_none());
    }

    #[test]
    fn cache_control_max_age_parses_header_directives() {
        assert_eq!(
            cache_control_max_age("public, max-age=123, must-revalidate"),
            Some(Duration::from_secs(123))
        );
        assert_eq!(cache_control_max_age("no-cache"), None);
    }
}
