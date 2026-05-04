use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::AuthMode;
use crate::ipam::store::IpamStore;
use crate::pat::{self, PatPepper};

const GOOGLE_ISSUERS: &[&str] = &["https://accounts.google.com", "accounts.google.com"];
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const DEFAULT_KEY_TTL: Duration = Duration::from_secs(60 * 60);
const MIN_KEY_TTL: Duration = Duration::from_secs(60);
const CLOCK_SKEW_SECONDS: u64 = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    BearerToken,
    Oidc,
}

/// How the request principal authenticated. Carried on `AuthenticatedPrincipal`
/// and propagated into the audit context so every mutation records its
/// auth method (and the originating PAT id, when applicable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Oidc,
    Pat,
    Bearer,
}

impl AuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Oidc => "oidc",
            AuthMethod::Pat => "pat",
            AuthMethod::Bearer => "bearer",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub kind: PrincipalKind,
    pub subject: String,
    pub email: Option<String>,
    pub audience: Option<String>,
    pub auth_method: AuthMethod,
    /// `Some(id)` only when `auth_method == AuthMethod::Pat`.
    pub pat_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct AuthConfig {
    mode: AuthMode,
    bearer_token: Option<String>,
    oidc_audience: Option<String>,
    allowed_emails: Vec<String>,
    admin_emails: Vec<String>,
    /// Optional store + pepper used by the PAT verifier. Both must be set
    /// for the `Bearer ncdr_pat_…` branch of `require_auth` to succeed;
    /// otherwise PAT-shaped tokens fall through to a generic 401.
    pat_store: Option<Arc<dyn IpamStore>>,
    pat_pepper: Option<Arc<PatPepper>>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("mode", &self.mode)
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "<set>"))
            .field("oidc_audience", &self.oidc_audience)
            .field("allowed_emails", &self.allowed_emails)
            .field("admin_emails", &self.admin_emails)
            .field("pat_store", &self.pat_store.as_ref().map(|_| "<set>"))
            .field("pat_pepper", &self.pat_pepper.as_ref().map(|_| "<set>"))
            .finish()
    }
}

impl AuthConfig {
    pub fn new(
        mode: AuthMode,
        bearer_token: Option<String>,
        oidc_audience: Option<String>,
        allowed_emails: Vec<String>,
    ) -> Self {
        Self {
            mode,
            bearer_token,
            oidc_audience,
            allowed_emails: allowed_emails
                .into_iter()
                .map(|e| e.to_ascii_lowercase())
                .collect(),
            admin_emails: Vec::new(),
            pat_store: None,
            pat_pepper: None,
        }
    }

    /// Attach the IPAM store + pepper used by the PAT verifier. Set on
    /// `serve` startup; left unset for unit tests that don't exercise PATs.
    pub fn with_pat_backend(mut self, store: Arc<dyn IpamStore>, pepper: Arc<PatPepper>) -> Self {
        self.pat_store = Some(store);
        self.pat_pepper = Some(pepper);
        self
    }

    pub fn has_pat_backend(&self) -> bool {
        self.pat_store.is_some() && self.pat_pepper.is_some()
    }

    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn bearer(token: Option<String>) -> Self {
        Self::new(AuthMode::Bearer, token, None, Vec::new())
    }

    pub fn oidc(audience: Option<String>) -> Self {
        Self::new(AuthMode::Oidc, None, audience, Vec::new())
    }

    pub fn with_allowed_emails(mut self, emails: Vec<String>) -> Self {
        self.allowed_emails = emails.into_iter().map(|e| e.to_ascii_lowercase()).collect();
        self
    }

    pub fn with_admin_emails(mut self, emails: Vec<String>) -> Self {
        self.admin_emails = emails.into_iter().map(|e| e.to_ascii_lowercase()).collect();
        self
    }

    pub fn allowed_emails(&self) -> &[String] {
        &self.allowed_emails
    }

    pub fn admin_emails(&self) -> &[String] {
        &self.admin_emails
    }

    pub fn oidc_audience(&self) -> Option<&str> {
        self.oidc_audience.as_deref()
    }

    pub fn is_admin(&self, email: Option<&str>) -> bool {
        if self.admin_emails.is_empty() {
            return false;
        }
        match email {
            Some(addr) => {
                let needle = addr.to_ascii_lowercase();
                self.admin_emails.iter().any(|a| a == &needle)
            }
            None => false,
        }
    }

    /// Validate the request's bearer token without enforcing the email
    /// allowlist. Returns the principal on success, or None if the token is
    /// missing/invalid. Callers (e.g. /me) use this when they want to know
    /// "is this user signed in at all?" independent of allowlist status.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Option<AuthenticatedPrincipal> {
        // Mirrors the dispatch logic in `require_auth` so /me and /admin
        // (which use this method outside the IPAM middleware) accept PATs
        // too. PAT verification needs the store + pepper configured; if
        // they're absent we silently skip the PAT branch.
        if let Some(token) = bearer_token(headers.get(header::AUTHORIZATION))
            && token.starts_with("ncdr_pat_")
        {
            if let (Some(store), Some(pepper)) = (self.pat_store.as_ref(), self.pat_pepper.as_ref())
            {
                return verify_pat(store, pepper.as_ref(), &self.allowed_emails, token)
                    .await
                    .ok();
            }
            return None;
        }
        match self.mode {
            AuthMode::None => None,
            AuthMode::Bearer => authenticate_bearer(headers, self.bearer_token.as_deref()),
            AuthMode::Oidc => authenticate_oidc(headers, self.oidc_audience.as_deref()).await,
        }
    }

    pub fn email_is_allowed(&self, email: Option<&str>) -> bool {
        self.email_allowed(email)
    }

    pub fn enabled(&self) -> bool {
        !matches!(self.mode, AuthMode::None)
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    fn email_allowed(&self, email: Option<&str>) -> bool {
        if self.allowed_emails.is_empty() {
            return true;
        }
        match email {
            Some(addr) => self
                .allowed_emails
                .iter()
                .any(|allowed| allowed == &addr.to_ascii_lowercase()),
            None => false,
        }
    }
}

pub async fn require_auth(config: AuthConfig, mut request: Request, next: Next) -> Response {
    if !config.enabled() {
        return next.run(request).await;
    }

    // Dispatch by header content. PAT-shaped bearer tokens take priority
    // over the OIDC/bearer branches: a `ncdr_pat_…` value can never be a
    // valid JWT or static bearer token, so trying those first would just
    // burn cycles for the same generic 401.
    let raw_bearer = bearer_token(request.headers().get(header::AUTHORIZATION));
    let principal = if let Some(token) = raw_bearer {
        if token.starts_with("ncdr_pat_") {
            let (Some(store), Some(pepper)) =
                (config.pat_store.as_ref(), config.pat_pepper.as_ref())
            else {
                // PAT-shaped bearer with no PAT backend configured: cannot
                // succeed. Fall back to a generic 401 without leaking the
                // misconfiguration.
                return unauthorized(config.mode);
            };
            match verify_pat(store, pepper.as_ref(), &config.allowed_emails, token).await {
                Ok(p) => Some(p),
                Err(_) => return unauthorized(config.mode),
            }
        } else {
            match config.mode {
                AuthMode::None => None,
                AuthMode::Bearer => {
                    authenticate_bearer(request.headers(), config.bearer_token.as_deref())
                }
                AuthMode::Oidc => {
                    authenticate_oidc(request.headers(), config.oidc_audience.as_deref()).await
                }
            }
        }
    } else {
        None
    };

    let Some(principal) = principal else {
        return unauthorized(config.mode);
    };

    if !config.email_allowed(principal.email.as_deref()) {
        warn!(
            email = principal.email.as_deref().unwrap_or("<none>"),
            "rejecting authenticated principal not in allowlist"
        );
        return forbidden();
    }

    // Derive tenant identity from the authenticated principal. OIDC mode
    // requires a verified email; bearer-token mode (single-operator deploys)
    // falls back to the constant subject "bearer-token" so a single-tenant
    // bucket still exists. PAT auth carries the OIDC owner_email, so it
    // takes the same email-as-tenant path as OIDC.
    let tenant_id = match principal.kind {
        PrincipalKind::Oidc => match principal.email.clone() {
            Some(email) => email,
            None => {
                warn!("rejecting OIDC principal without verified email");
                return unauthorized(config.mode);
            }
        },
        PrincipalKind::BearerToken => principal.subject.clone(),
    };
    request
        .extensions_mut()
        .insert(crate::tenant::Tenant(tenant_id));

    let ctx = crate::audit_context::AuditContext {
        caller_sub: Some(principal.subject.clone()),
        caller_email: principal.email.clone(),
        source_ip: request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_string()),
        request_id: Some(uuid::Uuid::new_v4().to_string()),
        auth_method: Some(principal.auth_method.as_str().to_string()),
        pat_id: principal.pat_id.clone(),
    };

    request.extensions_mut().insert(principal);
    crate::audit_context::scope(ctx, next.run(request)).await
}

/// Errors surfaced by [`verify_pat`]. All variants are externally collapsed
/// to a generic 401 by [`require_auth`] so the verifier doesn't leak which
/// failure mode (shape, miss, expired/revoked, allowlist) was hit.
#[derive(Debug)]
pub enum AuthError {
    Unauthorized,
}

/// Verify a `ncdr_pat_…` plaintext bearer token against the store. The token
/// must have already had its `Bearer ` prefix stripped.
///
/// Steps, in order:
///   1. Shape-check via [`pat::hash_for_lookup`] — invalid shape returns
///      Unauthorized without any DB access.
///   2. Store lookup with `(token_hash, now)` — the SQL predicate already
///      filters revoked / expired so any miss is a single uniform 401.
///   3. Allowlist check on `owner_email` (matching the existing OIDC
///      semantics: empty allowlist disables the check).
///   4. Detached `tokio::spawn` to update `last_used_at` — fire and forget,
///      errors logged at WARN; the request never blocks on this write.
pub(crate) async fn verify_pat(
    store: &Arc<dyn IpamStore>,
    pepper: &PatPepper,
    allowed_emails: &[String],
    token: &str,
) -> Result<AuthenticatedPrincipal, AuthError> {
    let hash = pat::hash_for_lookup(token, pepper).ok_or(AuthError::Unauthorized)?;
    let now = chrono::Utc::now().to_rfc3339();
    let row = store
        .pat_get_by_hash(&hash, &now)
        .await
        .map_err(|_| AuthError::Unauthorized)?
        .ok_or(AuthError::Unauthorized)?;

    if !allowed_emails.is_empty() {
        let needle = row.owner_email.to_ascii_lowercase();
        if !allowed_emails.iter().any(|e| e == &needle) {
            return Err(AuthError::Unauthorized);
        }
    }

    let principal = AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: row.owner_sub.clone(),
        email: Some(row.owner_email.clone()),
        audience: None,
        auth_method: AuthMethod::Pat,
        pat_id: Some(row.id.clone()),
    };

    // Detached last_used_at update — fire-and-forget so the request path
    // never waits on this write. WARN-level on failure (rare; transient
    // DB errors) is enough to surface persistent breakage in metrics.
    let touch_store = Arc::clone(store);
    let touch_id = row.id.clone();
    let touch_now = now;
    tokio::spawn(async move {
        if let Err(e) = touch_store.pat_touch_last_used(&touch_id, &touch_now).await {
            warn!(error = %e, pat_id = %touch_id, "failed to update PAT last_used_at");
        }
    });

    Ok(principal)
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
        auth_method: AuthMethod::Bearer,
        pat_id: None,
    })
}

async fn authenticate_oidc(
    headers: &HeaderMap,
    expected_audience: Option<&str>,
) -> Option<AuthenticatedPrincipal> {
    let expected_audience = expected_audience?;
    let jwt = bearer_token(headers.get(header::AUTHORIZATION))?;
    let keys = google_public_keys().await.ok()?;
    let claims = validate_google_id_token(jwt, expected_audience, &keys)?;

    Some(AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: claims.sub,
        email: claims
            .email
            .filter(|_| claims.email_verified.unwrap_or(false)),
        audience: Some(claims.aud),
        auth_method: AuthMethod::Oidc,
        pat_id: None,
    })
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

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
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
    email_verified: Option<bool>,
    exp: usize,
    iat: usize,
    nbf: Option<usize>,
    iss: String,
}

#[derive(Clone, Debug)]
struct GoogleKey {
    n: String,
    e: String,
}

#[derive(Debug, Default)]
struct GoogleKeyCache {
    keys: HashMap<String, GoogleKey>,
    expires_at: Option<Instant>,
}

static GOOGLE_KEYS: OnceLock<RwLock<GoogleKeyCache>> = OnceLock::new();

fn key_cache() -> &'static RwLock<GoogleKeyCache> {
    GOOGLE_KEYS.get_or_init(|| RwLock::new(GoogleKeyCache::default()))
}

async fn google_public_keys() -> Result<HashMap<String, GoogleKey>, ()> {
    let now = Instant::now();
    {
        let cache = key_cache().read().await;
        if cache.expires_at.is_some_and(|expires_at| expires_at > now) && !cache.keys.is_empty() {
            return Ok(cache.keys.clone());
        }
    }

    let (keys, ttl) = fetch_google_public_keys().await.map_err(|err| {
        warn!(error = %err, "failed to refresh Google OAuth public keys");
    })?;

    let mut cache = key_cache().write().await;
    cache.keys = keys.clone();
    cache.expires_at = Some(Instant::now() + ttl.max(MIN_KEY_TTL));
    Ok(keys)
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    #[serde(default)]
    kty: String,
    n: String,
    e: String,
}

async fn fetch_google_public_keys() -> Result<(HashMap<String, GoogleKey>, Duration), reqwest::Error>
{
    let response = reqwest::Client::new()
        .get(GOOGLE_JWKS_URL)
        .send()
        .await?
        .error_for_status()?;
    let ttl = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(cache_control_max_age)
        .unwrap_or(DEFAULT_KEY_TTL);
    let jwk_set = response.json::<JwkSet>().await?;
    let keys = jwk_set
        .keys
        .into_iter()
        .filter(|k| k.kty == "RSA" || k.kty.is_empty())
        .map(|k| (k.kid, GoogleKey { n: k.n, e: k.e }))
        .collect();
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

fn validate_google_id_token(
    jwt: &str,
    expected_audience: &str,
    keys: &HashMap<String, GoogleKey>,
) -> Option<OidcClaims> {
    let header = decode_header(jwt).ok()?;
    if header.alg != Algorithm::RS256 {
        return None;
    }
    let kid = header.kid.as_deref()?;
    let key = keys.get(kid)?;
    let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e).ok()?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[expected_audience]);
    validation.set_issuer(GOOGLE_ISSUERS);
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

/// Test-only helpers for integration tests that need to mint OIDC tokens
/// without contacting Google. Always compiled (so external integration
/// tests can call them) but `#[doc(hidden)]` to keep them out of the
/// public API surface.
#[doc(hidden)]
pub mod test_support {
    use super::*;
    use base64::Engine;

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Install an RSA public key into the JWKS cache used by the OIDC
    /// validator. Subsequent OIDC verifications find this key by `kid`
    /// and skip the network fetch.
    pub async fn install_jwks(kid: &str, n_be: &[u8], e_be: &[u8]) {
        let mut cache = key_cache().write().await;
        cache.keys.insert(
            kid.to_string(),
            GoogleKey {
                n: b64url(n_be),
                e: b64url(e_be),
            },
        );
        cache.expires_at = Some(Instant::now() + DEFAULT_KEY_TTL);
    }

    /// Clear the JWKS cache. Tests that exercise allowlist-removal-style
    /// scenarios call this so a stale key doesn't bleed across tests.
    pub async fn clear_jwks() {
        let mut cache = key_cache().write().await;
        cache.keys.clear();
        cache.expires_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde::Serialize;

    const TEST_KEY_ID: &str = "test-key";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        aud: String,
        email: Option<String>,
        email_verified: Option<bool>,
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

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn test_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    fn key_map(public: &RsaPublicKey) -> HashMap<String, GoogleKey> {
        let n = b64url(&public.n().to_bytes_be());
        let e = b64url(&public.e().to_bytes_be());
        HashMap::from([(TEST_KEY_ID.to_string(), GoogleKey { n, e })])
    }

    fn signed_id_token(
        private: &RsaPrivateKey,
        subject: &str,
        audience: &str,
        issuer: &str,
        exp: usize,
        iat: usize,
        email_verified: Option<bool>,
    ) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KEY_ID.to_string());
        let claims = TestClaims {
            sub: subject.to_string(),
            aud: audience.to_string(),
            email: Some("user@example.com".to_string()),
            email_verified,
            iss: issuer.to_string(),
            exp,
            iat,
        };
        let pem = private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("encode private key");
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("decoding key"),
        )
        .expect("sign jwt")
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
    fn google_id_token_validation_accepts_valid_signed_token() {
        let (private, public) = test_keypair();
        let issuer = "https://accounts.google.com";
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            issuer,
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        let claims =
            validate_google_id_token(&jwt, "expected-audience", &key_map(&public)).unwrap();
        assert_eq!(claims.sub, "117290938723847238472");
        assert_eq!(claims.aud, "expected-audience");
    }

    #[test]
    fn google_id_token_validation_accepts_short_form_issuer() {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "accounts.google.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        assert!(validate_google_id_token(&jwt, "expected-audience", &key_map(&public)).is_some());
    }

    #[test]
    fn google_id_token_validation_rejects_bad_audience() {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://accounts.google.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        assert!(validate_google_id_token(&jwt, "other-audience", &key_map(&public)).is_none());
    }

    #[test]
    fn google_id_token_validation_rejects_bad_issuer() {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://issuer.example.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        assert!(validate_google_id_token(&jwt, "expected-audience", &key_map(&public)).is_none());
    }

    #[test]
    fn google_id_token_validation_rejects_unknown_key_id() {
        let (private, _public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://accounts.google.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        assert!(validate_google_id_token(&jwt, "expected-audience", &HashMap::new()).is_none());
    }

    #[test]
    fn google_id_token_validation_rejects_expired_token() {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://accounts.google.com",
            now_seconds() - 3600,
            now_seconds() - 7200,
            Some(true),
        );
        assert!(validate_google_id_token(&jwt, "expected-audience", &key_map(&public)).is_none());
    }

    #[test]
    fn google_id_token_validation_rejects_future_issued_token() {
        let (private, public) = test_keypair();
        let future = now_seconds() + 3600;
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://accounts.google.com",
            future,
            future,
            Some(true),
        );
        assert!(validate_google_id_token(&jwt, "expected-audience", &key_map(&public)).is_none());
    }

    #[tokio::test]
    async fn oidc_auth_extracts_identity_from_valid_id_token() {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://accounts.google.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        );

        {
            let mut cache = key_cache().write().await;
            cache.keys = key_map(&public);
            cache.expires_at = Some(Instant::now() + DEFAULT_KEY_TTL);
        }

        let principal = authenticate_oidc(&headers, Some("expected-audience"))
            .await
            .unwrap();
        assert_eq!(principal.kind, PrincipalKind::Oidc);
        assert_eq!(principal.subject, "117290938723847238472");
        assert_eq!(principal.email.as_deref(), Some("user@example.com"));
        assert_eq!(principal.audience.as_deref(), Some("expected-audience"));
    }

    #[tokio::test]
    async fn oidc_auth_drops_email_when_unverified() {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            "expected-audience",
            "https://accounts.google.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(false),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        );

        {
            let mut cache = key_cache().write().await;
            cache.keys = key_map(&public);
            cache.expires_at = Some(Instant::now() + DEFAULT_KEY_TTL);
        }

        let principal = authenticate_oidc(&headers, Some("expected-audience"))
            .await
            .unwrap();
        assert_eq!(principal.email, None);
    }

    #[tokio::test]
    async fn oidc_auth_rejects_missing_authorization_header() {
        let headers = HeaderMap::new();
        assert!(
            authenticate_oidc(&headers, Some("expected-audience"))
                .await
                .is_none()
        );
    }

    #[test]
    fn google_id_token_validation_rejects_malformed_jwt() {
        let (_private, public) = test_keypair();
        assert!(
            validate_google_id_token("not-a-jwt", "expected-audience", &key_map(&public)).is_none()
        );
        assert!(
            validate_google_id_token("a.b.c", "expected-audience", &key_map(&public)).is_none()
        );
    }

    #[test]
    fn cache_control_max_age_parses_header_directives() {
        assert_eq!(
            cache_control_max_age("public, max-age=123, must-revalidate"),
            Some(Duration::from_secs(123))
        );
        assert_eq!(cache_control_max_age("no-cache"), None);
    }

    #[test]
    fn email_allowlist_permits_listed_addresses() {
        let config = AuthConfig::oidc(Some("aud".to_string())).with_allowed_emails(vec![
            "alice@example.com".to_string(),
            "BOB@EXAMPLE.COM".to_string(),
        ]);
        assert!(config.email_allowed(Some("alice@example.com")));
        assert!(config.email_allowed(Some("ALICE@example.com")));
        assert!(config.email_allowed(Some("bob@example.com")));
        assert!(!config.email_allowed(Some("eve@example.com")));
        assert!(!config.email_allowed(None));
    }

    #[test]
    fn empty_allowlist_permits_anyone() {
        let config = AuthConfig::oidc(Some("aud".to_string()));
        assert!(config.email_allowed(Some("anyone@example.com")));
        assert!(config.email_allowed(None));
    }
}
