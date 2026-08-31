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
use crate::ipam::models::UserStatus;
use crate::ipam::store::IpamStore;
use crate::pat::PatPepper;
use crate::pat_lifecycle;

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

/// Authorization tier carried on every [`AuthenticatedPrincipal`]. Ordered
/// `Reader < Allocator < Admin` via the variant declaration order — the
/// derived [`Ord`] lets call sites compare with `principal.role >= required`
/// without a per-role match.
///
/// **Default is [`Role::Reader`]** — least privilege. An authenticated OIDC
/// user whose email is not in any of the per-role lists
/// (`NETCIDR_ADMIN_EMAILS`, `NETCIDR_ALLOCATOR_EMAILS`,
/// `NETCIDR_READER_EMAILS`) gets read-only access by default; operators
/// must explicitly grant write or admin privileges. See ADR-0002.
///
/// **Bearer-token mode is the documented exception** — see
/// [`AuthConfig::role_for_email`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Reader,
    Allocator,
    Admin,
    /// Platform owner: everything `Admin` can do, plus user-directory
    /// management (`/admin/users`). PATs are capped at `Admin`, so this
    /// tier is only reachable via an interactive OIDC session (or the
    /// bearer-mode carve-out / CLI). See ADR-0006.
    PlatformAdmin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Reader => "reader",
            Role::Allocator => "allocator",
            Role::Admin => "admin",
            Role::PlatformAdmin => "platform_admin",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = crate::error::NetcidrError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "reader" => Ok(Role::Reader),
            "allocator" => Ok(Role::Allocator),
            "admin" => Ok(Role::Admin),
            "platform_admin" => Ok(Role::PlatformAdmin),
            other => Err(crate::error::NetcidrError::InvalidInput(format!(
                "invalid role {other:?}: expected one of reader|allocator|admin|platform_admin"
            ))),
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
    /// Resolved role for this principal. The final value is set by
    /// [`AuthConfig::finalize_principal`] after authentication succeeds.
    /// The `authenticate_oidc` / `authenticate_bearer` constructors leave
    /// this as [`Role::default`] because their role is fully derived from
    /// the email-resolved role; `verify_pat` stamps the stored PAT role
    /// here so `finalize_principal` can clamp it against the owner's
    /// current email-resolved role on every use.
    pub role: Role,
}

#[derive(Clone, Default)]
pub struct AuthConfig {
    mode: AuthMode,
    bearer_token: Option<String>,
    /// Accepted ID-token audiences. Populated by splitting
    /// `NETCIDR_OIDC_AUDIENCE` on commas, so a deployment can accept both
    /// the dashboard's web client and the CLI's desktop client. A single
    /// value parses to a one-element vec, keeping older configs working.
    oidc_audiences: Vec<String>,
    allowed_emails: Vec<String>,
    admin_emails: Vec<String>,
    allocator_emails: Vec<String>,
    reader_emails: Vec<String>,
    /// Optional store + pepper used by the PAT verifier. Both must be set
    /// for the `Bearer ncdr_pat_…` branch of `require_auth` to succeed;
    /// otherwise PAT-shaped tokens fall through to a generic 401.
    pat_store: Option<Arc<dyn IpamStore>>,
    pat_pepper: Option<Arc<PatPepper>>,
    /// Optional store backing the users directory (ADR-0006). Set whenever
    /// IPAM is enabled — independent of the PAT pepper, unlike `pat_store` —
    /// so role resolution and the allowlist check read the `users` table.
    /// With no store (bearer-only / non-IPAM deploys) both fall back to the
    /// in-memory env lists.
    user_store: Option<Arc<dyn IpamStore>>,
    /// Explicit allowlist mode. `None` derives from `allowed_emails`
    /// non-emptiness (the pre-flag behavior); `Some` pins it, letting a
    /// deployment drop the email env vars post-seed without silently
    /// flipping open. See `NETCIDR_ALLOWLIST_MODE` / ADR-0006.
    allowlist_mode: Option<crate::config::AllowlistMode>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("mode", &self.mode)
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "<set>"))
            .field("oidc_audiences", &self.oidc_audiences)
            .field("allowed_emails", &self.allowed_emails)
            .field("admin_emails", &self.admin_emails)
            .field("allocator_emails", &self.allocator_emails)
            .field("reader_emails", &self.reader_emails)
            .field("pat_store", &self.pat_store.as_ref().map(|_| "<set>"))
            .field("pat_pepper", &self.pat_pepper.as_ref().map(|_| "<set>"))
            .field("user_store", &self.user_store.as_ref().map(|_| "<set>"))
            .field("allowlist_mode", &self.allowlist_mode)
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
            oidc_audiences: split_audiences(oidc_audience.as_deref()),
            allowed_emails: allowed_emails
                .into_iter()
                .map(|e| e.to_ascii_lowercase())
                .collect(),
            admin_emails: Vec::new(),
            allocator_emails: Vec::new(),
            reader_emails: Vec::new(),
            pat_store: None,
            pat_pepper: None,
            user_store: None,
            allowlist_mode: None,
        }
    }

    /// Pin the allowlist mode explicitly (env `NETCIDR_ALLOWLIST_MODE` /
    /// config `allowlist_mode`). Without this, mode derives from the
    /// allowed-emails list's non-emptiness.
    pub fn with_allowlist_mode(mut self, mode: crate::config::AllowlistMode) -> Self {
        self.allowlist_mode = Some(mode);
        self
    }

    /// Attach the IPAM store + pepper used by the PAT verifier. Set on
    /// `serve` startup; left unset for unit tests that don't exercise PATs.
    pub fn with_pat_backend(mut self, store: Arc<dyn IpamStore>, pepper: Arc<PatPepper>) -> Self {
        self.pat_store = Some(store);
        self.pat_pepper = Some(pepper);
        self
    }

    /// Attach the IPAM store backing the users directory. Set whenever IPAM
    /// is enabled — even without a PAT pepper — so the allowlist check and
    /// role resolution read the `users` table instead of the env lists.
    pub fn with_user_store(mut self, store: Arc<dyn IpamStore>) -> Self {
        self.user_store = Some(store);
        self
    }

    /// The store used for user-directory reads. Prefers the explicitly
    /// attached `user_store`; falls back to `pat_store` so existing wiring
    /// (and tests) that only attach the PAT backend keep DB-backed
    /// resolution.
    fn user_store(&self) -> Option<&Arc<dyn IpamStore>> {
        self.user_store.as_ref().or(self.pat_store.as_ref())
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

    pub fn with_allocator_emails(mut self, emails: Vec<String>) -> Self {
        self.allocator_emails = emails.into_iter().map(|e| e.to_ascii_lowercase()).collect();
        self
    }

    pub fn with_reader_emails(mut self, emails: Vec<String>) -> Self {
        self.reader_emails = emails.into_iter().map(|e| e.to_ascii_lowercase()).collect();
        self
    }

    pub fn allowed_emails(&self) -> &[String] {
        &self.allowed_emails
    }

    pub fn admin_emails(&self) -> &[String] {
        &self.admin_emails
    }

    pub fn allocator_emails(&self) -> &[String] {
        &self.allocator_emails
    }

    pub fn reader_emails(&self) -> &[String] {
        &self.reader_emails
    }

    /// Resolve a principal's role from the configured per-role email maps.
    ///
    /// Precedence (when an email is present): admin > allocator > reader >
    /// [`Role::default`] (which is [`Role::Reader`] — least privilege).
    /// Email match is case-insensitive; lists are pre-lowercased by the
    /// builders.
    ///
    /// **Bearer-token mode is the documented exception.** Static
    /// bearer-token principals carry `email = None` and resolve to
    /// [`Role::PlatformAdmin`] unconditionally. Rationale: bearer mode is
    /// the single-operator service-token model — the operator who
    /// provisioned `NETCIDR_API_TOKEN` owns the token and is expected to
    /// have full access, including user management. Silently dropping
    /// bearer-mode callers to a lower tier on a policy flip would break
    /// existing service-to-service calls without warning, with no
    /// per-token override available (bearer tokens carry no identity
    /// beyond the shared secret). See ADR-0002 and ADR-0006 for the
    /// design discussion.
    pub async fn role_for_email(&self, email: Option<&str>) -> Role {
        self.resolve_access(email).await.0
    }

    /// Resolve `(role, allowlisted)` for an email in a single store
    /// round-trip — the hot-path helper behind [`Self::role_for_email`],
    /// [`Self::email_allowed`], and `require_auth`.
    ///
    /// With a store attached, both answers come from the caller's `users`
    /// row (ADR-0006):
    /// - `status = 'disabled'` → denied, always — an explicit deny beats
    ///   the open-mode default.
    /// - **Open mode** (env allowlist empty, matching the pre-DB
    ///   semantics): any verified principal is allowed; role = row's role
    ///   if present, else [`Role::default`].
    /// - **Closed mode**: allowed iff an active row exists.
    /// - A store read error fails closed (denied) — this is a security
    ///   boundary.
    ///
    /// With no store (bearer-only / non-IPAM deploys) both answers fall
    /// back to the in-memory env lists, preserving pre-DB behavior
    /// verbatim. `email = None` (static bearer) keeps the PlatformAdmin
    /// carve-out for role and the "denied in closed mode" rule for the
    /// allowlist.
    /// The effective open/closed decision: an explicitly pinned mode wins;
    /// otherwise an empty allowed-emails list means open (pre-flag
    /// behavior).
    fn open_mode(&self) -> bool {
        match self.allowlist_mode {
            Some(crate::config::AllowlistMode::Open) => true,
            Some(crate::config::AllowlistMode::Closed) => false,
            None => self.allowed_emails.is_empty(),
        }
    }

    async fn resolve_access(&self, email: Option<&str>) -> (Role, bool) {
        let open_mode = self.open_mode();
        let Some(email) = email else {
            return (Role::PlatformAdmin, open_mode);
        };
        if let Some(store) = self.user_store() {
            return match store.get_user(email).await {
                Ok(Some(user)) => match user.status {
                    UserStatus::Disabled => (user.role, false),
                    UserStatus::Active => (user.role, true),
                },
                Ok(None) => (Role::default(), open_mode),
                Err(e) => {
                    warn!(error = %e, "user directory read failed; denying access");
                    (Role::default(), false)
                }
            };
        }
        (
            self.role_for_email_from_env(email),
            self.email_allowed_from_env(email),
        )
    }

    /// In-memory env-list resolution (admin > allocator > reader > default).
    /// Used as the no-store fallback and as the bootstrap seed source.
    fn role_for_email_from_env(&self, email: &str) -> Role {
        let needle = email.to_ascii_lowercase();
        if self.admin_emails.iter().any(|e| e == &needle) {
            return Role::Admin;
        }
        if self.allocator_emails.iter().any(|e| e == &needle) {
            return Role::Allocator;
        }
        if self.reader_emails.iter().any(|e| e == &needle) {
            return Role::Reader;
        }
        Role::default()
    }

    /// The `(email, role)` seed pairs derived from the env lists, ordered so
    /// that a stronger role wins if an email appears in multiple lists
    /// (admin first; the store's seed is first-write-wins per email).
    pub fn role_seed_pairs(&self) -> Vec<(String, Role)> {
        let mut pairs = Vec::new();
        for e in &self.admin_emails {
            pairs.push((e.clone(), Role::Admin));
        }
        for e in &self.allocator_emails {
            pairs.push((e.clone(), Role::Allocator));
        }
        for e in &self.reader_emails {
            pairs.push((e.clone(), Role::Reader));
        }
        pairs
    }

    /// Attach the resolved role to a principal whose identity has been
    /// verified by one of the lower-level `authenticate_*` / `verify_pat`
    /// constructors. Centralising this here keeps the resolution policy in
    /// exactly one place — both `require_auth` and the public
    /// [`AuthConfig::authenticate`] funnel through here.
    ///
    /// For OIDC and static-bearer principals the email-resolved role is
    /// authoritative. For PAT principals it is a ceiling: the final role
    /// is `min(email_resolved_role, stored_pat_role)`, so a PAT can narrow
    /// the owner's current privileges (e.g. an admin mints a reader-only
    /// CI token) but never widen them, and a later demotion of the owner's
    /// email automatically narrows every existing PAT.
    async fn finalize_principal(
        &self,
        principal: AuthenticatedPrincipal,
    ) -> AuthenticatedPrincipal {
        let email_role = self.role_for_email(principal.email.as_deref()).await;
        let role = match principal.auth_method {
            AuthMethod::Pat => email_role.min(principal.role),
            AuthMethod::Oidc | AuthMethod::Bearer => email_role,
        };
        AuthenticatedPrincipal { role, ..principal }
    }

    pub fn oidc_audiences(&self) -> &[String] {
        &self.oidc_audiences
    }

    pub async fn is_admin(&self, email: Option<&str>) -> bool {
        // No-email principals (static bearer) are never "admin" for the
        // purposes of the /me surface, regardless of the bearer carve-out
        // in `role_for_email`. PlatformAdmin passes: it is a superset of
        // the tenant-admin tier.
        match email {
            Some(_) => self.role_for_email(email).await >= Role::Admin,
            None => false,
        }
    }

    pub async fn is_platform_admin(&self, email: Option<&str>) -> bool {
        // Same no-email exception as `is_admin`.
        match email {
            Some(_) => self.role_for_email(email).await == Role::PlatformAdmin,
            None => false,
        }
    }

    /// A contact address for access requests: the first active platform
    /// admin in the users directory, falling back to the first env-configured
    /// admin email for store-less deployments.
    pub async fn admin_contact(&self) -> Option<String> {
        if let Some(store) = self.user_store()
            && let Ok(users) = store.list_users().await
            && let Some(admin) = users
                .iter()
                .find(|u| u.role == Role::PlatformAdmin && u.status == UserStatus::Active)
        {
            return Some(admin.email.clone());
        }
        self.admin_emails.first().cloned()
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
        let principal = if let Some(token) = bearer_token(headers.get(header::AUTHORIZATION))
            && token.starts_with("ncdr_pat_")
        {
            if let (Some(store), Some(pepper)) = (self.pat_store.as_ref(), self.pat_pepper.as_ref())
            {
                verify_pat(store, pepper.as_ref(), !self.open_mode(), token)
                    .await
                    .ok()
            } else {
                None
            }
        } else {
            match self.mode {
                AuthMode::None => None,
                AuthMode::Bearer => authenticate_bearer(headers, self.bearer_token.as_deref()),
                AuthMode::Oidc => authenticate_oidc(headers, self.oidc_audiences()).await,
            }
        };
        match principal {
            Some(p) => Some(self.finalize_principal(p).await),
            None => None,
        }
    }

    pub async fn email_is_allowed(&self, email: Option<&str>) -> bool {
        self.email_allowed(email).await
    }

    pub fn enabled(&self) -> bool {
        !matches!(self.mode, AuthMode::None)
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    async fn email_allowed(&self, email: Option<&str>) -> bool {
        self.resolve_access(email).await.1
    }

    /// In-memory env-list allowlist check — the no-store fallback. Open
    /// mode admits anyone; closed mode requires list membership (an
    /// explicitly-closed deployment with an empty list denies all —
    /// operator misconfiguration fails safe).
    fn email_allowed_from_env(&self, email: &str) -> bool {
        if self.open_mode() {
            return true;
        }
        let needle = email.to_ascii_lowercase();
        self.allowed_emails.iter().any(|allowed| allowed == &needle)
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
            match verify_pat(store, pepper.as_ref(), !config.open_mode(), token).await {
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
                    authenticate_oidc(request.headers(), config.oidc_audiences()).await
                }
            }
        }
    } else {
        None
    };

    let Some(principal) = principal else {
        return unauthorized(config.mode);
    };

    // Resolve role + allowlist status in one user-directory read. The role
    // is attached *after* identity verification but *before* the allowlist
    // check, so a downgraded admin who was just removed from the directory
    // still gets a clean 403 from the email check below (not a confusing
    // role-derivation surprise).
    let (email_role, allowed) = config.resolve_access(principal.email.as_deref()).await;
    let role = match principal.auth_method {
        // PATs can narrow the owner's privileges but never widen them.
        AuthMethod::Pat => email_role.min(principal.role),
        AuthMethod::Oidc | AuthMethod::Bearer => email_role,
    };
    let principal = AuthenticatedPrincipal { role, ..principal };

    if !allowed {
        warn!(
            email = principal.email.as_deref().unwrap_or("<none>"),
            "rejecting authenticated principal not in the users directory allowlist"
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
///   3. Users-directory check on `owner_email` (ADR-0006): a disabled row
///      is always rejected; with `enforce_allowlist` (closed mode) an
///      active row must exist.
///   4. Detached `tokio::spawn` to update `last_used_at` — fire and forget,
///      errors logged at WARN; the request never blocks on this write.
pub(crate) async fn verify_pat(
    store: &Arc<dyn IpamStore>,
    pepper: &PatPepper,
    enforce_allowlist: bool,
    token: &str,
) -> Result<AuthenticatedPrincipal, AuthError> {
    let verified = pat_lifecycle::verify_bearer_token(store, pepper, enforce_allowlist, token)
        .await
        .map_err(|_| AuthError::Unauthorized)?;

    Ok(AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: verified.owner.subject,
        email: Some(verified.owner.email),
        audience: None,
        auth_method: AuthMethod::Pat,
        pat_id: Some(verified.pat_id),
        role: verified.role,
    })
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
        role: Role::default(),
    })
}

async fn authenticate_oidc(
    headers: &HeaderMap,
    expected_audiences: &[String],
) -> Option<AuthenticatedPrincipal> {
    if expected_audiences.is_empty() {
        return None;
    }
    let jwt = bearer_token(headers.get(header::AUTHORIZATION))?;
    let keys = google_public_keys().await.ok()?;
    let claims = validate_google_id_token(jwt, expected_audiences, &keys)?;

    Some(AuthenticatedPrincipal {
        kind: PrincipalKind::Oidc,
        subject: claims.sub,
        email: claims
            .email
            .filter(|_| claims.email_verified.unwrap_or(false)),
        audience: Some(claims.aud),
        auth_method: AuthMethod::Oidc,
        pat_id: None,
        role: Role::default(),
    })
}

/// Split a comma-separated audience config value into individual
/// audiences. Trims whitespace and drops empty entries, matching the
/// parsing rules `config::resolve_email_list` already uses for the email
/// lists so the two can't drift.
fn split_audiences(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
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
    expected_audiences: &[String],
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
    validation.set_audience(expected_audiences);
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

    /// Build a valid, freshly-signed test ID token for `aud`, along with the
    /// key id and RSA modulus/exponent (big-endian bytes) needed to install
    /// the matching public key into the JWKS cache via
    /// `test_support::install_jwks`. Centralizes the keypair + claims setup
    /// so multi-audience tests don't duplicate it.
    fn signed_test_token(aud: &str) -> (String, String, Vec<u8>, Vec<u8>) {
        let (private, public) = test_keypair();
        let jwt = signed_id_token(
            &private,
            "117290938723847238472",
            aud,
            "https://accounts.google.com",
            now_seconds() + 3600,
            now_seconds(),
            Some(true),
        );
        (
            jwt,
            TEST_KEY_ID.to_string(),
            public.n().to_bytes_be(),
            public.e().to_bytes_be(),
        )
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
            validate_google_id_token(&jwt, &["expected-audience".to_string()], &key_map(&public))
                .unwrap();
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
        assert!(
            validate_google_id_token(&jwt, &["expected-audience".to_string()], &key_map(&public))
                .is_some()
        );
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
        assert!(
            validate_google_id_token(&jwt, &["other-audience".to_string()], &key_map(&public))
                .is_none()
        );
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
        assert!(
            validate_google_id_token(&jwt, &["expected-audience".to_string()], &key_map(&public))
                .is_none()
        );
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
        assert!(
            validate_google_id_token(&jwt, &["expected-audience".to_string()], &HashMap::new())
                .is_none()
        );
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
        assert!(
            validate_google_id_token(&jwt, &["expected-audience".to_string()], &key_map(&public))
                .is_none()
        );
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
        assert!(
            validate_google_id_token(&jwt, &["expected-audience".to_string()], &key_map(&public))
                .is_none()
        );
    }

    #[tokio::test]
    async fn oidc_auth_extracts_identity_from_valid_id_token() {
        let (jwt, kid, n, e) = signed_test_token("expected-audience");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        );

        test_support::clear_jwks().await;
        test_support::install_jwks(&kid, &n, &e).await;

        let principal = authenticate_oidc(&headers, &["expected-audience".to_string()])
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

        let principal = authenticate_oidc(&headers, &["expected-audience".to_string()])
            .await
            .unwrap();
        assert_eq!(principal.email, None);
    }

    #[tokio::test]
    async fn oidc_auth_rejects_missing_authorization_header() {
        let headers = HeaderMap::new();
        assert!(
            authenticate_oidc(&headers, &["expected-audience".to_string()])
                .await
                .is_none()
        );
    }

    #[test]
    fn google_id_token_validation_rejects_malformed_jwt() {
        let (_private, public) = test_keypair();
        assert!(
            validate_google_id_token(
                "not-a-jwt",
                &["expected-audience".to_string()],
                &key_map(&public)
            )
            .is_none()
        );
        assert!(
            validate_google_id_token(
                "a.b.c",
                &["expected-audience".to_string()],
                &key_map(&public)
            )
            .is_none()
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

    #[tokio::test]
    async fn email_allowlist_permits_listed_addresses() {
        // Store-less config: exercises the env-Vec fallback path.
        let config = AuthConfig::oidc(Some("aud".to_string())).with_allowed_emails(vec![
            "alice@example.com".to_string(),
            "BOB@EXAMPLE.COM".to_string(),
        ]);
        assert!(config.email_allowed(Some("alice@example.com")).await);
        assert!(config.email_allowed(Some("ALICE@example.com")).await);
        assert!(config.email_allowed(Some("bob@example.com")).await);
        assert!(!config.email_allowed(Some("eve@example.com")).await);
        assert!(!config.email_allowed(None).await);
    }

    #[tokio::test]
    async fn empty_allowlist_permits_anyone() {
        let config = AuthConfig::oidc(Some("aud".to_string()));
        assert!(config.email_allowed(Some("anyone@example.com")).await);
        assert!(config.email_allowed(None).await);
    }

    #[tokio::test]
    async fn explicit_closed_mode_overrides_empty_allowlist() {
        // The post-cleanup deployment shape: email env vars removed, mode
        // pinned closed. An empty list must NOT flip the deployment open.
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_allowlist_mode(crate::config::AllowlistMode::Closed);
        assert!(!config.email_allowed(Some("anyone@example.com")).await);
        assert!(!config.email_allowed(None).await);
    }

    #[tokio::test]
    async fn explicit_open_mode_overrides_populated_allowlist() {
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_allowed_emails(vec!["alice@example.com".to_string()])
            .with_allowlist_mode(crate::config::AllowlistMode::Open);
        assert!(config.email_allowed(Some("stranger@example.com")).await);
    }

    #[tokio::test]
    async fn closed_mode_with_store_admits_only_active_directory_rows() {
        // The exact post-cleanup production shape: no email env vars at
        // all, mode pinned closed, users directory as source of truth.
        use crate::ipam::models::UserStatus;
        use crate::ipam::store::IpamStore;
        let store = crate::ipam::sqlite::SqliteStore::in_memory().unwrap();
        store.initialize().await.unwrap();
        store.migrate().await.unwrap();
        let store: Arc<dyn IpamStore> = Arc::new(store);
        store
            .upsert_user("alice@example.com", Role::Reader, UserStatus::Active, "t")
            .await
            .unwrap();
        store
            .upsert_user(
                "mallory@example.com",
                Role::Reader,
                UserStatus::Disabled,
                "t",
            )
            .await
            .unwrap();

        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_user_store(store)
            .with_allowlist_mode(crate::config::AllowlistMode::Closed);
        assert!(config.email_allowed(Some("alice@example.com")).await);
        assert!(!config.email_allowed(Some("mallory@example.com")).await);
        assert!(!config.email_allowed(Some("stranger@example.com")).await);
    }

    #[test]
    fn role_ordering_is_reader_lt_allocator_lt_admin_lt_platform_admin() {
        assert!(Role::Reader < Role::Allocator);
        assert!(Role::Allocator < Role::Admin);
        assert!(Role::Reader < Role::Admin);
        assert!(Role::Admin < Role::PlatformAdmin);
        assert_eq!(Role::Reader.max(Role::Admin), Role::Admin);
        assert_eq!(Role::Admin.max(Role::PlatformAdmin), Role::PlatformAdmin);
    }

    #[test]
    fn role_default_is_reader_least_privilege() {
        // PR2 of #102 flipped this from Admin to Reader. Authenticated
        // OIDC principals not in any per-role list resolve to read-only
        // access; operators must explicitly grant write/admin via the
        // NETCIDR_ALLOCATOR_EMAILS / NETCIDR_ADMIN_EMAILS env vars.
        assert_eq!(Role::default(), Role::Reader);
    }

    #[test]
    fn role_as_str_matches_documented_values() {
        assert_eq!(Role::Reader.as_str(), "reader");
        assert_eq!(Role::Allocator.as_str(), "allocator");
        assert_eq!(Role::Admin.as_str(), "admin");
    }

    // These exercise the no-store (env-list) fallback path of the now-async
    // `role_for_email`/`finalize_principal`. DB-backed resolution is covered by
    // the store-contract + API tests.
    #[tokio::test]
    async fn role_for_email_resolves_with_admin_allocator_reader_precedence() {
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_admin_emails(vec!["root@x".to_string()])
            .with_allocator_emails(vec!["dev@x".to_string(), "ROOT@X".to_string()])
            .with_reader_emails(vec!["readonly@x".to_string(), "dev@x".to_string()]);

        // Admin email is in all three lists; admin wins.
        assert_eq!(config.role_for_email(Some("root@x")).await, Role::Admin);
        // Allocator email is also in reader list; allocator wins.
        assert_eq!(config.role_for_email(Some("dev@x")).await, Role::Allocator);
        // Reader-only.
        assert_eq!(
            config.role_for_email(Some("readonly@x")).await,
            Role::Reader
        );
        // Case-insensitive: lists are pre-lowercased; caller email is lowercased on lookup.
        assert_eq!(config.role_for_email(Some("DEV@X")).await, Role::Allocator);
        // Unknown OIDC email → Role::default() (Reader as of PR2).
        assert_eq!(config.role_for_email(Some("unknown@x")).await, Role::Reader);
        // None email → PlatformAdmin. Static bearer-token principals (no
        // email) are the documented carve-out — see the role_for_email doc
        // + ADR-0002/ADR-0006.
        assert_eq!(config.role_for_email(None).await, Role::PlatformAdmin);
    }

    #[tokio::test]
    async fn role_for_email_falls_through_to_reader_when_no_lists_set() {
        // Default: unknown OIDC user → Reader. Bearer-token (None) stays
        // PlatformAdmin even with no lists configured.
        let config = AuthConfig::oidc(Some("aud".to_string()));
        assert_eq!(config.role_for_email(Some("anyone@x")).await, Role::Reader);
        assert_eq!(config.role_for_email(None).await, Role::PlatformAdmin);
    }

    #[tokio::test]
    async fn role_for_email_bearer_mode_always_returns_platform_admin() {
        // Explicit assertion of the bearer-token carve-out documented on
        // role_for_email and ADR-0002/ADR-0006. Bearer principals carry
        // email=None; they must keep the top tier regardless of which lists
        // are configured, including the "everything is locked down"
        // deployment shape — otherwise bearer-mode deployments would
        // silently lose user management on the platform-admin split.
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_admin_emails(vec!["specific-admin@x".to_string()])
            .with_allocator_emails(vec!["alice@x".to_string()])
            .with_reader_emails(vec!["bob@x".to_string()]);
        assert_eq!(config.role_for_email(None).await, Role::PlatformAdmin);
    }

    #[tokio::test]
    async fn finalize_principal_overwrites_role_from_config() {
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_reader_emails(vec!["readonly@x".to_string()]);
        let principal = AuthenticatedPrincipal {
            kind: PrincipalKind::Oidc,
            subject: "sub".to_string(),
            email: Some("readonly@x".to_string()),
            audience: None,
            auth_method: AuthMethod::Oidc,
            pat_id: None,
            role: Role::Admin, // pre-finalize value; lower-level constructors set this to Role::default()
        };
        let finalized = config.finalize_principal(principal).await;
        assert_eq!(finalized.role, Role::Reader);
    }

    fn pat_principal(email: &str, stored_role: Role) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            kind: PrincipalKind::Oidc,
            subject: "sub".to_string(),
            email: Some(email.to_string()),
            audience: None,
            auth_method: AuthMethod::Pat,
            pat_id: Some("pat-id".to_string()),
            role: stored_role,
        }
    }

    #[tokio::test]
    async fn finalize_principal_pat_clamps_when_stored_role_is_narrower_than_email_role() {
        // Admin user mints a reader-only PAT for a CI script.
        // Final role must be Reader — the PAT cannot widen the user's
        // privileges, and storing Reader narrows them on purpose.
        let config =
            AuthConfig::oidc(Some("aud".to_string())).with_admin_emails(vec!["root@x".to_string()]);
        let finalized = config
            .finalize_principal(pat_principal("root@x", Role::Reader))
            .await;
        assert_eq!(finalized.role, Role::Reader);
    }

    #[tokio::test]
    async fn finalize_principal_pat_clamps_when_email_role_is_narrower_than_stored_role() {
        // PAT was minted when the owner was Admin; the owner has since
        // been demoted to Reader (removed from admin_emails, no longer
        // listed). Final role must be Reader — every existing PAT
        // narrows automatically without the operator having to revoke.
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_reader_emails(vec!["former-admin@x".to_string()]);
        let finalized = config
            .finalize_principal(pat_principal("former-admin@x", Role::Admin))
            .await;
        assert_eq!(finalized.role, Role::Reader);
    }

    #[tokio::test]
    async fn finalize_principal_pat_preserves_role_when_both_match() {
        let config = AuthConfig::oidc(Some("aud".to_string()))
            .with_allocator_emails(vec!["dev@x".to_string()]);
        let finalized = config
            .finalize_principal(pat_principal("dev@x", Role::Allocator))
            .await;
        assert_eq!(finalized.role, Role::Allocator);
    }

    #[tokio::test]
    async fn finalize_principal_pat_picks_intermediate_role_when_stored_sits_below_email() {
        // Admin email, stored=Allocator → Allocator (PAT narrows by one tier).
        let config =
            AuthConfig::oidc(Some("aud".to_string())).with_admin_emails(vec!["root@x".to_string()]);
        let finalized = config
            .finalize_principal(pat_principal("root@x", Role::Allocator))
            .await;
        assert_eq!(finalized.role, Role::Allocator);
    }

    #[tokio::test]
    async fn finalize_principal_pat_clamps_to_reader_when_owner_falls_through_to_default() {
        // PAT owner is not on any list — the email-resolved role is
        // Role::default() (Reader as of PR2). Even an admin-stored PAT
        // resolves to Reader.
        let config = AuthConfig::oidc(Some("aud".to_string()));
        let finalized = config
            .finalize_principal(pat_principal("nobody@x", Role::Admin))
            .await;
        assert_eq!(finalized.role, Role::Reader);
    }

    #[tokio::test]
    async fn finalize_principal_bearer_ignores_stored_role_field() {
        // Static-bearer principals carry `email = None` and
        // `auth_method = Bearer`. The bearer carve-out keeps them at
        // PlatformAdmin regardless of any pre-finalize role value (which
        // should be Role::default() from authenticate_bearer anyway).
        let config = AuthConfig::oidc(Some("aud".to_string()));
        let principal = AuthenticatedPrincipal {
            kind: PrincipalKind::BearerToken,
            subject: "bearer-token".to_string(),
            email: None,
            audience: None,
            auth_method: AuthMethod::Bearer,
            pat_id: None,
            role: Role::Reader,
        };
        let finalized = config.finalize_principal(principal).await;
        assert_eq!(finalized.role, Role::PlatformAdmin);
    }

    #[test]
    fn oidc_audiences_splits_comma_separated_value() {
        let config = AuthConfig::oidc(Some("web-client,desktop-client".to_string()));
        assert_eq!(
            config.oidc_audiences(),
            &["web-client".to_string(), "desktop-client".to_string()]
        );
    }

    #[test]
    fn oidc_audiences_trims_and_drops_empties() {
        let config = AuthConfig::oidc(Some(" a , ,b, ".to_string()));
        assert_eq!(config.oidc_audiences(), &["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn oidc_audiences_single_value_is_back_compatible() {
        let config = AuthConfig::oidc(Some("only-one".to_string()));
        assert_eq!(config.oidc_audiences(), &["only-one".to_string()]);
    }

    #[test]
    fn oidc_audiences_empty_when_unset() {
        let config = AuthConfig::oidc(None);
        assert!(config.oidc_audiences().is_empty());
    }

    #[tokio::test]
    async fn oidc_auth_accepts_any_configured_audience() {
        let audiences = vec!["web-client".to_string(), "desktop-client".to_string()];

        for aud in ["web-client", "desktop-client"] {
            let (jwt, kid, n, e) = signed_test_token(aud);
            test_support::clear_jwks().await;
            test_support::install_jwks(&kid, &n, &e).await;

            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
            );

            let principal = authenticate_oidc(&headers, &audiences)
                .await
                .unwrap_or_else(|| panic!("audience {aud} should be accepted"));
            assert_eq!(principal.auth_method, AuthMethod::Oidc);
        }
    }

    #[tokio::test]
    async fn oidc_auth_rejects_unconfigured_audience() {
        let audiences = vec!["web-client".to_string(), "desktop-client".to_string()];
        let (jwt, kid, n, e) = signed_test_token("some-other-client");
        test_support::clear_jwks().await;
        test_support::install_jwks(&kid, &n, &e).await;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {jwt}")).unwrap(),
        );

        assert!(authenticate_oidc(&headers, &audiences).await.is_none());
    }
}
