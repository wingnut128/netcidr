//! Personal access token lifecycle policy.
//!
//! `crate::pat` owns low-level token primitives: shape, minting, and hashing.
//! This module owns the higher-level lifecycle policy shared by HTTP handlers
//! and auth middleware: owner identity, create validation, expiry calculation,
//! active-token verification, allowlist re-checks, and last-used updates.

use std::sync::Arc;

use tracing::warn;

use crate::auth::{AuthenticatedPrincipal, Role};
use crate::error::{NetcidrError, Result};
use crate::ipam::models::{CreatePersonalAccessToken, PersonalAccessTokenSummary};
use crate::ipam::store::IpamStore;
use crate::pat::{self, PatPepper};
use crate::validation;

pub const DEFAULT_EXPIRES_IN_DAYS: u32 = 90;
pub const MAX_EXPIRES_IN_DAYS: u32 = 365;
pub const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatOwner {
    pub tenant_id: String,
    pub subject: String,
    pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePatRequest {
    pub name: String,
    pub expires_in_days: Option<u32>,
    /// Caller-requested role for the new PAT. `None` defaults to the
    /// minting principal's resolved role, which preserves pre-feature
    /// behaviour (the verifier's clamp already enforces
    /// `min(owner_role, pat_role)`, so the default can never widen privileges).
    pub role: Option<Role>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedPat {
    pub summary: PersonalAccessTokenSummary,
    pub plaintext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPat {
    pub pat_id: String,
    pub owner: PatOwner,
    /// Role stored on the PAT row at mint time, already clamped by the
    /// minting principal's role. The auth path re-clamps against the
    /// owner's current email-resolved role on every use, so a later
    /// demotion of the owner narrows existing PATs automatically.
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyPatError {
    Unauthorized,
}

#[derive(Clone)]
pub struct PatLifecycle {
    store: Arc<dyn IpamStore>,
    pepper: Arc<PatPepper>,
}

impl PatLifecycle {
    pub fn new(store: Arc<dyn IpamStore>, pepper: Arc<PatPepper>) -> Self {
        Self { store, pepper }
    }

    pub async fn mint_for_owner(
        &self,
        owner: &PatOwner,
        role: Role,
        request: CreatePatRequest,
    ) -> Result<MintedPat> {
        let name = validate_name(&request.name)?;
        let days = validate_expires_in_days(request.expires_in_days)?;
        let minted = pat::mint(self.pepper.as_ref());
        let now = chrono::Utc::now();
        let expires_at = (now + chrono::Duration::days(days as i64)).to_rfc3339();

        let row = self
            .store
            .pat_create(&CreatePersonalAccessToken {
                tenant_id: owner.tenant_id.clone(),
                owner_sub: owner.subject.clone(),
                owner_email: owner.email.clone(),
                name,
                prefix: minted.prefix,
                token_hash: minted.hash.to_vec(),
                role,
                expires_at,
            })
            .await?;

        Ok(MintedPat {
            summary: row.into(),
            plaintext: minted.plaintext,
        })
    }

    pub async fn list_for_owner(
        &self,
        owner: &PatOwner,
    ) -> Result<Vec<PersonalAccessTokenSummary>> {
        self.store
            .pat_list_for_owner(&owner.tenant_id, &owner.subject)
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    pub async fn revoke_for_owner(&self, owner: &PatOwner, id: &str) -> Result<()> {
        validation::validate_identifier(id)?;
        let now = chrono::Utc::now().to_rfc3339();
        self.store
            .pat_revoke(&owner.tenant_id, &owner.subject, id, &now)
            .await
            .map(|_| ())
    }

    /// Mint a PAT for the identity carried by `principal`. The lifecycle
    /// owns the principal-to-owner translation so HTTP handlers don't
    /// reimplement it. Returns `NoVerifiedEmail` if the principal is
    /// missing the email that becomes the tenant/owner key.
    pub async fn mint_for_principal(
        &self,
        principal: &AuthenticatedPrincipal,
        request: CreatePatRequest,
    ) -> std::result::Result<MintedPat, MintForPrincipalError> {
        let owner =
            owner_from_principal(principal).ok_or(MintForPrincipalError::NoVerifiedEmail)?;
        // Stamp the row with the caller's resolved role unless they asked
        // for a narrower one. The verifier re-clamps `min(owner_role, pat_role)`
        // on every use, so even an explicit `Role::Admin` from a non-admin
        // caller cannot widen privileges — but storing it would be misleading,
        // so we clamp at mint time too. Belt and suspenders.
        let role = request.role.unwrap_or(principal.role).min(principal.role);
        self.mint_for_owner(&owner, role, request)
            .await
            .map_err(MintForPrincipalError::Lifecycle)
    }

    /// List the PATs owned by the identity carried by `principal`.
    pub async fn list_for_principal(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> std::result::Result<Vec<PersonalAccessTokenSummary>, MintForPrincipalError> {
        let owner =
            owner_from_principal(principal).ok_or(MintForPrincipalError::NoVerifiedEmail)?;
        self.list_for_owner(&owner)
            .await
            .map_err(MintForPrincipalError::Lifecycle)
    }

    /// Revoke a PAT belonging to the identity carried by `principal`.
    pub async fn revoke_for_principal(
        &self,
        principal: &AuthenticatedPrincipal,
        id: &str,
    ) -> std::result::Result<(), MintForPrincipalError> {
        let owner =
            owner_from_principal(principal).ok_or(MintForPrincipalError::NoVerifiedEmail)?;
        self.revoke_for_owner(&owner, id)
            .await
            .map_err(MintForPrincipalError::Lifecycle)
    }
}

/// Failure modes for the `*_for_principal` family. Separates "the
/// principal can't be mapped to a PAT owner" (a 403 the auth layer
/// should have caught — surfaced explicitly for defense in depth)
/// from downstream lifecycle errors that pass through unchanged.
#[derive(Debug)]
pub enum MintForPrincipalError {
    NoVerifiedEmail,
    Lifecycle(NetcidrError),
}

/// Translate an authenticated OIDC principal into the `PatOwner` that
/// keys storage. Today `tenant_id == email`; both fields are denormalised
/// for lookup ergonomics. Returns `None` if the principal lacks the
/// verified email — `require_auth` enforces this for OIDC mode, but the
/// lifecycle defends in depth.
fn owner_from_principal(principal: &AuthenticatedPrincipal) -> Option<PatOwner> {
    let email = principal.email.clone()?;
    Some(PatOwner {
        tenant_id: email.clone(),
        subject: principal.subject.clone(),
        email,
    })
}

pub async fn verify_bearer_token(
    store: &Arc<dyn IpamStore>,
    pepper: &PatPepper,
    allowed_emails: &[String],
    token: &str,
) -> std::result::Result<VerifiedPat, VerifyPatError> {
    let hash = pat::hash_for_lookup(token, pepper).ok_or(VerifyPatError::Unauthorized)?;
    let now = chrono::Utc::now().to_rfc3339();
    let row = store
        .pat_get_by_hash(&hash, &now)
        .await
        .map_err(|_| VerifyPatError::Unauthorized)?
        .ok_or(VerifyPatError::Unauthorized)?;

    if !allowed_emails.is_empty() {
        let needle = row.owner_email.to_ascii_lowercase();
        if !allowed_emails.iter().any(|e| e == &needle) {
            return Err(VerifyPatError::Unauthorized);
        }
    }

    let verified = VerifiedPat {
        pat_id: row.id.clone(),
        owner: PatOwner {
            tenant_id: row.tenant_id.clone(),
            subject: row.owner_sub.clone(),
            email: row.owner_email.clone(),
        },
        role: row.role,
    };

    let touch_store = Arc::clone(store);
    let touch_id = row.id;
    let touch_now = now;
    tokio::spawn(async move {
        if let Err(e) = touch_store.pat_touch_last_used(&touch_id, &touch_now).await {
            warn!(error = %e, pat_id = %touch_id, "failed to update PAT last_used_at");
        }
    });

    Ok(verified)
}

fn validate_name(raw: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(NetcidrError::InvalidInput(
            "name must not be empty".to_string(),
        ));
    }
    validation::validate_text_field(name, MAX_NAME_LEN)?;
    Ok(name.to_string())
}

fn validate_expires_in_days(expires_in_days: Option<u32>) -> Result<u32> {
    match expires_in_days {
        None => Ok(DEFAULT_EXPIRES_IN_DAYS),
        Some(0) => Err(NetcidrError::InvalidInput(
            "expires_in_days must be at least 1".to_string(),
        )),
        Some(n) if n > MAX_EXPIRES_IN_DAYS => Err(NetcidrError::InvalidInput(format!(
            "expires_in_days must not exceed {MAX_EXPIRES_IN_DAYS}"
        ))),
        Some(n) => Ok(n),
    }
}
