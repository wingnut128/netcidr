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
use crate::ipam::models::{PersonalAccessToken, PersonalAccessTokenSummary};
use crate::ipam::mutation::{
    AuditFact, Change, DecideCtx, Decision, Handle, Mutation, ReadSet, Snapshot, SystemClock,
    UuidIds,
};
use crate::ipam::store::{IpamStore, LockScope, Write};
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
    max_pats_per_tenant: u32,
}

impl PatLifecycle {
    pub fn new(
        store: Arc<dyn IpamStore>,
        pepper: Arc<PatPepper>,
        max_pats_per_tenant: u32,
    ) -> Self {
        Self {
            store,
            pepper,
            max_pats_per_tenant,
        }
    }

    pub async fn mint_for_owner(
        &self,
        owner: &PatOwner,
        role: Role,
        request: CreatePatRequest,
    ) -> Result<MintedPat> {
        let name = validate_name(&request.name)?;
        let days = validate_expires_in_days(request.expires_in_days)?;
        let now = chrono::Utc::now();

        // The secret is generated outside the unit; only its public prefix
        // and peppered hash enter the decision and the store.
        let minted = pat::mint(self.pepper.as_ref());
        let mutation = MintPat {
            owner: owner.clone(),
            name,
            role,
            prefix: minted.prefix,
            token_hash: minted.hash.to_vec(),
            now: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::days(days as i64)).to_rfc3339(),
            limit: self.max_pats_per_tenant,
        };
        let summary = self.run(&owner.tenant_id, mutation).await?;
        Ok(MintedPat {
            summary,
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
        let mutation = RevokePat {
            owner: owner.clone(),
            id: id.to_string(),
        };
        self.run(&owner.tenant_id, mutation).await
    }

    /// Run a PAT Mutation as one transaction unit under its owner's scope.
    async fn run<M: Mutation>(&self, tenant_id: &str, mutation: M) -> Result<M::Output> {
        Ok(crate::ipam::mutation::execute(
            self.store.as_ref(),
            &SystemClock,
            Arc::new(UuidIds),
            tenant_id,
            mutation,
            None,
        )
        .await?
        .into_inner())
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
        // for a narrower one, and never above Admin: PATs are capped at the
        // tenant-admin tier (ADR-0006) so platform-level access is never
        // mintable as a long-lived token (the DB CHECK also rejects
        // 'platform_admin'). The verifier re-clamps `min(owner_role, pat_role)`
        // on every use, so even an explicit `Role::Admin` from a non-admin
        // caller cannot widen privileges — but storing it would be misleading,
        // so we clamp at mint time too. Belt and suspenders.
        let role = request
            .role
            .unwrap_or(principal.role)
            .min(principal.role)
            .min(Role::Admin);
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
    enforce_allowlist: bool,
    token: &str,
) -> std::result::Result<VerifiedPat, VerifyPatError> {
    let hash = pat::hash_for_lookup(token, pepper).ok_or(VerifyPatError::Unauthorized)?;
    let now = chrono::Utc::now().to_rfc3339();
    let row = store
        .pat_get_by_hash(&hash, &now)
        .await
        .map_err(|_| VerifyPatError::Unauthorized)?
        .ok_or(VerifyPatError::Unauthorized)?;

    // The owner must still be admitted by the users directory (ADR-0006):
    // a disabled row is always rejected — disabling a user kills their
    // PATs immediately — and in closed mode (`enforce_allowlist`) an
    // active row must exist. Open mode admits owners with no row,
    // matching the OIDC semantics. Store errors fail closed.
    match store.get_user(&row.owner_email).await {
        Ok(Some(user)) if user.status == crate::ipam::models::UserStatus::Disabled => {
            return Err(VerifyPatError::Unauthorized);
        }
        Ok(Some(_)) => {}
        Ok(None) if enforce_allowlist => return Err(VerifyPatError::Unauthorized),
        Ok(None) => {}
        Err(_) => return Err(VerifyPatError::Unauthorized),
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

// ---------------------------------------------------------------------------
// Mutations under the PAT Owner's Lock Scope (ADR-0007)
// ---------------------------------------------------------------------------

fn owner_scope(owner: &PatOwner) -> LockScope {
    LockScope::PatOwner {
        tenant_id: owner.tenant_id.clone(),
        owner_sub: owner.subject.clone(),
    }
}

/// Mint a PAT unless the owner already holds `limit` active ones. Counting
/// and inserting under the owner's scope keeps the limit across processes.
struct MintPat {
    owner: PatOwner,
    name: String,
    role: Role,
    prefix: String,
    token_hash: Vec<u8>,
    now: String,
    expires_at: String,
    limit: u32,
}

impl Mutation for MintPat {
    type Output = PersonalAccessTokenSummary;
    type Reads = Handle<u64>;

    fn scope(&self) -> LockScope {
        owner_scope(&self.owner)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.active_pat_count(&self.owner.tenant_id, &self.owner.subject, &self.now)
    }

    fn decide(
        self,
        active: Self::Reads,
        snapshot: &Snapshot,
        cx: &DecideCtx,
    ) -> Result<Decision<PersonalAccessTokenSummary>> {
        let count = u32::try_from(*snapshot.get(active)?).unwrap_or(u32::MAX);
        if count >= self.limit {
            return Err(NetcidrError::PatLimitExceeded {
                count,
                limit: self.limit,
            });
        }
        let row = PersonalAccessToken {
            id: cx.new_id(),
            tenant_id: self.owner.tenant_id,
            owner_sub: self.owner.subject,
            owner_email: self.owner.email,
            name: self.name,
            prefix: self.prefix,
            token_hash: self.token_hash,
            role: self.role,
            created_at: self.now,
            expires_at: self.expires_at,
            last_used_at: None,
            revoked_at: None,
        };
        let change = Change::new(
            Write::InsertPat(row.clone()),
            AuditFact {
                action: "mint_pat",
                entity_type: "personal_access_token",
                entity_id: row.id.clone(),
                details: Some(format!("role={}", row.role.as_str())),
            },
        );
        Ok(Decision::new(row.into(), change))
    }
}

/// Revoke one of the owner's PATs. A PAT owned by anyone else reads as
/// missing (never revealing that it exists); revoking an already-revoked PAT
/// changes nothing.
struct RevokePat {
    owner: PatOwner,
    id: String,
}

impl Mutation for RevokePat {
    type Output = ();
    type Reads = Handle<Option<PersonalAccessToken>>;

    fn scope(&self) -> LockScope {
        owner_scope(&self.owner)
    }

    fn reads(&self, set: &mut ReadSet) -> Self::Reads {
        set.pat(&self.owner.tenant_id, &self.owner.subject, &self.id)
    }

    fn decide(self, pat: Self::Reads, snapshot: &Snapshot, cx: &DecideCtx) -> Result<Decision<()>> {
        let pat = snapshot
            .get(pat)?
            .as_ref()
            .ok_or_else(|| NetcidrError::PatNotFound(self.id.clone()))?;
        if pat.revoked_at.is_some() {
            return Ok(Decision::unchanged(()));
        }
        let change = Change::new(
            Write::RevokePat {
                tenant_id: self.owner.tenant_id.clone(),
                owner_sub: self.owner.subject.clone(),
                id: self.id.clone(),
                revoked_at: cx.now().to_rfc3339(),
            },
            AuditFact {
                action: "revoke_pat",
                entity_type: "personal_access_token",
                entity_id: self.id.clone(),
                details: None,
            },
        );
        Ok(Decision::new((), change))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::audit_context::AuditContext;
    use crate::ipam::store::Rows;

    fn owner() -> PatOwner {
        PatOwner {
            tenant_id: "o@x".to_string(),
            subject: "sub".to_string(),
            email: "o@x".to_string(),
        }
    }

    fn decide<M: Mutation>(m: M, rows: Vec<Rows>) -> Result<Decision<M::Output>> {
        let now = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
        let cx = DecideCtx::new(now, AuditContext::default(), Arc::new(UuidIds));
        let mut set = ReadSet::default();
        let reads = m.reads(&mut set);
        m.decide(reads, &Snapshot::new(rows), &cx)
    }

    fn mint(limit: u32) -> MintPat {
        MintPat {
            owner: owner(),
            name: "ci".to_string(),
            role: Role::Reader,
            prefix: "ncdr_pat_abc".to_string(),
            token_hash: vec![7; 32],
            now: "2026-10-01T12:00:00+00:00".to_string(),
            expires_at: "2026-12-30T12:00:00+00:00".to_string(),
            limit,
        }
    }

    #[test]
    fn mint_is_refused_at_the_limit_and_allowed_below_it() {
        let at_limit = decide(mint(2), vec![Rows::Count(2)]);
        assert!(matches!(
            at_limit,
            Err(NetcidrError::PatLimitExceeded { count: 2, limit: 2 })
        ));

        let d = decide(mint(2), vec![Rows::Count(1)]).unwrap();
        assert_eq!(d.output().prefix, "ncdr_pat_abc");
        assert_eq!(d.output().role, Role::Reader);
        assert_eq!(d.changes().len(), 1);
    }

    fn token(revoked_at: Option<&str>) -> PersonalAccessToken {
        PersonalAccessToken {
            id: "t1".to_string(),
            tenant_id: "o@x".to_string(),
            owner_sub: "sub".to_string(),
            owner_email: "o@x".to_string(),
            name: "ci".to_string(),
            prefix: "ncdr_pat_abc".to_string(),
            token_hash: vec![7; 32],
            role: Role::Reader,
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
            expires_at: "2027-01-01T00:00:00+00:00".to_string(),
            last_used_at: None,
            revoked_at: revoked_at.map(str::to_string),
        }
    }

    fn revoke() -> RevokePat {
        RevokePat {
            owner: owner(),
            id: "t1".to_string(),
        }
    }

    #[test]
    fn revoke_writes_once_and_hides_missing_tokens() {
        let d = decide(revoke(), vec![Rows::Pat(Some(token(None)))]).unwrap();
        assert_eq!(d.changes().len(), 1);

        let again = decide(
            revoke(),
            vec![Rows::Pat(Some(token(Some("2026-09-01T00:00:00+00:00"))))],
        )
        .unwrap();
        assert!(again.changes().is_empty());

        let missing = decide(revoke(), vec![Rows::Pat(None)]);
        assert!(matches!(missing, Err(NetcidrError::PatNotFound(_))));
    }
}
