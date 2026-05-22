use std::sync::Arc;

use netcidr::auth::Role;
use netcidr::ipam::sqlite::SqliteStore;
use netcidr::ipam::store::IpamStore;
use netcidr::pat::PatPepper;
use netcidr::pat_lifecycle::{self, CreatePatRequest, PatLifecycle, PatOwner, VerifyPatError};

const OWNER_EMAIL: &str = "owner@example.com";
const OWNER_SUB: &str = "oidc-sub-123";

async fn lifecycle() -> (PatLifecycle, Arc<dyn IpamStore>, Arc<PatPepper>) {
    let store = SqliteStore::in_memory().unwrap();
    store.initialize().await.unwrap();
    store.migrate().await.unwrap();
    let store: Arc<dyn IpamStore> = Arc::new(store);
    let pepper = Arc::new(PatPepper::from_bytes(&[0xA5u8; 32]).unwrap());
    (
        PatLifecycle::new(Arc::clone(&store), Arc::clone(&pepper)),
        store,
        pepper,
    )
}

fn owner() -> PatOwner {
    PatOwner {
        tenant_id: OWNER_EMAIL.to_string(),
        subject: OWNER_SUB.to_string(),
        email: OWNER_EMAIL.to_string(),
    }
}

#[tokio::test]
async fn lifecycle_mints_lists_and_verifies_for_owner() {
    let (lifecycle, store, pepper) = lifecycle().await;

    let minted = lifecycle
        .mint_for_owner(
            &owner(),
            Role::Admin,
            CreatePatRequest {
                name: "ci-runner".to_string(),
                expires_in_days: Some(30),
                role: None,
            },
        )
        .await
        .unwrap();

    assert!(minted.plaintext.starts_with("ncdr_pat_"));
    assert_eq!(minted.summary.name, "ci-runner");
    assert_eq!(minted.summary.prefix.len(), 12);
    assert_eq!(minted.summary.role, Role::Admin);

    let listed = lifecycle.list_for_owner(&owner()).await.unwrap();
    assert_eq!(listed, vec![minted.summary.clone()]);

    let verified = pat_lifecycle::verify_bearer_token(&store, &pepper, &[], &minted.plaintext)
        .await
        .unwrap();
    assert_eq!(verified.pat_id, minted.summary.id);
    assert_eq!(verified.owner.subject, OWNER_SUB);
    assert_eq!(verified.owner.email, OWNER_EMAIL);
    assert_eq!(verified.owner.tenant_id, OWNER_EMAIL);
    assert_eq!(verified.role, Role::Admin);
}

#[tokio::test]
async fn verify_bearer_token_surfaces_stored_role_for_clamp() {
    // verify_pat stamps `verified.role` on the principal so
    // finalize_principal can clamp it against the owner's current
    // email-resolved role. Confirm the stored role round-trips through
    // the verifier — not the role passed by the caller at verify time.
    let (lifecycle, store, pepper) = lifecycle().await;

    let minted = lifecycle
        .mint_for_owner(
            &owner(),
            Role::Reader,
            CreatePatRequest {
                name: "ci-reader".to_string(),
                expires_in_days: Some(30),
                role: None,
            },
        )
        .await
        .unwrap();

    let verified = pat_lifecycle::verify_bearer_token(&store, &pepper, &[], &minted.plaintext)
        .await
        .unwrap();
    assert_eq!(verified.role, Role::Reader);
}

#[tokio::test]
async fn lifecycle_rejects_invalid_create_policy_before_storage() {
    let (lifecycle, _store, _pepper) = lifecycle().await;

    assert!(
        lifecycle
            .mint_for_owner(
                &owner(),
                Role::Admin,
                CreatePatRequest {
                    name: " ".to_string(),
                    expires_in_days: Some(30),
                    role: None,
                },
            )
            .await
            .is_err()
    );
    assert!(
        lifecycle
            .mint_for_owner(
                &owner(),
                Role::Admin,
                CreatePatRequest {
                    name: "ok".to_string(),
                    expires_in_days: Some(0),
                    role: None,
                },
            )
            .await
            .is_err()
    );
    assert!(
        lifecycle
            .mint_for_owner(
                &owner(),
                Role::Admin,
                CreatePatRequest {
                    name: "ok".to_string(),
                    expires_in_days: Some(366),
                    role: None,
                },
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn lifecycle_verify_collapses_shape_miss_and_allowlist_failures() {
    let (lifecycle, store, pepper) = lifecycle().await;
    let minted = lifecycle
        .mint_for_owner(
            &owner(),
            Role::Admin,
            CreatePatRequest {
                name: "ci-runner".to_string(),
                expires_in_days: Some(30),
                role: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        pat_lifecycle::verify_bearer_token(&store, &pepper, &[], "ncdr_pat_too_short")
            .await
            .unwrap_err(),
        VerifyPatError::Unauthorized
    );
    assert_eq!(
        pat_lifecycle::verify_bearer_token(
            &store,
            &pepper,
            &["someone@example.com".to_string()],
            &minted.plaintext,
        )
        .await
        .unwrap_err(),
        VerifyPatError::Unauthorized
    );
}
